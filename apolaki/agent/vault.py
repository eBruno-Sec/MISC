"""
Encrypted identity vault.

Reusable secrets — credentials, cookies, bearer/refresh tokens, login recipes — must never sit in
plaintext in ordinary mission snapshots, reports, logs, SSE events, model context or exports. The
vault is a dedicated encrypted-at-rest store keyed by a stable reference; everything else carries
only that reference:

    vault://mission/<mission_id>/<role>

Look-ups return real secrets ONLY to the server-side transport (login, session application), never
to the model layer. `redact()` scrubs secret-bearing keys from any structure that is about to reach
a report/log/model.

Encryption: Fernet (AES-128-CBC + HMAC-SHA256) from `cryptography`. The key is taken from
APOLAKI_VAULT_KEY (urlsafe-base64, 32 bytes) when set, else a per-install key is generated once and
stored 0600 next to the vault. If `cryptography` is somehow unavailable the vault degrades to a
clearly-labelled NON-encrypted store that STILL enforces the redacted-reference contract — it never
pretends to be encrypted. is_encrypted() reports the true protection level.
"""
from __future__ import annotations

import base64
import json
import os
import threading

_REF_PREFIX = "vault://mission/"

# Keys whose values are secret and must be scrubbed from anything model/report/log-visible.
_SECRET_KEYS = {"password", "pass", "pwd", "secret", "token", "access_token", "refresh_token",
                "jwt", "id_token", "authorization", "cookie", "set-cookie", "api_key", "apikey",
                "session", "bearer", "credential"}

try:
    from cryptography.fernet import Fernet  # type: ignore
    _HAVE_FERNET = True
except Exception:  # pragma: no cover - exercised only when the dep is absent
    Fernet = None  # type: ignore
    _HAVE_FERNET = False


def _default_dir() -> str:
    return os.environ.get("APOLAKI_VAULT_DIR") or os.path.join(
        os.environ.get("BBH_DATA_DIR", "/app/data"), "vault")


class Vault:
    """One vault per data directory. Thread-safe. Per-mission JSON file of {role: token}."""

    def __init__(self, base_dir: str | None = None):
        self.dir = base_dir or _default_dir()
        self._lock = threading.RLock()
        self._fernet = None
        try:
            os.makedirs(self.dir, exist_ok=True)
        except Exception:
            pass
        if _HAVE_FERNET:
            self._fernet = Fernet(self._load_or_make_key())

    # ── key management ──
    def _load_or_make_key(self) -> bytes:
        env = os.environ.get("APOLAKI_VAULT_KEY")
        if env:
            key = env.encode() if isinstance(env, str) else env
            # accept a raw 32-byte secret too by urlsafe-b64 encoding it
            try:
                Fernet(key)
                return key
            except Exception:
                return base64.urlsafe_b64encode(_pad32(key))
        path = os.path.join(self.dir, ".key")
        try:
            if os.path.exists(path):
                with open(path, "rb") as f:
                    return f.read().strip()
        except Exception:
            pass
        key = Fernet.generate_key()
        try:
            with open(path, "wb") as f:
                f.write(key)
            os.chmod(path, 0o600)
        except Exception:
            pass
        return key

    def is_encrypted(self) -> bool:
        return self._fernet is not None

    # ── storage ──
    def _path(self, mission_id: str) -> str:
        safe = "".join(c for c in str(mission_id or "default") if c.isalnum() or c in "-_") or "default"
        return os.path.join(self.dir, f"{safe}.json")

    def _read(self, mission_id: str) -> dict:
        try:
            with open(self._path(mission_id), "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write(self, mission_id: str, data: dict) -> None:
        tmp = self._path(mission_id) + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self._path(mission_id))
        except Exception:
            pass

    def _enc(self, obj: dict) -> str:
        raw = json.dumps(obj).encode("utf-8")
        if self._fernet is not None:
            return "f:" + self._fernet.encrypt(raw).decode("ascii")
        return "p:" + base64.b64encode(raw).decode("ascii")  # labelled plaintext fallback

    def _dec(self, token: str):
        try:
            kind, _, payload = (token or "").partition(":")
            if kind == "f" and self._fernet is not None:
                return json.loads(self._fernet.decrypt(payload.encode("ascii")).decode("utf-8"))
            if kind == "p":
                return json.loads(base64.b64decode(payload.encode("ascii")).decode("utf-8"))
        except Exception:
            return None
        return None

    # ── public API ──
    def put(self, mission_id: str, role: str, secret: dict) -> str:
        """Encrypt+store a secret bundle under (mission, role). Returns its reference."""
        with self._lock:
            data = self._read(mission_id)
            data[role] = self._enc(dict(secret or {}))
            self._write(mission_id, data)
        return self.ref(mission_id, role)

    def get(self, ref: str):
        """Resolve a vault://mission/<mid>/<role> reference to its secret bundle (server-side only)."""
        parsed = self.parse_ref(ref)
        if not parsed:
            return None
        mission_id, role = parsed
        return self.get_role(mission_id, role)

    def get_role(self, mission_id: str, role: str):
        with self._lock:
            token = self._read(mission_id).get(role)
        return self._dec(token) if token else None

    def list_refs(self, mission_id: str) -> list:
        with self._lock:
            return [self.ref(mission_id, r) for r in self._read(mission_id).keys()]

    def delete(self, mission_id: str, role: str) -> None:
        with self._lock:
            data = self._read(mission_id)
            if role in data:
                del data[role]
                self._write(mission_id, data)

    def purge(self, mission_id: str) -> None:
        try:
            os.remove(self._path(mission_id))
        except Exception:
            pass

    # ── references ──
    @staticmethod
    def ref(mission_id: str, role: str) -> str:
        return f"{_REF_PREFIX}{mission_id}/{role}"

    @staticmethod
    def parse_ref(ref: str):
        if not isinstance(ref, str) or not ref.startswith(_REF_PREFIX):
            return None
        rest = ref[len(_REF_PREFIX):]
        if "/" not in rest:
            return None
        mid, role = rest.rsplit("/", 1)
        return (mid, role) if mid and role else None


# ── module-level default vault + redaction ──
_DEFAULT = None
_DEFAULT_LOCK = threading.Lock()


def default() -> Vault:
    global _DEFAULT
    if _DEFAULT is None:
        with _DEFAULT_LOCK:
            if _DEFAULT is None:
                _DEFAULT = Vault()
    return _DEFAULT


def is_ref(value) -> bool:
    return isinstance(value, str) and value.startswith(_REF_PREFIX)


def redact(obj, _depth: int = 0):
    """Return a copy of a dict/list with secret-bearing values replaced by '<redacted>'. Defense in
    depth for anything about to reach a report/log/model. Vault references pass through untouched
    (they are safe by construction)."""
    if _depth > 12:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if is_ref(v):
                out[k] = v
            elif isinstance(k, str) and k.lower() in _SECRET_KEYS and isinstance(v, (str, bytes)):
                out[k] = "<redacted>"
            else:
                out[k] = redact(v, _depth + 1)
        return out
    if isinstance(obj, list):
        return [redact(v, _depth + 1) for v in obj]
    return obj
