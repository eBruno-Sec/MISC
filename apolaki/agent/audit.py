"""
Structured, tamper-evident audit log.

Append-only JSONL where each record carries the SHA-256 of the previous record — a hash chain — so
any edit, reorder, or deletion of history is detectable (verify_chain). It records the
security-relevant, state-changing actions of an engagement: scans launched, credentials discovered,
sessions acquired, accounts created, intrusive checks run, mission exports. No secrets are stored —
metadata is passed through vault.redact, so only labels + vault references land in the log.

Pure logic (hashing/chaining) is unit-tested; the only side effect is appending a line to a file.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time

_GENESIS = "0" * 64


def _now() -> float:
    return time.time()


def _digest(entry: dict) -> str:
    """SHA-256 over the record's canonical JSON, excluding its own hash field."""
    payload = {k: entry[k] for k in entry if k != "hash"}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AuditLog:
    def __init__(self, path: str = None):
        self.path = path or os.path.join(os.environ.get("BBH_DATA_DIR", "/app/data"), "audit", "audit.jsonl")
        self._lock = threading.RLock()
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        except Exception:
            pass
        self._key = self._load_key()

    # ── signed head checkpoint (detects TRUNCATION — deleting tail records) ──
    def _load_key(self) -> bytes:
        env = os.environ.get("APOLAKI_AUDIT_KEY")
        if env:
            return env.encode()
        kp = self.path + ".key"
        try:
            if os.path.exists(kp):
                with open(kp, "rb") as f:
                    return f.read().strip()
            k = hashlib.sha256(os.urandom(32)).hexdigest().encode()
            with open(kp, "wb") as f:
                f.write(k)
            os.chmod(kp, 0o600)
            return k
        except Exception:
            return b"apolaki-audit-ephemeral"

    def _sign(self, msg: str) -> str:
        return hmac.new(self._key, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    def _checkpoint_path(self) -> str:
        return self.path + ".head"

    def _write_checkpoint(self, count: int, last_hash: str) -> None:
        cp = {"count": count, "last_hash": last_hash, "ts": _now()}
        cp["sig"] = self._sign("%d:%s" % (count, last_hash))
        try:
            with open(self._checkpoint_path(), "w", encoding="utf-8") as f:
                json.dump(cp, f)
        except Exception:
            pass

    def _read_checkpoint(self):
        try:
            with open(self._checkpoint_path(), "r", encoding="utf-8") as f:
                cp = json.load(f)
            if cp.get("sig") == self._sign("%d:%s" % (cp.get("count", -1), cp.get("last_hash", ""))):
                return cp
            return "TAMPERED"      # signature mismatch — the checkpoint itself was altered
        except Exception:
            return None

    def _read_lines(self) -> list:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return [json.loads(ln) for ln in f if ln.strip()]
        except Exception:
            return []

    def _last_hash(self) -> str:
        lines = self._read_lines()
        return lines[-1]["hash"] if lines else _GENESIS

    def record(self, action: str, *, actor: str = "system", target: str = "", mission: str = "",
               **meta) -> dict:
        """Append one tamper-evident audit entry. Metadata is redacted (no secrets)."""
        import vault
        with self._lock:
            entry = {"ts": _now(), "action": action, "actor": actor, "target": target,
                     "mission": mission, "meta": vault.redact(meta or {}), "prev": self._last_hash()}
            entry["hash"] = _digest(entry)
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                pass
            self._write_checkpoint(len(self._read_lines()), entry["hash"])
            return entry

    def entries(self, mission: str = None, action: str = None, limit: int = 500) -> list:
        rows = self._read_lines()
        if mission is not None:
            rows = [r for r in rows if r.get("mission") == mission]
        if action is not None:
            rows = [r for r in rows if r.get("action") == action]
        return rows[-limit:]

    def verify_chain(self) -> tuple:
        """(ok, first_bad_index). Recompute each record's hash + confirm it links to the previous
        (detects edits/reorders), THEN check the signed head checkpoint (detects TRUNCATION — deleting
        tail records leaves an otherwise-valid short chain — and tampering with the checkpoint itself).
        ok=True + index -1 when intact; index -2 = checkpoint forged/altered."""
        lines = self._read_lines()
        prev = _GENESIS
        for i, r in enumerate(lines):
            if r.get("prev") != prev:
                return False, i
            if _digest(r) != r.get("hash"):
                return False, i
            prev = r["hash"]
        cp = self._read_checkpoint()
        if cp == "TAMPERED":
            return False, -2
        if isinstance(cp, dict):
            if len(lines) < cp.get("count", 0):
                return False, len(lines)                     # tail records were deleted
            if len(lines) == cp.get("count") and prev != cp.get("last_hash"):
                return False, max(0, len(lines) - 1)
        return True, -1


_DEFAULT = None
_DEFAULT_LOCK = threading.Lock()


def default() -> AuditLog:
    global _DEFAULT
    if _DEFAULT is None:
        with _DEFAULT_LOCK:
            if _DEFAULT is None:
                _DEFAULT = AuditLog()
    return _DEFAULT


def record(action: str, **kw) -> dict:
    """Module-level convenience — append to the default audit log. Best-effort; never raises."""
    try:
        return default().record(action, **kw)
    except Exception:
        return {}
