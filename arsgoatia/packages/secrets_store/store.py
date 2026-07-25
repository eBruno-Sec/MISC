"""Dev-only local secret store (ADR 0003).

Raw secret material (JWTs, cookies) is stored here addressed by `secret_uri`;
everywhere else references only the uri + a sha256 fingerprint. The tool executor
fetches the plaintext by uri at call time and never logs or returns it. Named
`secrets_store` (not `secrets`) to avoid shadowing the stdlib module.

Encryption uses Fernet keyed from SESSION_SECRET when `cryptography` is present;
otherwise it falls back to reversible base64 (dev only) so the store still works
in minimal environments. The uri indirection + fingerprint are the invariant.
"""

from __future__ import annotations

import base64
import hashlib

from config.settings import get_settings

_URI_PREFIX = "secret://"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def make_uri(secret_id: str) -> str:
    return f"{_URI_PREFIX}{secret_id}"


def parse_uri(uri: str) -> str:
    if not uri.startswith(_URI_PREFIX):
        raise ValueError(f"not a secret uri: {uri}")
    return uri[len(_URI_PREFIX) :]


def _fernet_key() -> bytes:
    secret = get_settings().session_secret.encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(secret).digest())


def _fernet():
    """Return a Fernet instance, or None when cryptography is unavailable/broken.
    Catches BaseException because a misbuilt cryptography raises a Rust
    PanicException (not an Exception subclass); in that case we use the dev
    base64 fallback so the uri + fingerprint indirection still holds."""
    try:
        from cryptography.fernet import Fernet

        return Fernet(_fernet_key())
    except BaseException:  # noqa: BLE001 - broken/absent cryptography -> dev fallback
        return None


def encrypt(value: str) -> str:
    f = _fernet()
    if f is not None:
        return "f:" + f.encrypt(value.encode("utf-8")).decode("utf-8")
    return "b:" + base64.b64encode(value.encode("utf-8")).decode("utf-8")


def decrypt(token: str) -> str:
    scheme, _, payload = token.partition(":")
    if scheme == "f":
        f = _fernet()
        if f is None:
            raise RuntimeError("cryptography unavailable to decrypt a Fernet secret")
        return f.decrypt(payload.encode("utf-8")).decode("utf-8")
    if scheme == "b":
        return base64.b64decode(payload.encode("utf-8")).decode("utf-8")
    raise ValueError("unknown secret token format")


class SecretStore:
    async def put(self, session, *, tenant_id: str, assessment_id: str, value: str) -> dict:
        from domain.models import Secret

        row = Secret(
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            fingerprint=fingerprint(value),
            ciphertext=encrypt(value),
        )
        session.add(row)
        await session.flush()
        return {"secret_uri": make_uri(str(row.id)), "fingerprint": row.fingerprint}

    async def get(self, session, secret_uri: str) -> str:
        from domain.models import Secret

        row = await session.get(Secret, parse_uri(secret_uri))
        if row is None:
            raise KeyError(secret_uri)
        return decrypt(row.ciphertext)
