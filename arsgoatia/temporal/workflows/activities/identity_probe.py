"""Identity-bootstrap pure helpers (no I/O, no Temporal).

Deterministic identity generation and login-response parsing, separated so they
are unit-testable without a worker or a target.
"""

from __future__ import annotations

import hashlib


def default_identities(assessment_id: str, count: int = 2) -> list[dict]:
    """Generate `count` standard-user identities with stable, unique-per-assessment
    credentials. Passwords are deterministic (derived) but assessment-scoped."""
    out = []
    for i in range(count):
        seed = hashlib.sha256(f"{assessment_id}:{i}".encode()).hexdigest()[:16]
        out.append(
            {
                "email": f"ags_user{i}_{seed[:8]}@arsgoatia.test",
                "password": f"Ags!{seed}",
                "privilege_label": "standard_user",
            }
        )
    return out


def parse_login(payload: dict) -> tuple[str | None, str | None]:
    """Extract (token, object_id) from a Juice Shop /rest/user/login response.
    object_id is the user's basket id — the object the IDOR module targets."""
    auth = (payload or {}).get("authentication") or {}
    token = auth.get("token")
    basket_id = auth.get("bid")
    return (str(token) if token else None, str(basket_id) if basket_id is not None else None)
