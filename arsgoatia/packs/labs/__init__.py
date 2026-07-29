"""ArsGoatia lab definitions -- pre-configured vulnerable targets.

A lab definition pins a container image, port, fingerprint data, and
the set of challenges the lab is expected to expose so that the
orchestrator can scope assessments automatically.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LabDefinition:
    lab_id: str
    name: str
    description: str
    target_image: str
    target_port: int
    fingerprint: dict[str, str] = field(default_factory=dict)
    challenges: list[str] = field(default_factory=list)
    lab_only_shortcuts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in lab: JUICE_SHOP_LAB
# ---------------------------------------------------------------------------

JUICE_SHOP_LAB = LabDefinition(
    lab_id="juice_shop",
    name="OWASP Juice Shop",
    description="Intentionally insecure web application for security training",
    target_image="bkimminich/juice-shop",
    target_port=3000,
    fingerprint={
        "server": "Express",
        "x-powered-by": "Express",
        "content-type": "text/html; charset=utf-8",
    },
    challenges=[
        "BOLA on /rest/basket/{id}",
        "Admin section access",
        "SQL injection on login",
    ],
    lab_only_shortcuts=[
        "skip_tls_verification",
        "allow_default_credentials",
        "disable_rate_limiting",
    ],
)
