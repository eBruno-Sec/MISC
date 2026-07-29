"""OWASP Juice Shop lab pack — target configuration for the first vertical slice.

Defines the Juice Shop container target, known endpoints, identity bootstrapping
sequences, and challenge-to-technique mappings for the IDOR slice.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LabEndpoint:
    method: str
    path: str
    description: str
    requires_auth: bool = False
    risk_tier: str = "R1"


@dataclass(frozen=True)
class LabIdentity:
    email: str
    password: str
    register_path: str = "/api/Users"
    login_path: str = "/rest/user/login"


@dataclass(frozen=True)
class LabChallenge:
    name: str
    technique_id: str
    target_path: str
    cwe: str
    description: str


JUICE_SHOP_BASE_URL = "http://juice-shop:3000"
JUICE_SHOP_EXTERNAL_PORT = 42000

KNOWN_ENDPOINTS = [
    LabEndpoint("POST", "/api/Users", "User registration", requires_auth=False),
    LabEndpoint("POST", "/rest/user/login", "User login", requires_auth=False),
    LabEndpoint("GET", "/rest/basket/{id}", "Get basket by ID", requires_auth=True, risk_tier="R2"),
    LabEndpoint("GET", "/api/Products", "List products", requires_auth=False),
    LabEndpoint("GET", "/api/Products/{id}", "Get product by ID", requires_auth=False),
    LabEndpoint("GET", "/rest/products/search", "Search products", requires_auth=False),
    LabEndpoint("GET", "/api/Feedbacks", "List feedbacks", requires_auth=False),
    LabEndpoint("POST", "/api/Feedbacks", "Submit feedback", requires_auth=True),
    LabEndpoint("GET", "/api/Quantitys", "Get quantities", requires_auth=True),
    LabEndpoint("POST", "/rest/basket/{id}/checkout", "Checkout basket", requires_auth=True, risk_tier="R3"),
]

TEST_IDENTITIES = [
    LabIdentity(email="alice-test@juice-sh.op", password="AliceTest123!"),
    LabIdentity(email="bob-test@juice-sh.op", password="BobTest456!"),
]

CHALLENGES = [
    LabChallenge(
        name="View Basket",
        technique_id="web.authz.bola.differential",
        target_path="/rest/basket/{id}",
        cwe="CWE-639",
        description="Access another user's basket via direct object reference",
    ),
    LabChallenge(
        name="View Another User's Shopping Basket",
        technique_id="web.authz.bola.differential",
        target_path="/rest/basket/{id}",
        cwe="CWE-639",
        description="OWASP Juice Shop BOLA challenge — view basket belonging to another user",
    ),
    LabChallenge(
        name="Forged Feedback",
        technique_id="web.authz.bola.mutation",
        target_path="/api/Feedbacks",
        cwe="CWE-639",
        description="Submit feedback as another user via parameter tampering",
    ),
]
