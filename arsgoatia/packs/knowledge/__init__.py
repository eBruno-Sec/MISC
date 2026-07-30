"""ArsGoatia knowledge packs -- CWE and taxonomy mappings.

Maps CWE entries to OWASP categories and ArsGoatia technique IDs
so that the reasoning engine can link findings to known weakness
taxonomies.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CWEMapping:
    cwe_id: int
    name: str
    description: str
    owasp_categories: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()


_CWE_REGISTRY: dict[int, CWEMapping] = {}


def _register(mapping: CWEMapping) -> CWEMapping:
    _CWE_REGISTRY[mapping.cwe_id] = mapping
    return mapping


def get_cwe(cwe_id: int) -> CWEMapping | None:
    """Return a CWE mapping by ID, or ``None`` if unknown."""
    return _CWE_REGISTRY.get(cwe_id)


def list_cwes() -> list[CWEMapping]:
    """Return all registered CWE mappings sorted by cwe_id."""
    return sorted(_CWE_REGISTRY.values(), key=lambda m: m.cwe_id)


def cwes_for_technique(technique_id: str) -> list[CWEMapping]:
    """Return all CWE mappings whose techniques include *technique_id*."""
    return [m for m in _CWE_REGISTRY.values() if technique_id in m.techniques]


# ---------------------------------------------------------------------------
# Built-in CWE mappings
# ---------------------------------------------------------------------------

CWE_79 = _register(
    CWEMapping(
        cwe_id=79,
        name="Cross-site Scripting (XSS)",
        description="Improper neutralization of input during web page generation",
        owasp_categories=("A03:2021-Injection",),
        techniques=("web.injection.xss.reflected", "web.injection.xss.stored"),
    )
)

CWE_89 = _register(
    CWEMapping(
        cwe_id=89,
        name="SQL Injection",
        description="Improper neutralization of special elements used in an SQL command",
        owasp_categories=("A03:2021-Injection",),
        techniques=("web.injection.sqli.classic", "web.injection.sqli.blind"),
    )
)

CWE_284 = _register(
    CWEMapping(
        cwe_id=284,
        name="Improper Access Control",
        description="Software does not restrict or incorrectly restricts access to a resource",
        owasp_categories=("A01:2021-Broken Access Control",),
        techniques=("web.authz.bola.differential", "web.authz.privilege_escalation"),
    )
)

CWE_287 = _register(
    CWEMapping(
        cwe_id=287,
        name="Improper Authentication",
        description="Actor claims to have a given identity but verification is missing or flawed",
        owasp_categories=("A07:2021-Identification and Authentication Failures",),
        techniques=("web.authn.bypass.default_credentials", "web.authn.bypass.token_manipulation"),
    )
)

CWE_639 = _register(
    CWEMapping(
        cwe_id=639,
        name="Authorization Bypass Through User-Controlled Key",
        description="Broken object-level authorization (BOLA/IDOR)",
        owasp_categories=("A01:2021-Broken Access Control",),
        techniques=("web.authz.bola.differential",),
    )
)

CWE_862 = _register(
    CWEMapping(
        cwe_id=862,
        name="Missing Authorization",
        description=(
            "Software does not perform an authorization check for an actor's access to a resource"
        ),
        owasp_categories=("A01:2021-Broken Access Control",),
        techniques=("web.authz.missing_function_level",),
    )
)
