"""Reporting (§28). Atomic-finding + attack-chain reports as self-contained HTML,
plus machine-readable JSON and SARIF 2.1.0 exports. All interpolation is escaped
and reproduction blocks are redacted (reused evidence/poc redaction)."""

from reporting.exports import finding_json, sarif_report
from reporting.html import atomic_finding_html, attack_chain_html

__all__ = ["atomic_finding_html", "attack_chain_html", "finding_json", "sarif_report"]
