"""Machine-readable exports: canonical JSON and SARIF 2.1.0 (§28)."""

from __future__ import annotations

from typing import Any

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}

# Standards mappings for the slice's finding class.
_STANDARDS = {
    "authorization.object_level": {
        "cwe": ["CWE-639", "CWE-284"],
        "owasp_api": "API1:2023 Broken Object Level Authorization (BOLA)",
    }
}


def finding_json(finding: dict, evidence: list[dict] | None = None) -> dict:
    """Canonical finding export with evidence refs + standards mappings."""
    return {
        "id": finding.get("id"),
        "internal_class": finding.get("internal_class"),
        "title": finding.get("title"),
        "validation_state": finding.get("validation_state"),
        "severity_label": finding.get("severity_label"),
        "evidence_profile": finding.get("evidence_profile"),
        "evidence_refs": finding.get("evidence_refs", []),
        "capability_refs": finding.get("capability_refs", []),
        "standards": _STANDARDS.get(finding.get("internal_class", ""), {}),
        "evidence": evidence or [],
    }


def sarif_report(findings: list[dict]) -> dict:
    """SARIF 2.1.0. ruleId = internal_class, level from severity, evidence in
    properties. Chain severity is never emitted as a CVSS score."""
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rule_id = f.get("internal_class", "unknown")
        if rule_id not in rules_by_id:
            std = _STANDARDS.get(rule_id, {})
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "properties": {
                    "cwe": std.get("cwe", []),
                    "owasp": std.get("owasp_api", ""),
                },
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(f.get("severity_label", "informational"), "note"),
                "message": {"text": f.get("title", "") or f.get("summary", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": ep}
                        }
                    }
                    for ep in f.get("affected_endpoints", [])
                ],
                "properties": {
                    "validation_state": f.get("validation_state"),
                    "evidence_refs": f.get("evidence_refs", []),
                    "capability_refs": f.get("capability_refs", []),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ArsGoatia",
                        "informationUri": "https://github.com/eBruno-Sec/MISC/tree/main/arsgoatia",
                        "version": "0.1.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
