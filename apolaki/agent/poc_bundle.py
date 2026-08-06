"""Per-finding proof-of-concept evidence bundle (Strix absorption, #111).

A self-contained, submission-ready artifact for ONE confirmed finding: identity + taxonomy, the exact
confirming request/response as copy-paste PoC (poc.py), the FALSE-POSITIVE-safety negative control
(#115 proof contract), the evidence-graded impact (report grading), the retest/closure recipe (#117),
remediation, and provenance/versions. One bundle = everything a reviewer needs to BELIEVE, REPRODUCE,
and RE-VERIFY the finding with nothing external required. Pure; secrets are redacted (reuses poc.py).
"""
from __future__ import annotations

import datetime


def _iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _curl(finding: dict, exchanges: list) -> str:
    import poc
    if finding.get("curl"):
        return str(finding["curl"])
    for ex in (exchanges or []):
        if ex.get("url"):
            return poc.to_curl(ex, redact=True)
    tgt = finding.get("target")
    return ("curl -i -sk %s" % tgt) if tgt else ""


def build(finding: dict, exchanges: list = None, *, tool_version: str = "", target: str = "") -> dict:
    """Assemble the self-contained evidence bundle for one finding. Deterministic; pure. Reuses the
    #115 proof contract, the #117 retest recipe, and the report's evidence-graded impact + poc.py PoC."""
    import poc
    import retest
    import report
    import technique_model
    fam = str(finding.get("family") or "").lower()
    contract = technique_model.proof_contract({"vuln_class": fam or str(finding.get("cwe") or ""),
                                               "oracle": str(finding.get("oracle") or "")})
    grade = report.graded_business_impact(finding)
    rplan = retest.plan(finding)
    return {
        "schema": "apolaki.poc-bundle/1",
        "generated_at": _iso(),
        "finding": {
            "id": finding.get("id"), "title": finding.get("title"),
            "severity": finding.get("severity"), "confidence": finding.get("confidence"),
            "family": fam, "cwe": finding.get("cwe"), "owasp": finding.get("owasp"),
            "capec": finding.get("capec"), "cvss": finding.get("cvss"),
            "target": finding.get("target") or target,
        },
        "reproduction": {
            "curl": _curl(finding, exchanges),
            "markdown": poc.finding_markdown(finding, exchanges or [], redact=True),
        },
        "confirmation": {          # how it was kept honest (#115) — the FP-safety contract
            "oracle": str(finding.get("oracle") or ""),
            "negative_control": contract.get("negative_control"),
            "evidence_requirements": contract.get("evidence_requirements"),
            "safety": contract.get("safety"),
            "cleanup": contract.get("cleanup"),
        },
        "impact": grade,           # evidence-graded demonstrated / plausible / unverified
        "retest": rplan,           # #117 recipe to re-verify a fix (OPEN/CLOSED)
        "remediation": str(finding.get("remediation") or ""),
        "provenance": {"tool_version": tool_version or "", "found_by": finding.get("found_by") or "apolaki",
                       "skill_version": "apolaki.poc-bundle/1"},
    }


def build_all(findings: list, exchanges_by_finding: dict = None, *, tool_version: str = "",
              target: str = "") -> list:
    """Bundles for every CONFIRMED finding (candidates/leads are excluded — a PoC bundle asserts proof).
    exchanges_by_finding maps a finding id -> its captured HTTP exchanges."""
    exmap = exchanges_by_finding or {}
    out = []
    for f in findings or []:
        if str(f.get("confidence") or "").lower() != "confirmed":
            continue
        out.append(build(f, exmap.get(f.get("id")) or [], tool_version=tool_version, target=target))
    return out
