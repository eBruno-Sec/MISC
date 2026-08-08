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


# family -> the capability this finding class unlocks next (the deterministic "attack path" escalation).
_ENABLES = {
    "idor": "read or modify other users' objects; bulk exfiltration by walking ids",
    "bola": "read or modify other users' objects by id",
    "access_control": "reach data or functions beyond the user's authorization",
    "bfla": "invoke privileged functions as a low-privilege user",
    "sqli": "read the database, bypass authentication, or extract credentials",
    "sql_injection": "read the database, bypass authentication, or extract credentials",
    "ssrf": "reach internal services + cloud metadata -> IAM credential theft",
    "xss": "run script in a victim's session; steal tokens or act as the user",
    "stored_xss": "run script in every viewer's session (persistent)",
    "broken_auth": "impersonate other users or bypass authentication",
    "sensitive_exposure": "harvest secrets/credentials for lateral movement",
    "exposure": "harvest exposed secrets/backups/credentials for lateral movement",
    "open_redirect": "phish users or chain into OAuth token theft via a trusted-domain redirect",
    "csrf": "perform state-changing actions as an authenticated victim",
    "rce": "execute code on the server -> full compromise",
    "command_injection": "execute OS commands on the server",
    "xxe": "read server files or pivot via SSRF using external entities",
    "ics_ot": "read industrial process data (control/write frames are NEVER sent by Apolaki)",
    "mass_assignment": "set privileged attributes (e.g. become admin) via extra fields",
}


def _wstg_for_family(fam: str):
    """Best-effort WSTG test id for a finding family, via the technique registry (family -> technique.wstg)."""
    if not fam:
        return None
    try:
        import techniques
        for t in techniques.TECHNIQUES.values():
            if str(t.get("vuln_class", "")).lower() == fam and t.get("wstg"):
                return t.get("wstg")
    except Exception:
        pass
    return None


def standards(finding: dict) -> dict:
    """Every standard this finding VIOLATES — CWE/OWASP/CAPEC (from the finding) + the ASVS objective(s) it
    fails + the WSTG test id. Pure. Only present keys are returned (honest — no fabricated mappings)."""
    import asvs_model
    f = finding or {}
    out = {"cwe": f.get("cwe"), "owasp": f.get("owasp"), "capec": f.get("capec")}
    try:
        viol = asvs_model.map_findings([{**f, "id": f.get("id") or "f"}])
        cid2sum = {o["cid"]: o["summary"] for o in asvs_model.OBJECTIVES}
        if viol:
            out["asvs"] = [{"cid": c, "requirement": cid2sum.get(c)} for c in sorted(viol)]
    except Exception:
        pass
    w = _wstg_for_family(str(f.get("family") or "").lower())
    if w:
        out["wstg"] = w
    return {k: v for k, v in out.items() if v}


def attack_path(finding: dict, chains: list = None) -> dict:
    """What this finding ENABLES next (the deterministic attack path): the multi-step chain(s) it
    participates in + the capability its class unlocks. Pure."""
    f = finding or {}
    fam = str(f.get("family") or "").lower()
    fid = str(f.get("id") or "").lower()
    tgt = str(f.get("target") or "").lower()
    import json as _j
    in_chains = []
    for c in (chains or []):
        try:
            s = _j.dumps(c, default=str).lower()
        except Exception:
            s = str(c).lower()
        if (fid and fid in s) or (tgt and tgt in s) or (fam and fam in s):
            label = (c.get("title") or c.get("name") or (c.get("summary") or "")[:100]) if isinstance(c, dict) else str(c)[:100]
            if label:
                in_chains.append(label)
    return {"enables": _ENABLES.get(fam, "escalate impact within the affected component"),
            "in_chains": in_chains[:3]}


def build(finding: dict, exchanges: list = None, *, tool_version: str = "", target: str = "",
          chains: list = None) -> dict:
    """Assemble the self-contained evidence bundle for one finding. Deterministic; pure. Reuses the
    #115 proof contract, the #117 retest recipe, and the report's evidence-graded impact + poc.py PoC."""
    import poc
    import retest
    import report
    import remediation
    import technique_model
    fam = str(finding.get("family") or "").lower()
    contract = technique_model.proof_contract({"vuln_class": fam or str(finding.get("cwe") or ""),
                                               "oracle": str(finding.get("oracle") or "")})
    grade = report.graded_business_impact(finding)
    rplan = retest.plan(finding)
    out = {
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
        "attack_path": attack_path(finding, chains),   # what it enables next + the chain(s) it's part of
        "standards": standards(finding),               # CWE/OWASP/CAPEC + ASVS objective(s) + WSTG violated
        "retest": rplan,           # #117 recipe to re-verify a fix (OPEN/CLOSED)
        "fix_priority": remediation.fix_priority(finding),   # Fix Now / Fix If / Strengthen action priority
        "remediation": str(finding.get("remediation") or ""),
        "provenance": {"tool_version": tool_version or "", "found_by": finding.get("found_by") or "apolaki",
                       "skill_version": "apolaki.poc-bundle/1"},
    }
    # BROWSER-DERIVED evidence (#124): when the Browser Intelligence Engine confirmed this finding, the
    # bundle carries proof frozen from the ACTUAL run — before/after screenshots, the exact runtime request,
    # the mutated request, every negative control, and a replay script. Not reconstructed after the fact.
    be = finding.get("browser_evidence")
    if isinstance(be, dict) and be:
        out["browser_evidence"] = be
        out["reproduction"]["steps"] = list(be.get("reproduction_steps") or [])
        out["reproduction"]["replay_script"] = be.get("replay_script") or ""
        shots = be.get("screenshots") or {}
        out["reproduction"]["screenshots"] = sorted(shots) if isinstance(shots, dict) else []
    return out


def build_all(findings: list, exchanges_by_finding: dict = None, *, tool_version: str = "",
              target: str = "", chains: list = None) -> list:
    """Bundles for every CONFIRMED finding (candidates/leads are excluded — a PoC bundle asserts proof).
    exchanges_by_finding maps a finding id -> its captured HTTP exchanges; chains supplies the attack path."""
    exmap = exchanges_by_finding or {}
    out = []
    for f in findings or []:
        if str(f.get("confidence") or "").lower() != "confirmed":
            continue
        out.append(build(f, exmap.get(f.get("id")) or [], tool_version=tool_version, target=target,
                         chains=chains))
    return out
