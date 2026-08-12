"""Per-finding proof-of-concept evidence bundle (Strix absorption, #111).

A self-contained, submission-ready artifact for ONE confirmed finding: identity + taxonomy, the exact
confirming request/response as copy-paste PoC (poc.py), the FALSE-POSITIVE-safety negative control
(#115 proof contract), the evidence-graded impact (report grading), the retest/closure recipe (#117),
remediation, and provenance/versions. One bundle = everything a reviewer needs to BELIEVE, REPRODUCE,
and RE-VERIFY the finding with nothing external required. Pure; secrets are redacted (reuses poc.py).

The evidence contract is PER PROOF KIND (#123). It used to assume one shape for everything --
baseline, mutation, differential, replay -- so a SOURCE-DERIVED finding (`Cipher.getInstance("DES")`
at a known file and line) shipped a dossier promising "a negative-control request ... does NOT
reproduce the confirming signal (differential measured over a stable baseline)" and requiring
"baseline + mutation request/response retained for deterministic replay". No such experiment exists
for a static call site, so that was not an unproven claim (the defect `837b1f0` fixed on the report)
but an INAPPLICABLE one -- a category error the dossier stated in the present indicative under a key
literally named `confirmation`. `proof_schema.proof_kind` / `control_status` decide the shape;
`report.negative_control_claim` composes the one sentence every surface prints.
"""
from __future__ import annotations

import datetime


def _iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _curl(finding: dict, exchanges: list) -> str:
    """The confirming request as copy-paste curl, or "" when this finding has no request at all.

    The final fallback used to be `curl -i -sk <target>` unconditionally. For the code-assisted lane
    the target is a FILE PATH, so the dossier shipped `curl -i -sk src/main/java/.../Billing.java` --
    a command that cannot run, presented as the reproduction. A source-derived finding is reproduced
    by opening the file at the line (`reproduction.open`), not by a request that was never sent."""
    import poc
    import proof_schema
    if finding.get("curl"):
        return str(finding["curl"])
    for ex in (exchanges or []):
        if ex.get("url"):
            return poc.to_curl(ex, redact=True)
    if proof_schema.proof_kind(finding) == proof_schema.SOURCE_DERIVED:
        return ""
    tgt = finding.get("target")
    return ("curl -i -sk %s" % tgt) if tgt else ""


def source_evidence(finding: dict):
    """The evidence a SOURCE-DERIVED finding actually has, structured. None for any other kind. Pure.

    For a static call site the evidence is not an exchange -- it is the call site: the file, the line,
    the call as the parser resolved it, the rule that matched, and the counter-example that would
    falsify that rule. There is nothing behind it to go and observe, which is precisely why this lane
    is deterministic where HTTP is not (`codereview.py:142`).

    `call_api` / `call_value` / `value_resolved_from` are read when the producer supplies them and
    OMITTED otherwise. `codereview._source_finding` currently folds all three into its prose
    `evidence` string and throws the structured values away (patch 6a in docs/handoff/evidence.md);
    parsing them back out with a regex over a record is how this codebase has been bitten before, so
    the bundle carries the string verbatim and says less rather than guessing.
    """
    import proof_schema
    f = finding or {}
    if proof_schema.proof_kind(f) != proof_schema.SOURCE_DERIVED:
        return None
    out = {
        "file": f.get("target") or "",
        "line": f.get("line"),
        "analysis": str(f.get("analysis") or "static-call-site"),
        "call_site": str(f.get("evidence") or ""),
        "rule": {"family": str(f.get("family") or ""), "cwe": str(f.get("cwe") or ""),
                 "oracle": proof_schema.oracle_of(f)},
        "counter_example": proof_schema.counter_example(f),
        "runtime_observation": ("none required — the defect is definitional at the call site, so "
                                "there is no request, baseline or mutation to record"),
    }
    for key, src in (("call_api", "call_api"), ("call_value", "call_value"),
                     ("value_resolved_from", "value_resolved_from")):
        v = str(f.get(src) or "").strip()
        if v:
            out[key] = v
    return out


def _confirmation(finding: dict, contract: dict, oracle: str) -> dict:
    """The FP-safety block, PER PROOF KIND (#123, Breaker item 1 -- REJECTED twice).

    This block claimed one evidence shape for everything: "a negative-control request ... does NOT
    reproduce the confirming signal (differential measured over a stable baseline)" plus "baseline +
    mutation request/response retained for deterministic replay". For a source-derived finding that
    experiment cannot exist even in principle, so the claim was not merely unproven (the defect
    `837b1f0` fixed) but INAPPLICABLE -- and answering "not recorded" would have been a false claim
    too, because it says the experiment was available and skipped.

    The control sentence itself comes from `report.negative_control_claim` so the dossier and the
    report state one string, not two that drift.
    """
    import proof_schema
    import report
    claim = report.negative_control_claim(finding)
    out = {
        "proof_kind": proof_schema.proof_kind(finding),
        "control_status": claim["status"],
        "oracle": oracle,
        "negative_control": claim["text"],
        "evidence_requirements": list(contract.get("evidence_requirements") or []),
        "safety": contract.get("safety"),
        "cleanup": contract.get("cleanup"),
    }
    if out["proof_kind"] != proof_schema.SOURCE_DERIVED:
        return out
    ce = claim.get("counter_example")
    out["counter_example"] = ce
    reqs = []
    if oracle:
        reqs.append("Oracle satisfied: " + oracle)
    reqs.append("Call site located: file + line, resolved from parsed source rather than a text match.")
    reqs.append("Counter-example rule-checked: "
                + (ce or "the sibling clean call site the same rule must NOT match") + ".")
    reqs.append("NOT APPLICABLE: baseline + mutation request/response replay — no request exists for "
                "a static call site.")
    out["evidence_requirements"] = reqs
    return out


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
    import proof_schema
    fam = str(finding.get("family") or "").lower()
    # Read the oracle through the ONE canonical accessor. This used to read `finding["oracle"]`
    # directly, so every family whose producer spells it `success_oracle` (SCA, the DOM tools, ...)
    # reached the bundle with an empty confirmation oracle — while report.py read only the other
    # spelling. Both spellings are live; `oracle_of` is the single place that knows that.
    _oracle = proof_schema.oracle_of(finding)
    contract = technique_model.proof_contract({"vuln_class": fam or str(finding.get("cwe") or ""),
                                               "oracle": _oracle})
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
        # how it was kept honest (#115) — the FP-safety contract, PER PROOF KIND
        "confirmation": _confirmation(finding, contract, _oracle),
        "impact": grade,           # evidence-graded demonstrated / plausible / unverified
        "attack_path": attack_path(finding, chains),   # what it enables next + the chain(s) it's part of
        "standards": standards(finding),               # CWE/OWASP/CAPEC + ASVS objective(s) + WSTG violated
        "retest": rplan,           # #117 recipe to re-verify a fix (OPEN/CLOSED)
        "fix_priority": remediation.fix_priority(finding),   # Fix Now / Fix If / Strengthen action priority
        "remediation": str(finding.get("remediation") or ""),
        # The LANE travels with the dossier. Without it a reader holding only this JSON cannot tell a
        # SAST row from a DAST row — the one distinction `codereview.py:145` says must never be
        # folded away — and cannot check that the evidence shape matches the lane's claim.
        "provenance": {"tool_version": tool_version or "", "found_by": finding.get("found_by") or "apolaki",
                       "skill_version": "apolaki.poc-bundle/1",
                       "proof_kind": proof_schema.proof_kind(finding),
                       "lane": str(finding.get("lane") or ""),
                       "provenance": str(finding.get("provenance") or "")},
    }
    # SOURCE-DERIVED evidence: the call site IS the evidence. Sits beside `browser_evidence` — same
    # idea, a proof block whose shape matches how the finding was actually established.
    se = source_evidence(finding)
    if se:
        out["source_evidence"] = se
        if se.get("file") and se.get("line") is not None:
            out["reproduction"]["open"] = "%s:%s" % (se["file"], se["line"])
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
        tr = be.get("trace") or {}
        if tr.get("path"):
            # An interactive recording of the confirmed run — the reviewer scrubs the actual exploit
            # rather than reading a description of it.
            out["reproduction"]["trace"] = {"path": tr.get("path"), "viewer": tr.get("viewer"),
                                            "bytes": tr.get("bytes")}
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
