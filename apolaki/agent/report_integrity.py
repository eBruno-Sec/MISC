"""
Report metric-consistency validator — Apolaki's truth-first guardrail.

A pure, deterministic pass over the assembled report data that catches the exact
class of self-contradiction that makes an automated pentest report untrustworthy
(and that competing tools ship): headline metrics that disagree with the findings
beneath them, and confirmed/unconfirmed statuses that conflict between the summary
and the detail.

Real contradictions observed in a competitor report on the SAME target, each of
which a check here catches:
  • "Confirmed Exploits: 0" while 14 findings are marked CONFIRMED.
  • "Avg CVSS: 0" while the headline risk is 97/100 Critical.
  • "Known CVEs: 0" while AngularJS CVEs are listed in the findings.
  • "Technologies: 0" while AngularJS 1.7.7 is detected.
  • Reflected XSS marked "confirmed" in the summary but "UNCONFIRMED" in the detail.
  • Risk labelled Critical with 0 critical findings and no scoring formula shown.

Apolaki's own reports are consistent by construction, so on real Apolaki data this
returns a clean result — the value is (1) a visible integrity guarantee on every
report, (2) regression protection if the report layer ever drifts, and (3) it can
gate export on an error-level contradiction. Checks whose backing metric is absent
from a given report are skipped (never invented), so this only ever fires on a
genuine metric-vs-content mismatch.

Pure/deterministic and unit-tested; no I/O.
"""
from __future__ import annotations

import re

# must mirror report.risk_score's weights so we can independently recompute the
# score and prove it derives from CONFIRMED findings only (leads never inflate it)
_SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "informational": 1, "info": 1}
_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


def _title(x: dict) -> str:
    return (x or {}).get("title") or (x or {}).get("name") or "(untitled)"


def _sev(x: dict) -> str:
    return ((x or {}).get("severity") or "info").lower()


def _has_cve(f: dict) -> bool:
    blob = " ".join(str(f.get(k, "")) for k in ("cve", "cwe", "title", "description", "evidence"))
    return bool(_CVE_RE.search(blob)) or bool(f.get("cve"))


def _recompute_score(findings: list) -> int:
    return min(100, sum(_SEV_WEIGHT.get(_sev(f), 1) for f in (findings or [])))


def cvss_version_of(finding: dict):
    """Which CVSS version a finding carries a VALID vector for: '4.0', '3.1', or None. Report integrity
    ACCEPTS EITHER version (Codex Tier-2 #6) — a high/critical finding scored with v3.1 or v4 is both fine."""
    f = finding or {}
    v40 = str(f.get("cvss40_vector") or "")
    if v40:
        try:
            import cvss4
            if cvss4.is_valid(v40):
                return "4.0"
        except Exception:
            pass
    v31 = str(f.get("cvss31_vector") or f.get("cvss_vector") or "")
    if "CVSS:3." in v31:
        return "3.1"
    return None


def chain_cvss_violations(chains: list) -> list:
    """Names of attack chains that illegally carry a CVSS vector/score. CVSS scores ATOMIC vulnerabilities
    only; a chain's severity is Apolaki impact-path severity, never a CVSS vector (Codex Tier-2 #6)."""
    out = []
    for c in (chains or []):
        if any(str((c or {}).get(k) or "").strip()
               for k in ("cvss", "cvss_vector", "cvss31_vector", "cvss40_vector", "cvss_score")):
            out.append((c or {}).get("host") or (c or {}).get("narrative") or "(chain)")
    return out


def check_report_consistency(findings: list, leads: list, risk: dict = None,
                             counts: dict = None, attack_surface: dict = None,
                             tool_ledger: dict = None, chains: list = None) -> dict:
    """Validate the assembled report for metric/status contradictions.

    Returns {"ok": bool, "checks_run": int, "issues": [ {level, check, detail} ]}.
    `ok` is False only when an ERROR-level contradiction exists (a caller may block
    export on that); WARN-level items are advisory. Empty issues = clean report."""
    findings = findings or []
    leads = leads or []
    risk = risk or {}
    counts = counts or {}
    issues, checks = [], 0

    def add(level, check, detail):
        issues.append({"level": level, "check": check, "detail": detail})

    # 1) Confirmed-list integrity: every item in `findings` must actually be confirmed,
    #    and no `lead` may be marked confirmed — this catches the summary-vs-detail
    #    status conflict (a finding "confirmed" up top but "unconfirmed" in the table).
    checks += 1
    for f in findings:
        conf = (f.get("confidence") or "confirmed").lower()
        if conf not in ("confirmed", ""):
            add("error", "confirmed-status-conflict",
                f"'{_title(f)}' is in the CONFIRMED findings but its confidence is '{conf}'.")
    for l in leads:
        if (l.get("confidence") or "candidate").lower() == "confirmed":
            add("error", "confirmed-status-conflict",
                f"'{_title(l)}' is in the UNCONFIRMED leads but marked 'confirmed' — status conflict.")

    # 2) Count integrity: the severity distribution must total the confirmed count.
    checks += 1
    dist_total = sum(int(counts.get(k, 0)) for k in
                     ("critical", "high", "medium", "low", "informational", "info"))
    if counts and dist_total != len(findings):
        add("error", "count-mismatch",
            f"Severity distribution totals {dist_total} but there are {len(findings)} confirmed findings.")

    # 3) Risk-label integrity: the posture label must never exceed the top confirmed
    #    severity (four highs are not "Critical" unless a Critical was confirmed).
    checks += 1
    top = max((_RANK.get(_sev(f), 0) for f in findings), default=0)
    lbl = (risk.get("label") or "").lower()
    if lbl in _RANK and _RANK[lbl] > top:
        add("error", "risk-label-exceeds-evidence",
            f"Risk labelled '{risk.get('label')}' but the highest confirmed severity is "
            f"'{_top_name(top)}' — the label overstates the evidence.")
    # a Critical/High headline needs either a matching finding or a shown formula note
    checks += 1
    if lbl == "critical" and int(counts.get("critical", 0)) == 0 and not (risk.get("note") or "").strip():
        add("warn", "risk-label-unexplained",
            "Risk label 'Critical' with 0 critical findings and no scoring-formula note to explain it.")

    # 4) Risk-score source: recomputing from CONFIRMED findings must reproduce the
    #    reported score. A mismatch means unconfirmed leads leaked into the score —
    #    the single most important truth-first invariant.
    checks += 1
    if risk.get("score") is not None:
        recomputed = _recompute_score(findings)
        if int(risk["score"]) != recomputed:
            add("error", "risk-score-source",
                f"Reported risk score {risk.get('score')} does not equal the score recomputed "
                f"from confirmed findings only ({recomputed}); unconfirmed leads may have inflated it.")

    # 5) CVE metric vs content: if the report carries a Known-CVEs counter AND it is 0
    #    while findings cite CVEs, that is the competitor's "Known CVEs: 0 / Angular
    #    CVEs listed" bug. Only runs when such a counter is actually present.
    checks += 1
    known_cves = (attack_surface or {}).get("known_cves")
    cve_findings = [f for f in findings if _has_cve(f)]
    if known_cves is not None and int(known_cves) == 0 and cve_findings:
        add("error", "cve-count-mismatch",
            f"{len(cve_findings)} finding(s) cite CVE identifiers but Known CVEs = 0.")

    # 6) Technology metric vs content: a "Technologies: 0" counter alongside detected
    #    technologies is the competitor's "Technologies: 0 / Angular 1.7.7" bug.
    checks += 1
    tech_count = (attack_surface or {}).get("technologies_count")
    techs = (attack_surface or {}).get("technologies")
    detected = tech_count if tech_count is not None else (len(techs) if isinstance(techs, list) else None)
    tech_in_findings = any("angular" in _title(f).lower() or "component" in _title(f).lower()
                           or f.get("family") == "vulnerable_component" for f in findings)
    if detected == 0 and tech_in_findings:
        add("error", "technology-count-mismatch",
            "Technologies counter is 0 but a technology/version-specific finding is present.")

    # 7) Confirmed-exploit counter vs confirmed findings: if a report exposes a
    #    "confirmed exploits/findings" counter, it must not be 0 while confirmed
    #    findings exist (unless a note explains a stricter definition). Only runs
    #    when such a counter is present.
    checks += 1
    conf_counter = (tool_ledger or {}).get("confirmed_exploits")
    if conf_counter is not None and int(conf_counter) == 0 and findings and not (tool_ledger or {}).get("confirmed_note"):
        add("error", "confirmed-exploit-counter-mismatch",
            f"Confirmed-exploits counter is 0 but {len(findings)} confirmed finding(s) are reported.")

    # 8) Tool-ledger vs its own findings: a tool row that reports findings > 0 must not
    #    carry a note claiming "0 confirmed" / "No X confirmed". This is the exact
    #    contradiction the user flagged — run_sqli/run_xxe reading "0 confirmed" beside a
    #    confirmed finding because the ledger kept an earlier 0-result call's note.
    checks += 1
    _zero_re = re.compile(r"(?:\bno\b[\w\s/]*\bconfirmed\b|\b0\s+confirmed\b)", re.I)
    for t in ((tool_ledger or {}).get("tools") or []):
        if int(t.get("findings") or 0) > 0 and _zero_re.search(str(t.get("note") or "")):
            add("error", "ledger-note-contradiction",
                f"Tool '{t.get('tool')}' reports {t.get('findings')} finding(s) but its note says "
                f"\"{t.get('note')}\" — the ledger note contradicts the tool's own findings.")

    # N) CVSS is for ATOMIC findings only — an attack chain must never carry a CVSS vector/score.
    checks += 1
    for name in chain_cvss_violations(chains):
        add("error", "chain-level-cvss",
            f"Attack chain '{name}' carries a CVSS vector/score — CVSS scores atomic vulnerabilities only; "
            f"a chain's severity is Apolaki impact-path severity, not a CVSS vector.")

    return {"ok": not any(i["level"] == "error" for i in issues),
            "checks_run": checks, "issues": issues}


def _top_name(rank: int) -> str:
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "none"}.get(rank, "none")


def summary_line(result: dict) -> str:
    """One-line human summary for the report — the visible integrity guarantee."""
    result = result or {}
    errs = [i for i in result.get("issues", []) if i.get("level") == "error"]
    warns = [i for i in result.get("issues", []) if i.get("level") == "warn"]
    n = result.get("checks_run", 0)
    if not errs and not warns:
        # No leading "Consistent —": both call sites (HTML + Markdown) already render a
        # "Consistent" / "Contradictions found" status label before this line, so
        # prefixing it here produced the doubled "Consistent — Consistent —".
        return f"{n} automated consistency checks passed; no metric or status contradictions."
    parts = []
    if errs:
        parts.append(f"{len(errs)} contradiction{'s' if len(errs) != 1 else ''}")
    if warns:
        parts.append(f"{len(warns)} advisory")
    return f"{n} checks run — {', '.join(parts)} (see below)."
