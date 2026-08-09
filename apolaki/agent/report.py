"""
Report generation: HackerOne/Bugcrowd Markdown (original), a light-default
standalone HTML report (client-ready, ink-safe print, one-click dark toggle,
every field HTML-escaped), plus CSV and native JSON data package. All
deterministic; no network.
"""
import csv
import html as _html
import re
import io
import json
from datetime import datetime, timezone

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
SEV_COLORS = {
    "critical": "#ff3d6b", "high": "#fb923c", "medium": "#f59e0b",
    "low": "#00e5ff", "informational": "#6a8a9a", "info": "#6a8a9a",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _counts(findings: list) -> dict:
    counts = {}
    for f in findings:
        s = (f.get("severity") or "informational").lower()
        counts[s] = counts.get(s, 0) + 1
    return counts


# ── Markdown (original H1/BC format, enhanced) ───────────────────
def _status_note(status: str) -> str:
    """A one-line run-outcome note for a mission that did not finish cleanly, so a
    report never silently reads 'no vulnerabilities' for an aborted run."""
    s = (status or "").lower()
    if s in ("failed", "error"):
        return ("> ⚠ **Run status: FAILED.** This assessment did not complete (commonly a provider "
                "quota/rate-limit or network error, not a target result). Coverage below is partial — re-run to finish.")
    if s in ("stopped", "stopping"):
        return "> ⏹ **Run status: STOPPED by operator.** Coverage below is partial."
    if s == "interrupted":
        return "> ⚠ **Run status: INTERRUPTED.** The run was cut short; coverage below is partial."
    if s == "running":
        return "> ⏳ **Run status: RUNNING.** This report is a snapshot of an in-progress assessment."
    return ""


def _exec_note(execution: dict) -> str:
    """One line stating how the mission ran (strategy + AI usage)."""
    if not execution:
        return ""
    strat = (execution.get("strategy") or "").replace("_", "-")
    note = (execution.get("ai_note") or "").strip()
    label = {"deterministic": "Deterministic (no AI)", "low-ai": "Low-AI",
             "agentic": "Agentic", "manual": "Manual"}.get(strat, strat or "")
    parts = [p for p in (f"**Execution:** {label}" if label else "", note) if p]
    return " — ".join(parts)


def _leads_md(leads: list) -> str:
    if not leads:
        return ""
    lines = ["", "## Unconfirmed Leads", "",
             "_Signals worth manual verification — NOT confirmed vulnerabilities. "
             "Confirm before reporting to a program._", "",
             "| Severity | Confidence | Lead | Target |", "|---|---|---|---|"]
    for l in sorted(leads, key=lambda x: SEV_ORDER.get((x.get("severity") or "info").lower(), 5)):
        lines.append(f"| {(l.get('severity') or 'info').capitalize()} | {l.get('confidence','candidate')} "
                     f"| {l.get('title','')} | `{l.get('target','')}` |")
    return "\n".join(lines) + "\n"


def _ot_context_md(finding: dict) -> list:
    """OT/ICS context for an ICS finding (Codex Tier-3 #12): asset role + Purdue zone + process impact framed
    as POTENTIAL until an operator confirms the process context. Nothing rendered for non-ICS findings."""
    fam = str((finding or {}).get("family") or "").lower()
    if fam not in ("ics_ot", "ics", "ot"):
        return []
    try:
        import ot_context
    except Exception:
        return []
    ctx = ot_context.ot_asset_context(finding)
    imp = ot_context.process_impact(ctx)
    return ["**OT/ICS Context**", "",
            "- Asset role: %s — %s" % (ctx["role"], ctx["zone"]),
            "- Process criticality: %s (operator context %s)" % (ctx["criticality"], ctx["process_context"]),
            "- %s" % imp["statement"], ""]


def _scope_exclusion_md(scope: dict) -> list:
    """Record vulnerability classes the operator excluded (#34). Empty when nothing was excluded.

    Delegates to `scan_scope.report_block` so the wording an operator saw in the UI preview is the
    wording that reaches the report — two phrasings of the same decision is how a client and a tester end
    up disagreeing about what was tested."""
    cats = (scope or {}).get("exclude_categories") or []
    if not cats:
        return []
    try:
        import scan_scope as ss
        import techniques as T
        return ss.report_block(cats, [T.get(t["id"]) for t in T.list_techniques()])
    except Exception:
        return ["**Excluded from this assessment (operator scoping):** %s — not tested."
                % ", ".join(str(c) for c in cats), ""]


def _remediation_depth_md(finding: dict) -> list:
    """Design-level remediation for a finding (T5, BSRS Ch.5/6/8/9) as report lines.

    The tactical fix says how to close the defect. This says what removes the class, what bounds the
    damage when the fix fails, and — the part nothing else in the platform answers — what to do assuming
    the finding was already exploited. Family resolution goes through `_family_of`, so a finding carrying
    only a CWE still resolves. A family with no substantive guidance renders NOTHING; a padded
    remediation section is the failure mode this avoids."""
    try:
        import remediation_depth as _rd
        md = _rd.markdown(finding, family=_family_of(finding))
    except Exception:
        return []
    return md.split("\n") if md else []


def _remediation_depth_html(finding: dict, esc) -> str:
    """The T5 design-level block for the HTML report. `esc` is the caller's escaper, passed in so this
    cannot accidentally emit unescaped text. Empty string when the family has no substantive guidance."""
    try:
        import remediation_depth as _rd
        d = _rd.depth_for(finding, family=_family_of(finding))
    except Exception:
        return ""
    if not d:
        return ""
    rows = [("Remove the class", "least privilege / by construction", d["structural"]),
            ("Bound the blast radius", "if the fix is bypassed", d["blast_radius"]),
            ("Assume it was already exploited", "recovery posture", d["recovery"]),
            ("Verify the fix", "what a real check looks like", d["verify"])]
    return ("<h4>Design-level remediation</h4>"
            "<p class='sub'>The tactical fix closes this instance. These close the class, bound the "
            "damage when it recurs, and state what to do on the assumption it was already used.</p><ul>"
            + "".join("<li><b>%s</b> <span class='sub'>(%s)</span><br>%s</li>"
                      % (esc(t), esc(s), esc(b)) for t, s, b in rows)
            + "</ul>")


def _defense_controls_md(finding: dict) -> list:
    """Curated defensive-control mapping for a finding (Codex Tier-1 #3): the structured complement to the
    remediation line — each control + the attacker CAPABILITY it reduces. Honest: curated, not official
    D3FEND ids. Unknown family -> nothing rendered (no fabricated control)."""
    try:
        import defense_mapping
    except Exception:
        return []
    ctrls = defense_mapping.controls_for(finding)
    if not ctrls:
        return []
    out = ["**Defensive Controls** _(curated mapping — reduces attacker capability)_", ""]
    for c in ctrls:
        out.append("- **%s** → reduces: %s" % (c["name"], ", ".join(c["reduces"])))
    out.append("")
    return out


def business_logic_view(findings: list, leads: list) -> dict:
    """Headline summary of BUSINESS-LOGIC testing — the workflows probed, the abuse-test categories generated,
    and the outcomes (confirmed vs hypothesis-needs-verification). Business-logic flaws (double-spend, negative
    amounts, skipped/out-of-order steps) are what automated scanners CAN'T derive; Apolaki generates them from
    the workflow STRUCTURE (bizlogic.py). Pure — reads the business_logic/race signals already in the report."""
    import re
    fams = {"business_logic", "race"}
    conf = [f for f in (findings or []) if str(f.get("family") or "").lower() in fams
            and str(f.get("confidence") or "").lower() == "confirmed"]
    hyp = [x for x in (leads or []) if str(x.get("family") or "").lower() in fams]
    flows, cats = set(), set()
    for item in conf + hyp:
        title = str(item.get("title") or "")
        m = re.search(r"\(([^)]+)\)", title)                 # e.g. "(Checkout / order placement)"
        if m:
            flows.add(m.group(1).strip())
        if "—" in title:
            c = title.rsplit("—", 1)[-1].strip()
            if c:
                cats.add(c)
    return {
        "tested": bool(conf or hyp),
        "workflows": sorted(flows),
        "abuse_categories": sorted(cats),
        "confirmed": len(conf),
        "hypotheses_to_verify": len(hyp),
        "note": ("Business-logic flaws — double-spend / replay, negative amounts or quantities, skipped or "
                 "out-of-order steps — are what a human consultant tries but a scanner can't derive. Apolaki "
                 "generates these tests deterministically from the target's workflow structure."),
    }


def _engines_from_ledger(tool_ledger: dict) -> set:
    """The engine/tool names that actually RAN, from the tool_ledger. The ledger is structured
    {tools:[{tool,status,calls,...}], zap_status, authenticated, strategy, ai_calls} — the ran engines live
    under ['tools'] as {tool: name} rows, NOT the top-level keys. Reading the top-level keys (the prior bug)
    made ASVS objective coverage ALWAYS report 0 verified because no engine name ever matched."""
    tl = tool_ledger or {}
    tools = tl.get("tools")
    if isinstance(tools, list):
        return {str(t.get("tool") or t.get("name")) for t in tools
                if isinstance(t, dict) and (t.get("tool") or t.get("name"))}
    if isinstance(tools, dict):
        return set(tools.keys())
    return {k for k in tl.keys() if k not in ("tools", "zap_status", "authenticated", "strategy", "ai_calls")}


def coverage_rollup(findings: list, tool_ledger: dict, candidate_validation: dict = None) -> dict:
    """A single, honest COVERAGE view (competitor-inspired) rolling the ASVS objective model + the WSTG
    catalog + the candidate-validation ledger into the buckets a reader actually wants: of the security
    PROPERTIES Apolaki models, how many were confirmed-safe / found-vulnerable / inconclusive / blocked /
    not-tested. Pure — reuses asvs_model.assess (verified=safe, failed=vuln, attempted=inconclusive,
    blocked=safety/prereq, not_tested+not_applicable=not-tested) and wstg_catalog.coverage. Truth-first: this
    is a CURATED-PARTIAL model, never a full-coverage claim."""
    out = {"properties": {}, "wstg": {}, "candidates": {}, "model": "curated_partial"}
    try:
        import asvs_model
        a = asvs_model.assess(findings or [], attempted_engines=_engines_from_ledger(tool_ledger))
        t = a["tally"]
        total = a["total_objectives"]
        out["properties"] = {
            "confirmed_safe": t.get("verified", 0),
            "vulnerable": t.get("failed", 0),
            "inconclusive": t.get("attempted", 0),
            "blocked": t.get("blocked", 0),
            "not_tested": t.get("not_tested", 0) + t.get("not_applicable", 0),
            "total": total,
            "tested_pct": round(100.0 * (t.get("verified", 0) + t.get("failed", 0) + t.get("attempted", 0))
                                / total, 1) if total else 0.0,
        }
    except Exception:
        pass
    try:
        import wstg_catalog
        w = wstg_catalog.coverage()["tally"]
        out["wstg"] = {"tested": w.get("full", 0) + w.get("partial", 0), "full": w.get("full", 0),
                       "partial": w.get("partial", 0), "not_tested": w.get("none", 0),
                       "excluded": w.get("excluded", 0), "total": 109}
    except Exception:
        pass
    cv = candidate_validation or {}
    rows = cv.get("candidates") or cv.get("rows") or []
    if rows:
        b = {"confirmed": 0, "dismissed": 0, "blocked": 0, "unsupported": 0}
        for r in rows:
            st = str((r or {}).get("state") or (r or {}).get("status") or "").lower()
            for k in b:
                if k in st:
                    b[k] += 1
        out["candidates"] = {**b, "total": len(rows)}
    return out


def _asvs_md(findings: list, tool_ledger: dict) -> list:
    """Curated-partial ASVS-5 objective coverage for the report: which security PROPERTIES were verified /
    failed / blocked / not tested this mission. Findings violate objectives; a clean run of an objective's
    engine verifies it (negative-control discipline). The engines that ran are the tool-ledger keys. HONEST:
    this is never a full-ASVS claim (see the rendered disclaimer)."""
    try:
        import asvs_model
    except Exception:
        return []
    a = asvs_model.assess(findings or [], attempted_engines=_engines_from_ledger(tool_ledger))
    t = a["tally"]
    out = ["", "## ASVS Objective Coverage", "", "_%s_" % a["disclaimer"], "",
           "| Status | Count |", "| --- | --- |",
           "| Verified | %d |" % t["verified"], "| Failed (finding violates) | %d |" % t["failed"],
           "| Attempted (inconclusive) | %d |" % t["attempted"],
           "| Blocked (safety-excluded) | %d |" % t["blocked"], "| Not tested | %d |" % t["not_tested"], ""]
    failed = [o for o in a["objectives"] if o["status"] == "failed"]
    if failed:
        out += ["**Failed objectives — a finding violates the verification property:**", ""]
        for o in failed:
            ids = o["finding_ids"]
            shown = ", ".join(ids[:6]) + (" …+%d more" % (len(ids) - 6) if len(ids) > 6 else "")
            out.append("- `%s` (%s) %s _(%d findings: %s)_" % (o["cid"], o["chapter"], o["requirement"],
                                                               len(ids), shown))
        out.append("")
    return out


def generate_report(program: str, findings: list, scope: dict,
                     coverage: dict = None, chains: list = None, status: str = None,
                     ai_summary: str = None, execution: dict = None, leads: list = None,
                     delta: dict = None, tool_ledger: dict = None, intel: dict = None,
                     orchestration: dict = None) -> str:
    now = _now()
    findings = sanitize_finding_urls(findings)   # collapse any duplicated-host URL from prior-scan memory
    findings = _with_capec(findings)
    delta_block = "\n".join(_delta_lines(delta, findings))
    ledger_block = "\n".join(_ledger_md(tool_ledger))
    status_banner = _status_note(status)          # only failed/stopped/interrupted
    exec_note = _exec_note(execution)             # strategy + AI usage (always for det/low-AI)
    banner = "\n\n".join(b for b in (status_banner, exec_note) if b)
    ai_block = (f"## Executive Summary\n\n{ai_summary.strip()}\n\n" if (ai_summary or "").strip() else "")
    leads_md = _leads_md(leads)
    if not findings:
        # "ended early" only when the STATUS says so — not merely because an
        # execution note is present (which it always is for deterministic/low-AI).
        tail = " before the run ended early." if status_banner else " during this engagement."
        # A no-findings report is exactly where next-best-action matters most: hand the operator the
        # deterministic planner's ordered path to keep testing rather than a dead-end "nothing found".
        nb_block = ""
        _nb = (orchestration or {}).get("next_best") or []
        if _nb:
            _rows = "\n".join("- **%s** _(%s)_%s%s" % (a.get("id", ""), a.get("family", ""),
                              ((" — " + (a.get("action") or a.get("oracle") or "")[:90])
                               if (a.get("action") or a.get("oracle")) else ""),
                              (("  \n  ↳ filter-bypass: " + ", ".join("`%s`" % v for v in (a.get("bypass_ladder") or [])[:3]))
                               if a.get("bypass_ladder") else "")) for a in _nb[:6])
            nb_block = ("\n\n## Recommended Next Actions\n\n_Deterministic, evidence-driven planner "
                        "(precondition-gated, KEV-ranked) — where to keep testing next:_\n\n" + _rows + "\n")
        return (
            f"# Security Assessment Report: {program}\n\n"
            + (banner + "\n\n" if banner else "")
            + f"**Date:** {now}\n"
            f"**Scope:** {', '.join(scope.get('in_scope', []))}\n\n"
            + ai_block
            + "No confirmed vulnerabilities were recorded" + tail + "\n"
            + leads_md
            + nb_block
            + (("\n" + delta_block) if delta_block else "")
            + (("\n" + ledger_block) if ledger_block else "")
        )

    findings = sorted(findings, key=lambda f: SEV_ORDER.get((f.get("severity") or "informational").lower(), 5))
    counts = _counts(findings)

    lines = [
        f"# Security Assessment Report: {program}", "",
    ]
    if banner:
        lines += [banner, ""]
    lines += [
        f"**Date:** {now}",
        f"**Scope:** {', '.join(scope.get('in_scope', []))}",
        f"**Total Findings:** {len(findings)}", "",
    ]
    # Operator scoping (#34) goes NEAR THE TOP, not in an appendix. A reader who skims the summary and
    # sees no injection findings must learn on the same screen that injection was never tested — an
    # excluded class reads as a clean one otherwise, which is the most consequential misreading a
    # pentest report can invite.
    lines += _scope_exclusion_md(scope)
    if ai_block:
        lines += [ai_block.rstrip(), ""]
    lines += [
        "## Summary", "",
        "| Severity | Count |", "|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "informational", "info"]:
        if sev in counts:
            lines.append(f"| {sev.capitalize()} | {counts[sev]} |")

    if coverage:
        lines += ["", "## Assessment Coverage", ""]
        for k, v in coverage.items():
            lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")

    lines += _asvs_md(findings, tool_ledger)

    lines += ["", "---", "", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity", "informational")).upper()
        lines += [
            f"### Finding {i}: {f.get('title', 'Untitled')}", "",
            "**Summary**", "", f.get("description", ""), "",
            f"**Severity:** {sev}",
            f"**Target:** `{f.get('target', '')}`",
        ]
        _cv = estimated_cvss(f)
        _cvss_line = (f"{_cv[0]}{' (est.)' if _cv[2] else ''}" + (f" {_cv[1]}" if _cv[1] else "")) if _cv else "N/A"
        lines += [f"**CVSS:** {_cvss_line}", f"**CWE:** {f.get('cwe', 'N/A')}"]
        _v4vec = f.get("cvss40_vector")                # v4 stored INDEPENDENTLY of v3.1 (Codex Tier-2 #6)
        if _v4vec:
            try:
                import cvss4 as _c4
                _b4 = _c4.base_score(_v4vec)
                lines.append("**CVSS v4.0 (est.):** %s %s `%s` — %s"
                             % (_b4["base_score"], _b4["base_severity"].upper(), _b4["vector"], _b4["nomenclature"]))
            except Exception:
                pass
        if f.get("capec"):
            lines.append(f"**CAPEC:** {f['capec']}")
        if f.get("owasp"):
            lines.append(f"**OWASP:** {f['owasp']}")
        _prov = proof_provenance(f)
        if _prov:
            lines.append(f"**Tool & settings:** `{_prov}`")
        _bi = business_impact(f)
        if _bi:
            lines += ["", "**Why This Matters (plain English)**", "",
                      f"_What it is:_ {_bi[0]}", "", f"_If left unpatched:_ {_bi[1]}", ""]
        lines += ["", "**Steps to Reproduce**", ""]
        _rsteps = f.get("reproduction_steps") or ["Send the reproduction command below.",
                                                  "Confirm the response matches the evidence.",
                                                  "Compare with a benign baseline."]
        for j, step in enumerate(_rsteps, 1):
            lines.append(f"{j}. {step}")
        _curl = finding_curl(f)
        if _curl:
            lines += ["", "**Reproduction (copy-paste)**", "", "```bash", _curl, "```", ""]
        _impact = str(f.get("impact") or "").strip() or (_bi[1] if _bi else
                  "Impact depends on how the affected input is used downstream; verify reachability.")
        lines += ["", "**Impact**", "", _impact, ""]
        _g = graded_business_impact(f)
        if _g:
            lines += ["**Impact (evidence-graded)**", "",
                      f"- _Demonstrated:_ {_g['demonstrated']}",
                      f"- _Plausible next step:_ {_g['plausible']}",
                      f"- _Unverified worst case:_ {_g['unverified']}",
                      f"- _Confidence:_ {_g['confidence']} — {_g['assumptions']}", ""]
        _pr = proof_and_retest(f)
        lines += ["**How this was confirmed (false-positive safety)**", "", _pr["negative_control"], "",
                  "**Retest / closure**", "", _pr["retest"], ""]
        if str(f.get("false_positive_check") or "").strip():
            lines += ["**False-positive check**", "", str(f["false_positive_check"]), ""]
        lines += _ot_context_md(f)
        lines += ["**Remediation**", "", remediation_line(f), ""]
        # BSRS Ch.5/6/8/9 (T5): the design-level answer under the tactical one — what removes the CLASS,
        # what bounds the blast radius, and what to do ASSUMING it was already exploited. Renders only for
        # families with substantive guidance; `_family_of` is reused so a finding carrying only a CWE
        # still resolves. Empty string for everything else, by design — padding this section teaches
        # readers to skip it.
        lines += _remediation_depth_md(f)
        lines += _defense_controls_md(f)
        if f.get("evidence"):
            lines += ["**Supporting Material**", "", "```", str(f["evidence"]), "```", ""]
        for _lbl, _txt in evidence_items(f):
            lines += [f"**{_lbl}**", "", "```", _txt, "```", ""]
        lines += ["---", ""]

    if chains:
        lines += ["## Attack-Path Chains & Chaining Potential", "",
                  "_Where the confirmed findings lead when combined. Items marked "
                  "**(potential)** are a single confirmed bug's well-known escalation path — "
                  "verify reachability before claiming the full chain._", ""]
        for c in chains:
            tag = (" **(potential)**" if c.get("kind") == "potential"
                   else " **[data-flow]**" if c.get("kind") == "dataflow" else "")
            lines.append(f"- **{c.get('host')}** ({(c.get('severity') or '').upper()}){tag}: "
                         f"**{c.get('narrative')}**")
            _cs = str(c.get("summary") or "").strip()
            if _cs:
                lines.append(f"    - {_cs}")
        lines.append("")
    if leads_md:
        lines.append(leads_md)
    if delta_block:
        lines += ["", delta_block]
    if ledger_block:
        lines += ["", ledger_block]
    # Target Intelligence — what the target itself leaked (harvested from its own surface),
    # the raw material a general technique consumes as fixtures. Noisy 'encoded' bucket omitted.
    if intel and (intel.get("candidates") or {}):
        _SHOW = [("decoded", "Decoded values"), ("email", "Emails"), ("username", "Usernames"),
                 ("object_id", "Object IDs"), ("route", "Routes"), ("endpoint", "Endpoints"),
                 ("param", "Parameters"), ("url", "External URLs"), ("coupon", "Coupons"),
                 ("version", "Versions"), ("secret", "Secrets (redacted)"), ("comment", "Dev comments"),
                 ("hint", "Hints")]
        _cand = intel.get("candidates", {})
        _ilines = []
        for _k, _lbl in _SHOW:
            _vals = _cand.get(_k) or []
            if not _vals:
                continue
            _shown = ", ".join("`" + str(v) + "`" for v in _vals[:12])
            _more = len(_vals) - 12
            if _more > 0:
                _shown += " _(+" + str(_more) + " more)_"
            _ilines.append("- **" + _lbl + "** (" + str(len(_vals)) + "): " + _shown)
        if _ilines:
            lines += ["", "## Target Intelligence", "",
                      "_Candidates harvested from the target's own surface (DOM, JS, source maps, API "
                      "responses) — the clues the target leaks, and the raw material a general technique "
                      "consumes as run-time fixtures. Derived live from the target, not hardcoded. "
                      "Secrets redacted._", ""]
            lines += _ilines
    # Intelligence Orchestration — prove the knowledge model DROVE the scan, and give the operator the
    # deterministic next-best actions (the ordered path to keep testing), memory-aware from this engagement.
    if orchestration:
        _adv = orchestration.get("advisor") or []
        _nb = orchestration.get("next_best") or []
        if _adv or _nb:
            lines += ["", "## Intelligence Orchestration", ""]
            if _adv:
                lines += ["_The scan consulted the first-class technique knowledge model and prioritized "
                          "these techniques (relevance + CISA-KEV + confidence):_", ""]
                for a in _adv[:8]:
                    _why = ", ".join(a.get("reasons", []))[:100]
                    lines.append("- **%s** (score %s)%s" % (a.get("name") or a.get("id", ""),
                                 a.get("score", ""), (" — " + _why) if _why else ""))
            if _nb:
                lines += ["", "_**Next-best actions** (evidence-driven planner: precondition-gated, "
                          "KEV-ranked, aware of what this engagement already confirmed):_", ""]
                for a in _nb[:6]:
                    _act = (a.get("action") or a.get("oracle") or "")[:90]
                    _bl = a.get("bypass_ladder") or []
                    _byp = ("  \n  ↳ filter-bypass: " + ", ".join("`%s`" % v for v in _bl[:3])) if _bl else ""
                    lines.append("- **%s** _(%s)_%s%s" % (a.get("id", ""), a.get("family", ""),
                                 (" — " + _act) if _act else "", _byp))
    # WHAT THIS ASSESSMENT COULD NOT TEST (#125). Placed before Report Integrity so a reader meets the
    # limits of the run before its guarantees: absence of findings in an untested class is not evidence
    # of absence, and a report that omits this lets silence read as safety (WYSIATI).
    try:
        import capability_preflight as _cp
        _debt = _cp.coverage_debt()
        if not _debt["complete"]:
            lines += ["", _cp.report_section(_debt).rstrip()]
    except Exception:
        pass

    # report-integrity guarantee (metrics agree with findings; leads never inflate risk)
    import report_integrity as _ri
    _integ = _ri.check_report_consistency(findings, leads, risk_score(findings), counts)
    lines += ["", "## Report Integrity", "",
              ("> ✓ **Consistent** — " if _integ["ok"] else "> ⚠ **Contradictions found** — ")
              + _ri.summary_line(_integ)]
    for _i in _integ["issues"]:
        lines.append(f"> - `{_i['check']}` — {_i['detail']}")
    return "\n".join(lines)


# ── HTML (light-default standalone, dark toggle, all fields escaped) ──
# ── engagement / risk helpers ────────────────────────────────────
_ENGAGEMENT = {"passive": "Passive Reconnaissance", "active": "Active Assessment",
               "full": "Full Penetration Test"}
_SEV_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "informational": 1, "info": 1}

# ── plain-English business impact, keyed by vuln family (CWE as fallback) ──
# "means" = what the technical finding actually is, in words a non-technical
# stakeholder understands. "risk" = the concrete business consequence if it is
# not fixed. Deterministic (no AI) so every report carries it.
_BIZ = {
    "sqli": ("Your site builds database queries by pasting in text from the web address without keeping the "
             "attacker's input separate from the query's instructions, so a crafted value rewrites the query.",
             "An attacker can read or change your whole database — customer records, passwords, orders — and can "
             "sometimes take over the server. This is one of the most damaging and heavily-regulated breach types "
             "(data-protection fines, mandatory breach disclosure, loss of customer trust)."),
    "xss": ("Text from the visitor is echoed back into the page without being neutralised, so an attacker can make "
            "your site run their JavaScript in your customers' browsers.",
            "Attackers can hijack logged-in customer or admin sessions, steal data shown on the page, submit actions "
            "as the victim, or deface the site — all from a link that points at your real domain."),
    "crlf": ("A value from the web address is copied straight into the hidden control part of the response (its "
             "headers) without being cleaned, so an attacker can smuggle their own instructions in there.",
             "An attacker can poison shared caches so OTHER visitors are served a malicious page, plant or steal "
             "login cookies, or bounce your customers to a fake look-alike site — all while the address bar still "
             "shows your genuine domain. Leads to phishing that looks legitimate, account takeover, and brand damage."),
    "xxe": ("An endpoint that accepts XML will follow references inside that XML out to other files and systems.",
            "An attacker can read sensitive files off your server (config, credentials) and reach internal systems "
            "that are not meant to be exposed to the internet — a common first step toward a deeper breach."),
    "ssrf": ("A feature that fetches a URL can be pointed at addresses the attacker chooses, including your own "
             "internal network.",
             "An attacker can reach internal-only services and cloud metadata (which often hands out cloud "
             "credentials), pivoting from your public site into your private infrastructure."),
    "cmdi": ("Input is passed to the server's operating system as a command without being separated from it.",
             "An attacker can run their own commands on your server — effectively full control of that machine, "
             "including your data and anything it can reach."),
    "path_traversal": ("A file/path parameter can be tricked into stepping outside its intended folder.",
                       "An attacker can read files they should never see (configuration, credentials, source code), "
                       "which frequently unlocks a larger compromise."),
    "idor": ("The app trusts an ID in the request to decide what to show, without checking the requester is allowed "
             "to see it, so changing the ID reaches someone else's data.",
             "One customer can view or change another customer's records (orders, profiles, documents). This is a "
             "direct privacy breach and a top cause of reportable data-protection incidents."),
    "bfla": ("A privileged action or admin function does not properly check the caller's role.",
             "A normal or unauthenticated user can perform actions reserved for staff/admins — changing data, "
             "escalating privileges, or reaching administrative functions."),
    "vulnerable_component": ("Your site ships a third-party library with publicly-documented security flaws (CVEs).",
                             "Attackers scan for exactly these known-vulnerable versions and reuse off-the-shelf "
                             "exploits. Even if not yet abused here, it lowers the bar for an attack and is a common "
                             "audit/compliance finding. Fix is usually a version upgrade."),
    "open_redirect": ("A redirect parameter will forward visitors to any address, including attacker sites.",
                      "Attackers use YOUR trusted domain in links that quietly send victims to phishing or malware "
                      "pages, making their scam far more convincing and damaging your reputation."),
    "ssti": ("User input is rendered by the server's template engine as code rather than plain text.",
             "Typically leads to running attacker code on the server — often full server compromise."),
    "deserialization": ("The app rebuilds objects from attacker-supplied serialized data without validating it.",
                        "Frequently leads to running attacker code on the server — a critical, full-compromise class."),
    "takeover": ("A subdomain points at a third-party service that is no longer claimed, so an attacker can claim it.",
                 "An attacker can host their own content on YOUR subdomain — used for convincing phishing, cookie "
                 "theft, and bypassing trust in your brand."),
    "csrf": ("A state-changing action can be triggered from another site without the user intending it.",
             "An attacker can make a logged-in customer or admin perform actions unknowingly (change email, transfer, "
             "delete), abusing their session."),
    "cors": ("The site tells browsers to let other websites read its responses.",
             "Malicious sites can read data belonging to your logged-in users, leaking private information."),
    "exposure": ("Sensitive files or source are reachable directly over the web.",
                 "Anyone can download configuration, secrets, or source code — often handing attackers the keys to a "
                 "deeper breach."),
    "git_exposure": ("Your source-control folder is downloadable over the web.",
                     "Attackers can reconstruct your source code and often extract secrets/credentials from history."),
    "prototype_pollution": ("A client-side script lets attacker input set properties on JavaScript's shared base "
                            "object, so a crafted URL changes how the whole page's code behaves.",
                            "On its own it corrupts client-side logic; chained with a suitable sink it becomes DOM "
                            "XSS — attacker script running in your customers' browsers (session theft, account "
                            "takeover)."),
    "csti": ("The page's client-side template engine (AngularJS) evaluates attacker text from a link as code in "
             "the visitor's browser — it runs JavaScript, it does NOT run code on your server.",
             "From a crafted link on your real domain, an attacker's script runs in a victim's browser: stealing "
             "session cookies, taking over the account, capturing typed data, or driving convincing phishing. "
             "Impact is client-side (the same class as XSS); the server itself is not compromised by this bug."),
}
# CWE -> family, so a finding with a CWE but no recognised family still gets text.
_CWE_FAMILY = {
    "cwe-89": "sqli", "cwe-79": "xss", "cwe-113": "crlf", "cwe-611": "xxe", "cwe-918": "ssrf",
    "cwe-78": "cmdi", "cwe-22": "path_traversal", "cwe-639": "idor", "cwe-284": "idor",
    "cwe-285": "bfla", "cwe-1104": "vulnerable_component", "cwe-1035": "vulnerable_component",
    "cwe-601": "open_redirect", "cwe-1336": "ssti", "cwe-94": "ssti", "cwe-502": "deserialization",
    "cwe-352": "csrf", "cwe-942": "cors", "cwe-200": "exposure", "cwe-527": "git_exposure",
    "cwe-1321": "prototype_pollution", "cwe-1336": "ssti",
    "cwe-204": "username_enumeration", "cwe-208": "username_enumeration",
    "cwe-330": "weak_session_token", "cwe-384": "weak_session_token",
    "cwe-1392": "default_credentials", "cwe-521": "default_credentials",
    "cwe-326": "weak_ssh_crypto", "cwe-327": "weak_ssh_crypto",
    "cwe-1188": "snmp_default_community",
}

# CWE -> CAPEC attack pattern (MITRE). Only well-established 1:1 mappings are
# listed; an unmapped CWE simply gets no CAPEC rather than a guessed one
# (truth-first — same discipline as business_impact()).
_CWE_CAPEC = {
    "cwe-89": "CAPEC-66: SQL Injection",
    "cwe-79": "CAPEC-63: Cross-Site Scripting (XSS)",
    "cwe-78": "CAPEC-88: OS Command Injection",
    "cwe-22": "CAPEC-126: Path Traversal",
    "cwe-611": "CAPEC-201: XML External Entity (XXE) Injection",
    "cwe-918": "CAPEC-664: Server-Side Request Forgery",
    "cwe-352": "CAPEC-62: Cross-Site Request Forgery",
    "cwe-601": "CAPEC-194: Fake the Source of Data (Open Redirect)",
    "cwe-113": "CAPEC-34: HTTP Response Splitting",
    "cwe-94": "CAPEC-242: Code Injection",
    "cwe-1336": "CAPEC-242: Code Injection (Server-Side Template Injection)",
    "cwe-502": "CAPEC-586: Object Injection",
    "cwe-200": "CAPEC-116: Excavation (Information Exposure)",
    "cwe-285": "CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs",
    "cwe-639": "CAPEC-180: Exploiting Incorrectly Configured Access Control",
    "cwe-284": "CAPEC-180: Exploiting Incorrectly Configured Access Control",
}


def capec_for(finding: dict):
    """CAPEC attack pattern for a finding — an explicit `capec` field wins, else a
    known CWE->CAPEC mapping, else None (never invented)."""
    existing = str(finding.get("capec") or "").strip()
    if existing:
        return existing
    cwe = str(finding.get("cwe") or "").strip().lower()
    return _CWE_CAPEC.get(cwe)


def _with_capec(findings: list) -> list:
    """Return finding copies with `capec` filled where derivable — used at render/
    export time so CWE-tagged findings carry an attack-pattern id without mutating
    the stored records or touching the scan path."""
    out = []
    for f in findings or []:
        cap = capec_for(f)
        if cap and not f.get("capec"):
            f = {**f, "capec": cap}
        out.append(f)
    return out


def _family_of(finding: dict) -> str:
    fam = str(finding.get("family") or "").strip().lower()
    if fam:
        return fam
    return _CWE_FAMILY.get(str(finding.get("cwe") or "").strip().lower(), "")


# ── deterministic remediation per vuln family (real fixes, not "see detail") ──
_FAMILY_FIX = {
    "sqli": "Use parameterised queries / prepared statements — never concatenate input into SQL. "
            "Add least-privilege DB accounts and allowlist any dynamic column/sort names.",
    "xss": "Context-encode every output (HTML/attribute/JS/URL), use an auto-escaping template engine, "
           "and add a strict Content-Security-Policy.",
    "crlf": "Strip or reject CR/LF (%0d/%0a) in any value written to a response header; use the framework's "
            "header API instead of manual string concatenation.",
    "xxe": "Disable external entities and DOCTYPE processing in the XML parser (secure-processing / "
           "disallow-doctype-decl).",
    "ssrf": "Allowlist destination hosts and schemes, resolve-and-pin the IP, and block link-local/cloud-metadata "
            "ranges (169.254.169.254, 127.0.0.0/8, RFC1918).",
    "cmdi": "Do not invoke a shell — use native APIs. If unavoidable, pass arguments as an array (no shell string) "
            "and validate every value against an allowlist.",
    "path_traversal": "Canonicalise and confine file paths to a base directory (reject ../ and absolute paths); "
                      "serve files by an allowlisted id, not a user-supplied path.",
    "idor": "Enforce per-object authorization on every request (verify the caller may access that id); use "
            "unguessable ids as defence-in-depth.",
    "bfla": "Enforce role/function authorization server-side on every privileged action; deny by default.",
    "vulnerable_component": "Upgrade or remove the affected component (here: retire end-of-life AngularJS 1.x). "
                            "Adopt SCA and a regular dependency-patching cadence.",
    "open_redirect": "Validate redirect targets against an allowlist of internal paths; never redirect to a "
                     "user-supplied absolute URL, and strip //, /\\ and scheme tricks.",
    "request_url_override": "Never build a client-side fetch/XHR/WebSocket target from attacker-controllable input "
                            "(query/hash/message). Allowlist the destination origin+path, or use fixed relative "
                            "endpoints; treat the decoded value as data, not a URL.",
    "ssti": "Never render user input as a template; pass it as data to a sandboxed, auto-escaping engine.",
    "csti": "Never place untrusted input where a client-side template engine will evaluate it. Bind user data as "
            "text (Angular {{ }} interpolation of a scope value / ng-bind), not by concatenating it into the "
            "template; upgrade off the end-of-life AngularJS 1.x sandbox and add a strict Content-Security-Policy.",
    "deserialization": "Do not deserialise untrusted data; use a data-only format (JSON) with a strict schema, "
                       "or signed/allowlisted types.",
    "takeover": "Remove the dangling DNS record or reclaim the third-party resource; monitor for unclaimed CNAMEs.",
    "csrf": "Require a per-session anti-CSRF token on state-changing requests and set SameSite=Lax/Strict cookies.",
    "cors": "Do not reflect arbitrary Origins with credentials; allowlist trusted origins only.",
    "exposure": "Remove the exposed file from the web root and rotate any leaked secrets; block dotfiles/backups "
                "at the web server.",
    "git_exposure": "Block access to .git/ at the web server and rotate every secret found in the repo history.",
    "username_enumeration": "Return one identical, generic failure ('invalid username or password') with the same "
                            "status, body, and timing whether or not the account exists — on login, registration, "
                            "and password reset alike.",
    "weak_session_token": "Generate session tokens from a CSPRNG with >=128 bits of entropy; never encode "
                          "meaningful data (username/role) in the token; issue a fresh token on login/privilege "
                          "change.",
    "session_fixation": "Regenerate the session identifier on every privilege change, especially immediately "
                        "after login and logout; invalidate the pre-auth session server-side.",
    "default_credentials": "Change or disable the default account immediately; restrict the management interface "
                           "to trusted networks and require strong, unique credentials.",
    "weak_ssh_crypto": "Restrict sshd to strong algorithms only (curve25519 / group16-18-sha512 KEX; "
                       "chacha20-poly1305 + aes-gcm/ctr ciphers; *-etm hmac-sha2 MACs; rsa-sha2/ed25519 host "
                       "keys); remove CBC, SHA-1, arcfour, 3des, umac-64, ssh-rsa and ssh-dss.",
    "ldap_anonymous_read": "Disable anonymous bind (olcDisallows: bind_anon / AD dsHeuristics) or deny anonymous "
                           "read of the naming context so only authenticated principals can enumerate the directory.",
    "smb_null_session": "Deny anonymous access: 'restrict anonymous = 2' (Windows) / 'map to guest = Never' + "
                        "'restrict anonymous = yes' (Samba); disable SMBv1 and require authentication for share "
                        "enumeration; remove guest-readable shares.",
    "snmp_default_community": "Change or disable default community strings; move to SNMPv3 with auth + privacy; "
                             "restrict UDP/161 to trusted management hosts.",
    "smb_signing_disabled": "Require SMB signing everywhere ('server signing = mandatory' on Samba / the "
                            "'Digitally sign communications (always)' GPO on Windows) and enable EPA/channel "
                            "binding on domain controllers to stop NTLM relay.",
    "modbus_exposed": "Never expose Modbus/OT to untrusted networks: segment OT behind a firewall/DMZ + VPN, "
                      "restrict TCP/502 to the SCADA master(s), front legacy Modbus with an authenticating "
                      "gateway, and remove any internet reachability.",
    "vnc_no_auth": "Require a strong VNC password or disable password-only VNC; tunnel VNC over SSH/VPN and "
                   "restrict TCP/5900 to trusted management hosts.",
    "rsync_anon": "Set 'list = no' and require 'auth users' + a secrets file on every rsync module; restrict "
                  "TCP/873 to trusted hosts or tunnel rsync over SSH.",
    "ntp_monlist": "Upgrade ntpd to >=4.2.7 or add 'disable monitor' to ntp.conf; restrict mode-6/7 queries "
                   "('restrict ... noquery') and limit inbound UDP/123 from untrusted networks.",
    "ipmi_rakp": "Isolate IPMI/BMC (UDP/623) to a dedicated management VLAN reachable only by trusted admins; set "
                 "strong unique BMC passwords; disable IPMI-over-LAN where possible and prefer authenticated "
                 "Redfish/HTTPS.",
    "rdp_no_nla": "Require Network Level Authentication (CredSSP) on all RDP hosts via GPO; restrict TCP/3389 to "
                  "VPN/jump hosts; prefer an authenticated RD Gateway.",
}


def remediation_line(finding: dict) -> str:
    """A real, concise fix for a finding — explicit field first, then the family map,
    then the remediation CATALOG, else a safe generic (never 'see finding detail')."""
    if str(finding.get("remediation") or "").strip():
        return finding["remediation"].strip()
    fix = _FAMILY_FIX.get(_family_of(finding))
    if fix:
        return fix
    try:
        import remediation as _rem
        txt = _rem.remediation_text(finding)
        if txt:
            return txt
    except Exception:
        pass
    return "Validate and neutralise the untrusted input at this sink, and add a regression test."


# ── per-family "Validation After Fix" (how to prove the fix worked + a regression test) ──
_FAMILY_VALIDATION = {
    "sqli": "Re-send the confirming payloads (single quote, then the UNION metadata request). PASS = a normal 200 "
            "with the ordinary result set, no DB error, and no version/user/schema echoed back. Add an automated "
            "test that asserts the parameter is bound (parameterised) and that a quote yields no SQL error.",
    "xxe": "Re-send the external-entity XML body against the endpoint. PASS = the parser rejects the DOCTYPE/entity "
           "(fast error, no outbound fetch) and the baseline-vs-payload timing delta collapses to ~0s. Add a test "
           "posting a SYSTEM-entity body and asserting it is refused.",
    "csti": "Reload the crafted URL in a browser after the fix. PASS = the DOM shows the literal text {{7*7}} (or the "
            "value bound as inert text), NOT 49. Add an end-to-end (Playwright/Cypress) test asserting the marker is "
            "not evaluated for that parameter.",
    "crlf": "Replay the request with encoded CR/LF (%0d%0a) in the parameter. PASS = the injected header/line does "
            "NOT appear in the response headers. Add a test asserting CR/LF are stripped or rejected before any "
            "header write.",
    "prototype_pollution": "Reload the crafted URL and read Object.prototype in the console. PASS = the injected "
                           "marker property is absent (undefined). Add a browser test asserting the gadget no longer "
                           "writes to the prototype.",
    "open_redirect": "Reload the crafted URL in a browser. PASS = the browser stays on-site (or shows a blocked-"
                     "redirect notice) instead of navigating to the attacker host. Add a test asserting only "
                     "allowlisted internal targets are honoured.",
    "vulnerable_component": "After upgrading/removing the library, re-fingerprint the page. PASS = the vulnerable "
                            "version string is gone and SCA reports no known CVEs for the shipped version. Add the "
                            "version assertion to CI.",
    "xss": "Replay the payload and load the page in a browser. PASS = the payload renders as inert text and no "
           "script/alert executes. Add a test asserting the output is context-encoded at this sink.",
}


def validation_line(finding: dict) -> str:
    """How to PROVE the fix worked, plus the regression test to keep it fixed. Explicit
    field first, then the family map, else a safe generic tied to the reproduction."""
    v = str(finding.get("validation") or finding.get("regression_test") or "").strip()
    if v:
        return v
    return _FAMILY_VALIDATION.get(_family_of(finding),
                                  "Re-run the exact reproduction above and confirm the confirming condition no "
                                  "longer occurs; then add an automated regression test for this input at this sink.")


# ── estimated CVSS v3.1 per family (clearly labelled 'estimated' in the report) ──
# base-class estimates, NOT authoritative scoring — they orient triage; a real
# assessor should refine per exploitability. Kept deterministic (no invention beyond
# the documented class baseline).
_FAMILY_CVSS = {
    "sqli": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "cmdi": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ssti": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "deserialization": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ssrf": (8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "xxe": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L"),
    "bfla": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "path_traversal": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "exposure": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "git_exposure": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "vulnerable_component": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "takeover": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"),
    "idor": (6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "csrf": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    "xss": (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "csti": (8.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
    "crlf": (7.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N"),
    "prototype_pollution": (7.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N"),
    "cors": (5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"),
    "open_redirect": (4.7, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"),
}


# Canonical OWASP Top-10 (2021) category per finding family. Authoritative at render so a
# tool that mis-tagged (e.g. a vulnerable component as A03 Injection) is corrected centrally.
_OWASP_BY_FAMILY = {
    "sqli": "A03:2021 Injection", "xss": "A03:2021 Injection", "csti": "A03:2021 Injection",
    "ssti": "A03:2021 Injection", "crlf": "A03:2021 Injection", "cmdi": "A03:2021 Injection",
    "nosqli": "A03:2021 Injection", "code_injection": "A03:2021 Injection",
    "idor": "A01:2021 Broken Access Control", "bola": "A01:2021 Broken Access Control",
    "bfla": "A01:2021 Broken Access Control", "access_control": "A01:2021 Broken Access Control",
    "broken_access": "A01:2021 Broken Access Control", "open_redirect": "A01:2021 Broken Access Control",
    "csrf": "A01:2021 Broken Access Control", "traversal": "A01:2021 Broken Access Control",
    "ssrf": "A10:2021 Server-Side Request Forgery", "xxe": "A05:2021 Security Misconfiguration",
    "prototype_pollution": "A08:2021 Software and Data Integrity Failures",
    "deserialization": "A08:2021 Software and Data Integrity Failures",
    "vulnerable_component": "A06:2021 Vulnerable and Outdated Components",
    "backup_exposure": "A05:2021 Security Misconfiguration", "git_exposure": "A05:2021 Security Misconfiguration",
    "config_exposure": "A05:2021 Security Misconfiguration", "info_disclosure": "A05:2021 Security Misconfiguration",
    "credential_exposure": "A07:2021 Identification and Authentication Failures",
    "jwt": "A07:2021 Identification and Authentication Failures", "auth": "A07:2021 Identification and Authentication Failures",
    "business_logic": "A04:2021 Insecure Design",
}


def _owasp_of(f: dict) -> str:
    """Corrected OWASP category: canonical family map wins over a tool-supplied tag."""
    return _OWASP_BY_FAMILY.get(_family_of(f), str(f.get("owasp") or ""))


def estimated_cvss(finding: dict):
    """(score, vector, is_estimated) for a finding. An explicit score/vector on the
    finding wins (is_estimated False); otherwise a family baseline (is_estimated True);
    else None so the report shows nothing rather than a fake number."""
    sc = finding.get("cvss_score") or finding.get("cvss")
    vec = finding.get("cvss_vector")
    if sc:
        return (str(sc), str(vec or ""), False)
    base = _FAMILY_CVSS.get(_family_of(finding))
    if base:
        return (f"{base[0]}", base[1], True)
    return None


# ── AI-summary hygiene: no leaked Markdown / broken fragments in HTML ──
def clean_ai_text(text: str) -> list:
    """Turn an AI wrap-up (which may contain Markdown) into clean paragraph strings:
    strip **bold**/`code`/#/> markers, drop empty or obviously-truncated fragments."""
    import re as _re
    out = []
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s:
            continue
        s = _re.sub(r"\*\*(.+?)\*\*", r"\1", s)      # **bold** -> bold
        s = _re.sub(r"`([^`]+)`", r"\1", s)           # `code` -> code
        s = s.lstrip("#> ").replace("**", "").replace("`", "").strip("*_ ")
        if len(s) < 3 or s in {"are)", "/ properly sanitized"}:
            continue
        out.append(s)
    return out


def finding_curl(finding: dict) -> str:
    """A copy-paste reproduction command for a confirmed finding, from a captured
    request if present, else derived from the target URL (and method/body)."""
    if str(finding.get("curl") or "").strip():
        return finding["curl"].strip()
    target = str(finding.get("target") or finding.get("surface") or "").strip()
    if not target:
        return ""
    method = str(finding.get("method") or "GET").upper()
    body = finding.get("request_body") or finding.get("body")
    if method == "GET" and not body:
        return f"curl -i -sS -k --path-as-is '{target}'"
    parts = [f"curl -i -sS -k -X {method}"]
    if body:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"--data '{body}'")
    parts.append(f"'{target}'")
    return " ".join(parts)


def proof_provenance(f: dict) -> str:
    """One-line 'how this was proven': the tool and the exact settings/flags used.
    Empty when the finding carries neither (e.g. a native probe with no tool tag)."""
    tool = str(f.get("tool") or "").strip()
    settings = str(f.get("settings") or "").strip()
    if settings:
        return settings if tool and tool in settings else (f"{tool}: {settings}" if tool else settings)
    return tool


def evidence_items(f: dict) -> list:
    """Ordered (label, text) raw-proof artifacts a finding may carry beyond the main
    `evidence` string — raw request/response, tool log, timing, header diff, baseline.
    Only non-empty items are returned, each capped so a report never balloons."""
    import json as _json
    out = []
    for label, key in (("Raw request", "request"), ("Request body", "request_body"),
                       ("Raw response", "response"), ("Tool log", "log_tail"),
                       ("Timing samples", "timing"), ("Header diff", "header_diff"),
                       ("Baseline", "baseline")):
        v = f.get(key)
        if v is None:
            continue
        text = v if isinstance(v, str) else _json.dumps(v, indent=2, default=str)
        text = text.strip()
        if not text:
            continue
        out.append((label, text[:1800]))
    return out


def group_findings(findings: list) -> list:
    """Collapse duplicate findings that share a root cause (same family + affected
    parameter, or same title) into ONE representative carrying an `instances` list of
    every affected target. Preserves order by first occurrence. Distinct issues stay
    separate. This kills the '5 identical open-redirect cards' problem while keeping
    every raw instance for the appendix."""
    groups, order = {}, []
    for f in findings:
        fam = _family_of(f) or (f.get("title") or "").strip().lower()[:40]
        param = ""
        title = f.get("title") or ""
        m = title.rsplit(" in '", 1)
        if len(m) == 2 and m[1].endswith("'"):
            param = m[1][:-1]
        elif " on '" in title:
            param = title.rsplit(" on '", 1)[-1].rstrip("'")
        key = f"{fam}|{param}"
        if key not in groups:
            rep = dict(f)
            rep["instances"] = []
            groups[key] = rep
            order.append(key)
        g = groups[key]
        tgt = f.get("target") or f.get("surface") or ""
        if tgt and tgt not in g["instances"]:
            g["instances"].append(tgt)
        # The representative must reflect the STRONGEST proven finding in the group. When a
        # merged sibling is more severe (e.g. a UNION data-extraction that outranks the
        # error-based signal on the same parameter), promote its severity and proof fields
        # onto the representative — a critical must never hide behind a high just because it
        # was appended second. Accumulated instances / screenshots are preserved.
        if (SEV_ORDER.get((f.get("severity") or "info").lower(), 9)
                < SEV_ORDER.get((g.get("severity") or "info").lower(), 9)):
            _tags = list(dict.fromkeys((g.get("tags") or []) + (f.get("tags") or [])))
            for _k in ("severity", "title", "description", "evidence", "impact",
                       "reproduction_steps", "cwe", "capec", "owasp", "extracted_tables"):
                if f.get(_k) is not None:
                    g[_k] = f[_k]
            g["tags"] = _tags
        # carry the strongest browser PoC from ANY instance onto the representative, so
        # dedup never discards a screenshot / DOM snippet that a sibling captured. Prefer the
        # LARGEST screenshot: a blank/near-white page compresses to a few KB, so the biggest
        # base64 is the one with real page content (never let a blank-first instance win).
        _sh = f.get("screenshot") or ""
        if _sh and len(_sh) > len(g.get("screenshot") or ""):
            g["screenshot"] = _sh
        if not g.get("dom_snippet") and f.get("dom_snippet"):
            g["dom_snippet"] = f["dom_snippet"]
    return [groups[k] for k in order]


def business_impact(finding: dict):
    """(plain-English meaning, business consequence) for a finding, or None when we
    have no mapping (better to omit than to invent). Family first, then CWE."""
    fam = str(finding.get("family") or "").strip().lower()
    if fam in _BIZ:
        return _BIZ[fam]
    cwe = str(finding.get("cwe") or "").strip().lower()
    fam2 = _CWE_FAMILY.get(cwe)
    return _BIZ.get(fam2) if fam2 else None


# Evidence-aware impact grade (Pentera "exploitability over theoretical severity" + the mission's
# demonstrated / plausible / unverified discipline). Per family: (what a confirmed oracle DEMONSTRATES,
# the PLAUSIBLE next step, the UNVERIFIED worst case that must NOT be claimed without more evidence).
# Deterministic; grades DOWN from the flat consequence so a report never overclaims.
_IMPACT_GRADE = {
    "sqli": ("an injectable parameter confirmed by a control-vs-payload differential (the database interprets "
             "attacker input where an inert control does not)",
             "reading or altering application data the affected query can reach",
             "full-database exfiltration, authentication bypass, or OS/RCE"),
    "xss": ("attacker-controlled script executing in the browser through an unencoded reflected/stored sink",
            "theft of a logged-in victim's session, or actions performed as that victim",
            "mass account takeover or admin-session compromise at scale"),
    "idor": ("access to another account's object by changing only its identifier (the owner is denied on the control)",
             "viewing or altering other customers' records across the affected endpoint",
             "bulk enumeration/exfiltration of every user's records"),
    "bfla": ("a privileged/admin function invoked by an under-privileged caller",
             "unauthorized state changes or privilege escalation through that function",
             "full administrative takeover of the affected function set"),
    "ssrf": ("the server issuing a request to an attacker-chosen address (a unique out-of-band token returned)",
             "reaching internal-only services or cloud metadata from the public app",
             "cloud-credential theft and a pivot into private infrastructure"),
    "xxe": ("the XML parser resolving an attacker-supplied external entity",
            "reading server-side files or making internal requests",
            "secret/credential disclosure enabling a deeper breach"),
    "cmdi": ("attacker input changing the command the server runs (computed-output/timing oracle over baseline)",
             "running attacker commands in the application's OS context",
             "full compromise of the host and everything it can reach"),
    "ssti": ("server-side template evaluation of attacker input ({{7*7}}->49 while an inert control does not)",
             "code execution within the template context",
             "full server compromise"),
    "path_traversal": ("reading a file outside the intended directory via ../ traversal (an in-root control is normal)",
                       "disclosure of configuration, source, or credential files",
                       "a broader compromise seeded by the leaked material"),
    "open_redirect": ("the app redirecting to an attacker-chosen external host (a same-origin control stays on-site)",
                      "trusted-domain phishing, or an OAuth/SSRF allowlist bypass",
                      "credential theft through a redirect chain"),
    "csrf": ("a state-changing action triggered cross-site without the user's intent",
             "unwanted actions performed as the victim (settings/email change, transfer)",
             "account takeover where a sensitive action is reachable"),
    "vulnerable_component": ("a dependency whose version falls in a known-CVE range (a patched control does not match)",
                             "exposure to the public exploit(s) for that CVE where the code path is reachable",
                             "the worst outcome of the matched CVE (often RCE) — not demonstrated here"),
    "exposure": ("a sensitive file/resource served directly over the web (a control path 404s)",
                 "disclosure of the exposed configuration, secret, or source",
                 "credential reuse enabling a deeper breach"),
    "git_exposure": ("a downloadable source-control folder over the web",
                     "reconstruction of source and extraction of secrets from history",
                     "credential/key compromise enabling a deeper breach"),
    "deserialization": ("attacker-controlled serialized data reaching an unsafe deserializer (corrupt-and-watch oracle)",
                        "code paths toward server-side code execution",
                        "full server compromise"),
    "csti": ("client-side template evaluation of attacker text in the victim's browser (the server is not compromised)",
             "session/cookie theft or account takeover from a crafted link on the real domain",
             "widespread client-side compromise via a shared link"),
    "prototype_pollution": ("attacker input setting properties on JavaScript's shared base object",
                            "corrupted client-side logic, becoming DOM XSS when a suitable sink exists",
                            "browser-side account takeover via a chained sink"),
    "cors": ("a cross-origin read allowed by an over-permissive CORS policy",
             "another site reading your logged-in users' private data",
             "broad data leakage across authenticated users"),
}
_DEFAULT_GRADE = ("the confirming oracle condition for this vulnerability class",
                  "the direct consequence of the confirmed weakness",
                  "escalation beyond what was demonstrated — not claimed without further evidence")


def graded_business_impact(finding: dict):
    """Evidence-aware DEMONSTRATED / PLAUSIBLE / UNVERIFIED impact for a finding, or None for an
    unknown family. Truth-first: 'demonstrated' is gated on an oracle-confirmed finding; anything
    beyond it is explicitly labelled plausible or unverified so a report never overclaims (the
    mission's business-impact discipline). Deterministic; reuses business_impact()'s family resolution."""
    fam = str(finding.get("family") or "").strip().lower()
    if fam not in _IMPACT_GRADE:
        fam = _CWE_FAMILY.get(str(finding.get("cwe") or "").strip().lower(), fam)
    grade = _IMPACT_GRADE.get(fam)
    if not grade:
        return None
    dem, plaus, unv = grade
    confirmed = str(finding.get("confidence") or "").strip().lower() == "confirmed"
    return {
        "confidence": finding.get("confidence") or "unconfirmed",
        "demonstrated": ("Confirmed on this target: " + dem) if confirmed
                        else ("Signal observed but NOT oracle-confirmed (treat as a candidate): " + dem),
        "plausible": "Plausible next step (not demonstrated here): " + plaus,
        "unverified": "Unverified worst case — do NOT claim without further evidence: " + unv,
        "assumptions": ("Blast radius depends on the sensitivity of the affected data and its reachability; "
                        "assumes the demonstrated behaviour generalises across similar records/inputs."),
    }


def browser_evidence_html(finding: dict, e) -> str:
    """Render the Browser Intelligence Engine's evidence-derived proof (#124): the before/after
    screenshots, the exact runtime request, the mutated request, every negative control, and the replay
    script — all frozen from the ACTUAL confirmed run. Empty string when the finding has none."""
    be = finding.get("browser_evidence")
    if not isinstance(be, dict) or not be:
        return ""
    rows = []
    labels = {"exact_request": "Exact runtime request (owner)", "mutated_request": "Mutated request (attacker)"}
    for key in ("exact_request", "mutated_request"):
        x = be.get(key) or {}
        if x:
            rows.append((labels[key], x))
    for name, x in (be.get("negative_controls") or {}).items():
        pretty = {"anon": "Negative control — anonymous", "nonexistent": "Negative control — implausible id",
                  "control": "Negative control — attacker's own object"}.get(name, "Control — " + name)
        rows.append((pretty, x or {}))
    trs = "".join(
        "<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s B</td></tr>"
        % (e(lbl), e(str(x.get("url", ""))), e(str(x.get("status", ""))), e(str(x.get("len", 0))))
        for lbl, x in rows)
    shots = ""
    for lbl, s in sorted((be.get("screenshots") or {}).items()):
        b64 = (s or {}).get("png_b64")
        if b64:
            shots += ("<figure style='display:inline-block;max-width:48%%;margin:6px'>"
                      "<img src='data:image/png;base64,%s' style='max-width:100%%;border:1px solid #2a3b45'/>"
                      "<figcaption class='sub'>%s</figcaption></figure>" % (b64, e(lbl.replace("_", " "))))
    steps = "".join("<li>%s</li>" % e(str(s)) for s in (be.get("reproduction_steps") or []))
    fl = be.get("flow") or {}
    flow_html = ""
    if fl.get("steps"):
        flow_html = ("<h4>User flow (the route actually taken)</h4><table class='tbl'>"
                     "<tr><th>#</th><th>Actor</th><th>Action</th><th>Detail</th></tr>"
                     + "".join("<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
                               % (e(str(s.get("n"))), e(str(s.get("actor"))), e(str(s.get("action"))),
                                  e(str(s.get("url") or "")) + (" " if s.get("url") else "")
                                  + e(str(s.get("detail", ""))))
                               for s in fl["steps"]) + "</table>")
    tr = be.get("trace") or {}
    trace_html = ""
    if tr.get("path"):
        trace_html = ("<p><b>Interactive trace:</b> <code>%s</code> (%s bytes) — open with "
                      "<code>%s</code> to scrub the confirmed run: every action, DOM snapshot, console "
                      "line and network call.</p>"
                      % (e(str(tr.get("path"))), e(str(tr.get("bytes", 0))), e(str(tr.get("viewer", "")))))
    return ("<div class='biz'><h4>Browser runtime proof (Browser Intelligence Engine)</h4>"
            "<p class='sub'>Instrumentation: %s. The browser performed the attempt; the deterministic "
            "oracle decided the verdict.</p>"
            "%s"
            "<table class='tbl'><tr><th>Exchange</th><th>URL</th><th>Status</th><th>Size</th></tr>%s</table>"
            "%s"
            "%s%s"
            "<h4>Reproduce (from the actual run)</h4><ol>%s</ol>"
            "<h4>Replay script</h4><pre><code>%s</code></pre></div>"
            % (e(str(be.get("instrumentation", ""))),
               ("<p><b>Verdict:</b> %s</p>" % e(str((be.get("verdict") or {}).get("reason", "")))),
               trs, shots, flow_html, trace_html, steps, e(str(be.get("replay_script", "")))))


def proof_and_retest(finding: dict) -> dict:
    """A finding's FALSE-POSITIVE-safety negative control (from the #115 technique proof contract, keyed
    by family) + its RETEST/closure method (from the #117 closure loop). Deterministic; surfaces both in
    the report so a reviewer sees how the finding was kept honest and how to re-verify a fix."""
    import technique_model as _tm
    import retest as _rt
    fam = str(finding.get("family") or "").strip().lower()
    nc = _tm.proof_contract({"vuln_class": fam or str(finding.get("cwe") or ""), "oracle": ""}).get("negative_control")
    rp = _rt.plan(finding)
    if rp.get("retestable"):
        how = {"reachable": "the resource is still served with content",
               "offsite_redirect": "the redirect still points off-site",
               "reflects": "the crafted payload still reflects unencoded"}.get(rp["oracle"], "the oracle still fires")
        retest = "Re-request %s %s: OPEN if %s, CLOSED once the fix removes it (Apolaki auto-retests this)." % (
            rp["method"], rp["url"], how)
    else:
        retest = "Operator-driven: re-run the original confirming request + oracle (%s)." % rp.get("reason", "")
    return {"negative_control": nc, "retest": retest}


def risk_score(findings: list) -> dict:
    """Honest risk posture from CONFIRMED findings only (leads never inflate it —
    that is Apolaki's truth-first edge over tools that score off unconfirmed
    signal). 0-100 with a label + colour.

    THE FILTER IS THE CONTRACT, and it was missing. This summed severity over EVERY item handed to it,
    while `proof_schema.demote_unproven` is deliberately non-destructive: it rewrites a confirmed-but-
    unproven finding's confidence to "lead" and LEAVES IT IN THE LIST. So exactly the findings the proof
    gate had just rejected went on contributing their full severity weight to the headline number — the
    docstring's claim was the one thing the code did not do. Filtering here rather than at each call site
    means the guarantee holds for every caller, including any added later."""
    confirmed = [f for f in (findings or [])
                 if str((f or {}).get("confidence") or "confirmed").lower() not in ("lead", "unconfirmed",
                                                                                    "informational")]
    score = min(100, sum(_SEV_WEIGHT.get((f.get("severity") or "info").lower(), 1) for f in confirmed))
    findings = confirmed
    if score >= 70:
        label, color = "Critical", SEV_COLORS["critical"]
    elif score >= 40:
        label, color = "High", SEV_COLORS["high"]
    elif score >= 20:
        label, color = "Medium", SEV_COLORS["medium"]
    elif score >= 5:
        label, color = "Low", SEV_COLORS["low"]
    else:
        label, color = ("Informational" if findings else "No Confirmed Risk"), SEV_COLORS["info"]
    # Truth-first: the posture LABEL must not exceed the highest severity actually
    # confirmed. Four High findings are serious, but calling them "Critical" when no
    # Critical was confirmed reads as drama — cap the label at the top real severity.
    _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    _LBL = {4: ("Critical", SEV_COLORS["critical"]), 3: ("High", SEV_COLORS["high"]),
            2: ("Medium", SEV_COLORS["medium"]), 1: ("Low", SEV_COLORS["low"])}
    top = max((_RANK.get((f.get("severity") or "info").lower(), 0) for f in findings), default=0)
    if top and _RANK.get(label.lower(), 0) > top:
        label, color = _LBL[top]
    return {"score": score, "label": label, "color": color,
            "note": "Score = weighted sum of confirmed findings (critical 40 / high 25 / medium 10 / "
                    "low 3), capped at 100; label capped at the highest confirmed severity."}


def risk_signals(findings: list, leads: list, coverage: dict, attack_surface: dict,
                 chains: list) -> list:
    """Multi-axis risk SIGNALS for the executive view (absorbed from the reference
    dashboards) — but truth-first: these are descriptive signals about the engagement,
    NOT the risk score. The single confirmed-only score in risk_score() remains the
    authoritative posture; a target with zero confirmed findings never reads 'critical'
    here no matter how large its surface. Every signal states the factual basis it is
    computed from, so nothing is a black box. Returns [{label,pct,basis}]."""
    coverage = coverage or {}
    attack_surface = attack_surface or {}
    leads = leads or []
    chains = chains or []

    def _num(v):
        # Surface/coverage metrics can be 'n/a', None, or a formatted string — coerce
        # anything non-numeric to 0 so a descriptive placeholder never 500s the report.
        try:
            return int(float(str(v).strip()))
        except (TypeError, ValueError):
            return 0
    endpoints = _num(attack_surface.get("endpoints", 0))
    params = _num(attack_surface.get("params", 0))
    parameterized = _num(attack_surface.get("parameterized", 0))
    probed = _num(coverage.get("surface_urls", 0)) or endpoints
    exposure = sum(1 for x in (findings + leads)
                   if any(k in ((x.get("family") or "") + " " + " ".join(x.get("tags") or [])).lower()
                          for k in ("exposure", "secret", "disclosure", "backup", "sensitive")))
    conf_load = min(100, sum(_SEV_WEIGHT.get((f.get("severity") or "info").lower(), 1) for f in findings))
    sig = [
        {"label": "Confirmed vulnerability load", "pct": conf_load,
         "basis": f"{len(findings)} confirmed finding(s), severity-weighted"},
        {"label": "Attack surface", "pct": min(100, round(endpoints * 1.5 + params * 2)),
         "basis": f"{endpoints} endpoint(s), {params} unique parameter(s) mapped"},
        {"label": "Injectable surface", "pct": (round(100 * parameterized / endpoints) if endpoints else 0),
         "basis": f"{parameterized} of {endpoints} endpoint(s) accept input (injection candidates)"},
        {"label": "Information exposure", "pct": min(100, exposure * 20),
         "basis": f"{exposure} exposure signal(s) — secrets / backups / disclosure"},
        {"label": "Attack-chain potential", "pct": min(100, len(chains) * 34),
         "basis": f"{len(chains)} multi-step attack path(s) identified"},
        {"label": "Leads awaiting verification", "pct": min(100, len(leads) * 7),
         "basis": f"{len(leads)} advisory lead(s) not yet confirmed"},
    ]
    return sig


# ── Coverage Engine: the honest INVERSE of coverage ─────────────────────────
def coverage_gaps(mode=None, execution=None, tool_ledger=None, authenticated=None) -> list:
    """Whole test areas that could NOT be exercised this run, each with the concrete reason — so a
    reader knows the report's boundaries (absence of a finding in a gap area is NOT proof of safety).
    Returns [[area, reason_tag, explanation], ...]. Deterministic."""
    gaps = []
    m = (mode or "").lower()
    strat = ((execution or {}).get("strategy") or "").lower()
    led = tool_ledger if isinstance(tool_ledger, dict) else {}
    if authenticated is not True:
        gaps.append(["Authenticated attack surface", "no credentials supplied",
                     "Authenticated flows — role-based access, per-user objects (IDOR/BOLA) and admin "
                     "functions (BFLA) behind login — were not exercised. Supply a test account to cover them."])
    if m and m != "full":
        gaps.append(["Intrusive / deep DAST", "not run in Full mode",
                     "The intrusive active scanners (ZAP thorough-active, nmap NSE vuln scripts, the heavy "
                     "nuclei template set) only run in Full mode; this assessment did not include them."])
    if strat in ("deterministic", "manual", ""):
        gaps.append(["AI business-logic hunt", "proof-first (no-AI) run",
                     "The optional AI-driven business-logic reasoning pass was not performed. It is an "
                     "enhancement layer on the deterministic floor, not a detector — no CONFIRMED finding "
                     "is lost by skipping it."])
    gaps.append(["Fully-rendered browser behaviour", "request-level coverage",
                 "Issues that only surface in a real rendered browser (some DOM XSS, SPA client-side "
                 "routing/state) are only partially covered by request-level testing."])
    for t in (led.get("tools") or []):
        if not isinstance(t, dict):
            continue
        st = str(t.get("status") or "").lower()
        if st in ("error", "failed", "unavailable", "timeout", "skipped", "not-run"):
            gaps.append([str(t.get("tool", "tool")), st,
                         "This tool did not complete, so its coverage area may be incomplete."])
    return gaps


# ── Root-Cause inference: group findings by architectural weakness, not symptom ──
_ROOT_CAUSE = {
    "idor": "Broken object-level authorization", "bfla": "Broken function-level authorization",
    "mass_assignment": "Broken object-level authorization", "access_control": "Broken authorization",
    "sqli": "Unsafe handling of untrusted input (injection)", "nosqli": "Unsafe handling of untrusted input (injection)",
    "cmdi": "Unsafe handling of untrusted input (injection)", "ssti": "Unsafe handling of untrusted input (injection)",
    "xxe": "Unsafe handling of untrusted input (injection)", "crlf": "Unsafe handling of untrusted input (injection)",
    "command_injection": "Unsafe handling of untrusted input (injection)",
    "xss": "Output not neutralised before rendering (XSS)", "csti": "Output not neutralised before rendering (XSS)",
    "weak_password_reset": "Broken authentication / session management",
    "csrf": "Missing request-forgery protection", "open_redirect": "Unvalidated redirects & forwards",
    "vulnerable_component": "Known-vulnerable dependencies",
    "exposure": "Sensitive data / source exposure", "path_traversal": "Sensitive data / source exposure",
    "ssrf": "Server trusts a user-supplied destination (SSRF)", "deserialization": "Unsafe deserialization",
    "cors": "Overly-permissive cross-origin policy", "takeover": "Dangling / unclaimed infrastructure",
    "business_logic": "Business-logic / design flaw", "misconfig": "Security misconfiguration",
    # tool-emitted family aliases folded onto the same architectural causes (so groups MERGE, not split)
    "bola": "Broken object-level authorization", "stored_xss": "Output not neutralised before rendering (XSS)",
    "git_exposure": "Sensitive data / source exposure", "backup_exposure": "Sensitive data / source exposure",
    "config_exposure": "Sensitive data / source exposure", "credential_exposure": "Sensitive data / source exposure",
    "info_disclosure": "Sensitive data / source exposure",
    "jwt": "Broken authentication / session management", "oauth": "Broken authentication / session management",
    "prototype_pollution": "Unsafe handling of untrusted input (injection)",
    "host_header": "Unsafe handling of untrusted input (injection)",
    "llm_prompt_injection": "Unsafe handling of untrusted input (injection)",
    "crypto": "Weak or misused cryptography", "race": "Business-logic / design flaw",
    "cache_poisoning": "Security misconfiguration", "graphql": "Security misconfiguration",
    "upload": "Unrestricted file upload",
}


def root_cause_groups(findings: list) -> list:
    """Group confirmed findings by their ARCHITECTURAL root cause (e.g. 5 IDORs -> one 'Broken
    object-level authorization' weakness with 5 manifestations) so remediation targets the cause,
    not each symptom. Returns [{root_cause, count, worst, families, titles}], worst-first."""
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
    groups: dict = {}
    for f in findings or []:
        fam = (_family_of(f) or "").lower()
        rc = _ROOT_CAUSE.get(fam) or "Other"
        g = groups.setdefault(rc, {"root_cause": rc, "count": 0, "worst": "info",
                                   "families": set(), "titles": []})
        g["count"] += 1
        g["families"].add(fam or "?")
        g["titles"].append(f.get("title", "finding"))
        sev = (f.get("severity") or "info").lower()
        if rank.get(sev, 9) < rank.get(g["worst"], 9):
            g["worst"] = sev
    out = [{"root_cause": v["root_cause"], "count": v["count"], "worst": v["worst"],
            "families": sorted(v["families"]), "titles": v["titles"]} for v in groups.values()]
    out.sort(key=lambda g: (rank.get(g["worst"], 9), -g["count"]))
    return out


# ── Since-Last-Scan (historical delta) — truth-first, never calls "fixed" ──
def _delta_lines(delta: dict, findings: list) -> list:
    """Markdown lines for the 'Since Last Scan' section from a memory diff.
    A finding present last run but absent now is 'Not Re-confirmed' — NEVER
    'fixed'/'resolved' — and requires manual verification before closure."""
    if not delta or not delta.get("has_prior"):
        return []
    fd = delta.get("findings") or {}
    new_f = fd.get("added") or []
    not_reconf = fd.get("removed") or []
    lines = ["## Since Last Scan", "",
             "_Compared with the most recent prior mission on this target (cross-session "
             "memory, keyed by scope). Absence from this run is NOT proof of a fix._", ""]
    if not findings and not_reconf:
        lines += [f"> **0 vulnerabilities were confirmed in this run. However, {len(not_reconf)} "
                  f"previously confirmed finding{'s' if len(not_reconf) != 1 else ''} "
                  f"{'were' if len(not_reconf) != 1 else 'was'} not re-confirmed and require verification "
                  f"before closure.**", ""]
    def _sec(title, items, render):
        if not items:
            return []
        return [f"**{title} ({len(items)}):**", ""] + [render(x) for x in items] + [""]
    lines += _sec("New Findings", new_f, lambda f: f"- {f.get('title','finding')} — `{f.get('target','')}`")
    lines += _sec("Not Re-confirmed (verify — not necessarily fixed)", not_reconf,
                  lambda f: f"- {f.get('title','finding')} — `{f.get('target','')}` _(prior "
                            f"{(f.get('severity') or 'info')}; confirm status manually)_")
    for kind, label in (("subdomains", "New Subdomains"), ("endpoints", "New Endpoints"),
                        ("tech", "New Technology")):
        added = (delta.get(kind) or {}).get("added") or []
        lines += _sec(label, added, lambda v: f"- `{v}`")
    return lines


def _zap_status_text(status: str) -> str:
    return {"executed": "ZAP Executed",
            "executed_passive": "ZAP Executed — Passive Only (spider + passive scan, no active scan)",
            "executed_safe_active": "ZAP Executed — Safe Active (rate-limited, scope-guarded active scan)",
            "executed_thorough_active": "ZAP Executed — Thorough Active (deeper active scan, scope-guarded)",
            "not_configured": "Skipped — ZAP not configured (the zap service is unavailable / ZAP_ADDR unset)",
            "user_disabled": "Skipped — ZAP disabled by user (enable ZAP in scan setup to run the DAST pass)",
            "unavailable": "Skipped — ZAP enabled but unavailable (daemon not running); scan continued without it",
            "failed": "ZAP Failed — daemon error during the scan",
            "not_invoked": "ZAP Not Invoked — enabled but not scheduled for this run"}.get(
        (status or "not_configured"), "Skipped — ZAP not configured")


def _zap_badge(status: str) -> str:
    """Short one-word badge for the methodology metric card (robust to wording)."""
    return {"executed": "Run", "executed_passive": "Pass", "executed_safe_active": "Safe",
            "executed_thorough_active": "Deep", "not_configured": "Off", "user_disabled": "Off",
            "unavailable": "N/A", "failed": "Fail", "not_invoked": "Skip"}.get(status or "not_configured", "Off")


def _ledger_md(ledger: dict) -> list:
    """Markdown 'Methodology & Tool Ledger' — what ran, what was skipped and why,
    ZAP status, auth posture, AI usage. Satisfies the depth/coverage bar."""
    if not ledger:
        return []
    lines = ["## Methodology & Tool Ledger", ""]
    auth = "Authenticated (operator headers supplied)" if ledger.get("authenticated") else "Unauthenticated"
    strat = (ledger.get("strategy") or "").replace("_", "-") or "n/a"
    lines += [f"- **Execution strategy:** {strat}",
              f"- **AI calls used:** {ledger.get('ai_calls', 0)}",
              f"- **Authentication:** {auth}",
              f"- **ZAP (DAST):** {_zap_status_text(ledger.get('zap_status'))}", ""]
    tools = ledger.get("tools") or []
    if tools:
        lines += ["| Tool | Status | Calls | Findings | Note |", "|---|---|---|---|---|"]
        for t in tools:
            lines.append(f"| {t.get('tool','')} | {t.get('status','')} | {t.get('calls',0)} "
                         f"| {t.get('findings',0)} | {(t.get('note') or '').replace('|','/')} |")
        lines.append("")
    return lines


def _exec_summary_text(program, findings, leads, execution, counts) -> list:
    """Deterministic executive summary (used verbatim, or as a fallback when no AI
    wrap-up ran). Business-readable, and scrupulously honest about confirmation."""
    leads = leads or []
    n_conf, n_lead = len(findings), len(leads)
    rk = risk_score(findings)
    sev_bits = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low")
                if counts.get(s)]
    out = []
    if n_conf:
        worst = findings[0]                       # findings are severity-sorted (worst first)
        bi = business_impact(worst)
        consequence = ((bi[1] if bi else "") or str(worst.get("impact") or "")).strip()
        wsev = (worst.get("severity") or "").lower()
        # 1) headline ATTACK STORY — what a real attacker achieves, grounded in the worst CONFIRMED
        #    finding. The punch is in dramatising what is PROVEN, never in inflating the count.
        if consequence:
            out.append("Bottom line: " + (consequence[:1].lower() + consequence[1:]
                                          if consequence[:1].isupper() else consequence))
        # 2) the honest posture — proven, evidence-backed, confirmed-only score
        out.append(f"This assessment of {program} confirmed {n_conf} "
                   f"{'vulnerability' if n_conf == 1 else 'vulnerabilities'}"
                   + (f" ({', '.join(sev_bits)})" if sev_bits else "")
                   + " — every one reproduced with evidence — for a confirmed-risk posture of "
                     f"{rk['label']} ({rk['score']}/100).")
        # 3) the named issues, each proven below
        tops = ", ".join(f.get("title", "finding") for f in findings[:3])
        out.append(f"The most serious are {tops}. Each is proven below with a copy-paste reproduction.")
        # 4) why this matters NOW (only when there is a critical/high — keep it honest)
        if wsev in ("critical", "high"):
            out.append("Why this matters now: these are exploitable from the public internet today with "
                       "off-the-shelf tooling — an active exposure to close, not a backlog item to schedule.")
    else:
        out.append(f"This assessment of {program} confirmed no vulnerabilities with reproducible evidence — "
                   "and nothing was inflated to pad the report. The risk score reflects confirmed findings only.")
    if n_lead:
        out.append(f"Separately, {n_lead} unconfirmed lead{'s' if n_lead != 1 else ''} (static/candidate "
                   "signals) need manual verification before they count as vulnerabilities — listed apart, and "
                   "NOT included in the risk score.")
    return out


_HARDENING_RX = __import__("re").compile(
    r"content.security.policy|\bcsp\b|strict.transport|\bhsts\b|httponly|samesite|secure flag|"
    r"x-frame|clickjack|x-content-type|referrer.policy|permissions.policy|"
    r"\bspf\b|\bdmarc\b|\bcaa\b|dnssec|\bcors\b|cross-origin", __import__("re").I)


def hardening_summary(leads: list) -> list:
    """Consolidate the scattered response-header / cookie / DNS-email hardening LEADS
    (often dozens of duplicate ZAP alerts like 'CSP Not Set') into one compact posture
    list: (control, worst-severity, instance count). Truth-first — these are the same
    advisory leads, summarised (not new confirmed findings), so the risk score is
    unaffected. This is the one genuinely-missing presentation the market reports had."""
    import re as _re
    _rank = {"high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
    groups: dict = {}
    for l in leads or []:
        title = str(l.get("title") or "")
        if not _HARDENING_RX.search(title):
            continue
        name = _re.sub(r"^\s*zap:\s*", "", title, flags=_re.I).strip()
        name = _re.sub(r"\s*\(\d+\)\s*$", "", name)
        g = groups.setdefault(name, {"sev": "info", "n": 0})
        g["n"] += 1
        sev = (l.get("severity") or "info").lower()
        if _rank.get(sev, 0) > _rank.get(g["sev"], 0):
            g["sev"] = sev
    return sorted(([n, v["sev"], v["n"]] for n, v in groups.items()),
                  key=lambda r: (-_rank.get(r[1], 0), -r[2]))


def auth_requests_note(areq: dict) -> str:
    """Honest read of a 0-success authenticated pass, so 'succeeded 0' is never misread as a
    broken login. Distinguishes 'the session worked but there was no valid endpoint to test'
    (every candidate 4xx, e.g. 404 — the target exposes no testable object-endpoint) from a real
    auth rejection (401/403). Empty when some requests succeeded or none were attempted."""
    areq = areq or {}
    att = int(areq.get("attempted") or 0)
    suc = int(areq.get("succeeded") or 0)
    if not att or suc:
        return ""
    sd = areq.get("status_dist") or {}
    codes = [int(k) for k in sd.keys() if str(k).isdigit()]
    if codes and all(400 <= c < 500 for c in codes):
        if any(c in (401, 403) for c in codes):
            return ("session was rejected (401/403) on the tested endpoints — the credential may not "
                    "apply to these paths")
        return ("session established, but every authorization candidate returned 4xx (e.g. 404): the "
                "target exposes no testable object-endpoint here. This is NOT an authentication failure.")
    if not codes:
        return "no authenticated request reached a candidate endpoint"
    return ""


def _artery_with_note(aa: dict) -> dict:
    """Copy the auth artery, adding an honest note to authenticated_requests so JSON consumers and
    the UI Assurance panel can explain a 0-success authed pass rather than showing a bare 'succeeded 0'."""
    if not aa:
        return {"ran": False}
    areq = aa.get("authenticated_requests")
    note = auth_requests_note(areq) if isinstance(areq, dict) else ""
    if not note:
        return aa
    return {**aa, "authenticated_requests": {**areq, "note": note}}


_CVSS_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27}, "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss31_base_score(vector: str):
    """Deterministic CVSS 3.1 BASE score from a vector string (None if unparseable). Used by the
    integrity gate to catch a score that contradicts its own vector (CHAD final-audit defect #6)."""
    import math
    try:
        m = dict(p.split(":", 1) for p in str(vector).replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/") if ":" in p)
        av, ac, ui = _CVSS_W["AV"][m["AV"]], _CVSS_W["AC"][m["AC"]], _CVSS_W["UI"][m["UI"]]
        scope_c = m["S"] == "C"
        pr = _CVSS_W["PR_C" if scope_c else "PR_U"][m["PR"]]
        c, i, a = _CVSS_W["CIA"][m["C"]], _CVSS_W["CIA"][m["I"]], _CVSS_W["CIA"][m["A"]]
    except Exception:
        return None
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_c else (6.42 * iss)
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_c else 1.0) * (impact + expl), 10)
    return math.ceil(round(raw, 6) * 10) / 10.0   # CVSS "round up to 1 decimal"


def _netloc_repeats(url: str) -> bool:
    """True if a URL is malformed by a DUPLICATED host (scheme://host//host/… or the netloc appearing
    twice in the path) — the doubled-host bug CHAD final-audit defect #3 flagged."""
    from urllib.parse import urlparse
    try:
        p = urlparse(str(url))
        if not p.netloc:
            return False
        host = p.netloc.split("@")[-1].split(":")[0]
        # host name repeated inside the path (e.g. /ginandjuice.shop/resources/…), or a leading //host
        return bool(host) and (("/" + host + "/") in (p.path or "") or (p.path or "").startswith("//" + host))
    except Exception:
        return False


def _canon_url(url: str) -> str:
    """Collapse a duplicated host (scheme://host//host/… or a leading /host/ repeat) into one
    well-formed URL. Idempotent; leaves already-clean URLs untouched."""
    loc = str(url or "")
    if "://" not in loc:
        return loc
    try:
        scheme, rest = loc.split("://", 1)
        host = rest.split("/", 1)[0]
        path = rest[len(host):]
        h = host.split("@")[-1].split(":")[0]
        while h and (path.startswith("//" + h + "/") or path.startswith("/" + h + "/")):
            path = path[path.index(h) + len(h):]
        return scheme + "://" + host + path
    except Exception:
        return loc


def sanitize_finding_urls(findings: list) -> list:
    """Render-time guard: rewrite any duplicated-host URL in a finding's URL-bearing string fields
    (target/surface/location/curl and inline http(s) URLs in evidence/description). Fixes a finding
    restored from prior-scan MEMORY that was persisted before the crawler fix, so the shipped report
    (JSON and HTML alike) never prints a malformed URL (CHAD final-audit defect #3)."""
    def _fix_inline(s):
        return re.sub(r"https?://[^\s'\"<>)]+", lambda m: _canon_url(m.group(0)), str(s))
    out = []
    for f in findings or []:
        g = dict(f)
        for k in ("target", "surface", "location", "curl", "request"):
            if isinstance(g.get(k), str) and g[k]:
                g[k] = _canon_url(g[k]) if k in ("target", "surface", "location") else _fix_inline(g[k])
        for k in ("evidence", "description", "impact"):
            if isinstance(g.get(k), str) and "//" in g[k]:
                g[k] = _fix_inline(g[k])
        if isinstance(g.get("instances"), list):
            g["instances"] = [_canon_url(x) if isinstance(x, str) else x for x in g["instances"]]
        out.append(g)
    return out


def _cves_in(text) -> set:
    return set(re.findall(r"CVE-\d{4}-\d{4,7}", str(text or ""), re.I))


def report_integrity_check(findings: list, chains: list = None, candidate_validation: dict = None,
                           kev_cves=None) -> list:
    """Deterministic report-integrity GATES — returns a list of VIOLATIONS (empty == clean). Beyond
    field-presence, these are SEMANTIC cross-field checks (CHAD final-audit defect #6) enforced by the
    test suite AND run live at report time, so a deliberately bad fixture cannot pass:
      • HIGH/CRIT confirmed carries a CVSS vector/rationale; every confirmed has a repro AND oracle;
      • a credential/broken-auth repro actually AUTHENTICATES (POST + a password field), never a bare GET;
      • no finding URL (target/curl/location) carries a duplicated host;
      • no finding CLAIMS 'known-exploited/CISA KEV' unless it carries a CVE that is in the exact KEV set;
      • a CVSS score matches the score computed from its own vector (±0.5);
      • severity and CVSS band agree, or a rationale explains the gap;
      • a chain's narrative does not say 'prove/execute' while it is labelled unverified;
      • every candidate row is self-consistent (no confirmed-with-no-validator; unsupported reconciles);
      • no generic impact text is reused across unrelated families."""
    issues, findings = [], findings or []
    kevset = {str(x).upper() for x in (kev_cves or [])}
    for f in findings:
        title = f.get("title")
        sev = str(f.get("severity") or "").lower()
        conf = str(f.get("confidence") or "")
        fam = str(f.get("family") or "").lower()
        cwe = str(f.get("cwe") or "").upper()
        vec = str(f.get("cvss_vector") or "").strip()
        score = f.get("cvss_score")
        reps = f.get("reproduction_steps") or []
        curl = str(f.get("curl") or "")
        blob = " ".join(str(f.get(k) or "") for k in ("evidence", "description", "impact", "title")) + " " + " ".join(str(x) for x in (f.get("tags") or []))
        if sev in ("high", "critical") and conf == "confirmed":
            if not (vec or score or str(f.get("cvss_rationale") or "").strip()):
                issues.append("HIGH/CRITICAL finding without a CVSS vector or scoring rationale: %s" % title)
        if conf == "confirmed":
            has_oracle = bool(str(f.get("success_oracle") or "").strip()) or any("oracle" in str(s).lower() for s in reps)
            if not reps:
                issues.append("confirmed finding without reproduction steps: %s" % title)
            elif not has_oracle:
                issues.append("confirmed finding without a machine-checkable success oracle: %s" % title)
            # SEMANTIC: a credential / broken-auth proof must actually authenticate, not GET a page
            is_cred = fam in ("broken_auth", "exposed_credentials") or cwe == "CWE-522" or "credential" in str(title or "").lower()
            if is_cred:
                repro_txt = (curl + " " + " ".join(str(s) for s in reps)).lower()
                if "post" not in repro_txt or "password" not in repro_txt:
                    issues.append("credential/broken-auth finding whose reproduction does not authenticate (no POST + password field): %s" % title)
                if re.search(r"curl[^\n]*--path-as-is\s+'[^']+'\s*$", curl) or (curl and "post" not in curl.lower() and "-x" not in curl.lower() and "--data" not in curl.lower() and curl.count("\n") == 0):
                    issues.append("credential/broken-auth finding renders a bare GET reproduction: %s" % title)
        # SEMANTIC: URLs must be well-formed (no duplicated host anywhere the report will print them)
        for uk in ("target", "surface", "location", "curl"):
            uv = f.get(uk)
            for cand in ([uv] if isinstance(uv, str) else []):
                for tok in re.findall(r"https?://[^\s'\"<>]+", cand) or ([cand] if "://" in cand else []):
                    if _netloc_repeats(tok):
                        issues.append("finding carries a malformed URL with a duplicated host (%s): %s" % (uk, title))
                        break
        # SEMANTIC: a "known-exploited / CISA KEV" claim on a finding requires an EXACT CVE in the KEV set
        if kev_cves is not None and re.search(r"known[\s-]?exploited|cisa kev", blob, re.I):
            fcves = {c.upper() for c in _cves_in(blob) | _cves_in(f.get("cve")) | _cves_in(f.get("cves"))}
            if not (fcves & kevset):
                issues.append("finding claims 'known-exploited/CISA KEV' with no exact CVE present in the KEV set: %s" % title)
        # SEMANTIC: score must match the vector it is presented with (±0.5)
        if vec and isinstance(score, (int, float)):
            computed = cvss31_base_score(vec)
            if computed is not None and abs(computed - float(score)) > 0.5:
                issues.append("CVSS score %.1f disagrees with its vector (computes to %.1f): %s" % (float(score), computed, title))
        # SEMANTIC: severity band must agree with CVSS score unless a rationale explains the gap
        if isinstance(score, (int, float)) and not str(f.get("cvss_rationale") or "").strip():
            band = ("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info")
            _ok = {"critical": {"critical"}, "high": {"high"}, "medium": {"medium"}, "low": {"low", "info"}, "info": {"info", "low"}}
            if sev and sev in _ok and band not in _ok[sev]:
                issues.append("severity '%s' disagrees with CVSS %.1f (band '%s') and no rationale is given: %s" % (sev, float(score), band, title))
    for c in (chains or []):
        if "verified" not in c:
            issues.append("attack-path chain not labelled verified/hypothetical: %s" % (c.get("narrative") or c.get("name")))
        else:
            narr = (str(c.get("narrative") or "") + " " + str(c.get("summary") or "")).lower()
            # Overclaim only counts when it is AFFIRMATIVE and NOT accompanied by an explicit
            # disclaimer. Apolaki's honest chains always disclaim ("NOT a proven attack path",
            # "does not auto-execute", "infers", "co-located") — flagging those would be a false
            # positive (the colocated-chain disclaimer CHAD's re-run surfaced).
            overclaim = re.search(r"proves this|proven (?:attack )?path|auto-execute[sd]?|we (?:proved|executed)|apolaki (?:proves|proved)|executed the (?:exploit|attack|takeover|path)", narr)
            disclaimed = re.search(r"not a proven|does not auto-execute|does not execute|never (?:auto-)?execute|\binfers\b|co-located|co-present|no .*?\bwas executed\b|hypothetical|not proven", narr)
            if not c.get("verified") and overclaim and not disclaimed:
                issues.append("unverified chain narrates a PROVEN/executed path (wording overstates evidence): %s" % (c.get("name") or c.get("narrative")))
    seen = {}
    for f in findings:
        imp, fam = str(f.get("impact") or "").strip(), str(f.get("family") or "")
        if imp and imp in seen and seen[imp] != fam:
            issues.append("generic impact text reused across unrelated families (%s vs %s)" % (seen[imp], fam))
        elif imp:
            seen[imp] = fam
    # candidate-validation consistency + reconciliation
    cv = candidate_validation or {}
    recs = cv.get("records") or []
    counts = cv.get("counts") or {}
    if recs and "confirmed" not in counts:
        issues.append("candidate validation present but confirmed count missing (cannot reconcile)")
    for rc in recs:
        res = str(rc.get("result") or "").lower()
        val = str(rc.get("validator") or "").strip()
        orc = str(rc.get("oracle") or "").lower()
        cand = rc.get("candidate")
        # confirmed row must not simultaneously claim "no validator implemented"
        if res == "confirmed" and (not val or "no validator implemented" in orc) and not (rc.get("deduplicated") or rc.get("result_ref")):
            issues.append("candidate confirmed but its validator/oracle is empty or says 'no validator implemented': %s" % cand)
        # a row confirmed WITHOUT being independently attempted must name how it was confirmed
        if res == "confirmed" and rc.get("attempted") is False and not (rc.get("deduplicated") or rc.get("result_ref")):
            issues.append("candidate confirmed but not attempted and no confirming reference given: %s" % cand)
    # unsupported must be RECONCILED (surfaced in counts), never a hidden coverage debt
    n_unsupported = sum(1 for rc in recs if str(rc.get("result") or "").lower() == "unsupported")
    if n_unsupported and int(counts.get("unsupported", 0)) != n_unsupported:
        issues.append("unsupported candidate debt not reconciled in counts (%d rows vs counts=%s)" % (n_unsupported, counts.get("unsupported")))
    return issues


def reachability_warning(mode=None, attack_surface=None):
    """An ACTIVE/FULL scan that reached ZERO live hosts almost certainly never touched the
    target (a bare host defaults to https on :443; or the target is down / mis-scoped). Such a
    run must SAY SO: otherwise a clean-looking "complete" report with no findings reads as
    "target is secure" when it actually means "target was never tested". Returns a message
    string, or None when the run did reach a host (or was passive, where this does not apply)."""
    if (mode or "").lower() not in ("active", "full"):
        return None
    as_ = attack_surface or {}
    if "live_hosts" not in as_:
        return None
    try:
        if int(as_.get("live_hosts") or 0) > 0:
            return None
    except (TypeError, ValueError):
        return None
    return ("TARGET NOT REACHED: 0 live hosts. This active scan could not reach any in-scope host, "
            "so the results are passive recon plus prior intel only, NOT a live assessment. Check the "
            "scope carries a scheme and port (e.g. http://host:3000; a bare host defaults to https on "
            ":443) and that the target is up.")


def generate_html_report(program: str, findings: list, scope: dict,
                         coverage: dict = None, chains: list = None, status: str = None,
                         ai_summary: str = None, execution: dict = None, leads: list = None,
                         attack_surface: dict = None, playbook: list = None, mode: str = None,
                         delta: dict = None, tool_ledger: dict = None, report_id: str = None,
                         security_headers: list = None, intel: dict = None, kev_cwes: set = None,
                         kev_cves: set = None,
                         orchestration: dict = None, auth_artery: dict = None,
                         intel_provenance: dict = None, degraded: dict = None,
                         candidate_validation: dict = None) -> str:
    e = _html.escape
    leads = leads or []
    findings = sanitize_finding_urls(findings)   # collapse any duplicated-host URL from prior-scan memory
    raw_findings = _with_capec(findings)
    # Group duplicate findings by root cause (family + parameter). Counts, the risk
    # score and the cards all use the DISTINCT issues; every raw instance is kept on
    # each group's `instances` and listed in the affected-instances appendix.
    findings = group_findings(raw_findings)
    findings = sorted(findings, key=lambda f: SEV_ORDER.get((f.get("severity") or "informational").lower(), 5))
    counts = _counts(findings)
    rk = risk_score(findings)
    engagement = _ENGAGEMENT.get((mode or "").lower(), "Security Assessment")
    # Metric consistency: the Assessment Coverage tile must report the same UNIQUE finding
    # count as the headline, not the raw pre-grouping count (a CRLF on 2 endpoints is one
    # finding, not two). This kills the "6 confirmed vs 7 findings" contradiction.
    if isinstance(coverage, dict) and "findings" in coverage:
        coverage = {**coverage, "findings": len(findings)}

    # severity distribution bars (confirmed only)
    total_conf = len(findings) or 1
    dist_rows = ""
    for s in ("critical", "high", "medium", "low", "info"):
        n = counts.get(s, 0) + (counts.get("informational", 0) if s == "info" else 0)
        pct = int(100 * n / total_conf) if findings else 0
        dist_rows += (f"<div class='distrow'><span class='distlabel'>{s.upper()}</span>"
                      f"<span class='distbar'><i style='width:{pct}%;background:{SEV_COLORS[s]}'></i></span>"
                      f"<span class='distn'>{n}</span></div>")

    # Fix Now / Fix If / Strengthen — remediation ACTION priority ALONGSIDE technical severity (CVSS/CWE),
    # so the report answers "what to do first", not only how bad it is. Same pure classifier as the JSON.
    import remediation as _rem
    _fp = _rem.fix_priority_summary(findings, leads)["counts"]
    _fp_meta = [("fix_now", "Fix Now", "#e5484d", "confirmed, exploitable now"),
                ("fix_if", "Fix If", "#f5a623", "conditional / verify then fix"),
                ("strengthen", "Strengthen", "#4c9aff", "hardening / defense-in-depth")]
    _fp_cells = "".join(
        f"<div class='cov'><span style='color:{col}'>{_fp.get(k, 0)}</span><label>{lbl}</label>"
        f"<div class='sub' style='font-size:.7rem;line-height:1.2'>{desc}</div></div>"
        for k, lbl, col, desc in _fp_meta)
    fixpri_html = ("<h2 id='fixpriority'>Fix Priority</h2>"
                   "<div class='sub' style='margin:-.3rem 0 .5rem'>Remediation action priority — what to fix "
                   "first — shown ALONGSIDE technical severity (CVSS/CWE), never replacing it.</div>"
                   f"<div class='cov-grid'>{_fp_cells}</div>")

    # Coverage overview — of the security PROPERTIES Apolaki models, how many are confirmed-safe / vulnerable
    # / inconclusive / blocked / not-tested (rolled up from ASVS + WSTG + the candidate ledger). Truth-first:
    # a curated-partial model, never a full-coverage claim.
    _cr = coverage_rollup(raw_findings, tool_ledger, candidate_validation)
    _pp = _cr.get("properties") or {}
    _cov_meta = [("confirmed_safe", "Confirmed safe", "#3fb950"), ("vulnerable", "Vulnerable", "#e5484d"),
                 ("inconclusive", "Inconclusive", "#d29922"), ("blocked", "Blocked", "#8b949e"),
                 ("not_tested", "Not tested", "#6e7681")]
    _cov_cells = "".join(f"<div class='cov'><span style='color:{col}'>{_pp.get(k, 0)}</span><label>{lbl}</label></div>"
                         for k, lbl, col in _cov_meta) if _pp else ""
    _w = _cr.get("wstg") or {}
    _wstg_line = (f"<div class='sub' style='margin-top:.3rem'>WSTG active tests: {_w.get('tested', 0)}/"
                  f"{_w.get('total', 109)} covered ({_w.get('full', 0)} full, {_w.get('partial', 0)} partial), "
                  f"{_w.get('excluded', 0)} safety-excluded.</div>") if _w else ""
    cov_overview_html = (("<h2 id='coverage-overview'>Coverage Overview</h2>"
                          "<div class='sub' style='margin:-.3rem 0 .5rem'>Of the security properties Apolaki "
                          f"models ({_pp.get('total', 0)} ASVS objectives, curated-partial) — how many were "
                          "confirmed safe, found vulnerable, inconclusive, blocked, or not tested. Never a "
                          f"full-coverage claim.</div><div class='cov-grid'>{_cov_cells}</div>{_wstg_line}")
                         if _pp else "")

    # Business Logic Testing — headline capability: the workflows probed + abuse categories generated (the
    # tests a scanner can't derive), with confirmed vs hypothesis-to-verify outcomes.
    _bl = business_logic_view(raw_findings, leads)
    bizlogic_html = ""
    if _bl.get("tested"):
        _flows = ", ".join(e(f) for f in _bl["workflows"]) or "the discovered workflows"
        _cats = "".join(f"<span>{e(c)}</span>" for c in _bl["abuse_categories"])
        bizlogic_html = ("<h2 id='business-logic'>Business Logic Testing</h2>"
                         f"<div class='sub' style='margin:-.3rem 0 .5rem'>{e(_bl['note'])}</div>"
                         f"<p>Workflows probed: <b>{_flows}</b>. Abuse tests: "
                         f"<b>{_bl['confirmed']}</b> confirmed, <b>{_bl['hypotheses_to_verify']}</b> "
                         "hypotheses to verify (listed under Unconfirmed Leads).</p>"
                         f"<div class='meta'>{_cats}</div>")

    # attack surface metrics
    surf_html = ""
    if attack_surface:
        order = [("subdomains", "Subdomains"), ("live_hosts", "Live Hosts"),
                 ("endpoints", "Endpoints"), ("parameterized", "Parameterized"),
                 ("params", "Unique Params"), ("body_sinks", "XML/Body Sinks")]
        cells = "".join(f"<div class='cov'><span>{e(str(attack_surface.get(k, 0)))}</span><label>{lbl}</label></div>"
                        for k, lbl in order if k in attack_surface)
        if cells:
            surf_html = f"<h2 id='surface'>Attack Surface</h2><div class='cov-grid'>{cells}</div>"

    cov_html = ""
    if coverage:
        rows = "".join(f"<div class='cov'><span>{e(str(v))}</span><label>{e(k.replace('_',' '))}</label></div>"
                       for k, v in coverage.items())
        cov_html = f"<h2 id='coverage'>Assessment Coverage</h2><div class='cov-grid'>{rows}</div>"

    # Risk Signals — multi-axis executive view absorbed from the reference dashboards,
    # kept truth-first: descriptive signals only, the confirmed-only score stays the
    # authoritative posture. Each bar shows the factual basis it was computed from.
    signals_html = ""
    _sig = risk_signals(findings, leads, coverage, attack_surface, chains or [])
    if _sig:
        def _sig_color(p):
            return SEV_COLORS["high"] if p >= 70 else SEV_COLORS["medium"] if p >= 40 else "#00b8d4"
        sig_rows = "".join(
            f"<div class='distrow'><span class='distlabel'>{e(s['label'])}</span>"
            f"<span class='distbar'><i style='width:{int(s['pct'])}%;background:{_sig_color(s['pct'])}'></i></span>"
            f"<span class='distn'>{int(s['pct'])}</span></div>"
            f"<div class='sub' style='margin:-4px 0 10px 0'>{e(s['basis'])}</div>"
            for s in _sig)
        signals_html = ("<h2 id='signals'>Risk Signals</h2>"
                        "<p class='sub'>Descriptive, factual signals about this engagement. The confirmed-only "
                        "score above stays authoritative &mdash; these signals never change it.</p>"
                        f"<div class='dist' style='max-width:none'>{sig_rows}</div>")

    # ── absorbed from the reference reports' client-facing polish: Rules of Engagement
    #    block + CVSS score distribution (kept truth-first — buckets the CONFIRMED findings'
    #    estimated CVSS, no inflation). ──
    roe_html = (
        "<h2 id='roe'>Rules of Engagement</h2><div class='cov-grid'>"
        f"<div class='cov'><span>{e((mode or 'n/a').title())}</span><label>Assessment mode</label></div>"
        "<div class='cov'><span>Authorized</span><label>Engagement basis</label></div>"
        "<div class='cov'><span>Scope-enforced</span><label>Targeting</label></div>"
        "<div class='cov'><span>Non-destructive</span><label>Impact policy</label></div>"
        "<div class='cov'><span>CONFIDENTIAL</span><label>Classification</label></div></div>"
        "<p class='sub'>Testing is limited to in-scope hosts, enforced at the tool wrapper. Intrusive actions are "
        "gated by operator approval; no denial-of-service and no irreversible changes are performed. Authorized "
        "security assessment only.</p>")
    _buckets = {"Critical (9.0-10)": 0, "High (7.0-8.9)": 0, "Medium (4.0-6.9)": 0, "Low (0.1-3.9)": 0}
    _bcol = {"Critical (9.0-10)": "critical", "High (7.0-8.9)": "high", "Medium (4.0-6.9)": "medium", "Low (0.1-3.9)": "low"}
    for f in findings:
        cv = estimated_cvss(f)
        try:
            s = float(cv[0]) if cv else 0.0
        except (TypeError, ValueError):
            s = 0.0
        if s >= 9:
            _buckets["Critical (9.0-10)"] += 1
        elif s >= 7:
            _buckets["High (7.0-8.9)"] += 1
        elif s >= 4:
            _buckets["Medium (4.0-6.9)"] += 1
        elif s > 0:
            _buckets["Low (0.1-3.9)"] += 1
    cvss_html = ""
    if any(_buckets.values()):
        _tot = sum(_buckets.values()) or 1
        _rows = "".join(
            f"<div class='distrow'><span class='distlabel'>{k}</span>"
            f"<span class='distbar'><i style='width:{int(100 * v / _tot)}%;background:{SEV_COLORS[_bcol[k]]}'></i></span>"
            f"<span class='distn'>{v}</span></div>" for k, v in _buckets.items())
        cvss_html = f"<h2 id='cvss'>CVSS Score Distribution</h2><div class='dist' style='max-width:none'>{_rows}</div>"

    # Security Headers Coverage — absorbed from the reference reports. Factual: which
    # protective response headers were seen across probed hosts (present vs missing).
    sechdr_html = ""
    if security_headers:
        rows = ""
        for h in security_headers:
            pct = int(100 * h.get("present", 0) / max(1, h.get("total", 1)))
            col = SEV_COLORS["low"] if pct >= 80 else SEV_COLORS["medium"] if pct >= 40 else SEV_COLORS["high"]
            rows += (f"<div class='distrow'><span class='distlabel'>{e(h.get('header', ''))}</span>"
                     f"<span class='distbar'><i style='width:{pct}%;background:{col}'></i></span>"
                     f"<span class='distn'>{h.get('present', 0)}/{h.get('total', 0)}</span></div>")
        sechdr_html = ("<h2 id='secheaders'>Security Headers Coverage</h2>"
                       "<p class='sub'>Protective response headers observed across probed hosts. Low coverage on "
                       "CSP / HSTS / X-Frame-Options / X-Content-Type-Options is a hardening gap.</p>"
                       f"<div class='dist' style='max-width:none'>{rows}</div>")

    # CVE Intelligence — absorbed from the reference reports. Aggregates every CVE named in
    # confirmed findings + leads (from dependency/vulnerable-component detection).
    import re as _re2
    _cve_map = {}
    for _f in (findings + (leads or [])):
        _blob = (str(_f.get("title", "")) + " " + str(_f.get("description", "")) + " " + str(_f.get("evidence", "")))
        for _c in set(_re2.findall(r"CVE-\d{4}-\d{4,7}", _blob)):
            _cve_map.setdefault(_c, {"where": _f.get("title", ""), "sev": (_f.get("severity") or "info")})
    cve_html = ""
    if _cve_map:
        _rows = "".join(
            f"<tr><td><code>{e(c)}</code></td><td>{e(v['where'][:70])}</td>"
            f"<td><span class='sev' style='background:{SEV_COLORS.get(v['sev'].lower(), '#6a8a9a')}'>{e(v['sev'].upper())}</span></td></tr>"
            for c, v in sorted(_cve_map.items()))
        cve_html = ("<h2 id='cve'>CVE Intelligence</h2>"
                    f"<p class='sub'>{len(_cve_map)} CVE(s) identified from vulnerable components and behaviour.</p>"
                    "<table class='cve-tbl' style='width:100%;border-collapse:collapse;font-size:.85rem'>"
                    "<tr style='text-align:left;color:var(--muted)'><th>CVE</th><th>Source finding</th><th>Severity</th></tr>"
                    f"{_rows}</table>")

    # Target Intelligence — what the target itself leaked, harvested from its own surface
    # (DOM/JS/source-maps/API). The raw material a general technique consumes as fixtures
    # (the OSINT / source-review loop). Noisy 'encoded' bucket is intentionally not shown.
    intel_html = ""
    if intel and (intel.get("candidates") or {}):
        _SHOW = [("decoded", "Decoded values"), ("email", "Emails"), ("username", "Usernames"),
                 ("object_id", "Object IDs"), ("route", "Routes"), ("endpoint", "Endpoints"),
                 ("param", "Parameters"), ("url", "External URLs"), ("coupon", "Coupons"),
                 ("version", "Versions"), ("secret", "Secrets (redacted)"), ("comment", "Dev comments"),
                 ("hint", "Hints")]
        _cand = intel.get("candidates", {})
        _rows = ""
        for _k, _label in _SHOW:
            _vals = _cand.get(_k) or []
            if not _vals:
                continue
            _sample = ", ".join(e(str(v)) for v in _vals[:12])
            _more = len(_vals) - 12
            _moretxt = (" <span class='sub'>(+" + str(_more) + " more)</span>") if _more > 0 else ""
            _rows += ("<tr><td style='white-space:nowrap'><b>" + e(_label) + "</b></td>"
                      "<td>" + str(len(_vals)) + "</td>"
                      "<td style='font-family:monospace;font-size:.8rem'>" + _sample + _moretxt + "</td></tr>")
        if _rows:
            intel_html = ("<h2 id='intel'>Target Intelligence</h2>"
                          "<p class='sub'>Candidates harvested from the target's own surface (DOM, JS, source maps, "
                          "API responses) — the clues the target leaks, and the raw material a general technique "
                          "consumes as run-time fixtures. Derived live from the target, not hardcoded. Secrets redacted.</p>"
                          "<table style='width:100%;border-collapse:collapse;font-size:.85rem'>"
                          "<tr style='text-align:left;color:var(--muted)'><th>Kind</th><th>Count</th><th>Sample</th></tr>"
                          + _rows + "</table>")

    # confirmed findings — full proof density (grouped by root cause)
    cards = []
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "informational").lower()
        color = SEV_COLORS.get(sev, "#6a8a9a")
        # impact + steps always render (no blank HIGH card); fall back to family text.
        fam = _family_of(f)
        impact = str(f.get("impact") or "").strip() or (business_impact(f)[1] if business_impact(f) else
                 "See technical detail; impact depends on how the affected input is used downstream.")
        rsteps = f.get("reproduction_steps") or []
        if not rsteps:
            rsteps = ["Send the request shown in the reproduction command below.",
                      "Observe the confirming response in the evidence block.",
                      "Compare against a benign baseline to rule out a false positive."]
        steps = "".join(f"<li>{e(str(s))}</li>" for s in rsteps)
        ev = f"<h4>Evidence</h4><pre class='ev'>{e(str(f.get('evidence','')))}</pre>" if f.get("evidence") else ""
        # raw proof artifacts (request/response/tool log/timing) — the hard proof
        raw_html = "".join(f"<h4>{e(lbl)}</h4><pre class='ev'>{e(txt)}</pre>" for lbl, txt in evidence_items(f))
        # browser PoC: an embedded viewport screenshot (visual proof the bug fired in a
        # real headless browser) + a DOM snippet around the confirmation marker. Present
        # only on browser-confirmed findings (DOM audit); self-contained base64 data-URI.
        poc_html = ""
        _shot = str(f.get("screenshot") or "")
        if _shot.startswith("data:image/"):
            poc_html += ("<h4>Proof of concept (browser screenshot)</h4>"
                         f"<img alt='browser proof-of-concept screenshot' src='{e(_shot)}' "
                         "style='max-width:100%;height:auto;border:1px solid var(--border);border-radius:6px'>")
        if str(f.get("dom_snippet") or "").strip():
            poc_html += ("<h4>DOM proof (rendered markup at the sink)</h4>"
                         f"<pre class='ev'>{e(str(f.get('dom_snippet')))}</pre>")
        prov = proof_provenance(f)
        prov_html = f"<span>Tool &amp; settings: <code>{e(prov)}</code></span>" if prov else ""
        fpc = str(f.get("false_positive_check") or "").strip()
        fpc_html = f"<h4>False-positive check</h4><p>{e(fpc)}</p>" if fpc else ""
        # canonical classification: the finding's own CWE wins; only show the triage
        # note when it does NOT contradict it (kills the CWE-1104-vs-CWE-79 mismatch).
        note_txt = str(f.get("analyst_notes") or "")
        cwe = str(f.get("cwe") or "")
        if cwe and note_txt and ("cwe-" in note_txt.lower()) and (cwe.lower() not in note_txt.lower()):
            note_txt = ""
        notes = f"<p class='notes'>Triage: {e(note_txt)}</p>" if note_txt.strip() else ""
        # browser-confirmed bugs (DOM/CSTI/proto/redirect/XSS): the PROOF is the headless
        # browser evidence, NOT curl. Demote curl to a supplemental page-load request so it
        # is never mistaken for the reproduction of client-side execution.
        _ev_txt = str(f.get("evidence", ""))
        dom_confirmed = ("dom" in (f.get("tags") or [])) or ("Chromium" in _ev_txt) or ("rendered" in _ev_txt.lower())
        curl = finding_curl(f)
        if not curl:
            curl_html = ""
        elif dom_confirmed:
            curl_html = (f"<h4>Supplemental request (page load only — not the proof)</h4>"
                         f"<pre class='ev'>{e(curl)}</pre>"
                         f"<p class='sub'>This bug is confirmed in a real headless browser (see Evidence above); "
                         f"curl only fetches the page and cannot demonstrate client-side execution.</p>")
        else:
            curl_html = f"<h4>Reproduction (copy-paste)</h4><pre class='ev'>{e(curl)}</pre>"
        cv = estimated_cvss(f)
        cvss_disp = f"{cv[0]}{' (est.)' if cv[2] else ''}" if cv else "N/A"
        cvss_vec = f"<span>Vector: <code>{e(cv[1])}</code></span>" if (cv and cv[1]) else ""
        # CVSS-vs-evidence honesty: when a class-baseline CVSS assumes worst-case
        # (Integrity/Availability impact) but the test only DEMONSTRATED read access, say so —
        # never claim more impact than was proven.
        _evl = str(f.get("evidence", "")).lower()
        cvss_basis = ""
        if cv and cv[2] and ("read-only" in _evl or "no data dumped" in _evl or "read access" in _evl):
            cvss_basis = ("<span class='sub'>CVSS reflects the vulnerability class's full potential; the impact "
                          "<b>demonstrated in this test was read-only</b> (write/RCE not attempted per rules of engagement).</span>")
        rem = f"<h4>Remediation</h4><p>{e(remediation_line(f))}</p>"
        # T5: the design-level layer, in the HTML deliverable too — the markdown and HTML reports are
        # separate renderers, so shipping this in only one would give two different answers to the same
        # question depending on export format.
        rem += _remediation_depth_html(f, e)
        val = f"<h4>Validation After Fix (regression test)</h4><p>{e(validation_line(f))}</p>"
        inst = [x for x in (f.get("instances") or []) if x and x != f.get("target")]
        inst_html = ("<h4>Affected instances (" + str(len(inst) + 1) + ")</h4><ul>"
                     + "".join(f"<li><code>{e(str(x))}</code></li>" for x in [f.get('target')] + inst)
                     + "</ul>") if inst else ""
        bi = business_impact(f)
        biz_html = ""
        if bi:
            biz_html = (f"<div class='biz'><h4>Why This Matters (plain English)</h4>"
                        f"<p><b>What it is:</b> {e(bi[0])}</p>"
                        f"<p><b>If left unpatched:</b> {e(bi[1])}</p></div>")
        _g = graded_business_impact(f)
        graded_html = ""
        if _g:
            graded_html = (f"<div class='biz'><h4>Impact (evidence-graded)</h4>"
                           f"<p><b>Demonstrated:</b> {e(_g['demonstrated'])}</p>"
                           f"<p><b>Plausible next step:</b> {e(_g['plausible'])}</p>"
                           f"<p><b>Unverified worst case:</b> {e(_g['unverified'])}</p>"
                           f"<p class='sub'>Confidence: {e(str(_g['confidence']))} — {e(_g['assumptions'])}</p></div>")
        _pr = proof_and_retest(f)
        pr_html = (f"<div class='biz'><h4>How this was confirmed (false-positive safety)</h4>"
                   f"<p>{e(_pr['negative_control'])}</p>"
                   f"<h4>Retest / closure</h4><p>{e(_pr['retest'])}</p></div>")
        # Evidence-dossier chips: the remediation-action priority + the ASVS objective(s)/WSTG test this
        # finding violates — composed from the SAME primitives the downloadable poc-bundle uses (no island).
        import remediation as _remmod
        import poc_bundle as _pbmod
        _fp = _remmod.fix_priority(f)
        _fpcol = {"fix_now": "#e5484d", "fix_if": "#f5a623", "strengthen": "#4c9aff"}.get(_fp["tier"], "#888")
        _fp_chip = f"<span style='background:{_fpcol};color:#fff'>{e(_fp['label'])}</span>"
        _std = _pbmod.standards(f)
        _asvs_chip = ("<span>ASVS: " + e(", ".join(a["cid"] for a in _std["asvs"][:3])) + "</span>") if _std.get("asvs") else ""
        _wstg_chip = f"<span>WSTG: {e(str(_std['wstg']))}</span>" if _std.get("wstg") else ""
        # "a public exploit exists for this" belongs ON the finding, not only in a section at the end
        _edb_chip = ""
        try:
            import intel_feeds as _ifm
            _x = _ifm.exploits_for_finding(_ifm.load(), f)
            if _x.get("available"):
                _exact = _x["match"] == "cve"
                _edb_chip = ("<span style='background:%s;color:#fff' title='%s'>PUBLIC EXPLOIT%s</span>"
                             % ("#e5484d" if _exact else "#c98a2b",
                                e(str(_x.get("confidence", ""))), "" if _exact else " (lead)"))
        except Exception:
            _edb_chip = ""
        cards.append(f"""
        <article class="finding" style="--c:{color}">
          <div class="fh"><span class="sev">{e(sev.upper())}</span><h3>{i}. {e(str(f.get('title','Untitled')))}</h3></div>
          <div class="meta">
            <span>Target: <code>{e(str(f.get('target','')))}</code></span>
            <span>CVSS: {e(cvss_disp)}</span>
            <span>CWE: {e(cwe or 'N/A')}</span>
            {f"<span>CAPEC: {e(str(f.get('capec')))}</span>" if f.get('capec') else ''}
            {f"<span>OWASP: {e(_owasp_of(f))}</span>" if _owasp_of(f) else ''}
            {cvss_vec}
            {prov_html}
            <span class="tag-conf">CONFIRMED</span>
            {_fp_chip}{_asvs_chip}{_wstg_chip}{_edb_chip}
          </div>
          {cvss_basis}
          {biz_html}
          <h4>Technical detail</h4><p>{e(str(f.get('description','')))}</p>
          <h4>Impact</h4><p>{e(impact)}</p>
          {graded_html}
          {pr_html}
          {browser_evidence_html(f, e)}
          <h4>Steps to Reproduce</h4><ol>{steps}</ol>
          {curl_html}{ev}{raw_html}{poc_html}{fpc_html}{inst_html}{rem}{val}{notes}
        </article>""")
    findings_html = "".join(cards) if cards else (
        "<p class='sub'>No vulnerability was confirmed with reproducible evidence during this engagement. "
        "See Unconfirmed Leads below for signals that need manual verification.</p>")

    # priority remediation table (confirmed, severity-ordered, real fixes)
    rem_html = ""
    if findings:
        rrows = "".join(
            f"<tr><td>{i}</td><td><span class='sev' style='--c:{SEV_COLORS.get((f.get('severity') or 'info').lower(),'#6a8a9a')}'>"
            f"{e((f.get('severity') or 'info').upper())}</span></td><td>{e(str(f.get('title','')))}</td>"
            f"<td>{e(remediation_line(f))}</td></tr>"
            for i, f in enumerate(findings, 1))
        rem_html = ("<h2 id='remediation'>Priority Remediation</h2>"
                    "<table class='tbl'><tr><th>#</th><th>Severity</th><th>Finding</th><th>Fix</th></tr>"
                    + rrows + "</table>")

    # attack paths + chaining potential
    chain_html = ""
    if chains:
        # Dedup near-identical chains (same root → same outcome) and drop malformed nodes
        # (no narrative) so the section is not padded with duplicate SQLi paths or a raw dict.
        _cseen, _cclean = set(), []
        for _c in chains:
            _nar = str(_c.get("narrative") or "").strip()
            if not _nar:
                continue
            _parts = [p.strip().lower() for p in re.split(r"→|->", _nar) if p.strip()]
            _key = (_parts[0] if _parts else _nar.lower(), _parts[-1] if _parts else "")
            if _key in _cseen:
                continue
            _cseen.add(_key)
            _cclean.append(_c)
        chains = _cclean
    if chains:
        def _chain_li(c):
            _k = c.get("kind")
            ver = bool(c.get("verified"))
            badge = ("<span class='tag-conf' style='background:#1f9d6b'>VERIFIED</span>" if ver
                     else "<span class='tag-conf' style='background:#c98a2b'>PLAUSIBLE &mdash; hypothesis</span>")
            colo = " <span class='tag-conf' style='background:#7d8590'>CO-LOCATED (not a path)</span>" if _k == "colocated" else ""
            dataf = " <span class='tag-conf' style='background:#c0563a'>DATA-FLOW</span>" if _k == "dataflow" else ""
            colo += " <span class='tag-conf' style='background:#6a5acd'>POTENTIAL</span>" if _k == "potential" else ""
            summ = str(c.get("summary") or "").strip()
            basis = str(c.get("basis") or "").strip()
            missing = str(c.get("missing") or "").strip()
            extra = (f"<div class='sub' style='margin:.2rem 0 0 .2rem'>{e(summ)}</div>" if summ else "")
            if not ver and (basis or missing):
                extra += (f"<div class='sub' style='margin:.15rem 0 0 .2rem;font-size:.72rem'>"
                          f"<b>Basis:</b> {e(basis or 'inference from confirmed findings')} &middot; "
                          f"<b>To verify:</b> {e(missing or 'execute the step transition')}</div>")
            return (f"<li>{badge}{colo}{dataf} <b>{e(str(c.get('host')))}</b> "
                    f"<span class='sev' style='--c:{SEV_COLORS.get((c.get('severity') or '').lower(),'#6a8a9a')}'>"
                    f"{e(str((c.get('severity') or '').upper()))}</span> &mdash; <b>{e(str(c.get('narrative')))}</b>"
                    f"{extra}</li>")
        _nver = sum(1 for c in chains if c.get("verified"))
        items = "".join(_chain_li(c) for c in chains)
        chain_html = ("<h2 id='paths'>Attack-Path Chains &amp; Chaining Potential</h2>"
                      "<p class='sub'>These paths are <b>hypotheses inferred from co-present CONFIRMED findings</b> "
                      "&mdash; Apolaki does not execute the transition between steps (destructive + authorization-gated), "
                      "so a path is <b>PLAUSIBLE</b> unless explicitly <b>VERIFIED</b> (%d verified here). Each carries its "
                      "basis and exactly what must be proven to verify it end-to-end; <b>CO-LOCATED</b> means the findings "
                      "merely share a host and are not a path.</p>"
                      "<ul class='chains'>%s</ul>" % (_nver, items))

    # unconfirmed leads (Apolaki's honesty edge — kept distinct + labelled)
    leads_html = ""
    if leads:
        # Dedup: collapse repeated leads (same title) into ONE row with an instance count and
        # the affected-endpoint total, so the list is not padded with "AngularJS ng-app x3".
        _lg = {}
        for l in leads:
            k = (l.get("title", "").strip().lower(), (l.get("severity") or "info").lower())
            g = _lg.setdefault(k, {"l": l, "targets": []})
            t = l.get("target", "")
            if t and t not in g["targets"]:
                g["targets"].append(t)
        _uniq = [{**v["l"], "_n": max(1, len(v["targets"])), "_first": (v["targets"][0] if v["targets"] else v["l"].get("target", ""))}
                 for v in _lg.values()]
        def _lead_row(l):
            n = l.get("_n", 1)
            cnt = (" <span class='muted'>x" + str(n) + "</span>") if n > 1 else ""
            more = (" <span class='muted'>+" + str(n - 1) + " more</span>") if n > 1 else ""
            col = SEV_COLORS.get((l.get("severity") or "info").lower(), "#6a8a9a")
            return ("<tr><td><span class='sev' style='--c:" + col + "'>"
                    + e((l.get("severity") or "info").upper()) + "</span></td><td>"
                    + e(l.get("confidence", "candidate")) + "</td><td>"
                    + e(l.get("title", "")) + cnt + "</td><td><code>"
                    + e(l["_first"]) + "</code>" + more + "</td></tr>")
        rows = "".join(_lead_row(l) for l in sorted(_uniq, key=lambda x: SEV_ORDER.get((x.get("severity") or "info").lower(), 5)))
        leads_html = (f"<h2 id='leads'>Unconfirmed Leads ({len(_uniq)})</h2><p class='sub'>Signals worth manual verification — "
                      "<strong>NOT confirmed vulnerabilities</strong> and NOT counted in the risk score. "
                      "Confirm before reporting to a program.</p>"
                      "<table class='tbl'><tr><th>Severity</th><th>Confidence</th><th>Lead</th><th>Target</th></tr>"
                      + rows + "</table>")

    # Security Hardening Summary — consolidate the scattered header/cookie/DNS hardening
    # leads (dozens of duplicate ZAP alerts) into one compact posture table.
    hard_html = ""
    _hard = hardening_summary(leads)
    if _hard:
        hbody = "".join(
            f"<tr><td><span class='sev' style='--c:{SEV_COLORS.get(sev, '#6a8a9a')}'>{e(sev.upper())}</span></td>"
            f"<td>{e(name)}</td><td>{n}</td></tr>" for name, sev, n in _hard)
        hard_html = ("<h2 id='hardening'>Security Hardening Summary</h2>"
                     "<p class='sub'>Response-header, cookie and DNS/email hardening gaps, consolidated and "
                     "de-duplicated from the advisory leads. These are hardening improvements, <strong>not "
                     "confirmed exploits</strong>, and do not affect the risk score.</p>"
                     "<table class='tbl'><tr><th>Severity</th><th>Control / gap</th><th>Instances</th></tr>"
                     + hbody + "</table>")

    # manual-testing playbook (Round Table strength — what/how/cURL per surface)
    pb_html = ""
    if playbook:
        blocks = []
        for p in playbook[:12]:
            how = "".join(f"<li>{e(str(s))}</li>" for s in (p.get("how_to_test") or [])[:4])
            curls = "".join(f"<pre class='ev'>{e(str(c.get('cmd') if isinstance(c, dict) else c))}</pre>"
                            for c in (p.get("curl_steps") or [])[:2])
            pays = ", ".join(e(str(x)) for x in (p.get("payloads") or [])[:4])
            vuln_if = "".join(f"<li>{e(str(s))}</li>" for s in (p.get("vulnerable_if") or [])[:5])
            safe_if = "".join(f"<li>{e(str(s))}</li>" for s in (p.get("safe_if") or [])[:5])
            fp = p.get("false_positive_check") or ""
            tmpl = p.get("evidence_template") or ""
            sev = (p.get("severity") or "info").lower()
            blocks.append(
                f"<details class='pb'><summary><span class='sev' style='--c:{SEV_COLORS.get(sev,'#6a8a9a')}'>"
                f"{e(sev.upper())}</span> {e(str(p.get('title','')))} "
                f"<span class='sub'>{e(str(p.get('wstg','')))}</span></summary>"
                + (f"<p>{e(str(p.get('what_to_test','')))}</p>" if p.get('what_to_test') else "")
                + (f"<h4>How to test</h4><ol>{how}</ol>" if how else "")
                + (f"<h4>Payloads</h4><p><code>{pays}</code></p>" if pays else "")
                + (f"<h4>cURL</h4>{curls}" if curls else "")
                + (f"<h4>Vulnerable if</h4><ul class='vuln'>{vuln_if}</ul>" if vuln_if else "")
                + (f"<h4>Safe / inconclusive if</h4><ul class='safe'>{safe_if}</ul>" if safe_if else "")
                + (f"<h4>False-positive check</h4><p class='sub'>{e(str(fp))}</p>" if fp else "")
                + (f"<h4>Evidence to capture</h4><pre class='ev'>{e(str(tmpl))}</pre>" if tmpl else "")
                + "</details>")
        pb_html = ("<h2 id='playbook'>Manual Testing Playbook</h2>"
                   "<p class='sub'>Per-surface PoC walkthroughs — what to test, how, payloads, cURL, how to "
                   "READ the result (vulnerable vs safe), a false-positive check, and an evidence template. "
                   "These are manual test recommendations, not confirmed findings.</p>" + "".join(blocks))

    # appendix: tools + severity definitions
    tools_used = sorted({str(p.get("tool")) for p in []})  # reserved
    sevdefs = "".join(f"<tr><td><span class='sev' style='--c:{SEV_COLORS[s]}'>{s.upper()}</span></td><td>{d}</td></tr>"
                      for s, d in (("critical", "Direct, reliable path to full compromise or mass data loss."),
                                   ("high", "Serious impact (data exposure, auth bypass, injection) — fix urgently."),
                                   ("medium", "Meaningful weakness, usually needs a precondition or chain."),
                                   ("low", "Minor / hardening issue with limited standalone impact."),
                                   ("info", "Observation with no direct security impact.")))
    appendix = ("<h2 id='appendix'>Appendix — Severity Definitions</h2>"
                f"<table class='tbl'><tr><th>Level</th><th>Meaning</th></tr>{sevdefs}</table>")

    # root-cause summary — group confirmed findings by architectural weakness, not symptom
    rootcause_html = ""
    _rcg = root_cause_groups(findings)
    if _rcg and len(findings) > 1:
        rrows = "".join(
            f"<tr><td><span class='sev' style='--c:{SEV_COLORS.get(g['worst'], '#6a8a9a')}'>{e(g['worst'].upper())}</span></td>"
            f"<td><b>{e(g['root_cause'])}</b></td><td>{g['count']}</td>"
            f"<td class='sub'>{e(', '.join(g['titles'][:4]))}{'…' if len(g['titles']) > 4 else ''}</td></tr>"
            for g in _rcg)
        rootcause_html = ("<h2 id='rootcause'>Root-Cause Summary</h2>"
                          "<p class='sub'>The confirmed findings grouped by the underlying architectural weakness "
                          "rather than the symptom — fix the cause and multiple findings close at once.</p>"
                          "<table class='tbl'><tr><th>Severity</th><th>Root cause</th><th>Findings</th>"
                          "<th>Manifestations</th></tr>" + rrows + "</table>")

    # CISA KEV context — a finding is "known-exploited in the wild" ONLY when its EXACT CVE is in
    # CISA's KEV catalog (KEV is CVE-indexed; NEVER inferred from CWE class). A finding with no CVE,
    # or with a CVE not in the catalog, is explicitly reported as "not identified in KEV".
    kev_html = ""
    _kevset = {str(c).upper() for c in (kev_cves or set())}
    if findings and _kevset:
        _kev_hits, _no_cve, _checked = [], 0, 0
        for f in findings:
            _blob = "%s %s %s" % (f.get("cve") or "", f.get("cves") or "", f.get("evidence") or "")
            _cves = {m.upper() for m in re.findall(r"CVE-\d{4}-\d{3,7}", _blob, re.I)}
            if not _cves:
                _no_cve += 1
                continue
            _checked += 1
            _hit = sorted(c for c in _cves if c in _kevset)
            if _hit:
                _kev_hits.append((", ".join(_hit), f.get("title", "finding")))
        if _kev_hits:
            _krows = "".join("<tr><td><b>%s</b></td><td class='sub'>%s</td></tr>" % (e(c), e(t)) for c, t in _kev_hits)
            kev_html = ("<h2 id='kev'>Known-Exploited in the Wild (CISA KEV)</h2>"
                        "<p class='sub'>%d finding(s) carry a CVE that appears by EXACT id in CISA's KEV catalog "
                        "(under active exploitation in the wild). Matched by exact CVE only, never by CWE class.</p>"
                        "<table class='tbl'><tr><th>CVE</th><th>Confirmed finding</th></tr>%s</table>" % (len(_kev_hits), _krows))
        else:
            kev_html = ("<h2 id='kev'>Known-Exploited in the Wild (CISA KEV)</h2>"
                        "<p class='sub'>Not identified in KEV: no confirmed finding carries a CVE present in CISA's "
                        "Known Exploited Vulnerabilities catalog (%d finding(s) had a CVE checked by exact id; %d "
                        "carry no CVE and cannot be KEV-listed). KEV status is matched by exact CVE only, never "
                        "inferred from CWE class.</p>" % (_checked, _no_cve))

    # PUBLIC EXPLOIT AVAILABILITY (#112). A defect with a working public exploit is a different
    # operational emergency from one without: it is reachable by anyone, today, with no development
    # effort. Matched by EXACT CVE (strong) or by product+version in the exploit title (a lead, and
    # labelled as one). Index only — no exploit code is ever fetched or run by Apolaki.
    edb_html = ""
    try:
        import intel_feeds as _if
        _snaps = _if.load()
        if (_snaps.get("exploitdb") or {}).get("by_cve"):
            _rows, _lead = [], 0
            for f in findings:
                x = _if.exploits_for_finding(_snaps, f)
                if not x.get("available"):
                    continue
                if x["match"] != "cve":
                    _lead += 1
                _rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td class='sub'>%s</td></tr>"
                             % (e(str(f.get("title", ""))[:70]),
                                ("<b style='color:#e5484d'>EXACT CVE</b>" if x["match"] == "cve"
                                 else "<span style='color:#c98a2b'>product+version (lead)</span>"),
                                e(", ".join(x.get("cves") or []) or "—"),
                                e("; ".join("EDB-%s %s" % (n["edb_id"] if "edb_id" in n else n.get("id"),
                                                           n.get("title", ""))
                                            for n in x["entries"][:3]))))
            if _rows:
                edb_html = ("<h2 id='exploits'>Public Exploit Available</h2>"
                            "<p class='sub'>%d confirmed finding(s) correspond to a PUBLIC exploit in the "
                            "Exploit-DB index — no attacker needs to develop anything. %d matched by exact "
                            "CVE; %d are product+version leads from the exploit title and are NOT proof "
                            "that the exploit applies to this host. Apolaki indexes exploit metadata only: "
                            "it never downloads or runs exploit code.</p>"
                            "<table class='tbl'><tr><th>Finding</th><th>Match</th><th>CVE</th>"
                            "<th>Public exploit</th></tr>%s</table>"
                            % (len(_rows), len(_rows) - _lead, _lead, "".join(_rows)))
    except Exception:
        edb_html = ""

    # WHAT THIS ASSESSMENT COULD NOT TEST (#125) — the anti-WYSIATI section. A clean report makes a
    # reader assume the absent classes are safe; this says plainly which ones were never examined.
    capability_html = ""
    try:
        import capability_preflight as _cpmod
        _cdebt = _cpmod.coverage_debt()
        if not _cdebt["complete"]:
            _rows = "".join("<li>%s</li>" % e(str(c)) for c in _cdebt["untestable_classes"])
            _caps = "".join(
                "<tr><td><code>%s</code></td><td>%s</td><td class='sub'>%s</td></tr>"
                % (e(c["capability"]), e(", ".join(c["blocks"])), e(c["how_to_enable"]))
                for c in _cpmod.check() if not c["available"])
            capability_html = (
                "<h2 id='capability'>What This Assessment Could Not Test</h2>"
                "<p class='sub'>%d of %d capabilities were unavailable, so the classes below were "
                "<b>not tested</b>. This is not a statement that they are secure — it is a statement "
                "that they were not examined.</p><ul>%s</ul>"
                "<table class='tbl'><tr><th>Capability</th><th>Classes it would cover</th>"
                "<th>How to enable</th></tr>%s</table>"
                % (len(_cdebt["capabilities_missing"]), _cdebt["capabilities_total"], _rows, _caps))
    except Exception:
        capability_html = ""

    # Intelligence orchestration: show that the code-intelligence recon + the first-class technique
    # knowledge model actually DROVE this scan (not decorative dashboards). Answers "was the intel used".
    orch_html = ""
    if orchestration:
        ci = orchestration.get("code_intel") or {}
        adv = orchestration.get("advisor") or []
        parts = []
        if ci:
            parts.append("<p class='sub'>Code-intelligence recon mined <b>%d</b> API endpoint(s) from the "
                         "target's served JavaScript (<b>%d</b> folded into the scan surface), and raised "
                         "<b>%d</b> unlinked/sensitive-route and <b>%d</b> business-logic lead(s) that guided "
                         "this run.</p>" % (ci.get("endpoints", 0), ci.get("added_to_surface", 0),
                                            ci.get("sensitive_routes", 0), ci.get("logic_hypotheses", 0)))
        if adv:
            rows = "".join("<tr><td><b>%s</b></td><td>%s</td><td class='sub'>%s</td></tr>"
                           % (e(a.get("name") or a.get("id", "")), e(str(a.get("score", ""))),
                              e(", ".join(a.get("reasons", []))[:120])) for a in adv[:8])
            parts.append("<p class='sub'>The scan consulted the first-class technique knowledge model and "
                         "prioritized <b>%d</b> technique(s) to test (relevance to this target, CISA-KEV weight, "
                         "and confidence):</p><table class='tbl'><tr><th>Technique</th><th>Score</th><th>Why</th></tr>"
                         "%s</table>" % (len(adv), rows))
        nb = orchestration.get("next_best") or []
        if nb:
            rows = "".join("<tr><td><b>%s</b></td><td class='sub'>%s</td><td class='sub'>%s</td></tr>"
                           % (e(a.get("id", "")), e(a.get("family", "")),
                              e(a.get("action") or a.get("oracle") or "")[:110]) for a in nb[:6])
            parts.append("<p class='sub'>Deterministic <b>next-best actions</b> from the evidence-driven "
                         "planner (precondition-gated, KEV-ranked, and aware of what this engagement already "
                         "confirmed — the ordered path to keep testing):</p>"
                         "<table class='tbl'><tr><th>Technique</th><th>Class</th><th>Action / oracle</th></tr>"
                         "%s</table>" % rows)
        ap = orchestration.get("attack_paths") or []
        if ap:
            def _apr(a):
                fac = a.get("utility_factors") or {}
                why = ("impact %.2f · confidence %.2f · cost %s · risk %s"
                       % (fac.get("impact", 0), fac.get("evidence_confidence", 0),
                          fac.get("cost", 1), fac.get("risk", 1)))
                tgt = a.get("capability") or a.get("service") or a.get("target") or ""
                return ("<tr><td><b>%.3f</b></td><td>%s</td><td class='sub'>%s</td><td class='sub'>%s</td></tr>"
                        % (a.get("utility", 0), e((a.get("action") or "").replace("_", " ")),
                           e(str(tgt))[:48], e(why)))
            parts.append("<p class='sub'>Utility-ranked <b>attack-path opportunities</b> from the canonical "
                         "graph (Pentera-style expected value: probability &times; business-impact &times; "
                         "evidence-confidence &divide; execution-cost &divide; operational-risk, with "
                         "time-decayed confidence for unverified facts) — the graph ranking <b>which</b> lead "
                         "is worth pursuing next, most valuable first:</p>"
                         "<table class='tbl'><tr><th>Utility</th><th>Action</th><th>Target</th><th>Why</th></tr>"
                         "%s</table>" % "".join(_apr(a) for a in ap[:6]))
        if parts:
            orch_html = "<h2 id='orchestration'>Intelligence Orchestration</h2>" + "".join(parts)

    # coverage & limitations — the honest inverse of coverage: what could NOT be tested, and why
    gaps_html = ""
    _auth = bool(tool_ledger and tool_ledger.get("authenticated"))
    _gaps = coverage_gaps(mode, execution, tool_ledger, authenticated=_auth)
    if _gaps:
        grows = "".join(
            f"<tr><td><b>{e(a)}</b></td><td class='sub'><code>{e(tag)}</code></td><td class='sub'>{e(exp)}</td></tr>"
            for a, tag, exp in _gaps)
        gaps_html = ("<h2 id='coverage-gaps'>Coverage &amp; Limitations</h2>"
                     "<p class='sub'>What this assessment could <b>not</b> exercise, and why — so the boundaries are "
                     "explicit. <b>Absence of a finding in these areas is not evidence of safety.</b></p>"
                     "<table class='tbl'><tr><th>Area not covered</th><th>Reason</th><th>Detail</th></tr>"
                     + grows + "</table>")

    # methodology & tool ledger (tools run / skipped + why, ZAP status, auth, AI)
    method_html = ""
    if tool_ledger:
        zs = tool_ledger.get("zap_status")
        zcls = ("#1f9d6b" if (zs or "").startswith("executed")          # any executed_* → green
                else {"failed": "#ff3d6b", "not_configured": "#c98a2b",
                      "user_disabled": "#c98a2b", "unavailable": "#c98a2b"}.get(zs, "#6a8a9a"))
        auth = ("Authenticated (operator headers supplied)" if tool_ledger.get("authenticated")
                else "Unauthenticated")
        strat = e((tool_ledger.get("strategy") or "n/a").replace("_", "-"))
        rows = ""
        for t in (tool_ledger.get("tools") or []):
            st = (t.get("status") or "").lower()
            scol = {"executed": "#1f9d6b", "failed": "#ff3d6b",
                    "skipped": "#c98a2b"}.get(st, "#6a8a9a")
            rows += (f"<tr><td><code>{e(str(t.get('tool','')))}</code></td>"
                     f"<td><span class='sev' style='--c:{scol}'>{e(st.upper() or 'N/A')}</span></td>"
                     f"<td>{e(str(t.get('calls',0)))}</td><td>{e(str(t.get('findings',0)))}</td>"
                     f"<td>{e(str(t.get('note') or ''))}</td></tr>")
        tbl = (f"<table class='tbl'><tr><th>Tool</th><th>Status</th><th>Calls</th><th>Findings</th>"
               f"<th>Note</th></tr>{rows}</table>") if rows else ""
        method_html = (
            "<h2 id='methodology'>Methodology &amp; Tool Ledger</h2>"
            "<div class='cov-grid'>"
            f"<div class='cov'><span>{e(strat)}</span><label>Strategy</label></div>"
            f"<div class='cov'><span>{e(str(tool_ledger.get('ai_calls', 0)))}</span><label>AI Calls</label></div>"
            f"<div class='cov'><span style='color:{zcls}'>{e(_zap_badge(zs))}</span><label>ZAP</label></div>"
            "</div>"
            f"<p class='sub'><b>ZAP (DAST):</b> <span style='color:{zcls}'>{e(_zap_status_text(zs))}</span> · "
            f"<b>Auth:</b> {e(auth)}</p>" + tbl)

    # report integrity — a visible self-check that headline metrics agree with the
    # findings beneath them (Apolaki's guardrail against the self-contradicting
    # reports other tools ship). Green when clean; a warning box lists any conflict.
    import report_integrity as _ri
    integ = _ri.check_report_consistency(findings, leads, rk, counts, attack_surface, tool_ledger)
    _clean = not integ["issues"]
    _ic = "#1f9d6b" if integ["ok"] else "#c0392b"
    integrity_html = (
        "<h2 id='integrity'>Report Integrity</h2>"
        f"<p class='sub'>An automated cross-check that the headline metrics, risk score and "
        f"confirmed/unconfirmed statuses do not contradict each other. {integ['checks_run']} checks run.</p>"
        f"<div class='biz' style='border-left-color:{_ic}'>"
        f"<p><b style='color:{_ic}'>{'✓ Consistent' if _clean else '⚠ '+str(len([i for i in integ['issues'] if i['level']=='error']))+' contradiction(s)'}</b> — "
        f"{e(_ri.summary_line(integ))}</p>" +
        ("" if _clean else "<ul>" + "".join(
            f"<li><code>{e(i['check'])}</code> — {e(i['detail'])}</li>" for i in integ["issues"]) + "</ul>") +
        "</div>")
    # SEMANTIC integrity gate (cross-field): a repro that actually authenticates, well-formed URLs,
    # exact-CVE KEV claims, CVSS score matching its vector, chain wording matching its label, and
    # self-consistent candidate rows. Runs LIVE here (not only in tests) so the report cannot ship
    # a defect this gate can see (CHAD final-audit defect #6).
    _sem = report_integrity_check(findings, chains, candidate_validation, kev_cves=kev_cves)
    _sc = "#1f9d6b" if not _sem else "#c0392b"
    integrity_html += (
        f"<div class='biz' style='border-left-color:{_sc};margin-top:.6rem'>"
        f"<p><b style='color:{_sc}'>{'✓ 0 semantic violations' if not _sem else '⚠ '+str(len(_sem))+' semantic violation(s)'}</b> — "
        f"cross-field checks (auth reproduction, URL validity, exact-CVE KEV, CVSS↔vector, chain wording, candidate consistency).</p>" +
        ("" if not _sem else "<ul>" + "".join(f"<li>{e(v)}</li>" for v in _sem) + "</ul>") +
        "</div>")

    # since last scan (historical delta — never says "fixed")
    delta_html = ""
    if delta and delta.get("has_prior"):
        fd = delta.get("findings") or {}
        new_f = fd.get("added") or []
        not_reconf = fd.get("removed") or []
        parts = ["<h2 id='history'>Since Last Scan</h2>",
                 "<p class='sub'>Compared with the most recent prior mission on this target "
                 "(cross-session memory, keyed by scope). Absence from this run is <strong>not</strong> "
                 "proof of a fix.</p>"]
        if not findings and not_reconf:
            parts.append(
                "<div class='statusbar'>0 vulnerabilities were confirmed in this run. However, "
                f"{len(not_reconf)} previously confirmed finding"
                f"{'s' if len(not_reconf) != 1 else ''} "
                f"{'were' if len(not_reconf) != 1 else 'was'} not re-confirmed and require verification "
                "before closure.</div>")
        if new_f:
            items = "".join(f"<li>{e(str(f.get('title','finding')))} — <code>{e(str(f.get('target','')))}</code></li>"
                            for f in new_f)
            parts.append(f"<h4>New Findings ({len(new_f)})</h4><ul>{items}</ul>")
        if not_reconf:
            items = "".join(f"<li>{e(str(f.get('title','finding')))} — <code>{e(str(f.get('target','')))}</code> "
                            f"<span class='sub'>(prior {e(str(f.get('severity') or 'info'))}; confirm manually)</span></li>"
                            for f in not_reconf)
            parts.append("<h4>Not Re-confirmed <span class='sub'>(verify — not necessarily fixed)</span></h4>"
                         f"<ul>{items}</ul>")
        for kind, label in (("subdomains", "New Subdomains"), ("endpoints", "New Endpoints"),
                            ("tech", "New Technology")):
            added = (delta.get(kind) or {}).get("added") or []
            if added:
                items = "".join(f"<li><code>{e(str(v))}</code></li>" for v in added[:40])
                parts.append(f"<h4>{label} ({len(added)})</h4><ul>{items}</ul>")
        delta_html = "".join(parts)

    # header meta / banners
    scope_str = e(", ".join(scope.get("in_scope", [])))
    _sn = _status_note(status)
    status_html = (f'<div class="statusbar">{e(_sn.lstrip("> ").replace("**",""))}</div>' if _sn else "")
    _en = _exec_note(execution)
    exec_html = (f'<div class="execbar">{e(_en.replace("**",""))}</div>' if _en else "")
    cleaned_ai = clean_ai_text(ai_summary) if (ai_summary or "").strip() else []
    if cleaned_ai:
        # AI text is Markdown-stripped and fragment-filtered so no literal **bold**
        # or broken lines reach the HTML; fall back to the deterministic summary if
        # nothing survives validation.
        summ_paras = "".join(f"<p>{e(x)}</p>" for x in cleaned_ai)
    else:
        summ_paras = "".join(f"<p>{e(x)}</p>" for x in _exec_summary_text(program, findings, leads, execution, counts))

    # table of contents
    toc_items = [("summary", "Executive Summary"), ("posture", "Risk Posture")]
    if surf_html:
        toc_items.append(("surface", "Attack Surface"))
    if cov_html:
        toc_items.append(("coverage", "Assessment Coverage"))
    toc_items.append(("findings", "Confirmed Findings"))
    if chain_html:
        toc_items.append(("paths", "Attack-Path Chains"))
    if leads_html:
        toc_items.append(("leads", "Unconfirmed Leads"))
    if hard_html:
        toc_items.append(("hardening", "Security Hardening Summary"))
    if rem_html:
        toc_items.append(("remediation", "Priority Remediation"))
    if delta_html:
        toc_items.append(("history", "Since Last Scan"))
    if pb_html:
        toc_items.append(("playbook", "Manual Testing Playbook"))
    if method_html:
        toc_items.append(("methodology", "Methodology & Tool Ledger"))
    # Authentication & Assurance panel (CHAD capability E): surface the auth-artery PROOF (personas,
    # auth_success, REAL request counters, both-personas), the confirmed-vs-lead split, and the intel
    # provenance feeds + needs-validation worklist — the evidence a reviewer needs to trust the run.
    assurance_html = ""
    aa = auth_artery or {}
    prov = intel_provenance or {}
    if aa.get("ran") or prov.get("by_source"):
        n_conf = sum(1 for f in (findings or []) if str(f.get("confidence")) == "confirmed")
        n_lead = len(findings or []) - n_conf + len(leads or [])
        rows = []
        if aa.get("ran"):
            areq = aa.get("authenticated_requests") or {}
            personas = ", ".join(e(p.get("role", "")) for p in (aa.get("personas") or []) if p.get("role"))
            mtx = aa.get("matrix") or {}
            rows += [
                ("Personas established", "%s (auth_success=%s)" % (e(personas) or "—", e(str(aa.get("auth_success", 0))))),
                ("Authenticated requests", ("attempted <b>%s</b>, succeeded <b>%s</b>; both personas succeeded: <b>%s</b>%s"
                 % (e(str(areq.get("attempted", 0))), e(str(areq.get("succeeded", 0))),
                    "yes" if areq.get("both_personas_succeeded") else "no",
                    ("<br><span style='color:#c98a2b'>&#9888; " + e(auth_requests_note(areq)) + "</span>")
                    if auth_requests_note(areq) else ""))),
                ("Authorization matrix", "%s operation(s), %s finding(s)"
                 % (e(str(mtx.get("operations", 0))), e(str(mtx.get("findings", 0))))),
                ("Auth request status mix", e(str(areq.get("status_dist") or {}))),
            ]
        rows.append(("Findings posture", "<b>%d</b> confirmed &middot; <b>%d</b> unconfirmed lead(s) "
                     "(truth-first: only proof-backed findings are confirmed)" % (n_conf, n_lead)))
        if prov.get("by_source"):
            feeds = ", ".join("%s=%s" % (e(k), e(str(v))) for k, v in list((prov.get("by_source") or {}).items())[:8])
            rows.append(("Intel provenance (per source)", e(feeds)))
            rows.append(("Needs-validation worklist", "%s recovered fact(s) awaiting a live check"
                         % e(str(prov.get("needs_validation_count", 0)))))
        body_rows = "".join("<tr><td><b>%s</b></td><td class='sub'>%s</td></tr>" % (k, v) for k, v in rows)
        assurance_html = ("<h2 id='assurance'>Authentication &amp; Assurance</h2>"
                          "<p class='sub'>Proof the engagement did what it claims — the authentication artery "
                          "actually fired (real per-persona requests), findings are separated confirmed-vs-lead, "
                          "and every recovered intelligence fact carries its source + validation state.</p>"
                          "<table class='tbl'>" + body_rows + "</table>")
        toc_items.append(("assurance", "Authentication & Assurance"))
    # Candidate-validation ledger table: candidate -> validator -> attempted -> oracle -> result -> evidence.
    cval_html = ""
    cv = candidate_validation or {}
    cv_recs = cv.get("records") or []
    if cv_recs:
        cvc = cv.get("counts") or {}
        _rescol = {"confirmed": "#1f9d6b", "dismissed": "#7d8590", "blocked": "#c98a2b",
                   "scheduled": "#4493f8", "unsupported": "#ff3d6b"}
        # RECONCILE (CHAD #2/#6): candidate RECORDS dedupe into unique TECHNIQUES and unique confirmed
        # FINDINGS. A confirmed candidate is NOT an extra vulnerability — several map to one finding.
        n_records = len(cv_recs)
        n_tech = len({str(r.get("family") or "") for r in cv_recs})
        n_conf_cand = int(cvc.get("confirmed", 0))
        n_findings = len(findings or [])
        # consolidate identical rows (same technique+validator+result+oracle+evidence) into one with ×N
        groups, order = {}, []
        for r in cv_recs:
            key = (str(r.get("family") or ""), str(r.get("validator") or ""), str(r.get("result") or ""),
                   str(r.get("oracle") or ""), str(r.get("evidence") or ""), str(r.get("missing_prerequisite") or ""))
            if key not in groups:
                groups[key] = {"rec": r, "n": 0}
                order.append(key)
            groups[key]["n"] += 1
        rows = ""
        for key in order:
            g = groups[key]; r = g["rec"]; res = str(r.get("result") or "")
            miss = r.get("missing_prerequisite")
            cnt = (" <span class='cv-x'>&times;%d</span>" % g["n"]) if g["n"] > 1 else ""
            ev = e(str(r.get("evidence") or "")) + ((" <i>(needs: %s)</i>" % e(str(miss))) if miss else "")
            rows += ("<tr><td class='cv-fam'>%s%s</td><td class='cv-val'>%s</td><td class='cv-ran'>%s</td>"
                     "<td class='cv-or'>%s</td><td class='cv-res'><b style='color:%s'>%s</b></td>"
                     "<td class='cv-ev'>%s</td></tr>"
                     % (e(str(r.get("family") or "")), cnt, e(str(r.get("validator") or "")),
                        "yes" if r.get("attempted") else "no", e(str(r.get("oracle") or "")),
                        _rescol.get(res, "#7d8590"), e(res or "?"), ev))
        recon = ("<div class='recon'><b>%d</b> candidate record(s) across <b>%d</b> technique(s) &rarr; "
                 "<b>%d</b> confirmed candidate(s) deduplicate into <b>%d</b> unique confirmed finding(s); "
                 "<b>%d</b> dismissed &middot; <b>%d</b> blocked &middot; <b>%d</b> unsupported &middot; "
                 "<b>0</b> silently untested. A confirmed candidate is not an additional vulnerability &mdash; "
                 "duplicate candidates map to the same finding.</div>"
                 % (n_records, n_tech, n_conf_cand, n_findings, int(cvc.get("dismissed", 0)),
                    int(cvc.get("blocked", 0)), int(cvc.get("unsupported", 0))))
        cval_html = ("<h2 id='candval'>Candidate Validation</h2>"
                     "<p class='sub'>Every testable lead routed to a real validator and driven to an explicit "
                     "terminal state; identical candidates are consolidated (&times;N).</p>" + recon
                     + "<div class='tbl-wrap'><table class='tbl cv-tbl'><thead><tr><th>Technique</th>"
                     "<th>Validator</th><th>Ran</th><th>Oracle</th><th>Result</th><th>Evidence</th></tr></thead>"
                     "<tbody>" + rows + "</tbody></table></div>")
        toc_items.append(("candval", "Candidate Validation"))
    # DEGRADED banner (CHAD final #3): a halted/failed primary cycle means the run did NOT complete —
    # the report must SHOW that prominently so it is never read as a full assessment.
    degraded_html = ""
    if degraded:
        _dreason = e(str(degraded.get("reason", "unknown")))
        _ddetail = (": " + e(str(degraded.get("detail", ""))[:200])) if degraded.get("detail") else ""
        degraded_html = (
            "<div id='degraded' style='margin:1rem 0;padding:1rem 1.2rem;border-radius:10px;"
            "border:1px solid #ff3d6b;background:rgba(255,61,107,0.12)'>"
            "<b style='color:#ff3d6b'>&#9888; RUN DEGRADED &mdash; coverage is INCOMPLETE.</b> "
            "The primary planning cycle was halted (<code>" + _dreason + "</code>" + _ddetail + "). This "
            "report does <b>not</b> represent a full assessment; do not treat absence of findings as coverage.</div>")
        toc_items.append(("degraded", "Run Degraded"))
    reach_html = ""
    _rw = reachability_warning(mode, attack_surface)
    if _rw:
        reach_html = (
            "<div id='reach' style='margin:1rem 0;padding:1rem 1.2rem;border-radius:10px;"
            "border:1px solid #c98a2b;background:rgba(201,138,43,0.12)'>"
            "<b style='color:#c98a2b'>&#9888; " + e(_rw) + "</b></div>")
        toc_items.append(("reach", "Target Not Reached"))
    toc_items.append(("integrity", "Report Integrity"))
    toc_items.append(("appendix", "Appendix"))
    toc = "".join(f"<li><a href='#{i}'>{lbl}</a></li>" for i, lbl in toc_items)

    peek = "".join(
        f'<span class="chip" style="--c:{SEV_COLORS.get(s, "#6a8a9a")}">{e(s.upper())}: {counts[s]}</span>'
        for s in ["critical", "high", "medium", "low", "info", "informational"] if s in counts
    ) or '<span class="chip" style="--c:#6a8a9a">NO CONFIRMED FINDINGS</span>'
    if leads:
        peek += f'<span class="chip lead" title="unconfirmed — verify before reporting">LEADS: {len(leads)}</span>'

    _doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Apolaki Report — {e(program)}</title>
<style>
/* Light by default — client-ready / ink-safe. Dark is a one-click toggle
   (data-theme="dark"); print always forces light regardless of the toggle. */
:root{{--bg:#f5f7fa;--surface:#ffffff;--surface2:#eef2f7;--border:#d4dce4;--text:#1b2733;--dim:#5b6b7a;--bright:#0b1520;--accent:#0a58ca}}
:root[data-theme="dark"]{{--bg:#0a0e14;--surface:#111823;--surface2:#0d141d;--border:#1e2c3a;--text:#c8d6e0;--dim:#7d93a6;--bright:#f0f6fb;--accent:#38bdf8}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);line-height:1.6;
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}}
code,pre,.mono{{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace}}
.wrap{{max-width:920px;margin:0 auto;padding:2rem 1.4rem}}
h1{{color:var(--bright);font-size:2.15rem;font-weight:800;letter-spacing:-.015em;margin:0}}
h2{{color:var(--bright);border-bottom:1px solid var(--border);padding-bottom:.4rem;margin-top:2.6rem;font-size:1.15rem}}
h3{{color:var(--bright);margin:.2rem 0;font-size:1rem}}
h4{{color:var(--dim);text-transform:uppercase;font-size:.68rem;letter-spacing:.1em;margin:1rem 0 .3rem}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
.sub{{color:var(--dim);font-size:.82rem}}
/* cover */
.cover{{background:linear-gradient(135deg,var(--surface),var(--surface2));border:1px solid var(--border);
  border-radius:10px;padding:1.6rem 1.6rem 1.3rem;margin-bottom:1.4rem}}
.cover .cls{{display:inline-block;font-size:.62rem;letter-spacing:.18em;color:var(--dim);border:1px solid var(--border);
  border-radius:3px;padding:.15rem .5rem;margin-bottom:.9rem;text-transform:uppercase}}
.cmeta{{display:flex;flex-wrap:wrap;gap:.4rem 1.6rem;margin-top:.9rem;font-size:.8rem;color:var(--dim)}}
.cmeta b{{color:var(--text);font-weight:600}}
/* risk gauge */
.posture{{display:flex;align-items:center;gap:1.4rem;flex-wrap:wrap;background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:1.2rem 1.4rem;margin:.6rem 0}}
.gauge{{--c:var(--dim);width:104px;height:104px;border-radius:50%;flex:0 0 auto;display:grid;place-items:center;
  background:conic-gradient(var(--c) calc(var(--p)*1%),var(--border) 0);position:relative}}
.gauge::before{{content:"";position:absolute;inset:9px;border-radius:50%;background:var(--surface)}}
.gauge b{{position:relative;font-size:1.5rem;color:var(--bright);font-family:'JetBrains Mono',monospace}}
.gauge small{{position:relative;color:var(--dim);font-size:.6rem;display:block;text-align:center}}
.plabel{{font-size:1.15rem;font-weight:700}}
.dist{{flex:1;min-width:220px}}
.distrow{{display:flex;align-items:center;gap:.5rem;font-size:.72rem;margin:.18rem 0}}
.distlabel{{width:62px;color:var(--dim);letter-spacing:.06em}}
.distbar{{flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden}}
.distbar i{{display:block;height:100%}}
.distn{{width:22px;text-align:right;color:var(--text)}}
/* toc */
.toc{{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:.8rem 1.2rem;margin:1rem 0}}
.toc ol{{margin:.2rem 0;columns:2;font-size:.85rem}}
/* stat grid */
.cov-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:.6rem}}
.cov{{border:1px solid var(--border);background:var(--surface);border-radius:8px;padding:.8rem;text-align:center}}
.cov span{{display:block;font-size:1.5rem;color:var(--accent);font-weight:700;font-family:'JetBrains Mono',monospace}}
.cov label{{font-size:.6rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}}
.chips{{display:flex;gap:.5rem;flex-wrap:wrap;margin:.4rem 0}}
.chip{{border:1px solid var(--c);color:var(--c);border-radius:3px;padding:.28rem .7rem;font-size:.73rem;font-weight:600;letter-spacing:.06em;font-family:'JetBrains Mono',monospace}}
.chip.lead{{--c:#c98a2b;border-style:dashed}}
.summary{{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);
  border-radius:6px;padding:.9rem 1.2rem}}.summary p{{margin:.45rem 0}}
.finding{{border:1px solid var(--border);border-left:3px solid var(--c);background:var(--surface);
  border-radius:8px;padding:1.1rem 1.2rem;margin:1rem 0}}
.fh{{display:flex;align-items:center;gap:.7rem}}
.sev{{border:1px solid var(--c);color:var(--c);border-radius:3px;font-size:.6rem;padding:.15rem .5rem;letter-spacing:.08em;font-weight:700;font-family:'JetBrains Mono',monospace}}
.meta{{display:flex;gap:.5rem 1rem;flex-wrap:wrap;font-size:.72rem;color:var(--dim);margin:.5rem 0}}
.tag-conf{{color:#1f9d6b;border:1px solid #1f9d6b;border-radius:3px;padding:0 .4rem;font-size:.62rem;letter-spacing:.06em}}
.biz{{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--accent);
  border-radius:6px;padding:.5rem .9rem;margin:.7rem 0}}.biz p{{margin:.35rem 0;font-size:.86rem}}.biz b{{color:var(--bright)}}
code{{color:var(--accent);word-break:break-all}}
.ev{{background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:.7rem;overflow:auto;font-size:.74rem;white-space:pre-wrap;word-break:break-word}}
.notes{{color:var(--dim);font-style:italic;font-size:.78rem;border-top:1px dashed var(--border);padding-top:.5rem}}
ol,ul{{padding-left:1.3rem}}.chains li{{margin:.3rem 0}}
table.tbl{{width:100%;border-collapse:collapse;font-size:.8rem;margin-top:.6rem}}
table.tbl th,table.tbl td{{border:1px solid var(--border);padding:.45rem .6rem;text-align:left;vertical-align:top}}
table.tbl th{{color:var(--dim);text-transform:uppercase;font-size:.64rem;letter-spacing:.06em;background:var(--surface2)}}
details.pb{{border:1px solid var(--border);border-radius:6px;background:var(--surface);margin:.5rem 0;padding:.4rem .8rem}}
details.pb summary{{cursor:pointer;font-weight:600;color:var(--bright)}}
ul.vuln li{{color:#c0392b}}ul.safe li{{color:#1f9d6b}}
:root[data-theme="dark"] ul.vuln li{{color:#ff6b8a}}:root[data-theme="dark"] ul.safe li{{color:#4fd1a5}}
.statusbar{{background:rgba(231,148,87,.14);border:1px solid #e79457;color:#e79457;padding:.6rem .8rem;border-radius:5px;font-size:.8rem;margin:.6rem 0}}
.execbar{{background:var(--surface);border:1px solid var(--border);color:var(--dim);padding:.45rem .8rem;border-radius:5px;font-size:.76rem;margin:.6rem 0}}
footer{{margin-top:3rem;color:var(--dim);font-size:.7rem;border-top:1px solid var(--border);padding-top:1rem}}
.pdfbtn{{position:fixed;top:1rem;right:1rem;background:var(--accent);color:#001;border:none;
  font-size:.8rem;font-weight:700;padding:.5rem .9rem;cursor:pointer;border-radius:5px;z-index:10}}
@media print{{
  /* force light ink-safe output even if the dark toggle is active */
  :root,:root[data-theme="dark"]{{--bg:#fff;--surface:#fff;--surface2:#f5f7fa;--border:#c3ccd6;--text:#14181d;--dim:#55606b;--bright:#000;--accent:#0a58ca}}
  body{{background:#fff}}.wrap{{max-width:100%;padding:0}}
  .cover,.posture,.toc,.finding,.summary{{break-inside:avoid}}
  .gauge::before{{background:#fff}}
  .pdfbtn,.themebtn,.noprint{{display:none!important}}
}}
.themebtn{{position:fixed;top:1rem;right:7.4rem;background:var(--surface);color:var(--text);
  border:1px solid var(--border);font-size:.8rem;padding:.5rem .8rem;cursor:pointer;border-radius:5px;z-index:10}}
/* Candidate Validation table: fixed layout so long evidence WRAPS instead of squeezing/clipping */
.tbl-wrap{{overflow-x:auto;-webkit-overflow-scrolling:touch;margin-top:.5rem}}
.recon{{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:.55rem .8rem;font-size:.78rem;color:var(--dim);margin:.4rem 0 .7rem;line-height:1.5}}
table.cv-tbl{{table-layout:fixed;width:100%}}
table.cv-tbl td,table.cv-tbl th{{word-break:break-word;overflow-wrap:anywhere;white-space:normal;vertical-align:top}}
.cv-tbl .cv-fam{{width:12%}}.cv-tbl .cv-val{{width:12%}}.cv-tbl .cv-ran{{width:5%;text-align:center}}
.cv-tbl .cv-or{{width:22%}}.cv-tbl .cv-res{{width:9%}}.cv-tbl .cv-ev{{width:40%}}
.cv-x{{display:inline-block;background:var(--accent);color:#001;border-radius:8px;padding:0 .35rem;font-size:.62rem;font-weight:700;margin-left:.3rem;vertical-align:middle}}
/* Print/PDF: repeat table headers on every page + never split a row, finding, or heading */
table.tbl thead{{display:table-header-group}}
table.tbl tr,.finding,.recon,figure.shot{{break-inside:avoid}}
h1,h2,h3{{break-after:avoid}}
figure.shot{{margin:.6rem 0}}figure.shot img{{max-width:100%;height:auto;border:1px solid var(--border);border-radius:6px}}
figure.shot figcaption{{font-size:.72rem;color:var(--dim);margin-top:.25rem}}
/* keep the fixed Dark/PDF controls from covering the cover title on screen (hidden in print) */
@media screen{{.wrap{{padding-top:3.4rem}}}}
@media (max-width:640px){{.pdfbtn,.themebtn{{position:static;display:inline-block;margin:.3rem .3rem 0 0}} .cv-tbl .cv-or,.cv-tbl .cv-val{{width:auto}}}}
</style></head><body>
<button class="themebtn noprint" onclick="var r=document.documentElement;r.dataset.theme=r.dataset.theme==='dark'?'':'dark';this.textContent=r.dataset.theme==='dark'?'☀ Light':'🌙 Dark';">🌙 Dark</button>
<button class="pdfbtn noprint" onclick="window.print()">Save as PDF</button>
<div class="wrap">
<div class="cover">
  <span class="cls">Confidential · Authorized Testing Only</span>
  <h1>{engagement} Report</h1>
  <div class="sub">{e(program)}</div>
  <div class="cmeta">
    <span>Target: <b>{scope_str or e(program)}</b></span>
    <span>Engagement: <b>{e(engagement)}</b></span>
    <span>Scan mode: <b>{e((mode or 'n/a').title())}</b></span>
    <span>Report ID: <b>{e(report_id or '—')}</b></span>
    <span>Date: <b>{e(_now())}</b></span>
    <span>Confirmed findings: <b>{len(findings)}</b></span>
    <span>Unconfirmed leads: <b>{len(leads)}</b></span>
  </div>
  <div class="chips">{peek}</div>
</div>
{exec_html}
{status_html}
<div class="toc noprint-keep"><h4 style="margin-top:0">Contents</h4><ol>{toc}</ol></div>
{degraded_html}
{reach_html}
<h2 id="summary">Executive Summary</h2>
<div class="summary">{summ_paras}</div>

<h2 id="posture">Risk Posture</h2>
<div class="posture">
  <div class="gauge" style="--c:{rk['color']};--p:{rk['score']}"><div><b>{rk['score']}</b><small>/ 100</small></div></div>
  <div>
    <div class="plabel" style="color:{rk['color']}">{e(rk['label'])}</div>
    <div class="sub">Confirmed-risk score — computed from confirmed findings only. Unconfirmed leads never inflate it.</div>
    <div class="sub" style="margin-top:.25rem"><b>Methodology:</b> {e(rk['note'])}</div>
  </div>
  <div class="dist">{dist_rows}</div>
</div>
{fixpri_html}
{cov_overview_html}
{bizlogic_html}
{signals_html}
{cvss_html}
{roe_html}
{surf_html}
{cov_html}
{sechdr_html}
{cve_html}
{intel_html}
{rootcause_html}
{kev_html}
{edb_html}
{capability_html}
{orch_html}
{assurance_html}
{cval_html}

<h2 id="findings">Confirmed Findings</h2>
{findings_html}
{chain_html}
{leads_html}
{hard_html}
{rem_html}
{delta_html}
{pb_html}
{gaps_html}
{method_html}
{integrity_html}
{appendix}
<footer>Generated by Apolaki · deterministic, truth-first reporting. Confirmed findings carry reproducible
evidence; unconfirmed leads are advisory and must be verified before submission. Authorized security research only.</footer>
</div></body></html>"""
    # #8/#10 integrity: rebuild the Contents list from the ACTUAL rendered <h2 id> sections so the
    # TOC can never drift from the body (it was hand-maintained and missed ~10 sections).
    _secs, _tocseen, _toc2 = re.findall(r"<h2 id=['\"]([^'\"]+)['\"][^>]*>(.*?)</h2>", _doc, re.S), set(), ""
    for _sid, _lbl in _secs:
        if _sid in _tocseen:
            continue
        _tocseen.add(_sid)
        _toc2 += "<li><a href='#%s'>%s</a></li>" % (_sid, re.sub(r"<[^>]+>", "", _lbl).strip())
    if _toc2:
        _doc = re.sub(r'(<h4 style="margin-top:0">Contents</h4><ol>).*?(</ol>)',
                      lambda m: m.group(1) + _toc2 + m.group(2), _doc, count=1, flags=re.S)
    # UTF-8 safety: encode EVERY non-ASCII glyph as a numeric HTML entity so arrows,
    # dashes, checks and icons render correctly no matter how the byte stream is served
    # or opened — this is what kills the "â†'/â€"/Â·" mojibake once and for all.
    return _doc.encode("ascii", "xmlcharrefreplace").decode("ascii")


# ── CSV / JSON export ────────────────────────────────────────────
_CSV_FIELDS = ["title", "severity", "target", "cvss_score", "cwe", "capec", "owasp", "impact", "description"]


def findings_csv(findings: list) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for f in sorted(_with_capec(findings), key=lambda x: SEV_ORDER.get((x.get("severity") or "info").lower(), 5)):
        w.writerow({k: f.get(k, "") for k in _CSV_FIELDS})
    return buf.getvalue()


DATA_PACKAGE_VERSION = "1.1"


def findings_json(program: str, findings: list, scope: dict,
                  coverage: dict = None, chains: list = None, leads: list = None,
                  config: dict = None, attack_surface: dict = None, playbook: list = None,
                  tool_ledger: dict = None, delta: dict = None, execution: dict = None,
                  report_id: str = None, intel_provenance: dict = None,
                  auth_artery: dict = None, degraded: dict = None,
                  candidate_validation: dict = None) -> str:
    """Native JSON data package. The original keys (program, generated, scope, counts,
    lead_counts, coverage, chains, findings, leads) are always present and unchanged;
    the richer sections below are additive so existing consumers never break."""
    leads = leads or []
    # Dedupe to the SAME grouped findings the HTML renders (each carries an `instances`
    # list of every affected target), so the JSON headline count matches the HTML's — no
    # more "JSON says 13 confirmed / HTML says 7". Counts, risk and integrity all derive
    # from the grouped set here too.
    findings = group_findings(_with_capec(findings))
    # Fix Now / Fix If / Strengthen — a remediation-ACTION priority ALONGSIDE technical severity (CVSS/CWE),
    # so a consumer sees "what to do first", not only how bad it is. Additive per-item + a header summary.
    import remediation as _rem
    for _f in findings:
        _f["fix_priority"] = _rem.fix_priority(_f)
    for _l in leads:
        _l["fix_priority"] = _rem.fix_priority(_l)
    pkg = {
        # ── report metadata ──
        "report_id": report_id or "",
        "program": program,
        "generated": _now(),
        "generator": {"name": "Apolaki", "data_package_version": DATA_PACKAGE_VERSION},
        # ── exact scan configuration ──
        "config": config or {},
        "execution": execution or {},
        "scope": scope,
        # ── risk calculation (confirmed findings only) ──
        "risk": risk_score(findings),
        "counts": _counts(findings),
        "lead_counts": _counts(leads),
        # Fix Now / Fix If / Strengthen action-priority header (counts across findings+leads) — the
        # developer-facing triage lens next to technical severity.
        "fix_priority": _rem.fix_priority_summary(findings, leads),
        # ── coverage / attack surface / methodology ──
        "coverage": coverage or {},
        # unified COVERAGE rollup — of the security properties Apolaki models, how many are confirmed-safe /
        # vulnerable / inconclusive / blocked / not-tested (from ASVS + WSTG + the candidate ledger).
        "coverage_rollup": coverage_rollup(findings, tool_ledger, candidate_validation),
        # BUSINESS-LOGIC testing as a headline capability — the workflows probed + abuse categories + outcomes.
        "business_logic": business_logic_view(findings, leads),
        "attack_surface": attack_surface or {},
        "tool_ledger": tool_ledger or {},
        # ── intelligence provenance: WHERE the world model came from (per-source feed counts) +
        # the needs-validation worklist (wayback/github/cloud facts not yet checked live). Making
        # provenance visible is the truth-first counterpart to never trusting recovered intel blind.
        "intel_provenance": intel_provenance or {},
        # ── authentication artery proof: did the autonomous two-persona auth + authz matrix actually
        # fire (personas minted/reacquired, sessions obtained, matrix operations run)? Queryable
        # evidence so an "authenticated scan" is provable, not asserted. {"ran": False} when it didn't.
        "auth_artery": _artery_with_note(auth_artery),
        # ── candidate-validation ledger: every testable lead -> validator -> terminal state + evidence.
        # Proof that no testable lead is left sitting; blocked rows name the exact missing prerequisite.
        "candidate_validation": candidate_validation or {},
        # ── DEGRADED state: a halted/failed primary cycle (e.g. graph projection failure). When present
        # the run did NOT complete normally and coverage is incomplete — consumers MUST NOT read this
        # report as a full assessment (CHAD final #3).
        "degraded": degraded or None,
        # ── target reachability: an active/full scan that reached 0 live hosts never touched the
        # target (mis-scoped bare host on :443, or target down). Surfaced so a "complete" run with
        # no findings is never mistaken for "target is secure". None when a host was reached.
        "target_reachability": reachability_warning((config or {}).get("mode"), attack_surface),
        # ── results ──
        "chains": chains or [],
        "findings": findings,
        # Unconfirmed candidate/static signals — never confirmed vulnerabilities.
        # Consumers must treat these as advisory until manually verified.
        "leads": leads,
        # ── manual playbooks (recommendations, not findings) ──
        "playbooks": playbook or [],
        # ── prior-scan delta (never treat 'not re-confirmed' as fixed) ──
        "since_last_scan": delta or {},
        # ── export generation metadata ──
        "export": {"generated_at": _now(), "format": "json", "version": DATA_PACKAGE_VERSION},
    }
    # ── metric-consistency guarantee: a self-check that headline metrics agree with
    # the findings beneath them (no "Confirmed: 0 / 14 confirmed" style contradiction).
    import report_integrity as _ri
    pkg["integrity"] = _ri.check_report_consistency(
        findings, leads, pkg["risk"], pkg["counts"], attack_surface, tool_ledger)
    return json.dumps(pkg, indent=2, default=str)
