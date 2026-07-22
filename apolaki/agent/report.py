"""
Report generation: HackerOne/Bugcrowd Markdown (original), a dark-themed
standalone HTML report (APOLLO-style, every field HTML-escaped), plus CSV and
JSON export. All deterministic; no network.
"""
import csv
import html as _html
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


def generate_report(program: str, findings: list, scope: dict,
                     coverage: dict = None, chains: list = None, status: str = None,
                     ai_summary: str = None, execution: dict = None, leads: list = None) -> str:
    now = _now()
    status_banner = _status_note(status)          # only failed/stopped/interrupted
    exec_note = _exec_note(execution)             # strategy + AI usage (always for det/low-AI)
    banner = "\n\n".join(b for b in (status_banner, exec_note) if b)
    ai_block = (f"## Executive Summary\n\n{ai_summary.strip()}\n\n" if (ai_summary or "").strip() else "")
    leads_md = _leads_md(leads)
    if not findings:
        # "ended early" only when the STATUS says so — not merely because an
        # execution note is present (which it always is for deterministic/low-AI).
        tail = " before the run ended early." if status_banner else " during this engagement."
        return (
            f"# Security Assessment Report: {program}\n\n"
            + (banner + "\n\n" if banner else "")
            + f"**Date:** {now}\n"
            f"**Scope:** {', '.join(scope.get('in_scope', []))}\n\n"
            + ai_block
            + "No confirmed vulnerabilities were recorded" + tail + "\n"
            + leads_md
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

    lines += ["", "---", "", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity", "informational")).upper()
        lines += [
            f"### Finding {i}: {f.get('title', 'Untitled')}", "",
            "**Summary**", "", f.get("description", ""), "",
            f"**Severity:** {sev}",
            f"**Target:** `{f.get('target', '')}`",
            f"**CVSS:** {f.get('cvss_score', 'N/A')}{(' ' + f.get('cvss_vector', '')) if f.get('cvss_vector') else ''}",
            f"**CWE:** {f.get('cwe', 'N/A')}",
        ]
        if f.get("owasp"):
            lines.append(f"**OWASP:** {f['owasp']}")
        _bi = business_impact(f)
        if _bi:
            lines += ["", "**Why This Matters (plain English)**", "",
                      f"_What it is:_ {_bi[0]}", "", f"_If left unpatched:_ {_bi[1]}", ""]
        lines += ["", "**Steps to Reproduce**", ""]
        for j, step in enumerate(f.get("reproduction_steps", []), 1):
            lines.append(f"{j}. {step}")
        lines += ["", "**Impact**", "", f.get("impact", ""), ""]
        if f.get("remediation"):
            lines += ["**Remediation**", "", f["remediation"], ""]
        if f.get("evidence"):
            lines += ["**Supporting Material**", "", "```", str(f["evidence"]), "```", ""]
        if f.get("analyst_notes"):
            lines += [f"> _Triage: {f['analyst_notes']}_", ""]
        lines += ["---", ""]

    if chains:
        lines += ["## Attack-Path Chains", ""]
        for c in chains:
            lines += [f"- **{c.get('host')}** ({(c.get('severity') or '').upper()}): {c.get('narrative')}"]
        lines.append("")
    if leads_md:
        lines.append(leads_md)
    return "\n".join(lines)


# ── HTML (dark-themed standalone, all fields escaped) ────────────
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
}
# CWE -> family, so a finding with a CWE but no recognised family still gets text.
_CWE_FAMILY = {
    "cwe-89": "sqli", "cwe-79": "xss", "cwe-113": "crlf", "cwe-611": "xxe", "cwe-918": "ssrf",
    "cwe-78": "cmdi", "cwe-22": "path_traversal", "cwe-639": "idor", "cwe-284": "idor",
    "cwe-285": "bfla", "cwe-1104": "vulnerable_component", "cwe-1035": "vulnerable_component",
    "cwe-601": "open_redirect", "cwe-1336": "ssti", "cwe-94": "ssti", "cwe-502": "deserialization",
    "cwe-352": "csrf", "cwe-942": "cors", "cwe-200": "exposure", "cwe-527": "git_exposure",
    "cwe-1321": "prototype_pollution", "cwe-1336": "ssti",
}


def business_impact(finding: dict):
    """(plain-English meaning, business consequence) for a finding, or None when we
    have no mapping (better to omit than to invent). Family first, then CWE."""
    fam = str(finding.get("family") or "").strip().lower()
    if fam in _BIZ:
        return _BIZ[fam]
    cwe = str(finding.get("cwe") or "").strip().lower()
    fam2 = _CWE_FAMILY.get(cwe)
    return _BIZ.get(fam2) if fam2 else None


def risk_score(findings: list) -> dict:
    """Honest risk posture from CONFIRMED findings only (leads never inflate it —
    that is Apolaki's truth-first edge over tools that score off unconfirmed
    signal). 0-100 with a label + colour."""
    score = min(100, sum(_SEV_WEIGHT.get((f.get("severity") or "info").lower(), 1) for f in findings))
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
    return {"score": score, "label": label, "color": color}


def _exec_summary_text(program, findings, leads, execution, counts) -> list:
    """Deterministic executive summary (used verbatim, or as a fallback when no AI
    wrap-up ran). Business-readable, and scrupulously honest about confirmation."""
    leads = leads or []
    n_conf, n_lead = len(findings), len(leads)
    rk = risk_score(findings)
    sev_bits = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low")
                if counts.get(s)]
    line1 = (f"This assessment of {program} confirmed {n_conf} "
             f"{'vulnerability' if n_conf == 1 else 'vulnerabilities'}"
             + (f" ({', '.join(sev_bits)})" if sev_bits else "")
             + f", for an overall confirmed-risk posture of {rk['label']} ({rk['score']}/100).")
    if n_conf:
        tops = ", ".join(f.get("title", "finding") for f in findings[:3])
        line2 = f"The most significant confirmed issues are: {tops}. Each carries reproducible evidence below."
    else:
        line2 = ("No vulnerability was CONFIRMED with reproducible evidence during this engagement. "
                 "The risk score reflects confirmed findings only.")
    line3 = ""
    if n_lead:
        line3 = (f"An additional {n_lead} unconfirmed lead{'s' if n_lead != 1 else ''} "
                 "(static/candidate signals) require manual verification before they can be treated as "
                 "vulnerabilities — they are listed separately and are NOT counted in the risk score.")
    return [x for x in (line1, line2, line3) if x]


def generate_html_report(program: str, findings: list, scope: dict,
                         coverage: dict = None, chains: list = None, status: str = None,
                         ai_summary: str = None, execution: dict = None, leads: list = None,
                         attack_surface: dict = None, playbook: list = None, mode: str = None) -> str:
    e = _html.escape
    leads = leads or []
    counts = _counts(findings)
    findings = sorted(findings, key=lambda f: SEV_ORDER.get((f.get("severity") or "informational").lower(), 5))
    rk = risk_score(findings)
    engagement = _ENGAGEMENT.get((mode or "").lower(), "Security Assessment")

    # severity distribution bars (confirmed only)
    total_conf = len(findings) or 1
    dist_rows = ""
    for s in ("critical", "high", "medium", "low", "info"):
        n = counts.get(s, 0) + (counts.get("informational", 0) if s == "info" else 0)
        pct = int(100 * n / total_conf) if findings else 0
        dist_rows += (f"<div class='distrow'><span class='distlabel'>{s.upper()}</span>"
                      f"<span class='distbar'><i style='width:{pct}%;background:{SEV_COLORS[s]}'></i></span>"
                      f"<span class='distn'>{n}</span></div>")

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

    # confirmed findings — full proof density
    cards = []
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "informational").lower()
        color = SEV_COLORS.get(sev, "#6a8a9a")
        steps = "".join(f"<li>{e(str(s))}</li>" for s in (f.get("reproduction_steps") or []))
        ev = f"<h4>Evidence</h4><pre class='ev'>{e(str(f.get('evidence','')))}</pre>" if f.get("evidence") else ""
        notes = f"<p class='notes'>Triage: {e(str(f.get('analyst_notes','')))}</p>" if f.get("analyst_notes") else ""
        rem = f"<h4>Remediation</h4><p>{e(str(f.get('remediation','')))}</p>" if f.get("remediation") else ""
        cvss = f.get("cvss") or f.get("cvss_score")
        bi = business_impact(f)
        biz_html = ""
        if bi:
            biz_html = (f"<div class='biz'><h4>Why This Matters (plain English)</h4>"
                        f"<p><b>What it is:</b> {e(bi[0])}</p>"
                        f"<p><b>If left unpatched:</b> {e(bi[1])}</p></div>")
        cards.append(f"""
        <article class="finding" style="--c:{color}">
          <div class="fh"><span class="sev">{e(sev.upper())}</span><h3>{i}. {e(str(f.get('title','Untitled')))}</h3></div>
          <div class="meta">
            <span>Target: <code>{e(str(f.get('target','')))}</code></span>
            <span>CVSS: {e(str(cvss)) if cvss else 'N/A'}</span>
            <span>CWE: {e(str(f.get('cwe','N/A')))}</span>
            {f"<span>OWASP: {e(str(f.get('owasp')))}</span>" if f.get('owasp') else ''}
            <span class="tag-conf">CONFIRMED</span>
          </div>
          {biz_html}
          <h4>Technical detail</h4><p>{e(str(f.get('description','')))}</p>
          {f"<h4>Impact</h4><p>{e(str(f.get('impact','')))}</p>" if f.get('impact') else ''}
          {f"<h4>Steps to Reproduce</h4><ol>{steps}</ol>" if steps else ''}
          {ev}{rem}{notes}
        </article>""")
    findings_html = "".join(cards) if cards else (
        "<p class='sub'>No vulnerability was confirmed with reproducible evidence during this engagement. "
        "See Unconfirmed Leads below for signals that need manual verification.</p>")

    # priority remediation table (confirmed, severity-ordered)
    rem_html = ""
    if findings:
        rrows = "".join(
            f"<tr><td>{i}</td><td><span class='sev' style='--c:{SEV_COLORS.get((f.get('severity') or 'info').lower(),'#6a8a9a')}'>"
            f"{e((f.get('severity') or 'info').upper())}</span></td><td>{e(str(f.get('title','')))}</td>"
            f"<td>{e(str(f.get('remediation') or 'See finding detail.'))}</td></tr>"
            for i, f in enumerate(findings, 1))
        rem_html = ("<h2 id='remediation'>Priority Remediation</h2>"
                    "<table class='tbl'><tr><th>#</th><th>Severity</th><th>Finding</th><th>Fix</th></tr>"
                    + rrows + "</table>")

    # attack paths
    chain_html = ""
    if chains:
        items = "".join(f"<li><b>{e(str(c.get('host')))}</b> "
                        f"<span class='sev' style='--c:{SEV_COLORS.get((c.get('severity') or '').lower(),'#6a8a9a')}'>"
                        f"{e(str((c.get('severity') or '').upper()))}</span> — {e(str(c.get('narrative')))}</li>"
                        for c in chains)
        chain_html = f"<h2 id='paths'>Attack-Path Chains</h2><ul class='chains'>{items}</ul>"

    # unconfirmed leads (Apolaki's honesty edge — kept distinct + labelled)
    leads_html = ""
    if leads:
        rows = "".join(
            f"<tr><td><span class='sev' style='--c:{SEV_COLORS.get((l.get('severity') or 'info').lower(),'#6a8a9a')}'>"
            f"{e((l.get('severity') or 'info').upper())}</span></td><td>{e(l.get('confidence','candidate'))}</td>"
            f"<td>{e(l.get('title',''))}</td><td><code>{e(l.get('target',''))}</code></td></tr>"
            for l in sorted(leads, key=lambda x: SEV_ORDER.get((x.get('severity') or 'info').lower(), 5)))
        leads_html = ("<h2 id='leads'>Unconfirmed Leads</h2><p class='sub'>Signals worth manual verification — "
                      "<strong>NOT confirmed vulnerabilities</strong> and NOT counted in the risk score. "
                      "Confirm before reporting to a program.</p>"
                      "<table class='tbl'><tr><th>Severity</th><th>Confidence</th><th>Lead</th><th>Target</th></tr>"
                      + rows + "</table>")

    # manual-testing playbook (Round Table strength — what/how/cURL per surface)
    pb_html = ""
    if playbook:
        blocks = []
        for p in playbook[:12]:
            how = "".join(f"<li>{e(str(s))}</li>" for s in (p.get("how_to_test") or [])[:4])
            curls = "".join(f"<pre class='ev'>{e(str(c.get('cmd') if isinstance(c, dict) else c))}</pre>"
                            for c in (p.get("curl_steps") or [])[:2])
            pays = ", ".join(e(str(x)) for x in (p.get("payloads") or [])[:4])
            sev = (p.get("severity") or "info").lower()
            blocks.append(
                f"<details class='pb'><summary><span class='sev' style='--c:{SEV_COLORS.get(sev,'#6a8a9a')}'>"
                f"{e(sev.upper())}</span> {e(str(p.get('title','')))} "
                f"<span class='sub'>{e(str(p.get('wstg','')))}</span></summary>"
                + (f"<p>{e(str(p.get('what_to_test','')))}</p>" if p.get('what_to_test') else "")
                + (f"<h4>How to test</h4><ol>{how}</ol>" if how else "")
                + (f"<h4>Payloads</h4><p><code>{pays}</code></p>" if pays else "")
                + (f"<h4>cURL</h4>{curls}" if curls else "")
                + "</details>")
        pb_html = ("<h2 id='playbook'>Manual Testing Playbook</h2>"
                   "<p class='sub'>Per-surface guidance (what to test, how, payloads, cURL) for manual "
                   "verification and deeper exploitation.</p>" + "".join(blocks))

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

    # header meta / banners
    scope_str = e(", ".join(scope.get("in_scope", [])))
    _sn = _status_note(status)
    status_html = (f'<div class="statusbar">{e(_sn.lstrip("> ").replace("**",""))}</div>' if _sn else "")
    _en = _exec_note(execution)
    exec_html = (f'<div class="execbar">{e(_en.replace("**",""))}</div>' if _en else "")
    if (ai_summary or "").strip():
        summ_paras = "".join(f"<p>{e(pp.strip())}</p>" for pp in ai_summary.strip().split("\n") if pp.strip())
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
    if rem_html:
        toc_items.append(("remediation", "Priority Remediation"))
    if pb_html:
        toc_items.append(("playbook", "Manual Testing Playbook"))
    toc_items.append(("appendix", "Appendix"))
    toc = "".join(f"<li><a href='#{i}'>{lbl}</a></li>" for i, lbl in toc_items)

    peek = "".join(
        f'<span class="chip" style="--c:{SEV_COLORS.get(s, "#6a8a9a")}">{e(s.upper())}: {counts[s]}</span>'
        for s in ["critical", "high", "medium", "low", "info", "informational"] if s in counts
    ) or '<span class="chip" style="--c:#6a8a9a">NO CONFIRMED FINDINGS</span>'
    if leads:
        peek += f'<span class="chip lead" title="unconfirmed — verify before reporting">LEADS: {len(leads)}</span>'

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Apolaki Report — {e(program)}</title>
<style>
:root{{--bg:#0a0e14;--surface:#111823;--surface2:#0d141d;--border:#1e2c3a;--text:#c8d6e0;--dim:#7d93a6;--bright:#f0f6fb;--accent:#38bdf8}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);line-height:1.6;
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}}
code,pre,.mono{{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace}}
.wrap{{max-width:920px;margin:0 auto;padding:2rem 1.4rem}}
h1{{color:var(--bright);font-size:1.7rem;margin:0}}
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
.chip{{border:1px solid var(--c);color:var(--c);border-radius:3px;padding:.2rem .6rem;font-size:.7rem;letter-spacing:.06em;font-family:'JetBrains Mono',monospace}}
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
.statusbar{{background:rgba(231,148,87,.14);border:1px solid #e79457;color:#e79457;padding:.6rem .8rem;border-radius:5px;font-size:.8rem;margin:.6rem 0}}
.execbar{{background:var(--surface);border:1px solid var(--border);color:var(--dim);padding:.45rem .8rem;border-radius:5px;font-size:.76rem;margin:.6rem 0}}
footer{{margin-top:3rem;color:var(--dim);font-size:.7rem;border-top:1px solid var(--border);padding-top:1rem}}
.pdfbtn{{position:fixed;top:1rem;right:1rem;background:var(--accent);color:#001;border:none;
  font-size:.8rem;font-weight:700;padding:.5rem .9rem;cursor:pointer;border-radius:5px;z-index:10}}
@media print{{
  :root{{--bg:#fff;--surface:#fff;--surface2:#f5f7fa;--border:#c3ccd6;--text:#14181d;--dim:#55606b;--bright:#000;--accent:#0a58ca}}
  body{{background:#fff}}.wrap{{max-width:100%;padding:0}}
  .cover,.posture,.toc,.finding,.summary{{break-inside:avoid}}
  .gauge::before{{background:#fff}}
  .pdfbtn,.noprint{{display:none!important}}
}}
</style></head><body>
<button class="pdfbtn noprint" onclick="window.print()">Save as PDF</button>
<div class="wrap">
<div class="cover">
  <span class="cls">Confidential · Authorized Testing Only</span>
  <h1>{engagement} Report</h1>
  <div class="sub">{e(program)}</div>
  <div class="cmeta">
    <span>Target: <b>{scope_str or e(program)}</b></span>
    <span>Engagement: <b>{e(engagement)}</b></span>
    <span>Date: <b>{e(_now())}</b></span>
    <span>Confirmed findings: <b>{len(findings)}</b></span>
    <span>Unconfirmed leads: <b>{len(leads)}</b></span>
  </div>
  <div class="chips">{peek}</div>
</div>
{exec_html}
{status_html}
<div class="toc noprint-keep"><h4 style="margin-top:0">Contents</h4><ol>{toc}</ol></div>

<h2 id="summary">Executive Summary</h2>
<div class="summary">{summ_paras}</div>

<h2 id="posture">Risk Posture</h2>
<div class="posture">
  <div class="gauge" style="--c:{rk['color']};--p:{rk['score']}"><div><b>{rk['score']}</b><small>/ 100</small></div></div>
  <div>
    <div class="plabel" style="color:{rk['color']}">{e(rk['label'])}</div>
    <div class="sub">Confirmed-risk score — computed from confirmed findings only. Unconfirmed leads never inflate it.</div>
  </div>
  <div class="dist">{dist_rows}</div>
</div>
{surf_html}
{cov_html}

<h2 id="findings">Confirmed Findings</h2>
{findings_html}
{chain_html}
{leads_html}
{rem_html}
{pb_html}
{appendix}
<footer>Generated by Apolaki · deterministic, truth-first reporting. Confirmed findings carry reproducible
evidence; unconfirmed leads are advisory and must be verified before submission. Authorized security research only.</footer>
</div></body></html>"""


# ── CSV / JSON export ────────────────────────────────────────────
_CSV_FIELDS = ["title", "severity", "target", "cvss_score", "cwe", "owasp", "impact", "description"]


def findings_csv(findings: list) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for f in sorted(findings, key=lambda x: SEV_ORDER.get((x.get("severity") or "info").lower(), 5)):
        w.writerow({k: f.get(k, "") for k in _CSV_FIELDS})
    return buf.getvalue()


def findings_json(program: str, findings: list, scope: dict,
                  coverage: dict = None, chains: list = None, leads: list = None) -> str:
    leads = leads or []
    return json.dumps({
        "program": program,
        "generated": _now(),
        "scope": scope,
        "counts": _counts(findings),
        "lead_counts": _counts(leads),
        "coverage": coverage or {},
        "chains": chains or [],
        "findings": findings,
        # Unconfirmed candidate/static signals — never confirmed vulnerabilities.
        # Consumers must treat these as advisory until manually verified.
        "leads": leads,
    }, indent=2, default=str)
