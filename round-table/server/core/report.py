"""
Report generation: self-contained HTML, Markdown, CSV, JSON.

Every report is built around the test-guidance playbooks — for each surface:
what to test, how, payloads, confidence, tools, and step-by-step cURL.
"""
import csv
import html
import io
import json
from datetime import datetime
from typing import Any

SEV_COLOR = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
    "LOW": "#2563eb", "INFO": "#6b7280", "UNKNOWN": "#6b7280",
}
SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def _is_confirmed(g: dict) -> bool:
    return bool(g.get("confirmed")) or ("confirmed" in (g.get("tags") or []))


def _is_hunch(g: dict) -> bool:
    return bool(g.get("hunch")) or ("hunch" in (g.get("tags") or []))


def _risk_score(guidance: list) -> tuple:
    """Weighted risk score (0-98) with a label + colour, confirmed findings
    weighted higher. A summary indicator, not a formal CVSS aggregate."""
    w = {"CRITICAL": 35, "HIGH": 18, "MEDIUM": 7, "LOW": 2, "INFO": 0}
    raw = 0.0
    for g in guidance:
        base = w.get(g.get("severity", "INFO"), 0)
        raw += base * (1.3 if _is_confirmed(g) else 1.0)
    score = 0 if raw <= 0 else min(98, round(raw))
    if score >= 80:
        return score, "Critical", "#dc2626"
    if score >= 60:
        return score, "High", "#ea580c"
    if score >= 40:
        return score, "Medium", "#d97706"
    if score >= 15:
        return score, "Low", "#2563eb"
    return score, "Minimal", "#16a34a"


def _finding_card(g: dict) -> str:
    color = SEV_COLOR.get(g.get("severity", "INFO"), "#6b7280")
    tint = {"CRITICAL": "#fef2f2", "HIGH": "#fff7ed", "MEDIUM": "#fffbeb",
            "LOW": "#eff6ff", "INFO": "#f8fafc"}.get(g.get("severity", "INFO"), "#f8fafc")
    payloads = "".join(f"<li><code>{_esc(p)}</code></li>" for p in g.get("payloads", []))
    steps = "".join(f"<li>{_esc(s)}</li>" for s in g.get("how_to_test", []))
    curls = "".join(
        f'<div class="curl"><div class="curl-desc">{_esc(c.get("desc",""))}</div>'
        f'<pre>{_esc(c.get("cmd",""))}</pre></div>'
        for c in g.get("curl_steps", [])
    )
    refs = " · ".join(
        f'<a href="{_esc(r["url"])}" target="_blank" rel="noopener">{_esc(r["title"])}</a>'
        for r in g.get("references", [])
    )
    tools = ", ".join(_esc(t) for t in g.get("tools", []))
    rem = (g.get("remediation") or {}).get("summary") if isinstance(g.get("remediation"), dict) else None
    if _is_confirmed(g):
        badge = '<span class="tier tier-confirmed">CONFIRMED</span>'
    elif _is_hunch(g):
        badge = '<span class="tier tier-hunch">HUNCH</span>'
    else:
        badge = '<span class="tier tier-advisory">ADVISORY</span>'
    return f"""
    <div class="finding" style="border-left:4px solid {color};background:{tint}">
      <div class="finding-head">
        <span class="sev" style="background:{color}">{_esc(g.get('severity',''))}</span>
        {badge}
        <span class="conf">{_esc(g.get('confidence_label',''))} · {g.get('confidence',0)}%</span>
        {f'<span class="wstg">{_esc(g.get("wstg",""))}</span>' if g.get('wstg') else ''}
        <span class="finding-title">{_esc(g.get('title',''))}</span>
      </div>
      <div class="finding-body">
        <p class="surface"><strong>Where:</strong> <code>{_esc(g.get('surface',''))}</code></p>
        <p><strong>Evidence:</strong> {_esc(g.get('evidence',''))}</p>
        <p><strong>What to test:</strong> {_esc(g.get('what_to_test',''))}</p>
        {f'<div class="block"><strong>How to test / exploit</strong><ol>{steps}</ol></div>' if steps else ''}
        {f'<div class="block"><strong>Recommended payloads / injections</strong><ul class="payloads">{payloads}</ul></div>' if payloads else ''}
        {f'<div class="block"><strong>Step-by-step cURL</strong>{curls}</div>' if curls else ''}
        {f'<p class="rem"><strong>Remediation:</strong> {_esc(rem)}</p>' if rem else ''}
        <p class="meta"><strong>Tools:</strong> {tools}{f' &nbsp;·&nbsp; <strong>References:</strong> {refs}' if refs else ''}</p>
      </div>
    </div>"""


# ── HTML ────────────────────────────────────────────────────────────────────
def generate_html(mission: dict) -> str:
    res = mission.get("result", {}) or {}
    guidance = res.get("guidance", []) or []
    recon = res.get("recon", {}) or {}
    stats = res.get("stats", {}) or {}
    ai = res.get("ai", {}) or {}
    cfg = res.get("config") or mission.get("config") or {}
    target = mission.get("target", "")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    guidance = sorted(guidance, key=lambda g: (-SEV_RANK.get(g.get("severity", "INFO"), 0), -g.get("confidence", 0)))
    confirmed = [g for g in guidance if _is_confirmed(g)]
    other = [g for g in guidance if not _is_confirmed(g)]

    score, score_label, score_color = _risk_score(guidance)
    by_sev = stats.get("guidance", {}).get("by_severity", {}) or {}
    for g in guidance:
        by_sev.setdefault(g.get("severity", "INFO"), by_sev.get(g.get("severity", "INFO"), 0))
    endpoints = sum(len(v or []) for v in (recon.get("dir_bust") or {}).values())

    sev_rows = "".join(
        f'<tr><td><span class="sev" style="background:{SEV_COLOR.get(s,"#6b7280")}">{_esc(s)}</span></td>'
        f'<td>{n}</td><td>{round(100*n/max(len(guidance),1))}%</td></tr>'
        for s, n in sorted(by_sev.items(), key=lambda kv: -SEV_RANK.get(kv[0], 0)) if n
    )

    auth_on = isinstance(cfg.get("auth"), dict) and cfg["auth"].get("type") not in (None, "none")
    flags = []
    if cfg.get("recon_loop"): flags.append("recon-loop")
    if cfg.get("headless_dast"): flags.append("headless-DAST")
    if auth_on: flags.append("authenticated")
    if cfg.get("ai_redteam"): flags.append("AI-RedTeam")

    confirmed_html = (
        "".join(_finding_card(g) for g in confirmed)
        if confirmed else
        '<p class="muted">No findings were auto-confirmed. The playbooks below are advisory — verify them manually.</p>'
    )
    other_html = (
        "".join(_finding_card(g) for g in other)
        if other else '<p class="muted">—</p>'
    )

    rem_rows = "".join(
        f'<tr><td><span class="sev" style="background:{SEV_COLOR.get(g.get("severity","INFO"),"#6b7280")}">{_esc(g.get("severity",""))}</span></td>'
        f'<td>{_esc(g.get("title",""))}</td>'
        f'<td>{_esc((g.get("remediation") or {}).get("summary","") if isinstance(g.get("remediation"),dict) else "")}</td></tr>'
        for g in guidance
        if isinstance(g.get("remediation"), dict) and (g.get("remediation") or {}).get("summary")
    )

    ai_html = ""
    if ai.get("triage"):
        ai_html = f'<h2>Executive Narrative <span class="muted">(AI · {_esc(ai.get("model",""))})</span></h2><pre class="ai-text">{_esc(ai["triage"])}</pre>'

    live = recon.get("live_hosts", []) or []
    live_rows = "".join(
        f"<tr><td><code>{_esc(h.get('url',''))}</code></td><td>{_esc(h.get('status-code',''))}</td>"
        f"<td>{_esc(', '.join((h.get('tech') or [])[:4]))}</td><td>{_esc((h.get('title') or '')[:50])}</td></tr>"
        for h in live[:60]
    )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment · {_esc(target)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;font-size:13px;line-height:1.6;color:#1a1a1a;background:#fff;max-width:1080px;margin:0 auto;padding:0 40px 60px}}
.cover{{text-align:center;padding:70px 40px 44px;border-bottom:3px solid #1e293b;margin-bottom:32px}}
.cover h1{{font-size:30px;font-weight:800;color:#0f172a;margin-bottom:6px}}
.cover .dom{{font-size:16px;color:#64748b;font-family:'SF Mono','Consolas',monospace}}
.cover-meta{{margin-top:28px;display:inline-block;text-align:left}}
.cover-meta td{{padding:5px 16px;vertical-align:middle}}
.cover-meta .l{{font-weight:600;color:#64748b;text-align:right}}
.badge{{display:inline-block;padding:4px 16px;border-radius:6px;font-size:14px;font-weight:700;text-transform:uppercase;color:#fff}}
h2{{font-size:19px;font-weight:700;color:#0f172a;border-bottom:2px solid #e2e8f0;padding-bottom:7px;margin:34px 0 14px}}
.cards{{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}}
.mc{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 18px;min-width:110px;text-align:center;flex:1}}
.mc b{{display:block;font-size:22px;font-weight:700;color:#0f172a}}
.mc span{{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.4px}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;margin:10px 0}}
th{{background:#f1f5f9;text-align:left;padding:8px 12px;border-bottom:2px solid #e2e8f0;color:#475569;font-size:11px;text-transform:uppercase;letter-spacing:.3px}}
td{{padding:7px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}}
.sev{{color:#fff;font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;text-transform:uppercase}}
.finding{{padding:14px 18px;margin-bottom:12px;border-radius:6px}}
.finding-head{{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:8px}}
.finding-title{{font-weight:700;font-size:14px;color:#0f172a}}
.tier{{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;text-transform:uppercase}}
.tier-confirmed{{background:#dcfce7;color:#166534}}
.tier-advisory{{background:#e0e7ff;color:#3730a3}}
.tier-hunch{{background:#fef9c3;color:#854d0e}}
.conf,.wstg{{font-size:11px;color:#64748b}}
.finding-body p{{margin:5px 0;color:#334155}}
.block{{margin:10px 0;padding:9px 12px;background:#fff;border:1px solid #e2e8f0;border-radius:6px}}
.block strong{{display:block;margin-bottom:5px;color:#0f172a;font-size:12px}}
.block ol,.block ul{{margin-left:18px}}
.rem{{background:#f0fdf4;border-left:3px solid #16a34a;padding:6px 10px;border-radius:4px}}
code{{background:#f1f5f9;color:#0f172a;padding:1px 5px;border-radius:4px;font-family:'SF Mono','Consolas',monospace;font-size:11.5px;word-break:break-all}}
pre{{background:#0f172a;color:#e2e8f0;padding:9px 11px;border-radius:5px;overflow-x:auto;font-size:11.5px;margin:5px 0;font-family:'SF Mono','Consolas',monospace}}
.payloads code{{color:#b91c1c}}
.curl-desc{{color:#2563eb;font-size:11px;margin-top:6px;font-weight:600}}
.meta{{color:#64748b;font-size:11.5px}}
.ai-text{{white-space:pre-wrap;background:#f8fafc;border-left:3px solid #3b82f6;padding:14px 18px;border-radius:0 6px 6px 0;color:#334155;font-family:inherit;font-size:13px}}
a{{color:#2563eb;text-decoration:none}}a:hover{{text-decoration:underline}}
.muted{{color:#94a3b8;font-style:italic}}
.note{{background:#f0fdf4;border-left:4px solid #16a34a;padding:10px 16px;border-radius:0 6px 6px 0;color:#166534;font-size:12.5px;margin:14px 0}}
footer{{margin-top:48px;padding-top:18px;border-top:2px solid #e2e8f0;text-align:center;color:#94a3b8;font-size:11px}}
@media print{{body{{padding:0;max-width:none}}.finding,tr{{page-break-inside:avoid}}.cover{{page-break-after:always}}a{{color:inherit}}}}
@page{{size:A4;margin:15mm 18mm}}
</style></head><body>
<div class="cover">
  <h1>Security Assessment Report</h1>
  <p class="dom">{_esc(target)}</p>
  <div class="cover-meta"><table>
    <tr><td class="l">Date</td><td>{ts}</td></tr>
    <tr><td class="l">Scan mode</td><td>{_esc(mission.get('mode',''))}{(' · ' + ', '.join(flags)) if flags else ''}</td></tr>
    <tr><td class="l">Risk score</td><td><span class="badge" style="background:{score_color}">{score}/100 {score_label}</span></td></tr>
    <tr><td class="l">Classification</td><td><strong>CONFIDENTIAL</strong></td></tr>
  </table></div>
</div>

<h2>1. Executive Summary</h2>
<div class="cards">
  <div class="mc"><b style="color:{score_color}">{score}</b><span>Risk / 100</span></div>
  <div class="mc"><b>{len(confirmed)}</b><span>Confirmed</span></div>
  <div class="mc"><b>{len(guidance)}</b><span>Total findings</span></div>
  <div class="mc"><b>{stats.get('live_hosts',0)}</b><span>Live hosts</span></div>
  <div class="mc"><b>{endpoints}</b><span>Endpoints</span></div>
  <div class="mc"><b>{stats.get('open_ports',0)}</b><span>Open ports</span></div>
</div>
<table><thead><tr><th>Severity</th><th>Count</th><th>Share</th></tr></thead><tbody>{sev_rows or '<tr><td colspan=3 class=muted>No findings</td></tr>'}</tbody></table>
<div class="note"><strong>Methodology &amp; scope note:</strong> Round Table is advisory/recon-first. "Confirmed" findings were validated with safe, non-destructive probes (and, where enabled, a real headless browser); it never weaponizes or exploits. Advisory playbooks give the exact steps, payloads, and cURL for the tester to verify. Test only within authorized scope.</div>
{ai_html}

<h2>2. Confirmed Findings ({len(confirmed)})</h2>
{confirmed_html}

<h2>3. Test Playbooks — Advisory &amp; Hunches ({len(other)})</h2>
{other_html}

<h2>4. Remediation Summary</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Recommended remediation</th></tr></thead><tbody>{rem_rows or '<tr><td colspan=3 class=muted>—</td></tr>'}</tbody></table>

<h2>5. Attack Surface — Live Hosts</h2>
<table><thead><tr><th>URL</th><th>Status</th><th>Tech</th><th>Title</th></tr></thead><tbody>{live_rows or '<tr><td colspan=4 class=muted>None (passive mode or no active scan)</td></tr>'}</tbody></table>

<footer>Generated by Round Table on {ts} · recon &amp; advisory only — no exploitation.<br>This document contains confidential security assessment results. Handle according to classification. · github.com/eBruno-Sec/MISC</footer>
</body></html>"""


# ── Markdown ─────────────────────────────────────────────────────────────────
def generate_markdown(mission: dict) -> str:
    res = mission.get("result", {}) or {}
    guidance = res.get("guidance", []) or []
    target = mission.get("target", "")
    stats = res.get("stats", {}) or {}
    ai = res.get("ai", {}) or {}
    guidance = sorted(guidance, key=lambda g: (-SEV_RANK.get(g.get("severity", "INFO"), 0), -g.get("confidence", 0)))
    confirmed = [g for g in guidance if _is_confirmed(g)]
    other = [g for g in guidance if not _is_confirmed(g)]
    score, score_label, _ = _risk_score(guidance)
    out = [
        f"# Security Assessment Report — {target}",
        f"_Mode: {mission.get('mode','')} · Generated {datetime.now():%Y-%m-%d %H:%M}_",
        "",
        f"**Risk score:** {score}/100 ({score_label}) · **Confirmed:** {len(confirmed)} · "
        f"**Total findings:** {len(guidance)} · **Live hosts:** {stats.get('live_hosts',0)} · "
        f"**Open ports:** {stats.get('open_ports',0)}",
        "",
        "> Round Table is advisory/recon-first. \"Confirmed\" findings were validated with safe, "
        "non-destructive probes; it never weaponizes. Test only within authorized scope.",
        "",
    ]
    if ai.get("triage"):
        out += ["## Executive Narrative (AI)", "", "```", ai["triage"], "```", ""]

    def _emit(g):
        out.append(f"### [{g['severity']} · {g['confidence_label']} {g['confidence']}%] {g['title']}")
        out.append(f"- **Where:** `{g['surface']}`")
        out.append(f"- **WSTG:** {g.get('wstg','')}")
        out.append(f"- **Evidence:** {g.get('evidence','')}")
        out.append(f"- **What to test:** {g.get('what_to_test','')}")
        if g.get("how_to_test"):
            out.append("- **How to test:**")
            out += [f"  {i}. {s}" for i, s in enumerate(g["how_to_test"], 1)]
        if g.get("payloads"):
            out.append("- **Payloads:**")
            out += [f"  - `{p}`" for p in g["payloads"]]
        if g.get("curl_steps"):
            out.append("- **cURL:**")
            for c in g["curl_steps"]:
                out.append(f"  - {c.get('desc','')}:")
                out.append(f"    ```bash\n    {c.get('cmd','')}\n    ```")
        out.append(f"- **Tools:** {', '.join(g.get('tools', []))}")
        if g.get("references"):
            out.append("- **References:** " + ", ".join(f"[{r['title']}]({r['url']})" for r in g["references"]))
        out.append("")

    out += [f"## Confirmed Findings ({len(confirmed)})", ""]
    if confirmed:
        for g in confirmed:
            _emit(g)
    else:
        out += ["_No findings were auto-confirmed; the advisory playbooks below require manual verification._", ""]
    out += [f"## Test Playbooks — Advisory & Hunches ({len(other)})", ""]
    for g in other:
        _emit(g)
    return "\n".join(out)


# ── CSV ──────────────────────────────────────────────────────────────────────
def generate_csv(mission: dict) -> str:
    res = mission.get("result", {}) or {}
    guidance = res.get("guidance", []) or []
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["severity", "confidence", "title", "surface", "wstg", "category",
                "what_to_test", "how_to_test", "payloads", "tools", "curl", "references"])
    for g in guidance:
        w.writerow([
            g["severity"], f"{g['confidence']}% ({g['confidence_label']})", g["title"], g["surface"],
            g.get("wstg", ""), g.get("category", ""), g.get("what_to_test", ""),
            " | ".join(g.get("how_to_test", [])),
            " | ".join(g.get("payloads", [])),
            ", ".join(g.get("tools", [])),
            " | ".join(c.get("cmd", "") for c in g.get("curl_steps", [])),
            " ; ".join(r["url"] for r in g.get("references", [])),
        ])
    return buf.getvalue()


def _redact_auth(result: dict) -> dict:
    """Never let a session cookie/token leave in an exported report — redact the
    auth secrets while keeping the fact that the scan was authenticated."""
    import copy
    r = copy.deepcopy(result) if isinstance(result, dict) else {}
    cfg = r.get("config")
    if isinstance(cfg, dict) and isinstance(cfg.get("auth"), dict):
        a = cfg["auth"]
        if a.get("cookie"):
            a["cookie"] = "***redacted***"
        if a.get("bearer"):
            a["bearer"] = "***redacted***"
        if a.get("headers"):
            a["headers"] = [h.split(":", 1)[0] + ": ***redacted***" if ":" in h else "***redacted***"
                            for h in a["headers"]]
    return r


def generate_json(mission: dict) -> str:
    return json.dumps(_redact_auth(mission.get("result", {})), indent=2, default=str)
