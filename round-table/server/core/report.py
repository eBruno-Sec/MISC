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
    "LOW": "#65a30d", "INFO": "#0891b2", "UNKNOWN": "#6b7280",
}


def _esc(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


# ── HTML ────────────────────────────────────────────────────────────────────
def generate_html(mission: dict) -> str:
    res = mission.get("result", {}) or {}
    guidance = res.get("guidance", []) or []
    recon = res.get("recon", {}) or {}
    stats = res.get("stats", {}) or {}
    ai = res.get("ai", {}) or {}
    target = mission.get("target", "")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    gstats = stats.get("guidance", {})
    guidance_total = gstats.get("total", 0)
    by_sev = gstats.get("by_severity", {})
    sev_chips = "".join(
        f'<span class="chip" style="background:{SEV_COLOR.get(s, "#6b7280")}">{_esc(s)} {n}</span>'
        for s, n in sorted(by_sev.items(), key=lambda kv: -{"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}.get(kv[0],0))
    )

    cards = []
    for g in guidance:
        color = SEV_COLOR.get(g["severity"], "#6b7280")
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
        cards.append(f"""
        <div class="card">
          <div class="card-head" style="border-left:6px solid {color}">
            <span class="sev" style="background:{color}">{_esc(g['severity'])}</span>
            <span class="conf">Confidence: {_esc(g['confidence_label'])} ({g['confidence']}%)</span>
            <span class="wstg">{_esc(g.get('wstg',''))}</span>
            <h3>{_esc(g['title'])}</h3>
          </div>
          <div class="card-body">
            <p class="surface"><strong>Where:</strong> <code>{_esc(g['surface'])}</code></p>
            <p><strong>Evidence:</strong> {_esc(g.get('evidence',''))}</p>
            <p><strong>What to test:</strong> {_esc(g.get('what_to_test',''))}</p>
            {f'<div class="block"><strong>How to test</strong><ol>{steps}</ol></div>' if steps else ''}
            {f'<div class="block"><strong>Recommended payloads / injections</strong><ul class="payloads">{payloads}</ul></div>' if payloads else ''}
            {f'<div class="block"><strong>Step-by-step cURL</strong>{curls}</div>' if curls else ''}
            <p class="meta"><strong>Tools:</strong> {tools}</p>
            {f'<p class="meta"><strong>References:</strong> {refs}</p>' if refs else ''}
          </div>
        </div>""")

    ai_html = ""
    if ai.get("triage"):
        ai_html = f"""
        <section class="ai">
          <h2>AI Executive Summary <span class="muted">({_esc(ai.get('model',''))})</span></h2>
          <pre class="ai-text">{_esc(ai['triage'])}</pre>
        </section>"""

    live = recon.get("live_hosts", []) or []
    live_rows = "".join(
        f"<tr><td><code>{_esc(h.get('url',''))}</code></td><td>{_esc(h.get('status-code',''))}</td>"
        f"<td>{_esc(', '.join(h.get('tech', [])[:4]))}</td><td>{_esc((h.get('title') or '')[:50])}</td></tr>"
        for h in live[:60]
    )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Round Table Report · {_esc(target)}</title>
<style>
:root{{color-scheme:light dark}}
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;background:#0b0f17;color:#e5e7eb;line-height:1.55}}
.wrap{{max-width:1000px;margin:0 auto;padding:32px 20px 80px}}
header h1{{margin:0 0 4px;font-size:24px}}
header .sub{{color:#9ca3af;font-size:14px}}
.stripe{{height:4px;background:linear-gradient(90deg,#dc2626,#ea580c,#d97706,#65a30d,#0891b2);border-radius:2px;margin:16px 0}}
.chips{{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}}
.chip{{color:#fff;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}}
.statgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:16px 0}}
.stat{{background:#131a26;border:1px solid #1f2937;border-radius:10px;padding:12px}}
.stat b{{display:block;font-size:22px}}
.stat span{{color:#9ca3af;font-size:12px}}
h2{{margin:28px 0 10px;font-size:18px;border-bottom:1px solid #1f2937;padding-bottom:6px}}
.card{{background:#111827;border:1px solid #1f2937;border-radius:12px;margin:14px 0;overflow:hidden}}
.card-head{{padding:14px 16px;background:#0f1522}}
.card-head h3{{margin:8px 0 0;font-size:16px}}
.sev{{color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;margin-right:8px}}
.conf,.wstg{{font-size:12px;color:#9ca3af;margin-right:10px}}
.card-body{{padding:14px 16px;font-size:14px}}
.card-body p{{margin:6px 0}}
.block{{margin:12px 0;padding:10px 12px;background:#0d1420;border-radius:8px}}
.block strong{{display:block;margin-bottom:6px;color:#cbd5e1}}
code{{background:#0b1220;color:#7dd3fc;padding:1px 5px;border-radius:4px;font-size:13px;word-break:break-all}}
pre{{background:#0b1220;color:#d1fae5;padding:10px;border-radius:6px;overflow-x:auto;font-size:12.5px;margin:6px 0}}
.payloads code{{color:#fca5a5}}
.curl-desc{{color:#93c5fd;font-size:12px;margin-top:8px}}
.meta{{color:#9ca3af;font-size:12.5px}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0}}
td,th{{border:1px solid #1f2937;padding:6px 8px;text-align:left}}
.ai-text{{white-space:pre-wrap;color:#e5e7eb;background:#0d1420}}
a{{color:#60a5fa}}
.muted{{color:#6b7280;font-weight:400;font-size:13px}}
footer{{margin-top:40px;color:#6b7280;font-size:12px;text-align:center}}
</style></head><body><div class="wrap">
<header>
  <h1>Round Table · Recon &amp; Test-Guidance Report</h1>
  <div class="sub">Target: <strong>{_esc(target)}</strong> · Mode: {_esc(mission.get('mode',''))} · Generated {ts}</div>
</header>
<div class="stripe"></div>
<div class="chips">{sev_chips or '<span class="muted">No guidance generated</span>'}</div>
<div class="statgrid">
  <div class="stat"><b>{stats.get('subdomains',0)}</b><span>Subdomains</span></div>
  <div class="stat"><b>{stats.get('live_hosts',0)}</b><span>Live hosts</span></div>
  <div class="stat"><b>{stats.get('open_ports',0)}</b><span>Open ports</span></div>
  <div class="stat"><b>{stats.get('nuclei',0)}</b><span>Nuclei hits</span></div>
  <div class="stat"><b>{guidance_total}</b><span>Test playbooks</span></div>
</div>
{ai_html}
<h2>Test Playbooks ({len(guidance)})</h2>
{''.join(cards) if cards else '<p class="muted">No playbooks — try Active mode for a live application.</p>'}
<h2>Live Hosts</h2>
<table><tr><th>URL</th><th>Status</th><th>Tech</th><th>Title</th></tr>{live_rows or '<tr><td colspan=4 class=muted>None (passive mode or no active scan)</td></tr>'}</table>
<footer>Round Table // recon &amp; advisory only — no exploitation. Test only within authorized scope.<br>github.com/eBruno-Sec/round-table</footer>
</div></body></html>"""


# ── Markdown ─────────────────────────────────────────────────────────────────
def generate_markdown(mission: dict) -> str:
    res = mission.get("result", {}) or {}
    guidance = res.get("guidance", []) or []
    target = mission.get("target", "")
    stats = res.get("stats", {}) or {}
    ai = res.get("ai", {}) or {}
    g_total = stats.get("guidance", {}).get("total", 0)
    out = [
        f"# Round Table Report — {target}",
        f"_Mode: {mission.get('mode','')} · Generated {datetime.now():%Y-%m-%d %H:%M:%S}_",
        "",
        f"**Subdomains:** {stats.get('subdomains',0)} · **Live hosts:** {stats.get('live_hosts',0)} · "
        f"**Open ports:** {stats.get('open_ports',0)} · **Playbooks:** {g_total}",
        "",
    ]
    if ai.get("triage"):
        out += ["## AI Executive Summary", "", "```", ai["triage"], "```", ""]
    out += ["## Test Playbooks", ""]
    for g in guidance:
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


def generate_json(mission: dict) -> str:
    return json.dumps(mission.get("result", {}), indent=2, default=str)
