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


def generate_report(program: str, findings: list, scope: dict,
                     coverage: dict = None, chains: list = None, status: str = None) -> str:
    now = _now()
    banner = _status_note(status)
    if not findings:
        return (
            f"# Security Assessment Report: {program}\n\n"
            + (banner + "\n\n" if banner else "")
            + f"**Date:** {now}\n"
            f"**Scope:** {', '.join(scope.get('in_scope', []))}\n\n"
            + ("No confirmed vulnerabilities were recorded"
               + (" before the run ended early." if banner else " during this engagement.") + "\n")
        )

    findings = sorted(findings, key=lambda f: SEV_ORDER.get((f.get("severity") or "informational").lower(), 5))
    counts = _counts(findings)

    lines = [
        f"# Security Assessment Report: {program}", "",
        f"**Date:** {now}",
        f"**Scope:** {', '.join(scope.get('in_scope', []))}",
        f"**Total Findings:** {len(findings)}", "",
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
    return "\n".join(lines)


# ── HTML (dark-themed standalone, all fields escaped) ────────────
def generate_html_report(program: str, findings: list, scope: dict,
                         coverage: dict = None, chains: list = None, status: str = None) -> str:
    e = _html.escape
    counts = _counts(findings)
    findings = sorted(findings, key=lambda f: SEV_ORDER.get((f.get("severity") or "informational").lower(), 5))

    peek = "".join(
        f'<span class="chip" style="--c:{SEV_COLORS.get(s, "#6a8a9a")}">{e(s.upper())}: {counts[s]}</span>'
        for s in ["critical", "high", "medium", "low", "info", "informational"] if s in counts
    ) or '<span class="chip" style="--c:#6a8a9a">NO FINDINGS</span>'

    cov_html = ""
    if coverage:
        rows = "".join(f"<div class='cov'><span>{e(str(v))}</span><label>{e(k.replace('_',' '))}</label></div>"
                       for k, v in coverage.items())
        cov_html = f"<h2>Assessment Coverage</h2><div class='cov-grid'>{rows}</div>"

    cards = []
    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "informational").lower()
        color = SEV_COLORS.get(sev, "#6a8a9a")
        steps = "".join(f"<li>{e(str(s))}</li>" for s in (f.get("reproduction_steps") or []))
        ev = f"<pre class='ev'>{e(str(f.get('evidence','')))}</pre>" if f.get("evidence") else ""
        notes = f"<p class='notes'>Triage: {e(str(f.get('analyst_notes','')))}</p>" if f.get("analyst_notes") else ""
        rem = f"<h4>Remediation</h4><p>{e(str(f.get('remediation','')))}</p>" if f.get("remediation") else ""
        cards.append(f"""
        <article class="finding" style="--c:{color}">
          <div class="fh"><span class="sev">{e(sev.upper())}</span><h3>{i}. {e(str(f.get('title','Untitled')))}</h3></div>
          <div class="meta">
            <span>Target: <code>{e(str(f.get('target','')))}</code></span>
            <span>CVSS: {e(str(f.get('cvss_score','N/A')))}</span>
            <span>CWE: {e(str(f.get('cwe','N/A')))}</span>
            {f"<span>OWASP: {e(str(f.get('owasp')))}</span>" if f.get('owasp') else ''}
          </div>
          <p>{e(str(f.get('description','')))}</p>
          {f"<h4>Steps to Reproduce</h4><ol>{steps}</ol>" if steps else ''}
          <h4>Impact</h4><p>{e(str(f.get('impact','')))}</p>
          {rem}{ev}{notes}
        </article>""")

    chain_html = ""
    if chains:
        items = "".join(f"<li><b>{e(str(c.get('host')))}</b> "
                        f"<span class='sev' style='--c:{SEV_COLORS.get((c.get('severity') or '').lower(),'#6a8a9a')}'>"
                        f"{e(str((c.get('severity') or '').upper()))}</span> — {e(str(c.get('narrative')))}</li>"
                        for c in chains)
        chain_html = f"<h2>Attack-Path Chains</h2><ul class='chains'>{items}</ul>"

    scope_str = e(", ".join(scope.get("in_scope", [])))
    _sn = _status_note(status)
    status_html = (f'<div class="statusbar">{e(_sn.lstrip("> ").replace("**",""))}</div>' if _sn else "")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Apolaki Report — {e(program)}</title>
<style>
:root{{--bg:#020608;--surface:#080e12;--border:#0e2535;--text:#c8dde6;--dim:#6a8a9a;--bright:#f0f8fc;--accent:#00e5ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font-family:'JetBrains Mono',ui-monospace,monospace;line-height:1.6}}
.wrap{{max-width:960px;margin:0 auto;padding:2rem 1.25rem}}
h1{{color:var(--accent);font-size:1.5rem}}h2{{color:var(--bright);border-bottom:1px solid var(--border);padding-bottom:.4rem;margin-top:2.5rem}}
h3{{color:var(--bright);margin:.2rem 0}}h4{{color:var(--dim);text-transform:uppercase;font-size:.72rem;letter-spacing:.1em;margin:1rem 0 .3rem}}
.head{{border-bottom:1px solid var(--border);padding-bottom:1rem}}.sub{{color:var(--dim);font-size:.8rem}}
.chips{{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}}
.chip{{border:1px solid var(--c);color:var(--c);padding:.2rem .6rem;font-size:.72rem;letter-spacing:.08em}}
.cov-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:.6rem}}
.cov{{border:1px solid var(--border);background:var(--surface);padding:.7rem;text-align:center}}
.cov span{{display:block;font-size:1.4rem;color:var(--accent);font-weight:700}}.cov label{{font-size:.62rem;color:var(--dim);text-transform:uppercase}}
.finding{{border:1px solid var(--border);border-left:3px solid var(--c);background:var(--surface);padding:1.1rem;margin:1rem 0}}
.fh{{display:flex;align-items:center;gap:.7rem}}.sev{{border:1px solid var(--c);color:var(--c);font-size:.62rem;padding:.15rem .5rem;letter-spacing:.1em}}
.meta{{display:flex;gap:1rem;flex-wrap:wrap;font-size:.72rem;color:var(--dim);margin:.5rem 0}}
code{{color:var(--accent)}}.ev{{background:var(--bg);border:1px solid var(--border);padding:.7rem;overflow:auto;font-size:.75rem;white-space:pre-wrap}}
.notes{{color:var(--dim);font-style:italic;font-size:.78rem;border-top:1px dashed var(--border);padding-top:.5rem}}
ol,ul{{padding-left:1.3rem}}.chains li{{margin:.3rem 0}}
footer{{margin-top:3rem;color:var(--dim);font-size:.7rem;border-top:1px solid var(--border);padding-top:1rem}}
.pdfbtn{{position:fixed;top:1rem;right:1rem;background:var(--accent);color:#001;border:none;font-family:inherit;
  font-size:.8rem;font-weight:700;padding:.5rem .9rem;cursor:pointer;border-radius:3px;z-index:10}}
.statusbar{{background:rgba(231,148,87,.14);border:1px solid #e79457;color:#e79457;padding:.6rem .8rem;
  margin:1rem 0;border-radius:4px;font-size:.8rem}}
/* Print / Save-as-PDF: white background, ink-friendly, keep findings whole */
@media print{{
  :root{{--bg:#fff;--surface:#fff;--border:#bbb;--text:#111;--dim:#555;--bright:#000;--accent:#04c}}
  body{{background:#fff;color:#111}}
  .wrap{{max-width:100%;padding:0 .5rem}}
  .finding{{break-inside:avoid;page-break-inside:avoid}}
  .ev{{white-space:pre-wrap;word-break:break-word}}
  a{{color:#04c}}
  .pdfbtn,.noprint{{display:none!important}}
}}
</style></head><body>
<button class="pdfbtn noprint" onclick="window.print()">Save as PDF</button>
<div class="wrap">
<div class="head"><h1>Security Assessment Report — {e(program)}</h1>
<div class="sub">Generated {e(_now())} · Scope: {scope_str} · {len(findings)} finding(s)</div>
{status_html}
<div class="chips">{peek}</div></div>
{cov_html}
{chain_html}
<h2>Findings</h2>
{''.join(cards) if cards else "<p class='sub'>No confirmed vulnerabilities found during this engagement.</p>"}
<footer>Apolaki · authorized security research only. Verify every finding before submitting.</footer>
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
                  coverage: dict = None, chains: list = None) -> str:
    return json.dumps({
        "program": program,
        "generated": _now(),
        "scope": scope,
        "counts": _counts(findings),
        "coverage": coverage or {},
        "chains": chains or [],
        "findings": findings,
    }, indent=2, default=str)
