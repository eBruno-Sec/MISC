import os
import json
import html as _html
import secrets
from datetime import datetime
from core.ai_client import complete
from core.config import settings
from core.models import Finding
from core.surface import build_inventory
from sqlalchemy import select
from .base import BaseAgent

SEVERITY_COLORS = {
    "critical": "#ff0040",
    "high": "#ff3d6b",
    "medium": "#f59e0b",
    "low": "#00e5ff",
    "info": "#6a8a9a",
}

CVSS_MAP = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


class Apollo(BaseAgent):
    name = "apollo"
    symbol = "☀"
    display_name = "APOLLO"
    role = "Reporting & Risk Analysis"

    async def execute(self, target: str, context: dict = None) -> dict:
        await self.log("Compiling intelligence from all agents", "info")

        # Load all findings from DB
        result_db = await self.session.execute(
            select(Finding).where(Finding.mission_id == self.mission_id).order_by(Finding.timestamp)
        )
        findings = result_db.scalars().all()

        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            stats[sev] = stats.get(sev, 0) + 1

        await self.log(f"Findings: {stats['critical']} CRITICAL | {stats['high']} HIGH | {stats['medium']} MEDIUM | {stats['low']} LOW", "info")

        # AI executive summary (never fatal)
        try:
            exec_summary = await self._ai_summary(target, findings, context, stats)
        except Exception as e:
            await self.log(f"Executive summary generation failed: {e}. Using template.", "warn")
            exec_summary = self._default_summary(target, stats, context)

        # Generate report (never fatal — a render error must not fail a completed mission)
        report_path = ""
        try:
            report_path = await self._generate_html_report(target, findings, stats, exec_summary, context)
            await self.log(f"Report saved: {report_path}", "success")
        except Exception as e:
            await self.log(f"Report generation failed: {e}. Findings are preserved and exportable.", "error")

        await self.log(f"Mission assessment complete for {target}", "success")

        return {
            "report_path": report_path,
            "stats": stats,
            "total_findings": len(findings),
            "exec_summary": exec_summary,
        }

    async def _ai_summary(self, target: str, findings: list, context: dict, stats: dict) -> str:
        api_key = os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            return self._default_summary(target, stats, context)

        try:
            mode = (context or {}).get("athena", {}).get("mode", "passive")
            top_findings = [
                f"{fnd.title} ({fnd.severity.upper()}) - {(fnd.description or '')[:100]}"
                for fnd in sorted(findings, key=lambda x: CVSS_MAP.get(x.severity, 0), reverse=True)[:10]
            ]
            prompt = f"""You are APOLLO, the reporting module of the OLYMPUS security assessment platform.
Write a concise executive summary (3-4 paragraphs) for this authorized security assessment.

Target: {target}
Mode: {mode}
Findings: {stats["critical"]} critical, {stats["high"]} high, {stats["medium"]} medium, {stats["low"]} low

Top findings:
{chr(10).join(top_findings)}

Write as a professional security engineer reporting to a CISO. Focus on:
1. Overall risk posture
2. Most critical findings and business impact
3. Priority remediation roadmap
4. Risk reduction opportunities

Use plain text, no markdown headers, no bullet points. 3-4 tight paragraphs."""

            text = await complete(prompt, max_tokens=600)
            return text if text else self._default_summary(target, stats, context)
        except Exception as e:
            await self.log(f"AI summary failed: {e}. Using template summary.", "warn")
            return self._default_summary(target, stats, context)

    def _default_summary(self, target: str, stats: dict, context: dict) -> str:
        mode = (context or {}).get("athena", {}).get("mode", "passive")
        total = sum(stats.values())
        return (
            f"This {mode} security assessment of {target} identified {total} findings across "
            f"{stats['critical']} critical, {stats['high']} high, {stats['medium']} medium, "
            f"and {stats['low']} low severity categories. "
            f"Immediate remediation focus should be directed at critical and high-severity findings "
            f"to reduce exposure. Medium findings represent configuration and best-practice gaps "
            f"that should be addressed in a planned remediation cycle. "
            f"Full finding details, evidence, and remediation guidance are documented in this report."
        )

    # OWASP probe modules the offensive engine runs (context["ares"]["offensive"]).
    _MODULES = [
        ("sqli", "SQL Injection"), ("xss", "Cross-Site Scripting"), ("ssrf", "SSRF"),
        ("ssti", "Template Injection"), ("traversal", "Path Traversal"),
        ("open_redirect", "Open Redirect"), ("cors", "CORS Misconfiguration"),
        ("host_header", "Host-Header Injection"), ("auth", "Access Control / Auth"),
        ("dast", "DAST (dalfox)"), ("zap", "OWASP ZAP Active Scan"),
        ("content", "Content Discovery"), ("fuzz", "Parameter Auto-Fuzz"),
        ("forms", "Form / POST Injection"),
    ]
    # Discovered paths worth a manual look (candidates, never auto-confirmed).
    _INTERESTING = (
        "admin", "login", "api", "graphql", "upload", "debug", "backup",
        ".git", ".env", "config", "actuator", "swagger", "console",
        "dashboard", "manager", "phpmyadmin", "wp-admin", "setup", "install",
    )

    def _recon_sections(self, context: dict, subdomains: list, live_hosts: list):
        """Coverage panel, discovered content paths, and manual-test candidates —
        all derived from REAL recon data (never fabricated). Returns three HTML
        fragments (each may be ''). This is the coverage transparency Yggdrasil
        won on, kept honest: it only reports numbers the agents actually produced."""
        ares = (context or {}).get("ares", {}) or {}
        if not ares:
            return "", "", "", ""
        offensive = ares.get("offensive", {}) or {}
        directories = ares.get("directories", []) or []
        nuclei_hits = len(ares.get("vulnerabilities", []) or [])
        ran = bool(offensive)

        # 1) Coverage metrics + OWASP module matrix
        metrics = [
            ("Subdomains discovered", len(subdomains or [])),
            ("Live hosts", len(live_hosts or [])),
            ("Hosts actively scanned", offensive.get("hosts_scanned", ares.get("targets_scanned", 0))),
            ("URLs crawled", offensive.get("crawled_urls", 0)),
            ("Content paths found", len(directories)),
            ("Nuclei findings", nuclei_hits),
        ]
        metric_cells = "".join(
            f'<div class="cov-cell"><div class="cov-num">{_html.escape(str(v))}</div>'
            f'<div class="cov-label">{_html.escape(label)}</div></div>'
            for label, v in metrics
        )
        rows = ""
        for key, label in self._MODULES:
            hits = len(offensive.get(key, []) or [])
            state = "tested" if ran else "not run"
            state_cls = "mod-ok" if ran else "mod-skip"
            rows += (f'<tr><td>{_html.escape(label)}</td>'
                     f'<td class="{state_cls}">{state}</td>'
                     f'<td class="mod-hits">{hits if ran else "—"}</td></tr>')
        coverage_html = (
            '<div class="section"><h2>Assessment Coverage</h2>'
            f'<div class="cov-grid">{metric_cells}</div>'
            '<table class="cov-table"><thead><tr><th>OWASP Test Module</th>'
            '<th>Status</th><th>Hits</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

        # 1b) Attack-surface inventory (deduped endpoints + params)
        surface_html = ""
        inventory = build_inventory(offensive.get("endpoints", []) or [])
        if inventory:
            param_eps = sum(1 for e in inventory if e["parameterized"])
            erows = ""
            for e in inventory[:200]:
                params = ", ".join(e["params"][:12])
                if len(e["params"]) > 12:
                    params += f' +{len(e["params"]) - 12}'
                erows += (f'<tr><td class="path-url">{_html.escape(e["path"])}</td>'
                          f'<td class="surf-host">{_html.escape(e["host"])}</td>'
                          f'<td class="surf-params">{_html.escape(params)}</td></tr>')
            surface_html = (
                f'<div class="section"><h2>Attack Surface ({len(inventory)} endpoints, '
                f'{param_eps} parameterized)</h2>'
                '<table class="path-table"><thead><tr><th>Path</th><th>Host</th>'
                f'<th>Parameters</th></tr></thead><tbody>{erows}</tbody></table></div>'
            )

        # 2) Discovered content paths (real ffuf/crawl results)
        paths_html = ""
        if directories:
            prows = ""
            for d in directories[:250]:
                st = d.get("status", 0)
                cls = ("st-200" if st == 200 else "st-redir" if st in (301, 302)
                       else "st-403" if st == 403 else "st-other")
                prows += (f'<tr><td class="path-url">{_html.escape(d.get("url", ""))}</td>'
                          f'<td class="{cls}">{_html.escape(str(st))}</td>'
                          f'<td class="path-note">{_html.escape(d.get("note", "") or "")}</td></tr>')
            paths_html = (
                f'<div class="section"><h2>Discovered Content Paths ({len(directories)})</h2>'
                '<table class="path-table"><thead><tr><th>Path</th><th>Status</th>'
                f'<th>Note</th></tr></thead><tbody>{prows}</tbody></table></div>'
            )

        # 3) Manual test candidates (interesting paths -> manual review, NOT confirmed)
        seen, cands = set(), []
        for d in directories:
            u = d.get("url", "")
            low = u.lower()
            kw = next((k for k in self._INTERESTING if k in low), None)
            if kw and u not in seen:
                seen.add(u)
                cands.append((u, d.get("status", 0), kw))
        candidates_html = ""
        if cands:
            items = "".join(
                f'<li><input type="checkbox"> <span class="cand-url">{_html.escape(u)}</span>'
                f' <span class="cand-kw">{_html.escape(kw)}</span>'
                f' <span class="cand-st">HTTP {_html.escape(str(st))}</span></li>'
                for u, st, kw in cands[:80]
            )
            candidates_html = (
                '<div class="section"><h2>Manual Test Candidates</h2>'
                '<p class="cand-note">Interesting paths surfaced by recon that warrant manual '
                'review. These are <strong>candidates, not confirmed findings</strong>.</p>'
                f'<ul class="cand-list">{items}</ul></div>'
            )
        return coverage_html, surface_html, paths_html, candidates_html

    async def _generate_html_report(self, target: str, findings: list, stats: dict, exec_summary: str, context: dict) -> str:
        mode = (context or {}).get("athena", {}).get("mode", "passive")
        mission_summary = (context or {}).get("athena", {}).get("mission_summary", "")
        vendors = (context or {}).get("hermes", {}).get("vendors", [])
        subdomains = (context or {}).get("hermes", {}).get("subdomains", [])
        live_hosts = (context or {}).get("hermes", {}).get("live_hosts", [])
        # Coverage transparency panels (real recon numbers only; empty in passive runs).
        coverage_html, surface_html, paths_html, candidates_html = self._recon_sections(context, subdomains, live_hosts)
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        # Per-report nonce so the report's own script runs while any injected
        # inline script is blocked (defense in depth behind the html escaping).
        nonce = secrets.token_urlsafe(16)

        sorted_findings = sorted(
            findings,
            key=lambda x: CVSS_MAP.get(x.severity.lower(), 0),
            reverse=True,
        )

        findings_html = ""
        for i, fnd in enumerate(sorted_findings):
            color = SEVERITY_COLORS.get(fnd.severity.lower(), "#6a8a9a")
            try:
                cvss = float(fnd.cvss_score) if fnd.cvss_score is not None else CVSS_MAP.get(fnd.severity.lower(), 0)
            except (TypeError, ValueError):
                cvss = CVSS_MAP.get(fnd.severity.lower(), 0)
            # Escape every finding field before it enters the HTML. Evidence,
            # titles and descriptions can carry attacker-controlled scan content
            # (XSS PoC payloads, response snippets, ZAP alert text, matched URLs).
            sev = _html.escape((fnd.severity or "info").upper())
            title = _html.escape(fnd.title or "")
            found_by = _html.escape((fnd.found_by or "unknown").upper())
            description = _html.escape(fnd.description or "No description")
            evidence_block = (
                '<div class="field"><span class="field-label">EVIDENCE</span><pre>'
                + _html.escape(fnd.evidence)
                + "</pre></div>"
            ) if fnd.evidence else ""
            remediation_block = (
                '<div class="field"><span class="field-label">REMEDIATION</span><p>'
                + _html.escape(fnd.remediation)
                + "</p></div>"
            ) if fnd.remediation else ""
            findings_html += f"""
            <div class="finding" id="finding-{i}">
                <div class="finding-header">
                    <div>
                        <span class="sev-badge" style="background:{color}20;color:{color};border:1px solid {color}40">{sev}</span>
                        <span class="finding-title">{title}</span>
                    </div>
                    <div class="finding-meta">
                        <span class="cvss">CVSS {cvss:.1f}</span>
                        <span class="found-by">⊕ {found_by}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="field"><span class="field-label">DESCRIPTION</span><p>{description}</p></div>
                    {evidence_block}
                    {remediation_block}
                </div>
            </div>"""

        vendor_html = ""
        for v in vendors:
            vname = _html.escape(v.get("vendor", ""))
            vcat = _html.escape(v.get("category", ""))
            vendor_html += f'<span class="vendor-tag">{vname} <span class="vendor-cat">{vcat}</span></span>'

        # Build host section outside f-string: Python 3.11 cannot use dict["key"] syntax
        # inside single-quote f-string expressions
        if live_hosts:
            _host_items = ""
            for h in live_hosts[:50]:
                hhost = _html.escape(h.get("host", ""))
                hcode = _html.escape(str(h.get("status_code") or ""))
                _host_items += f'<div class="host-item"><span>{hhost}</span><span class="status-ok">{hcode}</span></div>'
            _host_section = (
                f'<div class="section"><h2>Live Hosts ({len(live_hosts)})</h2>'
                f'<div class="host-list">{_host_items}</div></div>'
            )
        else:
            _host_section = ""

        report_payload = {
            "target": target,
            "mode": mode.upper(),
            "date": now,
            "mission_id": self.mission_id,
            "summary": exec_summary,
            "stats": {
                "critical": stats.get("critical", 0),
                "high": stats.get("high", 0),
                "medium": stats.get("medium", 0),
                "low": stats.get("low", 0),
                "info": stats.get("info", 0),
                "total": len(findings),
            },
            "findings": [
                {
                    "title": fnd.title,
                    "severity": fnd.severity,
                    "cvss": fnd.cvss_score,
                    "found_by": fnd.found_by,
                    "description": fnd.description or "",
                    "evidence": fnd.evidence or "",
                    "remediation": fnd.remediation or "",
                }
                for fnd in sorted_findings
            ],
        }
        report_json = json.dumps(report_payload, ensure_ascii=False).replace("</", "<\\/")

        # No inline onclick handlers: they are wired via addEventListener in the
        # nonce'd script below so the report can run under a strict CSP.
        toolbar_html = (
            '<div class="export-bar">'
            '<button id="oly-print">Print / PDF</button>'
            '<button id="oly-md">Markdown</button>'
            '<button id="oly-txt">TXT</button>'
            '<button id="oly-json">JSON</button>'
            '</div>'
        )

        export_script = """<script nonce="__NONCE__">
const REPORT = __REPORT_JSON__;
function olyPrint(){ window.print(); }
function dl(name, mime, text){
  const b = new Blob([text], {type: mime});
  const u = URL.createObjectURL(b);
  const a = document.createElement('a');
  a.href = u; a.download = name; a.click();
  setTimeout(function(){ URL.revokeObjectURL(u); }, 1000);
}
function fname(ext){
  const t = (REPORT.target || 'report').replace(/[^a-z0-9.-]+/gi, '_');
  return 'olympus_' + t + '_' + (REPORT.mission_id || '').slice(0, 8) + '.' + ext;
}
function sevTag(x){ return (x || 'info').toUpperCase(); }
function toTxt(){
  const s = REPORT.stats, L = [];
  L.push('OLYMPUS SECURITY ASSESSMENT');
  L.push('Target: ' + REPORT.target);
  L.push('Mode: ' + REPORT.mode);
  L.push('Date: ' + REPORT.date);
  L.push('Report ID: ' + (REPORT.mission_id || ''));
  L.push('');
  L.push('FINDINGS: ' + s.critical + ' Critical, ' + s.high + ' High, ' + s.medium + ' Medium, ' + s.low + ' Low, ' + s.info + ' Info (Total ' + s.total + ')');
  L.push('');
  L.push('EXECUTIVE SUMMARY');
  L.push(REPORT.summary || '');
  L.push('');
  L.push('FINDINGS DETAIL');
  L.push('');
  REPORT.findings.forEach(function(f, i){
    L.push((i + 1) + '. [' + sevTag(f.severity) + '] ' + f.title);
    if (f.cvss !== null && f.cvss !== undefined) L.push('   CVSS: ' + f.cvss);
    if (f.found_by) L.push('   Source: ' + f.found_by);
    if (f.description) L.push('   Description: ' + f.description);
    if (f.evidence) { L.push('   Evidence:'); f.evidence.split('\n').forEach(function(e){ L.push('     ' + e); }); }
    if (f.remediation) L.push('   Remediation: ' + f.remediation);
    L.push('');
  });
  return L.join('\n');
}
function toMd(){
  const s = REPORT.stats, L = [];
  L.push('# OLYMPUS Security Assessment');
  L.push('');
  L.push('- **Target:** ' + REPORT.target);
  L.push('- **Mode:** ' + REPORT.mode);
  L.push('- **Date:** ' + REPORT.date);
  L.push('- **Report ID:** ' + (REPORT.mission_id || ''));
  L.push('');
  L.push('| Critical | High | Medium | Low | Info | Total |');
  L.push('|---|---|---|---|---|---|');
  L.push('| ' + s.critical + ' | ' + s.high + ' | ' + s.medium + ' | ' + s.low + ' | ' + s.info + ' | ' + s.total + ' |');
  L.push('');
  L.push('## Executive Summary');
  L.push('');
  L.push(REPORT.summary || '');
  L.push('');
  L.push('## Findings');
  L.push('');
  REPORT.findings.forEach(function(f, i){
    L.push('### ' + (i + 1) + '. ' + f.title);
    L.push('');
    var meta = '**Severity:** ' + sevTag(f.severity);
    if (f.cvss !== null && f.cvss !== undefined) meta += '  |  **CVSS:** ' + f.cvss;
    if (f.found_by) meta += '  |  **Source:** ' + f.found_by;
    L.push(meta);
    L.push('');
    if (f.description) { L.push(f.description); L.push(''); }
    if (f.evidence) { L.push('```'); L.push(f.evidence); L.push('```'); L.push(''); }
    if (f.remediation) { L.push('**Remediation:** ' + f.remediation); L.push(''); }
  });
  return L.join('\n');
}
function olyExport(kind){
  if (kind === 'json') return dl(fname('json'), 'application/json', JSON.stringify(REPORT, null, 2));
  if (kind === 'md') return dl(fname('md'), 'text/markdown', toMd());
  return dl(fname('txt'), 'text/plain', toTxt());
}
document.getElementById('oly-print').addEventListener('click', olyPrint);
document.getElementById('oly-md').addEventListener('click', function(){ olyExport('md'); });
document.getElementById('oly-txt').addEventListener('click', function(){ olyExport('txt'); });
document.getElementById('oly-json').addEventListener('click', function(){ olyExport('json'); });
</script>"""
        # Nonce first (touches only the template's script tag), then inject the
        # findings JSON so finding text can never collide with a placeholder.
        export_script = export_script.replace("__NONCE__", nonce)
        export_script = export_script.replace("__REPORT_JSON__", report_json)

        # Escaped header/summary values. target is already validated (no angle
        # brackets), but escape for defense in depth; exec_summary is model/text
        # output and must be treated as untrusted before rendering.
        esc_target = _html.escape(target)
        esc_mode = _html.escape(mode.upper())
        summary_html = chr(10).join(
            f'<p>{_html.escape(p)}</p>' for p in exec_summary.split(chr(10)) if p.strip()
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="script-src 'nonce-{nonce}'; object-src 'none'; base-uri 'none'">
<title>OLYMPUS Report — {esc_target}</title>
<style>
:root {{
  --bg: #020608; --surface: #080e12; --surface2: #0c1820;
  --border: #0e2535; --accent: #00e5ff; --accent2: #ff3d6b;
  --accent3: #39ff14; --gold: #f59e0b; --text: #c8dde6;
  --text-dim: #6a8a9a; --text-bright: #f0f8fc;
  --mono: 'Courier New', monospace;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: var(--mono); padding: 0; }}
.report-header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 3rem; }}
.report-header .classification {{ font-size: .7rem; letter-spacing: .3em; color: var(--accent3); margin-bottom: 1rem; }}
.report-header h1 {{ font-size: 2.5rem; color: var(--text-bright); font-weight: 900; letter-spacing: -.02em; margin-bottom: .5rem; }}
.report-header .subtitle {{ color: var(--text-dim); font-size: .85rem; }}
.meta-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1px; background: var(--border); margin: 2rem 0 0; border: 1px solid var(--border); }}
.meta-cell {{ background: var(--surface2); padding: 1rem 1.25rem; }}
.meta-label {{ font-size: .65rem; letter-spacing: .2em; color: var(--text-dim); margin-bottom: .3rem; text-transform: uppercase; }}
.meta-value {{ font-size: .9rem; color: var(--text-bright); }}
.section {{ padding: 2.5rem 3rem; border-bottom: 1px solid var(--border); }}
.section h2 {{ font-size: .7rem; letter-spacing: .25em; color: var(--accent2); text-transform: uppercase; margin-bottom: 1.5rem; }}
.exec-summary {{ font-size: .95rem; line-height: 2; color: var(--text); max-width: 900px; }}
.exec-summary p {{ margin-bottom: 1rem; }}
.stats-row {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1px; background: var(--border); border: 1px solid var(--border); }}
.stat {{ background: var(--surface); padding: 1.5rem; text-align: center; }}
.stat-num {{ font-size: 2.5rem; font-weight: 900; line-height: 1; margin-bottom: .4rem; }}
.stat-label {{ font-size: .65rem; letter-spacing: .15em; color: var(--text-dim); text-transform: uppercase; }}
.finding {{ border: 1px solid var(--border); border-top: none; }}
.finding:first-child {{ border-top: 1px solid var(--border); }}
.finding-header {{ display: flex; justify-content: space-between; align-items: center; padding: 1.25rem 1.5rem; background: var(--surface); border-bottom: 1px solid var(--border); gap: 1rem; flex-wrap: wrap; }}
.finding-title {{ font-size: .95rem; color: var(--text-bright); margin-left: .75rem; }}
.finding-meta {{ display: flex; gap: 1rem; align-items: center; }}
.sev-badge {{ font-size: .65rem; padding: .25rem .65rem; letter-spacing: .15em; white-space: nowrap; }}
.cvss {{ font-size: .75rem; color: var(--gold); }}
.found-by {{ font-size: .7rem; color: var(--text-dim); }}
.finding-body {{ padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }}
.field-label {{ font-size: .65rem; letter-spacing: .2em; color: var(--accent); display: block; margin-bottom: .4rem; text-transform: uppercase; }}
.finding-body p {{ font-size: .88rem; line-height: 1.9; color: var(--text); }}
.finding-body pre {{ font-size: .78rem; background: var(--surface2); border: 1px solid var(--border); padding: 1rem; color: var(--accent3); overflow-x: auto; white-space: pre-wrap; line-height: 1.7; }}
.vendor-tag {{ display: inline-flex; align-items: center; gap: .4rem; font-size: .72rem; padding: .25rem .65rem; background: rgba(0,229,255,.05); border: 1px solid rgba(0,229,255,.15); color: var(--accent); margin: .25rem; }}
.vendor-cat {{ color: var(--text-dim); font-size: .65rem; }}
.host-list {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: .5rem; margin-top: 1rem; }}
.host-item {{ background: var(--surface2); border: 1px solid var(--border); padding: .75rem 1rem; font-size: .82rem; display: flex; justify-content: space-between; }}
.status-ok {{ color: var(--accent3); }}
.footer {{ padding: 2rem 3rem; text-align: center; font-size: .72rem; color: var(--text-dim); border-top: 1px solid var(--border); }}
.export-bar {{ position: fixed; top: 1rem; right: 1rem; display: flex; gap: .5rem; z-index: 50; }}
.export-bar button {{ font-family: var(--mono); font-size: .7rem; letter-spacing: .1em; text-transform: uppercase; padding: .5rem .9rem; background: var(--surface2); color: var(--accent); border: 1px solid var(--accent); cursor: pointer; }}
.export-bar button:hover {{ background: var(--accent); color: var(--bg); }}
.cov-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 1px; background: var(--border); border: 1px solid var(--border); margin-bottom: 1.5rem; }}
.cov-cell {{ background: var(--surface); padding: 1.25rem; text-align: center; }}
.cov-num {{ font-size: 1.8rem; font-weight: 900; color: var(--accent); line-height: 1; margin-bottom: .35rem; }}
.cov-label {{ font-size: .62rem; letter-spacing: .12em; color: var(--text-dim); text-transform: uppercase; }}
.cov-table, .path-table {{ width: 100%; border-collapse: collapse; font-size: .8rem; }}
.cov-table th, .path-table th {{ text-align: left; padding: .6rem .8rem; color: var(--text-dim); font-size: .62rem; letter-spacing: .15em; text-transform: uppercase; border-bottom: 1px solid var(--border); }}
.cov-table td, .path-table td {{ padding: .5rem .8rem; border-bottom: 1px solid var(--border); }}
.mod-ok {{ color: var(--accent3); }}
.mod-skip {{ color: var(--text-dim); }}
.mod-hits {{ color: var(--gold); text-align: right; }}
.path-url {{ font-family: var(--mono); color: var(--text-bright); word-break: break-all; }}
.path-note {{ color: var(--text-dim); font-size: .72rem; }}
.surf-host {{ color: var(--text-dim); font-size: .72rem; }}
.surf-params {{ color: var(--accent); font-size: .72rem; word-break: break-all; }}
.st-200 {{ color: var(--accent3); }}
.st-redir {{ color: var(--accent); }}
.st-403 {{ color: var(--gold); }}
.st-other {{ color: var(--text-dim); }}
.cand-note {{ font-size: .82rem; color: var(--text-dim); margin-bottom: 1rem; }}
.cand-note strong {{ color: var(--accent2); }}
.cand-list {{ list-style: none; display: flex; flex-direction: column; gap: .4rem; }}
.cand-list li {{ background: var(--surface2); border: 1px solid var(--border); padding: .55rem .8rem; font-size: .8rem; }}
.cand-url {{ font-family: var(--mono); color: var(--text-bright); word-break: break-all; }}
.cand-kw {{ color: var(--accent2); font-size: .68rem; text-transform: uppercase; letter-spacing: .1em; margin-left: .4rem; }}
.cand-st {{ color: var(--text-dim); font-size: .7rem; margin-left: .4rem; }}
@media print {{ .export-bar {{ display: none; }} body {{ background: #fff; color: #000; }} .report-header, .section, .finding {{ break-inside: avoid; }} }}
</style>
</head>
<body>
{toolbar_html}
<div class="report-header">
  <div class="classification">AUTHORIZED SECURITY ASSESSMENT — OLYMPUS PLATFORM</div>
  <h1>Security Assessment Report</h1>
  <div class="subtitle">{esc_target} — {esc_mode} MODE — {now}</div>
  <div class="meta-grid">
    <div class="meta-cell"><div class="meta-label">Target</div><div class="meta-value">{esc_target}</div></div>
    <div class="meta-cell"><div class="meta-label">Assessment Mode</div><div class="meta-value">{esc_mode}</div></div>
    <div class="meta-cell"><div class="meta-label">Live Hosts</div><div class="meta-value">{len(live_hosts)}</div></div>
    <div class="meta-cell"><div class="meta-label">Subdomains</div><div class="meta-value">{len(subdomains)}</div></div>
    <div class="meta-cell"><div class="meta-label">Vendors Identified</div><div class="meta-value">{len(vendors)}</div></div>
    <div class="meta-cell"><div class="meta-label">Report Date</div><div class="meta-value">{now}</div></div>
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="exec-summary">{summary_html}</div>
</div>

<div class="section">
  <h2>Finding Statistics</h2>
  <div class="stats-row">
    <div class="stat"><div class="stat-num" style="color:#ff0040">{stats['critical']}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-num" style="color:#ff3d6b">{stats['high']}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-num" style="color:#f59e0b">{stats['medium']}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-num" style="color:#00e5ff">{stats['low']}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-num" style="color:#6a8a9a">{stats['info']}</div><div class="stat-label">Info</div></div>
  </div>
</div>

{coverage_html}

{surface_html}

{'<div class="section"><h2>Vendor Stack (Passive Intelligence)</h2>' + vendor_html + '</div>' if vendors else ''}

<div class="section">
  <h2>Findings Detail ({len(sorted_findings)} total)</h2>
  {findings_html or '<p style="color:var(--text-dim)">No findings recorded.</p>'}
</div>

{paths_html}

{candidates_html}

{_host_section}

<div class="footer">
  OLYMPUS Security Platform — Authorized Testing Only — Report ID: {self.mission_id[:8].upper()}
</div>
{export_script}
</body>
</html>"""

        os.makedirs(settings.reports_dir, exist_ok=True)
        report_filename = f"report_{self.mission_id}.html"
        report_path = os.path.join(settings.reports_dir, report_filename)
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        return report_path
