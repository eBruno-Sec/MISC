import os
import json
import html as html_lib
from datetime import datetime
from core.ai_client import complete
from core.config import settings
from core.models import Finding
from sqlalchemy import select
from .base import BaseAgent

SEVERITY_COLORS = {
    "critical": "#b42335",
    "high": "#c65348",
    "medium": "#b88136",
    "low": "#3b7f8f",
    "info": "#6f8078",
}

AGENT_DISPLAY = {
    "zeus": "ODIN",
    "athena": "FRIGG",
    "hermes": "HEIMDALL",
    "ares": "TYR",
    "hephaestus": "BROKKR",
    "hades": "SKULD",
    "apollo": "SAGA",
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
    symbol = "SA"
    display_name = "SAGA"
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

        # Generate report. A render error must be visible and retryable, but it must not
        # discard findings or block exports.
        report_path = ""
        report_error = None
        try:
            report_path = await self._generate_html_report(target, findings, stats, exec_summary, context)
            await self.log(f"Report saved: {report_path}", "success")
        except Exception as e:
            report_error = str(e)
            await self.log(f"Report generation failed: {e}. Findings are preserved and exportable; rerun Saga to retry.", "error")

        await self.log(f"Mission assessment complete for {target}", "success")

        return {
            "report_path": report_path,
            "report_error": report_error,
            "report_available": bool(report_path) and not report_error,
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
            prompt = f"""You are SAGA, the reporting module of the Yggdrasil security assessment workspace.
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
        if stats["critical"] or stats["high"]:
            priority = (
                "Immediate remediation focus should be directed at critical and high-severity findings "
                "to reduce exposure."
            )
        elif stats["medium"]:
            priority = (
                "No critical or high-severity findings were recorded. Remediation should focus on the "
                "medium-severity configuration and control gaps documented below."
            )
        elif total:
            priority = (
                "No critical, high, or medium-severity findings were recorded. Low and informational items "
                "should be reviewed as part of routine hardening."
            )
        else:
            priority = (
                "No findings were recorded. Review active scan coverage below to confirm the assessment depth "
                "matched the intended scope."
            )
        return (
            f"This {mode} security assessment of {target} identified {total} findings across "
            f"{stats['critical']} critical, {stats['high']} high, {stats['medium']} medium, "
            f"and {stats['low']} low severity categories. "
            f"{priority} "
            f"Full finding details, evidence, and remediation guidance are documented in this report."
        )

    async def _generate_html_report(self, target: str, findings: list, stats: dict, exec_summary: str, context: dict) -> str:
        mode = (context or {}).get("athena", {}).get("mode", "passive")
        mission_summary = (context or {}).get("athena", {}).get("mission_summary", "")
        vendors = (context or {}).get("hermes", {}).get("vendors", [])
        subdomains = (context or {}).get("hermes", {}).get("subdomains", [])
        live_hosts = (context or {}).get("hermes", {}).get("live_hosts", [])
        ares = (context or {}).get("ares", {})
        active_targets = ares.get("active_targets", []) if isinstance(ares, dict) else []
        active_target_count = len(active_targets) or (ares.get("targets_scanned", 0) if isinstance(ares, dict) else 0)
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        safe_target = html_lib.escape(str(target), quote=True)
        safe_mode = html_lib.escape(str(mode).upper(), quote=True)
        safe_now = html_lib.escape(now, quote=True)
        safe_exec_paragraphs = chr(10).join(
            f"<p>{html_lib.escape(p.strip(), quote=True)}</p>"
            for p in (exec_summary or "").split(chr(10))
            if p.strip()
        )

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
            safe_severity = html_lib.escape(str(fnd.severity or "info").upper(), quote=True)
            safe_title = html_lib.escape(str(fnd.title or "Untitled finding"), quote=True)
            safe_description = html_lib.escape(str(fnd.description or "No description"), quote=True)
            safe_evidence = html_lib.escape(str(fnd.evidence or ""), quote=True)
            safe_remediation = html_lib.escape(str(fnd.remediation or ""), quote=True)
            evidence_block = (
                '<div class="field"><span class="field-label">EVIDENCE</span><pre>'
                + safe_evidence
                + "</pre></div>"
            ) if fnd.evidence else ""
            remediation_block = (
                '<div class="field"><span class="field-label">REMEDIATION</span><p>'
                + safe_remediation
                + "</p></div>"
            ) if fnd.remediation else ""
            found_by = html_lib.escape(AGENT_DISPLAY.get(fnd.found_by or "", (fnd.found_by or "unknown").upper()), quote=True)
            findings_html += f"""
            <div class="finding" id="finding-{i}">
                <div class="finding-header">
                    <div>
                        <span class="sev-badge" style="background:{color}20;color:{color};border:1px solid {color}40">{safe_severity}</span>
                        <span class="finding-title">{safe_title}</span>
                    </div>
                    <div class="finding-meta">
                        <span class="cvss">CVSS {cvss:.1f}</span>
                        <span class="found-by">{found_by}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="field"><span class="field-label">DESCRIPTION</span><p>{safe_description}</p></div>
                    {evidence_block}
                    {remediation_block}
                </div>
            </div>"""

        vendor_html = ""
        for v in vendors:
            vname = html_lib.escape(str(v.get("vendor", "")), quote=True)
            vcat = html_lib.escape(str(v.get("category", "")), quote=True)
            vendor_html += f'<span class="vendor-tag">{vname} <span class="vendor-cat">{vcat}</span></span>'

        # Build host/target section outside f-string: Python 3.11 cannot use dict["key"] syntax
        # inside single-quote f-string expressions
        display_hosts = live_hosts or active_targets
        host_section_title = "Live Hosts" if live_hosts else "Active Targets Tested"
        if display_hosts:
            _host_items = ""
            for h in display_hosts[:50]:
                hhost = html_lib.escape(str(h.get("host", "")), quote=True)
                hcode = html_lib.escape(str(h.get("status_code") or h.get("source", "scanned")), quote=True)
                _host_items += f'<div class="host-item"><span>{hhost}</span><span class="status-ok">{hcode}</span></div>'
            _host_section = (
                f'<div class="section"><h2>{host_section_title} ({len(display_hosts)})</h2>'
                f'<div class="host-list">{_host_items}</div></div>'
            )
        else:
            _host_section = ""

        offensive = ares.get("offensive", {}) if isinstance(ares, dict) else {}
        coverage = offensive.get("coverage", {}) if isinstance(offensive, dict) else {}
        if ares:
            coverage_items = [
                ("In-Scope URLs", coverage.get("in_scope_urls", offensive.get("crawled_urls", 0))),
                ("Parameterized URLs", coverage.get("parameterized_urls", 0)),
                ("Traversal Candidates", coverage.get("traversal_candidate_urls", 0)),
                ("IDOR/BOLA Candidates", coverage.get("idor_candidate_urls", 0)),
                ("Content Paths", coverage.get("content_paths_discovered", len(offensive.get("content", [])))),
                ("Spider URLs", coverage.get("spider_urls", 0)),
                ("Param-Mined URLs", coverage.get("param_mining_urls", 0)),
                ("Generated Param URLs", coverage.get("generated_parameter_urls", 0)),
                ("Param Wordlist", coverage.get("parameter_wordlist_size", 0)),
                ("External Param Hits", coverage.get("external_parameter_candidates", 0)),
                ("Hidden Params", coverage.get("hidden_parameter_candidates", 0)),
                ("Declared Scope Paths", coverage.get("declared_scope_paths", 0)),
                ("Declared Seed URLs", coverage.get("declared_seed_urls", 0)),
                ("Auth Profiles", coverage.get("auth_profiles", 0)),
            ]
            module_items = [
                ("SQLi", len(offensive.get("sqli", []))),
                ("XSS", len(offensive.get("xss", []))),
                ("DAST", len(offensive.get("dast", []))),
                ("Auth/Exposure", len(offensive.get("auth", []))),
                ("Dependencies", len(offensive.get("dependency", []))),
                ("Manual Candidates", len(offensive.get("scope_candidates", []))),
                ("Param Mining", len(offensive.get("param_mining", []))),
                ("Generated Params", len(offensive.get("generated_params", []))),
                ("Arjun/x8", len(offensive.get("external_params", []))),
                ("Param Brute", len(offensive.get("hidden_params", []))),
                ("Traversal", len(offensive.get("path_traversal", []))),
                ("IDOR/BOLA", len(offensive.get("idor_bola", []))),
            ]
            coverage_html = "".join(
                f'<div class="coverage-item"><div class="coverage-num">{value}</div><div class="coverage-label">{label}</div></div>'
                for label, value in coverage_items
            )
            module_html = "".join(
                f'<div class="coverage-item"><div class="coverage-num">{value}</div><div class="coverage-label">{label}</div></div>'
                for label, value in module_items
            )
            notes = []
            if coverage.get("traversal_candidate_urls", 0) == 0:
                notes.append("Path traversal testing ran, but no file/path-like parameters were discovered to mutate.")
            if coverage.get("idor_candidate_urls", 0) == 0:
                notes.append("IDOR/BOLA testing ran, but no object-reference URLs were discovered.")
            if coverage.get("auth_profiles", 0) < 2:
                notes.append("Cross-role IDOR/BOLA confirmation needs at least two auth profiles; current run used heuristic checks only.")
            note_html = "".join(f'<p class="coverage-note">{html_lib.escape(n, quote=True)}</p>' for n in notes)
            _active_section = (
                '<div class="section"><h2>Active Scan Coverage (TYR)</h2>'
                f'<div class="coverage-grid">{coverage_html}</div>'
                '<h3 class="subhead">Module Results</h3>'
                f'<div class="coverage-grid">{module_html}</div>'
                f'{note_html}</div>'
            )
        elif mode != "passive":
            _active_section = (
                '<div class="section"><h2>Active Scan Coverage (TYR)</h2>'
                '<p class="coverage-note">Tyr results are absent from this report. Active scanning may have been denied, timed out, skipped, or failed before results were stored.</p>'
                '</div>'
            )
        else:
            _active_section = ""
        content_hits = offensive.get("content", []) if isinstance(offensive, dict) else []
        if content_hits:
            _content_items = ""
            for hit in content_hits[:80]:
                url = html_lib.escape(str(hit.get("url", "")), quote=True)
                status = html_lib.escape(str(hit.get("status", "?")), quote=True)
                length = hit.get("length")
                length_text = html_lib.escape(f" / {length} bytes", quote=True) if length is not None else ""
                _content_items += (
                    f'<div class="host-item"><span>{url}</span>'
                    f'<span class="status-ok">{status}{length_text}</span></div>'
                )
            more = ""
            if len(content_hits) > 80:
                more = f'<p class="coverage-note">{len(content_hits) - 80} additional discovered paths omitted from this view.</p>'
            _content_section = (
                f'<div class="section"><h2>Discovered Content Paths ({len(content_hits)})</h2>'
                f'<div class="host-list">{_content_items}</div>{more}</div>'
            )
        else:
            _content_section = ""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Yggdrasil Report - {safe_target}</title>
<style>
:root {{
  --bg: #f4f7f2; --surface: #ffffff; --surface2: #eef4f0;
  --border: #d7e2dc; --accent: #2f7566; --accent2: #b85c50;
  --accent3: #4f7c52; --gold: #b88136; --text: #34443d;
  --text-dim: #6f8078; --text-bright: #14241e;
  --font: Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  --mono: 'SFMono-Regular', Consolas, monospace;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 0; }}
.report-header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 3rem; }}
.report-header .classification {{ font-size: .72rem; letter-spacing: .12em; color: var(--accent3); margin-bottom: 1rem; text-transform: uppercase; font-weight: 800; }}
.report-header h1 {{ font-size: 2.35rem; color: var(--text-bright); font-weight: 850; margin-bottom: .5rem; }}
.report-header .subtitle {{ color: var(--text-dim); font-size: .92rem; }}
.meta-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1px; background: var(--border); margin: 2rem 0 0; border: 1px solid var(--border); }}
.meta-cell {{ background: var(--surface2); padding: 1rem 1.25rem; }}
.meta-label {{ font-size: .65rem; letter-spacing: .2em; color: var(--text-dim); margin-bottom: .3rem; text-transform: uppercase; }}
.meta-value {{ font-size: .9rem; color: var(--text-bright); }}
.section {{ padding: 2.5rem 3rem; border-bottom: 1px solid var(--border); }}
.section h2 {{ font-size: .72rem; letter-spacing: .12em; color: var(--accent2); text-transform: uppercase; margin-bottom: 1.5rem; }}
.exec-summary {{ font-size: .95rem; line-height: 2; color: var(--text); max-width: 900px; }}
.exec-summary p {{ margin-bottom: 1rem; }}
.stats-row {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1px; background: var(--border); border: 1px solid var(--border); }}
.stat {{ background: var(--surface); padding: 1.5rem; text-align: center; }}
.stat-num {{ font-size: 2.5rem; font-weight: 850; line-height: 1; margin-bottom: .4rem; }}
.stat-label {{ font-size: .68rem; letter-spacing: .08em; color: var(--text-dim); text-transform: uppercase; }}
.finding {{ border: 1px solid var(--border); border-top: none; }}
.finding:first-child {{ border-top: 1px solid var(--border); }}
.finding-header {{ display: flex; justify-content: space-between; align-items: center; padding: 1.25rem 1.5rem; background: var(--surface); border-bottom: 1px solid var(--border); gap: 1rem; flex-wrap: wrap; }}
.finding-title {{ font-size: .95rem; color: var(--text-bright); margin-left: .75rem; }}
.finding-meta {{ display: flex; gap: 1rem; align-items: center; }}
.sev-badge {{ font-size: .65rem; padding: .25rem .65rem; letter-spacing: .08em; white-space: nowrap; border-radius: 999px; }}
.cvss {{ font-size: .75rem; color: var(--gold); }}
.found-by {{ font-size: .7rem; color: var(--text-dim); }}
.finding-body {{ padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }}
.field-label {{ font-size: .65rem; letter-spacing: .2em; color: var(--accent); display: block; margin-bottom: .4rem; text-transform: uppercase; }}
.finding-body p {{ font-size: .88rem; line-height: 1.9; color: var(--text); }}
.finding-body pre {{ font-family: var(--mono); font-size: .78rem; background: var(--surface2); border: 1px solid var(--border); padding: 1rem; color: var(--text); overflow-x: auto; white-space: pre-wrap; line-height: 1.7; }}
.vendor-tag {{ display: inline-flex; align-items: center; gap: .4rem; font-size: .72rem; padding: .25rem .65rem; background: rgba(0,229,255,.05); border: 1px solid rgba(0,229,255,.15); color: var(--accent); margin: .25rem; }}
.vendor-cat {{ color: var(--text-dim); font-size: .65rem; }}
.host-list {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: .5rem; margin-top: 1rem; }}
.host-item {{ background: var(--surface2); border: 1px solid var(--border); padding: .75rem 1rem; font-size: .82rem; display: flex; justify-content: space-between; }}
.status-ok {{ color: var(--accent3); }}
.coverage-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 1px; background: var(--border); border: 1px solid var(--border); margin-bottom: 1rem; }}
.coverage-item {{ background: var(--surface); padding: 1rem; min-height: 86px; }}
.coverage-num {{ font-size: 1.8rem; font-weight: 850; color: var(--accent3); line-height: 1; margin-bottom: .45rem; }}
.coverage-label {{ font-size: .66rem; letter-spacing: .08em; color: var(--text-dim); text-transform: uppercase; line-height: 1.5; }}
.coverage-note {{ color: var(--text-dim); font-size: .82rem; line-height: 1.8; margin-top: .6rem; }}
.subhead {{ color: var(--accent); font-size: .68rem; letter-spacing: .2em; text-transform: uppercase; margin: 1.5rem 0 1rem; }}
.footer {{ padding: 2rem 3rem; text-align: center; font-size: .72rem; color: var(--text-dim); border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<div class="report-header">
  <div class="classification">AUTHORIZED SECURITY ASSESSMENT - YGGDRASIL PLATFORM</div>
  <h1>Security Assessment Report</h1>
  <div class="subtitle">{safe_target} - {safe_mode} MODE - {safe_now}</div>
  <div class="meta-grid">
    <div class="meta-cell"><div class="meta-label">Target</div><div class="meta-value">{safe_target}</div></div>
    <div class="meta-cell"><div class="meta-label">Assessment Mode</div><div class="meta-value">{safe_mode}</div></div>
    <div class="meta-cell"><div class="meta-label">Live Hosts</div><div class="meta-value">{len(live_hosts)}</div></div>
    <div class="meta-cell"><div class="meta-label">Active Targets Tested</div><div class="meta-value">{active_target_count}</div></div>
    <div class="meta-cell"><div class="meta-label">Subdomains</div><div class="meta-value">{len(subdomains)}</div></div>
    <div class="meta-cell"><div class="meta-label">Vendors Identified</div><div class="meta-value">{len(vendors)}</div></div>
    <div class="meta-cell"><div class="meta-label">Report Date</div><div class="meta-value">{safe_now}</div></div>
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="exec-summary">{safe_exec_paragraphs}</div>
</div>

<div class="section">
  <h2>Finding Statistics</h2>
  <div class="stats-row">
    <div class="stat"><div class="stat-num" style="color:#b42335">{stats['critical']}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-num" style="color:#c65348">{stats['high']}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-num" style="color:#b88136">{stats['medium']}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-num" style="color:#3b7f8f">{stats['low']}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-num" style="color:#6f8078">{stats['info']}</div><div class="stat-label">Info</div></div>
  </div>
</div>

{'<div class="section"><h2>Vendor Stack (Passive Intelligence)</h2>' + vendor_html + '</div>' if vendors else ''}

{_active_section}

{_content_section}

<div class="section">
  <h2>Findings Detail ({len(sorted_findings)} total)</h2>
  {findings_html or '<p style="color:var(--text-dim)">No findings recorded.</p>'}
</div>

{_host_section}

<div class="footer">
  Yggdrasil Security Assessment Workspace - Authorized Testing Only - Report ID: {self.mission_id[:8].upper()}
</div>
</body>
</html>"""

        os.makedirs(settings.reports_dir, exist_ok=True)
        report_filename = f"report_{self.mission_id}.html"
        report_path = os.path.join(settings.reports_dir, report_filename)
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        return report_path
