"""
MIMIR - AI triage and correlation.

Runs after all scanning, before SAGA reports. Where the other modules produce
raw findings from independent tools (nuclei, ZAP, sqlmap, dalfox, custom
probes), MIMIR reviews the whole set at once:

- suppresses likely false positives conservatively, never a confirmed hit
- maps each finding to CWE / OWASP for professional reporting
- chains related findings into higher-impact attack paths

It is strictly additive and non-destructive: it only annotates agent findings
that have no tag yet, annotates notes, and adds synthesized Attack Path
findings. With no AI key it is a no-op.
"""
import json
import os

from sqlalchemy import select

from core.ai_client import complete
from core.models import Finding
from core.triage import sanitize_attack_path
from .base import BaseAgent
from .athena import _extract_json


class Metis(BaseAgent):
    name = "metis"
    symbol = "MI"
    display_name = "MIMIR"
    role = "Triage & Correlation"

    async def execute(self, target: str, context: dict = None) -> dict:
        result = {"flagged": 0, "mapped": 0, "chains": 0, "summary": ""}

        api_key = os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            await self.log("No AI key configured; triage/correlation skipped", "warn")
            return result

        rows = await self.session.execute(
            select(Finding).where(Finding.mission_id == self.mission_id).order_by(Finding.timestamp)
        )
        findings = rows.scalars().all()
        if len(findings) < 2:
            await self.log("Too few findings to correlate; triage skipped", "info")
            return result

        await self.log(
            f"Correlating {len(findings)} findings (false-positive, CWE/OWASP, attack-path chaining)",
            "info",
        )

        catalog = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "found_by": f.found_by,
                "desc": (f.description or "")[:240],
                "evidence": (f.evidence or "")[:240],
            }
            for f in findings
        ]

        prompt = f"""You are MIMIR, the triage and correlation brain of the Yggdrasil security workspace.
You receive raw findings from multiple scanners (nuclei, ZAP, sqlmap, dalfox, custom probes) against {target}.
Review them like a senior penetration tester doing report QA, then return STRICT JSON.

Findings:
{json.dumps(catalog, ensure_ascii=False)}

Return ONLY this JSON shape:
{{
  "false_positives": ["<id>", ...],
  "mappings": {{"<id>": {{"cwe": "CWE-###", "owasp": "A##:2021"}}}},
  "attack_paths": [
    {{"title": "...", "severity": "critical|high|medium", "narrative": "step-by-step how an attacker chains these findings into real impact", "finding_ids": ["<id>", ...]}}
  ],
  "summary": "2-3 sentences: real risk vs noise, and the single most important thing to fix first"
}}

Rules:
- Be conservative with false_positives (high precision). Never suppress a confirmed injection, exposed secret, or takeover.
- Only propose attack_paths that are realistic given the findings; each must reference at least two finding ids.
- Certainty language must match the underlying finding, not exceed it. A finding titled "Suspected...", "...signal", "...pending validation", or "possible..." is NOT confirmed — never describe it in a narrative or summary as "confirmed SQL injection", "confirmed RCE", "remote code execution", or "full/complete compromise" unless a referenced finding's own title already proves that (e.g. "...sqlmap-confirmed...", "...out-of-band confirmed...", "...execution confirmed...", "...boolean-based blind...", "...UNION-based..."). When a path rests only on suspected/signal-tier findings, its severity must be "medium" at most and the narrative must say the chain is unconfirmed.
- No prose, no markdown, only the JSON object."""

        try:
            text = await complete(prompt, max_tokens=1500)
            data = _extract_json(text)
        except Exception as e:
            await self.log(f"Triage model call failed ({e}); findings left unchanged", "warn")
            return result

        by_id = {f.id: f for f in findings}
        fp_list = data.get("false_positives") if isinstance(data.get("false_positives"), list) else []
        mappings = data.get("mappings") if isinstance(data.get("mappings"), dict) else {}
        paths = data.get("attack_paths") if isinstance(data.get("attack_paths"), list) else []

        flagged = 0
        for fid in fp_list:
            f = by_id.get(fid)
            if not f or getattr(f, "is_manual", False) or f.tag:
                continue
            if f.analyst_notes and "possible false positive" in f.analyst_notes:
                continue
            note = "MIMIR: possible false positive - analyst should verify."
            f.analyst_notes = (f.analyst_notes + "\n" + note) if f.analyst_notes else note
            flagged += 1

        mapped = 0
        for fid, m in mappings.items():
            f = by_id.get(fid)
            if not f or not isinstance(m, dict):
                continue
            cwe = str(m.get("cwe", "")).strip()
            owasp = str(m.get("owasp", "")).strip()
            tags = " ".join(x for x in (cwe, owasp) if x)
            if not tags:
                continue
            if f.analyst_notes and "MIMIR classification" in f.analyst_notes:
                continue
            note = f"MIMIR classification: {tags}"
            f.analyst_notes = (f.analyst_notes + "\n" + note) if f.analyst_notes else note
            mapped += 1

        await self.session.commit()

        chains = 0
        sev_cvss = {"critical": 9.3, "high": 8.0, "medium": 5.5}
        for path in paths[:6]:
            if not isinstance(path, dict):
                continue
            title = str(path.get("title", "")).strip()
            if not title:
                continue
            sev = str(path.get("severity", "high")).lower()
            if sev not in sev_cvss:
                sev = "high"
            ids = [i for i in (path.get("finding_ids") or []) if i in by_id]

            # Deterministic guard (not just a prompt instruction): if none of the
            # chained findings are confirmed-tier by their OWN title/severity, cap
            # this path at medium and prepend an unconfirmed disclaimer — regardless
            # of what certainty language the model used. See core.triage for the rule.
            source_findings = {i: {"title": by_id[i].title, "severity": by_id[i].severity} for i in ids}
            safe = sanitize_attack_path({"severity": sev, "narrative": path.get("narrative", ""),
                                         "finding_ids": ids}, source_findings)
            sev = safe["severity"]
            narrative = str(safe.get("narrative", "")).strip()

            linked = "\n".join(f"- {by_id[i].title}" for i in ids)
            await self.add_finding(
                title=f"Attack Path: {title}",
                severity=sev,
                description=narrative or "Correlated multi-step attack path across several findings.",
                evidence=("Chained findings:\n" + linked) if linked else "Correlated from multiple findings.",
                cvss_score=sev_cvss[sev],
                remediation="Break the chain at any step; fixing the earliest root finding collapses the path.",
            )
            chains += 1

        summary = str(data.get("summary", "")).strip()
        if summary:
            await self.log(f"Triage verdict: {summary}", "info")
        await self.log(
            f"Triage complete: {flagged} possible false positive(s) flagged (advisory, none hidden), "
            f"{mapped} finding(s) mapped to CWE/OWASP, {chains} attack path(s) synthesized",
            "success",
        )
        result.update({"flagged": flagged, "mapped": mapped, "chains": chains, "summary": summary})
        return result
