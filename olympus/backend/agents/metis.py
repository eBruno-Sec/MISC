"""
METIS — AI triage and correlation.

Runs after all scanning, before APOLLO reports. Where the other gods produce raw
findings from independent tools (nuclei, ZAP, sqlmap, dalfox, custom probes),
METIS is the senior-analyst brain that reviews the whole set at once:

  - suppresses likely false positives (conservatively, never a confirmed hit)
  - maps each finding to CWE / OWASP for professional reporting
  - chains related findings into higher-impact attack paths (the thing no
    single scanner does): "exposed .env -> DB creds -> SQLi -> RCE"

It is strictly additive and non-destructive: it only tags agent findings that
have no tag yet (never manual or analyst-tagged findings), annotates notes, and
adds synthesized Attack Path findings. With no AI key it is a no-op.
"""
import json
import os

from sqlalchemy import select

from core.ai_client import complete
from core.models import Finding
from .base import BaseAgent
from .athena import _extract_json


class Metis(BaseAgent):
    name = "metis"
    symbol = "⚖"
    display_name = "METIS"
    role = "AI Triage & Correlation"

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

        prompt = f"""You are METIS, the triage and correlation brain of the OLYMPUS security platform.
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

        # ── Possible false positives: ADVISORY ONLY ──
        # Never auto-hide findings from the report. A scanner finding is the
        # analyst's call, not the model's; METIS only annotates a suspicion so
        # nothing is silently dropped. (An earlier version tagged these
        # false_positive, which let the model gut whole reports.)
        flagged = 0
        for fid in fp_list:
            f = by_id.get(fid)
            if not f or f.is_manual or f.tag:
                continue
            note = "METIS: possible false positive — analyst should verify."
            if f.analyst_notes and "possible false positive" in f.analyst_notes:
                continue
            f.analyst_notes = (f.analyst_notes + "\n" + note) if f.analyst_notes else note
            flagged += 1

        # ── CWE / OWASP mapping (append to notes, never overwrite) ──
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
            if f.analyst_notes and "METIS classification" in f.analyst_notes:
                continue
            note = f"METIS classification: {tags}"
            f.analyst_notes = (f.analyst_notes + "\n" + note) if f.analyst_notes else note
            mapped += 1

        await self.session.commit()

        # ── Attack paths (synthesized, additive findings) ──
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
            narrative = str(path.get("narrative", "")).strip()
            ids = [i for i in (path.get("finding_ids") or []) if i in by_id]
            linked = "\n".join(f"- {by_id[i].title}" for i in ids)
            await self.add_finding(
                title=f"Attack Path: {title}",
                severity=sev,
                description=narrative or "Correlated multi-step attack path across several findings.",
                evidence=("Chained findings:\n" + linked) if linked else "Correlated from multiple findings.",
                cvss_score=sev_cvss[sev],
                remediation="Break the chain at any step; fixing the earliest (root) finding collapses the whole path.",
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
