import json
import os
from core.ai_client import complete
from .base import BaseAgent


def _extract_json(text: str):
    """Pull a JSON object from an LLM response that may wrap it in prose or ```json fences."""
    import re
    t = text.strip()
    # strip code fences
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    # if there's surrounding prose, grab the outermost {...}
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        t = t[start:end + 1]
    return json.loads(t)


class Athena(BaseAgent):
    name = "athena"
    symbol = "🦉"
    display_name = "ATHENA"
    role = "AI Strategy & Intent Parsing"

    async def execute(self, target: str, context: dict = None) -> dict:
        mode = (context or {}).get("mode", "passive")
        scope = (context or {}).get("scope", "")

        await self.log(f"Analyzing mission parameters for {target}", "info")

        result = {
            "target": target,
            "mode": mode,
            "scope": scope,
            "threat_model": [],
            "key_areas": [],
            "mission_summary": "",
            "ai_available": False,
        }

        api_key = os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            await self.log("No AI API key configured. AI analysis skipped.", "warn")
            result["mission_summary"] = f"Manual assessment of {target} in {mode} mode."
            result["key_areas"] = ["DNS infrastructure", "Email security posture", "Certificate transparency"]
            return result

        try:
            prompt = f"""You are ATHENA, the strategy module of OLYMPUS autonomous security platform.
Analyze this authorized security assessment mission and return a JSON object.

Target: {target}
Mode: {mode} (passive=recon only, active=recon+scanning, full=recon+scanning+exploitation)
Scope: {scope or "full domain and subdomains"}

Return JSON with these fields:
- threat_model: list of 3-5 most likely threat vectors for this target type
- key_areas: list of 4-6 specific attack surface areas to prioritize
- mission_summary: 2-3 sentence executive description of this assessment
- risk_profile: "low" | "medium" | "high" based on mode and typical target complexity

Only return valid JSON, no markdown, no preamble."""

            text = await complete(prompt, max_tokens=800)
            if text:
                parsed = _extract_json(text)
                result.update(parsed)
                result["ai_available"] = True
                await self.log(f"Mission profile: {parsed.get('risk_profile', 'unknown').upper()} risk", "info")
                await self.log(f"Summary: {parsed.get('mission_summary', '')}", "info")

        except Exception as e:
            await self.log(f"AI analysis failed ({e}). Proceeding with standard assessment.", "warn")
            result["mission_summary"] = f"Security assessment of {target} in {mode} mode."
            result["key_areas"] = ["DNS infrastructure", "Email security", "Web surface", "Certificate transparency"]

        # Turn free-text scope notes into enforceable, validated scope rules.
        try:
            derived = await self._derive_scope(target, scope)
            if derived:
                result["scope_rules"] = derived
        except Exception as e:
            await self.log(f"Scope note interpretation error ({e}); notes not auto-enforced", "warn")

        await self.log("Mission parameters locked. Handing off to HERMES.", "success")
        return result

    async def _derive_scope(self, target: str, scope: str) -> dict:
        """Convert free-text scope notes into structured in/out-of-scope rules the
        platform can enforce. The model only *proposes*; is_valid_target disposes,
        so a hallucinated or malformed host is dropped. Rules can only narrow the
        set of already-discovered subdomains of the authorized target, never add a
        new external target, which bounds the blast radius of a bad suggestion."""
        import re as _re
        from core.security import is_valid_target

        notes = (scope or "").strip()
        if not notes:
            return {}

        prompt = f"""You convert authorized-penetration-test scope notes into strict JSON.
Target: {target}
Notes: {notes}

Return ONLY JSON: {{"in_scope": ["..."], "out_of_scope": ["..."]}}
Rules:
- Each array item is a bare hostname, wildcard host (*.example.com), IPv4, or IPv4 CIDR.
- Hosts the notes say to test/include go in in_scope.
- Hosts the notes say to avoid/exclude/never-touch go in out_of_scope.
- Only include hosts explicitly named or clearly implied for {target}. Never invent hosts.
- If the notes name no specific hosts, return empty arrays.
No prose, no markdown."""

        text = await complete(prompt, max_tokens=400)
        if not text:
            return {}
        parsed = _extract_json(text)

        def _classify(v: str) -> str:
            if "/" in v:
                return "cidr"
            if v.startswith("*."):
                return "wildcard"
            if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
                return "ip"
            return "domain"

        def _rules(items) -> list:
            out, seen = [], set()
            for it in items or []:
                v = str(it).strip().lower()
                if not v or v in seen or not is_valid_target(v):
                    continue
                seen.add(v)
                out.append({"identifier": v, "type": _classify(v)})
            return out

        in_rules = _rules(parsed.get("in_scope"))
        out_rules = _rules(parsed.get("out_of_scope"))
        if not (in_rules or out_rules):
            return {}
        await self.log(
            f"Interpreted scope notes into {len(in_rules)} in-scope / {len(out_rules)} out-of-scope rule(s)",
            "info",
        )
        return {"in_scope": in_rules, "out_of_scope": out_rules, "source": "ai_notes"}
