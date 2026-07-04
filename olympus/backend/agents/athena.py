import anthropic
from core.config import settings
from .base import BaseAgent


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

        if not settings.anthropic_api_key:
            await self.log("No Anthropic API key configured. AI analysis skipped.", "warn")
            result["mission_summary"] = f"Manual assessment of {target} in {mode} mode."
            result["key_areas"] = ["DNS infrastructure", "Email security posture", "Certificate transparency"]
            return result

        try:
            client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
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

            response = await client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=800,
                messages=[{"role": "user", "content": prompt}],
            )

            import json
            text = response.content[0].text.strip()
            parsed = json.loads(text)
            result.update(parsed)
            result["ai_available"] = True

            await self.log(f"Mission profile: {parsed.get('risk_profile', 'unknown').upper()} risk", "info")
            await self.log(f"Summary: {parsed.get('mission_summary', '')}", "info")

        except Exception as e:
            await self.log(f"AI analysis failed ({e}). Proceeding with standard assessment.", "warn")
            result["mission_summary"] = f"Security assessment of {target} in {mode} mode."
            result["key_areas"] = ["DNS infrastructure", "Email security", "Web surface", "Certificate transparency"]

        await self.log("Mission parameters locked. Handing off to HERMES.", "success")
        return result
