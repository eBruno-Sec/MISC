import json
import os
import re
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


def _rule_label(rule: dict) -> str:
    identifier = str(rule.get("identifier") or "").strip()
    rule_type = str(rule.get("type") or "unknown").strip() or "unknown"
    return f"{identifier} ({rule_type})" if identifier else f"unknown ({rule_type})"


def _summarize_scope_rules(scope_rules: dict | None, limit: int = 12) -> dict:
    scope_rules = scope_rules if isinstance(scope_rules, dict) else {}
    in_scope = [r for r in scope_rules.get("in_scope", []) if isinstance(r, dict)]
    out_of_scope = [r for r in scope_rules.get("out_of_scope", []) if isinstance(r, dict)]

    asset_types: dict[str, int] = {}
    for rule in in_scope:
        rule_type = str(rule.get("type") or "unknown").strip() or "unknown"
        asset_types[rule_type] = asset_types.get(rule_type, 0) + 1

    return {
        "has_rules": bool(in_scope or out_of_scope),
        "in_scope_count": len(in_scope),
        "out_of_scope_count": len(out_of_scope),
        "asset_types": asset_types,
        "in_scope_examples": [_rule_label(r) for r in in_scope[:limit]],
        "out_of_scope_examples": [_rule_label(r) for r in out_of_scope[:limit]],
        "truncated": len(in_scope) > limit or len(out_of_scope) > limit,
    }


def _default_key_areas(scope_summary: dict) -> list[str]:
    areas = ["DNS infrastructure", "Email security posture", "Certificate transparency"]
    asset_types = scope_summary.get("asset_types") or {}
    if any(t in asset_types for t in ("domain", "url")):
        areas.append("Declared web application surface")
    if "ip" in asset_types:
        areas.append("Declared network service surface")
    if any(t in asset_types for t in ("android", "android_package", "ios", "ios_app_id")):
        areas.append("Declared mobile application assets")
    if scope_summary.get("out_of_scope_count", 0):
        areas.append("Out-of-scope boundary enforcement")
    return areas[:6]


def _extract_declared_scope_paths(scope: str, limit: int = 160) -> list[dict]:
    """Extract PortSwigger-style declared paths and nearby vulnerability hints.

    These hints are not treated as proof. They seed Tyr with app paths that the
    authorized scope already says exist.
    """
    if not scope:
        return []

    rows: list[dict] = []
    current: dict | None = None
    path_re = re.compile(r"^(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)\s*(.*)$")
    vuln_terms = (
        "sql injection",
        "cross-site scripting",
        "xss",
        "xml external entity",
        "xxe",
        "open redirection",
        "prototype pollution",
        "template injection",
        "header injection",
        "vulnerable javascript dependency",
        "dom data manipulation",
        "link manipulation",
        "request url override",
        "base64-encoded data",
    )

    for raw in scope.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = path_re.match(line)
        if match:
            path = match.group(1)
            if path.startswith("//"):
                continue
            current = {"path": path, "hints": []}
            rows.append(current)
            tail = match.group(2).strip()
            if tail and any(term in tail.lower() for term in vuln_terms):
                current["hints"].append(tail)
            if len(rows) >= limit:
                break
            continue
        if current and any(term in line.lower() for term in vuln_terms):
            current["hints"].append(line)

    deduped = []
    seen = set()
    for row in rows:
        if row["path"] in seen:
            continue
        seen.add(row["path"])
        deduped.append(row)
    return deduped


def _trim_scope_notes(scope: str, max_chars: int = 6000) -> str:
    if not scope or len(scope) <= max_chars:
        return scope
    return scope[:max_chars] + "\n...[scope notes truncated for AI prompt; deterministic path extraction used full text]..."


class Athena(BaseAgent):
    name = "athena"
    symbol = "FR"
    display_name = "FRIGG"
    role = "AI Strategy & Intent Parsing"

    async def execute(self, target: str, context: dict = None) -> dict:
        mode = (context or {}).get("mode", "passive")
        scope = (context or {}).get("scope", "")
        scope_rules = (context or {}).get("scope_rules", {}) or {}
        scope_summary = _summarize_scope_rules(scope_rules)
        declared_paths = _extract_declared_scope_paths(scope)

        await self.log(f"Analyzing mission parameters for {target}", "info")
        if declared_paths:
            await self.log(f"Parsed {len(declared_paths)} declared path(s) from scope notes for Tyr seeding", "info")

        result = {
            "target": target,
            "mode": mode,
            "scope": scope,
            "scope_summary": scope_summary,
            "declared_paths": declared_paths,
            "threat_model": [],
            "key_areas": [],
            "mission_summary": "",
            "ai_available": False,
        }

        api_key = os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            await self.log("No AI API key configured. AI analysis skipped.", "warn")
            if scope_summary["has_rules"]:
                result["mission_summary"] = (
                    f"Manual assessment of {target} in {mode} mode using "
                    f"{scope_summary['in_scope_count']} parsed in-scope and "
                    f"{scope_summary['out_of_scope_count']} parsed out-of-scope rule(s)."
                )
            else:
                result["mission_summary"] = f"Manual assessment of {target} in {mode} mode."
            result["key_areas"] = _default_key_areas(scope_summary)
            return result

        try:
            parsed_scope = json.dumps(scope_summary, indent=2)
            declared_path_preview = json.dumps(declared_paths[:40], indent=2)
            prompt = f"""You are FRIGG, the strategy module of the Yggdrasil authorized security assessment platform.
Analyze this authorized security assessment mission and return a JSON object.

Target: {target}
Mode: {mode} (passive=recon only, active=recon+scanning, full=recon+scanning+exploitation)
Scope Notes: {_trim_scope_notes(scope) or "none provided"}
Parsed Scope Rules, produced by deterministic parser and used for enforcement:
{parsed_scope}
Declared Paths Extracted From Scope Notes, used only as scan seeds:
{declared_path_preview}

Return JSON with these fields:
- threat_model: list of 3-5 likely threat vectors for this assessment scope
- key_areas: list of 4-6 attack surface areas to prioritize
- mission_summary: 2-3 sentence executive description of the assessment plan, not discovered facts
- risk_profile: "low" | "medium" | "high" based on assessment mode and declared scope only
- scope_assumptions: list of any ambiguity or scope-boundary assumptions

Rules:
- Treat Parsed Scope Rules as the source of truth for scope boundaries.
- Use in_scope examples and asset types to tailor key_areas and mission_summary.
- Use declared paths as app-surface hints, not proof of vulnerabilities.
- Never include out_of_scope examples as targets to test; only mention them as exclusions or boundaries.
- If Scope Notes conflict with Parsed Scope Rules, mention ambiguity in scope_assumptions and obey Parsed Scope Rules.
- Do not invent credentials, usernames, passwords, technologies, dependencies, vulnerabilities, exposed endpoints, or business context.
- If credentials, app type, or vulnerabilities are not explicitly present in Scope Notes or Parsed Scope Rules, describe them as unknown.
- Do not say the target "exhibits", "has", or "contains" a vulnerability before Heimdall/Tyr evidence exists.
- For a bare domain with no scope notes or parsed scope rules, keep mission_summary neutral and evidence-aware.

Only return valid JSON, no markdown, no preamble."""

            text = await complete(prompt, max_tokens=800)
            if text:
                parsed = _extract_json(text)
                summary = str(parsed.get("mission_summary", ""))
                unsupported_terms = ("valid credentials", "password", "known vulnerable", "exhibits", "confirmed")
                if not scope and not scope_summary["has_rules"] and any(term in summary.lower() for term in unsupported_terms):
                    summary = (
                        f"Full-scope assessment of {target}. Target technology, credentials, "
                        "and vulnerability presence are unknown until recon and active testing provide evidence."
                    )
                    parsed["mission_summary"] = summary
                result.update(parsed)
                result["scope_summary"] = scope_summary
                result["declared_paths"] = declared_paths
                result["ai_available"] = True
                await self.log(f"Mission profile: {parsed.get('risk_profile', 'unknown').upper()} risk", "info")
                await self.log(f"Summary: {parsed.get('mission_summary', '')}", "info")
            else:
                await self.log("AI analysis returned no text before timeout. Proceeding with deterministic scope strategy.", "warn")
                if declared_paths:
                    result["mission_summary"] = (
                        f"Security assessment of {target} in {mode} mode using "
                        f"{len(declared_paths)} declared app path(s) extracted from scope notes."
                    )
                    result["key_areas"] = ["Declared web application surface", "Injection testing", "Client-side attack surface", "Access-control checks"]
                elif scope_summary["has_rules"]:
                    result["mission_summary"] = (
                        f"Security assessment of {target} in {mode} mode using parsed scope boundaries."
                    )
                    result["key_areas"] = _default_key_areas(scope_summary)
                else:
                    result["mission_summary"] = f"Security assessment of {target} in {mode} mode."
                    result["key_areas"] = _default_key_areas(scope_summary)

        except Exception as e:
            await self.log(f"AI analysis failed ({e}). Proceeding with standard assessment.", "warn")
            if scope_summary["has_rules"]:
                result["mission_summary"] = (
                    f"Security assessment of {target} in {mode} mode using parsed scope boundaries."
                )
            else:
                result["mission_summary"] = f"Security assessment of {target} in {mode} mode."
            result["key_areas"] = _default_key_areas(scope_summary)

        await self.log("Mission parameters locked. Handing off to Heimdall.", "success")
        return result
