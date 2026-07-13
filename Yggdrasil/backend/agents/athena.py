import json
import os
import re
from urllib.parse import urlparse
from core.ai_client import complete
from .base import BaseAgent


def _close_truncated_json(s: str):
    """Best-effort repair for JSON cut off by a token cap: walk the string tracking
    string/escape state and brace depth, then append the missing closers. Returns a
    candidate string, or None when the input was not actually truncated."""
    stack, in_str, escape = [], False, False
    for ch in s:
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            stack.append("}")
        elif ch == "[":
            stack.append("]")
        elif ch in "}]" and stack:
            stack.pop()
    if not stack and not in_str:
        return None  # not a truncation problem — leave it for the caller to raise
    if in_str:
        fixed = s + '"'
    else:
        fixed = s.rstrip().rstrip(",")
    return fixed + "".join(reversed(stack))


def _extract_json(text: str):
    """Pull a JSON object from an LLM response that may wrap it in prose or ```json
    fences. Tolerant of the common LLM malformations that used to hard-crash MIMIR
    triage — code fences, trailing commas, literal control chars in strings, and
    minor truncation — raising the last decode error only if every repair fails."""
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        t = t[start:end + 1]

    # trailing-comma repair: {"a":1,} -> {"a":1} ,  [1,2,] -> [1,2]
    repaired = re.sub(r",(\s*[}\]])", r"\1", t)

    last_err = None
    for cand in (t, repaired):
        for strict in (True, False):   # strict=False tolerates raw newlines in strings
            try:
                return json.loads(cand, strict=strict)
            except (json.JSONDecodeError, ValueError) as e:
                last_err = e

    salvaged = _close_truncated_json(repaired)
    if salvaged is not None:
        try:
            return json.loads(salvaged, strict=False)
        except (json.JSONDecodeError, ValueError) as e:
            last_err = e
    raise last_err or ValueError("no JSON object found")


def _extract_declared_scope_paths(scope: str) -> list:
    """Extract operator-declared URL paths and nearby vulnerability hints."""
    rows = []
    current = None

    def close_current():
        nonlocal current
        if current:
            current["hints"] = list(dict.fromkeys(current["hints"]))
            rows.append(current)
            current = None

    for raw in (scope or "").splitlines():
        line = raw.strip().strip("-*")
        if not line:
            continue

        path = None
        if line.startswith(("http://", "https://")):
            parsed = urlparse(line)
            if parsed.path and parsed.path != "/":
                path = parsed.path
        else:
            match = re.search(r"(?<!\S)/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*", line)
            if match:
                path = match.group(0)

        if path:
            close_current()
            current = {"path": path, "hints": []}
            trailing = line[line.find(path) + len(path):].strip(" :-")
            if trailing:
                current["hints"].append(trailing)
            continue

        if current:
            current["hints"].append(line)

    close_current()
    return rows


def _summarize_scope_rules(scope_rules: dict) -> dict:
    """Return a compact, UI-safe summary of structured scope rules."""
    rules = scope_rules or {}
    in_scope = [r for r in rules.get("in_scope", []) if isinstance(r, dict)]
    out_of_scope = [r for r in rules.get("out_of_scope", []) if isinstance(r, dict)]
    asset_types = {}
    for rule in in_scope:
        typ = str(rule.get("type") or "unknown").lower()
        asset_types[typ] = asset_types.get(typ, 0) + 1

    def examples(items):
        out = []
        for rule in items[:5]:
            ident = str(rule.get("identifier") or "").strip()
            typ = str(rule.get("type") or "unknown").strip() or "unknown"
            if ident:
                out.append(f"{ident} ({typ})")
        return out

    return {
        "has_rules": bool(in_scope or out_of_scope),
        "in_scope_count": len(in_scope),
        "out_of_scope_count": len(out_of_scope),
        "asset_types": asset_types,
        "in_scope_examples": examples(in_scope),
        "out_of_scope_examples": examples(out_of_scope),
    }


class Athena(BaseAgent):
    name = "athena"
    symbol = "FR"
    display_name = "FRIGG"
    role = "Strategy & Scope Interpretation"

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

        declared_paths = _extract_declared_scope_paths(scope)
        if declared_paths:
            result["declared_paths"] = declared_paths

        api_key = os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            await self.log("No AI API key configured. AI analysis skipped.", "warn")
            result["mission_summary"] = f"Manual assessment of {target} in {mode} mode."
            result["key_areas"] = ["DNS infrastructure", "Email security posture", "Certificate transparency"]
            return result

        try:
            prompt = f"""You are FRIGG, the strategy module of the Yggdrasil authorized security workspace.
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

        # Extract test credentials from scope notes for authenticated scanning.
        try:
            creds = await self._derive_credentials(scope)
            if creds:
                result["_credentials"] = creds
        except Exception as e:
            await self.log(f"Credential extraction error ({e})", "warn")

        await self.log("Mission parameters locked. Handing off to HEIMDALL.", "success")
        return result

    async def _derive_credentials(self, scope: str) -> list:
        """Pull test credentials out of free-text scope notes for authenticated
        scanning. Returns a list of {username, password, login_url?, role?}.
        Passwords are never written to logs."""
        notes = (scope or "").strip()
        if not notes:
            return []
        low = notes.lower()
        if not any(k in low for k in ("cred", "login", "user", "pass", "account", "sign in", "sign-in", "log in")):
            return []

        prompt = f"""Extract any test credentials from these AUTHORIZED-pentest scope notes.
Notes:
{notes}

Return ONLY JSON: {{"credentials": [{{"username": "...", "password": "...", "login_url": "<optional>", "role": "<optional>"}}]}}
Only include explicit username/password pairs actually present in the notes. If none, return {{"credentials": []}}.
No prose."""
        text = await complete(prompt, max_tokens=400)
        if not text:
            return []
        parsed = _extract_json(text)
        items = parsed.get("credentials") if isinstance(parsed, dict) else None
        if not isinstance(items, list):
            return []

        creds = []
        for it in items:
            if not isinstance(it, dict):
                continue
            u = str(it.get("username", "")).strip()
            p = str(it.get("password", "")).strip()
            if not u or not p:
                continue
            entry = {"username": u, "password": p}
            if it.get("login_url"):
                entry["login_url"] = str(it.get("login_url")).strip()
            if it.get("role"):
                entry["role"] = str(it.get("role")).strip()
            creds.append(entry)
        if creds:
            await self.log(
                f"Extracted {len(creds)} credential set(s) for authenticated scanning "
                f"(user: {creds[0]['username']})", "info")
        return creds

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
