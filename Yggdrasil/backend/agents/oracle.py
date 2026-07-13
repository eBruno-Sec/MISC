"""
ORACLE - the lab-solving advisor.

Not one of the seven mission gods. A standalone companion for working through
PortSwigger Web Security Academy labs (intentionally vulnerable training
targets). You paste the lab title, its description, and optionally a request
captured from Burp; ORACLE returns the vulnerability class, the exact exploit
steps, ready-to-send payloads, and the raw HTTP request to fire from Repeater.

It advises. It does not drive the lab or hold your session. You send the
request from Burp yourself, which keeps it reliable and inside PortSwigger's
intended usage.
"""
import json
import re

from core.ai_client import complete, AIUnavailable, AICompletionError


async def _complete_or_none(prompt: str, max_tokens: int, system: str) -> tuple[str | None, str | None]:
    """Call complete() and turn its structured exceptions into (text, error_note)
    instead of letting them propagate uncaught — Oracle is a best-effort advisor,
    not a mission-critical agent step, so a failure should degrade to a clear
    fallback message, never a raw exception."""
    try:
        return await complete(prompt, max_tokens=max_tokens, system=system), None
    except AIUnavailable as e:
        return None, f"No AI response. {e} — set AI_PROVIDER / AI_API_KEY in .env."
    except AICompletionError as e:
        return None, (f"No AI response. {e.provider}/{e.model} {e.status}: {e.detail}"
                      if e.detail else f"No AI response. {e.provider}/{e.model} {e.status}.")

SYSTEM = """You are ORACLE, an expert exploitation advisor for the PortSwigger Web Security Academy.
The user is solving intentionally vulnerable, authorized training labs that they own an instance of. Give complete, precise, working exploitation guidance.

You know the full Academy curriculum: SQL injection, XSS (reflected/stored/DOM), CSRF, clickjacking, SSRF, OS command injection, path traversal, file upload, authentication, access control / IDOR, business logic, information disclosure, JWT attacks, OAuth, SSTI, insecure deserialization, XXE, GraphQL, web cache poisoning/deception, HTTP request smuggling, prototype pollution, race conditions, NoSQL injection, API testing, and web LLM attacks.

Rules:
- Identify the exact vulnerability the lab targets from its title and description.
- Give the shortest reliable path to "Solved". Be specific to THIS lab, not generic theory.
- Provide exact, copy-pasteable payloads. No placeholders unless the user must substitute a lab-specific value, and when they must, name it clearly (e.g. YOUR-LAB-ID, COLLABORATOR-URL).
- When an HTTP request is the vehicle, output the full raw request the user pastes into Burp Repeater, including method, path, Host, and body.
- If the lab needs Burp Collaborator, the exploit server, or the browser, say so explicitly.
- Return ONLY a JSON object, no markdown fences, no prose outside it, with this schema:
{
  "vulnerability": "the specific vuln class this lab targets",
  "summary": "1-2 sentences: what the flaw is and why it works here",
  "difficulty": "apprentice | practitioner | expert",
  "steps": ["ordered, concrete steps to solve it"],
  "payloads": [{"label": "what this is", "value": "the exact payload"}],
  "request": "full raw HTTP request to send, or null if not applicable",
  "success_indicator": "how the user confirms the lab is solved",
  "notes": "gotchas, Burp tips, or common mistakes"
}"""


def _extract_json(text: str):
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    start = t.find("{")
    end = t.rfind("}")
    if start != -1 and end != -1 and end > start:
        t = t[start:end + 1]
    return json.loads(t)


def _fallback(raw: str, note: str) -> dict:
    return {
        "vulnerability": "See analysis",
        "summary": note,
        "difficulty": "",
        "steps": [],
        "payloads": [],
        "request": None,
        "success_indicator": "",
        "notes": "",
        "raw": raw,
    }


async def solve(lab_title: str, description: str, lab_url: str = "",
                category: str = "", captured_request: str = "",
                captured_response: str = "") -> dict:
    if not lab_title and not description:
        return _fallback("", "Provide at least a lab title or description.")

    ctx = f"Lab title: {lab_title or 'unknown'}\n"
    if category:
        ctx += f"Stated category: {category}\n"
    if lab_url:
        ctx += f"Lab URL: {lab_url}\n"
    ctx += f"\nLab description:\n{description or '(none provided)'}\n"
    if captured_request:
        ctx += f"\nRequest captured from Burp:\n{captured_request}\n"
    if captured_response:
        ctx += f"\nResponse observed:\n{captured_response}\n"

    prompt = ctx + "\nReturn the exploitation plan as JSON per the schema."

    text, error_note = await _complete_or_none(prompt, 1800, SYSTEM)
    if text is None:
        return _fallback("", error_note)

    try:
        data = _extract_json(text)
        # normalize shape
        data.setdefault("payloads", [])
        data.setdefault("steps", [])
        data.setdefault("request", None)
        return data
    except Exception:
        return _fallback(text, "Model did not return clean JSON; raw guidance below.")


async def followup(lab_title: str, description: str, prior: dict,
                   what_happened: str, captured_response: str = "") -> dict:
    prompt = (
        f"Lab title: {lab_title or 'unknown'}\n"
        f"Lab description:\n{description or '(none)'}\n\n"
        f"Your previous plan (JSON):\n{json.dumps(prior)[:3000]}\n\n"
        f"What happened when the user tried it:\n{what_happened}\n"
    )
    if captured_response:
        prompt += f"\nResponse the user saw:\n{captured_response}\n"
    prompt += "\nDiagnose why it did not solve and return a corrected plan as JSON per the schema."

    text, error_note = await _complete_or_none(prompt, 1800, SYSTEM)
    if text is None:
        return _fallback("", error_note)
    try:
        data = _extract_json(text)
        data.setdefault("payloads", [])
        data.setdefault("steps", [])
        data.setdefault("request", None)
        return data
    except Exception:
        return _fallback(text, "Model did not return clean JSON; raw guidance below.")
