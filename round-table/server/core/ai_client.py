"""
Unified, OPTIONAL AI completion client.

Round Table works fully without AI — the guidance engine is rule-based. When an
AI key is configured, Merlin (triage) and Gawain (playbook narrative) are
enriched. Configure in .env:

  AI_PROVIDER=openrouter          # or: anthropic
  AI_API_KEY=sk-or-v1-...
  AI_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
  AI_BASE_URL=https://openrouter.ai/api/v1   # optional (OpenRouter default)

Backward-compat: ANTHROPIC_API_KEY still works as a fallback key.
"""
import os
from typing import Optional


def ai_enabled() -> bool:
    return bool(os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))


def ai_info() -> dict:
    provider = os.getenv("AI_PROVIDER", "anthropic").lower().strip()
    model = os.getenv("AI_MODEL", "") or (
        "anthropic/claude-sonnet-4-6" if provider == "openrouter" else "claude-sonnet-4-6"
    )
    return {"enabled": ai_enabled(), "provider": provider, "model": model}


async def complete(prompt: str, max_tokens: int = 1500, system: Optional[str] = None) -> str:
    provider = os.getenv("AI_PROVIDER", "anthropic").lower().strip()
    api_key = os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or ""
    if not api_key:
        return ""
    try:
        if provider == "openrouter":
            return await _openrouter(prompt, api_key, max_tokens, system)
        return await _anthropic(prompt, api_key, max_tokens, system)
    except Exception as e:  # AI is non-fatal: degrade gracefully
        print(f"[ai_client] {provider} error: {type(e).__name__}: {e}", flush=True)
        return ""


async def _anthropic(prompt: str, api_key: str, max_tokens: int, system: Optional[str]) -> str:
    import anthropic as sdk

    model = os.getenv("AI_MODEL", "claude-sonnet-4-6")
    client = sdk.AsyncAnthropic(api_key=api_key)
    kwargs: dict = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system
    resp = await client.messages.create(**kwargs)
    text = resp.content[0].text if resp.content else ""
    return (text or "").strip()


async def _openrouter(prompt: str, api_key: str, max_tokens: int, system: Optional[str]) -> str:
    import httpx

    model = os.getenv("AI_MODEL", "anthropic/claude-sonnet-4-6")
    base = os.getenv("AI_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            f"{base}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/eBruno-Sec/round-table",
                "X-Title": "Round Table Recon Platform",
            },
            json={"model": model, "max_tokens": max_tokens, "messages": messages},
        )
    if r.status_code != 200:
        raise RuntimeError(f"OpenRouter HTTP {r.status_code}: {r.text[:300]}")
    data = r.json()
    if "error" in data:
        err = data["error"]
        msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
        raise RuntimeError(f"OpenRouter error: {msg}")
    choices = data.get("choices")
    if not choices:
        raise RuntimeError(f"OpenRouter returned no choices: {str(data)[:300]}")
    # Some models (esp. free ones) return null content — don't crash on it.
    content = (choices[0].get("message") or {}).get("content")
    return (content or "").strip()
