"""
Unified AI completion client.

Configure in .env:
  AI_PROVIDER=anthropic          # or: openrouter
  AI_API_KEY=sk-ant-...          # Anthropic key, or OpenRouter key
  AI_MODEL=claude-sonnet-4-6     # model string for the chosen provider
  AI_BASE_URL=...                # optional override (OpenRouter default: https://openrouter.ai/api/v1)

Backward-compat: ANTHROPIC_API_KEY still works as a fallback.
"""
import os
from typing import Optional


async def complete(prompt: str, max_tokens: int = 800, system: Optional[str] = None) -> str:
    provider = os.getenv("AI_PROVIDER", "anthropic").lower().strip()
    api_key = (
        os.getenv("AI_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY")
        or ""
    )

    if not api_key:
        return ""

    try:
        if provider == "openrouter":
            return await _openrouter(prompt, api_key, max_tokens, system)
        else:
            return await _anthropic(prompt, api_key, max_tokens, system)
    except Exception as e:
        # Non-fatal: AI features degrade gracefully
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
    return resp.content[0].text.strip()


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
                "HTTP-Referer": "https://github.com/eBruno-Sec/MISC/tree/main/olympus",
                "X-Title": "OLYMPUS Security Platform",
            },
            json={"model": model, "max_tokens": max_tokens, "messages": messages},
        )

    # Surface the real reason instead of a cryptic JSON parse error.
    if r.status_code != 200:
        raise RuntimeError(f"OpenRouter HTTP {r.status_code}: {r.text[:300]}")

    try:
        data = r.json()
    except Exception:
        raise RuntimeError(f"OpenRouter returned non-JSON: {r.text[:300]}")

    # OpenRouter can return a 200 with an error envelope instead of choices.
    if "error" in data:
        msg = data["error"].get("message", str(data["error"])) if isinstance(data["error"], dict) else str(data["error"])
        raise RuntimeError(f"OpenRouter error: {msg}")

    choices = data.get("choices")
    if not choices:
        raise RuntimeError(f"OpenRouter returned no choices: {str(data)[:300]}")

    return choices[0]["message"]["content"].strip()
