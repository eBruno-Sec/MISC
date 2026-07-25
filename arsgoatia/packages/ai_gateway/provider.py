"""AI provider adapter (ported from Yggdrasil core/ai_client.py).

Preserves the error contract: complete() never swallows a real failure into an
empty string. No key -> AIUnavailable (benign, "AI disabled"); an attempted call
that fails -> AICompletionError with provider/model/status/detail. Provider logic
stays in adapters behind an OpenAI-compatible shape (§15.2).
"""

from __future__ import annotations

import os
from typing import Optional


class AIUnavailable(Exception):
    """No AI key configured for the selected provider. Expected and benign."""

    def __init__(self, provider: str):
        self.provider = provider
        super().__init__(f"no AI key configured for provider '{provider}'")


class AICompletionError(Exception):
    """A completion was attempted (key present) but failed."""

    def __init__(self, provider: str, model: str, status: str, detail: str = ""):
        self.provider = provider
        self.model = model
        self.status = status
        self.detail = (detail or "")[:300]
        super().__init__(f"{provider}/{model} {status}: {self.detail}")


# Role -> env var for model routing (§15.3). Falls back to AI_MODEL then a default.
_ROLE_ENV = {
    "planner": "AI_PLANNER_MODEL",
    "hypothesis": "AI_HYPOTHESIS_MODEL",
    "report": "AI_REPORT_MODEL",
    "normalizer": "AI_NORMALIZER_MODEL",
}


def resolve_model(provider: str, role: str | None = None) -> str:
    if role and os.getenv(_ROLE_ENV.get(role, ""), ""):
        return os.environ[_ROLE_ENV[role]]
    default = "anthropic/claude-sonnet-4-6" if provider == "openrouter" else "claude-sonnet-4-6"
    return os.getenv("AI_MODEL") or default


async def complete(
    prompt: str, max_tokens: int = 800, system: Optional[str] = None, role: str | None = None
) -> str:
    provider = os.getenv("AI_PROVIDER", "anthropic").lower().strip()
    api_key = os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or ""
    model = resolve_model(provider, role)

    if not api_key:
        raise AIUnavailable(provider)

    if provider == "openrouter":
        text = await _openrouter(prompt, api_key, model, max_tokens, system)
    else:
        text = await _anthropic(prompt, api_key, model, max_tokens, system)

    if not text or not text.strip():
        raise AICompletionError(provider, model, "empty_response", "provider returned empty")
    return text


async def _anthropic(prompt, api_key, model, max_tokens, system) -> str:
    import anthropic as sdk

    client = sdk.AsyncAnthropic(api_key=api_key)
    kwargs: dict = {"model": model, "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}]}
    if system:
        kwargs["system"] = system
    try:
        resp = await client.messages.create(**kwargs)
    except Exception as e:  # noqa: BLE001
        status = f"HTTP {getattr(e, 'status_code', None)}" if getattr(e, "status_code", None) else type(e).__name__
        raise AICompletionError("anthropic", model, status, getattr(e, "message", None) or str(e)) from e
    if not resp.content or not getattr(resp.content[0], "text", None):
        raise AICompletionError("anthropic", model, "empty_response", "no text content")
    return resp.content[0].text.strip()


async def _openrouter(prompt, api_key, model, max_tokens, system) -> str:
    import httpx

    base = os.getenv("AI_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(
                f"{base}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/eBruno-Sec/MISC/tree/main/arsgoatia",
                    "X-Title": "ArsGoatia",
                },
                json={"model": model, "max_tokens": max_tokens, "messages": messages},
            )
    except Exception as e:  # noqa: BLE001
        raise AICompletionError("openrouter", model, type(e).__name__, str(e)) from e
    if r.status_code != 200:
        raise AICompletionError("openrouter", model, f"HTTP {r.status_code}", r.text[:300])
    try:
        data = r.json()
    except Exception as e:  # noqa: BLE001
        raise AICompletionError("openrouter", model, "non_json_response", r.text[:300]) from e
    if "error" in data:
        err = data["error"]
        msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
        raise AICompletionError("openrouter", model, "provider_error", msg)
    choices = data.get("choices")
    if not choices:
        raise AICompletionError("openrouter", model, "no_choices", str(data)[:300])
    return choices[0]["message"]["content"].strip()
