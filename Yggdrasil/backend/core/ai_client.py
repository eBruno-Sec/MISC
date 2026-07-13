"""
Unified AI completion client.

Configure in .env:
  AI_PROVIDER=anthropic          # or: openrouter
  AI_API_KEY=sk-ant-...          # Anthropic key, or OpenRouter key
  AI_MODEL=claude-sonnet-4-6     # model string for the chosen provider
  AI_BASE_URL=...                # optional override (OpenRouter default: https://openrouter.ai/api/v1)

Backward-compat: ANTHROPIC_API_KEY still works as a fallback.

Error contract: complete() never swallows a real failure into an empty string.
- No key configured -> raises AIUnavailable (expected/benign; callers should
  treat this as "AI disabled", not an error).
- A call was attempted (a key WAS present) and failed for any reason -> raises
  AICompletionError carrying provider/model/status/detail, so a caller can log
  the actual cause instead of downstream code choking on "" with a cryptic
  "Expecting value: line 1 column 1" JSON-parse error.
"""
import os
from typing import Optional


class AIUnavailable(Exception):
    """No AI key is configured for the selected provider. Expected and benign —
    not a failure. Callers should log once and degrade gracefully."""
    def __init__(self, provider: str):
        self.provider = provider
        super().__init__(f"no AI key configured for provider '{provider}'")


class AICompletionError(Exception):
    """A completion call was attempted (a key WAS configured) but failed.
    Carries enough structure for a caller to log provider/model/status/detail
    instead of a useless downstream JSON-parse error."""
    def __init__(self, provider: str, model: str, status: str, detail: str = ""):
        self.provider = provider
        self.model = model
        self.status = status
        self.detail = (detail or "")[:300]
        super().__init__(f"{provider}/{model} {status}: {self.detail}")


def _resolve_model(provider: str) -> str:
    default = "anthropic/claude-sonnet-4-6" if provider == "openrouter" else "claude-sonnet-4-6"
    return os.getenv("AI_MODEL") or default


async def complete(prompt: str, max_tokens: int = 800, system: Optional[str] = None) -> str:
    """Return the raw completion text. Raises AIUnavailable or AICompletionError
    on any failure — never silently returns "" for a real error. A genuinely
    empty completion from the provider is itself treated as AICompletionError
    (status="empty_response"), since callers downstream (e.g. MIMIR's JSON
    parser) cannot do anything useful with it either way."""
    provider = os.getenv("AI_PROVIDER", "anthropic").lower().strip()
    api_key = os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY") or ""
    model = _resolve_model(provider)

    if not api_key:
        raise AIUnavailable(provider)

    if provider == "openrouter":
        text = await _openrouter(prompt, api_key, max_tokens, system)
    else:
        text = await _anthropic(prompt, api_key, max_tokens, system)

    if not text or not text.strip():
        raise AICompletionError(provider, model, "empty_response",
                                "provider returned an empty completion")
    return text


async def _anthropic(prompt: str, api_key: str, max_tokens: int, system: Optional[str]) -> str:
    import anthropic as sdk
    model = _resolve_model("anthropic")
    client = sdk.AsyncAnthropic(api_key=api_key)
    kwargs: dict = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system
    try:
        resp = await client.messages.create(**kwargs)
    except Exception as e:
        # The anthropic SDK's APIStatusError family carries status_code/message;
        # extract defensively so this works across SDK versions without a hard
        # import-time dependency on the exact exception hierarchy.
        status = f"HTTP {getattr(e, 'status_code', None)}" if getattr(e, "status_code", None) else type(e).__name__
        detail = getattr(e, "message", None) or str(e)
        print(f"[ai_client] anthropic/{model} error: {status}: {detail[:300]}", flush=True)
        raise AICompletionError("anthropic", model, status, detail) from e

    if not resp.content or not getattr(resp.content[0], "text", None):
        raise AICompletionError("anthropic", model, "empty_response", "no text content in response")
    return resp.content[0].text.strip()


async def _openrouter(prompt: str, api_key: str, max_tokens: int, system: Optional[str]) -> str:
    import httpx
    model = _resolve_model("openrouter")
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
                    "HTTP-Referer": "https://github.com/eBruno-Sec/MISC/tree/main/Yggdrasil",
                    "X-Title": "Yggdrasil Security Workspace",
                },
                json={"model": model, "max_tokens": max_tokens, "messages": messages},
            )
    except Exception as e:
        print(f"[ai_client] openrouter/{model} network error: {type(e).__name__}: {str(e)[:300]}", flush=True)
        raise AICompletionError("openrouter", model, type(e).__name__, str(e)) from e

    if r.status_code != 200:
        detail = r.text[:300]
        print(f"[ai_client] openrouter/{model} HTTP {r.status_code}: {detail}", flush=True)
        raise AICompletionError("openrouter", model, f"HTTP {r.status_code}", detail)

    try:
        data = r.json()
    except Exception as e:
        raise AICompletionError("openrouter", model, "non_json_response", r.text[:300]) from e

    # OpenRouter can return a 200 with an error envelope instead of choices.
    if "error" in data:
        msg = data["error"].get("message", str(data["error"])) if isinstance(data["error"], dict) else str(data["error"])
        print(f"[ai_client] openrouter/{model} error envelope: {msg[:300]}", flush=True)
        raise AICompletionError("openrouter", model, "provider_error", msg)

    choices = data.get("choices")
    if not choices:
        raise AICompletionError("openrouter", model, "no_choices", str(data)[:300])

    return choices[0]["message"]["content"].strip()
