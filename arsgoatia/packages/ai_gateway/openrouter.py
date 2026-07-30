"""OpenRouter provider adapter for the ArsGoatia AI gateway.

Wraps the base contract layer with an actual HTTP call to OpenRouter's
``/chat/completions`` endpoint. Enforces the spend budget and applies
secret redaction before anything leaves the process.

The adapter is advisory-only: nothing here executes actions, changes scope,
or approves anything. Callers must treat responses as untrusted input.
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from packages.ai_gateway import (
    AIBudgetExceeded,
    AICompletionError,
    AIGateway,
    AIGatewayConfig,
    AIRequest,
    AIResponse,
    AIUnavailable,
    build_structured_prompt,
    redact_secrets_from_text,
)

# Rough per-1K-token blended pricing for common OpenRouter free/cheap models.
# Under-estimates are safer than over-estimates for a hard cap; adjust when
# using a paid model.
_DEFAULT_COST_PER_1K_TOKENS_USD = 0.0005


class OpenRouterGateway(AIGateway):
    """Async OpenRouter-backed completion gateway."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = "https://openrouter.ai/api/v1",
        config: AIGatewayConfig | None = None,
        cost_per_1k_tokens_usd: float = _DEFAULT_COST_PER_1K_TOKENS_USD,
    ) -> None:
        super().__init__(config)
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._cost_per_1k = cost_per_1k_tokens_usd

    async def complete(self, request: AIRequest) -> AIResponse:
        if not self._api_key:
            raise AIUnavailable("OpenRouter API key is empty")
        if self._budget.is_exceeded():
            raise AIBudgetExceeded(
                f"AI budget of ${self.config.budget_limit_usd:.2f} exhausted",
            )

        prompt_bundle = build_structured_prompt(request, self.config)

        user_text = prompt_bundle["user"]
        redacted_fields: list[str] = []
        if self.config.redact_secrets:
            user_text, redacted_fields = redact_secrets_from_text(user_text)

        payload = {
            "model": self.config.model_name,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {"role": "system", "content": prompt_bundle["system"]},
                {"role": "user", "content": user_text},
            ],
        }
        if request.response_schema is not None:
            payload["response_format"] = {"type": "json_object"}

        import httpx  # noqa: PLC0415

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://arsgoatia.dev",
                        "X-Title": "ArsGoatia",
                    },
                    json=payload,
                )
        except httpx.HTTPError as exc:
            raise AICompletionError(f"OpenRouter request failed: {exc!r}") from exc

        if resp.status_code >= 400:
            raise AICompletionError(
                f"OpenRouter returned {resp.status_code}: {resp.text[:200]}",
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise AICompletionError(f"OpenRouter returned non-JSON body: {exc!r}") from exc

        try:
            content = body["choices"][0]["message"]["content"]
            usage = body.get("usage", {})
            tokens = int(usage.get("total_tokens", 0))
        except (KeyError, IndexError, TypeError) as exc:
            raise AICompletionError(f"unexpected response shape: {body!r}") from exc

        cost = (tokens / 1000.0) * self._cost_per_1k
        self._budget.record(cost)

        return AIResponse(
            content=content,
            model=body.get("model", self.config.model_name),
            tokens_used=tokens,
            cost_usd=cost,
            request_id=str(uuid.uuid4()),
            redacted_fields=redacted_fields,
        )


def from_settings() -> AIGateway:
    """Build the appropriate gateway based on ArsGoatiaSettings.

    Returns :class:`OpenRouterGateway` when both an API key and provider are
    configured; otherwise returns the contract-layer :class:`AIGateway`
    which raises :class:`AIUnavailable` on every call.
    """
    from packages.config import get_settings  # noqa: PLC0415

    settings = get_settings()
    config = AIGatewayConfig(
        model_name=settings.ai_model,
        budget_limit_usd=settings.ai_budget_usd,
        redact_secrets=settings.ai_redact_secrets,
    )

    provider = getattr(settings, "ai_provider", "openrouter")
    api_key = getattr(settings, "ai_api_key", "") or ""
    base_url = getattr(settings, "ai_base_url", "https://openrouter.ai/api/v1")

    if provider == "openrouter" and api_key:
        return OpenRouterGateway(
            api_key=api_key,
            base_url=base_url,
            config=config,
        )
    return AIGateway(config)


async def propose_hypothesis(
    *,
    engagement_id: str,
    target_url: str,
    discovered_endpoints: list[str],
) -> dict[str, Any] | None:
    """Advisory hypothesis proposal — never affects control path.

    Returns ``None`` when the gateway is unavailable, over budget, or the
    model output cannot be parsed. Callers must treat any successful
    response as untrusted input.
    """
    gateway = from_settings()
    prompt = (
        "Given the target URL and enumerated endpoints below, propose up to 3 "
        "web-authorisation hypotheses ranked by expected likelihood of an IDOR "
        "or BOLA. For each, return {technique_id, target_endpoint, rationale, "
        "expected_evidence}.\n\n"
        f"Target: {target_url}\n"
        f"Endpoints: {json.dumps(discovered_endpoints)}"
    )
    request = AIRequest(
        role="hypothesis-proposer",
        prompt=prompt,
        response_schema={
            "type": "object",
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["technique_id", "target_endpoint", "rationale"],
                    },
                },
            },
        },
        engagement_id=engagement_id,
    )
    try:
        response = await gateway.complete(request)
    except (AIUnavailable, AIBudgetExceeded, AICompletionError):
        return None
    try:
        return json.loads(response.content)
    except ValueError:
        return None
