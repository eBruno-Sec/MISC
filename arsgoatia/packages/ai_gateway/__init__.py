"""ArsGoatia AI gateway.

This is the contract layer between ArsGoatia's reasoning components and
any underlying LLM provider.  It defines the request/response shapes,
budget enforcement, secret redaction, and structured-prompt construction
that every provider integration must go through.

No external API is called from this module.  ``AIGateway.complete`` is a
pure contract stub: it enforces budget limits and otherwise raises
``AIUnavailable`` because no provider is wired in.  Concrete provider
adapters live elsewhere and are expected to subclass or wrap this
gateway, never bypass it.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "AIGatewayConfig",
    "AIRequest",
    "AIResponse",
    "BudgetTracker",
    "redact_secrets_from_text",
    "build_structured_prompt",
    "AIGateway",
    "AIUnavailable",
    "AIBudgetExceeded",
    "AICompletionError",
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AIUnavailable(Exception):
    """No AI provider is configured or reachable."""


class AIBudgetExceeded(Exception):
    """The configured AI spend budget has been exhausted."""


class AICompletionError(Exception):
    """A provider call failed or returned an unusable completion."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AIGatewayConfig(BaseModel):
    model_name: str = "gpt-4o-mini"
    max_tokens: int = 4096
    temperature: float = 0.0
    budget_limit_usd: float = 25.0
    redact_secrets: bool = True


class AIRequest(BaseModel):
    role: str
    prompt: str
    response_schema: dict[str, Any] | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    engagement_id: str | None = None


class AIResponse(BaseModel):
    content: str
    model: str
    tokens_used: int
    cost_usd: float
    request_id: str
    redacted_fields: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Budget tracking
# ---------------------------------------------------------------------------


class BudgetTracker:
    """Tracks cumulative spend against a fixed limit, in USD."""

    def __init__(self, limit_usd: float) -> None:
        self.limit_usd = limit_usd
        self.spent_usd = 0.0

    def record(self, cost: float) -> None:
        """Record *cost* (USD) as spent."""
        self.spent_usd += cost

    def remaining(self) -> float:
        """Return the remaining budget, floored at zero."""
        return max(0.0, self.limit_usd - self.spent_usd)

    def is_exceeded(self) -> bool:
        """Return True once cumulative spend has reached the limit."""
        return self.spent_usd >= self.limit_usd


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

# Ordered so composite forms (e.g. "Bearer <jwt>") are consumed whole
# before their sub-parts (e.g. a bare JWT) get a second, redundant match.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)),
    ("basic_auth", re.compile(r"Basic\s+[A-Za-z0-9+/]+=*", re.IGNORECASE)),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "aws_secret_key",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{20,}"),
    ),
    (
        "api_key",
        re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?'),
    ),
    (
        "password",
        re.compile(r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?\S+["\']?'),
    ),
]


def redact_secrets_from_text(text: str) -> tuple[str, list[str]]:
    """Scan *text* for common secret formats and redact each match.

    Recognises Bearer tokens, Basic-auth headers, JWTs, AWS access-key
    IDs and secret keys, generic API keys, and password assignments.
    Each match is replaced with ``[REDACTED-N]`` in order of discovery.

    Returns ``(redacted_text, labels)`` where *labels* names the kind of
    secret redacted at each position (parallel to the ``[REDACTED-N]``
    markers, in order).
    """
    redacted_text = text
    labels: list[str] = []
    counter = 1

    for label, pattern in _SECRET_PATTERNS:

        def _substitute(match: re.Match[str], _label: str = label) -> str:
            nonlocal counter
            placeholder = f"[REDACTED-{counter}]"
            counter += 1
            labels.append(_label)
            return placeholder

        redacted_text = pattern.sub(_substitute, redacted_text)

    return redacted_text, labels


# ---------------------------------------------------------------------------
# Structured prompt construction
# ---------------------------------------------------------------------------


def build_structured_prompt(request: AIRequest, config: AIGatewayConfig) -> dict[str, Any]:
    """Build the wire-level prompt structure for a completion call.

    Assembles a system message that pins the model to structured output,
    the caller's prompt, and (if provided) explicit schema instructions.
    This is provider-agnostic: adapters translate it into whatever shape
    their SDK expects.
    """
    system_lines = [
        f"You are the {request.role} component of the ArsGoatia security "
        "validation platform.",
        "You must respond with valid JSON only -- no prose, no markdown "
        "code fences, no commentary.",
    ]
    if request.response_schema is not None:
        system_lines.append(
            "Your JSON response MUST conform exactly to this schema: "
            f"{request.response_schema}"
        )

    return {
        "system": " ".join(system_lines),
        "user": request.prompt,
        "response_schema": request.response_schema,
        "context": request.context,
        "model": config.model_name,
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
    }


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


class AIGateway:
    """Contract-layer entry point for all AI-assisted operations.

    Enforces the spend budget and secret-redaction policy declared in
    ``config``.  No provider is wired in at this layer -- ``complete``
    always raises ``AIUnavailable`` unless overridden or wrapped by a
    concrete provider adapter.
    """

    def __init__(self, config: AIGatewayConfig | None = None) -> None:
        self.config = config or AIGatewayConfig()
        self._budget = BudgetTracker(self.config.budget_limit_usd)

    async def complete(self, request: AIRequest) -> AIResponse:
        """Complete *request* against the configured provider.

        Raises ``AIBudgetExceeded`` if the spend budget has already been
        exhausted, and ``AIUnavailable`` because this contract layer has
        no provider wired in.
        """
        if self._budget.is_exceeded():
            raise AIBudgetExceeded(
                f"AI budget of ${self.config.budget_limit_usd:.2f} exceeded"
            )

        # Contract layer only -- building the request is as far as this
        # goes without a concrete provider adapter installed.
        build_structured_prompt(request, self.config)

        raise AIUnavailable("no provider configured")

    def get_budget_status(self) -> dict[str, Any]:
        """Return the current budget state as a plain dict."""
        return {
            "limit_usd": self.config.budget_limit_usd,
            "spent_usd": self._budget.spent_usd,
            "remaining_usd": self._budget.remaining(),
            "is_exceeded": self._budget.is_exceeded(),
        }
