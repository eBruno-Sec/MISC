"""AI gateway: redaction, structured-output validation, budget (§15).

Wraps the provider with the guarantees that make AI safe to use in the loop:
  * redact secrets/raw evidence before the prompt (fingerprints/summaries only);
  * deterministically post-validate the model's JSON against a schema;
  * enforce per-request/assessment/daily budget;
  * on AIUnavailable, invalid output, or over-budget -> return the caller's
    deterministic fallback (AI is advisory, never required).

The redaction, JSON extraction, validation, and budget checks are pure and
unit-tested; complete_structured() ties them to the provider.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ai_gateway.provider import AICompletionError, AIUnavailable, complete

# Patterns for secret-bearing values scrubbed before anything reaches a prompt.
_REDACTIONS = [
    (re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"), "<JWT>"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "Bearer <redacted>"),
    (re.compile(r"(?i)(authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*[^\s,;]+"), r"\1: <redacted>"),
    (re.compile(r"(?i)(password|secret|token)\"?\s*[:=]\s*\"?[^\s,;\"']+"), r"\1: <redacted>"),
]


def redact(text: str) -> str:
    """Scrub secret-bearing values from prompt text (fingerprints/summaries stay)."""
    out = text or ""
    for pattern, repl in _REDACTIONS:
        out = pattern.sub(repl, out)
    return out


def extract_json(text: str) -> Any | None:
    """Pull the first JSON object/array out of a model response (handles code
    fences and surrounding prose). Returns None if nothing parses."""
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    start = min([i for i in (candidate.find("{"), candidate.find("[")) if i != -1], default=-1)
    if start == -1:
        return None
    for end in range(len(candidate), start, -1):
        try:
            return json.loads(candidate[start:end])
        except Exception:  # noqa: BLE001 - keep shrinking the window
            continue
    return None


def validate_against_schema(data: Any, schema: dict) -> tuple[bool, str]:
    try:
        import jsonschema

        jsonschema.validate(data, schema)
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 - invalid -> quarantine
        return False, str(exc)[:200]


@dataclass
class BudgetLedger:
    request_budget_usd: float = 1.0
    assessment_budget_usd: float = 5.0
    daily_budget_usd: float = 10.0
    assessment_spent_usd: float = 0.0
    daily_spent_usd: float = 0.0
    last_denied_reason: str = field(default="")

    def can_spend(self, estimate_usd: float) -> bool:
        if estimate_usd > self.request_budget_usd:
            self.last_denied_reason = "request_budget"
            return False
        if self.assessment_spent_usd + estimate_usd > self.assessment_budget_usd:
            self.last_denied_reason = "assessment_budget"
            return False
        if self.daily_spent_usd + estimate_usd > self.daily_budget_usd:
            self.last_denied_reason = "daily_budget"
            return False
        return True

    def record(self, spent_usd: float) -> None:
        self.assessment_spent_usd += spent_usd
        self.daily_spent_usd += spent_usd


class AIGateway:
    def __init__(self, budget: BudgetLedger | None = None) -> None:
        self.budget = budget or BudgetLedger()

    async def complete_structured(
        self,
        *,
        role: str,
        prompt: str,
        schema: dict,
        fallback: Any,
        system: str | None = None,
        estimate_usd: float = 0.05,
        max_tokens: int = 1024,
    ) -> tuple[Any, str]:
        """Return (result, source). source in {ai, fallback:<reason>}. The result
        is ALWAYS schema-valid: on any failure the deterministic fallback is used."""
        if not self.budget.can_spend(estimate_usd):
            return fallback, f"fallback:{self.budget.last_denied_reason}"
        try:
            raw = await complete(redact(prompt), max_tokens=max_tokens,
                                 system=system, role=role)
        except AIUnavailable:
            return fallback, "fallback:ai_unavailable"
        except AICompletionError as exc:
            return fallback, f"fallback:ai_error:{exc.status}"
        self.budget.record(estimate_usd)
        data = extract_json(raw)
        if data is None:
            return fallback, "fallback:unparseable"
        ok, _ = validate_against_schema(data, schema)
        if not ok:
            return fallback, "fallback:schema_invalid"
        return data, "ai"
