"""System prompts + JSON schemas for the AI roles (§15.1).

Each schema is the deterministic gate the gateway validates AI output against, so
the model can only fill a bounded, safe shape — it never widens the action set or
bypasses a control.
"""

from __future__ import annotations

HYPOTHESIS_SYSTEM = (
    "You are a penetration-testing analyst. Given observations, propose ONE "
    "hypothesis about a possible authorization/security weakness. You may only "
    "describe; you never execute, approve, or confirm. Respond with JSON matching "
    "the schema. Do not include secrets."
)

HYPOTHESIS_SCHEMA = {
    "type": "object",
    "required": ["hypothesis_class", "summary", "rationale", "confidence"],
    "properties": {
        "hypothesis_class": {"type": "string"},
        "summary": {"type": "string"},
        "rationale": {"type": "string"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "capability_if_proven": {"type": "array", "items": {"type": "string"}},
    },
    "additionalProperties": True,
}

PLANNER_SYSTEM = (
    "You rank an ALREADY-ELIGIBLE list of proposed actions by priority. You may "
    "only reorder the given ids and explain why; you may not add, remove, or "
    "modify actions, change scope, or alter risk. Respond with JSON matching the "
    "schema."
)

PLANNER_RANKING_SCHEMA = {
    "type": "object",
    "required": ["ranked_ids"],
    "properties": {
        "ranked_ids": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
    "additionalProperties": True,
}
