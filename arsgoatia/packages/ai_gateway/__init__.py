"""AI gateway (§15). Proposal-only.

AI may summarize, propose hypotheses, rank modules, draft plans/reports, and
normalize output. AI may NOT execute target actions, approve, change scope,
invent evidence, confirm findings, receive raw secrets, or bypass safety/cost
controls. Every AI output is deterministically post-validated; on failure the
caller falls back to the deterministic path.
"""

from ai_gateway.gateway import AIGateway
from ai_gateway.provider import AICompletionError, AIUnavailable, complete

__all__ = ["AIGateway", "AICompletionError", "AIUnavailable", "complete"]
