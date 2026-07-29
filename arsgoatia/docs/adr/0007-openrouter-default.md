# ADR-0007: OpenRouter Free-Model Default for AI

**Status:** Accepted
**Date:** 2025-01-15
**Deciders:** Architecture team

## Context

ArsGoatia uses AI-assisted reasoning in several subsystems:

- **Hypothesis generation** -- Given recon data, the reasoning engine proposes
  candidate vulnerability hypotheses.
- **Remediation guidance** -- After a finding is confirmed, the system
  generates developer-facing remediation advice.
- **Report narrative** -- Human-readable report sections may be drafted with
  AI assistance.

These capabilities require access to a large language model. The platform must
support multiple LLM providers to avoid vendor lock-in, and the default
configuration must work without requiring paid API keys for initial setup and
development.

## Decision

Use OpenRouter as the default AI gateway, configured to use free-tier models
(e.g., `meta-llama/llama-3-8b-instruct:free`) for development. The
`packages/ai_gateway` module abstracts the LLM provider behind a common
interface, and the provider is selected via configuration.

**Critical constraint:** The AI fallback path must never bypass safety controls.
If the AI gateway is unavailable or returns an error, the system falls back to
deterministic-only operation (no AI-generated hypotheses, no AI-drafted
narratives). It must never skip policy evaluation, approval gates, or scope
enforcement because the AI layer is degraded.

## Consequences

**Positive:**

- **Zero-cost development** -- Developers can run the full stack without
  providing paid API keys.
- **Provider-agnostic** -- OpenRouter supports routing to multiple upstream
  models; switching providers requires only a configuration change.
- **Graceful degradation** -- The platform operates correctly without AI; AI
  features enhance but do not gate security-critical workflows.

**Negative:**

- **Rate limits** -- Free-tier models have strict rate limits and may be
  unavailable during peak usage. This is acceptable for dev/lab but not for
  production engagements.
- **Model quality** -- Free-tier models may produce lower-quality hypotheses or
  remediation guidance compared to larger paid models.
- **Latency variance** -- OpenRouter routing adds a hop; latency depends on
  upstream model availability.

## Notes

- **Production upgrade path:** Configure a direct API key for the chosen
  provider (Anthropic, OpenAI, etc.) or use a self-hosted model. The
  `ai_gateway` interface remains the same; only the provider configuration
  changes.
- The AI gateway configuration is in `packages/ai_gateway/`. Provider
  selection is controlled by the `ARSGOATIA_AI_PROVIDER` and
  `ARSGOATIA_AI_MODEL` environment variables.
- **Safety invariant:** The `packages/policy` module enforces that no
  autonomous action proceeds without policy evaluation, regardless of AI
  availability. This is tested in `tests/security/test_invariants.py`.
