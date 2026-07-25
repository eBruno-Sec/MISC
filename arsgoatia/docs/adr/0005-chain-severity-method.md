# ADR 0005 — ArsGoatia chain-severity method (not CVSS)

- Status: Accepted (slice)
- Date: 2026-07-25

## Context
Attack chains express aggregate impact that per-finding CVSS does not capture
(§17, §6.20). The spec forbids labeling chain severity as CVSS.

## Decision
Chains carry a `chain_severity` (informational..critical) computed by a versioned
ArsGoatia method and a machine-readable `chain_scoring_rationale`. The method is
explicitly **not** CVSS and is never presented as such. The slice ships a minimal
v1 (blast radius × capability escalation × validated-step count) that later
milestones refine.

## Consequences
- Reports display chain severity with the method version and rationale, so a
  reviewer can audit the score.
- Refining the method bumps its version; historical chains keep their scored
  version for reproducibility.
