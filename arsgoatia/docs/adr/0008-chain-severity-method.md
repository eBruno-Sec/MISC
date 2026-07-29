# ADR-0008: ArsGoatia Chain-Severity Method

**Status:** Accepted
**Date:** 2025-01-15
**Deciders:** Architecture team

## Context

When ArsGoatia confirms a vulnerability finding, it must communicate the
severity of that finding in reports. The security industry commonly uses CVSS
(Common Vulnerability Scoring System) for this purpose. However, CVSS has
significant limitations for the kind of findings ArsGoatia produces:

- **CVSS scores individual vulnerabilities in isolation.** ArsGoatia discovers
  attack chains -- sequences of vulnerabilities that compound in severity.
  A BOLA finding that alone is "Medium" may enable a chain that escalates to
  full account takeover ("Critical"). CVSS has no native mechanism for
  chain-level scoring.
- **CVSS is a standard with strict usage requirements.** Producing CVSS scores
  requires following the specification precisely. Labeling a custom severity
  metric as "CVSS" when it does not follow the specification would be
  misleading and could expose operators to liability.
- **ArsGoatia's deterministic confirmation model differs from CVSS assumptions.**
  CVSS scores encode likelihood and impact estimates. ArsGoatia's findings are
  deterministically confirmed with evidence; the question is not "how likely is
  exploitation" but "what was the confirmed impact of this chain."

## Decision

ArsGoatia uses its own **chain-severity method** for rating findings. This
method:

1. Assigns a **base severity** to each atomic finding using a defined rubric
   (considering access level, data sensitivity, and confirmed impact).
2. Computes a **chain severity** by evaluating how atomic findings compose --
   whether one finding enables or amplifies another.
3. Produces a severity label (Info / Low / Medium / High / Critical) and a
   numeric score on ArsGoatia's own scale.

**This method is never labeled as CVSS.** Reports explicitly identify the
scoring method as "ArsGoatia Chain-Severity" and include a methodology
reference. If consumers need CVSS scores, they must derive them independently
using the evidence ArsGoatia provides.

## Consequences

**Positive:**

- **Accurate chain representation** -- Severity reflects the compounded impact
  of chained vulnerabilities, which is the platform's core value proposition.
- **No misrepresentation** -- By not claiming CVSS compliance, ArsGoatia avoids
  misleading operators and auditors.
- **Deterministic** -- The severity computation is a pure function of confirmed
  evidence, not an estimate. Given the same evidence, the same score is always
  produced.
- **Extensible** -- The rubric can be updated as new vulnerability classes are
  added without needing to comply with an external specification's versioning.

**Negative:**

- **Unfamiliar to consumers** -- Security teams accustomed to CVSS will need to
  learn ArsGoatia's severity scale. The methodology reference in reports
  mitigates this.
- **Integration friction** -- Tools that ingest CVSS (e.g., vulnerability
  management platforms) cannot directly consume ArsGoatia severity scores.
  SARIF output includes the ArsGoatia severity; a mapping layer could be added
  if needed.
- **Perceived legitimacy** -- A proprietary scoring method may be viewed with
  skepticism compared to an industry standard. The deterministic,
  evidence-backed nature of the scores addresses this.

## Notes

- The chain-severity computation is implemented in `packages/domain/findings/`.
- The attack-chain graph is built and scored in `packages/graph/`.
- SARIF reports include the severity level in the `level` field and the
  ArsGoatia score in a property bag, clearly labeled as non-CVSS.
- Reports include a "Methodology" section that explains the chain-severity
  rubric for each engagement.
- Related: The reporting module in `packages/domain/reporting/` formats the
  severity labels and includes the methodology disclaimer.
