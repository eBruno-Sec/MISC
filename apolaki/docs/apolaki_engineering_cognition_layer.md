# Apolaki Engineering Cognition Layer

Standing reasoning disciplines to apply CONTINUOUSLY while designing, auditing, debugging, testing, and
improving Apolaki. This is not a task to complete — it is how the work is done. The north star: **do not
merely make Apolaki produce more findings; make Apolaki increasingly difficult to fool.**

## Critical thinking
Never accept the first plausible explanation. For every important conclusion ask: what evidence supports it?
what contradicts it? what am I assuming? what else could explain it? what would prove me wrong? can I
reproduce it independently? Keep the stages separate — **Observation → Hypothesis → Test → Evidence →
Conclusion** — and never collapse a hypothesis directly into a conclusion.

## First-principles thinking
When architecture gets confusing, reduce to required truths: what must this component accomplish? what inputs
does it actually require? what output must downstream receive? what invariant must never break? is the current
abstraction necessary or merely inherited? Don't preserve complexity because it exists; do preserve it when it
solves a real requirement.

## Root-cause thinking
Don't patch symptoms. What failed → why → what allowed it → why didn't existing controls detect it → could the
same cause exist elsewhere → what invariant/test prevents recurrence. Fix the smallest underlying cause that
eliminates the defect CLASS without weakening capability.

## Adversarial thinking
Try to disprove Apolaki's own assumptions. How could this safety rail be bypassed? how could this evidence
mislead? how could this parser misunderstand hostile input? how could an attacker manipulate the planner? how
could two individually-correct modules compose into unsafe behavior? what happens with malformed,
contradictory, delayed, duplicated, or adversarial data? Think as attacker AND defender.

## Systems thinking
Never evaluate a component only in isolation. Trace **Input → Scope → Planner → Tool → Evidence → Graph →
Finding → Report → Retest**. Evaluate feedback loops, shared state, dependencies, side effects, downstream
consequences. A locally-correct module can still create a globally-broken system.

## Bayesian thinking
Confidence is earned by evidence. Start uncertain; raise confidence when INDEPENDENT evidence agrees; lower it
when evidence conflicts, provenance is weak, observations are stale, negative controls fail, or environmental
noise explains the result. Never convert confidence into certainty just because several weak signals agree.

## Falsification
For important security hypotheses, actively search for evidence the hypothesis is FALSE. E.g. BOLA "User B can
read User A's object": positive test (B requests A's object) + negative controls (A requests own; anon
requests it; a nonexistent object; an equivalent legitimate object). Only promote when the DIFFERENTIAL
supports unauthorized access. Confirmation must survive attempts to disprove it. (This is exactly the
read_object_idor oracle discipline.)

## Counterfactual thinking
Ask what SHOULD happen if the suspected vuln did not exist, and compare to observed. Prefer differentials over
isolated responses.

## Second-order thinking
Before a change: what does it enable next? what could it break? does it create another source of truth? does
it weaken a safety invariant? does it increase false positives? does it add maintenance debt? does it change
planner behavior elsewhere? Optimize the system, not the immediate task.

## Occam's razor
Prefer the simplest explanation consistent with ALL evidence, and the smallest architecture that satisfies ALL
requirements — but never simplify by deleting required capability, evidence, safety, or extensibility. Simple
= fewer unnecessary moving parts, NOT weaker.

## Cognitive-bias resistance
Guard against confirmation, anchoring, availability, sunk-cost, automation, authority, novelty bias. Existing
code is not correct because it exists. New architecture is not better because it is new. AI output is not
correct because it sounds confident. Tests are not proof if they test the wrong thing. Documentation is not
truth. Measure against evidence.

## Intellectual humility
Grade claims: **Proven / Probable / Possible / Unknown / Disproven.** Don't hide uncertainty; when evidence is
insufficient, state exactly what evidence would resolve it.

## Precision (exact terminology)
`reachable ≠ executed` · `executed ≠ successful` · `successful request ≠ vulnerability` · `candidate ≠
confirmed` · `correlation ≠ causation` · `exposure ≠ exploitability` · `exploitability ≠ demonstrated impact`
· `test passed ≠ architecture verified`.

## Prioritization
Don't optimize what's easiest. Rank by **Risk × Evidence × Reachability × User-impact × Architectural-leverage
÷ Implementation-cost.** Safety and evidence-integrity defects override normal prioritization.

## Scientific debugging
Reproduce → minimize → hypothesize → instrument → change ONE meaningful variable → observe → reject/strengthen
→ fix root cause → reproduce original failure → run regression tests. Never randomly modify code until tests
turn green.

## Steelmanning
Before rejecting an architecture, find the strongest reason it may have been designed that way. Understand
before replacing; then compare alternatives against actual requirements and evidence.

## Continuous learning
Every meaningful defect should improve Apolaki's future reasoning. Can it become an invariant? a regression
test? an oracle? a planner rule? a graph fact? a technique precondition? a safety control? reusable knowledge?
Don't repeatedly rediscover the same lesson.

## Final mental model
Think like a **scientist** evaluating evidence · an **attacker** challenging assumptions · a **defender**
designing controls · an **engineer** implementing · an **architect** evaluating interactions · **QA** trying
to break the result · an **operator** judging usability · an **auditor** demanding proof · a **client** judging
trustworthiness.
