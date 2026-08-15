# wp3 - raising SWEEP_TARGET_CAP 400 -> 700. Conditions registered BEFORE the run.

Written and committed while the mission is in flight and before any key is read, because the value of
a pre-registered condition is that it cannot be edited once the number is known. wp1 established the
habit the hard way: the best headline figure the project had ever produced was reverted on a condition
written in advance, and reading it afterwards was the only thing that stopped a good-looking artifact
from shipping.

## The change

ONE variable: `BBH_SWEEP_TARGETS=700` (default 400). No code change - the constant is already
env-overridable. `run_web_probes` stays OUT of `_SWEEP_HTTP_ENGINES`, the Q-047 oracle fix is in, so
this run differs from the scored baseline in the budget and nothing else.

## Why 700

MEASURED over the real class spread (2524 candidates, 11 shapes, 456..27):
the dominant class draws 38 slots at cap 400 and 59 at cap 605, and the nine lost sqli true positives
sit at class indices 38-58. 605 is the boundary; 700 is the first round number above it with margin
for the live surface differing from the modelled one.

## What would make this a FAILURE, decided now

1. **Precision below 96.3%** (the re-derived baseline `ebd96f45`). More recall bought with false
   positives is not a gain. Revert rather than defend.
2. **Any NEW false positive whose mechanism is not understood.** wp2 taught this one: a score can
   improve while an unexplained FP class survives underneath it.
3. **Fewer than 7 of the nine named cases recovered** (00335 00337 00339 00341 00342 00428 00429
   00433 00438). The whole prediction is that these are budget-starved; recovering almost none of
   them falsifies it, and the cap goes back to 400.

## What would make it a SUCCESS

Precision >= 96.3% AND at least 7 of the nine recovered. Then the cap moves in the repo, with the
elapsed cost stated plainly in the same commit.

## The cost, predicted now so it can be wrong

The sweep is 92% of dispatches and 78% of tool-seconds (1593 s of 2103 s at 400 targets). At 700 the
sweep should cost ~2800 s and the mission ~3300 s, i.e. **+57%**. If it lands far from that, the
prediction was wrong and that is worth recording too - the per-URL cost is supposed to be linear in
target count and this is the first time that has been tested at a different budget.
