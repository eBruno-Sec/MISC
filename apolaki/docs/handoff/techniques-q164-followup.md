# Q-164 follow-up -- landing the diffs the audit lane could not apply

Lane: BUILDER. Write set, and nothing else:

    agent/liveness.py
    agent/tests/test_authscan.py
    agent/tests/test_validated_on.py
    docs/handoff/techniques-q164-followup.md

Input: `docs/handoff/techniques-q164.md`. That audit is NOT re-derived here. Each of its
handed-over diffs is verified to still apply, landed, and measured. Where a diff reaches a file
this lane does not own, the applicable half is landed and the rest is re-issued as a diff below.

Written as the work happens, not at the end.

## Starting state (MEASURED)

    $ git log --oneline -3 -- agent/techniques.py agent/tests/test_technique_badges.py
    a630efb Apolaki Q-164: badges are now re-earned per (technique, lab) or withdrawn (#123)

So the audit lane's own commit is in. The three handed-over diffs are what remains.

## Baseline before any edit (MEASURED)

    $ docker run --rm --network apolaki_default -v ".../apolaki/agent:/app" -w /app \
        apolaki-agent python -m pytest tests/ -p no:cacheprovider -q -p no:warnings \
        -k "liveness or validated_on or authscan or technique or badge"
    ........................................................................ [ 47%]
    ........................................................................ [ 94%]
    ..x..x...                                                                [100%]

153 passed, 2 xfailed, ZERO skipped. The `--network apolaki_default` flag is what makes that
true; without it ten of these silently skip and the run still prints green.

Lab bench, all up (`docker ps`): conpot, dvga, juice-shop, domsource, clientauthz, dvwa, snmpd,
openldap, smb, dnp3-outstation, vampi, mutillidae, bwapp, webgoat, owaspbench, sessionlife.

## FINDING 0 -- the handed-over `liveness.py` diff cannot be applied as written

Found before landing anything, by driving the pure function rather than reading it.

`agent/liveness.py:evaluate()` builds `by = {r["technique"]: r for r in results}`. The key is the
TECHNIQUE ALONE. Every check in `CHECKS` today happens to name a distinct technique, so the
collision has never been reachable -- but diff #2 adds a SECOND `snmp_default_community` check
(on conpot, alongside the existing snmpd one), which makes it reachable on the first run.

MEASURED, driving `liveness.evaluate` directly with hand-built results:

    # a CONFIRMED snmpd check and a SKIPPED conpot check, same technique
    confirmed: []                          skipped: ['snmp_default_community']
    regressions: ['snmp_default_community']            ok: False

    # THE SAME TWO RESULTS, list order reversed
    confirmed: ['snmp_default_community']  regressions: []                    ok: True

    # a DEAD check and a CONFIRMED check, same technique
    confirmed: ['snmp_default_community']  dead: []                           ok: True

Two distinct defects, both of which the diff would have shipped:

1. **The verdict depends on the order of a literal tuple.** Identical evidence, opposite answers.
2. **A CONFIRMED check MASKS a DEAD one.** `dead: []`, `ok: True`, with an engine measured dead
   on conpot. That is the exact silent-failure shape this module's own docstring was written to
   remove -- moved one layer up, into the scorer.

Landing the diff verbatim would have produced a gate that reports green on a dead engine, or a
false REGRESSION on a healthy one, depending only on where the line was pasted. So `evaluate()`
is fixed first, in the same commit as the checks that make the collision reachable.

The fix keeps the baseline's technique-id vocabulary (the baseline file is not in this write set)
and applies the module's own stated doctrine per technique:

    a technique is CONFIRMED iff at least one of its checks confirmed
                              AND none of its checks came back DEAD.

SKIPPED does not subtract, because the question was not asked -- that is `verdict()`'s rule
already. DEAD does subtract, because the question was asked and answered "no". For every
technique with exactly one check, which is all of them today, this is identical to the old
behaviour; the two collision cases above are the only results it changes.

## FINDING 1 -- diff 1's premise re-verified (MEASURED)

    exposed_credentials      -> {'engines': [], 'routable': False}
    graphql_batching_enabled -> {'engines': ['run_graphql'], 'routable': True}
    sqli_auth_bypass         -> {'engines': ['run_auth_sqli', 'run_sqli'], 'routable': True}
    snmp_default_community   -> {'engines': ['run_service_pack'], 'routable': True}

`exposed_credentials` still has no engine bound, so the audit's basis for withdrawing the badge
holds. The three re-earn targets are all routable, so diff 2's targets are still real.

## Work log

(filled in below as each slice lands)
