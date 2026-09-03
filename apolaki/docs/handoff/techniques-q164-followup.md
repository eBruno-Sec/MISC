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

### Slice 1 -- LANDED (309becd). `test_authscan.py`, the blocking equality assertion

Removed `assert TECHNIQUES["exposed_credentials"]["validated_on"] == ["ginandjuice"]` and replaced
it with the reason. The test's two real assertions (REGISTERED, and autonomously PLANNED once recon
exposes a credential) are untouched -- nothing was weakened to make anything pass, and nothing was
failing. `pytest tests/test_authscan.py` -> `..... [100%]`, 5 passed.

Still outstanding for the owner of `agent/techniques.py`: set `exposed_credentials`
`validated_on=[]`, and delete `("exposed_credentials", "ginandjuice")` from `DEBT` in
`agent/tests/test_technique_badges.py`. Re-issued as a diff at the bottom. Until both land the
badge stands and the debt entry stays correct, so the tree is consistent at every point.

### Slice 2 -- the `session_lifecycle` / `sessionlife` verdict: STAYS ON DEBT

The audit left this one UNRESOLVED because the lab was mid-landing in another lane's uncommitted
tree and it would not guess. Re-checked now.

**The other lane has NOT settled.** MEASURED:

    $ git show HEAD:apolaki/docker-compose.yml | grep -n sessionlife
    (absent at HEAD)
    $ git ls-files apolaki/labs/ | grep -i session
    (no tracked sessionlife source)
    $ git status --short apolaki/docker-compose.yml apolaki/labs/
     M apolaki/docker-compose.yml
    ?? apolaki/labs/sessionlife/          # one file: app.py

Byte-for-byte the same situation the audit recorded. The compose service and `labs/sessionlife/app.py`
are still uncommitted working-tree state.

But "unresolved" is not the best answer available now, because two DIFFERENT questions were being
run together. I separated them and measured both.

**Question 1 -- is the badge's claim TRUE?** Yes, and strongly. The engine is bound
(`engine_descriptor`: `engines=['run_session_lifecycle']`, `routable=True`), the lab answers on
`sessionlife:8080`, and driving the SHIPPING executor `_run_session_lifecycle` against all four
mounts gives the paired discrimination the lab was built for:

    /vuln           2 findings   confirmed CWE-613  session not invalidated on logout
                                 confirmed CWE-613  sessions survive a password change
    /secure         0 findings
    /expire-vuln    1 finding    confirmed CWE-613  declared expiry not enforced server-side
    /expire-secure  0 findings

Three confirmations on the vulnerable halves and ZERO on both secure halves. The engine declines
the safe case, so this is a discrimination and not an engine that fires at any session cookie.

**Question 2 -- does anything IN THE REPOSITORY re-run it?** No, and it cannot yet. That is the
question the badge answers to, and it is the one that decides the verdict.

**Verdict: STALE, stays on `DEBT`.** Not "cannot classify" -- the measured reason is that
`sessionlife` is not a repository artifact. A `CHECKS` entry naming it would be an ISLAND: on this
machine it confirms, and on every fresh clone `_reachable("sessionlife")` returns False and the
check is SKIPPED forever. It would also race the other lane, who can still change the port or the
mount before they commit.

It is decided by construction as well as by judgment, which is the part worth stating:
`test_technique_badges.liveness_pairs()` requires BOTH a `CHECKS` entry AND the technique in the
COMMITTED baseline. `agent/tests/liveness_baseline.json` is not in this lane's write set, so
`session_lifecycle` could not become a backed pair here even if I added the check. The debt entry
stays correct either way.

What clears it is one commit by the lab's owner, and the exact `CHECKS` entry to apply at that
moment is measured and handed over below -- ready, not guessed.

### Slice 3 -- LANDED (412ab98). `liveness.py`: `evaluate()` regrouped, two checks promoted

Two of the audit's three re-earns are now `CHECKS` entries, where `scripts/liveness.sh` runs them
and the ratchet protects them. Driven through the REAL runner (`liveness_run._run_one`), not a
re-implementation:

    [confirmed] snmp_default_community   lab=snmpd    ...default community ('public') at snmpd:161
    [confirmed] snmp_default_community   lab=conpot   ...default community ('public') at conpot:16100
    [confirmed] graphql_introspection    lab=dvga     GraphQL introspection enabled
    [confirmed] graphql_batching_enabled lab=dvga     GraphQL request batching enabled

    engine liveness: 4 checked, 3 confirmed, 0 dead, 0 skipped, 0 error
      newly live      graphql_batching_enabled

`evaluate()` was fixed FIRST, in the same commit, because FINDING 0 above makes the diff
unapplicable without it.

**An existing guard caught the first version of this change, and it was right to.**
`test_liveness.py:test_checks_sharing_a_family_must_disambiguate_by_title` went red:

    AssertionError: family 'snmp_default_community' is claimed by 2 checks with no title
    to tell them apart: ['snmp_default_community', 'snmp_default_community']

Answered by making both checks STRICTER, not by exempting them. The engine names the host it
questioned in its own finding title, so each check now pins its own host fragment
(`"snmpd:161"`, `"conpot:16100"`). Either check now fails if pointed at the other's lab -- which is
the property the ticket asks for, arrived at by a guard rather than by me.

### The third re-earn is NOT landed, and shipping it would have been an island

`sqli_auth_bypass`/`juiceshop` drives correctly -- MEASURED, confirmed, CWE-89, evidence
`email="' OR 1=1--" -> session/JWT token issued for an invalid credential`. It is still not in
`CHECKS`, for a reason that is structural rather than a judgment call:

    $ grep -n juice agent/liveness_run.py
    (NO juiceshop entry in _LAB_ADDR)

`_reachable()` falls back to `(lab, 80)`, so a `"lab": "juiceshop"` check resolves `juiceshop:80`,
which is neither the container's hostname (`juice-shop`) nor its port (3000). It would report
SKIPPED on every run, forever. `agent/liveness_run.py` is outside this lane's write set, so the
one-line `_LAB_ADDR` addition it needs cannot be made here, and landing the check without it would
ship a declaration that can never become a fact. Diff below. The badge stays backed meanwhile by
the live re-run already in `test_technique_badges.py`, so nothing regresses.

## On-disk mutants (MEASURED)

Every mutant was edited into `agent/liveness.py` ON DISK -- never monkeypatched -- driven through
the real runner against the real labs, then reverted with `git checkout` and the tree confirmed
clean between runs.

| # | mutant | what it tests | result |
|---|---|---|---|
| M1 | conpot check `port 16100 -> 161` (+ its title) | does the check DRIVE the named lab | **RED** `[dead] conpot`, `REGRESSION`, `ok=False` |
| M2a | batching check url `dvga:5013 -> domsource:8080` | does the check drive the named lab | **RED** `[dead]`, `regressions=['graphql_batching_enabled']` |
| M2b | batching check: `"title": "batching"` removed | is the title pin load-bearing | **FALSE PASS** -- see below |
| M3 | `evaluate()` grouping reverted to the pre-Q-164 one-liner, M1 still applied | is my `evaluate` fix load-bearing | **RED** in table order, **GREEN** when the entries are swapped -- see below |

**M1** is the one the ticket asks for. Pointed at the port the badge implied for the life of the
file, the check goes DEAD and the gate goes red. The badge cannot be re-earned by accident.

**M2b is the sharpest result, and it is not about my code.** With the title removed the check
reported:

    verdict: confirmed
    the finding it accepted as proof of BATCHING: GraphQL introspection enabled

A false pass: the check would report an engine live while that engine emitted nothing, because
introspection and batching share `family: "graphql"` and both come back from one call. That is why
the entry is pinned by title.

But the guard that is supposed to prevent this PASSED on M2b (`pytest -k family` -> 4 passed).
`test_checks_sharing_a_family_must_disambiguate_by_title` asserts `len(untitled) <= 1`, so it
permits exactly ONE untitled check per family -- and when a family has two or more checks sharing a
tool and input, that one untitled check is precisely the one any sibling's finding can satisfy.
The guard's own docstring says "if two checks share a family and NEITHER names a title"; the
measured failure needs only ONE to be untitled. A guard scoped to the case its author pictured.
Diff below; `test_liveness.py` is not in this lane's write set.

**M3 is the negative control for FINDING 0**, and it needed two runs because the defect is
order-dependent by nature. With the pre-Q-164 `evaluate` restored and M1's dead conpot check in
place:

    conpot check AFTER snmpd  (committed order)  ->  ok=False   the dead engine is caught by luck
    conpot check BEFORE snpd  (a plausible paste) ->  ok=True, dead=[]   A DEAD ENGINE, REPORTED GREEN

Then the same mutant and the same masking order with my grouping fix restored:

    conpot check BEFORE snmpd, fix intact -> ok=False, dead=['snmp_default_community']

Identical inputs, identical order, opposite verdicts. The fix is what catches it, and without it
this ticket would have shipped a gate that reports green on an engine it measured dead.

## Count: EARNED is 26, against the audit's 25

MEASURED through the audit's own predicate, `test_technique_badges.liveness_pairs()`:

    EARNED (a CHECK drives the named lab AND the committed baseline confirms it): 26
      snmp_default_community@conpot in EARNED: True
      graphql_batching_enabled@dvga  in EARNED: False
    claimed badge pairs: 51      DEBT size: 24      unbacked == DEBT: True

+1, and only +1, which is the honest number. `snmp_default_community`/`conpot` is genuinely
re-earned: a real check drives conpot:16100 and the committed baseline already records the
technique confirmed.

`graphql_batching_enabled`/`dvga` is NOT counted, deliberately. Its check exists and confirms live
(the runner reports it `newly live`), but `agent/tests/liveness_baseline.json` does not yet list the
technique, and that file is outside this lane's write set. `liveness_pairs()` requires BOTH halves
on purpose -- a check alone proves only that somebody wrote a check. It becomes the 27th the moment
anyone runs `scripts/liveness.sh --update`; claiming it now would be the same declaration-as-fact
error the ticket exists to remove.

### Slice 4 -- LANDED (a4aaad4). `test_validated_on.py`: a mention was counted as a run

Diff 3 from the audit, which it could not apply because it did not own the file.

`test_every_validated_on_claim_is_backed_by_a_recorded_artifact` grew its `backed` set by SCANNING
this directory's source text: any technique id on any line of any test file that also contained the
string `validated_on`, plus any id inside a `for` loop whose AST dump contained it. It therefore
credited the very line slice 1 deleted as evidence for `exposed_credentials`.

`backed` is now DERIVED from the two artifacts -- a liveness `CHECK` whose technique the committed
baseline records as confirmed -- and both halves are required.

MEASURED before changing it, because "the scan is worthless" was a hypothesis and it turned out to
be nearly, but not exactly, true:

    claims 49 | backed 24 | unbacked WITH the scan 24 | unbacked WITHOUT it 25
    scan credited 17 ids; only 4 were not already liveness-confirmed
      (graphql_batching_enabled, graphql_field_suggestions, reflected_xss, ssrf)
    of those 4, only ONE carries a badge at all
    the entire difference the scan made: ['graphql_batching_enabled']

So the whole text scan was buying exactly one technique, and buying it with the defect: that id's
scanned backing was a membership assertion in `test_local_import_guard.py`. The gap moves 24 -> 25,
UP, so the strict xfail cannot XPASS -- confirmed in the run, both xfails still xfail. The stale
reason string ("30 of 48", written before Q-164 withdrew 8 pairs) is re-measured to 25 of 49.

Two controls added, both in the write set:

| # | mutant | result |
|---|---|---|
| M4 | `_backed_by_something_that_runs` drops the baseline half (a CHECK alone backs a claim) | **RED**: `graphql_batching_enabled has a check but no baseline row, and was counted anyway` |

`test_a_mention_is_not_a_run` reconstructs the retired rule and drives it against a line of the
exact shape it accepted, so what a source-text scan buys stays an executable fact rather than a
comment in a handoff.

## A mistake I made, recorded because the recovery is the useful part

I ran mutant M4 against slice 4 BEFORE committing slice 4, then reverted it with
`git checkout apolaki/agent/tests/test_validated_on.py`. That discards the whole file, not the
mutant, so it took my uncommitted work with it and I had to re-apply the slice from scratch.

The house rule "land each green slice as its own commit" is not only about surviving a kill: an
uncommitted slice has no clean state to revert a mutant TO, so mutation testing and uncommitted work
cannot safely share a file. Commit first, then mutate, then `git checkout` -- which is what slices 1
and 3 did, and why their mutants cost nothing. The re-applied slice 4 was re-verified green and
committed before anything else touched it.

## Final state

    $ docker run --rm --network apolaki_default -v ".../apolaki/agent:/app" -w /app \
        apolaki-agent python -m pytest tests/ -p no:cacheprovider -q -p no:warnings -rs \
        -k "liveness or validated_on or authscan or technique or badge"
    ........................................................................ [ 46%]
    ........................................................................ [ 92%]
    ..x..x.....                                                              [100%]

155 passed, 2 xfailed, ZERO skipped (up from 153/2/0 -- the two new controls). Both strict xfails
still xfail, so nothing was laundered into an XPASS. Scoped with `-k` on purpose: other lanes are
editing `agent.py`, `planner.py`, `tools.py` and `semantic_differential.py` in this same tree, and
an unscoped run goes red on a torn read that is not this lane's.

## Patches for files this lane does not own

Each is measured, not proposed. In priority order.

### 1. `agent/liveness_run.py` + `agent/liveness.py` -- the third re-earn

One line unblocks it. `_LAB_ADDR`:

    +    # Q-164: sqli_auth_bypass's lab. The badge spells `juiceshop`; the container is `juice-shop`
    +    # on 3000, so without this the check resolves juiceshop:80 and SKIPS on every run forever.
    +    "juiceshop": ("juice-shop", 3000),

Then in `agent/liveness.py:CHECKS` (this lane will land it on request, once the line above exists):

    {"technique": "sqli_auth_bypass", "lab": "juiceshop", "kind": "tool",
     "tool": "_run_auth_sqli",
     "input": {"url": "http://juice-shop:3000/rest/user/login",
               "fields": ["email", "password"]},
     "family": "auth_bypass"},

MEASURED through the real dispatch, so it can be applied rather than trusted:

    confirmed  family=auth_bypass  cwe=CWE-89  "SQL injection (auth-bypass) in 'email'"
    evidence: POST http://juice-shop:3000/rest/user/login  email="' OR 1=1--"
              ->  session/JWT token issued for an invalid credential

### 2. `agent/tests/test_liveness.py` -- the table guard permits the case it exists to stop

`test_checks_sharing_a_family_must_disambiguate_by_title` asserts `len(untitled) <= 1`. MEASURED
(mutant M2b): with a family of two checks sharing a tool and input, the ONE untitled check the guard
permits is satisfied by its sibling's finding -- the batching check reported `confirmed` on the
introspection finding, and this guard passed.

    -            untitled = [c["technique"] for c in checks if not c.get("title")]
    -            assert len(untitled) <= 1, (
    +            # Q-164: `<= 1` was unsound. With two checks in a family the single permitted
    +            # untitled one is provable by the other's finding -- MEASURED, the untitled batching
    +            # check accepted "GraphQL introspection enabled" as its proof while this guard passed.
    +            untitled = [c["technique"] for c in checks if not c.get("title")]
    +            assert not untitled, (

Verified non-breaking against the table as committed: every multi-check family (`ics_ot`,
`graphql`, `snmp_default_community`) now titles all of its members.

### 3. `agent/techniques.py` + `agent/tests/test_technique_badges.py` -- finish the withdrawal

Slice 1 removed the blocker. The other half is still owed:

    exposed_credentials:  validated_on=["ginandjuice"]  ->  []
    and delete ("exposed_credentials", "ginandjuice") from DEBT in test_technique_badges.py

Both must land in the SAME commit: `DEBT` is asserted exactly in both directions, so withdrawing the
badge alone turns the gate red with "1 debt entr(ies) are no longer unbacked".

### 4. `agent/tests/liveness_baseline.json` -- bank the new confirmation

`scripts/liveness.sh --update`. `graphql_batching_enabled` is reported `newly live` and becomes the
27th EARNED pair. Note `scripts/liveness.sh` brings up only clientauthz, domsource, conpot, dvga,
openldap, smb and snmpd -- juice-shop, vampi, dvwa, dnp3-outstation and owaspbench must already be
running or their checks SKIP, and a skip banks nothing.

### 5. `agent/techniques.py` -- `session_lifecycle`, the day the lab lands

Apply nothing until `labs/sessionlife/` and the compose service are committed. At that moment the
badge is re-earnable and this entry is measured and ready:

    {"technique": "session_lifecycle", "lab": "sessionlife", "kind": "tool",
     "tool": "_run_session_lifecycle",
     "input": {"url": "http://sessionlife:8080/vuln/"},
     "family": "session_lifecycle", "cwe": "CWE-613",
     "title": "not invalidated on logout"},

plus `_LAB_ADDR`: `"sessionlife": ("sessionlife", 8080)`. The paired secure mounts
(`/secure`, `/expire-secure`) both return ZERO findings, measured above, so the negative control the
liveness table would want already exists in the lab. If the lab is abandoned instead, the badge must
be withdrawn and the `DEBT` entry deleted in the same commit.
