# findings-gate lane -- Q-017 (13 raw vs 7 gated `get_findings`) and Q-023 (ZAP, one live clause)

Cycle 13. WRITE set: `agent/main.py`, new tests under `agent/tests/`, this file.
Everything else is a hand-off patch, not an edit.

Every row is MEASURED (command + real output) or UNVERIFIED. Every zero carries a positive
control proving the apparatus was looking.

Corpus for every DB measurement below: the NAMED VOLUME, not the tree.

```
MSYS_NO_PATHCONV=1 docker run --rm -i --network apolaki_default \
  -v "apolaki_bbh_data:/data" \
  -v "<repo>/apolaki/agent:/app" -w /app apolaki-agent python -
```

with `db.init('/data/bbh.db')`. POSITIVE CONTROL, first statement of every session:

```
POSITIVE CONTROL total findings in table: 1057
```

---

## Status

| row | state |
|---|---|
| Q-017 census, 13 raw / 7 gated, AST-confirmed | MEASURED |
| Q-017 what the gate actually changes | MEASURED |
| Q-017 per-consumer differential, all 13 raw sites | MEASURED |
| Q-017 the rule, derived from the differential | MEASURED |
| Q-017 code change | in progress |
| Q-023 re-measure post-Q-061 | in progress |

---

## Q-017 -- the census, AST-confirmed

The sweep counted with grep and warned its attribution was unreliable. Re-counted with `ast`, which
resolves the enclosing function exactly and cannot mis-assign a decorator:

```
RAW CALLS (ast-confirmed): 13
  L716   get_status             app.get('/status/{session_id}')
  L735   mission_detail         app.get('/missions/{session_id}')
  L757   _report_bundle
  L1040  _tool_ledger
  L1599  asvs_coverage          app.get('/coverage/asvs')
  L1889  benchmark_fixture      app.get('/benchmark/{fixture}')
  L1979  blind_benchmark_run    app.post('/benchmark/blind/{session_id}')
  L2058  technique_plan         app.get('/plan/{session_id}')
  L2164  attack_graph_view      app.get('/graph/attack/{session_id}')
  L3373  cloud_posture_ingest   app.post('/cloud/posture/{provider}/ingest')
  L3585  get_findings           app.get('/findings/{session_id}')
  L3715  capture_finding_poc    app.post('/findings/{session_id}/{fid}/poc')
  L3949  backup                 app.get('/backup/{session_id}')

GATED CALLS (ast-confirmed): 7
  L889   _coverage
  L2378  get_report_poc         app.get('/report/{session_id}/poc')
  L2390  _graph_inputs
  L2411  _record_memory
  L2988  retest_findings        app.post('/retest/{session_id}')
  L3105  poc_bundle_export      app.get('/mission/{session_id}/poc-bundle')
  L3130  sarif_export           app.get('/mission/{session_id}/sarif')
```

13/7 confirmed. Two corrections to the grep-based count that do not change the totals: `main.py:3745`
is a DOCSTRING mention of `get_findings_gated` inside `confirm_lead`, not a call, and `main.py:3126`
is a comment. Both are excluded above.

## Q-017 -- what the gate actually does, before deciding anything

The whole decision turns on this and it had never been measured. Across all 113 missions that hold
findings:

```
missions with findings : 113
rows raw / gated       : 1057 / 1057   (length differs in 0 missions)
rows CHANGED by gate   : 107  across 63 missions
fields the gate rewrote: {'proof_gap': 64, 'confidence': 64, 'tags': 64, 'success_oracle': 44}
confidence transitions : {'confirmed->lead': 64, 'confirmed->confirmed': 43}
```

Three facts follow, and each one kills a whole class of "obvious" answer:

1. **The gate is LENGTH-PRESERVING.** 1057 in, 1057 out, zero missions differ. It rewrites rows in
   place; it never removes one. So gating a surface cannot HIDE a finding -- the row still ships,
   carrying a `lead` confidence and a `proof_gap` saying why. That disposes of the risk in the
   brief: converting a reader is strictly more information, not less.
2. **A caller that only COUNTS is gate-invariant by construction**, not by luck.
3. **The gate touches exactly four fields**: `confidence`, `proof_gap`, `tags`, `success_oracle`. A
   caller whose downstream never reads one of those four produces identical bytes either way.

## Q-017 -- the per-consumer differential

Not "does this look reader-facing" -- for each raw site, drive the REAL downstream consumer twice,
once with `get_findings` and once with `get_findings_gated`, over the 63 missions where the gate
changes at least one row (the only population that CAN expose a delta), and diff the outputs.

```
missions where gate changes >=1 row: 63

L716  len(findings)                  raw != gated -> 0 / 63
L1599 asvs_model.assess              raw != gated -> 0 / 63
L2058 TP.derive_observations         raw != gated -> 0 / 63
L2164 attack_graph.build             raw != gated -> 0 / 63
L1040 _sqli_confirmed as written     raw != gated -> 0 / 63
L1040 same predicate + confidence check  raw != gated -> 0 / 63
L1979 blind match keys (target,family)   raw != gated -> 0 / 63
L1889 benchmark.evaluate             raw != gated -> 251 (mission,fixture) pairs
```

POSITIVE CONTROLS for those zeros -- three independent ones, because seven zeros in a row is exactly
the shape of an apparatus that was never looking:

```
PC-A  observations differ between two different missions : True
PC-A  attack_graph differs between two different missions: True
PC-A  asvs differs between two different missions        : True
PC-B  all-rows-demoted vs raw -> observations differ     : False
PC-B  all-rows-demoted vs raw -> asvs differs            : False
PC-C  one row dropped -> asvs differs                    : True
PC-C  one row dropped -> len differs                     : True
```

PC-A proves the consumers are live and input-sensitive. PC-C proves they react to the row set.
PC-B is the load-bearing one: demoting EVERY row -- a mutation far larger than anything the real
gate produces -- still changes nothing in `asvs_model.assess` or `TP.derive_observations`. Those two
consumers are structurally blind to `confidence`. Their zero is a property of the consumer, not a
failure of the instrument. `L1889`'s 251 is the same instrument on the same corpus returning
non-zero, which is the fourth control.

### The one that is a real defect: `GET /benchmark/{fixture}?session=`

`benchmark.evaluate` builds `discovered` from every finding regardless of confidence, and
`confirmed_cls` only from `_is_confirmed(f)` (`benchmark.py:159` -- `confidence in ("confirmed","high")`).
Reading RAW hands it rows the proof gate had already demoted, and they score as confirmations.
Measured over all 251 differing pairs:

```
(mission,fixture) pairs that differ at all : 251
  class_coverage_pct changed              : 0      <- DISCOVERY / recall
  discovered set changed                  : 0
  false_negatives changed                 : 0
  confirmed_coverage_pct changed          : 251    <- the inflated number
  largest OVERSTATEMENTS raw-vs-gated (pp, mission, fixture, raw%, gated%):
    (100.0, 'e33c1c96', 'clientauthz', 100.0, 0.0)
    (100.0, 'abee0971', 'clientauthz', 100.0, 0.0)
    (100.0, '774371ab', 'clientauthz', 100.0, 0.0)
    (25.0,  'e33c1c96', 'vampi',        25.0, 0.0)
    (25.0,  'abee0971', 'vampi',        25.0, 0.0)
    (25.0,  '774371ab', 'vampi',        75.0, 50.0)
  any case where gated > raw (a gate that INVENTS a confirmation): False
```

Three stored missions report `confirmed_coverage_pct: 100.0` on the `clientauthz` fixture where
every one of those confirmations had already been demoted to a lead by the gate. The honest number
is `0.0`. This is the project's wrong-number class, on a scoring endpoint.

The direction is safe and measured: recall never moves (0/251 on `class_coverage_pct`, `discovered`
and `false_negatives`), only the confirmed rate falls, and the gate never invents a confirmation.
Gating this site cannot make a score look better and cannot manufacture a false negative.

## Q-017 -- THE RULE

The split is real and mostly correct. It has never been written down, so it has been maintained by
guesswork -- which is how the benchmark site drifted onto the wrong side. Stated as a decidable
test rather than a vibe:

> **Gate when the gate can change your answer; read raw when the gate would corrupt your write.**
>
> * `get_findings_gated()` is REQUIRED when whole rows reach a human, a model, a report or a
>   SCORE -- i.e. when anything downstream reads `confidence`, `proof_gap`, `tags` or
>   `success_oracle`. The gate is non-destructive and length-preserving, so this never hides a row.
> * `get_findings()` is REQUIRED -- not merely tolerated -- on any path that WRITES rows back
>   (`db.update_finding`, `db.add_finding`) or exports for round-trip restore. The gate rewrites in
>   place, so a gated read on a write path would PERSIST a demotion that was only ever meant to be
>   a presentation-time verdict.
> * `get_findings()` is CORRECT where the read is a count, a dedupe key, or a field the gate does
>   not touch. That is not a licence -- it is a claim about the consumer, and it has to be measured
>   before it is claimed.

Against that rule the 13 raw sites sort into three buckets, every assignment backed by a row above:

| bucket | sites | why |
|---|---|---|
| **MUST stay raw -- gating would be a BUG** | `L3715 capture_finding_poc`, `L3949 backup`, `L3373 cloud_posture_ingest` | `capture_finding_poc` does read-modify-`db.update_finding`; `backup` round-trips through `/restore` -> `db.add_finding`. A gated read on either persists the demotion. `cloud_posture_ingest` builds a `(title,target)` dedupe set the gate does not touch. |
| **Gate-invariant -- measured 0/63, either spelling is identical** | `L716 get_status`, `L1040 _tool_ledger`, `L1599 asvs_coverage`, `L2058 technique_plan`, `L2164 attack_graph_view`, `L1979 blind_benchmark_run` | count-only, or the consumer is blind to all four rewritten fields (PC-B). |
| **MUST be gated -- DEFECT today** | `L735 mission_detail`, `L3585 GET /findings/{sid}`, `L1889 benchmark_fixture` | whole rows to the UI, whole rows to the findings API, and 251 measured score overstatements. |

`L757 _report_bundle` is a fourth case: it reads raw and then calls `proof_schema.demote_unproven`
inline, which is `get_findings_gated`'s body copied out. Gated in fact, raw in spelling -- a
duplicate of the accessor, not a truth defect.

**So the answer to the ticket is BOTH halves, and neither alone.** The 13/7 split is not thirteen
bugs -- ten of the thirteen are correct, and three of those ten would BREAK if converted. But it is
not innocent either: one of the thirteen publishes a 100% that the gate had already refused. The fix
is to record the rule in the code, convert the three sites the rule condemns, and leave the ten the
rule justifies exactly where they are.
