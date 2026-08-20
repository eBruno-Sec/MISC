# Codex Q-085 zero / auto-store triage handoff

Branch: `codex/q087`

## Baseline and coordination

- The requested baseline was `e9e253a`. By worktree creation, `main` was at `4bdc27b`; the two
  intervening commits were integration/Coordinator records, and `e9e253a` and its actual merge
  `448403d` have the same tree. Work proceeded from current `main` as instructed.
- The immutable baseline archive had agent-tree SHA-1
  `5815d69780600fa32738b25037d04bb28ce207ce`.
- Baseline command used an isolated archive and `--network apolaki_default`; it completed in
  714.92 seconds:

```text
3350 passed, 11 skipped, 14 xfailed, 9 warnings in 714.92s (0:11:54)
```

## Part 1 - Q-085 to zero

Status: committed as `0f0d2b7bf248e0ed90a03e90390bcb8d48efa0a6`; full-suite verification passed.

### Fail before fix

The two new controls were written before production wiring. The first run failed semantically on
the exact eight leased transports while the credential replay control passed:

```text
F.
1 failed, 1 passed in 6.62s

agent.py:2883:_probe_for_creds:httpx.AsyncClient
auth.py:167:login:httpx.AsyncClient
authz.py:165:run_matrix:httpx.Client
bwapp_solvers.py:38:prove:httpx.Client
codeintel.py:150:harvest:httpx.Client
mutillidae_solvers.py:41:prove:httpx.Client
register.py:196:register:httpx.AsyncClient
replay.py:28:client:httpx.AsyncClient
```

### Production wiring and measured ratchet

All eight client factories now use the existing shared process-wide rate-policy chokepoints:

- async: `agent._probe_for_creds`, `auth.login`, `register.register`, `replay.client`;
- sync: `authz.run_matrix`, `bwapp_solvers.prove`, `codeintel.harvest`,
  `mutillidae_solvers.prove`.

The policy waits after a credentialed 429 but never replays the credential submission. A synthetic
POST/GET sequence observed exactly `POST /login` at t=0 and `GET /account` at t=2, with the POST body
sent once.

Measured repository-wide rate-policy census:

```text
before  8 ungated calls / 8 modules
after   0 ungated calls / 0 modules
```

The old strict xfail then failed by XPASS exactly as designed:

```text
..F.............................. [100%]
[XPASS(strict)] Q-085 LIVE GAP: 8 ungated target calls remain across 8 modules outside this lease
1 failed, 32 passed in 21.85s
```

The marker was retired in the same production slice and the ratchet was tightened to exact `0/0`.
Current rate-policy output:

```text
33 passed in 21.58s
```

Related auth/authz/solver/code-intelligence controls:

```text
86 passed in 35.79s
```

### Semantic mutation

The `replay.client` factory was changed back from the shared helper to raw `httpx.AsyncClient`.
The exact repository-wide assertion failed with the newly visible bypass, then the mutant was
reverted:

```text
FAILED tests/test_rate_policy.py::test_every_target_transport_uses_the_shared_rate_policy
Left contains one more item: 'replay.py:29:client:httpx.AsyncClient'
1 failed in 4.59s
```

No crash, import error, timeout, skip, or unrelated assertion was credited as a killed mutant.

## Part 2 - auto-store triage

Status: committed as `52faf38dab43606289055ee32ad9dd927c3c2ddf`, with the graph-dispatch
correction in `6979014b4c8018b42e66fd9b272b12c5819d2166`; full-suite verification passed.

Measured candidate set at baseline: eight engines, not the stale seven named by the strict-xfail
reason. The missing eighth was `run_whatweb`, newly deterministic after Q-050:

```text
confirm_create_object_idor  appends=1   INTRUSIVE
confirm_read_object_idor    appends=2   ACTIVE
run_fingerprint             appends=1   ACTIVE
run_github_recon            appends=1   PASSIVE
run_header_trust            appends=2   ACTIVE
run_saml                    appends=1   PASSIVE
run_service_pack            appends=15  ACTIVE
run_whatweb                  appends=1   ACTIVE
```

### Fail before fix

Execution controls were added before either set changed. The five parent-forwarding verdicts passed;
the three direct dispatches failed on the exact false-clean:

```text
x...FFF.... [100%]
run_fingerprint executed but its finding was dropped
run_github_recon executed but its finding was dropped
run_whatweb executed but its finding was dropped
3 failed, 7 passed, 1 xfailed in 3.75s
```

### Per-engine verdicts

No engine was bulk-added. Each verdict was observed through the production owner:

| engine | verdict | execution-proven owner |
|---|---|---|
| `confirm_create_object_idor` | parent-forwarded | `BBHAgent._do_persona_authz` |
| `confirm_read_object_idor` | parent-forwarded | `BBHAgent._do_persona_authz` |
| `run_header_trust` | parent-forwarded | `BBHAgent._do_header_trust` |
| `run_saml` | parent-forwarded | `BBHAgent._do_saml` |
| `run_service_pack` | both: parent-forwarded internally and auto-stored when graph-dispatched | `BBHAgent._run_service_packs`; `_graph_action_step` -> `_run_tool` |
| `run_fingerprint` | live false-clean; auto-store | direct `_run_tool` dispatch |
| `run_github_recon` | live false-clean; auto-store | direct `_run_tool` dispatch |
| `run_whatweb` | live false-clean; auto-store | direct `_run_tool` dispatch |

The parent controls execute the real owner method, inject a distinct child finding, and require that
exact object in both the emitted event and `agent.findings`. The direct controls execute `_run_tool`
and require the candidate to reach both a `lead` event and `agent.leads`.

An additional call-path audit caught a dual-route case before handoff: `run_service_pack` is forwarded
when `_run_service_packs` calls it internally, but `AssetGraph.next_best_actions` can also emit it and
`_graph_action_step` dispatches that route through `_run_tool`. Parent forwarding does not protect the
graph route. Adding the direct execution control before changing production failed semantically:

```text
FAILED test_directly_dispatched_finding_producers_reach_the_store_path[run_service_pack]
run_service_pack executed but its finding was dropped
1 failed in 3.71s
```

It is therefore in `_AUTO_STORE_TOOLS`, not the forwarding exemption list; the parent execution test
remains to protect the internal route.

The stale strict-xfail reason was corrected while measuring all eight, then superseded by retiring
the marker when the gate passed. Targeted result:

```text
12 passed in 3.96s
```

Combined storage/dispatcher and owner-path controls (before the additional direct service-pack case):

```text
368 passed, 3 warnings in 120.52s (0:02:00)
```

### Semantic mutations

Both mutants failed the exact intended assertion, then were reverted:

```text
M2 remove run_whatweb from _AUTO_STORE_TOOLS
   FAIL test_directly_dispatched_finding_producers_reach_the_store_path[run_whatweb]
   observed: run_whatweb executed but its finding was dropped

M3 delete the run_service_pack parent's finding event
   FAIL test_run_service_pack_findings_are_forwarded_by_run_service_packs
   observed: the exact child finding was absent from the parent's emitted events
```

No crash, import error, timeout, skip, or unrelated assertion was credited as a killed mutant.

## Final verification

Status: complete.

The final immutable snapshot used agent-tree SHA-1
`e37d0441a1b2c51109154a156ee18df19dc22fa8` from commit `6979014`.

### Targeted

```text
............................................. [100%]
45 passed in 22.69s
```

One earlier combined targeted run hit the existing 80 ms timing control at 56 ms versus its 60 ms
floor. The guard was not weakened or edited. Its exact isolated rerun passed (`1 passed in 3.02s`),
the combined rerun passed (`44 passed in 22.76s` before the final service-pack case), and the final
combined run above passed.

### Full isolated suite

```text
3362 passed, 11 skipped, 12 xfailed, 9 warnings in 709.98s (0:11:49)
```

Compared with the measured baseline, passing tests rose from 3350 to 3362, skips stayed at 11, and
xfails fell from 14 to 12 because both completed strict markers were deliberately retired. There
were zero failures.

### Queue integrity

```text
queue_gate: 77 headers, 52 distinct hashes cited, 6 ids with >1 header
queue_gate: OK
```

No benchmark application, case, label, scorer, denominator, `validated_on` value, Tier-3 baseline,
or Coordinator-owned queue/status file was changed. Benchmark suites were not rerun: this lane
changed transport policy coverage and result persistence, not detector/scorer output. Liveness and
bake/update commands were deliberately not run under this lease.

## Coordinator handoff

Suggested Q-085 queue/status text:

```text
Q-085 CLOSED: the repository-wide target-transport ratchet is 0 calls / 0 modules and its strict
xfail is retired. All eight residual client factories use the shared process policy; credentialed
requests wait after 429/503 but are never replayed. Auto-store triage also closed its strict xfail:
four direct dispatch paths now persist findings, while four child-only engines have execution-proven,
named parent owners. run_service_pack is dual-route and is protected on both paths.
```

Integration order:

```text
0f0d2b7bf248e0ed90a03e90390bcb8d48efa0a6
52faf38dab43606289055ee32ad9dd927c3c2ddf
6979014b4c8018b42e66fd9b272b12c5819d2166
```

The documentation-only verification commit follows those three. During final verification, `main`
advanced by `47d649d` in `service_router.py` comments and Coordinator queue text; it overlaps none of
this lane's files. This branch was intentionally left unrebased so the measured commit hashes above
remain the hashes the Coordinator cherry-picks.
