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

Status: implementation and targeted verification complete; commit pending.

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

Status: in progress.

Measured candidate set at baseline: eight engines. Every candidate will receive an execution-proven
verdict; no name will be bulk-added to the store set or forwarding allowlist.

## Final verification

Status: pending.
