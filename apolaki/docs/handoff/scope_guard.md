# scope-guard lane -- Q-018 (retest scope guard fails OPEN) and Q-017 (raw vs gated `get_findings`)

Cycle 12. WRITE set: `agent/main.py`, `agent/tests/test_retest_scope_guard.py` (new),
this file. Everything else is a hand-off patch, not an edit.

Every row below is MEASURED (command + real output) or UNVERIFIED. Nothing is a DONE marker
ahead of its evidence.

---

## Q-018 -- the fail-open, REPRODUCED LIVE before any change

Apparatus: the REAL `POST /retest/{sid}` handler driven through `fastapi.testclient.TestClient`
against a temp DB, with `httpx.AsyncClient.get` wrapped by a counter so every outbound request the
handler makes is recorded. Both hosts are local authorized docker labs on `apolaki_default`
(`juice-shop`, `dvwa`); "off scope" below means off THIS MISSION's scope, never unauthorized.

Command:

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v ".../apolaki/agent:/app" -v "<scratch>:/scratch" -w /app apolaki-agent \
  python /scratch/repro_q018.py
```

Both missions hold the SAME finding -- `{"family": "exposure", "target": "http://dvwa/robots.txt"}`,
seeded under a permissive scope and then re-scoped -- so the only variable is the scope shape.

```
O0 load_manual([dict]) : raises AttributeError: 'dict' object has no attribute 'strip'

[wf] scope bases=['http://juice-shop:3000']          <- POSITIVE CONTROL
  outbound requests  : []
  verdict            : inconclusive
  detail             : target out of mission scope
  log rows (etype)   : []

[mf] scope bases=[{'nested': 'dict'}]                <- THE DEFECT
  outbound requests  : ['http://dvwa/robots.txt']
  verdict            : open
  detail             : resource still served (HTTP 200, 26 bytes)
  log rows (etype)   : []
```

Three separate facts, each measured:

1. **The guard is skipped, and the skip has a live consequence.** With a malformed `bases`,
   `load_manual` raises, `main.py:2998` sets `_eng = None`, and the `if _eng is not None` test at
   `main.py:3007` is dead. A host the mission was NOT scoped to was actually requested.
2. **The positive control proves the apparatus was looking.** The identical finding under a
   well-formed `bases` produced ZERO outbound requests and the refusal string. So `[]` in the
   well-formed row is a guard firing, not an inert probe.
3. **The failure is INVISIBLE.** `log rows (etype)` is `[]` in BOTH runs. Today a refused retest and
   an unguarded retest leave byte-identical evidence in the mission log: none. This is the third
   clause of the DoD and it is a defect in its own right.

### Reachability -- this is not a synthetic scope shape

`findings_gate.off_scope` (`agent/findings_gate.py:94-104`) rebuilds a `ScopeEngine` from the SAME
`scope["bases"]` and has the SAME `except Exception: return False` fail-open. MEASURED, same run:

```
off_scope(http://dvwa/robots.txt, bases=['http://juice-shop:3000']) : True   (blocked)
off_scope(http://dvwa/robots.txt, bases=[{'nested':'dict'}])        : False  (ADMITTED)
```

So one malformed `bases` disables the write-time scope gate AND the retest-time scope guard. The
off-scope finding can be persisted through the product's own write path and then retested. Q-018 was
filed LOW on the assumption the malformed shape had to arrive by hand; the composition is what makes
it reachable end to end.

`agent/findings_gate.py` is NOT in this lane's write set. Hand-off patch is at the bottom of this
file; it is deliberately NOT applied here.

---

## Status

| item | state |
|---|---|
| Q-018 fail-open reproduced live | MEASURED (above) |
| Q-018 fail-closed fix | in progress |
| Q-018 negative control (well-formed scope still retests) | in progress |
| Q-018 visibility (refusal readable in the log) | in progress |
| Q-017 raw-vs-gated call-site census | in progress |
