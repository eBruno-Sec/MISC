# Q-044 source-proof lane — does the code-assisted lane ever land a finding in the DB?

**Lane**: source-proof (Breaker, read-only on product code). **Started** 2026-08-18.
**Deliverable**: one yes/no — does a real mission with `source_root` set store a finding carrying
`provenance=source-derived` in the findings table? Mission id + the query that shows it.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**.

---

## 0. Apparatus — the DB is in a named volume, and the positive control proves it was looked at

The findings DB is NOT in the tree. `agent/db.py:21` → `DB_PATH = os.getenv("BBH_DB_PATH", "/app/data/bbh.db")`,
and `docker-compose.yml` mounts the named volume `bbh_data` at `/app/data`. A container that mounts only
`agent:/app` sees an empty `/app/data` and every count returns 0. All queries below run **inside the live
`apolaki-agent-1` container**, which has the real volume.

**MEASURED** — `docker exec apolaki-agent-1 python -c "...sqlite3('/app/data/bbh.db')..."`

```
tables: ['missions', 'findings', 'exchanges', 'logs', 'sqlite_sequence', 'notes', 'profiles', 'memory_assets', 'memory_snapshots']
findings: 1057
missions: 153
cols: ['id', 'mission_id', 'data', 'created_at']
```

**MEASURED** — marker distribution across every stored finding (the ticket's baseline, reproduced exactly):

```
POSITIVE CONTROL findings scanned: 1057  missions with findings: 113
provenance: {'None': 1057}
lane:       {'None': 1057}
analysis:   {'None': 1057}
```

The apparatus finds 1057 findings across 113 missions and reports **zero** carrying any of the three
canonical markers. The zero is a real zero, not an empty database.

---

## 1. The deployed container HAS the wiring (Q-059 check)

Q-059 warns the deployed platform lags the tree, so "the code is wired" in the tree proves nothing about
what a live mission runs. **MEASURED** — inside the running container:

```
$ docker exec apolaki-agent-1 sh -c "grep -n '_run_source_review\|source_root' /app/main.py"
106:    source_root: Optional[str] = None
369:def _source_review_state(source_root: Optional[str] = None) -> dict:
398:async def _run_source_review(session_id: str, source_root: Optional[str]) -> dict:
600:               "source_review": _source_review_state(req.source_root)}
613:    source_review = await _run_source_review(session_id, req.source_root)
```

The deployed image carries the wiring (line numbers run 7 lower than the tree's — an older but
functionally present revision). **A live mission CAN exercise this path.**

---

## 2. Where the call happens — this is why the proof is cheap

**MEASURED** — `main.py` deployed, line 613: `_run_source_review` is awaited at the **end of `/engage`**,
before `/run` is ever called. The source lane therefore runs at mission-creation time and does **not**
require the DAST scan to execute. A real, persisted mission created through the production `/engage`
endpoint exercises the whole path synchronously.

## 3. The path, read end to end (static, before running it)

| step | file:line | what must hold |
|---|---|---|
| producer | `codereview.py:594` `_source_finding` | stamps `provenance`/`lane`/`analysis` on EVERY finding, one shared builder for Java + Python + the dataflow rule |
| tree walk | `codeintel.py:304` `review_source_tree` | returns `{lane, provenance, findings:[...]}` |
| evidence contract | `main.py:392` `_canonical_source_finding` | fails closed: all three markers + `proof_schema.proof_kind() == SOURCE_DERIVED` |
| write chokepoint | `db.py:168` `add_finding` → `db.py:151` `_gate` | SCHEMA normalize, SCOPE `off_scope`, TRUTH `is_lead` |

Two boundary reads done before running, both **MEASURED by reading the code**:

* `findings_gate.off_scope` (`findings_gate.py:75`) returns `False` for any target that does not start
  `http://`/`https://`. A source finding's `target` is a relative file path, so it is admitted.
* `findings_gate.is_lead` (`findings_gate.py:32`) reroutes only lead-like `confidence`. `_source_finding`
  sets `confidence="confirmed"`, so it is not rerouted.

**HAZARD identified in advance (UNVERIFIED until the run):** `db.add_finding` returns a **truthy id**
from `add_lead` when the TRUTH invariant reroutes a finding. `_run_source_review` counts `stored` as
`sum(1 for f in findings if db.add_finding(...))`, so a rerouted finding would be counted as *stored*
while living in the mission's **leads list**, not the findings table. If the run reports
`stored_findings > 0` and the findings table still shows 0, this is the boundary.

---

## STATUS: measurement in progress. Next: run the mission.
