# Q-067 - a NEGATIVE RESULT is recorded as a tool FAILURE

Lane: ledger-status (Builder). Owns `agent/main.py`, new tests under `agent/tests/`, this file.
Does NOT own `agent/tools.py`, `agent/agent.py`, `agent/report.py`, `agent/upload_tool.py` - patches for
those are written out here, not applied.

Every row below is MEASURED (command + real output) or UNVERIFIED. Nothing is marked done ahead of
its evidence.

---

## STATUS

| slice | what | state |
| --- | --- | --- |
| 1 | measure the live ledger rows behind Q-067 | **MEASURED** (section 1) |
| 2 | measure whether the fault/verdict distinction survives to the producer | **MEASURED** (section 2) |
| 3 | consumer-side mechanism in `main._tool_ledger` + tests | in progress |
| 4 | engine-side patch for `agent/tools.py` (not mine to apply) | in progress |
| 5 | anti-idle audit of the rest of the status derivation | in progress |

---

## 1. The ticket is right about the defect and WRONG about the numbers

Q-067 says `fetch_openapi` shows `status=failed, calls=10, findings=0` because the engine "probed 10
candidate paths on Juice Shop and correctly established that none serves an OpenAPI spec". The row is
real. **The claim that all 10 are negative results is not.** Read out of the live mission DB:

```
$ docker exec -i apolaki-agent-1 python - <<'PY'
import db, json
from collections import Counter
db.init()
rows = db.get_logs('57cc3b49', limit=4000)
fo = [r for r in rows if r.get("tool") == "fetch_openapi"]
...
PY

fetch_openapi rows: 20
Counter({'tool_call': 10, 'tool_error': 10})

=== 10 dispatch URLs ===
   https://juice-shop:3000/openapi.json
   https://juice-shop:3000/swagger.json
   https://juice-shop:3000/v3/api-docs
   https://juice-shop:3000/api-docs
   https://juice-shop:3000/swagger/v1/swagger.json
   http://juice-shop:3000/openapi.json
   http://juice-shop:3000/swagger.json
   http://juice-shop:3000/v3/api-docs
   http://juice-shop:3000/api-docs
   http://juice-shop:3000/swagger/v1/swagger.json

=== error histogram ===
   5  [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)
   5  Response is not valid JSON (not an OpenAPI spec)
```

So the true split is **5 genuine transport faults + 5 negative results**, not 10 negative results:
the five `https://` dispatches spoke TLS at a plaintext port and **never reached the target at all**.
The ledger shows only one error string because `_tool_ledger` keeps the last one written
(`a["error"] = str(...)[:140]`, last write wins), and the five http:// probes were dispatched after
the five https:// ones.

Two consequences, both of which change the work:

* **A blanket "this row is a negative result, mark it executed" would be wrong on 5 of its 10 calls.**
  It would bury five real transport faults - exactly the invisible-false-negative class Q-063 created
  the `errored` class to expose. The correct row is a MIXED one that shows both.
* The row also hides a second, separate defect: **the producer keeps one error string per tool and no
  error count**, so a tool that failed five different ways reports the fifth. Recorded in section 5.

The `_provenance` note on `agent/tests/tool_ledger_57cc3b49.json` is accurate - that fixture is
verbatim producer output. Its `fetch_openapi` note is the LAST of ten errors, which is why reading
the fixture alone makes the row look like 10 of 10 negatives.

---

## 2. Is the fault/verdict distinction present in what the engine returns? MEASURED: NO

The lane brief asks for a structural signal rather than a regex over error prose, and asks me to say
plainly if the information is not there. It is not there. Driving the REAL engine against the REAL
lab, the exact two URLs the mission dispatched:

```
$ docker run --rm --network apolaki_default -v ".../apolaki/agent:/app" -v "<scratch>:/sp" \
    -w /app apolaki-agent python /sp/probe_openapi.py

URL      : http://juice-shop:3000/api-docs
  fields : {'tool': 'fetch_openapi', 'target': 'http://juice-shop:3000/api-docs', 'success': False,
            'output': '', 'findings': [], 'error': 'Response is not valid JSON (not an OpenAPI spec)'}

URL      : https://juice-shop:3000/api-docs
  fields : {'tool': 'fetch_openapi', 'target': 'https://juice-shop:3000/api-docs', 'success': False,
            'output': '', 'findings': [], 'error': '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)'}
```

**The verdict and the fault are byte-identical in every field of `ToolResult` except the prose of
`error`:** same `success=False`, same empty `output`, same empty `findings`. The persisted rows carry
even less - `{type, tool, error, ts}` (measured: the full key set on all 20 rows is
`['error', 'input', 'permission', 'tool', 'ts', 'type']`). So **no producer-only fix can separate
these two without reading English**, which is the Q-056 rule-C shape this project already measured at
5 false positives in 6 and rejected.

### The positive control that proves the apparatus was looking, and hands us the fix

The same run, on a URL that returns valid JSON which simply is not a spec:

```
URL      : http://juice-shop:3000/rest/products/search?q=
  fields : {'tool': 'fetch_openapi', 'target': '...', 'success': True,
            'output': '0 endpoints imported', 'findings': [], 'error': None}
```

**The engine ALREADY HAS a "ran, reached the target, found no spec" channel and already uses it** -
`success=True` with an output note - for the JSON-but-no-endpoints case. The not-JSON case is the
same class of answer mispacked into the error channel. This is a one-site inconsistency inside
`_fetch_openapi`, not a missing concept.
