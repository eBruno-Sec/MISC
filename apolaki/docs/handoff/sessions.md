# Sessions lane — Q-032/033/034

Ticket: `session_headers` is a single global raw dict referenced at ~50 sites, so Apolaki cannot
hold two identities at once without them contaminating each other.

Status legend: MEASURED = command + real output in this file. UNVERIFIED = not yet proven.

---

## Slice 1 — the measurement (what the global actually costs)

### The count, MEASURED

```
$ grep -rn "session_headers" --include=*.py . | wc -l
83
$ grep -rn "session_headers" --include=*.py . | cut -d: -f1 | sort | uniq -c | sort -rn
     54 ./agent/tools.py
      6 ./agent/tests/test_bbh.py
      5 ./agent/main.py
      5 ./agent/agent.py
      4 ./agent/tests/test_tech_producer.py
      4 ./agent/tests/test_session_lifecycle.py
      1 ./agent/tests/test_sweep_class_coverage.py
      ... (4 more test files, 1 each)
```

"~50 sites" is CONFIRMED for `agent/tools.py` (54). Total across the codebase is 83, of which 19
are in tests and 10 in `main.py`/`agent.py`.

**But the site count is the wrong number.** Of the 54 sites in `tools.py`, 45 are the read-only
shape `{"User-Agent": _UA, **(self.session_headers or {})}` — a probe deliberately made AS THE
MISSION, with no caller identity involved. Those are correct today and need no change. The cost is
concentrated in **two transport choke points that merge the global into headers a caller supplied**:

| line | function | shape |
|---|---|---|
| 1613 | `_http_send` | `h = {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}` |
| 3279 | `_http` | `req_headers = {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}` |

### Mutation of the global mid-mission, MEASURED

```
$ grep -rn "session_headers\s*=" --include=*.py . | grep -v "==" | grep -v "session_headers: dict"
./agent/agent.py:1527:            self.tools.session_headers = {**sh, **sess}      <-- REBIND, mid-mission
./agent/main.py:554,567                                                            <-- construction
./agent/tools.py:1134:        self.session_headers = session_headers or {}         <-- construction
(remaining hits are test files)

$ grep -rn "session_headers\.\(update\|pop\|clear\|setdefault\)\|session_headers\[" --include=*.py .
./agent/main.py:563:            session_headers.update(res.get("headers", {}))     <-- pre-construction only
```

VERDICT: exactly **one** mid-mission write, `agent/agent.py:1527`, inside `_do_scan_auth`, gated on
`self.authenticated_scan and verified`. It is a REBIND, not an in-place mutation, so a reference
captured earlier is not retroactively changed. Every engine dispatched AFTER the auth artery runs
as a different identity than engines dispatched before it. That is by design and is announced in an
event, so it is not itself the defect — but it means the global is genuinely non-constant during a
mission, which is what makes the contamination below reachable in a real run.

### Contamination, MEASURED at the wire

Two shapes. Both are ORACLE defects, not tidiness defects.

**Shape 1 — the anonymous control row is not anonymous.** `_authz_matrix._headers_for`
(`tools.py:2018`) returns `{}` for rank 0 to mean "as nobody", then hands it to `_http_send`, which
merges the mission session straight back in.

**Shape 2 — cross-scheme bleed.** A Cookie-authenticated mission and a Bearer-authenticated persona
do not collide on a dict key, so BOTH ride the same request and the server chooses which identity
served it.

Proven by `agent/tests/test_session_identity.py`, which patches `tools._target_client` — i.e. BELOW
`_http_send`, so the merge under test still executes:

```
$ docker run --rm -v <HEAD-snapshot>/agent:/app -w /app apolaki-agent \
    python -m pytest tests/test_session_identity.py -p no:cacheprovider
E  AssertionError: the anonymous control row carried the mission session; ...
E    {'User-Agent': 'Mozilla/5.0 (compatible; Apolaki/2.0; +authorized-testing)',
E     'Cookie': 'sid=THE-MISSION-SESSION'}
E  AssertionError: the attacker persona's request also carried the mission's cookie ...
E    {'User-Agent': '...', 'Cookie': 'sid=THE-MISSION-SESSION',
E     'Authorization': 'Bearer ATTACKER-TOKEN'}
2 failed, 2 passed
```

### Why shape 1 is expensive, MEASURED by reading the oracle

`authz.build_matrix` reads the anon row THREE ways (`agent/authz.py:77-114`), and
`tools.py`'s horizontal-IDOR gate reads it a fourth way:

1. `missing_authentication` fires WHEN anon accessed the object (`authz.py:80`) -> a contaminated
   anon row accesses everything the mission can, so this **over-fires (FALSE POSITIVE, severity
   high) on every protected endpoint**.
2. `bfla` requires `not anon_got` (`authz.py:111`) -> **never fires (FALSE NEGATIVE)**.
3. horizontal IDOR requires `not _authz._accessed(sn, bn)` (`tools.py`, the `pair and anon_role`
   block) -> **every cross-user confirmation is suppressed (FALSE NEGATIVE)**.

So ONE contaminated row produces false positives in one gap type and false negatives in two others,
and it only does so when `authenticated_scan` is on — i.e. precisely on the runs that matter most.

### Why the suite was green on a real defect, MEASURED

Every existing authz/IDOR test monkeypatches `reg._http_send` itself
(`agent/tests/test_authz_matrix_driver.py:48` `reg._http_send = protected`, and the same pattern in
`test_bbh.py`). `_http_send` **is** the function that performs the contaminating merge, so the
defective line is never executed under test. The suite is not weak here; it is patched exactly at
the contamination boundary. Any test for this class of defect must patch below it — these do, at
`tools._target_client`.

### Falsified sub-hypothesis

"Two personas contaminate each other." NOT REPRODUCED. Persona-to-persona is clean: both go through
`_role_headers`, they collide on the same key when they use the same auth scheme, and the caller's
headers win the merge. `test_two_personas_do_not_contaminate_each_other` PASSES on HEAD and is kept
as a negative control. The contamination is specifically **mission -> persona**, one direction.
