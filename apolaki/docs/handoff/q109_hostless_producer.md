# Q-109 - what mints the 30 hostless graph endpoint nodes

LANE C (Breaker, READ-ONLY). No product code changed this cycle. Every claim below is either
MEASURED (command + real output shown) or explicitly UNVERIFIED.

Repo: `C:\Users\voice\Desktop\GitHub\MISC\apolaki`. Git root is the PARENT `MISC`.

---

## 0. The symptom, restated only to fix the vocabulary

```
graph_primary_state.hostless_endpoint | failed | DEGRADED: swallowed exception at
graph_primary_state.hostless_endpoint: ValueError: 30 graph endpoint node(s) carry no host, so no
absolute URL exists for them
```

The REPORTER is `agent/agent.py:3415-3460` (`AgentBrain._graph_primary_state`), and it is correct.
It drops an endpoint node it cannot resolve to an absolute URL, and records the drop with a count
and the first offenders. Nothing in this document proposes relaxing that drop.

The resolver it calls is `agent/agent.py:_endpoint_url`, whose whole contract is the refusal:

```python
        if "://" in s:
            return s if _up(s).netloc else ""
        host, sep, rest = s.partition("/")
        if not host:                     # a bare path - no host was ever recorded for this node
            return ""
```

So a node is "hostless" iff its KEY is a **bare path** (`/rest/user/login`) or a scheme-only URL.
That single line is the whole definition of the offender shape, and it is what the hunt below uses.

---

## 1. Recovering the three recorded offenders: UNVERIFIED, and why

**They could not be recovered from any store on this machine.** Two independent reasons, both
measured.

### 1a. The persisted mission database holds ZERO rows for this swallow

`ToolRegistry._swallow` (`agent/tools.py:4262-4300`) persists every swallow durably:

```python
                db.add_log(mission_id, "tool_error", {
                    "tool": active_tool or rec["where"],
                    "error": "DEGRADED: swallowed exception at %s: %s" %
                             (rec["where"], rec["error"]),
                    "target": rec["target"],
                })
```

MEASURED against the live mission DB (140 MB, inside the `apolaki_bbh_data` volume, mounted
read-only):

```
$ MSYS_NO_PATHCONV=1 docker run --rm -v apolaki_bbh_data:/d:ro apolaki-agent python -c "
import sqlite3
c=sqlite3.connect('file:/d/bbh.db?mode=ro',uri=True)
print('LOGS', c.execute('select count(*) from logs').fetchone())
print('tool_error', c.execute(\"select count(*) from logs where etype='tool_error'\").fetchone())
print('hostless', c.execute(\"select count(*) from logs where data like '%hostless%'\").fetchone())
print('graph_primary', c.execute(\"select count(*) from logs where data like '%graph_primary_state%'\").fetchone())
print('maxdate', c.execute('select max(created_at) from logs').fetchone())
"
LOGS (71536,)
tool_error (612,)
hostless (0,)
graph_primary (0,)
maxdate ('2026-08-24T20:19:29.721750+00:00',)
```

Zero. And more broadly, this DB contains **no `_swallow`-written row at all**:

```
$ ... print('DEGRADED', ...like '%DEGRADED%'); print('swallowed', ...like '%swallowed%')
DEGRADED (1,)
swallowed (0,)
```

The single `DEGRADED` hit is an unrelated `run_zap` `tool_result` string
(`b226bc05`, `active scan degraded, passive alerts kept`), not a swallow. So the
`_swallow -> db.add_log` path has produced nothing in this volume, and the operator's snapshot must
have come from a mission store that is not present here.

The Shopify missions themselves ARE in this DB, and their `tool_error` rows are all ordinary tool
failures, none of them the graph swallow:

```
$ ... select data from logs where mission_id='351e163d' and etype='tool_error'
http_probe                   | [Errno -2] Name or service not known      (x15)
fetch_openapi                | [Errno -2] Name or service not known      (x30)
run_zap                      | ZAP was enabled but no run_zap tool_call was persisted; ...
```

Mission rows for reference (`missions` has no `target` column; the program name carries it):

```
('351e163d', '24Aug2026_1019_shopify_DF3', 'full', 'failed', 'report', ...)
('d9ce9f0a', '24Aug2026_1019_shopify_DF3', 'full', 'failed', 'report', ...)
('80c76f01', '24Aug2026_shopify',          'full', 'failed', 'report', ...)
('30555296', '24Aug2026_shopify',          'full', 'failed', 'report', ...)
('07710343', '23Aug2026_shopify',          'full', 'failed', 'report', ...)
```

The host-side copy `apolaki/agent/data/bbh.db` is empty (`logs (0,)`), so there is no second store.

### 1b. Even where the row EXISTS, only the FIRST offender survives - the other two are truncated

This is a real defect in the ticket's own premise ("`_swallow` carries the first three offenders
VERBATIM in the mission record"). It does not.

`_swallow` truncates the exception text at 160 characters:

```python
        rec = {"where": str(where or "unknown")[:160], "target": str(target or "")[:200],
               "error": "%s: %s" % (type(exc).__name__, str(exc)[:160])}
```

The ValueError's message prefix, before the offenders begin, is:

```
30 graph endpoint node(s) carry no host, so no absolute URL exists for them; they cannot be probed and were NOT faked onto a bare scheme. First: 
```

MEASURED, reconstructing the exact message the code builds:

```
$ MSYS_NO_PATHCONV=1 docker run --rm apolaki-agent python -c "
msg = ('%d graph endpoint node(s) carry no host, so no absolute URL exists for '
       'them; they cannot be probed and were NOT faked onto a bare scheme. '
       'First: %s' % (30, ', '.join(['/rest/user/login','/api/v1/orders','/assets/app.js'])))
pre = msg.split('First: ')[0] + 'First: '
print('prefix_len', len(pre)); print('full_len', len(msg))
print(repr('ValueError: ' + msg[:160]))
"
prefix_len 145
full_len 193
'ValueError: 30 graph endpoint node(s) carry no host, so no absolute URL exists for them; they cannot be probed and were NOT faked onto a bare scheme. First: /rest/user/logi'
```

The prefix is **145 characters** for a 2-digit count, so `str(exc)[:160]` leaves **15 characters**
for the offender list. Offenders 2 and 3 are unreachable by construction, and offender 1 is cut
mid-token (`/rest/user/logi`) inside `error`.

`target` is a separate field capped at 200 and is set to `_unresolved[0]`, so **the first offender
is fully recoverable from `target`** - but only the first.

> HANDOFF NOTE (not part of the Q-109 patch): if the operator wants all three, either widen the
> `str(exc)` cap or move the offender list into a dedicated field. Filing this separately rather
> than folding it into the producer fix.

---

## 2. Search space covered

Every writer of an `endpoint` node in `agent/`, found with a tree-wide grep (not a single-file
grep - see "failure modes" in the lane brief):

```
$ grep -rn '"endpoint"' --include=*.py agent/ | grep observe
agent/agent.py:3242   g.observe("endpoint", ep_key, ...)            source="openapi"
agent/agent.py:3282   g.observe("endpoint", ep_key, ...)            source="form-capture"
agent/agent.py:3334   g.observe("endpoint", u, ...)                 source="recon"   (live_hosts)
agent/agent.py:3337   g.observe("endpoint", str(u), ...)            source="recon"   (tools.urls)
agent/archive_intel.py:34  graph.observe("endpoint", (h+path) if h else path, ...)  source="wayback"
agent/archive_intel.py:50  graph.observe("endpoint", val, ...)                      source="github"
agent/asset_graph.py:330   self.observe("endpoint", str(r), ...)                    source=<harvest>
agent/asset_graph.py:592   g.observe("endpoint", (host+path) if host else path, ...) source="recon"
agent/codereview_graph.py:68 graph.observe("endpoint", pfx+path, ...)               source="code_review"
agent/tools.py:4084   self.graph.observe("endpoint", (host+path) if host else path, ...) source="live-recon"
```

Three distinct key CONVENTIONS are in use, which is the root of the whole class:

| convention | key shape | writers | resolves? |
|---|---|---|---|
| A | absolute URL `https://h/p` | `agent.py:3334`, `agent.py:3337` | yes |
| B | `netloc + path` (`h/p`) | `agent.py:3242`, `agent.py:3282`, `tools.py:4084`, `asset_graph.py:592`, `archive_intel.py:34` (when `h`) | yes |
| C | **bare path** (`/p`) | `asset_graph.py:330`, `archive_intel.py:50`, `archive_intel.py:34` (when `h` empty), `codereview_graph.py:68` (when `pfx` empty) | **NO - dropped** |

Convention C is the offender class.

(work in progress - producer attribution and reproduction follow)
