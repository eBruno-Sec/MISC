# Arsenal-gap lane (Q-051 measurement)

Question being answered (Erwin's words): "All tools being used by apolaki harmoniously? Apolaki
should be using all tools including browser driver and devtools like an advanced genius pentester."

The deliverable is a MEASUREMENT of which engines never fire in a real mission, and why - not a
feature. Every row below is MEASURED (command + real output) or UNVERIFIED.

Status: in progress. Mission `6ddc56f6` (Juice Shop, mode=active) launched and running.

---

## HEADLINE RESULT (MEASURED) - the Q-051 report sections cannot render in this deployment

**The running agent container does not contain the Q-051 arsenal reporting code at all.**

```
docker exec apolaki-agent-1 python -c "import report; print(hasattr(report,'arsenal_gap'))"
arsenal_gap                  False
technique_coverage           False
_technique_md                False
ledger_finding_disagreement  False
_arsenal_md                  False
```

All five Q-051 functions exist in the working tree and none exist in the running binary. This is
the direct answer to "nobody has ever run a real mission and READ what those sections say": the
sections are not absent because the arsenal is idle, they are absent because **the code that emits
them has never been baked into the image that serves missions**. Any report produced by the
currently-running stack will have no Arsenal-coverage and no Technique-coverage section.

This confirms the prior warning to treat "the section is empty" as a hypothesis. Tested: the
section is empty because the renderer is not deployed.

### Why the drift exists (MEASURED)

`docker-compose.yml` service `agent` mounts only `./ui:/app/ui:ro` plus named data volumes. The
Python engine code is BAKED into the image, not bind-mounted. So a source commit does not reach a
running mission until the image is rebuilt.

```
git log --since="3 days ago" --oneline -- apolaki/agent/ | wc -l   ->  59
```
59 commits touched `agent/` since `apolaki-agent-1` started (container uptime 3 days).

File-level drift, sha256 first 12, tree vs running container:

| file | tree | container | state |
|---|---|---|---|
| `planner.py` | `4cacedc2448d` | `4cacedc2448d` | SAME |
| `tools.py` | `6d46eba6365c` | `e3cffa02c0db` | DRIFT |
| `report.py` | `e13e28cbc853` | `bfe363ad9cb6` | DRIFT |

Note the asymmetry: the permission model (`planner.py`) IS current, while the engine registry and
the report renderer are stale. A conclusion drawn from one of these files does not transfer to the
others.

NOT REBUILT - deliberately. A `docker compose build` SIGKILLs the running mission (three have died
that way), and the lane brief forbids it. The drift is reported, not fixed.

---

## DENOMINATOR (MEASURED) - state it in the same sentence as any percentage

There are TWO valid denominators and they are not interchangeable.

| surface | TOOL_PERMISSIONS | CLAUDE_TOOLS | registered with no `_<name>` dispatch method |
|---|---|---|---|
| working tree (what is committed) | **111** | **76** | **0** |
| running container (what actually scans) | **112** | **77** | **0** |

Exact symmetric difference (MEASURED, not inferred):

- in CONTAINER only, deleted from the tree since the image was baked:
  `run_dirsearch`, `run_ferox`, `run_gobuster`
- in TREE only, added since the bake and therefore **cannot possibly fire in mission `6ddc56f6`**:
  `run_mass_assign`, `run_ws_hijack`

So the three content-discovery adapters deleted in `466bae8` (Q-057) are **still registered and
still dispatchable in the running binary**. The tree is correct; the deployment is not. Confirmed
both ways:

```
tree:      TOOL_PERMISSIONS 111, ferox/dirsearch/gobuster registered: []
container: TOOL_PERMISSIONS 112, _run_ferox/_run_dirsearch/_run_gobuster all present
tree agent/tools.py:234  # Q-057: run_ferox / run_dirsearch / run_gobuster REMOVED 2026-08-16.
```

**The stale 92 from Q-050 is a third denominator again and must not be compared against either
of the above.**

### Disproved hypothesis (a result)

"An engine can be registered, described, and still unreachable via
`getattr(self, '_' + tool_name)`." **MEASURED FALSE on both surfaces**: registered-but-no-dispatch-
method is the empty set in the tree AND in the container. Nothing is unreachable by that mechanism.
The Coordinator independently falsified the mirror case (advertised-but-unregistered = 0). Both
halves of the reachability question are clean.

---

## STRUCTURAL GAP (MEASURED) - 42 of 112 engines cannot run at mode=active

This is a precondition of the whole run and it caps the answer before a single packet is sent.

```
tier histogram over TOOL_PERMISSIONS (denominator 112, running container):
  PASSIVE 15, ACTIVE 55, INTRUSIVE 42
allowed at mode=active: 70 / 112
allowed at mode=full:  112 / 112
```

`planner._allowed()` filters every candidate step by `TOOL_PERMISSIONS[tool] in _ALLOWED[mode]`,
and `_ALLOWED["active"]` is `{PASSIVE, ACTIVE}`. So **42 engines (37.5% of 112) are structurally
incapable of being selected in this mission** - classification `blocked_by_mode`, which is NOT the
same as "never planned" and must never be merged with it.

The 42 INTRUSIVE-only engines:

```
confirm_authz_write, confirm_create_object_idor, enumerate_ids, http_request, run_auth_sqli,
run_bfla, run_cache_poison, run_cmdi, run_content_discovery, run_dalfox, run_deserialization,
run_dir_harvest, run_dirsearch, run_encoded_cookie, run_exposure, run_ferox, run_ffuf,
run_form_cmdi, run_form_nosqli, run_gobuster, run_hash_crack, run_injection_probes, run_ldap,
run_llm_probe, run_nmap_vuln, run_nosqli, run_nosqlmap, run_param_mine, run_path_sqli, run_race,
run_sqli, run_sqli_structural, run_sqlmap, run_ssrf, run_stored_xss, run_upload_test,
run_web_probes, run_workflow, run_xpath, run_xxe, run_zap, test_numeric_abuse
```

Worth naming explicitly for Erwin: at `mode=active` Apolaki **cannot run SQLi (`run_sqli`,
`run_sqlmap`, `run_path_sqli`, `run_auth_sqli`, `run_sqli_structural`), SSRF, command injection,
XXE, NoSQLi, deserialization, race conditions, file upload or ZAP.** That is the mechanical reason
an unauthenticated active scan yields leads rather than confirmed findings - it is by design, and
it is a permission-tier fact, not an engine defect.

Also note `run_zap` is INTRUSIVE, and `POST /engage` independently rejects `enable_zap` unless
`mode == "full"`. ZAP therefore cannot fire in this mission on two independent gates. Its absence
from the ledger is `blocked_by_mode`, not a gap.

CAVEAT on Q-052: the ticket records active and full as "currently the same mission because the
permission model is enforced in the planner and not the dispatcher". The planner-side filter above
is real and does discriminate. Not investigated further - explicitly out of this lane's scope per
the brief.

---

## PRECONDITIONS VERIFIED LIVE (MEASURED) - the browser half of the question

Probed from inside `apolaki-agent-1`, so this is the path the engines actually use:

```
CDP_BROWSER_URL = http://headless-chrome:3000     (set)
ZAP_ADDR        = http://zap:8090                 (set)
http://headless-chrome:3000/json/version -> 200
http://juice-shop:3000/                  -> 200
http://zap:8090/                         -> 200
```

So the browser driver is configured and reachable. If a browser/CDP engine does not fire, the cause
is **not** a missing sidecar and must not be reported as one.

---

## SELF-CORRECTION (MEASURED) - "planner-named" is NOT the dispatch ceiling

I computed an intermediate claim and then falsified it with live data. Recording both, because the
disproof is the result.

CLAIM (intermediate): the deterministic path can only dispatch what `planner.py` names, so the
ceiling at mode=active is 24 of 111 engines, and the 47 engines permitted-at-active but never named
in `planner.py` cannot be selected.

FALSIFIED at 08:xx by the live ledger of mission `6ddc56f6`: `run_header_trust` and
`run_transport_posture` BOTH fired. Both are in that 47-engine "planner never names them" list.

CAUSE: there are at least TWO dispatch surfaces, not one. Besides `planner.py` step emission,
`agent.py` dispatches directly:

```
agent/agent.py:853    r = await self.tools.execute("run_dom_audit", {"url": page}, session_id)
agent/agent.py:3663   async for ev in self._run_tool("run_dom_audit", {"url": u}, session_id):
agent/agent.py:2266   bres = await self._exec_internal("confirm_browser_persona_bola", ...)
agent/agent.py:262    _SWEEP_BROWSER_ENGINES = ("run_xss", "run_dom_trace")
agent/agent.py:3635   _htools = ["run_form_xss","run_xpath","run_ldap","run_ssi","run_client_checks"]
```

So a static regex over `planner.py` understates reachability and MUST NOT be used to classify an
engine as unreachable. **Only the live ledger can separate the four classes.** The 24 and 47 figures
above are retained as a record of the disproved hypothesis, not as findings.

---

## CONFIRMED DEFECT (MEASURED) - two engines cannot test any target on a non-standard port

From the live ledger of `6ddc56f6` (`type == "tool_error"`):

```
TOOL: run_transport_posture
  ERR: SCOPE BLOCK: juice-shop:443 not in scope (host is in scope, but the operator pinned a
       different port)
TOOL: run_header_trust
  ERR: SCOPE BLOCK: juice-shop:80 not in scope (host is in scope, but the operator pinned a
       different port)
```

Both engines were DISPATCHED (this is NOT a planner gap). Exact per-tool counts from the live
ledger, so the blast radius is not overstated:

| engine | calls | results | scope_blocks | findings |
|---|---|---|---|---|
| `run_transport_posture` | 1 | **0** | 1 | 0 |
| `run_header_trust` | 6 | 5 | 1 | 0 |

- `run_transport_posture` is **100% dead on this target**: its only call was blocked, so it produced
  no result at all.
- `run_header_trust` is **partially affected**: it lost the origin-derived target but still tested 5
  discovered URLs (which carry `:3000`). Do not report it as dead.

### Root cause (MEASURED - reproduced deterministically in isolation)

Not a per-engine port constant. `_run_transport_posture` itself derives the port correctly
(`agent/tools.py:2604`, `port = p.port or (443 if is_https else 80)`). The defect is in the CALLERS,
and it is the same two lines:

```
agent/agent.py:2355  u = s if "://" in s else "https://" + s.split("/")[0]   # _do_transport_posture
agent/agent.py:2395  u = s if "://" in s else "http://"  + s.split("/")[0]   # _do_header_trust
```

Both rebuild an origin from `self.scope.to_dict()["in_scope"]`, which has ALREADY dropped the scheme
and the port. Reproduced standalone:

```
ScopeEngine().load_manual(['http://juice-shop:3000'], [], 'probe')
to_dict()["in_scope"]  ->  ['juice-shop']            # port stripped here
'juice-shop' has no "://"  ->  'https://juice-shop'  # port 443 invented here
scope.validate('https://juice-shop')  ->  False      # operator pinned :3000
```

So the chain is: scope normalises the entry to a bare host, the caller re-adds a DEFAULT scheme, and
that invents a port the operator never authorised. The scope engine then correctly refuses it. Every
Apolaki local lab runs on a non-standard port, so `_do_transport_posture` has been incapable of
auditing the pinned origin across the entire local lab fleet.

Per `agent/engine_descriptor.py:135-139`, the capabilities lost with it are `tls_posture`,
`cookie_scope_posture`, `http_security_headers` and `http_methods_audit`.

Classification: **ran and produced nothing for a defect reason.** This is precisely the case that
must not be read as "ran and found nothing" (healthy). `_tool_ledger()` in `agent/main.py:951`
renders it as:

```
elif not a["ok"] and a["scope_blocks"]:
    status, note = "skipped", (a["scope_note"] or "every target was out of scope - nothing tested")
```

which is honest and does surface the reason - but the engine is filed under `skipped`, so
`arsenal_gap()["silent"]` will not contain it and `arsenal_gap()["not_dispatched"]` will not either.
It lands in `dispatched` with zero findings and no gap flag. A reader of the Arsenal-coverage
section would see these two counted as engines that ran.

SUGGESTED PATCH (this lane owns neither `agent/agent.py` nor `agent/scope.py`, so it is recorded
here, not applied). Two options, in preference order:

1. Preferred - stop discarding the port at the source. Have `ScopeEngine.to_dict()["in_scope"]`
   preserve the operator's authorised origin (scheme + host + port) so callers do not have to guess.
   This fixes every present and future caller at once.
2. Local - have both callers reuse an origin the scan has already validated (e.g. the first
   in-scope entry from `self.tools.urls`) instead of synthesising `scheme + "://" + host`.

Do NOT "fix" this by relaxing `scope.validate`. The scope engine is behaving correctly and is the
authorisation gate; the bug is that a caller invented an unauthorised port.

A negative control for whoever patches it: re-run with scope `http://juice-shop:3000` and assert
`run_transport_posture` records >= 1 `tool_result`. Before the fix that count is 0, measured above.

---

## CONFIRMED DEFECT 2 (MEASURED) - `blocked_by_mode` is structurally dead; the report conflates the two classes it exists to separate

This is the defect that most damages the answer to Erwin's question, because it makes the
Arsenal-coverage section state the OPPOSITE of the truth for 40+ engines.

### The measurement

The real ledger produced by the live mission, passed to the TREE's `report.arsenal_gap()`:

```
ledger keys: ['ai_calls', 'authenticated', 'strategy', 'tools', 'zap_status']
ledger mode = None      strategy = 'deterministic'

arsenal_gap(real_ledger):
  error           : ''        <- imports fine, no swallowed failure
  dispatched      : 20
  silent          : 11
  not_dispatched  : 91        (111 tree denominator - 20 dispatched, consistent)
  blocked_by_mode : 0
```

### Positive control - the apparatus is not simply blind

Same ledger, same function, only the `mode` key added:

```
real ledger as produced (no mode key) -> blocked_by_mode: 0
same ledger + mode='active'           -> blocked_by_mode: 40
same ledger + mode='full'             -> blocked_by_mode: 0   (correct: full allows every tier)
```

So the function works. The 0 is not a broken measurement, it is a missing input.

### Root cause

`agent/main.py`, the return of `_tool_ledger()` - **there is no `mode` key**:

```
return {"tools": tools, "zap_status": zap,
        "authenticated": bool(ctx.get("authenticated")),
        "strategy": ex.get("strategy") or ctx.get("strategy") or "",
        "ai_calls": ex.get("ai_calls", 0)}
```

`arsenal_gap()` reads `mode` first, then falls back to `strategy` "ONLY when it names a real mode".
That fallback can NEVER fire, because the two vocabularies are disjoint:

```
strategy values : manual | deterministic | low_ai | agentic
planner._ALLOWED: active | full | passive
```

The producer was never updated to emit `mode`, so both the primary read and the fallback yield "",
`allowed` stays `None`, and the `blocked_by_mode` branch is skipped every time.

Note `_scan_config()` - the very next function in the same file - already carries `mode`, so the
value is available in scope and simply is not threaded in.

### Consequence, which is the reportable harm

`_arsenal_md()` prints tier-blocked engines ONLY inside `if gap["blocked_by_mode"]:`. With that list
permanently empty, all 40 tier-blocked engines fall through to:

```
Available but not selected: <...>
```

So a mode=active report tells the reader that `run_sqli`, `run_sqlmap`, `run_ssrf`, `run_cmdi`,
`run_xxe`, `run_zap` and ~34 others were **available and the planner chose not to select them**,
when in fact they were **structurally incapable of running at that permission tier**. Those are the
two classes with completely different fixes (raise the mode vs. fix the planner), and the report
currently merges them - the exact failure this section was built to prevent.

It also explains the brief's note that the tier line "had never rendered in a real report". The
reader fix (mode-then-strategy) landed; the producer half never did. Both halves of a fix have to be
verified.

### SUGGESTED PATCH (recorded, not applied - this lane does not own `agent/main.py`)

In `_tool_ledger()`, add the mission mode to the returned dict:

```
m = db.get_mission(session_id)          # already fetched at the top of the function
return {"tools": tools, "zap_status": zap,
        "mode": (m or {}).get("mode"),  # <-- the missing key
        "authenticated": ...,
        "strategy": ...,
        "ai_calls": ...}
```

NEGATIVE CONTROL the patcher must run, or the fix is unproven: render a mode=active report and
assert the Arsenal-coverage section contains a non-zero "unable to run at this permission tier"
count. Before the patch that count is 0 - measured above on a real ledger, twice.

Consider also deleting the `strategy` fallback rather than leaving it: it cannot ever resolve, and a
fallback that never fires is a guard that checks a declaration instead of a fact.

---

## Q-052 corroborated empirically (MEASURED) - reported, NOT fixed

Q-052 records that the permission model is enforced in the planner and not the dispatcher. Mission
`6ddc56f6` (mode=active) confirms it with data. Seven INTRUSIVE-tier engines ran anyway:

```
ran but INTRUSIVE (planner tier says impossible at mode=active): 7
run_encoded_cookie, run_exposure, run_injection_probes, run_ldap,
run_sqli, run_sqli_structural, run_xpath
```

Cause is the same second dispatch surface documented above: `planner._allowed()` gates step
emission, but `agent.py`'s direct sweeps (`self._run_tool` / `self.tools.execute` /
`_exec_internal`) never consult `TOOL_PERMISSIONS`.

OUT OF SCOPE for this lane per the brief - not touched, not fixed, no change proposed.

**But it constrains Defect 2's patch, so it must be read alongside it.** If `mode` is threaded into
the ledger, `arsenal_gap()` will label the remaining undispatched INTRUSIVE engines "unable to run
at this permission tier". On current behaviour that label is not reliable: the tier does not
actually prevent execution, it only prevents planner SELECTION. The wording would need to become
something like "not selectable by the planner at this tier" for it to be true.

The function is at least self-consistent: `blocked_by_mode` is computed only over engines NOT
dispatched, so the 7 above are excluded and the report will not contradict its own ledger.

Sanity check passed: `ran but NOT in TOOL_PERMISSIONS at all: []` - every engine that executed is
registered, so no unregistered engine is executing behind the permission map.

---

## Invocation-surface axis (from the Coordinator, MEASURED by them)

35 of the tree's 111 registered engines are absent from `CLAUDE_TOOLS`. Apolaki is
deterministic-first - the planner selects from the effects model, not from `CLAUDE_TOOLS` - so
"not advertised to the model" does NOT mean "never runs". Recorded as a classification axis for
each idle engine:

- advertised to the model AND planner-reachable -> idle may be an LLM-selection gap
- planner-reachable only (one of the 35) -> idle is a planner/effects-model gap
- neither -> genuinely unreachable, a real finding

`confirm_browser_persona_bola` and `run_dom_trace` are both browser-driver engines sitting in the
unadvertised 35. Flagged for hard look.

---

## Do not quote as evidence

- `run_metadata` and `_run_workflow` are known to misreport (Q-055 / Q-054, owned by another live
  lane). If they appear in the ledger, their result is UNRELIABLE either way.
- `run_workflow` is INTRUSIVE, so at mode=active it is `blocked_by_mode` and will not appear.

---

## Positive controls used

- The throwaway-container tree mount is proven non-empty: it returned real distinct sha256 hashes
  for 5 files and a registry count of 111. A Git-Bash `/tmp` mount silently mounting an empty
  volume would have yielded an import error or 0, not 111.
- The container/tree registry diff returned a NON-empty, specific, and independently
  git-corroborated set (`466bae8` names exactly the three adapters the diff found). A broken
  extraction would have returned an empty diff.
- Pending: before reporting any "engine X never fired", the ledger extraction must first be shown
  to see the engines that DID fire. Not yet done - mission still running.

---

## Open / in progress

- Mission `6ddc56f6` ledger extraction and four-way classification: in progress.
- Whether browser/CDP engines fired: in progress.
