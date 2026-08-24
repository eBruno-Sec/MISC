# Shopify false-positive lane — Q-097 / Q-096 / Q-098

**Origin:** a full deterministic assessment against the Shopify HackerOne program on 2026-08-24
produced 18 findings **without ever opening a socket to Shopify**. Three separate defects had to line
up for that to happen. This file is written AS THE WORK HAPPENS; if the lane dies, this is the
contribution.

**Baseline at HEAD `08158c2`:** 3581 passed / 11 skipped / 12 xfailed / 0 failed (Coordinator's
measurement; re-measured here — see §0).

**No traffic was sent to Shopify at any point in this lane.** Every live measurement below is against
the local docker labs on `apolaki_default`.

---

## 0. Baseline re-measurement

Command (backgrounded at the start of the lane):

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" -w /app apolaki-agent \
  python -m pytest tests/ -p no:cacheprovider -rfE -q
```

Result: PENDING (running).

---

## 1. Q-097 — `_run_transport_posture` invents header findings from a dead socket

### Reading of the code (MEASURED by reading, before any edit)

`agent/tools.py:3326` `_run_transport_posture`. At `:3347-3359`:

```python
headers, set_cookies = {}, []
try:
    r, _ = await self._http_send("GET", origin + "/", {}, None, True)
    headers = dict(r.headers or {})
    ...
except Exception as _apolaki_swallowed_2960:
    self._swallow(_apolaki_swallowed_2960, 'tools:_run_transport_posture:2960', "")
    pass
```

`headers` stays `{}` when the GET never completes, and `{}` is then handed to
`transport_posture.findings_for(... headers=headers ...)` → `analyze_security_headers(headers or {})`
(`agent/transport_posture.py:275`), which reports **every** protective header absent. The engine then
returns `success=True` with `"ran": true`.

`analyze_cookies` / `analyze_cookie_scope` (empty `set_cookies`) and `analyze_methods` (empty
`allow_header`) are on the same failure path; they happen to be quiet on empty input, so the header
analyser is the one that manufactures findings.

Q-093's chokepoint is in `_http` (`tools.py:4078`, `_http_record`). This path uses `_http_send`
(`tools.py:2282`), which **raises** instead of returning a dict, and the raise is caught locally. So
the Q-093 counter never sees it — confirmed by reading both functions.

The `reachable` signal is already measured and already ignored: `transport_posture.py:502` seeds
`out["reachable"] = False`, `:513` sets it True only after a completed handshake, and the summary
built at `tools.py:3384` copies it into `"tls": {"reachable": ...}` while emitting the findings
anyway.

### The RED gate (committed BEFORE the fix)

`agent/tests/test_transport_posture_dead_socket.py`. Five tests, and the split is the point:

```
$ docker run --rm --network apolaki_default -v ".../agent:/app" -w /app apolaki-agent \
    python -m pytest tests/test_transport_posture_dead_socket.py -p no:cacheprovider -q --tb=no
FF...                                                                    [100%]
```

**2 failed, 3 passed at HEAD.** The 2 failures are the defect; the 3 that ALREADY PASS are the
non-vacuity controls, and their passing before the fix is what proves the file can tell a dead socket
from a bare page rather than merely disliking findings.

MEASURED failure 1 — the 18-finding mechanism, reproduced:

```
AssertionError: header findings were emitted from a request that never completed:
  {'header_missing_x_content_type_options', 'header_missing_csp',
   'header_missing_permissions_policy', 'header_missing_framing_control',
   'header_missing_referrer_policy'}
 + where ... = ToolResult(tool='transport_posture', target='http://juice-shop:3000',
                          success=True, output='DEGRADED: 3 load-bearing c...', error=None)
```

5 rather than 6 only because this fixture is a plaintext origin, so the HSTS rule is correctly
skipped; the field mission was https, which is where the 6th came from. Note `success=True` and the
`DEGRADED:` prefix — the run KNEW three load-bearing calls had failed and emitted the findings anyway.
**Visibility is not enforcement**, in one ToolResult.

MEASURED failure 2 — the pure layer has no way to express "not observed":

```
TypeError: findings_for() got an unexpected keyword argument 'http_observed'
```

The three controls that pass at HEAD:
- a live page that genuinely sends no CSP still reports `header_missing_csp`;
- a live page that sends CSP/XFO/XCTO/Referrer-Policy/Permissions-Policy is accused of none of them;
- the real lab: juice-shop:3000, real sockets. MEASURED 2026-08-24 — it sends
  `x-frame-options: SAMEORIGIN` and `x-content-type-options: nosniff`, and sends neither
  Content-Security-Policy nor Referrer-Policy, so ONE real response proves both directions.

### The fix

Two files, one idea: **an absence can only be observed in something that arrived.**

1. `agent/transport_posture.py:findings_for` gains `http_observed: bool = True`. When it is False the
   cookie, protective-header and method analyses are not run at all. The default preserves every
   existing caller — `headers={}` still means "a response arrived carrying no protective headers" and
   still reports all six. The two states were previously the same VALUE; now they are different
   ARGUMENTS.
2. `agent/tools.py:_run_transport_posture` records `http_ok` / `http_err` in the `except` that
   previously only swallowed, and passes `http_observed=http_ok` down.
   - **Neither channel observed** (HTTP GET failed AND the TLS handshake was not reachable):
     `ran=False`, zero findings, `success=False`, and `error` naming the transport cause. This is the
     Shopify case.
   - **TLS reachable but the GET failed**: the TLS/certificate findings are real evidence and stay;
     the cookie/header/method half is WITHHELD and the summary says so. Silence about the whole origin
     would have thrown away a genuine observation.

`tls_reachable` is now read from the probe into the branch, so the flag that was already measured at
`transport_posture.py:502/513` and printed into `"tls": {"reachable": false}` finally decides
something.

**Stale swallow labels fixed** — the ticket names one, there were three, all in this function:
`:2960 -> :3367`, `:2967 -> :3374`, `:2972 -> :3380` (the true `self._swallow` call-site lines).

**Something the RED gate turned up that the ticket did not have.** The engine's own `res.output` on the
dead path begins:

```
DEGRADED: 3 load-bearing check(s) failed to execute; latest=tools:_run_transport_posture:2972 {"ran": ...
```

The dispatch KNEW all three of its calls had died, said so in its own output string, and emitted five
missing-header findings underneath that sentence with `success=True`. That is the ticket's "visibility
is not enforcement" in a single artifact, and it is now recorded in the test's `_summary()` helper so
the next reader does not have to rediscover it.

### MEASURED after the fix

```
$ docker run --rm --network apolaki_default -v ".../agent:/app" -w /app apolaki-agent \
    python -m pytest tests/test_transport_posture_dead_socket.py tests/test_transport_posture.py \
      tests/test_asvs_transport_config_objective.py tests/test_silent_failure_invariant.py \
      tests/test_deadcode_gate.py tests/test_oracle_properties.py \
      tests/test_ledger_negative_result.py tests/test_arsenal_errored_class.py \
      tests/test_scope_origin_carry.py tests/test_sqli_stability.py -p no:cacheprovider -q
EXIT=0     (176 tests, 1 xfail, 0 failed)
```

The gate file went `FF...` -> `.....`, and the three guards named in the house rules
(`test_deadcode_gate`, `test_silent_failure_invariant`, plus `test_external_tool_liveness` in the full
run) were not edited.

**A note on the first baseline run, so the record is honest.** The lane's opening full-suite baseline
was started against the LIVE working tree and then I edited `tools.py` while it was still running. It
finished `1 failed` on `test_sqli_stability.py::test_every_shipping_boolean_call_supplies_the_reference_sample`
— a source-reading guard that read a half-edited `tools.py`. Re-run against the settled tree: PASSES
(included in the command above). **That failure was my own torn read, not a regression**, and the
lesson is the same one `git archive emits CRLF` taught: a mid-flight snapshot of a shared tree is not
a measurement. Subsequent full-suite runs are started only when the tree is settled.

---

---

## 2. Q-096 — the scope REGEX is used as a hostname

### MEASURED at HEAD, before writing a line of fix

Three anchored patterns and nothing else, in the agent image:

```python
e = scope.ScopeEngine(); e.load_manual([r"^.*\.shopify\.com$", r"^.*\.shopifycs\.com$",
                                        r"^.*\.myshopify\.com$"], [], "Shopify")
```
```
in_scope types  [('^.*\\.shopify\\.com$', 'domain'), ...]        <- typed DOMAIN, not wildcard
base_urls()     ['https://^.*\\.shopify\\.com$', ...]            <- the curl command in the report
base_map()      {'^.*\\.shopify\\.com$': 'https://^.*\\.shopify\\.com$', ...}
base_roots      ['^.*\\.shopify\\.com$', ...]   <- agent.py:3758, seeds subfinder/crtsh/dns/asn
validate('https://^.*\\.shopify\\.com$')  -> (True,  'In scope via ^.*\\.shopify\\.com$')
validate('https://www.shopify.com')       -> (False, 'www.shopify.com not in scope')
```

**Read the last two lines together — this is the fact the ticket did not have.** The predicate was
not merely useless, it was **INVERTED**. The unresolvable pattern string was AUTHORISED (it literally
equals itself, so `_matches` accepted it), and every real asset the operator owns was REFUSED. Even
if recon had somehow discovered a live Shopify host, scope would have blocked it. That is the
mechanism behind "self-amplifying": there was no path by which a real host could enter the mission.

### Design decision, and why

The ticket asks me to choose between dropping an invalid entry with a loud mission-level error and
rejecting it at `load_manual`. **Both, split by what the entry can still be used for.** Scope does two
jobs and they were conflated:

| job | question | a pattern |
|---|---|---|
| PREDICATE | is this discovered host authorised? | **yes** — that is what a pattern is FOR |
| ADDRESS | what do I connect to? | **never** |

- A non-host entry is **typed `pattern` and parked in `in_scope_patterns`**, so it is absent from
  `in_scope`. That single move fixes all three `agent.py` drivers (`:3003` path seeding, `:3317`
  graph host observation, `:3758` recon roots) **without editing `agent.py`**, which this lane may not
  write. It is also why the `run_asn` / `run_dns` junk rows stop: those engines are seeded from
  `base_roots`, and a pattern is no longer in it. "SPF MISSING" on an unresolvable name cannot be
  reported because the name is never dispatched.
- It **still matches**, now as a real anchored `re.fullmatch` instead of a literal string compare —
  which is what the operator meant and what the literal compare never delivered. `validate()` keeps
  working as a predicate, which was the trap in this ticket.
- `base_urls()` / `base_map()` change from a **negative** filter (`if asset_type == "wildcard":
  continue`) to a **positive** one. The negative form is the actual root cause: it admits every shape
  nobody thought of, and a regex was one. Stated positively, the next unforeseen shape is refused by
  default.
- **When EVERY entry is a pattern, `load_manual` raises `ScopeConfigurationError`.** There is then no
  boundary that can become a target, and the discipline for that is already written down in this
  codebase at `main.py:3081`: *"Scope is the boundary between authorised testing and hitting something
  nobody asked us to touch... Unknown is not permission. The fix is not to make `load_manual`
  tolerant."* That call site already wraps `load_manual` in a try/except that turns the raise into an
  actionable refusal.

**Blast radius I accept, stated plainly:** `main.py:197 _scope_for()` rebuilds a stored mission's
scope, so re-opening a mission whose scope is all patterns now raises instead of returning an
engine. That is the correct direction — a mission whose boundary cannot be turned into a target
should not be re-armed — but it is a behaviour change for stored missions, and the Shopify mission is
one of them.

### The RED gate

`agent/tests/test_scope_pattern_is_not_a_target.py` — **`FFFFFF....` = 6 failed, 4 passed at HEAD.**
The four that already pass are the negative controls: a real-host scope is untouched, a wildcard keeps
exactly its old suffix semantics, a plain host is never read as a regex (`example.com` must not match
`exampleXcom` — the control on my own change, since widening a matcher is the dangerous direction),
and the SEC-1/SEC-2 port and path pins still hold.

The six failures, verbatim:

```
AttributeError: module 'scope' has no attribute 'ScopeConfigurationError'
AssertionError: a regex was emitted as a base URL:
  ['http://juice-shop:3000', 'https://^.*\\.shopify\\.com$', ...]
AssertionError: a regex is still an authorised target: 'In scope via ^.*\\.shopify\\.com$'
AssertionError: https://www.shopify.com is in the operator's scope: (False, 'www.shopify.com not in scope')
AssertionError: the operator's exclusion was not enforced
AssertionError: run_transport_posture was DISPATCHED at a regex instead of refused:
  success=False error='no response from https://^.*\\.shopify\\.com$ ([Errno -2] Name or service not known)'
```

That last one is worth pausing on. Q-097 is already landed, so the engine now *fails honestly* at the
pattern — and that is exactly why the assertion demands `SCOPE BLOCK` rather than "it failed". A
gate satisfied by "the engine could not resolve it" would pass on a build that still dispatches
active engines at a regex. The two defects are independent and the gate for each has to say so.

### MEASURED after the fix — the same script, the same three patterns

```
ScopeConfigurationError: no in-scope entry can be a target: "^.*\.shopify\.com$",
  "^.*\.shopifycs\.com$", "^.*\.myshopify\.com$". A scope pattern matches hosts, it cannot be
  connected to — supply at least one concrete host (or a wildcard root) alongside the pattern(s)...
```

and with one real host added, so the engine builds:

```
in_scope      [('juice-shop', 'domain')]
patterns      [('^.*\\.shopify\\.com$', 'pattern'), ...]
base_urls()   ['http://juice-shop:3000']
base_roots    ['juice-shop']                     <- recon can no longer be seeded with a regex
validate('https://^.*\\.shopify\\.com$')      -> (False, '^.*\\.shopify\\.com$ not in scope')
validate('https://www.shopify.com')           -> (True,  'In scope via pattern ^.*\\.shopify\\.com$')
validate('https://www.shopify.com.evil.tld')  -> (False, ...)     <- anchored, no suffix confusion
validate('http://juice-shop:3000/x')          -> (True,  'In scope via juice-shop:3000')
```

**The inversion is gone in both directions**: the pattern is refused as a target and the real host is
authorised. `to_dict()` carries `unusable_as_targets` naming each refused entry and why, so the
misconfiguration is in the mission record rather than being silence.

### One thing this turned up that is worth the next reader's time

The first fix used `try: re.compile(...) except re.error: None`, and
`test_silent_failure_invariant.py` went red on `assert counts["optional"] <= 387` -> `388 <= 387`.
That ceiling is ratcheted with zero slack precisely so a deleted swallow's seat cannot be silently
refilled, and mine would have refilled it. **The guard was right and the code was wrong.** Compiling
at LOAD time with no handler at all is the better design anyway: an entry that is neither a hostname
nor a compilable pattern is a boundary nobody can evaluate, so it must fail where the operator can
still fix it, not match nothing forever at request time.

### MEASURED

```
tests/test_scope_pattern_is_not_a_target.py  FFFFFF....  ->  ..........
```
plus `test_scope_path`, `test_scope_origin_carry`, `test_junk_host_filter`, the whole of
`test_bbh.py`, the Q-097 gate, and the `test_deadcode_gate` / `test_silent_failure_invariant`
guards: **EXIT=0**.

### Residual, reported not fixed (outside this lane's writable set)

`web_security._looks_like_host_identifier` (`web_security.py:136`) is the same disease in a second
place: its host test is `"." in ident and no whitespace`, which `^.*\.shopify\.com$` passes. So
`is_url_in_scope` also treats a regex as a host rule. It is not exploitable the way `base_urls()` was
— that path only ever REFUSES, never dials — and `web_security.py` is not writable in this lane, so
it is recorded here rather than changed. `to_rules()` deliberately keeps emitting `type: "domain"`
for a pattern so that module's behaviour is byte-identical to before.

---

## 3. Q-098 — evidence-graded impact text bound to CWE, not to the finding family

### The mechanism, exact

`transport_posture._FINDING_META` gives `header_missing_referrer_policy` the CWE **CWE-200**
(`transport_posture.py:346`) while the finding carries `family: "security_misconfig"`
(`transport_posture.py:404`). Both impact functions in `report.py` then did the same thing:

```python
fam = finding["family"]                    # "security_misconfig"
if fam not in _IMPACT_GRADE:               # true -- misconfig had no entry
    fam = _CWE_FAMILY[finding["cwe"]]      # "cwe-200" -> "exposure"
```

**This is why the field report shows exactly three, one per origin, and not eighteen**: Referrer-
Policy is the only one of the six header rules mapped to CWE-200. The other five are
CWE-693/1021/319, which `_CWE_FAMILY` does not list, so they fell through to nothing. A detail that
makes the diagnosis checkable rather than plausible.

`report._family_of` (`report.py:812`) already had the right rule — family first, CWE only when there
is no family. The two impact functions did not.

### It is not one finding, it is at least a dozen — MEASURED

Census over every `"family"`/`"cwe"` pair in the tree, run before writing the fix:

```
family+CWE pairs that TODAY borrow another family's graded text: 24
   anomaly              CWE-200  -> exposure          fingerprint      CWE-200  -> exposure
   attack_surface       CWE-200  -> exposure          graphql          CWE-200  -> exposure
   base64_param         CWE-89   -> sqli              info_disclosure  CWE-200  -> exposure
   bola                 CWE-204  -> username_enumeration                param_mine  CWE-200 -> exposure
   jwt                  CWE-326  -> weak_ssh_crypto   oauth            CWE-352  -> csrf
   llm_output_handling  CWE-79   -> xss               session_fixation CWE-384  -> weak_session_token
   ...
```

`base64_param` + CWE-89 is the one that should worry a reader most: a base64-shaped parameter
OBSERVATION inherits sqli's `Confirmed on this target: an injectable parameter confirmed by a
control-vs-payload differential`. That is the Referrer-Policy defect with a worse claim.

(About half the 24 are harmless — `crlf -> crlf`, `default_credentials -> default_credentials` and
friends map a family onto itself or onto a family with no graded entry, so they produce nothing
either way.)

### The fix

`_graded_family(finding)`: a **declared family is authoritative**, optionally through an explicit
`_FAMILY_ALIAS`. The CWE map is consulted only for a finding that declares **no family at all** —
which is its legitimate use and the case it was written for. Both `business_impact` and
`graded_business_impact` now route through it.

`_FAMILY_ALIAS` is deliberately tiny and each entry is a claim I can defend against the aliased
family's own oracle:

```python
"reflected_xss": "xss", "stored_xss": "xss", "dom_xss": "xss",
"bola": "idor",   # object-level authz: the oracle IS idor's (owner denied on the control)
```

Everything else that was borrowing loses the borrowed text. **No text is better than borrowed text**
— that is the ticket's thesis, so the fix has to be willing to pay it.

**The fix is not deletion.** Stripping the block would have left every misconfig finding with no
impact text, trading a false claim for no information. `security_misconfig` gets its own entry saying
what the check establishes and, in the third slot, what it explicitly does not:

```
demonstrated: the control's absence read directly out of the server's own response — the response
              was received and the header/attribute is not in it
plausible:    an otherwise-contained bug in this application reaching further, because the layer
              that would have limited it is not present
unverified:   any concrete compromise — a missing control is not itself an exploit and must not be
              reported as one
```

The second half of the `demonstrated` sentence is only true because Q-097 landed first. The three
tickets are one defect seen from three angles.

### MEASURED

```
tests/test_impact_binds_to_family.py   FFF...  ->  ......
```
RED at HEAD reproduced the field text verbatim:

```
AssertionError: a missing-header finding claims a demonstrated file exposure:
  'Confirmed on this target: a sensitive file/resource served directly over the web
   (a control path 404s)'
```

With `test_asvs_transport_config_objective`, `test_asvs_model` and `test_transport_posture`: EXIT=0.
The three tests that passed at HEAD and still pass are the controls that keep the fix honest — a
genuine `family: "exposure"` finding still emits that exact line in a rendered markdown report, a
finding with no family still resolves through its CWE, and a family that already resolved is
untouched.

### Not fixed, reported

`transport_posture`-family findings (TLS/certificate) still get no impact block at all: their CWEs
(295/297/326/327) map to `weak_ssh_crypto`, which is in neither table. That is missing text rather
than false text, so it is out of this ticket's scope and left for a separate one.
