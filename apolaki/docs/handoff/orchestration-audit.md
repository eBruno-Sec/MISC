# Orchestration Audit: are all 112 tools actually working and orchestrated?

ARCHITECT lane, read-only on code. Every claim below is either MEASURED (command + real
output quoted) or explicitly marked UNVERIFIED.

Method note that shapes everything here: a ledger zero has THREE indistinguishable
meanings -- the target is clean, the engine is broken, or the engine was never handed a
target. Five engines were traced today to an UPSTREAM cause and none of them to the
engine itself. So no row below is allowed to say "dead" on ledger evidence alone.

STATUS: COMPLETE for the buckets below. Six orchestration defects (A-F) established, one
hypothesis (a fourth query-string collapse) DISPROVED and recorded as such in 0.3.

Read `0.3.1` before trusting any number: `/app` in `apolaki-agent-1` is BAKED, not
bind-mounted, and it lagged HEAD partway through this audit.

Scope honesty: 29 of 112 rows remain UNRESOLVED (section 2.4). I did not establish which
of the three meanings their zeros carry, and they are listed rather than quietly counted
as clean.

---

## 0. THE PART I WOULD MOST REGRET LOSING: engines that CANNOT FIRE

32 of 112 registry tools have never been selected in any of the 180 missions that
produced at least one tool result. Measured by `scripts/tool_ledger.py` run inside
`apolaki-agent-1` (the container holding the real `/app/data/bbh.db` volume):

    MSYS_NO_PATHCONV=1 docker exec -i apolaki-agent-1 python - < scripts/tool_ledger.py

    NEVER DISPATCHED (registry, never selected in any mission): 32
       benchmark_lab, confirm_authz_write, confirm_idor, enumerate_ids, http_diff,
       http_read, list_workflows, mission_intel, mission_state, run_cloud_probe,
       run_default_creds, run_external_surface, run_hash_crack, run_ipmi_audit,
       run_jwt, run_ldap_enum, run_mass_assign, run_metadata, run_modbus_audit,
       run_nmap, run_nmap_vuln, run_ntp_audit, run_rdp_audit, run_rsync_audit,
       run_smb_enum, run_snmp_audit, run_ssh_audit, run_vnc_audit, run_whatweb,
       run_workflow, store_finding, test_numeric_abuse

Per-engine classification of this list follows in section 2. Cause analysis below.

### 0.1 DEFECT A -- the entire non-web service tier is STARVED by a same-host assumption

13 of the 32 never-dispatched tools are the network/service audit engines. They are NOT
broken. MEASURED by calling them by hand against the bench service hosts:

    MSYS_NO_PATHCONV=1 docker exec -i apolaki-agent-1 python - <<'PY'
    import asyncio, sys; sys.path.insert(0,'/app')
    import scope as S, tools
    sc = S.ScopeEngine(); sc.load_manual(["openldap","smb","conpot","dnp3-outstation"], [], "T")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    ... reg._run_service_pack({"host":host,"port":port,"service":svc})
    PY

    == openldap 389 ldap  err= None findings= 1
         medium LDAP allows anonymous directory read (openldap:389)
    == smb 445 smb        err= None findings= 2
         high   SMB allows null-session share enumeration (smb:445)
         medium SMB message signing not required (smb:445)
    == dnp3-outstation 20000 dnp3 err= None findings= 1
         high   Unauthenticated DNP3 industrial device reachable

Four real findings, two of them HIGH, from engines the ledger reports as never
dispatched. The engines are correct; the dispatcher never hands them a host.

CAUSE, quoted from `agent/agent.py` `_run_service_packs` (around line 2153):

    host = (_up(base).hostname if base else "") or recon.get("target") or recon.get("domain") or ""
    if not host or not self.scope.validate(host)[0]:
        return events
    ...
    async def _open(p):
        r, w = await _aio.wait_for(_aio.open_connection(host, p), timeout=1.5)

`host` is a SINGLE hostname derived from the PRIMARY WEB BASE. Every port in the sweep
is probed against that one host. A mission against `http://mutillidae` probes
`mutillidae:389`, `mutillidae:445`, `mutillidae:20000` -- all closed, because on this
bench (and on any real engagement with separate infrastructure hosts) the non-web
services live on DIFFERENT hosts that are in scope. The other in-scope assets are never
swept. This is the same shape as the `index.php?page=` collapse: the engine is fine, the
target selection discards the surface.

### 0.2 DEFECT B -- three UDP service engines can never be reached on the fallback path

Same function, the port list:

    probe = [p for p in (21, 22, 23, 25, 53, 102, 110, 143, 389, 445, 502, 873, 1433, 1521, 2049,
                         2375, 3306, 3389, 5432, 5900, 5985, 6379, 9200, 11211, 20000, 27017,
                         44818, 47808) if p not in known]

MEASURED: `service_router.fingerprint` knows all three of the missing ports --

    161 -> snmp        623 -> ipmi        123 -> ntp

but 161, 623 and 123 are absent from `probe`, and the sweep uses
`asyncio.open_connection`, which is TCP-only and cannot detect a UDP service even if the
port were listed. So `run_snmp_audit`, `run_ipmi_audit` and `run_ntp_audit` are reachable
ONLY via `parse_nmap_ports(recon["nmap"]["open_ports"])` -- i.e. only if nmap seeded them
first. And `run_nmap` is itself in the NEVER DISPATCHED list. Both doors are shut.

Note the comment block directly above `probe` documents this exact class of bug being
fixed once for the ICS/OT ports ("it omitted every industrial port ... silently
unreachable on the fallback path they were supposed to be guaranteed by"). The UDP three
were not caught by that pass.

### 0.3 DISPROVED -- there is NO fourth collapse point in the graph layer

I hypothesised a fourth query-string collapse in `asset_graph`, on top of the three
closed today (Q-172 `surface.build_inventory`, Q-174 the planner's form-discovery dedupe
and its step key, Q-178 `memory_assets`). It is NOT there. Recording the disproof because
a disproved hypothesis is a result, and because the earlier draft of this file asserted
it.

What misled me: I measured a SYNTHETIC call, passing `urlparse(u).path` into
`observe("endpoint", ...)` myself. That is not what the code does. The real path builds
`path` from `surface.build_inventory`, which Q-172 changed to carry the query.

MEASURED at HEAD, on the 45 real `page=` values `http://mutillidae/` publishes:

    URLs fed in                    : 45
    surface.build_inventory entries: 46      <-- Q-172 fix, holding
      sample path: '/index.php?page=add-to-your-blog.php'
    graph endpoint nodes           : 46      <-- via build_from_engagement("T", urls=urls)
       key: mutillidae/index.php?page=add-to-your-blog.php
       key: mutillidae/index.php
       key: mutillidae/index.php?page=arbitrary-file-inclusion.php

45 in, 46 nodes out, query preserved. The graph layer is correct at HEAD. The consumer
that matters (`agent.py:3721`, `for n in g.nodes("endpoint")`, which builds the planner's
probe URL list) therefore now receives all 45 pages, not one.

RESIDUE, one callsite, LOW value and UNVERIFIED impact: `asset_graph.py:355`, inside
`ingest_intel`, still keys a harvested candidate as `p.netloc + (p.path or "/")` and so
drops the query. That path only handles intel candidates that arrive carrying a full URL,
and the Q-109 comment block above it shows the hostless/route handling there was
deliberately reasoned about. I did not measure any engine starved by it. Not worth a fix
ahead of the two real defects in 0.1 and 0.2.

### 0.3.1 MEASUREMENT INTEGRITY NOTE -- read this before trusting any number here

`/app` in `apolaki-agent-1` is NOT bind-mounted from the repo; only `/app/ui` is:

    docker inspect apolaki-agent-1 --format '{{range .Mounts}}...'
    volume  apolaki_bbh_data      -> /app/data
    bind    ...apolaki/ui         -> /app/ui
    volume  apolaki_nuclei_templates -> /root/nuclei-templates

So the agent code in that container is BAKED INTO THE IMAGE and can lag HEAD. Mid-audit I
measured a real drift (`tools.py`, `agent.py` differing from the repo), the container then
restarted and rebaked, and all five files I check now hash identical to HEAD:

    SAME  asset_graph.py   SAME  surface.py   SAME  planner.py
    SAME  tools.py         SAME  agent.py

Every measurement in this file from section 0.3 onward was taken AFTER that rebake and is
against HEAD. The by-hand engine results in 0.1 and 0.4 were taken BEFORE it, against the
older baked `tools.py` -- they show engines PRODUCING findings, so a newer `tools.py` can
only improve them, but the exact finding text is from the older build. Anyone re-running
this audit should hash-check `/app/*.py` against the repo FIRST; I lost time to that.

### 0.35 DEFECT D -- run_jwt reads two places for a token; the app hands it back in a third

`run_jwt` is NEVER DISPATCHED across all 188 missions. It is not broken. STARVED, and the
gate is exactly quotable.

GATE, `agent/planner.py:1326-1333`:

    # JWT weakness analysis (alg-confusion / weak-secret / kid) - only when the scan
    # carries a bearer/JWT token (authed runs); harmless no-op on unauth scans.
    _blob = (_json.dumps(state.get("auth_headers") or {})
             + _json.dumps(state.get("recon", {}).get("cookies") or {}))
    _jm = _re.search(r"(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", _blob)
    if _jm:
        e_steps.append(_step("run_jwt", {"token": _jm.group(1)}, "run_jwt"))

The token is searched for in exactly two places: operator-supplied `auth_headers`, and
`recon.cookies`. It is NOT searched for in RESPONSE BODIES.

Why that matters here, MEASURED. Apolaki's own confirmed Juice Shop SQLi auth bypass
returns a JWT in the response body:

    POST http://juice-shop:3000/rest/user/login  {"email":"' OR 1=1--","password":"x"}
    status: 200
    JWT in RESPONSE BODY: YES
    token[:40]: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ ...

So the pipeline confirms a CRITICAL auth bypass, is handed a JWT as the prize, and the
JWT engine never sees it. The comment's "harmless no-op on unauth scans" is true and is
also the trap: nearly every mission is an unauth scan, and the one moment a token DOES
appear is the moment the gate is not looking.

And the engine works. Handed that exact live token:

    reg._run_jwt({"token": <717-char live juice-shop token>})
    run_jwt err= None findings= 1
        high | JWT uses RS256 - test algorithm confusion (RS->HS)

A HIGH finding, from an engine with 0 dispatches in 188 missions. Fix is to widen the
blob the regex scans to include harvested response bodies / captured Authorization
headers, which the scan already collects.

### 0.36 DEFECT E -- run_mass_assign needs a media type only OpenAPI ever records

`run_mass_assign` is NEVER DISPATCHED in 188 missions. It CHANGES STATE, it is the engine
`asvs_model.py` declares verifiable and `wstg_catalog.py` rides WSTG-INPV-20 on, and it
works. STARVED.

GATE, `agent/planner.py:1291-1306`:

    for fm in sorted((state.get("recon", {}).get("forms") or []), key=_form_value, reverse=True):
        act = fm.get("action"); meth = str(fm.get("method") or "").upper()
        if not act or act in ma_seen or meth not in _WRITE_METHODS:   continue
        if not _is_json_ct(fm.get("content_type")):                   continue
        bparams = [p for p in (fm.get("body_params") or []) if isinstance(p, dict) and p.get("name")]
        if not bparams:                                               continue

Two of those conditions can only be satisfied by an OpenAPI spec. MEASURED by reading
both HTML form producers -- `agent.py:_harvest_rendered_forms` (line ~4280) and
`tools.py` form capture (line ~4895). Both append exactly:

    {"action": act, "method": "POST", "fields": [...], "page": page_url}

No `content_type`. No `body_params`. So `_is_json_ct(None)` is False and the loop
`continue`s on every HTML-discovered form, forever. The code KNOWS this and says so at
`agent.py:3826`: "Only the spec producer records one (an HTML form posts urlencoded and
`_project_form_params` writes none)". That is a deliberate choice made to avoid an
always-fires false positive, and it is correct -- but it leaves the engine reachable ONLY
through `fetch_openapi` -> spec params -> `_graph_rebuilt_forms`, a chain that has never
completed in a recorded mission.

The engine is fine. MEASURED against VAmPI, first proving the target vulnerable BY HAND:

    POST /users/v1/register {"username":"arch50870",...,"admin":true}  -> 200 success
    GET  /users/v1/_debug -> arch50870 admin= True          <-- hand-proven vulnerable

then the engine itself:

    reg._run_mass_assign({"url":"http://vampi:5000/users/v1/register","method":"POST",
                          "body":<base json>, "read_url":".../users/v1/_debug"})
    mass_assign err= None findings= 1
        high | Mass assignment -- the request body binds the privileged attribute 'admin'

Incidental corroboration in the same `_debug` dump: `apolaki_ma_bf072fe93762... admin=
True`. That is this engine's own canary username, so it has succeeded against VAmPI
before -- outside any recorded mission. The capability is real and the dispatcher is the
only thing missing.

### 0.37 DEFECT F -- the whole investigative tier is model-only, and the model never drives it

The SYSTEM_PROMPT devotes its longest section to "INVESTIGATIVE TESTING (you are an
operator, not just a scanner runner)" -- acquire_session, http_read, http_diff,
http_request, confirm_idor, enumerate_ids, browser_navigate, test_numeric_abuse, and
store_finding. That entire tier is unreachable to the deterministic planner.

MEASURED, by diffing registry tool names against every literal `planner.py` can name:

    registry tools parsed              : 77
    NOT NAMEABLE by deterministic planner : 23
       acquire_session, benchmark_lab, browser_navigate, confirm_create_object_idor,
       confirm_idor, enumerate_ids, http_diff, http_read, http_request, list_workflows,
       mission_intel, mission_state, run_cloud_probe, run_external_surface,
       run_hash_crack, run_hash_id, run_jsonp, run_metadata, run_nmap, run_whatweb,
       run_workflow, store_finding, test_numeric_abuse

Cross-referenced against the ledger, the tier's lifetime totals across 188 missions:

    store_finding        0 runs        confirm_idor        0 runs
    enumerate_ids        0 runs        http_read           0 runs
    http_diff            0 runs        test_numeric_abuse  0 runs
    acquire_session      5 runs, always zero
    http_request         1 run,  always zero
    browser_navigate     1 run,  always zero
    confirm_read_object_idor / confirm_create_object_idor  1 run each, always zero

`confirm_idor` is the documented IDOR/BOLA ORACLE and IDOR/BOLA is the FIRST entry in the
prompt's PRIORITY VULN CLASSES. It has never executed. An AI key IS configured
(`ai_status()` -> ready True, provider openrouter, model `openrouter/free`), so this is
not a missing-key failure; the model simply is not driving these loops in practice.

Mitigating fact, so this is not overstated: BOLA coverage is not zero, because
deterministic equivalents exist and DO fire -- `run_bfla` is PROVEN (122/517 across 32
missions), and `run_authz_matrix` and `confirm_browser_persona_bola` each have a proven
run. The loss is the model-driven chaining loop, not the vulnerability class.

### 0.4 The engines starved by DEFECT C are provably fine

`run_form_cmdi` is the ledger's 428-runs-always-zero row. Handed the page that DEFECT C
discards, it confirms a CRITICAL on the first try. MEASURED:

    reg._run_form_cmdi({"url": "http://mutillidae/index.php?page=dns-lookup.php"})
    form_cmdi err= None findings= 1
        critical OS command injection (output) in 'target_host'

Ground truth for that page, verified independently first so the engine was calibrated
against a target proven vulnerable BY HAND:

    POST /index.php?page=dns-lookup.php  target_host=127.0.0.1;id
    status 200 len 52336
    UID HITS: ['uid=33(www-data)']

---

## 1. Census baseline (MEASURED)

    registry: 112 tools, across 180 missions with at least one tool result
    PROVEN (non-zero at least once, anywhere):  49 of 112
    ZERO-ONLY (ran, never once produced):       31
    ERROR-ONLY (never produced a result row):    0
    NEVER DISPATCHED:                           32

Bench health at audit time, `scripts/labs_health.py` inside the agent container:
all 10 labs ALIVE (juice-shop, mutillidae, bwapp, dvwa, webgoat, vampi, dvga,
clientauthz, domsource, wordpress).

Also measured: 5 names appear in mission tool results that are NOT in the registry --
`agent:_probe_for_creds:2893`, `cURL Console`, `codeintel.review_source_tree`,
`graph_primary_state.hostless_endpoint`, `tools:probe:4844`. These are the census
naming something the registry does not; they are not engines and are noted only so the
112 vs 117 discrepancy is not read as a missing tool.

---

## 2. PER-ENGINE DISPOSITION

Buckets are the five the operator asked for. Counts are over the 112-tool registry.

    PROVEN         49     non-zero at least once in a real mission (ledger, mission ids printed)
    STARVED        15     engine works BY HAND against a hand-proven target; never given one
    UNREACHABLE    17     the deterministic planner cannot name it; gate quoted below
    CORRECT-ZERO    2     ran against a target that genuinely lacks the bug, cause established
    BROKEN          0     none confirmed this audit
    UNRESOLVED     29     ZERO-ONLY, cause NOT established -- see 2.4, these are NOT "clean"

### 2.1 STARVED (15) -- orchestration defects, each proven by hand

Every row here was proven twice: the TARGET was shown vulnerable by hand first, then the
ENGINE was called by hand against it.

| engine | ledger | hand-run result | starved by |
|---|---|---|---|
| run_form_cmdi | 428 runs / 41 missions, always zero | `critical` OS command injection in 'target_host' | DEFECT C (fixed at HEAD by Q-172/174) |
| run_jwt | 0 dispatches / 188 missions | `high` JWT uses RS256 - alg confusion | DEFECT D, planner.py:1326 |
| run_mass_assign | 0 dispatches / 188 missions | `high` body binds privileged attribute 'admin' | DEFECT E, planner.py:1297 |
| run_service_pack | 5 runs / 4 missions, always zero | see 3 rows below | DEFECT A, agent.py:2153 |
| run_ldap_enum | 0 dispatches | `medium` LDAP anonymous directory read (openldap:389) | DEFECT A |
| run_smb_enum | 0 dispatches | `high` SMB null-session share enum + `medium` no signing (smb:445) | DEFECT A |
| run_modbus_audit (dnp3 sibling) | 0 dispatches | `high` unauthenticated DNP3 device (dnp3-outstation:20000) | DEFECT A |
| run_ssh_audit | 0 dispatches | not individually run; same pack path as the three above | DEFECT A |
| run_vnc_audit | 0 dispatches | not individually run; same pack path | DEFECT A |
| run_rsync_audit | 0 dispatches | not individually run; same pack path | DEFECT A |
| run_rdp_audit | 0 dispatches | not individually run; same pack path | DEFECT A |
| run_default_creds | 0 dispatches | not individually run; same pack path | DEFECT A |
| run_snmp_audit | 0 dispatches | UNVERIFIED by hand | DEFECT A + DEFECT B (UDP 161 absent) |
| run_ntp_audit | 0 dispatches | UNVERIFIED by hand | DEFECT A + DEFECT B (UDP 123 absent) |
| run_ipmi_audit | 0 dispatches | UNVERIFIED by hand | DEFECT A + DEFECT B (UDP 623 absent) |

Honest scoping of that table: 6 of the 15 were confirmed by executing the engine itself
(`run_form_cmdi`, `run_jwt`, `run_mass_assign`, and the ldap/smb/dnp3 packs). The other 9
ride the SAME dispatch path that I proved works, and are starved by the same named gate;
I did not execute each one, and the table says so.

### 2.2 UNREACHABLE (17) -- the planner cannot name them

MEASURED by diffing registry names against every string literal in `planner.py`. These
have 0 or ~1 lifetime dispatches AND cannot be scheduled deterministically, so they are
reachable only if the model chooses them:

    benchmark_lab, confirm_idor, confirm_authz_write, enumerate_ids, http_diff, http_read,
    list_workflows, mission_intel, mission_state, run_cloud_probe, run_external_surface,
    run_hash_crack, run_metadata, run_nmap, run_whatweb, run_workflow, store_finding,
    test_numeric_abuse

(`confirm_authz_write` is in the never-dispatched ledger list; the other 22 non-nameable
names include a few that DO fire occasionally via internal forwarding -- `run_hash_id`,
`run_jsonp`, `acquire_session`, `browser_navigate`, `http_request`,
`confirm_create_object_idor`, `confirm_read_object_idor` -- so they are counted in 2.4,
not here.)

The gate is not a condition, it is an absence: no code path in the deterministic planner
emits these steps. See DEFECT F in section 0.37.

### 2.3 CORRECT-ZERO (2) -- established, with the reason

`run_upload_test` -- 408 runs / 41 missions, always zero. I nearly filed this as BROKEN.
The target IS vulnerable to the extent that it accepts a `.php` upload with no extension
filter (MEASURED: `upload status: 200 | .php accepted: True`). But the file is never
stored. The same response carries mutillidae's own error:

    File     /app/upload-file.php
    Message  Error Detected. Unable to move PHP temp file to permanent location /arch7e5f3885.php

The upload directory is misconfigured -- it is trying to write to filesystem root. No
file is ever persisted, so nothing is retrievable and no CWE-434 can be honestly
confirmed. The engine declining to claim is CORRECT behaviour, and its zero is a LAB
BENCH DEFECT, not an engine defect. This is the same shape as the offline dalfox/sqlmap
databases: fix the lab, then re-measure the engine.

`run_waf_bypass` -- 1467 runs / 48 missions, always zero. No lab on this bench runs a WAF,
so there is nothing to bypass. Zero is the correct answer on every target it has ever
been given. It has never had a positive control, so its correctness is UNVERIFIED even
though its zero is explained.

### 2.4 UNRESOLVED (29) -- ZERO-ONLY with the cause NOT established

This is the bucket the operator's framing exists for, and I am not going to pretend it is
smaller than it is. These ran, never produced, and I could not establish WHICH of the
three meanings applies. They must not be read as "the target was clean".

The four most expensive, all fired at the whole surface by `_SWEEP_HTTP_ENGINES`
(`agent.py:356`):

    run_ssi              1995 runs / 48 missions, always zero
    run_css_injection    1467 runs / 48 missions, always zero
    run_sqli_structural  1467 runs / 48 missions, always zero
    run_waf_bypass       1467 runs / 48 missions, always zero   (explained, see 2.3)

MEASURED negative control for `run_sqli_structural`: against a URL I first proved
SQL-injectable by hand --

    baseline len: 53357  injected len: 60787
    injected 'Username=' count: 23        <-- 23 accounts dumped, SQLI CONFIRMED: True

    _run_sqli              err=None findings=2   high | SQL injection (error-based) in 'username'
    _run_sqli_structural   err=None findings=0
    _run_waf_bypass        err=None findings=0
    _run_css_injection     err=None findings=0

`run_sqli` confirms it twice. `run_sqli_structural` finds nothing on a confirmed SQLi.
That does NOT prove it broken -- "structural" is plausibly a distinct sub-class
(UNION/column-count shaped) that this error-based case does not exercise -- but it does
mean the engine has no positive control anywhere on this bench and 1467 runs of no
evidence. It needs a target built for it, or it needs deleting from the sweep.

COST, and this is why the sweep matters. The per-URL wall clock is already measured in
`agent.py:220-222`:

    run_waf_bypass 0.09   run_sqli_structural 0.07   run_ssi 0.06   run_css_injection 0.03

= 0.25 s per URL across the four, against 1.70 s per URL for all eight sweep engines
together. So 14.7% of the HTTP sweep's wall clock goes to four engines that have produced
nothing in 48 missions. At the current 700-URL cap that is ~175 s per mission.

The remaining 25 unresolved rows, for the record: run_form_nosqli (1210), run_nosqli
(573), run_github_recon (533), check_takeover (169), run_nuclei (160), run_session_token
(159), run_path_sqli (113), run_nosqli_body (84), run_cache_poison (72), run_llm_probe
(68), run_stored_xss (33), run_cache_deception (24), run_jsonp (20), run_username_enum
(17), run_ffuf (9), run_session_lifecycle (6), acquire_session (5), run_session_fixation
(5), browser_navigate (1), confirm_create_object_idor (1), confirm_read_object_idor (1),
http_request (1), run_cmdi (1), run_saml (1).

IMPORTANT on `run_nuclei`: its 160/121 zero row is HISTORICAL. The `-json` -> `-jsonl`
fix landed at HEAD after those missions ran. The ledger cannot show the fix until new
missions execute it; do not read that row as current.

### 2.5 PROVEN (49)

Unchanged from the ledger census in section 1; `scripts/tool_ledger.py` prints the mission
ids per tool and is the checkable record. Highest-confidence rows by breadth are
`http_probe` (7881 runs / 157 missions), `run_fingerprint` (3286/151), `run_katana`
(262/148), `run_sqli` (159 producing runs / 61 missions), `run_bfla` (122/32).

---

## 3. THE THREE DEFECTS TO FIX FIRST, RANKED BY COVERAGE UNLOCKED

### RANK 1 -- DEFECT A: sweep every in-scope host for services, not just the web host

Unlocks 15 engines (the entire STARVED table). Currently 13.4% of the registry cannot
fire on any engagement whose non-web services live on a different host than the web app --
which is every real engagement and this whole bench. Proven by hand to yield 2 HIGH and 2
MEDIUM findings in a single pass.

`agent/agent.py`, `_run_service_packs`, around line 2166. NOT APPLIED (read-only lane):

    - host = (_up(base).hostname if base else "") or recon.get("target") or recon.get("domain") or ""
    - if not host or not self.scope.validate(host)[0]:
    -     return events
    + hosts = [h for h in dict.fromkeys(
    +     ([_up(base).hostname] if base else [])
    +     + list(recon.get("live_hosts") or [])
    +     + [recon.get("target"), recon.get("domain")])
    +     if h and self.scope.validate(h)[0]]
    + if not hosts:
    +     return events

then fan the existing `_open`/`services.append` sweep over `hosts` instead of `host`,
keeping the same bounded semaphore. Every scope and HITL gate stays where it is; this
changes only WHICH in-scope hosts get swept.

### RANK 2 -- DEFECT F: give the investigative tier a deterministic path

Unlocks 17 engines (the UNREACHABLE table), including `confirm_idor`, the documented
oracle for the vuln class the system prompt ranks FIRST, which has never executed in 188
missions. This is the largest single block of registry that a deterministic mission can
never touch.

The fix is not one diff. The honest recommendation is to pick the three highest-value
primitives -- `confirm_idor`, `http_read`, `http_diff` -- and give the planner a step that
emits them whenever the graph holds an `object` node (it already computes exactly that set:
`asset_graph.py:466`, `for o in self.untested("object")`, which today emits only the
advisory `cross_user_test` action with no executor behind it). That closes the loop
between a planner tier that already exists and engines that already exist.

### RANK 3 -- DEFECT D + DEFECT E: two one-line-ish gates, two HIGH-yielding engines

Unlocks 2 engines, both proven to produce HIGH findings by hand, both cheap.

DEFECT D, `agent/planner.py:1329` -- widen where the JWT is looked for so the token the
scan already receives in a response body is seen:

      _blob = (_json.dumps(state.get("auth_headers") or {})
               + _json.dumps(state.get("recon", {}).get("cookies") or {})
    +          + _json.dumps(state.get("recon", {}).get("bodies") or [])[:200000]
    +          + _json.dumps(state.get("recon", {}).get("captured_headers") or {}))

UNVERIFIED: I did not confirm the exact key names for harvested bodies/captured headers;
whoever applies this must point it at whatever the harvest actually populates. The
MEASURED part is that a live juice-shop JWT arrives in the login RESPONSE BODY and that
`run_jwt` returns `high` when handed it.

DEFECT E, ROOT CAUSE NOW MEASURED -- `surface.operations_from_openapi` drops the
requestBody schema.

The gate at `planner.py:1297` requires BOTH a JSON media type AND non-empty `body_params`:

    if not _is_json_ct(fm.get("content_type")):                    continue
    bparams = [p for p in (fm.get("body_params") or []) if isinstance(p, dict) and p.get("name")]
    if not bparams:                                                continue

The media-type half WORKS. MEASURED against vampi's real spec:

    operations parsed     : 14
    ops WITH content_type : 5
        POST /books/v1              | ct= application/json | body_params= 0
        POST /users/v1/login        | ct= application/json | body_params= 0
        POST /users/v1/register     | ct= application/json | body_params= 0
        PUT  /users/v1/{username}/email | ct= application/json | body_params= 0

`POST /users/v1/register` is the exact endpoint I proved mass-assignable by hand. It gets
past the media-type check and is then killed by `body_params = 0` -- on every one of the
five.

And the spec is NOT at fault. It declares the properties plainly:

    requestBody.content["application/json"].schema.properties
        email    {type: string, example: user@tempmail.com}
        password {type: string, example: pass1}
        username {type: string, example: name1}

So `operations_from_openapi` parses the media type out of `requestBody.content` and does
not walk one level further into `.schema.properties` to emit `body_params`. That single
omission is what makes `run_mass_assign` unreachable even against a target that serves a
perfect spec and is genuinely vulnerable. It is the whole chain's load-bearing gap, and it
is upstream of the gate -- the gate itself is correct and must NOT be weakened (defaulting
the media type to JSON is the always-fires failure the code comment warns about).

Fix location: `agent/surface.py`, `operations_from_openapi`. Emit one `body_params` entry
per `schema.properties` key, in the shape `_graph_rebuilt_forms` already expects and
`mass_assign_tool.body_from_params` already reads:

    {"name": <prop>, "location": "body", "type": <prop.type>, "required": <prop in schema.required>}

Handle OpenAPI 3 (`requestBody.content[<ct>].schema`) and Swagger 2 (`parameters[] where
in=="body"` -> `.schema`), and resolve a top-level `$ref` before reading `.properties`.
UNVERIFIED: I did not write or run this change; what is MEASURED is that 5 ops carry a
media type, 0 carry body params, and the underlying spec declares 3 properties for the
endpoint that is provably vulnerable.

### Also worth doing, cheap: DEFECT B and the lab bench

DEFECT B -- add 161, 623, 123 to the `probe` list AND give them a UDP probe, or accept
that they are nmap-only and make sure nmap runs. Three engines, currently double-gated.

LAB -- mutillidae's upload directory is unwritable, so CWE-434 has no positive control on
this bench (section 2.3). Fixing the lab is what makes `run_upload_test`'s 408 zeros
interpretable. Same class as the dalfox/sqlmap database outage already fixed today.

---

## COORDINATOR RE-VERIFICATION (2026-09-03, at HEAD after Q-182..Q-186)

I re-measured this audit's three ranked defects against a REBUILT image. Rank 1 held and is fixed.
The other two do not reproduce, and the reason is the one this audit itself flagged at 0.3.1:
`/app` is baked, not bind-mounted, and lagged HEAD while the audit ran. The warning was right and
it applied to the audit's own measurements.

RANK 1 -- same-host service sweep. CONFIRMED and FIXED (Q-182). The four findings it predicted by
hand are the four the fixed sweep produces: SMB null-session (high), SMB signing not required
(medium), LDAP anonymous read (medium), unauthenticated DNP3 (high). Same four, not a different
four, which is what makes the diagnosis a transferable one.

RANK 2 -- "the investigative tier has no executor". DOES NOT HOLD. `cross_user_test` is mapped in
`agent.BBHAgent._GRAPH_ACTION_TOOLS`:

    "cross_user_test": ("run_bfla", "url"),   # object endpoint, never compared across personas

so untested `object` nodes DO reach an executor, and `run_bfla` has produced in 29 missions. The
narrower true statement survives: `confirm_idor` -- a stronger two-identity oracle -- has never
executed and is not wired. That is a real gap and a much smaller one, and it cannot be closed
without two authenticated personas, which an unauthenticated engagement does not have.

RANK 3 -- "operations_from_openapi drops the requestBody schema". DOES NOT HOLD. MEASURED against
VAmPI's live spec at HEAD:

    POST /users/v1/register    ct=application/json   body_params=3
    POST /users/v1/login       ct=application/json   body_params=2
    PUT  /users/v1/{username}/email                  body_params=1

and the whole chain executes: the planner emits 4 `run_mass_assign` steps including
`/users/v1/register`, and the engine confirms against it --

    high  confirmed  Mass assignment -- the request body binds the privileged attribute
    evidence: POST /users/v1/register accepted an attribute 'admin' it does not offer
    fields_tried [role, isAdmin, admin, userRole]  offered [email, password, username]

One correction against MYSELF while checking Rank 3: my first attempt passed `body_params` as the
input key and got "no base body -- ... no typed OpenAPI body parameters were supplied". The planner
sends `params` and the engine reads `params`; they agree. My test was wrong, not the code, and a
tool that refuses to invent a body it was not given is behaving correctly.

WHAT THIS DOES NOT CHANGE: the audit's method and its five buckets are the right instrument, and its
refusal to fold 29 unresolved zeros into "clean" is still the most valuable judgement in the file.
A stale measurement is a measurement problem, not a reasoning problem -- and the audit is the reason
Rank 1 was found at all.
