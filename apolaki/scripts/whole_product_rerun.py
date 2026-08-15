"""Whole-product rerun: owaspbench-q019 shape, current code, SEALED before any key is touched.

Drives BBHAgent.run() -- the same full pipeline the API mission uses -- not just _execute_plan, so
this is comparable to mission ebd96f45 -- re-scored 2026-08-14 to 96.3% precision / 1.84% recall,
26 TP / 1 FP / 1415 vulnerable, seal fab8a46e over docs/benchmarks/baseline_ebd96f45_claims.json.
(It was published as 22 TP / 23 claimed / 95.7%; that count collapsed five ldapi findings into one,
and the key says all five are true positives. Deltas against the old figure understate the loss.)

Writes /out/wp_claims.json and prints the SEAL (sha256 over the sorted distinct case ids). The key is
NOT read here and must not be read until the seal is recorded.

WHY THE EFFORT RECORD EXISTS (2026-08-14, breaker lane)
-------------------------------------------------------
The 2026-08-13 rerun lost 9 sqli cases against the baseline and the artifact could not say whether
the run had probed less or found less: it recorded findings and elapsed seconds and nothing about
how much work was done. Answering "did it converge or did it run out of budget?" needed the run
repeated. That is the expensive way to learn something the run already knew.

So every run now also records EFFORT and COVERAGE:

  effort.plan_steps      BBHAgent._plan_steps -- deterministic planner steps actually executed
  effort.step_cap        the MAX_STEPS literal, parsed out of agent.py at runtime so it cannot
                         silently drift away from this file
  effort.exit_reason     step_cap_exhausted | planner_fixpoint | degraded | stopped
  effort.tool_calls      every tool dispatch, counted by tool name
  effort.events          every event yielded by run(), counted by type
  coverage.probe_targets distinct URLs dispatched to each injection/probe tool
  coverage.cases_probed  distinct BenchmarkTest ids the run actually SENT a payload at

`cases_probed` vs `claims` is the whole discrimination: cases probed but not claimed = the oracles
saw them and said no; cases never probed = the sweep never got there. One number separates an oracle
regression from a coverage regression, and it costs nothing to record.

KNOWN BOUND ON THE COUNT, stated rather than left to be discovered: this reads the event stream, so
it sees every dispatch that goes through `BBHAgent._run_tool` (the planner batch, the graph actions
and the planner-independent sweep at agent.py:3424 all do). Dispatches made through
`_exec_internal` -- the auth artery and the service sweep -- yield no `tool_call` event and are NOT
counted here. `cases_probed` is therefore a LOWER bound on coverage, which is the safe direction:
it can never claim a case was tested when it was not.

The SEAL is unchanged -- sha256 over the sorted distinct claimed case ids -- so artifacts from
before this change stay comparable.

WHY THE ATTRIBUTION RECORD EXISTS (2026-08-14, selection lane)
--------------------------------------------------------------
The effort record answers "how much work" but not "which consumer spent it". Run A's census --
3659 tool calls against 309 plan steps -- already implies that most of the budget is dispatched
somewhere other than the planner loop, but the artifact could not say where, so "raise the step
cap" and "change what fills the steps" could not be told apart from the artifact alone.

So every run now ALSO records, per tool AND per phase:

  effort.phase_calls     tool dispatches attributed to the pipeline phase that made them
  effort.phase_seconds   wall clock inside each phase (tool time only -- see below)
  effort.tool_seconds    wall clock per tool, summed over its dispatches
  coverage.cases_by_tool distinct case ids each tool sent a payload at
  coverage.cases_by_phase       ... and the same per phase
  coverage.first_prober  case -> the FIRST tool that probed it, so a tool's UNIQUE contribution
                         (cases no other tool reached) is computable, not guessed
  effort.planner_batches every planner.next_batch return size, in order

HOW THE PHASE IS KNOWN, and what that costs. The phase is a STACK maintained by wrapping the
async-generator methods of BBHAgent by name (`_execute_plan`, `_inject_sweep_surface`, ...).
Wrapping preserves semantics -- each wrapper is an `async for` pass-through, so the agent's control
flow, ordering and laziness are unchanged -- and the wrappers are installed by this measurement
script only, never in the product. The agent is NOT edited to carry a phase field: an instrument
that changes the thing it measures is worth less than one that does not.

TOOL TIME IS NOT WALL TIME. `_run_tool` yields `tool_call` immediately before `tools.execute` and a
terminal event (`tool_result` / `tool_error` / `scope_block`) immediately after, so pairing them
bounds each dispatch exactly. Everything OUTSIDE a dispatch -- the crawl's `tools.execute` calls,
graph projection, report assembly -- is not in `tool_seconds`, so the phase seconds sum to LESS
than elapsed. `effort.unattributed_s` records the difference rather than hiding it.
"""
import asyncio
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, "/app")
os.environ.setdefault("BBH_DATA_DIR", "/tmp/wpdata")

import agent as agent_mod
import scope as scope_mod
import tools as tools_mod

TARGET = os.environ.get("WP_TARGET", "https://owaspbench:8443/benchmark/")
MODE = os.environ.get("WP_MODE", "active")
CASE_RE = re.compile(r"(BenchmarkTest\d{5})", re.I)

# Tools that actually deliver a payload. A case that appears here was TESTED; a case that does not
# was never reached, and the difference is the whole point of the coverage record.
# Names verified against tools.py's registry, not guessed -- a typo here would silently record
# zero coverage for a tool that ran, which is the failure this record exists to prevent.
PROBE_TOOLS = {
    "run_sqli", "run_auth_sqli", "run_path_sqli", "run_sqli_structural", "run_sqlmap",
    "run_xss", "run_form_xss", "run_stored_xss", "run_dalfox",
    "run_ldap", "run_xpath", "run_cmdi", "run_form_cmdi", "run_ssi", "run_ssrf", "run_xxe",
    "run_nosqli", "run_form_nosqli", "run_nosqlmap", "run_deserialization",
    "run_web_probes", "run_injection_probes", "run_dom_audit", "run_dom_trace",
    "run_css_injection", "run_race", "run_upload_test",
}


def case_ids(rec):
    blob = " ".join(str(rec.get(k, "")) for k in
                    ("title", "target", "evidence", "description", "request", "poc", "impact"))
    return {m.group(1) for m in CASE_RE.finditer(blob)}


def step_cap():
    """The planner's hard step budget, read from agent.py rather than duplicated here.

    Returns None when the literal cannot be found, which is itself worth recording: an exit reason
    derived from a stale constant would be worse than no exit reason at all.

    READS THE ORIGINAL, NOT THE WRAPPER (2026-08-14). `install_phases` replaces
    `BBHAgent._execute_plan` with a pass-through wrapper, and `inspect.getsource` on the wrapper
    finds no `MAX_STEPS` -- so calling this AFTER instrumentation silently returned None and the
    baseline artifact recorded `step_cap: None, exit_reason: unknown`. The instrument had broken the
    one field the run was instrumented to explain. `_ORIGINALS` keeps the pre-wrap callables so the
    source read is of the real method whenever this is called; `main` additionally reads the cap
    BEFORE installing anything and fails loudly if it cannot.
    """
    try:
        import inspect
        fn = _ORIGINALS.get("_execute_plan") or agent_mod.BBHAgent._execute_plan
        src = inspect.getsource(fn)
        m = re.search(r"MAX_STEPS\s*=\s*(\d+)", src)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def check_probe_tools():
    """Fail LOUDLY at startup if a PROBE_TOOLS name is not a real registered tool.

    A typo here would silently record zero coverage for a tool that ran, and the whole point of
    the coverage record is that "never probed" and "probed and declined" are different facts. A
    guard that checks a declaration instead of a fact is worse than none, so this checks the live
    registry, not a copy of the list.
    """
    import tools as _t
    known = set(_t.TOOL_PERMISSIONS) | {str(t.get("name")) for t in (_t.CLAUDE_TOOLS or [])}
    missing = sorted(PROBE_TOOLS - known)
    if missing:
        raise SystemExit("PROBE_TOOLS names not present in the tool registry: %s" % missing)
    return len(known)


# ── PHASE ATTRIBUTION ────────────────────────────────────────────────────────────────────────
# The pipeline phases whose dispatch cost we want told apart. Order is documentation only; the
# stack is what decides. Every name is checked against the class at startup (see install_phases)
# so a rename in agent.py fails loudly here instead of silently attributing its calls to "other".
PHASE_METHODS = [
    # BBHAgent.run(), in call order
    ("_surface_crawl", "recon.crawl"),
    ("_recon_code_intelligence", "recon.codeintel"),
    ("_run_service_packs", "recon.service_packs"),
    ("_do_transport_posture", "recon.transport"),
    ("_do_header_trust", "recon.header_trust"),
    ("_do_saml", "recon.saml"),
    ("_acquire_scan_auth", "recon.auth"),
    # _run_deterministic()
    ("_browser_harvest_surface", "browser_harvest"),
    ("_execute_plan", "planner"),
    ("_promote_leads", "planner.promote_leads"),
    ("_inject_sweep_surface", "sweep"),
    # post-scan, back in run()
    ("_probe_cloud_storage", "post.cloud"),
    ("_technique_advisor", "post.technique_advisor"),
    ("_close_autonomy_loop", "post.autonomy"),
    ("_validate_candidates", "post.validate_candidates"),
    ("_triage", "post.triage"),
]

_PHASE_STACK = ["boot"]
# pre-wrap callables, kept so anything that reads a method's SOURCE still sees the real one
_ORIGINALS: dict = {}


def _phase():
    return _PHASE_STACK[-1]


def install_phases(cls):
    """Wrap the named methods so the CURRENT pipeline phase is knowable at every yielded event.

    Pass-through wrappers only: an async generator is re-yielded item by item and a coroutine is
    awaited, so ordering, laziness and exceptions are unchanged. Returns the names actually
    wrapped; raises on a name that does not exist, because an attribution silently falling back to
    "other" is the failure mode this record exists to prevent.
    """
    import inspect
    missing = [n for n, _ in PHASE_METHODS if not hasattr(cls, n)]
    if missing:
        raise SystemExit("PHASE_METHODS names not found on BBHAgent: %s" % missing)
    wrapped = []
    for name, label in PHASE_METHODS:
        orig = getattr(cls, name)
        _ORIGINALS.setdefault(name, orig)
        if inspect.isasyncgenfunction(orig):
            def mk(orig=orig, label=label):
                async def gen(self, *a, **kw):
                    _PHASE_STACK.append(label)
                    try:
                        async for ev in orig(self, *a, **kw):
                            yield ev
                    finally:
                        _PHASE_STACK.pop()
                return gen
        elif inspect.iscoroutinefunction(orig):
            def mk(orig=orig, label=label):
                async def coro(self, *a, **kw):
                    _PHASE_STACK.append(label)
                    try:
                        return await orig(self, *a, **kw)
                    finally:
                        _PHASE_STACK.pop()
                return coro
        else:
            raise SystemExit("PHASE_METHODS entry %r is neither async gen nor coroutine" % name)
        setattr(cls, name, mk())
        wrapped.append(label)
    return wrapped


def install_planner_census(batches):
    """Record every planner.next_batch return size, in order, plus the LAST state it was given.

    The state dict holds live references (`done` is the executor's own set), so after the run the
    captured state reflects the final world -- which is what lets `would_schedule_more` be asked
    without a second full run. It is an ESTIMATE and is labelled as one: the graph-derived roots
    and urls are a snapshot from the last call, not from a re-projection.
    """
    import planner as _p
    orig = _p.next_batch
    holder = {"orig": orig}

    def wrapped(state):
        out = orig(state)
        batches.append(len(out or []))
        holder["state"] = state
        return out

    _p.next_batch = wrapped
    return holder


def install_rate_census(census):
    """Count what the target-rate policy actually did, so "more probing is not more pressure" is a
    measurement rather than an assertion.

    Every request the engines make goes through `_target_client`, which is bound to this same
    singleton, so a run that adds an engine adds requests that pass the SAME gate. What the
    artifact could not say is whether the gate ever engaged. `observe` returns a delay only for a
    limiting status with a usable Retry-After; `wait_async` returns the seconds actually slept.
    Both are recorded, and a run where `cooldowns` is 0 means the target never asked us to slow
    down -- which is a different and weaker claim than "we honoured it", and is labelled as such.
    """
    import browser_engine as _be
    pol = _be.target_rate_policy
    orig_obs, orig_wait = pol.observe, pol.wait_async

    def observe(url, status, headers):
        out = orig_obs(url, status, headers)
        census["observed"] = census.get("observed", 0) + 1
        if out is not None:
            census["cooldowns"] = census.get("cooldowns", 0) + 1
            census["cooldown_s"] = round(census.get("cooldown_s", 0.0) + float(out), 2)
        return out

    async def wait_async(url):
        waited = await orig_wait(url)
        if waited:
            census["waited_s"] = round(census.get("waited_s", 0.0) + float(waited), 2)
            census["waits"] = census.get("waits", 0) + 1
        return waited

    pol.observe = observe
    pol.wait_async = wait_async


def install_sweep_census(census):
    """Record how many targets `sweep_targets` HAD to choose from, and how many it kept.

    `cases_probed` says what was reached; it cannot say what was available, so "400 of 400" and
    "400 of 2100" are indistinguishable in the artifact -- and they are opposite facts about
    whether the cap binds. `sweep_targets` is pure and cheap (a list walk over the surface), so
    calling it a second time with an effectively infinite limit measures the headroom without
    changing what the run does: the recorded call's result is the one returned to the agent.
    """
    orig = agent_mod.sweep_targets

    def wrapped(urls, forms, in_scope, limit=agent_mod.SWEEP_TARGET_CAP):
        kept = orig(urls, forms, in_scope, limit=limit)
        try:
            avail = len(orig(urls, forms, in_scope, limit=10 ** 9))
        except Exception:
            avail = None
        census.append({"limit": limit, "kept": len(kept), "candidates": avail})
        return kept

    agent_mod.sweep_targets = wrapped


async def main():
    t0 = time.time()
    known_tools = check_probe_tools()
    print("probe-tool self-check OK (%d registered tools, %d payload-bearing tracked)"
          % (known_tools, len(PROBE_TOOLS)), flush=True)
    # READ THE CAP FIRST. Instrumentation must never be able to destroy the field the run exists to
    # explain -- it did exactly that once, and a None cap turns exit_reason into "unknown".
    cap_preflight = step_cap()
    if cap_preflight is None:
        raise SystemExit("MAX_STEPS literal not found in BBHAgent._execute_plan before "
                         "instrumentation -- refusing to run, the exit reason would be unfalsifiable")
    print("step cap read BEFORE instrumentation: %d" % cap_preflight, flush=True)
    wrapped_phases = install_phases(agent_mod.BBHAgent)
    planner_batches = []
    planner_state = install_planner_census(planner_batches)
    sweep_census = []
    install_sweep_census(sweep_census)
    rate_census = {"observed": 0, "cooldowns": 0, "cooldown_s": 0.0, "waits": 0, "waited_s": 0.0}
    install_rate_census(rate_census)
    print("phase attribution installed on %d method(s)" % len(wrapped_phases), flush=True)
    eng = scope_mod.ScopeEngine()
    eng.load_manual([TARGET], [], "owaspbench-q019-rerun")
    reg = tools_mod.ToolRegistry(eng, mission_id=None, lab_mode=True)
    ag = agent_mod.BBHAgent(eng, reg, asyncio.Event(), mode=MODE, auto_approve=True,
                            strategy="deterministic", mission_id=None)

    phases, ev_counts, tool_calls = [], {}, {}
    probe_targets, cases_probed, cases_touched = {}, set(), set()
    # attribution
    phase_calls, phase_seconds, tool_seconds = {}, {}, {}
    cases_by_tool, cases_by_phase, first_prober = {}, {}, {}
    tool_phase_calls = {}                     # "phase|tool" -> dispatch count
    open_call = None                          # (tool, phase, t_start) awaiting its terminal event
    _TERMINAL = ("tool_result", "tool_error", "scope_block")

    def _close(now):
        """Charge the open dispatch's wall clock to its tool and its phase."""
        nonlocal open_call
        if open_call is None:
            return
        name, ph, t_start = open_call
        dt = now - t_start
        tool_seconds[name] = tool_seconds.get(name, 0.0) + dt
        phase_seconds[ph] = phase_seconds.get(ph, 0.0) + dt
        open_call = None

    async for ev in ag.run("Whole-product benchmark rerun", "wp"):
        now = time.time()
        t = ev.get("type")
        ev_counts[str(t)] = ev_counts.get(str(t), 0) + 1
        if t in _TERMINAL:
            _close(now)
        if t == "tool_call":
            # a tool_call with an unclosed predecessor cannot happen (dispatch is sequential), but
            # close defensively rather than leak the previous interval into this one
            _close(now)
            name = str(ev.get("tool"))
            ph = _phase()
            open_call = (name, ph, now)
            tool_calls[name] = tool_calls.get(name, 0) + 1
            phase_calls[ph] = phase_calls.get(ph, 0) + 1
            tool_phase_calls["%s|%s" % (ph, name)] = tool_phase_calls.get("%s|%s" % (ph, name), 0) + 1
            inp = ev.get("input") or {}
            tgt = str(inp.get("url") or inp.get("target") or inp.get("host") or "")
            if tgt:
                # every tool dispatch, payload-bearing or not -- "the sweep reached here at all"
                hits = {m.group(1) for m in CASE_RE.finditer(tgt)}
                cases_touched |= hits
                if name in PROBE_TOOLS:
                    probe_targets.setdefault(name, set()).add(tgt)
                    cases_probed |= hits
                    if hits:
                        cases_by_phase.setdefault(ph, set()).update(hits)
                        for h in hits:
                            first_prober.setdefault(h, name)
                # PER-TOOL REACH IS RECORDED FOR *EVERY* DISPATCHING TOOL, not only the
                # payload-bearing set. `cases_probed` keeps its PROBE_TOOLS-only definition so the
                # figure stays comparable across artifacts -- but the question "what does this tool
                # cost and what does it reach" has to be answerable for a budget consumer like
                # run_waf_bypass, which is a sweep engine and is not in PROBE_TOOLS.
                if hits:
                    cases_by_tool.setdefault(name, set()).update(hits)
        elif t == "phase":
            phases.append((round(now - t0), ev.get("phase"), len(ag.findings)))
            print("[%5ds] %-10s findings=%d" % phases[-1], flush=True)
        elif t == "finding":
            f = ev.get("finding") or {}
            print("       + %-16s %s" % (f.get("family"), str(f.get("title"))[:70]), flush=True)
    _close(time.time())

    elapsed = round(time.time() - t0)
    findings = list(ag.findings or [])
    claimed = set()
    for f in findings:
        claimed |= case_ids(f)
    claims = sorted(claimed)
    seal = hashlib.sha256("\n".join(claims).encode("utf-8")).hexdigest()

    fam = {}
    for f in findings:
        k = str(f.get("family") or "?")
        fam[k] = fam.get(k, 0) + 1

    # ── EFFORT + EXIT REASON ──────────────────────────────────────────────
    steps = getattr(ag, "_plan_steps", None)
    cap = step_cap() or cap_preflight
    degraded = getattr(ag, "_degraded", None)
    if degraded:
        exit_reason = "degraded"
    elif ag.stop_event.is_set():
        exit_reason = "stopped"
    elif steps is None or cap is None:
        exit_reason = "unknown"
    elif steps >= cap:
        exit_reason = "step_cap_exhausted"
    else:
        exit_reason = "planner_fixpoint"

    # ── WOULD THE PLANNER HAVE SCHEDULED MORE? ─────────────────────────────
    # `steps >= cap` says the budget was reached, NOT that work was left. The two are different
    # facts and only the second justifies raising the cap. Ask the planner directly, with the
    # final `done` set (a live reference held by the executor) and the last world-state it saw.
    # ESTIMATE, and labelled one: the graph-derived roots/urls are last-call snapshots, not a
    # re-projection. It is nevertheless a real call to the real planner, not an argument.
    would_more = None
    try:
        st, orig_next = planner_state.get("state"), planner_state.get("orig")
        if st is not None and orig_next is not None:
            would_more = len(orig_next(st) or [])      # the ORIGINAL, so the census stays clean
    except Exception as _e:
        would_more = "error: %s: %s" % (type(_e).__name__, str(_e)[:80])

    out = {
        "target": TARGET, "mode": MODE, "elapsed_s": elapsed,
        "findings_total": len(findings),
        "leads_total": len(getattr(ag, "leads", []) or []),
        "by_family": fam,
        "distinct_cases_claimed": len(claims),
        "claims": claims,
        "seal_sha256": seal,
        "claim_rows": sorted({"%s | %s | %s" % (f.get("family"), str(f.get("title"))[:60],
                                                str(f.get("target"))[:70]) for f in findings}),
        "phases": phases,
        "effort": {
            "plan_steps": steps,
            "step_cap": cap,
            "exit_reason": exit_reason,
            "degraded": degraded,
            "recon_cycles": getattr(ag, "recon_cycles", None),
            "graph_actions_run": getattr(ag, "_graph_actions_run", 0),
            "tool_calls": dict(sorted(tool_calls.items())),
            "tool_calls_total": sum(tool_calls.values()),
            "events": dict(sorted(ev_counts.items())),
            "surface_urls": len(getattr(reg, "urls", []) or []),
            # ── attribution (2026-08-14, selection lane) ──
            "sweep_target_cap": getattr(agent_mod, "SWEEP_TARGET_CAP", None),
            "sweep_browser_cap": getattr(agent_mod, "SWEEP_BROWSER_CAP", None),
            "sweep_selection": sweep_census,
            "rate_policy": dict(rate_census),
            "planner_batches": planner_batches,
            "planner_batches_n": len(planner_batches),
            "planner_would_schedule_more": would_more,
            "phase_calls": dict(sorted(phase_calls.items())),
            "phase_seconds": {k: round(v, 1) for k, v in sorted(phase_seconds.items())},
            "tool_seconds": {k: round(v, 1) for k, v in sorted(tool_seconds.items())},
            "tool_phase_calls": dict(sorted(tool_phase_calls.items())),
            "attributed_s": round(sum(phase_seconds.values()), 1),
            # everything NOT inside a tool dispatch: the crawl's direct tools.execute calls, graph
            # projection, report assembly. Recorded rather than hidden, so the phase seconds are
            # never mistaken for a partition of the elapsed time.
            "unattributed_s": round(elapsed - sum(phase_seconds.values()), 1),
        },
        "coverage": {
            "cases_probed": sorted(cases_probed),
            "cases_probed_n": len(cases_probed),
            "cases_touched_n": len(cases_touched),
            "probe_targets_n": {k: len(v) for k, v in sorted(probe_targets.items())},
            # probed but silent: the oracles reached these and declined. Distinguishes a detection
            # regression (this list grows) from a coverage regression (this list shrinks with it).
            "probed_not_claimed": sorted(cases_probed - claimed),
            "claimed_not_probed": sorted(claimed - cases_probed),
            # ── attribution (2026-08-14, selection lane) ──
            "cases_by_tool": {k: sorted(v) for k, v in sorted(cases_by_tool.items())},
            "cases_by_tool_n": {k: len(v) for k, v in sorted(cases_by_tool.items())},
            "cases_by_phase_n": {k: len(v) for k, v in sorted(cases_by_phase.items())},
            # a tool's UNIQUE contribution: cases NO other tool probed. A tool whose whole case set
            # is also reached by seven others buys depth, not coverage, and the two are priced
            # differently when a budget is reallocated.
            "cases_unique_to_tool_n": {
                k: len(v - set().union(*[w for j, w in cases_by_tool.items() if j != k] or [set()]))
                for k, v in sorted(cases_by_tool.items())},
            "first_prober": dict(sorted(first_prober.items())),
        },
    }
    os.makedirs("/out", exist_ok=True)
    with open("/out/wp_claims.json", "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True, default=str)

    print()
    print("=== WHOLE-PRODUCT RERUN, SEALED ===")
    print("elapsed                 : %ds" % elapsed)
    print("findings total          :", len(findings))
    print("leads total             :", out["leads_total"])
    print("by family               :", fam)
    print("distinct cases claimed  :", len(claims))
    print("plan steps              : %s / cap %s" % (steps, cap))
    print("EXIT REASON             :", exit_reason)
    print("tool calls              : %d  (%s)" % (out["effort"]["tool_calls_total"],
                                                  out["effort"]["tool_calls"]))
    print("cases PROBED            :", len(cases_probed))
    print("probed but not claimed  :", len(out["coverage"]["probed_not_claimed"]))
    print("SEAL sha256             :", seal)
    print("(key NOT read; score only after this seal is recorded)")

    print()
    print("=== WHERE THE BUDGET GOES (dispatches / tool-seconds, by phase) ===")
    print("sweep caps              : targets %s, browser %s"
          % (out["effort"]["sweep_target_cap"], out["effort"]["sweep_browser_cap"]))
    for c in sweep_census:
        print("sweep selection         : kept %s of %s candidate(s) at limit %s"
              % (c["kept"], c["candidates"], c["limit"]))
    print("rate policy             : %s" % dict(rate_census))
    print("planner batches         : %d  sizes=%s" % (len(planner_batches), planner_batches[:24]))
    print("planner would schedule  : %s more step(s) at the final state (estimate)" % would_more)
    tot_c = sum(phase_calls.values()) or 1
    tot_s = sum(phase_seconds.values()) or 1.0
    print("%-26s %8s %7s %10s %7s %8s" % ("phase", "calls", "%", "tool_s", "%", "cases"))
    for ph in sorted(phase_calls, key=lambda k: -phase_seconds.get(k, 0.0)):
        print("%-26s %8d %6.1f%% %10.1f %6.1f%% %8d"
              % (ph, phase_calls[ph], 100.0 * phase_calls[ph] / tot_c,
                 phase_seconds.get(ph, 0.0), 100.0 * phase_seconds.get(ph, 0.0) / tot_s,
                 len(cases_by_phase.get(ph, ()))))
    print("attributed %.0fs of %ds elapsed; %.0fs outside any tool dispatch"
          % (sum(phase_seconds.values()), elapsed, out["effort"]["unattributed_s"]))
    print()
    print("%-24s %7s %9s %8s %8s %10s" % ("tool", "calls", "tool_s", "cases", "unique", "s/case"))
    for name in sorted(tool_seconds, key=lambda k: -tool_seconds[k])[:22]:
        n_cases = len(cases_by_tool.get(name, ()))
        uniq = out["coverage"]["cases_unique_to_tool_n"].get(name, 0)
        print("%-24s %7d %9.1f %8d %8d %10s"
              % (name, tool_calls.get(name, 0), tool_seconds[name], n_cases, uniq,
                 ("%.2f" % (tool_seconds[name] / n_cases)) if n_cases else "-"))


asyncio.run(main())
