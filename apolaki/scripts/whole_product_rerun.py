"""Whole-product rerun: owaspbench-q019 shape, current code, SEALED before any key is touched.

Drives BBHAgent.run() -- the same full pipeline the API mission uses -- not just _execute_plan, so
this is comparable to mission ebd96f45 (95.7% precision / 1.6% recall, 22 TP / 1 FP / 1415 vulnerable).

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

The SEAL is unchanged -- sha256 over the sorted distinct claimed case ids -- so artifacts from
before this change stay comparable.
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
    """
    try:
        import inspect
        src = inspect.getsource(agent_mod.BBHAgent._execute_plan)
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


async def main():
    t0 = time.time()
    known_tools = check_probe_tools()
    print("probe-tool self-check OK (%d registered tools, %d payload-bearing tracked)"
          % (known_tools, len(PROBE_TOOLS)), flush=True)
    eng = scope_mod.ScopeEngine()
    eng.load_manual([TARGET], [], "owaspbench-q019-rerun")
    reg = tools_mod.ToolRegistry(eng, mission_id=None, lab_mode=True)
    ag = agent_mod.BBHAgent(eng, reg, asyncio.Event(), mode=MODE, auto_approve=True,
                            strategy="deterministic", mission_id=None)

    phases, ev_counts, tool_calls = [], {}, {}
    probe_targets, cases_probed, cases_touched = {}, set(), set()
    async for ev in ag.run("Whole-product benchmark rerun", "wp"):
        t = ev.get("type")
        ev_counts[str(t)] = ev_counts.get(str(t), 0) + 1
        if t == "tool_call":
            name = str(ev.get("tool"))
            tool_calls[name] = tool_calls.get(name, 0) + 1
            inp = ev.get("input") or {}
            tgt = str(inp.get("url") or inp.get("target") or inp.get("host") or "")
            if tgt:
                # every tool dispatch, payload-bearing or not -- "the sweep reached here at all"
                cases_touched |= {m.group(1) for m in CASE_RE.finditer(tgt)}
                if name in PROBE_TOOLS:
                    probe_targets.setdefault(name, set()).add(tgt)
                    cases_probed |= {m.group(1) for m in CASE_RE.finditer(tgt)}
        elif t == "phase":
            phases.append((round(time.time() - t0), ev.get("phase"), len(ag.findings)))
            print("[%5ds] %-10s findings=%d" % phases[-1], flush=True)
        elif t == "finding":
            f = ev.get("finding") or {}
            print("       + %-16s %s" % (f.get("family"), str(f.get("title"))[:70]), flush=True)

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
    cap = step_cap()
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


asyncio.run(main())
