#!/usr/bin/env python3
"""Q-151. The ACROSS-ALL-MISSIONS tool ledger. One question: has this tool EVER worked?

    docker exec apolaki-agent-1 python /app/../scripts/tool_ledger.py

WHY THIS EXISTS AND tool_census.py IS NOT ENOUGH. The per-mission census answers "what happened
on this target". It cannot answer "is this tool working", because a tool that does not APPLY to
the target (an LDAP engine on a shop, a GraphQL engine on a site with no GraphQL) lands in
NEVER DISPATCHED and is indistinguishable there from a tool the planner can no longer reach.

So this reads every mission in the database at once and asks a different question per tool:
is there ANY recorded run, anywhere, in which this tool produced something? That is a claim about
the TOOL rather than about a target, and it is the only form of the claim that survives the
objection "well, that lab did not have the bug".

Buckets, worst news last:

  PROVEN      produced a non-zero result in at least one mission. The mission ids are printed,
              so the claim is checkable rather than asserted.
  ZERO-ONLY   dispatched, ran, returned zero EVERY time across every mission and every target.
              Not proof of a defect -- but it is a tool with no evidence behind it, and any
              "no findings" it contributes to a report is unearned.
  ERROR-ONLY  every recorded execution raised or was refused. Broken, or blocked; the note says.
  NEVER       in the registry, never dispatched by the planner in ANY mission. The planner cannot
              reach it, or nothing has ever been aimed at it.

`targets` counts DISTINCT missions a tool fired in. A tool that has only ever fired in one mission
is weaker evidence than the same tool firing across four different applications, and the column
exists so that difference is visible instead of averaged away.
"""
from __future__ import annotations

import collections
import json
import sqlite3
import sys

DB = "/app/data/bbh.db"


def ledger(db_path: str = DB) -> dict:
    con = sqlite3.connect(db_path)
    runs = collections.Counter()
    nonzero = collections.Counter()
    errs = collections.Counter()
    calls = collections.Counter()
    fired_in = collections.defaultdict(set)
    ran_in = collections.defaultdict(set)
    err_note = {}

    q = ("SELECT mission_id, etype, data FROM logs WHERE etype IN "
         "('tool_call','tool_result','tool_error','scope_block')")
    for mid, etype, data in con.execute(q):
        try:
            o = json.loads(data)
        except Exception:
            continue
        tool = o.get("tool")
        if not tool:
            continue
        if etype == "tool_call":
            calls[tool] += 1
        elif etype == "tool_result":
            runs[tool] += 1
            ran_in[tool].add(mid)
            try:
                n = int(str(o.get("count") or 0))
            except Exception:
                n = 0
            if n > 0:
                nonzero[tool] += 1
                fired_in[tool].add(mid)
        else:
            errs[tool] += 1
            err_note.setdefault(tool, str(o.get("error") or o.get("output") or "")[:100])

    try:
        sys.path.insert(0, "/app")
        import tools as _t
        registry = set(_t.TOOL_PERMISSIONS)
    except Exception:
        registry = set()

    seen = set(runs) | set(errs) | set(calls)
    proven = sorted((t, nonzero[t], runs[t], len(fired_in[t])) for t in registry if nonzero[t])
    zero_only = sorted((t, runs[t], len(ran_in[t])) for t in registry
                       if t in runs and not nonzero[t])
    error_only = sorted((t, errs[t], err_note.get(t, "")) for t in registry
                        if t in errs and t not in runs)
    never = sorted(registry - seen)
    # A tool outside the registry that still ran is its own problem: it means the census is
    # measuring a name the registry does not know, so record it rather than dropping it.
    unregistered = sorted(seen - registry) if registry else []
    return {"proven": proven, "zero_only": zero_only, "error_only": error_only,
            "never": never, "unregistered": unregistered, "registry": len(registry),
            "missions": len({m for s in ran_in.values() for m in s})}


def main() -> int:
    c = ledger(sys.argv[1] if len(sys.argv) > 1 else DB)
    reg = c["registry"]
    print("registry: %d tools, across %d missions with at least one tool result"
          % (reg, c["missions"]))
    print()
    print("PROVEN (non-zero at least once, anywhere): %d of %d" % (len(c["proven"]), reg))
    for t, nz, r, m in sorted(c["proven"], key=lambda x: (-x[3], -x[1])):
        print("   %-30s %4d/%-4d runs produced, in %d mission(s)" % (t, nz, r, m))
    print()
    print("ZERO-ONLY (ran, never once produced, on any target): %d" % len(c["zero_only"]))
    for t, r, m in sorted(c["zero_only"], key=lambda x: -x[1]):
        print("   %-30s %4d run(s) across %d mission(s), always zero" % (t, r, m))
    print()
    print("ERROR-ONLY (never produced a result row): %d" % len(c["error_only"]))
    for t, n, note in sorted(c["error_only"], key=lambda x: -x[1]):
        print("   %-30s %3d error(s)  %s" % (t, n, note))
    print()
    print("NEVER DISPATCHED (registry, never selected in any mission): %d" % len(c["never"]))
    if c["never"]:
        print("   " + ", ".join(c["never"]))
    if c["unregistered"]:
        print()
        print("RAN BUT NOT IN THE REGISTRY (the census is naming something the registry is not): %d"
              % len(c["unregistered"]))
        print("   " + ", ".join(c["unregistered"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
