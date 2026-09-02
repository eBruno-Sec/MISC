#!/usr/bin/env python3
"""Q-151. Per-tool census for ONE mission: which tools fired, which errored, which said nothing.

    docker exec apolaki-agent-1 python /app/../scripts/tool_census.py <mission_id>
    (or run it inside the container against /app/data/bbh.db)

WHY A ZERO IS NOT A VERDICT. A tool that returns 0 on a target WITHOUT the bug is correct. The
only thing that separates "engine is broken" from "engine is right and the target is clean" is
running it against a target that HAS the bug -- which is what this census is for: point it at a
known-vulnerable lab, and a tool that still reports nothing has a case to answer.

Four buckets, and the middle two are the interesting ones:

  FIRED       returned a non-zero count at least once -- working, on this target
  SILENT      ran, always count=0 -- suspect HERE, because this target is vulnerable
  ERRORED     every run raised or was refused -- broken, or blocked, and the note says which
  NEVER RAN   in the registry and never dispatched -- the planner never selected it
"""
from __future__ import annotations

import collections
import json
import sqlite3
import sys

DB = "/app/data/bbh.db"


def census(mission_id: str, db_path: str = DB) -> dict:
    con = sqlite3.connect(db_path)
    runs, nonzero, errs, calls = (collections.Counter() for _ in range(4))
    err_note: dict = {}

    for etype, data in con.execute(
            "SELECT etype, data FROM logs WHERE mission_id = ? AND etype IN "
            "('tool_call','tool_result','tool_error','scope_block')", (mission_id,)):
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
            try:
                n = int(str(o.get("count") or 0))
            except Exception:
                n = 0
            if n > 0:
                nonzero[tool] += 1
        else:
            errs[tool] += 1
            err_note.setdefault(tool, str(o.get("error") or o.get("output") or "")[:110])

    try:
        sys.path.insert(0, "/app")
        import tools as _t
        registry = set(_t.TOOL_PERMISSIONS)
    except Exception:
        registry = set()

    seen = set(runs) | set(errs) | set(calls)
    return {
        "fired": sorted((t, nonzero[t], runs[t]) for t in runs if nonzero[t]),
        "silent": sorted((t, runs[t]) for t in runs if not nonzero[t]),
        "errored": sorted((t, errs[t], err_note.get(t, "")) for t in errs if t not in runs),
        "never_ran": sorted(registry - seen),
        "registry": len(registry),
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    c = census(sys.argv[1])
    print("registry: %d tools\n" % c["registry"])
    print("FIRED (returned something at least once): %d" % len(c["fired"]))
    for t, nz, r in sorted(c["fired"], key=lambda x: -x[1]):
        print("   %-28s %d/%d runs produced" % (t, nz, r))
    print("\nSILENT (ran, always zero -- SUSPECT on a vulnerable target): %d" % len(c["silent"]))
    for t, r in sorted(c["silent"], key=lambda x: -x[1]):
        print("   %-28s %d run(s), never once a result" % (t, r))
    print("\nERRORED (never produced a result row): %d" % len(c["errored"]))
    for t, n, note in sorted(c["errored"], key=lambda x: -x[1]):
        print("   %-28s %d error(s)  %s" % (t, n, note))
    print("\nNEVER DISPATCHED (planner never selected it): %d" % len(c["never_ran"]))
    print("   " + ", ".join(c["never_ran"]) if c["never_ran"] else "   none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
