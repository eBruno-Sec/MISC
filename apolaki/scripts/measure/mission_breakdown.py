"""Per-tool wall-clock breakdown of a real mission, from the log timestamps.

tool_call at T0, its tool_result/tool_error at T1 -> that engine's real cost in situ.
Also reports the gap time not attributable to any tool.
"""
import sqlite3, json, sys, collections
from datetime import datetime

mid = sys.argv[1] if len(sys.argv) > 1 else 'ebd96f45'
c = sqlite3.connect('/app/data/bbh.db')
rows = list(c.execute(
    "select etype, data, created_at from logs where mission_id like ? order by id", (mid + '%',)))


def ts(s):
    return datetime.fromisoformat(s).timestamp()


tot_span = ts(rows[-1][2]) - ts(rows[0][2])
per = collections.defaultdict(lambda: {"n": 0, "s": 0.0})
pending = None
accounted = 0.0
for etype, data, at in rows:
    if etype == "tool_call":
        try:
            tool = json.loads(data).get("tool", "?")
        except Exception:
            tool = "?"
        pending = (tool, ts(at))
    elif etype in ("tool_result", "tool_error") and pending:
        tool, t0 = pending
        d = ts(at) - t0
        per[tool]["n"] += 1
        per[tool]["s"] += d
        accounted += d
        pending = None

items = sorted(per.items(), key=lambda kv: -kv[1]["s"])
print("mission %s   span %.0f s   tool-attributed %.0f s (%.0f%%)   unattributed %.0f s"
      % (mid, tot_span, accounted, 100 * accounted / max(tot_span, 1), tot_span - accounted))
print()
print("%-26s %6s %10s %9s %7s" % ("tool", "calls", "total_s", "mean_s", "%span"))
for tool, v in items[:30]:
    print("%-26s %6d %10.1f %9.2f %6.1f%%"
          % (tool, v["n"], v["s"], v["s"] / v["n"], 100 * v["s"] / max(tot_span, 1)))
print()
n = sum(v["n"] for v in per.values())
print("TOTAL calls %d, mean %.2f s/call" % (n, accounted / max(n, 1)))
