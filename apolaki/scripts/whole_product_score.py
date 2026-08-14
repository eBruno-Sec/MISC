"""Score the SEALED whole-product claims against the key. Run only after the seal is in history.

Re-verifies the seal before scoring: if the claims file has been touched since sealing, the sha256
will not match and the score is refused.

Also splits the misses two ways, which the recall number alone cannot do:

  MISSED-AFTER-PROBING  vulnerable, the run dispatched a payload at it, the oracles said no
                        -> a DETECTION shortfall
  NEVER PROBED          vulnerable, no payload was ever dispatched at it
                        -> a COVERAGE shortfall

Two runs whose recall moved by the same amount for these two different reasons need opposite fixes,
and until 2026-08-14 this harness recorded neither. Requires a claims file written by the current
`whole_product_rerun.py`; older artifacts have no `coverage` block and the split is skipped rather
than guessed.
"""
import csv
import hashlib
import json

CLAIMS = "/out/wp_claims.json"
KEY = "/out/key.csv"

# The standing comparison point. PROVENANCE, because it is not reproducible from the mission it
# names: docs/LEDGERS.md records mission ebd96f45 as 25 findings / 23 claimed cases / seal
# a95670f9..., while the agent store today returns 29 findings / 27 claimed cases for that same
# mission id (measured 2026-08-14, breaker lane) and no subset of it reproduces the recorded seal.
# The ledger figure is what every published delta has been measured against, so it stays the
# baseline -- but anything derived from it inherits this caveat and must say so.
BASELINE = {"tp": 22, "fp": 1, "claimed": 23, "elapsed": 5329,
            "precision": 22 / 23, "recall": 22 / 1415,
            "source": "docs/LEDGERS.md, mission ebd96f45, sealed 2026-08-11",
            "caveat": ("not reproducible from the mission store: ebd96f45 now returns 29 findings / "
                       "27 claimed cases and no subset reproduces seal a95670f9"),
            "steps": None, "exit_reason": None, "cases_probed": None}

d = json.load(open(CLAIMS))
claims = d["claims"]
seal = hashlib.sha256("\n".join(claims).encode("utf-8")).hexdigest()
print("seal recorded  :", d["seal_sha256"])
print("seal recomputed:", seal)
assert seal == d["seal_sha256"], "SEAL MISMATCH -- claims changed since sealing; refusing to score"

key = {}
with open(KEY) as fh:
    for row in csv.reader(fh):
        if not row or row[0].startswith("#") or len(row) < 3:
            continue
        key[row[0].strip()] = {"category": row[1].strip(),
                               "vulnerable": row[2].strip().lower() == "true",
                               "cwe": row[3].strip() if len(row) > 3 else ""}

vulnerable_total = sum(1 for v in key.values() if v["vulnerable"])
tp, fp, unknown, rows = 0, 0, 0, []
for c in claims:
    k = key.get(c)
    if not k:
        unknown += 1
        rows.append((c, "UNKNOWN", "", ""))
        continue
    if k["vulnerable"]:
        tp += 1
        rows.append((c, "TP", k["category"], k["cwe"]))
    else:
        fp += 1
        rows.append((c, "FP", k["category"], k["cwe"]))

precision = tp / (tp + fp) if (tp + fp) else 0.0
recall = tp / vulnerable_total if vulnerable_total else 0.0

effort = d.get("effort") or {}
coverage = d.get("coverage") or {}

print()
print("=== WHOLE-PRODUCT SCORE (blind: sealed before key) ===")
print("key entries            :", len(key))
print("vulnerable cases (denom):", vulnerable_total)
print("distinct cases claimed :", len(claims))
print("TRUE  POSITIVES        :", tp)
print("FALSE POSITIVES        :", fp)
print("unknown cases          :", unknown)
print()
print("PRECISION : %d/%d = %.1f%%   (baseline %.1f%%)"
      % (tp, tp + fp, 100 * precision, 100 * BASELINE["precision"]))
print("RECALL    : %d/%d = %.2f%%  (baseline %.2f%%)"
      % (tp, vulnerable_total, 100 * recall, 100 * BASELINE["recall"]))
print("ELAPSED   : %ds            (baseline %ds)" % (d["elapsed_s"], BASELINE["elapsed"]))

print()
print("=== EFFORT (what the run actually did) ===")
if effort:
    print("plan steps             : %s / cap %s" % (effort.get("plan_steps"), effort.get("step_cap")))
    print("EXIT REASON            :", effort.get("exit_reason"))
    print("tool calls             :", effort.get("tool_calls_total"))
    print("graph actions run      :", effort.get("graph_actions_run"))
    print("surface urls           :", effort.get("surface_urls"))
    print("by tool                :", effort.get("tool_calls"))
else:
    print("(no effort block -- claims file predates the 2026-08-14 harness; step count and exit")
    print(" reason are UNRECOVERABLE for this run and any 'it converged' / 'it ran out of budget'")
    print(" claim about it is unfalsifiable)")

miss_probed, miss_unprobed = [], []
if coverage.get("cases_probed"):
    probed = set(coverage["cases_probed"])
    for case, k in key.items():
        if not k["vulnerable"] or case in set(claims):
            continue
        (miss_probed if case in probed else miss_unprobed).append(case)
    print()
    print("=== WHERE THE RECALL WENT ===")
    print("cases PROBED (payload dispatched):", coverage.get("cases_probed_n"))
    print("cases TOUCHED (any dispatch)     :", coverage.get("cases_touched_n"))
    print("probed but NOT claimed           :", len(coverage.get("probed_not_claimed") or []))
    print("claimed but NOT probed           :", len(coverage.get("claimed_not_probed") or []),
          "(a claim with no recorded payload dispatch -- check the carrier)")
    print()
    print("MISSED-AFTER-PROBING (detection shortfall):", len(miss_probed))
    print("NEVER PROBED         (coverage shortfall):", len(miss_unprobed))
    denom = len(miss_probed) + len(miss_unprobed)
    if denom:
        print("  -> %.1f%% of the misses were never tested at all"
              % (100 * len(miss_unprobed) / denom))

# ── MARGINAL VALUE OF EACH BUDGET CONSUMER (2026-08-14, selection lane) ──────────────────────
# "Which tools consume the budget, and how many distinct VULNERABLE cases does each dispatch
# actually reach?" needs the key, so it lives here rather than in the rerun harness. Three columns
# decide a reallocation and no two of them are interchangeable:
#   reach_v   vulnerable cases this tool sent a payload at        (what the spend bought)
#   unique    cases NO other tool reached                         (coverage vs depth)
#   s/vuln    tool-seconds per vulnerable case reached            (the price)
# A tool with a large reach_v and 0 unique is riding a target list someone else also rides: its
# cost is depth, and cutting it costs detection, not coverage. A tool with a large unique is the
# only way those cases are tested at all.
cases_by_tool = {k: set(v) for k, v in (coverage.get("cases_by_tool") or {}).items()}
tool_seconds = (effort.get("tool_seconds") or {})
tool_calls_by = (effort.get("tool_calls") or {})
claimset = set(claims)
if cases_by_tool:
    print()
    print("=== MARGINAL VALUE PER BUDGET CONSUMER ===")
    print("%-24s %7s %8s %8s %8s %7s %8s %8s"
          % ("tool", "calls", "tool_s", "reach", "reach_v", "unique", "claimed", "s/vuln"))
    for name in sorted(cases_by_tool, key=lambda k: -tool_seconds.get(k, 0.0)):
        got = cases_by_tool[name]
        others = set().union(*[v for j, v in cases_by_tool.items() if j != name] or [set()])
        reach_v = {c for c in got if (key.get(c) or {}).get("vulnerable")}
        secs = tool_seconds.get(name, 0.0)
        print("%-24s %7d %8.1f %8d %8d %7d %8d %8s"
              % (name, tool_calls_by.get(name, 0), secs, len(got), len(reach_v),
                 len(got - others), len(got & claimset),
                 ("%.2f" % (secs / len(reach_v))) if reach_v else "-"))
    tot_s = sum(tool_seconds.values()) or 1.0
    print("total tool-seconds: %.0f of %ds elapsed (%.0f%%); the rest is crawl/projection/report"
          % (tot_s, d["elapsed_s"], 100.0 * tot_s / max(1, d["elapsed_s"])))

# ── WAS THE CASE PROBED BY AN ENGINE THAT COULD DETECT ITS CLASS? ────────────────────────────
# "probed" in the coverage record means SOME payload-bearing tool was dispatched at the case URL.
# That is the right definition for a coverage/detection split, and it is too weak for a detection
# claim: a pathtraver case that received run_sqli, run_ldap, run_xpath and run_ssi was probed by
# four engines, none of which can observe path traversal. Counting its miss as a DETECTION
# shortfall blames the oracle for a selection decision.
#
# The owning engine per category is NOT invented here -- it is `owasp_bench.ENGINES`, the map the
# per-category benchmark harness already uses to decide which engine is even allowed to score a
# category. Reusing it means this table cannot flatter the sweep by choosing a friendlier mapping.
OWNER = {}
try:
    import sys
    sys.path.insert(0, "/app")
    import owasp_bench as _ob
    OWNER = {cat: meth.lstrip("_") for cat, meth in (_ob.ENGINES or {}).items()}
except Exception as _e:
    print("(owasp_bench.ENGINES unavailable: %s -- class-correctness table skipped)" % type(_e).__name__)

if OWNER and cases_by_tool:
    probed_all = set(coverage.get("cases_probed") or [])
    per = {}
    for case, k in key.items():
        if not k["vulnerable"]:
            continue
        cat = k["category"]
        r = per.setdefault(cat, {"vuln": 0, "probed": 0, "owned": 0, "claimed": 0,
                                 "engine": OWNER.get(cat)})
        r["vuln"] += 1
        if case in probed_all:
            r["probed"] += 1
        eng = OWNER.get(cat)
        if eng and case in cases_by_tool.get(eng, set()):
            r["owned"] += 1
        if case in claimset:
            r["claimed"] += 1
    print()
    print("=== CLASS-CORRECT PROBING: did the OWNING engine ever run on the case? ===")
    print("%-14s %-20s %7s %8s %8s %8s" % ("category", "owning engine", "vuln", "probed",
                                            "by owner", "claimed"))
    for cat in sorted(per, key=lambda c: -per[c]["vuln"]):
        r = per[cat]
        print("%-14s %-20s %7d %8d %8d %8d"
              % (cat, r["engine"] or "(unmapped)", r["vuln"], r["probed"], r["owned"], r["claimed"]))
    tot_v = sum(r["vuln"] for r in per.values())
    tot_p = sum(r["probed"] for r in per.values())
    tot_o = sum(r["owned"] for r in per.values())
    print("%-14s %-20s %7d %8d %8d %8d" % ("TOTAL", "", tot_v, tot_p, tot_o,
                                            sum(r["claimed"] for r in per.values())))
    print()
    print("Of %d vulnerable cases, %d received SOME payload and %d received the engine that owns"
          % (tot_v, tot_p, tot_o))
    print("their class. Cases probed ONLY by engines that cannot detect them: %d -- a SELECTION"
          % (tot_p - tot_o))
    print("miss, recorded by the recall split as a DETECTION miss.")

phase_calls = (effort.get("phase_calls") or {})
phase_seconds = (effort.get("phase_seconds") or {})
cases_by_phase_n = (coverage.get("cases_by_phase_n") or {})
if phase_calls:
    print()
    print("=== WHERE THE BUDGET GOES, BY PIPELINE PHASE ===")
    tc = sum(phase_calls.values()) or 1
    ts = sum(phase_seconds.values()) or 1.0
    print("%-26s %8s %7s %10s %7s %8s" % ("phase", "calls", "%calls", "tool_s", "%time", "cases"))
    for ph in sorted(phase_calls, key=lambda k: -phase_seconds.get(k, 0.0)):
        print("%-26s %8d %6.1f%% %10.1f %6.1f%% %8d"
              % (ph, phase_calls[ph], 100.0 * phase_calls[ph] / tc, phase_seconds.get(ph, 0.0),
                 100.0 * phase_seconds.get(ph, 0.0) / ts, cases_by_phase_n.get(ph, 0)))
    print("planner batches      :", (effort.get("planner_batches") or [])[:20])
    print("planner would_more   :", effort.get("planner_would_schedule_more"),
          "(steps the planner would still schedule at the final state -- 0 means the cap did NOT bind)")
    print("sweep selection      :", effort.get("sweep_selection"))

print()
by = {}
for _c, verdict, cat, _cwe in rows:
    by[(cat, verdict)] = by.get((cat, verdict), 0) + 1
print("by (key category, verdict):", dict(sorted(by.items())))
print()
for r in rows:
    print("   %-20s %-8s %-12s %s" % r)

json.dump({"tp": tp, "fp": fp, "unknown": unknown, "claimed": len(claims),
           "vulnerable_total": vulnerable_total, "key_entries": len(key),
           "precision": round(precision, 4), "recall": round(recall, 5),
           "elapsed_s": d["elapsed_s"], "seal_sha256": seal,
           "rows": [list(r) for r in rows], "baseline": BASELINE,
           "effort": effort,
           "coverage_split": {"missed_after_probing": len(miss_probed),
                              "never_probed": len(miss_unprobed),
                              "missed_after_probing_cases": sorted(miss_probed)[:200]},
           "marginal_value": {
               name: {"calls": tool_calls_by.get(name, 0),
                      "tool_seconds": tool_seconds.get(name, 0.0),
                      "reach": len(got),
                      "reach_vulnerable": len([c for c in got if (key.get(c) or {}).get("vulnerable")]),
                      "unique": len(got - set().union(
                          *[v for j, v in cases_by_tool.items() if j != name] or [set()])),
                      "claimed": len(got & claimset)}
               for name, got in sorted(cases_by_tool.items())},
           "class_correct_probing": (per if OWNER and cases_by_tool else None)},
          open("/out/wp_score.json", "w"), indent=2, sort_keys=True, default=str)
print("\nwrote /out/wp_score.json")
