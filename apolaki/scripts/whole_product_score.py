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
                              "missed_after_probing_cases": sorted(miss_probed)[:200]}},
          open("/out/wp_score.json", "w"), indent=2, sort_keys=True, default=str)
print("\nwrote /out/wp_score.json")
