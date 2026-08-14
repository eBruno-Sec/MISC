"""Score the SEALED whole-product claims against the key. Run only after the seal is in history.

Re-verifies the seal before scoring: if the claims file has been touched since sealing, the sha256
will not match and the score is refused.
"""
import csv
import hashlib
import json

CLAIMS = "/out/wp_claims.json"
KEY = "/out/key.csv"
BASELINE = {"tp": 22, "fp": 1, "claimed": 23, "elapsed": 5329,
            "precision": 22 / 23, "recall": 22 / 1415}

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
           "rows": [list(r) for r in rows], "baseline": BASELINE},
          open("/out/wp_score.json", "w"), indent=2, sort_keys=True)
print("\nwrote /out/wp_score.json")
