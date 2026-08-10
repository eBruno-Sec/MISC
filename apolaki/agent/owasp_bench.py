"""OWASP Benchmark 1.2 scan + score harness.

TWO PHASES ON PURPOSE. `scan` drives the SHIPPING engines over the benchmark surface and emits JSON;
`score` reads expectedresults-1.2.csv and grades that JSON. Nothing in the scan path can see the answer
key -- it lives inside the benchmark container and is never served over HTTP -- so a run is blind by
construction. Seal (hash) the scan output before scoring and the blindness is auditable rather than
merely claimed. Same discipline as the ginandjuice blind benchmark.

    python owasp_bench.py scan --per-category 12 > run.json
    python owasp_bench.py score --run run.json --key expectedresults-1.2.csv

Only the 1639 crawlable black-box cases are in scope. The other 1101 (weakrand, crypto, hash,
trustbound) are code-level properties no black-box scanner can observe; scoring against them would
invent a denominator we cannot serve.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import re
import sys

BASE = "https://owaspbench:8443/benchmark/"

# category -> the SHIPPING registry method that owns it. Anything absent here is reported as
# "no engine mapped" rather than silently counted as a miss, so an unmapped category can never be
# mistaken for a detection failure.
ENGINES = {
    "sqli": "_run_sqli",
    "xss": "_run_xss",
    "pathtraver": "_run_web_probes",
    "ldapi": "_run_ldap",
    "xpathi": "_run_xpath",
    "cmdi": "_run_form_cmdi",
}
# families each category legitimately confirms through. A finding of any other family on a case is
# NOT credited -- detecting XSS on a SQLi case is not a SQLi detection.
FAMILIES = {
    "sqli": {"sqli", "sql_injection", "blind_sqli"},
    "xss": {"xss", "reflected_xss", "stored_xss", "dom_xss"},
    "pathtraver": {"path_traversal"},
    "ldapi": {"ldap_injection"},
    "xpathi": {"xpath_injection"},
    "cmdi": {"command_injection", "cmdi"},
}
_TESTNO = re.compile(r"(BenchmarkTest\d+)")


def case_urls(client, category: str) -> list:
    """Real hrefs from the category index. Never hand-build these: a constructed path 404s/500s
    because the live URL carries `.html` plus a per-case query string."""
    idx = client.get(BASE + "%s-Index.html" % category).text
    seen, out = set(), []
    for href in re.findall(r"href=[\"']([^\"']*BenchmarkTest\d+[^\"']*)", idx):
        m = _TESTNO.search(href)
        if not m or m.group(1) in seen:
            continue
        seen.add(m.group(1))
        out.append((m.group(1), BASE + href.lstrip("/").replace("benchmark/", "", 1)))
    return out


async def scan(per_category: int, categories: list, seed: int) -> dict:
    import httpx
    import scope as scope_mod
    import tools as tools_mod

    sc = scope_mod.ScopeEngine()
    sc.load_manual(["owaspbench"], [], "owaspbench")
    reg = tools_mod.ToolRegistry(sc, mission_id=None, lab_mode=True)
    rng = random.Random(seed)
    results, client = [], httpx.Client(verify=False, timeout=30, follow_redirects=True)
    for cat in categories:
        cases = case_urls(client, cat)
        picked = sorted(rng.sample(cases, min(per_category, len(cases))))
        method = ENGINES.get(cat)
        for name, url in picked:
            row = {"test": name, "category": cat, "url": url, "engine": method,
                   "families": [], "error": ""}
            if not method:
                row["error"] = "no engine mapped"
                results.append(row)
                continue
            try:
                inp = {"url": url}
                if method == "_run_web_probes":
                    inp["lab_mode"] = True
                res = await getattr(reg, method)(inp)
                row["families"] = [str(f.get("family") or "") for f in (res.findings or [])]
            except Exception as e:
                row["error"] = "%s: %s" % (type(e).__name__, str(e)[:120])
            results.append(row)
            print("  %-8s %-18s %s" % (cat, name, row["families"] or row["error"] or "-"),
                  file=sys.stderr, flush=True)
    return {"seed": seed, "per_category": per_category, "results": results}


def load_key(path: str) -> dict:
    """test name -> (category, is_real_vulnerability)."""
    key = {}
    with open(path, newline="", encoding="utf8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].strip().startswith("#") or len(row) < 3:
                continue
            key[row[0].strip()] = (row[1].strip().lower(), row[2].strip().lower() == "true")
    return key


def score(run: dict, key: dict) -> dict:
    """TPR, FPR and the Benchmark score (Youden J = TPR - FPR) per category and overall.

    A case counts as DETECTED only when a finding of that category's own family came back. Cases the
    key does not cover, or where no engine is mapped, are reported separately and never folded into a
    rate -- an unmeasured case is not a miss.
    """
    per, unscored = {}, []
    for r in run.get("results", []):
        entry = key.get(r["test"])
        if entry is None or r.get("error") == "no engine mapped":
            unscored.append(r["test"])
            continue
        _cat_in_key, is_vuln = entry
        cat = r["category"]
        b = per.setdefault(cat, {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "errors": 0})
        if r.get("error"):
            b["errors"] += 1
        detected = bool(set(r.get("families") or []) & FAMILIES.get(cat, set()))
        if is_vuln:
            b["tp" if detected else "fn"] += 1
        else:
            b["fp" if detected else "tn"] += 1
    total = {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "errors": 0}
    for b in per.values():
        for k in total:
            total[k] += b[k]
    return {"per_category": {c: _rates(b) for c, b in sorted(per.items())},
            "overall": _rates(total), "unscored": unscored}


def _rates(b: dict) -> dict:
    pos, neg = b["tp"] + b["fn"], b["fp"] + b["tn"]
    tpr = (b["tp"] / pos) if pos else None
    fpr = (b["fp"] / neg) if neg else None
    out = dict(b)
    out["tpr"] = tpr
    out["fpr"] = fpr
    out["youden"] = (tpr - fpr) if (tpr is not None and fpr is not None) else None
    return out


def _fmt(v):
    return "  n/a" if v is None else "%5.1f%%" % (100 * v)


def report(s: dict) -> str:
    lines = ["%-13s %5s %5s %5s %5s   %7s %7s %8s" % (
        "category", "TP", "FN", "FP", "TN", "TPR", "FPR", "score")]
    for cat, b in s["per_category"].items():
        lines.append("%-13s %5d %5d %5d %5d   %s %s %s"
                     % (cat, b["tp"], b["fn"], b["fp"], b["tn"],
                        _fmt(b["tpr"]), _fmt(b["fpr"]), _fmt(b["youden"])))
    o = s["overall"]
    lines.append("%-13s %5d %5d %5d %5d   %s %s %s"
                 % ("OVERALL", o["tp"], o["fn"], o["fp"], o["tn"],
                    _fmt(o["tpr"]), _fmt(o["fpr"]), _fmt(o["youden"])))
    if s["unscored"]:
        lines.append("unscored (no key entry or no engine mapped): %d" % len(s["unscored"]))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan")
    sc.add_argument("--per-category", type=int, default=12)
    sc.add_argument("--seed", type=int, default=1337)
    sc.add_argument("--categories", default="sqli,xss,pathtraver,ldapi,xpathi")
    so = sub.add_parser("score")
    so.add_argument("--run", required=True)
    so.add_argument("--key", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        out = asyncio.run(scan(a.per_category, [c for c in a.categories.split(",") if c], a.seed))
        print(json.dumps(out, indent=1))
        return 0
    with open(a.run, encoding="utf8") as fh:
        run = json.load(fh)
    print(report(score(run, load_key(a.key))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
