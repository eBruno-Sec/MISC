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
import os
import random
import re
import sys

# Both suites are served the same way, so one harness scores either. --base selects the target.
BASES = {"java": "https://owaspbench:8443/benchmark/",
         "python": "https://benchmarkpython:8443/benchmark/"}
BASE = BASES["java"]

# EVERY category the suite contains. The official macro-average divides by ALL of them, so a category we
# cannot detect scores 0 and still counts against us. Averaging only over the categories we happened to
# map would be grading on a denominator of our own choosing -- exactly the mistake that made an earlier
# run read 58.1% when the comparable figure was 30.5%.
SUITE_CATEGORIES = {
    "java": ["cmdi", "crypto", "hash", "ldapi", "pathtraver", "securecookie",
             "sqli", "trustbound", "weakrand", "xpathi", "xss"],
    "python": ["cmdi", "codeinj", "deserialization", "hash", "ldapi", "pathtraver", "redirect",
               "securecookie", "sqli", "trustbound", "weakrand", "xpathi", "xss", "xxe"],
}

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
    "weakrand": "_run_web_probes",
    "securecookie": "_run_web_probes",
    # Python v0.1 adds four categories the Java suite does not have.
    "xxe": "_run_xxe",
    "deserialization": "_run_deserialization",
    "redirect": "_run_injection_probes",
    "codeinj": "_run_injection_probes",
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
    "weakrand": {"weak_random"},
    "securecookie": {"insecure_cookie"},
    "xxe": {"xxe"},
    "deserialization": {"deserialization"},
    "redirect": {"open_redirect"},
    # CWE-94 in a Python app is typically an eval()/exec() sink. Our nearest oracle is the SSTI
    # expression probe, which confirms by evaluated arithmetic -- the same proof shape. If it does not
    # reach eval() sinks the category simply scores 0, which is an honest gap to report rather than a
    # reason to credit some unrelated family.
    "codeinj": {"ssti", "code_injection"},
}
_TESTNO = re.compile(r"(BenchmarkTest\d+)")


def case_urls(client, category: str, base: str = "") -> list:
    """Real hrefs from the category index. Never hand-build these: a constructed path 404s/500s
    because the live URL carries `.html` plus a per-case query string."""
    base = base or BASE
    idx = client.get(base + "%s-Index.html" % category).text
    seen, out = set(), []
    for href in re.findall(r"href=[\"']([^\"']*BenchmarkTest\d+[^\"']*)", idx):
        m = _TESTNO.search(href)
        if not m or m.group(1) in seen:
            continue
        seen.add(m.group(1))
        out.append((m.group(1), base + href.lstrip("/").replace("benchmark/", "", 1)))
    return out


def _load_done(path: str) -> dict:
    """Cases already recorded in a checkpoint file, so a killed run resumes instead of restarting."""
    done = {}
    if not path or not os.path.exists(path):
        return done
    with open(path, encoding="utf8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue          # a half-written final line is expected after a kill; drop it
            if row.get("test"):
                done[row["test"]] = row
    return done


async def scan(per_category: int, categories: list, seed: int, base: str = "",
               checkpoint: str = "") -> dict:
    import httpx
    import scope as scope_mod
    import tools as tools_mod

    from urllib.parse import urlparse
    host = urlparse(base or BASE).hostname or "owaspbench"
    sc = scope_mod.ScopeEngine()
    sc.load_manual([host], [], host)
    reg = tools_mod.ToolRegistry(sc, mission_id=None, lab_mode=True)
    rng = random.Random(seed)
    done = _load_done(checkpoint)
    ck = open(checkpoint, "a", encoding="utf8") if checkpoint else None
    results, client = [], httpx.Client(verify=False, timeout=30, follow_redirects=True)
    for cat in categories:
        cases = case_urls(client, cat, base)
        picked = sorted(rng.sample(cases, min(per_category, len(cases))))
        method = ENGINES.get(cat)
        for name, url in picked:
            if name in done:
                results.append(done[name]); continue
            row = {"test": name, "category": cat, "url": url, "engine": method,
                   "families": [], "error": ""}
            def _checkpoint(r):
                """FLUSH AND FSYNC PER CASE. The first full-suite attempt was SIGKILLed after ~700 cases
                and lost every one of them, because output was written only at the end."""
                if ck:
                    ck.write(json.dumps(r) + "\n")
                    ck.flush()
                    os.fsync(ck.fileno())

            if not method:
                row["error"] = "no engine mapped"
                results.append(row)
                _checkpoint(row)
                continue
            try:
                # MIRROR THE PLANNER instead of calling the engine on the bare page URL. A real mission
                # runs sweep_targets, which expands a page into its form pages and replays the page's
                # query against the form's ACTION -- a benchmark page is usually a static wrapper whose
                # parameter is only injectable on the handler. Measuring direct calls would score a code
                # path no scan actually takes.
                import agent as agent_mod
                import crawl as crawl_mod
                page = client.get(url).text
                forms = [{"action": f.get("action"), "page": url}
                         for f in crawl_mod.extract_forms(page, url)]
                targets = agent_mod.sweep_targets([url], forms, lambda u: host in u) or [url]
                fams, confs = [], []
                for t in targets:
                    inp = {"url": t}
                    if method == "_run_web_probes":
                        inp["lab_mode"] = True
                    res = await getattr(reg, method)(inp)
                    fams += [str(f.get("family") or "") for f in (res.findings or [])]
                    confs += [str(f.get("confidence") or "confirmed").lower()
                              for f in (res.findings or [])]
                row["targets"] = targets
                row["families"] = fams
                row["conf"] = confs
            except Exception as e:
                row["error"] = "%s: %s" % (type(e).__name__, str(e)[:120])
            results.append(row)
            _checkpoint(row)
            print("  %-8s %-18s %s" % (cat, name, row["families"] or row["error"] or "-"),
                  file=sys.stderr, flush=True)
    if ck:
        ck.close()
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


# Confidences the product does NOT report as a confirmed vulnerability. The proof gate demotes these to
# leads, so counting one as a detection scores something the tool would never actually claim -- it
# inflates TPR and, on a safe case, invents a false positive out of thin air. This is exactly what
# happened on the first Python run: two `candidate` deserialization leads scored as FPs.
_UNPROVEN = {"lead", "candidate", "unconfirmed", "informational", "tentative", "info"}


def _detected(row: dict, cat: str) -> bool:
    """True only when a CONFIRMED finding of this category's own family came back."""
    fams = row.get("families") or []
    # Older runs predate the confidence capture; treat them as confirmed so their numbers do not shift.
    confs = row.get("conf") or ["confirmed"] * len(fams)
    want = FAMILIES.get(cat, set())
    return any(f in want and c not in _UNPROVEN for f, c in zip(fams, confs))


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
        detected = _detected(r, cat)
        if is_vuln:
            b["tp" if detected else "fn"] += 1
        else:
            b["fp" if detected else "tn"] += 1
    total = {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "errors": 0}
    for b in per.values():
        for k in total:
            total[k] += b[k]
    cats = {c: _rates(b) for c, b in sorted(per.items())}
    # OFFICIAL SCORING IS A MACRO-AVERAGE of the per-category scores -- BenchmarkUtils averages the
    # category rates, it does not pool the cases. Pooling (micro) silently weights whichever category we
    # happened to sample most and is NOT comparable to a published Benchmark figure. Both are reported:
    # `official_macro` is the comparable number, `micro` is kept because it is the better description of
    # this run's raw hit rate when sampling is uneven.
    scored = [b["youden"] for b in cats.values() if b["youden"] is not None]
    macro = (sum(scored) / len(scored)) if scored else None
    # OFFICIAL: divide by every category the SUITE has, not by the ones we measured. A category with no
    # engine, or one we skipped, contributes 0 -- it is a real miss, not an exemption.
    suite = SUITE_CATEGORIES.get(run.get("target") or "", [])
    suite_macro, missing = None, []
    if suite:
        vals = []
        for c in suite:
            y = cats.get(c, {}).get("youden")
            vals.append(y if y is not None else 0.0)
            if c not in cats:
                missing.append(c)
        suite_macro = sum(vals) / len(vals)
    return {"per_category": cats, "overall": _rates(total),
            "official_macro": macro, "categories_scored": len(scored),
            "suite_macro": suite_macro, "suite_size": len(suite), "suite_missing": missing,
            "unscored": unscored}


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
    lines.append("")
    if s.get("suite_macro") is not None:
        lines.append("OFFICIAL SUITE SCORE (macro over ALL %d suite categories, unmeasured = 0): %s"
                     % (s.get("suite_size"), _fmt(s.get("suite_macro"))))
        lines.append("   ^ THIS is the number comparable to a published tool score")
        if s.get("suite_missing"):
            lines.append("   counted as 0 (no engine / not scanned): %s" % ", ".join(s["suite_missing"]))
    lines.append("measured-categories macro (%d cats, NOT comparable): %s"
                 % (s.get("categories_scored") or 0, _fmt(s.get("official_macro"))))
    lines.append("micro / pooled (NOT the official number): %s" % _fmt((s.get("overall") or {}).get("youden")))
    if s["unscored"]:
        lines.append("unscored (no key entry or no engine mapped): %d" % len(s["unscored"]))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan")
    sc.add_argument("--per-category", type=int, default=12)
    sc.add_argument("--seed", type=int, default=1337)
    sc.add_argument("--base", default="java", choices=sorted(BASES))
    sc.add_argument("--checkpoint", default="", help="append one JSON row per case; resumes if it exists")
    sc.add_argument("--categories", default="sqli,xss,pathtraver,ldapi,xpathi")
    so = sub.add_parser("score")
    so.add_argument("--run", required=True)
    so.add_argument("--key", required=True)
    so.add_argument("--base", default="java", choices=sorted(BASES))
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        out = asyncio.run(scan(a.per_category, [c for c in a.categories.split(",") if c],
                              a.seed, BASES[a.base], a.checkpoint))
        out["target"] = a.base
        print(json.dumps(out, indent=1))
        return 0
    with open(a.run, encoding="utf8") as fh:
        text = fh.read()
    try:
        run = json.loads(text)
    except Exception:
        # a checkpoint file: one JSON row per line, possibly truncated mid-line by a kill
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
        run = {"results": rows, "target": a.base}
    print(report(score(run, load_key(a.key))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
