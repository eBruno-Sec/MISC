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
    # CODE-ASSISTED (SAST) LANE ONLY. No HTTP response distinguishes AES/GCM from DES, so these three
    # are unreachable by the DAST lane and score 0 there -- which is the honest result, not a gap to
    # paper over. They are reachable by reading the source the operator supplies.
    #
    # `trustbound` is deliberately ABSENT. Its clean twins launder the tainted value through a
    # collection (`map.get("keyA-")`), a StringBuilder, or a ternary whose branch is decided by
    # constant folding -- distinguishing them needs real dataflow, not a call-site match. A
    # conservative approximation flags the clean twins, and a category mapped to a detector that
    # cannot separate them is a fabricated score. Leaving it unmapped scores an honest 0.
    "crypto": {"weak_crypto"},
    "hash": {"weak_hash"},
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
               checkpoint: str = "", shard: int = 0, shards: int = 1) -> dict:
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
        # SHARDING SPLITS WORK, NEVER THE SAMPLE. The sample is drawn first, from the same seed, so
        # `shards` workers over the same category cover exactly the cases one worker would have --
        # a stride slice, so no worker gets a contiguous run of test numbers and a shard that dies
        # leaves a spread-out gap rather than a block. Sampling per shard instead would give each
        # worker its own denominator, which is a different (and unstated) experiment.
        if shards > 1:
            picked = picked[shard::shards]
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


def scan_source(source_root: str, categories: list, base: str = "") -> dict:
    """CODE-ASSISTED (SAST) LANE. Grade the operator-supplied SOURCE, not the served application.

    Still blind by construction, and blind in the same two ways the DAST lane is. Case membership
    comes from the category index the app already serves over HTTP, exactly as `case_urls` gets it;
    the answer key stays inside the container and is never read here. Nothing in this path can see
    which cases are vulnerable.

    What it is NOT: a DAST result. Every row is stamped `lane: code-assisted` and the report refuses
    to present the number as anything else. Source is an explicit argument -- if a case has no file
    in the tree, that case is reported as "no source provided" and dropped from the denominator
    rather than counted as a miss.
    """
    import httpx
    import codeintel

    tree = codeintel.review_source_tree(source_root)
    by_stem: dict = {}
    for f in tree.get("findings") or []:
        stem = os.path.splitext(os.path.basename(f["file"]))[0]
        by_stem.setdefault(stem, []).append(f)
    have = {os.path.splitext(os.path.basename(p))[0] for p in (tree.get("files") or [])}

    results = []
    client = httpx.Client(verify=False, timeout=30, follow_redirects=True)
    for cat in categories:
        for name, url in case_urls(client, cat, base):
            fs = by_stem.get(name) or []
            row = {"test": name, "category": cat, "url": url,
                   "engine": "codeintel.review_source_tree", "lane": "code-assisted",
                   "provenance": "source-derived",
                   "families": [f["family"] for f in fs],
                   "conf": [f.get("confidence") or "confirmed" for f in fs],
                   "error": "" if name in have else "no source provided"}
            results.append(row)
            print("  %-10s %-18s %s" % (cat, name, row["families"] or row["error"] or "-"),
                  file=sys.stderr, flush=True)
    client.close()
    return {"lane": "code-assisted", "provenance": "source-derived", "source_root": source_root,
            "files_scanned": tree.get("files_scanned", 0),
            "properties_resolved": tree.get("properties_resolved", 0),
            "source_error": tree.get("error") or "", "results": results}


_UNMEASURED_ERRORS = ("no engine mapped", "no source provided")


def load_run(path: str, target: str = "") -> dict:
    """Read a scan artifact: either a full JSON document or a per-case checkpoint (one row per line).

    A checkpoint truncated mid-line by a kill is expected, so a row that will not parse is dropped
    rather than aborting the load -- losing one case is a smaller error than losing the whole run.
    """
    with open(path, encoding="utf8") as fh:
        text = fh.read()
    try:
        run = json.loads(text)
        if isinstance(run, dict) and "results" in run:
            return run
    except Exception:
        pass
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return {"results": rows, "target": target}


def merge_runs(runs: list) -> dict:
    """UNION several scan artifacts into one HYBRID run, one row per case.

    A real engagement runs more than one lane and the client receives the UNION of what they report,
    so the union is what must be scored -- including the union of their false positives. Merging is
    therefore deliberately symmetric: every family from every lane is carried onto the merged row, and
    nothing is dropped for being inconvenient.

    Two rules keep the merge from inventing a result:

    1. A case is UNSCORED only when EVERY contributing lane failed to measure it ("no engine mapped",
       "no source provided"). If one lane measured it, the case is measured -- booking it unscored
       would let a hybrid quietly narrow its own denominator, which is the exact mistake that made an
       earlier run read 58.1% when the comparable figure was 30.5%.
    2. The merged row records `lane: hybrid` and the contributing lanes by name, so the code-assisted
       contribution can never be silently reported as a DAST number. `score` surfaces those lanes and
       `report` prints the mixed-lane banner above the table.
    """
    merged: dict = {}
    order: list = []
    for run in runs:
        for r in run.get("results", []):
            test = r.get("test")
            if not test:
                continue
            lane = str(r.get("lane") or "dast")
            unmeasured = str(r.get("error") or "").startswith(_UNMEASURED_ERRORS)
            row = merged.get(test)
            if row is None:
                row = {"test": test, "category": r.get("category"), "url": r.get("url"),
                       "families": [], "conf": [], "error": "", "lanes": [], "engines": []}
                merged[test] = row
                order.append(test)
            fams = list(r.get("families") or [])
            confs = list(r.get("conf") or ["confirmed"] * len(fams))
            confs = (confs + ["confirmed"] * len(fams))[:len(fams)]
            row["families"] += fams
            row["conf"] += confs
            if r.get("engine"):
                row["engines"].append(r["engine"])
            if unmeasured:
                # Record the excuse VERBATIM; a later lane that DID measure this case clears it below.
                # It must stay verbatim: `score` decides a case is unmeasured by matching the start of
                # this string, so decorating it with the lane name (an earlier version of this function
                # wrote "dast: no engine mapped") makes the check miss and books a case NOTHING ever
                # analysed as a false negative. Lane attribution goes in its own field.
                row.setdefault("_unmeasured", []).append(str(r.get("error") or ""))
                row.setdefault("unmeasured_by", []).append("%s: %s" % (lane, r.get("error")))
            else:
                row["_measured"] = True
                if lane not in row["lanes"]:
                    row["lanes"].append(lane)
    out = []
    for test in order:
        row = merged[test]
        if row.pop("_measured", False):
            row["error"] = ""
            row.pop("unmeasured_by", None)
        else:
            row["error"] = (row.get("_unmeasured") or ["no engine mapped"])[0] or "no engine mapped"
        row.pop("_unmeasured", None)
        lanes = row["lanes"]
        row["lane"] = "hybrid" if len(lanes) > 1 else (lanes[0] if lanes else "dast")
        out.append(row)
    return {"results": out, "merged_from": len(runs)}


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


def _any_confirmed(row: dict) -> bool:
    """True when ANY confirmed finding came back, whatever family it claims.

    `_detected` deliberately only credits the case's OWN family — that is the official CWE-matching
    convention and it is correct for TPR. It is WRONG for a false-positive rate, and that error was
    load-bearing: 22 clean `securecookie` cases carried CONFIRMED `path_traversal` findings and every
    one of them scored as a true negative, because path_traversal is not securecookie's family. The
    published FPR was 0.0% while a client's report for those same cases would have carried 22 false
    positives.

    A within-family scorer structurally cannot measure a whole-product false-positive rate. Anything
    the tool would actually put in front of a client on a clean case is a false positive, whatever
    family it claims.
    """
    fams = row.get("families") or []
    confs = row.get("conf") or ["confirmed"] * len(fams)
    return any(c not in _UNPROVEN for c in confs[:len(fams)] or confs)


def score(run: dict, key: dict) -> dict:
    """TPR, FPR and the Benchmark score (Youden J = TPR - FPR) per category and overall.

    A case counts as DETECTED only when a finding of that category's own family came back. Cases the
    key does not cover, or where no engine is mapped, are reported separately and never folded into a
    rate -- an unmeasured case is not a miss.
    """
    per, unscored, lanes = {}, [], set()
    for r in run.get("results", []):
        entry = key.get(r["test"])
        # A case the tool was never actually given is UNSCORED, not a miss. "no source provided" is
        # the code-assisted lane's version of "no engine mapped": the analysis did not run, so its
        # result is unknown -- and silently booking an unknown as a false negative understates the
        # tool exactly as booking it as a pass would overstate it.
        if entry is None or str(r.get("error") or "").startswith(("no engine mapped",
                                                                  "no source provided")):
            unscored.append(r["test"])
            continue
        # A merged row carries EVERY lane that contributed to it. Recording only the row's summary
        # label would let a hybrid print as a single-lane result, and the banner is the one part of
        # this report that survives being copy/pasted into someone else's document.
        lanes.update(str(x) for x in (r.get("lanes") or [r.get("lane") or "dast"]))
        _cat_in_key, is_vuln = entry
        cat = r["category"]
        b = per.setdefault(cat, {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "errors": 0,
                                 "fp_any": 0, "tn_any": 0, "cross_family_fp": 0})
        if r.get("error"):
            b["errors"] += 1
        detected = _detected(r, cat)
        if is_vuln:
            b["tp" if detected else "fn"] += 1
        else:
            b["fp" if detected else "tn"] += 1
            # PRODUCT VIEW, tracked alongside the official one rather than replacing it. Both numbers
            # are real; they answer different questions, and quoting the wrong one is how 0.0% FPR got
            # published. `fp_any` counts every clean case the tool would have reported ANYTHING
            # confirmed on. `cross_family_fp` isolates the ones the official convention forgives.
            any_conf = _any_confirmed(r)
            b["fp_any" if any_conf else "tn_any"] += 1
            if any_conf and not detected:
                b["cross_family_fp"] += 1
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
    scored_p = [b["youden_product"] for b in cats.values() if b.get("youden_product") is not None]
    macro_product = (sum(scored_p) / len(scored_p)) if scored_p else None
    # OFFICIAL: divide by every category the SUITE has, not by the ones we measured. A category with no
    # engine, or one we skipped, contributes 0 -- it is a real miss, not an exemption.
    suite = SUITE_CATEGORIES.get(run.get("target") or "", [])
    suite_macro, suite_macro_product, missing = None, None, []
    if suite:
        vals, vals_p = [], []
        for c in suite:
            y = cats.get(c, {}).get("youden")
            vals.append(y if y is not None else 0.0)
            yp = cats.get(c, {}).get("youden_product")
            vals_p.append(yp if yp is not None else 0.0)
            if c not in cats:
                missing.append(c)
        suite_macro = sum(vals) / len(vals)
        suite_macro_product = sum(vals_p) / len(vals_p)
    return {"per_category": cats, "overall": _rates(total),
            "official_macro": macro, "categories_scored": len(scored),
            "suite_macro": suite_macro, "suite_size": len(suite), "suite_missing": missing,
            # The product figures. Quote THESE when the question is "how good is Apolaki"; quote the
            # official ones only when comparing against a published Benchmark score, and say which.
            "product_macro": macro_product, "suite_macro_product": suite_macro_product,
            "cross_family_fp": sum(b.get("cross_family_fp", 0) for b in cats.values()),
            "lanes": sorted(lanes), "unscored": unscored}


def _rates(b: dict) -> dict:
    pos, neg = b["tp"] + b["fn"], b["fp"] + b["tn"]
    tpr = (b["tp"] / pos) if pos else None
    fpr = (b["fp"] / neg) if neg else None
    out = dict(b)
    out["tpr"] = tpr
    out["fpr"] = fpr
    out["youden"] = (tpr - fpr) if (tpr is not None and fpr is not None) else None
    # The product view: same TPR, but every confirmed finding on a clean case counts against us.
    neg_any = b.get("fp_any", 0) + b.get("tn_any", 0)
    fpr_any = (b["fp_any"] / neg_any) if neg_any else None
    out["fpr_any"] = fpr_any
    out["youden_product"] = (tpr - fpr_any) if (tpr is not None and fpr_any is not None) else None
    return out


def _fmt(v):
    return "  n/a" if v is None else "%5.1f%%" % (100 * v)


def _lane_banner(lanes: list) -> list:
    """State the lane before the numbers, every time.

    A percentage travels; the sentence explaining what produced it does not. The only defence that
    survives a copy/paste into a report is a label printed above the table it belongs to.
    """
    if not lanes or lanes == ["dast"]:
        return []
    out = []
    if len(lanes) > 1:
        out += ["!! MIXED LANES IN ONE RUN (HYBRID RESULT): %s" % ", ".join(lanes),
                "   A source-derived detection and an HTTP-proven one are NOT the same evidence.",
                "   This figure is only meaningful quoted as a HYBRID (DAST + code-assisted) number,",
                "   printed next to the DAST-only figure. It may NEVER be compared against a published",
                "   DAST score (ZAP 17.99%, best-published 26%) -- those tools were never given source.",
                ""]
    if "code-assisted" in lanes:
        out += ["CODE-ASSISTED (SAST) LANE — findings are SOURCE-DERIVED from operator-supplied code.",
                "   This is not a DAST result. Do NOT fold it into a DAST figure and do NOT compare it",
                "   against a published DAST score (ZAP 17.99%, best-published 26%) — those tools were",
                "   never given the source. Quote it as what it is: a code-assisted number.",
                ""]
    return out


def report(s: dict) -> str:
    lines = _lane_banner(s.get("lanes") or [])
    lines += ["%-13s %5s %5s %5s %5s   %7s %7s %8s" % (
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
        # THE CAPTION MUST KNOW ITS LANE. These two lines sit directly under the number, which makes
        # them the ones that survive a copy/paste -- and on a HYBRID run they were printing
        # "comparable to a PUBLISHED tool score" eleven lines below a banner saying the opposite.
        # A caption that contradicts its own banner is worse than no caption: the banner scrolls away
        # and the caption travels with the figure.
        _hybrid = bool(s.get("lane") and "code" in str(s.get("lane")).lower())
        if _hybrid:
            lines.append("   ^ NOT comparable to a published DAST score -- this run includes the")
            lines.append("     code-assisted (SAST) lane, and those tools were never given the source")
        else:
            lines.append("   ^ comparable to a PUBLISHED tool score (official CWE-matching convention:")
            lines.append("     a finding only counts against a clean case if it claims that case's family)")
        lines.append("")
        lines.append("PRODUCT SUITE SCORE (same TPR; every confirmed finding on a clean case is an FP): %s"
                     % _fmt(s.get("suite_macro_product")))
        lines.append("   ^ the number to quote for 'how good is Apolaki'%s"
                     % (" -- as a HYBRID (DAST + code-assisted SAST) figure" if _hybrid else ""))
        _x = s.get("cross_family_fp") or 0
        if _x:
            lines.append("   cross-family false positives the official convention forgives: %d" % _x)
            lines.append("   (clean cases where the tool WOULD have reported something to a client)")
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
    sc.add_argument("--shard", default="0/1",
                    help="k/n -- run only every n-th case of the SAME sample, for parallel workers")
    sc.add_argument("--categories", default="sqli,xss,pathtraver,ldapi,xpathi")
    ss = sub.add_parser("scan-source", help="CODE-ASSISTED (SAST) lane: grade operator-supplied source")
    ss.add_argument("--source", required=True, help="path to the source tree; explicit, never inferred")
    ss.add_argument("--base", default="java", choices=sorted(BASES))
    ss.add_argument("--categories", default="crypto,hash,weakrand")
    mg = sub.add_parser("merge", help="UNION scan artifacts (DAST + code-assisted) into one hybrid run")
    mg.add_argument("--run", action="append", required=True,
                    help="repeatable; a scan JSON or a per-case checkpoint file")
    mg.add_argument("--base", default="java", choices=sorted(BASES))
    so = sub.add_parser("score")
    so.add_argument("--run", action="append", required=True,
                    help="repeatable; more than one merges them into a hybrid run first")
    so.add_argument("--key", required=True)
    so.add_argument("--base", default="java", choices=sorted(BASES))
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        k, _, n = a.shard.partition("/")
        shard, shards = int(k or 0), int(n or 1)
        if shards < 1 or not (0 <= shard < shards):
            ap.error("--shard must be k/n with 0 <= k < n")
        out = asyncio.run(scan(a.per_category, [c for c in a.categories.split(",") if c],
                              a.seed, BASES[a.base], a.checkpoint, shard, shards))
        out["target"] = a.base
        out["shard"] = a.shard
        print(json.dumps(out, indent=1))
        return 0
    if a.cmd == "scan-source":
        out = scan_source(a.source, [c for c in a.categories.split(",") if c], BASES[a.base])
        out["target"] = a.base
        if out.get("source_error"):
            print("SOURCE NOT USABLE: %s" % out["source_error"], file=sys.stderr)
        print(json.dumps(out, indent=1))
        return 0
    runs = [load_run(p, a.base) for p in a.run]
    if a.cmd == "merge":
        out = merge_runs(runs)
        out["target"] = a.base
        print(json.dumps(out, indent=1))
        return 0
    run = runs[0] if len(runs) == 1 else merge_runs(runs)
    # A scan artifact records the suite it ran against; keep it. `--base` only fills the gap for a
    # checkpoint file or a merge, which carry no target of their own. Overriding a recorded target
    # would silently score a Python run against the 11-category Java denominator.
    run["target"] = run.get("target") or a.base
    print(report(score(run, load_key(a.key))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
