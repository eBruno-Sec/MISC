"""Whole-product rerun: owaspbench-q019 shape, current code, SEALED before any key is touched.

Drives BBHAgent.run() -- the same full pipeline the API mission uses -- not just _execute_plan, so
this is comparable to mission ebd96f45 (95.7% precision / 1.6% recall, 22 TP / 1 FP / 1415 vulnerable).

Writes /out/wp_claims.json and prints the SEAL (sha256 over the sorted distinct case ids). The key is
NOT read here and must not be read until the seal is recorded.
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


def case_ids(rec):
    blob = " ".join(str(rec.get(k, "")) for k in
                    ("title", "target", "evidence", "description", "request", "poc", "impact"))
    return {m.group(1) for m in CASE_RE.finditer(blob)}


async def main():
    t0 = time.time()
    eng = scope_mod.ScopeEngine()
    eng.load_manual([TARGET], [], "owaspbench-q019-rerun")
    reg = tools_mod.ToolRegistry(eng, mission_id=None, lab_mode=True)
    ag = agent_mod.BBHAgent(eng, reg, asyncio.Event(), mode=MODE, auto_approve=True,
                            strategy="deterministic", mission_id=None)

    phases = []
    async for ev in ag.run("Whole-product benchmark rerun", "wp"):
        t = ev.get("type")
        if t == "phase":
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
    }
    os.makedirs("/out", exist_ok=True)
    with open("/out/wp_claims.json", "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)

    print()
    print("=== WHOLE-PRODUCT RERUN, SEALED ===")
    print("elapsed                 : %ds" % elapsed)
    print("findings total          :", len(findings))
    print("leads total             :", out["leads_total"])
    print("by family               :", fam)
    print("distinct cases claimed  :", len(claims))
    print("SEAL sha256             :", seal)
    print("(key NOT read; score only after this seal is recorded)")


asyncio.run(main())
