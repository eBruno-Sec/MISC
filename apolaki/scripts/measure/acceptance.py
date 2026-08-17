"""ACCEPTANCE: same target, same mode -- wall clock must drop AND the finding set must be identical.

Drives the REAL sweep path (the same _run_tool -> tools.execute pipeline a mission uses) over the
whole crawled surface of a lab, at whatever BBH_BROWSER_CONCURRENCY the environment sets. Prints a
stable, sorted fingerprint of the finding set plus the wall clock.

  MEAS_TARGET   base URL of the lab
  BBH_BROWSER_CONCURRENCY  the width under test
"""
import asyncio, hashlib, json, os, sys, time
sys.path.insert(0, "/app")

import scope as scope_mod
import tools as T

BASE = os.environ.get("MEAS_TARGET", "http://domsource:8080")
ENGINES = ("run_xss", "run_dom_trace", "run_dom_audit")


def _fp(f):
    """Stable identity of a finding. Deliberately EXCLUDES the per-render canary and the
    screenshot: both are random/binary in the serial path too, so including them would fail a
    serial-vs-serial comparison and prove nothing about parallelism."""
    ev = str(f.get("evidence") or "")
    for k in ("canary", "domtr", "domfr", "evilc"):
        ev = ev.replace(k, k)
    return {
        "title": f.get("title"),
        "family": f.get("family"),
        "severity": f.get("severity"),
        "confidence": f.get("confidence"),
        "cwe": f.get("cwe"),
        "target_path": (f.get("target") or "").split("?")[0].split("#")[0],
    }


async def crawl(reg, sc):
    """Seed the surface the way a mission does: fetch the root, harvest links."""
    await reg.execute("http_probe", {"url": BASE}, "acc")
    urls = [u for u in dict.fromkeys(list(reg.urls or []) + [BASE]) if sc.validate(u)[0]]
    return sorted(urls)


async def main():
    sc = scope_mod.ScopeEngine()
    sc.load_manual([BASE], [], "acceptance")
    reg = T.ToolRegistry(sc, mission_id=None, lab_mode=True)

    urls = await crawl(reg, sc)
    findings, t0 = [], time.perf_counter()
    for u in urls:
        for eng in ENGINES:
            try:
                res = await reg.execute(eng, {"url": u}, "acc")
                findings.extend(res.findings or [])
            except Exception as e:
                findings.append({"title": "ENGINE CRASH %s: %s" % (eng, type(e).__name__),
                                 "family": "crash", "severity": "info"})
    wall = time.perf_counter() - t0

    fps = sorted(json.dumps(_fp(f), sort_keys=True) for f in findings)
    digest = hashlib.sha256("\n".join(fps).encode()).hexdigest()[:16]
    print(json.dumps({
        "width": T.browser_concurrency(),
        "urls": len(urls),
        "wall_s": round(wall, 2),
        "s_per_url": round(wall / max(len(urls), 1), 2),
        "findings": len(findings),
        "digest": digest,
        "swallowed": len(reg.swallowed),
        "set": fps,
    }, indent=2))


asyncio.run(main())
