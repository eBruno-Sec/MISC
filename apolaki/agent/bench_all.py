"""Multi-lab regression harness (#101). Scan each REACHABLE benchmark lab through the real pipeline, score the
findings against benchmark.MANIFESTS with benchmark.evaluate(), and aggregate per-lab + overall so a change can be
regression-checked across every lab at once (precision-adjacent: unexpected classes; recall: class coverage;
coverage: which expected classes were reached). The AGGREGATION is pure and scan-function-injected, so it is
unit-testable with synthetic findings without standing up any container; the live driver drives the mission API."""
from __future__ import annotations

import benchmark

# Compose-network URL per manifest key — ONLY the labs actually wired in docker-compose.yml (others in
# benchmark.MANIFESTS are valid specs but not stood up here). The harness scans whatever is reachable.
LAB_URLS = {
    "juiceshop": "http://juice-shop:3000",
    "dvwa": "http://dvwa",
    "bwapp": "http://bwapp",
    "mutillidae": "http://mutillidae",
    "webgoat": "http://webgoat:8080/WebGoat",
    "vampi": "http://vampi:5000",
    "dvga": "http://dvga:5013",
}

# The minimum gate a change must not regress (labs that must always be reachable + scored in CI-adjacent runs).
MIN_GATE = ["juiceshop", "vampi"]


def aggregate(evaluations: list) -> dict:
    """Overall summary across per-lab benchmark.evaluate() results. Pure."""
    labs = [e for e in (evaluations or []) if isinstance(e, dict) and "metrics" in e]
    if not labs:
        return {"labs": 0, "mean_class_coverage_pct": 0.0, "mean_confirmed_coverage_pct": 0.0,
                "total_false_negatives": 0, "total_unexpected": 0, "per_lab": []}
    n = len(labs)
    return {
        "labs": n,
        "mean_class_coverage_pct": round(sum(e["metrics"]["class_coverage_pct"] for e in labs) / n, 1),
        "mean_confirmed_coverage_pct": round(sum(e["metrics"]["confirmed_coverage_pct"] for e in labs) / n, 1),
        "total_false_negatives": sum(e["metrics"]["false_negatives"] for e in labs),
        "total_unexpected": sum(e["metrics"]["unexpected_classes"] for e in labs),
        "per_lab": [{"fixture": e["fixture"], "name": e.get("name", e["fixture"]),
                     "class_coverage_pct": e["metrics"]["class_coverage_pct"],
                     "confirmed_coverage_pct": e["metrics"]["confirmed_coverage_pct"],
                     "false_negatives": e["metrics"]["false_negatives"],
                     "unexpected": e["metrics"]["unexpected_classes"]} for e in labs],
    }


def bench(labs: list, scan_fn) -> dict:
    """Run the harness over `labs` (manifest keys). `scan_fn(key, url) -> (findings, leads)` supplies each lab's
    scan output; the harness scores it with benchmark.evaluate() and aggregates. Pure w.r.t. scan_fn — inject a
    real scanner for a live run, or synthetic findings in a unit test. Skips keys with no wired URL / manifest."""
    evaluations = []
    for key in labs or []:
        url = LAB_URLS.get(key)
        if not url or key not in benchmark.MANIFESTS:
            continue
        try:
            findings, leads = scan_fn(key, url)
        except Exception as e:                               # a lab that errors is recorded, never crashes the sweep
            evaluations.append({"fixture": key, "url": url, "error": str(e)[:200]})
            continue
        ev = benchmark.evaluate(key, findings, leads)
        ev["url"] = url
        evaluations.append(ev)
    return {"results": evaluations, "summary": aggregate(evaluations),
            "gate_ok": all(any(e.get("fixture") == g and "metrics" in e for e in evaluations) for g in MIN_GATE)}


async def reachable(url: str, timeout: float = 6.0) -> bool:
    """True if the lab answers an HTTP request (any status) — so the harness scores only labs that are UP."""
    import httpx
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as c:
            r = await c.get(url)
            return r.status_code < 600
    except Exception:
        return False


async def reachable_labs(labs: list = None) -> list:
    """Subset of `labs` (default: all wired) that are currently reachable on the network."""
    keys = labs or list(LAB_URLS)
    out = []
    for k in keys:
        if k in LAB_URLS and await reachable(LAB_URLS[k]):
            out.append(k)
    return out


async def scan_via_mission(api_base: str, key: str, url: str, poll_s: int = 6, max_wait_s: int = 600):
    """Live scan_fn built on the REAL mission pipeline: engage + run a deterministic full scan against the lab,
    poll to completion, return (findings, leads). Used for a live sweep; unit tests inject a synthetic scan_fn."""
    import asyncio
    import httpx
    from urllib.parse import urlparse
    host = urlparse(url).netloc or url
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        eng = (await c.post(api_base + "/engage", json={
            "program_name": "bench-%s" % key, "in_scope": [host], "mode": "full",
            "strategy": "deterministic", "auto_approve": True})).json()
        sid = eng.get("session_id") or eng.get("id") or eng.get("sid")
        if not sid:
            return [], []
        await c.post(api_base + "/run/%s" % sid)
        waited = 0
        while waited < max_wait_s:
            await asyncio.sleep(poll_s)
            waited += poll_s
            m = (await c.get(api_base + "/missions/%s" % sid)).json()
            if str(m.get("status")) in ("complete", "error", "failed", "stopped"):
                return (m.get("findings") or []), (m.get("leads") or [])
        return [], []
