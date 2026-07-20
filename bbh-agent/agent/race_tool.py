"""
Race-condition (TOCTOU) testing via parallel requests.

Workflow from Bug Bounty Bootcamp (Li, Ch 12) + Web Security Testing Cookbook
(8.13/9.10): fire N identical requests simultaneously at a race-prone action
(coupon redeem, balance transfer, vote, invite accept, withdrawal) and look for
a single-use action succeeding more than once. The analysis is pure and
unit-tested; tools._run_race does the concurrent send with asyncio.gather.
"""
from __future__ import annotations


def _is_success(status: int) -> bool:
    return 200 <= (status or 0) < 300


def summarize(results: list) -> dict:
    """Tally a list of {status,length} race results."""
    dist = {}
    for r in results:
        s = r.get("status", 0)
        dist[s] = dist.get(s, 0) + 1
    successes = [r for r in results if _is_success(r.get("status"))]
    return {"total": len(results), "successes": len(successes),
            "status_distribution": dist,
            "success_lengths": sorted({r.get("length", 0) for r in successes})}


def analyze_race(url: str, results: list, concurrency: int) -> list:
    """Flag a race-condition candidate when a limited action succeeds more than
    once under concurrency. Reported as a candidate — the analyst confirms the
    action was meant to be single-use."""
    s = summarize(results)
    findings = []
    if s["successes"] >= 2:
        mixed = len(s["status_distribution"]) > 1  # some succeeded, some were rejected
        sev = "high" if mixed else "medium"
        findings.append({
            "title": "Race condition (TOCTOU) candidate",
            "severity": sev, "target": url,
            "description": (f"{s['successes']} of {concurrency} simultaneous requests succeeded "
                            f"(status distribution {s['status_distribution']}). If this action is meant to be "
                            "single-use (coupon, transfer, vote, withdrawal), the limit was bypassed by racing."),
            "impact": "Bypass single-use / rate limits: double-spend, coupon reuse, over-withdrawal, duplicate actions.",
            "reproduction_steps": [f"Send {concurrency} identical requests to {url} simultaneously",
                                   f"Observe {s['successes']} succeed where only one should",
                                   "Confirm the underlying action is limited/single-use"],
            "evidence": f"successes={s['successes']}/{concurrency}, statuses={s['status_distribution']}",
            "cwe": "CWE-362", "family": "race", "tags": ["race-condition", "business-logic"],
            "confidence": "candidate"})
    return findings
