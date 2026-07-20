"""
Race-condition (TOCTOU) testing via synchronized parallel requests.

Workflow from Bug Bounty Bootcamp (Li, Ch 12) + Web Security Testing Cookbook
(8.13/9.10): fire N identical requests at a race-prone action (coupon redeem,
balance transfer, vote, withdrawal) as close to simultaneously as possible, then
confirm the effect. Two things make this real rather than theatre:

  1. The requests must land together. tools._run_race warms a keep-alive/HTTP-2
     pool, parks N workers on a shared gate, and releases them at once — far
     closer to Kettle's single-packet idea than a bare asyncio.gather.
  2. The signal is a STATE CHANGE, not a pile of HTTP 200s. Transferring $10
     repeatedly returns 200 every time and is not a race. So the strong verdict
     comes from an optional verify request (e.g. a balance endpoint) read before
     and after the burst; a delta beyond a single operation is the finding. The
     2xx-over-limit count is only a weak secondary signal.

This module is pure/deterministic; the transport lives in tools._run_race.
"""
from __future__ import annotations

import re


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


def best_round(rounds: list) -> list:
    """Pick the burst with the most successes across a few retry rounds — race
    success depends on the server's scheduler, so we keep the best of several."""
    best, best_n = [], -1
    for r in rounds:
        n = sum(1 for x in r if _is_success(x.get("status")))
        if n > best_n:
            best, best_n = r, n
    return best


# Numbers in a response body (balances, counts, points) whose movement across the
# burst is the actual proof of a race.
_NUMS = re.compile(r"-?\d+(?:\.\d+)?")


def _numbers(body: str) -> list:
    return [float(x) for x in _NUMS.findall(body or "")][:200]


def verify_delta(before: dict, after: dict) -> dict:
    """Compare a state-reflecting response (e.g. a balance/vote-count endpoint)
    read before vs after the burst. `changed` is the strong race signal; we also
    surface the largest single numeric jump to characterize impact."""
    if not before or not after:
        return {"available": False}
    bb, ab = before.get("body", "") or "", after.get("body", "") or ""
    changed = bb != ab or before.get("length") != after.get("length")
    bn, an = _numbers(bb), _numbers(ab)
    max_jump = 0.0
    for x, y in zip(bn, an):
        max_jump = max(max_jump, abs(y - x))
    return {"available": True, "changed": changed, "max_numeric_jump": max_jump,
            "before_excerpt": bb[:200], "after_excerpt": ab[:200]}


def analyze_race(url: str, results: list, concurrency: int, rounds: int = 1,
                 verify: dict = None) -> list:
    """Build the race finding.

    Strong verdict: a verify request shows the state changed after the burst
    (the destination account gained more than one transfer's worth, the vote
    count jumped by >1, etc.) with 2+ concurrent successes.
    Weak verdict (candidate only): 2+ successes on what should be a single-use
    action, but no state check was provided to confirm it. This is deliberately
    conservative so the tool doesn't cry wolf on idempotent-but-repeatable calls.
    """
    s = summarize(results)
    if s["successes"] < 2:
        return []

    mixed = len(s["status_distribution"]) > 1     # some accepted, some rejected mid-race
    verify = verify or {}
    state_changed = verify.get("available") and verify.get("changed")

    if state_changed:
        jump = verify.get("max_numeric_jump", 0)
        sev = "critical" if jump and jump > 0 else "high"
        desc = (f"After firing {concurrency} simultaneous requests, {s['successes']} were accepted AND the verified "
                f"state changed (largest numeric jump {jump}). The action's single-use / balance check was raced.")
        conf = "confirmed"
        evidence = (f"successes={s['successes']}/{concurrency}; statuses={s['status_distribution']}; "
                    f"state before='{verify.get('before_excerpt','')}' after='{verify.get('after_excerpt','')}'")
    else:
        # no state proof — stay a candidate, and don't over-claim
        sev = "medium" if mixed else "low"
        note = ("no verify request was supplied, so this is unconfirmed — re-run with verify_url pointing at a "
                "state endpoint (balance/count) to prove impact")
        desc = (f"{s['successes']} of {concurrency} simultaneous requests were accepted "
                f"(statuses {s['status_distribution']}). If this action is single-use (coupon, transfer, vote, "
                f"withdrawal) the limit may have been raced — {note}.")
        conf = "candidate"
        evidence = f"successes={s['successes']}/{concurrency}; statuses={s['status_distribution']}"

    return [{
        "title": "Race condition (TOCTOU)" + ("" if state_changed else " candidate"),
        "severity": sev, "target": url, "description": desc,
        "impact": "Bypass single-use / balance checks: double-spend, coupon reuse, over-withdrawal, duplicate votes.",
        "reproduction_steps": [
            f"Read the state endpoint (baseline)" if verify.get("available") else "Note the resource's starting state",
            f"Fire {concurrency} identical requests to {url} simultaneously"
            + (f" (best of {rounds} rounds)" if rounds > 1 else ""),
            "Re-read the state endpoint and compare" if verify.get("available")
            else "Re-read the resource state to confirm the limit was bypassed",
            "Retry a few times — success depends on the server's scheduling"],
        "evidence": evidence, "cwe": "CWE-362", "family": "race",
        "tags": ["race-condition", "business-logic"], "confidence": conf}]
