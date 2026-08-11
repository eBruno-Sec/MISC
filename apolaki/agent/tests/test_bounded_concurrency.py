"""The bounded, deterministic concurrency primitive behind the browser-engine speedup.

MEASURED motivation (docs/handoff/throughput.md): 82% of run_xss's wall clock is a fixed
`page.wait_for_timeout(350)` after every navigation, run serially. The fix overlaps those waits --
which is only allowed if the overlap cannot change WHICH findings come back. Every test here exists
to pin one of the properties that makes that true.
"""
import asyncio
import random

import pytest

import tools


# ── the width dial ────────────────────────────────────────────────────────────
def test_browser_concurrency_default_is_bounded_and_greater_than_one(monkeypatch):
    monkeypatch.delenv("BBH_BROWSER_CONCURRENCY", raising=False)
    w = tools.browser_concurrency()
    assert w > 1, "a default of 1 would ship the serial behaviour the ticket exists to fix"
    assert w <= tools.BROWSER_CONCURRENCY_MAX


def test_browser_concurrency_is_configurable(monkeypatch):
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "3")
    assert tools.browser_concurrency() == 3


def test_browser_concurrency_is_never_unbounded(monkeypatch):
    """A scanner that melts a client's staging environment is worse than a slow one."""
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "100000")
    assert tools.browser_concurrency() == tools.BROWSER_CONCURRENCY_MAX

    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "0")
    assert tools.browser_concurrency() == 1
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "-5")
    assert tools.browser_concurrency() == 1


def test_browser_concurrency_survives_garbage(monkeypatch):
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "banana")
    assert tools.browser_concurrency() >= 1
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "")
    assert tools.browser_concurrency() >= 1


# ── the primitive ─────────────────────────────────────────────────────────────
def _run(coro):
    """Own loop per call, and CLOSED afterwards. A leaked loop is how one test file
    starts failing another one three files later."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.mark.parametrize("width", [1, 2, 3, 5, 8, 64])
def test_results_come_back_in_item_order_not_completion_order(width):
    """THE determinism property. Workers finish in a deliberately scrambled order; the
    result list must still follow the input list."""
    items = list(range(20))

    async def worker(i):
        # later items finish FIRST -- completion order is the reverse of item order
        await asyncio.sleep((20 - i) * 0.001)
        return i * 10

    out = _run(tools.bounded_map(items, worker, width))
    assert out == [(i, i * 10) for i in items]


def test_width_one_is_exactly_a_serial_loop():
    """Negative control (b): a single-URL / width-1 mission must not change its result."""
    seen = []

    async def worker(i):
        seen.append(("start", i))
        await asyncio.sleep(0.001)
        seen.append(("end", i))
        return i

    out = _run(tools.bounded_map([1, 2, 3, 4], worker, 1))
    assert out == [(1, 1), (2, 2), (3, 3), (4, 4)]
    # strictly interleaved start/end -- nothing ever overlapped
    assert seen == [("start", 1), ("end", 1), ("start", 2), ("end", 2),
                    ("start", 3), ("end", 3), ("start", 4), ("end", 4)]


def test_concurrency_is_actually_bounded():
    """The ceiling is real, not decorative: peak in-flight never exceeds the width."""
    state = {"now": 0, "peak": 0}

    async def worker(i):
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.005)
        state["now"] -= 1
        return i

    _run(tools.bounded_map(list(range(30)), worker, 4))
    assert state["peak"] <= 4
    assert state["peak"] > 1, "nothing ran concurrently -- the primitive did not parallelise"


def test_the_work_actually_overlaps():
    """The whole point: N sleeps of D cost about D, not N*D."""
    import time

    async def worker(i):
        await asyncio.sleep(0.05)
        return i

    t0 = time.perf_counter()
    _run(tools.bounded_map(list(range(8)), worker, 8))
    par = time.perf_counter() - t0
    assert par < 8 * 0.05 * 0.6, "sleeps did not overlap (%.3f s)" % par


def test_an_exception_in_one_item_does_not_lose_the_others():
    async def worker(i):
        if i == 2:
            raise RuntimeError("boom")
        return i

    out = _run(tools.bounded_map([1, 2, 3], worker, 3))
    assert out[0] == (1, 1)
    assert out[2] == (3, 3)
    assert isinstance(out[1][1], Exception), "a failing probe must surface, not vanish"


def test_empty_input_is_a_no_op():
    assert _run(tools.bounded_map([], lambda i: None, 4)) == []


# ── the skip predicate (the early-exit that keeps request counts down) ────────
def test_skip_is_evaluated_at_chunk_boundaries_so_the_run_stays_deterministic():
    """`skip` lets a confirmed (where,param) stop paying for its remaining payloads.
    It must be applied at FIXED chunk boundaries -- if it were applied the instant a
    sibling finished, which items got skipped would depend on timing and two identical
    runs could issue different numbers of requests."""
    confirmed = set()
    ran = []

    async def worker(i):
        await asyncio.sleep(random.random() * 0.004)
        ran.append(i)
        if i == 0:
            confirmed.add("p")
        return i

    # width 3 over 9 items: chunk [0,1,2] confirms, so chunks [3..5] and [6..8] are skipped.
    out = _run(tools.bounded_map(list(range(9)), worker, 3,
                                 skip=lambda i: "p" in confirmed))
    assert sorted(ran) == [0, 1, 2], "skip did not take effect at the next chunk boundary"
    assert [i for i, _ in out] == [0, 1, 2]


def test_skip_result_is_stable_across_repeated_runs():
    """Same input, same width => byte-identical outcome, every time. Run it enough
    times that a timing-dependent implementation would have been caught."""
    def once():
        confirmed = set()
        ran = []

        async def worker(i):
            await asyncio.sleep(random.random() * 0.003)
            ran.append(i)
            if i == 4:
                confirmed.add("hit")
            return i * 2

        out = _run(tools.bounded_map(list(range(12)), worker, 5,
                                     skip=lambda i: "hit" in confirmed))
        return sorted(ran), out

    first = once()
    for _ in range(12):
        assert once() == first


def test_skip_never_runs_when_the_predicate_is_false():
    async def worker(i):
        return i

    out = _run(tools.bounded_map([1, 2, 3], worker, 2, skip=lambda i: False))
    assert [i for i, _ in out] == [1, 2, 3]


# ── the platform keeps exactly one race primitive ────────────────────────────
def test_bounded_map_did_not_become_a_second_race_primitive():
    """`_run_race` parks N workers on a gate and releases them SIMULTANEOUSLY -- that
    simultaneity is the TOCTOU signal and must not be re-implemented (or diluted) here.
    bounded_map is the opposite contract: a ceiling on in-flight work, with no
    simultaneity guarantee at all."""
    import inspect
    src = inspect.getsource(tools.bounded_map)
    assert "Event" not in src, "a throughput limiter must not grow a race gate"
    assert "gate" not in src.lower()
    # and the real one is still there, still gated
    race_src = inspect.getsource(tools.ToolRegistry._run_race)
    assert "gate.set()" in race_src and "asyncio.Event()" in race_src
