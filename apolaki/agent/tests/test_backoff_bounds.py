"""Q-043 -- the two gaps `c02208d` left in the target Retry-After policy.

`c02208d` honours both header forms on both limiting statuses and clamps a single absurd value;
`tests/test_rate_policy.py` already holds that. This file holds what it did NOT do:

  GAP-1  the cap bounded one HEADER, never the WAIT. Measured: 270.0s of real waiting under a
         documented 30s cap, because the shared origin deadline is extend-only.
  GAP-2  the wait was invisible -- no counter, no event, and every call site discards the seconds
         the wait methods return.
  GAP-3  `wait_*` re-reads the deadline after each sleep with no iteration bound, so an injected
         sleeper that does not advance the clock spins forever.

Nothing here sleeps for real. Every test injects the clock and the sleeper, so a 30-second bound is
proved in milliseconds -- a suite that waits out a backoff is a suite people stop running.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import browser_engine as browser


def _run(coro):
    import asyncio
    return asyncio.new_event_loop().run_until_complete(coro)


def _extending_policy(max_wait, extensions, header="30"):
    """A policy whose origin deadline is pushed out by a sibling worker `extensions` times.

    This is the measured production shape, not a contrivance: `observe()` is extend-only and
    shared per origin, and a concurrent engine meeting a fresh 429 calls it while another caller
    is already parked on the gate.
    """
    clock, sleeps = [0.0], []
    policy = None

    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay
        if len(sleeps) <= extensions:
            policy.observe("https://a.example/sibling", 429, {"retry-after": header})

    policy = browser.TargetRatePolicy(max_wait=max_wait, clock=lambda: clock[0], sync_sleep=sleep)
    return policy, sleeps


# ---------------------------------------------------------------- GAP-1: the wait itself is bounded

def test_a_moving_deadline_cannot_park_a_caller_past_the_cap():
    """THE REGRESSION. Before the fix this waited 270.0s against a 30s cap."""
    policy, sleeps = _extending_policy(max_wait=30, extensions=8)
    policy.observe("https://a.example/first", 429, {"retry-after": "30"})

    waited = policy.wait_sync("https://a.example/next")

    assert waited <= 30, "a sibling's 429 extended the deadline out from under a waiting caller"
    assert sum(sleeps) <= 30
    assert waited == pytest.approx(30)


def test_the_bound_does_not_truncate_an_ordinary_single_cooldown():
    """POSITIVE CONTROL for the test above. A bound that clips normal waits would 'pass' the
    regression by never waiting at all, which is a false negative wearing a green tick."""
    clock, sleeps = [0.0], []
    policy = browser.TargetRatePolicy(max_wait=30, clock=lambda: clock[0],
                                      sync_sleep=lambda d: (sleeps.append(d),
                                                            clock.__setitem__(0, clock[0] + d)))
    policy.observe("https://a.example/x", 429, {"retry-after": "7"})

    assert policy.wait_sync("https://a.example/y") == pytest.approx(7)
    assert sleeps == [7], "an ordinary 7s cooldown was not honoured in full"


def test_the_cooldown_survives_a_truncated_crossing_so_the_next_request_waits_again():
    """Truncation releases ONE request, it does not cancel the target's cooldown. Without this the
    bound would degrade into 'ignore Retry-After after the first 30 seconds'."""
    policy, _ = _extending_policy(max_wait=30, extensions=8)
    policy.observe("https://a.example/first", 429, {"retry-after": "30"})
    policy.wait_sync("https://a.example/next")

    assert policy.remaining("https://a.example/next") > 0


@pytest.mark.parametrize("waiter", ["sync", "async"])
def test_both_transports_share_the_bound(waiter):
    """The async path is the HTTP engine and the sync path is the browser driver. A bound on one
    only is the island shape this codebase keeps producing."""
    clock, sleeps = [0.0], []
    policy = None

    def note(delay):
        sleeps.append(delay)
        clock[0] += delay
        if len(sleeps) <= 8:
            policy.observe("https://a.example/sibling", 429, {"retry-after": "30"})

    async def async_sleep(delay):
        note(delay)

    policy = browser.TargetRatePolicy(max_wait=30, clock=lambda: clock[0],
                                      sync_sleep=note, async_sleep=async_sleep)
    policy.observe("https://a.example/first", 429, {"retry-after": "30"})

    if waiter == "sync":
        waited = policy.wait_sync("https://a.example/next")
    else:
        waited = _run(policy.wait_async("https://a.example/next"))
    assert waited <= 30


# ------------------------------------------------------------------- GAP-3: no unbounded spinning

def test_a_sleeper_that_does_not_advance_the_clock_still_terminates():
    """A frozen clock spun 50001 times before the iteration cap existed. The house rules require
    tests to inject a fake sleep, so this trap sits directly on the path they mandate."""
    calls = []
    policy = browser.TargetRatePolicy(max_wait=30, clock=lambda: 0.0,
                                      sync_sleep=lambda d: calls.append(d))
    policy.observe("https://a.example/x", 429, {"retry-after": "3"})

    policy.wait_sync("https://a.example/x")

    assert len(calls) <= browser._WAIT_ITERATION_CAP


# ----------------------------------------------------------------------- GAP-2: the wait is VISIBLE

def test_a_wait_is_attributed_to_the_dispatch_that_incurred_it():
    clock = [0.0]
    policy = browser.TargetRatePolicy(
        max_wait=30, clock=lambda: clock[0],
        sync_sleep=lambda d: clock.__setitem__(0, clock[0] + d))
    policy.observe("https://a.example/x", 429, {"retry-after": "4"})

    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://a.example/x")

    assert box["waits"] == 1
    assert box["seconds"] == pytest.approx(4)
    assert box["origins"] == ["https://a.example:443"]
    assert browser.describe_wait(box) == "[backoff 4.0s x1]"


def test_a_truncated_wait_says_so_in_its_ledger_token():
    policy, _ = _extending_policy(max_wait=30, extensions=8)
    policy.observe("https://a.example/first", 429, {"retry-after": "30"})

    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://a.example/next")

    assert box["truncated"] == 1
    assert browser.describe_wait(box) == "[backoff 30.0s x1, truncated at cap]"


def test_a_dispatch_that_met_no_rate_limiting_records_nothing():
    """NEGATIVE CONTROL, and the compatibility guarantee: zero backoff must leave the ledger note
    byte-for-byte what it was before this feature existed."""
    policy = browser.TargetRatePolicy(
        sync_sleep=lambda d: pytest.fail("slept with no cooldown outstanding"))

    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://clean.example/a")

    # Q-043/Q-085 added `sources`. The guarantee this test protects is about the LEDGER NOTE, which
    # is unchanged and asserted below; the box is an internal accumulator and gaining a field is not
    # the thing being guarded. Asserting it exactly is still right -- it catches a stray key -- so
    # the expected shape is updated rather than the assertion loosened, and `sources: []` is now
    # pinned too: a dispatch that never waited must record no provenance either, which is a
    # guarantee the old shape could not express.
    assert box == {"waits": 0, "seconds": 0.0, "truncated": 0, "origins": [], "sources": []}
    assert browser.describe_wait(box) == ""
    assert browser.describe_wait(None) == ""


def test_a_response_without_retry_after_is_recorded_as_an_INFERRED_wait():
    """UPDATED DELIBERATELY, Q-043/Q-085, not deleted.

    This test used to assert that a 429 the server did not annotate must not manufacture a wait,
    and that was correct while nothing could tell an invented cooldown from a requested one. Two
    lanes refused to flip the default for exactly that reason, and they were right to.

    The blocker is now solved rather than overruled: the wait box and the typed `tool_backoff` row
    carry `sources`, so the ledger distinguishes the two. With that in place the safety argument
    wins -- nginx `limit_req` and Cloudflare both return bare 429s, and a tool that sends payloads
    at other people's systems must not ignore an explicit stop signal because it lacked a duration.

    What the test still pins is the thing the original was really protecting: an invented wait must
    never be able to pass itself off as one the target asked for.
    """
    slept = []
    policy = browser.TargetRatePolicy(sync_sleep=slept.append)
    assert policy.observe("https://a.example/x", 429, {}) == pytest.approx(2.0)
    # An unparseable header is not a hint; the 429 still stands on its own.
    assert policy.observe("https://a.example/x", 429, {"retry-after": "banana"}) == pytest.approx(2.0)

    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://a.example/x")
    assert box["waits"] == 1
    assert box["sources"] == ["inferred"], (
        "an invented cooldown must be labelled as invented; %r would let it read as one the target "
        "requested" % (box["sources"],))
    assert sum(slept) > 0


def test_the_opt_out_still_manufactures_nothing():
    """The behaviour the original control pinned, kept where it is still true.

    Flipping a default must not remove the ability to turn it off, and this is the exact assertion
    that used to guard the shipped path -- relocated to the explicit-config case rather than
    dropped, so nothing about it went unproven.
    """
    policy = browser.TargetRatePolicy(
        bare_retry_seconds=0.0,
        sync_sleep=lambda d: pytest.fail("waited on a 429 that carried no Retry-After"))
    assert policy.observe("https://a.example/x", 429, {}) is None
    assert policy.observe("https://a.example/x", 429, {"retry-after": "banana"}) is None

    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://a.example/x")
    assert box["waits"] == 0
    assert box["sources"] == []
    assert policy.stats()["waits"] == 0


def test_a_non_limiting_status_still_manufactures_nothing():
    """The half of the original control that must NEVER change.

    The fallback fires on an explicit rate-limit status. A 200, a 404 or a 500 is not one, and if
    flipping the default ever made an ordinary response park the mission, that is a self-inflicted
    denial of service rather than politeness.
    """
    policy = browser.TargetRatePolicy(
        sync_sleep=lambda d: pytest.fail("waited on a response that was not a rate limit"))
    for status in (200, 204, 301, 404, 418, 500, 502):
        assert policy.observe("https://a.example/x", status, {}) is None, status
    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://a.example/x")
    assert box["waits"] == 0
    assert policy.stats()["waits"] == 0


def test_a_header_supplied_wait_is_labelled_header_not_inferred():
    """POSITIVE CONTROL on the provenance itself.

    If `sources` reported "inferred" for everything, the test above would pass while the field was
    useless. This is the other half: an annotated 429 must be attributable to the target.
    """
    policy = browser.TargetRatePolicy(sync_sleep=lambda d: None)
    assert policy.observe("https://b.example/x", 429, {"retry-after": "1"}) == pytest.approx(1.0)
    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://b.example/x")
    assert box["waits"] == 1
    assert box["sources"] == ["header"]


def test_provenance_survives_the_wait_it_describes():
    """The bug this nearly shipped with, pinned so it cannot come back.

    `_next_wait` calls `remaining()`, which POPS an origin the moment its deadline expires. The
    first draft read `_deadline_sources` inside `_record_wait`, i.e. AFTER the sleep loop -- so
    every wait that ran to completion recorded an EMPTY `sources` and only truncated waits recorded
    anything. That is worse than not having the field: it looks like a working feature and is blank
    exactly when it matters. Provenance is now sampled before the loop.
    """
    clock = {"t": 0.0}
    policy = browser.TargetRatePolicy(clock=lambda: clock["t"],
                                      sync_sleep=lambda d: clock.__setitem__("t", clock["t"] + d))
    policy.observe("https://c.example/x", 429, {})          # inferred, 2.0s
    with browser.rate_wait_scope() as box:
        waited = policy.wait_sync("https://c.example/x")
    assert waited == pytest.approx(2.0), "the wait did not run to completion, so this proves nothing"
    assert box["sources"] == ["inferred"], (
        "sources was lost by the wait it describes -- sampled after remaining() popped the origin")


def test_process_wide_stats_count_observations_and_clamps():
    policy = browser.TargetRatePolicy(max_wait=30, clock=lambda: 0.0)
    policy.observe("https://a.example/x", 429, {"retry-after": "5"})
    policy.observe("https://a.example/x", 429, {"retry-after": "86400"})
    policy.observe("https://a.example/x", 200, {"retry-after": "5"})

    stats = policy.stats()
    assert stats["observations"] == 2, "a 200 was counted as a rate-limit observation"
    assert stats["capped"] == 1, "the 86400 clamp was not recorded"


def test_waits_outside_a_scope_still_reach_the_process_counters():
    """A bare threading.Thread does not inherit the ContextVar. Those waits must not vanish."""
    clock = [0.0]
    policy = browser.TargetRatePolicy(
        max_wait=30, clock=lambda: clock[0],
        sync_sleep=lambda d: clock.__setitem__(0, clock[0] + d))
    policy.observe("https://a.example/x", 429, {"retry-after": "6"})

    policy.wait_sync("https://a.example/x")     # no scope open

    assert policy.stats()["waits"] == 1
    assert policy.stats()["seconds"] == pytest.approx(6)
