"""Q-043: the bare-429 case -- a 429/503 the server did not annotate with Retry-After.

Run 1 of this lane measured this as a FAIL: 0.003 s on `_http`, 0.027 s on the browser path.
Run 2 checked whether it was an oversight before patching it, and it is not. It is a DESIGNED
boundary, guarded by a named negative control that a previous Q-043 commit (`9c37ced`) landed:

    test_backoff_bounds.py::test_a_response_without_retry_after_is_never_recorded_as_a_wait
    "The other negative control: a 429 the server did not annotate must not manufacture one."

Two defensible positions collide there:
  - the ticket's: a 429 IS the server saying slow down; nginx `limit_req` and Cloudflare both
    return one with no Retry-After, so honouring only the annotated case misses the common shape;
  - the existing control's: a scanner must not invent a cooldown the target never asked for,
    because an invented number is indistinguishable from a measured one in the ledger.

Deleting the control to satisfy the ticket would be weakening an oracle, so this does neither.
The backoff becomes CONFIGURABLE and stays OFF by default, which leaves the existing control
passing byte-for-byte while making the ticket's behaviour reachable and bounded. The default is
recorded as a deliberate choice rather than an accident -- see docs/handoff/rate_policy.md §4.

Every test here that asserts a wait also has the paired assertion that the default does NOT wait,
so a regression that flips the default on is caught by this file, not just by the other one.

===============================================================================================
THE DEFAULT WAS FLIPPED ON, 2026-08-20, AND THIS FILE CAUGHT IT. UPDATED DELIBERATELY.
===============================================================================================

The design above is correct and it worked exactly as written: the Coordinator changed
`RATE_POLICY_BARE_DEFAULT_SECONDS` from 0.0 to 2.0 and twelve tests in this file went red,
including six that exist purely as the paired assertion. That is the sentence at the top of this
docstring doing its job, and it is why the change is being recorded here rather than quietly
absorbed.

**The premise moved, not the standard.** The reason for OFF was, verbatim above: "an invented
number is indistinguishable from a measured one in the ledger". That is no longer true.
`TargetRatePolicy.observe()` now tags every cooldown `header` or `inferred`, the wait box carries
`sources`, and `tools.py::_ledger_outcome()` writes it into the durable typed `tool_backoff` row --
measured end to end:

    INFERRED (bare 429)      box.sources=['inferred']   row={'seconds': 2.0, 'sources': ['inferred']}
    HEADER (Retry-After: 1)  box.sources=['header']     row={'seconds': 1.0, 'sources': ['header']}

With the two distinguishable in the durable record, the objection dissolves and the safety argument
wins: nginx `limit_req` and Cloudflare both return bare 429s, and a tool that sends payloads at
other people's systems must not ignore an explicit stop signal because it lacked a duration.

**What this file now guards instead**, keeping the paired-assertion design intact -- every test that
asserts a wait is still paired with one asserting a case that must NOT wait:

  * the shipped default WAITS, and the wait is labelled `inferred`, never `header`;
  * `bare_retry_seconds=0.0` still manufactures nothing, so the opt-out cannot rot;
  * a non-limiting status still manufactures nothing, whatever the knob says;
  * a malformed knob falls back to the module default.

**That last one flipped direction and the reason is worth stating.** It used to fall back to 0.0
because "a malformed env var must not be the thing that parks a mission". Now it falls back to 2.0.
Both are defensible; they trade opposite failures. Falling back to 0.0 means a typo in
`BBH_RETRY_AFTER_BARE_SECONDS` SILENTLY DISABLES a safety feature, and nothing in the ledger says
so. Falling back to 2.0 means a typo costs a bounded 2 seconds per rate-limited origin, clamped by
`_max_wait()`. A knob that fails toward safety is the right choice for a knob whose purpose is
safety, and neither direction can park a mission because the ceiling is unchanged.
"""
from __future__ import annotations

import asyncio

import browser_engine as browser
import pytest


def _run(awaitable):
    return asyncio.run(awaitable)


def _policy(**kwargs):
    kwargs.setdefault("clock", lambda: 0.0)
    return browser.TargetRatePolicy(**kwargs)


# ------------------------------------------------- the default WAITS, and says who asked for it
@pytest.mark.parametrize("status", [429, 503])
@pytest.mark.parametrize("headers", [{}, {"retry-after": "banana"}, {"retry-after": ""}])
def test_by_default_an_unannotated_limit_is_honoured_and_labelled_inferred(status, headers):
    """The shipped path. All three header shapes are the same case: the limit carried no USABLE
    hint, so Apolaki supplies the delay -- and must say so."""
    clock = [0.0]
    policy = browser.TargetRatePolicy(
        clock=lambda: clock[0], sync_sleep=lambda d: clock.__setitem__(0, clock[0] + d))
    assert policy.observe("https://a.example/x", status, headers) == pytest.approx(2.0)

    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://a.example/x")
    assert box["waits"] == 1
    assert box["sources"] == ["inferred"], (
        "a cooldown Apolaki invented must never read as one the target requested; got %r"
        % (box["sources"],))
    assert policy.stats()["observations"] == 1


@pytest.mark.parametrize("status", [429, 503])
@pytest.mark.parametrize("headers", [{}, {"retry-after": "banana"}, {"retry-after": ""}])
def test_the_opt_out_still_manufactures_nothing(status, headers):
    """THE PAIRED ASSERTION, which is the design this file was built around: every case that now
    waits has a sibling that must not. Flipping a default must never remove the ability to turn the
    behaviour off, and this is the exact assertion the old default carried, kept where it is still
    true."""
    policy = browser.TargetRatePolicy(
        bare_retry_seconds=0.0,
        sync_sleep=lambda d: pytest.fail("waited on a %s with the fallback disabled" % status))
    assert policy.observe("https://a.example/x", status, headers) is None

    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://a.example/x")
    assert box["waits"] == 0
    assert box["sources"] == []
    assert policy.stats()["waits"] == 0
    assert policy.stats()["observations"] == 0


def test_the_bare_default_is_two_seconds_and_that_is_the_shipped_value():
    """The shipped constant, asserted so the flip is a deliberate edit and never a drift.

    2.0 is a CONVENTION, not a measurement -- nobody has measured how long a real unannotated 429
    wants, and the constant's comment says so. What is argued is that zero ignores an explicit stop
    signal, and that this value is bounded by `_max_wait()` and overridable back to 0.0.
    """
    assert browser.RATE_POLICY_BARE_DEFAULT_SECONDS == 2.0
    assert browser.TargetRatePolicy()._bare_wait() == 2.0


# ---------------------------------------------------------------- opting in
@pytest.mark.parametrize("status", [429, 503])
def test_an_explicit_bare_backoff_parks_an_unannotated_limit(status):
    sleeps = []
    clock = [0.0]

    def sync_sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    policy = browser.TargetRatePolicy(
        max_wait=10, bare_retry_seconds=2, clock=lambda: clock[0], sync_sleep=sync_sleep)
    assert policy.observe("https://a.example/x", status, {}) == 2.0

    with browser.rate_wait_scope() as box:
        policy.wait_sync("https://a.example/x")
    assert sleeps == [2.0]
    assert box["waits"] == 1 and box["seconds"] == pytest.approx(2.0)


def test_an_unparseable_retry_after_uses_the_bare_backoff_rather_than_being_dropped():
    """`Retry-After: banana` is a 429 whose hint is unusable, not a 429 that never happened."""
    policy = _policy(max_wait=10, bare_retry_seconds=2)
    assert policy.observe("https://a.example/x", 429, {"retry-after": "banana"}) == 2.0
    assert policy.remaining("https://a.example/x") == pytest.approx(2.0)


def test_an_annotated_limit_still_wins_over_the_bare_backoff():
    """The server's own number must never be overridden by our fallback, in either direction."""
    policy = _policy(max_wait=100, bare_retry_seconds=9)
    assert policy.observe("https://a.example/x", 429, {"retry-after": "1"}) == 1.0
    policy.clear()
    assert policy.observe("https://a.example/x", 429, {"retry-after": "30"}) == 30.0


def test_the_bare_backoff_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("BBH_RETRY_AFTER_BARE_SECONDS", "3")
    policy = _policy(max_wait=10)
    assert policy.observe("https://a.example/x", 429, {}) == 3.0


@pytest.mark.parametrize("raw", ["banana", "", "-1", "nan", "inf"])
def test_an_unusable_bare_setting_falls_back_to_the_module_default(monkeypatch, raw):
    """A malformed knob must not become an unbounded wait, and must not crash the policy.

    THE FALLBACK DIRECTION FLIPPED WITH THE DEFAULT, and that was the deliberate half of the change.
    It used to resolve to 0.0 on the reasoning that "a malformed env var must not be the thing that
    parks a mission". Both directions are defensible and they trade opposite failures:

        fall back to 0.0   a typo SILENTLY DISABLES a safety feature, and nothing says so
        fall back to 2.0   a typo costs a bounded 2s per rate-limited origin

    A knob whose purpose is safety should fail toward safety, and neither direction can park a
    mission because `_max_wait()` is unchanged. What both directions still guarantee, and what this
    test really exists for, is that no unusable value becomes a LARGE one.
    """
    monkeypatch.setenv("BBH_RETRY_AFTER_BARE_SECONDS", raw)
    policy = _policy(max_wait=10)
    assert policy._bare_wait() == browser.RATE_POLICY_BARE_DEFAULT_SECONDS
    assert policy._bare_wait() <= 10, "an unusable setting resolved to something unbounded"
    assert policy.observe("https://a.example/x", 429, {}) == pytest.approx(
        browser.RATE_POLICY_BARE_DEFAULT_SECONDS)


# ---------------------------------------------------------------- bounded
def test_the_bare_backoff_is_bounded_by_the_same_ceiling_as_the_header():
    """An absurd bare setting must clamp exactly like an absurd Retry-After does."""
    policy = _policy(max_wait=4, bare_retry_seconds=86400)
    assert policy.observe("https://a.example/x", 429, {}) == 4.0


def test_the_bare_backoff_never_applies_to_a_non_limiting_status():
    """A 200 or a 404 is not a rate limit, however the knob is set."""
    policy = browser.TargetRatePolicy(
        bare_retry_seconds=5,
        sync_sleep=lambda d: pytest.fail("parked on a status that was not a rate limit"))
    for status in (200, 301, 404, 500):
        assert policy.observe("https://a.example/x", status, {}) is None
    policy.wait_sync("https://a.example/x")


def test_the_bare_backoff_never_applies_to_an_unusable_origin():
    policy = _policy(bare_retry_seconds=5)
    for url in ("", "not-a-url", "ftp://a.example/x", "file:///etc/passwd"):
        assert policy.observe(url, 429, {}) is None


# ---------------------------------------------------------------- it reaches BOTH transports
def test_the_bare_backoff_reaches_the_async_transport_too():
    """The whole point of Q-043: a fix that covers one path and not the other is the original bug."""
    clock = [0.0]
    sleeps = []

    async def async_sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    policy = browser.TargetRatePolicy(
        max_wait=10, bare_retry_seconds=2, clock=lambda: clock[0], async_sleep=async_sleep)
    policy.observe("https://a.example/x", 429, {})
    waited = _run(policy.wait_async("https://a.example/y"))
    assert sleeps == [2.0] and waited == pytest.approx(2.0)


def test_the_bare_backoff_is_shared_per_origin_not_per_url():
    policy = _policy(max_wait=10, bare_retry_seconds=2)
    policy.observe("https://a.example/one", 429, {})
    assert policy.remaining("https://a.example/two") == pytest.approx(2.0)
    assert policy.remaining("https://b.example/two") == 0.0


# ------------------------------------------------------- HTTP-date in the PAST (Q-043 clause 3)
# The suite tested `wall + 7` and nothing else. MEASURED: deleting the `max(0.0, ...)` clamp in
# `retry_after_seconds` left the ENTIRE suite green (docs/handoff/rate_policy.md §6), so the clamp
# was carrying no test at all.
#
# What the clamp actually protects was measured on the mutant rather than assumed, and it is NOT
# what it first looks like. With the clamp removed:
#     observe(...) returns -114679926.9      <- a negative delay escapes to every caller
#     remaining(...)                == 0.0   <- still fine, `max(0.0, deadline - now)` clamps again
#     a sibling's live 10s cooldown == 10.0  <- still fine, `max(deadline, existing)` holds
# So the deadline itself is defended twice over downstream; the leak is the RETURN VALUE, which is
# what reaches ledger notes and the zap rate events (`retry_after_seconds` in a reported event).
# A report that says a target asked us to wait -114679926 seconds is the defect. The two sibling
# assertions below are kept as positive controls proving those two `max()` calls hold on their own.
_PAST = "Sun, 01 Jan 2023 00:00:00 GMT"


@pytest.mark.parametrize("status", [429, 503])
def test_a_retry_after_date_in_the_past_clamps_to_zero_and_never_goes_negative(status):
    policy = browser.TargetRatePolicy(
        max_wait=30, clock=lambda: 1000.0,
        sync_sleep=lambda d: pytest.fail("slept on a Retry-After date that had already passed"))
    assert policy.observe("https://a.example/x", status, {"retry-after": _PAST}) == 0.0
    assert policy.remaining("https://a.example/x") == 0.0
    policy.wait_sync("https://a.example/x")


def test_retry_after_seconds_never_returns_a_negative_delay():
    """Directly on the parser, so the clamp is guarded even if `observe` stops calling it."""
    assert browser.retry_after_seconds(_PAST) == 0.0
    assert browser.retry_after_seconds(_PAST, now=4102444800.0) == 0.0
    assert browser.retry_after_seconds("Thu, 01 Jan 2099 00:00:00 GMT", now=4102444800.0) == 0.0


def test_a_stale_date_cannot_erase_a_live_cooldown_set_by_a_sibling():
    """The real damage a negative delay would do: rewind a deadline another worker is parked on."""
    policy = _policy(max_wait=30)
    assert policy.observe("https://a.example/first", 429, {"retry-after": "10"}) == 10.0
    assert policy.remaining("https://a.example/x") == pytest.approx(10.0)
    policy.observe("https://a.example/second", 429, {"retry-after": _PAST})
    assert policy.remaining("https://a.example/x") == pytest.approx(10.0), \
        "a Retry-After date in the past rewound a live cooldown"
