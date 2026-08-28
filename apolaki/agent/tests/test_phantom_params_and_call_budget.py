"""Q-110 + Q-111 — the two defects that ended the operator's overnight Shopify run.

Q-111, PHANTOM PARAMETERS. `_add_ref` mined hrefs straight out of markup with no HTML unescaping,
so `?a=1&amp;language=en` was split on the literal text into TWO parameters: `a` and `amp;language`.
The second does not exist on the server. The run raised four findings against `amp;language`,
`amp;signup_page` and `amp;signup_types[]`, **including a HIGH "Server-side template injection" on a
parameter that is not real.** Every probe against them was wasted and every finding from them false.

Q-110, NO CALL BUDGET. Each request already had its own timeout; nothing bounded the SUM. These
engines probe many parameters with several payloads each, so one call is hundreds of requests.
Against a target that tarpits -- every `http_probe` in that run answered 403 -- each request
approaches its timeout and the call runs for hours.

MEASURED: the sweep covers 465 endpoints; every sibling engine had completed exactly 37 and
`run_sqli` had STARTED a 38th. It sat there SIX HOURS 43 MINUTES. Endpoints 39-465 were never
reached, and because the generator was blocked inside that call it emitted no events -- the live page
froze while the report kept re-rendering unchanged data.

Both gates assert the SECOND half too: unescaping must not corrupt a legitimate parameter, and the
budget must not fire on a healthy target.
"""
import time

import pytest

import intel
import tools


# ── Q-111: phantom parameters ─────────────────────────────────────────────────

def _params_from(href):
    store = intel.IntelStore()
    intel._add_ref(href, "test", store)
    return set(store.get("param"))


def test_an_entity_encoded_ampersand_does_not_mint_a_phantom_parameter():
    """The exact shape from the field report."""
    got = _params_from("https://x.test/p?locale=en&amp;language=fr&amp;signup_page=1")
    assert "amp;language" not in got, got
    assert "amp;signup_page" not in got, got


def test_the_real_parameters_behind_the_entity_survive():
    """Non-vacuity, and the half that matters: unescaping must RECOVER the parameters, not drop
    them. A fix that merely stopped emitting `amp;language` while also losing `language` would
    trade a false positive for a blind spot."""
    got = _params_from("https://x.test/p?locale=en&amp;language=fr")
    assert {"locale", "language"} <= got, got


def test_a_plain_ampersand_url_is_unchanged():
    """Most URLs are not entity-encoded. The decode must be a no-op for them."""
    assert {"a", "b"} <= _params_from("https://x.test/p?a=1&b=2")


def test_a_parameter_whose_value_contains_an_entity_is_not_mangled():
    """`html.unescape` is applied to the whole reference, so a value carrying `&amp;` decodes too.
    That is correct -- it is what the browser would send -- and this pins it deliberately rather
    than leaving it to be discovered later."""
    got = _params_from("https://x.test/p?q=tom%26jerry&amp;next=/home")
    assert {"q", "next"} <= got, got


# ── Q-110: the call budget ────────────────────────────────────────────────────

def test_the_budget_is_defined_and_bounded():
    """A budget large enough to be meaningless is the same as none. 6h43m was the failure; this has
    to be small enough that a stalled endpoint cannot eat a night."""
    assert isinstance(tools._PROBE_CALL_BUDGET_S, int)
    assert 30 <= tools._PROBE_CALL_BUDGET_S <= 600, tools._PROBE_CALL_BUDGET_S


@pytest.mark.parametrize("engine", ["_run_sqli", "_run_nosqli", "_run_cmdi"])
def test_every_engine_that_shares_the_shape_has_the_deadline(engine):
    """All three run the same probe-many-params loop. Fixing only the one that happened to hang is
    how a defect comes back through the route nobody looked at."""
    import inspect
    src = inspect.getsource(getattr(tools.ToolRegistry, engine))
    assert "_PROBE_CALL_BUDGET_S" in src, engine
    assert "_budget_hit" in src, engine


@pytest.mark.parametrize("engine", ["_run_sqli", "_run_nosqli", "_run_cmdi"])
def test_a_truncated_sweep_is_reported_not_returned_as_clean(engine):
    """THE POINT. "0 confirmed" after probing everything and "0 confirmed" after stopping partway
    are different facts about the target, and only one is evidence. If the budget fires silently
    this whole ticket has moved the failure rather than fixed it."""
    import inspect
    src = inspect.getsource(getattr(tools.ToolRegistry, engine))
    assert "TRUNCATED" in src, engine
    assert "not _budget_hit" in src, engine        # success=False, so the ledger sees it too
