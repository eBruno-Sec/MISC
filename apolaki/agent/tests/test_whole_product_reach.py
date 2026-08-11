"""The whole-product smoke test CODEBASE_REVIEW S11b called "the single highest-value test missing
from this repo" — and the reason it must assert TWO numbers, not one.

    "A whole-product smoke test — engage a mission against a standing lab, assert findings > 0 —
     would have caught both instantly."

It would not have. MEASURED (mission `90cee81c`): that mission found 2 findings against a 2740-case
target — a jQuery CVE and a credential in a comment, both from JS recon on the index page, neither of
them a test case. `findings > 0` passes on those two. The count was already 2 at the 50-second mark
and did not move for the next 61 minutes. A smoke test asserting only `findings > 0` would have gone
green over a mission that reached 12 of 2756 discovered pages.

So this asserts REACH as well as RESULT: how many distinct pages the product actually FETCHED, and how
many endpoints its deterministic sweep actually SELECTED. Those are the two numbers that collapsed,
and they are the two a future regression would collapse again.

Gated on APOLAKI_LIVE_LAB=1 because it makes real requests to a standing lab. When the gate IS set the
test never self-skips: an unreachable lab FAILS, because "the lab was down" reported as a pass is the
recorded SKIPPED-is-never-a-pass failure mode.
"""
from __future__ import annotations

import asyncio
import os
import socket
from urllib.parse import urlparse

import pytest

LIVE = os.environ.get("APOLAKI_LIVE_LAB") == "1"
SEED = os.environ.get("APOLAKI_LIVE_SEED", "https://owaspbench:8443/benchmark/")
# Floors, not targets. MEASURED before the Q-019 fix: 12 pages fetched, 20 endpoints selected. These
# sit far above the broken numbers and far below the measured post-fix ones (250 / 400), so they catch
# a collapse without becoming a moving goalpost that has to be edited every time coverage improves.
MIN_PAGES = int(os.environ.get("APOLAKI_LIVE_MIN_PAGES", "100"))
MIN_TARGETS = int(os.environ.get("APOLAKI_LIVE_MIN_TARGETS", "100"))

pytestmark = pytest.mark.skipif(
    not LIVE, reason="whole-product reach check: set APOLAKI_LIVE_LAB=1 (makes live requests)")


def _lab_up(url: str) -> bool:
    p = urlparse(url)
    try:
        with socket.create_connection((p.hostname, p.port or (443 if p.scheme == "https" else 80)), 5):
            return True
    except Exception:
        return False


def _run():
    import agent as agent_mod
    from scope import ScopeEngine
    from tools import ToolRegistry

    sc = ScopeEngine()
    sc.load_manual([SEED], [], "reach")
    tb = ToolRegistry(sc, lab_mode=True)
    tb._add_urls([SEED])
    ag = agent_mod.BBHAgent(sc, tb, asyncio.Event(), mode="active",
                            authenticated_scan=False, mission_id=None)
    visited = asyncio.run(ag._surface_crawl("reach", base=SEED))
    ag._seed_and_project_graph(tb.graph)
    _roots, g_urls, _recon = ag._graph_primary_state(tb.graph)
    targets = agent_mod.sweep_targets(tb.urls, tb.recon.get("forms"), lambda u: sc.validate(u)[0])
    return {"visited": visited, "surface": list(tb.urls or []), "graph_urls": g_urls,
            "targets": targets, "swallowed": list(getattr(tb, "swallowed", []) or [])}


@pytest.fixture(scope="module")
def reach():
    assert _lab_up(SEED), (
        "APOLAKI_LIVE_LAB=1 but %s is unreachable. A down lab is NOT a pass — start the lab or unset "
        "the gate." % SEED)
    return _run()


def test_the_product_actually_fetches_pages_not_just_discovers_them(reach):
    """Root cause #2, as a number. A URL that was never FETCHED can never become a target, so the
    fetched count is the ceiling on everything downstream. It was 12."""
    assert reach["visited"] >= MIN_PAGES, (
        "surface crawl fetched only %d page(s); coverage is O(pages fetched)" % reach["visited"])


def test_discovery_is_wider_than_what_was_fetched(reach):
    """Non-vacuity in the other direction: fetching a lot is only meaningful if discovery found more."""
    assert len(reach["surface"]) > reach["visited"] > 0


def test_every_discovered_url_is_addressable(reach):
    """Oracle (a): zero surface URLs with an empty netloc."""
    bad = [u for u in reach["surface"] if not urlparse(u).netloc]
    assert bad == [], "%d unaddressable URL(s) on the surface, e.g. %s" % (len(bad), bad[:3])


def test_the_planners_world_state_is_addressable(reach):
    """Oracle (b), at its source: the state handed to the planner is where `https:///…` was born."""
    bad = [u for u in reach["graph_urls"] if not urlparse(u).netloc]
    assert bad == [], "%d host-less entries in the planner world-state, e.g. %s" % (len(bad), bad[:3])
    assert reach["graph_urls"], "empty world-state passes the line above for free"


def test_the_sweep_selects_a_real_fraction_of_the_surface(reach):
    """Oracle (c) at the selection stage: 2756 discovered, 20 selected was the whole defect."""
    assert len(reach["targets"]) >= MIN_TARGETS, (
        "sweep selected %d target(s) from a %d-URL surface"
        % (len(reach["targets"]), len(reach["surface"])))


def test_the_budget_is_spent_across_the_application_not_one_directory(reach):
    """The ordering half. Before: all 20 targets were consecutive files in one category folder."""
    import agent as agent_mod
    shapes = {agent_mod.target_shape(t) for t in reach["targets"]}
    assert len(shapes) >= 3, "the whole budget went to %d structural shape(s)" % len(shapes)


def test_no_component_silently_dropped_a_hostless_url(reach):
    """If the producer regresses, the recorder must be what tells us — and here it must be quiet."""
    hostless = [s for s in reach["swallowed"] if "hostless" in s.get("where", "")]
    assert hostless == [], "components are still emitting host-less URLs: %s" % hostless[:2]
