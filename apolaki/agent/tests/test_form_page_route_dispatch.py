"""Q-174. Two collapses in series, and fixing the first one changed nothing.

Q-172 taught `build_inventory` that a route selector makes a distinct page. The acceptance mission
STILL never reached `dns-lookup.php`, because the form-discovery loop in the planner does not read
the inventory at all -- it iterates raw `urls`. Two separate places then flattened them:

  1. the dedup/probe URL was `_abs(u)`, and `_abs` is `base + _path(u)` with the query dropped, so
     every `index.php?page=<x>.php` normalized to the same `…/index.php`;
  2. after that was fixed, the STEP KEY was still `f"...page:{_host(pg)}{_path(pg)}"` -- the query
     dropped again -- so all 45 pages produced one identical key and the planner's own dedup
     collapsed them to a single step. The URL was right and the step existed once.

That is why acceptance runs as a mission and not as a unit test: a fix can be correct at the layer
it was written for and do nothing at the layer that dispatches.

The stakes are concrete. `dns-lookup.php` is command-injectable
(`target_host=127.0.0.1;id` -> `uid=33(www-data)`), `upload-file.php` carries a real upload form,
and between them `run_form_cmdi` and `run_upload_test` had burned 719 dispatches across 39 missions
without ever being handed either page.
"""
import planner


ROUTES = ["dns-lookup.php", "upload-file.php", "home.php", "login.php", "user-info.php"]


def _state(urls):
    return {"mode": "full", "roots": ["t.local"], "done": set(),
            "recon": {"subdomains": ["t.local"], "live_hosts": [{"url": "http://t.local"}]},
            "urls": list(urls), "bases": {"t.local": "http://t.local"},
            "intensity": "standard"}


def _drive(urls):
    state = _state(urls)
    done = state["done"]
    steps = []
    for _ in range(400):
        batch = planner.next_batch(state)
        if not batch:
            break
        for s in batch:
            done.add(s["key"])
            steps.append(s)
    return steps


def _targets(steps, tool):
    return [s["input"].get("url", "") for s in steps if s["tool"] == tool]


ROUTED_URLS = ["http://t.local/index.php?page=" + p for p in ROUTES]


def test_every_routed_page_is_handed_to_the_form_engine():
    got = _targets(_drive(ROUTED_URLS), "run_form_cmdi")
    for p in ROUTES:
        assert any(p in u for u in got), (
            "%s was never handed to run_form_cmdi; it collapsed into the shared /index.php page "
            "and the engine's zero on it would be correct and meaningless" % p)


def test_the_upload_engine_gets_them_too():
    got = _targets(_drive(ROUTED_URLS), "run_upload_test")
    assert any("upload-file.php" in u for u in got), got


def test_each_routed_page_has_a_DISTINCT_step_key():
    """THE second collapse. A correct URL on a step that exists once is still one page tested."""
    steps = [s for s in _drive(ROUTED_URLS)
             if s["tool"] == "run_form_cmdi" and "?page=" in s["input"].get("url", "")]
    keys = [s["key"] for s in steps]
    assert len(keys) == len(set(keys)), "route pages share a step key: %r" % keys
    assert len(keys) >= len(ROUTES), (
        "expected one step per routed page, got %d for %d pages -- the planner's dedup is still "
        "flattening them" % (len(keys), len(ROUTES)))


def test_the_route_page_budget_is_bounded():
    """A cap that discovery cannot blow past. New surface must not mean unbounded surface."""
    many = ["http://t.local/index.php?page=p%d.php" % i for i in range(200)]
    got = _targets(_drive(many), "run_form_cmdi")
    routed = [u for u in got if "?page=" in u]
    assert len(routed) <= planner.CAP_ROUTE_FORM_PAGES + 1, (
        "%d route pages dispatched against a cap of %d"
        % (len(routed), planner.CAP_ROUTE_FORM_PAGES))
    assert len(routed) > 10, (
        "the route budget collapsed back to the flat-page cap; a router app would again spend one "
        "slot for its whole surface")


def test_a_flat_page_is_still_reached():
    """Negative control: the ordinary path must not be starved by the new one."""
    got = _targets(_drive(ROUTED_URLS + ["http://t.local/about.php"]), "run_form_cmdi")
    assert any(u.endswith("/about.php") for u in got), got


# --- Q-177: the canonical entry point ----------------------------------------------------------
# The acceptance mission DID dispatch dns-lookup.php and still found nothing, because it dispatched
# `/includes/index.php?page=dns-lookup.php` -- an include directory Apache also indexes, where the
# form does not exist. run_form_cmdi answered "no body command injection in the page's forms",
# correctly, about a page that was not the one with the bug.
#
# MEASURED on that mission, 30 route slots spent:
#     /includes/index.php 22 | / 5 | /documentation/index.php 2 | /index.php 1
# The wrong entry point took 73% of the budget and the application's own router got ONE slot, and
# 25 distinct route values consumed 30 slots because two were tested twice.

DECOY = "http://t.local/includes/index.php?page=%s"
REAL = "http://t.local/index.php?page=%s"


def _both(pages):
    """The decoy discovered FIRST, which is the order that broke the mission."""
    out = []
    for p in pages:
        out.append(DECOY % p)
        out.append(REAL % p)
    return out


def test_the_shallowest_entry_point_wins():
    got = _targets(_drive(_both(ROUTES)), "run_form_cmdi")
    routed = [u for u in got if "?page=" in u]
    assert routed, got
    assert all("/includes/" not in u for u in routed), (
        "the budget was spent on a deeper path to the same logical page: %r" % routed)
    assert any("dns-lookup" in u for u in routed)


def test_one_logical_page_is_tested_once():
    """25 distinct values must not consume 30 slots."""
    routed = [u for u in _targets(_drive(_both(ROUTES)), "run_form_cmdi") if "?page=" in u]
    values = [u.split("?page=", 1)[1] for u in routed]
    assert len(values) == len(set(values)), "the same route value was tested twice: %r" % values


def test_a_deeper_path_is_still_used_when_it_is_the_only_one():
    """Negative control: preferring the canonical entry must not DROP a page reachable one way."""
    only_deep = [DECOY % "dns-lookup.php", REAL % "home.php"]
    routed = [u for u in _targets(_drive(only_deep), "run_form_cmdi") if "?page=" in u]
    assert any("dns-lookup" in u for u in routed), (
        "a route value reachable ONLY through a deeper path was dropped entirely: %r" % routed)
