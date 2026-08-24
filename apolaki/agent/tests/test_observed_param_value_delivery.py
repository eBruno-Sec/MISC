"""Q-095 -- param mining yields parameter NAMES, and 81.2% of query-bearing dispatches probe a
valueless parameter. This gate is about the 18.8% that MATTERS, and about proving it can tell the
two engine classes apart.

THE DISCRIMINATOR IS WHETHER THE ENGINE NEEDS A WORKING BASELINE (docs/handoff/param_values_fix.md).

  class A  BASELINE-DEPENDENT   fetches the URL AS GIVEN and compares a probe against it
                                (`_run_sqli`, `_run_cmdi`, `_run_nosqli`, `_run_web_probes`,
                                `_run_xpath`, `_run_ldap`, `_run_sqli_structural`, the SSTI branch
                                of `_run_injection_probes`, and `run_sqlmap`'s own dynamicity check)
  class B  VALUE-OVERWRITING    substitutes its payload FOR the value; the oracle is self-contained
                                (`_run_xss`, `_run_dom_audit`, `_run_ssrf`, `_run_ssi`)

A blank value destroys class A because the blank-value baseline is a DIFFERENT PAGE. MEASURED on
the live lab and asserted below as a fixture: `?q` and `?q=` both return the whole unfiltered
product list while `?q=apple` returns the filtered one. Class B does not care, because whatever the
value was, the payload replaces it -- and `test_a_value_overwriting_engine_is_unaffected...` proves
that by construction rather than by assertion-free assumption.

WHY THE EXECUTABLE GATE SITS AT THE PLANNER BOUNDARY, and not on a class-A engine end-to-end.
Two candidate engine-level fixtures were MEASURED and BOTH were disproved (recorded in
docs/handoff/param_values_fix.md section 3):

  * `_run_sqli` on `/rest/products/search` confirms with `?q` AND with `?q=apple` -- `ERROR_PROBES`
    contains `')`, which raises SQLITE_ERROR even with an empty prefix;
  * `sqli.analyze_boolean` returns False on that endpoint in BOTH directions -- juice-shop
    concatenates as `%'||q||'%`, so every boolean payload breaks the statement and both arms come
    back as the same 30-byte error object.

The surviving class-A proof is the ticket's own: sqlmap's dynamicity check concludes the parameter
does not change the page and stops BEFORE injecting -- a several-minute external run, unfit for a
unit suite. So the gate asserts the thing the fix actually changes and the thing every class-A
engine depends on: **the probe URL the planner hands out carries the value the crawl observed.**
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

import pytest

import dom_tool
import planner
import ssrf_tool
import surface as surface_mod
import xss_tool as xt

JUICE = "juice-shop:3000"
SEARCH = "http://%s/rest/products/search" % JUICE

# The two URLs the crawl really produces for this endpoint: one valueless (param mining / a warm
# start re-seed / a bare link) and one carrying the value a real request was OBSERVED with.
VALUELESS = SEARCH + "?q"
OBSERVED = SEARCH + "?q=apple"

# Class-A engines: every one of them is handed `_ex(ep)` by the phase-E inventory loop
# (planner.py:826-975) and every one of them fetches that URL as its baseline.
# `run_cmdi` is class A too (`base_r = await get(c, url)` at tools.py:9066) but is NOT in this
# tuple: planner.py:836 schedules it only when a parameter name is in `_CMD_PARAM`, and `q` is not.
# Asserting on an engine the planner never dispatches here would make the gate fail for the wrong
# reason. `run_ssrf` is likewise gated on `_URLISH_PARAM`, and is class B anyway.
BASELINE_DEPENDENT = ("run_sqli", "run_nosqli", "run_web_probes",
                      "run_injection_probes", "run_sqlmap")


def _state(urls, intensity="deep"):
    return {"mode": "full", "roots": [JUICE], "done": set(),
            "recon": {"subdomains": [JUICE], "live_hosts": [{"url": "http://" + JUICE}]},
            "urls": list(urls),
            "bases": {JUICE: "http://" + JUICE},
            "intensity": intensity}


def _drive(state):
    done = set()
    state["done"] = done
    steps = []
    for _ in range(200):
        batch = planner.next_batch(state)
        if not batch:
            break
        for s in batch:
            done.add(s["key"])
            steps.append(s)
    return steps


def _probe_urls(urls, tools=BASELINE_DEPENDENT):
    """{tool: probe url} for the search endpoint, as the planner would dispatch it."""
    out = {}
    for s in _drive(_state(urls)):
        if s["tool"] not in tools:
            continue
        u = (s.get("input") or {}).get("url")
        if u and urlparse(u).path == "/rest/products/search":
            out[s["tool"]] = u
    return out


def _qs(url):
    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))


# ── THE DEFECT: the observed value is recovered and then thrown away ──────────────────


def test_merge_observed_params_upgrades_a_blank_value_to_the_observed_one():
    """The two D3 helpers must agree. `observed_param_values` already runs the rule
    "a real value beats a blank one" (planner.py:286); `merge_observed_params` counts a
    blank-valued parameter as "already have it" and drops the observed value on the floor."""
    obs = planner.observed_param_values([VALUELESS, OBSERVED])
    assert obs[(JUICE, "/rest/products/search")] == {"q": "apple"}, (
        "observed_param_values no longer recovers the value; this test's premise is gone")
    assert planner.merge_observed_params(VALUELESS, {"q": "apple"}) == OBSERVED, (
        "the value 'apple' was OBSERVED on this endpoint and the probe URL is still valueless")


def test_a_baseline_dependent_engine_is_handed_the_observed_value_not_a_blank():
    """Every class-A engine's probe URL must carry `q=apple`. A blank `q` makes its baseline the
    unfiltered product list, which is a different page from the one the probe returns."""
    probes = _probe_urls([VALUELESS, OBSERVED])
    assert set(BASELINE_DEPENDENT) <= set(probes), (
        "planner stopped dispatching one of %s at /rest/products/search: got %s"
        % (sorted(BASELINE_DEPENDENT), sorted(probes)))
    for tool, url in sorted(probes.items()):
        assert _qs(url).get("q") == "apple", (
            "%s is probing %r -- its baseline is the UNFILTERED page, so its differential is "
            "measured against the wrong reference" % (tool, url))


def test_the_probe_url_does_not_depend_on_the_order_the_crawl_saw_the_urls_in():
    """THE SHARPEST FORM OF THE DEFECT. `build_inventory` keeps the FIRST URL it sees as the
    endpoint's `example`, so today whether the whole mission probes a working URL or a dead one is
    decided by which of the two the crawl happened to reach first."""
    blank_first = _probe_urls([VALUELESS, OBSERVED])
    value_first = _probe_urls([OBSERVED, VALUELESS])
    assert blank_first == value_first, (
        "crawl order changes the probe URL: blank-first gave %s, value-first gave %s"
        % (blank_first, value_first))


# ── THE NON-VACUITY CONTROL: a value-overwriting engine is unaffected BOTH WAYS ───────


@pytest.mark.parametrize("probe_of, label", [
    (lambda u: xt.set_param(u, "q", "APOLAKI_PAYLOAD"), "xss_tool.set_param (_run_xss)"),
    (lambda u: ssrf_tool.set_param(u, "q", "APOLAKI_PAYLOAD"), "ssrf_tool.set_param (_run_ssrf)"),
    (lambda u: dom_tool._add_query(u, "q", "APOLAKI_PAYLOAD"), "dom_tool._add_query (_run_dom_audit)"),
])
def test_a_value_overwriting_engine_is_unaffected_in_both_directions(probe_of, label):
    """This must hold BEFORE and AFTER the fix, or the gate cannot tell the two classes apart.

    A class-B engine substitutes its payload FOR whatever the value is, so the request it puts on
    the wire is byte-identical whether the planner handed it `?q` or `?q=apple`. That is the whole
    reason Q-092's A/B found these engines identical on both sides, and the reason "fix all 9873"
    is the wrong instruction: `run_xss` alone is 1059 of them and is provably harmless.
    """
    assert probe_of(VALUELESS) == probe_of(OBSERVED), (
        "%s produced different probes for the valueless and valued URL -- it is not "
        "value-overwriting after all, and the classification is wrong" % label)
    assert probe_of(VALUELESS) == SEARCH + "?q=APOLAKI_PAYLOAD", (
        "%s: unexpected probe %r" % (label, probe_of(VALUELESS)))


def test_the_two_classes_are_actually_distinguishable_on_this_fixture():
    """NEGATIVE CONTROL FOR THE CONTROL ABOVE. If the valueless and valued URL produced the same
    BASELINE request too, then "class B is unaffected" would be vacuously true of every engine and
    this file would prove nothing. The class-A baseline request is the URL AS GIVEN, unmodified."""
    assert VALUELESS != OBSERVED
    assert _qs(VALUELESS) == {"q": ""} and _qs(OBSERVED) == {"q": "apple"}


# ── NEVER SYNTHESIZE A VALUE ─────────────────────────────────────────────────────────


def test_a_parameter_never_observed_with_a_value_stays_blank():
    """An INVENTED value can make baseline and probe fail identically, which is exactly how an
    engine reports clean on a vulnerable field. `apple` is admissible only because it was OBSERVED.
    With nothing observed there is nothing to thread, and the blank must survive untouched."""
    assert planner.merge_observed_params(VALUELESS, {}) == VALUELESS
    obs = planner.observed_param_values([VALUELESS])
    assert obs[(JUICE, "/rest/products/search")] == {"q": ""}
    assert planner.merge_observed_params(
        VALUELESS, obs[(JUICE, "/rest/products/search")]) == VALUELESS
    probes = _probe_urls([VALUELESS])
    assert probes, "planner emitted no probe for the valueless-only surface"
    for tool, url in sorted(probes.items()):
        assert _qs(url) == {"q": ""}, (
            "%s invented a value: %r" % (tool, url))


def test_every_value_on_every_probe_url_was_observed_on_that_endpoint():
    """The general form: no probe URL may carry a value that no discovered URL for that same
    endpoint ever carried."""
    urls = [VALUELESS, OBSERVED, SEARCH + "?q=juice",
            "http://%s/rest/products/search?category=1" % JUICE]
    seen = {}
    for u in urls:
        p = urlparse(u)
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            seen.setdefault((p.netloc, p.path, k), set()).add(v)
    for tool, url in sorted(_probe_urls(urls).items()):
        p = urlparse(url)
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            allowed = seen.get((p.netloc, p.path, k))
            assert allowed and v in allowed, (
                "%s: parameter %r carries invented value %r (observed: %s)"
                % (tool, k, v, sorted(allowed or ())))


def test_a_real_value_is_never_churned_by_the_upgrade():
    """The upgrade fires on a BLANK value only. A parameter that already carries a real value keeps
    its own, so dedup keys, exchange ledgers and cached results do not move for endpoints that were
    never broken. (`test_planner_param_delivery` asserts the same rule from the other side.)"""
    assert planner.merge_observed_params("http://h/a?b=own", {"b": "other"}) == "http://h/a?b=own"
    assert planner.merge_observed_params(
        "http://h/a?b=own", {"b": "other", "c": "3"}) == "http://h/a?b=own&c=3"
    assert planner.merge_observed_params(OBSERVED, {"q": ""}) == OBSERVED


# ── THE FIXTURE, ASSERTED AGAINST THE LIVE LAB ───────────────────────────────────────


def test_live_a_blank_value_returns_a_different_page_than_the_observed_value():
    """The mechanism, in raw bytes, on the real target. This is the ground truth the whole gate
    stands on: with an empty value the baseline IS the unfiltered page, so a class-A engine's
    reference is a page the probe could never reproduce.

    SKIPPED IS NEVER A PASS -- an unreachable lab is no measurement, and the skip says so.
    """
    import httpx
    try:
        blank = httpx.get(VALUELESS, timeout=15)
        empty = httpx.get(SEARCH + "?q=", timeout=15)
        valued = httpx.get(OBSERVED, timeout=15)
    except Exception as e:
        pytest.skip("juice-shop lab unreachable (%s); no measurement, not a pass" % e)
    for r in (blank, empty, valued):
        if r.status_code != 200:
            pytest.skip("juice-shop served HTTP %s; no measurement" % r.status_code)
    assert len(blank.text) == len(empty.text), (
        "`?q` and `?q=` diverged (%d vs %d) -- the premise that a missing value and an empty "
        "value are the same input no longer holds" % (len(blank.text), len(empty.text)))
    assert len(valued.text) < len(blank.text) / 2, (
        "the observed value no longer filters the result set (blank=%d bytes, valued=%d) -- this "
        "endpoint has stopped exercising Q-095" % (len(blank.text), len(valued.text)))
