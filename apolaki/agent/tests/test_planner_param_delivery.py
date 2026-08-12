"""D3 (architecture.md 6.1) -- the planner knew every parameter and delivered one.

MEASURED BEFORE THE FIX, on the 7-URL surface below::

    t.local:3000/fetch    run_ssrf    tests=['cmd']    NEVER-TESTED=['target']
    t.local:3000/search   run_sqli    tests=['term']   NEVER-TESTED=['lang', 'url']
    t.local:3000/x        run_sqli    tests=['id']     NEVER-TESTED=['q']
    ... 16 (parameter, engine) pairs the planner knew about and never delivered.

`surface.build_inventory` unions the parameter NAMES per endpoint but keeps ONE `example` URL,
and the planner probed that example. So the parameters that did not happen to ride on the example
URL were never probed by any engine. The run_ssrf row is the sharpest form of it: run_ssrf was
scheduled BECAUSE the inventory saw the URL-ish parameter `target`, and was then handed a URL
carrying only `cmd`.

WHY THE OBVIOUS FIX IS INERT -- measured, and the reason for the shape of this one.
architecture.md proposes ``add params=ep["params"] to the existing step dicts``. `_run_sqli`,
`_run_nosqli`, `_run_cmdi` and `_run_xss` build every probe target with
``xss_tool.set_param(url, p, payload)``, which REPLACES an existing parameter and returns the url
UNCHANGED when the parameter is absent::

    >>> xss_tool.set_param("http://t.local:3000/x?id=1", "q", "PAYLOAD")
    'http://t.local:3000/x?id=1'          # payload not delivered; == the baseline URL

So iterating a `params=` list would send the baseline URL as the probe, baseline and probe would
fail identically, and the endpoint would be reported clean -- this repository's recorded
"probe with observed values" failure mode, reintroduced by the fix for it. The parameters are
therefore carried ON THE URL, which also fixes `run_injection_probes`, `run_web_probes`,
`run_sqlmap`, `run_dalfox` and `run_xxe` (none of which read `inp["params"]`) and leaves
`_run_xss`'s hidden-parameter discovery (which only runs when `params` is NOT supplied) intact.

`test_probe_url_carries_every_param_so_a_payload_actually_lands` is the negative control: it
asserts the OLD rule -- delivered set == params_of(example) -- no longer holds, and that a payload
lands on each formerly-unreachable parameter.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

import planner
import surface as surface_mod
import xss_tool as xt

# One endpoint per shape: two params, three params, and an endpoint whose URL-ish param
# (the reason run_ssrf is scheduled at all) is NOT on the example URL.
URLS = [
    "http://t.local:3000/x?id=1",
    "http://t.local:3000/x?q=a",
    "http://t.local:3000/search?term=x",
    "http://t.local:3000/search?lang=en",
    "http://t.local:3000/search?url=http://a",
    "http://t.local:3000/fetch?cmd=ls",
    "http://t.local:3000/fetch?target=http://b",
]
# The engines that take a per-endpoint probe URL from the phase-E inventory loop.
PARAM_ENGINES = ("run_sqli", "run_nosqli", "run_cmdi", "run_xss", "run_ssrf",
                 "run_injection_probes", "run_web_probes", "run_deserialization",
                 "run_dalfox")


def _state(urls=None, intensity="standard"):
    return {"mode": "full", "roots": ["t.local"], "done": set(),
            "recon": {"subdomains": ["t.local"],
                      "live_hosts": [{"url": "http://t.local:3000"}]},
            "urls": list(URLS if urls is None else urls),
            "bases": {"t.local": "http://t.local:3000"},
            "intensity": intensity}


def _drive(state):
    """Every step the planner emits, to exhaustion (the executor's own drive loop)."""
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


def _probe_urls(steps):
    """{endpoint tag: {tool: probe url}} for the per-endpoint engines."""
    out = {}
    for s in steps:
        if s["tool"] not in PARAM_ENGINES:
            continue
        url = (s.get("input") or {}).get("url")
        if not url:
            continue
        out.setdefault(s["key"].split(":", 1)[1], {})[s["tool"]] = url
    return out


def _inventory():
    return {f"{e['host']}{e['path']}": e
            for e in surface_mod.build_inventory(URLS) if e.get("parameterized")}


# ── the defect ───────────────────────────────────────────────────────────────────────


def test_every_parameter_the_inventory_knows_reaches_the_probe_url():
    inv = _inventory()
    probes = _probe_urls(_drive(_state()))
    assert set(inv) <= set(probes), "planner stopped emitting per-endpoint probes"
    for tag, ep in inv.items():
        known = set(ep["params"])
        for tool, url in sorted(probes[tag].items()):
            got = {k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
            assert known <= got, (
                "%s %s: planner knew %s and the probe URL carries only %s"
                % (tag, tool, sorted(known), sorted(got)))


def test_probe_url_carries_every_param_so_a_payload_actually_lands():
    """NEGATIVE CONTROL -- the old behaviour must be GONE, not merely supplemented.

    Two assertions, both of which FAIL on the pre-fix planner:
      1. the delivered parameter set is no longer `params_of(example)` (a strict superset now);
      2. `xss_tool.set_param` -- the function every injection engine builds its probe with --
         produces a URL DIFFERENT from the baseline for each formerly-unreachable parameter,
         i.e. the payload is on the wire. Assertion 1 alone would pass on a `params=`-only fix
         that never lands a payload.
    """
    inv = _inventory()
    probes = _probe_urls(_drive(_state()))
    widened = 0
    for tag, ep in inv.items():
        old_delivered = set(xt.params_of(ep["example"]))       # exactly the pre-fix behaviour
        known = set(ep["params"])
        missed_before = known - old_delivered
        assert missed_before, "fixture endpoint %s no longer exercises the defect" % tag
        for tool, url in sorted(probes[tag].items()):
            got = {k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
            assert got != old_delivered, (
                "%s %s: still delivering exactly params_of(example)=%s -- D3 is not fixed"
                % (tag, tool, sorted(old_delivered)))
            for p in sorted(missed_before):
                assert xt.set_param(url, p, "APOLAKI_PAYLOAD") != url, (
                    "%s %s: probing %r sends the baseline URL unchanged -- baseline and probe "
                    "fail identically and the endpoint reports clean" % (tag, tool, p))
            widened += 1
    assert widened, "no per-endpoint probe was checked"


def test_ssrf_is_handed_the_urlish_param_that_caused_it_to_be_scheduled():
    """/fetch is scheduled for SSRF because the inventory saw `target`; before the fix the
    engine received a URL carrying only `cmd`, so `ssrf_tool.ssrf_params` fell back to the
    non-URL-ish parameter and the real one was never tested."""
    probes = _probe_urls(_drive(_state()))
    url = probes["t.local:3000/fetch"]["run_ssrf"]
    got = {k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
    assert "target" in got, "run_ssrf still cannot see the URL-ish param it was scheduled for"


# ── the fix must not invent, churn, or drift ─────────────────────────────────────────


def test_merged_urls_use_only_observed_values():
    """Never probe with an invented value: every value on a probe URL was observed on some
    discovered URL for that same endpoint."""
    observed = {}
    for u in URLS:
        p = urlparse(u)
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            observed.setdefault((p.netloc, p.path, k), set()).add(v)
    for tag, tools in _probe_urls(_drive(_state())).items():
        for tool, url in tools.items():
            p = urlparse(url)
            for k, v in parse_qsl(p.query, keep_blank_values=True):
                seen = observed.get((p.netloc, p.path, k))
                assert seen and v in seen, (
                    "%s %s: parameter %r carries invented value %r (observed: %s)"
                    % (tag, tool, k, v, sorted(seen or ())))


def test_probe_urls_are_deterministic_across_runs():
    assert _probe_urls(_drive(_state())) == _probe_urls(_drive(_state()))


def test_an_endpoint_whose_example_already_has_every_param_is_untouched():
    """No churn: the merge is a no-op when there is nothing to recover, so dedup keys, exchange
    ledgers and cached results for already-complete endpoints do not move."""
    urls = ["http://t.local:3000/full?a=1&b=2"]
    probes = _probe_urls(_drive(_state(urls)))
    for tool, url in probes["t.local:3000/full"].items():
        assert url == "http://t.local:3000/full?a=1&b=2", (tool, url)


# ── the two helpers, directly ────────────────────────────────────────────────────────


def test_observed_param_values_groups_by_endpoint_and_prefers_a_real_value():
    got = planner.observed_param_values([
        "http://h/a?x=&y=2",
        "http://h/a?x=1",
        "http://h/b?x=9",
        "http://h/a",
        "not a url",
        "/relative?x=nope",          # no netloc -- not an endpoint
    ])
    assert got[("h", "/a")] == {"x": "1", "y": "2"}
    assert got[("h", "/b")] == {"x": "9"}
    assert ("", "/relative") not in got


def test_merge_observed_params_keeps_existing_values_and_sorts_the_additions():
    assert planner.merge_observed_params(
        "http://h/a?b=own", {"b": "other", "a": "1", "c": "3"}
    ) == "http://h/a?b=own&a=1&c=3"
    assert planner.merge_observed_params("http://h/a?b=1", {"b": "2"}) == "http://h/a?b=1"
    assert planner.merge_observed_params("", {"a": "1"}) == ""
    assert planner.merge_observed_params("http://h/a", {}) == "http://h/a"
