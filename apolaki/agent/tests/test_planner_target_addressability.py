"""Q-093 root cause (B) -- the planner's addressability chokepoint guards 2 of the 4 keys it declares.

SEPARATE DEFECT FROM Q-093 (A). (A) is `_http` dropping the transport outcome, which makes an
unrequestable URL VISIBLE. It does not stop one being built. This file is about the building.

Q-019 traced `https:///benchmark/cmdi-Index.html` -- scheme present, netloc EMPTY -- to
`planner._b("")` returning `f"https://{h}"` == `"https://"`, fixed `_b` to return `""` for an empty
host, and installed `planner._addressable` at `fresh()` as "Q-019's single chokepoint. **Every URL a
step targets is built here.**"  `tests/test_hostless_target_guard.py` pins it.

**IT IS NOT EVERY URL, AND ITS OWN GUARD FILE CANNOT SEE THE GAP.** `_addressable` inspects
`("url", "base_url")`. Twelve lines above it, planner.py declares:

    _TARGET_KEYS      = ("url", "base_url", "target")     # + target: run_nuclei / run_nmap_vuln
    _TARGET_LIST_KEYS = ("urls",)                         # the list run_js_review / run_saml fetch

`tests/test_hostless_target_guard.py::_step_urls` collects `("url", "base_url")` too -- the guard's
coverage is exactly congruent with the code's blind spot, so it passes green over the hole it exists
to close. That is this project's most expensive recurring shape: a guard that checks a declaration
rather than a fact.

**MEASURED, live, against HEAD 1d85fe3, driving the REAL `planner.next_batch` (no fixtures, no
stubs) over a surface carrying one host-less `.js` URL:**

    steps=45  unaddressable=2
        ('run_js_review', 'urls', "'/static/app.js'",        'NOT ABSOLUTE')
        ('run_js_review', 'urls', "'https:///static/b.js'",  'NOT ABSOLUTE')
        js_review input: {'urls': ['/static/app.js', 'https:///static/b.js']}

`https:///static/b.js` is the Q-019 string, still being emitted, through the one key both the
planner chokepoint AND the executor ingress skip. The path is direct and unfiltered:

    planner.py:642  js_urls = _rank_urls([u for u in urls if u.split("?")[0].lower().endswith(".js")])
    planner.py:662  d.append(_step("run_js_review", {"urls": js_urls[:CAP_JS]}, "run_js_review"))

`js_urls` comes straight off raw `state["urls"]`. It never passes through `_abs`, which is the
helper Q-019 built so that "no host, no URL" had one definition.

AND THE OTHER HALF OF THE GAP: `_b("")` now returns `""`, so `_step("run_nuclei", {"target": _b(h)})`
builds `{"target": ""}` for a host-less `h`. An empty string is not `https:///` -- it is a REAL value
meaning "there is no base" -- and `_addressable` never looks at `target` at all. `x or DEFAULT` where
the empty value is a real input is this codebase's recorded falsy-default failure mode; this is its
mirror image, an empty value flowing on because nothing asks about it.

WHAT IS ALREADY CLOSED, stated so nobody re-fixes it. MEASURED the same way, both return 0
unaddressable steps: an empty entry in `recon["subdomains"]` (planner.py:609 filters `if s`) and an
empty `roots` entry. Q-019's `_b`/`_abs`/`_addressable` work for the keys they cover.

THE FIX THIS FILE DEMANDS is not "add two more keys to a second list" -- that is how the two lists
drifted apart in the first place. `_addressable` must DERIVE its keys from `_TARGET_KEYS` and
`_TARGET_LIST_KEYS`, so a future target key is guarded by existing, and a test written against the
constants cannot be narrower than the code.
"""
from __future__ import annotations

from urllib.parse import urlparse

import pytest

import planner

BASE = "https://owaspbench:8443"
HOSTLESS = "https:///static/b.js"          # the Q-019 string, verbatim
RELATIVE = "/static/app.js"


def _unaddressable(step: dict) -> list:
    """Every declared target on this step that cannot be requested, derived from planner's own keys.

    Deliberately NOT a copy of `_addressable`'s rule: if it were, this file would agree with the
    code by construction and prove nothing. It states the property independently -- a request target
    must name a host -- and reads the KEY LIST from the module so it can never guard less than
    planner declares.
    """
    inp = step.get("input") or {}
    bad = []
    for k in planner._TARGET_KEYS:
        if k not in inp:
            continue
        v = inp[k]
        if not isinstance(v, str) or not v.strip():
            bad.append((k, v, "empty target"))
        elif "://" in v and not urlparse(v).netloc:
            bad.append((k, v, "scheme with no host"))
    for k in planner._TARGET_LIST_KEYS:
        for v in (inp.get(k) or []):
            p = urlparse(v) if isinstance(v, str) else None
            if p is None or p.scheme not in ("http", "https") or not p.netloc:
                bad.append((k, v, "not an absolute http(s) URL"))
    return bad


def _plan_all(roots, subs, urls, bases, mode="full"):
    """Run the REAL planner to exhaustion. Nothing here is stubbed."""
    done, steps = set(), []
    for _ in range(60):
        batch = planner.next_batch({
            "mode": mode, "roots": list(roots), "done": done,
            "recon": {"subdomains": list(subs), "live_hosts": [], "forms": []},
            "urls": list(urls), "bases": bases, "zap": False,
            "nmap_vuln": True, "nuclei_heavy": True, "intensity": "standard"})
        if not batch:
            break
        for s in batch:
            done.add(s["key"])
        steps += batch
    return steps


# THE NEGATIVE CONTROL FOR THIS FILE ITSELF. `pytest tests/test_planner_target_addressability.py -q`
# against HEAD 1d85fe3, the commit BEFORE `_addressable` derived its keys:
#
#     ..FFFF....                                                               [100%]
#     FAILED ...::test_every_declared_scalar_target_key_refuses_a_hostless_url[target]
#     FAILED ...::test_every_declared_list_target_key_refuses_a_hostless_url[urls]
#     FAILED ...::test_an_empty_target_is_refused
#     FAILED ...::test_the_real_planner_never_emits_a_hostless_js_bundle
#
# 4 failed, 6 passed. The 6 that ALREADY PASSED are `url`, `base_url` and all four negative
# controls -- so the file distinguishes a guarded key from an unguarded one rather than simply
# disliking every target. They were committed first as `xfail(strict=True)` (`8df4535`), marked
# per-key from an explicit `_UNGUARDED = ("target", "urls")`, and the marker was deleted by the fix
# that made them XPASS -- which, being strict, is how it was forced to be deleted.


# ── the gap, stated over planner's OWN declaration ────────────────────────────

@pytest.mark.parametrize("key", planner._TARGET_KEYS)
def test_every_declared_scalar_target_key_refuses_a_hostless_url(key):
    """MUST FAIL before the fix, for `target`. `url`/`base_url` already pass -- that is the control.

    Parametrized over the constant, not over a list written here, so adding a fifth target key to
    planner.py adds a test case rather than a blind spot.
    """
    step = {"tool": "run_nuclei", "input": {key: HOSTLESS}, "key": "k"}
    assert planner._addressable(step) is False, (
        "planner._TARGET_KEYS declares %r a request target, but _addressable admits %r under it"
        % (key, HOSTLESS))


@pytest.mark.parametrize("key", planner._TARGET_LIST_KEYS)
def test_every_declared_list_target_key_refuses_a_hostless_url(key):
    """MUST FAIL before the fix. This is the key that is still emitting the Q-019 string live."""
    step = {"tool": "run_js_review", "input": {key: [BASE + "/ok.js", HOSTLESS]}, "key": "k"}
    assert planner._addressable(step) is False, (
        "planner._TARGET_LIST_KEYS declares %r a request target, but _addressable admits a list "
        "containing %r" % (key, HOSTLESS))


def test_an_empty_target_is_refused():
    """MUST FAIL before the fix.

    `_b("")` returns `""` since Q-019, and `_step("run_nuclei", {"target": _b(h)})` carries it
    through. "" is a real value meaning "there is no base", never a target.
    """
    assert planner._addressable({"tool": "run_nuclei", "input": {"target": ""}, "key": "k"}) is False


def test_the_real_planner_never_emits_a_hostless_js_bundle():
    """MUST FAIL before the fix -- the live reproduction, end to end through `next_batch`.

    MEASURED against HEAD 1d85fe3:
        steps=45  unaddressable=2   run_js_review urls=['/static/app.js', 'https:///static/b.js']
    """
    steps = _plan_all(["owaspbench:8443"], [],
                      [BASE + "/x.html", RELATIVE, HOSTLESS], {"owaspbench": BASE})
    bad = [(s["tool"],) + tuple(b) for s in steps for b in _unaddressable(s)]
    assert bad == [], "the planner emitted %d unaddressable target(s): %s" % (len(bad), bad[:6])


# ── negative controls: all four MUST PASS before AND after ────────────────────
# Without these the fix "make _addressable return False" would pass everything above.

def test_a_bare_host_target_is_still_accepted():
    """`target` is POLYMORPHIC and must stay so.

    `run_nuclei` gets a URL (`_b(h)`), but `run_nmap_vuln` gets a bare host and `run_dork_gen` gets
    a bare domain -- neither is an absolute URL and both are perfectly addressable. A rule that
    demanded `http(s)://` on every `target` would silently delete the entire nmap and dork phases,
    trading a latent gap for a live capability loss.
    """
    for v in ("owaspbench:8443", "example.com", "10.0.0.5"):
        assert planner._addressable({"tool": "run_nmap_vuln", "input": {"target": v}, "key": "k"}) \
            is True, "a bare host target was refused: %r" % (v,)


def test_an_addressable_js_bundle_list_is_still_planned():
    """Non-vacuity: the guard must not be passing by scheduling nothing."""
    steps = _plan_all(["owaspbench:8443"], [],
                      [BASE + "/x.html", BASE + "/static/app.js", BASE + "/static/b.js"],
                      {"owaspbench": BASE})
    js = [s for s in steps if s["tool"] == "run_js_review"]
    assert js, "run_js_review was not planned at all on an addressable surface"
    assert js[0]["input"]["urls"], "run_js_review was planned with an empty bundle list"
    assert all(urlparse(u).netloc for u in js[0]["input"]["urls"])


def test_the_planner_still_plans_a_full_batch_on_an_addressable_surface():
    """Non-vacuity over the WHOLE plan, every phase, every declared key."""
    steps = _plan_all(["owaspbench:8443"], ["api.owaspbench"],
                      [BASE + "/x.html?q=1", BASE + "/static/app.js", BASE + "/graphql"],
                      {"owaspbench": BASE})
    assert len(steps) > 20, "only %d steps planned -- the guard is eating the plan" % len(steps)
    bad = [(s["tool"],) + tuple(b) for s in steps for b in _unaddressable(s)]
    assert bad == [], bad[:6]
    assert any(s["tool"] == "run_nuclei" for s in steps), "the nuclei phase was dropped"


def test_the_already_closed_paths_stay_closed():
    """Regression pin on what Q-019 DID fix, so a later change cannot quietly reopen it.

    MEASURED at 0 unaddressable steps each: an empty entry in `recon["subdomains"]`
    (planner.py:609 filters `if s`) and an empty `roots` entry.
    """
    for roots, subs in ((["owaspbench:8443"], ["", "api.owaspbench"]),
                        (["", "owaspbench:8443"], [])):
        steps = _plan_all(roots, subs, [BASE + "/x.html"], {"owaspbench": BASE})
        bad = [(s["tool"],) + tuple(b) for s in steps for b in _unaddressable(s)]
        assert bad == [], "roots=%r subs=%r reopened Q-019: %s" % (roots, subs, bad[:4])
