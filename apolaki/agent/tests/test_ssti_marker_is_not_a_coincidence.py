"""Q-126 - the SSTI oracle raised CVSS 9.8 against a live bug-bounty target on two digits.

From the operator's rerun, verbatim:

    Finding 1: Server-side template injection on 'locale'          HIGH   CVSS 9.8
    Target: https://admin.shopify.com/signup?locale=%7B%7B7%2A7%7D%7D...
    False-positive safety: NOT ESTABLISHED. NO NEGATIVE CONTROL WAS RECORDED.

The oracle was:

    _SSTI_MARKER = "49"
    if _SSTI_MARKER in probe_body and _SSTI_MARKER not in baseline_body:  -> HIGH

`49`. Two characters. A signup page contains a nonce, a build hash, asset URLs, pixel dimensions and
a timestamp, and the baseline and the probe are two separate requests -- any per-request variance
flips it. Nothing was injected; something on the second page contained the digits.

THIS IS THE THIRD NEIGHBOUR OF ONE DEFECT. Q-106 was CRLF matching a substring where the claim was
structural. Q-106b was the host-header oracle doing the same. This is SSTI, and it was found only
because a rerun surfaced it -- the audit after Q-106 checked its neighbours and stopped short of
this one. The lesson each time is identical: THE EVIDENCE MUST HAVE THE SHAPE OF THE CLAIM.

THE FIX IS RANDOM OPERANDS, and the length is not the point -- the ARITHMETIC is. `4831*7219` yields
`34874989`, which is not a substring of the payload, so an ECHO of the literal expression cannot
produce it. The number can only appear if something performed the multiplication. That converts a
coincidence detector into an oracle, and it is the same device the XSS canary and `run_dom_trace`'s
marker have used all along.

Reporting a 9.8 to a mature program on a coincidence is the most expensive thing this tool can do.
"""
import re

import web_security as ws


def _payload_and_expected():
    p = ws._ssti_payload()
    return p, ws.ssti_expected(p)


# -- the field false positive --------------------------------------------------

def test_a_stray_49_in_the_response_is_not_a_finding():
    """THE EXACT FIELD FAILURE. A page mentioning 49 -- a price, an id, a pixel width -- convicted
    admin.shopify.com of remote code execution."""
    payload, _ = _payload_and_expected()
    assert ws.analyze_ssti("<p>welcome</p>", "<p>welcome</p><img width=49>", payload) is None


def test_any_number_the_page_happens_to_carry_is_not_a_finding():
    """Generalised, because the old marker was not special -- it was merely short. A nonce, a build
    hash and a timestamp all differ between two requests to a live page."""
    payload, _ = _payload_and_expected()
    noisy = "<meta nonce='a49b31'><script src='/x.js?v=1749382'></script><span>2049</span>"
    assert ws.analyze_ssti("<p>base</p>", noisy, payload) is None


def test_the_literal_expression_echoed_back_is_not_a_finding():
    """Reflection is not evaluation, and this is the case the fix makes structurally impossible: the
    product is NOT a substring of the payload, so echoing the payload cannot produce it."""
    payload, expected = _payload_and_expected()
    assert expected not in payload, (payload, expected)
    assert ws.analyze_ssti("<p>base</p>", "you searched for " + payload, payload) is None


# -- non-vacuity: a real evaluation is still HIGH ------------------------------

def test_a_genuine_evaluation_is_still_HIGH():
    """Without this, `return None` satisfies every test above and the engine is deleted, not fixed."""
    payload, expected = _payload_and_expected()
    got = ws.analyze_ssti("<p>hello </p>", "<p>hello %s</p>" % expected, payload)
    assert got and got["severity"] == "HIGH", got
    assert got["expected"] == expected


def test_the_detail_names_the_product_so_a_reader_can_recheck_it():
    """A HIGH whose evidence cannot be re-derived by the person receiving it is not a report."""
    payload, expected = _payload_and_expected()
    got = ws.analyze_ssti("", expected, payload)
    assert expected in got["detail"], got["detail"]


# -- the negative control is kept ---------------------------------------------

def test_a_product_already_present_in_the_baseline_is_not_ours():
    """The baseline comparison survives the rewrite. If the number was there before we touched
    anything, we did not cause it."""
    payload, expected = _payload_and_expected()
    body = "order total %s" % expected
    assert ws.analyze_ssti(body, body, payload) is None


# -- the discriminator itself --------------------------------------------------

def test_the_operands_are_random_per_probe():
    """Two parameters on one page must not share a product, or one stray number convicts both."""
    payloads = {ws._ssti_payload() for _ in range(25)}
    assert len(payloads) >= 20, payloads


def test_every_payload_yields_a_product_that_is_not_in_the_payload():
    """THE PROPERTY THE WHOLE FIX RESTS ON, asserted over many draws rather than one lucky pair."""
    for _ in range(200):
        p = ws._ssti_payload()
        e = ws.ssti_expected(p)
        assert e and len(e) >= 6, (p, e)
        assert e not in p, (p, e)


def test_a_probe_carries_its_own_expression_and_the_builder_uses_it():
    """NO ISLANDS. A randomised payload generator nothing calls would leave the fixed marker live."""
    probes = ws.build_ssti_probes("https://t.test/p?name=bob&locale=en")
    assert probes, "the builder produced no probes, so nothing above is under test"
    assert len({pr.payload for pr in probes}) == len(probes), [pr.payload for pr in probes]
    for pr in probes:
        assert re.search(r"\{\{\d{4}\*\d{4}\}\}", pr.payload), pr.payload
        assert ws.ssti_expected(pr.payload) in ws.analyze_ssti(
            "", ws.ssti_expected(pr.payload), pr.payload)["detail"]


def test_an_oracle_that_was_not_told_what_it_sent_returns_nothing():
    """A caller that cannot say what it sent cannot say what came back. Silence, never a default
    verdict -- the fixed `49` WAS the default verdict, and it convicted a real company."""
    assert ws.analyze_ssti("", "34874989", "") is None
    assert ws.analyze_ssti("", "anything", "no operands here") is None
