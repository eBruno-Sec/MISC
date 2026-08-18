"""A confirmation oracle has THREE answers, and both boolean oracles must have the same discipline.

Q-040. The ticket in `docs/QUEUE.md` and the strict xfail in `test_sqli_boolean_noise_floor.py`
describe different halves; see `docs/handoff/boolean_oracle.md` section 1. This file covers the half
that was genuinely open:

  * `nosqli.analyze_boolean` had NO baseline-stability control at all, and
  * both oracles reported "I could not measure this endpoint" as `False`, i.e. as "clean".

MEASURED 2026-08-17, live, against `POST https://owaspbench:8443/benchmark/cmdi-00/
BenchmarkTest00494` with `productID=1&foo=1`. That is a CLEAN `cmdi` case -- the application never
reads the field -- so every ``True`` any boolean oracle returns on those bodies is a false positive
by construction. 16 byte-identical POSTs returned 2 distinct bodies in the arrival order

    A A B A A A B B A A A B B A A A

i.e. RUNS, not alternation. Ordered triples over those 16 responses, the reference sample being the
REAL next response in the sequence (`bs[i+1]`) exactly as `tools.py` takes it:

    oracle                                        fires        rate
    sqli.analyze_boolean, ungated (pre-cbcba79)   720/3150     0.229
    sqli.analyze_boolean, gated   (cbcba79)       438/3150     0.139
    nosqli.analyze_boolean (no gate existed)      720/3150     0.229

The middle row independently reproduces the pin's own 0.225 -> 0.150 from a fresh run. The bottom
row is why this file exists: the NoSQL oracle was sitting at the exact pre-fix rate of its sibling.

Every fixture below is transcribed from a live authorized lab, never invented:
  * `NOISE_A` / `NOISE_B` are imported from `test_sqli_boolean_noise_floor`, and were re-verified
    byte-identical to what BenchmarkTest00494 returns today.
  * `CAPTCHA_*` are real `GET http://juice-shop:3000/rest/captcha` responses (12 distinct in 12
    identical requests -- a per-response nonce, the noise shape the ticket names).
  * `REVIEWS` is a real `GET http://juice-shop:3000/rest/products/1/reviews` response -- the
    Mongo-backed endpoint, byte-identical on repeat (1 distinct in 6), so it is the STABLE control.
"""
import ast
import inspect
import itertools
import textwrap

import pytest

import nosqli_tool as nosqli
import sqli_tool as sqli
import tools
from test_sqli_boolean_noise_floor import NOISE_A, NOISE_B

# ── real Juice Shop /rest/captcha responses: a fresh nonce every request ──────────
CAPTCHA = [
    '{"captchaId":20,"captcha":"2-7+9","answer":"4"}',
    '{"captchaId":21,"captcha":"3-2*8","answer":"-13"}',
    '{"captchaId":22,"captcha":"6*9+7","answer":"61"}',
    '{"captchaId":23,"captcha":"2+3*2","answer":"8"}',
    '{"captchaId":24,"captcha":"1-1+10","answer":"10"}',
    '{"captchaId":25,"captcha":"6+3*8","answer":"30"}',
    '{"captchaId":26,"captcha":"7*7-7","answer":"42"}',
    '{"captchaId":27,"captcha":"2*10*6","answer":"120"}',
]

# ── a real Juice Shop response that DOES reproduce byte-for-byte ──────────────────
# `GET http://juice-shop:3000/rest/languages`, measured 1 distinct body in 6 identical
# requests. Rows 1 and 1..3 of the real 42-row array, verbatim -- a BARE JSON array, which
# is the only body shape this oracle's containment test can fire on at all (see
# `test_the_nosqli_containment_oracle_only_fires_on_a_bare_array`).
LANGS_ONE = ('[{"key":"az_AZ","lang":"Az\\u0259rbaycanca","icons":["az"],"shortKey":"AZ",'
             '"percentage":38,"gauge":"quarter"}]')
LANGS_THREE = ('[{"key":"az_AZ","lang":"Az\\u0259rbaycanca","icons":["az"],"shortKey":"AZ",'
               '"percentage":38,"gauge":"quarter"},{"key":"id_ID","lang":"Bahasa Indonesia",'
               '"icons":["id"],"shortKey":"ID","percentage":14,"gauge":"empty"},'
               '{"key":"ca_ES","lang":"Catalan","icons":["es-ct"],"shortKey":"CA",'
               '"percentage":8,"gauge":"empty"}]')
LANGS_EMPTY = "[]"

# a real Mongo-backed Juice Shop response, object-wrapped (1 distinct in 6)
REVIEWS = ('{"status":"success","data":[{"message":"One of my favorites!",'
           '"author":"admin@juice-sh.op","product":1,"likesCount":0,"likedBy":[],'
           '"_id":"bbwfX5ooKu2ZeAFrh","liked":true}]}')
REVIEWS_BROADENED = ('{"status":"success","data":[{"message":"One of my favorites!",'
                     '"author":"admin@juice-sh.op","product":1,"likesCount":0,"likedBy":[],'
                     '"_id":"bbwfX5ooKu2ZeAFrh","liked":true},{"message":"Great! We\'ll have an '
                     'apple party.","author":"basil@juice-sh.op","product":1,"likesCount":0,'
                     '"likedBy":[],"_id":"kXydagQKW7kKZ3iYa","liked":true}]}')


# ── the fixture is REALITY, and this pins that it still is ────────────────────────
def test_the_recorded_noise_pair_is_the_shape_the_lab_really_returns():
    """Both bodies come from byte-identical requests, and they straddle the 0.95 cut."""
    assert NOISE_A != NOISE_B
    assert sqli.similar(NOISE_A, NOISE_B) == pytest.approx(0.9091, abs=1e-3)
    assert len({*CAPTCHA}) == len(CAPTCHA), "a captcha body is different on every request, by design"


# ── ONE convention, not two ───────────────────────────────────────────────────────
def test_both_oracles_share_one_inconclusive_convention():
    """A second convention for the same idea is how two engines start disagreeing about what
    'could not decide' means. `nosqli` imports the names, it does not redefine them."""
    assert nosqli.INCONCLUSIVE_TOKEN is sqli.INCONCLUSIVE_TOKEN
    assert nosqli.Inconclusive is sqli.Inconclusive
    assert nosqli.is_inconclusive is sqli.is_inconclusive


def test_the_token_is_a_prefix_and_is_not_the_negative_result_token():
    """Same SHAPE as `main.NEGATIVE_RESULT_TOKEN` (a prefix the consumer prefix-matches, never
    English it classifies), deliberately NOT the same LITERAL.

    "the thing is not here" and "I could not establish whether the thing is here" are different
    verdicts. Folding the second into the first is the same lie Q-067 fixed, pointing the other
    way -- it would report an unmeasurable endpoint as proven clean.
    """
    import main as mainmod
    assert sqli.INCONCLUSIVE_TOKEN == "NOT MEASURABLE:"
    assert sqli.INCONCLUSIVE_TOKEN != mainmod.NEGATIVE_RESULT_TOKEN
    assert sqli.INCONCLUSIVE_TOKEN.endswith(":"), "prefix-matchable, like the sibling token"
    v = sqli.Inconclusive("the reference did not reproduce")
    assert v.token.startswith(sqli.INCONCLUSIVE_TOKEN)
    assert v.token[len(sqli.INCONCLUSIVE_TOKEN):].strip() == "the reference did not reproduce"


def test_the_third_outcome_is_falsy_so_no_untaught_caller_can_be_tricked_into_a_finding():
    """THE safety property of this design, and the reason the sentinel is not a truthy object.

    Every call site in the tree is `if <oracle>(...)`. A truthy sentinel would have turned every
    caller that has not yet learned about the third outcome into a false positive on exactly the
    unstable endpoints this ticket exists to protect -- the defect, wearing the fix's coat.
    """
    v = sqli.Inconclusive("whatever")
    assert not v
    assert bool(v) is False
    assert v == False          # noqa: E712 -- the point is that it compares equal to the old answer
    assert sqli.is_inconclusive(v)
    # ...while still being distinguishable by the callers that DO ask the stricter question
    assert v is not False
    assert not sqli.is_inconclusive(False)
    assert not sqli.is_inconclusive(True)


# ── sqli: the refusal paths now say WHICH refusal ─────────────────────────────────
def test_sqli_separates_could_not_measure_from_no_injection_here():
    base = "<html><body>" + ", ".join("row-%02d" % i for i in range(24)) + "</body></html>"
    false_ = "<html><body>" + ", ".join("row-%02d" % i for i in range(20)) + "</body></html>"

    # a real NEGATIVE: the reference reproduced and there is simply no differential
    plain = sqli.analyze_boolean(base, base, base, baseline_repeat=base)
    assert plain is False, "a decided negative must stay a plain False"
    assert not sqli.is_inconclusive(plain)

    # a REFUSAL: the reference did not reproduce
    refused = sqli.analyze_boolean(NOISE_A, NOISE_A, NOISE_B, baseline_repeat=NOISE_B)
    assert not refused, "still falsy -- the old callers keep their old safe behaviour"
    assert sqli.is_inconclusive(refused), "but it must no longer be indistinguishable from 'clean'"
    assert "did not reproduce" in refused.reason
    assert "1 of 2" in refused.reason, refused.reason

    # a REFUSAL: an observation the oracle needed never completed
    dead = sqli.analyze_boolean(base, base, false_, baseline_repeat=None)
    assert sqli.is_inconclusive(dead) and "did not complete" in dead.reason

    # and the confirmation is untouched
    assert sqli.analyze_boolean(base, base, false_, baseline_repeat=base) is True


def test_sqli_refuses_rather_than_clears_when_the_false_differential_does_not_reproduce():
    """The references reproduced byte-exactly, yet the SAME payload returned two different pages.
    That contradicts the determinism the gate just certified, so it is a refusal, not a clean
    verdict. `test_sqli_boolean_noise_floor` pins the falsiness; this pins the CLASS."""
    base = "<html><body>" + ", ".join("row-%02d" % i for i in range(24)) + "</body></html>"
    false_ = "<html><body>" + ", ".join("row-%02d" % i for i in range(20)) + "</body></html>"
    v = sqli.analyze_boolean(base, base, false_, baseline_repeat=base, false_repeat=base)
    assert not v and sqli.is_inconclusive(v) and "did not reproduce" in v.reason


# ── nosqli: the control that did not exist ────────────────────────────────────────
def test_nosqli_refuses_the_live_false_positive_the_gate_was_missing():
    """THE regression test for the 0.229 measured above.

    `NOISE_A`/`NOISE_B` are two responses to byte-identical POSTs on a CLEAN benchmark case, so a
    confirmation here is a false positive by construction. The operator body being byte-equal to
    the baseline while the control landed in the other state is exactly how the containment oracle
    fired: no injection is required to produce it.
    """
    # UNGATED -- the pre-fix behaviour, kept visible so the defect cannot be argued about
    assert nosqli.analyze_boolean(NOISE_A, NOISE_A, NOISE_B) is True, (
        "fixture must reproduce the measured false positive, or this test proves nothing")

    # GATED with a real second response to the same unprobed request
    v = nosqli.analyze_boolean(NOISE_A, NOISE_A, NOISE_B, baseline_repeat=NOISE_B)
    assert not v, "an endpoint that does not reproduce must not confirm a NoSQL injection"
    assert nosqli.is_inconclusive(v) and "did not reproduce" in v.reason


@pytest.mark.xfail(strict=True, reason=(
    "MEASURED, and a REAL residual rather than a test bug: 18 of the 120 ordered triples still "
    "confirm with the stability gate applied. Diagnosed, not guessed -- ONE repeat cannot "
    "establish stability on a BIMODAL page. NOISE_A/NOISE_B are the two states of one clean "
    "endpoint, so a single baseline_repeat lands in the SAME state as the baseline roughly half "
    "the time; the page then looks stable to the gate and the differential is indistinguishable "
    "from the injection it is supposed to prove. The gate is sound and closes the single-sample "
    "case -- the test above passes -- but it cannot decide bimodality from one sample. Closing "
    "this needs a stronger control: more than one repeat, or requiring the TRUE/FALSE pair to "
    "fall outside the OBSERVED noise envelope rather than merely differ. That carries a "
    "false-negative risk (an over-strict envelope blinds the oracle on a genuinely stable "
    "target), so it is filed as Q-070 rather than rushed. STRICT: the day a stronger control "
    "lands this XPASSes and must be retired deliberately."))
def test_nosqli_false_positive_rate_on_real_noise_goes_to_zero():
    """The measured rate, at scale, on the real bodies. Ordered triples with the reference drawn
    from the same two-state page -- every fire is a false positive by construction."""
    bodies = [NOISE_A, NOISE_A, NOISE_B, NOISE_A, NOISE_B, NOISE_B]
    ungated = gated = 0
    for i, (a, b, c) in enumerate(itertools.permutations(bodies, 3)):
        ref = bodies[(i + 1) % len(bodies)]
        ungated += bool(nosqli.analyze_boolean(a, b, c))
        gated += bool(nosqli.analyze_boolean(a, b, c, baseline_repeat=ref))
    assert ungated > 0, "positive control: the sweep must be able to fire, or the zero means nothing"
    assert gated == 0, "%d confirmations on responses containing no injection at all" % gated


def test_nosqli_still_confirms_a_real_broadening_on_a_page_that_reproduces():
    """THE negative control for the fix: it must not be silence.

    A genuinely stable target must still confirm. `LANGS_*` are real rows of Juice Shop's
    `/rest/languages` array, measured byte-identical on repeat, and a $ne-style bypass broadens
    a one-row result set into a three-row one.
    """
    assert nosqli.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_EMPTY,
                                  baseline_repeat=LANGS_ONE) is True
    # and the same page with several reproducing reference samples
    assert nosqli.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_EMPTY,
                                  baseline_samples=[LANGS_ONE, LANGS_ONE]) is True
    # the missing-param suppression still works alongside the new gate
    assert not nosqli.analyze_boolean(LANGS_ONE, LANGS_EMPTY, LANGS_EMPTY, LANGS_EMPTY,
                                      baseline_repeat=LANGS_ONE)
    # a control that broadens the SAME way proves nothing about the operator -> still no confirm
    assert not nosqli.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_THREE, LANGS_EMPTY,
                                      baseline_repeat=LANGS_ONE)


def test_the_nosqli_containment_oracle_only_fires_on_a_bare_array():
    """Recorded because it bounds what the fix above can be claimed to protect.

    `_row_fragment` strips ONE enclosing `[...]` pair, so on a bare array the fingerprint is the
    ROWS and a broadened response contains them. On an object-wrapped body -- `{"status":"success",
    "data":[...]}`, which is what Juice Shop and VAmPI actually serve on every endpoint measured --
    the fingerprint is the WHOLE body, and a broadened response never contains it verbatim. So
    this oracle is structurally incapable of confirming on those APIs.

    NOT this ticket, and deliberately not fixed here: widening the fingerprint is a change to what
    the oracle CONFIRMS on, which needs its own false-positive measurement. Pinned so it is a
    known bound rather than a surprise. See docs/handoff/boolean_oracle.md section 6.
    """
    assert nosqli.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_EMPTY) is True
    assert nosqli.analyze_boolean(REVIEWS, REVIEWS_BROADENED, '{"status":"success","data":[]}') \
        is False, "object-wrapped broadening cannot fire the containment oracle"


def test_nosqli_refuses_a_per_response_nonce_endpoint_instead_of_calling_it_clean():
    """The captcha shape. MEASURED: this endpoint never false-POSITIVED (0/336) -- containment
    cannot hold across a churning body -- so the bug here is the other direction, and it is the
    one this ticket names: an endpoint that cannot be measured was reported as measured and clean.
    """
    ungated = nosqli.analyze_boolean(CAPTCHA[0], CAPTCHA[1], CAPTCHA[2])
    assert ungated is False and not nosqli.is_inconclusive(ungated), (
        "pre-fix this was a bare False, i.e. reported to the operator as 'tested, clean'")
    v = nosqli.analyze_boolean(CAPTCHA[0], CAPTCHA[1], CAPTCHA[2], baseline_repeat=CAPTCHA[3])
    assert not v, "still falsy"
    assert nosqli.is_inconclusive(v), "and now it SAYS it could not measure the endpoint"


def test_nosqli_reference_contract_matches_sqli_exactly():
    """One discipline across both oracles, so a reviewer only has to learn it once.

    `None` means "the request was attempted and failed" and is refused; omitted means "not
    attempted" and leaves the pre-existing behaviour alone.
    """
    for mod in (sqli, nosqli):
        assert mod.is_inconclusive(mod.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_EMPTY,
                                                       baseline_repeat=None))
        assert mod.is_inconclusive(mod.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_EMPTY,
                                                       baseline_samples=[None]))
        assert mod.is_inconclusive(mod.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_EMPTY,
                                                       baseline_samples=[]))
    # omitted -> the gate does not run at all, and neither oracle changes its old answer
    assert nosqli.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_EMPTY) is True


def test_the_nosqli_gate_uses_equality_not_a_similarity_threshold():
    """The traversal precedent, and the measured reason `cbcba79` chose equality.

    BenchmarkTest00023's 12 distinct bodies were pairwise 0.9495..0.9766, so EVERY pair cleared a
    0.95 threshold and a threshold-based gate contributed nothing (FP/attempt 0.045 -> 0.045).
    A threshold on noise is not a test for its absence. Two responses to identical requests that
    differ AT ALL are the evidence, whatever their similarity.
    """
    near = LANGS_ONE.replace('"percentage":38', '"percentage":39')   # 1 char, similarity ~0.99
    assert sqli.similar(LANGS_ONE, near) > 0.98
    v = nosqli.analyze_boolean(LANGS_ONE, LANGS_THREE, LANGS_EMPTY, baseline_repeat=near)
    assert nosqli.is_inconclusive(v), "a 99%-similar reference is still a reference that CHANGED"


# ── the call site: this gate is INERT until tools.py supplies the sample ───────────
def _boolean_calls(func, module_name):
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == module_name
            and n.func.attr == "analyze_boolean"]


def test_the_sqli_carriers_all_still_supply_a_reference_sample():
    """The half that IS wired, pinned here too so this file stands alone as the lane's contract."""
    calls = _boolean_calls(tools.ToolRegistry._run_sqli, "sqli")
    assert len(calls) == 2, "measured shipping call-site baseline changed; review every new carrier"
    for c in calls:
        assert "baseline_repeat" in {k.arg for k in c.keywords}


@pytest.mark.xfail(strict=True, reason="THE GATE IS INERT UNTIL tools.py SUPPLIES THE SAMPLE. "
                                       "nosqli.analyze_boolean now accepts baseline_repeat, but "
                                       "tools.ToolRegistry._run_nosqli takes exactly ONE baseline "
                                       "response (tools.py:7846 `base_r = await get(c, url)`) and "
                                       "calls the oracle positionally, so the control cannot run "
                                       "in production and the measured 0.229 FP/attempt on "
                                       "BenchmarkTest00494 stands until it does. The parameter is "
                                       "optional BY NECESSITY -- making it required would break "
                                       "that positional call site instantly -- which is exactly "
                                       "the 'guard that exists but never runs' shape, so it is "
                                       "pinned rather than declared done. agent/tools.py is not "
                                       "this lane's file; the two-hunk patch is in "
                                       "docs/handoff/boolean_oracle.md section 5a. Applying it "
                                       "turns this XPASS and the marker must then be removed.")
def test_the_nosqli_carrier_supplies_a_reference_sample():
    calls = _boolean_calls(tools.ToolRegistry._run_nosqli, "ns")
    assert calls, "the boolean call site moved; re-derive before trusting this pin"
    for c in calls:
        assert "baseline_repeat" in {k.arg for k in c.keywords} or len(c.args) >= 5
