"""One repeat cannot establish stability on a BIMODAL page -- the N curve, MEASURED (Q-070).

Q-040 shipped a stability gate that demands the reference request reproduce byte-exactly. It is
sound, and it is a TWO-SAMPLE test: baseline plus one repeat. On a page whose output is not a
function of its input, two samples land in the same state often enough that the gate certifies the
page as stable and the oracle reads the page's own state change as the injection it was looking
for. Q-070's residual -- 18 of the pin's 120 ordered triples -- was that shape.

WHAT THE LIVE PAGE ACTUALLY DOES, captured 2026-08-18: 40 byte-identical POSTs to
`https://owaspbench:8443/benchmark/cmdi-00/BenchmarkTest00494` with `productID=1&foo=1`. That is a
CLEAN `cmdi` case; the application never reads either field, so the responses are the SAME
stochastic process with or without a payload, and every confirmation any boolean oracle returns on
them is a false positive by construction.

    AABBBAABBBAABBBAABBBAABBBAABBBAABBBAABBB

2 distinct bodies, pairwise similarity 0.9091, run lengths [2, 3] repeating sixteen times. It is
not alternation and it is not a coin: it is a PERIOD-5 CYCLE, and the longest run is 3. That single
number is what decides how many reference samples are enough here, and it is the reason a fix has
to be chosen by measurement -- nobody would have guessed a period-5 resolver cycle.

THE TRADEOFF, both halves measured on live data rather than asserted:

    N   references supplied   FP/attempt, bimodal page   live true positives confirming
    1   none (ungated)             0.395  (15/38)                  5 of 5
    2   1 repeat  <- SHIPPED       0.189  ( 7/37)                  5 of 5
    3   2 repeats                  0.000  ( 0/36)                  5 of 5
    4   3 repeats                  0.000  ( 0/35)                  5 of 5

Recall is the five boolean-blind true positives the oracle really finds on this lab
(00033/00428/00429/00433/00438, POST-form lane), replayed the same day: each returned ONE distinct
body in six identical requests, so every extra reference sample simply agrees and costs them
nothing. **N buys precision at the price of requests, not at the price of recall** -- on a page
that is genuinely stable, which is the only kind of page the oracle was ever entitled to decide.

WHAT N COSTS, since this runs per candidate parameter in a sweep. In the query-string carrier
(`tools.py:7457-7463`) the samples are taken ONCE per `_run_sqli` call, before the parameter loop,
so N-1 extra requests amortise across every parameter and every payload pair -- against roughly
8 boolean requests per parameter alone, N=4 is under a 5% increase on a two-parameter URL. In the
POST-form carrier (`tools.py:7558-7566`) they are taken inside the FIELD loop, so the cost is N-1
per field and does not amortise. That asymmetry is the real price and it belongs next to the
accuracy number.

The bodies here are the real ones. `NOISE_A`/`NOISE_B` are imported from
`test_sqli_boolean_noise_floor` and were re-verified byte-identical to the two states the live case
returned on 2026-08-18; the true-positive bodies below are transcribed from that same capture.
"""
import ast
import inspect
import textwrap

import pytest

import nosqli_tool as nosqli
import sqli_tool as sqli
import tools
from test_sqli_boolean_noise_floor import NOISE_A, NOISE_B

#: The arrival order of the two states over 40 byte-identical requests, 2026-08-18.
ARRIVAL = "AABBBAABBBAABBBAABBBAABBBAABBBAABBBAABBB"


def _sequence():
    return [NOISE_A if ch == "A" else NOISE_B for ch in ARRIVAL]


def _runs(s):
    out, cur = [], 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            cur += 1
        else:
            out.append(cur)
            cur = 1
    return out + [cur]


# ── the live true positives: real bodies, POST-form lane, `BenchmarkTest*=bar` ────────
#: `sqli-00/BenchmarkTest00033`. TRUE returns the baseline row, FALSE returns the header alone.
TP33 = ("Your results are: \nfoo \n", "Your results are: \nfoo \n", "Your results are: \n")
#: `sqli-00/BenchmarkTest00433`. Same shape, HTML-escaped row.
TP433 = ("Your results are: <br>\n&#x7b;USERID&#x3d;3, USERNAME&#x3d;foo, PASSWORD&#x3d;bar&#x7d;<br>\n",
         "Your results are: <br>\n&#x7b;USERID&#x3d;3, USERNAME&#x3d;foo, PASSWORD&#x3d;bar&#x7d;<br>\n",
         "Your results are: <br>\n")
#: `sqli-00/BenchmarkTest00428`. The 264-byte full-page shape shared with 00429/00438.
_P428 = ('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" '
         '"http://www.w3.org/TR/html4/loose.dtd">\n<html>\n<head>\n'
         '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">\n</head>\n'
         '<body>\n<p>\nYour results are:<br>\n%s</p>\n</body>\n</html>')
TP428 = (_P428 % "3,  foo,  bar<br>\n", _P428 % "3,  foo,  bar<br>\n", _P428 % "")

TRUE_POSITIVES = {"00033": TP33, "00433": TP433, "00428": TP428}


# ── the fixture is REALITY, and this pins the property that decides N ─────────────────
def test_the_live_bimodal_page_arrives_in_runs_and_the_longest_one_is_three():
    """The measured structure, pinned. A fix chosen against alternation is chosen against the
    one arrival order in which a two-sample gate is guaranteed to fire; this page does not
    alternate, and that is why the shipped gate only halved the rate instead of closing it."""
    assert len(ARRIVAL) == 40
    assert set(ARRIVAL) == {"A", "B"}
    assert _runs(ARRIVAL) == [2, 3] * 8, "a period-5 cycle, not a coin and not alternation"
    assert max(_runs(ARRIVAL)) == 3
    assert sqli.similar(NOISE_A, NOISE_B) == pytest.approx(0.9091, abs=1e-3)


def _fp_rate(oracle, n_refs):
    """Slide the transport's REAL request order over the real arrival sequence: baseline,
    n_refs-1 repeats, then TRUE, then FALSE. Every confirmation is a false positive."""
    seq = _sequence()
    fires = attempts = 0
    for i in range(len(seq) - (n_refs + 1)):
        w = seq[i:i + n_refs + 2]
        refs, t, f = w[:n_refs], w[n_refs], w[n_refs + 1]
        attempts += 1
        v = (oracle(refs[0], t, f) if n_refs == 1
             else oracle(refs[0], t, f, baseline_samples=refs[1:]))
        fires += bool(v)
    return fires, attempts


def test_the_false_positive_rate_falls_with_the_reference_sample_count():
    """HALF ONE OF THE DoD. The numbers, not an inequality -- a curve that merely trends the
    right way would let a future regression sit inside it unnoticed."""
    assert _fp_rate(sqli.analyze_boolean, 1) == (15, 38), "ungated: the positive control"
    assert _fp_rate(sqli.analyze_boolean, 2) == (7, 37), "one repeat: what production supplies"
    assert _fp_rate(sqli.analyze_boolean, 3) == (0, 36)
    assert _fp_rate(sqli.analyze_boolean, 4) == (0, 35)


def test_two_reference_samples_are_not_enough_because_the_runs_are_longer_than_two():
    """WHY, so the number above is a mechanism rather than a coincidence.

    A confirmation needs the references to agree AND the TRUE/FALSE pair to differ. With N=2 the
    window is 4 responses; inside a run of 3 the first two agree while the pair straddles the
    boundary. With N=3 the references only agree inside a run of at least 3, and this page's runs
    are at most 3, so TRUE and FALSE are then forced into the NEXT run together -- equal to each
    other, and there is no divergence left to misread.

    The two windows below are taken from the real sequence at the same offset, not built by hand,
    because a hand-built one is how a "why" test ends up explaining something the data never did.
    """
    assert max(_runs(ARRIVAL)) == 3
    seq = _sequence()
    assert ARRIVAL[2:7] == "BBBAA", "the window this argument is about"

    w = seq[2:2 + 2 + 2]          # N=2: refs BB agree, then TRUE=B, FALSE=A -> a false positive
    assert sqli.analyze_boolean(w[0], w[2], w[3], baseline_samples=w[1:2]) is True

    w = seq[2:2 + 3 + 2]          # N=3: refs BBB agree, but now TRUE=A and FALSE=A
    assert w[3] == w[4], "the pair is pushed into the next run TOGETHER"
    assert sqli.analyze_boolean(w[0], w[3], w[4], baseline_samples=w[1:3]) is False


def test_more_reference_samples_cost_the_live_true_positives_nothing():
    """HALF TWO OF THE DoD, and it is the half a false-positive fix usually pays with.

    MEASURED, not asserted: each of these endpoints returned ONE distinct body in six identical
    requests on 2026-08-18, so N extra references are N extra copies of the same bytes. The
    oracle confirms at every N tried. If this ever goes red, the precision fix has become
    silence.
    """
    for case, (base, true_, false_) in sorted(TRUE_POSITIVES.items()):
        assert sqli.analyze_boolean(base, true_, false_) is True, case
        for n in (2, 3, 4, 5, 6):
            v = sqli.analyze_boolean(base, true_, false_, baseline_samples=[base] * (n - 1))
            assert v is True, "%s lost its confirmation at N=%d" % (case, n)


def test_the_nosqli_oracle_is_flat_at_zero_across_the_whole_curve():
    """The Q-070 fix removed the shape rather than out-sampling it, so the nosqli oracle does not
    need the reference count to reach zero on this page -- it is already there ungated.

    Pinned next to the sqli curve on purpose: these two oracles sat at the SAME rate before
    (0.229 each, measured 2026-08-17), and a future change that reintroduces the whole-body
    fingerprint would show up here as the sqli numbers reappearing under the nosqli name.
    """
    for n in (1, 2, 3, 4):
        assert _fp_rate(nosqli.analyze_boolean, n)[0] == 0, "N=%d" % n
    # positive control: the same sweep, over a real broadening, does fire
    langs_one = ('[{"key":"az_AZ","lang":"Az\\u0259rbaycanca","icons":["az"],"shortKey":"AZ",'
                 '"percentage":38,"gauge":"quarter"}]')
    langs_three = (langs_one[:-1] + ',{"key":"id_ID","lang":"Bahasa Indonesia","icons":["id"],'
                   '"shortKey":"ID","percentage":14,"gauge":"empty"}]')
    assert nosqli.analyze_boolean(langs_one, langs_three, "[]",
                                  baseline_samples=[langs_one] * 3) is True


# ── the call site: N is INERT until tools.py forwards more than one sample ────────────
def _boolean_calls(func, module_name):
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == module_name
            and n.func.attr == "analyze_boolean"]


@pytest.mark.xfail(strict=True, reason=(
    "N IS INERT IN PRODUCTION. analyze_boolean has accepted baseline_samples since Q-040 and the "
    "curve above shows N=3 takes the live bimodal page from 0.189 to 0.000 at no cost in recall, "
    "but tools._run_sqli forwards only base_samples[1] (tools.py:7463 -> :7513, and :7566 -> "
    ":7586), so the shipped oracle runs at N=2 and the 0.189 stands. BOOLEAN_BASELINE_SAMPLE_COUNT "
    "lives in this lane's file, yet raising it ALONE buys extra requests and no extra evidence "
    "because the extras are dropped on the floor -- so it is deliberately left at 2 until the "
    "call site changes, and the two changes must land together. agent/tools.py is not this lane's "
    "file; the one-line patch is in docs/handoff/bimodal.md section 5. STRICT: applying it turns "
    "this XPASS and the marker must then be removed."))
def test_the_sqli_carriers_supply_enough_samples_to_survive_a_bimodal_page():
    assert sqli.BOOLEAN_BASELINE_SAMPLE_COUNT >= 3, (
        "N=2 leaves a measured 0.189 FP/attempt on a live bimodal page")
    calls = _boolean_calls(tools.ToolRegistry._run_sqli, "sqli")
    assert len(calls) == 2, "call-site baseline changed; re-derive before trusting this pin"
    for c in calls:
        assert "baseline_samples" in {k.arg for k in c.keywords}, (
            "a single baseline_repeat cannot establish stability on a bimodal page")
