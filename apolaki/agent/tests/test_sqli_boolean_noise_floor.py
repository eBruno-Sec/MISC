"""The blind-SQLi baseline-stability gate, attacked with the ordering the target actually produces.

MEASURED 2026-08-14 (docs/handoff/breaker.md, SESSION 4, TARGET 2) against the live OWASP Benchmark
lab. Two live sqli false positives, `BenchmarkTest00494` (key: cmdi, CLEAN) and
`BenchmarkTest00023` (key: weakrand), have ONE shared cause: a response body that changes between
byte-identical requests by about as much as an injected payload would change it.

The negative control that settles it is to hand the oracle four responses to the SAME request with
the SAME value and no payload at all -- every ``True`` is then a false positive by construction.
12 identical POSTs per field, all 400 ordered 4-tuples:

    case                field        distinct bodies  pairwise sim      FP/attempt ungated -> GATED
    BenchmarkTest00494  productID          2 of 12   0.9091..1.0000        0.225  ->  0.150
    BenchmarkTest00494  foo                2 of 12   0.9091..1.0000        0.280  ->  0.155
    BenchmarkTest00023  productID         12 of 12   0.9495..0.9764        0.045  ->  0.045
    BenchmarkTest00428  (true positive)    1 of 12   1.0000..1.0000        0.000  ->  0.000
    BenchmarkTest00033  (true positive)    1 of 12   1.0000..1.0000        0.000  ->  0.000

Two things that matters for:

1. The gate helps and does not fix. It halves 00494's rate and does NOTHING for 00023's.
2. **Every existing negative control models instability as strict alternation** -- ``NOISE_A`` then
   ``NOISE_B`` as the two reference samples (``test_sqli_oracle_negative_controls`` passes
   ``baseline_repeat=NOISE_B``; ``test_sqli_stability`` uses the sequence
   ``[NOISE_A, NOISE_B, ...]``). That is the one ordering in which a two-sample gate is guaranteed
   to fire. Measured, 00494's two states arrive in RUNS, so two consecutive reference samples
   usually land in the SAME state, the gate passes, and the oracle confirms. The tests pin the
   fix's best case; the target supplies its worst.

The xfails below are the worst case. They are STRICT: when the oracle is fixed they XPASS, the
suite goes red, and the marker has to be removed deliberately.
"""
import itertools

import pytest

import sqli_tool as sqli

# ── the two REAL bodies BenchmarkTest00494 returns for byte-identical requests ──
_CMDI_PAGE = ('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" '
              '"http://www.w3.org/TR/html4/loose.dtd">\n<html>\n<head>\n'
              '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">\n</head>\n'
              '<body>\n<p>\nHere is the standard output of the command:<br><br>'
              'Here is the std err of the command (if any):<br>ping&#x3a; moresafe&#x3a; %s<br>')
NOISE_A = _CMDI_PAGE % "No address associated with hostname"
NOISE_B = _CMDI_PAGE % "Name or service not known"

# ── BenchmarkTest00023: a weak-randomness case. The body carries a fresh java.util.Random value on
#    every response, so no two responses to identical requests are ever equal. Template and the
#    first three values are transcribed from live responses; the rest of the band was measured over
#    12 samples (0.9495..0.9766, 12 distinct bodies).
_WEAKRAND_PAGE = ('Floyd00023 has been remembered with cookie: rememberMe00023 whose value is: '
                  '%s<br/>\nWeak Randomness Test java.util.Random.nextFloat() executed\n')
OBSERVED_VALUES = ("99437195", "7079971", "4957906")


def _wr(value):
    return _WEAKRAND_PAGE % value


# ── facts the rest of the file rests on ───────────────────────────────────────
def test_the_two_cmdi_bodies_straddle_the_threshold_and_the_weakrand_bodies_sit_on_it():
    assert sqli.similar(NOISE_A, NOISE_B) == pytest.approx(0.9091, abs=1e-3)
    sims = [sqli.similar(_wr(a), _wr(b))
            for a, b in itertools.combinations(OBSERVED_VALUES, 2)]
    assert all(0.94 < s < 0.98 for s in sims), sims
    assert len({_wr(v) for v in OBSERVED_VALUES}) == len(OBSERVED_VALUES), (
        "a weakrand page returns a different body for every identical request, by design")


def test_the_noise_floor_is_the_discriminator_and_it_is_in_the_data():
    """A confirmation is only worth something when the payload moved the page by MORE than the page
    moves on its own. That comparison needs no new threshold -- both quantities are already
    measured by the oracle's own ``similar``.

    On the two false positives the claimed divergence is INSIDE the page's own noise band; on the
    true positive it is outside it. This is the property a fix has to implement, asserted here on
    the data so it cannot be argued about.
    """
    # BenchmarkTest00494. The oracle's evidence for "FALSE returned a different page" is
    # similar(TRUE, FALSE) = 0.9091 -- and 0.9091 is ALSO the similarity between two responses to
    # the same request with no payload. The claimed signal IS the noise, to four decimal places.
    claimed_divergence = sqli.similar(NOISE_A, NOISE_B)
    noise_floor = sqli.similar(NOISE_A, NOISE_B)
    assert claimed_divergence == noise_floor == pytest.approx(0.9091, abs=1e-3)

    # BenchmarkTest00023. MEASURED over 12 responses to identical requests: every pairwise
    # similarity fell in [0.9495, 0.9766]. The live confirmations sat at stf = 0.9495 and 0.9498 --
    # at the very bottom of that band, i.e. indistinguishable from another sample of the same page.
    WR_NOISE_BAND = (0.9495, 0.9766)
    for stf_of_a_live_fire in (0.9495, 0.9498):
        assert WR_NOISE_BAND[0] <= stf_of_a_live_fire <= WR_NOISE_BAND[1]
    observed = [sqli.similar(_wr(a), _wr(b))
                for a, b in itertools.combinations(OBSERVED_VALUES, 2)]
    assert all(WR_NOISE_BAND[0] <= s <= WR_NOISE_BAND[1] for s in observed), observed

    # A genuine boolean differential (BenchmarkTest00428-shaped: 264-byte baseline, 246-byte FALSE
    # row-count page) sits well OUTSIDE a noise floor of 1.0000.
    base = "<html><body>" + ", ".join("row-%02d" % i for i in range(24)) + "</body></html>"
    false_ = "<html><body>" + ", ".join("row-%02d" % i for i in range(20)) + "</body></html>"
    assert sqli.similar(base, base) == 1.0, "the true-positive page is byte-stable"
    assert sqli.similar(base, false_) < 1.0


# ── the oracle must keep working on the shapes that are genuinely injectable ───
def test_a_byte_stable_page_with_a_real_differential_still_confirms():
    """The four cases the 2026-08-13 rerun lost (00428/00429/00433/00438) and the one it kept
    (00033) all have a byte-identical baseline on repeat and a FALSE page that really is shorter.
    Any fix for the two false positives must leave this confirming, or it is not a fix, it is
    silence.
    """
    base = "<html><body>" + ", ".join("row-%02d" % i for i in range(24)) + "</body></html>"
    false_ = "<html><body>" + ", ".join("row-%02d" % i for i in range(20)) + "</body></html>"
    assert sqli.analyze_boolean(base, base, false_, baseline_repeat=base)


def test_the_gate_still_rejects_when_the_two_reference_samples_disagree():
    """The half of the gate that works, kept pinned so a rewrite cannot drop it."""
    assert not sqli.analyze_boolean(NOISE_A, NOISE_A, NOISE_B, baseline_repeat=NOISE_B)


# ── the defects, pinned ───────────────────────────────────────────────────────
@pytest.mark.xfail(strict=True, reason="LIVE DEFECT: BenchmarkTest00494 still confirms whenever "
                                       "both reference samples land in the same run of the "
                                       "alternation. MEASURED 2026-08-14: fires on 3 of 4 form "
                                       "fields with the gate on.")
def test_an_unstable_page_must_not_confirm_when_both_reference_samples_agree():
    assert not sqli.analyze_boolean(NOISE_A, NOISE_A, NOISE_B, baseline_repeat=NOISE_A)


@pytest.mark.xfail(strict=True, reason="LIVE DEFECT: BenchmarkTest00023, a weakrand case, is "
                                       "claimed as CWE-89 boolean-blind. The body carries a fresh "
                                       "PRNG value per response; the gate contributes nothing "
                                       "(FP/attempt 0.045 -> 0.045).")
def test_a_weak_random_page_must_not_confirm_blind_sqli():
    # base/true/false are three responses to the SAME endpoint; the value the page prints is the
    # only thing that differs, and the payload is never echoed. st=0.9697, stf=0.9495.
    base, true_, false_ = _wr("99437195"), _wr("4957906"), _wr("38381881")
    assert sqli.similar(base, true_) >= 0.95, "fixture: TRUE tracks the baseline"
    assert sqli.similar(true_, false_) < 0.95, "fixture: FALSE 'diverges' -- on noise alone"
    assert not sqli.analyze_boolean(base, true_, false_, baseline_repeat=_wr("7079971"))


@pytest.mark.xfail(strict=True, reason="LIVE DEFECT: the same weakrand noise confirms on a large "
                                       "fraction of sample triples, not as a rare coincidence. "
                                       "MEASURED: 9.4% of ordered triples over 123 observed-shape "
                                       "bodies satisfy the oracle.")
def test_weak_random_noise_must_not_confirm_at_scale():
    vals = ["%d" % v for v in (99437195, 7079971, 4957906, 38381881, 485838843, 601151017,
                               630799660, 101164292, 12345678, 3141592, 80661234, 55512340)]
    fires = sum(1 for a, b, c in itertools.permutations(vals, 3)
                if sqli.analyze_boolean(_wr(a), _wr(b), _wr(c), baseline_repeat=_wr(a)))
    assert fires == 0, "%d confirmations on responses that contain no injection at all" % fires
