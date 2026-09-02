"""Q-146 -- language-specific server-side code injection. Seven Burp checks; Apolaki had zero.

Mined from Burp's published scanner catalog, which lists these as distinct issues: PHP / Server-side
JavaScript / Perl / Ruby / Python / Expression Language / Unidentified code injection.

`cmdi_tool` does OS command injection (ping/host/exec). Evaluating `phpinfo()` or `${7*7}` in an
eval or template context is a different vulnerability with a different oracle, and nothing in the
tree detected any of it.

THE ORACLE IS BUILT FROM THE Q-126 LESSON, and this file exists to keep it that way. The SSTI oracle
used `_SSTI_MARKER = "49"` from `{{7*7}}` and raised **CVSS 9.8 against admin.shopify.com** because
a page contained the digits `49`. Two characters is a coincidence detector, not evidence.

So every probe here carries TWO independently-derived tokens:

    eval_token   a random-operand product, e.g. 9001*7287 -> a prefixed 8-digit value
    attr_token   a LANGUAGE-EXCLUSIVE construct in the same payload (PHP `strrev`, Python `[::-1]`,
                 Perl `scalar reverse`, JS `String.fromCharCode`, EL `hashCode()`)

Neither is a substring of the payload, so an ECHO cannot produce either one.

AND THE ATTRIBUTION IS HONEST, which is the part worth protecting. Arithmetic alone proves EVALUATION
but not WHICH interpreter -- `print("x".(A*B))` matches PHP and Python both. In that case the engine
reports `unidentified_code_injection` and explicitly declines to name a language. That is Burp's
seventh bucket and it is the difference between a finding and a guess.
"""
from __future__ import annotations

import code_injection as ci


LANGS = ("php", "python", "ruby", "perl", "javascript", "el")


def _probe(lang):
    return ci.build_probes("1", languages=[lang])[0]


def _resp(*tokens):
    return "<html><body>result: %s</body></html>" % " ".join(tokens)


# ── the property the whole oracle rests on ───────────────────────────────────

def test_no_token_is_ever_a_substring_of_its_own_payload():
    """THE LOAD-BEARING PROPERTY. If a token appeared in the payload, an application that merely
    ECHOES the payload would satisfy the oracle -- which is exactly how the SSTI check produced a
    CVSS 9.8 on a page that had simply reflected the input."""
    for _ in range(40):
        for pr in ci.build_probes("1"):
            assert pr.eval_token not in pr.payload, (pr.language, pr.payload, pr.eval_token)
            if pr.attr_token:
                assert pr.attr_token not in pr.payload, (pr.language, pr.payload, pr.attr_token)


def test_tokens_are_random_per_probe():
    """Two probes on one page must not share a token, or one stray value convicts both."""
    seen = {ci.build_probes("1", languages=["php"])[0].eval_token for _ in range(25)}
    assert len(seen) >= 20, seen


def test_every_language_produces_a_probe():
    got = {p.language for p in ci.build_probes("1")}
    assert set(LANGS) <= got, got


# ── positives: evaluation, attributed ────────────────────────────────────────

def test_each_language_is_attributed_when_its_exclusive_construct_evaluates():
    """Arithmetic AND the language-exclusive construct both evaluated -- the language is named."""
    for lang in LANGS:
        pr = _probe(lang)
        got = ci.analyze_code_injection("nothing here", _resp(pr.eval_token, pr.attr_token), pr)
        assert got, lang
        assert got["attributed"] is True, (lang, got)
        assert got["language"] == lang, (lang, got)
        assert got["severity"] == "HIGH", (lang, got)
        # EL is CWE-917 (Expression Language Injection), the rest CWE-94. Burp maps them the same
        # way; asserting one CWE for all six was MY error, not the module's.
        assert got["cwe"] == ("CWE-917" if lang == "el" else "CWE-94"), (lang, got)


def test_the_detail_names_both_tokens_so_a_reader_can_recheck_it():
    """A HIGH whose evidence cannot be re-derived by the person receiving it is not a report."""
    pr = _probe("php")
    got = ci.analyze_code_injection("x", _resp(pr.eval_token, pr.attr_token), pr)
    assert pr.eval_token in got["detail"] and pr.attr_token in got["detail"], got["detail"]


# ── the honest half: evaluation proven, language NOT claimed ─────────────────

def test_arithmetic_alone_is_unidentified_and_names_no_language():
    """`print("x".(A*B))` matches PHP and Python both. Naming one would be a guess dressed as a
    finding -- this is Burp's seventh bucket and the reason it exists."""
    pr = _probe("php")
    got = ci.analyze_code_injection("x", _resp(pr.eval_token), pr)
    assert got and got["check"] == "unidentified_code_injection", got
    assert got["attributed"] is False, got
    assert got["language"] == "", got
    assert got["severity"] == "HIGH", got          # evaluation IS proven; only attribution is not


def test_the_unidentified_detail_explains_why_it_declined_to_name_a_language():
    pr = _probe("php")
    got = ci.analyze_code_injection("x", _resp(pr.eval_token), pr)
    assert "NOT claimed" in got["detail"] or "ambiguous" in got["detail"], got["detail"]


# ── negative controls: the four ways this must stay silent ───────────────────

def test_an_echo_of_the_payload_is_never_a_finding():
    """THE Q-126 CASE. Reflection is not evaluation, and the token design makes this structurally
    impossible rather than merely unlikely."""
    for lang in LANGS:
        pr = _probe(lang)
        assert ci.analyze_code_injection("x", "you searched for " + pr.payload, pr) is None, lang


def test_a_token_already_in_the_baseline_is_not_ours():
    """If the value was there before we touched anything, we did not cause it."""
    for lang in LANGS:
        pr = _probe(lang)
        body = _resp(pr.eval_token, pr.attr_token)
        assert ci.analyze_code_injection(body, body, pr) is None, lang


def test_a_clean_response_is_silent():
    for lang in LANGS:
        pr = _probe(lang)
        assert ci.analyze_code_injection("<html>hello</html>", "<html>hello</html>", pr) is None, lang


def test_a_page_full_of_ordinary_numbers_is_silent():
    """The failure mode being prevented, stated directly: a real page carries nonces, ids, prices
    and timestamps. None of them can be a probe's own product."""
    noisy = ("<meta nonce='49'><span>2049</span><i>order 1749382</i>"
             "<b>total 34874989</b><script src='/x.js?v=99999999'></script>")
    for lang in LANGS:
        pr = _probe(lang)
        assert ci.analyze_code_injection("<html>base</html>", noisy, pr) is None, lang


def test_the_attribution_token_alone_does_not_confirm():
    """The arithmetic is the evaluation proof. A string-op result without it is not enough -- and
    without this, half the oracle could be dropped and everything else would still pass."""
    for lang in LANGS:
        pr = _probe(lang)
        # EL is excluded because its two tokens are THE SAME value by design: `hashCode()` is both
        # the evaluation proof and the attribution, so "attr without eval" is not a state that
        # exists for it. Skipping a case that cannot occur, not one that is inconvenient.
        if not pr.attr_token or pr.attr_token == pr.eval_token:
            continue
        assert ci.analyze_code_injection("x", _resp(pr.attr_token), pr) is None, lang


# ── EL is the one language with an unambiguous marker ────────────────────────

def test_expression_language_uses_a_java_exclusive_construct():
    """`hashCode()` is Java's h = 31h + c. No other language computes it, so EL is the one shape
    that needs no second construct to attribute -- and the module says so in its ambiguity note."""
    pr = _probe("el")
    assert "hashCode" in pr.payload, pr.payload
    got = ci.analyze_code_injection("x", _resp(pr.eval_token), pr)
    assert got and got["language"] == "el", got


# =================================================================================================
# BREAKER REGRESSION -- the self-check was one character too weak.
# =================================================================================================

def test_no_token_is_reachable_from_its_payload_by_DELETING_characters():
    """THE LOAD-BEARING PROPERTY, CORRECTED. The original asserted the token was not a SUBSTRING of
    the payload, and `el_replace` passed: payload `${"MARK-NONCE".replace("-","")}` against token
    `MARKNONCE`, differing by one deleted hyphen. Substring said safe. A sanitizer that strips
    punctuation from a reflected value says otherwise, and then an ECHO satisfies the oracle -- the
    precise failure the Q-126 rewrite existed to make impossible.

    Deletion is the right closure: it is what sanitizers, encoders and template filters do."""
    for _ in range(40):
        for pr in ci.build_probes("1", shapes_per_language=3):
            assert not ci._echo_satisfiable(pr.eval_token, pr.payload), (pr.shape, pr.payload,
                                                                        pr.eval_token)
            assert not ci._echo_satisfiable(pr.attr_token, pr.payload), (pr.shape, pr.payload,
                                                                        pr.attr_token)


def test_the_structurally_echo_satisfiable_shape_never_ships():
    """`el_replace` cannot be made safe by redrawing -- its token is its own payload minus a
    hyphen at every draw. It must be absent at EVERY shape count, not merely absent at the default
    of 1, which is the only reason it was not already live."""
    for per in (1, 2, 3, 9):
        shapes = {p.shape for p in ci.build_probes("1", shapes_per_language=per)}
        assert "el_replace" not in shapes, (per, shapes)


def test_dropping_the_broken_shape_did_not_drop_a_language():
    """A guard that achieves silence by emitting nothing is not a guard."""
    assert {p.language for p in ci.build_probes("1", shapes_per_language=3)} == set(LANGS)


def test_the_subsequence_check_is_not_vacuously_true():
    """NEGATIVE CONTROL. If `_echo_satisfiable` returned False unconditionally the two tests above
    would pass forever. Pin it to a case it must call True and one it must call False."""
    assert ci._echo_satisfiable("MARKNONCE", '${"MARK-NONCE".replace("-","")}') is True
    assert ci._echo_satisfiable("65551617", '${"MARK".hashCode()}') is False
