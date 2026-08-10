"""Session-token predictability analyzer (WAHH ch7, CWE-330/384). Confirms sequential or meaningful tokens;
a CSPRNG token yields nothing (no FP)."""
import base64

import blind_benchmark as bb
import session_token_tool as stt


def test_sequential_tokens_confirmed():
    toks = [str(1000 + i) for i in range(8)]                     # perfect arithmetic sequence
    res = stt.analyze(toks)
    assert res and res[0] == "sequential/predictable" and res[2] == "CWE-330"


def test_time_incrementing_component_confirmed():
    toks = ["31245%d-11727642587%02d" % (38 + i, 18 + i * 3) for i in range(6)]  # incrementing numeric part
    assert stt.analyze(toks) is not None


def test_meaningful_decoded_token_confirmed():
    toks = [base64.urlsafe_b64encode(("user=u%d;role=user;app=x" % i).encode()).decode() for i in range(5)]
    res = stt.analyze(toks)
    assert res and res[0] == "meaningful" and res[2] == "CWE-384"


def test_random_tokens_not_flagged():
    import os
    toks = [os.urandom(16).hex() for _ in range(12)]             # CSPRNG -> no sequence, no meaning
    assert stt.analyze(toks) is None
    assert stt.analyze(["abc", "def"]) is None                  # too few samples


def test_sessionish_name_detection():
    assert stt.is_sessionish("JSESSIONID") and stt.is_sessionish("connect.sid")
    assert not stt.is_sessionish("theme_pref")


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    f = stt.finding("https://x/", "sequential/predictable", "increments by 1", "CWE-330", "SESSIONID")
    assert f["family"] == "weak_session_token" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05


# ── tokens carried in the response BODY ───────────────────────────────────────────────────────────────
# The sampler read Set-Cookie only, so an API issuing {"access_token":"…"} was invisible and a sequential
# token there produced no finding at all — a false negative shaped like a CSPRNG.

def test_tokens_are_harvested_from_json_bodies_including_nested():
    got = stt.tokens_from_body('{"access_token":"abcdef123456","data":{"sessionId":"QUJDREVGMTIz"},'
                               '"user":{"name":"bob"},"ok":true,"count":7}')
    assert got == {"access_token": "abcdef123456", "data.sessionId": "QUJDREVGMTIz"}


def test_body_harvest_declines_what_would_manufacture_findings():
    # Non-JSON yields nothing: a regex over HTML would collect CSRF nonces and asset hashes.
    assert stt.tokens_from_body("<html><input name=csrf value=9f8e7d6c5b4a3210></html>") == {}
    assert stt.tokens_from_body("") == {} and stt.tokens_from_body(None) == {}
    # Right key, useless value: too short to be a session token.
    assert stt.tokens_from_body('{"token":"1"}') == {}
    # Right shape, wrong key: not every long string is a session token.
    assert stt.tokens_from_body('{"description":"a fairly long ordinary sentence value"}') == {}
    # A body too large to be a login response is not parsed at all.
    assert stt.tokens_from_body('{"token":"%s"}' % ("a" * 500_000)) == {}


def test_harvested_names_survive_the_sessionish_gate():
    """Both halves: harvesting is useless if the pipeline then discards the name it produced."""
    for key in stt.tokens_from_body('{"access_token":"abcdef123456","data":{"sessionId":"QUJDREVG"}}'):
        assert stt.is_sessionish(key), key


def test_sequential_body_token_is_confirmed_through_the_unchanged_analyzer():
    """End of the pipeline: body-carried samples must reach the same oracle a cookie would."""
    vals = [stt.tokens_from_body('{"access_token":"sess-%08d"}' % n)["access_token"] for n in range(1, 9)]
    assert len(set(vals)) == 8
    res = stt.analyze(vals)
    assert res and res[0] == "sequential/predictable", res
