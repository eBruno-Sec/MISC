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
