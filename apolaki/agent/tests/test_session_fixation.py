"""Session-fixation analyzer (WAHH ch7/ch8, CWE-384 / WSTG-SESS-03). Confirms only when a pre-auth session
cookie survives a SUCCESSFUL login unchanged; token rotation, a failed login, or no pre-auth token all yield
nothing (no FP)."""
import blind_benchmark as bb
import session_fixation_tool as sf


def test_unrotated_token_after_success_confirmed():
    pre = {"SESSIONID": "abc123def456", "theme": "dark"}
    post = {"SESSIONID": "abc123def456", "theme": "dark"}     # session cookie unchanged after login
    out = sf.analyze(pre, post, login_succeeded=True)
    assert out and out[0] == "SESSIONID"


def test_rotated_token_not_flagged():
    pre = {"JSESSIONID": "old0000token"}
    post = {"JSESSIONID": "new1111token"}                    # regenerated on login -> safe
    assert sf.analyze(pre, post, login_succeeded=True) is None


def test_failed_login_not_flagged():
    pre = {"SESSIONID": "abc123def456"}
    post = {"SESSIONID": "abc123def456"}
    assert sf.analyze(pre, post, login_succeeded=False) is None   # no auth happened -> proves nothing


def test_non_session_cookie_ignored():
    pre = {"csrf": "abc123def456"}                           # not session-ish
    post = {"csrf": "abc123def456"}
    assert sf.analyze(pre, post, login_succeeded=True) is None


def test_no_preauth_token_not_flagged():
    assert sf.analyze({}, {"SESSIONID": "issued0000after"}, login_succeeded=True) is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    f = sf.finding("https://x/login", "SESSIONID", "token unchanged after login")
    assert f["family"] == "session_fixation" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
