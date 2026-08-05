"""Username-enumeration analyzer (WAHH ch6, CWE-204 / WSTG-IDNT-04). Confirms a login that leaks account
existence via a status or message discrepancy; a generic-failure login that treats existing and non-existent
accounts identically yields nothing (no FP), even with per-request nonce noise + a reflected username echo."""
import blind_benchmark as bb
import username_enum_tool as ue

_USERS = ["zqx7nonexistent9", "wvk3nobody2", "real.user@site.test"]


def _resp(status, body, headers=None):
    return {"status": status, "body": body, "headers": headers or {}}


def test_message_discrepancy_confirmed():
    # existing account -> "invalid password"; non-existent -> "no such user"; usernames reflected + nonce noise
    absent1 = _resp(200, "<p>No account 'zqx7nonexistent9' found</p><input name=csrf value=a1b2c3d4e5f6a7b8c9d0e1f2>")
    absent2 = _resp(200, "<p>No account 'wvk3nobody2' found</p><input name=csrf value=ffee00112233445566778899aabb>")
    present = _resp(200, "<p>Invalid password for 'real.user@site.test'</p><input name=csrf value=0f0e0d0c0b0a09080706>")
    out = ue.enumerable(absent1, absent2, present, _USERS)
    assert out and out[1] == "CWE-204"


def test_status_oracle_confirmed():
    absent = _resp(200, "login failed")
    present = _resp(403, "account locked")               # existing account returns a distinct status (not a redirect)
    out = ue.enumerable(absent, absent, present, _USERS)
    assert out and "status oracle" in out[0]


def test_generic_failure_not_flagged():
    # a well-built login: identical generic message for both, only nonce + reflected username differ
    absent1 = _resp(200, "<p>Invalid username or password.</p><input name=csrf value=a1b2c3d4e5f6a7b8c9d0e1f2>")
    absent2 = _resp(200, "<p>Invalid username or password.</p><input name=csrf value=ffee00112233445566778899aabb>")
    present = _resp(200, "<p>Invalid username or password.</p><input name=csrf value=0f0e0d0c0b0a09080706deadbeef>")
    assert ue.enumerable(absent1, absent2, present, _USERS) is None


def test_authenticated_present_not_flagged():
    # if the 'present' probe actually logged in (session set), it is NOT a clean membership oracle
    absent1 = _resp(200, "no such user")
    absent2 = _resp(200, "no such user")
    present = _resp(200, "welcome", {"Set-Cookie": "session=abc; Path=/"})
    assert ue.enumerable(absent1, absent2, present, _USERS) is None


def test_mask_removes_reflected_username():
    m = ue.mask("Error for BobTheUser here", ["bobtheuser"])
    assert "bobtheuser" not in m and "@u@" in m


def test_parse_login_form_quoted_and_unquoted():
    quoted = '<form action="/do-login" method="post"><input name="email" type="text"><input name="pw" type="password"></form>'
    f = ue.parse_login_form(quoted, "http://h/login")
    assert f and f["action"] == "http://h/do-login" and f["user_field"] == "email" and f["pass_field"] == "pw"
    unq = "<form action=/auth method=post><input name=user type=text><input name=pass type=password></form>"
    g = ue.parse_login_form(unq, "http://h/login")
    assert g and g["action"] == "http://h/auth" and g["user_field"] == "user" and g["pass_field"] == "pass"


def test_parse_no_password_form_returns_none():
    assert ue.parse_login_form("<form><input name=q type=text></form>", "http://h/") is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    f = ue.finding("https://x/login", "status oracle", "CWE-204", "real.user@site.test", "login")
    assert f["family"] == "username_enumeration" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05


def test_timing_enum_confirms_decisive_gap():
    absent1 = [0.020, 0.022, 0.019, 0.021, 0.020, 0.023, 0.018, 0.021, 0.020, 0.022]
    absent2 = [0.021, 0.020, 0.022, 0.019, 0.021, 0.020, 0.022, 0.019, 0.021, 0.020]
    present = [0.210, 0.205, 0.215, 0.208, 0.212, 0.207, 0.211, 0.209, 0.213, 0.206]  # ~190ms slower, tight
    assert ue.timing_enumerable(absent1, absent2, present) is not None


def test_timing_enum_ignores_jitter_without_signal():
    import random
    random.seed(7)
    jit = lambda: [0.02 + random.uniform(-0.008, 0.008) for _ in range(12)]   # same distribution, only jitter
    assert ue.timing_enumerable(jit(), jit(), jit()) is None


def test_timing_enum_ignores_small_gap_within_noise():
    # present only ~10ms slower but the endpoint's own noise floor is ~8ms -> not decisive -> no FP
    absent1 = [0.020, 0.028, 0.019, 0.027, 0.021, 0.029, 0.020, 0.026]
    absent2 = [0.021, 0.020, 0.029, 0.019, 0.028, 0.020, 0.027, 0.019]
    present = [0.030, 0.031, 0.029, 0.032, 0.030, 0.031, 0.029, 0.030]
    assert ue.timing_enumerable(absent1, absent2, present) is None


def test_timing_enum_needs_enough_samples():
    assert ue.timing_enumerable([0.02, 0.02], [0.02, 0.02], [0.5, 0.5]) is None    # too few samples


def test_timing_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    f = ue.timing_finding("https://x/login", "median 210ms vs 20ms", "real.user@site.test", "email")
    assert f["family"] == "username_enumeration" and f["cwe"] == "CWE-208" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
