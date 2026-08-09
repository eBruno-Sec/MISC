"""Username-enumeration analyzer (WAHH ch6, CWE-204 / WSTG-IDNT-04). Confirms a login that leaks account
existence via a status or message discrepancy; a generic-failure login that treats existing and non-existent
accounts identically yields nothing (no FP), even with per-request nonce noise + a reflected username echo."""
import asyncio
import json

import blind_benchmark as bb
import scope
import tools
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


# ── JSON login APIs (no server-rendered <form>) ───────────────────────────────────────────────────────
# The analyzer above was already correct; the engine still reported nothing against a single-page app,
# because parse_login_form found no <form> and _run_username_enum returned early. These cover the
# DELIVERY path — that the right requests go out and their responses reach the unchanged oracle.

def test_shape_rejection_separates_a_refused_body_from_refused_credentials():
    assert ue.shape_rejected(400, '{"error":"email is required"}')
    assert ue.shape_rejected(422, "{}") and ue.shape_rejected(404, "") and ue.shape_rejected(415, "")
    assert ue.shape_rejected(200, '{"error":"missing required field: username"}')   # 200 + complaint
    # 401/403 mean the endpoint READ our body and judged the credentials — the shape was fine.
    assert not ue.shape_rejected(401, '{"error":"invalid email or password"}')
    assert not ue.shape_rejected(403, "") and not ue.shape_rejected(200, "{}")
    # Unrecognised/garbage status is treated as ACCEPTED-unless-proven: abandoning a real login endpoint
    # would report a clean bill of health for a vulnerable app, which is the failure that matters here.
    assert ue.shape_rejected(None, "") and ue.shape_rejected("weird", "")


def test_json_bodies_are_flat_or_enveloped_and_always_carry_the_password():
    shapes = ue.json_login_shapes()
    assert shapes[0] == ("flat:username", "username", "flat")           # most common first
    labels = [s[0] for s in shapes]
    assert "flat:email" in labels and "nested_user:email" in labels
    assert ue.json_login_body(("flat:email", "email", "flat"), "a@b.c", "pw") == \
        {"email": "a@b.c", "password": "pw"}
    assert ue.json_login_body(("nested_user:email", "email", "user"), "a@b.c", "pw") == \
        {"user": {"email": "a@b.c", "password": "pw"}}
    for s in shapes:
        assert "pw" in json.dumps(ue.json_login_body(s, "u", "pw"))     # a shape that drops it proves nothing


def _json_login_registry(known: str, uniform: bool):
    """A single-page app: the login page has no <form>, and the API accepts ONLY {"email":…,"password":…}."""
    sc = scope.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    sent = []

    async def _http(url, method="GET", headers=None, body=None, capture=False, **kw):
        if str(method).upper() == "GET":
            return {"status": 200, "headers": {}, "body": "<html><h1>Sign in</h1><div id='app'></div></html>"}
        payload = json.loads(body or "{}")
        if "email" not in payload:                       # rejects every other candidate shape
            return {"status": 400, "headers": {}, "body": '{"error":"email is required"}'}
        sent.append(payload["email"])
        if uniform:
            return {"status": 401, "headers": {}, "body": '{"error":"invalid email or password"}'}
        if payload["email"] == known:
            return {"status": 401, "headers": {}, "body": '{"error":"password is incorrect"}'}
        return {"status": 401, "headers": {}, "body": '{"error":"no account with that email"}'}

    reg._http = _http
    # Isolate the CONTENT differential: the timing side channel has its own tests and would otherwise fire
    # 30 unmeasurable requests against this fake.
    reg._timing_enum_done = True
    return reg, sent


def test_json_login_api_is_enumerated_after_shape_discovery():
    known = "real.user@site.test"
    reg, sent = _json_login_registry(known, uniform=False)
    res = asyncio.run(reg._run_username_enum({"url": "https://target.tld/login", "known_username": known}))
    assert res.findings, res.output
    f = res.findings[0]
    assert f["family"] == "username_enumeration" and bb._has_proof(f)
    # The pinned shape must be the one the API accepts, not the first one tried.
    assert "email" in f["title"] or "email" in f.get("evidence", "")
    assert known in sent and len([u for u in sent if u != known]) >= 2   # 1 known + 2 non-existent


def test_json_login_api_with_uniform_failure_yields_nothing():
    """Negative control. Same delivery path, same discovery, generic failure -> no finding."""
    known = "real.user@site.test"
    reg, sent = _json_login_registry(known, uniform=True)
    res = asyncio.run(reg._run_username_enum({"url": "https://target.tld/login", "known_username": known}))
    assert res.findings == [], res.findings
    assert known in sent            # it really did run the differential, it just found no discrepancy


def test_endpoint_that_refuses_every_shape_reports_no_finding():
    """An endpoint that is not a login API at all must produce nothing, and must not crash."""
    sc = scope.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)

    async def _http(url, method="GET", headers=None, body=None, capture=False, **kw):
        if str(method).upper() == "GET":
            return {"status": 200, "headers": {}, "body": "<html>no form here</html>"}
        return {"status": 404, "headers": {}, "body": "not found"}

    reg._http = _http
    res = asyncio.run(reg._run_username_enum({"url": "https://target.tld/login", "known_username": "a@b.c"}))
    assert res.findings == [] and "no JSON login shape" in res.output
