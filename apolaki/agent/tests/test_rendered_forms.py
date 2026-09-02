"""Q-158 -- rendered-form probing on a single-page app.

The pure half of `rendered_forms` is tested with NO browser: a DOM descriptor in, a probe plan
out; a captured request body in, a parameter path out; a response pair in, a verdict out.

Every fixture body in this file is a REAL response measured against juice-shop:3000, and the
mandatory negative control is a real field of the same real form -- juice-shop hashes the password
before it reaches the SQL statement, so the identical payload that breaks the `email` field is
inert in `password`. A synthetic "safe field" would only prove the oracle can be told to be quiet.
"""
import socket

import form_xss
import proof_schema
import pytest
import rendered_forms as rf
import sqli_tool
import xss_tool as xt

# ── real captured exchanges (juice-shop POST /rest/user/login, observed through the app's own XHR)
LOGIN_URL = "http://juice-shop:3000/rest/user/login"
BASELINE = {"observed": True, "status": 401, "url": LOGIN_URL, "method": "POST",
            "content_type": "application/json",
            "request_body": '{"email":"apolakirfq1f0@example.test","password":"Aa1!apolakirfq1f1"}',
            "response_content_type": "text/plain; charset=utf-8",
            "body": "Invalid email or password."}
PROBE_QUOTE = dict(BASELINE, status=500,
                   request_body='{"email":"apolakirfq1f0@example.test\'","password":"Aa1!apolakirfq1f1"}',
                   response_content_type="application/json; charset=utf-8",
                   body='{\n  "error": {\n    "message": "SQLITE_ERROR: unrecognized token: '
                        '\\"8cbf5f1b50b6b959250081a52429676b\\"",\n    "stack": "Error\\n    at '
                        'Database.<anonymous> (/juice-shop/node_modules/sequelize/lib/dialects/'
                        'sqlite/query.js:185:27)"\n  }\n}')
CONTROL_QUOTE = dict(BASELINE)                       # doubled quote -> statement repaired -> 401
SIBLING_PROBE = dict(BASELINE)                       # same payload in `password` -> hashed -> 401
BYPASS = dict(BASELINE, status=200,
              body='{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjp7'
                   'ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIn19.sig","bid":1,"umail":"a"}}')

# The rendered login form, exactly as FORM_SCAN_JS reads it off juice-shop `#/login`.
LOGIN_FORM = {
    "container": "form#login-form", "is_form": True, "action": None, "method": None,
    "fields": [
        {"tag": "input", "type": "text", "name": "email", "id": "email", "formcontrolname": "",
         "aria-label": "Text field for the login email", "aria_label": "Text field for the login email",
         "placeholder": "", "required": True, "selector": "#email"},
        {"tag": "input", "type": "password", "name": "password", "id": "password",
         "formcontrolname": "", "aria-label": "Text field for the login password",
         "aria_label": "Text field for the login password", "placeholder": "", "required": True,
         "selector": "#password"},
        {"tag": "input", "type": "checkbox", "name": "", "id": "rememberMe-input",
         "formcontrolname": "", "aria-label": "Checkbox to stay logged in", "placeholder": "",
         "required": False, "selector": "#rememberMe-input"},
    ],
    "submits": [{"text": "exit_to_app\nLog in", "id": "loginButton", "type": "submit",
                 "disabled": True, "rank": 0, "selector": "#loginButton"}],
}

# The rendered feedback form (`#/contact`): NO `name=` on any control at all.
FEEDBACK_FORM = {
    "container": "form#feedback-form", "is_form": True, "action": None, "method": None,
    "fields": [
        {"tag": "input", "type": "text", "name": "", "id": "mat-input-3", "formcontrolname": "",
         "aria-label": "Field with the name of the author", "placeholder": "", "required": False,
         "selector": "#mat-input-3"},
        {"tag": "textarea", "type": "textarea", "name": "", "id": "comment", "formcontrolname": "",
         "aria-label": "Field for entering the comment", "placeholder": "What did you like?",
         "required": True, "selector": "#comment"},
        {"tag": "input", "type": "range", "name": "", "id": "", "formcontrolname": "",
         "aria-label": "", "placeholder": "", "required": False, "selector": ""},
        {"tag": "input", "type": "text", "name": "", "id": "captchaControl", "formcontrolname": "",
         "aria-label": "Field for the result of the CAPTCHA", "placeholder": "", "required": True,
         "selector": "#captchaControl"},
    ],
    "submits": [{"text": "send\nSubmit", "id": "submitButton", "type": "submit", "disabled": True,
                 "rank": 0, "selector": "#submitButton"}],
}


# ══════════════════════════════════════════ 1. the defect this module exists for, asserted directly
def test_the_existing_parser_is_blind_to_both_lab_forms():
    """The premise of Q-158, pinned. `parse_forms` needs method="post", an action and name=; the
    SERVED SPA document has no <form> at all, and the RENDERED one has none of the three. This is
    also the guard against 'fixing' the gap by feeding rendered HTML to the old parser."""
    served = ('<!doctype html><html><body><app-root></app-root>'
              '<script src="/main.js"></script></body></html>')
    assert form_xss.parse_forms(served, "http://juice-shop:3000/") == []

    rendered = ('<form id="login-form" novalidate>'
                '<input id="email" type="text" aria-label="Text field for the login email">'
                '<input id="password" type="password" aria-label="Text field for the login password">'
                '<button id="loginButton" type="submit">Log in</button></form>')
    assert form_xss.parse_forms(rendered, "http://juice-shop:3000/") == [], (
        "rendering alone must NOT be mistaken for a fix -- the parser still drops this form")

    # rendered_forms reads the SAME form and finds two payload-carrying controls.
    assert [f["selector"] for f in rf.fillable_fields(LOGIN_FORM)] == ["#email", "#password"]


# ══════════════════════════════════════════════════════════ 2. descriptor -> plan (pure)
def test_field_identity_prefers_the_strongest_attribute_and_reports_which():
    assert rf.field_identity(LOGIN_FORM["fields"][0]) == ("email", "name")
    assert rf.identity_quality("name") == "strong"
    # the feedback form has no name= anywhere: identity falls to id, and says so
    label, src = rf.field_identity(FEEDBACK_FORM["fields"][1])
    assert (label, src) == ("comment", "id") and rf.identity_quality(src) == "medium"
    # a wholly anonymous control still parses (identity is not the wire name)
    assert rf.field_identity({"tag": "input"}) == ("", "")
    assert rf.identity_quality("") == "none"


def test_non_text_controls_are_never_fuzz_targets():
    assert rf.is_fillable(LOGIN_FORM["fields"][0])
    assert not rf.is_fillable(LOGIN_FORM["fields"][2])            # checkbox
    assert not rf.is_fillable(FEEDBACK_FORM["fields"][2])         # range slider, no selector
    assert [f["selector"] for f in rf.fillable_fields(FEEDBACK_FORM)] == [
        "#mat-input-3", "#comment", "#captchaControl"]
    assert rf.fillable_fields({}) == []


def test_values_are_shaped_so_the_client_side_validator_lets_the_request_leave():
    """MEASURED: juice-shop's submit button stays disabled until every required control validates,
    so a form filled with 'x' is a form that never submits. The shape is chosen from the control's
    IDENTITY, not its type= -- juice-shop renders its e-mail control as type=text."""
    email_like = {"tag": "input", "type": "text", "aria-label": "Email address field",
                  "id": "emailControl", "selector": "#emailControl"}
    assert rf.shaped_value(email_like, "MK") == "MK@example.test"
    pw = {"tag": "input", "type": "password", "id": "passwordControl", "selector": "#p"}
    shaped = rf.shaped_value(pw, "MK")
    assert "MK" in shaped and shaped != "MK"                     # complexity prefix, marker intact
    num = {"tag": "input", "type": "number", "id": "qty", "selector": "#q"}
    assert rf.shaped_value(num, "MK7") == "7"                    # a number field cannot carry letters
    assert rf.shaped_value({"tag": "textarea", "id": "comment", "selector": "#c"}, "MK") == "MK"


def test_baseline_gives_every_control_its_own_marker_in_one_submission():
    plan = rf.baseline_plan(LOGIN_FORM, tag="q1")
    assert set(plan["values"]) == {"#email", "#password"}
    assert len(set(plan["markers"].values())) == 2                # distinct, or the map is ambiguous
    for sel, mk in plan["markers"].items():
        assert mk in plan["values"][sel], "the shaping must not destroy the marker"
    assert plan["fields"]["#password"] == "password"
    assert rf.baseline_plan({"fields": []}, tag="q1")["values"] == {}


# ═══════════════════════════════════════════ 3. the app's own request -> the real parameter names
def test_marker_location_finds_the_parameter_name_the_app_chose():
    body = '{"email":"apolakirfq1f0@example.test","password":"Aa1!apolakirfq1f1"}'
    hit = rf.locate_marker(body, "application/json", "apolakirfq1f0")
    assert hit == {"found": True, "carrier": "json", "path": "email"}
    # nested + list bodies: the path is the whole route to the value
    nested = '{"user":{"contact":[{"mail":"MK"}]}}'
    assert rf.locate_marker(nested, "application/json", "MK")["path"] == "user.contact[0].mail"
    # the other two carriers
    assert rf.locate_marker("a=1&comment=MK", "application/x-www-form-urlencoded", "MK") == {
        "found": True, "carrier": "form", "path": "comment"}
    assert rf.locate_marker_in_url("http://h/s?q=MK&p=1", "MK") == {
        "found": True, "carrier": "query", "path": "q"}
    # absent is absent -- never a guess
    assert rf.locate_marker(body, "application/json", "nope")["found"] is False
    assert rf.locate_marker_in_url("http://h/s?q=1", "MK")["found"] is False
    # present but not decodable: reported honestly as raw, with no invented path
    assert rf.locate_marker("....MK....", "application/octet-stream", "MK") == {
        "found": True, "carrier": "raw", "path": ""}


def test_wire_form_is_the_observed_replacement_for_parse_forms_output():
    plan = {"markers": {"#email": "apolakirfq1f0", "#password": "apolakirfq1f1"},
            "values": {}, "fields": {}}
    wire = rf.wire_form(BASELINE, plan)
    assert wire["observed"] and wire["method"] == "POST" and wire["carrier"] == "json"
    assert wire["url"] == LOGIN_URL
    assert wire["params"] == {"#email": "email", "#password": "password"}
    assert wire["unmapped"] == []


def test_a_control_whose_value_never_reaches_the_wire_is_reported_unmapped_not_probed():
    """The silent-failure shape this codebase keeps finding: a field the app transformed or dropped
    must not be counted as probed."""
    plan = {"markers": {"#email": "apolakirfq1f0", "#captcha": "apolakirfq1f9"}}
    wire = rf.wire_form(BASELINE, plan)
    assert wire["params"] == {"#email": "email"} and wire["unmapped"] == ["#captcha"]


def test_wire_form_of_an_unsubmitted_form_claims_nothing():
    wire = rf.wire_form({"observed": False, "reason": "submit control never became actionable"},
                        {"markers": {"#a": "MK"}})
    assert wire["observed"] is False and wire["params"] == {} and wire["unmapped"] == ["#a"]
    assert "actionable" in wire["note"]


# ═════════════════════════════════════════════════════════ 4. stage-two planning (pure)
def test_probes_are_planned_only_for_controls_that_actually_reach_a_parameter():
    base = rf.baseline_plan(LOGIN_FORM, tag="q1")
    wire = {"observed": True, "url": LOGIN_URL, "params": {"#email": "email"}}
    plans = rf.probe_plans(LOGIN_FORM, wire, base, tag="q1")
    assert {p["field"] for p in plans} == {"#email"}, "an unmapped control is never probed"
    assert all(p["values"]["#password"] == base["values"]["#password"] for p in plans), (
        "only the field under test may change between baseline and probe")


def test_the_auth_bypass_payload_is_planned_only_for_an_observed_login_endpoint():
    base = rf.baseline_plan(LOGIN_FORM, tag="q1")
    login = {"observed": True, "url": LOGIN_URL, "params": {"#email": "email"}}
    other = {"observed": True, "url": "http://juice-shop:3000/api/Feedbacks",
             "params": {"#email": "comment"}}
    assert "auth_bypass" in {p["family"] for p in rf.probe_plans(LOGIN_FORM, login, base, tag="q1")}
    assert "auth_bypass" not in {p["family"] for p in rf.probe_plans(LOGIN_FORM, other, base, tag="q1")}


def test_every_sqli_probe_is_planned_with_its_escaped_quote_control():
    base = rf.baseline_plan(LOGIN_FORM, tag="q1")
    wire = {"observed": True, "url": LOGIN_URL, "params": {"#email": "email"}}
    plans = rf.probe_plans(LOGIN_FORM, wire, base, tag="q1")
    probe = next(p for p in plans if p["family"] == "sqli" and p["kind"] == "probe")
    ctrl = next(p for p in plans if p["family"] == "sqli" and p["kind"] == "control")
    assert probe["payload"].endswith("'") and ctrl["payload"].endswith("''")
    assert probe["payload"][:-1] == ctrl["payload"][:-2] == base["values"]["#email"]


def test_nothing_is_planned_before_the_application_has_shown_its_request():
    assert rf.probe_plans(LOGIN_FORM, {"observed": False}, rf.baseline_plan(LOGIN_FORM, tag="q"),
                          tag="q") == []


def test_the_xss_probe_carries_the_breakouts_its_oracle_can_confirm_on():
    base = rf.baseline_plan(LOGIN_FORM, tag="q1")
    wire = {"observed": True, "url": "http://h/api/x", "params": {"#email": "email"}}
    xss = next(p for p in rf.probe_plans(LOGIN_FORM, wire, base, tag="q1") if p["family"] == "xss")
    for ctx in xt.EXECUTABLE_ON_REFLECTION:
        assert xt.BREAKOUTS[ctx] in xss["payload"]


# ═════════════════════════════════════════════════════════════════ 5. the oracles (pure)
def test_error_oracle_confirms_the_injectable_field_of_the_real_form():
    v = rf.judge_error(BASELINE, PROBE_QUOTE, CONTROL_QUOTE)
    assert v["confirmed"] and v["oracle"] == "error-based"
    assert {h["dbms"] for h in v["hits"]} == {"SQLite"}
    kinds = {c["kind"] for c in v["negative_controls"]}
    assert kinds == {"benign-baseline-signature-absence", "escaped-quote-recovery"}


def test_error_oracle_stays_silent_on_the_correctly_neutralised_field():
    """THE MANDATORY NEGATIVE CONTROL. Same form, same payload, same endpoint -- but juice-shop
    hashes `password` before it reaches the statement, so the response is byte-identical to the
    benign baseline and the oracle must say nothing."""
    v = rf.judge_error(BASELINE, SIBLING_PROBE, CONTROL_QUOTE)
    assert v["confirmed"] is False and "signature" in v["reason"]


def test_error_oracle_refuses_when_the_baseline_ALREADY_carries_the_error():
    """The differential must be a real differential. An application that prints a SQL error on
    every request (a broken debug build, a chatty 500 page) has told us nothing about our quote --
    and an oracle that dropped the baseline from the comparison would confirm on all of them while
    still passing every other test in this file, because juice-shop's benign baseline is clean."""
    noisy_baseline = dict(BASELINE, status=500, body=PROBE_QUOTE["body"])
    v = rf.judge_error(noisy_baseline, PROBE_QUOTE, CONTROL_QUOTE)
    assert v["confirmed"] is False and "baseline lacked" in v["reason"]


def test_error_oracle_refuses_when_the_escaped_quote_control_errors_too():
    """A 500 that survives ESCAPING the quote was not caused by the quote."""
    v = rf.judge_error(BASELINE, PROBE_QUOTE, PROBE_QUOTE)
    assert v["confirmed"] is False and "ESCAPED-quote" in v["reason"]


def test_error_oracle_refuses_when_the_control_was_never_delivered():
    v = rf.judge_error(BASELINE, PROBE_QUOTE, {"observed": False, "reason": "button disabled"})
    assert v["confirmed"] is False and "not delivered" in v["reason"]


def test_no_verdict_is_ever_formed_from_a_submission_that_did_not_happen():
    """A form that never submitted is not a form that is clean."""
    ghost = {"observed": False, "reason": "submit control never became actionable"}
    for v in (rf.judge_error(ghost, PROBE_QUOTE), rf.judge_error(BASELINE, ghost),
              rf.judge_auth_bypass(ghost, BYPASS), rf.judge_reflection(ghost, PROBE_QUOTE, "x")):
        assert v["confirmed"] is False and "not observed" in v["reason"]


def test_no_verdict_is_formed_from_a_response_the_edge_produced():
    """429/503 never reached the application -- the live false HIGH `quote_break_recovers`
    documents came from exactly this shape."""
    for status in (429, 503):
        v = rf.judge_error(dict(BASELINE, status=status), PROBE_QUOTE)
        assert v["confirmed"] is False and str(status) in v["reason"]
        v = rf.judge_error(BASELINE, dict(PROBE_QUOTE, status=status))
        assert v["confirmed"] is False and str(status) in v["reason"]


def test_no_verdict_is_formed_across_two_different_endpoints():
    v = rf.judge_error(BASELINE, dict(PROBE_QUOTE, url="http://juice-shop:3000/api/Feedbacks"))
    assert v["confirmed"] is False and "different endpoints" in v["reason"]


def test_auth_bypass_oracle_confirms_a_session_the_benign_credential_did_not_get():
    v = rf.judge_auth_bypass(BASELINE, BYPASS)
    assert v["confirmed"] and v["how"] == "token"
    assert v["negative_controls"][0]["kind"] == "benign-invalid-credential"


def test_auth_bypass_oracle_stays_silent_for_the_hashed_field_and_for_a_non_login_endpoint():
    assert rf.judge_auth_bypass(BASELINE, SIBLING_PROBE)["confirmed"] is False
    feedback = "http://juice-shop:3000/api/Feedbacks"
    v = rf.judge_auth_bypass(dict(BASELINE, url=feedback), dict(BYPASS, url=feedback))
    assert v["confirmed"] is False and "credential-checking" in v["reason"]


def test_reflection_oracle_confirms_only_an_unencoded_breakout_in_a_markup_response():
    canary = "apolakirfq1x0"
    html = dict(BASELINE, status=200, response_content_type="text/html; charset=utf-8",
                body="<div>hello %s%s</div>" % (canary, xt.BREAKOUTS["html"]))
    assert rf.judge_reflection(BASELINE, html, canary)["confirmed"]

    # correctly encoded output -> silent (the ticket's mandatory encoded-field control)
    encoded = dict(html, body="<div>hello %s&lt;bbhx7h&gt;</div>" % canary)
    v = rf.judge_reflection(BASELINE, encoded, canary)
    assert v["confirmed"] is False and "encoded" in v["reason"]

    # reflected into a nosniff JSON body -> a browser does not parse it as markup (Q-160, and the
    # exact headers juice-shop's own `/api/Challenges/?sort=` error carries)
    as_json = dict(html, response_content_type="application/json",
                   response_headers={"Content-Type": "application/json",
                                     "X-Content-Type-Options": "nosniff"},
                   body='{"msg":"%s%s"}' % (canary, xt.BREAKOUTS["html"]))
    v = rf.judge_reflection(BASELINE, as_json, canary)
    assert v["confirmed"] is False and "markup" in v["reason"]

    # not reflected at all
    assert rf.judge_reflection(BASELINE, dict(html, body="<div>hi</div>"), canary)["confirmed"] is False


def test_judge_probe_routes_each_family_to_its_own_oracle():
    fam = lambda f, payload="x": {"family": f, "payload": payload}          # noqa: E731
    assert rf.judge_probe(BASELINE, BYPASS, fam("auth_bypass"))["oracle"] == "auth-bypass"
    assert rf.judge_probe(BASELINE, PROBE_QUOTE, fam("sqli"))["oracle"] == "error-based"
    assert rf.judge_probe(BASELINE, BASELINE, fam("xss", "apolakirfzz1x0<"))["oracle"] == "reflection"


# ═══════════════════════════════════════════════════════ 6. findings carry their proof
def _wire():
    return {"observed": True, "url": LOGIN_URL, "method": "POST", "carrier": "json",
            "params": {"#email": "email"}, "unmapped": []}


def _plan(family="sqli", payload="a@b.co'"):
    return {"kind": "probe", "field": "#email", "field_label": "email", "param": "email",
            "family": family, "payload": payload}


def test_error_finding_passes_the_project_proof_contract_and_names_the_rendered_control():
    v = rf.judge_error(BASELINE, PROBE_QUOTE, CONTROL_QUOTE)
    f = rf.finding("#/login", _plan(), _wire(), BASELINE, PROBE_QUOTE, v)
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, missing
    assert f["rendered_form"]["control"] == "#email" and f["rendered_form"]["route"] == "#/login"
    assert f["rendered_form"]["observed_endpoint"] == LOGIN_URL
    assert "rendered-form" in f["tags"] and "spa" in f["tags"]
    assert any("rendered control" in s for s in f["reproduction_steps"])
    assert len(f["negative_controls"]) >= 2


def test_auth_bypass_finding_passes_the_proof_contract():
    v = rf.judge_auth_bypass(BASELINE, BYPASS)
    f = rf.finding("#/login", _plan("auth_bypass", sqli_tool.AUTH_BYPASS_PAYLOADS[0]), _wire(),
                   BASELINE, BYPASS, v)
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, missing
    assert f["family"] == "auth_bypass" and f["rendered_form"]["control_label"] == "email"


def test_reflection_finding_passes_the_proof_contract():
    canary = "apolakirfq1x0"
    html = dict(BASELINE, status=200, response_content_type="text/html",
                body="<p>%s%s</p>" % (canary, xt.BREAKOUTS["html"]))
    v = rf.judge_reflection(BASELINE, html, canary)
    f = rf.finding("#/contact", _plan("xss", canary + xt.BREAKOUTS["html"]), _wire(), BASELINE, html, v)
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, missing
    assert f["cwe"] == "CWE-79"


# ══════════════════════════════════════════════ 7. the driver is dumb (no browser needed)
class _FakePage:
    """Enough Playwright surface to prove the driver RECORDS failures instead of dissolving them."""

    def __init__(self, evaluate=None):
        self._evaluate = evaluate or (lambda js, arg=None: [])

    def evaluate(self, js, arg=None):
        return self._evaluate(js, arg)


def test_read_forms_records_a_crash_instead_of_reporting_an_empty_control_surface():
    """`except Exception: return []` would make a crashed evaluate byte-identical to a page that
    genuinely renders no form -- and this module would then report 'no forms' about a page it
    never read. Fourth instance of that shape in this codebase; it is not repeated here."""
    def boom(js, arg=None):
        raise RuntimeError("Execution context was destroyed")

    errors = []
    assert rf.read_forms(_FakePage(boom), errors) == []
    assert errors and "Execution context was destroyed" in errors[0]
    assert rf.read_forms(_FakePage(), []) == []               # a genuinely empty page: no error


def test_obstruction_clearing_waits_for_the_condition_and_gives_up_on_a_deadline():
    """A FIXED SLEEP IS A RACE. Every pass re-reads whether the control is still covered; the loop
    is bounded by a deadline, never by a duration."""
    seen = {"n": 0}

    def covered_forever(js, arg=None):
        seen["n"] += 1
        return {"found": True, "covered": True, "layer": "div#cookie-bar"}

    page = _FakePage(covered_forever)
    page.keyboard = type("K", (), {"press": staticmethod(lambda k: None)})()
    page.get_by_role = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no such role"))
    out = rf.clear_obstruction(page, "#loginButton", budget_ms=0)
    assert "still covered by div#cookie-bar" in out
    assert seen["n"] >= 1

    clear = _FakePage(lambda js, arg=None: {"found": True, "covered": False, "layer": ""})
    assert rf.clear_obstruction(clear, "#loginButton") == "clear"
    absent = _FakePage(lambda js, arg=None: {"found": False, "covered": False, "layer": ""})
    assert rf.clear_obstruction(absent, "#nope") == "control-absent"


def test_run_without_a_browser_says_so_and_claims_nothing(monkeypatch):
    monkeypatch.setattr(rf, "available", lambda: (False, "playwright is not installed in this image"))
    out = rf.run("http://juice-shop:3000", ["#/login"])
    assert out["browser"] is False and out["ran"] is False and out["findings"] == []
    assert "playwright" in out["note"]


# ══════════════════════════════════════════════════════ 8. live acceptance test (the DoD)
def _lab_up(host="juice-shop", port=3000, timeout=3.0) -> bool:
    try:
        socket.create_connection((host, port), timeout).close()
        return True
    except OSError:
        return False


def test_live_confirms_an_injection_through_a_control_juice_shop_actually_submits():
    """Q-158 definition of done, executed.

    A form with NO action and NO method, driven in a real browser: the app sends its own request,
    the injectable control is confirmed, and the correctly-neutralised control of the SAME form
    stays silent."""
    if not _lab_up():
        pytest.skip("juice-shop lab unreachable (no route to juice-shop:3000); no measurement, "
                    "not a pass")
    usable, note = rf.available()
    if not usable:
        pytest.skip("browser unavailable in this image (%s); no measurement, not a pass" % note)

    out = rf.run("http://juice-shop:3000", ["#/login"], timeout_ms=25000, max_forms=1, tag="t158")
    assert out["ran"], out["note"]
    forms = [f for f in out["forms"] if (f.get("wire") or {}).get("observed")]
    assert forms, "no rendered form submitted a request: %s" % out

    form = forms[0]
    assert form["action"] is None and form["method_attr"] is None, (
        "the DoD requires a form with no action and no method attribute; got %r/%r"
        % (form["action"], form["method_attr"]))

    wire = form["wire"]
    assert wire["url"].endswith("/rest/user/login") and wire["method"] == "POST"
    assert wire["carrier"] == "json"
    assert wire["params"].get("#email") == "email", wire
    assert wire["params"].get("#password") == "password", wire

    confirmed = form["findings"]
    assert confirmed, "no injection confirmed; probes were %s" % form["probes"]
    controls = {f["rendered_form"]["control"] for f in confirmed}
    assert controls == {"#email"}, (
        "the hashed `password` control of the SAME form must stay silent; confirmed on %s" % controls)
    for f in confirmed:
        ok, missing = proof_schema.validate_confirmed(f)
        assert ok, (f["title"], missing)
    assert any(f["family"] in ("sqli", "auth_bypass") for f in confirmed)
