"""Reflected XSS through POST form fields (pure parse + reasoning). The GET-query engine misses a value
submitted in a POST form that reflects (e.g. a login username echoed into `var username='HERE'`). Browser
fill+submit confirmation is exercised in-mission; here we test form parsing, CSRF/hidden capture, the
danger-skip, and the finding shape."""
import blind_benchmark as bb
import form_xss as fx
import xss_tool as xt


def test_parse_forms_captures_hidden_token_but_fuzzes_only_text():
    html = """
      <form class=login-form method=POST action="/login">
        <input type="hidden" name="csrf" value="TOK123">
        <input type=username name="username">
        <button type=submit>Log in</button>
      </form>
    """
    forms = fx.parse_forms(html, "https://x/login")
    assert len(forms) == 1
    f = forms[0]
    assert f["action"] == "https://x/login" and f["method"] == "post"
    assert f["fields"]["csrf"] == "TOK123"          # hidden token captured (echoed on submit)
    assert f["text_fields"] == ["username"]         # only the text field is a fuzz target, not csrf/button


def test_parse_forms_skips_get_forms():
    assert fx.parse_forms('<form method=get action="/s"><input name=q></form>', "https://x") == []


def test_body_with_fills_target_and_echoes_rest():
    form = {"fields": {"csrf": "T", "username": ""}, "text_fields": ["username"]}
    body = fx.body_with(form, "username", "PAYLOAD")
    assert body == {"csrf": "T", "username": "PAYLOAD"}


def test_reflection_context_and_breakout_reuse_xss_tool():
    # canary reflected inside a <script> => 'script' context
    body = "<script>var u = '%s';</script>" % xt.CANARY
    assert fx.reflection_context(body) == "script"
    # an attribute-context breakout that survives unescaped is exploitable
    dq = '<input value="%s">' % xt.BREAKOUTS["attr_dq"]
    assert fx.exploitable_breakout(dq, "attr_dq")


def test_finding_confirmed_vs_candidate_and_benchmark_family():
    conf = fx.finding("https://x/login", "username", "script", "';alert(/x/)//", "alert fired", True)
    cand = fx.finding("https://x/login", "username", "attr_dq", '"><svg>', "breakout survived", False)
    assert conf["confidence"] == "confirmed" and conf["severity"] == "high"
    assert cand["confidence"] == "candidate" and cand["severity"] == "medium"
    assert conf["family"] == "reflected_xss" and conf["cvss_score"] == 6.1
    # the benchmark canonicalises + accepts the confirmed one as proof
    assert bb.finding_family(conf) == "reflected_xss" and bb._has_proof(conf)
    assert not bb._has_proof(cand)   # candidate (not confirmed) is NOT benchmark proof
