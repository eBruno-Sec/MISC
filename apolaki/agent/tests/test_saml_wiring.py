"""SAML engine reachability (#31) — the harvest half that made an executor meaningful.

`saml_signature_bypass` was gated on `saml_sso_detected` and counted as WIRED by the orchestration audit,
while `saml_tool` had no caller AND nothing ever captured a SAMLResponse to feed it. Doubly disconnected:
no executor, and no input for one.

These tests pin both halves — that the harvest works on both SSO bindings, and that the live path calls it.
"""
import base64
import zlib

import saml_tool as st

XML = ('<samlp:Response xmlns:samlp="urn:x"><Assertion ID="a">'
       '<Subject>bob@example.test</Subject></Assertion></samlp:Response>')
B64 = base64.b64encode(XML.encode()).decode()


def _deflated():
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return base64.b64encode(co.compress(XML.encode()) + co.flush()).decode()


def test_post_binding_value_in_a_query_string_is_harvested():
    """THE bug this caught. Base64 contains `+`, and form-decoding turns `+` into a space, corrupting the
    payload so decode() yields nothing. The first version used parse_qs and silently harvested ZERO from
    the Redirect binding while the POST binding worked — a partial failure that looks like 'no SAML here'."""
    assert "+" in B64, "fixture must actually exercise the + case"
    out = st.harvest(urls=["https://sp.example.test/acs?SAMLResponse=" + B64])
    assert len(out) == 1 and "Assertion" in out[0]["xml"]


def test_redirect_binding_deflated_value_is_harvested():
    out = st.harvest(urls=["https://idp.example.test/sso?SAMLResponse=" + _deflated()])
    assert len(out) == 1 and "Assertion" in out[0]["xml"]


def test_post_binding_hidden_form_input_is_harvested():
    body = '<form action="/acs"><input type="hidden" name="SAMLResponse" value="%s"></form>' % B64
    out = st.harvest(bodies=[body])
    assert len(out) == 1 and out[0]["source"].startswith("form:")


def test_a_parameter_that_merely_has_the_name_is_not_harvested():
    """FP guard: only values that decode to real SAML XML count, or any `?SAMLResponse=hello` invents a
    finding."""
    junk = base64.b64encode(b"just some text, not saml at all").decode()
    assert st.harvest(urls=["https://x.test/?SAMLResponse=" + junk]) == []
    assert st.harvest(bodies=["<p>the word SAMLResponse appears here</p>"]) == []


def test_harvest_is_pure_and_deduplicates():
    u = ["https://sp.test/acs?SAMLResponse=" + B64] * 3
    assert len(st.harvest(urls=u)) == 1
    assert st.harvest(urls=u) == st.harvest(urls=u)
    assert st.harvest() == []


def test_leads_are_leads_never_confirmed_findings():
    """plan_leads exists precisely because no live replay oracle ran. It must not claim confirmation."""
    for lead in st.plan_leads(XML, "https://sp.test/acs") or []:
        assert lead.get("confidence") != "confirmed", lead


def test_the_live_path_harvests_and_analyses():
    """Island check: the executor must call the harvest, not just exist."""
    import inspect
    import tools
    body = inspect.getsource(tools).split("async def _run_saml", 1)[1].split("\n    async def ", 1)[0]
    assert "harvest" in body and "plan_leads" in body


def _run_saml_code():
    """The EXECUTABLE body of _run_saml, docstring stripped.

    The first version of the test below matched the docstring, which explains *why* the intrusive half is
    excluded and therefore names it — prose, not a call. Checking code against prose is the exact mistake
    that let `graphql_argument_injection` ship as reachable-on-paper."""
    import inspect
    import tools
    body = inspect.getsource(tools).split("async def _run_saml", 1)[1].split("\n    async def ", 1)[0]
    return body.split('"""', 2)[-1]


def test_the_intrusive_half_is_not_auto_fired():
    """Generating a forged assertion and replaying it is a state-changing authentication attempt. The
    passive pass must not reach for it."""
    import tools
    code = _run_saml_code()
    assert "wrap_assertion" not in code and "confirm_bypass" not in code
    assert tools.TOOL_PERMISSIONS["run_saml"] == tools.PermissionLevel.PASSIVE


def test_the_agent_invokes_it_and_gates_on_the_sso_signal():
    """Registration is not invocation — the lesson from run_header_trust. And it must stay quiet on the
    overwhelming majority of targets rather than logging a no-op everywhere."""
    import inspect
    import agent as A
    cls = [c for _n, c in vars(A).items() if inspect.isclass(c) and hasattr(c, "_do_saml")][0]
    src = inspect.getsource(cls._do_saml)
    assert '"run_saml"' in src
    for sig in ("saml", "/sso", "/acs"):
        assert sig in src, sig
    assert "_do_saml" in inspect.getsource(A)


def test_absence_is_reported_as_untested_not_clean():
    """The capability-preflight discipline: a target with no SAML must not read as 'SAML is fine'."""
    import inspect
    import tools
    body = inspect.getsource(tools).split("async def _run_saml", 1)[1].split("\n    async def ", 1)[0]
    assert "UNTESTED" in body and "not clean" in body
