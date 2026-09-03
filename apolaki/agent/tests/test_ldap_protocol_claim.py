"""Q-187. A protocol-specific claim needs protocol-specific evidence.

MEASURED across FIVE consecutive acceptance missions, with byte-identical evidence each time:

    high  confirmed  LDAP injection in form field 'new_db'
    target: http://mutillidae/phpmyadmin/db_create.php
    oracle: ...the true predicate returned a strict record-set superset (102%, 112%, 122%, 132%)

phpMyAdmin on MySQL has no directory server anywhere near it, and the cited "record set" is the
application's own FONT-SIZE DROPDOWN. `evaluate_boolean` wraps `semantic_differential.evaluate` --
which is protocol-AGNOSTIC and proves only that the parameter changed the answer -- in LDAP prose,
and `finding()` hardcodes confidence=confirmed, CWE-90 and CVSS 8.2 on top of it.

THE DISCRIMINATOR IS THE ENDPOINT, NOT THE PROTOCOL, and finding that took two wrong attempts:

  1. Refusing every boolean-only verdict broke `test_shipping_tool_confirms_silent_vulnerable_
     fixture[ldap]`. That fixture is a SILENT LDAP app -- directory errors suppressed, detectable
     ONLY by the record differential -- which is the entire reason `boolean_pairs` exists. That
     change traded a false positive for a false negative on the real bug.
  2. The sharper rule: a record-set superset on a WRITE endpoint is not evidence of a filter. An
     endpoint that CREATES an object gains a record for ANY value it accepts, so the superset means
     the write succeeded and nothing more. On a GET search, the same superset is the detection.

`auth_state` is deliberately NOT downgraded on a form: a login form whose true predicate reaches
authenticated content IS a filter bypass, and the silent fixture depends on it.
"""
import ldap_tool as lp


def _grade(signal, protocol_evidence=False, where="form field"):
    """Exactly the expression the form-body call site uses."""
    return lp.finding("http://t.local/db_create.php", "new_db", where, "oracle text",
                      protocol_evidence=protocol_evidence or signal != "record_set")


def test_a_record_set_superset_on_a_write_form_does_not_claim_ldap():
    """THE regression, from five missions of a false HIGH on a MySQL-only stack."""
    f = _grade("record_set")
    assert f["confidence"] == "candidate", f
    assert "LDAP" not in f["title"], f["title"]
    assert f["severity"] == "medium", f["severity"]


def test_the_downgraded_finding_says_what_is_missing():
    f = _grade("record_set")
    gap = " ".join(f.get("proof_gap") or [])
    assert "no protocol evidence" in gap, gap
    assert "SQL" in gap and "XPath" in gap, (
        "the proof gap must name the sinks it could equally be, or a reader cannot act on it")


def test_an_auth_state_split_on_a_form_still_confirms():
    """POSITIVE CONTROL: a login form reaching authenticated content is a real filter bypass."""
    f = _grade("auth_state")
    assert f["confidence"] == "confirmed" and "LDAP injection" in f["title"], f


def test_a_directory_error_signature_still_confirms():
    """POSITIVE CONTROL: protocol evidence is exactly what entitles the LDAP claim."""
    f = lp.finding("http://t.local/s", "uid", "parameter", "an LDAP directory error appeared",
                   protocol_evidence=True)
    assert f["confidence"] == "confirmed" and f["severity"] == "high"
    assert f["cwe"] == "CWE-90"


def test_evaluate_reports_protocol_evidence_and_evaluate_boolean_does_not():
    """The two paths must disagree about what they observed, or the call site cannot grade them."""
    # A real signature from LDAP_ERRORS, not an invented one -- the first version of this test used
    # `javax.naming.NameNotFoundException`, which the detector does not list, so the test failed for
    # a reason that had nothing to do with the behaviour under test.
    err = lp.evaluate("clean baseline", "javax.naming.NamingException: bad search filter")
    assert err["confirmed"] and err["protocol_evidence"] is True, err
    same = "<html><body><p>same</p></body></html>"
    boo = lp.evaluate_boolean(same, same, "a", "b")
    assert boo["confirmed"] is False, boo
    assert boo["protocol_evidence"] is False


# --- the single decision point -----------------------------------------------------------------
# An earlier version of these tests re-derived the caller's expression and THREE mutants survived:
# a test that recomputes what the caller should do passes while the caller does something else.
# A fixture driving `_run_ldap` did not work either -- the engine fetches forms through
# `_target_client`, not the `httpx.AsyncClient` the fixture patched, so it made ZERO requests and
# the "no false claim" assertion passed vacuously on an empty finding list.
#
# So the rule was moved OUT of the call site into `ldap_tool.may_claim_ldap`, which the call site
# now simply calls. One function, one rule, one place to test -- and a mutant that changes the rule
# has nowhere to hide.


def test_a_record_set_superset_on_a_form_may_not_claim_ldap():
    """THE regression: the exact verdict shape behind five false HIGHs."""
    ev = {"confirmed": True, "protocol_evidence": False, "signal": "record_set"}
    assert lp.may_claim_ldap(ev, "form field") is False


def test_the_same_verdict_on_a_query_parameter_MAY_claim_ldap():
    """A silent LDAP server suppresses errors and is detectable only by the record differential on
    a SEARCH. Refusing that trades the false positive for a false negative on the real bug."""
    ev = {"confirmed": True, "protocol_evidence": False, "signal": "record_set"}
    assert lp.may_claim_ldap(ev, "parameter") is True


def test_an_auth_state_split_on_a_form_may_claim_ldap():
    """A login form whose true predicate reaches authenticated content IS a filter bypass."""
    ev = {"confirmed": True, "protocol_evidence": False, "signal": "auth_state"}
    assert lp.may_claim_ldap(ev, "form field") is True


def test_protocol_evidence_always_entitles_the_claim():
    ev = {"confirmed": True, "protocol_evidence": True, "signal": "record_set"}
    assert lp.may_claim_ldap(ev, "form field") is True


def test_the_call_site_uses_the_rule_rather_than_restating_it():
    """Pins the wiring: if a caller re-derives the expression inline, the rule can drift from it."""
    import inspect
    import tools
    src = inspect.getsource(tools.ToolRegistry._run_ldap)
    assert "may_claim_ldap" in src, "the engine no longer routes its grading through the one rule"
    assert 'signal") != "record_set"' not in src, (
        "the grading expression was restated at the call site; that is what made three mutants "
        "survive the first time")
