"""SAML SSO engine (#109): decode, signing-posture analysis, tamper variants, and a zero-FP bypass oracle."""
import base64
import zlib

import saml_tool as S

_SIGNED = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    '<saml:Subject><saml:NameID>alice@corp.com</saml:NameID></saml:Subject>'
    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">SIGDATA</ds:Signature>'
    '</saml:Assertion></samlp:Response>')

_UNSIGNED = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<saml:Assertion><saml:Subject><saml:NameID>alice@corp.com</saml:NameID></saml:Subject>'
    '</saml:Assertion></samlp:Response>')


def test_decode_plain_base64_and_deflated():
    b64 = base64.b64encode(_SIGNED.encode()).decode()
    assert S.decode(b64) == _SIGNED
    # HTTP-Redirect binding: raw-deflate then base64 then url-encode
    deflated = zlib.compressobj(9, zlib.DEFLATED, -15)
    comp = deflated.compress(_SIGNED.encode()) + deflated.flush()
    assert "<saml:Assertion" in (S.decode(base64.b64encode(comp).decode()) or "")


def test_analyze_signing_posture():
    a = S.analyze(_SIGNED)
    assert a["is_response"] and a["assertion_count"] == 1 and a["assertion_signed"] and not a["unsigned"]
    u = S.analyze(_UNSIGNED)
    assert u["unsigned"] and not u["assertion_signed"]


def test_strip_and_wrap_variants():
    stripped = S.strip_signatures(_SIGNED)
    assert "Signature" not in stripped and "Assertion" in stripped
    wrapped = S.wrap_assertion(_SIGNED, "admin@apolaki-test.local")
    assert wrapped.count("Assertion") >= 2 and "admin@apolaki-test.local" in wrapped
    assert "SIGDATA" in wrapped        # the original signed assertion is preserved (classic XSW)


def test_confirm_bypass_is_zero_fp():
    # tampered accepted + baseline worked -> confirmed
    hit = S.confirm_bypass({"authenticated": True, "status": 302}, {"authenticated": True, "status": 302})
    assert hit and hit["confirmed"]
    # SP rejected the tamper -> nothing claimed
    assert S.confirm_bypass({"authenticated": True}, {"authenticated": False, "status": 401}) is None
    # baseline never authenticated -> inconclusive, no claim
    assert S.confirm_bypass({"authenticated": False}, {"authenticated": True}) is None


def test_finding_shape():
    f = S.finding("signature_wrapping", "https://sp/acs", "SP authenticated a wrapped assertion")
    assert f["confidence"] == "confirmed" and f["cwe"] == "CWE-347" and f["family"] == "broken_auth"
    assert isinstance(f["reproduction_steps"], list) and "saml" in f["tags"]


def test_plan_leads_from_posture():
    assert S.plan_leads(_UNSIGNED, "https://sp/acs")[0]["title"].startswith("SAML assertion carries no signature")
    # response-signed but assertion-unsigned -> XSW lead
    resp_signed = _UNSIGNED.replace("</samlp:Response>",
                                    '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">S</ds:Signature></samlp:Response>')
    leads = S.plan_leads(resp_signed, "https://sp/acs")
    assert leads and "wrapping" in leads[0]["title"].lower()
    assert all(l["confidence"] == "lead" for l in leads)
