"""Q-098 -- an evidence claim belongs to the check that made it, never to a CWE.

FOUND IN THE FIELD, same 2026-08-24 Shopify report. Findings 11, 14 and 17 are titled
**"No Referrer-Policy"** and carry, verbatim:

    What it is:    Sensitive files or source are reachable directly over the web.
    Demonstrated:  Confirmed on this target: a sensitive file/resource served directly over the web
                   (a control path 404s)
    Confidence:    confirmed

**None of that happened.** No file was served, no control path was probed, nothing was confirmed --
and by Q-097 we now know the socket never even opened. This is the most reputationally dangerous of
the three: Q-096 and Q-097 produce findings a careful reader can dismiss, but this one asserts a
DEMONSTRATED exposure. Submitted to a program it is a false evidentiary claim.

THE MECHANISM, exact. `transport_posture._FINDING_META` gives `header_missing_referrer_policy` the
CWE **CWE-200** (`transport_posture.py:346`) and the finding carries `family: "security_misconfig"`
(`transport_posture.py:404`). `report.graded_business_impact` then does:

    fam = finding["family"]                       # "security_misconfig"
    if fam not in _IMPACT_GRADE:                  # true -- misconfig has no entry
        fam = _CWE_FAMILY[finding["cwe"]]         # "cwe-200" -> "exposure"

and `business_impact()` carries the identical fallback. So an information-exposure story is glued
onto a missing-header finding and stamped `confirmed`. Only the Referrer-Policy check is hit because
it is the only one of the six header rules mapped to CWE-200; the other five are CWE-693/1021/319,
which `_CWE_FAMILY` does not list. That is why the field report shows exactly three of them, one per
origin, and not eighteen.

**A CWE is a taxonomy label shared by unrelated checks. It cannot carry a claim about what THIS run
observed.** `report._family_of` already had this right (family first, CWE only when there is no
family); the two impact functions did not.

THE FIX IS NOT DELETION. Stripping the block would leave every misconfig finding with no impact text
at all, which trades a false claim for no information. `security_misconfig` gets its own entry saying
what the check actually establishes: the control's absence, read out of a response that was received
(which Q-097 now guarantees). The CWE fallback survives for its legitimate use -- a finding that
declares no family at all.

NON-VACUITY. A genuine exposure finding must still emit that exact line, in the rendered report, or
this file would be satisfied by a report that says nothing.
"""
from __future__ import annotations

import report
import transport_posture as tp

# The two sentences the field report printed under "No Referrer-Policy".
EXPOSURE_WHAT = "Sensitive files or source are reachable directly over the web."
EXPOSURE_DEMO = "a sensitive file/resource served directly over the web (a control path 404s)"

TARGET = "https://www.shopify.com"


def _referrer_policy_finding() -> dict:
    """The REAL finding, built by the engine that built the field one. Hand-writing the dict here
    would test my idea of the finding rather than the one the product emits."""
    fs = tp.findings_for(TARGET, headers={}, is_https=True, hostname="www.shopify.com")
    got = [f for f in fs if f["tags"][2] == "header_missing_referrer_policy"]
    assert len(got) == 1, "fixture drifted from the engine: %r" % ([f["tags"][2] for f in fs],)
    f = got[0]
    assert f["family"] == "security_misconfig" and f["cwe"] == "CWE-200", f
    return f


def _exposure_finding() -> dict:
    """A genuine exposure finding, for the non-vacuity control."""
    return {"title": "Exposed .env file", "severity": "high", "confidence": "confirmed",
            "family": "exposure", "cwe": "CWE-200", "target": TARGET + "/.env",
            "description": "The application's .env is served over HTTP.",
            "evidence": "GET https://www.shopify.com/.env -> 200 with DB_PASSWORD=...",
            "found_by": "exposure_probe"}


# ── the defect ────────────────────────────────────────────────────────────────

def test_a_missing_header_does_not_claim_a_demonstrated_file_exposure():
    """MUST FAIL before the fix."""
    f = _referrer_policy_finding()
    g = report.graded_business_impact(f)
    dem = (g or {}).get("demonstrated", "")
    assert EXPOSURE_DEMO not in dem, (
        "a missing-header finding claims a demonstrated file exposure: %r" % (dem,))
    bi = report.business_impact(f)
    assert EXPOSURE_WHAT not in ((bi or ("", ""))[0]), (
        "a missing-header finding is described as a file exposure: %r" % (bi,))


def test_no_security_misconfig_finding_can_emit_the_exposure_claim_in_a_RENDERED_report():
    """MUST FAIL before the fix -- stated against the artifact that was actually submitted.

    Every one of the six header findings goes through, not just Referrer-Policy, so a fix that
    special-cases one CWE does not pass.
    """
    fs = tp.findings_for(TARGET, headers={}, is_https=True, hostname="www.shopify.com")
    misconfig = [f for f in fs if f.get("family") == "security_misconfig"]
    assert len(misconfig) >= 6, "fixture must carry the whole family: %r" % (len(misconfig),)

    md = report.generate_report("Shopify", misconfig, {"in_scope": ["www.shopify.com"]})
    html = report.generate_html_report("Shopify", misconfig, {"in_scope": ["www.shopify.com"]})
    for name, doc in (("markdown", md), ("html", html)):
        assert EXPOSURE_DEMO not in doc, "%s report claims a demonstrated exposure" % name
        assert EXPOSURE_WHAT not in doc, "%s report describes a header as a file exposure" % name


def test_a_security_misconfig_finding_still_gets_an_honest_impact_block():
    """MUST FAIL before the fix -- it currently gets the WRONG one, and the fix must not answer that
    by giving it none. The text must describe what the check establishes: the control is absent from
    a response that was received."""
    f = _referrer_policy_finding()
    g = report.graded_business_impact(f)
    assert g, "the family lost its impact block entirely -- silence is not the fix"
    dem = g["demonstrated"].lower()
    assert "header" in dem or "control" in dem, dem
    assert "response" in dem, "the claim must be tied to the response it was read from: %r" % (dem,)
    bi = report.business_impact(f)
    assert bi and "defence" in bi[1].lower() or "defense" in (bi[1].lower() if bi else ""), bi


# ── non-vacuity + the CWE fallback's legitimate use: PASS before AND after ────

def test_a_genuine_exposure_finding_still_emits_exactly_that_line():
    """MUST PASS before AND after. Without this, a fix that deletes the sentence everywhere passes."""
    f = _exposure_finding()
    g = report.graded_business_impact(f)
    assert g and g["demonstrated"] == "Confirmed on this target: " + EXPOSURE_DEMO, g
    assert report.business_impact(f)[0] == EXPOSURE_WHAT

    md = report.generate_report("Prog", [f], {"in_scope": ["www.shopify.com"]})
    assert EXPOSURE_DEMO in md and EXPOSURE_WHAT in md


def test_the_cwe_fallback_survives_for_a_finding_that_declares_no_family():
    """MUST PASS before AND after. The fallback is not the defect -- OVERRIDING a declared family
    with it is. A finding carrying only a CWE still gets its text."""
    f = {"title": "Exposed backup", "severity": "medium", "confidence": "confirmed",
         "cwe": "CWE-200", "target": TARGET + "/db.sql.bak"}
    assert report.business_impact(f)[0] == EXPOSURE_WHAT
    assert report.graded_business_impact(f)["demonstrated"].endswith(EXPOSURE_DEMO)


def test_an_unrelated_family_is_not_regraded_by_its_cwe():
    """MUST PASS before AND after (sqli is in both maps, so the family already wins). The control on
    the fix's direction: family-first must not change a finding whose family already resolved."""
    f = {"title": "SQLi", "confidence": "confirmed", "family": "sqli", "cwe": "CWE-89",
         "target": TARGET}
    assert "injectable parameter" in report.graded_business_impact(f)["demonstrated"]
