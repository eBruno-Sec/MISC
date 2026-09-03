"""Q-171. The LIVE js-review lane reviewed somebody else's library as if the operator wrote it.

`codeintel.not_maintained_source` classifies a file as third-party or generated ON EVIDENCE, and
`review_source_tree` has demoted findings in such files since Q-083. `_run_js_review` -- the lane
that FETCHES .js over HTTP rather than walking a tree -- never called it.

MEASURED on a mutillidae mission: http://mutillidae/javascript/jQuery/jquery.js produced
"Predictable randomness: Math.random()" at MEDIUM confidence=confirmed. The call site is jQuery's
`expando`, whose own comment reads "Unique for each copy of jQuery on the page" -- a
collision-avoiding property name, not a security value. Handed that same file, the classifier
answers third-party immediately and quotes the licence banner it saw.

NARROWING THE DETECTOR WAS THE WRONG FIX, AND I TRIED IT FIRST. Requiring Math.random() to reach a
security-named identifier broke `test_negative_control_first_party_weak_randomness_is_still_
confirmed`, a control written to catch precisely that over-correction. The noise was never in the
rule. It was in scanning a dependency as if it were the application.

Demoted, never dropped: dropping it deletes the only place an operator learns the host serves
jQuery 1.8.3.
"""
import asyncio

import pytest

import scope as S
import tools


# A vendored library: a preserved bang banner naming product, version and licence, which is the
# evidence `not_maintained_source` quotes. The Math.random() below is jQuery's real construct.
VENDORED = """/*!
 * jQuery JavaScript Library v1.8.3
 * http://jquery.com/
 * Copyright 2012 jQuery Foundation
 * Released under the MIT license
 */
(function( window, undefined ) {
    var jQuery = {
        expando: "jQuery" + ( "1.8.3" + Math.random() ).replace( /[^0-9]/g, "" ),
        html: function (el, s) { el.innerHTML = s; }
    };
})(window);
"""

# The same constructs with no banner: this is the operator's own code and must stay as it was.
FIRST_PARTY = """function issue(el, s) {
    var sessionToken = Math.random().toString(36);
    el.innerHTML = s;
    return sessionToken;
}
"""


def _review(code, source):
    sc = S.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    res = asyncio.run(reg._run_js_review({"code": code, "source": source}))
    return res.findings or []


def _confidences(findings):
    return {str(f.get("confidence")) for f in findings}


def test_findings_in_a_vendored_library_are_demoted_by_the_live_lane():
    """THE regression, pinned at the CALL SITE -- the classifier was never the broken part."""
    findings = _review(VENDORED, "http://t.local/js/jquery.js")
    assert findings, "the file must still be REVIEWED; demotion is not suppression"
    assert "confirmed" not in _confidences(findings), (
        "the live lane reported confirmed findings against a vendored library: %r"
        % [(f.get("title"), f.get("confidence")) for f in findings][:4])
    assert all(f.get("confidence") == "lead" for f in findings), _confidences(findings)
    gaps = [g for f in findings for g in (f.get("proof_gap") or [])]
    assert any("third-party" in g for g in gaps), (
        "the demotion must say WHY, quoting what was observed, so a reader can overrule it")


def test_the_operators_own_code_is_untouched():
    """The negative control. A fix that silences everything is a worse defect than the noise."""
    findings = _review(FIRST_PARTY, "http://t.local/js/app.js")
    assert findings, "first-party JS must still be reviewed"
    assert not any(f.get("confidence") == "lead" and
                   any("third-party" in g for g in (f.get("proof_gap") or []))
                   for f in findings), "first-party code was demoted as a dependency"


def test_the_vendor_evidence_is_quotable_not_a_bare_verdict():
    import codeintel
    kind, evidence = codeintel.not_maintained_source("http://t.local/js/jquery.js", VENDORED)
    assert kind == "third-party"
    assert "jQuery JavaScript Library v1.8.3" in evidence, (
        "a medium-reliability signal is only safe when it shows its work")
