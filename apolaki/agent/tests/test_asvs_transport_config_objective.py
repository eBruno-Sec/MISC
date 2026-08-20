"""Q-053 GAP-4, consumer half: 24 real findings were invisible to the entire ASVS model.

`security_misconfig` and `transport_posture` carried NO objective key at all, so every finding
`transport_posture` has ever produced -- including 4 genuine session-cookie hardening findings against
a real target -- reached the report with no verification property attached. MEASURED against the live
corpus (positive control 1773 findings / 154 missions / 29,945 tool_call rows / 0 unparseable):

    security_misconfig + transport_posture stored : 24  (all confirmed, all found_by=transport_posture)
      Session cookie without a restrictive SameSite  4
      No Content-Security-Policy                     4
      HSTS not enabled on an HTTPS origin            4
      MIME sniffing not disabled                     4
      No Referrer-Policy                             4
      No Permissions-Policy                          4
    objectives keyed on either family              :  0

**NOTHING HERE IS HAND-SHAPED.** Every fixture is built by calling the REAL producer,
`transport_posture.findings_for`, because a hand-made finding that omits `family` maps to zero
objectives while the test still reads green -- that exact fixture defect left the violation path of
this module completely unexercised once already, and Q-071 was a second instance of it.

THE REFUSAL THAT MUST SURVIVE. Q-048 narrowed SESS-02 to `insecure_cookie` and explicitly REFUSED
`security_misconfig`, because `transport_posture` labels cookie, header and method findings alike, so
a missing Permissions-Policy would otherwise FAIL "session cookies carry Secure". That refusal was
correct. This objective is a NEW key those families can carry honestly, not a re-point of SESS-02,
and `test_the_refusal_q048_made_is_not_undone` fails if anyone re-points it.
"""
from __future__ import annotations

import asvs_model as A
import report
import transport_posture as tp

_TARGET = "https://ginandjuice.shop"

#: The six titles the LIVE corpus stores for this family, measured. If the producer stops emitting
#: them the fixtures below have quietly stopped representing reality and every count is meaningless.
_CORPUS_TITLES = {
    "Session cookie without a restrictive SameSite",
    "No Content-Security-Policy",
    "HSTS not enabled on an HTTPS origin",
    "MIME sniffing not disabled",
    "No Referrer-Policy",
    "No Permissions-Policy",
}


# ── fixtures: the REAL producer, driven with real observations ────────────────────────────────
def _header_findings() -> list:
    """An HTTPS origin serving none of the baseline security headers. `kind="header"`."""
    return tp.findings_for(_TARGET, headers={}, is_https=True)


def _cookie_finding() -> dict:
    """The 4-of-24 case: a session cookie that is Secure and HttpOnly but carries no SameSite."""
    fs = tp.findings_for(_TARGET, set_cookies=["session=abc123; Path=/; Secure; HttpOnly"],
                         is_https=True, hostname="ginandjuice.shop")
    ck = [f for f in fs if "cookie" in f["tags"]]
    assert len(ck) == 1, "producer changed shape: %s" % [f["title"] for f in ck]
    return ck[0]


def _tls_finding() -> dict:
    """The other family: `kind="tls"` is labelled `transport_posture`, not `security_misconfig`."""
    fs = tp.findings_for(_TARGET, protocols={"TLSv1": True, "TLSv1.2": True, "TLSv1.3": True})
    tls = [f for f in fs if f["family"] == "transport_posture"]
    assert len(tls) == 1, [f["title"] for f in tls]
    return tls[0]


def _clean_observation() -> list:
    """A HARDENED origin: every control the engine checks is present. The negative control."""
    return tp.findings_for(
        _TARGET,
        headers={"content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                 "strict-transport-security": "max-age=31536000",
                 "x-content-type-options": "nosniff",
                 "referrer-policy": "no-referrer",
                 "permissions-policy": "geolocation=()",
                 "x-frame-options": "DENY"},
        set_cookies=["session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict"],
        is_https=True, hostname="ginandjuice.shop")


# ── the fixtures are bound to reality, not to my imagination ──────────────────────────────────
def test_the_fixtures_are_the_real_producers_output_and_are_non_vacuous():
    """Guard the fixtures. Empty or family-less fixtures make every assertion below pass for free."""
    hdr = _header_findings()
    assert len(hdr) >= 5, "the header producer emitted %d findings" % len(hdr)
    assert {f["family"] for f in hdr} == {"security_misconfig"}
    assert {f["found_by"] for f in hdr} == {"transport_posture"}
    assert _cookie_finding()["family"] == "security_misconfig"
    assert _tls_finding()["family"] == "transport_posture"
    # both halves of the ternary at transport_posture.py:404 are exercised, which is what makes the
    # two-family key below a measurement rather than a guess
    assert {"security_misconfig", "transport_posture"} == \
        {f["family"] for f in hdr + [_cookie_finding(), _tls_finding()]}


def test_the_producer_still_emits_the_titles_the_live_corpus_stores():
    """The fixtures represent the 24 stored findings only while the producer still emits their shape."""
    seen = {f["title"].split(" — ")[0] for f in _header_findings() + [_cookie_finding()]}
    missing = _CORPUS_TITLES - seen
    assert not missing, "the producer no longer emits stored corpus titles %s -- re-measure" % missing


# ── the defect: invisible to the entire model ─────────────────────────────────────────────────
def test_every_transport_posture_family_now_reaches_an_objective():
    """FAILS BEFORE THE FIX: map_findings returned {} for both families, so all 24 mapped to nothing."""
    for label, fs in (("header", _header_findings()),
                      ("cookie", [_cookie_finding()]),
                      ("tls", [_tls_finding()])):
        m = A.map_findings(fs)
        assert "CONF-02" in m, "%s findings still map to no objective: %s" % (label, m)
        assert len(m["CONF-02"]) == len(fs)


def test_a_violation_fails_the_objective_end_to_end_in_both_renderers():
    """detection -> family -> model -> REPORT. A dict with the right key is the defect class here."""
    fs = _header_findings()
    r = A.assess(fs, attempted_engines={"run_transport_posture"})
    row = next(o for o in r["objectives"] if o["cid"] == "CONF-02")
    assert row["status"] == "failed" and len(row["finding_ids"]) == len(fs)

    md = report.generate_report("gap4", fs, {"in_scope": [_TARGET]},
                                tool_ledger={"run_transport_posture": {}})
    assert "Failed objectives" in md and "CONF-02" in md, \
        "the failed objective never reached the markdown report"

    html = report.generate_html_report("gap4", fs, {"in_scope": [_TARGET]},
                                       tool_ledger={"run_transport_posture": {}})
    assert "CONF-02" in html, "the failed objective never reached the HTML report"

    # and the rollup a client reads at the top of the page counts it as a vulnerable PROPERTY
    p = report.coverage_rollup(fs, {"run_transport_posture": {}})["properties"]
    assert p["vulnerable"] >= 1


# ── the refusal Q-048 made, which a re-point would silently undo ──────────────────────────────
def test_the_refusal_q048_made_is_not_undone():
    """A missing Permissions-Policy must NOT fail "session cookies carry Secure" (CWE-614).

    This is the assertion that makes CONF-02 a new honest key rather than a re-point of SESS-02. It
    fails the moment someone adds `security_misconfig` to SESS-02's `violated_by`.
    """
    sess02 = next(o for o in A.OBJECTIVES if o["cid"] == "SESS-02")
    assert tuple(sess02["violated_by"]) == ("insecure_cookie",), sess02["violated_by"]

    r = A.assess(_header_findings(), attempted_engines={"run_transport_posture", "run_web_probes"})
    assert next(o for o in r["objectives"] if o["cid"] == "SESS-02")["status"] != "failed"

    # POSITIVE CONTROL, in the opposite direction, so this cannot be satisfied by a SESS-02 that
    # simply never fails: the family that DOES belong to it still fails it.
    r2 = A.assess([{"id": "C", "family": "insecure_cookie"}],
                  attempted_engines={"run_web_probes"})
    assert next(o for o in r2["objectives"] if o["cid"] == "SESS-02")["status"] == "failed"


# ── negative controls: nothing to find must produce nothing ───────────────────────────────────
def test_a_hardened_origin_produces_no_finding_and_verifies_the_objective():
    """The engine RAN and found nothing: that is evidence the property held, not a missing test."""
    clean = _clean_observation()
    assert clean == [], "the 'hardened' fixture is not hardened: %s" % [f["title"] for f in clean]
    r = A.assess(clean, attempted_engines={"run_transport_posture"})
    assert next(o for o in r["objectives"] if o["cid"] == "CONF-02")["status"] == "verified"


def test_an_engine_that_never_ran_is_not_tested_and_never_verified():
    """The flattering direction. A capability that exists but did not run must not read verified."""
    r = A.assess([], attempted_engines=set())
    assert next(o for o in r["objectives"] if o["cid"] == "CONF-02")["status"] == "not_tested"


def test_an_empty_ledger_renders_no_claim_about_this_objective():
    """A report built from nothing must not say work was done. Q-084 survived because this was absent."""
    md = report.generate_report("empty", [], {"in_scope": [_TARGET]}, tool_ledger={})
    assert "Failed objectives" not in md
    assert "CONF-02" not in md
    html = report.generate_html_report("empty", [], {"in_scope": [_TARGET]}, tool_ledger={})
    assert "CONF-02" not in html


# ── the near-miss that made four of Q-048's six objectives unfailable ─────────────────────────
def test_the_engine_name_is_the_dispatch_name_and_not_the_toolresult_label():
    """`_run_transport_posture` builds `ToolResult("transport_posture", ...)` -- the LABEL. The ledger
    records the DISPATCH name, measured: run_transport_posture 13 rows, `transport_posture` absent as a
    dispatch name (control in the same query: check_takeover 140, takeover absent). Naming the label
    here pins the objective to not_tested on a perfect run, silently and in the flattering direction."""
    import tools
    conf02 = next(o for o in A.OBJECTIVES if o["cid"] == "CONF-02")
    names = A._engine_names(conf02)
    assert names == ("run_transport_posture",), names
    for n in names:
        assert hasattr(tools.ToolRegistry, "_" + n), "%s resolves to no dispatcher method" % n
        assert n in tools.TOOL_PERMISSIONS, "%s is not gated by any dispatch table" % n
    assert not hasattr(tools.ToolRegistry, "_transport_posture"), \
        "the ToolResult label became dispatchable -- re-measure which string the ledger records"


def test_adding_the_objective_did_not_reclassify_an_existing_one():
    """The evidence that a capability was ADDED rather than something quietly relabelled.

    `total_objectives` and the perfect-run `verified` tally must move together by exactly one, while
    `not_implemented` and `blocked` -- which are properties of the PRODUCT, not of a mission -- do not
    move at all. A model that dropped an objective, or that flipped one out of `not_implemented` to
    make room, fails this even though the raw totals could still look plausible.
    """
    import tools
    emitters = set(tools.TOOL_PERMISSIONS) | {t["name"] for t in tools.CLAUDE_TOOLS}
    reachable = {n for n in emitters if hasattr(tools.ToolRegistry, "_" + n)}
    assert "run_transport_posture" in reachable

    r = A.assess([], attempted_engines=reachable)
    assert r["total_objectives"] == len(A.OBJECTIVES) == 34
    assert r["tally"]["verified"] == 29          # 28 + CONF-02, which is newly assessable
    assert r["tally"]["not_implemented"] == 1    # unchanged: AUTHN-04 only
    assert r["tally"]["blocked"] == 2            # unchanged: AUTHN-05, AUTHN-06
    assert r["tally"]["not_tested"] == 0, \
        "the new objective is unreachable on a perfect run -- its engine name is wrong"
    assert sum(r["tally"].values()) == r["total_objectives"]
