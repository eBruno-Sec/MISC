"""Header-trust engine (T1) — authorization decided by a client-controlled header.

Found by walking OverTheWire Natas level 4, which grants on Referer. The two controls carry the weight:
without the value control, a flaky endpoint reads as a bypass; without the content control, a server that
IGNORES an override header looks identical to one that honours it.
"""
import header_trust_tool as ht


def ex(status, body=""):
    return {"status": status, "body": body}


PAGE = "<html><body>Access granted to the admin area</body></html>"
OTHER = "<html><body>Public home page, nothing sensitive here</body></html>"


# ── header trust ──────────────────────────────────────────────────────────────
def test_confirms_when_the_header_flips_the_decision_and_the_value_matters():
    v = ht.judge_header_trust(ex(403), ex(200, PAGE), ex(403))
    assert v["verdict"] == "confirmed"


def test_rejects_when_any_value_is_accepted():
    """If an implausible value also works, the server is not trusting the value — something else changed."""
    v = ht.judge_header_trust(ex(403), ex(200, PAGE), ex(200, PAGE))
    assert v["verdict"] == "rejected" and "implausible value was accepted" in v["reason"]


def test_missing_value_control_is_a_lead_never_a_confirmation():
    v = ht.judge_header_trust(ex(403), ex(200, PAGE), None)
    assert v["verdict"] == "lead"


def test_not_applicable_when_nothing_was_denied():
    """No denial means no authorization decision to bypass — this is the common case and must be quiet."""
    for s in (200, 302):
        assert ht.judge_header_trust(ex(s, PAGE), ex(200, PAGE), ex(403))["verdict"] == "not_applicable"


def test_rejects_when_the_header_changes_nothing():
    assert ht.judge_header_trust(ex(403), ex(403), ex(403))["verdict"] == "rejected"


def test_rejects_an_empty_200():
    assert ht.judge_header_trust(ex(403), ex(200, ""), ex(403))["verdict"] == "rejected"


# ── URL override ──────────────────────────────────────────────────────────────
def test_confirms_url_override_only_when_content_differs():
    v = ht.judge_url_override(ex(403), ex(200, OTHER), ex(200, PAGE))
    assert v["verdict"] == "confirmed"


def test_rejects_when_the_server_ignored_the_override():
    """THE trap: an ignored header serves the permitted page, which is a 200 and looks like success."""
    v = ht.judge_url_override(ex(403), ex(200, OTHER), ex(200, OTHER))
    assert v["verdict"] == "rejected" and "byte-identical" in v["reason"]


def test_url_override_needs_a_denied_path_to_begin_with():
    assert ht.judge_url_override(ex(200, PAGE), ex(200, OTHER), ex(200, PAGE))["verdict"] == "not_applicable"


# ── candidates + findings ─────────────────────────────────────────────────────
def test_candidates_carry_a_control_value_that_differs():
    cands = ht.header_candidates("https://t", "/admin")
    assert cands
    names = [c[0] for c in cands]
    assert "Referer" in names and "X-Forwarded-For" in names
    for name, value, control, why in cands:
        assert value and control and value != control, name
        assert len(why) > 15


def test_referer_candidate_uses_the_targets_own_origin():
    ref = [c for c in ht.header_candidates("https://t", "/admin") if c[0] == "Referer"][0]
    assert ref[1].startswith("https://t") and "invalid" in ref[2]


def test_findings_satisfy_the_proof_contract():
    import proof_schema
    probes = {"baseline": ex(403), "with_header": ex(200, PAGE), "value_control": ex(403)}
    v = ht.judge_header_trust(probes["baseline"], probes["with_header"], probes["value_control"])
    f = ht.finding_header_trust("https://t/admin", "Referer", "https://t/", "gate on origin", probes, v)
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, (f["title"], missing)
    assert f["cwe"] == "CWE-807"

    oprobes = {"direct": ex(403), "permitted": ex(200, OTHER), "overridden": ex(200, PAGE)}
    ov = ht.judge_url_override(oprobes["direct"], oprobes["permitted"], oprobes["overridden"])
    of = ht.finding_url_override("https://t", "/admin", "X-Original-URL", oprobes, ov)
    ok2, missing2 = proof_schema.validate_confirmed(of)
    assert ok2, (of["title"], missing2)
    assert "request_url_override" in of["tags"], "must be findable as the benchmark family it closes"


def test_this_is_not_cache_poisoning():
    """Shares header NAMES with cache_tool but asks a different question; the oracles must not blur."""
    assert "denied" in ht.ORACLE_HEADER and "cache" not in ht.ORACLE_HEADER.lower()
    assert "request line" in ht.ORACLE_OVERRIDE and "cache" not in ht.ORACLE_OVERRIDE.lower()


# ── body-signalled authorization (Natas 4 class) ──────────────────────────────
DENY = "<html><body><h1>natas4</h1><div>Access disallowed. You are visiting from elsewhere</div></body></html>"
DENY2 = "<html><body><h1>natas4</h1><div>Access disallowed. You are visiting from nowhere</div></body></html>"
GRANT = "<html><body><h1>natas4</h1><div>Access granted. The password for natas5 is REDACTEDVALUE</div></body></html>"


def test_body_differential_confirms_when_refusals_agree_and_grant_differs():
    """The Natas 4 shape: every response is 200 and the decision lives in the page."""
    v = ht.judge_body_differential(ex(200, DENY), ex(200, GRANT), ex(200, DENY2))
    assert v["verdict"] == "confirmed", v


def test_body_differential_refuses_on_a_dynamic_page():
    """THE false-positive guard. If no-header and implausible-value already disagree, the page is not
    stable and no change can be attributed to the header."""
    dyn1 = "<html>token=aaaaaaaaaaaaaaaaaaaa time=1</html>" + "x" * 200
    dyn2 = "<html>token=zzzzzzzzzzzzzzzzzzzz time=2</html>" + "y" * 200
    v = ht.judge_body_differential(ex(200, dyn1), ex(200, GRANT), ex(200, dyn2))
    assert v["verdict"] == "rejected" and "not stable enough" in v["reason"]


def test_body_differential_rejects_when_the_header_changed_nothing():
    v = ht.judge_body_differential(ex(200, DENY), ex(200, DENY2), ex(200, DENY2))
    assert v["verdict"] == "rejected"


def test_body_differential_defers_to_the_status_oracle_when_statuses_differ():
    v = ht.judge_body_differential(ex(403, DENY), ex(200, GRANT), ex(403, DENY2))
    assert v["verdict"] == "not_applicable" and "status oracle" in v["reason"]


def test_body_differential_needs_all_three_probes():
    assert ht.judge_body_differential(ex(200, DENY), ex(200, GRANT), None)["verdict"] == "lead"


def test_thresholds_are_ordered_sensibly():
    assert ht.STABLE_MIN > ht.DIFFER_MAX >= 0.5 and ht.MARGIN_MIN > 0


# ── the refusal names the value it wants ──────────────────────────────────────
NATAS4_DENIAL = '''<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/level.css">
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<div id="content">Access disallowed. You are visiting from "" while authorized users should come only
from "http://natas5.natas.labs.overthewire.org/"</div>'''


def test_the_expected_value_is_read_out_of_the_refusal():
    """Guessing an expected Referer is hopeless; the refusal usually states it. Same
    target-leaks-the-clue principle the intel harvester already uses."""
    vals = ht.expected_values_from_denial(NATAS4_DENIAL)
    assert "http://natas5.natas.labs.overthewire.org/" in vals


def test_static_assets_are_never_mistaken_for_the_expected_value():
    """Every page cites its own stylesheets; none of them is an access-control expectation. This is what
    made the naive URL scrape useless on the live target."""
    vals = ht.expected_values_from_denial(NATAS4_DENIAL)
    assert not any(v.endswith((".css", ".js")) for v in vals), vals


def test_harvested_values_are_tried_before_the_guess():
    cands = ht.header_candidates("http://natas4.example", "/", NATAS4_DENIAL)
    referers = [c for c in cands if c[0] == "Referer"]
    assert len(referers) >= 2, "both the harvested value and the own-origin guess should be tried"
    assert referers[0][1] == "http://natas5.natas.labs.overthewire.org/", "harvested value goes first"
    assert "refusal itself named" in referers[0][3]


def test_no_denial_body_still_yields_the_default_candidates():
    cands = ht.header_candidates("https://t", "/")
    assert [c for c in cands if c[0] == "Referer"] and len(cands) == len(ht.AUTH_HEADERS)


def test_harvest_is_bounded_and_deduped():
    body = " ".join('"http://h%d.example/"' % i for i in range(20))
    v = ht.expected_values_from_denial(body)
    assert 0 < len(v) <= 3 and len(set(v)) == len(v)
