"""Q-011 -- the mass-assignment oracle.

`mass_assignment` was declared in `engine_descriptor.PRECONDITIONS`, `asvs_model` ATHZ-04 and
`wstg_catalog.FULL["WSTG-INPV-20"]` while the only over-posting code in the tree was the Juice Shop
lab SOLVER. These tests are the capability's oracle, written before any wiring.

The tests that matter are the ones that must FAIL a confirmation. There are five:

  * a 200 on the write with no re-read                       -> lead
  * an endpoint that echoes the invented control attribute    -> clean
  * a field that already held the value on the baseline       -> clean
  * a read view that exposes the field on neither object      -> untested (never "clean")
  * a control or baseline that did not RUN                    -> lead

MEASURED live before this file existed (see docs/handoff/massassign.md):
  VAmPI      POST /users/v1/register {"admin": true} -> GET /users/v1/_debug shows "admin": true,
             while the ignored-field control and the baseline both read back "admin": false.
  Juice Shop POST /api/Users {"role":"admin"} -> GET /api/Users/24 shows "role":"admin".
The fixtures below are those exact response shapes.
"""
from __future__ import annotations

import json

import mass_assign_tool as MA
import proof_schema


# -- the two labs' real response shapes, as measured -----------------------------------------------

# VAmPI GET /users/v1/_debug -- a KEYED COLLECTION, and the only view of VAmPI's that exposes `admin`.
VAMPI_DEBUG = json.dumps({"users": [
    {"admin": False, "email": "mail1@mail.com", "password": "pass1", "username": "name1"},
    {"admin": True, "email": "admin@mail.com", "password": "pass1", "username": "admin"},
    {"admin": True, "email": "victim@example.com", "password": "x", "username": "apolaki_ma_aabbcc"},
]})
# VAmPI GET /users/v1/{username} -- the obvious view, which never exposes `admin`.
VAMPI_USER = json.dumps({"username": "apolaki_ma_aabbcc", "email": "victim@example.com"})
# Juice Shop GET /api/Users/24 -- an ENVELOPED single object.
JUICE_USER = json.dumps({"status": "success", "data": {
    "id": 24, "username": "", "email": "apolaki_ma_18708@example.com", "role": "admin",
    "deluxeToken": "", "isActive": True, "createdAt": "2026-08-15T13:27:14.393Z"}})


def _ctl(found=False, ran=True, field="apolaki_probe_deadbeef"):
    return {"ran": ran, "field": field, "found": found}


def _confirming_case(**over):
    """The exact VAmPI shape: baseline admin=False, re-read admin=True, control clean."""
    case = {"field": "admin", "sent_value": True,
            "baseline": {"ran": True, "found": True, "value": False},
            "after": {"found": True, "value": True},
            "control": _ctl(), "reread_ran": True}
    case.update(over)
    return case


# ══ the positive case ══════════════════════════════════════════════════════════════════════════

def test_confirms_the_measured_vampi_shape():
    v = MA.evaluate(**_confirming_case())
    assert v["verdict"] == MA.CONFIRMED, v["reason"]
    assert v["field"] == "admin"
    assert v["observed_value"] is True
    assert v["baseline_value"] is False


def test_confirms_the_measured_juice_shop_shape():
    obj = MA.locate_object(JUICE_USER, "id", 24)
    assert obj is not None
    found, val = MA.read_field(obj, "role")
    v = MA.evaluate(field="role", sent_value="admin",
                    baseline={"ran": True, "found": True, "value": "customer"},
                    after={"found": found, "value": val}, control=_ctl(), reread_ran=True)
    assert v["verdict"] == MA.CONFIRMED, v["reason"]


# ══ THE FALSE-POSITIVE GUARDS -- each of these must refuse to confirm ══════════════════════════

def test_an_accepted_write_without_a_reread_is_a_lead_never_a_confirmation():
    """A 200 is not the vulnerability. Without the separate re-read there is no oracle at all."""
    v = MA.evaluate(**_confirming_case(reread_ran=False, after={"found": False, "value": None}))
    assert v["verdict"] == MA.LEAD
    assert "could not be re-read" in v["reason"]


def test_an_endpoint_that_echoes_the_control_attribute_is_clean():
    """THE central FP guard. If the invented `apolaki_probe_<nonce>` attribute comes back, the
    endpoint round-trips whatever it is handed and persistence of `admin` means nothing. The
    privileged field still reads back as injected -- the ONLY difference from the confirming case is
    the control -- so this test fails the moment the control stops being consulted."""
    v = MA.evaluate(**_confirming_case(control=_ctl(found=True)))
    assert v["verdict"] == MA.CLEAN, v["reason"]
    assert "ECHOES" in v["reason"]


def test_a_field_that_already_held_the_value_is_clean():
    """The classic FP of this class: an object BORN with `role: admin`, or `verified: true` by
    default. The re-read is identical to the confirming case; only the baseline differs."""
    v = MA.evaluate(**_confirming_case(baseline={"ran": True, "found": True, "value": True}))
    assert v["verdict"] == MA.CLEAN, v["reason"]
    assert "default" in v["reason"]


def test_a_role_that_was_always_user_is_clean():
    """The ticket's own example, in string form: `role: user` that was always `user`."""
    v = MA.evaluate(field="role", sent_value="user",
                    baseline={"ran": True, "found": True, "value": "user"},
                    after={"found": True, "value": "user"}, control=_ctl(), reread_ran=True)
    assert v["verdict"] == MA.CLEAN


def test_a_control_that_did_not_run_caps_the_verdict_at_a_lead():
    v = MA.evaluate(**_confirming_case(control=_ctl(ran=False)))
    assert v["verdict"] == MA.LEAD
    assert "ignored-field control did not run" in v["reason"]


def test_a_baseline_that_did_not_run_caps_the_verdict_at_a_lead():
    v = MA.evaluate(**_confirming_case(baseline={"ran": False, "found": False, "value": None}))
    assert v["verdict"] == MA.LEAD
    assert "no baseline" in v["reason"]


def test_an_accepted_and_ignored_attribute_is_clean():
    """The normal state of a well-built API: it takes the field and drops it. The read view DOES
    expose the field (the baseline showed it), so this is a real negative, not an untested one."""
    v = MA.evaluate(**_confirming_case(after={"found": False, "value": None}))
    assert v["verdict"] == MA.CLEAN
    assert "accepted and discarded" in v["reason"]


def test_a_field_present_but_holding_something_else_is_clean():
    v = MA.evaluate(**_confirming_case(after={"found": True, "value": "customer"},
                                       field="role", sent_value="admin",
                                       baseline={"ran": True, "found": True, "value": "customer"}))
    assert v["verdict"] == MA.CLEAN
    assert "not the injected" in v["reason"]


def test_a_view_that_exposes_the_field_on_neither_object_is_untested_not_clean():
    """MEASURED on VAmPI: `GET /users/v1/{username}` returns {username, email} and can never answer
    whether `admin` bound. Calling that "clean" is a false negative wearing a verdict."""
    v = MA.evaluate(**_confirming_case(baseline={"ran": True, "found": False, "value": None},
                                       after={"found": False, "value": None}))
    assert v["verdict"] == MA.UNTESTED, v["reason"]
    assert v["verdict"] != MA.CLEAN
    assert "cannot answer" in v["reason"]


def test_the_control_is_checked_before_the_baseline_so_an_echoing_endpoint_never_confirms():
    """Ordering guard: an endpoint that echoes AND has an absent baseline must be clean/lead, never
    confirmed. Both disqualifiers together must not cancel out."""
    v = MA.evaluate(**_confirming_case(control=_ctl(found=True),
                                       baseline={"ran": False, "found": False, "value": None}))
    assert v["verdict"] in (MA.CLEAN, MA.LEAD)
    assert v["verdict"] != MA.CONFIRMED


# ══ candidate selection ════════════════════════════════════════════════════════════════════════

def test_the_candidate_list_is_general_and_covers_both_measured_labs():
    names = {c["field"] for c in MA.privileged_candidates(limit=len(MA.PRIVILEGED_FIELDS))}
    assert "admin" in names          # VAmPI
    assert "role" in names           # Juice Shop
    # ... and no lab-specific field ever enters the general list.
    assert not {MA._norm(n) for n, _, _ in MA.PRIVILEGED_FIELDS} & {
        MA._norm(x) for x in ("deluxeToken", "book_title", "totpSecret", "profileImage")}


def test_a_field_the_endpoint_offers_is_never_a_candidate():
    """Setting a DOCUMENTED parameter is the API working as designed. An API whose spec declares
    `role` would otherwise produce a guaranteed false positive on every scan."""
    names = {c["field"] for c in MA.privileged_candidates(["email", "password", "role"], limit=20)}
    assert "role" not in names
    assert "admin" in names


def test_offered_field_matching_ignores_case_and_separators():
    """`is_admin` in a spec must also suppress `isAdmin` and `admin` -- an application binds all
    three onto the same column, so testing the sibling spelling is testing a documented field."""
    names = {MA._norm(c["field"]) for c in MA.privileged_candidates(["is_admin"], limit=20)}
    assert "isadmin" not in names


def test_an_empty_offered_list_subtracts_nothing_and_a_zero_limit_yields_nothing():
    """`x or DEFAULT` in its two local forms. An empty offered list is a real input meaning 'no
    declared body fields were observed' and must not be confused with a missing argument; a limit of
    0 means NO candidates and must not fall through to the whole table."""
    assert len(MA.privileged_candidates([], limit=3)) == 3
    assert MA.privileged_candidates(["role"], limit=0) == []
    assert MA.privileged_candidates([], limit=0) == []


# ══ body assembly -- one variable at a time ════════════════════════════════════════════════════

def test_body_with_adds_exactly_one_attribute_and_keeps_the_rest():
    out = json.loads(MA.body_with({"email": "a@b.c", "password": "x"}, "admin", True))
    assert out == {"email": "a@b.c", "password": "x", "admin": True}


def test_body_with_accepts_a_json_string_body():
    out = json.loads(MA.body_with('{"username":"u"}', "role", "admin"))
    assert out == {"username": "u", "role": "admin"}


def test_an_unparseable_body_yields_nothing_rather_than_a_body_the_endpoint_never_asked_for():
    """If the base body is lost, sending `{"admin": true}` ALONE would draw a 400 that the driver
    would then read as a clean -- an invisible false negative. Refuse instead."""
    assert MA.body_with("not json at all", "admin", True) == ""
    assert MA.body_with(None, "admin", True) == ""
    assert MA.body_with({"a": 1}, "", True) == ""


def test_body_from_params_honours_the_declared_types_and_ignores_non_body_params():
    """The Q-031 typed body parameters. MEASURED on VAmPI's live spec: POST /users/v1/register
    declares email/password/username as body strings, and PUT /users/v1/{username}/email declares a
    PATH parameter that must never end up in the body."""
    body = MA.body_from_params([
        {"name": "email", "location": "body", "type": "string"},
        {"name": "count", "location": "body", "type": "integer"},
        {"name": "flag", "location": "body", "type": "boolean"},
        {"name": "username", "location": "path", "type": "string"},
    ], marker="apolaki_ma_x")
    assert set(body) == {"email", "count", "flag"}
    assert body["count"] == 1 and body["flag"] is False
    assert "apolaki_ma_x" in body["email"]


def test_body_from_params_returns_empty_when_the_operation_declares_no_body():
    assert MA.body_from_params([]) == {}
    assert MA.body_from_params([{"name": "q", "location": "query", "type": "string"}]) == {}


# ══ locating OUR object in a re-read ═══════════════════════════════════════════════════════════

def test_locates_our_object_inside_a_keyed_collection():
    """The VAmPI `_debug` shape. Two other users in the same list carry admin=True; the oracle must
    read OUR row, not the first true one it meets."""
    obj = MA.locate_object(VAMPI_DEBUG, "username", "apolaki_ma_aabbcc")
    assert obj is not None and obj["email"] == "victim@example.com"
    assert MA.read_field(obj, "admin") == (True, True)


def test_locates_our_object_inside_an_envelope():
    obj = MA.locate_object(JUICE_USER, "email", "apolaki_ma_18708@example.com")
    assert obj is not None and obj["role"] == "admin"


def test_a_view_without_our_object_locates_nothing():
    assert MA.locate_object(VAMPI_DEBUG, "username", "somebody_else") is None


def test_locating_without_a_key_returns_nothing_rather_than_the_first_object():
    """Without a key we cannot prove the object we read is the one we wrote. 'An' object is not
    proof, and an empty key is a real input, not a missing one."""
    assert MA.locate_object(VAMPI_DEBUG, "username", "") is None
    assert MA.locate_object(VAMPI_DEBUG, "", "apolaki_ma_aabbcc") is None
    assert MA.locate_object(JUICE_USER, "id", None) is None


def test_a_non_json_or_empty_response_locates_nothing():
    assert MA.locate_object("<html>404</html>", "id", "24") is None
    assert MA.locate_object("", "id", "24") is None


def test_read_field_reports_found_separately_from_value():
    """A field holding False/0/"" is a real observation; `if value:` would erase it, and the VAmPI
    baseline IS `admin: false`."""
    assert MA.read_field({"admin": False}, "admin") == (True, False)
    assert MA.read_field({"balance": 0}, "balance") == (True, 0)
    assert MA.read_field({"role": ""}, "role") == (True, "")
    assert MA.read_field({}, "admin") == (False, None)


def test_read_field_matches_across_naming_conventions():
    assert MA.read_field({"isAdmin": True}, "is_admin") == (True, True)
    assert MA.read_field({"IS_ADMIN": True}, "isAdmin") == (True, True)


def test_exposed_fields_reports_only_what_this_view_actually_shows():
    """This is how the read view is chosen -- against the BASELINE object, before any injected value
    exists, so the choice cannot be result-shopping."""
    baseline = MA.locate_object(VAMPI_DEBUG, "username", "name1")
    assert MA.exposed_fields(baseline, ["admin", "role", "isVerified"]) == {"admin": False}
    thin = MA.locate_object(VAMPI_USER, "username", "apolaki_ma_aabbcc")
    assert MA.exposed_fields(thin, ["admin", "role"]) == {}


# ══ value comparison ═══════════════════════════════════════════════════════════════════════════

def test_a_boolean_matches_its_storage_forms():
    """An ORM over SQLite hands back 1 for True; a form API hands back "true"."""
    for stored in (True, 1, "1", "true", "True", "yes", "on"):
        assert MA.same_value(True, stored), stored
    for stored in (False, 0, "0", "false", "no"):
        assert not MA.same_value(True, stored), stored


def test_a_non_boolean_send_never_matches_a_stored_boolean():
    """The widening applies ONLY to a bool we sent. Otherwise an integer field set to 1 would match
    a boolean True elsewhere in the object and manufacture a confirmation out of a type
    coincidence."""
    assert not MA.same_value(1, True)
    assert not MA.same_value("1", True)
    assert not MA.same_value("admin", True)


def test_strings_compare_case_insensitively_but_not_loosely():
    assert MA.same_value("admin", "Admin")
    assert MA.same_value("admin", " admin ")
    assert not MA.same_value("admin", "administrator")
    assert not MA.same_value("admin", "customer")


# ══ the finding: controls are ARTIFACTS, values are FIELDS ═════════════════════════════════════

def _finding():
    v = MA.evaluate(**_confirming_case())
    return MA.mass_assignment_finding(
        target="http://lab:5000/users/v1/register", method="POST", verdict=v,
        why="the bare administrator boolean",
        read_url="http://lab:5000/users/v1/_debug",
        control_evidence=("the same write carrying 'apolaki_probe_deadbeef' returned HTTP 200 and the "
                          "invented attribute was ABSENT from the re-read"),
        baseline_evidence="an object created with no extra attribute read back admin=False",
        object_key="username", object_value="apolaki_ma_aabbcc",
        offered_fields=["email", "password", "username"])


def test_the_finding_carries_a_recorded_control_artifact_under_a_proof_schema_control_key():
    f = _finding()
    assert any(k in f and f[k] for k in proof_schema.CONTROL_KEYS)
    kinds = {c["kind"] for c in f["negative_controls"]}
    assert kinds == {"ignored-field control", "baseline control"}
    for c in f["negative_controls"]:
        assert c["result"].strip(), "a control record with no result is a claim, not an artifact"


def test_the_finding_passes_the_platform_proof_gate():
    ok, missing = proof_schema.validate_confirmed(_finding())
    assert ok, missing


def test_the_finding_would_also_satisfy_the_stricter_access_control_proof_rules():
    """`report.py` renders mass_assignment as 'Broken object-level authorization' and
    `benchmark.py` maps it to access_control, so the evidence must carry access-control-grade
    signals even though `family_of` routes it to the default rules."""
    f = dict(_finding(), family="access_control")
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, missing


def test_values_are_bound_as_fields_and_never_only_in_prose():
    """Bind the value, never parse it back out of a rendered sentence."""
    f = _finding()
    assert f["param"] == "admin"
    assert f["injected_value"] is True
    assert f["observed_value"] is True
    assert f["baseline_value"] is False
    assert f["baseline_present"] is True
    assert f["method"] == "POST"
    assert f["read_url"].endswith("/users/v1/_debug")
    assert f["object_key"] == "username" and f["object_value"] == "apolaki_ma_aabbcc"


def test_the_finding_records_the_state_it_created_so_an_operator_can_undo_it():
    f = _finding()
    assert "apolaki_ma_aabbcc" in f["state_created"]
    assert "delete" in f["state_created"].lower()


def test_the_evidence_names_the_separate_reread_and_both_controls():
    ev = _finding()["evidence"]
    assert "SEPARATE re-read" in ev
    assert "NEGATIVE CONTROL 1" in ev and "NEGATIVE CONTROL 2" in ev
    assert "apolaki_probe_deadbeef" in ev


def test_the_cvss_score_matches_its_own_vector():
    """Nothing in the report pipeline recomputes a v3.1 score -- `report.check_report_honesty` is
    cited by two modules and does not exist -- so the arithmetic is pinned here.
    ISS = 1-(1-0.56)(1-0.56) = 0.8064; Impact = 6.42*0.8064 = 5.1771;
    Exploitability = 8.22*0.85(AV:N)*0.77(AC:L)*0.62(PR:L)*0.85(UI:N) = 2.8353; roundup(8.0124) = 8.1
    """
    assert MA._CVSS_VECTOR == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    iss = 1 - (1 - 0.56) * (1 - 0.56) * (1 - 0.0)
    impact = 6.42 * iss
    expl = 8.22 * 0.85 * 0.77 * 0.62 * 0.85
    import math
    expected = math.ceil(min(impact + expl, 10.0) * 10) / 10.0
    assert abs(MA._CVSS_SCORE - expected) < 0.05, (MA._CVSS_SCORE, expected)


# ══ the lead ═══════════════════════════════════════════════════════════════════════════════════

def test_an_unproven_write_produces_a_lead_that_is_not_confirmed():
    v = MA.evaluate(**_confirming_case(reread_ran=False, after={"found": False, "value": None}))
    lead = MA.unverified_lead(target="http://lab/api/x", method="POST", verdict=v,
                              read_url="", control_evidence="did not run",
                              baseline_evidence="did not run")
    assert lead["confidence"] == "lead"
    assert not proof_schema.is_confirmed(lead)
    assert lead["severity"] == "info"
    # a lead carries its controls too, so the report never prints an unbacked control sentence
    assert any(k in lead and lead[k] for k in proof_schema.CONTROL_KEYS)


def test_a_lead_never_claims_the_write_proved_anything():
    v = MA.evaluate(**_confirming_case(control=_ctl(ran=False)))
    lead = MA.unverified_lead(target="http://lab/api/x", method="POST", verdict=v, read_url="/x",
                              control_evidence="did not run", baseline_evidence="ok")
    assert "not proof" in lead["evidence"]
    assert "NOT established" in lead["impact"] or "Not established" in lead["impact"]


# ══ nonce / marker hygiene ═════════════════════════════════════════════════════════════════════

def test_the_control_attribute_name_is_fresh_per_endpoint():
    a, b = MA.control_field(MA.new_nonce()), MA.control_field(MA.new_nonce())
    assert a != b
    assert a.startswith(MA.CONTROL_PREFIX)


def test_an_empty_nonce_still_yields_a_name_no_application_defines():
    assert MA.control_field("") == MA.CONTROL_PREFIX
    assert MA.control_field(None) == MA.CONTROL_PREFIX


def test_markers_are_unique():
    assert MA.new_marker() != MA.new_marker()
