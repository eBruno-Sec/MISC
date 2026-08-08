"""Browser Intelligence Engine (#124) — the pure layer: hypothesis forming, THE ORACLE, evidence.

The oracle is the crown jewel: the browser performs the attempt, this decides truth. Every rejection
path below is a false positive that would otherwise ship.
"""
import bie


def _ex(status, body, url="http://t/rest/basket/1"):
    return bie.exchange(url, status, body)


OBJ = '{"id":1,"owner":"alice","items":[{"sku":"A-1","qty":2}]}'
OTHER = '{"id":2,"owner":"bob","items":[]}'
SHELL = "<html><body><app-root></app-root></body></html>"


# ── hypothesis forming ────────────────────────────────────────────────────────
def test_object_template_extracts_terminal_id():
    t, i = bie.object_template("http://t/rest/basket/12?x=1")
    assert t == "http://t/rest/basket/{id}" and i == "12"
    t, i = bie.object_template("http://t/api/orders/8f14e45f-ceea-467a-9c3a-1f2b3c4d5e6f")
    assert t == "http://t/api/orders/{id}"


def test_object_template_ignores_non_id_paths():
    assert bie.object_template("http://t/rest/basket")[0] is None
    assert bie.object_template("http://t/assets/main.js")[0] is None
    assert bie.object_template("http://t/")[0] is None


def test_swap_url_changes_only_the_id():
    assert bie.swap_url("http://t/rest/basket/1", "7") == "http://t/rest/basket/7"
    assert bie.swap_url("http://t/rest/basket", "7") is None


def test_object_candidates_pairs_same_template_different_id():
    cands = bie.object_candidates(["http://t/rest/basket/1", "http://t/assets/a.js"],
                                  ["http://t/rest/basket/2"])
    assert len(cands) == 1
    assert cands[0]["owner_id"] == "1" and cands[0]["attacker_id"] == "2"


def test_object_candidates_skips_identical_ids():
    # both personas hit the SAME object -> nothing cross-user to prove
    assert bie.object_candidates(["http://t/rest/basket/1"], ["http://t/rest/basket/1"]) == []


# ── THE ORACLE ────────────────────────────────────────────────────────────────
def test_confirms_only_with_identical_body_and_both_controls():
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=_ex(401, ""), nonexistent=_ex(404, ""),
                  control=_ex(200, OTHER))
    assert v["verdict"] == "confirmed"


def test_rejects_when_authorization_is_enforced():
    v = bie.judge(_ex(200, OBJ), _ex(403, ""), anon=_ex(401, ""), nonexistent=_ex(404, ""))
    assert v["verdict"] == "rejected" and "authorization enforced" in v["reason"]


def test_rejects_when_attacker_body_differs():
    v = bie.judge(_ex(200, OBJ), _ex(200, OTHER), anon=_ex(401, ""), nonexistent=_ex(404, ""))
    assert v["verdict"] == "rejected"


def test_rejects_public_resource():
    # anonymous gets the identical body -> nothing was bypassed
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=_ex(200, OBJ), nonexistent=_ex(404, ""))
    assert v["verdict"] == "rejected" and "PUBLIC" in v["reason"]


def test_rejects_spa_shell_catch_all():
    # every id returns the same SPA shell -> the route is not object-specific
    v = bie.judge(_ex(200, SHELL), _ex(200, SHELL), anon=_ex(401, ""), nonexistent=_ex(200, SHELL))
    assert v["verdict"] == "rejected" and "not object-specific" in v["reason"]


def test_rejects_indistinguishable_objects():
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=_ex(401, ""), nonexistent=_ex(404, ""),
                  control=_ex(200, OBJ))
    assert v["verdict"] == "rejected" and "not distinguishable" in v["reason"]


def test_missing_negative_control_is_a_lead_never_a_confirmation():
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=None, nonexistent=_ex(404, ""))
    assert v["verdict"] == "lead"
    v = bie.judge(_ex(200, OBJ), _ex(200, OBJ), anon=_ex(401, ""), nonexistent=None)
    assert v["verdict"] == "lead"


def test_not_applicable_when_owner_has_no_object():
    assert bie.judge(_ex(404, ""), _ex(200, OBJ))["verdict"] == "not_applicable"
    assert bie.judge(_ex(200, "{}"), _ex(200, "{}"))["verdict"] == "not_applicable"


# ── evidence + finding ────────────────────────────────────────────────────────
def _confirmed():
    cand = {"template": "http://t/rest/basket/{id}", "owner_url": "http://t/rest/basket/1",
            "owner_id": "1", "attacker_url": "http://t/rest/basket/2", "attacker_id": "2"}
    probes = {"baseline": _ex(200, OBJ), "mutation": _ex(200, OBJ), "anon": _ex(401, ""),
              "nonexistent": _ex(404, ""), "control": _ex(200, OTHER)}
    return cand, probes, bie.judge(probes["baseline"], probes["mutation"], anon=probes["anon"],
                                   nonexistent=probes["nonexistent"], control=probes["control"])


def test_finding_is_confirmed_bola_with_browser_evidence():
    cand, probes, v = _confirmed()
    f = bie.finding(cand, probes, v, owner="user_a", attacker="user_b")
    assert f["confidence"] == "confirmed" and f["family"] == "bola" and f["cwe"] == "CWE-639"
    ev = f["browser_evidence"]
    assert ev["exact_request"]["url"] == "http://t/rest/basket/1"
    assert set(ev["negative_controls"]) == {"anon", "nonexistent", "control"}
    assert "curl" in ev["replay_script"] and "1. baseline" in ev["replay_script"]
    assert len(ev["reproduction_steps"]) == 6


def test_confirmed_findings_satisfy_the_platform_proof_contract():
    """A CONFIRMED finding that fails proof_schema is silently demoted to a lead in the report — the
    strongest evidence in the engagement would then be presented as a guess. Regression guard for both
    BIE producers (the live run caught exactly this: a missing `impact`)."""
    import proof_schema
    cand, probes, v = _confirmed()
    f = bie.finding(cand, probes, v, owner="user_a", attacker="user_b")
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, "persona-swap BOLA finding fails the proof contract: %s" % missing
    assert proof_schema.demote_unproven([f])[0]["confidence"] == "confirmed"

    ctl = {**_ctl(), "probe_url": "http://t/admin/users", "hint": "admin"}
    cprobes = {"persona": _ex(200, ADMIN_PAGE), "anon": _ex(401, ""), "shell": _ex(200, SHELL)}
    cv = bie.judge_client_side_authz(ctl, cprobes["persona"], anon=cprobes["anon"], shell=cprobes["shell"])
    cf = bie.finding_client_side_authz(ctl, cprobes, cv, persona="user_b")
    ok2, missing2 = proof_schema.validate_confirmed(cf)
    assert ok2, "client-side-authz finding fails the proof contract: %s" % missing2
    assert proof_schema.demote_unproven([cf])[0]["confidence"] == "confirmed"


def test_lead_verdict_produces_a_lead_finding():
    cand, probes, _ = _confirmed()
    v = bie.judge(probes["baseline"], probes["mutation"], anon=None, nonexistent=probes["nonexistent"])
    f = bie.finding(cand, probes, v)
    assert f["confidence"] == "lead" and f["severity"] == "medium"


def test_evidence_never_leaks_session_secrets():
    h = {"Authorization": "Bearer supersecrettoken", "Cookie": "token=abc", "Accept": "application/json"}
    r = bie.redact_headers(h)
    assert r["Authorization"] == "<redacted>" and r["Cookie"] == "<redacted>"
    assert r["Accept"] == "application/json"
    ex = bie.exchange("http://t/x", 200, "body", h)
    assert "supersecrettoken" not in str(ex)
    cand, probes, v = _confirmed()
    assert "supersecrettoken" not in str(bie.browser_evidence(cand, probes, v))


def test_replay_script_uses_the_owner_url_and_the_implausible_id_control():
    cand, _, _ = _confirmed()
    s = bie.replay_script(cand)
    assert "http://t/rest/basket/1" in s and "http://t/rest/basket/%s" % bie._IMPLAUSIBLE_ID in s


# ── client-supplied identity parameters (route-interception tampering) ────────
MINE = '{"user":"alice","orders":[{"id":1,"total":10}]}'
THEIRS = '{"user":"bob","orders":[{"id":2,"total":99}]}'


def test_identity_params_finds_only_identity_bearing_params():
    got = dict(bie.identity_params("http://t/api/orders?userId=42&page=2&sort=asc"))
    assert got == {"userId": "42"}
    assert bie.identity_params("http://t/api/orders?page=2") == []


def test_mutate_param_changes_exactly_one_variable():
    u = bie.mutate_param("http://t/api/orders?userId=42&page=2", "userId", "43")
    assert "userId=43" in u and "page=2" in u


def test_same_endpoint_ignores_the_query():
    assert bie.same_endpoint("http://t/api/o?a=1", "http://t/api/o?a=2")
    assert not bie.same_endpoint("http://t/api/o", "http://t/api/p")


def test_param_candidates_need_two_personas_sending_different_values():
    c = bie.param_candidates(["http://t/api/orders?userId=42"], ["http://t/api/orders?userId=43"])
    assert len(c) == 1 and c[0]["param"] == "userId"
    assert c[0]["owner_value"] == "42" and c[0]["attacker_value"] == "43"
    # same value for both personas => not identity-scoped => no hypothesis
    assert bie.param_candidates(["http://t/api/o?userId=1"], ["http://t/api/o?userId=1"]) == []


def test_param_swap_confirms_only_when_the_other_persona_data_comes_back():
    v = bie.judge_param_swap(_ex(200, MINE), _ex(200, THEIRS), _ex(200, THEIRS), anon=_ex(401, ""))
    assert v["verdict"] == "confirmed"


def test_param_swap_rejects_the_SECURE_case_of_a_server_ignoring_the_param():
    v = bie.judge_param_swap(_ex(200, MINE), _ex(200, THEIRS), _ex(200, MINE), anon=_ex(401, ""))
    assert v["verdict"] == "rejected" and "SECURE" in v["reason"]


def test_param_swap_rejects_public_content_and_indistinguishable_personas():
    assert bie.judge_param_swap(_ex(200, MINE), _ex(200, THEIRS), _ex(200, THEIRS),
                                anon=_ex(200, THEIRS))["verdict"] == "rejected"
    assert bie.judge_param_swap(_ex(200, MINE), _ex(200, MINE), _ex(200, MINE))["verdict"] == "not_applicable"


def test_param_swap_third_outcome_is_a_lead_not_a_confirmation():
    v = bie.judge_param_swap(_ex(200, MINE), _ex(200, THEIRS), _ex(200, '{"user":"carol"}'))
    assert v["verdict"] == "lead"


def test_param_swap_finding_satisfies_the_proof_contract_and_names_the_variable():
    import proof_schema
    cand = {"template": "http://t/api/orders", "param": "userId", "owner_url": "http://t/api/orders?userId=42",
            "owner_value": "42", "attacker_url": "http://t/api/orders?userId=43", "attacker_value": "43"}
    probes = {"self_baseline": _ex(200, MINE), "other_baseline": _ex(200, THEIRS),
              "mutation": {**_ex(200, THEIRS), "param": "userId"}, "anon": _ex(401, "")}
    v = bie.judge_param_swap(probes["self_baseline"], probes["other_baseline"], probes["mutation"],
                             anon=probes["anon"])
    f = bie.finding_param_swap(cand, probes, v, owner="user_a", attacker="user_b",
                               mutation_method="route-interception")
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, missing
    mv = f["browser_evidence"]["mutated_variable"]
    assert mv == {"param": "userId", "from": "42", "to": "43", "method": "route-interception"}


# ── client-side control surface (CWE-602) ─────────────────────────────────────
ADMIN_PAGE = '{"users":[{"id":1,"email":"a@t"},{"id":2,"email":"b@t"}],"roles":["admin","user"]}'


def _ctl(**kw):
    base = {"tag": "a", "text": "Admin panel", "href": "/admin/users", "resolved": "http://t/admin/users",
            "routerlink": "", "id": "", "name": "", "visible": False, "disabled": False,
            "reason": "not-displayed"}
    return {**base, **kw}


def test_classify_splits_offered_from_withheld():
    c = bie.classify_controls([_ctl(hidden_by="self"), _ctl(visible=True, reason=""),
                               _ctl(visible=True, disabled=True, reason="disabled")])
    assert c["counts"]["offered"] == 1 and c["counts"]["withheld"] == 2
    assert c["counts"]["withheld_privileged"] == 2      # both mention "admin"/"user"


def test_a_control_in_a_collapsed_menu_is_not_withheld():
    """The user opens the hamburger and it is there. Counting it as withheld would flag every menu item
    in every SPA as a potential authorization bug — observed live on Juice Shop's closed side nav."""
    c = bie.classify_controls([_ctl(hidden_by="collapsed-container")])
    assert c["counts"]["collapsed"] == 1 and c["counts"]["withheld"] == 0
    assert bie.probe_targets(c, "http://t") == []


def test_a_disabled_control_stays_withheld_even_inside_a_menu():
    # disabled is an explicit refusal by the app, not merely "the container is closed"
    c = bie.classify_controls([_ctl(hidden_by="collapsed-container", disabled=True, reason="disabled")])
    assert c["counts"]["withheld"] == 1 and c["counts"]["collapsed"] == 0


def test_privilege_hint_ranks_only_privileged_words():
    assert bie.privilege_hint(_ctl(text="Admin panel", href="/x")) == "admin"
    assert bie.privilege_hint(_ctl(text="Home", href="/home", id="", name="")) == ""


def test_probe_targets_excludes_client_routes_and_unsafe_controls():
    cs = bie.classify_controls([
        _ctl(text="Admin", href="/admin/users", resolved="http://t/admin/users"),
        _ctl(text="Admin SPA", href="#/administration", resolved=""),
        _ctl(text="Delete user", tag="button", href="", resolved=""),
        _ctl(text="Manage", href="javascript:void(0)", resolved=""),
    ])
    got = [t["probe_url"] for t in bie.probe_targets(cs, "http://t")]
    assert got == ["http://t/admin/users"], "only real server resources may be auto-probed"


def test_client_side_authz_confirms_when_server_serves_a_withheld_control():
    v = bie.judge_client_side_authz(_ctl(), _ex(200, ADMIN_PAGE), anon=_ex(401, ""), shell=_ex(200, SHELL))
    assert v["verdict"] == "confirmed"


def test_client_side_authz_rejects_when_server_also_enforces():
    v = bie.judge_client_side_authz(_ctl(), _ex(403, ""), anon=_ex(401, ""), shell=_ex(200, SHELL))
    assert v["verdict"] == "rejected" and "enforced" in v["reason"]


def test_client_side_authz_rejects_the_spa_shell():
    v = bie.judge_client_side_authz(_ctl(), _ex(200, SHELL), anon=_ex(401, ""), shell=_ex(200, SHELL))
    assert v["verdict"] == "rejected" and "shell" in v["reason"]


def test_client_side_authz_rejects_public_content():
    v = bie.judge_client_side_authz(_ctl(), _ex(200, ADMIN_PAGE), anon=_ex(200, ADMIN_PAGE),
                                    shell=_ex(200, SHELL))
    assert v["verdict"] == "rejected" and "PUBLIC" in v["reason"]


def test_client_side_authz_not_applicable_when_the_ui_offers_the_control():
    v = bie.judge_client_side_authz(_ctl(visible=True, reason=""), _ex(200, ADMIN_PAGE))
    assert v["verdict"] == "not_applicable"


def test_client_side_authz_missing_shell_control_is_a_lead():
    v = bie.judge_client_side_authz(_ctl(), _ex(200, ADMIN_PAGE), anon=_ex(401, ""), shell=None)
    assert v["verdict"] == "lead"


def test_client_side_authz_finding_shape():
    ctl = {**_ctl(), "probe_url": "http://t/admin/users", "hint": "admin"}
    probes = {"persona": _ex(200, ADMIN_PAGE), "anon": _ex(401, ""), "shell": _ex(200, SHELL)}
    v = bie.judge_client_side_authz(ctl, probes["persona"], anon=probes["anon"], shell=probes["shell"])
    f = bie.finding_client_side_authz(ctl, probes, v, persona="user_b")
    assert f["cwe"] == "CWE-602" and f["confidence"] == "confirmed"
    assert f["browser_evidence"]["control"]["reason"] == "not-displayed"
    assert "curl" in f["browser_evidence"]["replay_script"]


# ── runtime -> planner vocabulary (no second brain) ───────────────────────────
def test_to_observations_maps_runtime_onto_the_planner_vocabulary():
    import technique_planner as tp
    obs = bie.to_observations({"browser": True, "requests": [
        "http://t/main.js", "http://t/rest/basket/1", "http://t/rest/user/login", "http://t/admin/panel"]})
    assert {"serves_js", "has_api", "has_login", "has_object_id", "has_sensitive_route"} <= obs
    assert obs <= set(tp.OBSERVATIONS), "BIE must speak the EXISTING observation vocabulary"


def test_to_observations_empty_when_no_browser():
    assert bie.to_observations({"browser": False}) == set()
    assert bie.to_observations(None) == set()


# ── graceful degradation ──────────────────────────────────────────────────────
def test_run_persona_swap_degrades_when_out_of_scope():
    r = bie.run_persona_swap("http://evil.example", owner_headers={}, attacker_headers={},
                             scope_ok=lambda u: False)
    assert r["ran"] is False and r["findings"] == [] and "scope" in r["note"]


def test_observe_degrades_without_a_base_url():
    r = bie.observe("")
    assert r["ran"] is False and r["requests"] == []
