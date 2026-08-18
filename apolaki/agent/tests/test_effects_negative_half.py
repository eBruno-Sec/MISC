"""Q-074 - the NEGATIVE half of the effects model, and the guards that must keep catching a phantom.

Q-007 removed `weak_password_reset`, which had no executor and generated all six rows of
`conflicts()`. That left `conflicts()` empty, and **an empty model and a correct model produce the
same plan for different reasons**. Q-074 asks for a real invalidation, MEASURED rather than asserted.

THE MEASUREMENT, and it does not name the engine the ticket named. Full apparatus and raw output in
`docs/handoff/effects2.md` sections 2-3; the two results this file pins:

  * `session_lifecycle` was DRIVEN over real HTTP against the shipped `sessionlife` lab with a real
    mission session held by a different account. It confirmed the vulnerable mount, declined the
    secure one, named the sacrificial identity it minted, and every engagement-state field
    (`session_headers`, `_sessions`, `_session_state`, `state.capabilities`) was identical before and
    after while the mission credential still reached the authenticated marker. Positive control on
    the same instrument: a direct logout moved it (200, True) -> (401, False). It gets NO entry.

  * `race_condition` / `run_race` DOES end the engagement's session. `tools._SESSION_KILL_RE` has
    exactly one use site (`_add_urls`), and `recon["forms"]` is a second, unfiltered door that
    `planner.py:616-623` turns into `run_race` steps carrying `self.session_headers`. Measured
    end-to-end the mission session went (200, True) -> (401, False) while `session_headers` still
    held the dead cookie. Re-measured on a form the session-kill regex does NOT match and could not
    match without disabling the engine - a credential-rotation form - so the effect survives the fix
    for that adjacent defect; a harmless form on the same probe left the session up.

THE NEGATIVE CONTROLS COME FIRST AND WERE RUN FIRST, against the tree with `EFFECTS` still empty of
negative effects. A guard written against an empty set is the easiest kind to satisfy vacuously, and
this codebase has shipped a guard that checks a declaration instead of a fact eight times. So every
clean-sheet assertion below is preceded by one proving the same apparatus rejects a dirty table -
including a negative effect declared on an engine MEASURED to have no route at all.
"""
import copy

import effect_search as es
import engine_descriptor as ed
import tools as TL

# MEASURED 2026-08-18, `ed.routing_audit()["unrouted"]`. Techniques the platform can rank and cannot
# dispatch. Used as the source of a DELIBERATELY UNROUTED engine for the controls below, so the
# control is armed from the tree's own facts rather than from an invented name.
UNROUTED_2026_08_18 = [
    "business_logic_abuse", "crlf_injection", "encoded_data_decode", "exposed_credentials",
    "security_misconfig_errors", "soft_deleted_login", "vulnerable_component", "waf_bypass",
    "weak_2fa_bypass", "weak_password_reset", "weak_secret_forgery",
]

# MEASURED: the techniques whose preconditions include `authenticated`. These are exactly the
# consumers a negative effect on `authenticated` must be reported against.
AUTHENTICATED_CONSUMERS = [
    "cache_deception", "jwt_forge", "jwt_key_confusion", "session_fixation",
    "session_lifecycle", "weak_2fa_bypass",
]


# ── NEGATIVE CONTROLS ───────────────────────────────────────────────────────────────────────────

def test_the_guard_still_fails_on_a_phantom_negative_effect_with_a_real_one_present():
    """THE control this ticket exists for. Q-007's guard was written when `invalidates` was empty
    everywhere; a real row must not make it lenient. Same guard, same table, one phantom added."""
    mut = copy.deepcopy(ed.EFFECTS)
    mut["weak_password_reset"] = {"establishes": ["authenticated"],
                                  "invalidates": ["authenticated"],
                                  "engine": ["run_weak_password_reset"]}
    a = ed.effects_audit(effects=mut)
    assert a["ok"] is False
    assert a["unregistered"] == ["weak_password_reset -> run_weak_password_reset"]
    assert a["unimplemented"] == ["weak_password_reset -> run_weak_password_reset"]
    # and the real row is still verified in the SAME pass, so the failure is the phantom's alone
    assert a["verified"].get("race_condition") == ["run_race"], a["verified"]


def test_the_guard_fails_on_a_negative_effect_declared_on_a_deliberately_unrouted_engine():
    """The instruction, taken literally: prove the guard rejects a negative effect on an engine the
    tree has MEASURED to have no route, before trusting it to pass on one that does.

    `business_logic_abuse` is a real, ranked technique with a real precondition and no dispatchable
    engine. Declaring that it destroys `authenticated` is precisely the shape of the defect Q-007
    closed, and it must be caught with no `engine` key AND with an invented one."""
    unrouted = ed.routing_audit()["unrouted"]
    assert unrouted == UNROUTED_2026_08_18, \
        "the unrouted set moved; re-measure before trusting this control (%r)" % (unrouted,)
    victim = "business_logic_abuse"
    assert victim in unrouted and victim not in ed.EFFECTS

    omitted = copy.deepcopy(ed.EFFECTS)
    omitted[victim] = {"establishes": [], "invalidates": ["authenticated"]}
    a = ed.effects_audit(effects=omitted)
    assert a["ok"] is False and victim in a["no_engine_declared"]

    invented = copy.deepcopy(ed.EFFECTS)
    invented[victim] = {"establishes": [], "invalidates": ["authenticated"],
                        "engine": ["run_business_logic_abuse"]}
    a = ed.effects_audit(effects=invented)
    assert a["ok"] is False
    assert a["unregistered"] == ["business_logic_abuse -> run_business_logic_abuse"]


def test_the_routing_audit_flags_a_phantom_negative_effect_independently(monkeypatch):
    """Two nets, not one. `routing_audit()`'s `phantom` list is the load-bearing invariant the
    platform already ships, and it scans by MEMBERSHIP so a typo cannot slip through the shape
    filter `effects_audit` uses on prose."""
    armed = copy.deepcopy(ed.EFFECTS)
    armed["weak_password_reset"] = {"establishes": [], "invalidates": ["authenticated"],
                                    "engine": ["run_weak_password_reset"]}
    monkeypatch.setattr(ed, "EFFECTS", armed)
    a = ed.routing_audit()
    assert a["ok"] is False
    assert a["phantom"] == ["weak_password_reset (effect_engine) -> run_weak_password_reset"]


def test_the_conflict_walk_reports_an_undispatchable_producer():
    """`conflicts()` is now non-empty, so the walk over it is finally exercised. Control first: a
    conflict row whose producer cannot be dispatched must be visible in the rows the walk returns,
    or the check that reads them proves nothing."""
    d = ed.build()
    d["fake_rotator"] = dict(d["race_condition"], id="fake_rotator", engines=[],
                             establishes=[], invalidates=["authenticated"])
    rows = ed.conflicts(d)
    bad = [(p, o, c) for p, o, c in rows if not d[p]["engines"]]
    assert bad, "the walk cannot see a producer with no engine; the shipped check is vacuous"
    assert {p for p, _, _ in bad} == {"fake_rotator"}


# ── THE SHIPPED TREE ────────────────────────────────────────────────────────────────────────────

def test_race_condition_is_the_only_declared_negative_effect():
    """One entry, and it is the one that was measured. A second appearing without a measurement in
    `docs/handoff/effects2.md` is the over-declaration this module's own rule forbids."""
    negative = sorted(t for t, e in ed.EFFECTS.items() if e.get("invalidates"))
    assert negative == ["race_condition"], negative
    assert ed.EFFECTS["race_condition"]["invalidates"] == ["authenticated"]
    # it establishes NOTHING: a race proves a limit can be bypassed, it does not hand the engagement
    # any observation the vocabulary can express
    assert ed.EFFECTS["race_condition"]["establishes"] == []


def test_the_negative_effect_names_an_engine_that_is_registered_and_implemented():
    assert ed.EFFECTS["race_condition"]["engine"] == ["run_race"]
    assert "run_race" in TL.TOOL_PERMISSIONS
    assert "run_race" in ed.engine_implementations()
    assert "run_apolaki_not_an_engine" not in TL.TOOL_PERMISSIONS, "membership test is not vacuous"
    assert ed.effects_audit()["verified"]["race_condition"] == ["run_race"]


def test_conflicts_are_exactly_the_techniques_that_require_authentication():
    """The Sussman half, now populated. Every consumer of `authenticated` is reported, and nothing
    else is — a row naming a technique that does not require it would be the walk inventing edges."""
    d = ed.build()
    rows = ed.conflicts(d)
    assert [c for _, _, c in rows] == AUTHENTICATED_CONSUMERS, rows
    assert {p for p, _, _ in rows} == {"race_condition"}
    assert {o for _, o, _ in rows} == {"authenticated"}
    for _p, _o, c in rows:
        assert "authenticated" in d[c]["requires"], c


def test_every_conflict_row_names_a_dispatchable_engine():
    """The invariant Q-007 reduces to, now exercised on the half that used to be empty."""
    d = ed.build()
    rows = ed.conflicts(d)
    assert rows, "the conflict walk found nothing; this test is not looking at anything"
    for pid, obs, cid in rows:
        assert d[pid]["engines"], "%s destroys %s for %s with no engine" % (pid, obs, cid)
        assert all(e in TL.TOOL_PERMISSIONS for e in d[pid]["engines"]), pid


# ── WHAT THE PLANNER DOES DIFFERENTLY ───────────────────────────────────────────────────────────

def test_breaks_now_reports_the_real_cost_of_running_a_race():
    """`breaks()` answered `[]` for every shipped engine while the model was empty. It is the
    module's per-action §4.4 warning and this is the first true answer it has ever given."""
    d = ed.build()
    obs = {"has_login", "authenticated", "serves_js"}
    cost = es.breaks(d, obs, "race_condition")
    assert cost == [t for t in AUTHENTICATED_CONSUMERS if t in es.applicable(d, obs)], cost
    assert "jwt_forge" in cost and "session_lifecycle" in cost
    # NEGATIVE CONTROL on the same call: an engine with no negative effect still costs nothing
    assert es.breaks(d, obs, "sqli_auth_bypass") == []
    # and the cost is CONDITIONAL on the observation being held in the first place
    assert es.breaks(d, {"has_login", "serves_js"}, "race_condition") == []


def test_successor_actually_removes_the_observation():
    d = ed.build()
    after = es.successor(d, {"has_login", "authenticated"}, "race_condition")
    assert after == frozenset({"has_login"})
    assert es.successor(d, {"has_login"}, "sqli_auth_bypass") == frozenset({"has_login",
                                                                           "authenticated"})


def test_the_frontier_reports_the_cost_of_an_always_on_engine():
    """The gap that made the entry decoration until it was closed, and it PREDATES this ticket.

    `frontier()["consequences"]` was keyed off `applicable_now`, and `applicable()` returns only
    engines with a NON-EMPTY precondition list — so an always-on engine could never appear there no
    matter what it establishes or destroys. MEASURED: that already silently dropped
    `browser_persona_bola` and `graphql_introspection`, 2 of the 11 existing entries, and it would
    have dropped the only negative effect in the model. `_plan_core` has always treated an always-on
    action as available in every state; this makes the decision surface agree with the search."""
    d = ed.build()
    f = es.frontier(d, {"has_login", "authenticated", "serves_js"})
    assert "race_condition" in f["consequences"], sorted(f["consequences"])
    assert "jwt_forge" in f["consequences"]["race_condition"]["breaks"]
    # the two pre-existing entries the same gap was dropping
    assert {"browser_persona_bola", "graphql_introspection"} <= set(f["consequences"])
    # `applicable_now` is UNCHANGED: it is the precondition filter's answer and this ticket does not
    # touch it. The always-on entries are listed separately so a consumer can tell them apart.
    assert "race_condition" not in f["applicable_now"]
    assert set(f["always_on_with_effects"]) == set(f["consequences"]) - set(f["applicable_now"])
    # NEGATIVE CONTROL: an always-on engine with NO declared effect is still absent — the fix widens
    # the surface by effects, not by always-on-ness
    assert "dom_xss" in ed.ALWAYS_ON and "dom_xss" not in ed.EFFECTS
    assert "dom_xss" not in f["consequences"]


def test_the_plan_search_is_deliberately_UNCHANGED_by_the_negative_effect():
    """Said rather than hidden. `plan()` records a candidate only when the goal appears in a
    successor state, and `race_condition` establishes nothing, so it can never shorten a plan — it
    can only add expansions. The entry changes `conflicts()`, `breaks()` and the frontier's
    consequences; it does NOT change any plan, and claiming otherwise would be the decoration this
    ticket warns about."""
    d = ed.build()
    for goal in ("authenticated", "credentials_exposed", "has_object_id"):
        r = es.plan(d, {"has_login", "serves_js"}, goal)
        assert "race_condition" not in r["plan"], (goal, r)
    r = es.plan(d, {"has_login"}, "authenticated")
    assert r["reachable"] and r["plan"] == ["sqli_auth_bypass"], r
