"""Forward search over effects (T8) — Automated Planning §4.2 (successor + goal test) and §4.4 (deleted
conditions).

Two kinds of test here, deliberately separated:

  * SYNTHETIC descriptors, where the expected plan is arithmetic and the Sussman case can be constructed
    exactly. These assert the algorithm.
  * The SHIPPED registry, asserting the search says something true about Apolaki specifically.

The synthetic half matters because the shipped registry could accidentally satisfy a weak test — a search
that ignored negative effects entirely would still pass most real-registry assertions.
"""
import effect_search as es
import engine_descriptor as ed


def _d(tid, requires=(), establishes=(), invalidates=()):
    return {"id": tid, "requires": list(requires), "establishes": list(establishes),
            "invalidates": list(invalidates), "permission": "passive", "vuln_class": "t",
            "oracle": "o", "always_on": False, "reached_by": "", "auto": True, "transferable": True}


def _reg(*ds):
    return {d["id"]: d for d in ds}


# ── the algorithm, on constructed inputs ───────────────────────────────────────────────────────

def test_goal_already_held_needs_no_plan():
    r = es.plan(_reg(_d("a", establishes=["x"])), {"x"}, "x")
    assert r["reachable"] and r["plan"] == [] and r["depth"] == 0


def test_single_step_plan():
    reg = _reg(_d("login_bypass", requires=["has_login"], establishes=["authenticated"]))
    r = es.plan(reg, {"has_login"}, "authenticated")
    assert r["reachable"] and r["plan"] == ["login_bypass"] and r["depth"] == 1


def test_multi_step_chain_is_found_in_order():
    """The answer the precondition filter structurally cannot give: the goal is TWO engines away."""
    reg = _reg(
        _d("recon", requires=["serves_js"], establishes=["has_login"]),
        _d("bypass", requires=["has_login"], establishes=["authenticated"]),
        _d("forge", requires=["authenticated"], establishes=["admin"]),
    )
    r = es.plan(reg, {"serves_js"}, "admin")
    assert r["reachable"]
    assert r["plan"] == ["recon", "bypass", "forge"], r


def test_shortest_path_wins_when_two_routes_exist():
    reg = _reg(
        _d("slow_a", requires=["s"], establishes=["m"]),
        _d("slow_b", requires=["m"], establishes=["goal"]),
        _d("fast", requires=["s"], establishes=["goal"]),
    )
    assert es.plan(reg, {"s"}, "goal")["plan"] == ["fast"]


def test_unreachable_goal_is_an_honest_result_not_an_error():
    reg = _reg(_d("a", requires=["s"], establishes=["x"]))
    r = es.plan(reg, {"s"}, "never_produced")
    assert r["reachable"] is False and r["plan"] == []
    assert "no engine sequence" in r["reason"]


def test_an_action_whose_preconditions_fail_is_not_available():
    reg = _reg(_d("gated", requires=["missing"], establishes=["goal"]))
    assert es.plan(reg, {"present"}, "goal")["reachable"] is False


# ── §4.4: negative effects ─────────────────────────────────────────────────────────────────────

def test_successor_applies_deletions_after_additions():
    """THE ordering rule. An engine that establishes and invalidates the same observation must end
    WITHOUT it — get this backwards and the planner emits plans that fail in the field."""
    reg = _reg(_d("reset", establishes=["authenticated"], invalidates=["authenticated"]))
    assert "authenticated" not in es.successor(reg, set(), "reset")


def test_sussman_the_plan_re_establishes_what_an_earlier_step_deleted():
    """Sussman, in Apolaki's vocabulary, and the exact reason concatenating two independent sub-plans is
    unsound: `rotate` achieves `has_token` at the COST of `authenticated`, which `needs_both` requires.

    The correct plan is not [login, rotate, needs_both] — that one fails at the last step. It is
    [login, rotate, login, needs_both]: the deleted condition is re-established. A search that ignored
    `invalidates` would emit the 3-step plan and it would break in the field."""
    reg = _reg(
        _d("login", requires=["has_login"], establishes=["authenticated"]),
        _d("rotate", requires=["authenticated"], establishes=["has_token"], invalidates=["authenticated"]),
        _d("needs_both", requires=["authenticated", "has_token"], establishes=["goal"]),
    )
    r = es.plan(reg, {"has_login"}, "goal")
    assert r["reachable"]
    assert r["plan"] == ["login", "rotate", "login", "needs_both"], r
    # The naive concatenation is genuinely invalid — walk it and the precondition fails.
    naive, state = ["login", "rotate", "needs_both"], frozenset({"has_login"})
    for step in naive[:-1]:
        state = es.successor(reg, state, step)
    assert "authenticated" not in state, "the naive plan's last step has an unmet precondition"


def test_a_goal_is_unreachable_when_nothing_can_re_establish_the_deleted_condition():
    """The other side of §4.4: remove the re-establishing action and the goal really is out of reach."""
    reg = _reg(
        _d("rotate", requires=["authenticated"], establishes=["has_token"], invalidates=["authenticated"]),
        _d("needs_both", requires=["authenticated", "has_token"], establishes=["goal"]),
    )
    assert es.plan(reg, {"authenticated"}, "has_token")["reachable"] is True
    assert es.plan(reg, {"authenticated"}, "goal")["reachable"] is False


def test_breaks_names_what_an_action_would_cost():
    reg = _reg(
        _d("rotate", requires=["authenticated"], establishes=["has_token"], invalidates=["authenticated"]),
        _d("victim", requires=["authenticated"], establishes=["x"]),
    )
    # `rotate` deletes its own precondition, so it is trivially in its own before-minus-after. Reporting
    # that would bury the one conflict that matters for ordering.
    assert es.breaks(reg, {"authenticated"}, "rotate") == ["victim"]


def test_unlocks_names_what_an_action_would_buy():
    reg = _reg(
        _d("bypass", requires=["has_login"], establishes=["authenticated"]),
        _d("forge", requires=["authenticated"], establishes=["x"]),
    )
    assert es.unlocks(reg, {"has_login"}, "bypass") == ["forge"]


# ── determinism + termination ──────────────────────────────────────────────────────────────────

def test_cycles_terminate():
    """jwt_forge and jwt_key_confusion each establish what the other requires — a real cycle in the
    shipped registry, so this is not hypothetical."""
    reg = _reg(
        _d("a", requires=["x"], establishes=["y"]),
        _d("b", requires=["y"], establishes=["x"]),
    )
    assert es.plan(reg, {"x"}, "unreachable")["reachable"] is False


def test_plans_are_reproducible():
    reg = _reg(
        _d("p", requires=["s"], establishes=["m"]),
        _d("q", requires=["s"], establishes=["m"]),
        _d("r", requires=["m"], establishes=["goal"]),
    )
    assert es.plan(reg, {"s"}, "goal") == es.plan(reg, {"s"}, "goal")


def test_max_depth_is_respected():
    reg = _reg(
        _d("s1", requires=["a"], establishes=["b"]),
        _d("s2", requires=["b"], establishes=["c"]),
        _d("s3", requires=["c"], establishes=["d"]),
    )
    assert es.plan(reg, {"a"}, "d", max_depth=3)["reachable"] is True
    assert es.plan(reg, {"a"}, "d", max_depth=2)["reachable"] is False


# ── against the engines Apolaki actually ships ─────────────────────────────────────────────────

def test_shipped_registry_reaches_authenticated_from_a_login_form():
    d = ed.build()
    r = es.plan(d, {"has_login"}, "authenticated")
    assert r["reachable"], r
    assert r["depth"] == 1
    assert d[r["plan"][0]]["establishes"] == ["authenticated"] or \
        "authenticated" in d[r["plan"][0]]["establishes"], r


def test_an_evidence_gated_plan_beats_an_equally_short_assumed_one():
    """Both reach the goal in one step. The gated one is strictly stronger — the assumed one depends on
    configured credentials that are not evidence — so the search must not pick by sort order."""
    reg = _reg(
        _d("aaa_always_on", establishes=["authenticated"]),          # sorts first, no preconditions
        _d("zzz_gated", requires=["has_login"], establishes=["authenticated"]),
    )
    r = es.plan(reg, {"has_login"}, "authenticated")
    assert r["plan"] == ["zzz_gated"], r
    assert r["assumes"] == []


def test_the_assumed_plan_is_still_offered_when_it_is_the_only_one():
    reg = _reg(_d("aaa_always_on", establishes=["authenticated"]))
    r = es.plan(reg, set(), "authenticated")
    assert r["plan"] == ["aaa_always_on"] and r["assumes"] == ["aaa_always_on"]


def test_a_shorter_assumed_plan_still_beats_a_longer_gated_one():
    """Depth dominates. Fewer assumptions is the TIE-break, not the primary criterion."""
    reg = _reg(
        _d("quick", establishes=["goal"]),
        _d("step1", requires=["s"], establishes=["m"]),
        _d("step2", requires=["m"], establishes=["goal"]),
    )
    assert es.plan(reg, {"s"}, "goal")["plan"] == ["quick"]


def test_a_plan_routed_through_an_always_on_engine_declares_the_assumption():
    """`browser_persona_bola` declares no observations because the persona artery reaches it, not evidence.
    The search must therefore treat it as applicable everywhere — including from no evidence at all — so
    the plan has to SAY that it depends on a path outside the observation vocabulary (configured
    credentials, a reachable browser) rather than presenting it as evidence-driven."""
    d = ed.build()
    r = es.plan(d, set(), "authenticated")
    assert r["reachable"], r
    assert r["assumes"], "an always-on step must be flagged as an assumption"
    for tid in r["assumes"]:
        assert d[tid]["always_on"] and not d[tid]["requires"], tid


def test_an_evidence_only_plan_assumes_nothing():
    """Negative control for the flag above: a fully gated path must come back with an empty `assumes`."""
    reg = _reg(
        _d("recon", requires=["serves_js"], establishes=["has_login"]),
        _d("bypass", requires=["has_login"], establishes=["authenticated"]),
    )
    r = es.plan(reg, {"serves_js"}, "authenticated")
    assert r["reachable"] and r["assumes"] == []


def test_shipped_registry_chains_js_recon_to_credential_use():
    """serves_js -> harvest exposed files -> credentials_exposed -> exposed_credentials becomes runnable.
    Two engines the current planner can only ever consider independently."""
    d = ed.build()
    r = es.plan(d, {"serves_js"}, "credentials_exposed")
    assert r["reachable"] and r["depth"] == 1, r
    assert "exposed_credentials" in es.unlocks(d, {"serves_js"}, r["plan"][0])


def test_shipped_registry_reports_the_cost_of_exactly_one_engine():
    """Q-007 then Q-074. This asserted the cost of `weak_password_reset`, an engine MEASURED to have no
    executor anywhere; Q-007 removed it and the shipped answer became "nothing breaks" everywhere.
    Q-074 measured the engine that really does destroy `authenticated` -- `run_race`, raced against a
    credential-rotation form with the mission's own session, taking the scan's `GET /api/me` from
    (200, True) to (401, False) -- so `breaks()` finally gives a true non-empty answer on the shipped
    tree. Kept as a PAIR so neither half can pass vacuously: exactly one engine costs anything, and
    every other one costs nothing."""
    d = ed.build()
    obs = {"has_login", "authenticated"}
    costly = sorted(tid for tid in ed.EFFECTS if es.breaks(d, obs, tid))
    assert costly == ["race_condition"], costly
    cost = es.breaks(d, obs, "race_condition")
    assert "jwt_forge" in cost and "weak_2fa_bypass" in cost, cost
    d["fake_rotator"] = dict(d["sqli_auth_bypass"], id="fake_rotator",
                             establishes=[], invalidates=["authenticated"])
    assert es.breaks(d, obs, "fake_rotator") == cost, "the walk is keyed to one entry, not the table"


def test_frontier_is_coherent_on_the_shipped_registry():
    d = ed.build()
    f = es.frontier(d, {"has_login", "serves_js"})
    assert "sqli_auth_bypass" in f["applicable_now"]
    assert f["reachable_goals"]["authenticated"]["reachable"] is True
    # Q-074 widened `consequences` by exactly the always-on engines that DECLARE an effect. It was
    # keyed off `applicable_now`, and `applicable()` returns only engines with a non-empty precondition
    # list -- so an always-on engine could never appear there whatever it establishes or destroys.
    # MEASURED before the fix: that silently dropped `browser_persona_bola` and `graphql_introspection`,
    # 2 of the 11 entries that had effects, and it would have hidden the only `invalidates` in the
    # model. `_plan_core` already treated an always-on action as available in every state.
    assert set(f["consequences"]) <= set(f["applicable_now"]) | set(f["always_on_with_effects"])
    assert set(f["always_on_with_effects"]) & set(f["consequences"]), "the widening did nothing"
    for t in f["always_on_with_effects"]:
        assert d[t]["always_on"] and (d[t]["establishes"] or d[t]["invalidates"]), t
    # `applicable_now` itself is untouched: it is the precondition filter's answer.
    assert not (set(f["always_on_with_effects"]) & set(f["applicable_now"]))
    for t, c in f["consequences"].items():
        assert isinstance(c["unlocks"], list) and isinstance(c["breaks"], list)


def test_hitting_the_search_bound_does_not_discard_a_plan_already_found(monkeypatch):
    """A false negative is the worst answer a planner can give. If the bound is reached AFTER a valid
    sequence is in hand, return it and say it may not be shortest — never claim unreachable."""
    # Names chosen so the goal-reaching action is expanded FIRST (actions run in id order), then the
    # bound trips on the next one — the exact interleaving where the old code threw the plan away.
    reg = _reg(
        _d("a_reach_it", requires=["s"], establishes=["goal"]),
        _d("b_noise", requires=["s"], establishes=["x"]),
        _d("c_noise", requires=["x"], establishes=["y"]),
    )
    monkeypatch.setattr(es, "MAX_EXPANSIONS", 1)
    r = es.plan(reg, {"s"}, "goal")
    assert r["reachable"] is True, r
    assert r["plan"] == ["a_reach_it"]
    assert "search bound" in r["reason"], "the bound must be disclosed, not hidden"


def test_the_bound_still_reports_unreachable_when_nothing_was_found(monkeypatch):
    """Negative control for the above — the bound must not start inventing plans."""
    reg = _reg(_d("a", requires=["s"], establishes=["x"]), _d("b", requires=["x"], establishes=["y"]))
    monkeypatch.setattr(es, "MAX_EXPANSIONS", 1)
    r = es.plan(reg, {"s"}, "never")
    assert r["reachable"] is False and r["plan"] == []


def test_reachability_endpoint_serves_the_search():
    """The production caller. Without one, this module is an island by Apolaki's own doctrine."""
    import asyncio
    import main as mainmod
    r = asyncio.run(mainmod.orchestration_reachability({"observations": ["has_login"],
                                                        "goal": "authenticated"}))
    assert "error" not in r, r
    assert r["plan"]["reachable"] is True
    assert r["frontier"]["applicable_now"]
    assert "authenticated" in r["vocabulary"]


def test_reachability_endpoint_rejects_invented_observations():
    """A typo'd observation must be reported, not silently treated as evidence — otherwise the frontier
    is computed from a state the caller never actually had."""
    import asyncio
    import main as mainmod
    r = asyncio.run(mainmod.orchestration_reachability({"observations": ["has_login", "is_pwned"]}))
    assert r["unknown_observations"] == ["is_pwned"]
    assert r["observations"] == ["has_login"]


def test_reachability_endpoint_survives_an_empty_body():
    import asyncio
    import main as mainmod
    r = asyncio.run(mainmod.orchestration_reachability({}))
    assert "error" not in r, r
    assert r["observations"] == [] and r["frontier"]["applicable_now"] == []


def test_frontier_is_pure():
    d = ed.build()
    assert es.frontier(d, {"has_login"}) == es.frontier(d, {"has_login"})
    assert ed.build() == d, "frontier mutated the descriptors"
