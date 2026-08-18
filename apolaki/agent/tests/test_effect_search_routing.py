"""Q-065 — a plan whose step cannot be dispatched must SAY SO.

The symptom on the ticket: a mission's autonomy loop wrote "next-best actions: ... weak_secret_forgery"
while nothing could execute it. The forward search had the same hole one layer down -- `plan()` returned
`reachable: True` for paths through techniques with no engine, and a consumer had no way to tell the
difference between "run this" and "there is no code for this".

Negative controls first: every "clean" assertion here is preceded by one proving the same apparatus
reports dirty when the input is dirty.
"""
import effect_search as es
import engine_descriptor as ed


def _d(tid, requires=(), establishes=(), invalidates=(), engines=None):
    d = {"id": tid, "requires": list(requires), "establishes": list(establishes),
         "invalidates": list(invalidates), "permission": "passive", "vuln_class": "t",
         "oracle": "o", "always_on": False, "reached_by": "", "auto": True, "transferable": True}
    if engines is not None:
        d["engines"] = list(engines)
    return d


def _reg(*ds):
    return {d["id"]: d for d in ds}


# ── NEGATIVE CONTROLS ───────────────────────────────────────────────────────────────────────────

def test_NEGATIVE_CONTROL_a_reachable_plan_with_no_engine_is_not_dispatchable():
    """The whole point. The path exists; the code does not."""
    reg = _reg(_d("ghost", requires=["has_login"], establishes=["authenticated"], engines=[]))
    r = es.plan(reg, {"has_login"}, "authenticated")
    assert r["reachable"] is True, "the search must still find the path"
    assert r["plan"] == ["ghost"]
    assert r["unroutable"] == ["ghost"]
    assert r["dispatchable"] is False, "a plan with no engine reported itself dispatchable"


def test_NEGATIVE_CONTROL_one_unroutable_step_poisons_an_otherwise_runnable_plan():
    reg = _reg(
        _d("real", requires=["serves_js"], establishes=["has_login"], engines=["run_crawl"]),
        _d("ghost", requires=["has_login"], establishes=["authenticated"], engines=[]),
    )
    r = es.plan(reg, {"serves_js"}, "authenticated")
    assert r["plan"] == ["real", "ghost"]
    assert r["unroutable"] == ["ghost"]
    assert r["dispatchable"] is False
    assert r["engines"] == {"real": ["run_crawl"], "ghost": []}


def test_NEGATIVE_CONTROL_frontier_flags_applicable_but_undispatchable():
    reg = _reg(_d("ghost", requires=["has_login"], establishes=["authenticated"], engines=[]))
    f = es.frontier(reg, {"has_login"})
    assert f["applicable_now"] == ["ghost"]
    assert f["unroutable_now"] == ["ghost"], "the decision surface hid an unrunnable action"


def test_NEGATIVE_CONTROL_a_missing_engines_key_is_UNKNOWN_not_unroutable():
    """Absence of a measurement is not a negative result. A descriptor built before routing existed
    must not be slandered as unroutable -- that would be a false alarm on every synthetic caller."""
    reg = _reg(_d("legacy", requires=["has_login"], establishes=["authenticated"]))   # no engines key
    r = es.plan(reg, {"has_login"}, "authenticated")
    assert r["reachable"] is True
    assert r["unroutable"] == []
    assert r["engines"] == {}
    assert r["dispatchable"] is True


# ── POSITIVE CONTROLS ───────────────────────────────────────────────────────────────────────────

def test_a_fully_routed_plan_is_dispatchable():
    reg = _reg(_d("real", requires=["has_login"], establishes=["authenticated"], engines=["run_sqli"]))
    r = es.plan(reg, {"has_login"}, "authenticated")
    assert r["dispatchable"] is True
    assert r["unroutable"] == []
    assert r["engines"] == {"real": ["run_sqli"]}


def test_the_annotation_is_purely_additive():
    """The planning answer must be byte-identical to what _plan_core computes; routing only annotates."""
    reg = _reg(
        _d("a", requires=["x"], establishes=["y"], engines=["run_a"]),
        _d("b", requires=["y"], establishes=["z"], engines=[]),
    )
    core = es._plan_core(reg, {"x"}, "z")
    full = es.plan(reg, {"x"}, "z")
    for k in ("reachable", "plan", "depth", "reason", "assumes"):
        assert full[k] == core[k], k


# ── THE SHIPPED REGISTRY: Q-065's real case ─────────────────────────────────────────────────────

def test_on_the_shipped_registry_the_jwt_techniques_are_dispatchable():
    """Q-066's concrete case, at the search layer. Both JWT techniques establish `authenticated`, so the
    forward search will route plans through them; both now carry the engine that actually runs."""
    d = ed.build()
    assert d["jwt_forge"]["engines"] == ["run_jwt"]
    assert d["jwt_key_confusion"]["engines"] == ["run_jwt"]
    # a state where jwt_forge is an applicable search operator, and it is not flagged unroutable
    _, unroutable = es._routing(d, ["jwt_forge", "jwt_key_confusion"])
    assert unroutable == [], unroutable


def test_a_real_shipped_plan_is_dispatchable_end_to_end():
    """A genuine multi-step answer off the shipped registry, with every step naming a live engine."""
    d = ed.build()
    r = es.plan(d, {"serves_js"}, "credentials_exposed")
    assert r["reachable"], r
    assert r["plan"], r
    for step in r["plan"]:
        assert d[step]["engines"], "%s has no engine" % step
        assert all(e in __import__("tools").TOOL_PERMISSIONS for e in d[step]["engines"])
    assert r["dispatchable"] is True, r


def test_every_shipped_producer_is_dispatchable_and_the_flag_still_fires():
    """Q-007. This pinned FOUR undispatchable EFFECTS producers as an honest limit. Measured, they were
    two different defects wearing the same label: `default_credentials` and `saml_signature_bypass` have
    real engines (`run_default_creds`, `run_saml` -- registered, implemented, dispatched) that the
    derivation could not see, and `weak_password_reset` / `soft_deleted_login` had no engine anywhere.
    The first pair is now routed via the `effect_engine` source; the second pair is out of EFFECTS.

    The limit being gone must NOT take the reporting with it, so the second half forces a plan through a
    synthetic producer with no engine and requires the flag to fire."""
    d = ed.build()
    bad = sorted(t for t in ed.EFFECTS if not d[t]["engines"])
    assert bad == [], bad
    assert len(ed.EFFECTS) >= 11, "the table emptied; the assertion above would pass for free"

    # the mechanism, on a producer that really has no engine
    d["ghost_producer"] = dict(d["sqli_auth_bypass"], id="ghost_producer", engines=[], routable=False)
    reg = {k: v for k, v in d.items() if k in ("ghost_producer",)}
    r = es.plan(reg, {"has_login"}, "authenticated")
    assert r["reachable"] is True
    assert r["unroutable"] == ["ghost_producer"]
    assert r["dispatchable"] is False


def test_frontier_still_names_undispatchable_actions_where_they_exist():
    d = ed.build()
    f = es.frontier(d, {"has_login", "authenticated"})
    assert f["applicable_now"], "nothing applicable — the fixture is wrong, not the code"
    assert set(f["unroutable_now"]) <= set(f["applicable_now"])
    # Q-007: no EFFECTS producer is unroutable any more, but techniques without effects still are --
    # `weak_password_reset` and `soft_deleted_login` keep their preconditions and remain executor-less,
    # which is exactly what the frontier exists to show an operator.
    assert "weak_password_reset" in f["unroutable_now"], f["unroutable_now"]
    assert not (set(f["unroutable_now"]) & set(ed.EFFECTS)), f["unroutable_now"]
