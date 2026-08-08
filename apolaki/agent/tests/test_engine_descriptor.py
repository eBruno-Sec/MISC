"""Engine descriptors (T6) — Black Hat Go Ch.10 contract + Automated Planning §4.2/§4.4 effects.

T6 declares only. The behaviour-delta assertions belong to T7, so what these tests protect is the
DECLARATION's integrity: that every effect is expressed in a vocabulary preconditions can actually
consume, and that no declaration points at a technique that does not exist.

Both failure modes are silent. A misspelled technique id or an invented effect term costs nothing at
import time and simply never fires — the same class of dead wiring the no-island rule exists to catch.
"""
import engine_descriptor as ed
import technique_planner as tp
import techniques as T


def test_every_declared_effect_names_a_real_technique():
    """A typo here is invisible: the entry just never matches, forever."""
    unknown = sorted(set(ed.EFFECTS) - set(T.TECHNIQUES))
    assert not unknown, "EFFECTS declared for non-existent techniques: %s" % unknown


def test_effects_use_the_precondition_vocabulary():
    """THE design constraint. An effect outside OBSERVATIONS can never satisfy any precondition, so it
    is a declaration that silently does nothing — precisely the defect this module was built to fix."""
    obs = set(tp.OBSERVATIONS)
    bad = sorted({e for eff in ed.EFFECTS.values()
                  for e in eff["establishes"] + eff["invalidates"] if e not in obs})
    assert not bad, "effects outside the observation vocabulary cannot chain: %s" % bad


def test_descriptor_covers_every_registered_technique():
    d = ed.build()
    assert set(d) == {t["id"] for t in T.TECHNIQUES.values() if t.get("id")}
    assert len(d) == len(T.TECHNIQUES)


def test_validate_passes_on_the_shipped_registry():
    r = ed.validate()
    assert r["ok"], r
    assert not r["unknown_effect_vocabulary"]
    assert not r["unknown_requirement_vocabulary"]


def test_descriptor_carries_both_halves_of_the_contract():
    """Applicability alone is what Apolaki had. The contract needs the successor state too."""
    d = ed.build()["sqli_auth_bypass"]
    assert d["requires"], "preconditions half"
    assert d["establishes"] == ["authenticated"], "effects half"
    assert set(d) >= {"id", "permission", "oracle", "requires", "establishes",
                      "invalidates", "always_on", "reached_by"}


def test_real_chains_exist_and_are_currently_invisible_to_the_planner():
    """The payoff. If this list is empty the effects model buys nothing."""
    ch = ed.chains()
    assert ch, "no producer establishes anything any consumer requires"
    # The canonical one: bypass authentication, and the authenticated-only engines become reachable.
    assert any(p == "sqli_auth_bypass" and o == "authenticated" for p, o, c in ch), ch
    # And it is genuinely not modelled today: the planner has no notion of an effect at all.
    assert not hasattr(tp, "EFFECTS"), "T7 has landed; this assertion should move"


def test_negative_effects_surface_a_real_ordering_conflict():
    """Automated Planning §4.4 — without deleted conditions the planner reorders into a broken plan."""
    cf = ed.conflicts()
    assert cf, "no negative effects declared; the Sussman half is missing"
    assert any(t == "weak_password_reset" and o == "authenticated" for t, o, c in cf), cf


def test_chains_and_conflicts_are_pure_and_deterministic():
    d = ed.build()
    assert ed.chains(d) == ed.chains(d)
    assert ed.conflicts(d) == ed.conflicts(d)
    assert ed.build() == d


def test_every_technique_with_effects_is_actually_reachable():
    """An effect on an unreachable technique is a lie to the planner: it says a capability is obtainable
    by an action that can never be taken. Caught exactly this on `find_hidden_route`, a lab-local catalog
    entry with no executor, which had been given an `establishes`."""
    d = ed.build()
    for tid in sorted(ed.EFFECTS):
        assert d[tid]["requires"] or d[tid]["always_on"], \
            "%s declares effects but is in neither _PRECONDITIONS nor ALWAYS_ON" % tid


def test_every_transferable_engine_is_reached_by_something():
    """Mirrors the no-island rule at descriptor level: gated by preconditions or always-on, never
    neither. Lab-local (`transferable=False`) catalog entries are exempt by design."""
    for tid, d in ed.build().items():
        assert d["requires"] or d["always_on"] or not (d["auto"] and d["oracle"] and d["transferable"]), tid
        assert d["reached_by"], tid


def test_audit_endpoint_actually_serves_the_effects_layer():
    """The descriptor is only worth having if something READS it. A declare-only module is an island by
    Apolaki's own doctrine, so this asserts the production caller exists and its payload is real —
    not that the module merely imports."""
    import asyncio
    import main as mainmod
    r = asyncio.run(mainmod.orchestration_audit())
    assert "error" not in r, r
    assert r["no_islands"] is True, r["islands"]
    ef = r["effects"]
    assert ef["vocabulary_ok"] is True
    assert ef["chain_count"] == len(ef["chains"]) > 0
    assert ef["conflict_count"] == len(ef["conflicts"]) > 0
    # Honesty: the UI must not imply the planner acts on these yet.
    assert ef["planner_uses_effects"] is False
    assert "not yet" in ef["note"] or "does not yet" in ef["note"]


def test_validate_catches_an_invented_effect_term():
    """Negative control: the check has to actually fail on a bad declaration."""
    d = ed.build()
    d["sqli_auth_bypass"] = dict(d["sqli_auth_bypass"], establishes=["root_on_the_box"])
    r = ed.validate(d)
    assert not r["ok"]
    assert any("root_on_the_box" in x for x in r["unknown_effect_vocabulary"])
