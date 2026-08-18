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


def test_the_shipped_conflict_set_is_exactly_the_measured_race_rows():
    """Q-007 then Q-074, and the history matters because the row COUNT is the same both times.

    Q-007: `conflicts()` returned six rows and all six came from `weak_password_reset`, MEASURED to
    have no executor on any surface. Removing it left the set EMPTY -- honest, and uninformative,
    because an empty model and a correct model produce the same plan for different reasons.

    Q-074 populated it from a MEASUREMENT rather than an assertion, and the engine is not the one the
    ticket named. `session_lifecycle` was DRIVEN against the shipped `sessionlife` lab with a live
    mission session held by another account and changed no engagement state at all. `run_race` ends
    the mission's session: raced against a credential-rotation form with `session_headers` merged in,
    the scan's own `GET /api/me` went (200, True) -> (401, False). Raw output, both probes and their
    positive controls, in docs/handoff/effects2.md section 3.

    Six rows again, from a real engine this time -- the number is a coincidence of there being six
    consumers of `authenticated`, which is what this pins."""
    cf = ed.conflicts()
    assert [t for t, e in ed.EFFECTS.items() if e.get("invalidates")] == ["race_condition"]
    assert {t for t, _o, _c in cf} == {"race_condition"}, cf
    assert {o for _t, o, _c in cf} == {"authenticated"}, cf
    assert [c for _t, _o, c in cf] == ["cache_deception", "jwt_forge", "jwt_key_confusion",
                                       "session_fixation", "session_lifecycle", "weak_2fa_bypass"], cf
    # NON-VACUITY: the apparatus is looking. The positive half of the same walk is large and real.
    assert len(ed.chains()) > 40, "the walk is not finding anything at all"


def test_the_sussman_machinery_sees_a_SECOND_negative_effect():
    """Negative control that survives the table no longer being empty. The old version proved
    `conflicts()` still worked when the table had nothing in it; this proves the walk is enumerating
    the TABLE and not hard-wired to the one entry that now exists."""
    d = ed.build()
    d["fake_rotator"] = dict(d["sqli_auth_bypass"], id="fake_rotator",
                             establishes=[], invalidates=["authenticated"])
    cf = ed.conflicts(d)
    assert {t for t, o, c in cf} == {"fake_rotator", "race_condition"}, cf
    assert ("fake_rotator", "authenticated", "jwt_forge") in cf, cf
    assert ("race_condition", "authenticated", "jwt_forge") in cf, cf


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
    # Q-007 emptied the conflict half; Q-074 populated it from a measurement. The count must MATCH the
    # list -- that is the assertion that actually catches a broken payload -- and the rows must be the
    # shipped ones, so an endpoint that quietly stopped computing them cannot read as "none exist".
    assert ef["conflict_count"] == len(ef["conflicts"]) == 6
    assert {c["technique"] for c in ef["conflicts"]} == {"race_condition"}
    assert {c["observation"] for c in ef["conflicts"]} == {"authenticated"}
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


# ── ALWAYS_ON reasons must be TRUE, not merely present ──────────────────────────────────────────

def test_every_function_an_always_on_reason_names_is_actually_wired():
    """THE guard for a defect class that shipped. `graphql_argument_injection` was declared ALWAYS_ON
    "via graphql_tool.build_query", and nothing called build_query, injectable_arguments or
    schema_operations. The engine ran on paper only.

    The no-island guard could not catch it: it proves a technique is DECLARED reached, and the
    declaration is prose. This checks the prose against the code."""
    r = ed.verify_always_on()
    assert r["ok"], "ALWAYS_ON reasons naming unwired functions:\n  " + "\n  ".join(r["unwired"])
    assert len(r["checked"]) >= 30, "verifier resolved suspiciously few identifiers: %d" % len(r["checked"])


def test_the_verifier_catches_an_unwired_reason(monkeypatch):
    """NEGATIVE CONTROL. A guard that cannot fail is not a guard. `bie.resolve_locator` is real, tested,
    and has no production caller — exactly the shape of the historical bug."""
    monkeypatch.setitem(ed.ALWAYS_ON, "fake_engine", "reached via bie.resolve_locator on every page")
    r = ed.verify_always_on()
    assert r["ok"] is False
    assert any("resolve_locator" in u for u in r["unwired"]), r["unwired"]


def test_the_verifier_ignores_prose_that_is_not_an_identifier():
    """Reasons are written for humans. Ordinary words must not be mistaken for functions, or the guard
    becomes noise and gets switched off."""
    assert ed._identifiers("always-on DOM sweep on every reflected param") == set()
    assert "run_xss" in ed._identifiers("always-on DOM sweep (run_xss / run_dom_trace on every page)")


def test_prose_files_do_not_count_as_wiring():
    """The false promise lived in techniques.py and in the reason itself. If a mention there counted as
    a reference, the guard would have passed the very bug it exists to catch."""
    assert "techniques.py" in ed._PROSE_FILES
    assert "engine_descriptor.py" in ed._PROSE_FILES


def test_a_tool_registered_by_string_still_counts_as_wired():
    """Tools are registered under a bare string ("run_service_pack") and implemented as a private method
    (`_run_service_pack`). Treating those as different names made the verifier report 13 wired ICS
    engines as broken — a false alarm that would have destroyed trust in the guard."""
    r = ed.verify_always_on()
    assert not any("service_pack" in u for u in r["unwired"]), r["unwired"]


def test_registration_alone_does_not_count_as_wired(monkeypatch, tmp_path):
    """THE hole that hid a second unreachable engine. `run_header_trust` was registered in the permission
    map and fully implemented, but its name was never passed to execute()/_exec_internal() and it was
    absent from the CLAUDE_TOOLS spec — unreachable by BOTH the deterministic and the agentic path. The
    first version of this verifier counted the registry key as a reference and passed it."""
    (tmp_path / "tools.py").write_text(
        '"run_ghost": PermissionLevel.ACTIVE,\n\n\nasync def _run_ghost(self, inp):\n    return 1\n',
        encoding="utf8")
    monkeypatch.setattr(ed, "ALWAYS_ON", {"ghost_engine": "reached via run_ghost on every origin"})
    r = ed.verify_always_on(str(tmp_path))
    assert r["ok"] is False, "registration + definition must not read as wired"
    assert any("run_ghost" in u for u in r["unwired"]), r["unwired"]


def test_an_invoked_tool_is_recognised_as_wired(monkeypatch, tmp_path):
    """Positive control for the rule above — adding a real call site must flip it to wired, or the check
    is simply always-fail."""
    (tmp_path / "tools.py").write_text(
        '"run_ghost": PermissionLevel.ACTIVE,\n\n\nasync def _run_ghost(self, inp):\n    return 1\n',
        encoding="utf8")
    (tmp_path / "agent.py").write_text(
        'async def go(self, sid):\n    return await self._exec_internal("run_ghost", {}, sid)\n',
        encoding="utf8")
    monkeypatch.setattr(ed, "ALWAYS_ON", {"ghost_engine": "reached via run_ghost on every origin"})
    assert ed.verify_always_on(str(tmp_path))["ok"] is True


def test_header_trust_is_invoked_not_merely_registered():
    """Regression for the specific engine. Its ALWAYS_ON reason claims it runs on every in-scope origin;
    that must remain true."""
    import os
    ag = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(ed.__file__))),
                           "agent", "agent.py"), encoding="utf8").read() \
        if False else open(os.path.join(os.path.dirname(os.path.abspath(ed.__file__)), "agent.py"),
                           encoding="utf8").read()
    assert '"run_header_trust"' in ag, "header-trust is registered but never invoked by the scan"
    assert "_do_header_trust" in ag
