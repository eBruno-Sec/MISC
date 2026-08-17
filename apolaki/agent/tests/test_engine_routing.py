"""Q-066 — the join between the technique/effect vocabulary and the engine registry.

The defect, measured before any of this was written: `PRECONDITIONS` (42 keys), `EFFECTS` (13 keys)
and the technique registry (88 keys) are all keyed by TECHNIQUE ID, while `tools.TOOL_PERMISSIONS` is
keyed by ENGINE NAME. 0 of 88 technique ids are engine names and no field on any technique record
holds one, so the planner could rank `jwt_forge` with no route to `run_jwt`.

THE NEGATIVE CONTROLS COME FIRST IN THIS FILE, DELIBERATELY. This codebase has shipped a guard that
checks a declaration instead of a fact eight times -- `test_techniques.py:17` asserts
`execution in ("auto", "operator")` over a field whose only value registry-wide is "auto", a guard
that cannot fail. Every assertion below about a clean sheet is preceded by a test proving the same
apparatus reports a dirty one when the tree is dirty.
"""
import re

import pytest

import engine_descriptor as ed
import techniques as T
import tools as TL
import wstg_catalog as W


def _synthetic(**over):
    """A minimal technique-shaped record. Not built through techniques._t() on purpose: this is the
    'somebody adds a new technique' case, and it must be catchable without cooperation from the
    registry's own constructor."""
    base = {"id": "synthetic_probe", "vuln_class": "test", "cwe": "CWE-0", "owasp": "A00:2021",
            "permission": "ACTIVE", "summary": "s", "detect": "d", "exploit": "e",
            "oracle": "o", "transferable": True, "execution": "auto", "wstg": None}
    base.update(over)
    return base


# ── NEGATIVE CONTROLS: prove the guard FAILS on a dirty tree ────────────────────────────────────

def test_NEGATIVE_CONTROL_a_phantom_engine_name_is_caught(monkeypatch):
    """The load-bearing negative control. `run_mass_assignment` (Q-011) was engine-SHAPED, named in
    this very catalog, and registered nowhere -- a route to nothing that three catalogs advertised.

    This must FAIL the audit. If it does not, the phantom check is decorative."""
    monkeypatch.setattr(W, "FULL", dict(W.FULL, **{"WSTG-INPV-20": "run_mass_assignment (the Q-011 phantom)"}))
    techs = {"mass_assignment": _synthetic(id="mass_assignment", wstg="WSTG-INPV-20")}
    a = ed.routing_audit(techniques=techs)
    assert a["phantom"], "a phantom engine name did not register as a phantom"
    assert any("run_mass_assignment" in p for p in a["phantom"]), a["phantom"]
    assert a["ok"] is False, "the audit reported ok with a route to a nonexistent engine"


def test_NEGATIVE_CONTROL_the_phantom_check_is_not_registry_filtered_into_uselessness():
    """Why the check is shape-based and not membership-based.

    `routes()` only ever emits names that ARE in the registry, so asserting 'every routed engine is
    registered' is true by construction and can never fail. The phantom check must therefore read the
    SOURCE prose, not routes()' output. This pins that difference."""
    reg = {"run_jwt"}
    assert ed._engines_named("run_jwt and run_ghost", reg) == {"run_jwt"}      # filtered
    assert ed._engine_shaped("run_jwt and run_ghost") == {"run_jwt", "run_ghost"}   # not filtered
    assert ed._engine_shaped("run_ghost") - reg == {"run_ghost"}


def test_NEGATIVE_CONTROL_a_technique_naming_no_engine_is_reported_unrouted():
    """A new technique that names nothing must show up as unrouted, not be silently absorbed."""
    techs = dict(T.TECHNIQUES)
    techs["synthetic_probe"] = _synthetic()          # no wstg, not in ALWAYS_ON -> no route
    a = ed.routing_audit(techniques=techs)
    assert "synthetic_probe" in a["unrouted"], a["unrouted"]
    assert a["total"] == len(T.TECHNIQUES) + 1
    assert a["routed"] == len(T.TECHNIQUES) - len(ed.routing_audit()["unrouted"])


def test_NEGATIVE_CONTROL_an_unreadable_registry_fails_closed():
    """Zero engines must never read as a clean sheet. My own first probe reported '0 flags' from a
    gate that had parsed nothing; an empty registry has to be loud, not green."""
    a = ed.routing_audit(registry=set())
    assert a["registry_readable"] is False
    assert a["ok"] is False
    assert a["routed"] == 0
    assert len(a["unrouted"]) == a["total"]


def test_NEGATIVE_CONTROL_the_underscore_normalisation_actually_matters():
    """This is a regression pin for an instrument bug I shipped into a measurement and had to retract.

    A tool is registered as `run_service_pack` and implemented as `_run_service_pack`; ALWAYS_ON's
    prose uses the underscored spelling. Matching without lstrip('_') reported 14 wired ICS engines
    as unroutable."""
    reg = {"run_service_pack"}
    assert ed._engines_named("-> _run_service_pack read-only OT probe", reg) == {"run_service_pack"}
    assert "run_service_pack" not in reg or "_run_service_pack" not in reg   # the two spellings are one


# ── POSITIVE CONTROLS: the apparatus finds real routes ──────────────────────────────────────────

def test_the_registry_is_actually_loaded():
    """Every zero below needs this: the instrument was looking."""
    reg = ed.engine_registry()
    assert len(reg) > 100, len(reg)
    assert "run_jwt" in reg


def test_the_concrete_case_jwt_forge_routes_to_run_jwt():
    """Q-066's named case, end to end. Both JWT techniques declare `authenticated` as an effect, so
    the forward search will route plans through them; before this join neither had a dispatch name."""
    d = ed.build()
    assert d["jwt_forge"]["engines"] == ["run_jwt"]
    assert d["jwt_key_confusion"]["engines"] == ["run_jwt"]
    assert d["jwt_forge"]["routed_by"]["run_jwt"] == ["wstg_full"]
    assert d["jwt_forge"]["routable"] is True
    # and the name is one the executor really dispatches
    assert "run_jwt" in TL.TOOL_PERMISSIONS
    assert any(s["name"] == "run_jwt" for s in TL.CLAUDE_TOOLS)


def test_both_derivation_sources_carry_real_weight():
    """Neither source is decorative: drop either and coverage drops."""
    r = ed.routes()
    srcs = {s for v in r.values() for ss in v.values() for s in ss}
    assert srcs == {"always_on_reason", "wstg_full"}, srcs
    only_ao = {t for t, v in r.items() if all(ss == ["always_on_reason"] for ss in v.values())}
    only_wstg = {t for t, v in r.items() if all(ss == ["wstg_full"] for ss in v.values())}
    assert len(only_ao) >= 5, only_ao
    assert len(only_wstg) >= 20, only_wstg


def test_every_derived_engine_name_is_dispatchable():
    """A route must reach something the executor can actually run."""
    r = ed.routes()
    names = {e for v in r.values() for e in v}
    assert names, "no routes derived at all"
    assert not (names - set(TL.TOOL_PERMISSIONS)), names - set(TL.TOOL_PERMISSIONS)


def test_no_phantom_engine_on_the_shipped_tree():
    """The invariant. Proven falsifiable by the first test in this file."""
    a = ed.routing_audit()
    assert a["phantom"] == [], a["phantom"]
    assert a["ok"] is True, a


# ── THE RATCHET: what is still unrouted, pinned exactly ─────────────────────────────────────────

# MEASURED 2026-08-17. These 13 techniques have no engine the platform can derive, and every one of
# them is auto + oracle + transferable -- i.e. all 13 PASS `technique_planner.orchestration_audit()`'s
# no-island check today while having no executor at all. That is Q-020 stated as a fact rather than as
# the unfailable `execution in ("auto","operator")` assertion.
#
# SHRINK THIS LIST, NEVER GROW IT. It is pinned as an exact set, not a count, so both directions are
# deliberate: adding an unroutable technique fails, and fixing one also fails until the fix is recorded.
UNROUTED_2026_08_17 = [
    "business_logic_abuse", "crlf_injection", "default_credentials", "encoded_data_decode",
    "exposed_credentials", "saml_signature_bypass", "security_misconfig_errors", "soft_deleted_login",
    "vulnerable_component", "waf_bypass", "weak_2fa_bypass", "weak_password_reset",
    "weak_secret_forgery",
]


def test_the_unrouted_set_is_exactly_what_was_measured():
    assert ed.routing_audit()["unrouted"] == UNROUTED_2026_08_17


def test_every_unrouted_technique_passes_the_no_island_guard_anyway():
    """The point of Q-020, made failable. The no-island guard classifies all 13 of these as reachable
    -- 'evidence-gated' or 'always-on with a stated reason' -- while nothing can dispatch them. A guard
    that checks a declaration passes what it exists to catch."""
    import technique_planner as tp
    audit = tp.orchestration_audit(list(T.TECHNIQUES.values()))
    reached = set(audit["gated"]) | set(audit["always_on"])
    assert audit["islands"] == [], audit["islands"]
    unrouted_but_declared_reachable = sorted(set(UNROUTED_2026_08_17) & reached)
    assert unrouted_but_declared_reachable == UNROUTED_2026_08_17, (
        "the no-island guard no longer covers these; re-measure before editing the pin")


def test_effect_producers_without_an_executor_are_named():
    """Q-065's shape, measured. A technique that DECLARES an effect but has no engine lets the forward
    search hand back a plan whose step cannot be dispatched."""
    a = ed.routing_audit()
    assert a["effect_producers_unrouted"] == [
        "default_credentials", "saml_signature_bypass", "soft_deleted_login", "weak_password_reset"]
    assert all(t in ed.EFFECTS for t in a["effect_producers_unrouted"])


# ── SHAPE / PURITY ──────────────────────────────────────────────────────────────────────────────

def test_routes_are_deterministic():
    assert ed.routes() == ed.routes()
    assert ed.build() == ed.build()


def test_descriptor_still_carries_the_old_contract():
    """Additive only. The T7 tables and the existing descriptor keys are untouched."""
    d = ed.build()["sqli_auth_bypass"]
    assert set(d) >= {"id", "permission", "oracle", "requires", "establishes", "invalidates",
                      "always_on", "reached_by", "engines", "routed_by", "routable"}
    assert d["establishes"] == ["authenticated"]
    assert ed.validate()["ok"]


def test_the_mapping_is_derived_and_not_a_typed_table():
    """The trap Q-066 names explicitly: a hand-written {"jwt_forge": "run_jwt"} dict would be a THIRD
    vocabulary and would rot like the two it joins. Assert no such literal exists in the module."""
    import os
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "engine_descriptor.py"), encoding="utf8").read()
    body = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    for tid in ("jwt_forge", "jwt_key_confusion"):
        pair = re.search(r'"%s"\s*:\s*[\("]*run_' % tid, body)
        assert not pair, "a literal technique->engine pair was typed for %s" % tid
