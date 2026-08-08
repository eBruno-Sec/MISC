"""
Engine descriptors (T6) — one declaration per engine, carrying preconditions AND effects.

Four books arrive at this from different directions:

  * *Black Hat Go* Ch.10 — a pluggable system needs a PUBLISHED contract, because otherwise every new
    plugin forces a change to the consumer, "defeating the entire purpose".
  * *Automated Planning* §4.2 — planning needs three things: a goal test, the actions applicable to a
    state, and **the successor state an action produces**. Apolaki has only the middle one.
  * *Automated Planning* §4.4 — the successor must include NEGATIVE effects, or the planner reproduces
    STRIPS's deleted-condition failure (the Sussman anomaly).
  * *MBT Essentials* §8.1 / *practical MBT* §4.1.3 — structural coverage needs transitions to count, and
    there are no transitions without declared effects.

THE ACTUAL DEFECT, stated precisely, because it is narrower and more fixable than "no effects model":
**preconditions and effects already exist but speak different languages.** Preconditions use the 17-term
observation vocabulary in `technique_planner.OBSERVATIONS` (`has_api`, `authenticated`, …). Effects exist
as `service_router` pack `enables` lists in an ad-hoc vocabulary (`arbitrary_file_read`, `ot_read`, …) and
as free-form `state.add_capability` strings. Nothing chains, because nothing an engine PRODUCES is
expressed in terms another engine can REQUIRE.

A descriptor therefore states effects in the SAME vocabulary as preconditions. That single choice is what
turns the applicability filter into a searchable graph.

**This module declares; it does not yet drive.** T7 makes the router, planner and registry read it, with a
test asserting the generated tables equal today's hand-maintained ones exactly — a pure refactor with zero
behaviour delta. Keeping declaration and adoption apart is deliberate: it makes the risky half reviewable
on its own.
"""
from __future__ import annotations


def _observations():
    import technique_planner as tp
    return set(tp.OBSERVATIONS)


# ── effects, declared in the PRECONDITION vocabulary so they can chain ──────────────────────────
#
# Conservative on purpose. A technique appears here only when its oracle genuinely establishes the
# observation for the rest of the engagement — not when it merely hints at it. An over-declared effect
# would make the planner chase a capability it does not really have, which is worse than no model.
#
# `establishes`  — observations that hold AFTER this technique confirms.
# `invalidates`  — observations that STOP holding. This is the Sussman half: a technique that changes a
#                  credential invalidates the session another technique was relying on, and a planner
#                  without negative effects will happily order those the wrong way round.
EFFECTS = {
    # Authentication achieved -> everything gated on `authenticated` becomes reachable.
    "sqli_auth_bypass":        {"establishes": ["authenticated"], "invalidates": []},
    "default_credentials":     {"establishes": ["authenticated"], "invalidates": []},
    "jwt_forge":               {"establishes": ["authenticated"], "invalidates": []},
    "jwt_key_confusion":       {"establishes": ["authenticated"], "invalidates": []},
    "soft_deleted_login":      {"establishes": ["authenticated"], "invalidates": []},
    "saml_signature_bypass":   {"establishes": ["authenticated"], "invalidates": []},

    # A password reset gets you in AS the victim, but rotates the credential — so any session another
    # technique already established is dead. This is the deleted-condition interaction, in Apolaki.
    "weak_password_reset":     {"establishes": ["authenticated"], "invalidates": ["authenticated"]},

    # Credential material recovered -> the exposed-credentials technique has something to consume.
    "sqli_union_extract":      {"establishes": ["credentials_exposed"], "invalidates": []},
    "exposed_files_harvest":   {"establishes": ["credentials_exposed"], "invalidates": []},
    "target_intel_harvest":    {"establishes": ["credentials_exposed"], "invalidates": []},

    # Surface discovery -> new inputs for the injection engines.
    "graphql_introspection":   {"establishes": ["has_api", "has_object_id"], "invalidates": []},
    # NOT `find_hidden_route`: it is a lab-local catalog entry with no executor and no gate, so an effect
    # declared on it could never fire. Over-declaring is worse than not declaring — it would make the
    # planner believe a capability is obtainable by an action it can never actually take.

    # Runtime/browser discovery of client-rendered surface.
    "browser_persona_bola":    {"establishes": ["has_object_id", "authenticated"], "invalidates": []},

    # An error oracle firing is itself an observation later techniques key on.
    "sqli_structural":         {"establishes": ["sql_error_seen"], "invalidates": []},
}


def descriptor(tech: dict, preconditions: dict, always_on: dict) -> dict:
    """One engine's full contract. Pure."""
    tid = tech.get("id", "")
    eff = EFFECTS.get(tid, {})
    return {
        "id": tid,
        "permission": tech.get("permission"),
        "vuln_class": tech.get("vuln_class"),
        "oracle": tech.get("oracle") or "",
        "requires": list(preconditions.get(tid, [])),
        "always_on": tid in always_on,
        "reached_by": always_on.get(tid, "") if tid in always_on else "evidence-gated preconditions",
        "establishes": list(eff.get("establishes", [])),
        "invalidates": list(eff.get("invalidates", [])),
        "auto": tech.get("execution", "auto") == "auto",
        "transferable": bool(tech.get("transferable")),
    }


def build() -> dict:
    """{id: descriptor} for every registered technique, assembled from the sources that exist today.

    Deliberately a VIEW rather than a new source of truth: nothing is migrated yet, so this cannot drift
    from the tables the platform actually runs on. T7 inverts that."""
    import techniques as T
    import technique_planner as tp
    return {t["id"]: descriptor(t, tp._PRECONDITIONS, tp.ALWAYS_ON)
            for t in T.TECHNIQUES.values() if t.get("id")}


def validate(descriptors: dict = None) -> dict:
    """Contract checks. Pure over the supplied descriptors.

    The load-bearing one is `unknown_effect_vocabulary`: an effect that is not a real observation can
    never satisfy any precondition, so it is a declaration that silently does nothing — exactly the kind
    of dead wiring the no-island rule exists to catch."""
    d = descriptors if descriptors is not None else build()
    obs = _observations()
    unknown_effect, unknown_require, unreachable = [], [], []
    for tid, desc in sorted(d.items()):
        for e in desc["establishes"] + desc["invalidates"]:
            if e not in obs:
                unknown_effect.append("%s -> %s" % (tid, e))
        for r in desc["requires"]:
            if r not in obs:
                unknown_require.append("%s <- %s" % (tid, r))
        if desc["auto"] and desc["oracle"] and desc["transferable"] \
                and not desc["requires"] and not desc["always_on"]:
            unreachable.append(tid)
    return {"total": len(d),
            "with_effects": sum(1 for x in d.values() if x["establishes"] or x["invalidates"]),
            "unknown_effect_vocabulary": unknown_effect,
            "unknown_requirement_vocabulary": unknown_require,
            "unreachable": unreachable,
            "ok": not (unknown_effect or unknown_require or unreachable)}


def chains(descriptors: dict = None) -> list:
    """[(producer, observation, consumer)] — every place one engine establishes what another requires.

    This is the payoff and the proof the model is real: today the planner cannot see any of these, so it
    can never decide to run the producer in order to reach the consumer. Pure."""
    d = descriptors if descriptors is not None else build()
    out = []
    for pid, prod in sorted(d.items()):
        for obs in prod["establishes"]:
            for cid, cons in sorted(d.items()):
                if cid != pid and obs in cons["requires"]:
                    out.append((pid, obs, cid))
    return out


def conflicts(descriptors: dict = None) -> list:
    """[(technique, observation, consumer)] where running `technique` DESTROYS a condition `consumer`
    needs — the Sussman anomaly, made visible. Pure."""
    d = descriptors if descriptors is not None else build()
    out = []
    for tid, t in sorted(d.items()):
        for obs in t["invalidates"]:
            for cid, c in sorted(d.items()):
                if cid != tid and obs in c["requires"]:
                    out.append((tid, obs, cid))
    return out
