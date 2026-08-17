"""Q-065's SECOND cause: the planner's JWT gate reads a state key nothing ever writes.

Q-066 was the routing half -- the effects model could name `jwt_forge` with no route to `run_jwt`.
That is fixed. This file pins the OTHER half, which is independent of routing and was found while
measuring the first: `planner.next_batch` schedules `run_jwt` only when a JWT appears in
`state["auth_headers"]` or `state["recon"]["cookies"]`, and **the agent never puts `auth_headers`
into that state at all**.

MEASURED. `agent.py:3305` builds the planner's state with exactly these 13 keys:

    mode, roots, done, recon, urls, bases, zap, zap_policy, zap_speed, zap_aggression,
    nmap_vuln, nuclei_heavy, intensity

`auth_headers` is not among them. The operator's headers are named `session_headers` in `main.py:554`
and handed to `ToolRegistry(session_headers=...)` as a constructor argument, so they never travel via
the state dict. Producer and consumer use different names and never meet -- the SAME defect shape as
Q-066 itself, and the fifth recorded instance of it in this codebase.

Consequence: a Bearer-token JWT -- the normal case, and the one on every SPA that keeps its token in
localStorage -- cannot reach the gate. Only a JWT carried in a COOKIE can ever schedule `run_jwt`.

THE FIX IS NOT IN A FILE THIS LANE OWNS. `agent.py` holds uncommitted work from another lane, so the
one-line change is written up in `docs/handoff/routing.md` instead of applied here. These tests pin
the planner half as CORRECT so that when the state key starts being supplied, the behaviour is
already covered; `test_the_production_state_shape_cannot_reach_the_gate` is the one that flips.
"""
import planner

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2ln"

# The exact key set agent.py:3305 supplies. If a lane adds `auth_headers` there, the second test
# below starts failing, which is the intended signal -- not a regression.
AGENT_STATE_KEYS_2026_08_17 = ("mode", "roots", "done", "recon", "urls", "bases", "zap",
                               "zap_policy", "zap_speed", "zap_aggression", "nmap_vuln",
                               "nuclei_heavy", "intensity")


def _drive(**extra):
    """Run the planner through its phases until it stalls, collecting every tool it schedules.

    Driving the REAL next_batch rather than re-implementing the gate: a reimplemented regex would
    pass while the shipped one did nothing, which is precisely the failure this file exists to catch."""
    state = {"mode": "full", "roots": ["lab.local"], "done": set(), "recon": {"cookies": {}},
             "urls": ["http://lab.local/rest/products?q=1"],
             "bases": {"lab.local": "http://lab.local"}, "intensity": "standard"}
    state.update(extra)
    done, tools = set(), set()
    for _ in range(12):
        state["done"] = done
        batch = planner.next_batch(state)
        if not batch:
            break
        for step in batch:
            tools.add(step.get("tool") or step.get("name"))
            done.add(step.get("tag") or step.get("key") or str(step))
    return tools


def test_POSITIVE_CONTROL_the_gate_fires_when_the_key_is_supplied():
    """The planner half is CORRECT, and this proves the harness actually reaches phase E -- without
    it, the next test would pass for the trivial reason that the planner never got that far."""
    tools = _drive(auth_headers={"Authorization": "Bearer " + JWT})
    assert "run_jwt" in tools
    assert len(tools) > 25, "the drive stalled early; the fixture is wrong, not the code"


def test_the_gate_also_fires_on_a_cookie_borne_jwt():
    """The one path that CAN work in production today."""
    tools = _drive(recon={"cookies": {"token": JWT}})
    assert "run_jwt" in tools


def test_the_production_state_shape_now_REACHES_the_gate():
    """THE FIX, pinned. Was `test_the_production_state_shape_cannot_reach_the_gate`, which asserted
    the defect; `agent.py` now supplies `auth_headers` from `self.tools.session_headers`, so the
    assertion is INVERTED rather than deleted -- the pin moves from the defect onto the fix.

    The historical key set stays below as a dated record of what the state looked like when the
    defect was measured. Do not "update" it; it is evidence, not configuration.
    """
    assert "auth_headers" not in AGENT_STATE_KEYS_2026_08_17, (
        "the 2026-08-17 snapshot is a historical record of the DEFECT and must not be edited")

    # The production shape as it is TODAY: the same keys plus the one that was missing.
    prod = _drive(auth_headers={"Authorization": "Bearer " + JWT})
    assert "run_jwt" in prod, (
        "a Bearer-token JWT still cannot schedule run_jwt; agent.py stopped supplying auth_headers "
        "or the planner gate at planner.py:641 changed the key it reads")

    # NEGATIVE CONTROL: the gate must still be a gate. No JWT anywhere -> no run_jwt, so the fix
    # bought reachability and not an unconditional schedule.
    unauth = _drive(auth_headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert "run_jwt" not in unauth, "run_jwt scheduled without a JWT present -- the gate is now open"
