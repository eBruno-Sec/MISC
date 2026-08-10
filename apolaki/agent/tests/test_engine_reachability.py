"""Every engine must be INVOCABLE by something.

execute() dispatches by getattr(self, "_" + tool_name), so an engine is reachable only if some caller
emits its name -- either the deterministic planner (a hardcoded list in agent.py) or the agentic path
(the CLAUDE_TOOLS spec handed to the model). An engine in NEITHER is dead capability: fully implemented,
registered for permissions, and impossible to run.

run_external_surface was exactly that. Implemented under #114, permission-registered, ~70 lines writing
to recon["external_surface"], and named in no spec and no planner list. It never ran once.
"""
import re

import tools


def _defined_engines():
    src = open(tools.__file__, encoding="utf8").read()
    return {"run_" + m for m in re.findall(r"async def _run_([a-z0-9_]+)\(", src)}


def _spec_names():
    return {t["name"] for t in tools.CLAUDE_TOOLS}


def _planner_names():
    import agent as agent_mod
    src = open(agent_mod.__file__, encoding="utf8").read()
    return set(re.findall(r'"(run_[a-z0-9_]+)"', src))


def test_the_reachability_scan_is_not_vacuous():
    """Guard the guard: if these sets ever come back empty the test below passes for free."""
    assert len(_defined_engines()) > 50
    assert len(_spec_names()) > 20
    assert len(_planner_names()) > 20


def test_external_surface_is_invocable():
    """The specific regression. It is implemented and permission-registered; it must be callable."""
    assert "run_external_surface" in _defined_engines()
    assert hasattr(tools.ToolRegistry, "_run_external_surface")
    assert "run_external_surface" in _spec_names() | _planner_names()


def test_no_engine_is_defined_without_any_possible_caller():
    """An engine reachable from neither the planner nor the model spec cannot ever execute.

    Aliases count. Some engines are exposed under a bare spec name (`enumerate_ids`) with a thin
    `_enumerate_ids` method forwarding to `_run_enumerate_ids`, so `run_X` is reachable when either
    `run_X` or `X` is advertised.
    """
    reachable = _spec_names() | _planner_names()
    orphans = sorted(e for e in _defined_engines()
                     if e not in reachable and e[len("run_"):] not in reachable)
    assert orphans == [], (
        "engines with no possible caller (implemented but unrunnable): %s" % orphans)


def test_every_advertised_tool_actually_dispatches():
    """The other direction, and the stronger guard. execute() resolves a spec name via
    getattr(self, "_" + name); a spec entry with no matching method is a tool the model can select and
    that then fails at call time. Catches a rename that updates the method but not the spec."""
    missing = sorted(n for n in _spec_names()
                     if not hasattr(tools.ToolRegistry, "_" + n)
                     and n not in ("store_finding", "generate_playbook"))
    assert missing == [], "advertised in CLAUDE_TOOLS but no _<name> method to dispatch to: %s" % missing
