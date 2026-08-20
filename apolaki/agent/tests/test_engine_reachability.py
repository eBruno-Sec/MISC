"""Static invocation-reference census for tool engines.

`execute()` dispatches by getattr(self, "_" + tool_name). An engine absent from both the CLAUDE_TOOLS
spec and exact `run_*` string literals in agent.py has no known invocation reference and is a strong
orphan candidate. Presence proves only a static reference, not that the deterministic scheduler can or
will select the engine. This file does not parse planner.py or trace values into `next_batch`.

run_external_surface was exactly that. Implemented under #114, permission-registered, ~70 lines writing
to recon["external_surface"], and named in neither static reference surface. It never ran once.
"""
import ast
import re

import tools


def _defined_engines():
    src = open(tools.__file__, encoding="utf8").read()
    return {"run_" + m for m in re.findall(r"async def _run_([a-z0-9_]+)\(", src)}


def _spec_names():
    return {t["name"] for t in tools.CLAUDE_TOOLS}


def _agent_literal_names():
    """Exact engine-name literals in executable agent syntax; not planner reachability."""
    import agent as agent_mod
    src = open(agent_mod.__file__, encoding="utf8").read()
    tree = ast.parse(src)
    return {node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and re.fullmatch(r"run_[a-z0-9_]+", node.value)}


def test_the_static_invocation_reference_census_is_not_vacuous():
    """Guard the guard: empty source/spec/reference sets must not make the orphan check pass."""
    assert len(_defined_engines()) > 50
    assert len(_spec_names()) > 20
    assert len(_agent_literal_names()) > 20


def test_external_surface_has_a_static_invocation_reference():
    """The specific regression: implementation alone cannot satisfy the reference census."""
    assert "run_external_surface" in _defined_engines()
    assert hasattr(tools.ToolRegistry, "_run_external_surface")
    assert "run_external_surface" in _spec_names() | _agent_literal_names()


def test_no_engine_is_defined_without_any_static_invocation_reference():
    """An engine referenced by neither agent syntax nor the model spec is an orphan candidate.

    Aliases count. Some engines are exposed under a bare spec name (`enumerate_ids`) with a thin
    `_enumerate_ids` method forwarding to `_run_enumerate_ids`, so `run_X` is reachable when either
    `run_X` or `X` is advertised.
    """
    references = _spec_names() | _agent_literal_names()
    orphans = sorted(e for e in _defined_engines()
                     if e not in references and e[len("run_"):] not in references)
    assert orphans == [], (
        "engines with no static invocation reference: %s" % orphans)


def test_every_advertised_tool_actually_dispatches():
    """The other direction, and the stronger guard. execute() resolves a spec name via
    getattr(self, "_" + name); a spec entry with no matching method is a tool the model can select and
    that then fails at call time. Catches a rename that updates the method but not the spec."""
    missing = sorted(n for n in _spec_names()
                     if not hasattr(tools.ToolRegistry, "_" + n)
                     and n not in ("store_finding", "generate_playbook"))
    assert missing == [], "advertised in CLAUDE_TOOLS but no _<name> method to dispatch to: %s" % missing
