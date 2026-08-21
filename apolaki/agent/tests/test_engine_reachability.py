"""Repository-wide static invocation-reference census for tool engines.

`execute()` dispatches by getattr(self, "_" + tool_name). An engine absent from both the CLAUDE_TOOLS
spec and exact executable `run_*` string literals outside its defining module has no known invocation
reference and is a strong orphan candidate. Presence proves only a static reference, not that the
deterministic scheduler can or will select the engine. Deterministic scheduling is a separate contract.

run_external_surface was exactly that. Implemented under #114, permission-registered, ~70 lines writing
to recon["external_surface"], and named in neither static reference surface. It never ran once.
"""
import ast
from pathlib import Path
import re

import deadcode_gate as dg
import tools


APP_DIR = Path(tools.__file__).resolve().parent


def _defined_engines(path=None):
    src = Path(path or tools.__file__).read_text(encoding="utf8")
    return {"run_" + m for m in re.findall(r"async def _run_([a-z0-9_]+)\(", src)}


def _spec_names():
    return {t["name"] for t in tools.CLAUDE_TOOLS}


def _production_python_paths(root=None):
    """Production Python modules, excluding tests and the engine-defining module itself."""
    base = Path(root or APP_DIR).resolve()
    return sorted(
        path for path in base.rglob("*.py")
        if "tests" not in path.relative_to(base).parts
        and "__pycache__" not in path.parts
        and path.resolve() != Path(tools.__file__).resolve()
    )


def _executable_string_literals(paths):
    """String constants in executable syntax, never comments or docstrings."""
    values = set()
    for path in paths:
        tree = ast.parse(Path(path).read_text(encoding="utf8"))
        docstrings = set()
        for owner in [tree] + [n for n in ast.walk(tree)
                               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]:
            body = getattr(owner, "body", ())
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                docstrings.add(id(body[0].value))
        values.update(
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and id(node) not in docstrings
        )
    return values


def _executable_engine_literals(paths=None):
    """Exact run_* constants in executable syntax across production consumers."""
    values = _executable_string_literals(
        paths if paths is not None else _production_python_paths())
    return {value for value in values if re.fullmatch(r"run_[a-z0-9_]+", value)}


def _dispatch_method_names(path=None):
    """Advertised names with a concrete ToolRegistry dispatch method."""
    tree = ast.parse(Path(path or tools.__file__).read_text(encoding="utf8"))
    methods = {
        node.name[1:] for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("_")
    }
    return _spec_names() & methods


def _deterministic_scheduler_names(paths=None):
    """Advertised exact tool names in the two deterministic scheduling surfaces."""
    use_paths = paths or (APP_DIR / "agent.py", APP_DIR / "planner.py")
    return _spec_names() & _executable_string_literals(use_paths)


def test_the_static_invocation_reference_census_is_not_vacuous():
    """Guard the guard: empty source/spec/reference sets must not make the orphan check pass."""
    assert len(_defined_engines()) > 50
    assert len(_spec_names()) > 20
    assert len(_production_python_paths()) > 100
    assert len(_executable_engine_literals()) > 20


def test_external_surface_has_a_static_invocation_reference():
    """The specific regression: implementation alone cannot satisfy the reference census."""
    assert "run_external_surface" in _defined_engines()
    assert hasattr(tools.ToolRegistry, "_run_external_surface")
    assert "run_external_surface" in _spec_names() | _executable_engine_literals()


def test_no_engine_is_defined_without_any_static_invocation_reference():
    """An engine referenced by neither agent syntax nor the model spec is an orphan candidate.

    Aliases count. Some engines are exposed under a bare spec name (`enumerate_ids`) with a thin
    `_enumerate_ids` method forwarding to `_run_enumerate_ids`, so `run_X` is reachable when either
    `run_X` or `X` is advertised.
    """
    references = _spec_names() | _executable_engine_literals()
    orphans = sorted(e for e in _defined_engines()
                     if e not in references and e[len("run_"):] not in references)
    assert orphans == [], (
        "engines with no static invocation reference: %s" % orphans)


def test_a_reference_planted_outside_agent_is_visible_to_the_census(tmp_path):
    """NEGATIVE CONTROL. The former guard opened agent.py and no other consumer module.

    Plant the reference in a sibling module that old scope could not see. The repository path census
    must include it and the executable-literal detector must observe it. Narrowing the path list back
    to agent.py makes this exact assertion fail.
    """
    (tmp_path / "agent.py").write_text("STEP = 'run_positive_control'\n", encoding="utf8")
    planted = tmp_path / "new_scheduler.py"
    planted.write_text("def schedule():\n    return 'run_planted_scope_bypass'\n", encoding="utf8")

    paths = _production_python_paths(tmp_path)
    assert planted in paths, "the repository census did not enumerate the planted module"
    assert "run_planted_scope_bypass" in _executable_engine_literals(paths), (
        "an engine reference outside agent.py is invisible; the old one-file guard has returned")


def test_comments_and_docstrings_cannot_rescue_an_engine_reference(tmp_path):
    path = tmp_path / "prose_only.py"
    path.write_text(
        "# run_comment_only\n"
        "def explain():\n"
        "    '''run_docstring_only'''\n"
        "    return 'ordinary text'\n",
        encoding="utf8",
    )
    names = _executable_engine_literals([path])
    assert "run_comment_only" not in names
    assert "run_docstring_only" not in names


def test_every_unscheduled_advertised_method_has_an_explicit_manual_contract():
    """G4. Manual reachability is a reviewed contract, not the residue after scheduling.

    The equality is load-bearing: a seventh advertised dispatch method absent from agent.py and
    planner.py fails here. Adding it to CLAUDE_TOOLS is not enough, and adding prose elsewhere cannot
    satisfy this scheduler census.
    """
    unscheduled = _dispatch_method_names() - _deterministic_scheduler_names()
    assert len(_spec_names()) == 75, "measured denominator moved; review the manual-only partition"
    assert len(_deterministic_scheduler_names()) == 69
    assert unscheduled == set(dg.MANUAL_ONLY_TOOL_CONTRACTS), (
        "advertised dispatch methods without a deterministic scheduler need an explicit verdict: %s"
        % sorted(unscheduled ^ set(dg.MANUAL_ONLY_TOOL_CONTRACTS)))


def test_the_scheduler_census_has_positive_controls_and_no_manual_false_positive():
    scheduled = _deterministic_scheduler_names()
    assert {"run_sqli", "run_xss", "run_mass_assign"} <= scheduled
    assert not (scheduled & set(dg.MANUAL_ONLY_TOOL_CONTRACTS))


def test_every_advertised_tool_actually_dispatches():
    """The other direction, and the stronger guard. execute() resolves a spec name via
    getattr(self, "_" + name); a spec entry with no matching method is a tool the model can select and
    that then fails at call time. Catches a rename that updates the method but not the spec."""
    missing = sorted(n for n in _spec_names()
                     if not hasattr(tools.ToolRegistry, "_" + n)
                     and n not in ("store_finding", "generate_playbook"))
    assert missing == [], "advertised in CLAUDE_TOOLS but no _<name> method to dispatch to: %s" % missing
