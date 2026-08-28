"""Q-108 — `res.ran` on a `ToolResult`, which has `success`. One typo, one whole engine lost.

Seen in the operator's live run as a single line:

    session-lifecycle artery error: AttributeError: 'ToolResult' object has no attribute 'ran'

`agent.py` built the session-lifecycle result with `bool(res.ran)`. `ToolResult` exposes `success`.
So every mission raised AttributeError there, the artery's `except` turned it into one info line, and
**the entire session-lifecycle leg (CWE-613) was lost on every run**. The engine executed; nothing it
produced ever reached the report.

WHY THE ARTERY HANDLER MADE THIS WORSE. It exists so one broken leg cannot kill the scan, which is
right. But it converts a crash into prose, and prose scrolls past. The mission looked healthy, the
suite was green, and the only evidence was one line in a live log nobody diffs. A swallowed
AttributeError is indistinguishable from an engine that simply found nothing -- the same shape as
every other ticket this week.

The AST guard is the durable half. Fixing this one call site fixes today; the guard is what stops the
next `.ran`, `.ok` or `.ran_ok` from costing another engine.
"""
import ast
import os

import pytest

import tools


AGENT_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent.py")


def _result(**kw):
    return tools.ToolResult(kw.pop("tool", "session_lifecycle"), kw.pop("target", "https://t/"),
                            kw.pop("success", True), kw.pop("output", "ok"), kw.pop("findings", []))


# ── the contract that was violated ────────────────────────────────────────────

def test_toolresult_has_success_and_not_ran():
    res = _result()
    assert hasattr(res, "success")
    assert not hasattr(res, "ran"), (
        "if ToolResult ever grows a `ran`, this test is the place to decide what it MEANS "
        "relative to `success` -- silently having both is how the original confusion started")


def test_the_expression_agent_builds_works_against_a_real_toolresult():
    """The exact shape of the crashed line, evaluated against a real object rather than a stub. A
    stub with a `ran` attribute would have passed while production kept failing."""
    res = _result(success=True, findings=[{"title": "x"}])
    built = {"ran": bool(res.success), "confirmed": len(res.findings or [])}
    assert built == {"ran": True, "confirmed": 1}

    dead = _result(success=False, findings=[])
    assert {"ran": bool(dead.success), "confirmed": len(dead.findings or [])} == \
        {"ran": False, "confirmed": 0}


# ── the durable half ──────────────────────────────────────────────────────────

def test_no_code_in_agent_py_reads_ran_off_an_object():
    """AST, not grep: `"ran"` appears legitimately as a DICT KEY all over this codebase (the
    session-lifecycle result publishes one). Only an ATTRIBUTE access is the bug, and a text search
    cannot tell those apart -- it would either miss the defect or drown in false hits."""
    tree = ast.parse(open(AGENT_PY, encoding="utf8").read(), filename=AGENT_PY)
    bad = [n.lineno for n in ast.walk(tree)
           if isinstance(n, ast.Attribute) and n.attr == "ran"]
    assert bad == [], (
        "agent.py reads `.ran` as an attribute at line(s) %r. ToolResult has `success`; a `.ran` "
        "read raises AttributeError, and the artery handler turns that into one info line while the "
        "engine's entire output is discarded." % (bad,))


def test_the_guard_would_catch_the_original_defect():
    """Non-vacuity. Without this the assertion above passes trivially on any file with no `.ran`,
    including an empty one, and would never have caught the line it exists for."""
    planted = ast.parse("x = something()\nd = {'ran': bool(x.ran)}\n")
    bad = [n.lineno for n in ast.walk(planted)
           if isinstance(n, ast.Attribute) and n.attr == "ran"]
    assert bad == [2], bad
