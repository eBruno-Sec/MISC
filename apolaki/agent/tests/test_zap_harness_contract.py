"""Q-023 -- the ZAP live harness must report ZAP facts, never harness misconfiguration.

Q-023 was filed as "ZAP has never executed in any mission". Measurement disproved the strong form of
that claim: `tools._run_zap` runs end to end, and `test_zap_live_acceptance` passes a real full
mission with a persisted `run_zap` tool_call. What was true is that nobody could SEE it, and one of
the reasons nobody could see it is in this file's subject.

The live acceptance module reads its inputs from the environment. Two of those reads were bare
`os.environ[...]` subscripts, so an unset variable raised `KeyError: 'ZAP_LIVE_SELF_HOST'` from a
file named `test_zap_live_acceptance` -- which reads, to anyone scanning output, as ZAP failing. That
is the project's recurring "the apparatus lied about the thing it was built to measure" shape, and it
cost this lane a run.

These tests run in the ORDINARY suite: they need no daemon, no lab and no network, because they check
the harness's own contract rather than ZAP's behaviour. `test_zap_live_acceptance`'s module-level
`skipif` means its own tests are invisible by default -- so if this contract is not asserted here, it
is asserted nowhere.
"""
from __future__ import annotations

import ast
import os
import socket
from pathlib import Path

import pytest

import test_zap_live_acceptance as live


LIVE_MODULE = Path(live.__file__).resolve()


def _bare_environ_reads(source: str, filename: str) -> list:
    """Every `os.environ[...]` READ in `source`, as (line, key) pairs.

    AST rather than a regex, deliberately: the fix that removed these reads also documents them in a
    docstring, and a text search cannot tell a live subscript from a quoted one. It also only counts
    `Load` context, so `os.environ["X"] = ...` (a deliberate write) is not confused for a read.
    """
    out = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        if not isinstance(node, ast.Subscript) or not isinstance(node.ctx, ast.Load):
            continue
        value = node.value
        if (isinstance(value, ast.Attribute) and value.attr == "environ"
                and isinstance(value.value, ast.Name) and value.value.id == "os"):
            key = node.slice.value if isinstance(node.slice, ast.Constant) else "<dynamic>"
            out.append((node.lineno, key))
    return sorted(out)


def test_zap_live_harness_never_reads_the_environment_without_a_contract():
    """No bare `os.environ[...]` in the live ZAP harness.

    Every input must either default to something the harness can derive (`_self_host`) or fail with a
    message naming the variable and a usable value (`_required_target`). A `KeyError` names the
    variable but not the fix, and does it in ZAP's voice.
    """
    found = _bare_environ_reads(LIVE_MODULE.read_text(encoding="utf8"), str(LIVE_MODULE))
    assert found == [], (
        "bare os.environ[...] reads in the ZAP live harness would surface a missing env var as a "
        "KeyError that reads like a ZAP failure: %s" % found
    )


def test_the_bare_environ_guard_actually_detects_one(tmp_path):
    """NEGATIVE CONTROL -- the guard above is worthless if it cannot fail.

    A guard that has never been shown to go red is a declaration, not a check (the lesson this
    codebase has now learned four times). Reintroduce the exact defect into a copy and require the
    same inventory function to catch it -- and assert the mutant TEXT really changed first, because a
    mutation that never applied is a false all-clear.
    """
    original = LIVE_MODULE.read_text(encoding="utf8")
    mutant_src = original.replace(
        "    host = _self_host()",
        '    host = os.environ["ZAP_LIVE_SELF_HOST"]',
    )
    assert mutant_src != original, "mutation did not apply -- the anchor line moved; fix this test"
    assert 'host = os.environ["ZAP_LIVE_SELF_HOST"]' in mutant_src

    mutant = tmp_path / "mutant_live_acceptance.py"
    mutant.write_text(mutant_src, encoding="utf8")

    found = _bare_environ_reads(mutant.read_text(encoding="utf8"), str(mutant))
    assert [key for _line, key in found] == ["ZAP_LIVE_SELF_HOST"], (
        "the reintroduced bare read was not detected; the guard cannot fail and proves nothing: %s"
        % found
    )
    # ...and the real file is still clean, so the mutant did not leak into the assertion above.
    assert _bare_environ_reads(original, str(LIVE_MODULE)) == []


def test_self_host_derives_a_reachable_address_when_the_variable_is_unset(monkeypatch):
    """The self-host is a harness fact the harness can supply, so an unset var must not be fatal.

    MEASURED before this default was chosen: on the `apolaki_default` user-defined network, a
    throwaway container serving on 42888 was reached from a second container using
    `socket.gethostname()` alone (HTTP 200). Docker's embedded DNS resolves the bare container
    hostname, which is exactly what ZAP needs to call back.
    """
    monkeypatch.delenv("ZAP_LIVE_SELF_HOST", raising=False)
    assert live._self_host() == socket.gethostname()


def test_self_host_treats_an_empty_variable_as_unset_on_purpose(monkeypatch):
    """`x or DEFAULT` hides a real empty-string input -- except where empty is meaningless.

    This project has been bitten twice by a falsy default swallowing a genuine empty value, so the
    decision is pinned rather than left to read as an accident. An empty hostname can be neither
    bound nor resolved; honouring it would only reproduce the failure the default replaces.
    """
    monkeypatch.setenv("ZAP_LIVE_SELF_HOST", "")
    assert live._self_host() == socket.gethostname()


def test_an_explicit_self_host_still_wins(monkeypatch):
    """The derived default must not become a silent override of an operator's explicit choice."""
    monkeypatch.setenv("ZAP_LIVE_SELF_HOST", "apolaki-zap-lane7-live")
    assert live._self_host() == "apolaki-zap-lane7-live"


@pytest.mark.parametrize("value", [None, ""])
def test_the_live_target_is_never_guessed_and_says_what_to_set(monkeypatch, value):
    """The target is a SCOPE decision, so unlike the self-host it must stay loud.

    The asymmetry is the point: deriving a callback address for ourselves is safe, choosing what to
    point a real full mission at is not. The failure must still name the variable AND a usable value,
    which a bare KeyError does not.
    """
    if value is None:
        monkeypatch.delenv("ZAP_LIVE_TARGET", raising=False)
    else:
        monkeypatch.setenv("ZAP_LIVE_TARGET", value)
    with pytest.raises(AssertionError) as excinfo:
        live._required_target()
    message = str(excinfo.value)
    assert "ZAP_LIVE_TARGET" in message
    assert "http://" in message, "the error must carry a usable example, not just the var name"


def test_an_explicit_live_target_is_returned_unchanged(monkeypatch):
    monkeypatch.setenv("ZAP_LIVE_TARGET", "http://domsource:8080")
    assert live._required_target() == "http://domsource:8080"


def test_the_live_module_is_still_gated_off_by_default():
    """REGRESSION -- making the harness self-sufficient must not switch it on.

    These tests engage real missions against real labs. Defaulting the self-host removes a papercut;
    it must not remove the opt-in. If `ZAP_LIVE_ACCEPTANCE` is unset the module must stay skipped.
    """
    assert live.LIVE == bool(os.getenv("ZAP_LIVE_ACCEPTANCE"))
    marks = getattr(live, "pytestmark")
    marks = marks if isinstance(marks, list) else [marks]
    skipifs = [m for m in marks if m.name == "skipif"]
    assert skipifs, "the live ZAP module lost its opt-in gate"
    assert skipifs[0].args[0] is (not live.LIVE)
