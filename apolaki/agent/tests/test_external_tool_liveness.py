"""Q-092: an external tool that RUNS AND FAILS must not be reported as a clean scan.

THE DEFECT, measured live (see docs/handoff/tool_liveness_audit.md section 11):

    $ sqlmap -u http://juice-shop:3000/x --batch --no-such-flag
    EXIT=2, stdout 217 bytes (banner only), stderr 79 bytes ("no such option")

`ToolRegistry._cmd` measures that exit code -- `_out_text, _exit = out.decode(...), proc.returncode`
-- and then discards it at the return edge, handing back only `(stdout, stderr)`.  `_exit` survives
only into the provenance record inside the `finally` block, where no caller can reach it.  Fourteen
wrappers therefore guard on `err.startswith("__MISSING__")`, which catches a MISSING BINARY and
nothing else.  A tool that ran and failed is byte-identical to a tool that ran and found nothing:
`_run_sqlmap` returns `success=True, "No SQLi confirmed"` for a sqlmap that never scanned.

This was not theoretical.  `run_nuclei` shipped 155 corpus invocations of `nuclei -json`, a flag
nuclei v3 renamed to `-jsonl`; it exited 2 before scanning every single time and all 155 were
recorded as clean scans.

WHY THE NEGATIVE CONTROL IS THE IMPORTANT HALF.  This project has shipped five guards that could
not fail.  `test_cmd_hands_back_the_exit_status` and
`test_wrapper_reports_not_ran_when_the_tool_exits_nonzero` MUST FAIL against today's `_cmd`, which
cannot express the distinction at all -- there is no value on the return edge that carries it.  If
they ever pass without the chokepoint being fixed, they have stopped testing anything.

`test_the_rig_itself_can_tell_the_two_apart` and `test_wrapper_reports_success_when_the_tool_runs_
cleanly` are the other half: they PASS today.  Without them a fix of "always report failure" would
satisfy the guard, and a rig whose two fake binaries did not actually differ would fail the guard
for the wrong reason.

The fake binaries are real executables on PATH, deliberately: stubbing `_cmd` itself would test the
stub.  The whole point is what a genuine non-zero `proc.returncode` does to the return edge.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys

import pytest

import scope as scope_mod
import tools as tools_mod


# The fake binaries are `#!/bin/sh` scripts on PATH.  The agent suite's authority is the Linux
# agent image (`docker run ... apolaki-agent python -m pytest tests/`); this guard exists so a
# Windows-host invocation reports "not applicable here" instead of a spurious failure, and it is
# never the environment the gate is judged in.
pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX fake-binary fixture; the gate runs in the Linux agent image")


def _fake_binary(directory, name: str, exit_code: int, stdout: str = "", stderr: str = "") -> str:
    """Write a real executable that prints fixed output and exits with a fixed code."""
    path = os.path.join(str(directory), name)
    with open(path, "w", newline="\n") as fh:
        fh.write("#!/bin/sh\n")
        if stdout:
            fh.write("cat <<'APOLAKI_EOF'\n%s\nAPOLAKI_EOF\n" % stdout)
        if stderr:
            fh.write("cat >&2 <<'APOLAKI_EOF'\n%s\nAPOLAKI_EOF\n" % stderr)
        fh.write("exit %d\n" % int(exit_code))
    os.chmod(path, 0o755)
    return path


def _registry():
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["target.tld"], [], "Q-092")
    return tools_mod.ToolRegistry(sc, mission_id=None, lab_mode=True)


def _exit_status_of(result):
    """Recover the exit status from whatever `_cmd` hands back, or None if it hands back none.

    Deliberately permissive about SHAPE and strict about PRESENCE.  Q-092 prescribes the value on
    the return edge but not its packaging, so a 3-tuple, a namedtuple field or a small result
    object all satisfy it; only "the caller cannot obtain the exit status at all" fails.
    """
    for attr in ("exit_code", "exit", "returncode", "status", "code"):
        value = getattr(result, attr, None)
        if isinstance(value, int):
            return value
    if isinstance(result, (tuple, list)):
        for item in result[2:]:
            if isinstance(item, int):
                return item
        for item in result:
            if isinstance(item, dict):
                for key in ("exit_code", "returncode", "exit", "status"):
                    if isinstance(item.get(key), int):
                        return item[key]
    if isinstance(result, dict):
        for key in ("exit_code", "returncode", "exit", "status"):
            if isinstance(result.get(key), int):
                return result[key]
    return None


# ── the rig's own controls: these PASS today ────────────────────────────────────────────────────

def test_the_rig_itself_can_tell_the_two_apart(tmp_path):
    """The two fake binaries really do differ in exit status at the OS level.

    Without this, a failure of the guards below could mean "the fixture is broken" rather than
    "`_cmd` drops the exit code", and the guard would be untrustworthy in the direction that
    matters.
    """
    failing = _fake_binary(tmp_path, "apolaki_fail", 2, stdout="banner only",
                           stderr="apolaki_fail: error: no such option: --nope")
    clean = _fake_binary(tmp_path, "apolaki_clean", 0, stdout="all tested parameters look fine")

    bad = subprocess.run([failing], capture_output=True, text=True)
    good = subprocess.run([clean], capture_output=True, text=True)

    assert bad.returncode == 2, "fixture must produce a genuinely non-zero exit"
    assert good.returncode == 0, "fixture must produce a genuinely zero exit"
    # The two are indistinguishable on the ONE axis every wrapper currently reads: neither stdout
    # carries a confirmation marker.  That is precisely why the exit code is load-bearing.
    for out in (bad.stdout, good.stdout):
        assert "is vulnerable" not in out and "sqlmap identified" not in out


def test_missing_binary_is_still_reported(tmp_path, monkeypatch):
    """The one failure mode `_cmd` DOES surface must keep working -- proof the rig drives the real
    code path, and the baseline the exit-code guard is measured against."""
    monkeypatch.setenv("PATH", str(tmp_path))
    registry = _registry()
    out, err = asyncio.run(registry._cmd(["apolaki_definitely_not_installed", "-x"]))
    assert out == ""
    assert err.startswith("__MISSING__"), (
        "the missing-binary signal is the only outcome `_cmd` reports today; if this breaks, the "
        "exit-code guard below is measuring a different defect than the one it names")


def test_wrapper_reports_success_when_the_tool_runs_cleanly(tmp_path, monkeypatch):
    """POSITIVE CONTROL. A tool that exits 0 and genuinely finds nothing is a real clean scan.

    A fix that satisfied the guards below by failing every run would break this, which is the whole
    reason it is here.  It passes today and must keep passing after the chokepoint is repaired.
    """
    _fake_binary(tmp_path, "sqlmap", 0,
                 stdout="[INFO] testing connection\n[INFO] all tested parameters do not appear "
                        "to be injectable")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    registry = _registry()

    res = asyncio.run(registry._run_sqlmap({"url": "http://target.tld/x?id=7"}))

    assert res.success is True, "a tool that ran and found nothing is a completed scan"
    assert "No SQLi confirmed" in res.output
    assert not any(f.get("severity") for f in res.findings if isinstance(f, dict)), (
        "a clean run must not manufacture a graded finding")


# ── the guards: these MUST FAIL against today's `_cmd` ───────────────────────────────────────────

def test_cmd_hands_back_the_exit_status(tmp_path, monkeypatch):
    """THE CHOKEPOINT. `_cmd` must return the exit status as a value its callers can read.

    MUST FAIL TODAY: `_cmd` returns `(stdout, stderr)` and keeps `_exit` for the provenance record
    inside `finally`, so `_exit_status_of` finds nothing and this assertion cannot be satisfied by
    any caller.  This is Q-089's `FindingWriteId` invariant in the subprocess path -- outcome
    fidelity lives in a value on the return edge, not in a side channel.
    """
    _fake_binary(tmp_path, "apolaki_exit2", 2, stdout="banner only",
                 stderr="apolaki_exit2: error: no such option: --json")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    registry = _registry()

    result = asyncio.run(registry._cmd(["apolaki_exit2", "--json"]))
    status = _exit_status_of(result)

    assert status is not None, (
        "_cmd measures proc.returncode and discards it at the return edge; no caller can check "
        "whether the tool succeeded, so a failed run is byte-identical to a clean one")
    assert status == 2, "the exit status handed back must be the one the process actually returned"


def test_cmd_reports_a_zero_exit_as_zero(tmp_path, monkeypatch):
    """The other side of the same edge: a successful run must report 0, not merely 'not None'.

    MUST FAIL TODAY for the same reason.  Paired with the test above so the repaired `_cmd` cannot
    satisfy the guard by hard-coding a failure constant.
    """
    _fake_binary(tmp_path, "apolaki_exit0", 0, stdout="finished cleanly")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    registry = _registry()

    result = asyncio.run(registry._cmd(["apolaki_exit0"]))
    status = _exit_status_of(result)

    assert status is not None, "see test_cmd_hands_back_the_exit_status"
    assert status == 0


def test_wrapper_reports_not_ran_when_the_tool_exits_nonzero(tmp_path, monkeypatch):
    """The user-visible half: a wrapper whose tool exited non-zero must NOT report a clean zero.

    MUST FAIL TODAY.  This reproduces the measured sqlmap case exactly -- exit 2, a usage error on
    stderr, no confirmation marker on stdout -- and today `_run_sqlmap` answers
    `success=True, "No SQLi confirmed [standard]"`, which is the false-clean this ticket exists to
    kill.  `success` is this codebase's spelling of `ran`: `ToolResult(tool, target, success,
    output, findings, error)`.
    """
    _fake_binary(tmp_path, "sqlmap", 2, stdout="        ___\n       __H__\n{1.7.2#stable}",
                 stderr="Usage: python3 sqlmap [options]\n\nsqlmap: error: no such option: --json")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    registry = _registry()

    res = asyncio.run(registry._run_sqlmap({"url": "http://target.tld/x?id=7"}))

    assert res.success is False, (
        "sqlmap exited 2 without scanning; reporting a completed scan makes a broken tool "
        "indistinguishable from a target with no SQL injection")
    assert res.error, "the failure must be carried on the result, not only in the logs"
    assert "No SQLi confirmed" not in (res.output or ""), (
        "'No SQLi confirmed' is a claim about the TARGET; a tool that never ran has made no such "
        "finding about it")


def test_a_failed_run_is_distinguishable_from_a_clean_run(tmp_path, monkeypatch):
    """The invariant stated directly: the two outcomes must not be equal.

    MUST FAIL TODAY -- today they ARE equal, which is the defect in one line.  Kept separate from
    the assertion above because this is the property that matters even if the chosen spelling of
    "did not run" changes later.
    """
    failed_dir = tmp_path / "failed"
    clean_dir = tmp_path / "clean"
    failed_dir.mkdir()
    clean_dir.mkdir()
    _fake_binary(failed_dir, "sqlmap", 2, stdout="banner only",
                 stderr="sqlmap: error: no such option: --json")
    _fake_binary(clean_dir, "sqlmap", 0,
                 stdout="[INFO] all tested parameters do not appear to be injectable")

    real_path = os.environ.get("PATH", "")
    registry = _registry()

    monkeypatch.setenv("PATH", str(failed_dir) + os.pathsep + real_path)
    failed = asyncio.run(registry._run_sqlmap({"url": "http://target.tld/x?id=7"}))
    monkeypatch.setenv("PATH", str(clean_dir) + os.pathsep + real_path)
    clean = asyncio.run(registry._run_sqlmap({"url": "http://target.tld/x?id=7"}))

    assert (failed.success, bool(failed.error)) != (clean.success, bool(clean.error)), (
        "a tool that exited 2 without scanning and a tool that scanned and found nothing produce "
        "the identical ToolResult; every one of the 155 nuclei runs in the corpus was the former "
        "and was recorded as the latter")
