"""The per-tool execution ledger must classify status HONESTLY. Regression for an optest
finding: a SCOPE BLOCK (an out-of-scope target skipped on purpose — e.g. a third-party CDN
a page loads, or a discovered subdomain on a non-pinned port) is CORRECT enforcement, not a
tool failure. A tool that returned results on its in-scope targets must read 'executed'
(with a skipped count), never 'failed'. Only a genuine error with no successful call is
'failed'; a tool whose every target was out of scope is 'skipped'."""
from __future__ import annotations

import os
import tempfile

import db as dbmod
import main as mainmod


def _fresh(mid: str):
    dbmod.init(os.path.join(tempfile.mkdtemp(), "t.db"))
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["juice-shop:3000"]}, {})


def _ledger(mid: str):
    return {t["tool"]: t for t in mainmod._tool_ledger(mid)["tools"]}


def test_scope_block_on_one_call_does_not_fail_a_tool_that_ran():
    # http_probe: 3 in-scope calls that returned, 1 off-scope target skipped (the real optest case).
    _fresh("led1")
    for _ in range(3):
        dbmod.add_log("led1", "tool_call", {"tool": "http_probe"})
        dbmod.add_log("led1", "tool_result", {"tool": "http_probe", "count": 12, "output": "links + params"})
    dbmod.add_log("led1", "tool_call", {"tool": "http_probe"})
    dbmod.add_log("led1", "scope_block", {"tool": "http_probe",
                                          "error": "SCOPE BLOCK: js.maxmind.com not in scope"})
    row = _ledger("led1")["http_probe"]
    assert row["status"] == "executed"            # NOT "failed" — it ran on its in-scope targets
    assert row["findings"] == 36
    assert "off-scope target" in row["note"] and "skipped" in row["note"]


def test_tool_with_every_target_out_of_scope_is_skipped_not_failed():
    # run_nuclei handed only a discovered subdomain on the wrong port -> nothing in-scope ran.
    _fresh("led2")
    dbmod.add_log("led2", "tool_call", {"tool": "run_nuclei"})
    dbmod.add_log("led2", "scope_block", {"tool": "run_nuclei",
                                          "error": "SCOPE BLOCK: www.juice-shop:443 not in scope (different port)"})
    row = _ledger("led2")["run_nuclei"]
    assert row["status"] == "skipped"             # did not run in-scope, but did NOT fail
    assert "out of scope" in row["note"].lower() or "not in scope" in row["note"].lower()


def test_genuine_error_with_no_successful_call_still_reads_failed():
    # A real crash (not a scope block) with nothing returned stays "failed" — behavior preserved.
    _fresh("led3")
    dbmod.add_log("led3", "tool_call", {"tool": "run_katana"})
    dbmod.add_log("led3", "tool_error", {"tool": "run_katana", "error": "katana: exec format error"})
    row = _ledger("led3")["run_katana"]
    assert row["status"] == "failed"
    assert "katana" in row["note"].lower()


def test_a_real_error_on_one_call_but_others_succeeded_is_executed_flagged():
    # If a tool errored on one call yet still returned on another, it executed (with a caveat).
    _fresh("led4")
    dbmod.add_log("led4", "tool_call", {"tool": "run_xss"})
    dbmod.add_log("led4", "tool_result", {"tool": "run_xss", "count": 0, "output": "0 XSS signal(s)"})
    dbmod.add_log("led4", "tool_call", {"tool": "run_xss"})
    dbmod.add_log("led4", "tool_error", {"tool": "run_xss", "error": "timeout on /search"})
    row = _ledger("led4")["run_xss"]
    assert row["status"] == "executed"
    assert "errored" in row["note"]


def test_clean_tool_is_executed_without_caveats():
    _fresh("led5")
    dbmod.add_log("led5", "tool_call", {"tool": "run_fingerprint"})
    dbmod.add_log("led5", "tool_result", {"tool": "run_fingerprint", "count": 5, "output": "stack: Express"})
    row = _ledger("led5")["run_fingerprint"]
    assert row["status"] == "executed"
    assert "off-scope" not in row["note"] and "errored" not in row["note"]
