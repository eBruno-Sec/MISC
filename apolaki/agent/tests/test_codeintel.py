"""Tests for the Code Intelligence static reviewer."""
from __future__ import annotations

import os
import tempfile

import codeintel
import techniques as T


def _write(d, name, body):
    with open(os.path.join(d, name), "w", encoding="utf-8") as f:
        f.write(body)


def test_review_finds_known_sinks():
    d = tempfile.mkdtemp()
    _write(d, "app.js",
           "  // app.put('/x', security.isAuthorized())\n"
           "const q = 'SELECT * FROM u WHERE id=' + req.query.id\n"
           "child_process.exec(req.body.cmd)\n"
           "const apiKey = 'AKIA1234567890abcdef'\n")
    r = codeintel.review(d)
    rules = {f["rule"] for f in r["findings"]}
    assert "commented_auth" in rules      # missing-auth route
    assert "code_exec_sink" in rules      # command injection
    assert "sql_string_build" in rules    # sqli
    assert "hardcoded_secret" in rules
    assert r["total"] >= 4
    for f in r["findings"]:               # every lead is actionable
        assert f["technique"] and f["confirm"] and f["file"] and f["line"] and f["severity"]


def test_every_rule_maps_to_a_real_technique():
    # a code finding must link into the taxonomy — no dangling technique ids
    for rid, tech, _sev, _rx, _why, _conf in codeintel._RULES:
        assert tech in T.TECHNIQUES, "rule '%s' maps to unknown technique '%s'" % (rid, tech)


def test_review_graceful_on_bad_path():
    r = codeintel.review("/no/such/dir/does/not/exist")
    assert "error" in r and r["findings"] == []


def test_skips_noise_dirs_and_caps():
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "node_modules"))
    _write(os.path.join(d, "node_modules"), "junk.js", "child_process.exec(req.body.x)\n")
    r = codeintel.review(d)
    assert r["total"] == 0                # node_modules skipped
