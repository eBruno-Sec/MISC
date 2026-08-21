"""I-4: behavioural confirmations retain the control that ruled out a benign result.

The control belongs on the finding emitted by the oracle.  A report/proof consumer must
not infer one later from a family name or from a confident-sounding description.
"""

import asyncio

import pytest

import exposure_tool as exposure
import header_trust_tool as header_trust
import proof_schema
import sqli_tool as sqli
import xss_tool as xss
from tools import ToolRegistry, _mark_source_derived, _not_found_control


def _sqli_findings():
    return {
        "error": sqli.error_finding(
            "https://target.test/items?id=1", "id", "'",
            [{"dbms": "SQLite", "pattern": "SQLITE_ERROR"}],
        ),
        "quote_recovery": sqli.quote_recovery_finding(
            "https://target.test/items?id=1", "id", 200, 500, 200,
        ),
        "boolean": sqli.boolean_finding(
            "https://target.test/items?id=1", "id",
            {"ctx": "numeric", "true": "1 AND 1=1", "false": "1 AND 1=2"},
        ),
        "auth_bypass": sqli.auth_bypass_finding(
            "https://target.test/login", "email", "' OR 1=1--",
            "session/JWT token issued for an invalid credential",
        ),
        "union": sqli.union_finding(
            "https://target.test/items?id=1", "id", 3, "'", ["users"],
            ["user@example.test:0123456789abcdef"],
        ),
        "time": sqli.time_finding(
            "https://target.test/items?id=1", "id",
            {"dbms": "MySQL", "payload": "1 AND SLEEP(5)",
             "control": "1 AND SLEEP(0)"},
            0.12, 5.21, 5,
        ),
        "structural": sqli.structural_finding(
            "https://target.test/items?sort=name", "sort",
            [{"dbms": "SQLite", "pattern": "no such table"}],
        ),
    }


def _assert_sqli_controls(findings):
    assert set(findings) == {
        "error", "quote_recovery", "boolean", "auth_bypass", "union", "time", "structural",
    }
    for name, finding in findings.items():
        assert finding["confidence"] == "confirmed", name
        assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED, name
        controls = finding.get("negative_controls")
        assert isinstance(controls, list) and controls, name
        assert all(isinstance(control, dict) and control.get("kind") for control in controls), name


def test_every_sqli_confirmation_carries_its_executed_negative_control():
    _assert_sqli_controls(_sqli_findings())


def test_sqli_control_artifacts_quote_the_observation_that_was_run():
    findings = _sqli_findings()
    quote = findings["quote_recovery"]["negative_controls"]
    assert quote[0]["status"] == 200
    assert quote[1]["status"] == 200
    assert quote[1]["payload_suffix"] == "''"

    boolean = findings["boolean"]["negative_controls"]
    assert boolean[0]["payload"] == "1 AND 1=2"
    assert "diverged" in boolean[0]["result"]

    timing = findings["time"]["negative_controls"]
    assert timing == [{
        "kind": "zero-delay-control",
        "payload": "1 AND SLEEP(0)",
        "elapsed_seconds": 0.12,
        "result": "control stayed below the injected 5s delay",
    }]


def test_clean_sqli_twins_do_not_reach_a_confirmed_builder():
    assert sqli.error_signatures("normal page", "normal page") == []
    assert not sqli.quote_break_recovers(200, 200, 200)
    assert not sqli.analyze_boolean(
        "same", "same", "same", baseline_samples=["same", "same"]
    )
    assert not sqli.auth_bypass_confirmed(401, "denied", 401, "denied")
    confirmed, hits = sqli.structural_confirmed("normal", "normal", "normal")
    assert not confirmed and hits == []


def test_no_consumer_backfills_a_missing_runtime_control():
    bare = {
        "title": "synthetic confirmed runtime finding",
        "confidence": "confirmed",
        "family": "sqli",
        "evidence": "payload changed the target",
    }
    assert proof_schema.control_status(bare) == proof_schema.CONTROL_NOT_RECORDED
    assert "negative_controls" not in bare


def _assert_union_baseline_blocks():
    calls = []

    async def get(_client, target):
        calls.append(target)
        raise AssertionError("no UNION probe may run when its marker is already in the baseline")

    got = asyncio.run(ToolRegistry._sqli_union(
        object(), None, get, "https://target.test/items?id=1", "id", "1",
        "ordinary page already containing " + sqli.UNION_MARK,
    ))
    assert got is None
    assert calls == []


def test_union_marker_must_be_absent_from_the_real_baseline():
    _assert_union_baseline_blocks()


def test_semantic_mutant_dropping_control_artifacts_is_killed(monkeypatch):
    original = sqli._base

    def drops_artifact(*args, **kwargs):
        finding = original(*args, **kwargs)
        finding.pop("negative_controls", None)
        return finding

    monkeypatch.setattr(sqli, "_base", drops_artifact)
    with pytest.raises(AssertionError, match="error"):
        _assert_sqli_controls(_sqli_findings())


def test_semantic_mutant_bypassing_union_baseline_is_killed(monkeypatch):
    monkeypatch.setattr(sqli, "union_hit", lambda _body: False)
    with pytest.raises(AssertionError, match="no UNION probe may run"):
        _assert_union_baseline_blocks()


def test_exposure_emitter_retains_the_not_found_twin():
    check = {
        "name": "Environment file exposed", "path": ".env", "severity": "high",
        "family": "config_exposure", "sig": [r"DB_PASSWORD="],
    }
    finding = exposure.classify(
        check, 200, "DB_PASSWORD=secret", "text/plain", "ordinary not-found page",
    )
    assert finding is not None
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    assert finding["negative_controls"][0]["kind"] == "not-found-baseline"
    assert finding["negative_controls"][0]["response_length"] == len("ordinary not-found page")


def test_null_byte_harvest_retains_the_plain_path_refusal():
    finding = exposure.harvest_finding(
        "https://target.test/files/secret.bak%2500.md", "files/secret.bak", True,
        "confidential password=secret",
    )
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    assert finding["negative_controls"][0]["kind"] == "plain-path-refusal"


def test_direct_harvest_retains_the_random_not_found_twin():
    control = {
        "kind": "not-found-baseline", "status": 404, "response_length": 18,
        "result": "random sibling did not return sensitive content",
    }
    finding = exposure.harvest_finding(
        "https://target.test/files/secret.bak", "files/secret.bak", False,
        "confidential password=secret", negative_control=control,
    )
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    assert finding["negative_controls"] == [control]


def test_reflected_xss_retains_the_harmless_canary_control():
    finding = xss.reflection_finding(
        "https://target.test/search?q=hello", "q", "html",
        evidence='...<bbh-xss-marker data-x="1">...',
    )
    assert finding["confidence"] == "confirmed"
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    assert finding["negative_controls"][0]["payload"] == xss.CANARY


def test_header_trust_retains_both_denial_controls():
    probes = {
        "baseline": {"status": 403, "body": "denied"},
        "with_header": {"status": 200, "body": "private account"},
        "value_control": {"status": 403, "body": "denied"},
    }
    finding = header_trust.finding_header_trust(
        "https://target.test/admin", "X-Forwarded-For", "127.0.0.1", "loopback trusted",
        probes, {"verdict": "confirmed", "reason": "only the valid value granted access"},
    )
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_RECORDED
    kinds = {item["kind"] for item in finding["negative_controls"]}
    assert kinds == {"header-absent", "implausible-header-value"}

    override = header_trust.finding_url_override(
        "https://target.test", "/admin", "X-Rewrite-URL",
        {"direct": {"status": 403, "body": "denied"},
         "permitted": {"status": 200, "body": "home"},
         "overridden": {"status": 200, "body": "private account"}},
        {"verdict": "confirmed", "reason": "override served the denied resource"},
    )
    assert proof_schema.control_status(override) == proof_schema.CONTROL_RECORDED
    assert {item["kind"] for item in override["negative_controls"]} == {
        "direct-denied-path", "permitted-path-body",
    }


def test_random_not_found_control_requires_an_observation_that_ran():
    assert _not_found_control({"status": 404, "body": "missing"}) == {
        "kind": "not-found-baseline", "status": 404, "response_length": 7,
        "result": "the randomized missing-path response did not match the reported sensitive resource",
    }
    assert _not_found_control({"status": 0, "body": ""}) is None
    assert _not_found_control({"status": 404, "body": "", "error": "timeout"}) is None


def test_js_review_confirmation_is_typed_as_source_derived_before_emission():
    finding = {
        "title": "Credential exposed in a source comment", "confidence": "confirmed",
        "family": "sensitive_exposure", "evidence": "source line 7",
    }
    assert _mark_source_derived([finding]) == [finding]
    assert proof_schema.proof_kind(finding) == proof_schema.SOURCE_DERIVED
    assert proof_schema.control_status(finding) == proof_schema.CONTROL_NOT_APPLICABLE


def test_source_marker_leaves_nonconfirmed_review_output_unchanged():
    candidate = {"confidence": "candidate", "family": "sensitive_exposure"}
    _mark_source_derived([candidate, "raw review note"])
    assert "provenance" not in candidate


def test_semantic_mutant_dropping_exposure_control_is_killed():
    check = {
        "name": "Environment file exposed", "path": ".env", "severity": "high",
        "family": "config_exposure", "sig": [r"DB_PASSWORD="],
    }
    mutant = exposure.classify(
        check, 200, "DB_PASSWORD=secret", "text/plain", "ordinary not-found page",
    )
    mutant.pop("negative_controls")
    with pytest.raises(AssertionError, match="recorded"):
        assert proof_schema.control_status(mutant) == proof_schema.CONTROL_RECORDED


def test_semantic_mutant_dropping_source_provenance_is_killed():
    mutant = {"title": "source secret", "confidence": "confirmed", "family": "sensitive_exposure"}
    _mark_source_derived([mutant])
    for key in ("provenance", "lane", "analysis"):
        mutant.pop(key)
    with pytest.raises(AssertionError, match="source-derived"):
        assert proof_schema.proof_kind(mutant) == proof_schema.SOURCE_DERIVED


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# THE EMITTER INVENTORY -- because everything above is a list of NAMES.
#
# MEASURED 2026-08-21 by the guard-verification lane: deleting the `negative_controls` artifact from
# `tools.ToolRegistry._confirm_read_object_idor` -- a confirmed cross-user IDOR emitter -- left this
# file at `17 passed` AND the full suite at `3507 passed / 0 failed`, byte-identical to the pristine
# tree. Every emitter named above is genuinely pinned; an emitter NOT named above was free to ship
# with its control deleted and nothing in 3507 tests noticed. Transcript:
# docs/handoff/guard_verification.md.
#
# This is a RATCHET ON THE ARTIFACTS THAT EXIST, not a claim that every confirmed emitter has one --
# that claim would be false, and a guard asserting it would be the fourth guard here that cannot
# fail. It ratchets in the DELETION direction only: a lane adding a control is never blocked, and a
# lane removing one has to say so here.
# ══════════════════════════════════════════════════════════════════════════════════════════════════

import ast
from pathlib import Path

#: (module, enclosing function) -> number of measured sites attaching a `negative_controls` artifact.
#: Counted as AST NODES (a subscript assignment or a dict-literal key), never as grep lines.
_CONTROL_ATTACHMENTS = {
    ("bie.py", "browser_evidence"): 1,
    ("bie.py", "finding_client_side_authz"): 1,
    ("bie.py", "finding_param_swap"): 1,
    ("exposure_tool.py", "classify"): 1,
    ("exposure_tool.py", "harvest_finding"): 2,
    ("header_trust_tool.py", "finding_header_trust"): 1,
    ("header_trust_tool.py", "finding_url_override"): 1,
    ("mass_assign_tool.py", "mass_assignment_finding"): 1,
    ("mass_assign_tool.py", "unverified_lead"): 1,
    ("sqli_tool.py", "_base"): 1,
    ("tools.py", "_confirm_create_object_idor"): 1,
    ("tools.py", "_confirm_read_object_idor"): 2,
    ("tools.py", "_run_authz_matrix"): 1,
    ("tools.py", "_run_exposure"): 1,
    ("tools.py", "probe"): 1,
    ("tools.py", "probe_url"): 1,
    ("ws_tool.py", "cswsh_finding"): 1,
    ("ws_tool.py", "upgrade_lead"): 1,
    ("xss_tool.py", "reflection_finding"): 1,
}


def _control_attachment_sites(paths):
    """Sites that ATTACH a `negative_controls` artifact, by AST node.

    Two shapes, both real in this tree: `finding["negative_controls"] = [...]` (a subscript
    assignment) and `"negative_controls": [...]` inside a returned dict literal. Only
    `negative_controls` is counted -- the other `proof_schema.CONTROL_KEYS` names collide with
    unrelated payload/catalog dictionaries (`cmdi_tool.time_payloads` uses `control` for a timing
    payload, `main.defense_catalog` uses `controls` for D3FEND rows), and counting those would make
    this inventory move for reasons that have nothing to do with a finding's proof."""
    out = {}
    for path in paths:
        tree = ast.parse(Path(path).read_text(encoding="utf8"), filename=str(path))
        parents = {child: parent for parent in ast.walk(tree)
                   for child in ast.iter_child_nodes(parent)}

        def owner(node):
            cur = node
            while cur in parents:
                cur = parents[cur]
                if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return cur.name
            return "<module>"

        for node in ast.walk(tree):
            hits = 0
            if isinstance(node, ast.Assign):
                hits += sum(1 for t in node.targets
                            if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                            and t.slice.value == "negative_controls")
            if isinstance(node, ast.Dict):
                hits += sum(1 for k in node.keys
                            if isinstance(k, ast.Constant) and k.value == "negative_controls")
            if hits:
                key = (Path(path).name, owner(node))
                out[key] = out.get(key, 0) + hits
    return out


def _production_modules():
    root = Path(proof_schema.__file__).resolve().parent
    return sorted(p for p in root.rglob("*.py")
                  if not ({"tests", "tier3"} & set(p.relative_to(root).parts[:-1])))


def test_no_emitter_quietly_stops_attaching_its_control():
    """The measured artifact ratchet. Deleting a control artifact from ANY emitter that has one is
    red -- including the emitters this file does not name, which is exactly the gap that let a
    confirmed IDOR emitter lose its control with a fully green suite."""
    measured = _control_attachment_sites(_production_modules())
    lost = {key: {"pinned": n, "measured": measured.get(key, 0)}
            for key, n in _CONTROL_ATTACHMENTS.items() if measured.get(key, 0) < n}
    assert lost == {}, (
        "an emitter stopped attaching its negative-control artifact. A finding it grades CONFIRMED "
        "now carries no evidence that the benign explanation was ruled out. If the removal is "
        "deliberate, lower the count HERE in the same commit and say why:\n%r" % lost)


def test_the_attachment_scan_is_non_vacuous_and_sees_both_shapes(tmp_path):
    """POSITIVE CONTROL. A scanner returning {} would make the ratchet above pass forever. Both
    production shapes must be visible, and an emitter with no control must NOT be counted."""
    both = tmp_path / "planted_emitter.py"
    both.write_text(
        'def subscript_shape(f):\n    f["negative_controls"] = [{"kind": "k"}]\n    return f\n\n'
        'def literal_shape():\n    return {"confidence": "confirmed", "negative_controls": [{"kind": "k"}]}\n\n'
        'def no_control():\n    return {"confidence": "confirmed"}\n',
        encoding="utf8")
    assert _control_attachment_sites([both]) == {
        ("planted_emitter.py", "subscript_shape"): 1,
        ("planted_emitter.py", "literal_shape"): 1,
    }
    assert len(_control_attachment_sites(_production_modules())) >= len(_CONTROL_ATTACHMENTS)


def test_every_pinned_attachment_names_a_real_production_module():
    """A pin for a module that no longer exists is an inventory guarding nothing."""
    names = {p.name for p in _production_modules()}
    assert {mod for mod, _fn in _CONTROL_ATTACHMENTS} <= names
