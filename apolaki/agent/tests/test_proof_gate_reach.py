"""Anything that PRESENTS a finding must read it through the proof gate (#125, Codex audit).

`proof_schema.demote_unproven` is deliberately non-destructive: it rewrites a confirmed-but-unproven
finding's confidence to "lead" and leaves the row in the list. That design is fine, but it means the gate
only helps a consumer that actually calls it — and it was called in exactly ONE of fourteen places that
read findings. The gate ran, correctly rejected a finding, and almost every consumer ignored the verdict:

    risk_score()          a demoted lead still added its full severity weight (80/Critical vs 40/High)
    coverage counts       "Assessment Coverage -> Findings" disagreed with "Total Findings"
    AI wrap-up prompt     demoted rows asserted to the model as "confirmed findings"
    retest planner        a demoted lead re-confirmed or dismissed as if it had been real
    memory snapshot       future scans inherit demoted rows as prior confirmed truth
    SARIF / PoC export    proof-gated semantics stop holding exactly where output leaves the platform

Patching them one at a time is the wrong fix, because the next consumer inherits the bug. This is the
ratchet: the count of presentation-path readers still using RAW findings may fall, never rise.

Q-076 -- WHAT THIS FILE GOT WRONG, and it is the same defect it exists to catch.

The ratchet was a COUNT and nothing else. Measured at HEAD it stood at 11 raw sites against a ceiling of
14: slack 3, and the failure message named NONE of them while the scan held every `file:line`. That is not
a cosmetic gap. One site could be gated and a new one introduced in the same commit AT CONSTANT COUNT and
this file was structurally incapable of noticing -- the SARIF leak recorded in the comment below is that
exact event, caught late only because a human happened to look.

A COUNT CANNOT BE DIFFED. Naming the delta is not a formatting change; it requires recording WHICH sites
were raw when the baseline was taken. That is `_RAW_BASELINE`. The shape is the one `liveness.py::evaluate`
has had all along (`regressions = base - confirmed`, named) with the polarity inverted, because here the
baseline records what is RAW: `newly_raw = now - base` FAILS, `resolved = base - now` never does.
"""
import ast
import os
import shutil
from collections import Counter

import pytest

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Call sites that legitimately need the RAW, un-gated set: scan-time storage, dedupe, and the blind
# benchmark seal (which must hash what the engines actually produced, before any reporting concern).
# Anything NOT here that reads raw findings and shows them to a human, a model, an export or a future
# scan is a gap. Each entry names WHY, so an addition has to be argued rather than appended.
#
# Q-076: this dict was DEAD. `grep -rn _RAW_IS_CORRECT agent/` returned two hits, both in this file --
# its own definition and the word inside a failure string. No code read it, and neither entry described a
# counted site: db.py's raw calls are excluded structurally by `_scan_raw_sites` (bare-name branch), and
# `_close_autonomy_loop` holds no `get_findings` call at all -- agent.py's only raw site is in
# `BBHAgent._triage`. So the message advised "add it to _RAW_IS_CORRECT with a reason", and doing that
# changed nothing, because the count never consulted the dict.
#
# It is now an ANNOTATION on the diff, keyed the same way as the baseline (`file.py::scope`), and NOT an
# exclusion. An excluded entry would vanish from the diff, and Q-017 established that a gate may annotate
# a reader, never hide it. A raw-correct site stays counted, stays named, and carries its reason.
_RAW_IS_CORRECT = {
    "db.py": "internal: iterating rows to build derived tables. Enforced in the scanner, not here: "
             "db.py's own bare-name `get_findings(mid)` calls are skipped structurally",
    "agent.py::BBHAgent._triage": "scan-time: triage reasons about what the engines actually produced, "
                                  "before any presentation concern. Its sibling read four lines up is "
                                  "already gated, which is the pair that makes the split deliberate",
}

# Raw `db.get_findings(` call sites remaining. THIS NUMBER MAY ONLY FALL.
# 20 -> 15: the PoC export, PoC bundle, retest planner, cross-session memory snapshot and graph inputs
# now read get_findings_gated (Codex batch 2 #5, #6, #11). Five consumers that presented proof-demoted
# rows as confirmed.
# MEASURED, not estimated — I first wrote 11 from memory and the real count was 20, which is exactly the
# kind of invented baseline that makes a ratchet meaningless. Two consumers (the AI wrap-up prompt and the
# coverage counts) are already migrated; the rest are tracked in tasks #50/#51 and are recorded here
# rather than silently tolerated. Lower this as each is moved to get_findings_gated().
# RATCHETED 15 -> 14 when the SARIF export was gated. A ceiling that is never lowered lets a real leak
# hide under the allowance: SARIF sat raw while its sibling poc_bundle_export was gated, and the count
# stayed under 15 so nothing failed. Lower this every time a reader is migrated.
#
# RATCHETED 14 -> 11 (Q-076). The ceiling had never been lowered to the truth, so it carried slack 3 --
# room for three silent additions, which is the same allowance the comment directly above says let SARIF
# hide. MEASURED at HEAD e66f4ca on a clean agent tree: 11 sites, listed in `_RAW_BASELINE`. No reason for
# the slack was ever written down, and this file's own instruction is to lower it per migration.
#
# The set ratchet does NOT make this one redundant. The set catches a SWAP at constant count; the ceiling
# catches ADDITIONS. Only with the ceiling at the true count do the two fire on the same event.
_KNOWN_UNGATED = 11

# The baseline as a SET, which is a different thing from the number above and exists for a different
# reason (Q-076, the same design Q-075 applied to the dead-code ratchet).
#
# KEYED BY ENCLOSING SCOPE, NOT `file:line`. Ten of the eleven sites are in main.py; inserting one
# function near the top of that file renumbers every site below it and a line-keyed baseline would report
# the whole file as `newly_raw`. That is the rot direction this design forbids. A scope name is stable
# under line drift and is also the thing a reader needs -- WHICH CONSUMER is ungated, not a coordinate.
# `file:line` is still printed in the message, as diagnostics rather than as identity.
#
# A MULTISET (`key -> n`), not a plain set. The mapping is 1:1 today (11 sites, 11 distinct scopes) but
# with a plain set a SECOND raw call added inside an already-recorded scope would be invisible to
# `newly_raw` -- the same blind spot in a smaller box.
#
# `sum(_RAW_BASELINE.values()) <= _KNOWN_UNGATED` is enforced below, and that inequality is what makes a
# firing alarm provably non-empty: if every site present were already recorded at its baseline
# multiplicity the count could be at most the recorded total, and the ratchet would not have fired.
#
# Deliberately NO staleness test. This set moves whenever any lane gates a site, and failing their green
# work to force an edit to a file they do not own is how a gate earns the distrust that gets it silenced.
# Rot runs one way only: a gated site leaves a name here that is no longer raw, which surfaces in
# `resolved` and can never invent a false `newly_raw`.
_RAW_BASELINE = {
    "agent.py::BBHAgent._triage": 1,
    "main.py::_report_bundle": 1,
    "main.py::_tool_ledger": 1,
    "main.py::asvs_coverage": 1,
    "main.py::attack_graph_view": 1,
    "main.py::backup": 1,
    "main.py::blind_benchmark_run": 1,
    "main.py::capture_finding_poc": 1,
    "main.py::cloud_posture_ingest": 1,
    "main.py::get_status": 1,
    "main.py::technique_plan": 1,
}


def _scope_index(tree):
    """[(lineno, end_lineno, qualified_name)] for every def/class, innermost resolvable by max lineno."""
    out = []

    def walk(node, prefix):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                q = prefix + ch.name
                out.append((ch.lineno, getattr(ch, "end_lineno", ch.lineno), q))
                walk(ch, q + ".")
            else:
                walk(ch, prefix)

    walk(tree, "")
    return out


def _scope_at(index, lineno):
    best = None
    for lo, hi, q in index:
        if lo <= lineno <= hi and (best is None or lo > best[0]):
            best = (lo, q)
    return best[1] if best else "<module>"


def _reason_for(key):
    """The `_RAW_IS_CORRECT` justification for a site, by exact key or by whole-file entry."""
    if key in _RAW_IS_CORRECT:
        return _RAW_IS_CORRECT[key]
    return _RAW_IS_CORRECT.get(key.split("::")[0])


def _ratchet_message(count, ceiling, regressions, resolved, recorded, sites):
    """The failure text. Assembled from what the scan FOUND, so it cannot drift from the finding.

    Both branches matter. The old message printed a bare count and left the reader with nothing to act on;
    an empty list beside a failure is no better, because it reads as "nothing new". If a true set
    difference has nothing to show, say why."""
    head = ("raw db.get_findings() call sites: %d (ceiling %d, recorded baseline %d)"
            % (count, ceiling, recorded))
    lines = [head]
    if regressions:
        lines.append("NEWLY RAW -- present in this tree, not in the recorded baseline:")
        for key in regressions:
            where = ", ".join("%s:%d" % (s["file"], s["line"]) for s in sites if s["key"] == key)
            why = _reason_for(key)
            lines.append("  %-44s %s" % (key, where))
            if why:
                lines.append("      _RAW_IS_CORRECT says: %s" % why)
    else:
        lines.append("NEWLY RAW -- none. The recorded baseline holds every site now present, so a true "
                     "set difference has no names to give; the count moved without the set moving, which "
                     "is only possible if the recorded baseline outgrew the ceiling.")
    if resolved:
        lines.append("resolved since the baseline was recorded (green work, never a failure):")
        for key in resolved:
            lines.append("  %s" % key)
    lines.append("A new consumer must read db.get_findings_gated(). If raw is genuinely correct, it must "
                 "be argued in _RAW_IS_CORRECT *and* recorded in _RAW_BASELINE -- the dict annotates the "
                 "name, it does not remove it from the count.")
    return "\n".join(lines)


def _scan_raw_sites(app_dir=None):
    """Every raw `db.get_findings(` site across the agent, diffed against the recorded baseline.

    Returns the count, the located sites, the true set difference in both directions, and the message.
    Takes a directory so the negative control can run against a frozen copy of the real tree."""
    app = app_dir or AGENT_DIR
    sites = []
    for fname in sorted(os.listdir(app)):
        if not fname.endswith(".py"):
            continue
        src = open(os.path.join(app, fname), encoding="utf8").read()
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        index = _scope_index(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = getattr(f, "attr", None) or getattr(f, "id", None)
            if name != "get_findings":
                continue
            if fname == "db.py" and isinstance(f, ast.Name):
                continue                       # db.py calling its own helper
            sites.append({"key": "%s::%s" % (fname, _scope_at(index, node.lineno)),
                          "file": fname, "line": node.lineno})

    now = Counter(s["key"] for s in sites)
    newly_raw = sorted(k for k in now if k not in _RAW_BASELINE)
    grew = sorted(k for k in now if k in _RAW_BASELINE and now[k] > _RAW_BASELINE[k])
    resolved = sorted(k for k in _RAW_BASELINE if k not in now)
    regressions = sorted(set(newly_raw) | set(grew))
    count = len(sites)
    recorded = sum(_RAW_BASELINE.values())
    return {
        "count": count, "sites": sites, "by_key": dict(now),
        "newly_raw": newly_raw, "grew": grew, "regressions": regressions, "resolved": resolved,
        "ok": count <= _KNOWN_UNGATED and not regressions,
        "message": _ratchet_message(count, _KNOWN_UNGATED, regressions, resolved, recorded, sites),
    }


def _raw_call_count(app_dir=None):
    """How many `db.get_findings(` call sites exist across the agent (excluding the accessor itself)."""
    return _scan_raw_sites(app_dir)["count"]


@pytest.fixture(scope="module")
def scan():
    return _scan_raw_sites()


def test_a_gated_accessor_exists_and_applies_the_proof_gate():
    """The fix has to be reachable, not just documented."""
    import db
    assert hasattr(db, "get_findings_gated")
    src = open(os.path.join(AGENT_DIR, "db.py"), encoding="utf8").read()
    i = src.find("def get_findings_gated")
    assert "demote_unproven" in src[i:i + 1500], "the gated accessor does not apply the gate"


def test_the_gated_accessor_actually_demotes(monkeypatch):
    """Behaviour, not presence. A confirmed access-control finding with no ownership proof must come back
    as a lead — that is the default enforced family set."""
    import db
    import proof_schema as ps
    unproven = [{"title": "IDOR", "family": "idor", "confidence": "confirmed",
                 "severity": "high", "evidence": "changed the id and got a 200"}]
    monkeypatch.setattr(db, "get_findings", lambda _mid: list(unproven))
    out = db.get_findings_gated("m1")
    assert len(out) == 1, "non-destructive: the row must survive, demoted"
    direct = ps.demote_unproven(list(unproven))
    assert out[0].get("confidence") == direct[0].get("confidence")


def test_the_number_of_ungated_presentation_readers_never_grows(scan):
    """RATCHET ONE, the count. Every raw reader that shows findings onward is a place the proof gate does
    not reach. Lower the ceiling as consumers are migrated; a rise means a new consumer was wired to raw
    findings. The ceiling is a coarse backstop -- ratchet two is what names the change."""
    assert scan["count"] <= _KNOWN_UNGATED, scan["message"]


def test_no_raw_site_appears_that_the_recorded_baseline_does_not_hold(scan):
    """RATCHET TWO, the SET -- and the one the count cannot express (Q-076).

    A gated site and a new raw site in the same commit leave the count untouched. This is the assertion
    that sees it, and it names the consumer rather than a number. `resolved` is deliberately absent from
    this condition: a name leaving the baseline is another lane gating a reader, which is the outcome the
    whole file wants, and failing it would make this gate an obstacle to its own purpose."""
    assert not scan["regressions"], scan["message"]


def test_a_recorded_baseline_no_larger_than_the_ceiling_guarantees_a_named_entry(scan):
    """The property that makes the alarm's message provably non-empty.

    If every site present were already recorded at its baseline multiplicity, the count could be at most
    the recorded total; with that total <= the ceiling the count ratchet would not have fired. So whenever
    it does fire there is at least one name to print. Letting the recorded set outgrow the ceiling
    silently reintroduces the empty-message case this ticket exists to remove."""
    recorded = sum(_RAW_BASELINE.values())
    assert recorded <= _KNOWN_UNGATED, (
        "recorded baseline of %d exceeds the ceiling of %d -- a rise could then name nothing"
        % (recorded, _KNOWN_UNGATED))


def test_the_ceiling_carries_no_undocumented_slack():
    """DoD item 4, as an executable fact rather than a note. Slack is the room a new raw site has to
    appear without failing the count, and slack 3 is what let SARIF sit raw.

    Asserted between the two LITERALS in this file, not against the tree. Written the other way round --
    ceiling minus the live count -- it would go red the moment another lane gated a reader, punishing
    exactly the work it wants. This form can only be broken by editing this file: lowering the ceiling
    without dropping the site from `_RAW_BASELINE`, or the reverse, and both are mistakes."""
    recorded = sum(_RAW_BASELINE.values())
    assert _KNOWN_UNGATED == recorded, (
        "ceiling %d against a recorded baseline of %d leaves slack %d. Lower the ceiling to the number of "
        "sites you actually recorded, or write down why the room is deliberate."
        % (_KNOWN_UNGATED, recorded, _KNOWN_UNGATED - recorded))


def test_the_recorded_baseline_has_not_drifted_far_from_the_tree(scan):
    """The soft half: this file goes stale as other lanes gate readers, and a baseline far above the real
    count would leave the ceiling permitting sites that no longer exist. It is a WARNING ratchet with room
    in it, on the same reasoning as the dead-code gate's -- failing a lane the moment it migrates one
    reader is how a gate gets silenced. Tighten both literals when this fires."""
    drift = _KNOWN_UNGATED - scan["count"]
    assert drift <= 3, (
        "ceiling %d is stale against an actual %d -- re-measure and lower both _KNOWN_UNGATED and "
        "_RAW_BASELINE" % (_KNOWN_UNGATED, scan["count"]))


def test_every_raw_is_correct_entry_states_a_reason():
    """An allowlist without reasons is a list of exceptions nobody can review. It was also, until Q-076,
    read by nothing at all -- so the reasons had gone unchecked for as long as they had gone unused."""
    for key, why in _RAW_IS_CORRECT.items():
        assert len(why) > 25, "%s is allowlisted without a real reason: %r" % (key, why)


def test_the_message_names_the_delta_in_both_directions():
    """The message itself, on synthetic inputs. The old one printed only `(n, ceiling)` and the reader had
    to go find the sites by hand."""
    sites = [{"key": "main.py::brand_new", "file": "main.py", "line": 4242}]
    named = _ratchet_message(12, 11, ["main.py::brand_new"], ["main.py::backup"], 11, sites)
    assert "main.py::brand_new" in named and "main.py:4242" in named
    assert "NEWLY RAW" in named
    assert "main.py::backup" in named and "never a failure" in named

    blind = _ratchet_message(12, 11, [], [], 11, [])
    assert "none" in blind and "no names to give" in blind

    annotated = _ratchet_message(12, 11, ["agent.py::BBHAgent._triage"], [], 11,
                                 [{"key": "agent.py::BBHAgent._triage", "file": "agent.py", "line": 1}])
    assert "_RAW_IS_CORRECT says: scan-time" in annotated, (
        "a raw-correct site must be named AND annotated, never hidden")


# ── controls ───────────────────────────────────────────────────────────────────────────────────

def test_the_scan_actually_finds_the_real_call_sites(scan):
    """POSITIVE CONTROL. A gate that can never fire is decoration, and a scan returning zero would make
    every ratchet above pass for the wrong reason."""
    assert scan["count"] > 0, "the scan found nothing at all in %s" % AGENT_DIR
    assert {s["file"] for s in scan["sites"]} >= {"main.py"}, scan["sites"]
    for s in scan["sites"]:
        assert s["line"] > 0 and s["key"].count("::") == 1, s


def test_the_baseline_literals_cannot_be_self_read(tmp_path):
    """Recording the baseline as strings nearly silenced a DIFFERENT ratchet in Q-075: `scan_methods()`
    read its own source and the recorded `file.py::Class.method` literals matched inside themselves,
    taking the count to 0 with the file still green. Check the same hazard here rather than assume it.

    Two independent reasons it cannot happen, both asserted: this file lives in `agent/tests/` and the
    scan only lists top-level `agent/*.py`, and the scan matches AST Call nodes, so a name inside a string
    literal is not a call however the file is reached."""
    scanned = {s["file"] for s in _scan_raw_sites()["sites"]}
    assert not any(f.startswith("test_") for f in scanned), scanned
    assert os.path.isdir(os.path.join(AGENT_DIR, "tests"))

    shutil.copyfile(os.path.abspath(__file__), str(tmp_path / "self_read_probe.py"))
    forced = _scan_raw_sites(str(tmp_path))
    assert forced["count"] == 0, (
        "this file's own baseline literals were counted as call sites: %s" % forced["sites"])


def test_a_string_that_looks_like_a_call_is_not_counted(tmp_path):
    """The other half of the same control, isolated. If a name in a comment or a string could count, the
    baseline would be measuring text rather than code."""
    (tmp_path / "decoy.py").write_text(
        'BASELINE = "main.py::get_status"\n'
        'NOTE = "db.get_findings(mid) appears here as text only"\n'
        '# db.get_findings(mid)\n', encoding="utf8")
    assert _scan_raw_sites(str(tmp_path))["count"] == 0

    (tmp_path / "real.py").write_text(
        "import db\n\n\ndef reader(mid):\n    return db.get_findings(mid)\n", encoding="utf8")
    live = _scan_raw_sites(str(tmp_path))
    assert live["count"] == 1 and live["sites"][0]["key"] == "real.py::reader", live["sites"]


def test_the_scope_key_survives_line_drift(tmp_path):
    """Why the key is a scope and not `file:line`. Ten of eleven sites are in main.py; if the key moved
    with the line number, one insertion at the top of that file would report every site below it as
    newly raw."""
    body = "import db\n\n\ndef reader(mid):\n    return db.get_findings(mid)\n"
    (tmp_path / "drift.py").write_text(body, encoding="utf8")
    before = _scan_raw_sites(str(tmp_path))["sites"][0]
    (tmp_path / "drift.py").write_text("# a lane added a comment block\n" * 20 + body, encoding="utf8")
    after = _scan_raw_sites(str(tmp_path))["sites"][0]
    assert after["line"] != before["line"], "the control needs the line to actually move"
    assert after["key"] == before["key"] == "drift.py::reader"


def test_a_second_raw_call_in_a_recorded_scope_is_still_a_regression(tmp_path):
    """Why the baseline is a multiset. With a plain set, a second raw call inside an already-recorded
    consumer would be absorbed: the key is present, so `now - base` is empty and the gate says nothing."""
    (tmp_path / "main.py").write_text(
        "import db\n\n\ndef get_status(mid):\n"
        "    a = db.get_findings(mid)\n"
        "    b = db.get_findings(mid)\n"
        "    return a, b\n", encoding="utf8")
    res = _scan_raw_sites(str(tmp_path))
    assert res["count"] == 2
    assert res["newly_raw"] == [], "the key itself IS recorded; only its multiplicity changed"
    assert res["grew"] == ["main.py::get_status"], res
    assert res["regressions"] == ["main.py::get_status"]
    assert "main.py::get_status" in res["message"]


# ── the mandatory negative control (Q-076) ─────────────────────────────────────────────────────

@pytest.fixture
def real_tree_copy(tmp_path):
    """A frozen COPY of the real agent tree. Each control must gate a site and add another, and every live
    module belongs to some other lane -- so it is done here instead. Frozen also means the before and
    after halves measure the SAME bytes, immune to another lane editing mid-test.

    FUNCTION-scoped, not module-scoped. A shared copy that each control mutates makes the second one pass
    only because the first ran, and an ordering dependency inside the control for a diagnostics bug is a
    poor place to economise. 179 file copies cost far less than the scans do."""
    for fn in os.listdir(AGENT_DIR):
        if fn.endswith(".py"):
            shutil.copyfile(os.path.join(AGENT_DIR, fn), str(tmp_path / fn))
    return str(tmp_path)


def _gate_one_site(tree, key):
    """Rewrite one recorded site to the gated accessor, the way a migrating lane would. Returns the key."""
    before = _scan_raw_sites(tree)
    victim = next(s for s in before["sites"] if s["key"] == key)
    path = os.path.join(tree, victim["file"])
    lines = open(path, encoding="utf8").read().split("\n")
    assert "db.get_findings(" in lines[victim["line"] - 1], lines[victim["line"] - 1]
    lines[victim["line"] - 1] = lines[victim["line"] - 1].replace(
        "db.get_findings(", "db.get_findings_gated(")
    open(path, "w", encoding="utf8").write("\n".join(lines))
    return before


def test_a_gated_site_and_a_new_raw_site_in_the_same_run_are_both_named(real_tree_copy):
    """NEGATIVE CONTROL, mandatory and specified in the ticket.

    THE EXACT DEFECT: gate one site, add another, count unchanged. The count ratchet passes -- it must,
    and this asserts that it does, because a control that also moved the count would not prove the set
    ratchet contributed anything. The set ratchet fails and names BOTH sides.

    This is the SARIF event reproduced mechanically: a sibling export left raw while its pair was gated,
    under a ceiling that never noticed.

    Everything is measured as a DELTA against `before` rather than against `_RAW_BASELINE` directly. The
    literals in this file go stale the moment another lane gates a reader, and a control that demanded an
    exact match would then fail for their reason instead of mine."""
    before = _gate_one_site(real_tree_copy, "main.py::backup")
    assert before["count"] > 0, "positive control: the scan must see the real tree at all"

    open(os.path.join(real_tree_copy, "security.py"), "a", encoding="utf8").write(
        "\n\ndef apolaki_deliberate_raw_reader(mid):\n"
        "    \"\"\"Q-076 negative control. A new ungated presentation reader.\"\"\"\n"
        "    import db\n"
        "    return db.get_findings(mid)\n")

    after = _scan_raw_sites(real_tree_copy)

    assert after["count"] == before["count"], (
        "the control is only meaningful at CONSTANT COUNT: %d -> %d" % (before["count"], after["count"]))
    assert after["count"] <= _KNOWN_UNGATED, "the count ratchet must still pass -- that IS the defect"

    island = "security.py::apolaki_deliberate_raw_reader"
    assert set(after["newly_raw"]) - set(before["newly_raw"]) == {island}, after["newly_raw"]
    assert set(after["resolved"]) - set(before["resolved"]) == {"main.py::backup"}, after["resolved"]
    assert not after["ok"], "the set ratchet must FAIL where the count ratchet cannot"

    msg = after["message"]
    assert island in msg, "the added site is not named: %s" % msg
    assert "main.py::backup" in msg, "the gated site is not named: %s" % msg
    assert "security.py:" in msg, "the message must locate the new site: %s" % msg

    # And the innocents stay out of the NEWLY RAW block. The old message named nothing; a message that
    # names the wrong thing is the Q-075 failure in the other direction, and equally distrusted.
    newly_block = msg.split("NEWLY RAW")[1].split("resolved since")[0]
    for innocent in ("main.py::get_status", "main.py::technique_plan", "agent.py::BBHAgent._triage"):
        assert innocent not in after["newly_raw"], innocent
        assert innocent not in newly_block, "%s is not the delta and must not be named" % innocent


def test_gating_a_site_alone_is_never_a_failure(real_tree_copy):
    """Rot runs ONE WAY. Another lane migrating a reader leaves a stale name in `_RAW_BASELINE`; that must
    surface as `resolved` and must NOT fail their green work, or this gate becomes the obstacle it was
    built to remove. This is why there is deliberately no staleness test on the recorded baseline."""
    before = _gate_one_site(real_tree_copy, "main.py::backup")
    res = _scan_raw_sites(real_tree_copy)

    assert res["count"] == before["count"] - 1, (before["count"], res["count"])
    assert set(res["resolved"]) - set(before["resolved"]) == {"main.py::backup"}, res["resolved"]
    assert res["regressions"] == before["regressions"], "gating a reader invented a regression"
    if not before["regressions"]:
        assert res["ok"], "a resolved site must never fail the gate: %s" % res["message"]


# ── the consumers this ratchet exists to protect ───────────────────────────────────────────────

def test_the_ai_wrapup_does_not_assert_demoted_findings_to_the_model():
    """It labels the payload 'confirmed findings' in the prompt, so an unproven row reaching it puts a
    false claim in the executive summary a human reads first."""
    src = open(os.path.join(AGENT_DIR, "agent.py"), encoding="utf8").read()
    i = src.find("def _ai_wrapup")
    assert i > 0
    body = src[i:i + 2000]
    assert "get_findings_gated" in body, "_ai_wrapup still reads raw findings"


def test_coverage_counts_agree_with_the_gated_set():
    src = open(os.path.join(AGENT_DIR, "main.py"), encoding="utf8").read()
    i = src.find("def _coverage")
    assert i > 0
    assert "get_findings_gated" in src[i:i + 1500], "_coverage still counts raw findings"
