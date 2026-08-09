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
"""
import ast
import os

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Call sites that legitimately need the RAW, un-gated set: scan-time storage, dedupe, and the blind
# benchmark seal (which must hash what the engines actually produced, before any reporting concern).
# Anything NOT here that reads raw findings and shows them to a human, a model, an export or a future
# scan is a gap. Each entry names WHY, so an addition has to be argued rather than appended.
_RAW_IS_CORRECT = {
    "db.py": "internal: iterating rows to build derived tables",
    "agent.py:_close_autonomy_loop": "scan-time: the loop reasons about what engines produced",
}

# Raw `db.get_findings(` call sites remaining. THIS NUMBER MAY ONLY FALL.
# 20 -> 15: the PoC export, PoC bundle, retest planner, cross-session memory snapshot and graph inputs
# now read get_findings_gated (Codex batch 2 #5, #6, #11). Five consumers that presented proof-demoted
# rows as confirmed.
# MEASURED, not estimated — I first wrote 11 from memory and the real count was 20, which is exactly the
# kind of invented baseline that makes a ratchet meaningless. Two consumers (the AI wrap-up prompt and the
# coverage counts) are already migrated; the rest are tracked in tasks #50/#51 and are recorded here
# rather than silently tolerated. Lower this as each is moved to get_findings_gated().
_KNOWN_UNGATED = 15


def _raw_call_count():
    """How many `db.get_findings(` call sites exist across the agent (excluding the accessor itself)."""
    n = 0
    for fname in sorted(os.listdir(AGENT_DIR)):
        if not fname.endswith(".py"):
            continue
        src = open(os.path.join(AGENT_DIR, fname), encoding="utf8").read()
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = getattr(f, "attr", None) or getattr(f, "id", None)
            if name != "get_findings":
                continue
            if fname == "db.py" and isinstance(f, ast.Name):
                continue                       # db.py calling its own helper
            n += 1
    return n


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


def test_the_number_of_ungated_presentation_readers_never_grows():
    """RATCHET. Every raw reader that shows findings onward is a place the proof gate does not reach.
    Lower this number as consumers are migrated; a rise means a new consumer was wired to raw findings."""
    n = _raw_call_count()
    assert n <= _KNOWN_UNGATED, (
        "raw db.get_findings() call sites rose to %d (tracked ceiling %d). New consumers must read "
        "db.get_findings_gated() unless raw is genuinely correct — and if it is, add it to "
        "_RAW_IS_CORRECT with a reason." % (n, _KNOWN_UNGATED))


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
