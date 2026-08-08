"""Dead-code gate (#125): every top-level function must have a caller.

The no-island doctrine one level down. Both failure modes it guards against were real here: an
integration gap (something written but never wired) and a superseded duplicate sitting next to the live
engine, waiting to be called by mistake.
"""
import pytest

import deadcode_gate as dg


# Both scans walk the whole source tree, so each call costs seconds. Six real-tree scans in one file was
# enough to push this past a two-minute timeout. Computed ONCE and shared -- the assertions are unchanged,
# only the number of walks is. A correctness check nobody can afford to run gets skipped, which is how a
# gate quietly stops guarding.
@pytest.fixture(scope="module")
def res():
    return dg.scan()


@pytest.fixture(scope="module")
def qual():
    return dg.scan_qualified()


def test_no_unexplained_dead_functions(res):
    """THE GATE. A function with no caller is either unwired or obsolete; either way it needs a decision,
    not silence. Add a caller, delete it, or justify it in ALLOWED_UNUSED with a reason."""
    assert not res["unused"], "functions with no caller and no justification: %s" % [
        "%s (%s)" % (u["name"], ", ".join(u["at"])) for u in res["unused"]]


def test_the_allowlist_does_not_rot(res):
    """An entry that is now called must leave the allowlist, or the list stops meaning anything."""
    assert not res["stale_allowlist"], (
        "these are no longer unused and should be removed from ALLOWED_UNUSED: %s"
        % res["stale_allowlist"])


def test_every_allowlist_entry_states_a_reason():
    for name, why in dg.ALLOWED_UNUSED.items():
        assert len(why) > 25, "%s is allowlisted without a real reason: %r" % (name, why)


def test_the_scan_actually_finds_things(res):
    """A gate that can never fire is decoration. The scan must see the real codebase."""
    assert res["total_functions"] > 200, res["total_functions"]


def test_framework_invoked_functions_are_not_flagged(res):
    """FastAPI routes are decorated and have no in-repo caller by design; flagging them would drown the
    signal. Recognised structurally rather than by a name list that would rot."""
    flagged = {u["name"] for u in res["unused"]}
    for route in ("get_status", "get_report", "lab_targets", "proxy_status"):
        assert route not in flagged, "%s is a FastAPI route and must not be flagged" % route


# ── the qualified scan: what the bare-name check cannot see ─────────────────────────────────────

def test_the_bare_name_scan_is_fooled_by_a_name_collision():
    """Documents the blind spot as an executable fact rather than a comment. Two modules define `helper`;
    only one is called. The bare-name scan sees a hit and clears BOTH."""
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "alpha.py"), "w", encoding="utf8").write(
        "def helper():\n    return 1\n")
    open(os.path.join(d, "beta.py"), "w", encoding="utf8").write(
        "def helper():\n    return 2\n\n\ndef go():\n    return helper()\n")
    bare = {u["name"] for u in dg.scan(d)["unused"]}
    assert "helper" not in bare, "bare-name scan should (wrongly) consider alpha.helper used"
    qual = set(dg.scan_qualified(d)["unused"])
    assert "alpha.helper" in qual, "qualified scan must catch the uncalled one"
    assert "beta.helper" not in qual, "the genuinely called one must not be flagged"


def test_the_qualified_scan_resolves_import_aliases():
    """`import probe_selection as ps` then `ps.pairwise(...)` is a real call, not dead code. A checker
    that missed aliases would be unusable noise."""
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "lib.py"), "w", encoding="utf8").write("def work():\n    return 1\n")
    open(os.path.join(d, "app.py"), "w", encoding="utf8").write(
        "import lib as L\n\n\ndef run():\n    return L.work()\n")
    assert "lib.work" not in set(dg.scan_qualified(d)["unused"])


def test_the_qualified_scan_honours_from_imports():
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "lib.py"), "w", encoding="utf8").write("def work():\n    return 1\n")
    open(os.path.join(d, "app.py"), "w", encoding="utf8").write(
        "from lib import work\n\n\ndef run():\n    return work()\n")
    assert "lib.work" not in set(dg.scan_qualified(d)["unused"])


def test_a_function_referenced_as_a_value_is_not_dead():
    """A function in a dispatch table is never CALLED by name. Requiring a paren would flag every
    guidance._rule_* entry."""
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "lib.py"), "w", encoding="utf8").write(
        "def rule_a():\n    return 1\n\n\nRULES = [rule_a]\n")
    assert "lib.rule_a" not in set(dg.scan_qualified(d)["unused"])


def test_the_ratchet_holds(qual):
    """The count may fall, never rise. A new unwired function fails this immediately, while the existing
    backlog is triaged deliberately rather than bulk-deleted — those entries are CANDIDATES, not proven
    dead, and deleting unproven code is how a working engine gets removed."""
    q = qual
    assert q["ok"], ("qualified dead-code count rose to %d (baseline %d). New entries:\n  %s"
                     % (q["count"], q["baseline"], "\n  ".join(q["unused"][-5:])))


def test_the_baseline_is_not_slack(qual):
    """A baseline far above the real count would silently permit regressions up to it."""
    q = qual
    assert q["baseline"] - q["count"] <= 3, (
        "baseline %d is stale against an actual %d — tighten it" % (q["baseline"], q["count"]))


def test_the_qualified_scan_honours_the_allowlist(qual):
    """A function with a written justification is unwired-but-explained, not unwired-and-unexplained.
    Counting both toward the ratchet makes the number mean two things at once."""
    assert qual["allowed"], "the allowlist should still be catching some entries"
    for name in qual["allowed"]:
        assert name.split(".")[-1] in dg.ALLOWED_UNUSED
    assert not (set(qual["unused"]) & set(qual["allowed"])), "an entry cannot be both"
