"""Dead-code gate (#125): every top-level function must have a caller.

The no-island doctrine one level down. Both failure modes it guards against were real here: an
integration gap (something written but never wired) and a superseded duplicate sitting next to the live
engine, waiting to be called by mistake.
"""
import deadcode_gate as dg


def test_no_unexplained_dead_functions():
    """THE GATE. A function with no caller is either unwired or obsolete; either way it needs a decision,
    not silence. Add a caller, delete it, or justify it in ALLOWED_UNUSED with a reason."""
    res = dg.scan()
    assert not res["unused"], "functions with no caller and no justification: %s" % [
        "%s (%s)" % (u["name"], ", ".join(u["at"])) for u in res["unused"]]


def test_the_allowlist_does_not_rot():
    """An entry that is now called must leave the allowlist, or the list stops meaning anything."""
    res = dg.scan()
    assert not res["stale_allowlist"], (
        "these are no longer unused and should be removed from ALLOWED_UNUSED: %s"
        % res["stale_allowlist"])


def test_every_allowlist_entry_states_a_reason():
    for name, why in dg.ALLOWED_UNUSED.items():
        assert len(why) > 25, "%s is allowlisted without a real reason: %r" % (name, why)


def test_the_scan_actually_finds_things():
    """A gate that can never fire is decoration. The scan must see the real codebase."""
    res = dg.scan()
    assert res["total_functions"] > 200, res["total_functions"]


def test_framework_invoked_functions_are_not_flagged():
    """FastAPI routes are decorated and have no in-repo caller by design; flagging them would drown the
    signal. Recognised structurally rather than by a name list that would rot."""
    res = dg.scan()
    flagged = {u["name"] for u in res["unused"]}
    for route in ("get_status", "get_report", "lab_targets", "proxy_status"):
        assert route not in flagged, "%s is a FastAPI route and must not be flagged" % route
