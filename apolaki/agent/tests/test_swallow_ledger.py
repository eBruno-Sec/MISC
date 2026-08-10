"""A crashed check must never be indistinguishable from a clean target.

This is the codebase's deepest defect class: 328 of 769 broad exception handlers in shipping code were
followed immediately by a bare `pass`, so a probe that threw produced no finding -- and no finding reads
exactly like "nothing here". These pin the mechanism that makes such a failure visible.
"""
import asyncio

import cookie_flags
import scope
import tools


def _reg():
    sc = scope.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    return tools.ToolRegistry(sc, mission_id=None, lab_mode=True)


def test_swallow_records_instead_of_discarding():
    reg = _reg()
    assert reg.swallowed == []
    try:
        raise ValueError("boom")
    except Exception as e:
        reg._swallow(e, "web_probes.cookie_flags", "https://target.tld/x")
    rec = reg.swallowed[0]
    assert rec["where"] == "web_probes.cookie_flags"
    assert "ValueError" in rec["error"] and "boom" in rec["error"]


def test_ledger_is_bounded_so_a_hostile_target_cannot_grow_it_forever():
    reg = _reg()
    for _ in range(600):
        try:
            raise RuntimeError("x" * 4000)
        except Exception as e:
            reg._swallow(e, "engine.loop", "https://target.tld/" + "y" * 4000)
    assert len(reg.swallowed) == 500
    assert len(reg.swallowed[0]["target"]) <= 200


def test_a_crashed_check_is_reported_in_the_tool_output():
    """The whole point. A check that threw must change what the operator sees, not vanish."""
    reg = _reg()

    async def _http(url, method="GET", *a, **kw):
        return {"status": 200, "headers": {"set-cookie": "SID=1; HttpOnly"}, "body": "<html></html>"}

    reg._http = _http

    def broken(*_a, **_k):
        raise AttributeError("evaluate went missing")

    orig, cookie_flags.evaluate = cookie_flags.evaluate, broken
    try:
        res = asyncio.run(reg._run_web_probes({"url": "https://target.tld/p?q=1"}))
    finally:
        cookie_flags.evaluate = orig

    assert any(s["where"] == "web_probes.cookie_flags" for s in reg.swallowed), reg.swallowed
    assert "failed to execute" in res.output and "cookie_flags" in res.output, res.output


def test_a_clean_run_says_nothing_about_failures():
    """Negative control: the warning must not appear when every check actually ran."""
    reg = _reg()

    async def _http(url, method="GET", *a, **kw):
        return {"status": 200, "headers": {}, "body": "<html>nothing interesting</html>"}

    reg._http = _http
    res = asyncio.run(reg._run_web_probes({"url": "https://target.tld/p?q=1"}))
    assert "failed to execute" not in res.output, res.output
