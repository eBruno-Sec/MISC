"""An app mounted on a subpath must still get scanned.

Regression for a mission that returned ZERO findings in 40 seconds against a target carrying 1415 real
vulnerabilities. Scope pinned /benchmark, recon seeded the HOST ROOT, scope correctly refused it, and
every later phase received an empty surface. Scope was right; the seed was wrong.
"""
import asyncio

import agent as agent_mod
import scope as scope_mod
import tools as tools_mod


def _agent(in_scope):
    sc = scope_mod.ScopeEngine()
    sc.load_manual(in_scope, [], "T")
    t = tools_mod.ToolRegistry(sc, mission_id=None, lab_mode=True)
    return sc, t, agent_mod.BBHAgent(sc, t, asyncio.Event(), mode="passive",
                                     authenticated_scan=False, mission_id=None)


def test_the_host_root_is_out_of_scope_when_a_path_is_pinned():
    """The precondition that made the failure invisible: refusing the root is CORRECT behaviour."""
    sc, _, _ = _agent(["https://owaspbench:8443/benchmark/"])
    assert sc.validate("https://owaspbench:8443/benchmark/")[0] is True
    assert sc.validate("https://owaspbench:8443/")[0] is False


def _seeded_urls(in_scope):
    sc, t, a = _agent(in_scope)

    async def _drain():
        out = []
        async for ev in a.run("test", "sess"):
            out.append(ev)
            if len(out) > 8:      # only the opening events matter here
                break
        return out

    try:
        asyncio.run(_drain())
    except Exception:
        pass                      # later phases need network; the seed happens first
    return list(t.urls or [])


def test_a_pinned_path_is_seeded_so_the_app_is_reachable():
    urls = _seeded_urls(["https://owaspbench:8443/benchmark/"])
    assert any(u.rstrip("/").endswith("/benchmark") for u in urls), urls


def test_a_bare_host_scope_seeds_nothing_extra():
    """Negative control: with no pinned path the old behaviour is unchanged, so this cannot become a
    source of invented targets."""
    urls = _seeded_urls(["https://owaspbench:8443"])
    assert not any(u.rstrip("/").endswith("/benchmark") for u in urls), urls
