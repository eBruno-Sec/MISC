"""A bounded scan spends its last slot on the highest-value observed work.

These are execution tests, not declarations about cap constants.  Each regression puts the
valuable candidate *after* enough ordinary candidates to exhaust the old first-N path.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import agent as agent_mod
import mass_assign_tool as ma
import planner
from tools import ToolRegistry


def _drain(state: dict, rounds: int = 160) -> list[dict]:
    out = []
    for _ in range(rounds):
        batch = planner.next_batch(state)
        if not batch:
            break
        out.extend(batch)
        state["done"].update(step["key"] for step in batch)
    else:
        raise AssertionError("planner did not terminate")
    return out


def _state(urls, forms=None) -> dict:
    return {
        "mode": "full",
        "roots": ["t.test"],
        "done": set(),
        "recon": {
            "subdomains": [],
            "live_hosts": [{"url": "https://t.test"}],
            "forms": list(forms or []),
        },
        "urls": list(urls),
        "bases": {"t.test": "https://t.test"},
        "intensity": "standard",
    }


def test_endpoint_cap_keeps_a_late_command_sink():
    """CAP_ENDPOINTS used to cut first and rank later, making the rank ceremonial."""
    ordinary = ["https://t.test/catalog/p%02d?x=1" % i
                for i in range(planner.CAP_ENDPOINTS + 5)]
    valuable = "https://t.test/admin/execute?cmd=id"
    steps = _drain(_state(ordinary + [valuable]))
    assert any(s["tool"] == "run_cmdi" and s["input"].get("url") == valuable for s in steps), (
        "the endpoint cap discarded a command sink because it was discovered last")


def test_mass_assignment_ranks_read_views_before_any_upstream_cap():
    """A concrete object template after thirty generic paths must still reach _ma_views."""
    ordinary = ["https://t.test/users/v1/noise%02d" % i
                for i in range(planner.CAP_REST + 2)]
    template = "https://t.test/users/v1/{username}"
    form = {
        "action": "https://t.test/users/v1/register",
        "method": "POST",
        "content_type": "application/json",
        "body_params": [
            {"name": "username", "location": "body", "type": "string"},
            {"name": "email", "location": "body", "type": "string"},
        ],
    }
    steps = _drain(_state(ordinary + [template], [form]))
    step = next(s for s in steps if s["tool"] == "run_mass_assign")
    assert "/users/v1/{username}" in step["input"]["read_paths"], (
        "an upstream first-N cap discarded the exact object view before _ma_views could rank it")


class _Scope:
    @staticmethod
    def validate(url):
        return (str(url).startswith("https://t.test/"), "")


class _CrawlTools:
    def __init__(self, urls):
        self.urls = list(urls)
        self.recon = {}
        self.calls = []

    async def _http(self, _url, _method, capture=False):
        return {"error": "not served in the fixture", "status": 0, "body": ""}

    async def execute(self, tool, inp, _session_id):
        self.calls.append((tool, inp["url"]))

    def _add_urls(self, urls):
        self.urls.extend(urls)

    def _swallow(self, exc, owner, target):
        raise AssertionError("fixture unexpectedly degraded: %s %s %s" % (owner, target, exc))


def test_surface_page_budget_keeps_a_late_high_value_route(monkeypatch):
    """A one-page budget must visit the observed attack surface, not the first cosmetic page."""
    ordinary = ["https://t.test/about/p%02d" % i for i in range(12)]
    valuable = "https://t.test/admin/execute?cmd=id"
    tools = _CrawlTools(ordinary + [valuable])
    scan = object.__new__(agent_mod.BBHAgent)
    scan.tools = tools
    scan.scope = _Scope()
    scan.stop_event = asyncio.Event()
    monkeypatch.setenv("BBH_SURFACE_DEPTH", "1")
    monkeypatch.setenv("BBH_SURFACE_PAGES", "1")

    visited = asyncio.run(scan._surface_crawl("cap-ordering", "https://t.test/"))

    assert visited == 1
    assert tools.calls == [("http_probe", valuable)], (
        "the page budget was spent on discovery order instead of security value")


def test_shape_spread_orders_the_browser_budget_before_truncation():
    """The existing sweep/browser cap is sound: every structural class gets a front slot."""
    urls = ["https://t.test/%s/Case%03d?p=1" % (group, i)
            for group in ("alpha", "beta", "gamma") for i in range(12)]
    selected = agent_mod.sweep_targets(urls, [], lambda _u: True, limit=6)
    assert {url.split("/")[3] for url in selected} == {"alpha", "beta", "gamma"}


def test_shape_spread_does_not_hide_a_late_high_value_shape():
    """Shape diversity is not value ordering when there are more shapes than budget slots."""
    ordinary = ["https://t.test/%s/item?p=1" % name for name in (
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet")]
    valuable = "https://t.test/admin/execute?cmd=id"
    selected = agent_mod.sweep_targets(ordinary + [valuable], [], lambda _u: True, limit=3)
    assert valuable in selected, "early low-value shapes consumed the cap before the attack surface"


def test_mass_assignment_view_cap_is_applied_after_semantic_ranking():
    """The _ma_views cap is already sound; a late exact template outranks generic listings."""
    paths = ["/users/v1/noise%02d" % i for i in range(12)] + ["/users/v1/{username}"]
    ranked = ma.read_views("/users/v1/register", paths,
                           key_field="username", key_value="alice", limit=2)
    assert ranked[0] == "/users/v1/alice"

    holder = type("RegistryView", (), {"_MA_MAX_VIEWS": 3})()
    views = ToolRegistry._ma_views(holder, "https://t.test", "/users/v1/register", "",
                                  paths, "username", "alice", "17")
    assert views[0][0] == "<write>/<id>"
    assert any(tag == "/users/v1/{username}" for tag, _ in views)
    assert len(views) == 3


def _raw_work_caps(path: Path) -> set[tuple[str, str, str]]:
    """Raw ``name[:cap]`` work cuts in production source.

    The small name vocabulary is deliberate: it describes remote work queues, not evidence strings,
    protocol frames, report rows, or bounded parser input.  A new raw cut must either be changed to an
    ordered expression or receive a measured, named contract below.
    """
    import ast

    work_names = {
        "targets", "frontier", "origins", "host_roots", "live_hosts", "page_urls",
        "rest_urls", "dom_pages", "param_eps", "read_paths", "cands", "urls", "specs",
        "fields", "operations",
    }
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def owner(node):
        cur = node
        while cur in parents:
            cur = parents[cur]
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return cur.name
        return "<module>"

    out = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)
                and node.slice.upper is not None and isinstance(node.value, ast.Name)
                and node.value.id in work_names):
            continue
        out.add((owner(node), node.value.id, ast.unparse(node.slice.upper)))
    return out


def test_raw_production_work_caps_have_an_explicit_ordering_contract():
    root = Path(__file__).resolve().parents[1]
    measured = {
        (path.name, fn, name, upper)
        for path in root.glob("*.py")
        for fn, name, upper in _raw_work_caps(path)
    }
    # Every survivor has a named ordering contract. Output-only caps are included so a future change
    # cannot quietly turn one into target work without revisiting this inventory.
    contracted = {
        ("agent.py", "_do_transport_posture", "origins", "3"):
            "ScopeEngine.base_urls preserves the operator-authorized origin order",
        ("hashid_tool.py", "summarize", "cands", "3"):
            "display-only summary; identify emits specific signatures before ambiguous raw hashes",
        ("planner.py", "next_batch", "host_roots", "CAP_HOSTS"):
            "_rank_host_names puts operator roots before discovered hosts",
        ("planner.py", "next_batch", "targets", "CAP_HOSTS"):
            "_rank_host_names puts operator roots before discovered hosts",
        ("planner.py", "next_batch", "targets", "CAP_ZAP"):
            "_rank_host_names puts operator roots before discovered hosts",
        ("planner.py", "next_batch", "dom_pages", "CAP_DOM"):
            "operator-ranked roots precede globally ranked parameter endpoints",
        ("planner.py", "next_batch", "param_eps", "8"):
            "param_eps is globally ranked by _endpoint_value before this secondary cut",
        ("planner.py", "next_batch", "param_eps", "3"):
            "param_eps is globally ranked by _endpoint_value before this secondary cut",
        ("tools.py", "_run_authz_matrix", "operations", "40"):
            "planner supplies security-ranked operations; explicit operator lists retain operator order",
        ("tools.py", "_confirm_create_object_idor", "specs", "6"):
            "explicit proven app specs precede target-derived speculative specs",
        ("tools.py", "_httpx_fallback", "targets", "25"):
            "planner puts operator roots before discovered hosts; manual input retains operator order",
        ("tools.py", "_run_httpx", "targets", "400"):
            "planner puts operator roots before discovered hosts; manual input retains operator order",
        ("tools.py", "_run_external_surface", "cands", "500"):
            "persistence-only ceiling; the graph consumer receives the full candidate set first",
        ("tools.py", "_run_js_review", "urls", "20"):
            "planner supplies ranked JS URLs; explicit operator URLs retain operator order",
        ("tools.py", "_run_wayback", "urls", "50"):
            "display-only preview; every URL is ingested and added to the surface before this cut",
        ("tools.py", "_run_katana", "urls", "50"):
            "display-only preview; every URL is added to the surface before this cut",
        ("tools.py", "_run_stored_xss", "fields", "8"):
            "target-declared form order is the only pre-probe evidence available",
        ("tools.py", "_run_form_cmdi", "fields", "6"):
            "target-declared form order is the only pre-probe evidence available",
        ("tools.py", "_run_form_cmdi", "fields", "2"):
            "same ordered field list as the output oracle; this is the expensive blind fallback",
        ("tools.py", "_run_ws_hijack", "cands", "self._WS_MAX_ENDPOINTS"):
            "explicit observations precede advertised endpoints, which precede opt-in defaults",
    }
    assert measured == set(contracted), "raw first-N work caps without the measured contract: %r" % sorted(
        measured - set(contracted))
    assert all(reason.strip() for reason in contracted.values())


def test_cap_guard_detects_a_planted_previously_invisible_bypass(tmp_path):
    planted = tmp_path / "outside_old_scope.py"
    planted.write_text("def run(targets):\n    return targets[:7]\n", encoding="utf-8")
    assert _raw_work_caps(planted) == {("run", "targets", "7")}
