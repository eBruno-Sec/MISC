from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import agent as agent_mod
import db
import main
import pytest
import scope as scope_mod
import tools
import zap_client


def _run(awaitable):
    return asyncio.run(awaitable)


def _registry(url: str = "https://zap-target.example/") -> tools.ToolRegistry:
    scope = scope_mod.ScopeEngine()
    scope.load_manual([url], [], "ZAP control")
    return tools.ToolRegistry(scope, mission_id="zap-control", lab_mode=True)


def test_zap_alert_is_explicitly_lead_only_even_without_scanner_confidence():
    """A missing ZAP grade must not fall through a confirm-by-tool allow-list."""
    finding = zap_client.alert_to_finding({
        "alert": "SQL Injection",
        "risk": "High",
        "url": "https://zap-target.example/item?id=1",
        "param": "id",
        "cweid": "89",
        "evidence": "scanner signature",
    })

    assert finding["confidence"] == "candidate"
    assert finding["scanner_confidence"] == ""
    assert agent_mod.BBHAgent._is_confirmed(None, "run_zap", finding) is False
    assert agent_mod.BBHAgent._is_confirmed(None, "zap", finding) is False


def test_zap_scanner_grade_is_retained_but_never_promoted_to_apolaki_proof():
    finding = zap_client.alert_to_finding({
        "alert": "Cross Site Scripting",
        "risk": "Medium",
        "confidence": "High",
        "url": "https://zap-target.example/search?q=x",
        "evidence": "reflected token",
    })

    assert finding["confidence"] == "candidate"
    assert finding["scanner_confidence"] == "High"


class _FakeZap:
    instances = []

    def __init__(self, *args, **kwargs):
        self.calls = []
        self.safe = False
        self.history = 0
        self.ajax_error = bool(kwargs.pop("ajax_error", False))
        self.pscan_checks = 0
        type(self).instances.append(self)

    async def version(self):
        return "2.17.0"

    async def stop_all(self):
        self.calls.append("stop_all")

    async def new_context(self, _name):
        return "1"

    async def include_in_context(self, _name, _regex):
        return None

    async def configure_target_safety(self, _url, hosts=None):
        self.calls.append("configure_target_safety")
        self.safe = True
        return {"requests_per_second": 1.0}

    async def history_cursor(self):
        return self.history

    async def observe_rate_limits(self, cursor, _url, _policy, allowed_hosts=None):
        return self.history, None

    def _target(self, name):
        assert self.safe, "%s reached the target before the ZAP safety rule existed" % name
        self.calls.append(name)
        self.history += 1

    async def access_url(self, _url, request_id=""):
        self._target("access_url")
        return {"sendRequest": [{
            "id": str(self.history),
            "requestHeader": f"GET {_url} HTTP/1.1\r\nHost: zap-target.example\r\n\r\n",
            "responseHeader": "HTTP/1.1 200 OK\r\n\r\n",
        }]}

    async def spider(self, _url, context=None):
        self._target("spider")
        return "spider-1"

    async def spider_status(self, _sid):
        return 100

    async def spider_stop(self, _sid):
        self.calls.append("spider_stop")

    async def ajax_start(self, _url, context=None):
        self._target("ajax_start")
        if self.ajax_error:
            raise RuntimeError("ajax unavailable")

    async def ajax_status(self):
        return "stopped"

    async def ajax_stop(self):
        self.calls.append("ajax_stop")

    async def wait_int(self, status_fn, cap=300, interval=3, stop_event=None, guard=None):
        if guard and await guard():
            return False
        return await status_fn() >= 100

    async def wait_str(self, status_fn, cap=180, interval=3, stop_event=None, guard=None):
        if guard and await guard():
            return False
        return (await status_fn()).lower() in ("stopped", "complete", "completed")

    async def pscan_remaining(self):
        self.pscan_checks += 1
        return 0

    async def add_scan_header(self):
        return None

    async def set_injectable(self):
        return None

    async def set_scan_rate(self, delay_ms=0, threads_per_host=None):
        return None

    async def set_hosts_per_scan(self, hosts=1):
        return None

    async def set_attack_strength(self, strength="MEDIUM", threshold=None):
        return None

    async def set_oast_service(self, _name):
        return None

    async def ascan(self, _url, context_id=None, policy=None):
        self._target("ascan")
        return "ascan-1"

    async def ascan_status(self, _sid):
        return 100

    async def ascan_stop(self, _sid):
        self.calls.append("ascan_stop")

    async def alerts(self, baseurl=None, count=1000):
        return []

    async def alerts_since(self, cursor, baseurl=None, count=1000):
        return await self.alerts(baseurl=baseurl, count=count), 0


def _install_fake_zap(monkeypatch, *, ajax_error=False):
    _FakeZap.instances.clear()

    def factory(*args, **kwargs):
        kwargs["ajax_error"] = ajax_error
        return _FakeZap(*args, **kwargs)

    monkeypatch.setattr(zap_client, "configured", lambda: True)
    monkeypatch.setattr(zap_client, "ZapClient", factory)


def test_run_zap_installs_verified_safety_before_every_target_driver(monkeypatch):
    _install_fake_zap(monkeypatch)
    result = _run(_registry()._run_zap({
        "url": "https://zap-target.example/",
        "policy": "safe_active",
        "spider_seconds": 1,
        "scan_seconds": 1,
    }))

    assert result.success, result.error
    client = _FakeZap.instances[-1]
    assert client.calls.index("configure_target_safety") < client.calls.index("access_url")
    assert {"access_url", "spider", "ajax_start", "ascan"}.issubset(client.calls)


def test_ajax_spider_failure_is_reported_and_active_path_drains_passive_queue(monkeypatch):
    _install_fake_zap(monkeypatch, ajax_error=True)
    result = _run(_registry()._run_zap({
        "url": "https://zap-target.example/",
        "policy": "safe_active",
        "spider_seconds": 1,
        "scan_seconds": 1,
    }))

    assert result.success, result.error
    assert "AJAX spider degraded: RuntimeError: ajax unavailable" in result.output
    assert _FakeZap.instances[-1].pscan_checks > 0


def test_target_retry_after_aborts_zap_before_the_next_driver(monkeypatch):
    class RateLimitedZap(_FakeZap):
        async def access_url(self, url, request_id=""):
            self._target("access_url")
            return {"sendRequest": [{
                "id": "1",
                "requestHeader": f"GET {url} HTTP/1.1\r\nHost: zap-target.example\r\n\r\n",
                "responseHeader": (
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\n\r\n"),
            }]}

    RateLimitedZap.instances.clear()
    monkeypatch.setattr(zap_client, "configured", lambda: True)
    monkeypatch.setattr(zap_client, "ZapClient", RateLimitedZap)

    result = _run(_registry()._run_zap({
        "url": "https://zap-target.example/", "policy": "safe_active"}))

    assert not result.success
    assert "No clean or vulnerability verdict was produced" in result.error
    client = RateLimitedZap.instances[-1]
    assert "access_url" in client.calls
    assert "spider" not in client.calls and "ajax_start" not in client.calls and "ascan" not in client.calls


def test_seed_result_cannot_be_replaced_by_interleaved_history(monkeypatch):
    class DirectRateLimitedZap(_FakeZap):
        async def access_url(self, url, request_id=""):
            self._target("access_url")
            return {"sendRequest": [{
                "id": "1",
                "requestHeader": f"GET {url} HTTP/1.1\r\nHost: zap-target.example\r\n\r\n",
                "responseHeader": (
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\n\r\n"),
            }]}

        async def observe_rate_limits(self, *_args, **_kwargs):
            raise AssertionError("seed decision must not consult interleaved history")

    DirectRateLimitedZap.instances.clear()
    monkeypatch.setattr(zap_client, "configured", lambda: True)
    monkeypatch.setattr(zap_client, "ZapClient", DirectRateLimitedZap)

    result = _run(_registry()._run_zap({
        "url": "https://zap-target.example/", "policy": "passive"}))

    assert not result.success
    assert "target rate limit" in result.error
    client = DirectRateLimitedZap.instances[-1]
    assert "spider" not in client.calls


def test_unobservable_secondary_seed_cannot_degrade_into_more_traffic(monkeypatch):
    class MissingSeedResponseZap(_FakeZap):
        async def access_url(self, url, request_id=""):
            self._target("access_url")
            if self.calls.count("access_url") > 1:
                return {}
            return {"sendRequest": [{
                "id": "1",
                "requestHeader": f"GET {url} HTTP/1.1\r\nHost: zap-target.example\r\n\r\n",
                "responseHeader": "HTTP/1.1 200 OK\r\n\r\n",
            }]}

    MissingSeedResponseZap.instances.clear()
    monkeypatch.setattr(zap_client, "configured", lambda: True)
    monkeypatch.setattr(zap_client, "ZapClient", MissingSeedResponseZap)
    registry = _registry()
    registry.urls = ["https://zap-target.example/discovered"]

    result = _run(registry._run_zap({
        "url": "https://zap-target.example/", "policy": "passive"}))

    assert not result.success
    assert "seed response was not observable" in result.error
    assert "spider" not in MissingSeedResponseZap.instances[-1].calls


class _MissionTools:
    def __init__(self):
        self.recon = {"target": "zap-target.example", "domain": "zap-target.example",
                      "live_hosts": [], "subdomains": []}
        self.urls = ["https://zap-target.example/"]


class _MissionAgent:
    async def run(self, _objective, _session_id):
        yield {"type": "complete", "content": "done"}


def _mission_session():
    return {
        "scope": None,
        "agent": _MissionAgent(),
        "tools": _MissionTools(),
        "stop_event": asyncio.Event(),
        "objective": "ZAP invocation control",
        "status": "created",
        "events": [],
        "task": None,
        "done": False,
    }


def test_enabled_mission_cannot_complete_without_persisted_run_zap_call(tmp_path):
    old_path = db.DB_PATH
    session_id = "zapmissing"
    try:
        db.init(str(tmp_path / "zap-missing.db"))
        db.create_mission(session_id, "P", "full", "o",
                          {"in_scope": ["zap-target.example"]},
                          {"enable_zap": True, "zap_policy": "passive"})
        main.sessions[session_id] = _mission_session()

        _run(main._drive_mission(session_id))

        mission = db.get_mission(session_id)
        logs = db.get_logs(session_id, limit=100)
        assert mission["status"] == "failed"
        assert any(row.get("type") == "tool_error" and row.get("tool") == "run_zap"
                   and "no run_zap tool_call" in row.get("error", "") for row in logs)
    finally:
        main.sessions.pop(session_id, None)
        db.init(old_path)


def test_zap_off_mission_completion_and_log_stream_are_unchanged(tmp_path):
    old_path = db.DB_PATH
    session_id = "zapoff"
    try:
        db.init(str(tmp_path / "zap-off.db"))
        db.create_mission(session_id, "P", "full", "o",
                          {"in_scope": ["zap-target.example"]},
                          {"enable_zap": False})
        main.sessions[session_id] = _mission_session()

        _run(main._drive_mission(session_id))

        mission = db.get_mission(session_id)
        logs = db.get_logs(session_id, limit=100)
        assert mission["status"] == "complete"
        assert [row.get("type") for row in logs] == ["complete"]
    finally:
        main.sessions.pop(session_id, None)
        db.init(old_path)


_ZAP_TARGET_DRIVERS = frozenset({"access_url", "spider", "ajax_start", "ascan"})


def _zap_production_paths(root: Path):
    return sorted(path for path in Path(root).rglob("*.py")
                  if not ({"tests", "tier3"} & set(path.relative_to(root).parts[:-1])))


def _zap_call_inventory(methods, root=None):
    """Find calls by API method, independent of receiver spelling or aliasing."""
    root = Path(root or Path(tools.__file__).resolve().parent)
    rows = []
    for path in _zap_production_paths(root):
        tree = ast.parse(path.read_text(encoding="utf8"), filename=str(path))
        parents = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in methods):
                continue
            functions = []
            owner = node
            while owner in parents:
                owner = parents[owner]
                if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(owner.name)
            rows.append({
                "module": path.relative_to(root).as_posix(),
                "line": node.lineno,
                "method": node.func.attr,
                "call": ast.unparse(node.func),
                "functions": functions,
            })
    return sorted(rows, key=lambda row: (row["module"], row["line"], row["method"]))


def _zap_target_driver_bypasses(root=None):
    bypasses = []
    for row in _zap_call_inventory(_ZAP_TARGET_DRIVERS, root):
        if row["module"] == "tools.py" and "_run_zap" in row["functions"]:
            continue
        bypasses.append("%s:%d:%s" % (row["module"], row["line"], row["call"]))
    return bypasses


def test_zap_target_drivers_are_absent_outside_the_guarded_run_zap_subtree():
    """Known target-driving ZAP APIs may occur only below the guarded `_run_zap` entry point."""
    bypasses = _zap_target_driver_bypasses()
    assert bypasses == [], "ZAP target drivers exist outside guarded _run_zap: %s" % bypasses

    rows = _zap_call_inventory(_ZAP_TARGET_DRIVERS)
    counts = {name: sum(row["method"] == name for row in rows)
              for name in _ZAP_TARGET_DRIVERS}
    assert counts == {name: 1 for name in _ZAP_TARGET_DRIVERS}, (
        "the guarded ZAP driver inventory changed: %s" % counts)

    safety = _zap_call_inventory({"configure_target_safety"})
    assert len(safety) == 1
    assert safety[0]["module"] == "tools.py" and "_run_zap" in safety[0]["functions"]
    assert safety[0]["line"] < min(row["line"] for row in rows), (
        "ZAP target safety must be established before any target driver")


def test_zap_guard_rejects_a_duplicate_driver_in_a_sibling_module(tmp_path, monkeypatch):
    """Negative control: presence in `_run_zap` cannot excuse a second target driver elsewhere."""
    fake_root = tmp_path / "agent"
    fake_root.mkdir()
    fake_tools = fake_root / "tools.py"
    fake_tools.write_text(
        "class Registry:\n"
        "    async def _run_zap(self, zap, url):\n"
        "        await zap.configure_target_safety(url)\n"
        "        await zap.access_url(url)\n"
        "        await zap.spider(url)\n"
        "        await zap.ajax_start(url)\n"
        "        await zap.ascan(url)\n\n"
        "    async def next_tool(self):\n"
        "        return None\n",
        encoding="utf8")
    duplicate = fake_root / "other_module.py"
    duplicate.write_text(
        "async def duplicate(zap, url):\n"
        "    await zap.ascan(url)\n",
        encoding="utf8")
    monkeypatch.setattr(tools, "__file__", str(fake_tools))

    with pytest.raises(AssertionError, match="outside guarded _run_zap"):
        test_zap_target_drivers_are_absent_outside_the_guarded_run_zap_subtree()

    duplicate.write_text(
        "async def inspect_without_driving(zap):\n"
        "    return await zap.alerts()\n",
        encoding="utf8")
    test_zap_target_drivers_are_absent_outside_the_guarded_run_zap_subtree()


def test_zap_driver_inventory_does_not_depend_on_receiver_variable_name(tmp_path):
    fake_root = tmp_path / "agent"
    fake_root.mkdir()
    path = fake_root / "renamed_receiver.py"
    path.write_text(
        "async def duplicate(zap, url):\n"
        "    scanner = zap\n"
        "    await scanner.ascan(url)\n",
        encoding="utf8")

    assert _zap_target_driver_bypasses(fake_root) == [
        "renamed_receiver.py:3:scanner.ascan"
    ]
