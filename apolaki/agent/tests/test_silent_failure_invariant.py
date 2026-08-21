"""I-5: a crashed load-bearing check must not be reported as a clean result.

The census is AST-based.  A handler is swallowed when its body can only discard the
exception (pass/continue/break, return None/False, or assign literal fallback values).
The load-bearing classification is deliberately narrower than "all broad excepts": it
requires a target/oracle/dispatch/persistence call in the protected block.  Optional and
control-plane handlers are reported separately and are not release blockers.
"""
from __future__ import annotations

import ast
import asyncio
from collections import Counter
from pathlib import Path

import auth
import browser_engine
import register
import scope
import tools


_CONTROL_PLANE = {
    "asvs_model.py", "bench_all.py", "bench_contract.py", "bench_juliet.py",
    "benchmark.py", "benchmark_assert.py", "blind_benchmark.py", "ci_summary.py",
    "db.py", "deadcode_gate.py", "intel_extractor.py", "intel_feeds.py", "labs.py",
    "liveness.py", "liveness_run.py", "main.py", "mutation_gate.py", "owasp_bench.py",
    "poc_bundle.py", "proof_schema.py", "report.py", "sarif_io.py", "wstg_catalog.py",
}

# These protected calls LOOK load-bearing to a syntax-only pass, but their owner returns a
# typed degraded/failed result or they are best-effort enrichment beside the owning engine.
# Expected counts make every reason identify measured call sites; a new handler does not
# inherit an exemption just because it lives in the same file.
_OPTIONAL_LOAD_OWNERS = {
    ("asset_graph.py", "build_from_engagement"): (1, "`c` is a service-route dict; `.get` is not target traffic"),
    ("authz.py", "build_matrix"): (1, "field-level enrichment failure leaves the matrix and its other controls intact"),
    ("authz.py", "run_matrix"): (1, "the returned matrix records the failed request as status=0"),
    ("bie.py", "_attach_cdp"): (1, "CDP attachment is optional enrichment beside the Playwright trace"),
    ("bie.py", "_new_persona"): (2, "the BIE entry point returns its explicit degraded result when navigation cannot start"),
    ("bie.py", "route_mutate"): (1, "the route mutation returns a typed empty/degraded exchange to its oracle"),
    ("bie.py", "har_response_for"): (1, "`c` is a HAR candidate dict; `.get` is not target traffic"),
    ("bie.py", "_capture_shots"): (1, "screenshots are optional evidence enrichment after the differential"),
    ("bie.py", "observe"): (1, "observe returns the documented BIE degraded shape"),
    ("codeintel.py", "harvest"): (6, "black-box source harvesting is best-effort enrichment; the source analyser remains runnable"),
    ("natas_ladder.py", "engines_for"): (1, "`c` is a comment finding dict; `.get` is not target traffic"),
    ("natas_ladder.py", "solve_level"): (3, "the B2 ladder reports the level unsolved with its full denominator"),
    ("natas_ladder.py", "confirm_vulnerability"): (2, "the B2 ladder reports no confirmation; it never claims a clean B1 result"),
    ("transport_posture.py", "probe_tls"): (1, "the returned posture row explicitly says TLS was unavailable"),
}

_RAW_HTTP = {
    "aiohttp.ClientSession", "asyncio.open_connection", "httpx.AsyncClient", "httpx.Client",
    "httpx.get", "httpx.post", "httpx.request", "requests.get", "requests.post",
    "socket.create_connection", "urllib.request.urlopen", "websockets.connect",
}
_EXACT_LOAD_CALLS = {
    "_browser_engine.drive", "_browser_engine.rate_limited_goto",
    "_browser_engine.rate_limited_goto_sync", "browser_engine.drive",
    "browser_engine.rate_limited_goto", "browser_engine.rate_limited_goto_sync",
    "db.add_exchange", "db.add_finding", "db.update_finding", "self._cmd",
    "self._exec_internal", "self._http", "self._http_send", "self._run_tool",
    "self.tools.execute",
}
_TARGET_RECEIVERS = {
    "c", "client", "page", "pg", "reader", "resp", "response", "route", "session",
    "sock", "socket", "websocket", "writer", "ws",
}
_TARGET_METHODS = {
    "click", "delete", "eval_on_selector", "evaluate", "fill", "get", "goto", "patch",
    "post", "put", "read", "recv", "request", "send", "wait_for_response",
}


def _constant(node):
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_constant(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all((key is None or _constant(key)) and _constant(value)
                   for key, value in zip(node.keys, node.values))
    return False


def _swallowed(handler):
    def silent(stmt):
        if isinstance(stmt, (ast.Pass, ast.Continue, ast.Break)):
            return True
        if isinstance(stmt, ast.Return):
            return stmt.value is None or (
                isinstance(stmt.value, ast.Constant) and stmt.value.value in (None, False))
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            return stmt.value is not None and _constant(stmt.value)
        return False

    return bool(handler.body) and all(silent(stmt) for stmt in handler.body)


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _load_call(call):
    name = _dotted(call.func)
    parts = name.split(".")
    leaf = parts[-1] if parts else ""
    if name in _RAW_HTTP or name in _EXACT_LOAD_CALLS:
        return True
    if len(parts) >= 2 and parts[-2] in _TARGET_RECEIVERS and leaf in _TARGET_METHODS:
        return True
    if leaf in {
        "_exec_internal", "_http", "_http_send", "_run_tool", "add_exchange",
        "add_finding", "execute", "fetch", "post", "send", "update_finding",
    }:
        return True
    return leaf.startswith(("analyze_", "confirm_", "probe_")) or leaf in {
        "control_status", "error_signatures", "evaluate", "quote_break_recovers",
        "validate_confirmed",
    }


def _production_paths(root=None):
    root = Path(tools.__file__).resolve().parent if root is None else Path(root).resolve()
    return sorted(path for path in root.rglob("*.py")
                  if not ({"tests", "tier3"} & set(path.relative_to(root).parts[:-1])))


def _partition(paths=None):
    root = Path(tools.__file__).resolve().parent
    paths = _production_paths(root) if paths is None else [Path(path) for path in paths]
    rows = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf8"), filename=str(path))
        parents = {child: parent for parent in ast.walk(tree)
                   for child in ast.iter_child_nodes(parent)}
        for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
            if not _swallowed(handler):
                continue
            owner = handler
            while owner in parents and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner = parents[owner]
            function = owner.name if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)) else "<module>"
            protected = parents.get(handler)
            calls = []
            if isinstance(protected, ast.Try):
                calls = [node for stmt in protected.body for node in ast.walk(stmt)
                         if isinstance(node, ast.Call)]
            module = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
            owner_key = (module, function)
            load_shaped = any(_load_call(call) for call in calls)
            if module in _CONTROL_PLANE:
                category = "control-plane"
            elif module.endswith("_solvers.py") or owner_key in _OPTIONAL_LOAD_OWNERS:
                category = "optional"
            elif load_shaped:
                category = "load-bearing"
            else:
                category = "optional"
            rows.append({"module": module, "function": function, "line": handler.lineno,
                         "category": category, "owner": owner_key,
                         "load_shaped": load_shaped})
    return rows


def _registry(mission_id="m-silent"):
    engine = scope.ScopeEngine()
    engine.load_manual(["target.tld"], [], "silent failure test")
    return tools.ToolRegistry(engine, mission_id=mission_id, lab_mode=True)


def test_partition_is_non_vacuous_and_matches_the_measured_rebased_tree():
    rows = _partition()
    counts = Counter(row["category"] for row in rows)
    trees = _production_paths()
    all_handlers = sum(isinstance(node, ast.ExceptHandler)
                       for path in trees
                       for node in ast.walk(ast.parse(path.read_text(encoding="utf8"))))
    assert len(trees) == 178
    # 917 at 1c357c8; the durable observer adds one guarded persistence handler.
    # This is a floor so deleting production modules cannot make the census quietly shrink.
    assert all_handlers >= 917
    # Independent re-measurement at 1c357c8.  The lease's 562 has no executable
    # predicate; applying its written definition produces 570, partitioned here.
    assert counts["optional"] <= 388
    assert counts["control-plane"] <= 77
    assert counts["load-bearing"] == 0, [
        "%s:%d:%s" % (r["module"], r["line"], r["function"])
        for r in rows if r["category"] == "load-bearing"
    ]


def test_every_optional_load_owner_names_a_reason_and_measured_call_sites():
    rows = _partition()
    counts = Counter(row["owner"] for row in rows if row["load_shaped"])
    wrong = {}
    for owner, (expected, reason) in _OPTIONAL_LOAD_OWNERS.items():
        if not isinstance(reason, str) or not reason.strip() or counts[owner] != expected:
            wrong[owner] = {"expected": expected, "actual": counts[owner], "reason": reason}
    assert wrong == {}


def test_repository_guard_catches_a_planted_load_bearing_bypass(tmp_path):
    planted = tmp_path / "brand_new_engine.py"
    planted.write_text(
        "import httpx\n\ndef probe(url):\n"
        "    try:\n        return httpx.get(url)\n    except Exception:\n        return None\n",
        encoding="utf8",
    )
    rows = _partition([planted])
    assert [(row["function"], row["category"]) for row in rows] == [
        ("probe", "load-bearing")
    ]


def test_swallowed_engine_failure_is_visible_in_result_and_durable_ledger(monkeypatch):
    reg = _registry()
    logged = []
    monkeypatch.setattr(tools.db, "add_log", lambda mid, kind, data: logged.append((mid, kind, data)))

    async def dispatch(name, _inp, _sid):
        try:
            raise RuntimeError("oracle parser exploded")
        except Exception as exc:
            reg._swallow(exc, "run_sqli.boolean_oracle", "https://target.tld/search?q=1")
        finding = {"title": "still valid", "severity": "high", "confidence": "confirmed"}
        return tools.ToolResult(name, "https://target.tld/search?q=1", True,
                                "tested 1 parameter, 1 confirmed", [finding])

    monkeypatch.setattr(reg, "_dispatch_engine", dispatch)
    result = asyncio.run(reg.execute("run_sqli", {"url": "https://target.tld/search?q=1"}, "m-silent"))
    assert "DEGRADED" in result.output and "run_sqli.boolean_oracle" in result.output
    errors = [data for _mid, kind, data in logged if kind == "tool_error"]
    assert errors and errors[0]["tool"] == "run_sqli"
    assert "oracle parser exploded" in errors[0]["error"]
    assert [finding["title"] for finding in result.findings] == ["still valid"]


def test_clean_engine_result_and_ledger_are_byte_unchanged(monkeypatch):
    reg = _registry()
    logged = []
    monkeypatch.setattr(tools.db, "add_log", lambda mid, kind, data: logged.append((kind, dict(data))))

    async def dispatch(name, _inp, _sid):
        return tools.ToolResult(name, "https://target.tld/", True, "clean result", [])

    monkeypatch.setattr(reg, "_dispatch_engine", dispatch)
    result = asyncio.run(reg.execute("run_sqli", {"url": "https://target.tld/"}, "m-silent"))
    assert result.output == "clean result"
    assert [kind for kind, _data in logged] == ["tool_call", "tool_result"]


def test_swallow_outside_execute_is_still_durable(monkeypatch):
    reg = _registry()
    logged = []
    monkeypatch.setattr(tools.db, "add_log", lambda mid, kind, data: logged.append((mid, kind, data)))
    reg._swallow(RuntimeError("sweep dispatch died"), "sweep.run_sqli", "https://target.tld/")
    assert logged and logged[0][1] == "tool_error"
    assert logged[0][2]["tool"] == "sweep.run_sqli"


class _Headers(dict):
    def get_list(self, _name):
        return []


class _Response:
    def __init__(self, body="<html>login</html>", payload=None):
        self.text = body
        self.url = "https://target.tld/login"
        self.status_code = 200
        self.headers = _Headers({"content-type": "text/html"})
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _Cookies(dict):
    pass


class _FailingJsonClient:
    def __init__(self):
        self.cookies = _Cookies()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def get(self, *_args, **_kwargs):
        return _Response()

    async def post(self, *_args, **kwargs):
        if "json" in kwargs:
            raise RuntimeError("JSON transport unavailable")
        return _Response()


def test_login_fallback_transport_failure_is_not_reported_as_plain_no_session(monkeypatch):
    monkeypatch.setattr(browser_engine, "rate_limited_async_client",
                        lambda *_args, **_kwargs: _FailingJsonClient())
    result = asyncio.run(auth.login("https://target.tld/login", "nobody", "invalid"))
    assert result["verified"] is False
    assert "JSON fallback degraded" in result["note"]
    assert "JSON transport unavailable" in result["note"]


def test_registration_fallback_transport_failure_is_explicit(monkeypatch):
    monkeypatch.setattr(browser_engine, "rate_limited_async_client",
                        lambda *_args, **_kwargs: _FailingJsonClient())
    account = {"email": "new@target.tld", "username": "new", "password": "Strong123!"}
    result = asyncio.run(register.register("https://target.tld/register", account=account))
    assert result["created"] is False
    assert "degraded" in result["note"]
    assert "JSON transport unavailable" in result["note"]
