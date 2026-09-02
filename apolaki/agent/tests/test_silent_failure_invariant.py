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


def _partition(paths=None, predicate=None):
    """`predicate` selects WHICH handlers are censused.  The classification below is
    identical either way, so the two censuses are directly comparable."""
    root = Path(tools.__file__).resolve().parent
    paths = _production_paths(root) if paths is None else [Path(path) for path in paths]
    predicate = _swallowed if predicate is None else predicate
    rows = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf8"), filename=str(path))
        parents = {child: parent for parent in ast.walk(tree)
                   for child in ast.iter_child_nodes(parent)}
        for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
            if not predicate(handler):
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
    # 178 -> 179: Q-112 adds `agent/middlebox.py`. 179 -> 180: Q-142 adds `agent/deadline.py`. 180 -> 181: Q-145 adds `agent/csp_audit.py`. 181 -> 185: Q-146 `code_injection.py`, Q-147 `dom_sinks.py`, Q-148 `passive_disclosure.py`, Q-149 `jwt_attacks.py`. This equality exists so
    # the census cannot quietly stop parsing part of the tree; a module ADDED is a legitimate move
    # and the number moves with it, while a module that vanishes still trips it.
    # 185 -> 188: cycle 20 lanes add `rendered_forms.py` (Q-158), `nosqli_body.py` (Q-155)
    # and `spa_routes.py` (Q-163), each a new engine module with its own test file.
    assert len(trees) == 188
    # 917 at 1c357c8; the durable observer adds one guarded persistence handler.
    # This is a floor so deleting production modules cannot make the census quietly shrink.
    assert all_handlers >= 917
    # Independent re-measurement at 1c357c8.  The lease's 562 has no executable
    # predicate; applying its written definition produces 570, partitioned here.
    # LOWERED 388 -> 387: `_run_dalfox`'s `except: pass` around a per-line `json.loads` is
    # gone (Q-091 -- it parsed a JSON ARRAY line by line, so it discarded every line of
    # every possible dalfox output).  Ratcheted rather than left slack, so the seat that
    # handler occupied cannot be silently refilled.
    # 387 -> 407. Twenty from the three cycle-20 engine modules, which are browser and network
    # drivers: spa_routes 10, rendered_forms 7, nosqli_body 4 (one of spa_routes' became a
    # recorder, below). Checked rather than waved through, because +20 handlers is exactly the
    # size of jump this census exists to make somebody look at:
    #   * BOTH load-bearing handlers the lanes introduced were FIXED, not budgeted --
    #     `spa_routes._href` (a failed href read makes a real navigation look like none, losing the
    #     route) and `spa_routes._settle`'s control-count reset (stale count -> the stability wait
    #     satisfies itself against the previous page). Both now record through the active registry.
    #   * The remaining twenty are optional by the census's own rule: no oracle reads their silence
    #     as a clean result. Most are Playwright timeouts on a bounded wait, where the timeout IS
    #     the answer and is returned as a reason string rather than swallowed.
    assert counts["optional"] <= 407
    # 77 -> 78: Q-121 adds one guarded persistence handler in `main.py` (`_record_memory`), the
    # same best-effort shape as the report-time graph save right beside it -- `tools.graph.save`
    # writing the LIVE graph must not abort mission teardown if persistence fails. `main.py` is
    # already in `_CONTROL_PLANE`, so this is not a release blocker; the ceiling moves with it.
    assert counts["control-plane"] <= 78
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


# ═══════════════════════════════════════════════════════════════════════════════
# I-5 REPAIR — guard-falsification lane, 2026-08-21.
#
# The census above CANNOT see the defect I-5 exists to catch.  `_swallowed()`
# applies `_constant()` to its Assign branch but not to its Return branch, so a
# handler ending `return []` / `{}` / `""` — or a bare `return <name>` — is
# classified into NO category and constrained by NO ceiling.
#
# MEASURED at 6c7ed00: deleting the `_swallow` recorder from
# `tools.ToolRegistry._traversal_differential` (tools.py:3854) leaves this file at
# 8 passed and the census byte-identical — optional 388 / control-plane 77 /
# load-bearing 0 — while a crashed traversal oracle becomes indistinguishable
# from a completed scan that found nothing.  The SAME deletion ending
# `return None` instead of `return out` is killed, naming the line.  One token.
# docs/handoff/guard_falsification.md, mutants M5-POS and M5-HUNT.
#
# The repair did NOT assert the strong claim "no load-bearing handler swallows
# silently", because when it was written that claim was FALSE: 15 such handlers existed
# under the guard's own written definition.  Asserting it then is how the unfalsifiable
# guards in this repo got written.  It ratchets instead, in the DELETION direction only:
# adding a recorder is never blocked, removing one is red, and the message names
# the owner.  Lower a baseline deliberately, in the same commit, with the reason.
#
# Those 15 have since been FIXED rather than merely capped, so the strong claim is now
# true and is asserted as an equality at the bottom of this file.  It is asserted
# because it was measured, not to make the guard sound stronger.
#
# AST NODE counts (not grep LINE counts) over the same 178 production modules.
_SWALLOW_RECORDERS = {
    ("agent.py", "_authenticated_recrawl"): 4,
    ("bie.py", "session_fingerprint"): 1,
    ("dns_recon.py", "doh"): 1,
    ("enip_audit_tool.py", "_list_identity_tcp"): 1,
    ("agent.py", "_do_header_trust"): 1,
    ("agent.py", "_do_persona_authz"): 11,
    ("agent.py", "_do_saml"): 1,
    ("agent.py", "_do_scan_auth"): 2,
    ("agent.py", "_do_session_lifecycle"): 1,
    ("agent.py", "_do_transport_posture"): 2,
    ("agent.py", "_execute_plan"): 1,
    ("agent.py", "_graph_action_step"): 1,
    ("agent.py", "_graph_primary_state"): 2,
    ("agent.py", "_identify_dumped_hashes"): 1,
    ("agent.py", "_inject_sweep_surface"): 9,
    ("agent.py", "_probe_cloud_storage"): 1,
    ("agent.py", "_probe_for_creds"): 1,
    ("agent.py", "_project_spec_params"): 1,
    ("agent.py", "_reacquire_personas"): 1,
    # Q-118: LOWERED 1 -> 0, with the reason the ratchet asks for. The deleted recorder was
    # `codeintel.session_kill_route`, which existed only because this function appended to
    # `tools.urls` PAST `_add_urls` and therefore had to re-implement one of that intake's
    # guarantees by hand. The fold now goes THROUGH `_add_urls`, so the refusal is no longer local
    # and no longer needs a local record: the URL is QUARANTINED into `session_kill_urls`, where
    # `_run_session_lifecycle` can still use it, instead of being discarded with a log line. The
    # trace got stronger, not weaker -- `test_session_kill_door` now asserts the quarantine list.
    ("agent.py", "_recon_code_intelligence"): 0,
    ("agent.py", "_reject_hostless_step"): 1,
    ("agent.py", "_reject_session_kill_step"): 1,
    ("agent.py", "_run_pack"): 1,
    ("agent.py", "_run_service_packs"): 2,
    ("agent.py", "_surface_crawl"): 2,
    ("agent.py", "_validate_candidates_impl"): 2,
    ("tools.py", "_acquire_session"): 2,
    ("tools.py", "_audit_one"): 4,
    ("tools.py", "_benchmark_lab"): 1,
    ("tools.py", "_browser_dialog_scan"): 1,
    # Q-092: the external-tool chokepoint.  Deleting this one recorder re-silences every
    # subprocess wrapper at once, and no per-wrapper row would move to show it.
    ("tools.py", "_cmd"): 1,
    ("tools.py", "_browser_navigate"): 3,
    ("tools.py", "_confirm_authz_write"): 3,
    ("tools.py", "_confirm_create_object_idor"): 5,
    ("tools.py", "_confirm_read_object_idor"): 3,
    ("tools.py", "_discover_params"): 1,
    ("tools.py", "_fetch"): 1,
    ("tools.py", "_form_xss_browser_confirm"): 4,
    ("tools.py", "_get"): 1,
    ("tools.py", "_gql_post"): 1,
    ("tools.py", "_locate"): 1,
    ("tools.py", "_post"): 2,
    ("tools.py", "_render"): 2,
    ("tools.py", "_run_authz_matrix"): 1,
    ("tools.py", "_run_bfla"): 3,
    ("tools.py", "_run_content_discovery"): 1,
    ("tools.py", "_run_dalfox"): 1,
    ("tools.py", "_run_dir_harvest"): 1,
    ("tools.py", "_run_dom_audit"): 3,
    ("tools.py", "_run_dom_trace"): 2,
    ("tools.py", "_run_enumerate_ids"): 2,
    ("tools.py", "_run_exposure"): 1,
    ("tools.py", "_run_external_surface"): 1,
    ("tools.py", "_run_form_cmdi"): 2,
    ("tools.py", "_run_github_recon"): 1,
    ("tools.py", "_run_injection_probes"): 5,
    ("tools.py", "_run_jsonp"): 1,
    ("tools.py", "_run_ldap"): 1,
    ("tools.py", "_run_mass_assign"): 1,
    ("tools.py", "_run_param_mine"): 1,
    ("tools.py", "_run_race"): 1,
    ("tools.py", "_run_service_pack"): 1,
    ("tools.py", "_run_session_fixation"): 1,
    ("tools.py", "_run_session_token"): 1,
    ("tools.py", "_run_sourcemap"): 2,
    ("tools.py", "_run_sqli"): 2,
    ("tools.py", "_run_ssi"): 1,
    ("tools.py", "_run_transport_posture"): 3,
    ("tools.py", "_run_web_probes"): 6,
    ("tools.py", "_run_ws_hijack"): 2,
    ("tools.py", "_run_xpath"): 1,
    ("tools.py", "_run_xss"): 5,
    ("tools.py", "_run_xxe"): 2,
    ("tools.py", "_send"): 2,
    ("tools.py", "_sl_login"): 1,
    ("tools.py", "_sl_logout_variant"): 2,
    ("tools.py", "_sl_marker"): 1,
    ("tools.py", "_sl_mint"): 1,
    ("tools.py", "_sl_pwchange_variant"): 2,
    ("tools.py", "_socket_service_probe"): 2,
    # the module-level face of `_swallow` itself; deleting its one forwarding call would
    # silence all three module-level helpers at once and no per-owner row would move.
    ("tools.py", "_swallow"): 1,
    ("tools.py", "_submit"): 1,
    ("tools.py", "_timed"): 1,
    ("tools.py", "_traversal_differential"): 1,
    ("tools.py", "_wm_audit"): 3,
    ("tools.py", "_wm_confirm"): 4,
    ("tools.py", "_wm_harness_server"): 1,
    ("tools.py", "_write"): 1,
    ("tools.py", "_ws_handshake"): 2,
    ("tools.py", "get"): 2,
    ("tools.py", "probe"): 1,
    ("tools.py", "q"): 1,
    ("tools.py", "read_state"): 1,
    ("tools.py", "send"): 1,
    ("tools.py", "worker"): 1,
}


def _swallow_recorder_census(paths=None):
    """AST NODE count of `*._swallow(...)` calls, keyed by (module, function) owner."""
    root = Path(tools.__file__).resolve().parent
    paths = _production_paths(root) if paths is None else [Path(path) for path in paths]
    census = Counter()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf8"), filename=str(path))
        parents = {child: parent for parent in ast.walk(tree)
                   for child in ast.iter_child_nodes(parent)}

        def owner(node):
            while node in parents:
                node = parents[node]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node.name
            return "<module>"

        module = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.name
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "_swallow"):
                census[(module, owner(node))] += 1
    return census


def _recorder_losses(baseline, census):
    """Owners that LOST recorders.  Gains are deliberately invisible to this ratchet."""
    return {owner: (expected, census.get(owner, 0))
            for owner, expected in baseline.items() if census.get(owner, 0) < expected}


def _literal_return_swallow(handler):
    """A handler that discards the exception into a literal value it RETURNS.

    Same discard as `_swallowed`'s Assign branch (`out = []`), in the shape that
    branch cannot see (`return []`).

    Kept separate from `_swallowed` still, but no longer for the original reason.  The
    15 load-bearing handlers that made folding it in go red are FIXED, so folding would
    now leave `load-bearing` at 0 either way.  What blocks it is the other 74 rows:
    merging moves 61 optional + 13 control-plane handlers into the main census, which
    needs `counts["optional"] <= 388` RAISED to absorb them.  A ceiling is not raised to
    make a merge fit.

    Strictly DISJOINT from `_swallowed`: `return None` / `return False` satisfy both
    predicates, and counting them twice inflated this census from 89 to 134 on the
    first attempt.  This censuses only the shape the shipped predicate misses.
    """
    if _swallowed(handler):
        return False
    saw = False
    for stmt in handler.body:
        if isinstance(stmt, ast.Return) and stmt.value is not None and _constant(stmt.value):
            saw = True
            continue
        if isinstance(stmt, (ast.Pass, ast.Continue, ast.Break)):
            continue
        return False
    return saw


def test_swallow_recorders_are_never_silently_deleted():
    losses = _recorder_losses(_SWALLOW_RECORDERS, _swallow_recorder_census())
    assert losses == {}, (
        "a degradation recorder was DELETED — owner: (expected, found). Removing one "
        "turns a load-bearing failure back into a clean result, and the census above "
        "cannot see it happen (M5-HUNT). If the removal is intended, lower the "
        "baseline in the same commit with the reason: %r" % sorted(losses.items()))


def test_the_recorder_ratchet_can_actually_fail():
    """Negative control.  A ratchet nobody has seen go red is a declaration.

    Synthetic on purpose: a control built from the live census would itself go red
    on the very mutant it exists to describe, which is how a control stops being one.
    The floors below are non-vacuity checks, not a second ratchet.
    """
    census = _swallow_recorder_census()
    assert sum(census.values()) >= 100 and len(census) >= 50, dict(census)
    baseline = {("m.py", "kept"): 1, ("m.py", "thinned"): 2, ("m.py", "erased"): 1}
    actual = Counter({("m.py", "kept"): 1, ("m.py", "thinned"): 1, ("m.py", "added"): 9})
    assert _recorder_losses(baseline, actual) == {
        ("m.py", "thinned"): (2, 1),      # partial deletion is caught
        ("m.py", "erased"): (1, 0),       # total deletion is caught
    }                                     # ("m.py", "added") is deliberately ignored


def test_recorder_census_sees_a_planted_recorder(tmp_path):
    planted = tmp_path / "brand_new_engine.py"
    planted.write_text(
        "class E:\n    def probe(self):\n        try:\n            self._http()\n"
        "        except Exception as exc:\n            self._swallow(exc, 'e.probe', '')\n",
        encoding="utf8")
    assert _swallow_recorder_census([planted]) == Counter({("brand_new_engine.py", "probe"): 1})


def test_the_shipped_census_predicate_is_asymmetric_between_assign_and_return(tmp_path):
    """The measured hole, pinned so it cannot be re-opened silently."""
    def handler(body):
        return ast.parse("def f():\n    try:\n        pass\n    except Exception:\n"
                         "        %s\n" % body).body[0].body[0].handlers[0]

    assert _swallowed(handler("out = []")) is True        # literal fallback, SEEN
    assert _swallowed(handler("return []")) is False      # same discard, NOT seen
    assert _swallowed(handler("return out")) is False     # the M5-HUNT shape
    assert _literal_return_swallow(handler("return []")) is True

    planted = tmp_path / "brand_new_engine.py"
    planted.write_text(
        "import httpx\n\ndef probe(url):\n"
        "    try:\n        return httpx.get(url)\n    except Exception:\n        return []\n",
        encoding="utf8")
    assert _partition([planted]) == []                    # invisible to the shipped census
    assert [(row["function"], row["category"])
            for row in _partition([planted], predicate=_literal_return_swallow)] == [
        ("probe", "load-bearing")]


def test_literal_return_discards_are_censused_and_capped():
    """MEASURED at 6c7ed00, unmutated: 89 handlers, 15 of them on load-bearing paths.

    Ceilings, not equalities: FIXING one of these must never turn this red, and
    adding a 90th must.  The load-bearing survivors are named on failure so the list
    can only be argued down one site at a time.

    LOWERED 15 -> 3 -> 0, each step in the commit that earned it.  Every one of the 15
    now records before returning the SAME empty value, so the handler is no longer a bare
    literal-return discard and drops out of this census.  Twelve are ToolRegistry methods
    or their closures and use `self._swallow`; the other three are module-level helpers
    with no `self` (bie.session_fingerprint, dns_recon.doh,
    enip_audit_tool._list_identity_tcp) and reach the same ledger through
    `tools._ACTIVE_REGISTRY`, published for the span of `ToolRegistry.execute`.

    Each has an oracle in `tests/test_silent_failure_residue.py` that forces the protected
    call to raise and asserts the ledger names the owner.  All were measured RED against a
    `git archive HEAD` snapshot of production and green after.

    Zero is now an EQUALITY, not a ceiling: with the residue cleared, one new
    `except: return []` on a load-bearing path is a regression, not a budget item.
    """
    rows = _partition(predicate=_literal_return_swallow)
    counts = Counter(row["category"] for row in rows)
    named = ["%s:%d:%s" % (r["module"], r["line"], r["function"])
             for r in rows if r["category"] == "load-bearing"]
    # 61 -> 63. Both new entries are in `spa_routes.py` and both are defensive `urlparse`
    # wrappers -- `split_fragment` and `inventory_path` return a safe default for a malformed URL,
    # which yields no route. That is the correct answer and no oracle reads their silence as
    # "clean", which is what keeps them OPTIONAL rather than load-bearing. The module's one
    # LOAD-BEARING discard (`_href`, where a failed read would make a real navigation look like no
    # navigation and lose the route) was fixed to record instead of raising this ceiling further.
    assert counts["optional"] <= 63
    assert counts["control-plane"] <= 13
    assert counts["load-bearing"] == 0, named
