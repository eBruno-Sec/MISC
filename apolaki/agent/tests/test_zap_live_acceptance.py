from __future__ import annotations

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import time

import browser_engine
import db
import main
import pytest
import scope as scope_mod
import tools


LIVE = bool(os.getenv("ZAP_LIVE_ACCEPTANCE"))
pytestmark = pytest.mark.skipif(not LIVE, reason="requires the pinned local ZAP daemon and labs")


def _run(awaitable):
    return asyncio.run(awaitable)


@contextmanager
def _limiting_target(host: str, port: int):
    starts = []
    observations = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            return

        def do_GET(self):
            with lock:
                started = time.monotonic()
                starts.append(started)
                index = len(starts)
                observations.append({
                    "index": index,
                    "method": self.command,
                    "path": self.path,
                    "started": started,
                    "headers": dict(self.headers.items()),
                })
            body = b"limited" if index == 1 else b"unexpected follow-up"
            self.send_response(429 if index == 1 else 200)
            if index == 1:
                self.send_header("Retry-After", "2")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}/", starts, observations
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_real_zap_retry_after_aborts_before_a_second_target_request():
    host = os.environ["ZAP_LIVE_SELF_HOST"]
    browser_engine.target_rate_policy.clear()
    with _limiting_target(host, 42888) as (url, starts, observations):
        scope = scope_mod.ScopeEngine()
        scope.load_manual([url], [], "live ZAP rate control")
        registry = tools.ToolRegistry(scope, mission_id="zap-rate-live", lab_mode=True)
        registry.stop_event = asyncio.Event()

        result = _run(registry._run_zap({"url": url, "policy": "passive"}))
        returned = time.monotonic()
        time.sleep(0.35)

    print(json.dumps({"observations": observations, "result_error": result.error}, sort_keys=True))
    assert not result.success
    assert "target rate limit" in result.error
    assert len(starts) == 1
    assert browser_engine.target_rate_policy.remaining(url) > 0
    print(json.dumps({"requests": len(starts), "returned_at": returned,
                      "retry_remaining": browser_engine.target_rate_policy.remaining(url),
                      "error": result.error}, sort_keys=True))


def test_real_full_mission_persists_run_zap_tool_call(tmp_path, monkeypatch):
    target = os.environ["ZAP_LIVE_TARGET"]
    old_path = db.DB_PATH
    session_id = None
    monkeypatch.setenv("BBH_REQUEST_BUDGET", "2")
    try:
        db.init(str(tmp_path / "zap-live-mission.db"))

        async def exercise():
            engaged = await main.engage(main.EngageRequest(
                program_name="lane7-zap-live",
                in_scope=[target],
                mode="full",
                strategy="deterministic",
                auto_approve=True,
                enable_zap=True,
                require_zap=True,
                zap_policy="passive",
            ))
            sid = engaged["session_id"]
            await main.run_mission(sid)
            await asyncio.wait_for(main.sessions[sid]["task"], timeout=600)
            return sid

        session_id = _run(exercise())
        logs = db.get_logs(session_id, limit=100000)
        calls = [row for row in logs
                 if row.get("type") == "tool_call" and row.get("tool") == "run_zap"]
        results = [row for row in logs
                   if row.get("type") == "tool_result" and row.get("tool") == "run_zap"]
        mission = db.get_mission(session_id)

        assert len(calls) == 1
        assert len(results) == 1
        assert mission["status"] == "complete"
        print(json.dumps({"mission_id": session_id, "status": mission["status"],
                          "tool_call": calls[0], "tool_result": results[0]}, sort_keys=True))
    finally:
        if session_id:
            main.sessions.pop(session_id, None)
        if db._conn is not None:
            db._conn.close()
        db._conn = None
        db.DB_PATH = old_path
