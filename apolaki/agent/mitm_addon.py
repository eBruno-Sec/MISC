"""
Apolaki mitmproxy addon -- loaded by `mitmdump -s mitm_addon.py` inside the proxy sidecar.

Two jobs:
  1. SENSOR   -- stream every response as a redacted one-line JSON record to a shared flows file the
                 agent reads (live traffic view + HAR export).
  2. REWRITE  -- apply deterministic match-and-replace rules (a JSON file the agent writes) to requests
                 and responses in flight: set request headers, find/replace request/response bodies,
                 force a response status, or block a request outright.

Runs in the mitmproxy container, which has ONLY this file on its path -- so it is fully self-contained
(no Apolaki imports). Secrets are never persisted: Authorization/Cookie/token headers are redacted
before a record is written. The rules file is re-read only when its mtime changes (cheap hot-reload).
"""
import json
import os
import time

FLOWS_DIR = os.environ.get("PROXY_FLOWS_DIR", "/data")
FLOWS_FILE = os.path.join(FLOWS_DIR, "flows.jsonl")
RULES_FILE = os.path.join(FLOWS_DIR, "rules.json")
MAX_LINES = 2000
SECRET_HDRS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "token",
               "proxy-authorization"}

_rules_cache = {"mtime": -1.0, "rules": []}


def _redact(headers):
    out = {}
    try:
        for k, v in headers.items():
            out[str(k)] = "<redacted>" if str(k).lower() in SECRET_HDRS else str(v)
    except Exception:
        pass
    return out


def _load_rules():
    try:
        st = os.stat(RULES_FILE)
    except FileNotFoundError:
        _rules_cache["rules"] = []
        _rules_cache["mtime"] = -1.0
        return _rules_cache["rules"]
    except Exception:
        return _rules_cache["rules"]
    if st.st_mtime != _rules_cache["mtime"]:
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            _rules_cache["rules"] = data.get("rules", []) if isinstance(data, dict) else (data or [])
            _rules_cache["mtime"] = st.st_mtime
        except Exception:
            _rules_cache["rules"] = []
    return _rules_cache["rules"]


def _match(rule, method, host, path):
    m = rule.get("match", {}) or {}
    if m.get("method") and m["method"].upper() != str(method).upper():
        return False
    if m.get("host") and m["host"].lower() not in str(host).lower():
        return False
    if m.get("path_contains") and m["path_contains"] not in str(path):
        return False
    return bool(m)


def request(flow):
    """Apply request-side rules before the request leaves for the target."""
    req = flow.request
    for rule in _load_rules():
        if not _match(rule, req.method, req.host, req.path):
            continue
        for k, v in (rule.get("set_request_headers") or {}).items():
            req.headers[str(k)] = str(v)
        for pair in (rule.get("replace_request_body") or []):
            try:
                req.text = req.text.replace(pair["find"], pair.get("replace", ""))
            except Exception:
                pass
        if rule.get("block"):
            try:
                from mitmproxy import http
                flow.response = http.Response.make(int(rule.get("block_status", 403)),
                                                   b"blocked by apolaki proxy",
                                                   {"content-type": "text/plain"})
            except Exception:
                pass
        flow.metadata["apolaki_rule"] = rule.get("id", "")


def response(flow):
    """Apply response-side rules, then record the (redacted) flow for the agent to read."""
    resp = flow.response
    req = flow.request
    for rule in _load_rules():
        if not _match(rule, req.method, req.host, req.path):
            continue
        if rule.get("set_response_status"):
            try:
                resp.status_code = int(rule["set_response_status"])
            except Exception:
                pass
        for pair in (rule.get("replace_response_body") or []):
            try:
                resp.text = resp.text.replace(pair["find"], pair.get("replace", ""))
            except Exception:
                pass
        if rule.get("id"):
            flow.metadata["apolaki_rule"] = rule.get("id", "")
    _write_flow(flow)


def _write_flow(flow):
    req = flow.request
    resp = flow.response
    try:
        latency = 0.0
        try:
            if resp and req.timestamp_start and resp.timestamp_end:
                latency = round((resp.timestamp_end - req.timestamp_start) * 1000, 1)
        except Exception:
            pass
        rec = {"id": getattr(flow, "id", ""), "ts": time.time(), "method": req.method,
               "url": req.pretty_url, "host": req.host, "path": req.path,
               "status": resp.status_code if resp else 0,
               "req_headers": _redact(req.headers), "resp_headers": _redact(resp.headers) if resp else {},
               "resp_ct": (resp.headers.get("content-type", "") if resp else ""),
               "resp_len": len(resp.content) if (resp and resp.content) else 0, "ms": latency,
               "matched_rule": flow.metadata.get("apolaki_rule", "")}
        os.makedirs(FLOWS_DIR, exist_ok=True)
        with open(FLOWS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
        _trim()
    except Exception:
        pass


def _trim():
    """Keep the flows file bounded (ring-buffer semantics) so a long session can't fill the volume."""
    try:
        with open(FLOWS_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if len(lines) > MAX_LINES:
            with open(FLOWS_FILE, "w", encoding="utf-8") as f:
                f.writelines(lines[-MAX_LINES:])
    except Exception:
        pass
