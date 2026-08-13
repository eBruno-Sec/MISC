"""
Intercept proxy integration -- Apolaki's Burp/ZAP-core, the real intercepting man-in-the-middle the
platform was missing. A mitmproxy sidecar sits between the browser engine and every target; the browser
routes through it, so EVERY request/response is captured live, and deterministic MATCH-AND-REPLACE rules
can rewrite traffic in flight (Burp's "match & replace" / intercept -- rule-driven rather than
click-to-edit, which fits Apolaki's deterministic-first model and actually scales).

Split of duties:
  * the mitm addon (mitm_addon.py) runs INSIDE the proxy container: streams redacted flows to a shared
    file and applies the rules file the agent writes.
  * this module runs in the AGENT: reads that flows file (view / HAR export), writes the rules file, and
    replays a captured request (optionally mutated) as a fresh send.

With no proxy sidecar running everything degrades to a clearly-labelled empty result -- nothing is faked
and the HTTP + browser engines keep working. Pure + dependency-light; zero LLM.

How it works (answer to "does it work like Burp, built-in, no setup?"): yes -- start it with
`docker compose --profile proxy up -d mitmproxy` and the browser engine auto-routes through it (the
agent passes Chrome `--proxy-server`/`--ignore-certificate-errors` launch args when PROXY_URL is set).
No manual proxy config, no CA import dance for the headless browser. It captures like Burp's proxy and
rewrites like Burp's match-and-replace; interception is expressed as rules (reproducible) instead of a
human pausing each request.
"""
from __future__ import annotations

import json
import os
import time

import capture as _cap   # reuse the exact redaction + HAR header/timestamp helpers (one HAR shape platform-wide)

FLOWS_FILE = "flows.jsonl"
RULES_FILE = "rules.json"


def flows_dir(d=None):
    return d or os.environ.get("PROXY_FLOWS_DIR", "/app/data/proxy")


def proxy_url(u=None):
    return (u or os.environ.get("PROXY_URL", "")).rstrip("/")


def _flows_path(d=None):
    return os.path.join(flows_dir(d), FLOWS_FILE)


def _rules_path(d=None):
    return os.path.join(flows_dir(d), RULES_FILE)


# ------------------------------------------------------------------------------------ captured flows
class FlowStore:
    """The live traffic the proxy has seen, read from the addon's append-only flows file (bounded tail)."""

    def __init__(self, flows=None):
        self.flows = flows or []

    @classmethod
    def load(cls, d=None, limit=500):
        s = cls()
        try:
            with open(_flows_path(d), "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-int(limit):]
        except FileNotFoundError:
            return s
        except Exception:
            return s
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                s.flows.append(json.loads(ln))
            except Exception:
                pass
        return s

    def to_dict(self):
        by_host, by_status, rule_hits = {}, {}, {}
        for e in self.flows:
            by_host[e.get("host", "")] = by_host.get(e.get("host", ""), 0) + 1
            b = "%dxx" % (int(e.get("status") or 0) // 100)
            by_status[b] = by_status.get(b, 0) + 1
            r = e.get("matched_rule") or ""
            if r:
                rule_hits[r] = rule_hits.get(r, 0) + 1
        return {"count": len(self.flows), "by_host": by_host, "by_status": by_status,
                "rule_hits": rule_hits, "flows": self.flows}

    def har(self):
        """Export captured proxy traffic as a HAR 1.2 document -- same shape capture.py emits (one HAR
        format everywhere), so it opens in Burp/Chrome/any HTTP tool. Headers are already redacted."""
        entries = []
        for e in self.flows:
            entries.append({
                "startedDateTime": _cap._iso(e.get("ts", time.time())), "time": e.get("ms", 0), "cache": {},
                "request": {"method": e.get("method", "GET"), "url": e.get("url", ""), "httpVersion": "HTTP/1.1",
                            "headers": _cap._hdr_list(e.get("req_headers")), "cookies": [],
                            "queryString": [], "headersSize": -1, "bodySize": -1},
                "response": {"status": e.get("status", 0), "statusText": "", "httpVersion": "HTTP/1.1",
                             "headers": _cap._hdr_list(e.get("resp_headers")), "cookies": [],
                             "content": {"size": e.get("resp_len", 0), "mimeType": e.get("resp_ct", "")},
                             "redirectURL": "", "headersSize": -1, "bodySize": e.get("resp_len", 0)},
                "timings": {"send": 0, "wait": e.get("ms", 0), "receive": 0},
            })
        return {"log": {"version": "1.2", "creator": {"name": "apolaki-proxy", "version": "1"}, "entries": entries}}


def status(d=None, url=None):
    """Is the intercept proxy configured/active, and what has it captured? Never raises."""
    purl = proxy_url(url)
    path = _flows_path(d)
    exists = os.path.exists(path)
    count, last_age = 0, None
    if exists:
        try:
            st = os.stat(path)
            last_age = round(max(0.0, time.time() - st.st_mtime), 1)
            fs = FlowStore.load(d)
            count = len(fs.flows)
        except Exception:
            pass
    return {"configured": bool(purl), "proxy_url": purl or None, "flows_file": path,
            "active": bool(purl) and exists, "flows_captured": count, "last_flow_age_s": last_age,
            "note": "" if purl else "no intercept proxy configured (docker compose --profile proxy up -d mitmproxy)"}


# ------------------------------------------------------------------------------------ match-and-replace rules
_STR_MATCH = ("host", "path_contains", "method")


class RuleSet:
    """Deterministic match-and-replace rules the mitm addon applies in flight. A rule matches on
    host/path/method and may set request headers, find/replace request or response bodies, force a
    response status, or block. Reproducible interception -- the pentest equivalent of Burp match-and-replace."""

    def __init__(self, rules=None):
        self.rules = list(rules or [])

    @classmethod
    def load(cls, d=None):
        try:
            with open(_rules_path(d), "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return cls([])
        return cls(data.get("rules", []) if isinstance(data, dict) else (data or []))

    def validate(self):
        """Return a normalized, safe rule list; raise ValueError on a malformed rule (fail loud to the API,
        never write junk the addon would choke on)."""
        out = []
        for i, r in enumerate(self.rules):
            if not isinstance(r, dict):
                raise ValueError("rule %d is not an object" % i)
            m = r.get("match") or {}
            if not isinstance(m, dict):
                raise ValueError("rule %d 'match' must be an object" % i)
            for k in _STR_MATCH:
                if k in m and not isinstance(m[k], str):
                    raise ValueError("rule %d match.%s must be a string" % (i, k))
            if not any(m.get(k) for k in _STR_MATCH):
                raise ValueError("rule %d must match on at least one of host/path_contains/method" % i)
            norm = {"id": str(r.get("id") or ("rule_%d" % i)), "match": {k: m[k] for k in _STR_MATCH if m.get(k)}}
            for key in ("set_request_headers",):
                if r.get(key):
                    if not isinstance(r[key], dict):
                        raise ValueError("rule %d %s must be an object" % (i, key))
                    norm[key] = {str(k): str(v) for k, v in r[key].items()}
            for key in ("replace_request_body", "replace_response_body"):
                if r.get(key):
                    pairs = []
                    for p in r[key]:
                        if not isinstance(p, dict) or "find" not in p:
                            raise ValueError("rule %d %s entries need a 'find'" % (i, key))
                        pairs.append({"find": str(p["find"]), "replace": str(p.get("replace", ""))})
                    norm[key] = pairs
            if r.get("set_response_status"):
                norm["set_response_status"] = int(r["set_response_status"])
            if r.get("block"):
                norm["block"] = True
                norm["block_status"] = int(r.get("block_status", 403))
            out.append(norm)
        return out

    def save(self, d=None):
        """Atomically write the validated rules to the shared file the addon watches (mtime-triggered reload)."""
        rules = self.validate()
        os.makedirs(flows_dir(d), exist_ok=True)
        path = _rules_path(d)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"rules": rules, "updated": time.time()}, f)
        os.replace(tmp, path)
        return rules

    @staticmethod
    def matches(rule, method, host, path):
        m = rule.get("match", {})
        if m.get("method") and m["method"].upper() != str(method).upper():
            return False
        if m.get("host") and m["host"].lower() not in str(host).lower():
            return False
        if m.get("path_contains") and m["path_contains"] not in str(path):
            return False
        return bool(m)


# ------------------------------------------------------------------------------------ replay (resend, optionally mutated)
def replay(flow, mutations=None, send=False, timeout=20, verify=False):
    """Build a modified request from a captured flow (Burp Repeater-style) and optionally re-issue it.
    `mutations` may set method/url and add/override headers or a body. Deterministic; when send=False (or
    httpx is unavailable) it returns just the request spec so the caller can inspect or route it. Bounded,
    single request -- never a loop, so it can't become a DoS."""
    mutations = mutations or {}
    spec = {
        "method": str(mutations.get("method") or (flow or {}).get("method") or "GET").upper(),
        "url": mutations.get("url") or (flow or {}).get("url") or "",
        "headers": dict((flow or {}).get("req_headers") or {}),
        "body": mutations.get("body"),
    }
    for k, v in (mutations.get("headers") or {}).items():
        spec["headers"][str(k)] = str(v)
    # drop redaction placeholders so a replay doesn't send the literal string "<redacted>"
    spec["headers"] = {k: v for k, v in spec["headers"].items() if v != "<redacted>"}
    if not spec["url"]:
        return {"sent": False, "note": "no url to replay", "request": spec}
    if not send:
        return {"sent": False, "request": spec}
    try:
        import httpx
    except Exception:
        return {"sent": False, "note": "httpx unavailable", "request": spec}
    try:
        import browser_engine as _browser_engine
        _browser_engine.target_rate_policy.wait_sync(spec["url"])
        t0 = time.time()
        r = httpx.request(spec["method"], spec["url"], headers=spec["headers"],
                          content=spec["body"], timeout=timeout, verify=verify, follow_redirects=False)
        _browser_engine.target_rate_policy.observe(str(r.url) or spec["url"],
                                                   r.status_code, r.headers)
        return {"sent": True, "request": spec,
                "response": {"status": r.status_code, "len": len(r.content),
                             "content_type": r.headers.get("content-type", ""),
                             "ms": round((time.time() - t0) * 1000, 1),
                             "server": r.headers.get("server", "")}}
    except Exception as e:
        return {"sent": False, "note": "replay send failed: %s" % str(e)[:120], "request": spec}


# ------------------------------------------------------------------------------------ proxy -> planner sensor
def to_observations(flowstore=None, d=None):
    """Map captured proxy traffic onto the deterministic planner vocabulary, so everything the intercept
    proxy sees (especially browser-only traffic HTTP recon misses) feeds the SAME technique planner + attack
    graph as HTTP recon -- one shared observation model, the proxy is not an island. Pure."""
    fs = flowstore if flowstore is not None else FlowStore.load(d)
    out = set()
    if not fs.flows:
        return out
    paths = " ".join((f.get("path") or "").lower() + " " + (f.get("url") or "").lower() for f in fs.flows)
    cts = " ".join((f.get("resp_ct") or "").lower() for f in fs.flows)
    if "javascript" in cts or ".js" in paths:
        out.add("serves_js")
    if any(t in paths for t in ("/api/", "/rest/", "/v1/", "/v2/", "graphql")):
        out.add("has_api")
    if any(t in paths for t in ("login", "signin", "/session", "/auth", "/oauth")):
        out.add("has_login")
    if any(t in paths for t in ("search", "q=", "query=")):
        out.add("has_search_param")
    if any(t in paths for t in ("redirect", "returnurl", "return_to", "next=", "url=", "to=")):
        out.add("has_redirect_param")
    if any(t in paths for t in ("id=", "/id/", "userid", "orderid", "productid", "/basket/")):
        out.add("has_object_id")
    if any(t in paths for t in ("upload", "file=")):
        out.add("has_file_upload")
    return out


# ------------------------------------------------------------------------------------ browser launch args
def browser_launch_args(url=None):
    """Chrome launch args that route the headless browser through the intercept proxy (empty when no proxy
    is configured, so the browser engine just launches normally). --ignore-certificate-errors trusts the
    mitm CA without an import step -- acceptable for a controlled recon browser against lab/scan targets."""
    purl = proxy_url(url)
    if not purl:
        return []
    return ["--proxy-server=%s" % purl, "--ignore-certificate-errors"]
