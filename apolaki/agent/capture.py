"""
Traffic capture -- a unified, deterministic ledger of the request/response pairs the platform makes,
the Burp/ZAP-style core Apolaki was missing. Every engine (HTTP + browser) records here, so one place
holds the whole engagement's traffic: viewable, exportable as HAR 1.2, and replayable. Bounded ring
buffer per engagement; secret headers redacted at rest. Pure + dependency-light, no LLM.
"""
from __future__ import annotations

import datetime
import time

_MAX = 800
_SECRET_HDRS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "token", "proxy-authorization"}


def _redact(h):
    if not h:
        return {}
    try:
        return {k: ("<redacted>" if str(k).lower() in _SECRET_HDRS else v) for k, v in dict(h).items()}
    except Exception:
        return {}


def _hdr_list(h):
    return [{"name": str(k), "value": str(v)} for k, v in (h or {}).items()]


def _iso(t):
    return datetime.datetime.utcfromtimestamp(t).replace(microsecond=0).isoformat() + "Z"


class CaptureStore:
    """Bounded ring of request/response summaries. add() is called from every execution engine."""

    def __init__(self, cap=_MAX):
        self.cap = cap
        self.entries = []

    def add(self, method, url, status, req_headers=None, resp_headers=None, resp_len=0, ms=0.0,
            engine="http", resp_ct=""):
        self.entries.append({"t": time.time(), "engine": engine, "method": str(method).upper(),
                             "url": url, "status": status, "req_headers": _redact(req_headers),
                             "resp_headers": _redact(resp_headers), "resp_ct": resp_ct,
                             "resp_len": int(resp_len or 0), "ms": round(float(ms or 0), 1)})
        if len(self.entries) > self.cap:
            self.entries = self.entries[-self.cap:]

    def to_dict(self):
        by_engine, by_status = {}, {}
        for e in self.entries:
            by_engine[e["engine"]] = by_engine.get(e["engine"], 0) + 1
            b = "%dxx" % (int(e["status"] or 0) // 100)
            by_status[b] = by_status.get(b, 0) + 1
        return {"count": len(self.entries), "by_engine": by_engine, "by_status": by_status,
                "entries": self.entries}

    def har(self, program="apolaki"):
        """Export the ledger as a HAR 1.2 document (standard, opens in any HTTP tool)."""
        return {"log": {"version": "1.2", "creator": {"name": "apolaki", "version": "1"},
                "entries": [{
                    "startedDateTime": _iso(e["t"]), "time": e.get("ms", 0), "cache": {},
                    "request": {"method": e["method"], "url": e["url"], "httpVersion": "HTTP/1.1",
                                "headers": _hdr_list(e.get("req_headers")), "cookies": [],
                                "queryString": [], "headersSize": -1, "bodySize": -1},
                    "response": {"status": e["status"], "statusText": "", "httpVersion": "HTTP/1.1",
                                 "headers": _hdr_list(e.get("resp_headers")), "cookies": [],
                                 "content": {"size": e.get("resp_len", 0), "mimeType": e.get("resp_ct", "")},
                                 "redirectURL": "", "headersSize": -1, "bodySize": e.get("resp_len", 0)},
                    "timings": {"send": 0, "wait": e.get("ms", 0), "receive": 0},
                } for e in self.entries]}}


def from_dict(d):
    """Rehydrate a CaptureStore from a persisted to_dict() (for post-scan HAR export/replay)."""
    s = CaptureStore()
    s.entries = list((d or {}).get("entries", []))
    return s
