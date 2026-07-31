"""Tests for the traffic-capture ledger (bounded ring, secret redaction, HAR 1.2 export)."""
from __future__ import annotations

import capture


def test_ring_is_bounded_and_redacts_secrets():
    s = capture.CaptureStore(cap=3)
    for i in range(5):
        s.add("GET", "http://t/%d" % i, 200)
    assert s.to_dict()["count"] == 3                       # ring bounded to cap
    s2 = capture.CaptureStore()
    s2.add("POST", "http://t/x", 201, req_headers={"Cookie": "token=abc", "Accept": "*/*"})
    assert s2.entries[0]["req_headers"]["Cookie"] == "<redacted>"      # secret header masked
    assert s2.entries[0]["req_headers"]["Accept"] == "*/*"            # non-secret kept


def test_to_dict_rollups():
    s = capture.CaptureStore()
    s.add("GET", "http://t/a", 200, engine="http")
    s.add("GET", "http://t/b", 404, engine="browser")
    d = s.to_dict()
    assert d["by_engine"] == {"http": 1, "browser": 1}
    assert d["by_status"]["2xx"] == 1 and d["by_status"]["4xx"] == 1


def test_har_export_shape():
    s = capture.CaptureStore()
    s.add("GET", "http://t/a", 200, resp_headers={"Content-Type": "application/json"}, resp_len=42, ms=7)
    har = s.har()
    assert har["log"]["version"] == "1.2"
    e = har["log"]["entries"][0]
    assert e["request"]["method"] == "GET" and e["response"]["status"] == 200
    assert e["response"]["content"]["size"] == 42


def test_from_dict_roundtrip():
    s = capture.CaptureStore()
    s.add("GET", "http://t", 200)
    assert capture.from_dict(s.to_dict()).har()["log"]["entries"][0]["request"]["url"] == "http://t"
