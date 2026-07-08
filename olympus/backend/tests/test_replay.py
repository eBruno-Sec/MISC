"""Unit tests for the request-workbench engine (core/replay.py).

Pure functions only (mutate / scoring / diff); the network send() is exercised
via the live API. Run from the backend dir:  python -m pytest tests/ -q
"""
from core import replay


def test_mutate_query_replaces_only_target_param():
    url = "https://t.example/catalog?category=1&sort=asc"
    u, b, extra = replay.mutate(url, None, "category", "query", "PAYLOAD")
    assert "category=PAYLOAD" in u
    assert "sort=asc" in u              # other params preserved
    assert extra == {}


def test_mutate_body_form_encoded():
    u, b, extra = replay.mutate("https://t.example/login", "user=admin&pass=x",
                                "pass", "body", "' OR 1=1--")
    assert "user=admin" in b
    assert "pass=" in b and "1%3D1" in b  # payload url-encoded into the body
    assert extra == {}


def test_mutate_header():
    u, b, extra = replay.mutate("https://t.example/", None, "X-Forwarded-For",
                                "header", "127.0.0.1")
    assert extra == {"X-Forwarded-For": "127.0.0.1"}
    assert u == "https://t.example/"


def test_score_status_change_and_error_signature():
    baseline = {"status": 200, "length": 100, "duration_ms": 50}
    hit = {"status": 500, "length": 250, "duration_ms": 60,
           "reflected": False, "error_signatures": ["sql syntax"]}
    # +3 status change, +1 length, +4 error signature = 8
    assert replay.score_result(baseline, hit) == 8


def test_score_time_based_and_reflection():
    baseline = {"status": 200, "length": 100, "duration_ms": 40}
    hit = {"status": 200, "length": 100, "duration_ms": 5200,
           "reflected": True, "error_signatures": []}
    # +2 reflected, +3 time-based (>4000ms over baseline) = 5
    assert replay.score_result(baseline, hit) == 5


def test_score_boring_is_zero():
    baseline = {"status": 200, "length": 100, "duration_ms": 40}
    hit = {"status": 200, "length": 110, "duration_ms": 45,
           "reflected": False, "error_signatures": []}
    assert replay.score_result(baseline, hit) == 0   # <40 length delta, nothing else


def test_diff_responses_reports_deltas():
    a = {"status": 200, "length": 100, "duration_ms": 10,
         "headers": {"X-A": "1", "Server": "nginx"}, "body": "hello\nworld"}
    b = {"status": 302, "length": 40, "duration_ms": 12,
         "headers": {"Server": "nginx", "Location": "/evil"}, "body": "hello\nthere"}
    d = replay.diff_responses(a, b)
    assert d["status"]["changed"] is True
    assert d["length"]["delta"] == -60
    assert "location" in d["headers"]["added"]
    assert "x-a" in d["headers"]["removed"]
    assert "world" in d["body_diff"] and "there" in d["body_diff"]


def test_header_diff_case_insensitive_change():
    d = replay._header_diff({"Content-Type": "text/html"}, {"content-type": "application/json"})
    assert "content-type" in d["changed"]
