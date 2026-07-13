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


# ── cross-role access control ────────────────────────────────────
def test_access_verdict_flags_bola():
    results = [
        {"role": "user-a", "status": 200, "length": 1500, "is_owner": True, "is_anon": False},
        {"role": "user-b", "status": 200, "length": 1490, "is_owner": False, "is_anon": False},
        {"role": "anon", "status": 401, "length": 20, "is_owner": False, "is_anon": True},
    ]
    v = replay.access_verdict(results)
    assert v["anomaly"] is True
    assert "user-b" in v["flags"]
    assert "anon" not in v["flags"]          # 401 => access control working for anon
    assert any("BROKEN_ACCESS_CONTROL" in r.get("flag", "") for r in results if r["role"] == "user-b")


def test_access_verdict_clean_when_others_denied():
    results = [
        {"role": "user-a", "status": 200, "length": 1500, "is_owner": True, "is_anon": False},
        {"role": "user-b", "status": 403, "length": 15, "is_owner": False, "is_anon": False},
        {"role": "anon", "status": 302, "length": 0, "is_owner": False, "is_anon": True},
    ]
    v = replay.access_verdict(results)
    assert v["anomaly"] is False
    assert v["flags"] == []


def test_access_verdict_unauthenticated_access_without_owner():
    results = [
        {"role": "anon", "status": 200, "length": 3000, "is_owner": False, "is_anon": True},
    ]
    v = replay.access_verdict(results)
    assert v["anomaly"] is True
    assert "anon" in v["flags"]
    assert "UNAUTHENTICATED_ACCESS" in results[0]["flag"]


def test_access_verdict_length_mismatch_not_flagged():
    # user-b gets 200 but a tiny error page, not the owner's object -> no flag
    results = [
        {"role": "user-a", "status": 200, "length": 1500, "is_owner": True, "is_anon": False},
        {"role": "user-b", "status": 200, "length": 80, "is_owner": False, "is_anon": False},
    ]
    v = replay.access_verdict(results)
    assert v["anomaly"] is False
