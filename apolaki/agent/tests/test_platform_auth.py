"""Platform auth gate: local-only-open by default, token-enforced when APOLAKI_API_TOKEN is set,
with an allowlist for health/docs/UI. Constant-time compare. Pure."""
from __future__ import annotations

import platform_auth as PA


def test_open_by_default(monkeypatch):
    monkeypatch.delenv("APOLAKI_API_TOKEN", raising=False)
    assert PA.required() is False
    assert PA.check("anything") is True            # no token configured -> always allow
    assert PA.authorize("/engage", {}) is True


def test_token_enforced_when_set(monkeypatch):
    monkeypatch.setenv("APOLAKI_API_TOKEN", "s3cret")
    assert PA.required() is True
    assert PA.check("s3cret") is True
    assert PA.check("wrong") is False
    assert PA.check("") is False


def test_exempt_paths_stay_open(monkeypatch):
    monkeypatch.setenv("APOLAKI_API_TOKEN", "s3cret")
    for p in ("/health", "/", "/openapi.json", "/ui/index.html", "/static/app.js"):
        assert PA.authorize(p, {}) is True
    assert PA.authorize("/engage", {}) is False                          # gated, no token
    assert PA.authorize("/engage", {"x-apolaki-token": "s3cret"}) is True
    assert PA.authorize("/engage", {"authorization": "Bearer s3cret"}) is True


def test_wrong_token_denied(monkeypatch):
    monkeypatch.setenv("APOLAKI_API_TOKEN", "s3cret")
    assert PA.authorize("/graph/abc", {"x-apolaki-token": "nope"}) is False


def test_query_token_accepted_for_sse(monkeypatch):
    # EventSource can't set headers, so a `token` query param is accepted for streaming endpoints.
    monkeypatch.setenv("APOLAKI_API_TOKEN", "s3cret")
    assert PA.authorize("/stream/abc", {}, query_token="s3cret") is True
    assert PA.authorize("/stream/abc", {}, query_token="nope") is False
    assert PA.authorize("/stream/abc", {}) is False
