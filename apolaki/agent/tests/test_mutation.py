"""Tests for the payload mutation engine (deterministic families + mutations + bounded retry)."""
from __future__ import annotations

import mutation


def test_variants_dedupe_and_encode():
    v = mutation.variants("sqli", limit=30)
    assert "' OR 1=1--" in v                              # a base family payload
    assert any("%27" in x for x in v)                    # a url-encoded variant is generated
    assert len(v) == len(set(v))                          # deduped


def test_base_payload_leads():
    v = mutation.variants("xss", base="CUSTOM<x>", limit=10)
    assert v[0] == "CUSTOM<x>"                            # the caller's base comes first


def test_unknown_class_with_base_still_mutates():
    v = mutation.variants("weird", base="p ayload")
    assert "p/**/ayload" in v                             # whitespace -> comment mutation applied


def test_retry_policy_is_bounded():
    r = mutation.retry_policy("sqli")
    assert r["max_attempts"] == 6 and r["stop_on_confirm"] is True and len(r["backoff_ms"]) == 6
