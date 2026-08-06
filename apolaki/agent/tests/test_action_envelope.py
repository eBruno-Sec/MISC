"""Durable action envelope (Codex Tier-3 #11): stable idempotency key, approval bound to input+scope,
intrusive-without-approval rejected, no raw secrets in the envelope, failed/cancelled stay visible."""
import json

import action_envelope as E


def test_same_action_input_scope_gives_same_idempotency_key():
    a = E.make_envelope("m1", "run_xss", {"url": "http://app/x", "param": "q"}, {"hosts": ["app"]})
    b = E.make_envelope("m1", "run_xss", {"url": "http://app/x", "param": "q"}, {"hosts": ["app"]})
    assert a["idempotency_key"] == b["idempotency_key"]
    assert a["action_id"] != b["action_id"]              # distinct action ids, same idempotency key


def test_changed_scope_invalidates_prior_approval():
    env = E.make_envelope("m1", "run_sqli", {"url": "http://app/x"}, {"hosts": ["app"]},
                          permission="INTRUSIVE")
    env = E.authorize(env, approval_id="appr-1")["envelope"]
    ok = E.validate_before_execute(env, {"hosts": ["app"]}, {"url": "http://app/x"})
    assert ok["allowed"] is True
    changed = E.validate_before_execute(env, {"hosts": ["OTHER"]}, {"url": "http://app/x"})
    assert changed["allowed"] is False and "scope changed" in changed["reason"]
    changed_in = E.validate_before_execute(env, {"hosts": ["app"]}, {"url": "http://app/CHANGED"})
    assert changed_in["allowed"] is False and "input changed" in changed_in["reason"]


def test_intrusive_action_without_approval_is_rejected():
    env = E.make_envelope("m1", "run_cmdi", {"url": "http://app/x"}, {"hosts": ["app"]},
                          permission="INTRUSIVE")
    assert env["requires_approval"] is True
    dec = E.authorize(env)
    assert dec["allowed"] is False and dec["envelope"]["status"] == "rejected"
    vb = E.validate_before_execute(env, {"hosts": ["app"]}, {"url": "http://app/x"})
    assert vb["allowed"] is False


def test_passive_active_do_not_require_approval_by_default():
    env = E.make_envelope("m1", "run_fingerprint", {"url": "http://app"}, {"hosts": ["app"]},
                          permission="ACTIVE")
    assert env["requires_approval"] is False
    assert E.validate_before_execute(env, {"hosts": ["app"]}, {"url": "http://app"})["allowed"] is True


def test_raw_secrets_never_enter_the_envelope():
    inputs = {"url": "http://app/x", "headers": {"Authorization": "Bearer SECRET-TOKEN-123",
                                                 "Cookie": "session=abcdef-secret"}}
    env = E.make_envelope("m1", "run_xss", inputs, {"hosts": ["app"]})
    blob = json.dumps(env)
    assert "SECRET-TOKEN-123" not in blob and "abcdef-secret" not in blob
    # secret-stripping is stable: rotating the token does not change the idempotency key
    inputs2 = {"url": "http://app/x", "headers": {"Authorization": "Bearer DIFFERENT-TOKEN",
                                                  "Cookie": "session=zzz"}}
    env2 = E.make_envelope("m1", "run_xss", inputs2, {"hosts": ["app"]})
    assert env["idempotency_key"] == env2["idempotency_key"]


def test_failed_and_cancelled_remain_visible():
    env = E.make_envelope("m1", "run_xss", {"url": "http://app"}, {"hosts": ["app"]})
    assert E.mark(env, "failed")["status"] == "failed"
    assert E.mark(env, "cancelled")["status"] == "cancelled"
    assert "updated_at" in E.mark(env, "executed")
