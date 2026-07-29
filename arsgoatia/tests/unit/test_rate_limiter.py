"""Unit tests for the rate limiter and budget ledger."""
from __future__ import annotations

import time
from uuid import uuid4

import pytest

from packages.rate_limiter import (
    BudgetDenialReason,
    BudgetLedger,
    BudgetSpec,
    ConsumptionRecord,
    TokenBucket,
)


class TestTokenBucket:
    def test_initial_full(self):
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.available >= 9.9

    def test_consume_succeeds_within_capacity(self):
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.consume(5) is True
        assert bucket.available < 6.0

    def test_consume_fails_when_empty(self):
        bucket = TokenBucket(capacity=5, refill_rate=0.0)
        bucket.consume(5)
        assert bucket.consume(1) is False

    def test_consume_all_then_deny(self):
        bucket = TokenBucket(capacity=3, refill_rate=0.0)
        assert bucket.consume(3) is True
        assert bucket.consume(1) is False

    def test_drain_zeroes_tokens(self):
        bucket = TokenBucket(capacity=10, refill_rate=0.0)
        bucket.drain()
        assert bucket.consume(1) is False

    def test_capacity_capped(self):
        bucket = TokenBucket(capacity=5, refill_rate=100.0)
        time.sleep(0.01)
        assert bucket.available <= 5.0


class TestBudgetSpec:
    def test_defaults(self):
        spec = BudgetSpec()
        assert spec.max_requests == 50_000
        assert spec.max_cost_usd == 25.0
        assert spec.max_concurrent == 10
        assert spec.requests_per_second == 10.0

    def test_custom(self):
        spec = BudgetSpec(max_requests=100, max_cost_usd=1.0, max_concurrent=2)
        assert spec.max_requests == 100


class TestBudgetLedger:
    def _ledger_with_engagement(self, requests=1000, cost=10.0, concurrent=5):
        ledger = BudgetLedger()
        tid = uuid4()
        eid = uuid4()
        spec = BudgetSpec(
            max_requests=requests,
            max_cost_usd=cost,
            max_concurrent=concurrent,
            requests_per_second=1000.0,
            burst_capacity=requests,
        )
        ledger.register(tid, eid, spec)
        return ledger, tid, eid

    def test_check_allowed(self):
        ledger, tid, eid = self._ledger_with_engagement()
        result = ledger.check(tid, eid, requests_needed=10, cost_usd=0.01)
        assert result.allowed is True
        assert result.denial_reason is None

    def test_check_unregistered_uses_defaults(self):
        ledger = BudgetLedger()
        tid = uuid4()
        eid = uuid4()
        result = ledger.check(tid, eid, requests_needed=1, cost_usd=0.0)
        assert result.allowed is True

    def test_requests_exceeded(self):
        ledger, tid, eid = self._ledger_with_engagement(requests=10)
        ledger.consume(tid, eid, uuid4(), requests_consumed=10, cost_usd=0.0)
        result = ledger.check(tid, eid, requests_needed=1, cost_usd=0.0)
        assert result.allowed is False
        assert result.denial_reason == BudgetDenialReason.REQUESTS_EXCEEDED

    def test_cost_exceeded(self):
        ledger, tid, eid = self._ledger_with_engagement(cost=1.0)
        ledger.consume(tid, eid, uuid4(), requests_consumed=1, cost_usd=1.0)
        result = ledger.check(tid, eid, requests_needed=1, cost_usd=0.01)
        assert result.allowed is False
        assert result.denial_reason == BudgetDenialReason.COST_EXCEEDED

    def test_concurrency_exceeded(self):
        ledger, tid, eid = self._ledger_with_engagement(concurrent=2)
        ledger.consume(tid, eid, uuid4(), requests_consumed=1)
        ledger.consume(tid, eid, uuid4(), requests_consumed=1)
        result = ledger.check(tid, eid, requests_needed=1)
        assert result.allowed is False
        assert result.denial_reason == BudgetDenialReason.CONCURRENCY_EXCEEDED

    def test_release_decrements_active(self):
        ledger, tid, eid = self._ledger_with_engagement(concurrent=1)
        ledger.consume(tid, eid, uuid4(), requests_consumed=1)
        assert ledger.active_count(tid, eid) == 1
        ledger.release(tid, eid)
        assert ledger.active_count(tid, eid) == 0
        result = ledger.check(tid, eid, requests_needed=1)
        assert result.allowed is True

    def test_consume_records_usage(self):
        ledger, tid, eid = self._ledger_with_engagement()
        aid = uuid4()
        ledger.consume(tid, eid, aid, requests_consumed=5, cost_usd=0.05)
        assert ledger.consumed_requests(tid, eid) == 5
        assert abs(ledger.consumed_cost_usd(tid, eid) - 0.05) < 1e-9

    def test_consume_returns_record(self):
        ledger, tid, eid = self._ledger_with_engagement()
        aid = uuid4()
        record = ledger.consume(tid, eid, aid, requests_consumed=10, cost_usd=0.1)
        assert isinstance(record, ConsumptionRecord)
        assert record.requests_consumed == 10
        assert record.action_id == aid

    def test_records_for_engagement(self):
        ledger, tid, eid = self._ledger_with_engagement()
        ledger.consume(tid, eid, uuid4(), 1, 0.01)
        ledger.consume(tid, eid, uuid4(), 2, 0.02)
        other_tid = uuid4()
        other_eid = uuid4()
        ledger.consume(other_tid, other_eid, uuid4(), 5, 0.05)
        records = ledger.records_for_engagement(tid, eid)
        assert len(records) == 2

    def test_emergency_stop_denies_all(self):
        ledger, tid, eid = self._ledger_with_engagement()
        ledger.emergency_stop(tid, eid)
        result = ledger.check(tid, eid, requests_needed=1)
        assert result.allowed is False
        assert result.denial_reason == BudgetDenialReason.EMERGENCY_STOP

    def test_emergency_stop_is_irreversible(self):
        ledger, tid, eid = self._ledger_with_engagement()
        ledger.emergency_stop(tid, eid)
        assert ledger.is_emergency_stopped(tid, eid) is True

    def test_emergency_stop_does_not_affect_other_engagements(self):
        ledger, tid, eid_a = self._ledger_with_engagement()
        eid_b = uuid4()
        spec = BudgetSpec(requests_per_second=1000.0, burst_capacity=1000)
        ledger.register(tid, eid_b, spec)
        ledger.emergency_stop(tid, eid_a)
        result = ledger.check(tid, eid_b, requests_needed=1)
        assert result.allowed is True

    def test_snapshot(self):
        ledger, tid, eid = self._ledger_with_engagement(requests=100, cost=5.0)
        ledger.consume(tid, eid, uuid4(), 10, 0.5)
        snap = ledger.snapshot(tid, eid)
        assert snap["max_requests"] == 100
        assert snap["consumed_requests"] == 10
        assert snap["remaining_requests"] == 90
        assert abs(snap["consumed_cost_usd"] - 0.5) < 1e-9
        assert snap["emergency_stopped"] is False

    def test_remaining_requests_in_check(self):
        ledger, tid, eid = self._ledger_with_engagement(requests=100)
        ledger.consume(tid, eid, uuid4(), 30)
        result = ledger.check(tid, eid, requests_needed=10)
        assert result.allowed is True
        assert result.remaining_requests == 60  # 100 - 30 - 10

    def test_multiple_consumes_accumulate(self):
        ledger, tid, eid = self._ledger_with_engagement(requests=1000)
        for _ in range(5):
            ledger.consume(tid, eid, uuid4(), 10, 0.0)
        assert ledger.consumed_requests(tid, eid) == 50
        assert ledger.active_count(tid, eid) == 5

    def test_release_below_zero_clamps(self):
        ledger, tid, eid = self._ledger_with_engagement()
        ledger.release(tid, eid)
        assert ledger.active_count(tid, eid) == 0

    def test_consumed_requests_unregistered(self):
        ledger = BudgetLedger()
        assert ledger.consumed_requests(uuid4(), uuid4()) == 0

    def test_consumed_cost_unregistered(self):
        ledger = BudgetLedger()
        assert ledger.consumed_cost_usd(uuid4(), uuid4()) == 0.0
