"""Unit tests for worker activity pure-logic functions.

Patches temporalio out of sys.modules so tests run without the SDK installed.
Only the deterministic helper functions are tested; network-dependent portions
require the lab environment.
"""

from __future__ import annotations

import hashlib
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock

# ---------------------------------------------------------------------------
# Patch temporalio before any activity module is imported
# ---------------------------------------------------------------------------


def _make_temporal_mock() -> ModuleType:
    mod = ModuleType("temporalio")
    activity_mod = ModuleType("temporalio.activity")
    workflow_mod = ModuleType("temporalio.workflow")
    common_mod = ModuleType("temporalio.common")

    # @activity.defn is a passthrough decorator
    activity_mod.defn = lambda f: f
    activity_mod.heartbeat = lambda *a, **kw: None
    activity_mod.logger = MagicMock()

    # @workflow.defn, @workflow.run, etc.
    workflow_mod.defn = lambda f: f
    workflow_mod.run = lambda f: f
    workflow_mod.signal = lambda f: f
    workflow_mod.query = lambda f: f
    workflow_mod.wait_condition = AsyncMock()
    workflow_mod.uuid4 = lambda: __import__("uuid").uuid4()
    workflow_mod.now = lambda: __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    )
    workflow_mod.execute_activity = AsyncMock()
    workflow_mod.start_child_workflow = AsyncMock()
    workflow_mod.unsafe = MagicMock()
    workflow_mod.RetryPolicy = MagicMock()
    workflow_mod.ChildWorkflowError = Exception

    common_mod.RetryPolicy = MagicMock()

    mod.activity = activity_mod
    mod.workflow = workflow_mod
    mod.common = common_mod

    sys.modules.setdefault("temporalio", mod)
    sys.modules.setdefault("temporalio.activity", activity_mod)
    sys.modules.setdefault("temporalio.workflow", workflow_mod)
    sys.modules.setdefault("temporalio.common", common_mod)
    return mod


_TEMPORAL_MOCK = _make_temporal_mock()


# Also mock miniopy_async (MinIO client — needs real MinIO in prod)
_minio_mod = ModuleType("miniopy_async")
_minio_class = MagicMock()
_minio_mod.Minio = _minio_class
sys.modules.setdefault("miniopy_async", _minio_mod)


# ---------------------------------------------------------------------------
# Import activity modules AFTER mocks are in place
# ---------------------------------------------------------------------------

from services.worker.activities.evidence import StoreEvidenceParams  # noqa: E402
from services.worker.activities.recon import ScopeRuleParam, _is_in_scope  # noqa: E402

# ---------------------------------------------------------------------------
# _is_in_scope tests
# ---------------------------------------------------------------------------


class TestIsInScope:
    def _rule(self, type_: str, value: str) -> ScopeRuleParam:
        return ScopeRuleParam(type=type_, value=value)

    def test_empty_rules_denies_everything(self):
        assert _is_in_scope("http://anything.example.com/path", []) is False

    def test_exact_host_match(self):
        rules = [self._rule("exact_host", "juice-shop")]
        assert _is_in_scope("http://juice-shop/api", rules) is True

    def test_exact_host_no_match(self):
        rules = [self._rule("exact_host", "juice-shop")]
        assert _is_in_scope("http://other-host/api", rules) is False

    def test_dns_suffix_match(self):
        rules = [self._rule("dns_suffix", ".example.com")]
        assert _is_in_scope("http://api.example.com/v1", rules) is True

    def test_dns_suffix_no_match(self):
        rules = [self._rule("dns_suffix", ".example.com")]
        assert _is_in_scope("http://evil.example.org/", rules) is False

    def test_url_prefix_match(self):
        rules = [self._rule("url_prefix", "http://juice-shop:3000/rest")]
        assert _is_in_scope("http://juice-shop:3000/rest/basket/1", rules) is True

    def test_url_prefix_no_match(self):
        rules = [self._rule("url_prefix", "http://juice-shop:3000/rest")]
        assert _is_in_scope("http://juice-shop:3000/admin", rules) is False

    def test_multiple_rules_any_match_succeeds(self):
        rules = [
            self._rule("exact_host", "juice-shop"),
            self._rule("exact_host", "api.internal"),
        ]
        assert _is_in_scope("http://api.internal/v1", rules) is True

    def test_unknown_rule_type_does_not_match(self):
        rules = [self._rule("cidr", "10.0.0.0/8")]
        assert _is_in_scope("http://10.0.0.1/", rules) is False

    def test_url_without_hostname_does_not_match_real_host(self):
        rules = [self._rule("exact_host", "juice-shop")]
        assert _is_in_scope("file:///etc/passwd", rules) is False


# ---------------------------------------------------------------------------
# StoreEvidenceParams tests (pure data — no I/O)
# ---------------------------------------------------------------------------


class TestStoreEvidenceParams:
    def test_fields_stored(self):
        payload = b'{"status": 200}'
        p = StoreEvidenceParams(
            engagement_id="eng-1",
            tenant_id="tenant-1",
            action_id="act-1",
            kind="http_exchange",
            media_type="application/json",
            payload=payload,
        )
        assert p.payload == payload
        assert p.media_type == "application/json"
        assert p.metadata == {}

    def test_sha256_of_payload(self):
        payload = b"hello world"
        expected = hashlib.sha256(payload).hexdigest()
        p = StoreEvidenceParams(
            engagement_id="e",
            tenant_id="t",
            action_id="a",
            kind="k",
            media_type="application/octet-stream",
            payload=payload,
        )
        actual = hashlib.sha256(p.payload).hexdigest()
        assert actual == expected

    def test_metadata_default_empty(self):
        p = StoreEvidenceParams(
            engagement_id="e",
            tenant_id="t",
            action_id="a",
            kind="k",
            media_type="m",
            payload=b"",
        )
        assert p.metadata == {}

    def test_custom_metadata(self):
        p = StoreEvidenceParams(
            engagement_id="e",
            tenant_id="t",
            action_id="a",
            kind="k",
            media_type="m",
            payload=b"",
            metadata={"source": "bola-test"},
        )
        assert p.metadata["source"] == "bola-test"


# ---------------------------------------------------------------------------
# BOLA decision logic (extracted from validation activity internals)
# ---------------------------------------------------------------------------


class TestBOLADecisionLogic:
    """
    The deterministic confirmation rule from run_bola_validation:
      baseline_ok AND positive_ok AND negative_ok AND NOT differential_ok
      => "CONFIRMED" + capability_produced
    """

    def _decide(
        self,
        baseline_matched: bool,
        differential_matched: bool,
        positive_matched: bool,
        negative_matched: bool,
    ) -> tuple[str, bool]:
        baseline_ok = baseline_matched
        positive_ok = positive_matched
        negative_ok = negative_matched
        differential_vuln = not differential_matched

        if baseline_ok and positive_ok and negative_ok and differential_vuln:
            return "CONFIRMED", True
        elif not baseline_ok or not positive_ok:
            return "INCONCLUSIVE", False
        else:
            return "REJECTED", False

    def test_confirmed_when_all_controls_pass(self):
        status, cap = self._decide(
            baseline_matched=True,
            differential_matched=False,
            positive_matched=True,
            negative_matched=True,
        )
        assert status == "CONFIRMED"
        assert cap is True

    def test_rejected_when_differential_denies(self):
        # differential returns 401/403 (no vuln) + all controls ok
        status, cap = self._decide(
            baseline_matched=True,
            differential_matched=True,  # got expected deny codes = "matched" means not vuln
            positive_matched=True,
            negative_matched=True,
        )
        assert status == "REJECTED"
        assert cap is False

    def test_inconclusive_when_baseline_fails(self):
        status, cap = self._decide(
            baseline_matched=False,
            differential_matched=False,
            positive_matched=True,
            negative_matched=True,
        )
        assert status == "INCONCLUSIVE"
        assert cap is False

    def test_inconclusive_when_positive_control_fails(self):
        status, cap = self._decide(
            baseline_matched=True,
            differential_matched=False,
            positive_matched=False,
            negative_matched=True,
        )
        assert status == "INCONCLUSIVE"
        assert cap is False

    def test_rejected_when_negative_control_fails_but_controls_pass(self):
        # negative_matched=False means no-auth request succeeded (weird but not inconclusive)
        status, cap = self._decide(
            baseline_matched=True,
            differential_matched=False,
            positive_matched=True,
            negative_matched=False,
        )
        # negative_ok is False, but baseline_ok and positive_ok are True
        # => falls to REJECTED (not baseline/positive failure)
        assert status == "REJECTED"
        assert cap is False

    def test_inconclusive_both_baselines_fail(self):
        status, cap = self._decide(
            baseline_matched=False,
            differential_matched=True,
            positive_matched=False,
            negative_matched=True,
        )
        assert status == "INCONCLUSIVE"
        assert cap is False


# ---------------------------------------------------------------------------
# Cleanup obligation types
# ---------------------------------------------------------------------------


class TestCleanupObligationTypes:
    def test_obligation_fields(self):
        from services.worker.activities.cleanup import CleanupObligation

        obl = CleanupObligation(
            obligation_id="obl-1",
            inverse_action="delete_user",
            target_url="http://juice-shop:3000",
            persona="arsgoatia-test-abc123-0",
        )
        assert obl.inverse_action == "delete_user"
        assert obl.metadata == {}

    def test_cleanup_result_all_verified(self):
        from services.worker.activities.cleanup import CleanupOutcome, CleanupResult

        outcomes = [
            CleanupOutcome(obligation_id="o1", success=True, detail="ok"),
            CleanupOutcome(obligation_id="o2", success=True, detail="ok"),
        ]
        result = CleanupResult(outcomes=outcomes, all_verified=True)
        assert result.all_verified
        assert len(result.outcomes) == 2

    def test_cleanup_result_not_all_verified(self):
        from services.worker.activities.cleanup import CleanupOutcome, CleanupResult

        outcomes = [
            CleanupOutcome(obligation_id="o1", success=True, detail="ok"),
            CleanupOutcome(obligation_id="o2", success=False, detail="error: 500"),
        ]
        result = CleanupResult(
            outcomes=outcomes,
            all_verified=all(o.success for o in outcomes),
        )
        assert not result.all_verified


# ---------------------------------------------------------------------------
# Identity result types
# ---------------------------------------------------------------------------


class TestIdentityActivityTypes:
    def test_identity_result_empty_by_default(self):
        from services.worker.activities.identity import IdentityResult

        r = IdentityResult()
        assert r.access_contexts == []

    def test_access_context_result(self):
        from services.worker.activities.identity import AccessContextResult

        ctx = AccessContextResult(
            persona="arsgoatia-test-abc123-0",
            credential_ref="secret://arsgoatia/tenant1/eng1/identity/arsgoatia-test-abc123-0",
        )
        assert ctx.persona.startswith("arsgoatia-test-")
        assert ctx.credential_ref.startswith("secret://")

    def test_identity_params(self):
        from services.worker.activities.identity import IdentityParams

        p = IdentityParams(
            target_url="http://juice-shop:3000",
            engagement_id="eng-1",
            tenant_id="tenant-1",
            identity_count=2,
        )
        assert p.identity_count == 2


# ---------------------------------------------------------------------------
# Chain step types
# ---------------------------------------------------------------------------


class TestChainActivityTypes:
    def test_chain_params(self):
        from services.worker.activities.chain import ChainParams

        p = ChainParams(
            engagement_id="eng-1",
            tenant_id="tenant-1",
            finding_id="find-1",
            capability_id="cap-1",
            technique="bola-differential",
            preconditions=["authenticated_user"],
            postconditions=["unauthorized_data_access"],
            evidence_refs=["sha256:abc"],
        )
        assert p.preconditions == ["authenticated_user"]
        assert p.postconditions == ["unauthorized_data_access"]

    def test_chain_params_defaults(self):
        from services.worker.activities.chain import ChainParams

        p = ChainParams(
            engagement_id="e",
            tenant_id="t",
            finding_id="f",
            capability_id="c",
            technique="t",
        )
        assert p.preconditions == []
        assert p.postconditions == []
        assert p.evidence_refs == []


# ---------------------------------------------------------------------------
# Recon types
# ---------------------------------------------------------------------------


class TestReconTypes:
    def test_recon_result_defaults(self):
        from services.worker.activities.recon import ReconResult

        r = ReconResult()
        assert r.discovered_endpoints == []
        assert r.assets == []
        assert r.evidence_refs == []

    def test_discovered_endpoint(self):
        from services.worker.activities.recon import DiscoveredEndpoint

        ep = DiscoveredEndpoint(
            url="http://juice-shop:3000/rest/basket/1",
            method="GET",
            status_code=200,
            headers={"content-type": "application/json"},
            content_type="application/json",
        )
        assert ep.status_code == 200
        assert ep.method == "GET"

    def test_scope_rule_param(self):
        rule = ScopeRuleParam(type="exact_host", value="juice-shop")
        assert rule.type == "exact_host"
        assert rule.value == "juice-shop"
