"""ArsGoatia execution boundary agent (runner-agent).

The runner-agent is the only component that actually executes actions
against target systems.  It verifies the signed action envelope before
execution, runs the action within the declared safety constraints, and
reports the result back to the orchestration layer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

logger = logging.getLogger("arsgoatia.services.runner_agent")


class ExecutionStatus(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    REJECTED = "rejected"
    ERROR = "error"


@dataclass(frozen=True)
class ExecutionResult:
    """Result of a single action execution."""

    result_id: UUID
    action_id: UUID
    status: ExecutionStatus
    started_at: datetime
    completed_at: datetime
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class RunnerAgent:
    """Execution boundary agent.

    Enforces the trust boundary between the orchestration layer and
    target systems.  Every action must pass envelope verification
    before execution is permitted.
    """

    signing_key: bytes = b""
    _current_revocation_epoch: int = 0
    _nonce_store: set[str] = field(default_factory=set, init=False, repr=False)

    def verify_envelope(self, envelope_data: dict[str, Any]) -> list[str]:
        """Verify the action envelope before execution.

        Returns a list of validation errors.  An empty list means the
        envelope is valid and execution may proceed.

        Checks performed:
        - Required fields are present and non-empty.
        - HMAC signature is valid under the signing key.
        - Nonce has not been replayed.
        - Revocation epoch is current.
        """
        errors: list[str] = []

        # Structural validation
        required_fields = (
            "actionId",
            "tenantId",
            "engagementRevisionId",
            "technique",
            "target",
            "nonce",
            "effectiveRiskTier",
        )
        for f in required_fields:
            if envelope_data.get(f) in (None, ""):
                errors.append(f"missing required field: {f}")

        if errors:
            return errors

        # Signature verification
        signature = envelope_data.get("signature")
        if not signature:
            errors.append("missing envelope signature")
        elif self.signing_key:
            from packages.envelope import verify_action_envelope

            if not verify_action_envelope(envelope_data, signature, self.signing_key):
                errors.append("invalid envelope signature")

        # Nonce replay check
        nonce = envelope_data.get("nonce", "")
        if nonce in self._nonce_store:
            errors.append("nonce replay detected")
        else:
            self._nonce_store.add(nonce)

        # Revocation epoch
        envelope_epoch = envelope_data.get("revocationEpoch", 0)
        if envelope_epoch < self._current_revocation_epoch:
            errors.append(
                f"envelope epoch {envelope_epoch} is behind "
                f"current epoch {self._current_revocation_epoch}"
            )

        return errors

    def execute_action(
        self,
        envelope_data: dict[str, Any],
    ) -> ExecutionResult:
        """Execute the action described by the verified envelope.

        The envelope MUST have passed ``verify_envelope`` first.
        This stub returns a placeholder result; the real implementation
        dispatches to the appropriate technique adapter.
        """
        action_id_str = envelope_data.get("actionId", "")
        try:
            action_id = UUID(action_id_str)
        except (ValueError, AttributeError):
            action_id = uuid4()

        started_at = datetime.now(timezone.utc)

        # TODO: dispatch to technique adapter based on envelope["technique"]
        logger.info(
            "Executing action %s (technique=%s)",
            action_id,
            envelope_data.get("technique", "unknown"),
        )

        completed_at = datetime.now(timezone.utc)

        return ExecutionResult(
            result_id=uuid4(),
            action_id=action_id,
            status=ExecutionStatus.SUCCESS,
            started_at=started_at,
            completed_at=completed_at,
            output={"stub": True},
        )

    def report_result(self, result: ExecutionResult) -> dict[str, Any]:
        """Format an execution result for reporting back to orchestration.

        Returns a serializable dict suitable for Temporal activity
        completion or event publishing.
        """
        return {
            "result_id": str(result.result_id),
            "action_id": str(result.action_id),
            "status": result.status.value,
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat(),
            "output": result.output,
            "error": result.error,
            "evidence_refs": result.evidence_refs,
        }


__all__ = ["ExecutionResult", "ExecutionStatus", "RunnerAgent"]
