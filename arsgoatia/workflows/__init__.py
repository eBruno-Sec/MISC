"""ArsGoatia workflow definitions — shared constants and helpers for Temporal workflows.

Workflow code must be deterministic: no I/O, no datetime.now(), no random,
no uuid4(). Use workflow.now() and workflow.uuid4() from the Temporal SDK,
or delegate to activities.
"""

from __future__ import annotations

CONTROL_QUEUE = "workflow-control"
WEB_QUEUE = "workflow-web"
NAMESPACE = "arsgoatia"

SIGNAL_PAUSE = "PauseAssessment"
SIGNAL_RESUME = "ResumeAssessment"
SIGNAL_EMERGENCY_STOP = "EmergencyStop"
SIGNAL_PROVIDE_APPROVAL = "ProvideApproval"
SIGNAL_CANCEL = "CancelAssessment"

QUERY_STATUS = "GetStatus"
QUERY_PROGRESS = "GetProgress"
QUERY_PENDING_APPROVALS = "GetPendingApprovals"

DEFAULT_WORKFLOW_EXECUTION_TIMEOUT_HOURS = 168
DEFAULT_ACTIVITY_START_TO_CLOSE_TIMEOUT_SECONDS = 300
DEFAULT_HEARTBEAT_TIMEOUT_SECONDS = 30
