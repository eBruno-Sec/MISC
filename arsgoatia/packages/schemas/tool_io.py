"""Tool execution request/result (§21).

The tool SDK is the only component that touches a target. A ToolRequest always
carries a signed action envelope; a ToolResult always references its raw output
as immutable evidence.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from schemas.action_envelope import ActionEnvelope


class ExitState(str, enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    POLICY_DENIED = "policy_denied"


class ToolRequest(BaseModel):
    tool_id: str
    tool_version: str
    action_envelope: ActionEnvelope
    input_artifact_refs: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    output_schema_version: int = 1


class ToolResult(BaseModel):
    execution_id: UUID = Field(default_factory=uuid4)
    exit_state: ExitState
    started_at: datetime
    finished_at: datetime
    normalized_output: dict[str, Any] = Field(default_factory=dict)
    raw_output_evidence_ref: UUID | None = None
    parser_version: str = "1.0.0"
    warnings: list[str] = Field(default_factory=list)
