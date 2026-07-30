"""ArsGoatia workflow packs -- ordered assessment flows.

A workflow pack describes a sequence of steps that the orchestrator
executes for a particular kind of assessment.  Each step references
an optional technique and declares a gate type that the orchestrator
must honour before proceeding.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class WorkflowStep:
    step_id: str
    technique_id: str | None
    description: str
    gate: str = "none"  # "none" | "approval" | "stop_condition"
    coverage_expectation: str = ""


@dataclass(frozen=True)
class WorkflowPack:
    pack_id: str
    version: str
    description: str
    steps: tuple[WorkflowStep, ...] = ()
    stop_conditions: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in workflow: BOLA_ASSESSMENT_FLOW
# ---------------------------------------------------------------------------

BOLA_ASSESSMENT_FLOW = WorkflowPack(
    pack_id="bola_assessment_flow",
    version="1.0.0",
    description="End-to-end BOLA/IDOR assessment workflow",
    steps=(
        WorkflowStep(
            step_id="recon",
            technique_id=None,
            description="Enumerate API endpoints and object identifiers",
            gate="none",
            coverage_expectation="all_endpoints",
        ),
        WorkflowStep(
            step_id="identity_bootstrap",
            technique_id=None,
            description="Create or obtain test identities",
            gate="none",
            coverage_expectation="min_2_identities",
        ),
        WorkflowStep(
            step_id="hypothesis_generation",
            technique_id=None,
            description="Generate BOLA hypotheses from endpoint analysis",
            gate="none",
            coverage_expectation="one_per_endpoint",
        ),
        WorkflowStep(
            step_id="action_proposal",
            technique_id="web.authz.bola.differential",
            description="Propose differential-access actions for each hypothesis",
            gate="none",
            coverage_expectation="one_per_hypothesis",
        ),
        WorkflowStep(
            step_id="approval_gate",
            technique_id=None,
            description="Pause for operator approval of proposed actions",
            gate="approval",
            coverage_expectation="all_proposed_actions",
        ),
        WorkflowStep(
            step_id="differential_execution",
            technique_id="web.authz.bola.differential",
            description="Execute approved differential-access probes",
            gate="none",
            coverage_expectation="all_approved_actions",
        ),
        WorkflowStep(
            step_id="evidence_validation",
            technique_id=None,
            description="Validate exchange results against confirmation rules",
            gate="none",
            coverage_expectation="all_executed_actions",
        ),
        WorkflowStep(
            step_id="finding_confirmation",
            technique_id=None,
            description="Confirm or reject findings based on evidence quality",
            gate="stop_condition",
            coverage_expectation="all_validated_results",
        ),
        WorkflowStep(
            step_id="capability_proof",
            technique_id=None,
            description="Build capability proof artefacts for confirmed findings",
            gate="none",
            coverage_expectation="all_confirmed_findings",
        ),
        WorkflowStep(
            step_id="chain_step",
            technique_id=None,
            description="Evaluate attack-chain extensions from confirmed findings",
            gate="approval",
            coverage_expectation="all_confirmed_findings",
        ),
        WorkflowStep(
            step_id="reporting",
            technique_id=None,
            description="Generate assessment report with findings and evidence",
            gate="none",
            coverage_expectation="full_assessment",
        ),
    ),
    stop_conditions=[
        "max_findings_reached",
        "coverage_target_met",
        "operator_stop",
        "time_budget_exhausted",
    ],
)
