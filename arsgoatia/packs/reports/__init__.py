"""ArsGoatia report packs -- report template definitions.

A report template describes the sections and export formats that the
reporting subsystem uses to materialise assessment outputs.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReportTemplate:
    template_id: str
    version: str
    name: str
    description: str
    sections: tuple[str, ...] = ()
    export_formats: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Built-in templates
# ---------------------------------------------------------------------------

FINDING_REPORT_TEMPLATE = ReportTemplate(
    template_id="finding_report",
    version="1.0.0",
    name="Finding Report",
    description="Standard per-finding report with evidence and remediation",
    sections=(
        "executive_summary",
        "finding_details",
        "evidence",
        "impact_analysis",
        "remediation",
        "references",
    ),
    export_formats=("pdf", "html", "json"),
)

CHAIN_REPORT_TEMPLATE = ReportTemplate(
    template_id="chain_report",
    version="1.0.0",
    name="Attack Chain Report",
    description="Multi-finding attack chain narrative with blast-radius analysis",
    sections=(
        "objective",
        "blast_radius",
        "attack_path",
        "cut_points",
        "severity_assessment",
        "evidence_chain",
    ),
    export_formats=("pdf", "html", "json"),
)
