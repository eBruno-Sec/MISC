from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from temporalio import activity


@dataclass
class FindingParam:
    finding_id: str
    weakness: str
    affected_object: str
    status: str
    confidence: float
    severity: float
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class ReportParams:
    engagement_id: str
    tenant_id: str
    findings: list[FindingParam]
    evidence_refs: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class ReportResult:
    html_report_id: str = ""
    json_report_id: str = ""
    sarif_report_id: str = ""


@activity.defn
async def generate_reports(params: ReportParams) -> ReportResult:
    from services.worker.activities.evidence import (  # noqa: PLC0415
        StoreEvidenceParams,
        store_evidence,
    )

    activity.heartbeat("generating JSON report")
    json_report = _build_json_report(params)
    json_id = await store_evidence(
        StoreEvidenceParams(
            engagement_id=params.engagement_id,
            tenant_id=params.tenant_id,
            action_id="report-json",
            kind="report",
            media_type="application/json",
            payload=json.dumps(json_report, sort_keys=True, indent=2).encode(),
        )
    )

    activity.heartbeat("generating HTML report")
    html_report = _build_html_report(params, json_report)
    html_id = await store_evidence(
        StoreEvidenceParams(
            engagement_id=params.engagement_id,
            tenant_id=params.tenant_id,
            action_id="report-html",
            kind="report",
            media_type="text/html",
            payload=html_report.encode(),
        )
    )

    activity.heartbeat("generating SARIF report")
    sarif_report = _build_sarif_report(params)
    sarif_id = await store_evidence(
        StoreEvidenceParams(
            engagement_id=params.engagement_id,
            tenant_id=params.tenant_id,
            action_id="report-sarif",
            kind="report",
            media_type="application/sarif+json",
            payload=json.dumps(sarif_report, sort_keys=True, indent=2).encode(),
        )
    )

    activity.logger.info(
        "Reports generated",
        extra={"engagement_id": params.engagement_id},
    )

    return ReportResult(
        html_report_id=html_id,
        json_report_id=json_id,
        sarif_report_id=sarif_id,
    )


def _build_json_report(params: ReportParams) -> dict:
    return {
        "schema_version": "1.0",
        "engagement_id": params.engagement_id,
        "tenant_id": params.tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "finding_id": f.finding_id,
                "weakness": f.weakness,
                "affected_object": f.affected_object,
                "status": f.status,
                "confidence": f.confidence,
                "severity": f.severity,
                "evidence_refs": f.evidence_refs,
            }
            for f in params.findings
        ],
        "metadata": params.metadata,
    }


def _build_html_report(params: ReportParams, json_data: dict) -> str:
    findings_rows = ""
    for f in params.findings:
        findings_rows += (
            f"<tr><td>{f.finding_id}</td><td>{f.weakness}</td>"
            f"<td>{f.affected_object}</td><td>{f.status}</td>"
            f"<td>{f.severity}</td><td>{f.confidence}</td></tr>\n"
        )

    return f"""<!DOCTYPE html>
<html>
<head><title>ArsGoatia Engagement Report</title></head>
<body>
<h1>ArsGoatia Security Validation Report</h1>
<p>Engagement: {params.engagement_id}</p>
<p>Tenant: {params.tenant_id}</p>
<p>Generated: {json_data["generated_at"]}</p>
<h2>Findings ({len(params.findings)})</h2>
<table border="1">
<tr><th>ID</th><th>Weakness</th><th>Object</th>
<th>Status</th><th>Severity</th><th>Confidence</th></tr>
{findings_rows}
</table>
</body>
</html>"""


def _build_sarif_report(params: ReportParams) -> dict:
    results = []
    for f in params.findings:
        results.append(
            {
                "ruleId": f.weakness,
                "level": "error" if f.severity >= 7.0 else "warning",
                "message": {
                    "text": (
                        f"{f.weakness} found on {f.affected_object} (confidence: {f.confidence})"
                    ),
                },
                "properties": {
                    "finding_id": f.finding_id,
                    "status": f.status,
                    "severity": f.severity,
                    "evidence_refs": f.evidence_refs,
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ArsGoatia",
                        "version": "0.1.0",
                        "informationUri": "https://arsgoatia.dev",
                    },
                },
                "results": results,
            },
        ],
    }
