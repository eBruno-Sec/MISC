from __future__ import annotations

import html
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from temporalio import activity


async def _persist_report_row(
    *,
    tenant_id: str,
    engagement_id: str,
    report_type: str,
    fmt: str,
    digest: str,
    storage_uri: str,
) -> None:
    from sqlalchemy import text  # noqa: PLC0415

    from packages.persistence import get_session_factory, set_tenant  # noqa: PLC0415

    try:
        factory = get_session_factory()
        async with factory() as session:
            async with session.begin():
                await set_tenant(session, tenant_id)
                await session.execute(
                    text(
                        """
                        INSERT INTO reporting.report
                            (id, tenant_id, engagement_id, report_type, format,
                             digest, storage_uri, created_at)
                        VALUES
                            (:id, :tid, :eid, :rt, :fmt, :dg, :uri, :now)
                        """
                    ),
                    {
                        "id": uuid.uuid4(),
                        "tid": tenant_id,
                        "eid": engagement_id,
                        "rt": report_type,
                        "fmt": fmt,
                        "dg": digest,
                        "uri": storage_uri,
                        "now": datetime.now(timezone.utc),
                    },
                )
    except Exception as exc:
        activity.logger.warning(f"report-row persist failed: {exc}")


async def _persist_finding_row(
    *,
    tenant_id: str,
    engagement_id: str,
    finding_id: str,
    technique: str,
    target: str,
    title: str,
    severity: str,
    evidence_refs: list[str],
) -> None:
    from sqlalchemy import text  # noqa: PLC0415

    from packages.persistence import get_session_factory, set_tenant  # noqa: PLC0415

    try:
        factory = get_session_factory()
        async with factory() as session:
            async with session.begin():
                await set_tenant(session, tenant_id)
                await session.execute(
                    text(
                        """
                        INSERT INTO findings.finding
                            (id, tenant_id, engagement_id, state, technique_id, target,
                             title, severity, evidence_refs, capability_refs, created_at, updated_at)
                        VALUES
                            (:id, :tid, :eid, 'CONFIRMED', :tech, :tgt, :title, :sev,
                             CAST(:refs AS jsonb), '[]'::jsonb, :now, :now)
                        """
                    ),
                    {
                        "id": finding_id,
                        "tid": tenant_id,
                        "eid": engagement_id,
                        "tech": technique,
                        "tgt": target,
                        "title": title,
                        "sev": severity,
                        "refs": json.dumps(evidence_refs),
                        "now": datetime.now(timezone.utc),
                    },
                )
    except Exception as exc:
        activity.logger.warning(f"finding-row persist failed: {exc}")


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
    await _persist_report_row(
        tenant_id=params.tenant_id,
        engagement_id=params.engagement_id,
        report_type="engagement",
        fmt="json",
        digest=json_id,
        storage_uri=f"evidence://{json_id}",
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
    await _persist_report_row(
        tenant_id=params.tenant_id,
        engagement_id=params.engagement_id,
        report_type="engagement",
        fmt="html",
        digest=html_id,
        storage_uri=f"evidence://{html_id}",
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
    await _persist_report_row(
        tenant_id=params.tenant_id,
        engagement_id=params.engagement_id,
        report_type="engagement",
        fmt="sarif",
        digest=sarif_id,
        storage_uri=f"evidence://{sarif_id}",
    )

    # Persist each finding into findings.finding so the UI /findings list works.
    for f in params.findings:
        await _persist_finding_row(
            tenant_id=params.tenant_id,
            engagement_id=params.engagement_id,
            finding_id=f.finding_id,
            technique=f.weakness,
            target=f.affected_object,
            title=f"{f.weakness} on {f.affected_object}",
            severity=_severity_label(f.severity),
            evidence_refs=f.evidence_refs,
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


def _severity_label(sev: float) -> str:
    if sev >= 9.0:
        return "critical"
    if sev >= 7.0:
        return "high"
    if sev >= 4.0:
        return "medium"
    if sev >= 1.0:
        return "low"
    return "info"


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
        fid = html.escape(f.finding_id)
        weakness = html.escape(f.weakness)
        obj = html.escape(f.affected_object)
        st = html.escape(f.status)
        findings_rows += (
            f"<tr><td>{fid}</td><td>{weakness}</td>"
            f"<td>{obj}</td><td>{st}</td>"
            f"<td>{f.severity}</td><td>{f.confidence}</td></tr>\n"
        )

    eid = html.escape(params.engagement_id)
    tid = html.escape(params.tenant_id)
    gen = html.escape(json_data["generated_at"])

    return f"""<!DOCTYPE html>
<html>
<head><title>ArsGoatia Engagement Report</title></head>
<body>
<h1>ArsGoatia Security Validation Report</h1>
<p>Engagement: {eid}</p>
<p>Tenant: {tid}</p>
<p>Generated: {gen}</p>
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
