"""Report-generation activity (§28, report-generation queue).

Generates the atomic-finding and attack-chain reports (HTML) plus JSON and SARIF
exports for confirmed findings, stores each immutably in object storage under the
reports/ prefix, and records a report row. No target egress.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from temporalio import activity

log = logging.getLogger("report")


@activity.defn(name="generate_reports")
async def generate_reports(params: dict[str, Any]) -> dict[str, Any]:
    from domain import repositories as repo
    from domain.db import session_scope
    from evidence.store import EvidenceStore
    from reporting.exports import finding_json, sarif_report
    from reporting.html import atomic_finding_html, attack_chain_html

    tenant_id = params["tenant_id"]
    assessment_id = params["assessment_id"]
    store = EvidenceStore()
    generated: list[dict] = []

    def _finding_dict(f) -> dict:
        return {
            "id": str(f.id),
            "internal_class": f.internal_class,
            "title": f.title,
            "summary": f.summary,
            "technical_description": f.technical_description,
            "validation_state": f.validation_state,
            "severity_label": f.severity_label,
            "evidence_profile": f.evidence_profile,
            "evidence_refs": [str(e) for e in (f.evidence_refs or [])],
            "capability_refs": [str(c) for c in (f.capability_refs or [])],
            "capability_labels": ["read_foreign_object"] if f.capability_refs else [],
        }

    async def _store(report_type: str, content: bytes, media_type: str, session) -> None:
        stored = store.put(
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            evidence_type="tool_output",
            content=content,
            media_type=media_type,
            captured_by="reporting",
        )
        await repo.create_report(
            session,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            report_type=report_type,
            object_uri=stored["object_uri"],
            sha256=stored["sha256"],
            media_type=media_type,
        )
        generated.append({"type": report_type, "uri": stored["object_uri"], "sha256": stored["sha256"]})

    async with session_scope(tenant_id) as session:
        findings = await repo.get_confirmed_findings(session, assessment_id)
        finding_dicts = [_finding_dict(f) for f in findings]

        for fd in finding_dicts:
            html = atomic_finding_html(fd)
            await _store("atomic_finding_html", html.encode("utf-8"), "text/html", session)

        # JSON + SARIF over all confirmed findings.
        payload = {"findings": [finding_json(fd) for fd in finding_dicts]}
        await _store("findings_json", json.dumps(payload, indent=2).encode("utf-8"), "application/json", session)
        sarif = sarif_report(finding_dicts)
        await _store("sarif", json.dumps(sarif, indent=2).encode("utf-8"), "application/json", session)

        # Attack-chain reports.
        chains = await repo.list_attack_chains(session, assessment_id)
        for chain in chains:
            steps = await repo.list_chain_steps(session, str(chain.id))
            chain_dict = {
                "id": str(chain.id),
                "title": chain.title,
                "objective": chain.objective,
                "chain_severity": chain.chain_severity,
                "chain_scoring_rationale": chain.chain_scoring_rationale,
            }
            step_dicts = [
                {
                    "sequence_number": s.sequence_number,
                    "finding_id": str(s.finding_id) if s.finding_id else None,
                    "resulting_capability_ids": [str(c) for c in (s.resulting_capability_ids or [])],
                    "validation_state": s.validation_state,
                }
                for s in steps
            ]
            html = attack_chain_html(chain_dict, step_dicts)
            await _store("attack_chain_html", html.encode("utf-8"), "text/html", session)

    return {"status": "ok", "reports": generated, "count": len(generated)}
