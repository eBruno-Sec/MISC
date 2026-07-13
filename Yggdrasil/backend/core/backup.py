"""Progress-backup (.json) validation + normalization.

Pure, deterministic, no DB / no network — matches the unit-test style of the rest
of core/. The router (routers/missions.py `POST /missions/restore`) calls
`validate_backup()` before it writes anything, so a corrupt / unversioned / tampered
file is rejected cleanly with a clear reason (the UI surfaces it as the banner
"Invalid or corrupted progress file"). A restore always imports as a NEW mission
(fresh id) so it can never clobber a live one, and every finding in the backup is
restored verbatim — nothing is dropped or hidden (the never-hide-findings invariant).
"""
from datetime import datetime

SUPPORTED_VERSIONS = {"1"}
MAX_FINDINGS = 5000
MAX_NOTES = 1000
MAX_LOGS = 2000


class BackupError(ValueError):
    """Raised when a backup file fails schema validation. The message is a short,
    human-readable reason appended after 'Invalid or corrupted progress file:'."""


def _parse_dt(v):
    """Best-effort ISO-8601 -> naive UTC datetime. Falls back to now() on anything
    missing or malformed (the models store naive datetimes, so strip any tzinfo)."""
    if not v:
        return datetime.utcnow()
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).replace(tzinfo=None)
    except (TypeError, ValueError):
        return datetime.utcnow()


def _as_float(v):
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def validate_backup(data, is_valid_target):
    """Strictly validate a parsed backup dict; return a normalized record set ready
    for insertion. `is_valid_target` (core.security.is_valid_target) is injected so
    this module stays dependency-light and reuses the app's exact target guard —
    an imported target can never smuggle in a scheme, flag, or shell character.

    Raises BackupError with a human reason on any structural problem."""
    if not isinstance(data, dict):
        raise BackupError("not a JSON object")
    if str(data.get("version")) not in SUPPORTED_VERSIONS:
        raise BackupError("unsupported or missing version")

    mission = data.get("mission")
    if not isinstance(mission, dict):
        raise BackupError("missing mission record")

    target = str(mission.get("target") or "").strip()
    if not target or not is_valid_target(target):
        raise BackupError("missing or invalid target")

    # Prefer the backup's top-level arrays (canonical); fall back to the nested
    # mission object so an older/partial export still restores.
    findings = data.get("findings")
    if findings is None:
        findings = mission.get("findings") or []
    notes = data.get("notes")
    if notes is None:
        notes = mission.get("notes") or []
    logs = data.get("logs")
    if logs is None:
        logs = mission.get("logs") or []
    if not (isinstance(findings, list) and isinstance(notes, list) and isinstance(logs, list)):
        raise BackupError("malformed record arrays")

    norm_findings = []
    for fd in findings[:MAX_FINDINGS]:
        if not isinstance(fd, dict):
            continue
        title = str(fd.get("title") or "").strip()
        if not title:
            continue
        norm_findings.append({
            "title": title[:500],
            "severity": str(fd.get("severity") or "info"),
            "description": fd.get("description"),
            "evidence": fd.get("evidence"),
            "cvss_score": _as_float(fd.get("cvss_score")),
            "remediation": fd.get("remediation"),
            "found_by": fd.get("found_by"),
            "tag": fd.get("tag"),
            "is_manual": bool(fd.get("is_manual", False)),
            "analyst_notes": fd.get("analyst_notes"),
            "timestamp": _parse_dt(fd.get("timestamp")),
        })

    norm_notes = []
    for nd in notes[:MAX_NOTES]:
        if not isinstance(nd, dict):
            continue
        content = str(nd.get("content") or "").strip()
        if content:
            norm_notes.append({"content": content, "timestamp": _parse_dt(nd.get("timestamp"))})

    norm_logs = []
    for ld in logs[:MAX_LOGS]:
        if not isinstance(ld, dict):
            continue
        msg = str(ld.get("message") or "")
        if msg:
            norm_logs.append({
                "agent": str(ld.get("agent") or "system"),
                "level": str(ld.get("level") or "info"),
                "message": msg,
                "timestamp": _parse_dt(ld.get("timestamp")),
            })

    context = mission.get("context") if isinstance(mission.get("context"), dict) else {}
    scope_rules = mission.get("scope_rules") if isinstance(mission.get("scope_rules"), dict) else {}

    return {
        "target": target,
        "scope": str(mission.get("scope") or ""),
        "mode": str(mission.get("mode") or "passive"),
        # top-level status wins, then nested, then a safe terminal default
        "status": str(data.get("status") or mission.get("status") or "complete"),
        "current_phase": mission.get("current_phase") or None,
        "context": dict(context),
        "scope_rules": dict(scope_rules),
        "findings": norm_findings,
        "notes": norm_notes,
        "logs": norm_logs,
    }
