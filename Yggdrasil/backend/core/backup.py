"""Progress-backup (.json) validation + normalization.

Pure, deterministic, no DB / no network — matches the unit-test style of the rest
of core/. The router (routers/missions.py `POST /missions/restore`) calls
`validate_backup()` before it writes anything, so a corrupt / unversioned / tampered
file is rejected cleanly with a clear reason (the UI surfaces it as the banner
"Invalid or corrupted progress file"). A restore always imports as a NEW mission
(fresh id) so it can never clobber a live one, and every finding in the backup is
restored verbatim — nothing is dropped or hidden (the never-hide-findings invariant).
"""
import copy
import hashlib
import json
import re
from datetime import date, datetime, timezone

from core.timeutil import utcnow

SUPPORTED_VERSIONS = {"1"}
PAYLOAD_SUPPORTED_VERSIONS = {"2"}
MAX_FINDINGS = 5000
MAX_NOTES = 1000
MAX_LOGS = 2000
MAX_EXCHANGES = 10000
REDACTION = "<redacted>"


class BackupError(ValueError):
    """Raised when a backup file fails schema validation. The message is a short,
    human-readable reason appended after 'Invalid or corrupted progress file:'."""


class BackupValidationError(BackupError):
    """Raised when a versioned workspace backup fails integrity validation."""


SECRET_KEY_PARTS = (
    "api_key", "apikey", "authorization", "cookie", "csrf", "password",
    "passwd", "secret", "token", "x-api-key", "x-auth-token",
)


def _is_secret_key(key: object) -> bool:
    low = str(key).lower()
    return any(part in low for part in SECRET_KEY_PARTS)


def _scrub_secrets(value):
    """Return a JSON-safe copy with credential-looking values redacted."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if _is_secret_key(k):
                out[k] = REDACTION
            else:
                out[k] = _scrub_secrets(v)
        return out
    if isinstance(value, list):
        return [_scrub_secrets(v) for v in value]
    return value


def _canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _state_hash(state: dict) -> str:
    return hashlib.sha256(_canonical_json(state).encode("utf-8")).hexdigest()


def _sanitize_workspace_id(workspace_id: object) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(workspace_id or "workspace")).strip(".-")
    while ".." in safe:
        safe = safe.replace("..", ".")
    return safe or "workspace"


def safe_backup_filename(workspace_id: object) -> str:
    """Build a filesystem-safe backup filename for browser downloads."""
    return f"YGGDRASIL_backup_{date.today().isoformat()}_{_sanitize_workspace_id(workspace_id)}.json"


def build_backup_payload(workspace_id: str, mission: dict, findings: list = None,
                         notes: list = None, logs: list = None,
                         exchanges: list = None) -> dict:
    """Build a v2 workspace backup with a tamper-evident state hash."""
    state = {
        "workspace_id": str(workspace_id or ""),
        "mission": _scrub_secrets(copy.deepcopy(mission or {})),
        "findings": _scrub_secrets(copy.deepcopy(findings or [])),
        "notes": _scrub_secrets(copy.deepcopy(notes or [])),
        "logs": _scrub_secrets(copy.deepcopy(logs or [])),
        "http_exchanges": _scrub_secrets(copy.deepcopy(exchanges or [])),
    }
    return {
        "version": "2",
        "platform": "YGGDRASIL",
        "workspace_id": str(workspace_id or ""),
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "state": state,
        "sha256": _state_hash(state),
    }


def validate_backup_payload(payload: dict) -> dict:
    """Validate and return the normalized state from a v2 workspace backup."""
    if not isinstance(payload, dict):
        raise BackupValidationError("not a JSON object")
    if str(payload.get("version")) not in PAYLOAD_SUPPORTED_VERSIONS:
        raise BackupValidationError("unsupported or missing version")
    state = payload.get("state")
    if not isinstance(state, dict):
        raise BackupValidationError("missing state")
    expected = payload.get("sha256") or payload.get("hash")
    if not expected:
        raise BackupValidationError("missing state hash")
    if not isinstance(expected, str) or expected != _state_hash(state):
        raise BackupValidationError("backup hash mismatch")

    mission = state.get("mission")
    findings = state.get("findings") or []
    notes = state.get("notes") or []
    logs = state.get("logs") or []
    exchanges = state.get("http_exchanges") or state.get("exchanges") or []
    if not isinstance(mission, dict):
        raise BackupValidationError("missing mission record")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise BackupValidationError("invalid or oversized findings")
    if not isinstance(notes, list) or len(notes) > MAX_NOTES:
        raise BackupValidationError("invalid or oversized notes")
    if not isinstance(logs, list) or len(logs) > MAX_LOGS:
        raise BackupValidationError("invalid or oversized logs")
    if not isinstance(exchanges, list) or len(exchanges) > MAX_EXCHANGES:
        raise BackupValidationError("invalid or oversized http exchanges")

    clean = copy.deepcopy(state)
    clean["mission"] = _scrub_secrets(clean.get("mission") or {})
    clean["findings"] = _scrub_secrets(clean.get("findings") or [])
    clean["notes"] = _scrub_secrets(clean.get("notes") or [])
    clean["logs"] = _scrub_secrets(clean.get("logs") or [])
    clean["http_exchanges"] = _scrub_secrets(exchanges)
    return clean


def summarize_backup(payload: dict) -> dict:
    """Return a small operator-facing summary for a validated backup file."""
    state = validate_backup_payload(payload)
    mission = state.get("mission") or {}
    return {
        "workspace_id": state.get("workspace_id") or payload.get("workspace_id") or "",
        "target": mission.get("target") or "",
        "mode": mission.get("mode") or "",
        "findings": len(state.get("findings") or []),
        "notes": len(state.get("notes") or []),
        "logs": len(state.get("logs") or []),
        "http_exchanges": len(state.get("http_exchanges") or []),
    }


def _parse_dt(v):
    """Best-effort ISO-8601 -> naive UTC datetime. Falls back to now() on anything
    missing or malformed (the models store naive datetimes, so strip any tzinfo)."""
    if not v:
        return utcnow()
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).replace(tzinfo=None)
    except (TypeError, ValueError):
        return utcnow()


def _as_float(v):
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _normalize_exchange(ex: dict) -> dict | None:
    if not isinstance(ex, dict):
        return None
    url = str(ex.get("url") or "").strip()
    if not url:
        return None
    from core.poc import redact_headers

    try:
        status_code = int(ex["status_code"]) if ex.get("status_code") is not None else None
    except (TypeError, ValueError):
        status_code = None
    try:
        duration_ms = int(ex["duration_ms"]) if ex.get("duration_ms") is not None else None
    except (TypeError, ValueError):
        duration_ms = None

    return {
        "finding_id": None,
        "method": str(ex.get("method") or "GET").upper()[:16],
        "url": url,
        "request_headers": redact_headers(ex.get("request_headers") or {}),
        "request_body": ex.get("request_body"),
        "status_code": status_code,
        "response_headers": redact_headers(ex.get("response_headers") or {}),
        "response_body": ((ex.get("response_body") or "")[:4000] or None),
        "duration_ms": duration_ms,
        "source": ex.get("source"),
        "notes": ex.get("notes"),
        "redacted": True,
    }


def validate_backup(data, is_valid_target):
    """Strictly validate a parsed backup dict; return a normalized record set ready
    for insertion. `is_valid_target` (core.security.is_valid_target) is injected so
    this module stays dependency-light and reuses the app's exact target guard —
    an imported target can never smuggle in a scheme, flag, or shell character.

    Raises BackupError with a human reason on any structural problem."""
    if not isinstance(data, dict):
        raise BackupError("not a JSON object")
    if str(data.get("version")) == "2":
        state = validate_backup_payload(data)
        data = {
            "version": "1",
            "mission": state.get("mission") or {},
            "findings": state.get("findings") or [],
            "notes": state.get("notes") or [],
            "logs": state.get("logs") or [],
            "http_exchanges": state.get("http_exchanges") or [],
            "status": (state.get("mission") or {}).get("status"),
            "current_phase": (state.get("mission") or {}).get("current_phase"),
        }
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
    exchanges = data.get("http_exchanges")
    if exchanges is None:
        exchanges = data.get("exchanges") or mission.get("http_exchanges") or []
    if not (isinstance(findings, list) and isinstance(notes, list) and isinstance(logs, list) and isinstance(exchanges, list)):
        raise BackupError("malformed record arrays")
    if len(findings) > MAX_FINDINGS:
        raise BackupError("too many findings")
    if len(notes) > MAX_NOTES:
        raise BackupError("too many notes")
    if len(logs) > MAX_LOGS:
        raise BackupError("too many logs")
    if len(exchanges) > MAX_EXCHANGES:
        raise BackupError("too many http exchanges")

    norm_findings = []
    for fd in findings:
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
    for nd in notes:
        if not isinstance(nd, dict):
            continue
        content = str(nd.get("content") or "").strip()
        if content:
            norm_notes.append({"content": content, "timestamp": _parse_dt(nd.get("timestamp"))})

    norm_logs = []
    for ld in logs:
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

    norm_exchanges = []
    for ex in exchanges:
        clean = _normalize_exchange(ex)
        if clean:
            norm_exchanges.append(clean)

    context = mission.get("context") if isinstance(mission.get("context"), dict) else {}
    scope_rules = mission.get("scope_rules") if isinstance(mission.get("scope_rules"), dict) else {}

    return {
        "target": target,
        "scope": str(mission.get("scope") or ""),
        "mode": str(mission.get("mode") or "passive"),
        # top-level status wins, then nested, then a safe terminal default
        "status": str(data.get("status") or mission.get("status") or "complete"),
        "current_phase": mission.get("current_phase") or None,
        "context": _scrub_secrets(dict(context)),
        "scope_rules": _scrub_secrets(dict(scope_rules)),
        "findings": norm_findings,
        "notes": norm_notes,
        "logs": norm_logs,
        "exchanges": norm_exchanges,
    }
