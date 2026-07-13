from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from datetime import datetime
from typing import Any



BACKUP_SCHEMA = "yggdrasil.workspace_backup"
SUPPORTED_VERSIONS = {1, 2}
MAX_BACKUP_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 1000
MAX_NOTES = 500
MAX_LOGS = 5000
MAX_EXCHANGES = 1000

SECRET_KEY_PATTERN = re.compile(
    r"(?i)(authorization|cookie|password|passwd|secret|token|api[_-]?key|csrf|session)"
)

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_WILDCARD_RE = re.compile(
    r"^\*\.(?=.{1,251}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _is_valid_target(value: str) -> bool:
    if not value or value.startswith("-"):
        return False
    value = value.strip()
    if len(value) > 261:
        return False
    if any(c in value for c in (";", "&", "|", "$", "`", " ", "\t", "\n", "'", '"', "\\", "<", ">")):
        return False
    host = value
    if "/" not in value and value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            return False
    if host == "localhost":
        return True
    try:
        if "/" in host:
            ipaddress.ip_network(host, strict=False)
            return True
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(host) or _WILDCARD_RE.match(host))


class BackupValidationError(ValueError):
    pass


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def backup_sha256(payload: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(payload)
    unsigned.pop("sha256", None)
    return hashlib.sha256(canonical_json(unsigned).encode("utf-8")).hexdigest()


def sign_backup(payload: dict[str, Any]) -> dict[str, Any]:
    signed = copy.deepcopy(payload)
    signed["sha256"] = backup_sha256(signed)
    return signed


def safe_backup_filename(workspace_id: str, now: datetime | None = None) -> str:
    safe_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", workspace_id or "workspace").strip("-._")
    if not safe_id:
        safe_id = "workspace"
    date = (now or datetime.utcnow()).strftime("%Y-%m-%d")
    return f"YGGDRASIL_backup_{date}_{safe_id[:64]}.json"


def scrub_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            skey = str(key)
            clean[skey] = "[REDACTED]" if SECRET_KEY_PATTERN.search(skey) else scrub_secrets(item)
        return clean
    if isinstance(value, list):
        return [scrub_secrets(item) for item in value]
    return value


def build_backup_payload(
    *,
    workspace_id: str,
    mission: dict[str, Any],
    findings: list[dict[str, Any]],
    notes: list[dict[str, Any]],
    logs: list[dict[str, Any]],
    exchanges: list[dict[str, Any]] | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    state = {
        "mission": scrub_secrets(mission),
        "findings": scrub_secrets(findings),
        "notes": scrub_secrets(notes),
        "logs": scrub_secrets(logs),
        "http_exchanges": scrub_secrets(exchanges or []),
    }
    payload = {
        "schema": BACKUP_SCHEMA,
        "version": 2,
        "workspace_id": workspace_id,
        "created_at": (created_at or datetime.utcnow()).isoformat(),
        "state": state,
    }
    return sign_backup(payload)


def validate_backup_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise BackupValidationError("Backup must be a JSON object")
    encoded_size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    if encoded_size > MAX_BACKUP_BYTES:
        raise BackupValidationError(f"Backup exceeds maximum size of {MAX_BACKUP_BYTES} bytes")

    version = payload.get("version", 1)
    if version not in SUPPORTED_VERSIONS:
        raise BackupValidationError(f"Unsupported backup version: {version}")

    if version == 2:
        if payload.get("schema") != BACKUP_SCHEMA:
            raise BackupValidationError("Unsupported backup schema")
        expected = payload.get("sha256")
        if not isinstance(expected, str) or not expected:
            raise BackupValidationError("Backup is missing sha256")
        actual = backup_sha256(payload)
        if actual != expected:
            raise BackupValidationError("Backup sha256 mismatch")
        state = payload.get("state")
    else:
        state = payload.get("state", payload)

    if not isinstance(state, dict):
        raise BackupValidationError("Backup state must be an object")

    mission = state.get("mission")
    if not isinstance(mission, dict):
        raise BackupValidationError("Backup mission must be an object")
    target = str(mission.get("target", "")).strip()
    if not _is_valid_target(target):
        raise BackupValidationError("Backup target is invalid")

    findings = _expect_list(state, "findings", MAX_FINDINGS)
    notes = _expect_list(state, "notes", MAX_NOTES)
    logs = _expect_list(state, "logs", MAX_LOGS)
    exchanges = _expect_list(state, "http_exchanges", MAX_EXCHANGES, required=False)

    normalized = {
        "version": version,
        "workspace_id": str(payload.get("workspace_id") or mission.get("id") or "unknown"),
        "mission": {
            "target": target,
            "scope": str(mission.get("scope") or ""),
            "mode": str(mission.get("mode") or "passive"),
            "scope_rules": mission.get("scope_rules") if isinstance(mission.get("scope_rules"), dict) else {},
            "context": scrub_secrets(mission.get("context") if isinstance(mission.get("context"), dict) else {}),
        },
        "findings": [_normalize_finding(item) for item in findings],
        "notes": [_normalize_note(item) for item in notes],
        "logs": [_normalize_log(item) for item in logs],
        "http_exchanges": [_normalize_exchange(item) for item in exchanges],
    }
    return normalized


def summarize_backup(payload: Any) -> dict[str, Any]:
    data = validate_backup_payload(payload)
    return {
        "version": data["version"],
        "workspace_id": data["workspace_id"],
        "target": data["mission"]["target"],
        "mode": data["mission"]["mode"],
        "findings": len(data["findings"]),
        "notes": len(data["notes"]),
        "logs": len(data["logs"]),
        "http_exchanges": len(data["http_exchanges"]),
    }


def _expect_list(state: dict[str, Any], key: str, cap: int, *, required: bool = True) -> list[Any]:
    value = state.get(key)
    if value is None and not required:
        return []
    if not isinstance(value, list):
        raise BackupValidationError(f"Backup {key} must be a list")
    if len(value) > cap:
        raise BackupValidationError(f"Backup {key} exceeds maximum count of {cap}")
    return value


def _normalize_finding(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise BackupValidationError("Finding entries must be objects")
    title = str(item.get("title") or "").strip()
    if not title:
        raise BackupValidationError("Finding title is required")
    severity = str(item.get("severity") or "info").lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"
    return {
        "title": title[:500],
        "severity": severity,
        "description": _optional_str(item.get("description")),
        "evidence": _optional_str(item.get("evidence")),
        "cvss_score": item.get("cvss_score") if isinstance(item.get("cvss_score"), (int, float)) else None,
        "remediation": _optional_str(item.get("remediation")),
        "found_by": _optional_str(item.get("found_by")),
        "tag": item.get("tag") if item.get("tag") in {None, "confirmed", "false_positive", "reported", "fixed"} else None,
        "is_manual": bool(item.get("is_manual", False)),
        "analyst_notes": _optional_str(item.get("analyst_notes")),
    }


def _normalize_note(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise BackupValidationError("Note entries must be objects")
    content = str(item.get("content") or "").strip()
    if not content:
        raise BackupValidationError("Note content is required")
    return {"content": content[:20000]}


def _normalize_log(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise BackupValidationError("Log entries must be objects")
    message = str(item.get("message") or "").strip()
    if not message:
        raise BackupValidationError("Log message is required")
    return {
        "agent": str(item.get("agent") or "import")[:80],
        "level": str(item.get("level") or "info")[:20],
        "message": message[:20000],
        "raw_output": _optional_str(item.get("raw_output")),
    }


def _normalize_exchange(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise BackupValidationError("HTTP exchange entries must be objects")
    url = str(item.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        raise BackupValidationError("HTTP exchange URL must be absolute HTTP(S)")
    return {
        "label": _optional_str(item.get("label")),
        "method": str(item.get("method") or "GET").upper()[:12],
        "url": url,
        "request_headers": scrub_secrets(item.get("request_headers") if isinstance(item.get("request_headers"), dict) else {}),
        "request_body": _optional_str(item.get("request_body")),
        "response_status": int(item.get("response_status") or 0) or None,
        "response_headers": scrub_secrets(item.get("response_headers") if isinstance(item.get("response_headers"), dict) else {}),
        "response_body": _optional_str(item.get("response_body")),
        "finding_id": _optional_str(item.get("finding_id")),
    }


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text[:100000]
