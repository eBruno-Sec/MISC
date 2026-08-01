"""
Structured, tamper-evident audit log.

Append-only JSONL where each record carries the SHA-256 of the previous record — a hash chain — so
any edit, reorder, or deletion of history is detectable (verify_chain). It records the
security-relevant, state-changing actions of an engagement: scans launched, credentials discovered,
sessions acquired, accounts created, intrusive checks run, mission exports. No secrets are stored —
metadata is passed through vault.redact, so only labels + vault references land in the log.

Pure logic (hashing/chaining) is unit-tested; the only side effect is appending a line to a file.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

_GENESIS = "0" * 64


def _now() -> float:
    return time.time()


def _digest(entry: dict) -> str:
    """SHA-256 over the record's canonical JSON, excluding its own hash field."""
    payload = {k: entry[k] for k in entry if k != "hash"}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AuditLog:
    def __init__(self, path: str = None):
        self.path = path or os.path.join(os.environ.get("BBH_DATA_DIR", "/app/data"), "audit", "audit.jsonl")
        self._lock = threading.RLock()
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        except Exception:
            pass

    def _read_lines(self) -> list:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return [json.loads(ln) for ln in f if ln.strip()]
        except Exception:
            return []

    def _last_hash(self) -> str:
        lines = self._read_lines()
        return lines[-1]["hash"] if lines else _GENESIS

    def record(self, action: str, *, actor: str = "system", target: str = "", mission: str = "",
               **meta) -> dict:
        """Append one tamper-evident audit entry. Metadata is redacted (no secrets)."""
        import vault
        with self._lock:
            entry = {"ts": _now(), "action": action, "actor": actor, "target": target,
                     "mission": mission, "meta": vault.redact(meta or {}), "prev": self._last_hash()}
            entry["hash"] = _digest(entry)
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception:
                pass
            return entry

    def entries(self, mission: str = None, action: str = None, limit: int = 500) -> list:
        rows = self._read_lines()
        if mission is not None:
            rows = [r for r in rows if r.get("mission") == mission]
        if action is not None:
            rows = [r for r in rows if r.get("action") == action]
        return rows[-limit:]

    def verify_chain(self) -> tuple:
        """(ok, first_bad_index). Recompute each record's hash and confirm it links to the previous —
        detects any tampering with the history. ok=True + index -1 when intact."""
        prev = _GENESIS
        for i, r in enumerate(self._read_lines()):
            if r.get("prev") != prev:
                return False, i
            if _digest(r) != r.get("hash"):
                return False, i
            prev = r["hash"]
        return True, -1


_DEFAULT = None
_DEFAULT_LOCK = threading.Lock()


def default() -> AuditLog:
    global _DEFAULT
    if _DEFAULT is None:
        with _DEFAULT_LOCK:
            if _DEFAULT is None:
                _DEFAULT = AuditLog()
    return _DEFAULT


def record(action: str, **kw) -> dict:
    """Module-level convenience — append to the default audit log. Best-effort; never raises."""
    try:
        return default().record(action, **kw)
    except Exception:
        return {}
