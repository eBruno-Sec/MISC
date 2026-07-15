"""
Zero-config persistence for Round Table.

Plain sqlite3 guarded by a process-wide lock. No ORM, no external DB container —
one file on a mounted volume. Every helper is safe to call from either the async
event loop or a mission worker thread.
"""
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

DATA_DIR = Path(os.getenv("ROUNDTABLE_DATA_DIR", "/app/data"))
DB_PATH = DATA_DIR / "roundtable.db"

_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA busy_timeout=5000")
    return _conn


def init_db() -> None:
    with _lock:
        c = _connect()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS missions (
                id           TEXT PRIMARY KEY,
                target       TEXT NOT NULL,
                mode         TEXT NOT NULL,
                status       TEXT NOT NULL,
                created_at   REAL NOT NULL,
                updated_at   REAL NOT NULL,
                error        TEXT,
                scope_json   TEXT,
                result_json  TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                mission_id   TEXT NOT NULL,
                seq          INTEGER NOT NULL,
                ts           REAL NOT NULL,
                level        TEXT NOT NULL,
                phase        TEXT,
                message      TEXT NOT NULL,
                PRIMARY KEY (mission_id, seq)
            );
            CREATE INDEX IF NOT EXISTS idx_events_mission ON events(mission_id);
            """
        )
        c.commit()


def now() -> float:
    return time.time()


def new_id() -> str:
    return uuid.uuid4().hex[:12]


# ── missions ────────────────────────────────────────────────────────────────
def create_mission(target: str, mode: str, scope: dict[str, Any]) -> str:
    mid = new_id()
    ts = now()
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO missions (id,target,mode,status,created_at,updated_at,scope_json,result_json)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (mid, target, mode, "queued", ts, ts, json.dumps(scope), json.dumps({})),
        )
        c.commit()
    return mid


def update_mission(mid: str, **fields: Any) -> None:
    if not fields:
        return
    if "result" in fields:
        fields["result_json"] = json.dumps(fields.pop("result"), default=str)
    if "scope" in fields:
        fields["scope_json"] = json.dumps(fields.pop("scope"), default=str)
    fields["updated_at"] = now()
    cols = ", ".join(f"{k}=?" for k in fields)
    with _lock:
        c = _connect()
        c.execute(f"UPDATE missions SET {cols} WHERE id=?", (*fields.values(), mid))
        c.commit()


def _row_to_mission(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "target": row["target"],
        "mode": row["mode"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "error": row["error"],
        "scope": json.loads(row["scope_json"] or "{}"),
        "result": json.loads(row["result_json"] or "{}"),
    }


def get_mission(mid: str) -> Optional[dict[str, Any]]:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM missions WHERE id=?", (mid,)).fetchone()
    return _row_to_mission(row) if row else None


def list_missions(limit: int = 100) -> list[dict[str, Any]]:
    with _lock:
        c = _connect()
        rows = c.execute(
            "SELECT id,target,mode,status,created_at,updated_at,error FROM missions"
            " ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out = []
    for r in rows:
        # Lightweight summary (no heavy result blob) for the list view.
        res = get_mission_stats(r["id"])
        out.append(
            {
                "id": r["id"],
                "target": r["target"],
                "mode": r["mode"],
                "status": r["status"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "error": r["error"],
                "stats": res,
            }
        )
    return out


def get_mission_stats(mid: str) -> dict[str, Any]:
    with _lock:
        c = _connect()
        row = c.execute("SELECT result_json FROM missions WHERE id=?", (mid,)).fetchone()
    if not row:
        return {}
    res = json.loads(row["result_json"] or "{}")
    return res.get("stats", {})


def delete_mission(mid: str) -> None:
    with _lock:
        c = _connect()
        c.execute("DELETE FROM events WHERE mission_id=?", (mid,))
        c.execute("DELETE FROM missions WHERE id=?", (mid,))
        c.commit()


# ── events (terminal feed) ──────────────────────────────────────────────────
def add_event(mid: str, level: str, phase: Optional[str], message: str) -> dict[str, Any]:
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT COALESCE(MAX(seq),0)+1 AS s FROM events WHERE mission_id=?", (mid,)
        ).fetchone()
        seq = row["s"]
        ts = now()
        c.execute(
            "INSERT INTO events (mission_id,seq,ts,level,phase,message) VALUES (?,?,?,?,?,?)",
            (mid, seq, ts, level, phase, message),
        )
        c.commit()
    return {"seq": seq, "ts": ts, "level": level, "phase": phase, "message": message}


def get_events(mid: str, after_seq: int = 0) -> list[dict[str, Any]]:
    with _lock:
        c = _connect()
        rows = c.execute(
            "SELECT seq,ts,level,phase,message FROM events WHERE mission_id=? AND seq>? ORDER BY seq",
            (mid, after_seq),
        ).fetchall()
    return [dict(r) for r in rows]
