"""
SQLite persistence layer.

OLYMPUS uses Postgres across a multi-container stack; Apolaki stays single-container,
so we persist missions, findings, HTTP-exchange evidence, the event log, notes,
and auth profiles to a single SQLite file on a mounted volume. Findings and
exchange payloads are stored as JSON blobs so new fields never require a
migration (the OLYMPUS `context`-JSON discipline).

Writes are small and local; we use a shared connection with a lock and hand the
async layer sync helpers to call.
"""
import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

DB_PATH = os.getenv("BBH_DB_PATH", "/app/data/bbh.db")
_lock = threading.Lock()
_conn: sqlite3.Connection = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init(path: str = None) -> None:
    global _conn
    p = path or DB_PATH
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    _conn = sqlite3.connect(p, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    with _lock:
        _conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS missions(
                id TEXT PRIMARY KEY, program TEXT, mode TEXT, status TEXT,
                phase TEXT, objective TEXT, scope TEXT, context TEXT,
                created_at TEXT, updated_at TEXT);
            CREATE TABLE IF NOT EXISTS findings(
                id TEXT PRIMARY KEY, mission_id TEXT, data TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS exchanges(
                id TEXT PRIMARY KEY, mission_id TEXT, finding_id TEXT,
                data TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT,
                etype TEXT, data TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS notes(
                id TEXT PRIMARY KEY, mission_id TEXT, body TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS profiles(
                id TEXT PRIMARY KEY, mission_id TEXT, name TEXT, role TEXT,
                headers TEXT, is_owner INTEGER, created_at TEXT);
            CREATE TABLE IF NOT EXISTS memory_assets(
                target_key TEXT, kind TEXT, value TEXT,
                first_seen TEXT, last_seen TEXT,
                PRIMARY KEY(target_key, kind, value));
            CREATE TABLE IF NOT EXISTS memory_snapshots(
                id TEXT PRIMARY KEY, target_key TEXT, mission_id TEXT,
                data TEXT, created_at TEXT);
            CREATE INDEX IF NOT EXISTS ix_find_mid ON findings(mission_id);
            CREATE INDEX IF NOT EXISTS ix_exch_mid ON exchanges(mission_id);
            CREATE INDEX IF NOT EXISTS ix_log_mid ON logs(mission_id);
            CREATE INDEX IF NOT EXISTS ix_mem_tk ON memory_assets(target_key);
            CREATE INDEX IF NOT EXISTS ix_snap_tk ON memory_snapshots(target_key, created_at);
            """
        )
        _conn.commit()


def _exec(sql: str, params=()):
    with _lock:
        cur = _conn.execute(sql, params)
        _conn.commit()
        return cur


def _query(sql: str, params=()):
    with _lock:
        return [dict(r) for r in _conn.execute(sql, params).fetchall()]


# ── Missions ─────────────────────────────────────────────────────
def create_mission(mid: str, program: str, mode: str, objective: str,
                   scope: dict, context: dict = None) -> None:
    _exec(
        "INSERT OR REPLACE INTO missions VALUES(?,?,?,?,?,?,?,?,?,?)",
        (mid, program, mode, "created", "init", objective,
         json.dumps(scope), json.dumps(context or {}), _now(), _now()),
    )


def update_mission(mid: str, **fields) -> None:
    if not fields:
        return
    cols, vals = [], []
    for k, v in fields.items():
        if k in ("scope", "context") and not isinstance(v, str):
            v = json.dumps(v)
        cols.append(f"{k}=?")
        vals.append(v)
    cols.append("updated_at=?")
    vals.append(_now())
    vals.append(mid)
    _exec(f"UPDATE missions SET {', '.join(cols)} WHERE id=?", vals)


def get_mission(mid: str):
    rows = _query("SELECT * FROM missions WHERE id=?", (mid,))
    if not rows:
        return None
    m = rows[0]
    m["scope"] = json.loads(m.get("scope") or "{}")
    m["context"] = json.loads(m.get("context") or "{}")
    return m


def list_missions(limit: int = 100) -> list:
    rows = _query("SELECT * FROM missions ORDER BY created_at DESC LIMIT ?", (limit,))
    out = []
    for m in rows:
        counts = finding_counts(m["id"])
        try:
            parent_id = json.loads(m.get("context") or "{}").get("parent_id")
        except (ValueError, TypeError):
            parent_id = None
        out.append({
            "id": m["id"], "program": m["program"], "mode": m["mode"],
            "status": m["status"], "phase": m["phase"], "created_at": m["created_at"],
            "counts": counts, "parent_id": parent_id,
        })
    return out


def delete_mission(mid: str) -> None:
    for tbl in ("findings", "exchanges", "logs", "notes", "profiles"):
        _exec(f"DELETE FROM {tbl} WHERE mission_id=?", (mid,))
    _exec("DELETE FROM missions WHERE id=?", (mid,))


# ── Findings ─────────────────────────────────────────────────────
def add_finding(mid: str, finding: dict) -> str:
    fid = finding.get("id") or uuid.uuid4().hex[:12]
    finding["id"] = fid
    _exec("INSERT OR REPLACE INTO findings VALUES(?,?,?,?)",
          (fid, mid, json.dumps(finding), _now()))
    return fid


def get_findings(mid: str) -> list:
    return [json.loads(r["data"]) for r in _query(
        "SELECT data FROM findings WHERE mission_id=? ORDER BY created_at", (mid,))]


def update_finding(fid: str, finding: dict) -> None:
    finding["id"] = fid
    _exec("UPDATE findings SET data=? WHERE id=?", (json.dumps(finding), fid))


def delete_finding(fid: str) -> None:
    _exec("DELETE FROM findings WHERE id=?", (fid,))


def finding_counts(mid: str) -> dict:
    counts = {}
    for f in get_findings(mid):
        s = (f.get("severity") or "info").lower()
        counts[s] = counts.get(s, 0) + 1
    return counts


# ── HTTP exchange evidence ───────────────────────────────────────
def add_exchange(mid: str, exchange: dict, finding_id: str = None) -> str:
    from poc import redact_headers
    eid = exchange.get("id") or uuid.uuid4().hex[:12]
    exchange["id"] = eid
    # Redact sensitive headers AT REST (OLYMPUS hard contract).
    if "request_headers" in exchange:
        exchange["request_headers"] = redact_headers(exchange["request_headers"])
    if "response_headers" in exchange:
        exchange["response_headers"] = redact_headers(exchange["response_headers"])
    _exec("INSERT OR REPLACE INTO exchanges VALUES(?,?,?,?,?)",
          (eid, mid, finding_id, json.dumps(exchange), _now()))
    return eid


def get_exchanges(mid: str, finding_id: str = None) -> list:
    if finding_id:
        rows = _query("SELECT data FROM exchanges WHERE mission_id=? AND finding_id=?",
                      (mid, finding_id))
    else:
        rows = _query("SELECT data FROM exchanges WHERE mission_id=?", (mid,))
    return [json.loads(r["data"]) for r in rows]


# ── Logs (event feed persistence) ────────────────────────────────
def add_log(mid: str, etype: str, data: dict) -> None:
    _exec("INSERT INTO logs(mission_id,etype,data,created_at) VALUES(?,?,?,?)",
          (mid, etype, json.dumps(data), _now()))


def get_logs(mid: str, limit: int = 1000) -> list:
    rows = _query("SELECT etype,data,created_at FROM logs WHERE mission_id=? "
                  "ORDER BY id LIMIT ?", (mid, limit))
    return [{"type": r["etype"], **json.loads(r["data"]), "ts": r["created_at"]} for r in rows]


# ── Notes ────────────────────────────────────────────────────────
def add_note(mid: str, body: str) -> str:
    nid = uuid.uuid4().hex[:12]
    _exec("INSERT INTO notes VALUES(?,?,?,?)", (nid, mid, body, _now()))
    return nid


def get_notes(mid: str) -> list:
    return _query("SELECT id,body,created_at FROM notes WHERE mission_id=? ORDER BY created_at", (mid,))


def delete_note(nid: str) -> None:
    _exec("DELETE FROM notes WHERE id=?", (nid,))


# ── Auth profiles (cross-role access-check) ──────────────────────
def add_profile(mid: str, name: str, role: str, headers: dict, is_owner: bool) -> str:
    pid = uuid.uuid4().hex[:12]
    _exec("INSERT INTO profiles VALUES(?,?,?,?,?,?,?)",
          (pid, mid, name, role, json.dumps(headers or {}), 1 if is_owner else 0, _now()))
    return pid


def get_profiles(mid: str, redacted: bool = True) -> list:
    from poc import REDACTED
    rows = _query("SELECT id,name,role,headers,is_owner FROM profiles WHERE mission_id=?", (mid,))
    out = []
    for r in rows:
        headers = json.loads(r["headers"] or "{}")
        if redacted:
            headers = {k: REDACTED for k in headers}
        out.append({"id": r["id"], "name": r["name"], "role": r["role"],
                    "headers": headers, "is_owner": bool(r["is_owner"])})
    return out


def get_profiles_raw(mid: str) -> list:
    rows = _query("SELECT id,name,role,headers,is_owner FROM profiles WHERE mission_id=?", (mid,))
    return [{"id": r["id"], "name": r["name"], "role": r["role"],
             "headers": json.loads(r["headers"] or "{}"), "is_owner": bool(r["is_owner"])}
            for r in rows]


def delete_profile(pid: str) -> None:
    _exec("DELETE FROM profiles WHERE id=?", (pid,))


# ── Cross-session memory (per-target intel, keyed by scope, not mission) ──
def record_memory(target_key: str, mission_id: str, snapshot: dict) -> str:
    """Persist a mission's snapshot: upsert accumulated assets (first/last seen)
    and append the snapshot for later diffing. Only in-scope, secret-free data
    ever reaches here (the caller builds the snapshot from recon/surface)."""
    import memory as memory_mod
    now = _now()
    with _lock:
        for kind, value in memory_mod.asset_pairs(snapshot):
            _conn.execute(
                "INSERT INTO memory_assets(target_key,kind,value,first_seen,last_seen) "
                "VALUES(?,?,?,?,?) ON CONFLICT(target_key,kind,value) "
                "DO UPDATE SET last_seen=excluded.last_seen",
                (target_key, kind, value, now, now))
        sid = uuid.uuid4().hex[:12]
        _conn.execute("INSERT INTO memory_snapshots VALUES(?,?,?,?,?)",
                      (sid, target_key, mission_id, json.dumps(snapshot), now))
        _conn.commit()
    return sid


def get_memory_assets(target_key: str) -> dict:
    """Accumulated assets for a target grouped by kind, each with first/last
    seen — the warm-start seed for a new mission on the same program."""
    rows = _query(
        "SELECT kind,value,first_seen,last_seen FROM memory_assets "
        "WHERE target_key=? ORDER BY kind,value", (target_key,))
    out = {}
    for r in rows:
        out.setdefault(r["kind"], []).append(
            {"value": r["value"], "first_seen": r["first_seen"], "last_seen": r["last_seen"]})
    return out


def get_prior_snapshot(target_key: str, before_mission: str = None) -> dict:
    """Most recent snapshot for a target, excluding one mission (the current
    one) — the baseline a 'since last scan' diff compares against."""
    if before_mission:
        rows = _query(
            "SELECT data FROM memory_snapshots WHERE target_key=? AND mission_id!=? "
            "ORDER BY created_at DESC LIMIT 1", (target_key, before_mission))
    else:
        rows = _query(
            "SELECT data FROM memory_snapshots WHERE target_key=? "
            "ORDER BY created_at DESC LIMIT 1", (target_key,))
    return json.loads(rows[0]["data"]) if rows else {}


def get_snapshot(mission_id: str) -> dict:
    """This mission's own recorded snapshot (used to render surface/topology for
    an archived mission whose live agent is gone)."""
    rows = _query(
        "SELECT data FROM memory_snapshots WHERE mission_id=? "
        "ORDER BY created_at DESC LIMIT 1", (mission_id,))
    return json.loads(rows[0]["data"]) if rows else {}
