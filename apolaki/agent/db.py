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
            ctx = json.loads(m.get("context") or "{}")
        except (ValueError, TypeError):
            ctx = {}
        out.append({
            "id": m["id"], "program": m["program"], "mode": m["mode"],
            "status": m["status"], "phase": m["phase"], "created_at": m["created_at"],
            "counts": counts, "parent_id": ctx.get("parent_id"),
            "leads": len(ctx.get("leads") or []),
        })
    return out


def delete_mission(mid: str) -> None:
    for tbl in ("findings", "exchanges", "logs", "notes", "profiles"):
        _exec(f"DELETE FROM {tbl} WHERE mission_id=?", (mid,))
    _exec("DELETE FROM missions WHERE id=?", (mid,))


# ── Findings ─────────────────────────────────────────────────────
#: The THREE invariants `findings_gate` states, named once so both writers below and the bypass
#: controls in tests/test_gate_write_paths.py refer to the same list:
#:   SCHEMA (#6)  `normalize`  — reproduction_steps is ALWAYS a list; safe defaults for always-read fields
#:   SCOPE  (#8)  `off_scope`  — a provably out-of-scope target is never persisted (fail-open otherwise)
#:   TRUTH  (#7)  `is_lead`    — a lead-confidence item goes to the leads list, never the findings table
#
#: WHAT A WRITE ACTUALLY DID (Q-089). The three invariants above produce three genuinely different
#: outcomes, and for years they were reported through ONE `str`: the finding id, the LEAD id, or "".
#: A refusal was distinguishable (falsy); a REROUTE was not — it returns a truthy id exactly like a
#: store, so `sum(1 for f in fs if db.add_finding(...))` counted rows that were never written and
#: `/engage` told the operator a source-derived finding was stored when the table held nothing.
#: Invariant I-2 measured 0 unowned paths and was RIGHT: the ownership is not missing, the OUTCOME
#: was ambiguous at the boundary. These three names are that outcome's vocabulary.
STORED = "stored"        #: a row now exists in the findings table
REROUTED = "rerouted"    #: TRUTH (#7) — the item went to the mission's leads list; NO findings row
REFUSED = "refused"      #: SCOPE (#8) — provably off-scope; nothing was written anywhere


#: Q-090-B/C. `update_finding` has FOUR outcomes and returned `bool`, so `False` meant three
#: different things and `True` meant two. The callers could not tell them apart and both of them
#: reported something untrue:
#:
#:   main.py:3789  `if not db.update_finding(...)` -> 404 "finding not found in this mission"
#:                 -- answered on an OFF-SCOPE refusal, with the row sitting in the table.
#:   main.py:3825  discards the return entirely -> {"ok": true, "bytes": 4, "attached_to": "f1"}
#:                 -- answered when nothing was attached.
#:
#: Same shape as Q-089 one function over. `bool` CANNOT be subclassed in Python, so this carries the
#: legacy truthiness through `__bool__` instead: every existing `if db.update_finding(...)` keeps its
#: exact behaviour, and a caller that needs the outcome asks for it.
UPDATED = "updated"          #: the row was updated in place (#6)
UPDATE_REROUTED = "rerouted" #: TRUTH (#7) — the row LEFT the findings table for the leads list
UPDATE_REFUSED = "refused"   #: SCOPE (#8) — off-scope; the write did not happen, the old row stands
UPDATE_MISSING = "missing"   #: no such finding in THIS mission (tenant isolation #10)


class FindingUpdateResult:
    """What `update_finding` did, in a value that is still usable as the bool it used to be.

    `__bool__` reproduces the OLD truthiness exactly -- True for UPDATED and UPDATE_REROUTED, False
    for UPDATE_REFUSED and UPDATE_MISSING -- so no existing caller changes behaviour by upgrading.
    That is deliberate and it is also the trap: **truthiness is what was ambiguous**. A REROUTED
    update is truthy and leaves NO row in the findings table, exactly as a REROUTED add is. Any
    caller reporting a COUNT or a STATUS must read `.updated` or `.verdict`, never `bool(...)`, and
    `tests/test_outcome_fidelity.py` enforces that repository-wide.
    """

    __slots__ = ("verdict",)

    def __init__(self, verdict: str):
        self.verdict = verdict

    def __bool__(self) -> bool:
        return self.verdict in (UPDATED, UPDATE_REROUTED)

    @property
    def updated(self) -> bool:
        """True ONLY when a row remains in the findings table carrying the edit."""
        return self.verdict == UPDATED

    def __repr__(self) -> str:
        return "FindingUpdateResult(%r)" % self.verdict

    def __eq__(self, other):
        # Legacy call sites and tests compare against True/False. Preserve that, and keep the
        # verdict comparable too, so neither style silently stops matching.
        if isinstance(other, FindingUpdateResult):
            return self.verdict == other.verdict
        if isinstance(other, bool):
            return bool(self) is other
        if isinstance(other, str):
            return self.verdict == other
        return NotImplemented

    def __hash__(self):
        return hash(self.verdict)


class FindingWriteId(str):
    """The id `add_finding` returns, carrying WHAT HAPPENED to the write.

    It IS a `str` — deliberately, and that is the whole design. TWENTY-ONE production call sites read
    this value as an id (`f["id"] = db.add_finding(...)`), json-serialise it, bind it to sqlite,
    compare and hash it; a wrapper object would have broken every one of them silently, in a way a
    green suite would not have shown. Subclassing `str` leaves all of that byte-identical and adds
    the one thing the caller could not previously ask:

        write = db.add_finding(mid, finding)
        if write.stored:                  # a ROW EXISTS — not merely "something happened"
            ...
        write.verdict                     # STORED | REROUTED | REFUSED

    TRUTHINESS IS UNCHANGED ON PURPOSE. A rerouted lead is still truthy (it is a real lead id, and
    `tests/test_findings_gate.py` pins that), so `if db.add_finding(...)` still answers the OLD
    question — "did anything happen" — which is never the same as "was it stored". That the old
    question is asked NOWHERE in production is a repository-wide absence, proved by AST census in
    `tests/test_finding_write_verdict.py`, not by hoping the type change caught every caller."""

    #: (no __slots__: CPython rejects a nonempty __slots__ on a subtype of a variable-length builtin)
    def __new__(cls, value: str, verdict: str):
        self = super().__new__(cls, value or "")
        self.verdict = verdict
        return self

    def __reduce__(self):
        """Rebuild through BOTH arguments, so copy/deepcopy/pickle keep the verdict.

        MEASURED, and it is the reason this method exists: `copy` reconstructs a `str` subclass by
        calling `cls.__new__(cls, <the string>)`, so without this
        `copy.deepcopy({"id": db.add_finding(...)})` raised
        `TypeError: __new__() missing 1 required positional argument: 'verdict'`. That is exactly the
        back-compat break subclassing `str` was chosen to avoid, and no findings test would have
        reached it — nothing in production deepcopies a finding today. The one that does it next year
        would have found it instead."""
        return (self.__class__, (str(self), self.verdict))

    @property
    def stored(self) -> bool:
        """True only when a row was INSERTed into the findings table."""
        return self.verdict == STORED


def _gate(mid: str, finding: dict):
    """Evaluate all three invariants for a write of `finding` into mission `mid`.

    Returns (verdict, finding) where verdict is "admit" | "reject" | "lead". ONE implementation, so a
    write path cannot enforce two of three — which is exactly how `update_finding` came to enforce
    none. Callers decide what "reject"/"lead" mean for their operation (INSERT vs UPDATE differ);
    they do NOT get to decide whether the invariants are evaluated."""
    import findings_gate as _fg
    finding = _fg.normalize(finding)                     # SCHEMA (#6) — total, never rejects
    scope = (get_mission(mid) or {}).get("scope") or {}
    if _fg.off_scope(finding, scope):
        return "reject", finding                         # SCOPE (#8)
    if _fg.is_lead(finding):
        return "lead", finding                           # TRUTH (#7)
    return "admit", finding


def add_finding(mid: str, finding: dict) -> FindingWriteId:
    """Persist a CONFIRMED finding — a write chokepoint, so the central finding-gate is enforced here
    for EVERY producer (deterministic tools, the model's store_finding, API paths):
      * schema-normalize (reproduction_steps -> list, safe defaults)   [#6]
      * REJECT a finding whose target is provably out of the mission scope (returns "" — not written) [#8]
      * ROUTE a lead-confidence finding to the mission's leads list, never the confirmed table          [#7]
    Fail-open on scope only when scope is absent / the target has no host (we block only proven-off-scope).

    RETURNS A `FindingWriteId` — a `str` id (unchanged for every caller that reads it as one) that
    also carries `.verdict` / `.stored`. Q-089: only ONE of the three outcomes above leaves a row, so
    a caller that reports a COUNT must ask `.stored`; the truthiness of the id cannot answer it,
    because a reroute returns the lead's own id."""
    verdict, finding = _gate(mid, finding)
    if verdict == "reject":
        return FindingWriteId("", REFUSED)                # off-scope: refuse to persist (safety #8)
    if verdict == "lead":                                 # not a confirmed finding -> leads (truth #7)
        return FindingWriteId(add_lead(mid, finding), REROUTED)
    fid = finding.get("id") or uuid.uuid4().hex[:12]
    finding["id"] = fid
    _exec("INSERT OR REPLACE INTO findings VALUES(?,?,?,?)",
          (fid, mid, json.dumps(finding), _now()))
    return FindingWriteId(fid, STORED)


def add_lead(mid: str, lead: dict) -> str:
    """Append an UNPROVEN lead to the mission's leads list (mission context), NOT the confirmed-findings
    table. Keeps leads first-class + surfaced in the report's Unconfirmed-Leads section without ever being
    counted as a confirmed finding. Bounded to the most-recent 200. Returns the lead id.

    Q-014: the id is stamped under BOTH `id` and `_lid`. `main._record_execution` writes `_lid` and the
    confirm/dismiss endpoints and `ui/index.html` both address leads by it, so a lead created here — a
    lead the TRUTH invariant (#7) itself produced — was unreachable: the API 404'd it and the UI
    rendered it with no buttons at all. Same value under both keys, so nothing that reads either
    spelling has to change."""
    lid = lead.get("id") or lead.get("_lid") or uuid.uuid4().hex[:12]
    lead["id"] = lid
    lead["_lid"] = lead.get("_lid") or lid
    m = get_mission(mid)
    if not m:
        return lid
    ctx = m.get("context") or {}
    leads = list(ctx.get("leads") or [])
    if not any((l or {}).get("id") == lid for l in leads):
        leads.append(lead)
    ctx["leads"] = leads[-200:]
    update_mission(mid, context=ctx)
    return lid


def get_findings(mid: str) -> list:
    """RAW findings, exactly as the engines stored them — the proof gate has NOT been applied.

    Prefer `get_findings_gated()` for anything a human or a model will read. See its docstring for why
    this distinction is load-bearing.

    Q-102: `observed_at` is attached here, from the row's OWN `created_at`. This statement already
    ORDERED BY that column and did not SELECT it -- the timestamp was used and discarded inside a
    single query, so every consumer downstream had to invent a time or print none. That is the same
    shape as `_cmd` discarding `proc.returncode` and `_key_bits` discarding the key algorithm.

    It is attached only when the finding does not already carry one, because a re-imported or
    replayed finding's own recorded instant beats the moment this database happened to store it. And
    it comes from the ROW, never from `now()`: a report that stamps itself at render time looks
    authoritative while saying nothing about when the evidence was seen."""
    out = []
    for r in _query("SELECT data, created_at FROM findings WHERE mission_id=? ORDER BY created_at",
                    (mid,)):
        f = json.loads(r["data"])
        if isinstance(f, dict) and not f.get("observed_at") and r["created_at"]:
            f["observed_at"] = r["created_at"]
        out.append(f)
    return out


def get_findings_gated(mid: str, enforce_families=None) -> list:
    """Findings with the truth-first proof gate applied: a confirmed-but-unproven item is demoted to a
    lead before any consumer sees it.

    WHY THIS EXISTS AS A SEPARATE ACCESSOR. `proof_schema.demote_unproven` is deliberately
    non-destructive — it rewrites confidence and leaves the row in place — so the gate only helps a
    consumer that actually calls it. It was called in exactly ONE of fourteen places that read findings,
    which meant the risk score, the coverage counts, the AI wrap-up prompt, the retest planner, the
    cross-session memory snapshot and the SARIF/PoC exports all presented demoted rows as confirmed. The
    gate ran, correctly rejected a finding, and almost every consumer ignored the verdict.

    Anything that PRESENTS findings — to a report, an export, a model, a future scan — must read through
    here. Raw access stays available under `get_findings()` for scan-time work (storage, dedupe,
    benchmark sealing) where the un-gated set is the correct input."""
    rows = get_findings(mid)
    try:
        import proof_schema as _ps
        return _ps.demote_unproven(rows, enforce_families)
    except Exception:
        return rows


def get_finding(mid: str, fid: str):
    """One finding scoped to its mission — None if the id doesn't belong to this mission (tenant isolation)."""
    rows = _query("SELECT data FROM findings WHERE mission_id=? AND id=?", (mid, fid))
    return json.loads(rows[0]["data"]) if rows else None


def update_finding(mid: str, fid: str, finding: dict) -> bool:
    """Update a finding ONLY within its own mission — the WHERE clause pins BOTH mission_id AND id so a
    finding id from one mission can never mutate another mission's row (tenant isolation, #10). Returns
    True when a row was actually updated.

    Q-013: this used to be a raw UPDATE. It reached the same table `add_finding` guards, so every
    invariant `add_finding` enforces was bypassable in two calls — POST a clean finding, then PUT it
    with a string `reproduction_steps`, an off-scope target, or `confidence: lead`. All three landed.
    The gate is now evaluated HERE too, with the update-shaped consequence for each verdict:
      * reject (#8 off-scope) -> the write does not happen at all; the stored row keeps its old target
        and False is returned. Moving a finding out of scope is not an edit, it is a new finding at a
        target we are not authorized to report.
      * lead   (#7)           -> the row LEAVES the confirmed-findings table and is appended to the
        mission's leads list. Rewriting the row in place would leave a lead sitting in the confirmed
        table, which is the masquerade the invariant exists to prevent.
      * admit                 -> normal UPDATE of the schema-normalized finding (#6)."""
    verdict, finding = _gate(mid, finding)
    finding["id"] = fid
    if verdict == "reject":
        return FindingUpdateResult(UPDATE_REFUSED)       # off-scope: refuse the write (safety #8)
    if verdict == "lead":
        # only reroute a row that actually belongs to this mission — never let a foreign fid create a
        # lead here (tenant isolation #10 must hold on this branch too).
        if get_finding(mid, fid) is None:
            return FindingUpdateResult(UPDATE_MISSING)
        delete_finding(mid, fid)
        add_lead(mid, finding)                           # demoted out of the confirmed table (truth #7)
        return FindingUpdateResult(UPDATE_REROUTED)
    cur = _exec("UPDATE findings SET data=? WHERE mission_id=? AND id=?", (json.dumps(finding), mid, fid))
    # Q-090-B/C: FOUR outcomes, and the old `bool` collapsed them into two. `False` meant off-scope
    # OR foreign-fid OR no-such-row; `True` meant a real update OR a reroute that DELETED the row.
    # `FindingUpdateResult.__bool__` reproduces the old truthiness byte-for-byte, so this change is
    # invisible to every existing caller — and `.updated`/`.verdict` are now askable by the two
    # handlers that were reporting the wrong thing.
    return FindingUpdateResult(UPDATED if getattr(cur, "rowcount", 0) else UPDATE_MISSING)


def delete_finding(mid: str, fid: str) -> bool:
    """Delete a finding ONLY within its own mission (WHERE mission_id AND id) — cross-mission delete by a
    bare finding id is impossible (tenant isolation, #10). Returns True when a row was actually removed."""
    cur = _exec("DELETE FROM findings WHERE mission_id=? AND id=?", (mid, fid))
    return bool(getattr(cur, "rowcount", 0))


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
    """The mission's events, oldest first -- but when the limit bites, the NEWEST `limit` rows.

    Q-017: this was `ORDER BY id LIMIT ?`, which keeps the OLDEST n and silently discards everything
    after them. MEASURED on mission 54155d4b (1287 rows): `get_logs(limit=500)[-1].ts` was 22:31:01
    against a true last event of 22:35:20 -- the mission view and the backup export both ended four
    minutes early, and a truncated tail looks exactly like a mission that stopped. For a log the
    interesting end is the recent one; a run that died has its cause in the last rows, not the first.

    Two-step rather than a reversed scan in Python: `ORDER BY id DESC LIMIT ?` lets SQLite walk the
    index backwards and stop, so the cost tracks `limit` rather than the mission's whole history, and
    the outer flip restores chronological order for every existing caller. Callers see the same shape
    and the same ordering they always did -- only WHICH rows survive truncation changes.
    """
    rows = _query("SELECT etype,data,created_at FROM ("
                  "  SELECT id,etype,data,created_at FROM logs WHERE mission_id=? "
                  "  ORDER BY id DESC LIMIT ?"
                  ") ORDER BY id", (mid, limit))
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
