"""Staged intel-knowledge promotion (#114): candidate -> validating -> validated -> fixture_backed ->
reviewed -> production, ONE gated step at a time. Internet intel stays UNTRUSTED (candidate) until it
earns each promotion with EVIDENCE; auto-promotion into production is PROHIBITED (production requires a
human reviewer). Deterministic in-memory store. No contamination: a guess never silently becomes trusted.
"""
from __future__ import annotations

import time
from collections import Counter

import intel_sources as _src

_STORE: dict = {}          # rec_id -> record (carries validation_state, evidence, history)
_LAST_PASS: dict = {}      # the last corroborate() result, so an empty registry can say WHY

_CONF = {"candidate": 0.3, "validating": 0.35, "validated": 0.55, "fixture_backed": 0.7,
         "reviewed": 0.85, "production": 0.95, "rejected": 0.0}


def reset():
    _STORE.clear()
    _LAST_PASS.clear()


def _rid(rec: dict) -> str:
    return "%s|%s|%s" % (rec.get("source"), rec.get("cve") or (rec.get("references") or [""])[0],
                         rec.get("source_type"))


def ingest(records: list) -> int:
    """Add ingested provenance records as CANDIDATES (dedup by id). Ingest is ALWAYS candidate — an
    ingested record can never enter above candidate, no matter what state it claims.

    ENTRY is candidate and stays candidate: every record is stored by the loop below before anything
    can promote it. `corroborate()` then runs as a SEPARATE, evidence-carrying pass over the store —
    it cannot admit a record and it cannot skip a rung, because it goes through `advance()` like any
    other caller. Q-021D: this call is what gives the promotion ladder a driver in product code.
    Before it, `advance()` had callers in `agent/tests/test_intel_registry.py` only, so `production()`
    was structurally always empty and any consumer wired to it read `[]` forever while its test
    stayed green."""
    n = 0
    for r in records or []:
        rid = _rid(r)
        if rid in _STORE:
            continue
        rec = dict(r)
        rec["validation_state"] = "candidate"
        rec["confidence"] = _CONF["candidate"]
        rec["_id"] = rid
        rec["_history"] = [["candidate", time.time()]]
        _STORE[rid] = rec
        n += 1
    if n:
        corroborate()          # one snapshot read per ingest call, not per record
    return n


def advance(rec_id: str, to_state: str, *, evidence=None, reviewed_by: str = None):
    """Advance one record exactly ONE gated step. Returns (ok, reason). Anti-contamination requirements:
      validated       -> needs deterministic validation `evidence`
      fixture_backed  -> needs a regression `evidence` (fixture)
      production      -> needs a human `reviewed_by` (internet intel never auto-promotes to production)."""
    rec = _STORE.get(rec_id)
    if not rec:
        return False, "unknown record"
    frm = rec["validation_state"]
    if not _src.can_promote(frm, to_state):
        return False, "illegal transition %s -> %s (one gated step only, no queue-jump)" % (frm, to_state)
    if to_state == "validated" and not evidence:
        return False, "validated requires deterministic validation evidence"
    if to_state == "fixture_backed" and not evidence:
        return False, "fixture_backed requires a regression fixture"
    if to_state == "production" and not reviewed_by:
        return False, "production requires a human reviewer (no auto-promotion of internet intel)"
    rec["validation_state"] = to_state
    rec["confidence"] = _CONF.get(to_state, rec.get("confidence", 0.3))
    rec["_history"].append([to_state, time.time()])
    if evidence:
        rec.setdefault("_evidence", []).append(str(evidence)[:200])
    if reviewed_by:
        rec["reviewed_by"] = reviewed_by
    return True, "ok"


# ── Q-021D: the promotion path ────────────────────────────────────────────────────────────────
#
# #114 built the trust ladder and stopped before anything could climb it. What makes a candidate
# climb is NOT a heuristic and NOT a second read of the feed that produced it: it is a SECOND,
# INDEPENDENT, LOCALLY-HELD tier-A catalogue that names the same exact CVE.
#
# The one that exists offline today is the CISA KEV snapshot on disk — `intel_feeds.load()` ->
# `kev["cves_meta"]`, a dict of 1656 CVE ids each carrying the product CISA names, alongside
# `manifest["refreshed_at"]`, a real snapshot stamp. A record from `nvd` / `ghsa` / `cve_v5` whose
# exact CVE is in that catalogue has been witnessed by a source that did not produce it.
#
# INDEPENDENCE IS A RULE HERE, not a comment, because the alternative is a catalogue corroborating
# itself: a record whose own `source` is `cisa_kev` can never be witnessed by the KEV snapshot. KEV
# is already loaded twice in this codebase (the `intel_feeds` snapshot and
# `intel_connectors._parse_kev`), and without this rule the second copy would silently validate the
# first.
#
# EXACT CVE ONLY. `intel_feeds.known_exploited_cwes` carries the standing warning that a CWE in KEV
# does not make an arbitrary finding of that class KEV-listed. Corroboration here matches the CVE id
# and nothing else — never the CWE, never the product name alone.
#
# WHERE THIS DELIBERATELY STOPS: at `validated`. `fixture_backed` needs a regression fixture and
# `production` needs a human `reviewed_by`; both stay explicit `advance()` calls, because
# "auto-promote internet intel into executable production skills" is on `intel_sources.PROHIBITED`
# and that rule is right. This pass raises the ladder's ceiling from "nothing" to `validated`.

def _kev_witness(snapshots):
    """(cve -> catalogue entry, stamp) from the LOCAL CISA KEV snapshot.

    Returns `({}, stamp)` when no snapshot is on disk. A cold read is REPORTED by the caller, never
    reported as "nothing is known-exploited" — an empty catalogue and a catalogue that matched
    nothing are different facts and the caller must be able to tell them apart."""
    kev = (snapshots or {}).get("kev") or {}
    man = (snapshots or {}).get("manifest") or {}
    stamp = {"source": "cisa_kev", "via": "local snapshot (intel_feeds)",
             "catalog_version": kev.get("catalog_version"),
             "snapshot_at": man.get("refreshed_at")}
    return (kev.get("cves_meta") or {}), stamp


def corroborate(snapshots=None) -> dict:
    """The evidence-carrying promotion pass: candidate -> validating -> validated, ONE gated
    `advance()` call per step, never further. Offline: reads a local snapshot, makes no request.

    `validating` means EXAMINED — every candidate the pass looks at moves there, and a record with no
    independent witness STAYS there. That is the load-bearing part: `validating` is not a waypoint
    that everything drifts through, it is where uncorroborated intel stops.

    Idempotent: re-running re-examines `validating` records against the current snapshot, so a
    refreshed catalogue can validate a record the previous pass could not."""
    if snapshots is None:
        import intel_feeds as _feeds
        snapshots = _feeds.load()
    meta, stamp = _kev_witness(snapshots)
    res = {"status": "ok", "examined": 0, "validated": 0, "unwitnessed": 0, "same_source": 0,
           "catalog": len(meta), "witness": stamp}
    if not meta:
        # NON-VACUITY: nothing was examined because there was nothing to examine WITH. Saying
        # "0 validated" here without this status would read exactly like "nothing corroborated".
        res.update(status="no_witness_snapshot",
                   note="no local CISA KEV snapshot on disk; nothing examined, nothing advanced")
        _LAST_PASS.clear()
        _LAST_PASS.update(res)
        return res
    for rec in list(_STORE.values()):
        state = rec["validation_state"]
        if state not in ("candidate", "validating"):
            continue
        if state == "candidate":
            ok, _why = advance(rec["_id"], "validating",
                               evidence="examined against %s %s" % (stamp["source"],
                                                                    stamp.get("catalog_version")))
            if not ok:
                continue
        res["examined"] += 1
        if str(rec.get("source") or "") == "cisa_kev":
            # same catalogue on both sides — not a second opinion. Stays at `validating`.
            res["same_source"] += 1
            continue
        cve = str(rec.get("cve") or "").strip().upper()
        hit = meta.get(cve) if cve else None
        if not hit:
            res["unwitnessed"] += 1
            continue
        product = str((hit or {}).get("product") or "").strip()
        ok, _why = advance(rec["_id"], "validated",
                           evidence="exact CVE %s independently listed by %s (catalog %s, snapshot_at "
                                    "%s) as %s" % (cve, stamp["source"], stamp.get("catalog_version"),
                                                   stamp.get("snapshot_at"), product or "unnamed product"))
        if ok:
            # the product string is the one the CATALOGUE observed, not one derived from the record.
            rec["witness"] = dict(stamp, cve=cve, product=product,
                                  ransomware=bool((hit or {}).get("ransomware")))
            res["validated"] += 1
    _LAST_PASS.clear()
    _LAST_PASS.update(res)
    return res


def by_state(state: str) -> list:
    return [r for r in _STORE.values() if r["validation_state"] == state]


# The ladder as an ORDER, derived from the one public definition of the states so the two can never
# drift. `rejected` is the LAST element of `intel_sources.VALIDATION_STATES`, which makes its index
# the HIGHEST — a plain `index >= threshold` comparison would rank a rejected record above a
# production one. It is excluded by name everywhere below, deliberately and not by luck.
_ORDER = {s: i for i, s in enumerate(_src.VALIDATION_STATES)}


def trusted(min_state: str = "validated") -> list:
    """Records at or above `min_state`, strongest rung first. THE CONSUMER READS THIS.

    `production()` alone is not a usable consumer contract: production requires a human reviewer, so a
    consumer wired to it reads `[]` on every unattended run. Reading `validated`-and-above lets
    corroborated intel be used while the `confidence` weight (`_CONF`) still keeps a `candidate` from
    ever outranking a `fixture_backed` record — the ordering below is that rule made explicit."""
    lo = _ORDER.get(min_state)
    if lo is None:
        return []
    out = []
    # Walk the rungs from the top down, `rejected` never among them. Built out of `by_state` rather
    # than one filtered comprehension so the rung set is enumerated explicitly and the ordering is a
    # consequence of the walk instead of a second, separately-maintained sort key.
    for rung in reversed(_src.VALIDATION_STATES[lo:]):
        if rung == "rejected":
            continue
        out.extend(sorted(by_state(rung), key=lambda r: str(r.get("cve") or "")))
    return out


def production() -> list:
    """Only PRODUCTION-state records are trusted knowledge safe to drive engines.

    Expressed through `trusted()` so "at or above this rung" has exactly one definition; production is
    the top non-rejected rung, so the returned set is unchanged."""
    return trusted("production")


def stats() -> dict:
    """Registry census, and WHY it reads the way it does. Served by `GET /intel/registry`.

    `{'total': 0, 'by_state': {}}` is the exact output that made three separate readings of this
    module conclude the trust ladder was broken. It was never wrong, it was mute: a store that is
    empty because every source is switched off looks identical to one that fetched and found
    nothing, and both look identical to one that lost its contents at the last restart. The three
    fields below make an empty registry state which of those it is - the labelled-empty contract, so
    a consumer cannot read silence as a clean result.

      store            the persistence honesty. This IS a per-process in-memory dict; it does not
                       survive a restart, and saying so beats implying durability it does not have.
      state            populated / cold / disabled.
      last_pass        the last `corroborate()` result, or {} if the promotion pass has never run in
                       this process. `validated: 0` next to `catalog: 0` means the witness catalogue
                       was missing, which is a different fact from 'nothing corroborated'."""
    counts = dict(Counter(r["validation_state"] for r in _STORE.values()))
    enabled = _src.enabled_sources()
    if _STORE:
        state, why = "populated", "%d records ingested in this process" % len(_STORE)
    elif not enabled:
        state, why = "disabled", ("every intel source is disabled (the default), so nothing has been "
                                  "fetched; this is a configuration state, not a clean result")
    else:
        state, why = "cold", ("sources are enabled but nothing has been fetched into this process "
                              "yet; the store does not survive a restart")
    return {"total": len(_STORE), "by_state": counts,
            "store": "in-memory, per-process; NOT persisted across a restart",
            "state": state, "why": why, "enabled_sources": enabled,
            "last_pass": dict(_LAST_PASS)}
