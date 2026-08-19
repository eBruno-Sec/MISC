"""Q-081 anti-idle — the KEY-reachability predicate, applied to the WSTG taxonomy tables.

Q-081's shape, stated once: **a guard validates one field of a record thoroughly while never testing
whether the record can reach a consumer at all.** `effects_audit` had it (three checks on the engine,
none on the key). This file pins the same predicate one registry over.

`wstg_catalog.coverage()` iterates `CATALOG.items()` and buckets each id from `FULL` / `PARTIAL` /
`EXCLUDED`. So:

  * a `FULL`/`PARTIAL`/`EXCLUDED` key outside `CATALOG` is **read by nothing** — the coverage
    statement never sees it and the tally never counts it. Same inertness as an `EFFECTS` row keyed
    on a non-technique.
  * an id in two maps at once makes the coverage bucket depend on the `elif` ORDER in `coverage()`
    rather than on the declaration, which is a silent tie-break nobody wrote down.
  * a technique record's `wstg` field is a SECOND, independent declaration of the same taxonomy fact,
    and `routes()` already resolves `wstg_catalog.FULL[rec["wstg"]]` to derive an engine from it. An
    id claimed there and absent from `CATALOG` is a claim against a test that does not exist.

MEASURED before any of this was written (probe output in `docs/handoff/audit_key.md` §7): the three
hard faults are at **0**, and the reported one is at **3** — `WSTG-CLNT-11`, `WSTG-CLNT-13` and
`WSTG-INPV-16` are claimed by `jsonp_info_leak`, `csti` and `crlf_injection` while `coverage()`
reports each as `none` / "not yet implemented".

**THE NEGATIVE CONTROLS COME FIRST IN THIS FILE, AND THEY CAME FIRST IN TIME.** Q-081 exists because
the Q-074 lane wrote one before trusting the guard it was exercising and the control found the hole.
A guard whose fault lists are empty on the shipped tree is indistinguishable from a guard that cannot
fail, and this codebase has shipped that eleven times — so every fault list below is fired
deliberately with an injected table before the shipped zero is allowed to mean anything.
"""
import copy

import engine_descriptor as ed
import techniques as T
import wstg_catalog as W


def _tables():
    """The shipped tables, copied so a mutation cannot leak between tests."""
    return {"catalog": dict(W.CATALOG), "full": dict(W.FULL), "partial": dict(W.PARTIAL),
            "excluded": dict(W.EXCLUDED), "techniques": copy.deepcopy(T.TECHNIQUES)}


# A WSTG id that is genuinely not in the catalog. Asserted, never assumed — the whole file is
# worthless if this happens to be a real id.
FAKE_ID = "WSTG-APOL-99"


# ── NEGATIVE CONTROLS: each fault list, fired on purpose ────────────────────────────────────────

def test_control_the_fake_id_is_really_absent():
    """The premise every control below rests on."""
    assert FAKE_ID not in W.CATALOG
    assert FAKE_ID not in W.FULL and FAKE_ID not in W.PARTIAL and FAKE_ID not in W.EXCLUDED


def test_a_FULL_key_outside_the_catalog_fails():
    """The exact Q-081 shape: a row declaring a confirming engine for a test `coverage()` never
    reads. It would raise the product's apparent coverage in the reader's mind and change no number."""
    t = _tables()
    t["full"][FAKE_ID] = "run_csrf"
    a = ed.wstg_audit(**t)
    assert a["ok"] is False, a
    assert a["map_keys_outside_catalog"] == ["FULL -> %s" % FAKE_ID], a["map_keys_outside_catalog"]
    # attributable to the one fault: nothing else fired
    assert a["maps_overlap"] == []
    assert a["claimed_ids_outside_catalog"] == []


def test_a_PARTIAL_key_outside_the_catalog_fails():
    t = _tables()
    t["partial"][FAKE_ID] = "something touches it"
    a = ed.wstg_audit(**t)
    assert a["ok"] is False
    assert a["map_keys_outside_catalog"] == ["PARTIAL -> %s" % FAKE_ID]


def test_an_EXCLUDED_key_outside_the_catalog_fails():
    """An exclusion is a REFUSAL with a stated reason. One keyed on a nonexistent id is a safety
    promise about nothing, which is worse than untidy — it reads as due diligence."""
    t = _tables()
    t["excluded"][FAKE_ID] = "refused on safety grounds"
    a = ed.wstg_audit(**t)
    assert a["ok"] is False
    assert a["map_keys_outside_catalog"] == ["EXCLUDED -> %s" % FAKE_ID]


def test_an_id_in_two_maps_at_once_fails():
    """`coverage()` resolves this by `if FULL / elif PARTIAL / else`, so the winner is decided by
    statement order and not by anything anyone declared."""
    t = _tables()
    wid = sorted(t["full"])[0]
    t["partial"][wid] = "also claimed here"
    a = ed.wstg_audit(**t)
    assert a["ok"] is False
    assert a["maps_overlap"] == ["%s in FULL and PARTIAL" % wid], a["maps_overlap"]
    assert a["map_keys_outside_catalog"] == []


def test_a_technique_claiming_an_id_outside_the_catalog_fails():
    """The technique registry's `wstg` column is the second declaration of the same fact, and
    `routes()` derives an engine from it. A claim against an id the catalog does not define can
    never be confirmed or refuted by anything."""
    t = _tables()
    t["techniques"]["csrf"] = dict(t["techniques"]["csrf"], wstg=FAKE_ID)
    a = ed.wstg_audit(**t)
    assert a["ok"] is False
    assert a["claimed_ids_outside_catalog"] == ["csrf -> %s" % FAKE_ID]
    assert a["map_keys_outside_catalog"] == []


def test_the_audit_fails_closed_when_a_fact_table_cannot_be_read():
    """An unreadable catalog makes EVERY claim look unknown. That is an INSTRUMENT failure and must
    fail closed rather than report itself as 47 findings — the same rule `effects_audit` learned when
    `bool(known)` joined its non-vacuity clause."""
    t = _tables()
    t["catalog"] = {}
    a = ed.wstg_audit(**t)
    assert a["ok"] is False
    assert a["catalog_size"] == 0

    t = _tables()
    t["techniques"] = {}
    a = ed.wstg_audit(**t)
    assert a["ok"] is False
    assert a["checked"] == 0


# ── THE NEGATIVE CONTROL DoD 2 ASKS FOR: a clean table must still PASS ───────────────────────────

def test_a_clean_table_still_passes():
    """A guard that rejects everything is not a fix. This project has already paid once for a fix
    that traded one error class for the other, so the shipped tree passing is asserted as its own
    fact and not inferred from the mutants failing."""
    a = ed.wstg_audit(**_tables())
    assert a["ok"] is True, a
    assert a["map_keys_outside_catalog"] == []
    assert a["maps_overlap"] == []
    assert a["claimed_ids_outside_catalog"] == []


def test_a_newly_added_clean_row_passes_too():
    """Stronger than the row above: the guard accepts a row it has never seen, so `ok` is not
    passing because the shipped tables happen to be memorised."""
    t = _tables()
    wid = sorted(set(t["catalog"]) - set(t["full"]) - set(t["partial"]) - set(t["excluded"]))[0]
    t["full"][wid] = "run_csrf"
    a = ed.wstg_audit(**t)
    assert a["ok"] is True, a


# ── NON-VACUITY: the instrument was looking ─────────────────────────────────────────────────────

def test_the_audit_actually_read_the_tables():
    a = ed.wstg_audit()
    assert a["catalog_size"] == 109, a["catalog_size"]
    assert a["checked"] > 40, "the technique wstg column was not read"
    assert a["full_size"] + a["partial_size"] + a["excluded_size"] > 80


# ── THE REPORTED FAULT, PINNED SO IT CAN ONLY CHANGE DELIBERATELY ───────────────────────────────

# MEASURED 2026-08-19 on an isolated snapshot of HEAD. Every one of these is in CATALOG and in none
# of the three maps, so `coverage()` buckets it `none` / "not yet implemented" while a technique with
# an oracle claims it. REPORTED and not asserted into `ok`, for the reason `differs_from_derived_route`
# and `routing_audit()["unrouted"]` get the same treatment: `FULL` is deliberately conservative
# ("only where a deterministic confirming engine exists"), so a technique's claim is not by itself
# proof that a confirming engine exists, and failing here would punish the more honest catalog.
#
# Two of the three look like the TECHNIQUE record being wrong rather than the catalog, which is
# exactly why this is a lead and not a verdict:
#   * csti claims WSTG-CLNT-13 "Cross Site Script Inclusion" — but CSTI is client-side TEMPLATE
#     injection, a different test.
#   * crlf_injection claims WSTG-INPV-16 and `routes()` derives NO engine for it at all.
CLAIMED_BUT_UNMAPPED_2026_08_19 = [
    "crlf_injection -> WSTG-INPV-16",
    "csti -> WSTG-CLNT-13",
    "jsonp_info_leak -> WSTG-CLNT-11",
]


def test_the_claimed_but_unmapped_set_is_exactly_the_measured_one():
    """A pin, not an oracle. It moves when someone decides it should — by mapping the id in
    `wstg_catalog` or by correcting the technique's `wstg` field — and never by accident."""
    a = ed.wstg_audit()
    assert a["claimed_but_unmapped"] == CLAIMED_BUT_UNMAPPED_2026_08_19, a["claimed_but_unmapped"]
    assert a["ok"] is True, "the reported list must NOT be in the ok clause"


def test_the_reported_list_can_grow_and_still_not_fail_the_audit():
    """The half of the pin above that a passing shipped tree cannot demonstrate: `claimed_but_unmapped`
    is genuinely outside `ok`, rather than empty-and-therefore-harmless."""
    t = _tables()
    wid = sorted(set(t["catalog"]) - set(t["full"]) - set(t["partial"]) - set(t["excluded"]))[0]
    t["techniques"]["csrf"] = dict(t["techniques"]["csrf"], wstg=wid)
    a = ed.wstg_audit(**t)
    assert "csrf -> %s" % wid in a["claimed_but_unmapped"]
    assert a["ok"] is True, "a reported fault must not silently become an asserted one"
