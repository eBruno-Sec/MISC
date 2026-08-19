"""Q-074 run 4 — an effect's KEY must be a technique that exists, not only its engine.

THE HOLE, MEASURED BEFORE ANY OF THIS WAS WRITTEN. `effects_audit` interrogated the declared ENGINE
three independent ways (declared at all / registered / implemented) and never once interrogated the
KEY. So this entry passed with `ok=True`:

    "csrf_token_missing": {"establishes": [], "invalidates": ["authenticated"],
                           "engine": ["run_csrf"]}

`run_csrf` is a real, registered, implemented, dispatchable engine, so every existing check was
satisfied. `csrf_token_missing` is not a technique. MEASURED consequences of that entry, on the live
platform, at the same moment the guard said `ok=True`:

    effects_audit ok        : True          <- the guard is happy
    build() descriptors     : 88, and 'csrf_token_missing' is NOT among them
    conflicts() rows        : 6, producers  ['race_condition']   <- unchanged

`build()` walks `TECHNIQUES`, so a row keyed on a non-technique never becomes a descriptor and no
consumer ever sees it. **The declaration is silently inert and passes the guard** — which is the
Q-007 defect in different clothes: a claim recorded as a fact that nothing can act on. The whole point
of Q-007's guard was that a declaration must be checked against a fact table; the key was the one
field it took on trust.

THE NEGATIVE CONTROLS COME FIRST, and they were run as file-level mutants before the fix was trusted
(`docs/handoff/effects4.md` section 5). A guard written against a near-empty set is the easiest kind
to satisfy vacuously, and this codebase has shipped declaration-checking guards ten times.
"""
import copy

import engine_descriptor as ed
import techniques as T


# A real, registered, implemented, dispatchable engine — so the ENGINE half of the guard cannot be
# what fails. Taken from the tree, not invented: it is the engine `routes()` derives for technique
# `csrf`, and it is one of the four Q-074 run 4 measured destroying a mission session.
REAL_ENGINE = "run_csrf"


def _entry(tid, engine=REAL_ENGINE):
    return {tid: {"establishes": [], "invalidates": ["authenticated"], "engine": [engine]}}


# ── NEGATIVE CONTROLS ───────────────────────────────────────────────────────────────────────────

def test_the_guard_fails_on_a_key_that_is_not_a_technique():
    """The measured hole. A plausible name + a REAL engine used to return ok=True."""
    assert REAL_ENGINE in ed.engine_registry(), "control: the engine must be real, or this proves nothing"
    assert REAL_ENGINE in ed.engine_implementations()
    assert "csrf_token_missing" not in T.TECHNIQUES, "control: the key must genuinely not be a technique"

    dirty = copy.deepcopy(ed.EFFECTS)
    dirty.update(_entry("csrf_token_missing"))
    a = ed.effects_audit(effects=dirty)
    assert a["ok"] is False, a
    assert a["unknown_technique"] == ["csrf_token_missing"], a["unknown_technique"]
    # and the engine half stayed silent, so the failure is attributable to the KEY alone
    assert a["unregistered"] == []
    assert a["unimplemented"] == []
    assert a["no_engine_declared"] == []


def test_the_guard_fails_on_a_key_that_is_a_near_miss_of_a_real_technique():
    """Near-miss spelling is the shape that fails SILENTLY and in the flattering direction — four of
    the six Q-048 objectives that could not fail failed exactly this way (`default_creds` vs
    `default_credentials`). `csrf` IS a technique; `csrf_token` is not."""
    assert "csrf" in T.TECHNIQUES, "control: the correctly-spelled id must exist"
    dirty = copy.deepcopy(ed.EFFECTS)
    dirty.update(_entry("csrf_token"))
    a = ed.effects_audit(effects=dirty)
    assert a["ok"] is False, a
    assert a["unknown_technique"] == ["csrf_token"]


def test_an_unknown_key_with_no_engine_reports_BOTH_faults():
    """The check runs before the `no_engine_declared` continue, so one fault cannot mask the other."""
    dirty = copy.deepcopy(ed.EFFECTS)
    dirty["not_a_technique_at_all"] = {"establishes": [], "invalidates": ["authenticated"]}
    a = ed.effects_audit(effects=dirty)
    assert a["ok"] is False
    assert a["unknown_technique"] == ["not_a_technique_at_all"]
    assert a["no_engine_declared"] == ["not_a_technique_at_all"]


def test_the_guard_fails_closed_when_the_technique_table_cannot_be_read():
    """An unreadable technique table makes EVERY key unknown. That is an INSTRUMENT failure and must
    not be reported as a clean sheet OR as 12 findings — it must fail closed, like the other two fact
    tables already do."""
    a = ed.effects_audit(techniques={})
    assert a["ok"] is False
    assert a["technique_table_size"] == 0


def test_the_two_engine_checks_still_fail_independently_of_the_new_one():
    """The new check must not have become the only one that can fire. A REAL technique key pointed at
    an invented engine still fails, with `unknown_technique` empty."""
    dirty = copy.deepcopy(ed.EFFECTS)
    dirty.update(_entry("csrf", engine="run_apolaki_not_an_engine"))
    a = ed.effects_audit(effects=dirty)
    assert a["ok"] is False
    assert a["unknown_technique"] == [], "the key is a real technique; only the engine is a phantom"
    assert a["unregistered"] == ["csrf -> run_apolaki_not_an_engine"]
    assert a["unimplemented"] == ["csrf -> run_apolaki_not_an_engine"]


# ── THE SHIPPED TREE ────────────────────────────────────────────────────────────────────────────

def test_every_shipped_effects_key_is_a_real_technique():
    a = ed.effects_audit()
    assert a["ok"] is True, a
    assert a["unknown_technique"] == []
    assert a["technique_table_size"] > 80, "non-vacuity: the technique table was actually read"
    assert set(ed.EFFECTS) <= set(T.TECHNIQUES)


def test_every_shipped_effects_key_survives_into_a_descriptor():
    """The fact the guard now protects, asserted directly rather than through the guard. An entry
    whose key is not a technique is dropped by `build()` without a word; this pins that no shipped
    entry is being dropped that way."""
    built = ed.build()
    missing = sorted(set(ed.EFFECTS) - set(built))
    assert missing == [], f"declared an effect on {missing}, which build() does not emit"


def test_a_non_technique_key_is_measurably_inert_which_is_why_the_guard_is_needed():
    """The justification for the check above, kept as a measurement rather than as prose: the reason a
    bad key is dangerous is precisely that NOTHING downstream complains about it."""
    saved = copy.deepcopy(ed.EFFECTS)
    try:
        ed.EFFECTS.update(_entry("csrf_token_missing"))
        assert "csrf_token_missing" not in ed.build(), "build() silently drops it"
        assert {r[0] for r in ed.conflicts()} == {"race_condition"}, "conflicts() never sees it"
    finally:
        ed.EFFECTS.clear()
        ed.EFFECTS.update(saved)
    assert ed.effects_audit()["ok"] is True, "restore control"
