"""`validated_on` - is it a measurement or a string somebody typed? (VALIDATED BREAKER lane, #123)

MEASURED ANSWER: it is typed. An `ast` walk over the tree finds 54 production producers, all of them
literal `_t(validated_on=[...])` keyword arguments. Nothing derives the value from a run. The
liveness machinery writes a SEPARATE, honest artifact (`tests/liveness_baseline.json`), and
`techniques.technique_status()` correctly reads THAT for the UI's "proven" stat.

The defect is that the fix stopped there. Three other modules still run the old
`"proven" if validated_on` rule, so the same product reports 48 and 16 as "proven", and a hand-typed
string reorders 40 of 42 techniques in a live scan plan.

WHAT THIS FILE IS
-----------------
Two kinds of test, kept apart on purpose:

  * PASSING tests pin the COUPLING that is genuinely intended (score is a function of lab count) and
    the parts of the honesty model that already work (technique_status, the claimed/proven split).
    They must keep passing after any fix.

  * STRICT XFAILS are the measured defects, executable rather than prose in a hand-off. Each asserts
    the property that SHOULD hold. The day a Builder fixes one it XPASSes, the suite goes red, and
    the marker has to be removed deliberately - the defect cannot be quietly forgotten. This is the
    same device used by test_sweep_class_coverage.py (Q-047) and test_sqli_boolean_noise_floor.py.

NOTHING HERE WEAKENS AN EXISTING GATE. The five existing per-lab guards are left untouched; they are
measured, not modified. See docs/handoff/validated.md for the full census.
"""
from __future__ import annotations

import ast
import json
import os

import pytest

import techniques as T
import technique_model as TM
import technique_planner as TP

_HERE = os.path.dirname(os.path.abspath(__file__))
_AGENT = os.path.dirname(_HERE)

# The fabricated claim: two lab ids that name nothing, anywhere, ever.
FABRICATED = {
    "id": "fabricated_negative_control",
    "vuln_class": "sql_injection", "cwe": "CWE-89", "owasp": "A03:2021",
    "permission": T.ACTIVE, "transferable": True,
    "summary": "negative control", "detect": "n/a", "exploit": "n/a", "oracle": "n/a",
    "validated_on": ["fabricated_lab_9000", "fabricated_lab_9001"],
}


def _claims():
    """{technique id -> validated_on} for every record that claims one."""
    return {t["id"]: list(t["validated_on"]) for t in T.TECHNIQUES.values() if t.get("validated_on")}


def _known_lab_ids():
    """Every lab id the agent's own registries can resolve to a real target definition.

    Q-088: this used to reimplement a SUBSET of the real vocabulary (just the three target
    registries), so it disagreed with the product's own `techniques.known_labs()`, which also
    counts a lab as legal once a liveness RUN has actually confirmed a technique against it
    (domsource, openfmb) -- a lab nobody wired into benchmark.py/bench_all.py/labs.py but that a
    real run demonstrably reached. Re-implementing a stale copy of the rule instead of calling the
    real one is the exact shape this file's own `test_packs_and_techniques_now_report_the_SAME_
    proven_number` docstring warns about ("a test that reads prose tests prose"). Call the product
    function directly so this test measures what the product actually accepts, not a stand-in."""
    return set(T.known_labs())


# ══════════════════════════════════════════════════════════════════════════════════════════
# PASSING - the measurement itself, and the parts that already work
# ══════════════════════════════════════════════════════════════════════════════════════════

def test_every_production_producer_of_validated_on_is_a_hand_typed_literal():
    """THE CORE MEASUREMENT. Walk techniques.py with `ast` and confirm no value is ever computed.

    Structure matters here and a regex would lie: a keyword argument, a dict-literal key and a
    subscript store are three different producers. If a Builder later derives the field from the
    liveness ledger, this test fails - and that failure is the good news, not a regression.
    """
    src = open(os.path.join(_AGENT, "techniques.py"), encoding="utf8").read()
    tree = ast.parse(src)
    literal, computed = [], []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != "validated_on":
                continue
            try:
                ast.literal_eval(kw.value)
                literal.append(kw.value.lineno)
            except Exception:
                computed.append(kw.value.lineno)
    assert literal, "no validated_on producers found - the census would be vacuous"
    assert len(literal) >= 50, len(literal)
    assert computed == [], (
        "A validated_on value is now COMPUTED at lines %s. If that computation reads the liveness "
        "ledger, the defect this file pins is fixed: delete this test and the xfails below." % computed)


#: Liveness checks that assert a platform CAPABILITY rather than a vulnerability technique. Each one
#: is listed deliberately: an entry here is a statement that the id has no typed claim to carry and
#: never will, so adding one is a decision rather than an oversight.
_NON_TECHNIQUE_LIVENESS = {
    # Q-113/Q-109: the crawl grew the surface and every endpoint it produced was addressable.
    "surface_discovery",
    # Q-126/Q-021B: a persisted TechnologyFact is a recon observation, never a confirmed
    # vulnerability by that ticket's own design -- there is no lab to validate a "technique" of
    # detection against, only wiring to prove still carries a version to `recon["technology"]`.
    "technology_detection",
}


def test_the_liveness_ledger_is_the_only_run_derived_record():
    """The honest artifact exists and is disjoint in kind from the typed field: liveness_baseline.json
    is WRITTEN BY A RUN, validated_on is written by a human. Both name techniques; only one is earned."""
    base = json.load(open(os.path.join(_HERE, "liveness_baseline.json"), encoding="utf8"))
    live = set(base.get("live") or [])
    assert live, "empty liveness baseline would make every claim below vacuous"

    # Not every liveness check is a vulnerability TECHNIQUE. `surface_discovery` asserts REACH -- the
    # crawl grew the surface and every endpoint it produced was addressable -- which is a capability
    # of the platform, not a technique with labs to validate against, so it has no typed claim to
    # carry and never will. The allowlist is EXPLICIT rather than an intersection so that a genuinely
    # new technique cannot slip out of the assertion below by being absent from `TECHNIQUES`.
    unclassified = live - set(T.TECHNIQUES) - _NON_TECHNIQUE_LIVENESS
    assert not unclassified, (
        "a liveness id is neither a technique nor a declared capability check, so nothing checks "
        "whether it carries a typed claim: %s" % sorted(unclassified))

    proven = live & set(T.TECHNIQUES)
    claims = _claims()
    # every liveness-earned TECHNIQUE also carries a typed claim -> the two ledgers do not
    # contradict, the typed one is simply a superset. That is the honesty debt, and it is reportable.
    assert proven <= set(claims), sorted(proven - set(claims))
    assert len(claims) > len(proven), (len(claims), len(proven))


def test_technique_status_is_the_fixed_rule_and_still_holds():
    """Q-012 applied correctly. NOT a defect - pinned so a later change cannot quietly undo it."""
    v = T.taxonomy_view("owasp")
    assert v["proven"] == len(T._liveness_verified() & set(T.TECHNIQUES))
    assert v["claimed"] == len(_claims())
    assert v["unverified"] == v["claimed"] - v["proven"]
    assert v["claimed"] > v["proven"], "the gap IS the honesty debt; collapsing it would hide the defect"


def test_planner_confidence_is_a_function_of_lab_COUNT():
    """The intended coupling, pinned. `registry_seed` ranks by how many labs a technique names.
    That rule is fine; what is not fine is that the input is typed (see the xfails)."""
    seed = {s["id"]: s for s in TP.registry_seed()}
    for tid, labs in _claims().items():
        exp = 60 if len(set(labs)) >= 2 else 40
        assert seed[tid]["confidence"]["score"] == exp, (tid, labs)
    for tid in set(T.TECHNIQUES) - set(_claims()):
        assert seed[tid]["confidence"]["score"] == 20, tid


def test_the_existing_per_lab_guards_only_fail_on_REMOVAL():
    """The five existing guards assert `lab in validated_on`. That is a MEMBERSHIP test: it fails when
    a claim is deleted and cannot fail when one is added. Demonstrated directly, so the direction is
    recorded as a fact rather than as an opinion in a document."""
    tid = "modbus_exposed"            # guarded by test_ics_real_stack.py:188
    rec = T.TECHNIQUES[tid]
    original = list(rec["validated_on"])
    try:
        # ADDING a fabricated lab: the existing guard's assertion still holds.
        rec["validated_on"] = original + ["fabricated_lab_9000"]
        assert "conpot" in rec["validated_on"], "the existing guard's exact assertion"
        # REMOVING the real one: only now does it fail.
        rec["validated_on"] = ["fabricated_lab_9000"]
        assert "conpot" not in rec["validated_on"]
    finally:
        rec["validated_on"] = original
    assert T.TECHNIQUES[tid]["validated_on"] == original, "registry must be restored"


# ══════════════════════════════════════════════════════════════════════════════════════════
# STRICT XFAILS - the measured defects. Each XPASSes the moment it is fixed.
# ══════════════════════════════════════════════════════════════════════════════════════════

_Q_VOCAB = ("Q-088 (owner: unassigned). RE-MEASURED 2026-08-29: techniques.known_labs() now derives the vocabulary "
            "honestly (target registries + liveness-vouched labs), so domsource and openfmb (both named by a "
            "liveness-confirmed technique) now resolve. 2 of 14 claimed ids still do not: natas (an external "
            "OverTheWire target header_trust_authz claims Level 4 on, with no test/liveness check behind the "
            "claim) and sessionlife (an untracked labs/sessionlife/ dir with no compose service, no registry "
            "entry, no liveness check at HEAD). Both are genuinely fabricated-in-effect claims -- typed, never "
            "earned -- until someone actually proves them.")


@pytest.mark.xfail(strict=True, reason=_Q_VOCAB)
def test_every_validated_on_lab_id_names_a_target_the_agent_can_resolve():
    """A capability claim must name something that exists. Fails today on 2 ids (natas, sessionlife)."""
    known = _known_lab_ids()
    unknown = sorted({lab for labs in _claims().values() for lab in labs} - known)
    assert unknown == [], "validated_on names targets no lab registry knows: %s" % unknown


# FIXED (Q-088). Was a strict xfail: two invented lab ids used to yield status='proven', confidence
# 90/100 in the HIGH tier, a two-entry evidence list, generalized=True, and a clean schema validation.
# technique_model.from_registry now defers "proven" to techniques.technique_status() (the shared
# predicate) and filters `evidence` to labs techniques.known_labs() actually resolves, so a fabricated
# id can no longer buy either. The marker is gone rather than weakened -- STRICT is what made the fix
# visible: it XPASSed, the suite went red, and this comment is the deliberate removal that follows.
def test_a_fabricated_validated_on_is_rejected_by_the_canonical_model():
    """THE NEGATIVE CONTROL. Two invented lab ids must not buy 'proven', a high-tier confidence score,
    an evidence entry, or 'generalized'."""
    t = TM.from_registry(FABRICATED)
    assert t["status"] != "proven", "a technique nothing ever ran is not 'proven'"
    assert t["confidence"]["tier"] != "high", t["confidence"]
    assert t["evidence"] == [], "fabricated lab ids became evidence entries: %r" % t["evidence"]
    assert not T.is_generalized(FABRICATED), "two invented strings should not confer 'generalized'"


# FIXED (Q-088). Was a strict xfail: technique_model.from_registry and technique_planner.registry_seed
# both still ran the old 'proven if validated_on' rule (main.py:/packs already agreed with
# techniques.technique_status() at the time this was written). Both non-chokepoint modules now defer
# to the same shared predicate instead of re-deriving the word locally.
def test_one_rule_for_proven_across_every_module():
    """Three modules must not disagree with techniques.technique_status() about the same technique."""
    seed = {s["id"]: s for s in TP.registry_seed()}
    disagree = []
    for tid, rec in T.TECHNIQUES.items():
        truth = T.technique_status(rec)
        if seed[tid]["status"] == "proven" and truth != "proven":
            disagree.append((tid, "technique_planner", truth))
        if TM.from_registry(rec)["status"] == "proven" and truth != "proven":
            disagree.append((tid, "technique_model", truth))
    assert disagree == [], "%d modules-vs-truth disagreements, e.g. %s" % (len(disagree), disagree[:4])


@pytest.mark.xfail(strict=True, reason=(
    "Q-088 (owner: unassigned). MEASURED: /packs sums 'proven' as len(validated_on)>0 = 48; /techniques reports the "
    "liveness-earned 16. The same product publishes two 'proven' numbers differing by 32."))
def test_packs_and_techniques_report_the_same_proven_number():
    """Reproduces agent/main.py:2129 arithmetic exactly, without needing the HTTP app up."""
    by_class = {}
    for t in T.TECHNIQUES.values():
        by_class.setdefault(t["vuln_class"], []).append(t)
    packs_proven = sum(sum(1 for t in ts if t.get("validated_on")) for ts in by_class.values())
    assert packs_proven == T.taxonomy_view("owasp")["proven"], (packs_proven,)


@pytest.mark.xfail(strict=True, reason=(
    "Q-088 (owner: unassigned). MEASURED: 34 of 48 claims are named by no test assertion at all; widening 'backed' to include the "
    "liveness ledger still leaves 30 of 48 with nothing behind them - all 24 juiceshop claims and both "
    "dvwa claims among them. The beyond-web claims ARE backed by recorded replies; the web side is not."))
def test_every_validated_on_claim_is_backed_by_a_recorded_artifact():
    """Backed = confirmed by a liveness run, or replayed by a test that names the id on a
    validated_on line. Anything else is a claim with nothing behind it."""
    backed = set(T._liveness_verified())
    for fn in os.listdir(_HERE):
        if not fn.endswith(".py") or fn == os.path.basename(__file__):
            continue
        text = open(os.path.join(_HERE, fn), encoding="utf8", errors="replace").read()
        if "validated_on" not in text:
            continue
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.For) and "validated_on" in ast.dump(node):
                for sub in ast.walk(node.iter):
                    if isinstance(sub, ast.Constant) and sub.value in T.TECHNIQUES:
                        backed.add(sub.value)
        for line in text.splitlines():
            if "validated_on" in line:
                for tid in T.TECHNIQUES:
                    if '"%s"' % tid in line or "'%s'" % tid in line:
                        backed.add(tid)
    unbacked = sorted(set(_claims()) - backed)
    assert unbacked == [], "%d claims with no recorded proof: %s" % (len(unbacked), unbacked[:6])


# FIXED. Was a strict xfail reading: "capability_matrix.py:63 states 'Cross-lab generalization' as
# live_proven citing 'validated_on across juiceshop/dvwa/ginandjuice', but no generalized technique
# involves dvwa. validate() checks evidence is a non-empty STRING, never that the string is true."
#
# The marker is gone because the lane's own repair closed it, and STRICT is what made that visible:
# the fix landed, the test XPASSed, and the suite went red until someone retired the marker on
# purpose. That is the entire argument for strict over plain xfail -- a plain one would have gone
# green silently and left a "known defect" in the file for a defect that no longer exists, which is
# the same declaration-vs-fact rot this ticket was raised to remove.
def test_capability_matrix_generalization_row_cites_only_real_labs():
    import capability_matrix as CM
    real = {lab for tid in T.generalized() for lab in T.TECHNIQUES[tid]["validated_on"]}
    for c in CM.CAPABILITIES:
        if "generaliz" in c["name"].lower():
            assert set(c["labs"]) <= real, "cites labs backing no generalized technique: %s" % (
                sorted(set(c["labs"]) - real),)


# ── one rule for "proven", enforced at the API boundary too ──────────────────
def test_packs_and_techniques_now_report_the_SAME_proven_number():
    """The closing half of the two-subsystems-disagree defect.

    MEASURED before the fix: `/packs` summed `proven` as `len(validated_on) > 0` and reported **48**,
    while `techniques` reported **16** about the same registry. A count is not a display detail -- it
    is the number a reader uses to decide what this product can do, and two of them cannot both be it.

    This asserts the API's arithmetic against the shared predicate rather than against a literal, so
    it keeps holding as techniques are added or their evidence changes.

    ASSERTED ON BEHAVIOUR, NOT ON SOURCE TEXT. The first draft grepped main.py for the old expression
    and failed against the FIX'S OWN COMMENT, which quotes it. That is the second time in one day a
    source-scanning assertion matched a historical citation rather than live code -- the same shape as
    the `check_report_honesty` guard. A test that reads prose tests prose.
    """
    import techniques as _T

    old_rule = sum(1 for t in _T.TECHNIQUES.values() if t.get("validated_on"))
    shared = sum(1 for t in _T.TECHNIQUES.values() if _T.is_proven(t))
    view = _T.taxonomy_view("owasp")["proven"]

    assert shared == view, ("the shared predicate and the taxonomy view disagree: %d vs %d"
                            % (shared, view))
    assert old_rule > shared, (
        "the old rule no longer over-counts (%d vs %d), so this test has stopped discriminating"
        % (old_rule, shared))

    # And the predicate is the strict one: a fabricated lab cannot buy `proven`.
    fake = {"id": "x", "vuln_class": "sqli", "validated_on": ["apolaki_not_a_lab"]}
    assert not _T.is_proven(fake), "a lab id that names no target must not confer proven"
