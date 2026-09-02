"""Q-074 — how far the NEGATIVE half of the effects model actually reaches.

`test_effects_negative_half.py` pins what the `race_condition` row MEANS. This module pins something
different and, for this project, more expensive to get wrong: **who reads it.**

The single question Q-074 exists to answer is whether the planner does anything differently because a
negative-effect row exists. MEASURED at HEAD c226ae0, over all 184 production `.py` files:

    NEGATIVE-HALF function readers (conflicts / breaks / successor):
        main.py:1344  engine_descriptor.conflicts        <- POST /orchestration/audit
        count: 1
    agent.py    qualified reads=0  from-imports=[]  raw substring present: False (both modules)
    planner.py  qualified reads=0  from-imports=[]  raw substring present: False (both modules)

The answer is NO, and it is structural rather than a property of this row: the two files that decide
what a scan RUNS do not import the effects model at all. So the row is load-bearing for one number in
one JSON report and for nothing else — proved by mutation in
`test_deleting_the_only_negative_row_changes_reporting_and_nothing_else` below.

**WHY THIS IS A TEST AND NOT ONLY A HANDOFF PARAGRAPH.** The claim "the negative half is inert" is
the kind that rots silently: a later lane wires `breaks()` into `planner.py`, the docs still say
decoration, and the next reader believes the docs. These tests are a REACH LEDGER. If someone wires
it, `test_the_negative_half_reaches_no_scan_path` fails — and that failure is the correct one: it
forces the wiring and the written claim to be updated in the same commit. It is not a bar against
wiring. Deleting these tests to wire the model is fine; deleting the docs claim at the same time is
the point.

**INSTRUMENT NOTE, and it is why the analyser below is written the way it is.** `effects3.md`
recorded an earlier consumer sweep that walked every `ast.Name` and reported `frontier` read at
`agent.py`, `intel.py` and `natas_ladder.py`. Those are LOCAL VARIABLES named `frontier` in files
that do not import the module at all — a bare-name match producing the flattering answer. This walk
resolves each file's OWN module alias from its own import statements and counts only attribute access
qualified on that alias, plus `from <mod> import <name>` bindings. The raw-substring check is the
belt-and-braces control: it would catch a read through `importlib`, a string, or an alias the
resolver missed.
"""
import ast
import os

import effect_search as es
import engine_descriptor as ed

_AGENT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_MODULES = ("engine_descriptor", "effect_search")

# The functions that read `invalidates` and nothing else. `plan()` and `frontier()` reach it too, but
# only transitively through `successor()`, and the mutation test below measures that neither of their
# outputs moves when the row is deleted — so they are not counted as negative-half readers.
_NEGATIVE_HALF = frozenset({"conflicts", "breaks", "successor"})

# The files that decide what a scan RUNS. If either of these ever reads the effects model, the
# verdict recorded in docs/handoff/negative_effects.md stops being true.
_SCAN_PATH = ("agent.py", "planner.py")


def _production_files():
    """Every production `.py` under the agent root. Tests, caches and vendored trees excluded."""
    out = []
    for root, dirs, names in os.walk(_AGENT_ROOT):
        dirs[:] = [d for d in dirs if d not in ("tests", "__pycache__", ".git", "node_modules")]
        for n in sorted(names):
            if n.endswith(".py"):
                out.append(os.path.join(root, n))
    return out


def _consumer_graph():
    """(qualified attribute reads, from-imports) on the two effects modules, by resolved alias."""
    reads, fromimports = [], []
    for path in _production_files():
        try:
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
        except (SyntaxError, UnicodeDecodeError):
            continue
        alias = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in _MODULES:
                        alias[a.asname or a.name] = a.name
            elif isinstance(node, ast.ImportFrom) and node.module in _MODULES:
                for a in node.names:
                    fromimports.append((os.path.relpath(path, _AGENT_ROOT), node.module, a.name))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id in alias:
                    reads.append((os.path.relpath(path, _AGENT_ROOT).replace(os.sep, "/"),
                                  alias[node.value.id], node.attr))
    return reads, fromimports


# ── the analyser has to work before any zero it prints means anything ────────────────────────────

def test_POSITIVE_CONTROL_the_analyser_resolves_a_real_alias_and_a_real_from_import():
    """Every zero below is worthless unless this passes. `main.py` binds both modules under short
    aliases (`ED`, `ES`); `technique_planner.py` uses a from-import. The walk must see both forms."""
    reads, fromimports = _consumer_graph()
    assert reads, "the consumer walk found NO reads at all; it is not looking at anything"
    main_reads = {(m, a) for f, m, a in reads if f == "main.py"}
    assert ("engine_descriptor", "build") in main_reads, sorted(main_reads)
    assert ("effect_search", "frontier") in main_reads, sorted(main_reads)
    assert ("effect_search", "plan") in main_reads, sorted(main_reads)
    # the from-import form, which alias resolution alone would miss
    tp = {(m, n) for f, m, n in fromimports if f.replace(os.sep, "/") == "technique_planner.py"}
    assert ("engine_descriptor", "PRECONDITIONS") in tp, sorted(tp)
    # and the walk covers the whole tree, not one directory
    assert len(_production_files()) > 100, len(_production_files())


# ── the answer to Q-074's single question ────────────────────────────────────────────────────────

def test_the_negative_half_reaches_no_scan_path():
    """**The answer to Q-074, enforced.** `agent.py` and `planner.py` — the mission runner and the
    step planner — do not import the effects model, so no value in it can change what a scan does.

    Checked three independent ways, because a single check that returns nothing is the shape this
    project keeps being bitten by: resolved-alias attribute reads, from-imports, and a raw substring
    scan that needs no parsing at all and would catch an `importlib` or string-based read."""
    reads, fromimports = _consumer_graph()
    for name in _SCAN_PATH:
        assert [r for r in reads if r[0] == name] == [], name
        assert [f for f in fromimports if f[0].replace(os.sep, "/") == name] == [], name
        with open(os.path.join(_AGENT_ROOT, name), encoding="utf-8") as fh:
            src = fh.read()
        for mod in _MODULES:
            assert mod not in src, (
                "%s now mentions %s. If the effects model has been wired into the scan path this "
                "test SHOULD fail -- update docs/handoff/negative_effects.md, which currently "
                "records the negative half as inert with respect to scheduling." % (name, mod))
        # POSITIVE CONTROL on the same substring instrument: it is capable of finding a mention.
        assert "planner" in src or "tools" in src, name


def test_the_only_production_reader_of_the_negative_half_is_the_audit_endpoint():
    """`conflicts()` at `main.py:1344`, serving `POST /orchestration/audit`, is the whole production
    reach of the negative half. `breaks()` has no production caller outside `effect_search.frontier`
    itself, and `successor()` none outside this module's own `plan`/`unlocks`/`breaks`."""
    reads, _ = _consumer_graph()
    neg = {(f, m + "." + a) for f, m, a in reads if a in _NEGATIVE_HALF}
    assert neg == {("main.py", "engine_descriptor.conflicts")}, sorted(neg)
    # POSITIVE CONTROL: the same walk finds plenty of POSITIVE-half readers, so the singleton above
    # is a fact about the negative half and not about the walk being narrow.
    pos = {(f, m + "." + a) for f, m, a in reads if a not in _NEGATIVE_HALF}
    assert len(pos) >= 5, sorted(pos)
    assert ("scan_scope.py", "engine_descriptor.build") in pos, sorted(pos)


# ── what the row is worth, by mutation ───────────────────────────────────────────────────────────

_OBS = {"has_login", "authenticated", "serves_js"}


def _snapshot():
    d = ed.build()
    f = es.frontier(d, _OBS)
    return {
        "conflicts": len(ed.conflicts(d)),
        "breaks_race": es.breaks(d, _OBS, "race_condition"),
        "consequences": len(f["consequences"]),
        "always_on_with_effects": len(f["always_on_with_effects"]),
        "chains": len(ed.chains(d)),
        "applicable_now": len(f["applicable_now"]),
        "reachable_goals": len(f["reachable_goals"]),
        "plan_auth": es.plan(d, {"has_login"}, "authenticated")["plan"],
        "plan_creds": es.plan(d, {"has_login"}, "credentials_exposed")["plan"],
        "descriptors": len(d),
    }


def test_deleting_the_only_negative_row_changes_reporting_and_nothing_else(monkeypatch):
    """THE MUTATION. Delete the one row with a non-empty `invalidates` — which reconstitutes the
    pre-Q-074 model byte for byte — and measure every consumer.

    Four values move, and every one of them is read by `POST /orchestration/audit` or by nothing.
    Six values do not move, and `plan()` is among them: `_plan_core` records a candidate only when
    the goal appears in a successor state, and `race_condition` establishes nothing, so a
    negative-only action can never shorten a plan. Stated rather than hidden — claiming a plan
    improvement here would be exactly the decoration Q-074 warns about."""
    assert [k for k, v in ed.EFFECTS.items() if v.get("invalidates")] == ["race_condition"], (
        "this test is keyed to the ONE negative row; the table has changed and it must be re-measured")

    before = _snapshot()
    monkeypatch.setattr(ed, "EFFECTS",
                        {k: v for k, v in ed.EFFECTS.items() if k != "race_condition"})
    after = _snapshot()

    # CHANGED -- and every one of these is reporting surface
    assert (before["conflicts"], after["conflicts"]) == (6, 0)
    assert before["breaks_race"] == ["cache_deception", "jwt_forge", "jwt_key_confusion",
                                     "session_fixation", "session_lifecycle", "weak_2fa_bypass"]
    assert after["breaks_race"] == []
    assert (before["consequences"], after["consequences"]) == (8, 7)
    assert (before["always_on_with_effects"], after["always_on_with_effects"]) == (3, 2)

    # UNCHANGED -- nothing the search or the descriptor build depends on
    for k in ("chains", "applicable_now", "reachable_goals", "plan_auth", "plan_creds",
              "descriptors"):
        assert before[k] == after[k], (k, before[k], after[k])
    assert before["plan_auth"] == ["sqli_auth_bypass"], before["plan_auth"]
    # 88 -> 94: cycle 18 declared six new techniques, each with a typed claim and a route.
    assert before["descriptors"] == 94, before["descriptors"]


def test_the_row_is_restored_after_the_mutation(monkeypatch):
    """NEGATIVE CONTROL for the test above: monkeypatch is per-test, so the shipped table is intact
    for everything that follows. A mutation test that leaks its mutant poisons the whole module."""
    assert len(ed.conflicts(ed.build())) == 6
    assert ed.EFFECTS["race_condition"]["invalidates"] == ["authenticated"]
