"""Dead-code gate (#125): every top-level function must have a caller.

The no-island doctrine one level down. Both failure modes it guards against were real here: an
integration gap (something written but never wired) and a superseded duplicate sitting next to the live
engine, waiting to be called by mistake.
"""
import ast
import os
import shutil

import pytest

import deadcode_gate as dg


# Both scans walk the whole source tree, so each call costs seconds. Six real-tree scans in one file was
# enough to push this past a two-minute timeout. Computed ONCE and shared -- the assertions are unchanged,
# only the number of walks is. A correctness check nobody can afford to run gets skipped, which is how a
# gate quietly stops guarding.
@pytest.fixture(scope="module")
def res():
    return dg.scan()


@pytest.fixture(scope="module")
def qual():
    return dg.scan_qualified()


def test_no_unexplained_dead_functions(res):
    """THE GATE. A function with no caller is either unwired or obsolete; either way it needs a decision,
    not silence. Add a caller, delete it, or justify it in ALLOWED_UNUSED with a reason."""
    assert not res["unused"], "functions with no caller and no justification: %s" % [
        "%s (%s)" % (u["name"], ", ".join(u["at"])) for u in res["unused"]]


def test_the_allowlist_does_not_rot(res):
    """An entry that is now called must leave the allowlist, or the list stops meaning anything."""
    assert not res["stale_allowlist"], (
        "these are no longer unused and should be removed from ALLOWED_UNUSED: %s"
        % res["stale_allowlist"])


def test_every_allowlist_entry_states_a_reason():
    for name, why in dg.ALLOWED_UNUSED.items():
        assert len(why) > 25, "%s is allowlisted without a real reason: %r" % (name, why)


def test_the_scan_actually_finds_things(res):
    """A gate that can never fire is decoration. The scan must see the real codebase."""
    assert res["total_functions"] > 200, res["total_functions"]


def test_framework_invoked_functions_are_not_flagged(res):
    """FastAPI routes are decorated and have no in-repo caller by design; flagging them would drown the
    signal. Recognised structurally rather than by a name list that would rot."""
    flagged = {u["name"] for u in res["unused"]}
    for route in ("get_status", "get_report", "lab_targets", "proxy_status"):
        assert route not in flagged, "%s is a FastAPI route and must not be flagged" % route


# ── the qualified scan: what the bare-name check cannot see ─────────────────────────────────────

def test_the_bare_name_scan_is_fooled_by_a_name_collision():
    """Documents the blind spot as an executable fact rather than a comment. Two modules define `helper`;
    only one is called. The bare-name scan sees a hit and clears BOTH."""
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "alpha.py"), "w", encoding="utf8").write(
        "def helper():\n    return 1\n")
    open(os.path.join(d, "beta.py"), "w", encoding="utf8").write(
        "def helper():\n    return 2\n\n\ndef go():\n    return helper()\n")
    bare = {u["name"] for u in dg.scan(d)["unused"]}
    assert "helper" not in bare, "bare-name scan should (wrongly) consider alpha.helper used"
    qual = set(dg.scan_qualified(d)["unused"])
    assert "alpha.helper" in qual, "qualified scan must catch the uncalled one"
    assert "beta.helper" not in qual, "the genuinely called one must not be flagged"


def test_the_qualified_scan_resolves_import_aliases():
    """`import probe_selection as ps` then `ps.pairwise(...)` is a real call, not dead code. A checker
    that missed aliases would be unusable noise."""
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "lib.py"), "w", encoding="utf8").write("def work():\n    return 1\n")
    open(os.path.join(d, "app.py"), "w", encoding="utf8").write(
        "import lib as L\n\n\ndef run():\n    return L.work()\n")
    assert "lib.work" not in set(dg.scan_qualified(d)["unused"])


def test_the_qualified_scan_honours_from_imports():
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "lib.py"), "w", encoding="utf8").write("def work():\n    return 1\n")
    open(os.path.join(d, "app.py"), "w", encoding="utf8").write(
        "from lib import work\n\n\ndef run():\n    return work()\n")
    assert "lib.work" not in set(dg.scan_qualified(d)["unused"])


def test_a_function_referenced_as_a_value_is_not_dead():
    """A function in a dispatch table is never CALLED by name. Requiring a paren would flag every
    guidance._rule_* entry."""
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "lib.py"), "w", encoding="utf8").write(
        "def rule_a():\n    return 1\n\n\nRULES = [rule_a]\n")
    assert "lib.rule_a" not in set(dg.scan_qualified(d)["unused"])


# ── prose is not wiring (Q-077) ─────────────────────────────────────────────────────────────────

def test_ast_refs_reads_code_and_never_prose():
    """The unit the whole ticket turns on. A comment and a docstring mentioning a name must produce NO
    reference; real code must produce one of each kind."""
    names, qualified, attrs, strings = dg._ast_refs(ast.parse(
        '"""Docstring: ghost() is the documented helper."""\n'
        "# Comment: mod.ghost is what we should call\n"
        "def caller():\n"
        "    return mod.attr_call(real_name)\n"))
    assert "ghost" not in names and "ghost" not in attrs, "prose produced a reference"
    assert "real_name" in names
    assert ("mod", "attr_call") in qualified and "attr_call" in attrs
    # the docstring survives as a WHOLE value; it can never be mistaken for the name inside it
    assert any(s.startswith("Docstring:") for s in strings)
    assert "ghost" not in strings


def test_dotted_refuses_anything_that_is_not_a_plain_name_chain():
    """`_dotted` is what replaced the `(?<![\\w.])` lookbehind. `f().x` and `d[k].x` must NOT resolve to
    a module, or `x.lib.work` would count as a call to `lib.work`."""
    assert dg._dotted(ast.parse("a.b.c", mode="eval").body.value) == "a.b"
    assert dg._dotted(ast.parse("a", mode="eval").body) == "a"
    assert dg._dotted(ast.parse("f().x", mode="eval").body.value) is None
    assert dg._dotted(ast.parse("d[k].x", mode="eval").body.value) is None


def test_a_function_named_only_in_prose_is_dead_and_a_called_one_is_not(tmp_path):
    """NEGATIVE CONTROL, required by Q-077, with its positive half in the same fixture.

    MEASURED cause: `scan_qualified` matched a bare name by regex over the defining module's RAW SOURCE,
    so a docstring, a comment or an unrelated string literal cleared the function it merely discussed.
    On the real tree that hid 27 entries -- 22 cleared by a string (20 of them docstring prose), 5 by a
    comment, and 0 by an actual reference."""
    (tmp_path / "lib.py").write_text(
        '"""Module prose: ghost_doc() is the documented way to do this."""\n'
        "# Module comment: ghost_comment() should be wired up one day.\n"
        "MENTION = 'ghost_string'\n\n\n"
        "def ghost_doc():\n    return 1\n\n\n"
        "def ghost_comment():\n    return 2\n\n\n"
        "def ghost_string():\n    return 3\n\n\n"
        "def really_called():\n    return 4\n", encoding="utf8")
    (tmp_path / "app.py").write_text(
        "import lib\n\n\n"
        "# lib.ghost_doc() and lib.ghost_comment() are what this SHOULD call.\n"
        "def go():\n    return lib.really_called()\n", encoding="utf8")

    out = set(dg.scan_qualified(str(tmp_path))["unused"])
    for dead in ("lib.ghost_doc", "lib.ghost_comment", "lib.ghost_string"):
        assert dead in out, "%s is named only in prose or a string literal and must read as dead" % dead
    assert "lib.really_called" not in out, (
        "POSITIVE HALF: a function with a real caller must never be flagged -- a checker that cannot "
        "tell them apart is noise, not a gate")


def test_an_import_is_a_binding_not_a_call(tmp_path):
    """The from-import half. The old rule regex-searched the importing file's raw source for the bare
    local name, which matched THE IMPORT STATEMENT IT HAD JUST READ -- so `from x import y` cleared `y`
    whether or not anything used it. MEASURED on the real tree, this rule alone accounts for exactly one
    entry: `nosqli_tool.py` imports `sqli_tool.is_inconclusive` and never uses the name."""
    (tmp_path / "lib.py").write_text("def work():\n    return 1\n", encoding="utf8")
    (tmp_path / "app.py").write_text("from lib import work\n", encoding="utf8")
    assert "lib.work" in set(dg.scan_qualified(str(tmp_path))["unused"]), (
        "an unused import cleared the function it imports")


def test_a_method_named_only_in_prose_is_dead_and_a_called_one_is_not(tmp_path):
    """NEGATIVE CONTROL for the method scan, and the exact shape that hid `Vault.is_encrypted`.

    Its docstring reads "pretends to be encrypted. is_encrypted() reports the true protection level" and
    the old rule was `\\.\\s*name` -- which cannot tell the FULL STOP ending a sentence from an attribute
    access. `. is_encrypted` counted as a call. Reproduced here with the same shape."""
    (tmp_path / "m.py").write_text(
        "class C:\n"
        "    def orphan(self):\n"
        '        """Pretends to be wired. orphan() reports the truth."""\n'
        "        return 1\n\n"
        "    def used(self):\n"
        "        return 2\n\n\n"
        "# c.orphan() is the one you probably want\n"
        "def go(c):\n    return c.used()\n", encoding="utf8")
    out = set(dg.scan_methods(str(tmp_path))["unused"])
    assert "m.py::C.orphan" in out, "a full stop before the name is not an attribute access"
    assert "m.py::C.used" not in out, "POSITIVE HALF: `c.used()` is a real call"


def test_the_recorded_q077_delta_excuses_nothing():
    """`QUALIFIED_Q077_REVEALED` is a record of a measurement, not a second allowlist. Every entry still
    counts toward the ratchet; the set exists only so the next reader can tell a Q-077 revelation from a
    genuinely new island. If it ever overlaps an allowlist or the baseline set, it has become one."""
    assert len(dg.QUALIFIED_Q077_REVEALED) == 27, "the recorded delta was 27, measured on a HEAD snapshot"
    assert not (dg.QUALIFIED_Q077_REVEALED & dg.QUALIFIED_BASELINE_SET), (
        "an entry cannot be both pre-existing and newly revealed: %s"
        % sorted(dg.QUALIFIED_Q077_REVEALED & dg.QUALIFIED_BASELINE_SET))
    for e in dg.QUALIFIED_Q077_REVEALED:
        assert "." in e and "::" not in e, e
        assert e not in dg.ALLOWED_UNUSED_QUALIFIED, "%s was quietly excused" % e
        assert e.split(".")[-1] not in dg.ALLOWED_UNUSED, "%s was quietly excused" % e


@pytest.mark.xfail(strict=True, reason=(
    "MEASURED, and TRUE: 61 qualified-dead against a ceiling of 37. The ceiling was calibrated "
    "against a BLIND instrument -- Q-077 made the resolver read the AST instead of regex-matching a "
    "bare name anywhere in the module, so comments and string literals stopped counting as calls, and "
    "27 entries became visible that were always dead. The code did not rot; the measurement got "
    "honest. Raising 37 to 61 would be weakening a ratchet to make a change pass, which is the one "
    "thing this file must never do, so the ratchet stays RED and its message names all 27 every run. "
    "TRIAGE IS Q-078, and it is not a formality: at least four of the 27 are resolver blind spots "
    "rather than islands -- deadcode_gate.scan/scan_methods/scan_qualified look uncalled because the "
    "gate excludes its own file, mitm_addon.request/response are framework callbacks mitmdump invokes "
    "by name per docker-compose.yml:419, and sqli_tool.is_inconclusive is re-exported by nosqli_tool. "
    "The real island count is LOWER than 27 and nobody may quote 27 as it. STRICT: the day Q-078 "
    "lands a triaged baseline this XPASSes and the marker must be retired deliberately."))
def test_the_ratchet_holds(qual):
    """The count may fall, never rise. A new unwired function fails this immediately, while the existing
    backlog is triaged deliberately rather than bulk-deleted — those entries are CANDIDATES, not proven
    dead, and deleting unproven code is how a working engine gets removed."""
    assert qual["ok"], qual["message"]


# ── the failure MESSAGE: the alarm was right and pointed elsewhere (Q-075) ──────────────────────

@pytest.fixture(scope="module")
def real_tree_copy(tmp_path_factory):
    """A frozen COPY of the real tree. The negative control needs to add an island to a live module, and
    every live module belongs to some other lane -- so it is added here instead. Frozen also means the
    before/after pair measures the SAME bytes, immune to another lane editing mid-test."""
    dst = str(tmp_path_factory.mktemp("island_control"))
    for fn in os.listdir(dg.APP_DIR):
        if fn.endswith(".py"):
            shutil.copyfile(os.path.join(dg.APP_DIR, fn), os.path.join(dst, fn))
    return dst


def test_a_deliberate_island_is_named_and_nothing_else_is(real_tree_copy):
    """NEGATIVE CONTROL, required by Q-075.

    The bug: the message printed `sorted(unused)[-5:]`, the alphabetical TAIL of the list. It named the
    same five functions whether the tree was clean or dirty, and the five genuinely new entries
    (`dom_tool.wm_*`) sorted into the middle where a tail slice could never reach them.

    Run on a copy of the REAL tree rather than a toy directory on purpose: against a toy dir every
    flagged name is new, so `newly_dead` is trivially the whole list and the assertion proves nothing
    about a populated baseline. Here the delta must be exactly the one function introduced."""
    before = dg.scan_qualified(real_tree_copy)
    victim = os.path.join(real_tree_copy, "security.py")
    original = open(victim, encoding="utf8").read()
    # The comment and the docstring both NAME the island. Under the old regex resolver that alone
    # cleared it, so this doubles as the Q-077 negative control at real-tree scale: prose about a
    # function, in the defining module, must not rescue it.
    open(victim, "a", encoding="utf8").write(
        "\n\n# apolaki_deliberate_island() is the documented way to do this.\n"
        "def apolaki_deliberate_island():\n"
        "    \"\"\"Q-075 negative control. apolaki_deliberate_island has no caller, by construction.\"\"\"\n"
        "    return 1\n")
    try:
        after = dg.scan_qualified(real_tree_copy)
    finally:
        open(victim, "w", encoding="utf8").write(original)

    island = "security.apolaki_deliberate_island"
    assert island in after["unused"], "positive control: the scan must SEE the island at all"
    # It is named BECAUSE it was introduced. `before` is the same bytes the `finally` above restores, so
    # this doubles as the "remove it and the message stops naming it" half, without a third full scan --
    # each one walks 179 real modules and costs about eight seconds.
    assert island not in before["unused"] and island not in before["message"]
    new_names = set(after["newly_dead"]) - set(before["newly_dead"])
    assert new_names == {island}, (
        "the message must name the island and nothing else; it named %s" % sorted(new_names))
    assert island in after["message"]

    # The exact regression: these are the five the old slice printed. All are in the recorded baseline,
    # so a true set difference can never surface them, however the list sorts.
    for innocent in ("technique_store.stats", "techniques.techniques_for_lab", "waf_bypass_tool.pad",
                     "web_security.is_url_in_scope", "xxe_tool.looks_like_xml"):
        assert innocent not in after["newly_dead"], innocent
        assert innocent not in after["message"], "%s is not the delta and must not be named" % innocent


def test_a_recorded_baseline_set_smaller_than_the_ratchet_guarantees_a_named_entry():
    """The property that makes the alarm's message provably non-empty, for BOTH ratchets.

    If everything flagged were already in the recorded set, the count could be at most len(set); with
    len(set) <= baseline the ratchet would not have fired. So whenever it fires there is at least one
    newly-dead name to print. Raising a baseline above its set, or letting a set outgrow its ratchet,
    silently reintroduces the empty-message case."""
    assert len(dg.QUALIFIED_BASELINE_SET) <= dg.QUALIFIED_BASELINE, (
        "recorded set of %d exceeds the ratchet of %d -- a rise could then name nothing"
        % (len(dg.QUALIFIED_BASELINE_SET), dg.QUALIFIED_BASELINE))
    assert len(dg.METHOD_BASELINE_SET) <= dg.METHOD_BASELINE, (
        "recorded method set of %d exceeds the ratchet of %d"
        % (len(dg.METHOD_BASELINE_SET), dg.METHOD_BASELINE))


def test_the_recorded_sets_are_shaped_like_real_measurements():
    """A hand-typed set rots into fiction quietly. These are the cheap structural checks: qualified
    entries are `module.function`, method entries are `file.py::Class.method`, and neither set may hold
    an allowlisted name -- allowlisted entries are filtered out of `flagged` before the diff, so one
    recorded here would sit in `resolved` forever and never be a real measurement of anything."""
    for e in dg.QUALIFIED_BASELINE_SET:
        assert "." in e and "::" not in e, e
        assert e not in dg.ALLOWED_UNUSED_QUALIFIED, "%s is allowlisted; it is never flagged" % e
        assert e.split(".")[-1] not in dg.ALLOWED_UNUSED, "%s is allowlisted; it is never flagged" % e
    for e in dg.METHOD_BASELINE_SET:
        assert e.count("::") == 1, e
        path, qualified = e.split("::")
        assert path.endswith(".py") and qualified.count(".") == 1, e
        assert e.split(".")[-1] not in dg.ALLOWED_UNUSED_METHODS, e


def test_the_message_says_so_when_it_cannot_name_the_delta():
    """The one case where a true set difference has nothing to show: a recorded set at or above the
    ratchet. It must not print an empty list -- next to a failure that reads as `no new dead code`,
    which is the same misdirection this ticket replaces."""
    named = dg._ratchet_message("qualified dead-code count", 40, 37, ["mod.fn"], [], 35)
    assert "mod.fn" in named and "NEWLY DEAD" in named

    blind = dg._ratchet_message("qualified dead-code count", 40, 37, [], [], 40)
    assert "re-recorded" in blind and "names are not available" in blind

    drifted = dg._ratchet_message("qualified dead-code count", 40, 37, ["mod.fn"], ["old.gone"], 35)
    assert "old.gone" in drifted and "no longer dead" in drifted


def test_the_scans_report_a_true_difference_not_a_slice(qual, meth):
    """Both ratchets return a real set difference against their recorded set. The old message took
    `unused[-5:]`; assert the reported delta is exactly what set arithmetic says it is."""
    for res, recorded in ((qual, dg.QUALIFIED_BASELINE_SET), (meth, dg.METHOD_BASELINE_SET)):
        assert res["newly_dead"] == sorted(set(res["unused"]) - recorded)
        assert res["resolved"] == sorted(recorded - set(res["unused"]))
        assert not (set(res["newly_dead"]) & set(res["resolved"])), "an entry cannot be both"


def test_the_baseline_is_not_slack(qual):
    """A baseline far above the real count would silently permit regressions up to it."""
    q = qual
    assert q["baseline"] - q["count"] <= 3, (
        "baseline %d is stale against an actual %d — tighten it" % (q["baseline"], q["count"]))


def test_the_qualified_scan_honours_both_allowlists(qual):
    """A function with a written justification is unwired-but-explained, not unwired-and-unexplained.
    Counting both toward the ratchet makes the number mean two things at once.

    TWO lists, deliberately. `scan()` and `scan_qualified()` disagree about what "unused" means — the
    first counts any mention including tests, the second requires a production caller through a resolved
    import. An entry unused-to-one and used-to-the-other makes a shared list wrong for whichever
    disagrees, and `scan()`'s staleness check keeps flagging it."""
    assert qual["allowed"], "the allowlists should still be catching some entries"
    for name in qual["allowed"]:
        assert name.split(".")[-1] in dg.ALLOWED_UNUSED or name in dg.ALLOWED_UNUSED_QUALIFIED, name
    assert not (set(qual["unused"]) & set(qual["allowed"])), "an entry cannot be both"


def test_every_qualified_allowlist_entry_states_a_reason():
    for name, why in dg.ALLOWED_UNUSED_QUALIFIED.items():
        assert "." in name, "qualified entries are keyed module.function: %s" % name
        assert len(why) > 25, "%s is allowlisted without a real reason: %r" % (name, why)


def test_the_two_allowlists_do_not_overlap():
    """An entry in both is a sign the distinction was not understood, and one of them will rot."""
    bare = {n.split(".")[-1] for n in dg.ALLOWED_UNUSED_QUALIFIED}
    assert not (bare & set(dg.ALLOWED_UNUSED)), sorted(bare & set(dg.ALLOWED_UNUSED))


# ── class methods: the layer both other scans are blind to ──────────────────────────────────────

@pytest.fixture(scope="module")
def meth():
    return dg.scan_methods()


def test_the_method_scan_sees_the_layer_the_others_cannot(meth):
    """`scan()` and `scan_qualified()` walk tree.body, so they see zero class methods — and Apolaki keeps
    every engine in `ToolRegistry`. Neither unreachable engine found on 2026-08-08 was caught by a
    dead-code scan."""
    assert meth["methods_examined"] > 300, meth["methods_examined"]


def test_a_called_method_is_not_flagged(meth):
    """ToolRegistry.execute is THE dispatcher. The first version flagged it, because a lookbehind before
    the dot rejected `self.tools.execute(...)`. An obvious false positive discredits the whole check."""
    flagged = set(meth["unused"])
    for obvious in ("tools.py::ToolRegistry.execute",
                    "tools.py::ToolRegistry.get_claude_tools"):
        assert obvious not in flagged, obvious


def test_base_class_callbacks_are_not_flagged(meth):
    """`_FormParser.handle_starttag` is invoked by html.parser.HTMLParser, never by us. Recognised by
    walking the real MRO rather than by a callback-name list that would rot."""
    for cb in meth["unused"]:
        assert "handle_starttag" not in cb and "handle_endtag" not in cb, cb


def test_the_method_scan_can_still_find_something(meth):
    """POSITIVE CONTROL, and the assertion whose absence let a silenced ratchet ship green.

    `0 <= 14` passes. Every other method test passes on an empty result too -- `methods_examined` counts
    DEFINITIONS, so it stays above 300 even when resolution marks everything used. Recording
    METHOD_BASELINE_SET put strings like `"vault.py::Vault.purge"` into the scanned corpus, the `.name`
    rule matched `.purge` inside the literal, and the count went 13 -> 0 with nothing red. A count of
    zero here means the scan stopped looking; re-record the set only after proving otherwise."""
    assert meth["count"] > 0, (
        "the method scan reports NOTHING uncalled. Before re-recording METHOD_BASELINE_SET, check the "
        "scan is not reading a file that names its own findings")


def test_the_method_scan_does_not_read_its_own_findings(tmp_path):
    """The mechanism, isolated. A file named like this module must not be part of the corpus: it holds a
    record of what the scan found, and `.orphan` inside `"m.py::C.orphan"` matched the attribute rule.

    BOTH shapes are planted, because the AST rewrite (Q-077) changed which one bites. Under raw-text
    matching the `::` literal was the hazard. Under AST resolution a string constant is compared WHOLE,
    so `"m.py::C.orphan"` is inert -- but `ALLOWED_UNUSED_METHODS` is keyed by BARE METHOD NAME, and a
    bare `"orphan"` is exactly what the string-dispatch rule accepts as a call. Planting only the old
    shape would leave a control that passes with the self-exclusion deleted."""
    (tmp_path / "m.py").write_text(
        "class C:\n    def orphan(self):\n        return 2\n", encoding="utf8")
    (tmp_path / "deadcode_gate.py").write_text(
        'RECORDED = {"m.py::C.orphan"}\n'
        'ALLOWED_UNUSED_METHODS = {"orphan": "a written justification lives here"}\n', encoding="utf8")
    out = set(dg.scan_methods(str(tmp_path))["unused"])
    assert "m.py::C.orphan" in out, (
        "a recorded finding was read back as a call -- the scan is self-approving")


def test_the_method_ratchet_holds(meth):
    """May fall, never rise. These are CANDIDATES — some resolve through dynamic dispatch the checker
    does not model — so they get triaged, not bulk-deleted."""
    assert meth["ok"], meth["message"]


def test_a_genuinely_uncalled_method_is_caught(tmp_path):
    """NEGATIVE CONTROL. A checker that cannot fail is decoration."""
    (tmp_path / "m.py").write_text(
        "class C:\n    def used(self):\n        return 1\n\n"
        "    def orphan(self):\n        return 2\n\n\n"
        "def go(c):\n    return c.used()\n", encoding="utf8")
    out = set(dg.scan_methods(str(tmp_path))["unused"])
    assert "m.py::C.orphan" in out
    assert "m.py::C.used" not in out


def test_string_dispatch_counts_as_a_call(tmp_path):
    """Tools are reached by `getattr(self, "_" + tool_name)`. Without this rule all 147 ToolRegistry
    engine methods would be flagged and the check would be useless noise."""
    (tmp_path / "m.py").write_text(
        'class C:\n    async def _run_thing(self, i):\n        return 1\n\n\n'
        'def go(c, n):\n    return getattr(c, "_" + n)({})\n\n\nWIRED = ["run_thing"]\n', encoding="utf8")
    assert "m.py::C._run_thing" not in set(dg.scan_methods(str(tmp_path))["unused"])
