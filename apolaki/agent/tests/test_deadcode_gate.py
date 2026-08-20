"""Dead-code gate (#125): every top-level function must have a caller.

The no-island doctrine one level down. Both failure modes it guards against were real here: an
integration gap (something written but never wired) and a superseded duplicate sitting next to the live
engine, waiting to be called by mistake.
"""
import ast
import os
import re
import shutil
import warnings

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
        # Q-078 triage may excuse an entry, but ONLY through the list whose entries name a caller that a
        # test resolves. Those two lists above take a sentence; this one takes a caller that must exist.
        if e in dg.ALLOWED_UNUSED_NAMED_CALLER:
            status = dg.resolve_named_caller(e)[0]
            assert status != dg.ANCHOR_MISSING, (
                "%s was excused by ALLOWED_UNUSED_NAMED_CALLER and its named caller is GONE from a file "
                "that is right here -- so either the excuse was never true or this is an island now" % e)
            assert status == dg.RESOLVED or e in dg.NAMED_CALLER_OUTSIDE_CHECKOUT, (
                "%s could not be resolved and is not one of the entries pinned as unverifiable in this "
                "environment" % e)


# ── Q-078: the triage of those 27 ───────────────────────────────────────────────────────────────

def test_a_module_stashed_on_an_attribute_is_still_that_module(tmp_path):
    """MEASURED FALSE POSITIVE, and the reason this ticket touched the resolver at all.

    `intel.harvest` read as dead for the whole life of this gate while `tools.py:1848` calls it on every
    scoped fetch, because `tools.py:1246` stashes the module on `self._intel_mod` and the reference then
    resolves as the pair `("self._intel_mod", "harvest")`, which never matches the import alias
    `_intel`. Reproduced here with the same shape: import-as, re-bind onto an attribute, call.

    An allowlist entry would have recorded the lie permanently. The resolver was what was wrong."""
    (tmp_path / "lib.py").write_text("def work():\n    return 1\n", encoding="utf8")
    (tmp_path / "app.py").write_text(
        "class R:\n"
        "    def __init__(self):\n"
        "        import lib as _lib\n"
        "        self._lib_mod = _lib\n\n"
        "    def go(self):\n"
        "        return self._lib_mod.work()\n", encoding="utf8")
    assert "lib.work" not in set(dg.scan_qualified(str(tmp_path))["unused"]), (
        "a module reached through an attribute it was stashed on is still that module")


def test_attribute_rebinding_does_not_become_a_type_blind_dot_name_rule(tmp_path):
    """NEGATIVE CONTROL for the fix above, and the failure mode that would make it worthless.

    The cheap version of this fix is "any `.work()` on anything counts", which is the deliberately
    type-blind rule `scan_methods` uses and precisely what `scan_qualified` exists NOT to do -- 90
    function names in this codebase are defined in more than one module. Only an assignment whose
    RIGHT-HAND SIDE IS ALREADY A KNOWN MODULE BINDING may create one, so an ordinary object with a
    same-named method must leave the real function reading as dead."""
    (tmp_path / "lib.py").write_text("def work():\n    return 1\n", encoding="utf8")
    (tmp_path / "app.py").write_text(
        "import lib\n\n\n"                      # imported, so `lib` is a known module here...
        "class Other:\n"
        "    def work(self):\n        return 2\n\n\n"
        "class R:\n"
        "    def __init__(self):\n"
        "        self._helper = Other()\n\n"    # ...but THIS is not a module binding
        "    def go(self):\n"
        "        return self._helper.work()\n", encoding="utf8")
    assert "lib.work" in set(dg.scan_qualified(str(tmp_path))["unused"]), (
        "an attribute holding an ordinary object cleared a module function of the same name -- the "
        "resolver has degenerated into the type-blind `.name` rule")


def test_prose_naming_a_stashed_module_call_is_still_not_wiring(tmp_path):
    """Q-077's negative control, re-run against the Q-078 fix. Widening the resolver is exactly when a
    comment gets a second chance to pass for a call, so the same prose that could not clear a function
    before must not clear it now."""
    (tmp_path / "lib.py").write_text("def work():\n    return 1\n", encoding="utf8")
    (tmp_path / "app.py").write_text(
        "import lib as _lib\n\n\n"
        "class R:\n"
        "    def __init__(self):\n"
        "        self._lib_mod = _lib\n\n"
        "    def go(self):\n"
        '        """self._lib_mod.work() is what this should call one day."""\n'
        "        # self._lib_mod.work()\n"
        "        return None\n", encoding="utf8")
    assert "lib.work" in set(dg.scan_qualified(str(tmp_path))["unused"]), (
        "a stashed-module call named only in a docstring and a comment counted as wiring")


def test_every_named_caller_allowlist_entry_resolves_to_a_real_caller():
    """THE MECHANISM THAT KEEPS THIS LIST FROM GOING DECORATIVE.

    An allowlist entry saying "allowed" is how a gate stops being a gate. Every entry in
    `ALLOWED_UNUSED_NAMED_CALLER` names a caller, and this opens the file and finds it. Delete the
    caller, rename it, or invent one, and this goes red -- the justification is CHECKED, not written.

    The anchor must also NAME the thing it excuses (the function or its defining module), so an entry
    cannot point at an arbitrary line that happens to exist.

    ONE environment-shaped exception, and it is pinned by name rather than by rule. The suite runs in a
    container that mounts ONLY `agent/`, so `docker-compose.yml` -- the file that records mitmdump
    loading the addon -- is genuinely not there to open. That is a LIMIT, not a pass: it is confined to
    `NAMED_CALLER_OUTSIDE_CHECKOUT`, the anchor-missing state is still a hard failure for those entries,
    and `test_the_resolver_reads_a_file_at_the_repository_root` runs the same entry and the same anchor
    through all three states against a synthetic root."""
    assert dg.ALLOWED_UNUSED_NAMED_CALLER, "the list emptied itself"
    resolved_here = 0
    for entry, rec in dg.ALLOWED_UNUSED_NAMED_CALLER.items():
        kind, caller, anchor, why = rec
        assert kind in ("framework", "re-export", "harness"), "%s: unknown kind %r" % (entry, kind)
        assert len(why) > 40, "%s is excused without a real reason: %r" % (entry, why)
        mod, fn = entry.rsplit(".", 1)
        assert fn in anchor or mod in anchor, (
            "%s: the anchor %r names neither the function nor its module, so it does not evidence "
            "anything" % (entry, anchor))
        status, path, lineno, line = dg.resolve_named_caller(entry)
        assert status != dg.ANCHOR_MISSING, (
            "%s claims a caller in %s containing %r. The file is right here and the anchor is NOT in it. "
            "Either the caller was removed -- in which case this is a real island now -- or the entry "
            "was never true." % (entry, caller, anchor))
        if status == dg.FILE_UNREACHABLE:
            assert entry in dg.NAMED_CALLER_OUTSIDE_CHECKOUT, (
                "%s names a caller in %s, which is not in this checkout, and it is not one of the "
                "entries pinned as unverifiable here. An entry that cannot be checked anywhere is the "
                "word 'allowed' with extra steps." % (entry, caller))
            continue
        assert status == dg.RESOLVED, (entry, status)
        assert os.path.isfile(path) and lineno > 0 and anchor in line
        resolved_here += 1
    # POSITIVE CONTROL. Without this the loop above passes an empty tree, a broken resolver, or a list
    # every entry of which claimed to be unreachable.
    assert resolved_here >= len(dg.ALLOWED_UNUSED_NAMED_CALLER) - len(dg.NAMED_CALLER_OUTSIDE_CHECKOUT)
    assert resolved_here >= 8, "only %d entries actually resolved against the real tree" % resolved_here


def test_a_fabricated_named_caller_does_not_resolve(monkeypatch):
    """NEGATIVE CONTROL for the check above. A check that passes whatever it is given proves nothing, and
    this file has been bitten by exactly that: `scan_methods` once reported 0 uncalled methods with every
    test green, because `0 <= 14` passes and nothing asserted the scan could still find anything.

    THE FABRICATED ANCHOR IS ASSEMBLED AT RUNTIME, and that is the whole lesson of this test rather than
    a style tic. Written as one literal, the fabrication puts itself into this file -- and this file is
    the very file the fabricated entry names as its caller, so the resolver finds it and the control
    reports success while proving the opposite of what it claims. That is not hypothetical: it is the
    bug this test shipped with. The assertion below that the string is absent from both files is the
    guard, and it is what a negative control needs to be worth running."""
    absent = "ghost_fn_" + "nothing_anywhere_calls_this()"
    for fn in ("deadcode_gate.py", os.path.join("tests", "test_deadcode_gate.py")):
        src = open(os.path.join(dg.APP_DIR, fn), encoding="utf8").read()
        assert absent not in src, (
            "the fabricated anchor is a literal in %s, so 'it did not resolve' would prove nothing about "
            "the resolver -- assemble it at runtime" % fn)

    # file present, anchor absent -> the excuse died. Distinct from the file being missing.
    monkeypatch.setitem(dg.ALLOWED_UNUSED_NAMED_CALLER, "ghost_mod.ghost_fn",
                        ("harness", "tests/test_deadcode_gate.py", absent, "fabricated, for the control"))
    assert dg.resolve_named_caller("ghost_mod.ghost_fn")[0] == dg.ANCHOR_MISSING, (
        "a caller that is not in the file resolved anyway -- the resolver is not reading the file")
    # file absent -> a different answer, and no exception
    monkeypatch.setitem(dg.ALLOWED_UNUSED_NAMED_CALLER, "ghost_mod.ghost_fn",
                        ("harness", "tests/test_no_such_file_at_all.py", "ghost_fn", "fabricated"))
    assert dg.resolve_named_caller("ghost_mod.ghost_fn")[0] == dg.FILE_UNREACHABLE
    assert dg.resolve_named_caller("not.in.the.list.at.all")[0] == dg.NOT_LISTED


def test_the_resolver_reads_a_file_at_the_repository_root(tmp_path):
    """POSITIVE CONTROL for the one state the container cannot exercise against the real tree.

    `mitm_addon.request` names `docker-compose.yml`, which sits beside `agent/` and is therefore absent
    when the suite runs with only `agent/` mounted. Tolerating that is only honest if the apparatus is
    proven to work when the file IS there, so this builds the real shape -- a root holding `agent/` and a
    compose file -- and drives the REAL entry with the REAL anchor through all three states.

    Without this, "file-unreachable" would be a state nothing ever escapes, which is a pass wearing a
    different word."""
    (tmp_path / "agent").mkdir()
    root = str(tmp_path / "agent")
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "  proxy:\n    command:\n"
        '      - "mkdir -p /data && exec mitmdump -p 8080 -s /addon/mitm_addon.py --set x=1"\n',
        encoding="utf8")
    status, path, lineno, line = dg.resolve_named_caller("mitm_addon.request", root)
    assert status == dg.RESOLVED, (status, path)
    assert lineno == 3 and "mitmdump" in line, (lineno, line)
    assert os.path.basename(path) == "docker-compose.yml"

    compose.write_text("  proxy:\n    image: mitmproxy/mitmproxy\n", encoding="utf8")
    assert dg.resolve_named_caller("mitm_addon.request", root)[0] == dg.ANCHOR_MISSING, (
        "the addon stopped being loaded and the resolver still called the excuse good")
    compose.unlink()
    assert dg.resolve_named_caller("mitm_addon.request", root)[0] == dg.FILE_UNREACHABLE


def test_the_unverifiable_entries_are_pinned_by_name_and_nothing_else_is():
    """The hole in the mechanism, bounded and counted.

    Exactly two entries cannot be checked in the environment the suite runs in. Naming them in a
    frozenset -- rather than writing a rule like "framework entries may be unverifiable" -- means a third
    one cannot appear by accident: it takes an edit here, reviewed the way a raised ratchet would be.
    Every other entry must resolve against the real tree on this run."""
    named = set(dg.ALLOWED_UNUSED_NAMED_CALLER)
    assert dg.NAMED_CALLER_OUTSIDE_CHECKOUT <= named, sorted(dg.NAMED_CALLER_OUTSIDE_CHECKOUT - named)
    assert len(dg.NAMED_CALLER_OUTSIDE_CHECKOUT) <= 2, sorted(dg.NAMED_CALLER_OUTSIDE_CHECKOUT)
    for entry in dg.NAMED_CALLER_OUTSIDE_CHECKOUT:
        kind, caller, _anchor, _why = dg.ALLOWED_UNUSED_NAMED_CALLER[entry]
        assert kind == "framework", "%s is unverifiable here without being framework-invoked" % entry
        assert not caller.startswith("tests/"), (
            "%s names %s as unreachable, but the test tree is mounted -- so it IS reachable and this "
            "entry is dodging the check" % (entry, caller))
    for entry in named - dg.NAMED_CALLER_OUTSIDE_CHECKOUT:
        assert dg.resolve_named_caller(entry)[0] == dg.RESOLVED, entry


def test_no_entry_cites_the_file_that_declares_it():
    """An anchor written into `deadcode_gate.py` is present in `deadcode_gate.py` BY CONSTRUCTION, so an
    entry naming that file as its caller would prove itself. Declaration-versus-fact, inside the
    instrument built to detect it -- rejected in the resolver and forbidden here, because a rule that
    only lives in one of those two places fails silently when it breaks."""
    for entry, rec in dg.ALLOWED_UNUSED_NAMED_CALLER.items():
        assert os.path.basename(rec[1]) != "deadcode_gate.py", (
            "%s cites the file that declares the allowlist as its own caller" % entry)


def test_the_resolver_refuses_a_self_citation(monkeypatch):
    """NEGATIVE CONTROL for the rule above: an entry citing `deadcode_gate.py`, with an anchor that IS
    genuinely in it, must still not resolve."""
    anchor = "ALLOWED_UNUSED_NAMED_CALLER = {"
    assert anchor in open(os.path.join(dg.APP_DIR, "deadcode_gate.py"), encoding="utf8").read(), (
        "positive control: the anchor must really be in the file, or refusing it proves nothing")
    monkeypatch.setitem(dg.ALLOWED_UNUSED_NAMED_CALLER, "deadcode_gate.self_citing",
                        ("harness", "deadcode_gate.py", anchor, "fabricated self-citation"))
    assert dg.resolve_named_caller("deadcode_gate.self_citing")[0] != dg.RESOLVED


def test_the_named_caller_list_does_not_overlap_the_other_two():
    """Three lists that can excuse an entry is two too many to keep straight by hand. They must be
    disjoint, or a reader cannot tell which justification is load-bearing -- the same reasoning that
    keeps ALLOWED_UNUSED and ALLOWED_UNUSED_QUALIFIED separate."""
    named = set(dg.ALLOWED_UNUSED_NAMED_CALLER)
    assert not (named & set(dg.ALLOWED_UNUSED_QUALIFIED)), sorted(named & set(dg.ALLOWED_UNUSED_QUALIFIED))
    bare = {e.rsplit(".", 1)[1] for e in named}
    assert not (bare & set(dg.ALLOWED_UNUSED)), sorted(bare & set(dg.ALLOWED_UNUSED))


def test_the_triaged_islands_are_still_counted():
    """The 17 REAL ISLANDS from the Q-078 triage are NOT excused, and this asserts it directly.

    The triage's whole risk is that "classified" quietly becomes "cleared". Being named in a handoff
    document is not a justification; only a resolvable caller is, and these have none. See
    docs/handoff/island_triage.md section 3.5 for the evidence per entry."""
    islands = {
        "api_protocols.inventory", "archive_intel.needs_validation", "bench_all.bench", "bie.observe",
        "capability_matrix.state_rank", "cloud_iam.collect_live", "codereview_graph.hypotheses",
        "codereview_graph.link_runtime_to_source", "exposure_tool.paths", "fingerprint.fingerprint",
        "ics_fingerprint.finding", "report.control_ran", "saml_tool.finding", "service_router.plan",
        "ssrf_tool.bypass_payloads", "techniques.classes", "tool_provenance.argv_hash",
    }
    assert len(islands) == 17
    assert islands < dg.QUALIFIED_Q077_REVEALED, "every triaged island came from the recorded 27"
    for e in islands:
        assert e not in dg.ALLOWED_UNUSED_NAMED_CALLER, "%s was excused, not wired" % e
        assert e not in dg.ALLOWED_UNUSED_QUALIFIED, e
        assert e.rsplit(".", 1)[1] not in dg.ALLOWED_UNUSED, e


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


# ── the accounting gate: what still fires while the ratchet is pinned (Q-078, run 3) ────────────

def test_no_flagged_entry_is_unaccounted_for(qual):
    """THE GATE THAT WORKS WHILE THE RATCHET IS PINNED. Not xfailed, and it must never become one.

    `test_the_ratchet_holds` is `xfail(strict=True)` at 51 against 37, so a RISE in the count cannot fail
    the suite — the test fails either way and the failure is the expected one. MEASURED by mutation on a
    copy of the real tree: appending an island to `security.py` took the count 51 -> 52 with the whole
    file still green, exit 0. The bare-name `scan()` gate is what would normally catch that, and
    `test_the_bare_name_scan_is_fooled_by_a_name_collision` shows the case it cannot see — which is the
    case the mutation used, a new `summarize` beside the existing hashid_tool/race_tool ones.

    So this asserts a different property, one the ceiling does not appear in: every flagged entry is one
    somebody has already measured and written down. 51 = 34 still-dead from `QUALIFIED_BASELINE_SET` +
    17 still-dead from `QUALIFIED_Q077_REVEALED`, exactly, with nothing left over."""
    assert qual["unaccounted"] == [], qual["message"]
    assert qual["accounted"]
    # The arithmetic, asserted rather than described: the two recorded sets partition what is flagged.
    flagged = set(qual["unused"])
    recorded = flagged & dg.QUALIFIED_BASELINE_SET
    revealed = flagged & dg.QUALIFIED_Q077_REVEALED
    assert len(recorded) + len(revealed) == qual["count"], (
        "%d recorded + %d Q-077-revealed != %d flagged" % (len(recorded), len(revealed), qual["count"]))
    # POSITIVE CONTROL: an empty `unaccounted` must mean the check looked and found nothing, never that
    # it had nothing to look at. Both sets must still be contributing entries to the count.
    assert recorded and revealed, "one of the recorded sets contributes nothing; the check is vacuous"


def test_the_accounting_gate_catches_the_island_the_pinned_ratchet_swallows(real_tree_copy, qual):
    """NEGATIVE CONTROL for the gate above, at real-tree scale and with the name that defeats `scan()`.

    A colliding name on purpose: `summarize` is already defined by `hashid_tool` and `race_tool`, so the
    bare-name scan sees the word and clears the new one. Under the pin, nothing else in this file goes
    red. This is the reproduction of that hole and the proof it is now closed."""
    before_unaccounted = qual["unaccounted"]
    assert before_unaccounted == [], "the real tree must be accounted for before the island is added"

    victim = os.path.join(real_tree_copy, "security.py")
    original = open(victim, encoding="utf8").read()
    open(victim, "a", encoding="utf8").write(
        "\n\ndef summarize(rows):\n"
        "    \"\"\"Q-078 negative control: an island whose NAME COLLIDES with hashid_tool.summarize.\"\"\"\n"
        "    return {\"n\": len(rows)}\n")
    try:
        after = dg.scan_qualified(real_tree_copy)
    finally:
        open(victim, "w", encoding="utf8").write(original)

    island = "security.summarize"
    assert island in after["unused"], "positive control: the qualified scan must SEE the island"
    assert after["unaccounted"] == [island], (
        "the accounting gate must name the island and nothing else; it named %s" % after["unaccounted"])
    assert "UNACCOUNTED" in after["message"] and island in after["message"]
    # And the half that makes this worth having: the COUNT ratchet says nothing new. It was already
    # False, so the strict xfail is satisfied by the same failure before and after — which is exactly
    # how a new island travelled in unnoticed.
    assert after["ok"] is False and qual["ok"] is False
    assert after["count"] == qual["count"] + 1


def test_a_recorded_measurement_cannot_grow_to_absorb_a_new_island():
    """The one dishonest way to satisfy the accounting gate is to record the new island as if it had
    always been there. Both sets are therefore bounded at the sizes they were MEASURED at.

    They may SHRINK — an entry leaves a recorded set when someone deletes it after wiring the function,
    and `resolved` reports that drift meanwhile. They may not grow. If a future resolver fix reveals more
    genuinely-dead entries the way Q-077 did, that is a triage ticket with evidence per entry, not an
    edit to a number here — and forcing that edit to be deliberate and reviewed is the entire point."""
    assert len(dg.QUALIFIED_BASELINE_SET) <= 35, (
        "the baseline set was MEASURED at 35 entries on a clean HEAD snapshot; growing it to %d absorbs "
        "an island into a record of a measurement that never included it"
        % len(dg.QUALIFIED_BASELINE_SET))
    assert len(dg.QUALIFIED_Q077_REVEALED) == 27, "the Q-077 delta was measured at exactly 27"
    assert not (dg.QUALIFIED_BASELINE_SET & dg.QUALIFIED_Q077_REVEALED), "the two records must be disjoint"
    assert dg.RECORDED_QUALIFIED == dg.QUALIFIED_BASELINE_SET | dg.QUALIFIED_Q077_REVEALED
    # Neither record may quietly become an allowlist. The rule is DIRECTIONAL and run 3 had it flat:
    # see RECORDED_THEN_EXCUSED. Excusing a recorded entry is the move that drops the count without
    # wiring anything, so it costs an edit here as well as one to the allowlist.
    assert _recorded_entries_excused_without_a_pin(
        dg.RECORDED_QUALIFIED, dg.ALLOWED_UNUSED_NAMED_CALLER, dg.ALLOWED_UNUSED_QUALIFIED,
        dg.ALLOWED_UNUSED, dg.RECORDED_THEN_EXCUSED) == []


def _recorded_entries_excused_without_a_pin(recorded, named_caller, prose, bare, pin):
    """Every recorded entry that some allowlist excuses and RECORDED_THEN_EXCUSED does not account for.

    All THREE excuse paths, because `scan_qualified._justified` honours three and a check that knew
    about two would pass the one it exists to catch -- the shape run 2 recorded in §8.3, where a test
    named for two allowlists silently ignored a third."""
    return sorted(e for e in recorded
                  if (e in named_caller or e in prose or e.split(".")[-1] in bare) and e not in pin)


def test_the_recorded_then_excused_pin_is_bounded_and_every_member_earns_its_place():
    """The pin's own integrity, checked in BOTH directions, plus the control that keeps it non-vacuous.

    A pin that may hold any name is not a pin. Bounded at the 9 MEASURED, and every member must still be
    BOTH recorded AND excused -- so a name whose excuse was withdrawn cannot squat here and quietly stay
    exempt from the directional rule."""
    assert len(dg.RECORDED_THEN_EXCUSED) <= 9, (
        "9 recorded-then-excused entries were MEASURED; growing to %d without a triage entry per name is "
        "how the exemption widens" % len(dg.RECORDED_THEN_EXCUSED))
    for e in dg.RECORDED_THEN_EXCUSED:
        assert e in dg.RECORDED_QUALIFIED, "%s is pinned as recorded-then-excused but is in no record" % e
        assert e in dg.ALLOWED_UNUSED_NAMED_CALLER, (
            "%s is pinned as excused but no allowlist excuses it; the pin is stale and the entry is "
            "exempt from the directional rule for nothing" % e)
    # POSITIVE CONTROL: the apparatus had something to look at. The pin is non-empty and it is exactly
    # the overlap that exists on this tree, so the check above ran over 9 real names rather than none.
    assert dg.RECORDED_THEN_EXCUSED, "an empty pin makes the directional rule flat again"
    # EXACT, not merely bounded, and only for the named-caller path -- which is where all 9 live. It says
    # a name cannot be pinned BEFORE it is excused: pre-loading the pin would be pre-authorising a future
    # excuse. The other two excuse paths carry no members today, so the main assertion above is what has
    # teeth for them, and it is the reason that assertion checks all three rather than this one.
    assert dg.RECORDED_THEN_EXCUSED == dg.RECORDED_QUALIFIED & frozenset(dg.ALLOWED_UNUSED_NAMED_CALLER)

    # NEGATIVE CONTROL: the same helper, driven with a recorded entry that IS excused and is NOT pinned,
    # must name it. Without this the main assertion's empty list would be indistinguishable from a helper
    # that never looks at anything -- and one of run 2's four red tests was exactly that.
    victim = sorted(dg.RECORDED_QUALIFIED - dg.RECORDED_THEN_EXCUSED)[0]
    # The bare-name path below keys on `victim`'s last segment, so a second recorded entry sharing it
    # would make the control expect the wrong list. Asserted rather than assumed.
    assert [e for e in dg.RECORDED_QUALIFIED if e.split(".")[-1] == victim.split(".")[-1]] == [victim]
    caught = _recorded_entries_excused_without_a_pin(
        dg.RECORDED_QUALIFIED, {victim: ("harness", "x", "y", "z")}, {}, {},
        dg.RECORDED_THEN_EXCUSED)
    assert caught == [victim], "the check must name an unpinned excused entry; it returned %r" % caught
    # And once for each of the other two excuse paths, so none of the three is decorative.
    assert _recorded_entries_excused_without_a_pin(
        dg.RECORDED_QUALIFIED, {}, {victim: "prose"}, {}, dg.RECORDED_THEN_EXCUSED) == [victim]
    assert _recorded_entries_excused_without_a_pin(
        dg.RECORDED_QUALIFIED, {}, {}, {victim.split(".")[-1]: "bare"}, dg.RECORDED_THEN_EXCUSED) == [victim]
    # ...and the pin really does suppress: the same victim, pinned, is not reported.
    assert _recorded_entries_excused_without_a_pin(
        dg.RECORDED_QUALIFIED, {victim: ("harness", "x", "y", "z")}, {}, {},
        dg.RECORDED_THEN_EXCUSED | {victim}) == []


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


def test_the_qualified_scan_honours_all_three_allowlists(qual):
    """A function with a written justification is unwired-but-explained, not unwired-and-unexplained.
    Counting both toward the ratchet makes the number mean two things at once.

    THREE lists, deliberately, and this test was called `..._both_allowlists` until Q-078 added the
    third — a name asserting "both" over three things is the same prose-versus-fact rot the gate exists
    to catch, so it was renamed rather than quietly left to drift.

      ALLOWED_UNUSED             `scan()`'s list: a mention anywhere, tests included, counts as a use.
      ALLOWED_UNUSED_QUALIFIED   `scan_qualified()`'s: a production caller through a resolved import.
      ALLOWED_UNUSED_NAMED_CALLER  Q-078's: the caller exists but lives where neither scan looks, so the
                                 entry NAMES it and a resolver opens the file and finds it.

    The first two disagree about what "unused" means — an entry unused-to-one and used-to-the-other makes
    a shared list wrong for whichever disagrees, and `scan()`'s staleness check keeps flagging it. The
    third is a different kind of claim: not "this is fine" but "here is the caller", which is why it is
    the only one whose justification is checked rather than read."""
    assert qual["allowed"], "the allowlists should still be catching some entries"
    for name in qual["allowed"]:
        assert (name.split(".")[-1] in dg.ALLOWED_UNUSED or name in dg.ALLOWED_UNUSED_QUALIFIED
                or name in dg.ALLOWED_UNUSED_NAMED_CALLER), name
        # An entry excused by the third list is excused by a FACT, so the fact is checked here too --
        # otherwise the scan could honour a list the resolver has already stopped agreeing with.
        if name in dg.ALLOWED_UNUSED_NAMED_CALLER:
            assert dg.resolve_named_caller(name)[0] != dg.ANCHOR_MISSING, (
                "%s is excused by a caller that is no longer in the file it names" % name)
    assert not (set(qual["unused"]) & set(qual["allowed"])), "an entry cannot be both"
    # POSITIVE CONTROL: the third list must actually be doing work in the scan, not merely existing.
    assert set(qual["allowed"]) & set(dg.ALLOWED_UNUSED_NAMED_CALLER), (
        "no named-caller entry reached the scan's allowed list -- either the scan stopped honouring it "
        "or every entry has been wired, in which case the list should shrink")


def _module_functions():
    """{function name: {modules that define it}} across the production tree. Read from the AST, so a
    name that only appears in a comment is not a definition of anything."""
    out = {}
    for fn in sorted(os.listdir(dg.APP_DIR)):
        if not fn.endswith(".py"):
            continue
        try:
            tree = ast.parse(open(os.path.join(dg.APP_DIR, fn), encoding="utf8").read())
        except Exception:
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.setdefault(node.name, set()).add(fn[:-3])
    return out


def test_every_bare_allowlist_entry_names_the_module_that_defines_it():
    """ALLOWED_UNUSED's reasons are `"<module>: <why>"`, and that prefix is now LOAD-BEARING: it is the
    only module `scan_qualified` will excuse the name in. So it has to be true, not merely written.

    A typo'd or stale owner fails closed -- the entry stops excusing anything and the count rises -- which
    is the safe direction but a confusing way to learn about it. This says it plainly instead."""
    defined = _module_functions()
    # POSITIVE CONTROL: the reader found real definitions before any conclusion is drawn from absence.
    assert len(defined) > 500, "only %d functions parsed; the reader is blind" % len(defined)
    assert "scan_qualified" in defined, "the reader cannot see a function it is running inside"

    assert set(dg.ALLOWED_UNUSED_OWNER) == set(dg.ALLOWED_UNUSED), "every entry must yield an owner"
    for name, owner in dg.ALLOWED_UNUSED_OWNER.items():
        assert owner, "%s: no module prefix in its reason, so it now excuses nothing" % name
        assert name in defined, "%s is allowlisted but no module defines it" % name
        assert owner in defined[name], (
            "%s says it belongs to %r but is defined in %s -- the exemption applies to a module that "
            "does not have this function" % (name, owner, sorted(defined[name])))


def test_a_justification_written_for_one_module_does_not_excuse_another(real_tree_copy, qual):
    """NEGATIVE CONTROL, and the hole it closes was live until Q-078 run 4.

    `ALLOWED_UNUSED` is keyed by bare name; `scan_qualified` entries are `module.function`. Matching the
    halves meant one line of prose about `wordlists.payloads_for` excused a brand-new dead function named
    `payloads_for` in ANY module. That defeats the count ratchet AND the accounting gate above it, so
    while the strict xfail is pinned it was a completely silent path for new dead code.

    Paired with its control, because a mutation that nothing catches proves nothing on its own: the same
    island under an ordinary name must be caught, so the difference is the allowlist and not the scan."""
    victim = os.path.join(real_tree_copy, "security.py")
    original = open(victim, encoding="utf8").read()
    borrowed = sorted(n for n, o in dg.ALLOWED_UNUSED_OWNER.items() if o != "security")[0]
    assert borrowed not in original, "%s must not already be in security.py for this to mean anything" % borrowed

    def _with(fn_name):
        open(victim, "w", encoding="utf8").write(
            original + "\n\ndef %s(rows):\n    return {'n': len(rows)}\n" % fn_name)
        return dg.scan_qualified(real_tree_copy)

    try:
        stolen = _with(borrowed)
        plain = _with("brand_new_island_fn")
    finally:
        open(victim, "w", encoding="utf8").write(original)

    entry = "security." + borrowed
    assert entry in stolen["unused"], (
        "%s is excused by a justification written about %s -- one module's reason must not cover "
        "another's function" % (entry, dg.ALLOWED_UNUSED_OWNER[borrowed]))
    assert stolen["unaccounted"] == [entry], stolen["unaccounted"]
    assert entry not in stolen["allowed"]
    # CONTROL: an ordinary name is caught the same way, so the borrowed name is not being caught by some
    # unrelated property of `security.py`.
    assert plain["unaccounted"] == ["security.brand_new_island_fn"]
    assert stolen["count"] == plain["count"] == qual["count"] + 1
    # ...and the owner's own entry is STILL excused. A fix that closed the hole by disabling the
    # allowlist would pass everything above and be a different, worse bug.
    owner_entry = "%s.%s" % (dg.ALLOWED_UNUSED_OWNER[borrowed], borrowed)
    assert owner_entry in qual["allowed"], (
        "%s must still be excused in its own module; the hole was the borrowing, not the list" % owner_entry)


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


# ── Q-078 run 5: documenting an exemption must not retire it ─────────────────────────────────────

def _an_allowlisted_name():
    """One ALLOWED_UNUSED key, chosen at RUNTIME. Never written as a literal anywhere in this file --
    see `test_this_file_does_not_reference_the_names_it_defends`, which is not fastidiousness but the
    defect that produced this whole slice."""
    return sorted(dg.ALLOWED_UNUSED)[0]


def _refs_in(path):
    """(every AST-visible reference in `path`, nodes walked). Same three kinds `_ast_reference_sites`
    counts, re-derived here so the test does not check the gate against itself."""
    seen, nodes = set(), 0
    with warnings.catch_warnings():
        # Same reason the gate suppresses here: compiling a file re-emits its SyntaxWarnings against
        # `<unknown>` and against whichever test triggered the read. See
        # `test_reading_the_corpus_does_not_re_report_another_file_s_warning`.
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(open(path, encoding="utf8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            ref = node.id
        elif isinstance(node, ast.Attribute):
            ref = node.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            ref = node.value
        else:
            continue
        nodes += 1
        seen.add(ref)
    return seen, nodes


def test_this_file_does_not_reference_the_names_it_defends():
    """THE TRAP THIS SLICE FELL INTO, pinned so the next run cannot repeat it.

    `scan()` reads `agent/tests/*.py`, and under the AST rule a whole string constant equal to an
    allowlisted name IS a reference. So writing one of those six names as a literal in the file that
    guards them would retire the entry it is testing -- the control's own text becoming the evidence,
    which is §8.2's defect one rule later.

    Run 4 hit the regex version of this: two sentences in a docstring explaining the
    `wordlists.payloads_for` exemption pushed that entry into `stale_allowlist` and turned
    `test_the_allowlist_does_not_rot` red demanding its deletion. MEASURED, on `git archive HEAD` versus
    HEAD plus run 4's files: 1 corpus hit (the `def` line) versus 3 (+ two docstring lines here), stale
    [] versus ['payloads_for']. No caller existed in either tree."""
    here = os.path.join(dg.APP_DIR, "tests", "test_deadcode_gate.py")
    seen, nodes = _refs_in(here)
    # POSITIVE CONTROL: the walk is looking. Without this an empty intersection is equally consistent
    # with a reader that parsed nothing.
    assert nodes > 500, "only %d reference nodes in this file; the walk is blind" % nodes
    assert "ALLOWED_UNUSED" in seen, "the walk cannot see an attribute this file demonstrably uses"
    collide = sorted(seen & set(dg.ALLOWED_UNUSED))
    assert not collide, (
        "this file references %s, which ALLOWED_UNUSED excuses -- so the gate's own test now retires "
        "the entries it defends. Build the name at runtime (_an_allowlisted_name) instead of writing "
        "it as a literal." % collide)


def test_prose_about_an_allowlisted_entry_does_not_retire_it(tmp_path):
    """NEGATIVE CONTROL AND ITS PAIR, and the pair is the whole point: a rule that never reports
    staleness would pass the first half alone.

    Run on a handful of synthetic files rather than a copy of the real tree because `scan()` over the
    corpus costs ~135s MEASURED -- the code path is identical, only the walk is smaller."""
    name = _an_allowlisted_name()
    prose = tmp_path / "prose"
    prose.mkdir()
    (prose / "talks.py").write_text(
        "# %s() is the documented operator-facing variant and is kept deliberately.\n"
        "def unrelated():\n"
        '    """This module explains why %s stays on the allowlist. It does not call %s."""\n'
        "    return 1\n" % (name, name, name), encoding="utf8")
    only_prose = dg.scan(str(prose))
    assert only_prose["reference_nodes"] > 0, "positive control: the reference reader saw nothing at all"
    assert only_prose["stale_allowlist"] == [], (
        "a comment and a docstring ABOUT %s were read as a call to it: %s"
        % (name, only_prose["stale_sites"]))

    # THE PAIR. Same directory, same allowlist, one real attribute reference added. If this does not
    # fire, the fix above did not make the check honest -- it made it silent.
    called = tmp_path / "called"
    called.mkdir()
    (called / "talks.py").write_text((prose / "talks.py").read_text(encoding="utf8"), encoding="utf8")
    (called / "uses.py").write_text(
        "import wordlists as wl\n\n\ndef go(x):\n    return wl.%s(x)\n" % name, encoding="utf8")
    real = dg.scan(str(called))
    assert real["stale_allowlist"] == [name], (
        "a genuine call to %s must retire its entry; got %s" % (name, real["stale_allowlist"]))
    assert real["stale_sites"][name] == "uses.py:5", real["stale_sites"]


def test_a_bare_name_and_a_dispatch_string_also_retire_an_entry(tmp_path):
    """The other two reference kinds, so the pair above is not read as "only attributes count".

    `from wordlists import payloads_for` then a bare use is an `ast.Name`; `getattr(mod, "...")` dispatch
    is a whole string constant. Both are real wiring and both must retire an entry, or a function could
    be wired through either and keep its exemption."""
    name = _an_allowlisted_name()
    for label, body in (("bare", "from wordlists import %s\n\n\ndef go(x):\n    return %s(x)\n"),
                        ("dispatch", "import wordlists as wl\n\n\ndef go(x):\n"
                                     '    return getattr(wl, "%s")(x)\n')):
        d = tmp_path / label
        d.mkdir()
        (d / "uses.py").write_text(body.replace("%s", name), encoding="utf8")
        assert dg.scan(str(d))["stale_allowlist"] == [name], "%s reference missed" % label

    # CONTROL: a string that merely CONTAINS the name is prose, not dispatch. This is the exact
    # distinction the regex could not draw, so it is asserted rather than assumed.
    d = tmp_path / "substring"
    d.mkdir()
    (d / "uses.py").write_text(
        'def go():\n    return "see %s for the operator path"\n' % name, encoding="utf8")
    assert dg.scan(str(d))["stale_allowlist"] == []


def test_the_declaring_file_would_retire_its_own_allowlist_if_it_were_read(tmp_path):
    """MUTATION, proving the self-exclusion in `_ast_reference_sites` is load-bearing and not inherited
    superstition.

    Every ALLOWED_UNUSED key is a whole string constant in `deadcode_gate.py`, so the whole-string rule
    matches all of them exactly. Read that file and the allowlist retires itself -- the declaration
    proving the fact, which is the shape this module exists to catch. The mutation cannot be applied by
    editing the module, so the file is copied in under a name the exclusion does not match."""
    src = open(os.path.join(dg.APP_DIR, "deadcode_gate.py"), encoding="utf8").read()
    (tmp_path / "copy_of_the_gate.py").write_text(src, encoding="utf8")
    mutant, nodes = dg._ast_reference_sites(str(tmp_path), set(dg.ALLOWED_UNUSED))
    assert nodes > 0, "positive control: the reader saw nothing"
    assert set(mutant) == set(dg.ALLOWED_UNUSED), (
        "the mutation must retire EVERY entry, or the exclusion is guarding less than it claims: %s"
        % sorted(set(dg.ALLOWED_UNUSED) - set(mutant)))

    # The exclusion restored: same bytes, real basename, nothing retired.
    (tmp_path / "deadcode_gate.py").write_text(src, encoding="utf8")
    os.remove(str(tmp_path / "copy_of_the_gate.py"))
    guarded, nodes2 = dg._ast_reference_sites(str(tmp_path), set(dg.ALLOWED_UNUSED))
    assert nodes2 == 0, "the declaring file was read anyway: %s" % guarded
    assert guarded == {}


def test_reading_the_corpus_does_not_re_report_another_file_s_warning(tmp_path):
    r"""`_ast_reference_sites` is the first thing in this module to COMPILE `tests/*.py`, and compiling
    re-emits every SyntaxWarning those files carry -- blamed on `<unknown>:<line>` and on whichever test
    triggered the scan.

    MEASURED at clean HEAD: `tests/test_client_request_source.py:95` has `\w` in a non-raw docstring;
    pytest already reports it against that file and line, and this reader added a second copy naming
    `test_no_unexplained_dead_functions`. A gate that attributes another file's defect to itself is
    noise a reader learns to ignore, which is how a gate stops being read at all.

    This docstring is RAW and the fixture below builds its backslash with `chr(92)`, because the first
    version of this test wrote both as literals and so introduced two fresh copies of the exact warning
    it exists to remove -- MEASURED, `tests/test_deadcode_gate.py:1096` and `:1103` in the run that
    caught it.

    POSITIVE CONTROL FIRST: the same source, compiled without the suppression, must genuinely warn --
    otherwise this test passes on a Python that does not emit SyntaxWarning here and proves nothing."""
    src = ('def go():\n    """a docstring with an invalid escape: %sw+"""\n    return 1\n' % chr(92))
    (tmp_path / "noisy.py").write_text(src, encoding="utf8")
    with warnings.catch_warnings(record=True) as control:
        warnings.simplefilter("always")
        compile(src, "noisy.py", "exec")
    assert any(issubclass(w.category, SyntaxWarning) for w in control), (
        "positive control: this source does not warn on this interpreter, so the check below is vacuous")

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        dg._ast_reference_sites(str(tmp_path), set(dg.ALLOWED_UNUSED))
    assert not [w for w in caught if issubclass(w.category, SyntaxWarning)], (
        "reading the corpus re-reported another file's SyntaxWarning: %s"
        % [str(w.message) for w in caught])


# ── Q-078 run 5, the island hunt: a dead function's reference launders its helpers ────────────────

def _delete_top_level(path, names):
    """Cut the named top-level functions out of a module, bottom-up so the line numbers hold."""
    text = open(path, encoding="utf8").read()
    lines = text.split("\n")
    for lo, hi in sorted(((n.lineno, n.end_lineno) for n in ast.parse(text).body
                          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names),
                         reverse=True):
        del lines[lo - 1:hi]
    open(path, "w", encoding="utf8").write("\n".join(lines))


def _callerless(res):
    """Every entry `scan_qualified` found unreachable that has NO caller of any kind.

    `ALLOWED_UNUSED_NAMED_CALLER` is subtracted, and that subtraction is the whole difference between a
    measurement and a scare: those ten entries DO have callers -- pytest, mitmdump, `nosqli_tool` -- so
    deleting them falsely orphans their helpers. MEASURED: the first version of this experiment deleted
    them and reported 20 "new" islands, most of them helpers of mitmdump's addon hooks and of this
    gate's own pytest entry points. Correcting the seed took it to 11."""
    return {e for e in set(res["unused"]) | set(res["allowed"])
            if e not in dg.ALLOWED_UNUSED_NAMED_CALLER}


def _transitive_callerless(work, rounds=8):
    """(single_pass, fixed_point, per_round) -- iteratively delete every callerless function and
    re-resolve, so a function whose only references came from code already proven dead becomes visible.

    Destructive, so `work` must be a COPY. Converges in 3 rounds on this tree."""
    first = _callerless(dg.scan_qualified(work))
    seen, per_round = set(first), []
    for _ in range(rounds):
        by_mod = {}
        for e in seen:
            m, _sep, f = e.rpartition(".")
            by_mod.setdefault(m, set()).add(f)
        for m, funcs in by_mod.items():
            p = os.path.join(work, m + ".py")
            if os.path.isfile(p):
                _delete_top_level(p, funcs)
        new = _callerless(dg.scan_qualified(work)) - seen
        per_round.append(sorted(new))
        if not new:
            break
        seen |= new
    return first, seen, per_round


# MEASURED on a clean `git archive HEAD` snapshot (5d72aa3), fixed point reached in 3 rounds:
#
#   single pass  59 callerless      fixed point  74      transitive-only  15
#
# Each of these has NO caller that is itself reachable. They are invisible to every scan in this
# repository because `scan_qualified` counts ANY reference inside the defining module as life, and does
# not ask whether the referring function is itself dead. So a recorded island conceals its own helpers,
# and the count is a floor for a second reason on top of Q-077's.
#
# Every entry names the ALREADY-RECORDED island it hangs off, which is the "name the caller" rule
# pointed the only direction it can point for a genuinely dead function -- name the dead thing that
# reaches it:
#
#   security.is_valid_target          <- security.validate_targets      (ALLOWED_UNUSED)
#   bench_all.aggregate               <- bench_all.bench                (QUALIFIED_BASELINE_SET, 3.5)
#   bie._css_quote/locator_chain/
#      locator_quality                <- bie.observe                    (QUALIFIED_BASELINE_SET, 3.5)
#   saml_tool.strip_signatures        <- saml_tool.finding / confirm_bypass
#   cvss4.is_valid, mission_export.validate   <- a round-0 dead function in their own module
#   web_security._is_host_rule, _rule_matches_url, _host_matches_rule,
#      _looks_like_host_identifier, _path_matches_rule, _is_path_rule
#                                     <- web_security.is_url_in_scope   (QUALIFIED_BASELINE_SET)
#
# The web_security six are the find. `is_url_in_scope` is ONE line in QUALIFIED_BASELINE_SET and it
# conceals a six-function private cluster -- the host/path-aware scope matcher, lines 123-220. Its
# producer `ScopeEngine.to_rules` is likewise dead (METHOD_BASELINE_SET), and `scope.py:8` and
# `scope.py:267` both declare in prose that `to_rules` is "consumed by web_security.is_url_in_scope".
# Producer and consumer are both dead, each documented as feeding the other, and the only thing that
# runs the pipeline is a test. Scope IS still enforced -- `ScopeEngine.validate()` is called at ~20
# sites in agent.py -- by the coarser host check, not by this one. That distinction is the difference
# between a finding and a false alarm and is stated rather than left to the reader.
#
# `ics_fingerprint.is_write_frame` was the 15th and left this set the way the `gone` assertion below
# demands be confirmed: DELETED, not wired. Q-078 run 6 removed `agent/ics_fingerprint.py` whole -- the
# cluster it hung off was 8 of 8 dead, and this entry was the 8th, laundered by `is_read_only` in the
# same file. It is recorded here rather than dropped silently because "the fixed point shrank" is a
# claim, and the reason it shrank is the thing a reader needs.
TRANSITIVE_ONLY = frozenset({
    "bench_all.aggregate", "bie._css_quote", "bie.locator_chain", "bie.locator_quality",
    "cvss4.is_valid", "mission_export.validate",
    "saml_tool.strip_signatures", "security.is_valid_target", "web_security._host_matches_rule",
    "web_security._is_host_rule", "web_security._is_path_rule",
    "web_security._looks_like_host_identifier", "web_security._path_matches_rule",
    "web_security._rule_matches_url",
})


@pytest.fixture
def disposable_tree_copy(tmp_path_factory):
    """A copy of the real tree that this test is allowed to DESTROY, and deliberately not
    `real_tree_copy`.

    `real_tree_copy` is `scope="module"` and shared with two other tests. Both of those mutate one file
    and restore it in a `finally`; the fixed point below deletes dozens of functions across dozens of
    modules and cannot put them back. Reusing it would have left whichever tests ran afterwards
    measuring a tree this one had hollowed out -- a green suite reporting on a corpus that no longer
    exists. Function-scoped, so every run starts from the real bytes."""
    dst = str(tmp_path_factory.mktemp("transitive"))
    for fn in os.listdir(dg.APP_DIR):
        if fn.endswith(".py"):
            shutil.copyfile(os.path.join(dg.APP_DIR, fn), os.path.join(dst, fn))
    return dst


def test_a_dead_function_s_reference_launders_its_helpers(disposable_tree_copy):
    """A RECORDED MEASUREMENT of what no scan in this repository can see, and a ratchet on it.

    This is NOT a raised ceiling: `QUALIFIED_BASELINE` is untouched and this number never feeds it. It
    is a new, previously unmeasured quantity, recorded at the value it was found at.

    Run on a COPY because it deletes functions to find the next layer."""
    single, fixed, per_round = _transitive_callerless(disposable_tree_copy)
    # POSITIVE CONTROL: the scan saw a real tree, not an empty directory.
    assert len(single) > 40, "only %d callerless entries; the scan is not reading the tree" % len(single)
    assert per_round and not per_round[-1], "the fixed point did not converge: %s" % per_round

    extra = fixed - single
    new = sorted(extra - TRANSITIVE_ONLY)
    gone = sorted(TRANSITIVE_ONLY - extra)
    assert not new, (
        "functions with no reachable caller that NO scan here reports -- their only references come "
        "from code already proven dead. Triage each one and add it to TRANSITIVE_ONLY with the island "
        "it hangs off, or wire it: %s" % new)
    assert not gone, (
        "these were transitively dead and are not any more, which is the good direction -- confirm each "
        "was WIRED rather than deleted, then remove it from TRANSITIVE_ONLY: %s" % gone)


def test_the_transitive_pass_measures_laundering_and_not_something_else(tmp_path):
    """NEGATIVE CONTROL for the test above, on a tree small enough to reason about completely.

    `helper` is referenced exactly once, from `island`, which nothing calls. The single pass must clear
    `helper` -- that IS the blind spot -- and the fixed point must catch it. Without this, the recorded
    set above is a list of names with no demonstrated mechanism behind it."""
    (tmp_path / "a.py").write_text(
        "def helper():\n    return 1\n\n\ndef island():\n    return helper()\n", encoding="utf8")
    single, fixed, _rounds = _transitive_callerless(str(tmp_path))
    assert single == {"a.island"}, single
    assert fixed == {"a.island", "a.helper"}, fixed

    # PAIR: a helper reached from a LIVE function must survive the fixed point, or the pass would
    # simply be deleting the whole tree one layer at a time.
    (tmp_path / "b.py").write_text(
        "import a\n\n\ndef used():\n    return a.helper()\n", encoding="utf8")
    (tmp_path / "c.py").write_text(
        "import b\n\n\ndef go():\n    return b.used()\n\n\nENTRY = go\n", encoding="utf8")
    single2, fixed2, _r2 = _transitive_callerless(str(tmp_path))
    assert "a.helper" not in single2 and "a.helper" not in fixed2, (single2, fixed2)


# Backticked `_private` tokens in this gate's prose that belong to some OTHER module, or to no module at
# all. Two entries, each naming where it lives -- the same contract every allowlist in `deadcode_gate.py`
# carries, applied to its paperwork. A third costs a deliberate edit here.
PROSE_FOREIGN = {
    "_intel": "tools.py's import alias for the intel module; the Q-078 blind-spot example",
    "_run_x": "a naming PATTERN in the string-dispatch rule, not a function that exists anywhere",
}


def test_the_gate_s_prose_only_names_helpers_that_exist():
    """The file's whole thesis, applied to the file: prose that names code must be checked.

    Written because run 5 produced a live instance of the defect within minutes of writing about it. The
    module docstring said "`stale` is now resolved off the AST (`_ast_referenced_names`)" after the
    helper had been renamed to `_ast_reference_sites`. Nothing failed. A reader would have searched for a
    function that does not exist, in the file whose entire subject is prose asserting things the code
    does not do.

    Scoped to backticked `_private` names because a leading underscore means "local to this module", so
    the claim is checkable without a judgement call. Anything genuinely foreign goes in PROSE_FOREIGN
    with its home named."""
    src = open(os.path.join(dg.APP_DIR, "deadcode_gate.py"), encoding="utf8").read()
    tree = ast.parse(src)
    defined = {n.name for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    defined |= {t.id for n in tree.body if isinstance(n, ast.Assign)
                for t in n.targets if isinstance(t, ast.Name)}

    cited = set(re.findall(r"`(_[a-z][A-Za-z0-9_]*)`", src))
    # POSITIVE CONTROL: the reader found real citations, and found the one this test was written for.
    assert len(cited) >= 3, "only %s cited; the extractor is not reading the prose" % sorted(cited)
    assert "_ast_refs" in cited, "the extractor cannot see a citation that is demonstrably in the file"

    missing = sorted(n for n in cited if n not in defined and n not in PROSE_FOREIGN)
    assert not missing, (
        "this module's prose names %s, which it does not define -- renamed, deleted, or a typo. Fix the "
        "prose, or add it to PROSE_FOREIGN naming the module it really lives in." % missing)
    # ...and the exemptions must stay exemptions: a name that this module HAS defined must not sit in
    # PROSE_FOREIGN claiming to be somebody else's.
    squatting = sorted(n for n in PROSE_FOREIGN if n in defined)
    assert not squatting, "PROSE_FOREIGN claims %s is foreign, but this module defines it" % squatting
