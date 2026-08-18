"""
Dead-code gate — every top-level function must have a caller (#125).

The no-island doctrine says an engine must feed the rest of the platform. This applies the same rule one
level down: a function nobody calls is either an integration gap (something that SHOULD be wired and
isn't) or maintenance debt that will eventually be called by mistake.

Both failure modes were real here. The first sweep found `dom_trace.trace_param`, a fully-written
source-to-sink tracer emitting exactly the families a benchmark had just missed — which looked like a
smoking gun until inspection showed `tools._run_dom_trace` reimplements the same logic asynchronously and
is the live path. So it was the second kind: a superseded duplicate sitting next to the real engine,
waiting for someone to call the wrong one.

Framework-invoked functions have no in-repo caller by design (FastAPI routes, pytest tests, middleware).
Those are recognised structurally — a decorated top-level function is assumed framework-called — rather
than by maintaining a name list that would rot.

**`scan()` UNDER-REPORTS, and by more than "conservative" suggests.** It matches a BARE NAME across the
whole corpus, so a function counts as used the moment any unrelated module mentions the same word. 90
function names in this codebase are defined in more than one module (`finding` x30, `analyze` x20,
`probe` x11). It also counts test files, so a function only its own test calls looks wired.

That is not theoretical. `probe_selection.pairwise`, `safety_label` and `full_grid` had no production
caller while `scan()` reported nothing, because `coverage` and `describe` collide with same-named
functions in `main.py`, `report.py`, `wstg_catalog.py` and `stealth.py`. Following that thread found
`graphql_argument_injection` running on paper only.

`scan_qualified()` is the honest check: module-resolved, import-alias-aware, production-only. It reports
substantially more, and those extras are CANDIDATES, not proven-dead — several will be reachable through
patterns it does not model. So it ships as a RATCHET (`QUALIFIED_BASELINE`) rather than a blocking gate:
the number may go down, never up. New dead code fails immediately; the existing backlog gets triaged
deliberately instead of bulk-deleted, which is what "remove obsolete code only after proving it is
unused" requires.
"""
from __future__ import annotations

import ast
import os
import re

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Prefixes for functions a framework or protocol calls, never our code.
_FRAMEWORK_PREFIX = re.compile(r"^(main$|test_|_?__)")

# Known-unused, deliberately kept. Each entry must say WHY, or it does not belong here.
ALLOWED_UNUSED = {
    "build_error_xml": "xxe_tool: error-based XXE variant kept for the operator-driven path; not auto-fired",
    "extract_script_srcs": "dependency_intel: alternate extraction path retained for non-HTML inputs",
    "is_ics_ot": "service_router: safety predicate kept available to any future ICS caller; trivially correct",
    "payloads_for": "wordlists: operator/API-facing helper",
    "seclists_available": "wordlists: environment probe used by operators to check SecLists presence",
    "validate_targets": "security: batch validator kept beside is_valid_target for API callers",
}


# Justifications for the QUALIFIED scan only. Kept SEPARATE from ALLOWED_UNUSED on purpose: the two
# scans disagree about what "unused" means -- `scan()` counts a mention anywhere (including tests) as a
# use, `scan_qualified()` requires a production caller through a resolved import. An entry that is
# unused-to-one and used-to-the-other makes a shared list wrong for whichever scan disagrees, and
# `scan()`'s staleness check will keep flagging it. Learned by putting two SAML entries in the wrong
# list and failing test_the_allowlist_does_not_rot.
ALLOWED_UNUSED_QUALIFIED = {
    "saml_tool.confirm_bypass": "judges a REPLAYED tampered assertion; the replay is a state-changing "
                                "authentication attempt, so it stays operator-gated. run_saml auto-fires "
                                "only the passive harvest+analyze half",
    "saml_tool.wrap_assertion": "builds the XML-signature-wrapping variant; generating a forged "
                                "assertion is not something to auto-fire. Same gate as confirm_bypass",
}


def _decorated(node) -> bool:
    return bool(getattr(node, "decorator_list", None))


def scan(app_dir: str = None) -> dict:
    """{unused, allowed, stale_allowlist}. Conservative: a name appearing anywhere outside its own
    definition counts as used, so this under-reports rather than over-reports."""
    app = app_dir or APP_DIR
    defs, corpus = {}, {}
    for fn in sorted(os.listdir(app)):
        # This module must exclude ITSELF: ALLOWED_UNUSED names every allowlisted function, so counting
        # those mentions would make each entry look called and the allowlist would silently self-approve.
        if not fn.endswith(".py") or fn == os.path.basename(__file__):
            continue
        try:
            src = open(os.path.join(app, fn), encoding="utf8").read()
        except Exception:
            continue
        corpus[fn] = src
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not _decorated(node):
                if not _FRAMEWORK_PREFIX.match(node.name):
                    defs.setdefault(node.name, []).append("%s:%d" % (fn, node.lineno))

    tdir = os.path.join(app, "tests")
    if os.path.isdir(tdir):
        for fn in os.listdir(tdir):
            if fn.endswith(".py"):
                try:
                    corpus["tests/" + fn] = open(os.path.join(tdir, fn), encoding="utf8").read()
                except Exception:
                    pass
    ui = os.path.join(app, "..", "ui", "index.html")
    if os.path.exists(ui):
        try:
            corpus["ui/index.html"] = open(ui, encoding="utf8").read()
        except Exception:
            pass

    unused = []
    for name, places in sorted(defs.items()):
        pat = re.compile(r"\b%s\b" % re.escape(name))
        hits = sum(max(0, len(pat.findall(src)) - sum(1 for p in places if p.startswith(f + ":")))
                   for f, src in corpus.items())
        if hits == 0:
            unused.append({"name": name, "at": places})
    flagged = [u for u in unused if u["name"] not in ALLOWED_UNUSED]
    allowed = [u["name"] for u in unused if u["name"] in ALLOWED_UNUSED]
    stale = sorted(set(ALLOWED_UNUSED) - {u["name"] for u in unused})
    return {"unused": flagged, "allowed": allowed, "stale_allowlist": stale,
            "total_functions": len(defs), "passed": not flagged and not stale}


# The count `scan_qualified` reports today. A RATCHET, not a target: it may fall, never rise. Raising it
# to make a change pass would defeat the point — the whole reason this exists is that the bare-name check
# let a genuinely unreachable engine ship.
#
# 52 when first measured; 47 after wiring `probe_selection` (pairwise/safety_label) and the GraphQL
# argument functions into live paths; 40 once the check started honouring ALLOWED_UNUSED, which removed
# six entries that already carried a written justification; 37 after wiring saml_tool.harvest/plan_leads and allowlisting the operator-gated intrusive half. Lower it whenever the real number drops, so
# the ratchet stays tight enough to catch the next regression.
QUALIFIED_BASELINE = 37

# The baseline as a SET, which is a different thing from the number above and exists for a different
# reason (Q-075).
#
# The ratchet fired correctly on a real island -- five `dom_tool.wm_*` helpers -- and reported as "New
# entries" five names that were not the delta, sat in files the cycle never touched, and cost four probes
# to clear. The message was printing `sorted(unused)[-5:]`: the alphabetical TAIL, identical on a clean
# tree and a dirty one.
#
# The reason it printed a slice is worth stating rather than fixing quietly: a COUNT CANNOT BE DIFFED.
# `QUALIFIED_BASELINE` is a number, so the gate had nothing to subtract and no way to name what changed.
# Printing the true set difference is not a formatting change; it requires recording which functions were
# dead when the baseline was taken. That is this set, MEASURED on a clean `git archive HEAD` snapshot.
#
# It is a DIAGNOSTIC REFERENCE, never the threshold -- the ratchet is still the count. Two consequences:
#
#   * `len(QUALIFIED_BASELINE_SET) <= QUALIFIED_BASELINE` is enforced by a test, and that inequality is
#     what makes the alarm's message provably non-empty. If everything flagged were already in this set,
#     the count could be at most len(set) <= baseline and the ratchet would not have fired. So a failure
#     always has at least one name to print.
#   * Rot runs one way only. Wiring a recorded entry leaves a name here that is no longer dead, which
#     shows up in `resolved` and can never invent a false `newly_dead`. There is deliberately no hard
#     staleness test: this set moves whenever any lane wires anything, and failing their green work to
#     force an edit to a file they do not own is how a gate earns the distrust that gets it silenced.
QUALIFIED_BASELINE_SET = frozenset({
    "action_envelope.mark", "archive_intel.mark_validated", "bench_all.scan_via_mission",
    "bie.har_response_for", "bie.resolve_locator", "candidate_pipeline.plan_targets",
    "db.get_snapshot", "graph_model.neighbors", "graph_model.related_findings",
    "hashid_tool.summarize", "ics_dnp3_s7.is_read_only", "ics_fingerprint.ethernetip_list_identity",
    "ics_fingerprint.identify_protocol", "ics_fingerprint.is_read_only",
    "ics_fingerprint.modbus_read_device_id", "ics_fingerprint.parse_ethernetip_identity",
    "ics_fingerprint.parse_modbus_device_id", "intel_connectors.reset", "intel_registry.advance",
    "intel_registry.reset", "mission_export.summary", "ot_context.declare_protocol_safety",
    "race_tool.best_round", "remediation_depth.families_covered", "report_integrity.cvss_version_of",
    "security.expand_cidr", "service_router.known_services", "sqli_tool.looks_like_login",
    "stealth.describe", "technique_store.dedup_key", "technique_store.stats",
    "techniques.techniques_for_lab", "waf_bypass_tool.pad", "web_security.is_url_in_scope",
    "xxe_tool.looks_like_xml",
})


def _ratchet_message(kind, count, baseline, newly, resolved, recorded):
    """The failure text for either ratchet. Lives HERE, beside the data, rather than in the assertion.

    A message assembled at the call site is re-derived by every caller and drifts from what the scan
    actually found -- which is the defect this replaces. The scan reports its own finding; the test, a
    liveness script and an operator at a REPL all read the same sentence."""
    head = "%s rose to %d (baseline %d)." % (kind, count, baseline)
    if newly:
        msg = ("%s\nNEWLY DEAD -- in this tree, not in the recorded baseline set of %d:\n  %s"
               % (head, recorded, "\n  ".join(newly)))
    else:
        # Unreachable while len(SET) <= baseline (see the note on QUALIFIED_BASELINE_SET). Say so
        # honestly rather than printing nothing: an empty list beside a failure reads as "no new dead
        # code", which is the same misdirection this replaces.
        msg = ("%s\nNothing outside the recorded baseline set of %d, so that set is larger than the "
               "ratchet permits and must be re-recorded -- the count is right, the names are not "
               "available." % (head, recorded))
    if resolved:
        # Drift, shown where someone is already reading. Not a failure: entries leave this set by being
        # WIRED, which is the direction the ratchet exists to encourage.
        msg += ("\n(%d recorded entr%s since been wired and no longer dead: %s)"
                % (len(resolved), "y has" if len(resolved) == 1 else "ies have",
                   ", ".join(resolved[:8]) + (", ..." if len(resolved) > 8 else "")))
    return msg


def _module_bindings(tree, known_modules):
    """({module: {names it is bound to here}}, {(module, original, local)}) for one parsed file. Pure."""
    aliased, from_imported = {}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for al in node.names:
                base = al.name.split(".")[0]
                if base in known_modules:
                    aliased.setdefault(base, set()).add(al.asname or al.name)
        elif isinstance(node, ast.ImportFrom):
            base = (node.module or "").split(".")[0]
            if base in known_modules:
                for al in node.names:
                    from_imported.add((base, al.name, al.asname or al.name))
    return aliased, from_imported


def scan_qualified(app_dir: str = None) -> dict:
    """Module-resolved dead-code scan: PRODUCTION callers only, name collisions impossible.

    A function counts as used when it is referenced inside its own module, or through an import of that
    specific module (`probe_selection.pairwise`, `ps.pairwise`, or `from probe_selection import pairwise`)
    — never merely because some unrelated file happens to define the same word.

    Tests are deliberately excluded. A function only its own test calls is exercised, not wired, and that
    distinction is the one `scan()` cannot make.

    Returns {unused, count, baseline, ok}. `ok` is the RATCHET: count must not exceed the baseline."""
    app = app_dir or APP_DIR
    srcs, trees = {}, {}
    for fn in sorted(os.listdir(app)):
        if not fn.endswith(".py"):
            continue
        try:
            s = open(os.path.join(app, fn), encoding="utf8").read()
            trees[fn] = ast.parse(s)
            srcs[fn] = s
        except Exception:
            continue

    modules = {fn[:-3]: {n.name for n in trees[fn].body
                         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                         and not _decorated(n) and not _FRAMEWORK_PREFIX.match(n.name)}
               for fn in trees}
    bindings = {fn: _module_bindings(t, modules) for fn, t in trees.items()}

    # Index which files import each module. Without this the search is O(functions x files) — 1391
    # functions across 166 files is ~231k regex passes over the whole tree, which took the scan past a
    # two-minute test timeout. A module is only reachable from files that import it, so this narrows the
    # inner loop from every file to typically a handful, with no change in result.
    importers = {}
    for other, (aliased, from_imported) in bindings.items():
        for mod in aliased:
            importers.setdefault(mod, set()).add(other)
        for (mod, _orig, _local) in from_imported:
            importers.setdefault(mod, set()).add(other)

    unused = []
    for mod, funcs in sorted(modules.items()):
        own = srcs.get(mod + ".py", "")
        for f in sorted(funcs):
            # Own module: any mention other than the definition itself. NOT requiring a call, because a
            # function placed in a dispatch table is referenced as a value.
            body = re.sub(r"^\s*(async\s+)?def\s+%s\s*\(" % re.escape(f), "", own, flags=re.M)
            if re.search(r"(?<![\w.])%s\b" % re.escape(f), body):
                continue
            hit = False
            for other in sorted(importers.get(mod, ())):
                if other == mod + ".py":
                    continue
                src = srcs[other]
                aliased, from_imported = bindings[other]
                for name in aliased.get(mod, ()):
                    if re.search(r"(?<![\w.])%s\.%s\b" % (re.escape(name), re.escape(f)), src):
                        hit = True
                        break
                if hit:
                    break
                if any(m == mod and orig == f and re.search(r"(?<![\w.])%s\b" % re.escape(local), src)
                       for (m, orig, local) in from_imported):
                    hit = True
                    break
            if not hit:
                unused.append("%s.%s" % (mod, f))
    # Honour the same allowlist `scan()` uses. Without this, six functions that already carry a written
    # justification counted toward the ratchet, which both inflates the number and makes it mean two
    # different things at once ("unwired" vs "unwired and unexplained"). Matched on the bare name because
    # ALLOWED_UNUSED is keyed that way.
    def _justified(entry):
        return entry.split(".")[-1] in ALLOWED_UNUSED or entry in ALLOWED_UNUSED_QUALIFIED

    allowed = [u for u in unused if _justified(u)]
    flagged = [u for u in unused if not _justified(u)]
    # The TRUE set difference, not a slice of the sorted list. `newly_dead` is what this tree has that the
    # recorded baseline did not; `resolved` is what has been wired since it was recorded.
    newly = sorted(set(flagged) - QUALIFIED_BASELINE_SET)
    resolved = sorted(QUALIFIED_BASELINE_SET - set(flagged))
    return {"unused": flagged, "allowed": allowed, "count": len(flagged),
            "baseline": QUALIFIED_BASELINE, "ok": len(flagged) <= QUALIFIED_BASELINE,
            "newly_dead": newly, "resolved": resolved,
            "message": _ratchet_message("qualified dead-code count", len(flagged), QUALIFIED_BASELINE,
                                        newly, resolved, len(QUALIFIED_BASELINE_SET))}


# Methods flagged by `scan_methods` that are deliberately kept. Same rule as ALLOWED_UNUSED: a reason or
# it does not belong here.
ALLOWED_UNUSED_METHODS = {}

# Current `scan_methods` count. Ratchet, same contract as QUALIFIED_BASELINE: may fall, never rise.
#
# 53 on the first run, but 39 of those were MY OWN checker being wrong, in two ways worth remembering:
#   * a lookbehind before the dot (`(?<![\w])\.name`) rejected the ordinary `self.tools.execute(...)`,
#     because the character before the dot is a word char -- it flagged ToolRegistry.execute as uncalled
#   * HTMLParser callbacks (handle_starttag/handle_endtag) are invoked by the BASE class, not by us
# 14 after both fixes. A checker whose obvious false positives are that visible gets ignored wholesale,
# which is worse than not having one at all.
METHOD_BASELINE = 14

# The method ratchet's message carried the SAME defect as the qualified one and is fixed the same way --
# it was printing `unused[-5:]`, a slice of a sorted list, with no set to diff against. Measured on the
# same clean `git archive HEAD` snapshot: 13 entries against a baseline of 14. Diagnostic reference only;
# METHOD_BASELINE stays the ratchet. See QUALIFIED_BASELINE_SET for why there is no staleness test.
METHOD_BASELINE_SET = frozenset({
    "asset_graph.py::AssetGraph.add_enable", "asset_graph.py::AssetGraph.enabling",
    "asset_graph.py::AssetGraph.mark_consumed", "asset_graph.py::AssetGraph.plan_next",
    "browser_engine.py::TargetRatePolicy.reset_stats", "budget.py::MissionBudget.exhausted",
    "investigation.py::InvestigationState.get_var", "personas.py::PersonaManager.headers_for",
    "personas.py::PersonaManager.prove_privileged", "scope.py::ScopeEngine._extract_host",
    "scope.py::ScopeEngine.to_rules", "vault.py::Vault.list_refs", "vault.py::Vault.purge",
})


def scan_methods(app_dir: str = None) -> dict:
    """Uncalled CLASS METHODS — the layer both other scans cannot see at all.

    `scan()` and `scan_qualified()` walk `tree.body`, so they only ever see module-level functions. This
    codebase keeps 348 methods in classes, 147 of them in `ToolRegistry` — which is to say **every engine
    Apolaki runs is in the blind spot**. Neither unreachable engine found on 2026-08-08
    (`graphql_argument_injection`, `run_header_trust`) was caught by a dead-code scan; both were found by
    following an ALWAYS_ON reason to the code it named.

    Resolution is deliberately CONSERVATIVE — it under-reports rather than inventing work:

      * `self.name` anywhere counts (the ordinary call, including from a subclass)
      * `.name` as an attribute on any receiver counts — the receiver's type is not inferred, so a
        same-named method elsewhere can mask a dead one. Accepted: a false negative here costs nothing,
        a false positive costs someone's afternoon.
      * a STRING literal matching the name counts, because dispatch is
        `getattr(self, "_" + tool_name)` — and for a private `_run_x` the dispatch string is `"run_x"`,
        so both spellings are checked. This is the rule that stops all 147 tool methods being flagged.
      * dunder, `test_`, decorated (framework-invoked) names are skipped

    It EXCLUDES ITS OWN SOURCE, for the reason `scan()` does and one this module learned the hard way.
    Recording `METHOD_BASELINE_SET` for the Q-075 message put 13 strings shaped
    `"vault.py::Vault.purge"` into this file. The `.name` attribute rule then matched `.purge` INSIDE
    that literal, so all 13 recorded methods counted as called and the scan reported **0 uncalled
    methods, down from 13** — a completely silenced ratchet, with every test in this file still green
    (`0 <= 14` passes; nothing asserted the scan could still find anything). Measured, not theorised:
    same snapshot, count 13 before the set was added and 0 after. A record of what a checker found must
    never be readable BY that checker.

    Returns {unused, allowed, count, baseline, ok, methods_examined, newly_dead, resolved, message}."""
    app = app_dir or APP_DIR
    srcs, trees = {}, {}
    for fn in sorted(os.listdir(app)):
        if not fn.endswith(".py") or fn == os.path.basename(__file__):
            continue
        try:
            s = open(os.path.join(app, fn), encoding="utf8").read()
            trees[fn] = ast.parse(s)
            srcs[fn] = s
        except Exception:
            continue
    corpus = "\n".join(srcs.values())

    methods = []
    for fn, tree in trees.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for m in node.body:
                if not isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) or _decorated(m):
                    continue
                if _FRAMEWORK_PREFIX.match(m.name) or m.name.startswith("__"):
                    continue
                methods.append((fn, node.name, m.name))

    def _is_override(module_file, class_name, method_name):
        """True when the method OVERRIDES something a base class defines — so the BASE invokes it, not us.

        `_FormParser.handle_starttag` is called by `html.parser.HTMLParser`, never by Apolaki. Resolved by
        walking the real MRO rather than keeping a list of callback names, which would rot the moment
        someone subclasses something new. Import failures fall through to "not an override": a checker
        that cannot import a module should under-claim, not silently exclude."""
        try:
            mod = __import__(module_file[:-3])
            c = getattr(mod, class_name, None)
            return bool(c) and any(hasattr(b, method_name) for b in c.__mro__[1:])
        except Exception:
            return False

    unused = []
    for fn, cls, name in sorted(methods):
        stem = name.lstrip("_")
        # Strip definitions of this name so `def name(` never counts as a use.
        body = re.sub(r"^\s*(async\s+)?def\s+%s\s*\(" % re.escape(name), "", corpus, flags=re.M)
        # NO lookbehind before the dot. The first version used `(?<![\w])\.name`, which rejects the
        # ordinary `self.tools.execute(...)` — the character before the dot is `s`, a word char — and so
        # flagged `ToolRegistry.execute` as uncalled. A checker whose obvious false positives are that
        # visible gets ignored wholesale, which is worse than not having it.
        used = (re.search(r"self\s*\.\s*%s\b" % re.escape(name), body)
                or re.search(r"\.\s*%s\b" % re.escape(name), body)
                or re.search(r"[\"']_?%s[\"']" % re.escape(stem), body))
        if not used and not _is_override(fn, cls, name):
            unused.append("%s::%s.%s" % (fn, cls, name))

    allowed = [u for u in unused if u.split(".")[-1] in ALLOWED_UNUSED_METHODS]
    flagged = [u for u in unused if u.split(".")[-1] not in ALLOWED_UNUSED_METHODS]
    newly = sorted(set(flagged) - METHOD_BASELINE_SET)
    resolved = sorted(METHOD_BASELINE_SET - set(flagged))
    return {"unused": flagged, "allowed": allowed, "count": len(flagged),
            "baseline": METHOD_BASELINE, "ok": len(flagged) <= METHOD_BASELINE,
            "methods_examined": len(methods), "newly_dead": newly, "resolved": resolved,
            "message": _ratchet_message("uncalled method count", len(flagged), METHOD_BASELINE,
                                        newly, resolved, len(METHOD_BASELINE_SET))}
