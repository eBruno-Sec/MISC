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

**AND EVERY SCAN HERE USED TO READ COMMENTS AS CODE (Q-077).** All three resolvers matched a bare name
by REGEX OVER RAW SOURCE, so prose about a function counted as a use of it. Measured on a clean HEAD
snapshot: switching `scan_qualified` and `scan_methods` to resolve references off the AST took the
qualified count 35 -> 62 and the method count 13 -> 14, with ZERO entries resolved in the other
direction. Of the 27 newly-visible qualified entries, **22 were cleared by a string (20 of them
docstring prose), 5 by a comment, and 0 by a real reference.** Three of the 27 are `scan`,
`scan_qualified` and `scan_methods` themselves -- this module's own docstring, the one you are reading,
was the only thing keeping its own entry points off the list. That is the declaration-versus-fact
pattern living inside the instrument built to detect it.

**THAT PARAGRAPH WAS ITSELF THE SHAPE IT DESCRIBES, and it stayed wrong for two tickets (Q-078, run 5).**
"All three resolvers" is the confession; Q-077 converted TWO. `scan()`'s `unused` set is still a regex
over raw source, deliberately (see the conservatism note above) -- but the SAME regex also fed
`stale_allowlist`, and there the conservatism inverts. For `flagged`, "a mention counts as a use" makes
the gate quiet, which is the documented under-report. For `stale`, the identical rule makes the gate
LOUD IN THE WRONG DIRECTION: it declares a still-dead function "no longer unused" and the remedy it
demands is to delete a true justification.

MEASURED, and the trigger was this file's own paperwork. Run 4 wrote a test whose docstring explains the
`wordlists.payloads_for` exemption; `scan()` reads `agent/tests/*.py`, matched `\bpayloads_for\b` in that
prose twice, and `test_the_allowlist_does_not_rot` failed demanding the entry's removal --

    git archive HEAD  : 1 corpus hit  (wordlists.py:192, the `def` line)          stale []
    HEAD + run 4      : 3 corpus hits (+ tests/test_deadcode_gate.py:817,818)     stale ['payloads_for']

Neither new hit is a caller. Both are sentences ABOUT the allowlist entry, inside the test that guards
it. This module already excludes ITSELF from the corpus for exactly this hazard ("ALLOWED_UNUSED names
every allowlisted function, so counting those mentions would make each entry look called") -- the hazard
simply moved one file over, into the test file that by construction names every entry it defends.
Documenting an exemption must never retire it. `stale` is now resolved off the AST (`_ast_reference_sites`),
which closes it for prose in ANY file rather than for one more excluded filename.

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
import warnings

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Advertised ToolRegistry methods intentionally absent from deterministic scheduling.
#
# This is a CONTRACT, not an exemption from the dead-code scan. Every name must remain advertised,
# dispatch through the real dynamic ToolRegistry.execute path, and remain absent from the deterministic
# scheduler census; tests assert all three facts as one equality. A newly unscheduled method therefore
# fails until it is either scheduled or receives a reviewed contract here.
#
# `dispatcher` names the manual caller that really exists. `why_no_scheduler` names why a deterministic
# caller should not exist; prose alone is insufficient because the tests execute every entry through
# that dispatcher. The four read-only operator utilities expose state or benchmark controls that the
# deterministic agent already owns directly. The two `run_*` entries are deliberately operator-selected.
MANUAL_ONLY_TOOL_CONTRACTS = {
    "benchmark_lab": {
        "permission": "active",
        "kind": "operator-utility",
        "dispatcher": "tools.py ToolRegistry.execute",
        "why_no_scheduler": (
            "Known-lab scoring is an operator benchmark action, not target detection. A production "
            "mission cannot infer that it is authorized to invoke a lab completion oracle."),
    },
    "list_workflows": {
        "permission": "passive",
        "kind": "operator-utility",
        "dispatcher": "tools.py ToolRegistry.execute",
        "why_no_scheduler": (
            "This lists operator-selectable workflow metadata. The deterministic planner schedules "
            "run_workflow directly and has no reason to spend a target step listing its own packs."),
    },
    "mission_intel": {
        "permission": "passive",
        "kind": "operator-utility",
        "dispatcher": "tools.py ToolRegistry.execute",
        "why_no_scheduler": (
            "This is a read-only operator/model view of the registry's current intelligence. The "
            "deterministic agent consumes that state in-process rather than scheduling a tool read."),
    },
    "mission_state": {
        "permission": "passive",
        "kind": "operator-utility",
        "dispatcher": "tools.py ToolRegistry.execute",
        "why_no_scheduler": (
            "This is a read-only operator/model view of investigation state. The deterministic "
            "agent owns that state directly, so scheduling a tool call would only serialize it."),
    },
    "run_external_surface": {
        "permission": "active",
        "kind": "operator-selected-engine",
        "dispatcher": "tools.py ToolRegistry.execute",
        "why_no_scheduler": (
            "External expansion can query third-party intelligence and fetch the in-scope favicon. "
            "It remains an explicit operator-selected expansion rather than a universal mission step."),
    },
    "run_hash_crack": {
        "permission": "intrusive",
        "kind": "dependency-blocked-engine",
        "dispatcher": "tools.py ToolRegistry.execute",
        "why_no_scheduler": (
            "The shipped agent image contains neither hashcat nor John, so deterministic scheduling "
            "would guarantee a visible skipped dispatch. It remains manual for runtimes that add an "
            "offline cracker and for operators who explicitly supply a previously acquired hash."),
    },
}

# Prefixes for functions a framework or protocol calls, never our code.
_FRAMEWORK_PREFIX = re.compile(r"^(main$|test_|_?__)")

# Known-unused, deliberately kept. Each entry must say WHY, or it does not belong here.
#
# THE REASONS WERE AUDITED IN Q-078 RUN 5 AND FOUR OF THE SIX WERE ASSERTING A REACHABILITY THAT DOES
# NOT EXIST. "operator-driven path", "operator/API-facing", "used by operators", "for API callers" --
# an unfiltered whole-repo grep (.py, .html, .yml, .sh, Makefile, Dockerfile, tests, ui/, compose;
# excluding only __pycache__ and docs/) returns EXACTLY SIX LINES for these six names, and every one is
# the function's own `def`. There is no CLI, no endpoint and no script that reaches any of them. That is
# the Q-077 declaration-versus-fact shape sitting in the allowlist -- the one place the ticket says it
# costs most, because an entry whose stated reason is a caller nobody can find is how a list rots
# invisibly. Rewritten to say what is true: zero callers, why it is kept anyway, and what would make it
# live. The `"<module>: "` prefix is load-bearing (see ALLOWED_UNUSED_OWNER) and is preserved.
ALLOWED_UNUSED = {
    "build_error_xml": (
        "xxe_tool: error-based XXE variant. ZERO references anywhere (MEASURED Q-078 run 5) -- there is "
        "no operator path in this repository that fires it. Kept because its two siblings ARE wired "
        "(build_inband_xml at 5 sites, build_oob_xml at 3), so the family is 2 of 3 and this is the "
        "unbuilt third, not a stray. Wiring the error-based branch beside them retires this entry"),
    "extract_script_srcs": (
        "dependency_intel: alternate extraction path for non-HTML inputs. ZERO references anywhere "
        "(MEASURED Q-078 run 5); the live path calls fingerprint_js_content and fingerprint_url "
        "directly. Retained as the non-HTML entry point a future non-HTML source would need"),
    "is_ics_ot": (
        "service_router: safety predicate, kept available to any FUTURE ICS caller and trivially "
        "correct. ZERO references anywhere (MEASURED Q-078 run 5) -- the only entry here whose original "
        "reason already said so rather than naming a caller class that does not exist"),
    "payloads_for": (
        "wordlists: payload set for a classified finding class. ZERO references anywhere (MEASURED "
        "Q-078 run 5). It was recorded as an 'operator/API-facing helper' and it is NEITHER -- main.py "
        "exposes wl.catalog, wl.get_words, wl.target_credentials and wl.target_paths and never this. "
        "It is also the entry that proved the anti-rot check was reading prose as calls"),
    "seclists_available": (
        "wordlists: environment probe for SecLists presence. ZERO references anywhere (MEASURED Q-078 "
        "run 5); get_words does the same check inline as `root = _seclists_root()` at wordlists.py:43, "
        "so this is the accessor form of a test the live path already performs"),
    "validate_targets": (
        "security: batch splitter into (valid, rejected). ZERO references anywhere (MEASURED Q-078 run "
        "5) -- there are no 'API callers'; the only production import of this module anywhere is "
        "`from security import safe_flags` at tools.py:4161. AND IT LAUNDERS is_valid_target: that "
        "function's only non-test reference is at security.py:87 INSIDE this dead function, which is "
        "why no scan here reports it. Proven by mutation -- delete this function and the qualified "
        "count goes 51 -> 52 with security.is_valid_target the exact delta. See TRANSITIVE_ONLY"),
}

# Which MODULE each ALLOWED_UNUSED justification was written about, read off the reason itself (Q-078,
# run 4). `scan()` is a bare-name scan and this changes nothing for it; `scan_qualified` is NOT, and
# matching its dotted entries against a BARE-NAME list was a hole big enough to walk a new island through.
#
# MEASURED by mutation, on a writable copy of the real tree, with its own paired control:
#
#   append `def payloads_for(rows)` to security.py  -> count 51 -> 51, allowed, unaccounted []  SILENT
#   append `def brand_new_island_fn(rows)` to it    -> count 51 -> 52, unaccounted
#                                                      ['security.brand_new_island_fn']  CAUGHT
#
# One line of justification written about `wordlists.payloads_for` was silently excusing a brand-new
# dead function in `security`, a module with no relationship to it -- defeating the count ratchet AND
# the accounting gate above it, which is worse than the hole run 3 closed. 130 function names in this
# tree are defined in more than one module, so the collision surface is not theoretical.
#
# The fix costs nothing because the answer was already written down. Every reason here is
# `"<module>: <why>"`, and that prefix is the module the exemption is about -- prose stating a fact the
# code then ignored, which is the exact Q-077 shape this file exists to catch, sitting in the file
# itself. Now the prose is load-bearing and CHECKED: `test_every_bare_allowlist_entry_names_the_module_
# that_defines_it` asserts each declared owner really defines that function.
#
# FAILS CLOSED by construction. A reason without the prefix yields an owner that matches no module, so
# the entry stops excusing anything and counts toward the ratchet -- the safe direction. It cannot fail
# open.
#
# MEASURED, and this is the number that matters for a hardening: all six owners resolve to the module
# that defines them, each name is defined in exactly one module today, and the qualified count is
# UNCHANGED at 51. Nothing was being hidden; the door was simply unlocked.
ALLOWED_UNUSED_OWNER = {name: why.split(":")[0].strip() for name, why in ALLOWED_UNUSED.items()}


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


# Entries the QUALIFIED scan cannot see a caller for BECAUSE OF WHERE THE CALLER LIVES, not because
# there isn't one (Q-078). Each names the caller, and a test RESOLVES it against the real tree.
#
# WHY THIS IS NOT JUST A THIRD ALLOWLIST. An allowlist entry that says "allowed" is how a gate becomes
# decorative -- the exact defect this whole line of work exists to prevent. So an entry here cannot say
# "allowed": it is (kind, caller_file, anchor, why), and
# `test_every_named_caller_allowlist_entry_resolves_to_a_real_caller` opens `caller_file`, requires
# `anchor` to be present in it, and requires `anchor` to name either the function itself or its defining
# module. Delete the caller, rename it, or invent one, and the suite goes red. The justification is
# CHECKED, not merely written.
#
# ANCHORS ARE SUBSTRINGS, NEVER LINE NUMBERS, and that is a lesson rather than a style choice. Q-077's
# own xfail cites `docker-compose.yml:419` for the mitmdump invocation; at HEAD that line is 399, and
# 419 was the uncommitted working copy of a file another lane was editing. A line number into a live
# file is rot on arrival.
#
# Three kinds, and the distinction matters because only one of them could ever be closed by wiring:
#   framework -- invoked by name from outside the Python corpus. A caller in `agent/` would be a BUG.
#   re-export -- published on another module's surface; there the import IS the use.
#   harness   -- the function's product is a CI verdict and pytest is its scheduler. `scan_qualified`
#                excludes tests on purpose, so "unwired" is the right answer to the question it asks
#                and the wrong answer to the question a reader has.
ALLOWED_UNUSED_NAMED_CALLER = {
    "mitm_addon.request": (
        "framework", "docker-compose.yml", "-s /addon/mitm_addon.py",
        "mitmproxy addon hook, invoked BY NAME by mitmdump. The proxy container mounts only this file "
        "(./agent/mitm_addon.py:/addon/mitm_addon.py:ro) and the module imports nothing from Apolaki by "
        "design, so an in-repo caller would mean the addon was being driven in-process, which is not "
        "how the sidecar works"),
    "mitm_addon.response": (
        "framework", "docker-compose.yml", "-s /addon/mitm_addon.py",
        "the response-side half of the same mitmproxy addon contract; same invocation, same reason"),
    "sqli_tool.is_inconclusive": (
        "re-export", "nosqli_tool.py", "from sqli_tool import",
        "RE-EXPORTED as the shared third-outcome convention from Q-070. The gate's rule that an import "
        "binds a name rather than using it is right for an ordinary import and wrong for a re-export, "
        "where the import IS the use: it publishes the symbol on nosqli_tool's surface. That the two "
        "are one object is asserted in tests/test_boolean_oracle_stability.py"),
    "deadcode_gate.scan": (
        "harness", "tests/test_deadcode_gate.py", "return dg.scan()",
        "this gate's own bare-name entry point; pytest is its scheduler and its product is a verdict"),
    "deadcode_gate.scan_qualified": (
        "harness", "tests/test_deadcode_gate.py", "return dg.scan_qualified()",
        "this gate's own module-resolved entry point -- the one that produces the ratchet"),
    "deadcode_gate.scan_methods": (
        "harness", "tests/test_deadcode_gate.py", "return dg.scan_methods()",
        "this gate's own method-scan entry point, the layer the other two cannot see"),
    "description_gate.audit": (
        "harness", "tests/test_description_gate.py", "dg.audit(_tools_source())",
        "the description-vs-code gate's entry point, run against the live tools source every suite run"),
    "engine_descriptor.effects_audit": (
        "harness", "tests/test_effects_engine_fact.py", "ed.effects_audit()",
        "Q-007's guard: does every declared effect belong to an engine that exists? A CI verdict, and "
        "its negative half lives in tests/test_effects_negative_half.py"),
    # This list's own resolver, flagged by this list's own gate on the first run after it was written --
    # which is the mechanism working, not an embarrassment, so it is recorded the same way as everything
    # else rather than special-cased out of the scan.
    "deadcode_gate.resolve_named_caller": (
        "harness", "tests/test_deadcode_gate.py", "dg.resolve_named_caller(entry)",
        "resolves every entry in this list against the real tree; the test that calls it is the whole "
        "reason an entry here cannot degrade into the word 'allowed'"),
    "ics_dnp3_s7._dnp3_crc_table": (
        "harness", "tests/test_ics_dnp3_s7.py", "ics._dnp3_crc_table(data)",
        "a SECOND, INDEPENDENT implementation of the DNP3 CRC whose only purpose is to falsify the "
        "first -- the test asserts the bitwise and table-driven results agree, which is how the CRC is "
        "verified without trusting a memorised vector. A production caller would defeat it, and "
        "deleting it as dead code would delete a negative control"),
}


# The resolver's four answers. "the caller is not there" and "the file is not here" are DIFFERENT
# facts and conflating them is what makes a checked allowlist decorative again: the first means the
# excuse died and the entry is now a real island, the second means this process cannot see far enough
# to judge. One is a failure; the other is a limit, and a limit that reports itself as a pass is the
# shape of every defect this file exists to catch.
RESOLVED = "resolved"
ANCHOR_MISSING = "anchor-missing"
FILE_UNREACHABLE = "file-unreachable"
NOT_LISTED = "not-listed"

# The entries whose caller lives OUTSIDE `agent/` and so cannot be opened when the suite runs the way
# it is always run: a container with ONLY `agent/` mounted at /app, where the repository root does not
# exist (MEASURED -- `ls /` in the agent image has no docker-compose.yml, and `/app/..` is `/`).
#
# PINNED BY NAME, not described by a rule, because this is the one hole in the mechanism. A rule like
# "framework entries may be unverifiable" lets the hole widen silently; a frozenset means a third
# unverifiable entry cannot be added without a deliberate edit here, reviewed like a raised ratchet.
# Everything NOT in this set must resolve for real on every run, in every environment.
#
# MEASURED against the real repository root, which is the half the container cannot run --
#   docker-compose.yml:419 (399 at HEAD; the working copy carries another lane's edits)
#   - "mkdir -p /data && chmod 0777 /data && exec mitmdump --listen-host 0.0.0.0 -p 8080
#      -s /addon/mitm_addon.py --set termlog_verbosity=info"
# and `test_the_resolver_reads_a_file_at_the_repository_root` exercises this entry, this anchor and all
# three states against a synthetic root, so the apparatus is proven even where the tree is not.
NAMED_CALLER_OUTSIDE_CHECKOUT = frozenset({"mitm_addon.request", "mitm_addon.response"})

# This module DECLARES the allowlist, so every anchor in it is present in it by construction. Matching
# here would let an entry cite its own declaration as proof of itself -- declaration-versus-fact, inside
# the instrument built to detect it. Skipped in the resolver AND forbidden by a test, because a rule
# worth having twice is one that would be invisible if it broke.
_DECLARING_FILE = "deadcode_gate.py"


def resolve_named_caller(entry: str, root: str = None):
    """(status, path, lineno, line) for an ALLOWED_UNUSED_NAMED_CALLER entry. This is what stops the
    list rotting into decoration -- see the note above it.

      RESOLVED         the named file was opened and the anchor is in it. The excuse is a fact.
      ANCHOR_MISSING   the file is here and the anchor is NOT. The caller was renamed or deleted, so
                       either the entry was never true or the function is a real island now. HARD FAIL,
                       everywhere, for every entry.
      FILE_UNREACHABLE the named file is not in this checkout. Tolerated ONLY for the entries pinned in
                       NAMED_CALLER_OUTSIDE_CHECKOUT, and never conflated with ANCHOR_MISSING.
      NOT_LISTED       `entry` is not in the allowlist at all.

    `root` defaults to the directory holding `agent/*.py`; the caller file is looked for there and one
    level up, so an entry may name the test tree or the repository root."""
    rec = ALLOWED_UNUSED_NAMED_CALLER.get(entry)
    if not rec:
        return (NOT_LISTED, "", 0, "")
    _kind, caller, anchor, _why = rec
    base = root or APP_DIR
    opened = ""
    for candidate in (os.path.join(base, caller), os.path.join(base, "..", caller)):
        if not os.path.isfile(candidate) or os.path.basename(candidate) == _DECLARING_FILE:
            continue
        try:
            src = open(candidate, encoding="utf8").read()
        except Exception:
            continue
        opened = os.path.normpath(candidate)
        for i, line in enumerate(src.split("\n"), 1):
            if anchor in line:
                return (RESOLVED, opened, i, line.strip())
    return (ANCHOR_MISSING, opened, 0, "") if opened else (FILE_UNREACHABLE, "", 0, "")


def _decorated(node) -> bool:
    return bool(getattr(node, "decorator_list", None))


def _ast_reference_sites(app: str, wanted) -> tuple:
    """({name: "file:line" of its first REAL reference}, reference_nodes_seen) over the corpus `scan()`
    reads -- production modules (minus this one) plus the test tree -- read off the AST, never off raw
    source text.

    This exists for `stale_allowlist` and nothing else. `unused` stays on the regex on purpose: there it
    over-counts uses and so UNDER-reports dead code, which is the documented, deliberate conservatism.
    `stale` is the same rule pointed the other way, where over-counting uses makes the gate demand the
    deletion of a justification for a function that is still dead. A retraction is not a conservative
    error, so it does not get to run on a conservative signal.

    Three reference kinds count, matching what `_ast_refs` can prove:

      * `ast.Name`      -- `from wordlists import payloads_for` then `payloads_for(...)`
      * `ast.Attribute` -- `wl.payloads_for(...)`, on any receiver. The receiver's type is not inferred,
                           the same deliberately type-blind rule `scan_methods` uses: a same-named
                           attribute elsewhere can mask a retirement. That under-claims staleness, which
                           is the safe direction for a signal whose remedy is a deletion.
      * a WHOLE string constant equal to the name -- `getattr(mod, "payloads_for")` dispatch. Whole
                           value, not a substring: a docstring is one Constant holding prose, so it can
                           no longer smuggle a name past the check the way a regex over raw text did.

    A definition can never count itself: `def payloads_for(...)` is a FunctionDef, so the old "subtract
    one hit per definition site" correction has no AST equivalent to need, and one more place to be
    off-by-one is gone with it.

    NOT read here: `ui/index.html`, which the regex corpus does include. MEASURED -- an unfiltered
    whole-repo grep for all six ALLOWED_UNUSED names returns exactly six lines, each one the function's
    own `def`, so no entry has a UI mention to lose; and the suite runs in a container that mounts only
    `agent/`, where that file does not exist at all. A JavaScript token is not a Python caller.

    The LOCATION is returned, not just the fact, because the failure this replaces was unreadable: "these
    are no longer unused" named the entry and nothing else, and the reader's only move was to guess. The
    site turns the message into an instruction -- go here, look at this line, decide whether it is a call
    or a sentence."""
    sites, nodes = {}, 0
    paths = [os.path.join(app, fn) for fn in sorted(os.listdir(app))
             # SELF-EXCLUSION, and here it is LOAD-BEARING rather than inherited: every ALLOWED_UNUSED
             # key is a whole string CONSTANT in this file, so the whole-string rule above would match
             # all six exactly and retire the entire allowlist on the strength of its own declaration.
             # The AST rule does not save us from this one; the exclusion does. Proven by
             # `test_the_declaring_file_would_retire_its_own_allowlist_if_it_were_read`.
             if fn.endswith(".py") and fn != os.path.basename(__file__)]
    tdir = os.path.join(app, "tests")
    if os.path.isdir(tdir):
        paths += [os.path.join(tdir, fn) for fn in sorted(os.listdir(tdir)) if fn.endswith(".py")]
    for path in paths:
        try:
            # This is the first thing here to compile `tests/*.py`, and compiling re-emits every
            # SyntaxWarning those files carry -- attributed to `<unknown>:<line>` and to whichever test
            # happened to trigger the scan. MEASURED at clean HEAD: `tests/test_client_request_source.py`
            # has `\w` in a non-raw docstring, pytest already reports it correctly against that file and
            # line, and reading the file here added a SECOND copy blaming `test_no_unexplained_dead_
            # functions`. Suppressed at the read, not globally: the real report is untouched (positive
            # control in `test_reading_the_corpus_does_not_re_report_another_file_s_warning`), and a gate
            # that misattributes another file's defect to itself is noise a reader learns to ignore.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(open(path, encoding="utf8").read())
        except Exception:
            continue
        label = os.path.basename(path)
        if os.path.basename(os.path.dirname(path)) == "tests":
            label = "tests/" + label
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
            if ref in wanted and ref not in sites:
                sites[ref] = "%s:%d" % (label, node.lineno)
    return sites, nodes


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
    # STALE = "this entry is now REALLY CALLED", resolved off the AST -- not "the regex above stopped
    # finding it unused", which is what it used to mean and which a sentence about the entry was enough
    # to trigger. See `_ast_reference_sites` and the docstring at the top of this module for the run that
    # measured it. An entry in `unused` has zero text hits and so can never be referenced, so this set is
    # a strict subset of the old one: the check can only get quieter, never louder, which is why it ships
    # with a paired control that adds a real call and requires the entry to be named.
    sites, ref_nodes = _ast_reference_sites(app, set(ALLOWED_UNUSED))
    stale = sorted(sites)
    # POSITIVE CONTROL, carried in the result so no test can conclude anything from an empty `stale`
    # without first proving the reader saw the tree. A blind `_ast_reference_sites` -- wrong directory,
    # every parse failing -- returns an empty dict and produces the same empty `stale` as a clean tree.
    return {"unused": flagged, "allowed": allowed, "stale_allowlist": stale,
            "stale_sites": sites, "reference_nodes": ref_nodes,
            "total_functions": len(defs), "passed": not flagged and not stale}


# The count `scan_qualified` reports today. A RATCHET, not a target: it may fall, never rise. Raising it
# to make a change pass would defeat the point — the whole reason this exists is that the bare-name check
# let a genuinely unreachable engine ship.
#
# 52 when first measured; 47 after wiring `probe_selection` (pairwise/safety_label) and the GraphQL
# argument functions into live paths; 40 once the check started honouring ALLOWED_UNUSED, which removed
# six entries that already carried a written justification; 37 after wiring saml_tool.harvest/plan_leads and allowlisting the operator-gated intrusive half. Lower it whenever the real number drops, so
# the ratchet stays tight enough to catch the next regression.
#
# **THIS NUMBER IS STALE BY MEASUREMENT AND IS DELIBERATELY NOT BEING RAISED (Q-077).** Every value in
# the history above was produced by a resolver that read comments and docstrings as calls. The true
# count under AST resolution is 62. Raising 37 to 62 would be weakening a ratchet to make a change
# pass, which is the one thing this file must never do, so the ratchet FAILS and names the 27 entries
# it was previously blind to. Triage -- deciding which of the 27 to wire, delete or justify -- is a
# separate ticket; only that triage may move this number, and only downward as entries are resolved.
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
#
# Q-077 DELIBERATELY DOES NOT FOLD ITS 27 NEW ENTRIES IN HERE, and the reason is the whole point of
# Q-075. `newly_dead` is `flagged - THIS SET`. Recording all 62 would make `newly_dead` empty, drop the
# message into its "the names are not available" branch, and hand the next reader a failure that names
# nothing -- re-creating, in one edit, exactly the defect Q-075 closed. So this stays the 35 measured
# under the OLD resolver, the 27 are recorded separately in QUALIFIED_Q077_REVEALED below, and the
# ratchet's failure text names all 27 every time it runs. The invariant
# `len(QUALIFIED_BASELINE_SET) <= QUALIFIED_BASELINE` also survives, which is what guarantees the
# message is non-empty at all.
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

# The 27 entries the regex resolver could not see (Q-077). MEASURED on a clean `git archive HEAD`
# snapshot: count 35 with the old resolver, 62 with the AST one, `resolved` empty both ways.
#
# This is a RECORD OF THE DELTA, not a second allowlist and not a threshold. Nothing here is excused
# from the ratchet -- all 27 count toward the 62 that fails it. It exists so the next reader can tell a
# Q-077 revelation from a genuinely new island someone added afterwards, which the count alone cannot
# distinguish.
#
# TRIAGE, from reading each definition and its importers (see docs/handoff/gate_truth.md section 4):
#   * FRAMEWORK-INVOKED, not islands (2): mitm_addon.request/response are mitmproxy addon hooks. The
#     proxy container mounts mitm_addon.py and mitmdump calls them by name (docker-compose.yml:419),
#     so there is no in-repo caller BY DESIGN -- the same category as a FastAPI route, but undecorated,
#     so the structural rule cannot see it.
#   * GATE ENTRY POINTS called from outside the scanned corpus (4): deadcode_gate.scan /
#     scan_qualified / scan_methods and description_gate.audit. Reached by tests and liveness scripts;
#     `scan_qualified` excludes tests on purpose, so "unwired" is the correct verdict for what it
#     measures, and the honest fix is a production caller, not an allowlist entry.
#   * REAL ISLANDS, no reference of any kind anywhere in production (21). Every other entry below.
QUALIFIED_Q077_REVEALED = frozenset({
    "api_protocols.inventory", "archive_intel.needs_validation", "bench_all.bench", "bie.observe",
    "capability_matrix.state_rank", "cloud_iam.collect_live", "codereview_graph.hypotheses",
    "codereview_graph.link_runtime_to_source", "deadcode_gate.scan", "deadcode_gate.scan_methods",
    "deadcode_gate.scan_qualified", "description_gate.audit", "engine_descriptor.effects_audit",
    "exposure_tool.paths", "fingerprint.fingerprint", "ics_dnp3_s7._dnp3_crc_table",
    "ics_fingerprint.finding", "intel.harvest", "mitm_addon.request", "mitm_addon.response",
    "report.control_ran", "saml_tool.finding", "service_router.plan", "sqli_tool.is_inconclusive",
    "ssrf_tool.bypass_payloads", "techniques.classes", "tool_provenance.argv_hash",
})


# EVERY ENTRY ANYONE HAS EVER MEASURED AND TRIAGED, as one set. Not an allowlist and not a threshold:
# nothing here is excused, and every member still counts toward the ratchet. It is the set an ACCOUNTING
# CHECK subtracts, and that check exists because of a hole a reader will not otherwise see.
#
# **THE PIN IS A HOLE, MEASURED.** `test_the_ratchet_holds` is `xfail(strict=True)` while the count sits
# at 51 against a ceiling of 37, so a count RISE cannot fail the suite -- the test fails either way and
# the failure is the expected one. Mutation, on a copy of the real tree at HEAD:
#
#   append `def summarize(rows)` to security.py -- an island whose name COLLIDES with
#   hashid_tool.summarize and race_tool.summarize --> scan_qualified count 51 -> 52, ok False before
#   and False after, and the suite stays GREEN.
#
# The bare-name `scan()` gate is what normally catches a new island, and a colliding name is precisely
# what it cannot see (`test_the_bare_name_scan_is_fooled_by_a_name_collision` proves that on a synthetic
# tree; 90 function names in this codebase are defined in more than one module). So between the pin and
# the collision there was NO gate on new dead code at all, for as long as the pin lasts -- and the pin
# lasts until 14 islands in files other lanes own are closed.
#
# The accounting check closes it WITHOUT touching a threshold: every flagged entry must be one someone
# has already measured and written down. A brand-new island is in neither set, so it fails immediately,
# by name, whatever it is called. It cannot be satisfied by raising `QUALIFIED_BASELINE` -- the ceiling
# does not appear in it -- and the one way to satisfy it dishonestly, recording the new island as if it
# were an old measurement, is blocked by the size bounds asserted on both sets.
#
# Kept SEPARATE from `ok` on purpose. "the count rose" and "an entry nobody has ever looked at is here"
# are different facts with different fixes, and collapsing them into one boolean is the mistake run 2
# recorded about RESOLVED versus FILE_UNREACHABLE. `scan_methods` gets no equivalent because its ratchet
# is NOT pinned (14 <= 14, ok True): its count gate still fires, so its `newly_dead` already fails.
RECORDED_QUALIFIED = QUALIFIED_BASELINE_SET | QUALIFIED_Q077_REVEALED

# The entries that are in a recorded measurement AND excused by an allowlist, PINNED BY NAME (Q-078,
# run 4). Nine, all from QUALIFIED_Q077_REVEALED, all excused via ALLOWED_UNUSED_NAMED_CALLER.
#
# WHY THIS EXISTS, and it is a correction to run 3 rather than a new idea. Run 3 asserted the flat rule
# "no recorded entry may be allowlisted", reasoning that an allowlisted entry is filtered out of
# `flagged` before the diff and so could never be falsified. The rule was RED on arrival -- MEASURED,
# nine violations, `test_a_recorded_measurement_cannot_grow_to_absorb_a_new_island` failing on
# `deadcode_gate.scan_qualified` -- because it had the direction backwards.
#
# The two directions are different acts:
#   RECORD-then-EXCUSE  a measurement was taken while the entry was flagged, and triage LATER found it a
#                       caller. That is the ticket working. Deleting the name from the record afterwards
#                       would rewrite a measurement to match a later opinion; the Q-077 delta was 27 and
#                       stays 27 however the triage of those 27 lands.
#   EXCUSE-then-RECORD  adding an already-excused name to a record. That entry can never be flagged, so
#                       it sits in the record doing nothing, and it is how a record gets padded.
#
# Only the second is dishonest, and a set cannot tell you which order its members arrived in. So the
# nine that went the first way are pinned by name, exactly as NAMED_CALLER_OUTSIDE_CHECKOUT pins the two
# entries whose caller the container cannot open. A tenth takes a deliberate edit HERE plus the
# allowlist edit, in two places a reviewer reads -- which is the teeth: quietly excusing a recorded entry
# is the move that drops the count without wiring anything, and it now costs two visible edits and a
# caller that `resolve_named_caller` must actually find.
#
# The pin is bounded and checked in both directions by
# `test_the_recorded_then_excused_pin_is_bounded_and_every_member_earns_its_place`: every member must
# still be BOTH recorded AND excused, so a stale name cannot squat here after the fact.
RECORDED_THEN_EXCUSED = frozenset({
    "deadcode_gate.scan", "deadcode_gate.scan_methods", "deadcode_gate.scan_qualified",
    "description_gate.audit", "engine_descriptor.effects_audit", "ics_dnp3_s7._dnp3_crc_table",
    "mitm_addon.request", "mitm_addon.response", "sqli_tool.is_inconclusive",
})


def _ratchet_message(kind, count, baseline, newly, resolved, recorded, unaccounted=()):
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
        # WIRED or DELETED, both directions the ratchet exists to encourage.
        #
        # "or deleted" is not padding. It read "have since been wired" until Q-078 run 6 removed
        # `ics_fingerprint.py`, at which point six recorded entries landed here and the sentence asserted
        # that six functions that no longer exist had been wired into production. A drift report that
        # states the wrong reason for the drift is the same prose-versus-fact defect this file exists to
        # catch, so the sentence names both ways out and leaves the reader to check which.
        msg += ("\n(%d recorded entr%s since been wired or deleted and %s no longer dead: %s)"
                % (len(resolved), "y has" if len(resolved) == 1 else "ies have",
                   "is" if len(resolved) == 1 else "are",
                   ", ".join(resolved[:8]) + (", ..." if len(resolved) > 8 else "")))
    if unaccounted:
        # The one class a reader must not mistake for backlog. `newly_dead` holds everything outside the
        # BASELINE set, which today is 17 entries Q-078 triaged and named -- known, priced, and waiting on
        # files their lanes own. These are different: nobody has ever looked at them.
        it = "it" if len(unaccounted) == 1 else "them"
        msg += ("\nUNACCOUNTED -- flagged in this tree and in NEITHER recorded measurement, so no triage "
                "has ever covered %s. Wire %s, delete %s, or record %s as a measurement WITH the "
                "evidence; raising the ceiling does not answer this:\n  %s"
                % (it, it, it, it, "\n  ".join(unaccounted)))
    return msg


def _dotted(node):
    """`a`, `a.b`, `a.b.c` for a pure Name/Attribute chain; None for anything else (`f().x`, `d[k].x`).

    None matters: it is what keeps `x.lib.work` from resolving as the module `lib`, which is the job the
    old `(?<![\\w.])` lookbehind did in the regex."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return base + "." + node.attr if base else None
    return None


def _ast_refs(tree):
    """(names, qualified, attrs, strings) for one parsed module. Pure. THE Q-077 FIX.

    Every reference is read off the AST, so a name that appears only in a COMMENT or a DOCSTRING is not a
    reference to anything. The old resolvers ran a regex over raw source text, which made prose about a
    function count as a use of it -- the declaration-versus-fact pattern living inside the instrument
    built to detect it. MEASURED by the postMessage lane: `find_message_listeners` and `wm_scan_hint` were
    both uncalled and both absent from the failure list because both were named in an explanatory comment.

      * `names`      -- bare `ast.Name` ids. A module-level function used in its own module, or through
                        `from x import f`, appears here. An `import` statement does NOT: importing a name
                        binds it, it does not use it, and the old regex counted the import line itself as
                        the use it was looking for.
      * `qualified`  -- (receiver-path, attribute) pairs, so `L.work` resolves to the module bound as `L`.
      * `attrs`      -- every attribute name on any receiver, for the method scan's deliberately
                        type-blind `.name` rule.
      * `strings`    -- WHOLE string-constant values, for the method scan's string-dispatch rule
                        (`getattr(self, "_" + tool_name)`). Whole values, not a substring search: a
                        docstring is one Constant holding prose, so it can no longer smuggle a name in
                        the way `["']_?name["']` over raw text could.
    """
    names, qualified, attrs, strings = set(), set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            attrs.add(node.attr)
            base = _dotted(node.value)
            if base:
                qualified.add((base, node.attr))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.add(node.value)
    return names, qualified, attrs, strings


def _module_bindings(tree, known_modules):
    """({module: {names it is bound to here}}, {(module, original, local)}) for one parsed file. Pure.

    A module is bound by an `import`, and ALSO by being STASHED ON AN ATTRIBUTE (Q-078). MEASURED false
    positive: `intel.harvest` read as dead for the entire life of this gate while
    `agent/tools.py:1848` calls it on every scoped fetch --

        tools.py:1246   self._intel_mod = _intel          # `import intel as _intel` one line above
        tools.py:1848   self._intel_mod.harvest(material, self.intel)

    The reference resolves as the pair `("self._intel_mod", "harvest")`, which never matches the import
    alias `_intel`, so the live harvest path was reported as an island. An allowlist entry would have
    recorded that lie permanently; the resolver is what was wrong.

    DELIBERATELY NARROW. Only an assignment whose RIGHT-HAND SIDE IS ALREADY A KNOWN MODULE BINDING
    creates a new one, so `self.foo.harvest(...)` where `self.foo` is an ordinary object still resolves
    to nothing. Widening this to "any attribute access named `harvest`" is the type-blind rule
    `scan_methods` uses, and it is exactly what `scan_qualified` exists NOT to do."""
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

    # Second pass, over the WHOLE module first: an import inside a function body can appear after the
    # assignment that re-binds it (it does, in `tools.py`), so aliases must all be known before any
    # assignment is considered.
    rebinds = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        src = _dotted(node.value)
        if not src:
            continue
        for tgt in node.targets:
            dst = _dotted(tgt)
            if dst and dst != src:
                rebinds.append((dst, src))
    # Fixed point, for a chain (`a = intel` then `self.m = a`). Bounded: three hops is far past
    # anything in this tree and a cycle must not spin.
    for _ in range(3):
        grew = False
        for dst, src in rebinds:
            for names in aliased.values():
                if src in names and dst not in names:
                    names.add(dst)
                    grew = True
        if not grew:
            break
    return aliased, from_imported


def scan_qualified(app_dir: str = None) -> dict:
    """Module-resolved dead-code scan: PRODUCTION callers only, name collisions impossible.

    A function counts as used when it is referenced inside its own module, or through an import of that
    specific module (`probe_selection.pairwise`, `ps.pairwise`, or `from probe_selection import pairwise`)
    — never merely because some unrelated file happens to define the same word.

    Tests are deliberately excluded. A function only its own test calls is exercised, not wired, and that
    distinction is the one `scan()` cannot make.

    References are resolved from the AST (`_ast_refs`), never by regex over source text. A name that
    appears only in a comment or a docstring is prose, not wiring (Q-077).

    Returns {unused, count, baseline, ok}. `ok` is the RATCHET: count must not exceed the baseline."""
    app = app_dir or APP_DIR
    trees = {}
    for fn in sorted(os.listdir(app)):
        if not fn.endswith(".py"):
            continue
        try:
            trees[fn] = ast.parse(open(os.path.join(app, fn), encoding="utf8").read())
        except Exception:
            continue
    refs = {fn: _ast_refs(t) for fn, t in trees.items()}

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
        own_names = refs.get(mod + ".py", (frozenset(),))[0]
        for f in sorted(funcs):
            # Own module: any REFERENCE other than the definition itself. NOT requiring a call, because a
            # function placed in a dispatch table is referenced as a value -- `RULES = [rule_a]` is an
            # `ast.Name`, so it counts, while `def rule_a(...)` is a FunctionDef and never can.
            if f in own_names:
                continue
            hit = False
            for other in sorted(importers.get(mod, ())):
                if other == mod + ".py":
                    continue
                other_names, other_qualified, _attrs, _strings = refs[other]
                aliased, from_imported = bindings[other]
                # `import probe_selection as ps` + `ps.pairwise(...)`, resolved as a (receiver, attr) pair
                # rather than by matching the text `ps.pairwise`.
                if any((name, f) in other_qualified for name in aliased.get(mod, ())):
                    hit = True
                    break
                # `from probe_selection import pairwise` + a bare use of `pairwise`. The import statement
                # itself is NOT a use: `ImportFrom` binds an alias and produces no `ast.Name`, where the
                # old regex searched the raw source and matched the import line it had just read.
                if any(m == mod and orig == f and local in other_names
                       for (m, orig, local) in from_imported):
                    hit = True
                    break
            if not hit:
                unused.append("%s.%s" % (mod, f))
    # Honour the same allowlist `scan()` uses. Without this, six functions that already carry a written
    # justification counted toward the ratchet, which both inflates the number and makes it mean two
    # different things at once ("unwired" vs "unwired and unexplained").
    #
    # ALLOWED_UNUSED is keyed by BARE NAME, and this scan's entries are `module.function`. Matching the
    # bare halves excused ANY module's function that happened to share the name -- MEASURED, a new
    # `security.payloads_for` island rode in on the justification written for `wordlists.payloads_for`
    # with the count unmoved and `unaccounted` empty. So the OWNING MODULE must match too; see
    # ALLOWED_UNUSED_OWNER.
    def _justified(entry):
        mod, _, bare = entry.rpartition(".")
        return (ALLOWED_UNUSED_OWNER.get(bare) == mod or entry in ALLOWED_UNUSED_QUALIFIED
                or entry in ALLOWED_UNUSED_NAMED_CALLER)

    allowed = [u for u in unused if _justified(u)]
    flagged = [u for u in unused if not _justified(u)]
    # The TRUE set difference, not a slice of the sorted list. `newly_dead` is what this tree has that the
    # recorded baseline did not; `resolved` is what has been wired since it was recorded.
    newly = sorted(set(flagged) - QUALIFIED_BASELINE_SET)
    resolved = sorted(QUALIFIED_BASELINE_SET - set(flagged))
    # The accounting check -- see RECORDED_QUALIFIED. `newly_dead` is "not in the BASELINE set", which
    # today is 17 triaged, named, priced islands; `unaccounted` is "in NO recorded measurement", which is
    # nobody has ever looked at this. While the ratchet is pinned by a strict xfail, this is the only
    # thing in the file that can fail on new dead code.
    unaccounted = sorted(set(flagged) - RECORDED_QUALIFIED)
    return {"unused": flagged, "allowed": allowed, "count": len(flagged),
            "baseline": QUALIFIED_BASELINE, "ok": len(flagged) <= QUALIFIED_BASELINE,
            "newly_dead": newly, "resolved": resolved, "unaccounted": unaccounted,
            "accounted": not unaccounted,
            "message": _ratchet_message("qualified dead-code count", len(flagged), QUALIFIED_BASELINE,
                                        newly, resolved, len(QUALIFIED_BASELINE_SET), unaccounted)}


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
#
# RE-BASELINED to 14 by the Q-077 AST rewrite, which added exactly one entry and resolved none:
# `vault.py::Vault.is_encrypted`. Its docstring reads "pretends to be encrypted. is_encrypted() reports
# the true protection level" -- and the old `\.\s*name` rule cannot tell the FULL STOP ending the
# previous sentence from an attribute access, so `. is_encrypted` counted as a call. Unlike the
# qualified set this one is folded in, because 14 <= METHOD_BASELINE: the method ratchet still passes,
# so recording it keeps the set a true measurement without emptying any failure message.
METHOD_BASELINE_SET = frozenset({
    "asset_graph.py::AssetGraph.add_enable", "asset_graph.py::AssetGraph.enabling",
    "asset_graph.py::AssetGraph.mark_consumed", "asset_graph.py::AssetGraph.plan_next",
    "browser_engine.py::TargetRatePolicy.reset_stats", "budget.py::MissionBudget.exhausted",
    "investigation.py::InvestigationState.get_var", "personas.py::PersonaManager.headers_for",
    "personas.py::PersonaManager.prove_privileged", "scope.py::ScopeEngine._extract_host",
    "scope.py::ScopeEngine.to_rules", "vault.py::Vault.is_encrypted", "vault.py::Vault.list_refs",
    "vault.py::Vault.purge",
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
    trees = {}
    for fn in sorted(os.listdir(app)):
        # SELF-EXCLUSION, preserved verbatim through the Q-077 AST rewrite. See the paragraph above: a
        # record of what a checker found must never be readable BY that checker. The Coordinator
        # reproduced the silencing by mutation -- delete this one clause and the scan reports
        # `count 0, ok True` with every other test in the file still green.
        if not fn.endswith(".py") or fn == os.path.basename(__file__):
            continue
        try:
            trees[fn] = ast.parse(open(os.path.join(app, fn), encoding="utf8").read())
        except Exception:
            continue
    # ONE walk of the whole corpus, not one regex pass per method over the joined source (Q-077). Every
    # receiver's attribute name, and every whole string-constant value -- both read off the AST, so a
    # method named only in a comment is no longer indistinguishable from one that is called.
    corpus_attrs, corpus_strings = set(), set()
    for tree in trees.values():
        _names, _qualified, attrs, strings = _ast_refs(tree)
        corpus_attrs |= attrs
        corpus_strings |= strings

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
        # An attribute access on ANY receiver counts, the type is not inferred -- `self.tools.execute(...)`
        # and `c.used()` resolve the same way. That subsumes the old pair of regexes: `self.name` was
        # always a subset of `.name`, and the first version's `(?<![\w])\.name` lookbehind rejected
        # `self.tools.execute(...)` outright because the character before the dot is `s`.
        # A definition can never count: `def name(...)` is a FunctionDef, not an Attribute, so the old
        # "strip the def line first" step has no AST equivalent to need.
        used = (name in corpus_attrs
                or stem in corpus_strings or ("_" + stem) in corpus_strings)
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
