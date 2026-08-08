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
# six entries that already carried a written justification. Lower it whenever the real number drops, so
# the ratchet stays tight enough to catch the next regression.
QUALIFIED_BASELINE = 40


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
    allowed = [u for u in unused if u.split(".")[-1] in ALLOWED_UNUSED]
    flagged = [u for u in unused if u.split(".")[-1] not in ALLOWED_UNUSED]
    return {"unused": flagged, "allowed": allowed, "count": len(flagged),
            "baseline": QUALIFIED_BASELINE, "ok": len(flagged) <= QUALIFIED_BASELINE}
