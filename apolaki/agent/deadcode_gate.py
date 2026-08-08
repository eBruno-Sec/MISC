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
