"""Every first-party module attribute a tool references must actually exist (#125).

THE DEFECT THIS EXISTS FOR. `tools._run_dom_trace` evaluated `dt.DOM_SCAN_JS` in the rendered page.
`dom_trace.DOM_SCAN_JS` did not exist — a refactor had replaced the old browser_engine flow and left a
dead `_TRACE_JS` behind carrying the same JavaScript, so the logic LOOKED present. The call sits inside
`try: ... except Exception: pass`, so the AttributeError was swallowed on every single render.

The consequences were invisible and large: `in_href` / `in_src` / `in_attr` / `in_text` were never
populated, which silently retired `dom_link_manipulation` and `dom_data_manipulation` completely, and
— because the XSS payload pass only runs where the canary `reflected` — stopped every DOM-XSS payload
render from firing too. Three families quietly stopped being detectable and nothing failed.

A missing attribute behind a broad `except` cannot be caught by unit tests of the pure helpers, and it
cannot be caught by importing the module either: the name resolves at attribute-access time, in a branch
that only runs against a live browser. Reading the reference statically and checking it against the real
module is what catches it.

Scope is deliberately FIRST-PARTY modules only. Third-party attribute surfaces change between versions
and are not ours to pin; our own modules are.
"""
import ast
import importlib
import os

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FILES = ("tools.py", "agent.py", "main.py")

# Attributes that legitimately do not exist as module globals.
_IGNORE_ATTRS = {"__name__", "__file__", "__doc__", "__dict__", "__class__"}


def _first_party_modules():
    """Module names that live in the agent directory — the ones this repo is responsible for."""
    return {f[:-3] for f in os.listdir(AGENT_DIR)
            if f.endswith(".py") and not f.startswith("_") and f != "conftest.py"}


def _functions(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _alias_map(fn, first_party):
    """alias -> module name, for first-party modules imported INSIDE this function."""
    out = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Import):
            for a in node.names:
                mod = a.name.split(".")[0]
                if mod in first_party:
                    out[a.asname or mod] = mod
    return out


def _rebound(fn, aliases):
    """Aliases reassigned in this scope — their attributes are no longer the module's."""
    hit = set()
    for node in ast.walk(fn):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets = [node.target]
        for t in targets:
            if isinstance(t, ast.Name) and t.id in aliases:
                hit.add(t.id)
    return hit


def _attr_refs(fn, aliases):
    """(alias, attribute) pairs referenced directly in this scope."""
    refs = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id in aliases:
                refs.add((node.value.id, node.attr))
    return refs


def _collect_missing():
    first_party = _first_party_modules()
    cache, missing = {}, []
    for fname in _FILES:
        path = os.path.join(AGENT_DIR, fname)
        if not os.path.exists(path):
            continue
        tree = ast.parse(open(path, encoding="utf8").read())
        for fn in _functions(tree):
            aliases = _alias_map(fn, first_party)
            if not aliases:
                continue
            skip = _rebound(fn, set(aliases))
            for alias, attr in sorted(_attr_refs(fn, set(aliases))):
                if alias in skip or attr in _IGNORE_ATTRS:
                    continue
                mod_name = aliases[alias]
                if mod_name not in cache:
                    try:
                        cache[mod_name] = importlib.import_module(mod_name)
                    except Exception:
                        cache[mod_name] = None
                mod = cache[mod_name]
                if mod is None:
                    continue                    # unimportable here (optional dep) — not this test's job
                if not hasattr(mod, attr):
                    missing.append("%s:%d %s() -> %s.%s does not exist"
                                   % (fname, fn.lineno, fn.name, mod_name, attr))
    return missing


def test_no_tool_references_a_module_attribute_that_does_not_exist():
    missing = _collect_missing()
    assert missing == [], "unresolvable first-party module attributes:\n  " + "\n  ".join(missing)


def test_the_dom_scan_constant_the_tracer_evaluates_is_present():
    """The specific regression, asserted by name: without it the DOM sink scan silently returns nothing
    and three families stop being detectable."""
    import dom_trace as dt
    assert isinstance(dt.DOM_SCAN_JS, str) and len(dt.DOM_SCAN_JS) > 100
    for key in ("in_href", "in_src", "in_attr", "in_text"):
        assert key in dt.DOM_SCAN_JS, key


def test_the_guard_catches_a_missing_attribute():
    """Negative control: a guard that cannot fail proves nothing."""
    src = ("def broken():\n"
           "    import dom_trace as dt\n"
           "    return dt.THIS_ATTRIBUTE_DOES_NOT_EXIST\n")
    tree = ast.parse(src)
    fn = list(_functions(tree))[0]
    aliases = _alias_map(fn, _first_party_modules())
    assert aliases == {"dt": "dom_trace"}
    refs = _attr_refs(fn, set(aliases))
    assert ("dt", "THIS_ATTRIBUTE_DOES_NOT_EXIST") in refs
    import dom_trace
    assert not hasattr(dom_trace, "THIS_ATTRIBUTE_DOES_NOT_EXIST")
