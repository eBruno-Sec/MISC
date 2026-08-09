"""Every function that USES a function-locally-imported module must IMPORT it (#125).

THE DEFECT THIS EXISTS FOR. `tools.py` imports `httpx` inside each function that needs it — there is no
module-level import — and `_graphql_argument_injection` used `httpx.AsyncClient` without one. Every call
raised NameError, and because `_run_graphql` awaits it without a guard, the exception took the WHOLE
GraphQL tool down with it: introspection, batching and field-suggestion findings were lost too, on any
real GraphQL endpoint. The unit tests passed throughout, because they exercise the pure helpers and
never reach the network call.

A missing local import is invisible to every test that does not execute that exact line, and pyflakes
does not flag it either: `httpx` is a legitimate name elsewhere in the file, so the reference looks
resolvable. A static check is the only thing that catches the class rather than the instance.

The guard is deliberately about NAMES THAT ARE ONLY EVER IMPORTED LOCALLY. A module imported at the top
of the file is in scope everywhere and needs no local import; this checks the opposite convention, which
is the one that can silently break.
"""
import ast
import os

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Files that follow the local-import convention for heavy/optional dependencies.
_FILES = ("tools.py", "agent.py", "main.py")


def _module_level_imports(tree):
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                names.add(a.asname or a.name)
    return names


def _local_imports(fn):
    """Names imported ANYWHERE inside this function body (any nesting)."""
    names = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                names.add(a.asname or a.name)
    return names


def _bound_names(fn):
    """Names bound in this scope other than by import: parameters and assignment targets. A closure that
    receives `dom` as an argument is not missing an import of it."""
    names = set()
    args = fn.args
    for a in list(args.args) + list(args.posonlyargs) + list(args.kwonlyargs):
        names.add(a.arg)
    for a in (args.vararg, args.kwarg):
        if a:
            names.add(a.arg)
    def _targets(t):
        """Every name a binding target introduces, including tuple/list unpacking and starred targets.
        Missing these is what made a response object named `rt` look like the rsync module imported as
        `rt` somewhere else in the file — the guard's name-based heuristic collides otherwise."""
        if isinstance(t, ast.Name):
            names.add(t.id)
        elif isinstance(t, ast.Starred):
            _targets(t.value)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                _targets(e)

    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                _targets(t)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            _targets(node.target)
        elif isinstance(node, ast.NamedExpr):                       # walrus
            _targets(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _targets(node.target)
        elif isinstance(node, (ast.comprehension,)):
            _targets(node.target)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not fn:
            names.add(node.name)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            _targets(node.optional_vars)
    return names


def _attribute_roots(fn):
    """Names used as `name.something` DIRECTLY in this scope (not inside a nested function, which is
    checked separately with its own enclosing scope)."""
    roots, nested = set(), set()
    for node in ast.walk(fn):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not fn:
            for inner in ast.walk(node):
                nested.add(id(inner))
    for node in ast.walk(fn):
        if id(node) in nested:
            continue
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            roots.add(node.value.id)
    return roots


def _functions(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _locally_imported_modules(tree):
    """Modules this file imports ONLY inside functions — the ones a missing local import breaks."""
    mod_level = _module_level_imports(tree)
    local = set()
    for fn in _functions(tree):
        local |= _local_imports(fn)
    return local - mod_level


def scan_scopes(tree, local_only, mod_level):
    """Report (lineno, fn_name, missing_module) with LEXICAL SCOPING: a nested function inherits every
    name its enclosing functions imported or bound. Without that, every closure that uses the parent's
    `import httpx as fx` looks like a defect, and the guard drowns in false positives."""
    out = []

    def visit(fn, inherited):
        visible = inherited | _local_imports(fn) | _bound_names(fn)
        for name in sorted((_attribute_roots(fn) & local_only) - visible):
            out.append((fn.lineno, fn.name, name))
        for node in ast.iter_child_nodes(fn):
            _descend(node, visible)

    def _descend(node, visible):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            visit(node, visible)
            return
        for child in ast.iter_child_nodes(node):
            _descend(child, visible)

    for node in tree.body:
        _descend(node, mod_level)
    return out


def test_no_function_uses_a_local_only_module_it_did_not_import():
    offenders = []
    for fname in _FILES:
        path = os.path.join(AGENT_DIR, fname)
        if not os.path.exists(path):
            continue
        tree = ast.parse(open(path, encoding="utf8").read())
        mod_level = _module_level_imports(tree)
        local_only = _locally_imported_modules(tree)
        for lineno, fn_name, name in scan_scopes(tree, local_only, mod_level):
            offenders.append("%s:%d %s() uses %s.* without importing it" % (fname, lineno, fn_name, name))
    assert offenders == [], "missing function-local imports:\n  " + "\n  ".join(offenders)


def test_the_guard_actually_catches_the_bug_it_was_written_for():
    """A guard that cannot fail is worth nothing — this is the negative control. This source is the shape
    `_graphql_argument_injection` had: httpx imported locally elsewhere, used here without an import."""
    src = (
        "def ok():\n"
        "    import httpx\n"
        "    return httpx.AsyncClient()\n"
        "def broken():\n"
        "    return httpx.AsyncClient()\n"
    )
    tree = ast.parse(src)
    mod_level = _module_level_imports(tree)
    local_only = _locally_imported_modules(tree)
    assert local_only == {"httpx"}
    found = []
    for fn in _functions(tree):
        missing = (_attribute_roots(fn) & local_only) - (_local_imports(fn) | mod_level)
        if missing:
            found.append((fn.name, sorted(missing)))
    assert found == [("broken", ["httpx"])], found


def test_graphql_techniques_claim_only_what_actually_fired_on_dvga():
    """graphql_field_suggestions stays unproven: DVGA answered introspection, batching and a confirmed
    SQLi through pastes(filter), but never produced a 'Did you mean' suggestion, so there is nothing to
    claim. The three that fired only did so AFTER the missing httpx import above was restored — before
    that, _run_graphql raised and every GraphQL finding was lost."""
    import techniques as T
    for tid in ("graphql_introspection", "graphql_batching_enabled", "graphql_argument_injection"):
        assert "dvga" in T.TECHNIQUES[tid]["validated_on"], tid
    assert T.TECHNIQUES["graphql_field_suggestions"]["validated_on"] == []
