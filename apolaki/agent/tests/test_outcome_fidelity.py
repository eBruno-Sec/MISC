"""I-2b OUTCOME FIDELITY -- the half of I-2 that an ownership census structurally cannot see.

WHY THIS FILE EXISTS. Q-089 (`7b82202`): `db.add_finding` has THREE outcomes -- INSERT, reroute to
the leads list (TRUTH #7), off-scope refusal (SCOPE #8) -- and reported all three through one `str`.
Only the refusal was distinguishable (it is falsy). A reroute returns the LEAD's id, TRUTHY exactly
like a store, so

    stored = sum(1 for f in findings if db.add_finding(session_id, f))     # main.py, pre-Q-089

reported `stored_findings=1` while the findings table held ZERO rows, and `/engage` told the operator
a finding was stored.

Invariant I-2 measured 0 unowned paths and was RIGHT. I-2 counts EDGES (producer -> persistence
owner); this path has exactly one owner. The defect lives on the RETURN edge, which an ownership
census does not traverse. So I-2 splits:

    I-2a  ownership          every finding-producing path reaches exactly ONE persistence owner
    I-2b  outcome fidelity   for every owner with MORE THAN ONE OUTCOME, every caller reporting a
                             COUNT or a STATUS must distinguish them          <-- THIS FILE

**An invariant that counts structure cannot see a defect that lives in a value.**

HOW THE OWNERS ARE FOUND: BY MEASUREMENT, NEVER BY A HAND-WRITTEN LIST. A hand-written owner list is
the declaration-vs-fact defect this codebase has hit twelve times -- a guard that checks a
declaration passes exactly what it exists to catch. `_multi_outcome_owners` DERIVES them:

  1. EFFECTS. A function's write-destination set is the union of its direct writes (an `_exec` /
     `execute` whose SQL literal starts INSERT/UPDATE/DELETE/REPLACE -> `sql:<table>`; a
     `write_text` / `write_bytes` / `writelines` / `json.dump` -> `file`) and, to a fixpoint, the
     destination sets of every production function it calls. Call resolution is by AST and handles
     `import x`, `import x as y` and `from x import f [as g]`, because a `mod.attr(` text scan has
     produced a confidently wrong ZERO in this repo twice this week.
  2. OUTCOMES. Each `return` in a writer is labelled with the destinations DEFINITELY written before
     it on its own path (a linear walk of the statement tree: an `if` contributes nothing to the
     fall-through unless BOTH arms wrote; loop and `try` bodies contribute nothing, since they may
     not run to completion). Two returns with different labels are two OUTCOMES.
  3. AMBIGUITY. An owner is TRUTHINESS-AMBIGUOUS when two returns with DIFFERENT outcomes are both
     non-statically-falsy -- i.e. the caller's cheapest test cannot separate "it was written" from
     "it was not". That is the Q-089 property, stated generally.

MEASURED 2026-08-21 against this tree: 178 production modules, 2469 functions, 88 transitive
writers, **14 multi-outcome owners, 11 of them truthiness-ambiguous**. `db.add_finding` is one of
them -- it is the anchor, and if the derivation ever stops finding it, the derivation is broken and
`test_the_known_q089_owner_is_still_derived` goes red rather than the tree going quiet.

WHAT THE GUARD FOUND (all three CONFIRMED BY EXECUTION, not by reading -- transcripts and the exact
patches are in `docs/handoff/outcome_fidelity.md`). The second multi-outcome owner is
`db.update_finding`, which has the same defect one function over: its REROUTE branch DELETEs the row
from the findings table, appends it to the leads list, and returns `True` -- indistinguishable from
a genuine in-place UPDATE -- while an off-scope refusal returns `False`, indistinguishable from
"no such finding". Three callers report a STATUS from that ambiguity:

  Q-090-A  POST /leads/{sid}/{lid}/confirm   an off-scope lead is DELETED from the leads list, no
           findings row is written, and the operator is told
           {"ok": true, "promoted": true, "machine_proof": true, "finding_id": ""}.  DATA LOSS.
  Q-090-B  PUT  /findings/{sid}/{fid}        an off-scope refusal is reported as HTTP 404
           "finding not found in this mission" -- while the row is right there.
  Q-090-C  POST /findings/{sid}/{fid}/poc    the write return is DISCARDED; the endpoint answers
           {"ok": true, "bytes": N, "attached_to": fid} with nothing attached.

This lane may not edit `main.py` / `agent.py`, so those three are pinned below as `_KNOWN_OPEN` and
reproduced as `xfail(strict=True)` -- each one retires in the commit that fixes it, the way Q-089
retired its own. The ratchet is EXACT in both directions: a new violation is red (the guard's job)
and a stale entry is red (so a landed fix must delete its line, rather than leaving a guard that
quietly guards nothing).
"""
from __future__ import annotations

import ast
import os
import re
import tempfile

import pytest

import db as dbmod
import main as mainmod

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ══════════════════════════════════════════════════════════════════════════════════════════════════
# THE PINNED INVENTORY. Every measured violation is in exactly ONE of these two tables.
# ══════════════════════════════════════════════════════════════════════════════════════════════════

#: Confirmed defects, each REPRODUCED BY EXECUTION (see the xfails at the bottom of this file and the
#: transcripts in docs/handoff/outcome_fidelity.md). Owner: the Codex lane holding main.py/agent.py.
#: DELETE the entry in the commit that lands the fix -- `test_no_pinned_violation_is_stale` requires
#: it, so a closed defect cannot leave a guard entry behind guarding nothing.
_KNOWN_OPEN = {
    # Q-090-A CLOSED in the commit that removed this entry. `confirm_lead` now gates the lead
    # removal on `fid.stored`, so a SCOPE refusal keeps the lead and answers 409 instead of
    # deleting it and reporting promoted=True. The pin is retired here rather than left behind
    # guarding nothing -- which is the rule the docstring above states and this guard enforces.
    ("agent.py", "BBHAgent._triage", "discarded-return", "db:update_finding"):
        "Q-090-D. The triage phase writes CWE/OWASP annotations back per finding and discards each "
        "return. A refusal or a reroute here removes the row mid-report with no signal; the loop "
        "continues and the report is generated from a set that no longer matches the table. Lower "
        "severity than A-C (nothing is reported to an operator) but the same blind write.",
}

#: Reads that DO distinguish the outcomes, or where the status is not a claim about the write. Each
#: names ONE measured call site; a second violation of the same shape in the same function is DRIFT,
#: not a free extension of the exemption (`test_every_exemption_matches_exactly_one_measured_site`).
_DISTINGUISHED = {
    ("db.py", "update_finding", "discarded-return", "db:add_lead"):
        "`add_lead(mid, finding)` inside update_finding's TRUTH (#7) branch. add_lead's no-write "
        "outcome requires a missing missions row, and `get_finding(mid, fid)` three lines above has "
        "returned a findings row for this mission -- which `delete_mission` cannot leave behind, "
        "since it DELETEs findings BEFORE missions (db.py:140-142). The id is not reported anywhere.",
    ("main.py", "engage", "status-report", "main:_run_source_review"):
        "`'status': 'created'` in /engage's response is the MISSION lifecycle state, not a claim "
        "about the source review -- which publishes its own `stored_findings`, made honest by Q-089 "
        "and pinned by tests/test_finding_write_verdict.py. Not an outcome report of the call above.",
}

#: Keys whose CONSTANT-TRUTHY value in a returned mapping is a claim that a write succeeded.
_STATUS_KEYS = frozenset({
    "ok", "status", "success", "stored", "imported", "saved", "promoted", "written",
    "persisted", "created", "updated", "attached_to", "count", "restored",
    "stored_findings", "findings_stored", "imported_count",
})

#: Attribute reads that ASK the owner what it did. A caller that reads one has distinguished the
#: outcomes and is not a violation, whatever else it then reports.
_OUTCOME_ACCESSORS = frozenset({"stored", "verdict"})

_WRITE_SQL = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE)\b", re.I)
_SQL_TABLE = re.compile(r"^\s*(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO)"
                        r"\s+([A-Za-z_]\w*)", re.I)
_EXEC_NAMES = frozenset({"_exec", "execute", "executemany", "executescript"})
_FILE_WRITE_NAMES = frozenset({"write_text", "write_bytes", "writelines"})


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# DERIVATION -- effects, outcomes, ambiguity. Corpus-injectable so the planted-bypass tests below can
# run the REAL derivation over a synthetic tree instead of a reimplementation of it.
# ══════════════════════════════════════════════════════════════════════════════════════════════════

def _production_sources(root=None):
    """Every production module, including future nested packages. `tests/` and `tier3/` are not
    production: a test may legitimately assert the truthiness of a lead id, and that is the pin."""
    root = root or AGENT_DIR
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ("tests", "tier3", "__pycache__", ".git", "data", "rules")]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                path = os.path.join(dirpath, fn)
                with open(path, encoding="utf-8", errors="replace") as fh:
                    out.append((os.path.relpath(path, root).replace("\\", "/"), fh.read()))
    return sorted(out)


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _sql_destination(call):
    """`sql:<table>` when this Call is a direct SQL write with a literal statement, else None."""
    if _dotted(call.func).split(".")[-1] not in _EXEC_NAMES or not call.args:
        return None
    arg = call.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        sql = arg.value
    elif isinstance(arg, ast.JoinedStr):
        sql = "".join(p.value for p in arg.values
                      if isinstance(p, ast.Constant) and isinstance(p.value, str))
    else:
        return None
    if not _WRITE_SQL.match(sql):
        return None
    table = _SQL_TABLE.match(sql)
    return "sql:" + (table.group(1).lower() if table else "?")


def _file_destination(call):
    name = _dotted(call.func)
    tail = name.split(".")[-1]
    if tail in _FILE_WRITE_NAMES or (tail == "dump" and name.split(".")[0] == "json"):
        return "file"
    return None


def _module_index(root=None):
    """modname -> {tree, aliases, from-imports, top-level+method defs}. One parse per module."""
    mods = {}
    for rel, src in _production_sources(root):
        try:
            tree = ast.parse(src)
        except SyntaxError:                                  # a module that cannot parse is not a caller
            continue
        aliases, direct = {}, {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[0]] = item.name.split(".")[-1]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    direct[item.asname or item.name] = (node.module.split(".")[-1], item.name)
        funcs = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                funcs[node.name] = node
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        funcs[node.name + "." + child.name] = child
        name = os.path.basename(rel)[:-3]
        mods[name] = {"rel": rel, "name": name, "tree": tree, "aliases": aliases,
                      "direct": direct, "funcs": funcs}
    return mods


def _resolve_call(call, mod, mods):
    """(module, function) for a call, resolving `import x as y`, `from x import f as g`, and a bare
    name bound to a def in the same module. Returns None when the callee is not production code."""
    func = call.func
    if isinstance(func, ast.Name):
        if func.id in mod["direct"]:
            target = mod["direct"][func.id]
            return target if target[0] in mods else None
        return (mod["name"], func.id) if func.id in mod["funcs"] else None
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        target = mod["aliases"].get(func.value.id)
        if target in mods:
            return (target, func.attr)
    return None


def _direct_effects(fnode):
    out = set()
    for node in ast.walk(fnode):
        if isinstance(node, ast.Call):
            dest = _sql_destination(node) or _file_destination(node)
            if dest:
                out.add(dest)
    return out


def _effect_table(mods):
    """(module, function) -> write-destination set, to a fixpoint over the production call graph."""
    effects = {(name, fname): _direct_effects(fnode)
               for name, mod in mods.items() for fname, fnode in mod["funcs"].items()}
    for _ in range(16):                                     # the graph is shallow; 16 is generous
        changed = False
        for name, mod in mods.items():
            for fname, fnode in mod["funcs"].items():
                grown = set(effects[(name, fname)])
                for node in ast.walk(fnode):
                    if isinstance(node, ast.Call):
                        target = _resolve_call(node, mod, mods)
                        if target and target != (name, fname) and target in effects:
                            grown |= effects[target]
                if grown != effects[(name, fname)]:
                    effects[(name, fname)] = grown
                    changed = True
        if not changed:
            break
    return effects


def _expr_effects(node, mod, mods, effects):
    if node is None:
        return set()
    out = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            dest = _sql_destination(sub) or _file_destination(sub)
            if dest:
                out.add(dest)
            target = _resolve_call(sub, mod, mods)
            if target in effects:
                out |= effects[target]
    return out


def _returns_with_outcomes(fnode, mod, mods, effects):
    """[(lineno, frozenset(destinations DEFINITELY written before this return), value_node)].

    A linear walk, deliberately conservative about what counts as "definitely written": an `if`
    without an else adds nothing to the fall-through, a loop body may not execute, and a `try` body
    may raise partway. Over-conservatism here can only MERGE outcomes (missing an owner), never
    invent one -- so the denominator this reports is a floor, not a guess."""
    found = []

    def walk(body, wrote):
        cur = set(wrote)
        for stmt in body:
            if isinstance(stmt, ast.Return):
                found.append((stmt.lineno,
                              frozenset(cur | _expr_effects(stmt.value, mod, mods, effects)),
                              stmt.value))
                return cur, True
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue                                    # a nested def is its own owner
            if isinstance(stmt, ast.If):
                cur |= _expr_effects(stmt.test, mod, mods, effects)
                then, then_left = walk(stmt.body, cur)
                if stmt.orelse:
                    other, other_left = walk(stmt.orelse, cur)
                    if then_left and not other_left:
                        cur = other
                    elif other_left and not then_left:
                        cur = then
                    elif not (then_left or other_left):
                        cur = then & other                  # definite only if BOTH arms wrote it
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                cur |= _expr_effects(getattr(stmt, "iter", None) or getattr(stmt, "test", None),
                                     mod, mods, effects)
                walk(stmt.body, cur)                        # may not execute -> nothing definite
                walk(stmt.orelse, cur)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    cur |= _expr_effects(item.context_expr, mod, mods, effects)
                cur, _ = walk(stmt.body, cur)
            elif isinstance(stmt, ast.Try):
                walk(stmt.body, cur)                        # may raise partway -> nothing definite
                for handler in stmt.handlers:
                    walk(handler.body, cur)
                walk(stmt.orelse, cur)
                cur, _ = walk(stmt.finalbody, cur)
            elif isinstance(stmt, (ast.Raise, ast.Continue, ast.Break)):
                return cur, True
            else:
                cur |= _expr_effects(stmt, mod, mods, effects)
        return cur, False

    end, terminated = walk(fnode.body, set())
    if not terminated and any(value is not None for _, _, value in found):
        found.append((fnode.end_lineno or fnode.lineno, frozenset(end), None))
    return found


def _truth_class(node):
    """'F' statically falsy, 'T' statically truthy, '?' not statically decidable."""
    if node is None:
        return "F"
    if isinstance(node, ast.Constant):
        return "T" if node.value else "F"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return "T" if node.elts else "F"
    if isinstance(node, ast.Dict):
        return "T" if node.keys else "F"
    return "?"


def _multi_outcome_owners(root=None, mods=None, effects=None):
    """(module, function) -> {outcomes, ambiguous, line} for every DERIVED multi-outcome owner."""
    mods = mods if mods is not None else _module_index(root)
    effects = effects if effects is not None else _effect_table(mods)
    owners = {}
    for name, mod in sorted(mods.items()):
        for fname, fnode in sorted(mod["funcs"].items()):
            if not effects[(name, fname)]:
                continue                                    # not a writer: nothing to be unfaithful about
            rets = _returns_with_outcomes(fnode, mod, mods, effects)
            labels = {label for _, label, _ in rets}
            if len(labels) < 2 or not any(v is not None for _, _, v in rets):
                continue
            ambiguous = any(
                rets[i][1] != rets[j][1]
                and _truth_class(rets[i][2]) != "F" and _truth_class(rets[j][2]) != "F"
                for i in range(len(rets)) for j in range(i + 1, len(rets)))
            owners[(name, fname)] = {
                "outcomes": sorted("+".join(sorted(label)) or "<none>" for label in labels),
                "ambiguous": ambiguous, "line": fnode.lineno}
    return owners


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# THE VIOLATION CENSUS -- callers reporting a COUNT or a STATUS from an ambiguous return
# ══════════════════════════════════════════════════════════════════════════════════════════════════

def _boolean_context(node, parents):
    """The name of the boolean context this expression sits in, or '' -- the COUNT half. `sum(1 for x
    in xs if OWNER(...))` and `len([... if OWNER(...)])` both land on 'comprehension condition'."""
    parent = parents.get(node)
    while isinstance(parent, ast.UnaryOp):
        node, parent = parent, parents.get(parent)
    if isinstance(parent, ast.BoolOp):
        return "and/or"
    if isinstance(parent, (ast.If, ast.While, ast.IfExp)) and parent.test is node:
        return type(parent).__name__.lower() + " test"
    if isinstance(parent, ast.Assert) and parent.test is node:
        return "assert"
    if isinstance(parent, ast.comprehension) and any(cond is node for cond in parent.ifs):
        return "comprehension condition"
    if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name) \
            and parent.func.id in ("bool", "any", "all"):
        return parent.func.id + "()"
    return ""


def _enclosing(mod):
    """node -> qualified enclosing def name ('Class.method' for methods), for stable violation keys.
    Keys are function NAMES, never line numbers: a violation must not move when an unrelated edit
    shifts the file, or the ratchet fails for the wrong reason and gets weakened to make it stop."""
    owner = {}

    def visit(node, name):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, name + "." + child.name if name else child.name)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_name = (name + "." + child.name) if name else child.name
                owner[child] = child_name
                visit(child, child_name)
            else:
                owner[child] = name
                visit(child, name)

    visit(mod["tree"], "")
    return owner


def _outcome_fidelity_violations(root=None):
    """Sorted (module, function, kind, owner) keys for every caller that reports a COUNT or a STATUS
    from a truthiness-AMBIGUOUS multi-outcome return without asking the owner what it did."""
    mods = _module_index(root)
    effects = _effect_table(mods)
    owners = {key for key, meta in _multi_outcome_owners(mods=mods, effects=effects).items()
              if meta["ambiguous"]}
    violations = []
    for name, mod in sorted(mods.items()):
        tree = mod["tree"]
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
        enclosing = _enclosing(mod)
        calls = [(n, _resolve_call(n, mod, mods)) for n in ast.walk(tree) if isinstance(n, ast.Call)]
        calls = [(n, t) for n, t in calls if t in owners and t != (name, enclosing.get(n, ""))]
        if not calls:
            continue

        tainted, scopes_calling, discarded = {}, {}, []
        for node, target in calls:
            scope = enclosing.get(node, "")
            scopes_calling.setdefault(scope, []).append((node.lineno, target))
            context = _boolean_context(node, parents)
            if context:
                violations.append((mod["rel"], scope, "boolean-read", "%s:%s" % target))
            parent = parents.get(node)
            if isinstance(parent, ast.Await):
                parent = parents.get(parent)
            if isinstance(parent, ast.Assign) and len(parent.targets) == 1 \
                    and isinstance(parent.targets[0], ast.Name):
                tainted[(scope, parent.targets[0].id)] = (node.lineno, target)
            elif isinstance(parent, ast.Expr):
                discarded.append((mod["rel"], scope, "discarded-return", "%s:%s" % target))

        # ONE HOP through a local name: the same question asked two lines later.
        distinguished = set()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)):
                continue
            key = (enclosing.get(node, ""), node.id)
            if key not in tainted:
                continue
            _, target = tainted[key]
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.attr in _OUTCOME_ACCESSORS:
                distinguished.add(key[0])                   # this scope ASKED what happened
                continue
            if _boolean_context(node, parents):
                violations.append((mod["rel"], key[0], "boolean-read", "%s:%s" % target))

        violations += [row for row in discarded if row[1] not in distinguished]

        # STATUS: a CONSTANT-truthy status key in a mapping built after an ambiguous write, in a
        # scope that never asked the owner what it did. A constant cannot be a claim about a write.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            scope = enclosing.get(node, "")
            if scope not in scopes_calling or scope in distinguished:
                continue
            before = [(line, t) for line, t in scopes_calling[scope] if line < node.lineno]
            if not before:
                continue
            for key_node, value in zip(node.keys, node.values):
                if isinstance(key_node, ast.Constant) and key_node.value in _STATUS_KEYS \
                        and _truth_class(value) == "T":
                    violations.append((mod["rel"], scope, "status-report", "%s:%s" % before[-1][1]))
    return sorted(set(violations))


def _fmt(rows):
    return "\n".join("    %s:%s  %s  <- %s" % row for row in sorted(rows)) or "    (none)"


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# 1. THE DENOMINATOR -- non-vacuity, and the anchor that proves the derivation still works
# ══════════════════════════════════════════════════════════════════════════════════════════════════

def test_the_production_corpus_and_writer_census_are_non_vacuous():
    """A census that silently loads less is how a guard goes quiet. These floors are DELIBERATE,
    REVIEWED numbers: lowering one must name the module and the commit that removed it, never
    accommodate a census that broke. Measured 2026-08-21: 178 modules, 2469 functions, 88 writers."""
    mods = _module_index()
    effects = _effect_table(mods)
    writers = [key for key, dests in effects.items() if dests]
    assert len(mods) >= 178, "the production-module census loaded too little: %d" % len(mods)
    assert len(effects) >= 2400, "the function census loaded too little: %d" % len(effects)
    assert len(writers) >= 80, (
        "the writer census found only %d function(s); it was 88 when this guard was written, so the "
        "effect resolver is broken rather than the tree having stopped writing" % len(writers))


def test_the_multi_outcome_owner_denominator_is_derived_and_non_vacuous():
    """THE DENOMINATOR, reported. 14 multi-outcome owners, 11 truthiness-ambiguous, measured
    2026-08-21. Not a hand-written list: change `_returns_with_outcomes` and this number moves."""
    owners = _multi_outcome_owners()
    ambiguous = [k for k, v in owners.items() if v["ambiguous"]]
    assert len(owners) >= 12, (
        "the multi-outcome derivation found only %d owner(s) (14 when written): %s"
        % (len(owners), sorted(owners)))
    assert len(ambiguous) >= 9, (
        "the ambiguity classifier found only %d ambiguous owner(s) (11 when written): %s"
        % (len(ambiguous), sorted(ambiguous)))
    assert len(ambiguous) < len(owners), (
        "every owner classified ambiguous -- the classifier is not discriminating, so a clean "
        "result below would be a property of the classifier and not of the tree")


def test_the_known_q089_owner_is_still_derived():
    """THE ANCHOR. `db.add_finding` is the owner Q-089 proved has three outcomes. If the derivation
    stops finding it, the derivation is broken -- and this fails instead of the tree going quiet."""
    owners = _multi_outcome_owners()
    assert ("db", "add_finding") in owners, (
        "the derivation lost db.add_finding, the one owner PROVEN multi-outcome by Q-089: %s"
        % sorted(owners))
    meta = owners[("db", "add_finding")]
    assert meta["ambiguous"], "add_finding's reroute is truthy exactly like a store -- Q-089's ticket"
    assert len(meta["outcomes"]) == 3, (
        "add_finding has three outcomes (refuse / reroute-to-leads / INSERT): %s" % meta["outcomes"])


def test_the_second_owner_the_guard_found_is_still_derived():
    """`db.update_finding` -- found by MEASUREMENT, not by the Q-089 ticket, and the whole reason
    this guard was worth building. Its REROUTE returns True after DELETEing the row from findings."""
    owners = _multi_outcome_owners()
    assert ("db", "update_finding") in owners
    assert owners[("db", "update_finding")]["ambiguous"]


def test_the_three_verdicts_of_the_anchor_owner_still_differ_at_runtime():
    """A NON-VACUITY control on the derivation's premise: the static claim "three outcomes" is only
    meaningful if the running function really produces three. Asserted against the TABLE and the
    LEADS LIST, never against the return value alone."""
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "i2b.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)
    scope = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}
    dbmod.create_mission("i2b", "I-2b", "active", "o", scope, {})
    base = {"title": "t", "severity": "low", "confidence": "confirmed", "evidence": "e",
            "impact": "i", "reproduction_steps": ["s"]}

    stored = dbmod.add_finding("i2b", dict(base, target="http://app:3000/a"))
    rerouted = dbmod.add_finding("i2b", dict(base, target="http://app:3000/b", confidence="lead"))
    refused = dbmod.add_finding("i2b", dict(base, target="http://evil.example.com/c"))

    assert (stored.verdict, rerouted.verdict, refused.verdict) == (
        dbmod.STORED, dbmod.REROUTED, dbmod.REFUSED)
    assert len(dbmod.get_findings("i2b")) == 1, "only the admitted finding is a row"
    assert len(((dbmod.get_mission("i2b") or {}).get("context") or {}).get("leads") or []) == 1
    # THE Q-089 PROPERTY, restated: two of the three are truthiness-identical.
    assert bool(stored) and bool(rerouted), "a reroute is truthy exactly like a store"
    assert stored.stored is True and rerouted.stored is False


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# 2. THE RATCHET -- exact in both directions
# ══════════════════════════════════════════════════════════════════════════════════════════════════

def test_no_caller_reports_a_count_or_status_from_an_undistinguished_multi_outcome_return():
    """I-2b. Every measured violation must be pinned as a KNOWN-OPEN defect or as a NAMED
    distinguished read. A new one is this guard's entire job."""
    pinned = set(_KNOWN_OPEN) | set(_DISTINGUISHED)
    new = [row for row in _outcome_fidelity_violations() if row not in pinned]
    assert not new, (
        "NEW outcome-fidelity violations -- a caller reports a COUNT or a STATUS from a return that "
        "cannot tell a write from a reroute or a refusal (this is Q-089's shape):\n%s\n"
        "Ask the owner what it did (db.FindingWriteId.stored / .verdict), or pin it with a reason."
        % _fmt(new))


def test_no_pinned_violation_is_stale():
    """The other direction. A fixed defect must have its entry DELETED in the fixing commit; a guard
    carrying entries for defects that no longer exist is a guard nobody can read. Four guards in this
    project have shipped unable to fail -- an inventory that only ever grows becomes one of them."""
    current = set(_outcome_fidelity_violations())
    stale = [row for row in set(_KNOWN_OPEN) | set(_DISTINGUISHED) if row not in current]
    assert not stale, (
        "pinned outcome-fidelity entries no longer measured -- delete them in the commit that fixed "
        "them (and retire the matching xfail):\n%s" % _fmt(stale))


def test_every_pinned_entry_names_a_reason():
    for table, label in ((_KNOWN_OPEN, "_KNOWN_OPEN"), (_DISTINGUISHED, "_DISTINGUISHED")):
        for key, reason in table.items():
            assert isinstance(reason, str) and len(reason.strip()) > 40, (
                "%s[%s] must say WHAT it is and why, in prose a reader can check" % (label, key))


def test_the_two_pinned_tables_are_disjoint():
    """A site cannot be both an open defect and an accepted read. Overlap is how an exemption
    silently swallows a defect."""
    assert set(_KNOWN_OPEN) & set(_DISTINGUISHED) == set()


def test_every_exemption_matches_exactly_one_measured_site():
    """Copied from the rate-policy guard, for the same reason: an exemption names ONE measured call
    site. A second violation of the same shape in the same function is drift, not a free extension."""
    current = _outcome_fidelity_violations()
    counts = {key: current.count(key) for key in _DISTINGUISHED}
    assert {k: c for k, c in counts.items() if c != 1} == {}, (
        "each distinguished-read exemption must match exactly one measured site: %s" % counts)


def test_the_violation_census_is_non_vacuous():
    """A census that found nothing would pass both ratchets forever."""
    current = _outcome_fidelity_violations()
    # 8 -> 7: Q-090-A was FIXED (main.py:confirm_lead now reads `fid.stored`). Lowering a
    # non-vacuity floor is only ever legitimate alongside the fix that removed the site, named in
    # the same commit -- never to accommodate a census that broke.
    assert len(current) >= 3, (
        "the violation census found only %d site(s); it was 3 after Q-090-A/B/C closed, so the "
        "resolver is broken rather than the tree being clean: %s" % (len(current), current))
    # SHAPE COVERAGE MOVED OFF THE PRODUCTION CENSUS, and the reason is the point of this whole file.
    # This used to assert that all three shapes were still present IN PRODUCTION. Fixing Q-090-B
    # removed the last `boolean-read` from the tree, so the assertion started failing on a CLEAN
    # result -- it could not tell "the detector broke" from "the codebase stopped doing it", which is
    # the exact confusion a non-vacuity control exists to resolve.
    #
    # The guarantee it was reaching for is that the DETECTOR can still see all three shapes, and that
    # is a property of the detector, not of production. It belongs on the planted bypasses below,
    # where every shape is deliberately present and always will be. Asserted there instead:
    # `test_every_violation_shape_is_provably_detectable`. Production is then free to reach zero,
    # which is the goal, without silently disarming the guard on its way.
    assert {row[2] for row in current} <= {"boolean-read", "status-report", "discarded-return"}, (
        "the census reported a shape this guard does not model: %s" % current)


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# 3. PLANTED BYPASSES -- a guard that has never failed is indistinguishable from one that cannot
# ══════════════════════════════════════════════════════════════════════════════════════════════════

_OWNER_SRC = (
    "import uuid\n"
    "_conn = None\n"
    "def _exec(sql, params=()):\n"
    "    return _conn.execute(sql, params)\n"
    "def add_thing(mid, thing):\n"
    "    if thing.get('bad'):\n"
    "        return ''\n"
    "    if thing.get('lead'):\n"
    "        return add_side(mid, thing)\n"
    "    tid = uuid.uuid4().hex\n"
    "    _exec('INSERT INTO things VALUES(?,?)', (tid, mid))\n"
    "    return tid\n"
    "def add_side(mid, thing):\n"
    "    sid = uuid.uuid4().hex\n"
    "    _exec('UPDATE missions SET data=? WHERE id=?', (thing, mid))\n"
    "    return sid\n"
)


def _fake_tree(tmp_path, caller_src):
    root = tmp_path / "agent"
    (root / "pkg").mkdir(parents=True)
    (root / "store.py").write_text(_OWNER_SRC, encoding="utf8")
    (root / "pkg" / "caller.py").write_text(caller_src, encoding="utf8")
    return str(root)


def test_the_derivation_finds_a_brand_new_multi_outcome_owner(tmp_path):
    """NON-VACUITY OF THE DERIVATION ITSELF, in a nested package the census has never seen. If this
    fails, the 14 owners above are a property of the corpus, not of the measurement."""
    owners = _multi_outcome_owners(root=_fake_tree(tmp_path, "x = 1\n"))
    assert ("store", "add_thing") in owners, sorted(owners)
    assert owners[("store", "add_thing")]["ambiguous"]
    assert len(owners[("store", "add_thing")]["outcomes"]) == 3


def test_the_derivation_does_not_call_a_single_outcome_writer_multi_outcome(tmp_path):
    """THE OTHER HALF OF THE MUTANT. A derivation that flagged every writer would make the ratchet
    meaningless -- everything would be pinned and nothing would be measured."""
    root = _fake_tree(tmp_path, "x = 1\n")
    (tmp_path / "agent" / "store.py").write_text(
        "_conn = None\n"
        "def _exec(sql, params=()):\n"
        "    return _conn.execute(sql, params)\n"
        "def add_thing(mid, thing):\n"
        "    _exec('INSERT INTO things VALUES(?,?)', (thing, mid))\n"
        "    return mid\n", encoding="utf8")
    assert ("store", "add_thing") not in _multi_outcome_owners(root=root)


#: Every planted bypass, named so the parametrized test AND the shape-coverage control read the
#: SAME specimens. Two copies would let one drift and quietly stop covering a shape.
_PLANTED = [
    ("import store\ndef f(m, x):\n    if store.add_thing(m, x):\n        return 1\n",
     "boolean-read"),
    ("import store as _s\ndef f(m, xs):\n    return sum(1 for x in xs if _s.add_thing(m, x))\n",
     "boolean-read"),
    ("from store import add_thing\ndef f(m, x):\n    return bool(add_thing(m, x))\n",
     "boolean-read"),
    ("from store import add_thing as at\ndef f(m, x):\n    tid = at(m, x)\n"
     "    if tid:\n        return 1\n",
     "boolean-read"),
    ("import store\ndef f(m, x):\n    return store.add_thing(m, x) and 2\n",
     "boolean-read"),
    ("import store\ndef f(m, xs):\n    return len([x for x in xs if store.add_thing(m, x)])\n",
     "boolean-read"),
    ("import store\ndef f(m, x):\n    tid = store.add_thing(m, x)\n"
     "    return {'ok': True, 'id': tid}\n",
     "status-report"),
    ("import store as _s\ndef f(m, x):\n    _s.add_thing(m, x)\n    return {'stored': 1}\n",
     "status-report"),
    ("import store\ndef f(m, x):\n    store.add_thing(m, x)\n    return None\n",
     "discarded-return"),
]


@pytest.mark.parametrize("planted,shape", _PLANTED)
def test_the_guard_goes_red_on_a_planted_bypass(tmp_path, planted, shape):
    """THE MANDATORY PLANTED BYPASS, one per binding form and per violation shape -- including the
    aliased and from-imported spellings a `mod.attr(` text scan misses, and the `sum(1 for ...)` that
    Q-089 actually shipped. A guard that has never failed cannot be told apart from one that cannot
    fail; this project has shipped four of those."""
    rows = _outcome_fidelity_violations(root=_fake_tree(tmp_path, planted))
    planted_rows = [r for r in rows if r[0] == "pkg/caller.py"]
    assert planted_rows, "the census did not flag a planted bypass:\n%s" % planted
    assert any(r[2] == shape for r in planted_rows), (
        "flagged, but not as a %s: %s\n%s" % (shape, planted_rows, planted))


def test_every_violation_shape_is_provably_detectable(tmp_path):
    """SHAPE COVERAGE, moved here from the production census.

    The census used to assert all three shapes were still present IN PRODUCTION. That made a CLEAN
    tree indistinguishable from a broken detector -- and it started failing the moment Q-090-B removed
    the last `boolean-read` from the codebase, i.e. on a success. Whether the detector can SEE a shape
    is a property of the detector; it belongs where the shapes are guaranteed to exist.

    Every shape is asserted against a freshly planted specimen, so production is free to reach zero
    without disarming the guard on the way down.
    """
    seen = set()
    for i, (planted, shape) in enumerate(_PLANTED):
        # `i`, not `len(seen)`: several specimens share a shape, so a set-length index collides and
        # the second one raises FileExistsError. Caught by running it.
        rows = _outcome_fidelity_violations(root=_fake_tree(tmp_path / ("p%d" % i), planted))
        seen |= {r[2] for r in rows if r[0] == "pkg/caller.py"}
    assert seen >= {"boolean-read", "status-report", "discarded-return"}, (
        "the detector can no longer see every violation shape it claims to model; detected only %s"
        % sorted(seen))


def test_the_guard_does_not_flag_an_ordinary_id_use(tmp_path):
    """A guard that flagged everything would also be vacuous. Using the return AS AN ID is the
    dominant, correct idiom and must stay silent -- that is what made `str` the right Q-089 fix."""
    rows = _outcome_fidelity_violations(root=_fake_tree(
        tmp_path,
        "import store\n"
        "def f(m, x):\n"
        "    x['id'] = store.add_thing(m, x)\n"
        "    tid = store.add_thing(m, x)\n"
        "    return {'id': tid, 'title': x.get('title')}\n"))
    assert [r for r in rows if r[0] == "pkg/caller.py"] == []


def test_the_guard_does_not_flag_a_caller_that_asks_what_happened(tmp_path):
    """THE FIX SHAPE MUST BE ACCEPTED. A caller that reads `.stored` HAS distinguished the outcomes,
    so it may report any count or status it likes. If this failed, the guard would punish the very
    remediation it demands and the next lane would weaken it instead of using it."""
    rows = _outcome_fidelity_violations(root=_fake_tree(
        tmp_path,
        "import store\n"
        "def f(m, xs):\n"
        "    n = 0\n"
        "    for x in xs:\n"
        "        w = store.add_thing(m, x)\n"
        "        if w.stored:\n"
        "            n += 1\n"
        "    return {'ok': True, 'stored': n}\n"))
    assert [r for r in rows if r[0] == "pkg/caller.py"] == []


def test_the_resolver_ignores_a_same_named_function_from_another_module(tmp_path):
    """A `mod.attr(` scan cannot tell `store.add_thing` from `other.add_thing`. This one can, and a
    false positive here would be pinned as a defect and waste the next lane's day."""
    root = _fake_tree(tmp_path,
                      "import other\ndef f(m, x):\n    if other.add_thing(m, x):\n        return 1\n")
    (tmp_path / "agent" / "other.py").write_text(
        "def add_thing(m, x):\n    return bool(x)\n", encoding="utf8")
    assert [r for r in _outcome_fidelity_violations(root=root) if r[0] == "pkg/caller.py"] == []


# ══════════════════════════════════════════════════════════════════════════════════════════════════
# 4. THE THREE DEFECTS THE GUARD FOUND -- reproduced through the REAL endpoints
#
# Each is `xfail(strict=True)`: it FAILS today, and the day the fix lands it passes UNEXPECTEDLY and
# goes red, which is how the fixing commit is made to retire it -- exactly how Q-089 retired its own
# strict xfail. Strict matters: a plain xfail would let a fix land with the guard still claiming the
# defect is open, and would let a REGRESSION land with nobody noticing it was ever closed.
# ══════════════════════════════════════════════════════════════════════════════════════════════════

_Q090 = ("Q-090 (owner: the Codex lane holding main.py/agent.py). The patch is in "
         "docs/handoff/outcome_fidelity.md. Retire this xfail IN the commit that lands it, and "
         "delete the matching _KNOWN_OPEN entry -- test_no_pinned_violation_is_stale requires both.")

SCOPE_APP = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}
SCOPE_WIDE = {"in_scope": ["app", "old"], "bases": ["http://app:3000", "http://old:3000"],
              "out_of_scope": []}


@pytest.fixture
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.delenv("APOLAKI_API_TOKEN", raising=False)
    dbmod.init(str(tmp_path / "i2b.db"))
    mainmod.sessions.clear()
    client = TestClient(mainmod.app)
    try:
        yield client
    finally:
        client.close()
        mainmod.sessions.clear()


_LEAD = {"id": "lead001", "_lid": "lead001", "title": "Reflected XSS", "severity": "high",
         "family": "xss", "cwe": "CWE-79", "impact": "script execution in the victim browser",
         "evidence": "HTTP 200 response reflected the probe token <svg onload=1> at /q",
         "how_to_confirm": ["GET /q?x=<svg onload=1>"], "description": "reflected"}

_FINDING = {"id": "f1", "title": "SQLi", "severity": "high", "confidence": "confirmed",
            "family": "sqli", "cwe": "CWE-89", "evidence": "e", "impact": "i",
            "reproduction_steps": ["s"]}


def test_q090a_confirming_an_off_scope_lead_must_not_destroy_it_and_claim_promotion(api):
    """MEASURED 2026-08-21 against the real endpoint: HTTP 200
    {"ok": true, "promoted": true, "machine_proof": true, "finding_id": ""} -- while the findings
    table holds 0 rows AND the leads list holds 0. The lead is GONE. `db.add_finding` REFUSED it
    (SCOPE #8) and returned "", and the endpoint removed the lead anyway because it never asked."""
    sid = "q090a"
    dbmod.create_mission(sid, "Q-090", "active", "o", SCOPE_APP, {})
    dbmod.add_lead(sid, dict(_LEAD, target="http://elsewhere.example.com/q"))
    assert len(api.get("/missions/%s" % sid).json()["leads"]) == 1, "precondition: the lead exists"

    body = api.post("/leads/%s/lead001/confirm" % sid,
                    json={"operator": "erwin", "rationale": "reproduced by hand"}).json()

    rows = dbmod.get_findings(sid)
    leads = api.get("/missions/%s" % sid).json()["leads"]
    assert not (body.get("promoted") and not rows and not leads), (
        "the lead was destroyed, no finding row was written, and the operator was told "
        "promoted=%r finding_id=%r" % (body.get("promoted"), body.get("finding_id")))
    assert len(rows) + len(leads) == 1, (
        "an operator confirmation must leave the item SOMEWHERE: %d row(s), %d lead(s)"
        % (len(rows), len(leads)))


def test_q090b_a_refused_edit_must_not_be_reported_as_a_missing_finding(api):
    """MEASURED: the row is in the table and `PUT /findings/{sid}/{fid}` answers 404 "finding not
    found in this mission". `db.update_finding` returns False for BOTH "no such finding" and "the
    write was refused as off-scope", and the endpoint reports the second as the first."""
    sid = "q090b"
    dbmod.create_mission(sid, "Q-090", "active", "o", SCOPE_WIDE, {})
    assert dbmod.add_finding(sid, dict(_FINDING, target="http://old:3000/q",
                                       url="http://old:3000/q")).stored
    dbmod.update_mission(sid, scope=SCOPE_APP)          # scope narrowed after the fact
    assert len(dbmod.get_findings(sid)) == 1, "precondition: the row is still in the table"

    response = api.put("/findings/%s/f1" % sid, json={"analyst_notes": "reviewed by erwin"})

    assert not (response.status_code == 404 and len(dbmod.get_findings(sid)) == 1), (
        "the finding EXISTS and the API answered %d %r"
        % (response.status_code, response.json().get("detail")))


def test_q090c_a_poc_that_was_not_written_must_not_be_reported_as_attached(api, monkeypatch):
    """MEASURED: {"ok": true, "bytes": 4, "attached_to": "f1"} with no `poc_screenshot` on the row.
    `capture_finding_poc` calls `db.update_finding` as a bare statement and throws the return away --
    the same shape as Q-089's `/restore`, which answered {"imported": true} for a partial restore."""
    import browser_engine
    sid = "q090c"
    dbmod.create_mission(sid, "Q-090", "active", "o", SCOPE_WIDE, {})
    assert dbmod.add_finding(sid, dict(_FINDING, target="http://old:3000/q",
                                       url="http://old:3000/q")).stored
    dbmod.update_mission(sid, scope=SCOPE_APP)
    monkeypatch.setattr(browser_engine, "screenshot",
                        lambda url, **kw: {"browser": "chromium", "png_b64": "AAAA", "bytes": 4})

    body = api.post("/findings/%s/f1/poc" % sid).json()
    row = dbmod.get_finding(sid, "f1") or {}

    assert not (body.get("ok") and "poc_screenshot" not in row), (
        "the endpoint answered %r and the finding carries no screenshot" % body)
