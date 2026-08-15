"""ASVS-5 curated-partial objective model (Codex Tier-1 #1): findings violate objectives, clean attempted
checks verify them, blocked/untested are never counted as verified, and the model never claims full ASVS.

Q-012 adds the guard that matters: every `engine` name in OBJECTIVES must resolve to something a REAL
dispatcher can reach, computed from the dispatch tables rather than from a hand-written allowlist (an
allowlist would be the same declaration-vs-fact defect one layer up), plus the rule that a capability the
product does not have reports "not_implemented" and never hides inside "not_tested".

Q-048 closes the same defect one level DOWN. Q-012 proved the engine can RUN; it did not prove the engine
can FAIL. `assess()` records "verified" when an objective's engine ran and no finding in its `violated_by`
set exists — an inference that is sound ONLY if that engine can actually EMIT one of those families. Six
objectives could not: they read "verified" in every possible run, asserting a property nothing tested.
The producer map below is computed from SOURCE with `ast` for the same reason the reachability scan is —
a hand-written "engine X emits family Y" table would be the declaration-vs-fact defect all over again.
"""
import ast
import functools
import os
import re

import asvs_model as A
import tools

AGENT_ROOT = os.path.dirname(os.path.abspath(A.__file__))
_SKIP_DIRS = {"tests", "__pycache__", "data", "rules"}


# ── Q-048: which finding families can each engine actually emit? (derived from source) ────────────────
#
# Recognises the four shapes the tree really uses to set a family, all of which are load-bearing:
#   {"family": "xss"} literal · f(family="xss") keyword · d["family"] = "xss" · and a literal passed
#   POSITIONALLY into a callee parameter named `family` (dom_tool builds every DOM finding through
#   `_base(url, title, sev, desc, ev, family, cwe, ...)`, so reading dict literals alone reports ZERO
#   families for run_dom_audit — an engine that confirms four classes).
# Values may be a literal, a NAME bound to one, a ternary (transport_posture.py:397 picks its family with
# `"transport_posture" if kind in ("tls","cert") else "security_misconfig"`), or an `or` chain.
# Edges follow `import x as y` (including imports written INSIDE a function, which is how tools.py imports
# nearly every helper), `from x import f`, and `self._method(...)`, then close transitively.

def _const_strs(node, consts, local):
    """Every string this expression can evaluate to, or None if it is dynamic."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        for src in (local, consts):
            if node.id in src:
                return {src[node.id]}
        return None
    if isinstance(node, ast.IfExp):
        got = (_const_strs(node.body, consts, local) or set()) | \
              (_const_strs(node.orelse, consts, local) or set())
        return got or None
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        got = set()
        for v in node.values:
            got |= (_const_strs(v, consts, local) or set())
        return got or None
    return None


def _str_assigns(node):
    out = {}
    for n in ast.walk(node):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) \
                and isinstance(n.value.value, str):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, n.value.value)
    return out


def _record_import(n, aliases, froms):
    if isinstance(n, ast.Import):
        for a in n.names:
            aliases[a.asname or a.name.split(".")[0]] = a.name
    elif isinstance(n, ast.ImportFrom):
        for a in n.names:
            if n.level and not n.module:
                aliases[a.asname or a.name] = a.name
            else:
                froms[a.asname or a.name] = (n.module or "", a.name)


def _imports_under(node):
    """Imports bound ANYWHERE under `node` — used for ONE function at a time."""
    aliases, froms = {}, {}
    for n in ast.walk(node):
        _record_import(n, aliases, froms)
    return aliases, froms


def _module_level_imports(tree):
    """Imports bound at MODULE scope only.

    Scoping matters and getting it wrong over-attributes badly: tools.py binds `import saml_tool as st`
    INSIDE _run_saml (tools.py:2347). Collecting aliases from the whole module tree leaked that binding
    into every other method, so any unrelated method with a local `st` variable calling `st.foo()`
    resolved to saml_tool and inherited its families — which is how _browser_navigate came to look like a
    producer of `broken_auth`. A map that over-attributes makes the ratchet weaker, not noisier: a dead
    engine looks live and the false-verify path it guards stays open.
    """
    aliases, froms = {}, {}

    def walk(body):
        for n in body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue                       # function-local imports are per-function, not module-wide
            _record_import(n, aliases, froms)
            for attr in ("body", "orelse", "finalbody"):
                inner = getattr(n, attr, None)
                if isinstance(inner, list):
                    walk(inner)                # module-level try:/if: import guards are common
            for h in getattr(n, "handlers", []) or []:
                walk(h.body)
    walk(tree.body)
    return aliases, froms


class _Mod:
    def __init__(self, name, tree):
        self.name, self.tree = name, tree
        self.aliases, self.froms = _module_level_imports(tree)
        self.consts = _str_assigns(ast.Module(body=[b for b in tree.body
                                                    if isinstance(b, ast.Assign)], type_ignores=[]))
        self.funcs = {}
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[n.name] = n
            elif isinstance(n, ast.ClassDef):
                for m in n.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.funcs["%s.%s" % (n.name, m.name)] = m


def _load_modules():
    mods = {}
    for dirpath, dirnames, filenames in os.walk(AGENT_ROOT):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in sorted(filenames):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    tree = ast.parse(fh.read(), filename=path)
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue
            name = os.path.relpath(path, AGENT_ROOT)[:-3].replace(os.sep, ".")
            mods[name] = _Mod(name, tree)
    return mods


def _resolve(f, fnode, mi, qual, mods):
    """A call's func expression -> (module, qualname), or (module, '*') when it is not a known def."""
    aliases, froms = dict(mi.aliases), dict(mi.froms)
    if not isinstance(fnode, ast.Module):
        a2, f2 = _imports_under(fnode)
        aliases.update(a2)
        froms.update(f2)
    cls = qual.split(".")[0] if "." in qual else None
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        if f.value.id == "self" and cls:
            tgt = "%s.%s" % (cls, f.attr)
            return (mi.name, tgt) if tgt in mi.funcs else None
        m = aliases.get(f.value.id) or (froms.get(f.value.id) or (None,))[0]
        if m in mods:
            return (m, f.attr if f.attr in mods[m].funcs else "*")
    elif isinstance(f, ast.Name):
        if f.id in froms and froms[f.id][0] in mods:
            m, orig = froms[f.id]
            return (m, orig if orig in mods[m].funcs else "*")
        if f.id in mi.funcs:
            return (mi.name, f.id)
    return None


def _returned_strs(fnode):
    return {n.value.value for n in ast.walk(fnode)
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str) and n.value.value}


def _families_here(fnode, mi, qual, mods):
    """Families this node emits itself: dict/keyword/subscript literals, plus literals it hands to a
    callee parameter named `family`."""
    fams = set()
    local = _str_assigns(fnode) if not isinstance(fnode, ast.Module) else {}
    bound = {t.id: n.value for n in ast.walk(fnode) if isinstance(n, ast.Assign)
             and isinstance(n.value, ast.Call) for t in n.targets if isinstance(t, ast.Name)}
    for n in ast.walk(fnode):
        if isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and k.value == "family":
                    fams |= (_const_strs(v, mi.consts, local) or set())
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) \
                        and t.slice.value == "family":
                    fams |= (_const_strs(n.value, mi.consts, local) or set())
        elif isinstance(n, ast.Call):
            for kw in n.keywords:
                if kw.arg == "family":
                    fams |= (_const_strs(kw.value, mi.consts, local) or set())
            if isinstance(n.func, ast.Attribute) and n.func.attr == "setdefault" and len(n.args) == 2 \
                    and isinstance(n.args[0], ast.Constant) and n.args[0].value == "family":
                fams |= (_const_strs(n.args[1], mi.consts, local) or set())
            # literal handed to a callee's `family` parameter
            tgt = _resolve(n.func, fnode, mi, qual, mods)
            tnode = mods[tgt[0]].funcs.get(tgt[1]) if tgt and tgt[0] in mods else None
            if tnode is None:
                continue
            names = [p.arg for p in (list(tnode.args.posonlyargs) + list(tnode.args.args))]
            arg = None
            if "family" in names and names.index("family") < len(n.args):
                arg = n.args[names.index("family")]
            for kw in n.keywords:
                if kw.arg == "family":
                    arg = kw.value
            if arg is None:
                continue
            got = _const_strs(arg, mi.consts, local)
            if got:
                fams |= got
            elif isinstance(arg, ast.Name) and arg.id in bound:
                # `fam = gadget_family(...)` -> `gadget_finding(url, prop, nav, fam)`
                g = _resolve(bound[arg.id].func, fnode, mi, qual, mods)
                gnode = mods[g[0]].funcs.get(g[1]) if g and g[0] in mods else None
                if gnode is not None:
                    fams |= _returned_strs(gnode)
    return fams


@functools.lru_cache(maxsize=1)
def _family_producers():
    """engine tool name -> every finding family a call to it can end up emitting."""
    mods = _load_modules()
    direct, graph = {}, {}
    for mname, mi in mods.items():
        modlvl = ast.Module(body=[b for b in mi.tree.body if not isinstance(
            b, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))], type_ignores=[])
        for qual, fnode in list(mi.funcs.items()) + [("<module>", modlvl)]:
            key = (mname, qual)
            direct[key] = _families_here(fnode, mi, qual, mods)
            graph[key] = {t for t in (_resolve(n.func, fnode, mi, qual, mods)
                                      for n in ast.walk(fnode) if isinstance(n, ast.Call)) if t}
        star = (mname, "*")
        direct[star] = set().union(*[direct[(mname, q)] for q in list(mi.funcs) + ["<module>"]]) \
            if mi.funcs or True else set()
        graph[star] = set().union(*[graph[(mname, q)] for q in list(mi.funcs) + ["<module>"]]) \
            if mi.funcs or True else set()
    fams = {k: set(v) for k, v in direct.items()}
    for _ in range(60):
        changed = False
        for k, tgts in graph.items():
            for t in tgts:
                add = fams.get(t)
                if add and not add <= fams[k]:
                    fams[k] |= add
                    changed = True
        if not changed:
            break
    out = {}
    for qual in mods["tools"].funcs:
        if qual.startswith("ToolRegistry._"):
            out[qual[len("ToolRegistry._"):]] = fams[("tools", qual)]
    return out


def _dispatch_reachable():
    """Every tool name a real dispatcher can reach — DERIVED from the dispatch tables, never hand-listed.

    `ToolRegistry.execute()` resolves a call with `getattr(self, "_" + tool_name)`, so a name is reachable
    only when BOTH hold: some emitter can name it, and the method it would resolve to exists. There are two
    emitters, and checking one alone was how phantoms survived — `TOOL_PERMISSIONS` (the gate every
    deterministic/internal dispatch passes through) and `CLAUDE_TOOLS` (the spec handed to the model).
    Aliases fall out for free: spec name `enumerate_ids` resolves via `_enumerate_ids`.
    """
    emitters = set(tools.TOOL_PERMISSIONS) | {t["name"] for t in tools.CLAUDE_TOOLS}
    return {n for n in emitters if hasattr(tools.ToolRegistry, "_" + n)}


def test_the_reachability_scan_is_not_vacuous():
    """Guard the guard: if this set came back empty every assertion below would pass for free."""
    reachable = _dispatch_reachable()
    assert len(reachable) > 50
    assert {"run_sqli", "run_authz_matrix", "run_js_review"} <= reachable


def test_every_objective_engine_resolves_to_a_real_dispatcher():
    """Q-012, the regression that fails the moment the model regains a phantom.

    Six names claimed capability nothing could reach: authz_matrix (the ToolResult LABEL of
    run_authz_matrix), dependency_intel + bizlogic_graph (MODULES, not tools), header_analysis and
    run_deser (never existed at all), run_mass_assignment (no executor, Q-011). Each silently pinned its
    objective to "not_tested" even on a mission that ran every engine in the product.
    """
    reachable = _dispatch_reachable()
    phantom = sorted({n for o in A.OBJECTIVES for n in A._engine_names(o)
                      if n != A.NO_ENGINE and n not in reachable})
    assert phantom == [], (
        "OBJECTIVES name engines no dispatcher can reach (claimed capability that cannot run): %s" % phantom)


def test_no_engine_sentinel_is_only_used_where_a_reason_is_declared():
    """NO_ENGINE must never become a quiet parking spot for a broken name. An objective with no engine has
    to say WHY — safety-excluded (blocked) or capability-absent (not_implemented) — and must not mix the
    sentinel with a real engine, which would let a reader think something ran."""
    for o in A.OBJECTIVES:
        names = A._engine_names(o)
        if A.NO_ENGINE in names:
            assert names == (A.NO_ENGINE,), "%s mixes NO_ENGINE with a real engine: %s" % (o["cid"], names)
            assert o.get("blocked_reason") or o.get("not_implemented_reason"), \
                "%s has no engine and no reason — indistinguishable from an untested objective" % o["cid"]
        else:
            assert not o.get("not_implemented_reason"), \
                "%s claims not-implemented while naming a real engine" % o["cid"]


def test_curated_objectives_tally_and_shape():
    r = A.assess()
    assert r["total_objectives"] == len(A.OBJECTIVES)
    assert sum(r["tally"].values()) == r["total_objectives"]
    assert r["model_type"] == "curated_partial"
    # every objective row carries curated provenance and a local (non-authoritative) cid
    for row in r["objectives"]:
        assert row["provenance"] == "curated"
        assert row["standard"] == "OWASP_ASVS" and row["version"] == "5.0-curated-partial"
        assert not re.match(r"^V\d", row["cid"])         # not a spoofed official clause number (V6.2.1)


def test_findings_map_to_violated_requirements():
    findings = [{"id": "F1", "family": "sqli"}, {"id": "F2", "family": "idor"}]
    m = A.map_findings(findings)
    assert m["VAL-01"] == ["F1"] and m["ATHZ-01"] == ["F2"]
    r = A.assess(findings)
    val01 = next(o for o in r["objectives"] if o["cid"] == "VAL-01")
    athz01 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-01")
    assert val01["status"] == "failed" and val01["finding_ids"] == ["F1"]
    assert athz01["status"] == "failed" and athz01["finding_ids"] == ["F2"]


def test_clean_attempted_check_marks_verified():
    # SQLi engine ran, no sqli finding -> the SQLi objective is VERIFIED (negative-control discipline)
    r = A.assess([], attempted_engines={"run_sqli"})
    val01 = next(o for o in r["objectives"] if o["cid"] == "VAL-01")
    assert val01["status"] == "verified"
    assert r["tally"]["verified"] >= 1


def test_finding_beats_clean_run():
    # engine ran but a violating finding exists -> failed wins over verified
    r = A.assess([{"id": "F9", "family": "sqli"}], attempted_engines={"run_sqli"})
    val01 = next(o for o in r["objectives"] if o["cid"] == "VAL-01")
    assert val01["status"] == "failed"


def test_blocked_objectives_are_never_verified():
    # lockout + MFA are safety-excluded: blocked no matter what engines "ran"
    r = A.assess([], attempted_engines={"run_default_creds", "n/a"})
    blocked = [o for o in r["objectives"] if o["status"] == "blocked"]
    assert {o["cid"] for o in blocked} >= {"AUTHN-05", "AUTHN-06"}
    for o in blocked:
        assert o["status"] != "verified" and o.get("blocked_reason")


def test_attempt_only_objectives_never_auto_verify():
    # business-logic reasoning ran, but it is inconclusive-by-nature -> "attempted", not "verified".
    # Q-012: was driven by "bizlogic_graph", a MODULE name that can never appear in a real ledger, so this
    # asserted behaviour for an input the product cannot produce. Now driven by the real engines.
    r = A.assess([], attempted_engines={"run_workflow", "test_numeric_abuse", "run_race"})
    busl = [o for o in r["objectives"] if o["cid"] in ("BUSL-01", "BUSL-02")]
    assert all(o["status"] == "attempted" for o in busl)


def test_real_emitted_families_fail_their_objective_even_when_engine_ran():
    # Regression: Apolaki's real dominant families (access_control, backup_exposure) must FAIL their
    # objective, never read "verified" just because the authz/exposure engine ran clean of narrower families.
    findings = [{"id": "A", "family": "access_control"}, {"id": "B", "family": "backup_exposure"}]
    ran = {"run_bfla", "confirm_idor", "run_authz_matrix", "run_exposure", "run_dir_harvest"}
    r = A.assess(findings, attempted_engines=ran)
    athz0 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-00")
    comm3 = next(o for o in r["objectives"] if o["cid"] == "COMM-03")
    assert athz0["status"] == "failed" and athz0["finding_ids"] == ["A"]
    assert comm3["status"] == "failed" and comm3["finding_ids"] == ["B"]


def test_umbrella_access_control_fails_when_any_child_violation_exists():
    # #11 regression: ATHZ-00 is the UMBRELLA "no broken access control" property. A confirmed idor/bola/
    # bfla/privilege_escalation/mass_assignment must FAIL it too — it can never read "verified" while a
    # specific access-control child is failed (that self-contradiction was the bug).
    # Q-012: `run_mass_assignment` used to sit in this `ran` set — a name that can NEVER appear in a real
    # ledger, because no such executor exists (Q-011). Asserting behaviour for an impossible input is the
    # guard-that-checks-a-declaration pattern; the set now contains only names a real dispatcher emits.
    # ATHZ-04 is not_implemented, and the mass_assignment case below proves a finding still FAILS it.
    ran = {"run_bfla", "confirm_idor", "run_authz_matrix"}
    for fam, child_cid in (("idor", "ATHZ-01"), ("bola", "ATHZ-01"), ("bfla", "ATHZ-02"),
                           ("privilege_escalation", "ATHZ-02"), ("mass_assignment", "ATHZ-04")):
        r = A.assess([{"id": "X", "family": fam}], attempted_engines=ran)
        athz0 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-00")
        child = next(o for o in r["objectives"] if o["cid"] == child_cid)
        assert athz0["status"] == "failed", "ATHZ-00 must fail for child family %s" % fam
        assert child["status"] == "failed"


def test_untested_is_not_verified():
    r = A.assess()          # nothing ran
    assert r["tally"]["verified"] == 0
    assert r["tally"]["not_tested"] > 0


def test_a_perfect_run_leaves_nothing_merely_not_tested():
    """THE Q-012 regression, stated as an outcome rather than a name check.

    Drive assess() with every engine a real dispatcher can reach — the best a mission could possibly do —
    and nothing may come back "not_tested". Before the fix this returned 3 (AUTHN-04, ATHZ-04, BUSL-01):
    objectives that read "we did not get to it" when the truth was "no engine we have could ever get to it".
    A phantom re-entering OBJECTIVES fails this immediately.
    """
    r = A.assess([], attempted_engines=_dispatch_reachable())
    left = sorted(o["cid"] for o in r["objectives"] if o["status"] == "not_tested")
    assert left == [], "a perfect run still reports these as merely-untested: %s" % left
    assert r["tally"]["not_tested"] == 0


def test_absent_capability_reports_not_implemented_with_a_reason():
    """A capability the product does not have must be distinguishable from one it merely skipped."""
    r = A.assess([], attempted_engines=_dispatch_reachable())
    ni = [o for o in r["objectives"] if o["status"] == "not_implemented"]
    # Q-048 swapped the membership of this set, in both directions, and the count is a coincidence:
    #   ATHZ-04 LEFT  — Q-011 shipped `run_mass_assign`, so the capability now exists.
    #   COMM-04 JOINED — check_takeover yields recon candidates that carry no family and never become
    #                    findings, so a takeover cannot be recorded as a violation.
    assert {o["cid"] for o in ni} == {"AUTHN-04", "COMM-04"}
    for o in ni:
        assert o.get("not_implemented_reason"), "%s is not_implemented with no stated reason" % o["cid"]
        assert o["engine"] == A.NO_ENGINE
    assert r["tally"]["not_implemented"] == 2
    # and it is never quietly counted as a pass
    assert "not_implemented" in A.STATUSES and r["tally"]["verified"] == 27


def test_not_implemented_survives_every_engine_claiming_to_have_run():
    """Absence of capability is a property of the PRODUCT, not of the mission: no set of "engines that ran",
    however dishonest or over-broad, can flip a not-implemented objective to verified."""
    liar = _dispatch_reachable() | {n for o in A.OBJECTIVES for n in A._engine_names(o)} | {A.NO_ENGINE}
    r = A.assess([], attempted_engines=liar)
    for cid in ("AUTHN-04", "COMM-04"):          # Q-048: ATHZ-04 gained a real engine, COMM-04 lost one
        o = next(x for x in r["objectives"] if x["cid"] == cid)
        assert o["status"] == "not_implemented", "%s flipped to %s" % (cid, o["status"])


def test_a_finding_still_fails_a_not_implemented_objective():
    """Negative control on the precedence order: a violation someone else proved must never be hidden
    behind "we have no engine" — failed outranks not_implemented.

    Q-048: ATHZ-04 is no longer the not_implemented example (Q-011 shipped `run_mass_assign`), so the
    precedence half of this test now rides on COMM-04, which IS not_implemented — nothing in the product
    can record a subdomain takeover as a finding, but an imported/human-supplied one must still fail it.
    The mass_assignment case is kept because it still proves the umbrella rule below."""
    r = A.assess([{"id": "M1", "family": "mass_assignment"}], attempted_engines=set())
    athz4 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-04")
    assert athz4["status"] == "failed" and athz4["finding_ids"] == ["M1"]
    # the actual not_implemented -> failed precedence, on an objective that really is not_implemented
    t = A.assess([{"id": "T1", "family": "takeover"}], attempted_engines=set())
    comm4 = next(o for o in t["objectives"] if o["cid"] == "COMM-04")
    assert comm4["status"] == "failed" and comm4["finding_ids"] == ["T1"]
    # ...and the umbrella access-control objective fails with it
    athz0 = next(o for o in r["objectives"] if o["cid"] == "ATHZ-00")
    assert athz0["status"] == "failed"


def test_authz_matrix_objectives_verify_from_the_REAL_ledger_name():
    """The naming-boundary bug, pinned to the name a real mission actually records.

    `_run_authz_matrix` returns ToolResult("authz_matrix", ...), but BOTH tool_call emitters
    (agent.py:551 and agent.py:634) log the REQUESTED name, so a real ledger carries
    "run_authz_matrix" and never the bare label. The model matched the label, so ATHZ-00 read
    not_tested on a mission where the authz matrix genuinely ran. Measured in docs/handoff/asvs.md.

    Q-048 dropped AUTHN-02 from this test, and NOT to make it pass: run_authz_matrix emits `idor` and
    `excessive_data_exposure`, which are AUTHORIZATION failures, so it could never fail "authentication
    cannot be bypassed" and had no business verifying it. The property under test here is the ledger
    NAMING boundary, and ATHZ-00 exercises both halves of it exactly as before.
    """
    r = A.assess([], attempted_engines={"run_authz_matrix"})
    o = next(x for x in r["objectives"] if x["cid"] == "ATHZ-00")
    assert o["status"] == "verified", "ATHZ-00 did not verify from the real ledger name"
    # the bare ToolResult LABEL is not a ledger key and must verify nothing
    stale = A.assess([], attempted_engines={"authz_matrix"})
    o = next(x for x in stale["objectives"] if x["cid"] == "ATHZ-00")
    assert o["status"] == "not_tested", "ATHZ-00 verified from a name no ledger records"


def test_report_never_claims_full_asvs_coverage():
    all_engines = {n for o in A.OBJECTIVES for n in A._engine_names(o)}
    r = A.assess([], attempted_engines=all_engines)
    assert r["model_type"] == "curated_partial"
    assert "not" in r["disclaimer"].lower() and "full asvs" in r["disclaimer"].lower()
    # even with every engine "run", verified can never reach 100% because some objectives are blocked
    assert r["verified_pct"] < 100.0


# ── Q-048: an objective must be capable of FAILING ────────────────────────────────────────────────

def test_the_producer_map_is_not_vacuous():
    """Guard the guard. If this map came back empty, or attributed every family to every engine, the
    ratchet below would pass for free — the exact failure shape this ticket exists to stop.

    The last three assertions pin the two analyser defects that made the map UNDER-report while I was
    building it, because under-reporting invents never-fail objectives that are actually fine:
      * a family chosen by a TERNARY (transport_posture.py:397) read as 0 families,
      * a family passed POSITIONALLY into a callee's `family` parameter (dom_tool `_base`) read as 0
        families for run_dom_audit — which briefly made me report VAL-08 as unfailable. It is not.
    """
    prod = _family_producers()
    assert len(prod) > 50, "producer map is empty/tiny — every producibility assertion would be vacuous"
    everything = set().union(*prod.values())
    assert len(everything) > 50
    # discriminating, not a firehose: the SQLi engine emits sqli and does NOT emit unrelated classes
    assert "sqli" in prod["run_sqli"]
    assert not ({"xxe", "oauth", "race"} & prod["run_sqli"])
    # ...and no single engine is credited with the whole vocabulary
    assert max(len(v) for v in prod.values()) < len(everything) / 2
    assert "security_misconfig" in prod["run_transport_posture"]        # ternary family
    assert "prototype_pollution" in prod["run_dom_audit"]               # positional `family` argument
    assert {"csti", "xss"} <= prod["run_dom_audit"]


def test_every_engine_can_fail_the_objective_it_verifies():
    """THE Q-048 ratchet, and the reason it is stated PER ENGINE rather than per objective.

    `_engine_ran` is `any(...)`: a single named engine running is enough to stamp an objective
    "verified". So an engine that cannot emit ANY family in that objective's `violated_by` is a
    false-verify path in its own right, even when a sibling engine in the same tuple is fine — a
    mission that happened to run only the dead one would report a property nothing tested.

    Adding an objective whose violating family no producer can emit fails here immediately.
    """
    prod = _family_producers()
    dead = []
    for o in A.OBJECTIVES:
        names = A._engine_names(o)
        if names == (A.NO_ENGINE,):
            continue                      # covered by the NO_ENGINE/reason guard above
        violated = set(o["violated_by"])
        for n in names:
            if not (prod.get(n, set()) & violated):
                dead.append("%s/%s (engine emits %s; objective fails on %s)"
                            % (o["cid"], n, sorted(prod.get(n, set())) or "nothing", sorted(violated)))
    assert dead == [], (
        "these engines can never emit a family that FAILS the objective they are trusted to verify, so a "
        "clean run of them is not evidence of anything:\n  " + "\n  ".join(dead))


def test_no_objective_is_structurally_incapable_of_failing():
    """The headline property, stated as an outcome. Every objective that can reach "verified" must have
    at least one engine able to produce a finding that contradicts it. Six could not when Q-048 opened
    (AUTHN-01/02/03, SESS-01, SESS-02, COMM-04) — all six read "verified" on a perfect run."""
    prod = _family_producers()
    unfailable = sorted(o["cid"] for o in A.OBJECTIVES
                        if A._engine_names(o) != (A.NO_ENGINE,)
                        and not any(prod.get(n, set()) & set(o["violated_by"])
                                    for n in A._engine_names(o)))
    assert unfailable == [], (
        "these objectives can reach 'verified' but nothing in the product could ever contradict "
        "them: %s" % unfailable)


def test_a_not_implemented_objective_still_names_a_family_someone_could_emit():
    """NO_ENGINE objectives are exempt from the ratchet (nothing runs, so nothing false-verifies), but a
    `violated_by` naming a family with NO producer anywhere is dead weight that can never fire either.
    Recorded rather than asserted-away: AUTHN-04's `cleartext_transport` is deliberately such a family,
    and the honest reading is that the objective is unassessable, which is what it already says."""
    prod = _family_producers()
    anywhere = set().union(*prod.values())
    for o in A.OBJECTIVES:
        if A._engine_names(o) != (A.NO_ENGINE,) or not o["violated_by"]:
            continue
        if not (set(o["violated_by"]) & anywhere):
            assert o.get("not_implemented_reason"), (
                "%s can neither be verified nor failed and gives no reason" % o["cid"])
