"""Q-058 follow-on — an engine must not advertise a parameter its code never reads.

WHERE THIS RULE COMES FROM. It is the gate for Q-058 item 3, generalised. `run_hash_crack` declared
`hash_type` in its `input_schema`, described to the model as *"optional; auto-identified if omitted"*,
and the token appeared EXACTLY ONCE in all 10,052 lines of `agent/tools.py` — on that schema line. A
model reading the schema would supply the parameter; nothing would happen; the crack would run at the
top auto-identified mode and report "Not cracked" rather than "wrong mode".

WHY IT LIVES HERE AND NOT IN `description_gate.py`. An earlier lane measured this rule (as "rule E")
and REJECTED it at an ~86% engine-level false-positive rate: 7 engines flagged, 6 of them false. The
false six consume their parameters INDIRECTLY — `_store_finding` forwards the whole dict
(`db.add_finding(self.mission_id, dict(inp))`), and the session/headers families resolve through
`self._identity(...)` / `self._role_headers(inp, "owner")`, which take `inp` rather than a named key.
A rule with that noise profile gets silenced, and a silenced gate is worse than none.

WHAT CHANGED. Subtract the indirect consumers instead of trying to trace them: if an implementation
hands `inp` (or any expression containing it) to another call, this rule ABSTAINS on that engine
entirely. It cannot then see a genuinely-unread parameter on those six, and that is the honest price.
On everything else it compares a declared name against every name, string, attribute and keyword in
the implementation, which is a comparison rather than an interpretation.

MEASURED, both sides, same apparatus, 72 engines / 188 properties read each time:
  * pre-fix (`b3bef1c`): 1 flagged — `run_hash_crack: hash_type`. The one true positive, alone.
  * post-fix (this tree): 0 flagged, 6 abstained.
So the refinement is 0 false positives here, against rule E's 6.
"""
import ast
import pathlib


# ── extraction ───────────────────────────────────────────────────────────────

def _schema_properties(tree):
    """{engine: [declared property names]} from CLAUDE_TOOLS' input_schema."""
    out = {}
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "CLAUDE_TOOLS"):
            continue
        for element in getattr(node.value, "elts", []):
            if not isinstance(element, ast.Dict):
                continue
            spec = {k.value: v for k, v in zip(element.keys, element.values)
                    if isinstance(k, ast.Constant)}
            name_node = spec.get("name")
            if not (isinstance(name_node, ast.Constant) and isinstance(name_node.value, str)):
                continue
            props = []
            schema = spec.get("input_schema")
            if isinstance(schema, ast.Dict):
                for k, v in zip(schema.keys, schema.values):
                    if isinstance(k, ast.Constant) and k.value == "properties" and isinstance(v, ast.Dict):
                        props = [kk.value for kk in v.keys
                                 if isinstance(kk, ast.Constant) and isinstance(kk.value, str)]
            out[name_node.value] = props
    return out


def _methods(tree, registry_class="ToolRegistry"):
    return {m.name: m for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == registry_class
            for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _mentions(fn):
    """Every name an implementation could be reading a parameter through."""
    seen = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            seen.add(n.value)
        elif isinstance(n, ast.Name):
            seen.add(n.id)
        elif isinstance(n, ast.Attribute):
            seen.add(n.attr)
        elif isinstance(n, ast.keyword) and n.arg:
            seen.add(n.arg)
    return seen


def _hands_off_inp(fn):
    """True when the whole input dict is passed to another call, so a parameter may be consumed out
    of sight. This is the exemption that takes rule E from 6 false positives to 0."""
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        for arg in list(n.args) + [k.value for k in n.keywords]:
            if isinstance(arg, ast.Name) and arg.id == "inp":
                return True
            if isinstance(arg, ast.Call) and any(isinstance(x, ast.Name) and x.id == "inp"
                                                 for x in ast.walk(arg)):
                return True
    return False


def audit_unread_parameters(source):
    """(flagged, abstained, engines_read, properties_read). Flagged is the defect."""
    tree = ast.parse(source)
    methods, flagged, abstained = _methods(tree), {}, {}
    engines = properties = 0
    for engine, props in sorted(_schema_properties(tree).items()):
        fn = methods.get("_" + engine)
        if fn is None or not props:
            continue
        engines += 1
        properties += len(props)
        unread = [p for p in props if p not in _mentions(fn)]
        if not unread:
            continue
        (abstained if _hands_off_inp(fn) else flagged)[engine] = unread
    return flagged, abstained, engines, properties


# ── the fixture, verbatim from the commit where the defect lived ─────────────

# `git show b3bef1c:apolaki/agent/tools.py`, lines 233 and 958-966 plus the head of the
# implementation, unedited. b3bef1c is the parent of the commit that fixed this. Pinned here rather
# than described, so the MUST-FIRE case cannot drift with the tree — and NOT invented: three invented
# fixtures produced three vacuous tests in this project in one session.
_PRE_FIX_HASH_CRACK = '''
TOOL_PERMISSIONS = {
    "run_hash_crack": PermissionLevel.INTRUSIVE,   # OFFLINE dictionary crack of a supplied hash (never live auth)
}

CLAUDE_TOOLS = [
    {"name": "run_hash_crack",
     "description": ("INTRUSIVE (offline): Attempt an OFFLINE dictionary crack of a SUPPLIED hash against a local "
                     "wordlist using hashcat or John (whichever is installed; skips gracefully if neither)."),
     "input_schema": {"type": "object", "properties": {
         "hash": {"type": "string"}, "hash_type": {"type": "string", "description": "optional; auto-identified if omitted"},
         "wordlist": {"type": "string", "description": "catalog id or absolute path; defaults to the common-passwords list"}},
         "required": ["hash"]}},
]


class ToolRegistry:
    async def _run_hash_crack(self, inp: dict) -> ToolResult:
        h = (inp.get("hash") or "").strip()
        cands = hid.identify(h)
        wlspec = inp.get("wordlist") or "passwords-common"
        return ToolResult("hash_crack", "", True, "", [])
'''


def _tools_source():
    return (pathlib.Path(__file__).resolve().parent.parent / "tools.py").read_text(encoding="utf-8")


# ── MUST-FIRE ────────────────────────────────────────────────────────────────

def test_the_rule_fires_on_the_real_pre_fix_hash_crack():
    flagged, abstained, engines, props = audit_unread_parameters(_PRE_FIX_HASH_CRACK)
    assert engines == 1 and props == 3, (engines, props)     # the apparatus read the fixture
    assert flagged == {"run_hash_crack": ["hash_type"]}, flagged
    assert abstained == {}, abstained


def test_the_rule_goes_quiet_once_the_parameter_is_actually_read():
    """The defect is the SILENCE, not the declaration. One line naming the parameter clears it."""
    fixed = _PRE_FIX_HASH_CRACK.replace(
        "        cands = hid.identify(h)",
        "        cands = hid.identify(h)\n        want = inp.get(\"hash_type\")")
    assert 'inp.get("hash_type")' in fixed, "mutation did not apply"
    flagged, _, _, _ = audit_unread_parameters(fixed)
    assert flagged == {}, flagged


def test_the_rule_abstains_when_the_whole_input_is_handed_on():
    """NEGATIVE CONTROL, and the reason rule E was rejected. `db.add_finding(mission, dict(inp))`
    consumes every key without naming one. Flagging that shape produced 6 false positives out of 7
    engines; abstaining is what makes the rule shippable."""
    indirect = _PRE_FIX_HASH_CRACK.replace(
        '        return ToolResult("hash_crack", "", True, "", [])',
        '        db.add_finding(self.mission_id, dict(inp))\n'
        '        return ToolResult("hash_crack", "", True, "", [])')
    assert "dict(inp)" in indirect, "mutation did not apply"
    flagged, abstained, _, _ = audit_unread_parameters(indirect)
    assert flagged == {}, flagged
    assert abstained == {"run_hash_crack": ["hash_type"]}, abstained


# ── THE GATE, against the live tree ──────────────────────────────────────────

# The engines this rule ABSTAINS on, recorded rather than hidden. Each hands `inp` to a helper that
# resolves keys by name out of sight (`self._identity(inp)`, `self._role_headers(inp, "owner")`,
# `db.add_finding(self.mission_id, dict(inp))`). If one stops doing that, it starts being checked,
# which is the correct direction: the abstention is a property of the CODE, not a permission.
KNOWN_INDIRECT = {
    "confirm_idor", "enumerate_ids", "http_read", "http_request", "store_finding",
    "test_numeric_abuse",
}


def test_no_engine_advertises_a_parameter_it_never_reads():
    flagged, abstained, engines, properties = audit_unread_parameters(_tools_source())
    # POSITIVE CONTROL. A rule that parsed nothing would report the same zero.
    assert engines > 60, engines
    assert properties > 150, properties
    assert flagged == {}, (
        "engine(s) advertising a parameter the implementation never reads. The schema is a claim "
        "under test: either honour the parameter or drop the property — do NOT reword the "
        "description to hide it:\n  "
        + "\n  ".join("%s: %s" % (e, " ".join(p)) for e, p in sorted(flagged.items())))
    assert set(abstained) == KNOWN_INDIRECT, sorted(abstained)
