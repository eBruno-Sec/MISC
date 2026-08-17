"""Q-056 — a gate for the DECLARATION-vs-FACT defect family, applied to engine DESCRIPTIONS.

THE DEFECT CLASS. Four audited engines carried a description their code did not support:
`run_ferox` advertised *"Recursive content discovery"* and passed `--no-recursion`; `run_metadata`
advertises EXIF extraction its only JPEG branch cannot perform; `_run_workflow`'s docstring claimed
findings it discarded; `run_external_surface` describes itself PASSIVE and is registered ACTIVE.

WHY THE EXISTING GATES ARE ALL BLIND TO IT. `test_engine_reachability` and `test_deadcode_gate` ask
whether an engine is present, registered, implemented and reachable. Every one of the four is all
four things. The gap is between what an engine SAYS and what it DOES, and no structural gate in this
codebase looked at the text of a claim at all.

WHAT THIS MODULE DOES *NOT* DO. It does not try to check natural language against behaviour in
general — that is not gateable, and a noisy gate gets silenced, which is worse than none (see
docs/handoff/descriptions.md for the rules that were measured and REJECTED, with their false-positive
counts). It implements exactly two narrow, high-precision rules where the claim and the fact are both
machine-readable and sit in the same file:

  RULE A — NEGATED CAPABILITY. An engine that passes a literal `--no-X` / `--disable-X` / `--skip-X`
  / `--without-X` command-line flag must not advertise X. This is the ferox shape: the word
  "Recursive" in a spec description beside the literal string `--no-recursion` in the implementation.
  The negated token is derived from the flag itself — there is no hardcoded antonym table.

  RULE B — UNDECLARED PERMISSION TIER. Every engine's leading declaration phrase must name, as a bare
  token, the PermissionLevel it is registered under. This is the external_surface shape: a docstring
  opening `PASSIVE/ACTIVE-light ...` on an engine registered ACTIVE. `ACTIVE-light` is deliberately
  NOT accepted as a declaration of ACTIVE — a hyphen-qualified tier is a hedge that reads *softer*
  than the tier it names, and reading softer than you are registered is the whole defect. Compound
  honest declarations (`ACTIVE/INTRUSIVE:`, `ACTIVE, INTRUSIVE (opt-in):`) pass, because the
  registered tier IS named as a bare token in them.

Both rules are pure static analysis over one source file's AST, so they run in-process with no
target, no binary and no network. `audit()` takes SOURCE TEXT, never a path, so a caller can pin a
regression fixture to the exact source it was measured against instead of to whatever the tree says
when the test happens to run.
"""
from __future__ import annotations

import ast
import re
from typing import Dict, List, NamedTuple, Optional

# ── the three permission tiers, as they appear in prose ──────────────────────
TIERS = ("PASSIVE", "ACTIVE", "INTRUSIVE")

# A BARE tier token. `(?![-\w])` is the load-bearing part: it rejects `ACTIVE-light`, which names the
# tier only to soften it. `\b` alone would accept it, and accepting it would miss the one live
# instance this rule exists to catch.
_TIER_TOKEN = re.compile(r"\b(PASSIVE|ACTIVE|INTRUSIVE)(?![-\w])")

# The leading declaration phrase: everything up to the first colon, when that colon is close enough
# to the start to be a declaration rather than ordinary punctuation deep in the prose.
_DECL_MAX = 160

# A negating command-line flag. One or two leading dashes (this tree passes both: `--no-sandbox`,
# `-no-interactsh`), a negating prefix, an optional separator, then the negated capability token.
_NEGATING_FLAG = re.compile(r"^--?(?:no|non|without|disable|skip)[-_]?(.+)$", re.IGNORECASE)

# The negated token is stemmed before it is looked for in the claim text, because English inflects:
# `--no-recursion` must match the word "Recursive". Six characters is enough for `recurs` to reach
# both, and short enough that a longer flag word cannot miss its own adjective.
_STEM_LEN = 6
_STEM_MIN = 3


class Violation(NamedTuple):
    """One contradiction between what an engine declares and what its code does."""
    rule: str          # "negated_capability" | "undeclared_tier"
    engine: str        # tool name as registered, e.g. "run_ferox"
    detail: str        # the evidence, quoted, so a human can adjudicate without opening the file

    def __str__(self) -> str:
        return f"[{self.rule}] {self.engine}: {self.detail}"


class Facts(NamedTuple):
    """What the source FILE says about each engine, separated from any judgement of it."""
    descriptions: Dict[str, str]   # tool name -> CLAUDE_TOOLS description (spec'd engines only)
    permissions: Dict[str, str]    # tool name -> PermissionLevel attribute name
    docstrings: Dict[str, str]     # tool name -> `_<name>` implementation docstring
    literals: Dict[str, List[str]] # tool name -> every literal str constant in `_<name>`'s body


# ── extraction ───────────────────────────────────────────────────────────────
def _literal_str(node: Optional[ast.AST]) -> str:
    """Best-effort literal string from a Constant, an implicit concatenation, or a folded BinOp.

    Falls back to joining every string Constant in the subtree rather than returning "", because an
    empty claim silently passes every rule — the falsy-default failure this codebase has been bitten
    by three times. A joined approximation can only ever make a rule fire MORE.
    """
    if node is None:
        return ""
    try:
        value = ast.literal_eval(node)
        if isinstance(value, str):
            return value
    except Exception:
        pass
    return " ".join(n.value for n in ast.walk(node)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str))


def analyse(source: str, registry_class: str = "ToolRegistry") -> Facts:
    """Read one module's tool declarations and implementations out of its AST."""
    tree = ast.parse(source)
    descriptions: Dict[str, str] = {}
    permissions: Dict[str, str] = {}
    methods: Dict[str, ast.AST] = {}

    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "CLAUDE_TOOLS":
            for element in getattr(node.value, "elts", []):
                if not isinstance(element, ast.Dict):
                    continue
                spec = {k.value: v for k, v in zip(element.keys, element.values)
                        if isinstance(k, ast.Constant)}
                name = _literal_str(spec.get("name"))
                if name:
                    descriptions[name] = _literal_str(spec.get("description"))
        elif isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "TOOL_PERMISSIONS":
            for key, value in zip(node.value.keys, node.value.values):
                if isinstance(key, ast.Constant) and isinstance(value, ast.Attribute):
                    permissions[key.value] = value.attr
        elif isinstance(node, ast.ClassDef) and node.name == registry_class:
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods[member.name] = member

    docstrings, literals = {}, {}
    for name in set(descriptions) | set(permissions):
        fn = methods.get("_" + name)
        if fn is None:
            continue
        docstrings[name] = ast.get_docstring(fn) or ""
        literals[name] = [n.value for n in ast.walk(fn)
                          if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    return Facts(descriptions, permissions, docstrings, literals)


# ── RULE A: negated capability ───────────────────────────────────────────────
def _stem(token: str) -> str:
    return re.sub(r"[^a-z]", "", token.lower())[:_STEM_LEN]


def check_negated_capability(facts: Facts) -> List[Violation]:
    """An engine must not advertise a capability its own command line switches off.

    Every literal argument in the implementation that reads as a negating flag has its negated token
    stemmed and looked for in the engine's own claim text (spec description + implementation
    docstring). `--no-recursion` on an engine selling "Recursive content discovery" is the whole rule.
    """
    out: List[Violation] = []
    for engine in sorted(facts.literals):
        claim = (facts.descriptions.get(engine, "") + " " + facts.docstrings.get(engine, "")).lower()
        if not claim.strip():
            continue
        for literal in facts.literals[engine]:
            match = _NEGATING_FLAG.match(literal.strip())
            if not match:
                continue
            stem = _stem(match.group(1))
            if len(stem) < _STEM_MIN:
                continue                       # `--nonce` is not a negation of "ce"
            claimed = re.search(r"\b" + re.escape(stem), claim)
            if not claimed:
                continue
            window = claim[max(0, claimed.start() - 40):claimed.end() + 40].replace("\n", " ")
            out.append(Violation(
                "negated_capability", engine,
                f"passes {literal!r} while its description claims '{stem}...' — ...{window.strip()}..."))
    return out


# ── RULE B: undeclared permission tier ───────────────────────────────────────
def declaration_phrase(text: str) -> str:
    """The leading tier declaration, by this file's own convention: `TIER: what it does`."""
    head = text[:_DECL_MAX]
    colon = head.find(":")
    return head[:colon + 1] if colon != -1 else head


def declared_tiers(text: str) -> List[str]:
    """The tiers named as BARE tokens in a declaration phrase. `ACTIVE-light` names none."""
    return [m.group(1) for m in _TIER_TOKEN.finditer(declaration_phrase(text))]


def check_undeclared_tier(facts: Facts) -> List[Violation]:
    """The tier an engine is REGISTERED under must be named in the tier it DECLARES.

    Checked against both surfaces an engine speaks through — its CLAUDE_TOOLS description (what the
    model is told) and its implementation docstring (what the next engineer is told). Either one
    naming a tier set that excludes the registered level is a contradiction between two declarations
    in the same file, which is why this rule needs no runtime and produces no judgement calls.

    An engine that declares NO tier at all is not flagged here: silence is a documentation gap, not a
    contradiction, and conflating the two is how a gate acquires the noise that gets it silenced.
    """
    out: List[Violation] = []
    for engine in sorted(facts.permissions):
        registered = facts.permissions[engine]
        if registered not in TIERS:
            continue
        for surface, text in (("spec description", facts.descriptions.get(engine, "")),
                              ("docstring", facts.docstrings.get(engine, ""))):
            declared = declared_tiers(text)
            if declared and registered not in declared:
                out.append(Violation(
                    "undeclared_tier", engine,
                    f"registered {registered} but its {surface} declares "
                    f"{'/'.join(declared)} — {declaration_phrase(text).strip()!r}"))
    return out


# ── the gate ─────────────────────────────────────────────────────────────────
RULES = (check_negated_capability, check_undeclared_tier)


def audit(source: str, registry_class: str = "ToolRegistry") -> List[Violation]:
    """Every description-vs-code contradiction this module can prove, from SOURCE TEXT."""
    facts = analyse(source, registry_class)
    return [v for rule in RULES for v in rule(facts)]
