"""Q-056 — the gate for the description-vs-code defect family, tested against the REAL defects.

A guard that checks a declaration is not a guard. Every rule in `description_gate` is exercised here
against source COPIED VERBATIM from the commits where the defect actually lived, and each one is
paired with a NEGATIVE CONTROL taken from an engine in the same tree whose description and code
agree. Three invented fixtures produced three vacuous tests in this project in one session; none of
the source below is invented.

PROVENANCE OF EVERY FIXTURE
  * `_FEROX_SOURCE`         — `git show 466bae8^:agent/tools.py`. `run_ferox` was DELETED in 466bae8
                              along with `run_dirsearch`, `run_gobuster` and `_bin_discovery`, so this
                              file is now the only place the evidence lives. Historical, not live.
  * `_CHROME_FLAGS_SOURCE`  — `run_dom_audit` at ece2dbd, the negative control for rule A: it passes
                              `--no-sandbox` and `--disable-gpu` and advertises neither.
  * `_EXTERNAL_SURFACE_SOURCE` / `_CREATE_OBJECT_IDOR_SOURCE` — the two live rule-B instances at
                              ece2dbd, pinned here because the lane that owns `tools.py` is fixing
                              descriptions right now and a fixture must not move under its test.
  * `_HONEST_COMPOUND_SOURCE` — `run_nuclei` and `confirm_authz_write` at ece2dbd: both name two
                              tiers in one declaration, and both are honest. They are the false
                              positives rule B has to NOT produce.
"""
import pathlib

import pytest

import description_gate as dg


# ── fixtures, verbatim ───────────────────────────────────────────────────────

# `git show 466bae8^:agent/tools.py` — spec, permission entry and implementation, unedited.
_FEROX_SOURCE = '''
TOOL_PERMISSIONS = {
    "run_ferox": PermissionLevel.INTRUSIVE,        # optional feroxbuster adapter
}

CLAUDE_TOOLS = [
    {"name": "run_ferox",
     "description": "INTRUSIVE: Recursive content discovery via feroxbuster (optional; skips gracefully if unavailable). Native content_discovery + ffuf remain the default.",
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "wordlist": {"type": "string"}}, "required": ["url"]}},
]


class ToolRegistry:
    async def _run_ferox(self, inp: dict) -> ToolResult:
        url = (inp.get("url") or "").strip()
        wl = inp.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        return await self._bin_discovery("ferox", ["feroxbuster", "-u", url, "-w", wl,
                                                   "--silent", "--no-recursion", "-k"], url)
'''

# `run_dom_audit` at ece2dbd. Passes the same shape of negating flag as ferox, claims nothing it
# switches off. If rule A cannot tell these two apart it is not a rule, it is a grep for "--no-".
_CHROME_FLAGS_SOURCE = '''
TOOL_PERMISSIONS = {
    "run_dom_audit": PermissionLevel.ACTIVE,
}

CLAUDE_TOOLS = [
    {"name": "run_dom_audit",
     "description": "ACTIVE: Headless-browser DOM audit of a rendered page.",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
]


class ToolRegistry:
    async def _run_dom_audit(self, inp: dict) -> ToolResult:
        args = ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
        return await self._chrome(args, inp)
'''

# `run_external_surface` at ece2dbd — docstring opens PASSIVE, registry says ACTIVE.
_EXTERNAL_SURFACE_SOURCE = '''
TOOL_PERMISSIONS = {
    "run_external_surface": PermissionLevel.ACTIVE,            # ASN/favicon/permutation/CT candidates (#114)
}

CLAUDE_TOOLS = [
    {"name": "run_external_surface",
     "description": "ACTIVE: External attack-surface expansion for a host.",
     "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
]


class ToolRegistry:
    async def _run_external_surface(self, inp: dict) -> ToolResult:
        """PASSIVE/ACTIVE-light external attack-surface expansion (#114): ASN + BGP prefix, favicon pivot
        hash, permuted subdomain candidates, and a certificate-transparency harvest."""
        return ToolResult("external_surface", "", True, "", [])
'''

# `confirm_create_object_idor` at ece2dbd — spec AND registry say INTRUSIVE, docstring says ACTIVE.
_CREATE_OBJECT_IDOR_SOURCE = '''
TOOL_PERMISSIONS = {
    "confirm_create_object_idor": PermissionLevel.INTRUSIVE,   # creates+deletes an owned object (bounded, cleaned up)
}

CLAUDE_TOOLS = [
    {"name": "confirm_create_object_idor",
     "description": ("INTRUSIVE (bounded + self-cleaning): CONFIRM an IDOR/BOLA by definitive ownership — "
                     "create a uniquely-owned object as the owner persona, then read (Full: also delete) it "
                     "as the attacker persona."),
     "input_schema": {"type": "object", "properties": {"base_url": {"type": "string"}}, "required": ["base_url"]}},
]


class ToolRegistry:
    async def _confirm_create_object_idor(self, inp: dict) -> ToolResult:
        """ACTIVE: CREATE-OBJECT IDOR (CHAD C). Create a uniquely-owned object as the OWNER persona,
        then try to READ (and, in Full mode only, DELETE) it as the ATTACKER persona."""
        return ToolResult("create_object_idor", "", True, "", [])
'''

# Two honest compound declarations at ece2dbd. `run_nuclei` leads with its registered tier;
# `confirm_authz_write` does not, but names it as a bare token in the same phrase. Neither is a lie,
# and a rule that flags them is a rule that gets silenced.
_HONEST_COMPOUND_SOURCE = '''
TOOL_PERMISSIONS = {
    "run_nuclei": PermissionLevel.ACTIVE,
    "confirm_authz_write": PermissionLevel.INTRUSIVE,          # cross-user WRITE test (restores, but state-changing)
    "run_subfinder": PermissionLevel.PASSIVE,
}

CLAUDE_TOOLS = [
    {"name": "run_nuclei",
     "description": ("ACTIVE/INTRUSIVE: Template vuln scanner. Safe tags: tech,misconfig,exposed-panels,takeovers. "
                     "Intrusive tags: cve,sqli,xss,rce. Start safe, escalate to cve only on confirmed targets."),
     "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
    {"name": "run_subfinder",
     "description": "PASSIVE: Enumerate subdomains via OSINT sources. Zero direct target contact.",
     "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
]


class ToolRegistry:
    async def _run_nuclei(self, inp: dict) -> ToolResult:
        return await self._cmd(["nuclei", "-silent", "-no-interactsh"])

    async def _confirm_authz_write(self, inp: dict) -> ToolResult:
        """ACTIVE, INTRUSIVE (opt-in): horizontal WRITE authorization test with RESTORE. Reads the
        owner's object state, has a DIFFERENT user attempt a bounded change, re-reads as the owner."""
        return ToolResult("authz_write", "", True, "", [])

    async def _run_subfinder(self, inp: dict) -> ToolResult:
        """PASSIVE: subdomain enumeration via OSINT sources; zero direct target contact."""
        return ToolResult("subfinder", "", True, "", [])
'''


def _engines(source, rule=None):
    return sorted(v.engine for v in dg.audit(source) if rule is None or v.rule == rule)


# ── RULE A — negated capability ──────────────────────────────────────────────

def test_rule_a_fires_on_the_real_ferox_source():
    """MUST-FIRE. The historical instance: 'Recursive content discovery' beside `--no-recursion`."""
    violations = [v for v in dg.audit(_FEROX_SOURCE) if v.rule == "negated_capability"]
    assert [v.engine for v in violations] == ["run_ferox"]
    assert "--no-recursion" in violations[0].detail


def test_rule_a_derives_the_negated_token_rather_than_matching_a_hardcoded_pair():
    """The rule must not be a lookup table containing the one answer it was built to produce."""
    mutated = _FEROX_SOURCE.replace("--no-recursion", "--no-crawling").replace(
        "Recursive content discovery", "Crawling content discovery")
    assert "--no-crawling" in mutated, "mutation did not apply"
    assert _engines(mutated, "negated_capability") == ["run_ferox"]


def test_rule_a_negative_control_chrome_sandbox_flags_are_not_claims():
    """NEGATIVE CONTROL. Same flag shape, no matching claim — must stay silent."""
    assert _engines(_CHROME_FLAGS_SOURCE, "negated_capability") == []


def test_rule_a_goes_quiet_when_the_claim_is_removed():
    """The claim is what makes it a violation, not the flag."""
    without_claim = _FEROX_SOURCE.replace("Recursive content discovery", "Content discovery")
    assert "Recursive" not in without_claim, "mutation did not apply"
    assert _engines(without_claim, "negated_capability") == []


# ── RULE B — undeclared permission tier ──────────────────────────────────────

def test_rule_b_fires_on_external_surface():
    """MUST-FIRE. Docstring declares PASSIVE; the engine is registered ACTIVE."""
    violations = [v for v in dg.audit(_EXTERNAL_SURFACE_SOURCE) if v.rule == "undeclared_tier"]
    assert [v.engine for v in violations] == ["run_external_surface"]
    assert "registered ACTIVE" in violations[0].detail and "PASSIVE" in violations[0].detail


def test_rule_b_fires_on_create_object_idor():
    """MUST-FIRE. Spec and registry both say INTRUSIVE; the implementation docstring says ACTIVE."""
    assert _engines(_CREATE_OBJECT_IDOR_SOURCE, "undeclared_tier") == ["confirm_create_object_idor"]


def test_a_hyphen_qualified_tier_is_a_hedge_not_a_declaration():
    """`ACTIVE-light` reads SOFTER than ACTIVE. Accepting it as a declaration of ACTIVE is exactly
    how this rule would pass the one live instance it exists to catch."""
    assert dg.declared_tiers("PASSIVE/ACTIVE-light external attack-surface expansion (#114): ...") == ["PASSIVE"]
    assert dg.declared_tiers("ACTIVE/INTRUSIVE: template scanner") == ["ACTIVE", "INTRUSIVE"]
    assert dg.declared_tiers("ACTIVE, INTRUSIVE (opt-in): write test") == ["ACTIVE", "INTRUSIVE"]


def test_rule_b_negative_control_honest_declarations():
    """NEGATIVE CONTROL. Three engines whose declarations and registrations agree — including two
    COMPOUND declarations, which a leading-token-only rule would have flagged."""
    assert _engines(_HONEST_COMPOUND_SOURCE, "undeclared_tier") == []


def test_rule_b_is_silent_when_no_tier_is_declared_at_all():
    """Silence is a documentation gap, not a contradiction. Four engines at ece2dbd declare no tier;
    flagging them would add noise this gate cannot afford."""
    source = _HONEST_COMPOUND_SOURCE.replace("PASSIVE: Enumerate subdomains via OSINT sources. Zero direct target contact.",
                                             "Enumerate subdomains via OSINT sources.")
    source = source.replace('"""PASSIVE: subdomain enumeration via OSINT sources; zero direct target contact."""',
                            '"""Subdomain enumeration via OSINT sources."""')
    assert "PASSIVE: Enumerate" not in source, "mutation did not apply"
    assert _engines(source, "undeclared_tier") == []


def test_rule_b_catches_the_dangerous_direction():
    """An engine that reads SAFER than it is registered is the failure that matters: the model is the
    consumer of these descriptions and it decides what to call from them."""
    escalated = _HONEST_COMPOUND_SOURCE.replace(
        '"run_subfinder": PermissionLevel.PASSIVE', '"run_subfinder": PermissionLevel.INTRUSIVE')
    assert "run_subfinder\": PermissionLevel.INTRUSIVE" in escalated, "mutation did not apply"
    assert _engines(escalated, "undeclared_tier") == ["run_subfinder", "run_subfinder"]  # spec + docstring


# ── THE GATE, against the live tree ──────────────────────────────────────────

# Every description-vs-code contradiction OPEN in `tools.py`, with the ticket that owns it. This is a
# ratchet, not an allowlist that can absorb anything: a contradiction on any engine NOT named here
# fails the suite. Entries leave this set only when the description or the registration is corrected
# — never by editing the description to fit the code, which is the same defect wearing a hat.
KNOWN_OPEN = {
    # Q-056. Docstring declares PASSIVE; TOOL_PERMISSIONS registers ACTIVE. The engine fetches the
    # target's favicon, so ACTIVE is the correct registration and the docstring is the wrong half.
    "run_external_surface",
    # Q-056 (found BY this gate, not by the audit that motivated it). Spec description and
    # TOOL_PERMISSIONS both say INTRUSIVE; the implementation docstring opens ACTIVE. The engine
    # creates and deletes objects on a live target.
    "confirm_create_object_idor",
}


def _tools_source():
    path = pathlib.Path(__file__).resolve().parent.parent / "tools.py"
    return path.read_text(encoding="utf-8")


def test_no_new_description_contradiction_in_tools_py():
    live = dg.audit(_tools_source())
    unexpected = [v for v in live if v.engine not in KNOWN_OPEN]
    assert not unexpected, (
        "NEW description-vs-code contradiction(s). An engine's description is a claim under test; fix "
        "the code or the registration, do not soften the claim:\n  "
        + "\n  ".join(str(v) for v in unexpected))


def test_the_gate_actually_reads_the_live_tree():
    """Negative control for the test above. A gate that silently parsed nothing would pass it, which
    is precisely how a guard in this codebase passed four engines that never ran."""
    facts = dg.analyse(_tools_source())
    assert len(facts.permissions) > 90, len(facts.permissions)
    assert len(facts.descriptions) > 60, len(facts.descriptions)
    assert facts.permissions.keys() >= facts.descriptions.keys()
    # every spec'd engine resolves to a real implementation whose body was actually collected
    assert all(facts.literals.get(name) for name in facts.descriptions), \
        sorted(n for n in facts.descriptions if not facts.literals.get(n))


@pytest.mark.parametrize("engine", sorted(KNOWN_OPEN))
def test_known_open_contradictions_are_still_the_ones_recorded(engine):
    """If a KNOWN_OPEN entry stops firing, the defect was fixed and the ledger owes an update. This
    is what stops the set above from decaying into a permanent excuse."""
    live = {v.engine for v in dg.audit(_tools_source())}
    if engine not in live:
        pytest.fail(f"{engine} no longer contradicts itself — remove it from KNOWN_OPEN and record "
                    f"the fix in docs/handoff/descriptions.md")
