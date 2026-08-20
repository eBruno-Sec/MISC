"""Q-050. An engine the planner can dispatch, whose findings nothing stores, is a false-clean.

`agent._AUTO_STORE_TOOLS` is a set, and `agent.py` has exactly ONE store site:

    if not result.error and tool_name in _AUTO_STORE_TOOLS:
        async for ev in self._auto_store(result):

So an engine absent from that set runs, emits `tool_call` and `tool_result`, and has every finding it
produced dropped on the floor. The mission looks like it tested the property. It did not report what
it found.

THIS DEFECT HAS NOW HAPPENED THREE TIMES IN ONE TICKET. Q-050 gave three engines a deterministic
trigger; the first (`run_hash_id`) had the second half caught while it was being wired, the second
(`run_ws_hijack`) was spotted by the lane in its last message before a session limit killed it, and
the third (`run_mass_assign`) was found only by auditing the line the first one added. Wiring reach
and wiring effect are two actions and only one of them was ever enforced -- which is the same shape
as Q-051 (reader half shipped, producer half did not) and Q-084 (the parameter existed, nothing read
it).

`run_mass_assign` is the one that matters most: it CHANGES STATE, `asvs_model.py:179` declares it the
verifying engine for an ASVS objective, and `wstg_catalog.py:110` rides WSTG-INPV-20 on it. A mission
would send the write, confirm the privileged attribute persisted on a separate re-read, and report
clean.

WHY THIS FILE IS NOT JUST TWO NAMES IN A LIST. A test asserting `"run_mass_assign" in
_AUTO_STORE_TOOLS` pins the two instances we happen to know about and catches no fourth. The general
rule is derived from the source instead: an engine that BUILDS A FINDINGS LIST and is reachable from
the deterministic scheduler must be able to store what it finds.
"""
from __future__ import annotations

import inspect
import re

import pytest

import agent as agentmod
import tools as toolsmod

# Engines that legitimately produce findings the deterministic path never dispatches, or whose output
# is stored by a different owner. Every entry NAMES ITS REASON -- an unexplained entry here is how an
# allowlist rots, which the dead-code gate learned the same week this was written.
_NOT_AUTO_STORED_AND_WHY = {
    # Model-facing tool: the LLM calls it explicitly to persist something it already holds. Putting
    # it in _AUTO_STORE_TOOLS would store a finding twice.
    "store_finding": "the storage primitive itself",
    # Sub-engines whose findings are FORWARDED by their parent (Q-054 shut these sinks): the parent
    # is in the set and carries them, so storing here would double-count.
    "confirm_authz_write": "forwarded by run_workflow",
    "enumerate_ids": "forwarded by run_workflow",
}


def _builds_findings(method) -> bool:
    """True when the engine constructs and appends to a findings list of its own.

    Deliberately syntactic and deliberately CONSERVATIVE. It looks for an assignment creating
    `findings` plus at least one `findings.append(`, which is the shape every engine in this codebase
    uses. It will miss an engine that returns findings from a helper without naming the local
    (`run_hash_id` is exactly that case, and it is in the set already), so this test UNDER-reports.
    That is the right direction for a gate: it can nag about a real omission, never invent one.
    """
    try:
        src = inspect.getsource(method)
    except (OSError, TypeError):
        return False
    return bool(re.search(r"^\s*findings\s*(,[^=]*)?=\s*\[", src, re.M)) and "findings.append(" in src


def _deterministically_reachable() -> set:
    """Engine names the deterministic schedulers can emit.

    Same instrument as the Q-050 census, and the same soundness argument: the scan includes comments
    and docstrings, so it can only produce false POSITIVES -- a name found here might be a mention
    rather than a dispatch. A gate that over-includes nags; one that under-includes misses the defect
    it exists to catch, and over-inclusion is the safe direction.
    """
    import agent as a
    import planner as p
    names = set()
    for mod in (a, p):
        src = inspect.getsource(mod)
        for tool in toolsmod.TOOL_PERMISSIONS:
            if re.search(r"\b%s\b" % re.escape(tool), src):
                names.add(tool)
    return names


@pytest.mark.xfail(strict=True, reason=(
    "MEASURED 2026-08-20, and held open deliberately rather than allowlisted away. The general rule "
    "flags NINE engines that are reachable from the deterministic scheduler, build a findings list, "
    "and are absent from _AUTO_STORE_TOOLS. Two of them (run_mass_assign, run_ws_hijack) are fixed "
    "in this same commit and are no longer flagged. The other seven are UNTRIAGED:\n"
    "    confirm_create_object_idor  x1   INTRUSIVE\n"
    "    confirm_read_object_idor    x2   ACTIVE\n"
    "    run_fingerprint             x1   ACTIVE\n"
    "    run_github_recon            x1   PASSIVE\n"
    "    run_header_trust            x2   ACTIVE\n"
    "    run_saml                    x1   PASSIVE\n"
    "    run_service_pack            x15  ACTIVE\n"
    "Each needs a verdict of its own: findings genuinely forwarded by a parent (as run_workflow "
    "forwards confirm_authz_write) belong in _NOT_AUTO_STORED_AND_WHY with the owner NAMED, and "
    "anything else is a live false-clean. run_service_pack is the loudest at 15 append sites. "
    "Adding all seven to either list without measuring which is which would be guessing, and an "
    "allowlist entry with no named reason is how a gate becomes decorative. STRICT: when the seven "
    "are triaged this XPASSes, the suite goes red, and the marker must be retired deliberately."))
def test_every_finding_producing_reachable_engine_can_store_what_it_finds():
    """THE GENERAL GATE, and the reason this file is not just two names in a list.

    A test asserting `"run_mass_assign" in _AUTO_STORE_TOOLS` pins the instances we happen to know
    about and catches no fourth. This derives the rule from the source instead, so an engine wired
    without its second half fails on the day it is wired rather than in a client's clean report.
    """
    reachable = _deterministically_reachable()
    missing = []
    for tool in sorted(toolsmod.TOOL_PERMISSIONS):
        if tool in agentmod._AUTO_STORE_TOOLS or tool in _NOT_AUTO_STORED_AND_WHY:
            continue
        if tool not in reachable:
            continue
        method = getattr(toolsmod.ToolRegistry, "_" + tool, None)
        if method is not None and _builds_findings(method):
            missing.append(tool)
    assert not missing, (
        "these engines are reachable from the deterministic scheduler AND build a findings list, but "
        "are absent from agent._AUTO_STORE_TOOLS -- every finding they produce is dropped at "
        "dispatch and the mission reports clean:\n  %s\n"
        "Add each to _AUTO_STORE_TOOLS, or add it to _NOT_AUTO_STORED_AND_WHY in this file WITH the "
        "reason its findings are stored elsewhere. Never add it here without naming the other owner."
        % "\n  ".join(missing))


def test_the_two_that_were_dropped_are_named_so_the_regression_is_explicit():
    """The specific instances, pinned separately from the general rule.

    The rule above is conservative by construction, so if someone weakens `_builds_findings` this
    test still fails and says which engines stopped being covered.
    """
    for tool in ("run_mass_assign", "run_ws_hijack", "run_hash_id"):
        assert tool in agentmod._AUTO_STORE_TOOLS, (
            "%s was given a deterministic trigger by Q-050; without auto-store it executes and its "
            "findings are discarded" % tool)


def test_the_detector_is_not_vacuous():
    """POSITIVE CONTROL. A gate that has never fired is indistinguishable from one that cannot.

    `_builds_findings` must say YES to an engine that plainly builds findings and NO to one that
    plainly does not, or the gate above passes by failing to look.
    """
    yes = getattr(toolsmod.ToolRegistry, "_run_mass_assign", None)
    assert yes is not None and _builds_findings(yes), \
        "the detector cannot see a findings list in an engine that demonstrably has one"
    no = getattr(toolsmod.ToolRegistry, "_run_hash_id", None)
    assert no is not None and not _builds_findings(no), (
        "the detector claims run_hash_id builds a local findings list; it does not -- it returns "
        "them from a helper. If that changed, this control needs a different specimen, not removal")


def test_there_is_still_exactly_one_store_site():
    """The gate above is only meaningful while `_AUTO_STORE_TOOLS` is the ONLY thing standing between
    an engine's findings and the database. If a second store path appears, membership stops being
    decisive and this whole file needs rethinking rather than extending."""
    src = inspect.getsource(agentmod)
    sites = [l.strip() for l in src.splitlines()
             if "_AUTO_STORE_TOOLS" in l and not l.strip().startswith("#")
             and not re.match(r"\s*_AUTO_STORE_TOOLS\s*=", l)]
    assert len(sites) == 1, (
        "expected exactly one guard site reading _AUTO_STORE_TOOLS, found %d: %s" % (len(sites), sites))
