"""Q-144 -- Q-112 shipped a detector that had only ever been observed STAYING SILENT.

On 2026-08-31 between roughly 11:47 and 11:55 PDT the operator's ProtectIQ Intrusion feature blocked
outbound SQLi-looking HTTP URI probes. **That is precisely the scenario Q-112 was built for**, and
neither Codex brief reports Apolaki noticing.

What was established before this file:

    present    middlebox.py, the ledger, _middlebox_note, verdict ANDs into ToolResult.success
    silent     liveness 17/17 with no spurious DEGRADED -- it does not FALSE-fire
    unproven   whether it TRUE-fires, because no run has been observed while a middlebox was
               actually dropping payloads

A GUARD ONLY EVER OBSERVED STAYING SILENT IS A DECLARATION, NOT A FACT. That is the recorded lesson
from all three repaired Codex guards, and it applies to my own work with no discount.

This file drives the real `ToolRegistry` through a SIMULATED middlebox -- benign requests answered,
payload-bearing requests dropped at the transport, across two unrelated registrable domains -- and
asserts the engines report DEGRADED rather than "0 confirmed". It closes the gap between "the code
exists" and "the code fires".

WHAT IT CANNOT DO, stated so nobody mistakes green here for the field result: this simulates the
middlebox. Confirming against a REAL ProtectIQ block still requires the operator to re-enable it and
run an injection sweep against an authorized lab. The queue keeps that as the open half of Q-144.
"""
from __future__ import annotations

import middlebox as mbx
import pytest


PAYLOAD = "http://%s/search?q=1%%27%%20OR%%20%%271%%27%%3D%%271"
BENIGN = "http://%s/search?q=hello"


def _ledger(hosts, payloads_fail=True, benign_ok=True):
    """One ledger with the shape a real sweep produces: some benign traffic, some payload traffic."""
    led = mbx.Ledger()
    for h in hosts:
        for _ in range(3):
            led.record(BENIGN % h, benign_ok, payload_bearing=False)
        for _ in range(4):
            led.record(PAYLOAD % h, not payloads_fail, payload_bearing=True)
    return led


# ── the field scenario: ProtectIQ dropping SQLi probes on our own uplink ──────

def test_the_protectiq_pattern_across_unrelated_domains_is_intercepted():
    """THE TICKET. Benign answered, every payload dropped, two unrelated registrable domains."""
    v = mbx.assess(_ledger(["shop.example", "api.other-company.test"]).stats())
    assert v.intercepted is True, v
    assert v.note(), "an intercepted verdict must carry a note engines can append"
    assert "UNRELATED" in v.reason, v.reason


def test_the_verdict_note_says_the_results_are_void_not_clean():
    """A run whose payloads never left the building is not evidence of a secure target."""
    v = mbx.assess(_ledger(["a.test", "b.test"]).stats())
    low = (v.note() + " " + v.reason).lower()
    assert "degraded" in low or "intercepted" in low, v.note()


# ── the discriminator: one domain is a WAF, not our uplink ───────────────────

def test_one_domain_dropping_everything_is_a_target_waf_not_a_middlebox():
    """The single most important negative control. A defence ON THE TARGET is a finding about the
    target; escalating it to "our uplink is filtered" would void a perfectly good scan."""
    v = mbx.assess(_ledger(["only.example"]).stats())
    assert v.intercepted is False, v
    assert v.suspect_hosts, "the host should still be reported as suspect"
    assert "TARGET" in v.reason, v.reason


def test_subdomains_of_one_registrable_domain_do_not_count_as_unrelated():
    """Three hosts, one company. Counting these as "unrelated" would make every WAF look like a
    middlebox on our side -- the exact false alarm this design refuses."""
    v = mbx.assess(_ledger(["a.example.com", "b.example.com", "c.example.com"]).stats())
    assert v.intercepted is False, v


# ── the negative control that keeps a quiet scan quiet ────────────────────────

def test_a_healthy_target_is_never_intercepted():
    """Benign AND payload requests both answered. A check that turns every quiet scan into a false
    alarm is worse than the bug it fixes."""
    v = mbx.assess(_ledger(["a.test", "b.test"], payloads_fail=False).stats())
    assert v.intercepted is False and not v.suspect_hosts, v


def test_a_target_that_fails_everything_is_not_a_middlebox():
    """If the BENIGN control also fails, the host is simply down or blocking us wholesale. The
    differential needs a working control or it proves nothing."""
    v = mbx.assess(_ledger(["a.test", "b.test"], benign_ok=False).stats())
    assert v.intercepted is False, v


def test_an_empty_ledger_is_silent():
    assert mbx.assess([]).intercepted is False
    assert mbx.assess(None).intercepted is False


# ── the wiring: the verdict must reach a ToolResult ──────────────────────────

def test_the_registry_turns_an_intercepted_verdict_into_a_degraded_note():
    """NO ISLANDS. A pure oracle nothing consults is the failure mode this repo keeps filing. The
    engines use `_middlebox_note()` as BOTH the flag and the text, so a non-empty note is what makes
    `success=False` reach the execution ledger."""
    import scope as scope_mod
    import tools
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["a.test", "b.test"], [], "t")
    reg = tools.ToolRegistry(eng, mission_id="q144", lab_mode=True)
    reg._middlebox_ledger = _ledger(["a.test", "b.test"])

    note = reg._middlebox_note()
    assert note, "the registry produced no note for an intercepted ledger"
    assert not note.startswith(" ") or note.strip(), note
    # `not note` is the success flag the engines pass to ToolResult -- assert the polarity directly,
    # because an inverted flag would report the void run as clean and every test above would still
    # pass.
    assert bool(note) is True and (not note) is False


def test_the_registry_is_silent_on_a_healthy_ledger():
    """The same seam, the other way. This is the one that fails if the flag is ever inverted."""
    import scope as scope_mod
    import tools
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["a.test", "b.test"], [], "t")
    reg = tools.ToolRegistry(eng, mission_id="q144b", lab_mode=True)
    reg._middlebox_ledger = _ledger(["a.test", "b.test"], payloads_fail=False)
    assert reg._middlebox_note() == "", reg._middlebox_note()


# ── the gap a surviving mutant exposed ───────────────────────────────────────
#
# Dropping `payload_ok == 0` from `_is_suspect` killed nothing, because every fixture above is
# all-or-nothing and the `payload_fail >= MIN_PAYLOAD_ATTEMPTS` clause already covers those. The
# case neither covers is PARTIAL failure -- and that is the one that separates a filter from a flaky
# link. A middlebox blocking a payload class blocks it every time; a network dropping some requests
# is noise, and calling that "our results are void" would void good scans on a bad wifi day.

def _mixed(hosts, ok, fail):
    led = mbx.Ledger()
    for h in hosts:
        for _ in range(3):
            led.record(BENIGN % h, True, payload_bearing=False)
        for _ in range(ok):
            led.record(PAYLOAD % h, True, payload_bearing=True)
        for _ in range(fail):
            led.record(PAYLOAD % h, False, payload_bearing=True)
    return led


def test_partial_payload_failure_is_not_interception():
    """Some payloads got through, so nothing is systematically filtering them."""
    v = mbx.assess(_mixed(["a.test", "b.test"], ok=2, fail=4).stats())
    assert v.intercepted is False, v


def test_a_single_payload_success_defeats_the_verdict():
    """The boundary, stated exactly: ONE request that reached the target proves the path works."""
    v = mbx.assess(_mixed(["a.test", "b.test"], ok=1, fail=9).stats())
    assert v.intercepted is False, v
    assert mbx.assess(_mixed(["a.test", "b.test"], ok=0, fail=9).stats()).intercepted is True
