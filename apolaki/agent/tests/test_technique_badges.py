"""Q-164: a technique's lab badge must be re-earned by something that RUNS, or it must go.

THE DEFECT. `agent/techniques.py` records, per technique, the lab ids its oracle was once confirmed
against. Every one of those values is a literal a human typed. 56 records carried one; exactly 24 of
them had anything that re-ran the technique. A badge nothing re-checks is a claim this tool makes
about itself with no evidence behind it -- the same class of defect as a finding reported
`confidence=confirmed` with no oracle. The full per-badge audit is docs/handoff/techniques-q164.md.

WHY THIS FILE EXISTS ALONGSIDE test_validated_on.py. That file already MEASURES the gap and pins it
as a strict xfail. It cannot enforce it, and it has two blind spots this file is shaped to cover:

  1. It counts a MENTION as backing. Its `backed` set grows for any technique id appearing on any
     line of any test file that also contains the field's name -- so
     `assert TECHNIQUES["exposed_credentials"][<the field>] == ["ginandjuice"]` marks that technique
     backed, when the line re-runs nothing and merely pins one literal against another. A guard that
     accepts a declaration as evidence passes exactly what it exists to catch.
  2. It is TECHNIQUE-granular. `dom_xss` is liveness-confirmed, so it counts as backed -- and that
     is precisely why nobody noticed its badge named `juiceshop` while the only thing re-running it
     drove `domsource`. A wrong lab survives every technique-granular check by construction.

So this file works at (technique, lab) PAIR granularity, and it accepts exactly two things as
backing: a liveness CHECK the committed baseline records as confirmed, or a live re-run in THIS file
that actually passed in THIS session.

THE SKIP COUPLING IS THE POINT. The live re-runs below add their pair to `_EARNED_HERE` only on
success. They run before the gate (pytest executes a module in definition order), so a live check
that SKIPPED or failed leaves its pair unbacked, and the gate then goes red because the pair is not
on the debt list. SKIPPED is never a pass -- not even when the skip is one of ours. Their skip
message uses the "lab unreachable" wording conftest.py's Q-094 gate watches for, so a run made
without `--network apolaki_default` fails loudly instead of quietly testing less.

A NOTE ON HOW THIS FILE IS WRITTEN. It deliberately never puts a technique id on the same source
line as the registry field's name, and never names that field inside a loop over technique ids.
That is not cosmetic: test_validated_on.py's `backed` heuristic scans this directory's source text,
so a file that spelled both together would silently mark ~24 unproven techniques as backed and
turn that gate green by existing. Fixing another lane's gate is not this ticket; feeding it a false
positive would be a regression.
"""
from __future__ import annotations

import asyncio

import pytest

import liveness as LV
import techniques as T

# The registry field under audit. Held as a name so it never shares a line with a technique id.
_FIELD = "validated_on"


# ── the alias between a liveness CHECK's lab key and the id a badge spells ────────────────────
# `dnp3_exposed` is confirmed by the check whose lab key is "dnp3" (host `dnp3-outstation`); the
# badge spells the container's product name instead. docker-compose.yml:352 and liveness.py's own
# comment both say they are the same container, so the two strings are recorded as one lab rather
# than papered over by loosening the comparison. Any OTHER mismatch stays a failure.
_LAB_ALIAS = {"dnp3": ("dnp3", "openfmb")}


def claimed_pairs(registry=None) -> set:
    """Every badge in the registry as a (technique id, lab id) pair. Pure."""
    out = set()
    for tid, rec in (registry or T.TECHNIQUES).items():
        for lab in (rec.get(_FIELD) or []):
            out.add((tid, lab))
    return out


def liveness_pairs() -> set:
    """(technique id, lab id) pairs an end-to-end liveness run re-runs AND the baseline confirms.

    Both halves matter. A CHECKS entry alone proves only that somebody wrote a check; the committed
    baseline is the artifact a RUN produced. A check whose technique is not in the baseline is a
    check that has never been seen to pass, and it backs nothing."""
    confirmed = T._liveness_verified()
    out = set()
    for chk in LV.CHECKS:
        tid = chk.get("technique")
        if tid not in confirmed or tid not in T.TECHNIQUES:
            continue
        for lab in _LAB_ALIAS.get(chk.get("lab"), (chk.get("lab"),)):
            out.add((tid, lab))
    return out


def unbacked(claimed: set, live: set, here: set) -> set:
    """THE PREDICATE, pure and separately testable so the negative control can drive it directly."""
    return set(claimed) - set(live) - set(here)


# Pairs re-earned by a live re-run in this file, added only when that re-run passed.
_EARNED_HERE: set = set()

# What the live re-runs below are SUPPOSED to earn. Used only to tell two different reds apart in
# the gate's message -- it is never subtracted from the gap, because a declared intention is not a
# run and subtracting it would restore exactly the defect this file exists to remove.
_REEARN_DECLARED = frozenset({("snmp_default_community", "conpot"),
                              ("graphql_batching_enabled", "dvga"),
                              ("sqli_auth_bypass", "juiceshop")})


# ══ THE HONESTY DEBT ══════════════════════════════════════════════════════════════════════════
# Badges with no re-runner as of Q-164. Frozen here so the gate below can be EXACT in both
# directions: a new badge that nothing re-runs fails because it is absent from this list, and an
# entry that becomes backed (or whose badge is withdrawn) ALSO fails, because the list must then
# shrink deliberately. A debt list that can only be read and never has to be updated is the shape
# that let a dead-code ratchet report green while rising -- this one cannot go stale silently.
#
# The verdict behind each entry, and what would clear it, is in docs/handoff/techniques-q164.md.
# NOTHING here is an approval. Every line is a claim the product has not earned.
DEBT = frozenset({
    # -- local lab, alive, a real engine bound, and no check points at it (re-earnable) --
    ("sqli_union_extract", "juiceshop"),
    ("idor_bola_read", "juiceshop"),
    ("browser_persona_bola", "juiceshop"),
    ("missing_authentication", "juiceshop"),
    ("unrestricted_file_upload", "juiceshop"),
    ("exposed_files_harvest", "juiceshop"),
    ("csti", "juiceshop"),
    ("ssti", "juiceshop"),
    ("xxe_file_ssrf", "juiceshop"),
    ("target_intel_harvest", "juiceshop"),
    ("csrf", "juiceshop"),
    ("excessive_data_exposure", "juiceshop"),
    ("jsonp_info_leak", "juiceshop"),
    ("race_condition", "juiceshop"),
    ("archive_slip", "juiceshop"),
    ("find_hidden_route", "juiceshop"),
    ("request_url_override", "domsource"),
    # DVWA needs a login plus a security=low cookie, and the two engines that would prove these are
    # a timing-based sweep and an INTRUSIVE probe that submits discovered forms. Neither belongs in
    # a suite that runs on every change; both want a liveness CHECK entry instead (diff in handoff).
    ("command_injection", "dvwa"),
    ("path_traversal", "dvwa"),
    # -- off this bench: PortSwigger's public ginandjuice.shop. Authorized targets here are the
    #    local docker labs only, so no run made from this repo can re-earn these.
    ("base64_param", "ginandjuice"),
    ("prototype_pollution", "ginandjuice"),
    ("csti", "ginandjuice"),
    ("exposed_credentials", "ginandjuice"),
    # -- the lab exists only as uncommitted local state: no compose service, no source and no
    #    registry entry at HEAD, so `known_labs()` cannot resolve it. Left in place ON PURPOSE
    #    because another lane has that lab in flight in the working tree; withdrawing the badge
    #    from under them would race. Recommendation is in the handoff.
    ("session_lifecycle", "sessionlife"),
})


# ══ LIVE RE-EARNS ═════════════════════════════════════════════════════════════════════════════
# Each drives the SHIPPING executor against a standing lab and requires the real oracle to fire,
# with a negative control where the lab can supply one. A pair enters `_EARNED_HERE` only here.

def test_reearn_snmp_default_community_on_conpot():
    """The `conpot` half of this badge had no check: liveness only targets `snmpd:161`, and
    test_ics_real_stack.py names the id in a membership assertion without replaying one SNMP byte
    (its four neighbours in that same loop each have a recorded reply; this one does not).

    MEASURED, and not what the compose file reads like: conpot's SNMP is published as
    `127.0.0.1:42162:16100/udp`, so the container listens on 16100. `conpot:161` answers nothing.
    """
    import snmp_audit_tool as snmp

    res = snmp.probe("conpot", 16100, timeout=8.0)
    if not res.get("reachable"):
        pytest.skip("conpot lab unreachable (no SNMPv2c answer on 16100/udp); no measurement, "
                    "not a pass")
    got = snmp.analyze(res)
    assert got, res
    community, sysdescr = got
    assert community in snmp.DEFAULT_COMMUNITIES, community
    assert len(str(sysdescr).strip()) >= 8, sysdescr

    # NEGATIVE CONTROL. Without this the test proves only that something answers UDP 16100, which a
    # honeypot willing to reply to anything would satisfy while the oracle decided nothing.
    bogus = snmp.probe("conpot", 16100, communities=("apolaki-q164-not-a-community",), timeout=8.0)
    assert not bogus.get("reachable"), (
        "conpot answered a community nobody configured, so accepting 'public' proves nothing "
        "about default-community exposure: %r" % (bogus,))
    assert snmp.analyze(bogus) is None, bogus

    _EARNED_HERE.add(("snmp_default_community", "conpot"))


def test_reearn_graphql_batching_enabled_on_dvga():
    """DVGA is the badge's lab and the engine is `_run_graphql`, but the only thing pinning the
    claim was `assert "dvga" in ...` in test_local_import_guard.py -- a membership assertion, which
    test_validated_on.py:171 already demonstrated cannot fail on an addition.

    Matched by TITLE, not family. liveness.py records that matching `family == "graphql"` let the
    BATCHING finding satisfy the INTROSPECTION check while introspection emitted nothing; the same
    trap inverted would let introspection satisfy this one.
    """
    reg = _registry(["dvga:5013"])
    res = asyncio.run(reg._run_graphql({"url": "http://dvga:5013/graphql"}))
    findings = list(getattr(res, "findings", []) or [])
    if not findings:
        pytest.skip("dvga lab unreachable (no GraphQL findings at all); no measurement, not a pass")
    hit = _confirmed(findings, title="batching")
    assert hit, "no confirmed batching finding among %r" % ([f.get("title") for f in findings],)
    assert hit.get("cwe") == "CWE-770", hit
    # The evidence must state the differential (N sent -> N returned), not merely assert the verdict.
    assert "5" in str(hit.get("evidence") or ""), hit.get("evidence")

    _EARNED_HERE.add(("graphql_batching_enabled", "dvga"))


def test_reearn_sqli_auth_bypass_on_juiceshop():
    """The registry's very first record, and nothing re-ran it. `_run_auth_sqli` is the shipping
    executor and Juice Shop's `/rest/user/login` is the badge's own lab.

    The oracle is the technique's, unchanged: a session token issued where invalid credentials are
    rejected. `_run_auth_sqli` baselines with a freshly random benign credential on every call, so
    a 'confirmed' here is a differential and not a page that returns 200 to everything.
    """
    reg = _registry(["juice-shop:3000"])
    res = asyncio.run(reg._run_auth_sqli(
        {"url": "http://juice-shop:3000/rest/user/login", "fields": ["email", "password"]}))
    findings = list(getattr(res, "findings", []) or [])
    if not findings:
        pytest.skip("juice-shop lab unreachable (login endpoint produced no result); no "
                    "measurement, not a pass")
    hit = _confirmed(findings, title="auth-bypass")
    assert hit, "no confirmed auth-bypass finding among %r" % ([f.get("title") for f in findings],)
    assert hit.get("cwe") == "CWE-89", hit
    assert "token" in str(hit.get("evidence") or "").lower(), hit.get("evidence")

    _EARNED_HERE.add(("sqli_auth_bypass", "juiceshop"))


# ══ THE GATE ══════════════════════════════════════════════════════════════════════════════════

def test_every_badge_is_backed_by_something_that_RUNS():
    """EXACT equality, both directions, at pair granularity.

    - a badge that nothing re-runs and is not on the debt list  -> FAIL (the new-claim direction)
    - a debt entry that is now backed, or whose badge was withdrawn -> FAIL (the ratchet direction)

    The second direction is the one that is usually missing. A list of known exceptions that only
    ever has to be read is exactly how a ratchet reports green while the thing it bounds rises.
    """
    live = liveness_pairs()
    assert len(live) >= 24, ("the liveness ledger collapsed to %d pair(s); every verdict below "
                             "would be meaningless" % len(live))
    gap = unbacked(claimed_pairs(), live, _EARNED_HERE)

    new_claims = sorted(gap - DEBT)
    missed_reearn = sorted((gap - DEBT) & _REEARN_DECLARED)
    assert not missed_reearn, (
        "%d pair(s) this file is supposed to re-earn LIVE did not: %s. Its live check skipped or "
        "failed, so the badge is unproven for this run -- that is the intended coupling, not a "
        "registry problem. If you selected a subset of this file, run the whole file: the gate "
        "reads what actually ran, never what the file declares." % (len(missed_reearn), missed_reearn))
    assert not new_claims, (
        "%d badge(s) claim a lab that nothing re-runs and that this audit never accepted: %s. "
        "Either add a check that re-earns the pair, or withdraw the badge -- withdrawing is a "
        "legitimate outcome." % (len(new_claims), new_claims))

    cleared = sorted(DEBT - gap)
    assert not cleared, (
        "%d debt entr(ies) are no longer unbacked: %s. That is good news and the list must shrink "
        "to match -- delete them from DEBT in this file so the remaining debt keeps meaning what "
        "it says. If the badge was withdrawn instead, delete the entry for the same reason."
        % (len(cleared), cleared))


def test_the_three_live_reearns_actually_ran():
    """A skipped re-earn must not look like a pass. The gate above already goes red when a pair is
    missing from `_EARNED_HERE`, but it says so in the vocabulary of badges; this says it plainly,
    so the cause is not misread as a registry edit."""
    assert _EARNED_HERE == {("snmp_default_community", "conpot"),
                            ("graphql_batching_enabled", "dvga"),
                            ("sqli_auth_bypass", "juiceshop")}, sorted(_EARNED_HERE)


# ══ NEGATIVE CONTROLS ═════════════════════════════════════════════════════════════════════════
# A gate counts only when someone can make it fail. Both directions of the gate are driven here.

def test_a_badge_on_a_lab_nothing_checks_is_reported():
    """THE NEGATIVE CONTROL for the new-claim direction, driven through the real predicate."""
    fabricated = ("fabricated_technique_q164", "fabricated_lab_9000")
    gap = unbacked(claimed_pairs() | {fabricated}, liveness_pairs(), _EARNED_HERE)
    assert fabricated in gap, "the predicate did not report a pair nothing anywhere re-runs"
    assert sorted(gap - DEBT) == [fabricated], sorted(gap - DEBT)


def test_the_gate_goes_red_when_a_REAL_record_gains_an_unchecked_lab():
    """The control above builds its own inputs, which is the weaker half: it proves the predicate
    discriminates, not that the gate reads the registry. So mutate a real record and drive the gate
    itself, then restore. `unrestricted_file_upload` is used because its badge is already on the
    debt list, so the mutation is the only thing that can move the result."""
    tid = "unrestricted_file_upload"
    rec = T.TECHNIQUES[tid]
    original = list(rec[_FIELD])
    try:
        rec[_FIELD] = original + ["mutillidae"]
        gap = unbacked(claimed_pairs(), liveness_pairs(), _EARNED_HERE)
        assert (tid, "mutillidae") in gap - DEBT, (
            "a lab id typed onto a real record was accepted by the gate")
        with pytest.raises(AssertionError):
            test_every_badge_is_backed_by_something_that_RUNS()
    finally:
        rec[_FIELD] = original
    assert T.TECHNIQUES[tid][_FIELD] == original, "the registry must be restored"
    # and the gate is green again, so the red above was the mutation and nothing else
    test_every_badge_is_backed_by_something_that_RUNS()


def test_the_gate_goes_red_when_a_DEBT_entry_is_silently_cleared():
    """THE RATCHET DIRECTION, which is the one a list of known exceptions usually cannot check.
    Withdraw a badge that is on the debt list and the gate must complain that the list is stale --
    not quietly pass because the world got better."""
    tid = "race_condition"
    rec = T.TECHNIQUES[tid]
    original = list(rec[_FIELD])
    assert (tid, "juiceshop") in DEBT, "fixture assumption changed; pick another debt entry"
    try:
        rec[_FIELD] = []
        with pytest.raises(AssertionError) as ei:
            test_every_badge_is_backed_by_something_that_RUNS()
        assert "no longer unbacked" in str(ei.value), str(ei.value)
    finally:
        rec[_FIELD] = original
    assert T.TECHNIQUES[tid][_FIELD] == original, "the registry must be restored"


def test_a_wrong_LAB_on_a_liveness_proven_technique_is_still_caught():
    """The blind spot that motivated pair granularity. `dom_xss` is liveness-confirmed, so every
    technique-granular gate calls it backed however its badge is spelled. Re-point the badge at a
    lab the check does not drive and this gate must still object."""
    rec = T.TECHNIQUES["dom_xss"]
    original = list(rec[_FIELD])
    assert original == ["domsource"], original
    try:
        rec[_FIELD] = ["juiceshop"]          # the value Q-164 corrected
        gap = unbacked(claimed_pairs(), liveness_pairs(), _EARNED_HERE)
        assert ("dom_xss", "juiceshop") in gap - DEBT, (
            "a liveness-proven technique kept its badge while naming a lab nothing drove it against")
    finally:
        rec[_FIELD] = original


# ══ helpers ═══════════════════════════════════════════════════════════════════════════════════

def _registry(hosts):
    from scope import ScopeEngine
    from tools import ToolRegistry
    sc = ScopeEngine()
    sc.load_manual(list(hosts), [], "q164-badges")
    return ToolRegistry(sc, lab_mode=True)


def _confirmed(findings, title: str):
    """The first CONFIRMED finding whose title carries `title`, with real evidence behind it.

    Same bar as liveness._match: a lead never satisfies a re-earn, and evidence shorter than a
    dozen characters is a verdict with nothing under it."""
    want = title.lower()
    for f in findings or []:
        if str(f.get("confidence") or "").lower() not in ("confirmed", "high") and not f.get("confirmed"):
            continue
        if want not in str(f.get("title") or "").lower():
            continue
        if len(str(f.get("evidence") or f.get("success_oracle") or "").strip()) < 12:
            continue
        return f
    return None
