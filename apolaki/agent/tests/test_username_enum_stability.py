"""The Q-040 defect shape, found in a THIRD oracle: `username_enum_tool.enumerable`.

Q-040 was "a boolean-differential oracle with no baseline-stability control calls a flapping page a
vulnerability". It was fixed in `sqli_tool.analyze_boolean` (cbcba79) and the same discipline was
carried into `nosqli_tool`, `header_trust_tool` and `web_security`. This file records the same shape
surviving in `username_enum_tool`, where it is NOT a missing control -- the control is present and
correct -- but a confirmation path that RETURNS BEFORE REACHING IT.

WHAT `enumerable` ALREADY DOES RIGHT
------------------------------------
It is handed THREE observations: two different non-existent usernames (`absent1`, `absent2`) and one
known-existing account (`present`). The two absent samples exist precisely to measure the endpoint's
own noise floor, and on the BODY path they do exactly that:

    noise  = similarity(m_a1, m_a2)     # how alike two NON-existent responses are
    signal = similarity(m_pr, m_a1)     # how alike existing vs non-existent is
    if signal < noise - _MARGIN:        # diverges beyond the endpoint's OWN noise

That is a better control than a fixed threshold, because it is empirical: the floor is measured on
this endpoint rather than assumed. `test_the_body_noise_floor_is_real` pins that it works.

WHAT IT DOES NOT DO
-------------------
The STATUS-oracle branch sits ABOVE the noise floor and returns first:

    s_pres, s_abs = int(present.get("status") or 0), int(absent1.get("status") or 0)
    ...
    if s_pres and s_abs and s_pres != s_abs:
        return (... "status oracle", "CWE-204")

`absent2`'s status is never read -- not on this path, not anywhere in the function. So the second
reference sample, which was already fetched and already passed in, is structurally ignored, and a
single status difference between ONE absent sample and the present sample is enough to confirm.

MEASURED 2026-08-20, calling the shipped function directly (agent image, python 3.12):

    absent2.status varied over 200 / 302 / 401 / 500 / 503, all else held constant
      -> the verdict never changed.  The second reference is not consulted.

    absent1=200, absent2=500, present=500, all three bodies BYTE-IDENTICAL
      -> CONFIRMED "the existing account returns HTTP 500 while a non-existent one
         returns HTTP 200 (status oracle)"  -- a false positive on an endpoint whose
         own second reference proves it is not a function of its input.

WHY THIS IS REACHABLE IN PRODUCTION, not merely constructible
-------------------------------------------------------------
The three requests are sent in sequence to a LOGIN endpoint with deliberately wrong passwords. The
mechanisms that make a login's status vary mid-sequence are ordinary rather than exotic: a rate
limiter or lockout tripping partway through the sequence (429/423 on the later request), or an
intermittent 5xx. In each case the LAST request in the sequence is the one that changes -- and
`present` is sent last, so the flap lands exactly where it is read as signal.

HONEST NEGATIVE, stated because a zero needs a positive control:
  * 30 identical-shape failed logins each against juice-shop, dvwa and bwapp produced ONE status
    apiece ({401: 30}, {200: 30}, {200: 30}) and one distinct body apiece -- so this flap was NOT
    observed on our three standing login labs, and nothing here claims it was.
  * The findings corpus (named volume `apolaki_bbh_data`, 1773 findings across 154 missions,
    positive control: 101 CWE-89 rows) contains ZERO CWE-204 findings, so there is also no stored
    production instance. That cuts both ways and is recorded rather than argued.
The defect is therefore pinned on the STRUCTURAL measurement -- the second reference is provably
never read -- which does not depend on catching a flap in the wild.

THE FIX COSTS NOTHING. `absent2` is already fetched and already an argument; requiring the two
absent samples to AGREE before the status difference is credited adds zero requests. One-line patch
in `docs/handoff/oracle_soundness.md`. `agent/username_enum_tool.py` is not this lane's file (it has
no owner in the QUEUE ownership table), so this is pinned and handed off rather than edited here --
the same protocol `test_boolean_oracle_stability.py` used for the inert nosqli gate.

FIXTURES ARE COPIED FROM REALITY. The response body below is the verbatim body returned by the live
`apolaki-juice-shop-1` lab at `POST /rest/user/login` with a wrong password, captured 2026-08-20:
HTTP 401, body `Invalid email or password.`, byte-identical across an absent and a present account
(Juice Shop's login is correctly NON-enumerable, which is what makes it the right negative control).
"""
import pytest

import username_enum_tool as ue


# Captured verbatim from apolaki-juice-shop-1, POST /rest/user/login, wrong password, 2026-08-20.
# All three of (absent1, absent2, present) returned exactly this, HTTP 401 -- a correctly
# implemented, NON-enumerable login.
JUICE_401_BODY = "Invalid email or password."

USERNAMES = ["nosuchuser_aaaa@example.com", "nosuchuser_bbbb@example.com", "admin@juice-sh.op"]


def _obs(status, body=JUICE_401_BODY):
    return {"status": status, "body": body}


# ── the controls that must keep passing ──────────────────────────────────────────────

def test_a_real_status_oracle_on_a_stable_endpoint_still_confirms():
    """THE MANDATORY NEGATIVE CONTROL. A stability check that suppresses real findings is a worse
    defect than the one it fixes. On an endpoint whose two absent samples AGREE, a genuinely
    different status for the existing account is real evidence and must still confirm."""
    v = ue.enumerable(_obs(200), _obs(200), _obs(401), USERNAMES)
    assert v is not None, "a real status oracle on a stable endpoint stopped confirming"
    assert v[1] == "CWE-204"
    assert "status oracle" in v[0]


def test_the_live_juice_shop_login_is_not_enumerable():
    """The real capture, used as it was measured: Juice Shop answers an absent and a present account
    identically (401, same body), so the oracle must find nothing. This is the fixture's provenance
    check -- if this ever confirms, the fixture stopped describing the lab."""
    assert ue.enumerable(_obs(401), _obs(401), _obs(401), USERNAMES) is None


def test_the_body_noise_floor_is_real():
    """The control `enumerable` ALREADY has, pinned so the fix below cannot be mistaken for adding
    the first one. Two absent bodies that differ from each other set an empirical floor, and a
    present body no further away than that floor is refused."""
    a1 = "<html>Login failed. ref=00001</html>"
    a2 = "<html>Login failed. ref=99999</html>"
    pr = "<html>Login failed. ref=12345</html>"
    assert ue.enumerable({"status": 200, "body": a1}, {"status": 200, "body": a2},
                         {"status": 200, "body": pr}, USERNAMES) is None


# ── the pin ──────────────────────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason=(
    "MEASURED DEFECT, Q-040's shape in a third oracle. `username_enum_tool.enumerable` returns a "
    "CWE-204 status oracle from `s_pres != s_abs` BEFORE the empirical noise floor it already "
    "computes, and never reads `absent2['status']` on any path -- varying that value over "
    "200/302/401/500/503 leaves the verdict unchanged. So one status difference against ONE "
    "reference confirms, on an endpoint whose own second reference proves it is unstable. Reachable "
    "in production because the three probes are sequential and `present` is sent LAST, so a rate "
    "limiter, lockout or intermittent 5xx tripping mid-sequence lands exactly on the sample read as "
    "signal. The fix costs ZERO extra requests -- `absent2` is already fetched and already an "
    "argument -- and is the one-line patch in docs/handoff/oracle_soundness.md. "
    "agent/username_enum_tool.py is unowned in the QUEUE ownership table and is not this lane's "
    "file, so this is pinned and handed off. Applying the patch turns this XPASS and the marker "
    "must be removed in the same commit."))
def test_the_status_oracle_must_consult_both_reference_samples():
    """A status difference is only evidence if the two references AGREE on the status first.

    absent1=200 and absent2=500 is the endpoint stating, in its own output, that its status is not
    a function of its input. `present` landing on 500 is then a coin flip, not a membership oracle
    -- and the bodies here are byte-identical, so there is no other signal to fall back on."""
    v = ue.enumerable(_obs(200), _obs(500), _obs(500), USERNAMES)
    assert v is None, (
        "confirmed a username-enumeration status oracle on an endpoint whose two IDENTICAL "
        "reference requests returned different statuses (200 vs 500): %r" % (v,))
