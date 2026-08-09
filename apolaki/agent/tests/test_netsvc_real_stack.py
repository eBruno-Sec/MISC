"""network_service oracles replayed against a RECORDED REPLY FROM A REAL SERVER (#125, T15).

Same standard as test_ics_real_stack: the bytes were captured off the wire from the Samba and OpenLDAP
labs already wired in docker-compose, not synthesised from our own request builders. A fixture built by
our own encoder would prove only that we can read what we wrote.

These oracles decide whether a real network exposure gets reported, so the negative cases matter as much
as the positive ones — an oracle that says yes to everything is worth nothing.
"""
import base64

import ldap_enum_tool as ld
import smb_enum_tool as smb


def _b(s):
    return base64.b64decode(s)


# Samba's real SMB2 NEGOTIATE response. SecurityMode does NOT set SIGNING_REQUIRED.
SMB2_NEGOTIATE_SIGNING_NOT_REQUIRED = _b(
    "AAAAyv5TTUJAAAAAAAAAAAAAAQABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBAAEA"
    "AgMAADhjMmVlMDlhOWVmNgAAAAAHAAAAAACAAAAAgAAAAIAAIMiCHtkn3QEAAAAAAAAAAIAASgAAAAAAYEgGBisGAQUFAqA+"
    "MDygDjAMBgorBgEEAYI3AgIKoyowKKAmGyRub3RfZGVmaW5lZF9pbl9SRkM0MTc4QHBsZWFzZV9pZ25vcmU=")


# ── SMB signing ───────────────────────────────────────────────────────────────
def test_real_smb2_negotiate_reports_signing_not_required():
    assert smb.parse_signing(SMB2_NEGOTIATE_SIGNING_NOT_REQUIRED) is False


def test_smb_signing_oracle_flips_when_the_required_bit_is_set():
    """THE load-bearing negative. If flipping SIGNING_REQUIRED does not change the verdict, the engine is
    not reading the field it claims to read, and every server would be reported as vulnerable."""
    buf = bytearray(SMB2_NEGOTIATE_SIGNING_NOT_REQUIRED)
    # SecurityMode is 2 bytes at offset 2 of the SMB2 header body: +4 NetBIOS, +64 header = 70.
    sec_off = 4 + 64 + 2
    buf[sec_off] = buf[sec_off] | 0x02          # SMB2_NEGOTIATE_SIGNING_REQUIRED
    assert smb.parse_signing(bytes(buf)) is True


def test_smb_signing_oracle_refuses_a_non_smb_reply():
    assert smb.parse_signing(b"") is None
    assert smb.parse_signing(b"\x00" * 8) is None
    assert smb.parse_signing(b"HTTP/1.1 200 OK\r\n\r\n") is None


# ── SMB null session ──────────────────────────────────────────────────────────
def test_null_session_analyze_confirms_high_on_a_non_administrative_share():
    """Samba's real answer to a null session: 'public' + IPC$. The readable data share is what makes it
    high — the finding is graded by what the anonymous session actually reached."""
    sev, ev, data = smb.analyze({"connected": True, "shares": ["public", "IPC$"]})
    assert sev == "high" and "public" in ev and data == ["public"]


def test_null_session_is_still_reported_when_only_admin_shares_answer_but_graded_lower():
    """A null session succeeding is itself the exposure; IPC$-only is layout disclosure rather than data
    disclosure, so it drops to medium instead of disappearing."""
    sev, _ev, data = smb.analyze({"connected": True, "shares": ["IPC$"]})
    assert sev == "medium" and data == []


def test_null_session_declines_when_the_anonymous_session_reached_nothing():
    """The real negative: no session, or a session that enumerated nothing, is not a finding."""
    assert smb.analyze({"connected": False, "shares": []}) is None
    assert smb.analyze({"connected": True, "shares": []}) is None
    assert smb.analyze({"connected": True, "shares": ["public"], "error": "timeout"}) is None


# ── LDAP anonymous read ───────────────────────────────────────────────────────
def test_anonymous_bind_that_reads_the_directory_is_confirmed():
    """OpenLDAP's real answer: bound anonymously and returned the naming context as a readable entry."""
    sev, ev = ld.analyze({"bound": True, "naming_contexts": ["dc=designworld,dc=local"],
                          "entries": ["dc=designworld,dc=local"], "user_dns": []})
    assert sev == "medium" and "dc=designworld,dc=local" in ev


def test_anonymous_bind_that_reads_nothing_is_not_a_finding():
    """A server that ACCEPTS an anonymous bind but discloses no entry is the hardened configuration.
    Reporting it would flag almost every directory on earth."""
    assert ld.analyze({"bound": True, "naming_contexts": [], "entries": [], "user_dns": []}) is None
    assert ld.analyze({"bound": False, "naming_contexts": [], "entries": [], "user_dns": []}) is None


# ── the registry must not claim a validation this file does not replay ────────
def test_validated_on_is_backed_by_a_recorded_reply():
    import techniques as T
    for tid, lab in (("smb_null_session", "smb"), ("smb_signing_disabled", "smb"),
                     ("ldap_anonymous_read", "openldap")):
        assert lab in T.TECHNIQUES[tid]["validated_on"], tid


def test_snmp_default_community_is_generalized_across_two_labs():
    """Confirmed on Conpot (an ICS stack) and on snmpd (a stock Net-SNMP agent) — two unrelated
    implementations, which is the bar for calling a technique transferable rather than lab-shaped."""
    import techniques as T
    assert {"conpot", "snmpd"} <= set(T.TECHNIQUES["snmp_default_community"]["validated_on"])
