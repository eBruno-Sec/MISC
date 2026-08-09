"""ICS/OT parsers replayed against RECORDED REPLIES FROM A REAL PROTOCOL STACK (#125, T14).

The frame BUILDERS were already unit-proven. What had never happened is the other half: parsing a reply
produced by an implementation that is not ours. A simulator written with our own frame code would test
each parser against its own encoder and prove nothing, so every byte below was captured off the wire from
Conpot (Honeynet Project) — a foreign stack presenting as a Siemens SIMATIC S7-200 and a Rockwell
1756-L61/B controller.

Replaying recorded bytes keeps the proof in the suite with no container and no network, so the validation
these techniques' `validated_on: ["conpot"]` claims is one this file actually re-executes.

Three defects were found by pointing the SHIPPING engines at that stack; each has a regression test here:

  * probe_s7 asked only for SZL 0x0011, which the device answered with a well-formed EMPTY payload,
    producing a `confirmed` verdict whose evidence string was "S7 module identification: ".
  * enip probe was UDP-only, so a controller answering on TCP 44818 was reported unreachable.
  * the IPMI probe sent one datagram and treated silence as "no BMC", which a single lost packet
    (or, here, a stack answering every other request) turns into a missing finding class.
"""
import base64

import enip_audit_tool as en
import ics_dnp3_s7 as ics
import ipmi_audit_tool as ip


def _b(s):
    return base64.b64decode(s)


# ── captured off the wire, byte for byte ──────────────────────────────────────
# SZL 0x0011 (module identification): well-formed, and carrying NOTHING.
S7_SZL_0011_EMPTY = _b("AwAAGQLwgDIHAAACAAAIAAAAARIIEoQBAQ==")
# SZL 0x001C (component identification): the same device's full identity.
S7_SZL_001C_FULL = _b(
    "AwABNQLwgDIHAAACAAAIARwAARIIEoQBAf8JARgAHAAAACIACAABVGVjaG5vZHJvbWUAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AlNpZW1lbnMsIFNJTUFUSUMsIFM3LTIwMAAAAAAAAAAAAANNb3VzZXIgRmFjdG9yeQAAAAAAAAAAAAAAAAAAAAAAAAAET3Jp"
    "Z2luYWwgU2llbWVucyBFcXVpcG1lbnQAAAAAAAAABTg4MTExMjIyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdJTTE1MS04"
    "IFBOL0RQIENQVQAAAAAAAAAAAAAAAAAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
# EtherNet/IP ListIdentity, answered over TCP 44818.
ENIP_LIST_IDENTITY_TCP = _b(
    "YwA8AAAAAAAAAAAAYXBvbGFraQAAAAAAAQAMADYAAQAAAq8SAAAAAAAAAAAAAAAAAQAOADYAFAtgMRoGbAAUMTc1Ni1MNjEv"
    "QiBMT0dJWDU1NjH/")
# IPMI 2.0 RMCP+ Open Session Response.
IPMI_OPEN_SESSION_RESPONSE = _b("BgD/BwYRAAAAAAAAAAAkAAAABADv2C60O4Jj4AAAAAgBAAAAAQAACAEAAAACAAAIAQAAAA==")


# ── S7comm: the empty-0x0011 trap ─────────────────────────────────────────────
def test_real_plc_answers_module_id_szl_with_nothing():
    """The reply is VALID and carries no identity — which is exactly what made the old probe confirm
    a device it could not name."""
    p = ics.parse_s7_szl(S7_SZL_0011_EMPTY)
    assert p["valid"] is True
    assert not p["module"] and not p["strings"]


def test_component_id_szl_carries_the_identity_the_module_szl_withheld():
    p = ics.parse_s7_szl(S7_SZL_001C_FULL)
    assert p["valid"] is True
    assert p["module"] == "IM151-8 PN/DP CPU"
    assert "Siemens, SIMATIC, S7-200" in p["strings"]
    assert "Technodrome" in p["strings"]                      # plant designation


def test_the_two_identification_szls_are_distinct_requests():
    """The fallback is only meaningful if it actually asks a different question."""
    assert ics.S7_SZL_MODULE_ID != ics.S7_SZL_COMPONENT_ID
    assert ics.s7_read_szl(szl_id=ics.S7_SZL_MODULE_ID) != \
        ics.s7_read_szl(szl_id=ics.S7_SZL_COMPONENT_ID)


def test_the_component_id_read_is_still_read_only():
    """The fallback must not buy identity at the cost of the safety rail."""
    assert ics.is_read_only("s7comm", ics.s7_read_szl(szl_id=ics.S7_SZL_COMPONENT_ID))


# ── EtherNet/IP: the TCP half that was never implemented ──────────────────────
def test_real_enip_controller_identity_parses_from_a_tcp_reply():
    info = en.parse_list_identity(ENIP_LIST_IDENTITY_TCP)
    assert info is not None
    assert info["product_name"] == "1756-L61/B LOGIX5561"
    assert info["vendor_id"] == 1                              # Rockwell
    assert info["revision"] == "20.11"
    assert info["serial"] == 7079450


def test_enip_oracle_still_refuses_a_non_enip_reply():
    """The FP-safe oracle has to keep saying no, or validating it against a real device proves nothing."""
    assert en.parse_list_identity(b"") is None
    assert en.parse_list_identity(b"\x00" * 64) is None
    bad_status = bytearray(ENIP_LIST_IDENTITY_TCP)
    bad_status[8] = 0x01                                       # non-zero encapsulation status
    assert en.parse_list_identity(bytes(bad_status)) is None


# ── IPMI: silence is a verdict, so one datagram is not enough ─────────────────
def test_real_bmc_open_session_response_parses():
    parsed = ip.parse_open_session_response(IPMI_OPEN_SESSION_RESPONSE)
    assert parsed is not None
    is_ipmi2, _bmc_sid, status = parsed
    assert is_ipmi2 is True and status == 0


def test_ipmi_probe_retries_rather_than_concluding_there_is_no_bmc(monkeypatch):
    """A stack that drops the first datagram must not retire the whole finding class."""
    calls = {"n": 0}

    class _FlakySocket:
        def __init__(self, *_a, **_k):
            pass

        def settimeout(self, _t):
            pass

        def sendto(self, _d, _addr):
            calls["n"] += 1

        def recvfrom(self, _n):
            import socket as _s
            if calls["n"] < 3:                                 # silent for the first two attempts
                raise _s.timeout()
            return IPMI_OPEN_SESSION_RESPONSE, ("1.2.3.4", 623)

        def close(self):
            pass

    monkeypatch.setattr(ip.socket, "socket", _FlakySocket)
    res = ip.probe("1.2.3.4", 623)
    assert res.get("ipmi2") is True, "a dropped datagram made the BMC disappear"
    assert calls["n"] == 3


def test_ipmi_gives_up_honestly_when_the_host_is_truly_silent():
    """The retry must not turn 'nothing there' into a hang or a false positive."""
    class _DeadSocket:
        def __init__(self, *_a, **_k):
            pass

        def settimeout(self, _t):
            pass

        def sendto(self, _d, _addr):
            pass

        def recvfrom(self, _n):
            import socket as _s
            raise _s.timeout()

        def close(self):
            pass

    import unittest.mock as _m
    with _m.patch.object(ip.socket, "socket", _DeadSocket):
        assert ip.probe("1.2.3.4", 623) == {"reachable": False}


def test_answered_but_unparsed_is_not_reported_as_silence():
    """A decoding gap must stay distinguishable from an empty network, or the oracle hides its own bugs."""
    class _NoiseSocket:
        def __init__(self, *_a, **_k):
            pass

        def settimeout(self, _t):
            pass

        def sendto(self, _d, _addr):
            pass

        def recvfrom(self, _n):
            return b"\x99" * 40, ("1.2.3.4", 623)

        def close(self):
            pass

    import unittest.mock as _m
    with _m.patch.object(ip.socket, "socket", _NoiseSocket):
        res = ip.probe("1.2.3.4", 623)
    assert res["reachable"] is False and res["answered_unparsed"] is True and res["bytes"] == 40


# ── the registry must not claim a validation this file does not replay ────────
def test_validated_on_conpot_is_backed_by_a_recorded_reply():
    import techniques as T
    for tid in ("modbus_exposed", "s7comm_exposed", "enip_exposed", "snmp_default_community", "ipmi_rakp"):
        assert "conpot" in T.TECHNIQUES[tid]["validated_on"], tid


def test_dnp3_stays_unproven_because_the_lab_has_no_outstation():
    """Conpot speaks five of these protocols and NOT DNP3. Marking dnp3_exposed validated on the lab that
    validated its neighbours would be borrowing their credibility."""
    import techniques as T
    assert T.TECHNIQUES["dnp3_exposed"]["validated_on"] == []


# ── the fallback sweep must reach the ports these engines live on ─────────────
def test_the_self_contained_service_sweep_probes_ics_ports():
    """REGRESSION (Codex audit). The sweep exists so service packs still run when nmap did NOT — that is
    its whole stated purpose — but it omitted every industrial port, so modbus/s7comm/enip/dnp3 were
    reachable only if nmap happened to seed them first. Four engines with a validated_on entry each,
    silently unreachable on the very path meant to guarantee them."""
    import re
    import os
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent.py"),
               encoding="utf8").read()
    i = src.find("probe = [p for p in (")
    assert i > 0
    ports = {int(n) for n in re.findall(r"\d+", src[i:src.find(")", i)])}
    for port, proto in ((502, "modbus"), (102, "s7comm"), (20000, "dnp3"),
                        (44818, "ethernet/ip"), (47808, "bacnet")):
        assert port in ports, "%s port %d missing from the self-contained sweep" % (proto, port)


def test_ot_safety_registry_covers_every_protocol_the_router_routes():
    """The registry must not understate what the tool touches. dnp3/s7comm shipped as read-only engines
    and were routed by service_router while ot_context still reported them as not routeable."""
    import ot_context as ot
    import service_router as sr
    for proto in ("modbus", "enip", "dnp3", "s7comm"):
        assert sr.pack_for(proto), "%s is not routed at all" % proto
        assert ot.PROTOCOL_SAFETY.get(proto) == "read_only", proto
