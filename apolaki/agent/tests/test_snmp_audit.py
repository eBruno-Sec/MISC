"""SNMP default-community audit (infra pentest, CWE-1188). Confirms only when a documented default community
yields a GetResponse with error-status 0; an unreachable/errored agent yields nothing. Also checks the
hand-built BER GetRequest is well-formed and the response parser round-trips."""
import blind_benchmark as bb
import snmp_audit_tool as snmp


def test_build_get_is_wellformed_ber():
    pkt = snmp.build_get("public")
    assert pkt[0] == 0x30 and b"public" in pkt                # SEQUENCE + community present
    tag, body, _ = snmp._read_tlv(pkt, 0)                     # parses as a TLV
    assert tag == 0x30 and len(body) > 0


def test_oid_encodes_sysdescr():
    # 1.3.6.1.2.1.1.1.0 -> first two arcs 1.3 = 0x2b, then 6 1 2 1 1 1 0
    oid = snmp._oid((1, 3, 6, 1, 2, 1, 1, 1, 0))
    assert oid[0] == 0x06 and oid[2:] == bytes([0x2b, 6, 1, 2, 1, 1, 1, 0])


def _fake_response(community, err, sysdescr):
    val = snmp._tlv(0x04, sysdescr.encode()) if sysdescr is not None else snmp._tlv(0x05, b"")
    vb = snmp._tlv(0x30, snmp._oid((1, 3, 6, 1, 2, 1, 1, 1, 0)) + val)
    pdu = snmp._tlv(0xA2, snmp._int(1) + snmp._int(err) + snmp._int(0) + snmp._tlv(0x30, vb))
    return snmp._tlv(0x30, snmp._int(1) + snmp._tlv(0x04, community.encode()) + pdu)


def test_parse_response_extracts_sysdescr():
    out = snmp.parse_response(_fake_response("public", 0, "Linux router 5.15"))
    assert out and out[0] == 0 and out[1] == "Linux router 5.15"


def test_parse_rejects_non_response_tag():
    assert snmp.parse_response(snmp.build_get("public")) is None      # a GetRequest (0xA0) is not a response (0xA2)


def test_analyze_confirms_default_community():
    assert snmp.analyze({"reachable": True, "community": "public", "sysdescr": "x"})[0] == "public"
    assert snmp.analyze({"reachable": False}) is None
    assert snmp.analyze({"error": "timeout"}) is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    f = snmp.finding("10.0.0.4", 161, "public", "Linux router")
    assert f["family"] == "snmp_default_community" and f["cwe"] == "CWE-1188" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
