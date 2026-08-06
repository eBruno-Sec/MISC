"""EtherNet/IP (CIP) OT exposure audit (ICS #107): read-only ListIdentity fingerprint with an FP-safe
oracle and a HARD read-only rail (no CIP write is constructible in the module)."""
import struct

import enip_audit_tool as E


def _resp(vendor=0x0001, name=b"1756-EN2T/A", serial=12345678):
    item = struct.pack("<H16s", 1, b"\x00" * 16)                 # encap version + socket address
    item += struct.pack("<HHH", vendor, 0x000C, 0x0036)          # vendor, device_type, product_code
    item += bytes([2, 1])                                        # revision major.minor
    item += struct.pack("<H", 0x0030)                            # device status
    item += struct.pack("<I", serial)                            # serial number
    item += bytes([len(name)]) + name + bytes([3])              # name_len + name + state
    body = struct.pack("<HHH", 1, 0x000C, len(item)) + item      # CPF: count, item type, item len
    header = struct.pack("<HHII8sI", 0x0063, len(body), 0, 0, b"apolaki\x00", 0)
    return header + body


def test_parse_confirms_a_real_identity_response():
    info = E.parse_list_identity(_resp())
    assert info["vendor_id"] == 1 and info["product_name"] == "1756-EN2T/A"
    assert info["serial"] == 12345678 and info["revision"] == "2.1"


def test_oracle_rejects_non_enip_and_malformed():
    assert E.parse_list_identity(b"HTTP/1.1 200 OK\r\n\r\n") is None
    assert E.parse_list_identity(b"") is None
    # right size, wrong encapsulation command -> not confirmed
    bad = bytearray(_resp())
    struct.pack_into("<H", bad, 0, 0x0065)
    assert E.parse_list_identity(bytes(bad)) is None
    # valid encap but non-identity item type -> not confirmed
    bad2 = _resp()
    bad2 = bad2[:26] + struct.pack("<H", 0x00AA) + bad2[28:]
    assert E.parse_list_identity(bad2) is None


def test_request_is_the_only_thing_built_and_carries_no_payload():
    req = E.build_list_identity()
    cmd, length = struct.unpack("<HH", req[:4])
    assert cmd == 0x0063 and length == 0 and len(req) == 24        # discovery only, zero CIP payload
    # READ-ONLY RAIL: the module builds nothing but ListIdentity — no write/forward-open/set-attribute
    builders = [n for n in dir(E) if n.startswith("build_")]
    assert builders == ["build_list_identity"]
    assert not any(k in n.lower() for n in dir(E) for k in ("write", "forward_open", "set_attribute"))


def test_probe_round_trips_over_a_real_socket():
    """Not synthetic: bind a real UDP mock PLC and prove probe() sends, receives, and parses over the wire."""
    import socket
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.settimeout(5)

    def serve():
        try:
            _data, addr = srv.recvfrom(1024)
            srv.sendto(_resp(name=b"MockPLC", serial=42), addr)
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    res = E.probe("127.0.0.1", port, timeout=3)
    assert res["reachable"] and res["device_info"]["product_name"] == "MockPLC"
    assert res["device_info"]["serial"] == 42


def test_finding_is_read_only_ics_and_well_formed():
    f = E.finding("10.0.0.5", 44818, E.parse_list_identity(_resp()))
    assert f["cwe"] == "CWE-306" and f["family"] == "ics_ot" and f["severity"] == "high"
    assert f["target"] == "enip://10.0.0.5:44818" and f["confidence"] == "confirmed"
    assert "no CIP write" in f["false_positive_check"]
