"""Modbus/TCP OT exposure audit (ICS pentest, CWE-306). Confirms an unauthenticated Modbus device from a
well-formed read response; a non-Modbus service (no matching MBAP echo) yields nothing. Verifies the engine
builds ONLY read function codes — the hard OT safety rail."""
import struct

import blind_benchmark as bb
import modbus_audit_tool as mb


def test_requests_are_read_only_function_codes():
    # the safety rail: the module must only ever build READ function codes (0x2B device-id, 0x03 read-holding)
    assert mb.build_read_device_id()[7] == 0x2B and mb.build_read_device_id()[8] == 0x0E
    assert mb.build_read_holding()[7] == 0x03
    # no write/diagnostic function code (0x05/0x06/0x0F/0x10) is constructible from the public API
    assert not any(hasattr(mb, n) for n in ("build_write_register", "build_write_coil", "write"))


def test_mbap_is_wellformed():
    req = mb.build_read_holding(tid=0x1234, unit=1, addr=0, count=1)
    tid, proto, length, unit = struct.unpack(">HHHB", req[:7])
    assert tid == 0x1234 and proto == 0 and length == len(req) - 6 and unit == 1


def test_parse_rejects_wrong_transaction_or_protocol():
    good = struct.pack(">HHHB", 7, 0, 4, 1) + bytes([0x03, 0x02, 0x00, 0x01])
    assert mb.parse_response(good, 7)[0] == 0x03
    assert mb.parse_response(good, 9) is None                  # wrong tid
    bad_proto = struct.pack(">HHHB", 7, 5, 4, 1) + bytes([0x03])
    assert mb.parse_response(bad_proto, 7) is None             # protocol id != 0


def test_analyze_confirms_reachable_modbus():
    out = mb.analyze({"reachable": True, "device_info": {"vendor": "Acme PLC"}, "readable": True})
    assert out and out[0] == "high" and "Acme PLC" in out[1]
    assert mb.analyze({"reachable": False}) is None
    assert mb.analyze({"error": "timeout"}) is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    res = {"reachable": True, "device_info": {"vendor": "Acme"}, "readable": True}
    sev, ev = mb.analyze(res)
    f = mb.finding("10.0.0.9", 502, sev, ev, res)
    assert f["family"] == "modbus_exposed" and f["cwe"] == "CWE-306" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
