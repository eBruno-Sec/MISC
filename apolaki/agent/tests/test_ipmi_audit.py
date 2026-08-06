"""IPMI 2.0 RMCP+ exposure audit (BMC pentest, CWE-522 / CVE-2013-4786). Confirms only a valid RMCP+ Open
Session Response (RMCP class 0x07 + IPMI auth 0x06 + payload type 0x11); a non-IPMI UDP reply yields nothing.
Detection only — the request never proceeds to RAKP Message 1 / a credential."""
import struct

import blind_benchmark as bb
import ipmi_audit_tool as ipmi


def test_open_session_request_shape():
    req = ipmi.build_open_session_request(b"\xa4\xa3\xa2\xa0")
    assert req[:4] == bytes([0x06, 0x00, 0xFF, 0x07])       # RMCP header, class 0x07 (IPMI)
    assert req[4] == 0x06 and req[5] == 0x10                # RMCP+ auth type, payload type 0x10 (open session req)
    # payload: [16:20] tag/priv/resv, [20:24] console sid, [24:32] the RAKP-HMAC-SHA1 auth algorithm payload
    assert req[24:32] == bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00])


def _open_session_response(status=0x00, bmc_sid=b"\x01\x02\x03\x04"):
    rmcp = bytes([0x06, 0x00, 0xFF, 0x07])
    payload = (bytes([0x00, status, 0x04, 0x00]) + b"\xa4\xa3\xa2\xa0" + bmc_sid
               + bytes([0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00]))
    session = bytes([0x06, 0x11]) + b"\x00" * 8 + struct.pack("<H", len(payload))
    return rmcp + session + payload


def test_parse_confirms_open_session_response():
    out = ipmi.parse_open_session_response(_open_session_response(bmc_sid=b"\xde\xad\xbe\xef"))
    assert out and out[0] is True and out[1] == "deadbeef" and out[2] == 0x00


def test_parse_rejects_non_ipmi():
    assert ipmi.parse_open_session_response(b"\x06\x00\xff\x07\x06\x10" + b"\x00" * 20) is None   # 0x10 = a request, not a response
    assert ipmi.parse_open_session_response(b"HTTP/1.1 400" + b"\x00" * 20) is None
    assert ipmi.parse_open_session_response(b"\x06\x00") is None


def test_analyze_confirms_ipmi2():
    out = ipmi.analyze({"ipmi2": True, "bmc_session_id": "deadbeef", "status": 0})
    assert out and "CVE-2013-4786" in out[0]
    assert ipmi.analyze({"reachable": False}) is None
    assert ipmi.analyze({"error": "timeout"}) is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    res = {"ipmi2": True, "bmc_session_id": "deadbeef", "status": 0}
    (ev,) = ipmi.analyze(res)
    f = ipmi.finding("10.0.0.5", 623, ev, res)
    assert f["family"] == "ipmi_rakp" and f["cwe"] == "CWE-522" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
