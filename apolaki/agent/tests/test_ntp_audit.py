"""NTP monlist/amplification audit (infra pentest, CWE-406). Confirms only when the server returns a mode-7
monlist response; a non-mode-7 reply, a patched server (no reply), or a non-NTP service yields nothing."""
import struct

import blind_benchmark as bb
import ntp_audit_tool as ntp


def test_monlist_request_shape():
    req = ntp.build_monlist()
    assert req[0] == 0x17 and req[2] == 0x03 and req[3] == 0x2A and len(req) == 48


def test_parse_confirms_mode7_response():
    # byte0: response bit 0x80 + mode 7 -> 0x97 ; err|nitems field = 5 items
    resp = bytes([0x97, 0x00, 0x03, 0x2A]) + struct.pack(">H", 5) + b"\x00" * 10
    out = ntp.parse_monlist_response(resp)
    assert out and out[0] is True and out[1] == 5


def test_parse_rejects_non_mode7():
    assert ntp.parse_monlist_response(bytes([0x1C]) + b"\x00" * 20) is None    # a normal mode-4 NTP reply
    assert ntp.parse_monlist_response(b"\x17\x00") is None                     # too short / a request echo


def test_analyze_confirms_monlist():
    out = ntp.analyze({"monlist": True, "nitems": 42, "resp_len": 460})
    assert out and "monlist" in out[0]
    assert ntp.analyze({"reachable": False}) is None
    assert ntp.analyze({"error": "timeout"}) is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    res = {"monlist": True, "nitems": 42, "resp_len": 460}
    (ev,) = ntp.analyze(res)
    f = ntp.finding("10.0.0.6", 123, ev, res)
    assert f["family"] == "ntp_monlist" and f["cwe"] == "CWE-406" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
