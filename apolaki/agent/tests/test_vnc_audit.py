"""VNC no-auth audit (infra pentest, CWE-306). Confirms only when the RFB handshake advertises security type
'None' (1); a password-protected server (VNC-auth only) or a non-RFB service yields nothing."""
import struct

import blind_benchmark as bb
import vnc_audit_tool as vnc


def test_parse_security_types_37_list():
    # RFB >=3.7: [count][types...]
    assert vnc.parse_security_types(bytes([2, 1, 2]), 8) == [1, 2]
    assert vnc.parse_security_types(bytes([1, 2]), 8) == [2]
    assert vnc.parse_security_types(bytes([0]), 8) == []        # count 0 = server rejected


def test_parse_security_types_33_single():
    assert vnc.parse_security_types(struct.pack(">I", 1), 3) == [1]     # RFB 3.3 single type = None
    assert vnc.parse_security_types(struct.pack(">I", 2), 3) == [2]


def test_analyze_confirms_none_auth():
    out = vnc.analyze({"rfb_version": "RFB 003.008", "security_types": [1, 2], "no_auth": True})
    assert out and "None" in out[0]
    assert vnc.analyze({"security_types": [2], "no_auth": False}) is None
    assert vnc.analyze({"error": "not RFB"}) is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    res = {"rfb_version": "RFB 003.008", "security_types": [1], "no_auth": True}
    (ev,) = vnc.analyze(res)
    f = vnc.finding("10.0.0.7", 5900, ev, res)
    assert f["family"] == "vnc_no_auth" and f["cwe"] == "CWE-306" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
