"""RDP NLA audit (infra pentest, CWE-287). Confirms only when the server returns an RDP Negotiation RESPONSE
(NLA not enforced); a HYBRID_REQUIRED failure (NLA required) or a non-RDP reply yields nothing."""
import struct

import blind_benchmark as bb
import rdp_audit_tool as rdp


def test_neg_request_shape():
    req = rdp.build_neg_request(0)
    assert req[0] == 0x03 and req[5] == 0xE0                 # TPKT + X.224 Connection Request
    assert struct.unpack(">H", req[2:4])[0] == len(req)      # TPKT length matches
    assert req[11] == 0x01                                   # RDP Negotiation Request type


def _cc(ntype, value):
    tpkt = bytes([0x03, 0x00, 0x00, 0x13])
    x224 = bytes([0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00])   # LI, CC(0xD0), refs, class
    neg = struct.pack("<BBHI", ntype, 0x00, 0x0008, value)
    return tpkt + x224 + neg


def test_parse_response_vs_failure():
    assert rdp.parse_neg_response(_cc(0x02, 0)) == ("response", 0)        # accepted standard RDP
    assert rdp.parse_neg_response(_cc(0x02, 1)) == ("response", 1)        # TLS, still no NLA
    assert rdp.parse_neg_response(_cc(0x03, 5)) == ("failure", 5)         # HYBRID_REQUIRED (NLA enforced)
    assert rdp.parse_neg_response(b"not-rdp-at-all") is None


def test_analyze_confirms_no_nla():
    assert rdp.analyze({"nla_required": False, "selected_protocol": 0}) is not None
    assert rdp.analyze({"nla_required": True, "failure_code": 5}) is None
    assert rdp.analyze({"reachable": False}) is None
    assert rdp.analyze({"error": "timeout"}) is None


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    res = {"nla_required": False, "selected_protocol": 0}
    (ev,) = rdp.analyze(res)
    f = rdp.finding("10.0.0.4", 3389, ev, res)
    assert f["family"] == "rdp_no_nla" and f["cwe"] == "CWE-287" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
