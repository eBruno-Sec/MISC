"""SMB null-session audit (AD/file-server pentest, CWE-306). Confirms only when an anonymous session can
enumerate shares; a failed connection, an error, or an empty share list yields nothing (no FP). A non-admin
share escalates to high; admin/$ shares only is medium."""
import blind_benchmark as bb
import smb_enum_tool as smb


def test_no_connection_not_flagged():
    assert smb.analyze({"connected": False}) is None
    assert smb.analyze({"error": "timed out"}) is None
    assert smb.analyze({"connected": True, "shares": []}) is None


def test_admin_shares_only_is_medium():
    out = smb.analyze({"connected": True, "shares": ["IPC$", "ADMIN$", "C$"]})
    assert out and out[0] == "medium" and out[2] == []


def test_data_share_is_high():
    out = smb.analyze({"connected": True, "shares": ["IPC$", "public", "finance"]})
    assert out and out[0] == "high" and set(out[2]) == {"public", "finance"}


def test_admin_share_classification():
    assert smb._is_admin_share("IPC$") and smb._is_admin_share("C$") and smb._is_admin_share("print$")
    assert not smb._is_admin_share("public") and not smb._is_admin_share("shared")


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    sev, ev, data = smb.analyze({"connected": True, "shares": ["IPC$", "public"]})
    f = smb.finding("10.0.0.3", 445, sev, ev, data)
    assert f["family"] == "smb_null_session" and f["cwe"] == "CWE-306" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05


def test_smb2_negotiate_request_wellformed():
    req = smb._smb2_negotiate_request()
    assert req[4:8] == b"\xfeSMB"                              # SMB2 header after the 4-byte TCP length prefix
    import struct
    assert struct.unpack(">I", req[:4])[0] == len(req) - 4     # length prefix matches


def test_parse_signing_reads_securitymode():
    import struct
    def _resp(secmode):
        return b"\x00\x00\x00\x50" + b"\xfeSMB" + b"\x00" * 60 + struct.pack("<H", 65) + struct.pack("<H", secmode)
    assert smb.parse_signing(_resp(0x0003)) is True           # ENABLED|REQUIRED -> required
    assert smb.parse_signing(_resp(0x0001)) is False          # ENABLED only -> NOT required (relay-able)
    assert smb.parse_signing(b"garbage") is None


def test_signing_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    f = smb.signing_finding("10.0.0.3", 445)
    assert f["family"] == "smb_signing_disabled" and f["cwe"] == "CWE-347" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
