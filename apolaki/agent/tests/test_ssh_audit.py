"""SSH service audit (network pentest, CWE-326). Confirms weak KEX/cipher/MAC/host-key algorithms from the
server's KEXINIT offer; a modern hardened offer yields nothing. Critically, EXACT-match classification must NOT
false-flag the strong group16/18-sha512 exchanges or the sha2 MACs (the naive-substring FP the live probe
caught)."""
import blind_benchmark as bb
import ssh_audit_tool as ssh

_STRONG = {
    "kex": "curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
    "hostkey": "rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp256",
    "ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr",
    "macs": "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256",
}


def test_hardened_offer_is_clean():
    assert ssh.analyze(_STRONG) is None                       # no weak algo -> no finding, no FP


def test_no_false_positive_on_strong_sha512_and_group16_18():
    # the exact FP the live DW-OpenVPN probe exposed: 'group1' must NOT match group16/18, 'sha1' must NOT match sha512
    assert not ssh._weak_kex("diffie-hellman-group16-sha512")
    assert not ssh._weak_kex("diffie-hellman-group18-sha512")
    assert not ssh._weak_kex("diffie-hellman-group14-sha256")
    assert not ssh._weak_mac("hmac-sha2-512-etm@openssh.com")
    assert not ssh._weak_hostkey("rsa-sha2-512")


def test_weak_mac_only_is_low():
    offer = dict(_STRONG, macs="hmac-sha1,umac-64@openssh.com,hmac-sha2-256")
    out = ssh.analyze(offer)
    assert out and out[1] == "low" and "hmac-sha1" in out[0]["mac"] and "umac-64@openssh.com" in out[0]["mac"]
    assert "kex" not in out[0] and "cipher" not in out[0]


def test_weak_cbc_cipher_is_medium():
    offer = dict(_STRONG, ciphers="aes128-cbc,3des-cbc,aes256-ctr")
    out = ssh.analyze(offer)
    assert out and out[1] == "medium" and "aes128-cbc" in out[0]["cipher"] and "3des-cbc" in out[0]["cipher"]


def test_weak_kex_sha1_and_group1():
    assert ssh._weak_kex("diffie-hellman-group14-sha1")
    assert ssh._weak_kex("diffie-hellman-group1-sha1")
    assert ssh._weak_kex("diffie-hellman-group-exchange-sha1")


def test_deprecated_hostkey_is_medium():
    out = ssh.analyze(dict(_STRONG, hostkey="ssh-rsa,ssh-dss,ssh-ed25519"))
    assert out and out[1] == "medium" and set(out[0]["hostkey"]) == {"ssh-rsa", "ssh-dss"}


def test_finding_is_proof_with_cvss():
    from report import cvss31_base_score
    weak, sev = ssh.analyze(dict(_STRONG, macs="hmac-sha1,hmac-sha2-256"))
    f = ssh.finding("10.0.0.1", 22, weak, sev, "SSH-2.0-OpenSSH_8.9p1")
    assert f["family"] == "weak_ssh_crypto" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
