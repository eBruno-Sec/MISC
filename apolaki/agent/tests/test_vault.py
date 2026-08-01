"""Encrypted identity vault: roundtrip, reference format, on-disk secrecy, and the
redacted-reference contract. Works whether or not `cryptography` is installed (the raw literal
must never appear on disk in either mode)."""
from __future__ import annotations

import vault as V


def test_put_get_roundtrip(tmp_path):
    v = V.Vault(str(tmp_path))
    ref = v.put("m1", "user_a", {"username": "apolaki_a", "password": "SUPERSECRET", "cookie": "s=1"})
    assert ref == "vault://mission/m1/user_a"
    got = v.get(ref)
    assert got["password"] == "SUPERSECRET"
    assert got["cookie"] == "s=1"
    assert v.get_role("m1", "user_a")["username"] == "apolaki_a"


def test_reference_parsing():
    assert V.Vault.parse_ref("vault://mission/m1/user_a") == ("m1", "user_a")
    assert V.Vault.parse_ref("not-a-ref") is None
    assert V.is_ref("vault://mission/x/y") is True
    assert V.is_ref("password123") is False


def test_secret_never_on_disk_plaintext(tmp_path):
    v = V.Vault(str(tmp_path))
    v.put("m1", "user_a", {"password": "SUPERSECRET_LITERAL"})
    # read every file in the vault dir; the literal secret must not appear (encrypted OR b64 fallback)
    blob = ""
    for p in tmp_path.rglob("*"):
        if p.is_file():
            blob += p.read_text(errors="ignore")
    assert "SUPERSECRET_LITERAL" not in blob


def test_list_and_purge(tmp_path):
    v = V.Vault(str(tmp_path))
    v.put("m1", "user_a", {"password": "x"})
    v.put("m1", "user_b", {"password": "y"})
    assert set(v.list_refs("m1")) == {"vault://mission/m1/user_a", "vault://mission/m1/user_b"}
    v.delete("m1", "user_a")
    assert v.list_refs("m1") == ["vault://mission/m1/user_b"]
    v.purge("m1")
    assert v.list_refs("m1") == []


def test_bad_ref_returns_none(tmp_path):
    v = V.Vault(str(tmp_path))
    assert v.get("vault://mission/nope/none") is None
    assert v.get("garbage") is None


def test_redact_scrubs_secrets_keeps_refs():
    red = V.redact({
        "role": "user_a",
        "password": "SECRET",
        "authorization": "Bearer abc",
        "identity_ref": "vault://mission/m1/user_a",
        "nested": {"cookie": "s=1", "note": "safe"},
        "list": [{"token": "t"}],
    })
    assert red["password"] == "<redacted>"
    assert red["authorization"] == "<redacted>"
    assert red["identity_ref"] == "vault://mission/m1/user_a"   # refs pass through
    assert red["nested"]["cookie"] == "<redacted>"
    assert red["nested"]["note"] == "safe"
    assert red["list"][0]["token"] == "<redacted>"
    assert red["role"] == "user_a"
