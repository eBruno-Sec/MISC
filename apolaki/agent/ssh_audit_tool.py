"""SSH service audit (network pentest, beyond web — CWE-326/327). Apolaki's first non-HTTP service engine: it
reads the SSH KEXINIT handshake the server sends (NO authentication, NO credential attempt, NO brute-force — a
purely passive read of what the daemon advertises) and flags weak / deprecated key-exchange, cipher, MAC, and
host-key algorithms an attacker in a MITM position could downgrade to. Deterministic + FP-safe: the server
literally lists these algorithm names in its offer, and matching is by EXACT name / anchored suffix — never a
loose substring (a naive `group1` check false-flags the strong `group16-sha512`; a naive `sha1` check false-
flags `sha512`). A modern hardened sshd offers none of them and yields nothing. Pure logic here (weak-set
classification + finding); the caller performs the one read-only TCP handshake via probe()."""
from __future__ import annotations

import socket
import struct


def _weak_kex(a: str) -> bool:
    n = (a or "").lower()
    # SHA-1-based key exchange (offline-collision / downgrade risk). Anchored on the -sha1 SUFFIX so the strong
    # groupNN-sha256/sha512 exchanges are NOT matched; plus the classic 1024-bit group1.
    return (n.endswith("-sha1") or n in ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1") or n.startswith("gss-group1-"))


def _weak_cipher(a: str) -> bool:
    n = (a or "").lower()
    # CBC (plaintext-recovery, CVE-2008-5161) + legacy stream/block ciphers + the null cipher.
    return (n.endswith("-cbc") or n.startswith(("3des", "arcfour", "blowfish", "cast128", "des-")) or n == "none")


def _weak_mac(a: str) -> bool:
    n = (a or "").lower()
    # MD5 / SHA-1 / 64-bit-UMAC / truncated (-96) tags / the null MAC. `-sha1` won't match `-sha2-...`.
    return ("md5" in n or "-sha1" in n or n.startswith("umac-64") or n.endswith("-96") or n == "none")


def _weak_hostkey(a: str) -> bool:
    # ssh-rsa is SHA-1 RSA (deprecated); ssh-dss is 1024-bit DSA. rsa-sha2-256/512, ecdsa, ed25519 are fine.
    return (a or "").lower() in ("ssh-dss", "ssh-rsa")


def analyze(offer: dict):
    """(weak, severity) where weak = {category: [algos]} of everything deprecated the server offers, and severity
    is 'medium' when a weak cipher/kex/host-key is present (a real downgrade attack) or 'low' for weak-MAC-only
    (hardening). None when the offer is clean. `offer` = {kex, hostkey, ciphers, macs} name-list strings/lists."""
    def _split(v):
        return [x for x in (v.split(",") if isinstance(v, str) else (v or [])) if x]
    weak = {
        "kex": [a for a in _split(offer.get("kex")) if _weak_kex(a)],
        "cipher": [a for a in _split(offer.get("ciphers")) if _weak_cipher(a)],
        "mac": [a for a in _split(offer.get("macs")) if _weak_mac(a)],
        "hostkey": [a for a in _split(offer.get("hostkey")) if _weak_hostkey(a)],
    }
    weak = {k: v for k, v in weak.items() if v}
    if not weak:
        return None
    severity = "medium" if (weak.get("cipher") or weak.get("kex") or weak.get("hostkey")) else "low"
    return weak, severity


def probe(host: str, port: int = 22, timeout: float = 8.0) -> dict:
    """One READ-ONLY SSH handshake: exchange banners, read the server's SSH_MSG_KEXINIT, and return its advertised
    algorithm name-lists + the server banner. No authentication is attempted. Returns {error} on failure."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, int(port)))
        banner = b""
        while b"\n" not in banner and len(banner) < 512:
            c = s.recv(1)
            if not c:
                break
            banner += c
        s.sendall(b"SSH-2.0-ApolakiAudit\r\n")
        hdr = b""
        while len(hdr) < 4:
            hdr += s.recv(4 - len(hdr))
        plen = struct.unpack(">I", hdr)[0]
        if plen > 70000:
            return {"error": "implausible packet length (not SSH?)"}
        body = b""
        while len(body) < plen:
            chunk = s.recv(plen - len(body))
            if not chunk:
                break
            body += chunk
        pad = body[0]
        payload = body[1:len(body) - pad]
        if not payload or payload[0] != 20:                  # 20 = SSH_MSG_KEXINIT
            return {"error": "no KEXINIT received"}
        off, lists = 17, []                                  # skip msg-type byte + 16-byte cookie
        for _ in range(10):
            ln = struct.unpack(">I", payload[off:off + 4])[0]
            off += 4
            lists.append(payload[off:off + ln].decode("latin-1"))
            off += ln
        return {"banner": banner.decode("latin-1", "replace").strip(),
                "kex": lists[0], "hostkey": lists[1], "ciphers": lists[3], "macs": lists[5]}
    except Exception as e:
        return {"error": str(e)[:120]}
    finally:
        try:
            s.close()
        except Exception:
            pass


def finding(host: str, port: int, weak: dict, severity: str, banner: str) -> dict:
    parts = ["%s: %s" % (k, ", ".join(v)) for k, v in weak.items()]
    vec = ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" if severity == "medium"
           else "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N")
    return {
        "title": "SSH server offers weak cryptographic algorithms (%s:%d)" % (host, port),
        "severity": severity, "family": "weak_ssh_crypto", "confidence": "confirmed",
        "target": "%s:%d" % (host, port), "cwe": "CWE-326",
        "cvss_vector": vec, "cvss_score": 5.9 if severity == "medium" else 3.7,
        "evidence": ("The SSH daemon at %s:%d (%s) advertises deprecated algorithms an on-path attacker can "
                     "negotiate down to — %s. Read passively from the server's KEXINIT; no login was attempted."
                     % (host, port, banner or "banner hidden", "; ".join(parts))),
        "success_oracle": "the server's KEXINIT name-lists literally include these weak algorithms",
        "reproduction_steps": [
            "Open a TCP connection to %s:%d and complete the SSH banner exchange." % (host, port),
            "Read the server's SSH_MSG_KEXINIT packet and parse its algorithm name-lists.",
            "Observe the weak entries (%s) — negotiable by any client that offers only these." % "; ".join(parts)],
        "impact": ("A MITM attacker can force a weak cipher/MAC/KEX and attempt session decryption or tampering; "
                   "weak host-key algorithms weaken server authentication."),
        "remediation": ("Restrict sshd to strong algorithms only: KexAlgorithms curve25519-sha256 + "
                        "diffie-hellman-group16/18-sha512; Ciphers chacha20-poly1305 + aes*-gcm/ctr; MACs the "
                        "*-etm hmac-sha2-256/512 set; HostKeyAlgorithms rsa-sha2-*/ed25519. Remove CBC, SHA-1, "
                        "arcfour, 3des, umac-64, ssh-rsa, ssh-dss."),
        "tags": ["ssh", "weak-crypto", "cwe-326", "network-service"],
    }
