"""
Offline hash identification + optional offline cracking helpers.

Two strictly-offline capabilities:

  1. identify() — pattern-based hash-type identification (length + charset + prefix).
     100% offline, PASSIVE, no network, no target contact. Used to classify secrets
     that were ALREADY obtained (e.g. a password hash dumped via a confirmed SQLi).

  2. crack command builders — build a validated ARGUMENT ARRAY for hashcat or John the
     Ripper to crack an ALREADY-OBTAINED hash against a LOCAL wordlist. This is OFFLINE
     dictionary work on data you already hold; it does NOT contact, authenticate to, or
     brute-force any live service. The prohibition on attacking live authentication
     endpoints / brute-forcing credentials over the network is preserved: nothing here
     ever sends a credential anywhere. The subprocess is run by tools._cmd (arg array,
     no shell) and skips gracefully when the binary is absent.
"""
from __future__ import annotations

import re

# (name, hashcat -m mode or None, John format or None). Ordered so the most specific
# prefixed formats win before the generic hex-by-length guesses.
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64ISH = re.compile(r"^[A-Za-z0-9+/=._-]+$")


def _looks_hex(s: str, n: int) -> bool:
    return len(s) == n and bool(_HEX.match(s))


def identify(value: str) -> list:
    """Return a ranked list of {'name','hashcat','john','confidence'} candidate hash
    types for a single token. Offline heuristic — a hint for the operator, never a
    confirmed fact. Empty for anything that is not hash-shaped."""
    v = (value or "").strip()
    if not v or len(v) < 8 or len(v) > 4096 or " " in v:
        return []
    out = []

    def add(name, hc, john, conf):
        out.append({"name": name, "hashcat": hc, "john": john, "confidence": conf})

    # ── prefixed / structured formats (high confidence) ──
    if v.startswith(("$2a$", "$2b$", "$2y$")) and len(v) == 60:
        add("bcrypt", "3200", "bcrypt", "high")
    elif v.startswith("$1$"):
        add("md5crypt (Unix)", "500", "md5crypt", "high")
    elif v.startswith("$5$"):
        add("sha256crypt (Unix)", "7400", "sha256crypt", "high")
    elif v.startswith("$6$"):
        add("sha512crypt (Unix)", "1800", "sha512crypt", "high")
    elif v.startswith("$argon2"):
        add("Argon2", None, "argon2", "high")
    elif v.startswith("$pbkdf2"):
        add("PBKDF2", None, "pbkdf2", "high")
    elif v.count(".") == 2 and all(_B64ISH.match(p or "") for p in v.split(".")):
        add("JWT (JSON Web Token)", None, None, "high")
    elif v.startswith("{SHA}") or v.startswith("{SSHA}"):
        add("LDAP SHA/SSHA", "111", "ssha", "high")
    # ── raw hex by length (medium — length is ambiguous across algorithms) ──
    elif _looks_hex(v, 32):
        add("MD5", "0", "raw-md5", "medium")
        add("NTLM", "1000", "nt", "medium")
        add("MD4", "900", "raw-md4", "low")
    elif _looks_hex(v, 40):
        add("SHA-1", "100", "raw-sha1", "medium")
    elif _looks_hex(v, 56):
        add("SHA-224", "1300", "raw-sha224", "medium")
    elif _looks_hex(v, 64):
        add("SHA-256", "1400", "raw-sha256", "medium")
    elif _looks_hex(v, 96):
        add("SHA-384", "10800", "raw-sha384", "medium")
    elif _looks_hex(v, 128):
        add("SHA-512", "1700", "raw-sha512", "medium")
    elif v.startswith("*") and _looks_hex(v[1:], 40):
        add("MySQL 4.1+ (SHA1(SHA1))", "300", "mysql-sha1", "high")
    return out


def summarize(value: str) -> str:
    """One-line human summary of the top candidates for a token."""
    cands = identify(value)
    if not cands:
        return ""
    top = ", ".join("%s (%s)" % (c["name"], c["confidence"]) for c in cands[:3])
    return top


# ── offline crack command builders (executed by tools._cmd — arg array, no shell) ──
def hashcat_cmd(hash_file: str, wordlist: str, mode: str) -> list:
    """Argument array for a straight offline dictionary attack. `-a 0` = wordlist mode.
    No rules, no network, no brute-force mask. Bounded by the wordlist the operator
    supplies. --potfile-disable keeps runs reproducible."""
    return ["hashcat", "-m", str(mode), "-a", "0", "--quiet", "--potfile-disable",
            hash_file, wordlist]


def john_cmd(hash_file: str, wordlist: str, fmt: str | None = None) -> list:
    cmd = ["john", "--wordlist=" + wordlist]
    if fmt:
        cmd.append("--format=" + fmt)
    cmd.append(hash_file)
    return cmd
