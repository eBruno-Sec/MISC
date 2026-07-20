"""
Insecure-deserialization detection.

From Bug Bounty Bootcamp (Li, Ch 14). Two layers, matching the chapter's method
and safe for authorized testing (no gadget chains are ever sent):

  1. Format detection (pure): decide whether a user-controlled value (query
     param, cookie, or token) is a serialized object — PHP `serialize()`, Java
     `ObjectInputStream` (AC ED 00 05 / base64 `rO0`), Python `pickle`, .NET
     `BinaryFormatter`, or Ruby `Marshal`. Detection works on both raw and
     base64-wrapped blobs (decode-and-inspect magic bytes, not just a prefix
     guess), so it is precise.

  2. Sink confirmation (active, non-destructive): send a CORRUPTED copy of the
     blob (one byte flipped / truncated) and look for a deserialization
     EXCEPTION signature in the response (unserialize() offset error,
     InvalidClassException, UnpicklingError, SerializationException, ...). An
     error that only appears for the mangled blob proves the value is actually
     deserialized server-side — the real vulnerability signal — without ever
     sending an RCE payload.

Pure/deterministic; unit-tested. tools._run_deserialization does the transport.
"""
from __future__ import annotations

import base64
import binascii
import re

# ── format detection ─────────────────────────────────────────────
_PHP_RE = re.compile(r'^(?:O:\d+:"[^"]*":\d+:\{|a:\d+:\{|s:\d+:"|b:[01];|i:-?\d+;|d:-?\d|N;)')


def _b64_try(value: str) -> bytes | None:
    v = (value or "").strip()
    # URL-safe or standard; tolerate missing padding
    if not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", v or "") or len(v) < 8:
        return None
    v = v.replace("-", "+").replace("_", "/")
    v += "=" * (-len(v) % 4)
    try:
        return base64.b64decode(v, validate=False)
    except (binascii.Error, ValueError):
        return None


def _magic(raw: bytes) -> str:
    """Classify raw bytes by serialization magic. '' if unknown."""
    if raw[:4] == b"\xac\xed\x00\x05":
        return "Java"
    if raw[:1] == b"\x80" and raw[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05"):
        return "Python pickle"
    if raw[:2] in (b"(d", b"(l", b"}q", b"]q"):        # pickle protocol 0/1
        return "Python pickle"
    if raw[:2] == b"\x04\x08":
        return "Ruby Marshal"
    if raw[:8] == b"\x00\x01\x00\x00\x00\xff\xff\xff":  # .NET BinaryFormatter
        return ".NET"
    return ""


def detect_format(value: str) -> dict | None:
    """Return {format, encoding, evidence} if `value` looks serialized, else None."""
    v = (value or "").strip()
    if not v:
        return None
    # PHP serialize() is text — check the raw string first
    if _PHP_RE.match(v):
        return {"format": "PHP", "encoding": "raw", "evidence": v[:40]}
    # raw binary magic (rare in a URL but possible in a cookie)
    try:
        raw_bytes = v.encode("latin-1")
        fmt = _magic(raw_bytes)
        if fmt:
            return {"format": fmt, "encoding": "raw", "evidence": raw_bytes[:6].hex()}
    except Exception:
        pass
    # base64-wrapped blob
    dec = _b64_try(v)
    if dec:
        fmt = _magic(dec)
        if fmt:
            return {"format": fmt, "encoding": "base64", "evidence": dec[:6].hex()}
        if _PHP_RE.match(dec[:40].decode("latin-1", "ignore")):
            return {"format": "PHP", "encoding": "base64", "evidence": dec[:40].decode("latin-1", "ignore")}
    return None


def find_serialized_inputs(params: dict, cookies: dict) -> list:
    """Scan query params + cookies for serialized values."""
    out = []
    for loc, bag in (("query", params or {}), ("cookie", cookies or {})):
        for name, value in bag.items():
            fmt = detect_format(value if isinstance(value, str) else str(value))
            if fmt:
                out.append({"location": loc, "name": name, "value": value, **fmt})
    return out


# ── corrupt a blob to elicit a deserialization error (no gadget) ──
def corrupt(value: str, fmt: dict) -> str:
    """Return a benign-but-malformed copy that a deserializer will choke on."""
    v = value or ""
    if fmt.get("encoding") == "base64":
        dec = _b64_try(v) or b""
        if len(dec) > 6:
            b = bytearray(dec)
            b[len(b) // 2] ^= 0xFF              # flip a middle byte
            b = b[:-1]                           # and truncate the tail
            return base64.b64encode(bytes(b)).decode()
        return v[:-2] if len(v) > 4 else v + "=="
    # raw (PHP text etc.): break the length/structure so parsing fails mid-way
    if len(v) > 6:
        return v[: len(v) // 2] + v[len(v) // 2 + 1:]  # drop a char (breaks length prefixes)
    return v + "}}}}"


# ── deserialization-exception signatures ─────────────────────────
ERROR_SIGNATURES = {
    "PHP": (r"unserialize\(\)", r"__PHP_Incomplete_Class", r"Error at offset",
            r"Cannot unserialize", r"unexpected end of serialized data"),
    "Java": (r"java\.io\.InvalidClassException", r"java\.io\.StreamCorruptedException",
             r"java\.io\.OptionalDataException", r"ObjectInputStream", r"ClassNotFoundException",
             r"invalid stream header"),
    "Python pickle": (r"UnpicklingError", r"insecure string pickle", r"unpickling stack underflow",
                      r"pickle data was truncated", r"could not find MARK", r"_pickle\."),
    ".NET": (r"BinaryFormatter", r"SerializationException", r"System\.Runtime\.Serialization",
             r"End of Stream encountered"),
    "Ruby Marshal": (r"marshal data too short", r"dump format error", r"Marshal\.load",
                     r"incompatible marshal file format"),
}
_GENERIC = (r"yaml\.load", r"ObjectInputStream", r"readObject", r"deserializ")


def analyze_errors(baseline_body: str, probe_body: str, fmt: str) -> list:
    """Signatures present for the corrupted blob but not in the baseline."""
    base = baseline_body or ""
    body = probe_body or ""
    pats = list(ERROR_SIGNATURES.get(fmt, ())) + list(_GENERIC)
    hits = []
    for p in pats:
        rx = re.compile(p, re.I)
        if rx.search(body) and not rx.search(base):
            hits.append(p.replace("\\", ""))
    return hits[:5]


# ── finding builders ─────────────────────────────────────────────
def exposure_finding(url: str, inp: dict) -> dict:
    return {
        "title": f"User-controlled {inp['format']} serialized object in {inp['location']} '{inp['name']}'",
        "severity": "medium", "target": url,
        "description": (f"The {inp['location']} value '{inp['name']}' is a {inp['format']} serialized object "
                        f"({inp['encoding']}-encoded). If the server deserializes attacker-controlled data, this is an "
                        "insecure-deserialization sink that can lead to RCE via gadget chains."),
        "impact": "Potential remote code execution / object injection if the blob is deserialized without validation.",
        "reproduction_steps": [f"Observe '{inp['name']}' carries a {inp['format']} serialized blob",
                               "Confirm the server deserializes it (corrupt it and watch for a parser error)",
                               "If confirmed, assess reachable gadget chains (ysoserial / phpggc) — do not run destructive gadgets without authorization"],
        "evidence": f"{inp['format']} ({inp['encoding']}): {inp['evidence']}",
        "cwe": "CWE-502", "family": "deserialization", "tags": ["deserialization"], "confidence": "candidate",
    }


def error_finding(url: str, inp: dict, matched: list) -> dict:
    return {
        "title": f"Insecure deserialization confirmed in {inp['location']} '{inp['name']}' ({inp['format']})",
        "severity": "high", "target": url,
        "description": (f"Corrupting the {inp['format']} blob in '{inp['name']}' produced a deserialization exception "
                        f"({', '.join(matched)}) that the untampered value did not. The server deserializes "
                        "attacker-controlled data — a confirmed insecure-deserialization sink."),
        "impact": ("Object injection and, with a reachable gadget chain, remote code execution, auth bypass, or "
                   "data tampering."),
        "reproduction_steps": [f"Send the original {inp['format']} blob in '{inp['name']}' — normal response",
                               f"Send a corrupted copy — the response leaks a deserialization error ({', '.join(matched)})",
                               "Escalate with an appropriate gadget chain only under explicit authorization"],
        "evidence": f"error signatures: {', '.join(matched)}",
        "cwe": "CWE-502", "family": "deserialization", "tags": ["deserialization", "rce"], "confidence": "confirmed",
    }
