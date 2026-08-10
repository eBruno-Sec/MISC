"""Discovery of CUSTOM REQUEST-HEADER inputs (CWE-20 delivery vector, not a vulnerability class).

An app that routes a value through a request header instead of a query param or a form field is
invisible to every engine that only rewrites URLs and bodies: the payload never arrives, the response
never changes, and the endpoint is reported clean. This is common in SPAs and APIs -- tenant ids, user
ids, trace context and feature flags all travel in `X-…` headers -- and it is a DELIVERY gap, so the
existing oracles confirm normally once the header is actually sent.

Discovery is deliberately generic. Three signals, none of them tied to any particular application:

  1. `xhr.setRequestHeader("Name", …)` with a literal name, in inline or same-origin script text.
  2. An attribute whose NAME carries "header" (`data-header`, `data-header-name`, `header-name`) --
     the conventional way markup declares one.
  3. An element whose attribute VALUE announces a header-submitting action (any value containing
     "header", e.g. method="submitHeaderForm"); the element's own identifying token is then the header
     name. This is what catches the dynamic case `setRequestHeader(tok, value)` where the literal never
     appears in the script at all.

Pure: no network, no browser. The caller sends the probes.
"""
from __future__ import annotations

import re

# Header names we must never invent traffic for: hop-by-hop, auth, or ones whose rewriting would change
# the meaning of the request rather than test the app. Cookie has its own engine.
_SKIP = {"content-type", "content-length", "host", "connection", "accept", "accept-encoding",
         "accept-language", "user-agent", "referer", "origin", "cookie", "authorization",
         "transfer-encoding", "upgrade", "te", "trailer", "expect"}
_VALID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$")
_SET_HDR = re.compile(r"""setRequestHeader\s*\(\s*['"]([A-Za-z0-9_-]{2,64})['"]""")
_ATTR_NAMED_HEADER = re.compile(r"""\b[\w-]*header[\w-]*\s*=\s*["']([^"']{2,64})["']""", re.I)
_TAG = re.compile(r"<[a-zA-Z][^>]{0,2000}>")
_ATTRS = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
# Tokens that identify an element; the first that looks like a header name wins for signal 3.
_ID_ATTRS = ("data-header-name", "data-header", "testcase", "data-testid", "name", "id")


def _attrs(tag: str) -> dict:
    out = {}
    for m in _ATTRS.finditer(tag):
        out[m.group(1).lower()] = m.group(2) or m.group(3) or m.group(4) or ""
    return out


def _ok(name: str) -> bool:
    n = (name or "").strip()
    return bool(_VALID.match(n)) and n.lower() not in _SKIP


def discover_header_names(html: str, scripts: str = "") -> list:
    """Candidate custom request-header names for this page, most explicit first, de-duplicated."""
    found, seen = [], set()

    def add(n):
        n = (n or "").strip()
        if _ok(n) and n.lower() not in seen:
            seen.add(n.lower())
            found.append(n)

    blob = (html or "") + "\n" + (scripts or "")
    for m in _SET_HDR.finditer(blob):                       # 1) explicit literal
        add(m.group(1))
    for m in _ATTR_NAMED_HEADER.finditer(html or ""):       # 2) attribute NAMED like a header
        add(m.group(1))
    for tag in _TAG.findall(html or ""):                    # 3) element declaring a header action
        a = _attrs(tag)
        if not any("header" in str(v).lower() for v in a.values()):
            continue
        for key in _ID_ATTRS:
            if a.get(key) and _ok(a[key]):
                add(a[key])
                break
    return found
