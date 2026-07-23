"""
File-upload abuse testing (CWE-434 unrestricted upload of a dangerous file type).

Non-destructive: every payload is a small, INERT canary — never real shell code
that could execute meaningfully if a filter is bypassed. The goal is proving the
FILTER can be bypassed, not achieving code execution.

Method (mirrors PortSwigger Academy's file-upload lab methodology):

  1. CONTROL — upload an obviously-blocked extension (.exe) with plain content.
     If the app has no filtering at all, this is accepted too (informational —
     "no upload restrictions observed" is itself worth flagging as a lead, not a
     confirmed bypass, since nothing was actually bypassed).

  2. BYPASS VARIANTS — a server-executable extension (.php/.asp/.jsp/.phtml)
     disguised via: double extension (shell.php.jpg), null byte (shell.php%00.jpg),
     case variation (shell.pHp), trailing semicolon (shell.php;.jpg), and a
     magic-byte prefix (GIF89a) so a naive image-signature check also passes.

  3. VERDICT — CONFIRMED only when the CONTROL was rejected (proving a filter
     exists) AND a BYPASS variant carrying a dangerous extension was accepted —
     that is a real, provable filter bypass. If the control is also accepted,
     there is no filter to bypass and this is downgraded to an informational
     lead ("no upload restriction observed"), never invented as a bypass.

Acceptance/rejection is read from the response: explicit success/failure
keywords, JSON status fields, a 2xx/3xx with a returned file URL, or a 4xx.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin


class _UploadFormParser(HTMLParser):
    """Finds <form> elements carrying a file <input> — a candidate upload
    endpoint. Mirrors csrf_tool._FormParser's style, but also tracks enctype
    and input `type` so a non-file field name (used as the multipart field to
    inject the payload under) can be picked correctly."""
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"method": a.get("method", "get").lower(), "action": a.get("action", ""),
                        "enctype": a.get("enctype", "").lower(), "file_field": None, "other_fields": []}
        elif tag == "input" and self._cur is not None and a.get("name"):
            if a.get("type", "text").lower() == "file":
                self._cur["file_field"] = a["name"]
            else:
                self._cur["other_fields"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            if self._cur.get("file_field"):
                self.forms.append(self._cur)
            self._cur = None


def find_upload_forms(html: str, base_url: str = "") -> list:
    """Forms with a file input — {method, action, enctype, file_field, other_fields}."""
    p = _UploadFormParser()
    try:
        p.feed(html or "")
    except Exception:
        pass
    out = []
    for f in p.forms:
        action = urljoin(base_url, f["action"]) if (base_url and f["action"]) else (f["action"] or base_url)
        out.append({"method": (f["method"] or "post").upper(), "action": action,
                    "enctype": f["enctype"], "file_field": f["file_field"], "other_fields": f["other_fields"]})
    return out

# tiny inert payload — a comment only, never functional shell code
CANARY_BODY_TPL = "APOLAKI-UPLOAD-TEST-{token} (inert marker; safe non-executing content)"
GIF_MAGIC = b"GIF89a"  # 1x1 GIF header so a naive image-signature sniff passes

DANGEROUS_EXTS = ("php", "phtml", "php5", "php7", "pht", "asp", "aspx", "jsp", "jspx")
BLOCKED_CONTROL_EXT = "exe"

_REJECT_RE = re.compile(
    r"\b(?:not allowed|forbidden|invalid (?:file|type|extension)|unsupported (?:file|type)|"
    r"file type|extension is not|rejected|blocked|denied|disallowed)\b", re.IGNORECASE)
_ACCEPT_RE = re.compile(r'"(?:success|ok|uploaded)"\s*:\s*true|"status"\s*:\s*"(?:ok|success)"', re.IGNORECASE)
_URL_RE = re.compile(r'"(?:url|path|location|file(?:name|Url)?)"\s*:\s*"([^"]+)"', re.IGNORECASE)


def bypass_filenames(base: str = "apolaki") -> list:
    """(filename, ext_that_would_actually_execute) pairs, image-input field name
    hints excluded — these are FILENAMES only, the caller sets the multipart part."""
    out = []
    for ext in DANGEROUS_EXTS[:3]:                      # bounded — keep the probe fast
        out.append((f"{base}.{ext}.jpg", ext))           # double extension
        out.append((f"{base}.{ext.upper()[0]}{ext[1:]}", ext))  # case variation, e.g. .pHp
        out.append((f"{base}.{ext};.jpg", ext))           # trailing semicolon (legacy Apache)
    return out[:6]


def verdict(control_status: int, control_body: str,
           bypass_status: int, bypass_body: str) -> str:
    """'accepted' | 'rejected' for one upload attempt, from status + body signals."""
    body = bypass_body if bypass_status else control_body
    rejected_kw = bool(_REJECT_RE.search(bypass_body or ""))
    if bypass_status and bypass_status >= 400:
        return "rejected"
    if rejected_kw:
        return "rejected"
    if bypass_status in (200, 201, 202, 302) or _ACCEPT_RE.search(bypass_body or ""):
        return "accepted"
    return "rejected"


def extract_url(body: str) -> str:
    m = _URL_RE.search(body or "")
    return m.group(1) if m else ""


def multipart_body(file_field: str, filename: str, file_content: str,
                   other_fields: list = None, content_type: str = "image/gif") -> tuple:
    """(headers, body_str) for a manually-built multipart/form-data request — gives
    exact control over filename/Content-Type per part, which httpx's `files=` param
    does not expose as precisely when a filter check depends on both."""
    boundary = "ApolakiUploadBoundary7f3c9a"
    parts = []
    for name in (other_fields or []):
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n1\r\n')
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        f'Content-Type: {content_type}\r\n\r\n{file_content}\r\n')
    parts.append(f'--{boundary}--\r\n')
    body = "".join(parts)
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return headers, body


def _base(field: str, filename: str, ext: str) -> dict:
    return {
        "title": f"Unrestricted file upload — extension-filter bypass ('{filename}')",
        "severity": "critical", "target": filename,
        "description": (f"The upload endpoint rejected a plainly-blocked file (.{BLOCKED_CONTROL_EXT}), proving a "
                        f"filter exists, but accepted '{filename}' — a filename crafted to disguise a "
                        f".{ext} (server-executable) extension. The filter can be bypassed."),
        "impact": ("An attacker can upload a server-side script (webshell) and, if it lands in a web-servable "
                   "directory and the server maps execution by any recognised extension in the filename, "
                   "achieve remote code execution on the host."),
        "reproduction_steps": [
            f"Confirm a plain .{BLOCKED_CONTROL_EXT} upload is rejected (baseline filter check)",
            f"Upload a file named '{filename}' with image-shaped content (GIF89a header)",
            "Observe the upload is ACCEPTED despite carrying a disguised server-executable extension",
            "If the returned path is web-servable, verify manually whether the extension is honoured for execution"],
        "evidence": f"Control (.{BLOCKED_CONTROL_EXT}) rejected; '{filename}' accepted",
        "cwe": "CWE-434", "family": "upload", "tags": ["upload", "cwe-434"],
        "confidence": "confirmed", "field": field,
    }


def bypass_finding(field: str, filename: str, ext: str, upload_url: str = "") -> dict:
    f = _base(field, filename, ext)
    if upload_url:
        f["description"] += f" The server returned a retrievable location: {upload_url}"
        f["reproduction_steps"].insert(3, f"Fetch the returned location ({upload_url}) to confirm it is served")
    return f


def no_restriction_lead(field: str) -> dict:
    """The blocked-extension CONTROL itself was accepted — there is no filter to
    bypass, so this is an observation (no confirmed bypass happened), not a finding."""
    return {
        "title": "No file-extension restriction observed on upload endpoint",
        "severity": "medium", "confidence": "candidate", "family": "upload",
        "description": (f"An upload with a plainly dangerous extension (.{BLOCKED_CONTROL_EXT}) was accepted "
                        "without any extension filtering being observed. This is a lead, not a confirmed "
                        "bypass — no filter was actually defeated because none was detected."),
        "field": field, "tags": ["upload", "cwe-434", "lead"],
    }
