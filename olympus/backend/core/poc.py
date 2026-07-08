"""Proof-of-concept rendering.

Turns a captured HTTP exchange + finding into copy-ready reproduction (curl,
raw HTTP) and a Markdown PoC block suitable for HackerOne / Bugcrowd / Intigriti
submissions or client reports.

Pure functions over plain dicts: no DB, no network, trivially unit-testable.
"""
from shlex import quote
from urllib.parse import urlparse

SENSITIVE_HEADERS = {
    "cookie", "authorization", "set-cookie", "x-api-key",
    "x-auth-token", "proxy-authorization", "x-csrf-token",
}
REDACTED = "<redacted>"

# httpx adds these; curl/the raw request sets them itself.
_SKIP_CURL_HEADERS = {"host", "content-length"}


def redact_headers(headers: dict) -> dict:
    """Mask credential-bearing header values while keeping the header names, so a
    PoC still shows that auth is required without leaking the session."""
    out = {}
    for k, v in (headers or {}).items():
        out[k] = REDACTED if str(k).lower() in SENSITIVE_HEADERS else v
    return out


def to_curl(ex: dict, redact: bool = True) -> str:
    """Render a captured exchange as a copy-pasteable curl command."""
    method = (ex.get("method") or "GET").upper()
    url = ex.get("url") or ""
    headers = ex.get("request_headers") or {}
    if redact:
        headers = redact_headers(headers)
    parts = ["curl -i -sk"]
    if method != "GET":
        parts.append("-X " + method)
    for k, v in headers.items():
        if str(k).lower() in _SKIP_CURL_HEADERS:
            continue
        parts.append("-H " + quote(f"{k}: {v}"))
    body = ex.get("request_body")
    if body:
        parts.append("--data " + quote(body))
    parts.append(quote(url))
    return " ".join(parts)


def to_raw_http(ex: dict, redact: bool = True) -> str:
    """Render a captured exchange as a raw HTTP/1.1 request block."""
    method = (ex.get("method") or "GET").upper()
    url = ex.get("url") or ""
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    headers = ex.get("request_headers") or {}
    if redact:
        headers = redact_headers(headers)
    lines = [f"{method} {path} HTTP/1.1"]
    if p.netloc:
        lines.append(f"Host: {p.netloc}")
    for k, v in headers.items():
        if str(k).lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    body = ex.get("request_body") or ""
    return ("\n".join(lines) + "\n\n" + body).rstrip()


def finding_markdown(finding: dict, exchanges: list = None, redact: bool = True) -> str:
    """Build a copy-ready Markdown PoC block for one finding."""
    exchanges = exchanges or []
    title = finding.get("title") or "Untitled finding"
    sev = (finding.get("severity") or "info").upper()

    lines = [f"## {title}", ""]
    meta = [f"**Severity:** {sev}"]
    if finding.get("cvss_score") is not None:
        meta.append(f"**CVSS:** {finding['cvss_score']}")
    if finding.get("found_by"):
        meta.append(f"**Source:** {finding['found_by']}")
    lines += ["  |  ".join(meta), ""]

    urls = list(dict.fromkeys(e.get("url") for e in exchanges if e.get("url")))
    if urls:
        lines.append("**Affected endpoint(s):**")
        lines += [f"- `{u}`" for u in urls]
        lines.append("")

    if finding.get("description"):
        lines += ["### Summary", finding["description"], ""]

    lines += ["### Steps to reproduce", ""]
    if exchanges:
        for i, ex in enumerate(exchanges, 1):
            note = f" ({ex['notes']})" if ex.get("notes") else ""
            lines += [f"{i}. Send the request below{note}:", "",
                      "```bash", to_curl(ex, redact), "```", ""]
            lines += ["<details><summary>Raw HTTP request</summary>", "",
                      "```http", to_raw_http(ex, redact), "```", "</details>", ""]
            resp = ex.get("response_body")
            if resp:
                lines += [f"Observed response (HTTP {ex.get('status_code', '?')}):", "",
                          "```", resp[:1500], "```", ""]
    else:
        ev = finding.get("evidence")
        if ev:
            lines += ["```", ev, "```", ""]
        else:
            lines += ["_No captured request/response; see finding evidence._", ""]

    if finding.get("remediation"):
        lines += ["### Remediation", finding["remediation"], ""]

    if redact and exchanges:
        lines += ["> Sensitive headers (Cookie/Authorization) are redacted. "
                  "Replace them with a valid authorized session to reproduce.", ""]
    return "\n".join(lines)


def mission_markdown(target: str, findings: list, exchanges_by_finding: dict,
                     redact: bool = True) -> str:
    """Assemble a full-mission Markdown PoC report from findings + evidence."""
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: sev_rank.get((f.get("severity") or "info").lower(), 5))
    counts = {}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        counts[s] = counts.get(s, 0) + 1

    head = [f"# Security Assessment — {target}", "",
            "**Findings:** " + ", ".join(f"{counts.get(s, 0)} {s}"
            for s in ("critical", "high", "medium", "low", "info")), "", "---", ""]
    body = []
    for f in findings:
        body.append(finding_markdown(f, exchanges_by_finding.get(f.get("id"), []), redact))
        body.append("\n---\n")
    return "\n".join(head + body).rstrip() + "\n"
