from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlparse


SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "x-csrf-token",
}

REDACTION = "[REDACTED]"


def redact_headers(headers: Mapping[str, object] | None) -> dict[str, str]:
    """Return a string-keyed header dict with credential-bearing values removed."""
    clean: dict[str, str] = {}
    for name, value in (headers or {}).items():
        key = str(name)
        clean[key] = REDACTION if key.lower() in SENSITIVE_HEADERS else str(value)
    return clean


def render_curl(method: str, url: str, headers: Mapping[str, object] | None = None, body: str | None = None) -> str:
    method = (method or "GET").upper()
    parts = ["curl", "-i", "-X", _shell_quote(method), _shell_quote(url)]
    for name, value in redact_headers(headers).items():
        parts.extend(["-H", _shell_quote(f"{name}: {value}")])
    if body:
        parts.extend(["--data-binary", _shell_quote(body)])
    return " ".join(parts)


def render_raw_http(method: str, url: str, headers: Mapping[str, object] | None = None, body: str | None = None) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    lines = [f"{(method or 'GET').upper()} {path} HTTP/1.1"]
    if parsed.netloc and not any(str(k).lower() == "host" for k in (headers or {})):
        lines.append(f"Host: {parsed.netloc}")
    for name, value in redact_headers(headers).items():
        lines.append(f"{name}: {value}")
    lines.append("")
    if body:
        lines.append(body)
    return "\r\n".join(lines)


def render_markdown_poc(
    method: str,
    url: str,
    request_headers: Mapping[str, object] | None = None,
    request_body: str | None = None,
    response_status: int | None = None,
    response_headers: Mapping[str, object] | None = None,
    response_body: str | None = None,
) -> str:
    chunks = [
        "### Reproduction Request",
        "",
        "```bash",
        render_curl(method, url, request_headers, request_body),
        "```",
        "",
        "### Raw HTTP",
        "",
        "```http",
        render_raw_http(method, url, request_headers, request_body),
        "```",
    ]
    if response_status is not None:
        chunks.extend([
            "",
            "### Observed Response",
            "",
            "```http",
            f"HTTP/1.1 {response_status}",
        ])
        for name, value in redact_headers(response_headers).items():
            chunks.append(f"{name}: {value}")
        chunks.append("")
        if response_body:
            chunks.append(response_body)
        chunks.append("```")
    return "\n".join(chunks)


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
