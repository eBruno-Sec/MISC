"""Server-Side Includes (SSI) injection engine (CWE-97), distilled from *Beginner Web Application Pentester*
(Ali Abdollahi, "Testing for SSI injection"). A server with SSI enabled processes directives like
`<!--#echo var="DATE_GMT" -->` embedded in a page BEFORE serving it. If user input reaches an SSI-parsed
response unsanitised, the server executes the injected directive.

CONFIRMATION IS NON-DESTRUCTIVE + DETERMINISTIC — the whole point. We inject ONLY the benign `#echo
var="DATE_GMT"` directive (never `#exec cmd`, which would be RCE), wrapped in two copies of a unique random
marker: `MK…<!--#echo var="DATE_GMT" -->…MK`. In the response the text BETWEEN the two markers is:
  - the LITERAL directive           -> reflected, NOT executed          -> not vulnerable
  - an HTML-ENCODED directive        -> output-encoded, NOT executed     -> not vulnerable (still has #echo)
  - a DATE string                    -> the server EXECUTED the include  -> CONFIRMED
Because we own both markers (random), nothing but SSI execution can place a real date between them, so this
does not false-positive on ordinary reflection. Pure logic here (payload + oracle + finding); HTTP in tools.
"""
from __future__ import annotations

import re

# The benign, read-only directive we inject. DATE_GMT is a standard SSI variable present on every SSI server
# (Apache mod_include, nginx SSI, IIS), so a positive result does not depend on server-specific vars, and it
# NEVER runs a command (unlike #exec) — safe to fire on a live target.
_DIRECTIVE = '<!--#echo var="DATE_GMT" -->'

# A DATE_GMT render always carries a 4-digit year and (in the default timefmt) a month abbrev / time. We
# require a year so a stray reflected number can't confirm; the marker sandwich already rules out coincidence.
_DATE_RE = re.compile(r"\b(19|20)\d{2}\b")
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")


def marker(token: str) -> str:
    return "mk%smk" % token


def payload(token: str) -> str:
    """The injection value: benign #echo directive sandwiched between two copies of the unique marker."""
    m = marker(token)
    return m + _DIRECTIVE + m


def _between(body: str, token: str) -> str:
    """The text the server produced BETWEEN our two markers, or '' if the sandwich isn't intact."""
    m = re.escape(marker(token))
    hit = re.search(m + r"(.*?)" + m, body or "", re.S | re.I)
    return hit.group(1) if hit else ""


def evaluate(body: str, token: str) -> dict:
    """Confirmed ONLY when the text between our markers is a DATE (the executed directive) rather than the
    literal or HTML-encoded directive. Non-destructive: we only ever asked the server to echo its own date."""
    mid = _between(body, token)
    if not mid:
        return {"confirmed": False, "oracle": ""}
    low = mid.lower()
    # still contains the directive (literal reflection) or an encoded copy -> NOT executed
    if "#echo" in low or "<!--" in low or "&lt;!--" in low:
        return {"confirmed": False, "oracle": ""}
    if _DATE_RE.search(mid) and any(mo in low for mo in _MONTHS):
        got = mid.strip()[:60]
        return {"confirmed": True, "oracle": "the SSI directive #echo var=\"DATE_GMT\" was executed by the "
                "server and replaced with a live date ('%s') between our unique markers" % got}
    return {"confirmed": False, "oracle": ""}


def finding(url: str, where: str, param: str, oracle: str) -> dict:
    return {
        "title": "Server-Side Includes (SSI) injection in %s '%s'" % (where, param),
        "severity": "high", "family": "ssi_injection", "confidence": "confirmed", "target": url,
        "cwe": "CWE-97", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "cvss_score": 9.1,
        "evidence": ("The %s '%s' is written into an SSI-parsed response unsanitised. A benign "
                     "`#echo var=\"DATE_GMT\"` directive was executed by the server. %s" % (where, param, oracle)),
        "success_oracle": oracle,
        "reproduction_steps": [
            "Inject `%s` into '%s' (a benign date echo wrapped in unique markers)." % (_DIRECTIVE, param),
            "The server returns a live date between the markers instead of the literal directive.",
            "Escalate risk: an unrestricted server also honours `<!--#include file=...-->` (file read) and, "
            "if the exec directive is enabled, `<!--#exec cmd=...-->` (command execution) — do NOT fire those."],
        "impact": ("SSI injection lets an attacker read server files via `#include` and, where the exec directive "
                   "is enabled, run OS commands (`#exec cmd`) — a path to full server compromise."),
        "remediation": ("Disable the SSI exec directive (Options -Includes / IncludesNOEXEC); never write "
                        "user input into SSI-parsed pages; context-encode `<`, `!`, `-`, `#` before output."),
        "tags": ["ssi", "injection", "cwe-97"],
    }
