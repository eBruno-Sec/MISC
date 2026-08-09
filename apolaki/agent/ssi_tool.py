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

# WE SET THE FORMAT RATHER THAN GUESSING IT. The old oracle required a month ABBREVIATION in the output,
# which is only present under the DEFAULT timefmt. A server configured with a numeric format —
# `2026-08-09 17:42:01` is entirely ordinary — executed the directive and still failed confirmation: a
# false negative caused by the oracle assuming a server setting it had no reason to assume.
#
# `#config timefmt` is part of the same SSI vocabulary as `#echo` (Apache mod_include, nginx, IIS), so we
# can declare the format we want and then require exactly that shape back. %Y-%j (year + day-of-year) is
# used because it cannot be confused with an ordinary date already on the page, and the token makes the
# whole string unique per request.
_FMT_PREFIX = "APO"


def _fmt_directive(token: str) -> str:
    return '<!--#config timefmt="%s-%s-%%Y-%%j" -->' % (_FMT_PREFIX, token)


def _expanded_re(token: str):
    """What an EXECUTED directive must produce: our prefix+token, then a real year and day-of-year."""
    return re.compile(r"%s-%s-((?:19|20)\d{2})-(\d{1,3})\b" % (_FMT_PREFIX, re.escape(token)))


# Legacy fallback: a server that ignores #config but honours #echo still renders the default format.
# Kept so the format-setting change can only ADD confirmations, never remove one.
_DATE_RE = re.compile(r"\b(19|20)\d{2}\b")
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")


def marker(token: str) -> str:
    return "mk%smk" % token


def payload(token: str) -> str:
    """The injection value: benign #echo directive sandwiched between two copies of the unique marker."""
    m = marker(token)
    return m + _fmt_directive(token) + _DIRECTIVE + m


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
    # The raw format string coming back means it was REFLECTED, not expanded — never a confirmation.
    if "%Y" in mid or "%j" in mid:
        return {"confirmed": False, "oracle": ""}
    # PRIMARY: the format we asked the server to adopt, expanded. Format-independent by construction, and
    # the token makes it unforgeable — nothing but SSI expansion puts APO-<token>-YYYY-DDD in the body.
    exp = _expanded_re(token).search(mid)
    if exp:
        year, doy = int(exp.group(1)), int(exp.group(2))
        if 1 <= doy <= 366:
            return {"confirmed": True,
                    "oracle": "the SSI directives #config timefmt + #echo var=\"DATE_GMT\" were EXECUTED: "
                              "the server adopted our requested time format and rendered '%s' (year %d, "
                              "day-of-year %d) between our unique markers. The literal format string "
                              "%%Y-%%j is absent, so this is expansion and not reflection."
                              % (exp.group(0), year, doy)}
    # FALLBACK: a server that ignores #config but honours #echo still emits the default format.
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
