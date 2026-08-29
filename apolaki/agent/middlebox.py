"""Q-112: a middlebox eating our OWN payloads is indistinguishable from a clean target.

THE DEFECT THIS EXISTS FOR, MEASURED IN THE FIELD.

The operator scanned an authorized program from his home network. Mid-scan he opened his ISP
gateway's app and found the router's own IPS dropping Apolaki's probes OUTBOUND, before they ever
left the network:

    16:50  HTTP URI Comment Characters SQL Injection was blocked
    16:50  HTTP URI 1=1 SQL Injection was blocked
    16:50  HTTP URI Equal To SQL Injection was blocked
    16:54  HTTP URI Union Select SQL Injection was blocked

Those strings are `sqli_tool`'s payloads. The report for the same run said, of the same endpoints:

    run_sqli            | executed | 70 | 0 | tested 3 param(s), 0 confirmed SQLi
    run_sqli_structural | executed | 69 | 0 | 0 structural SQLi finding(s)
    run_xpath / run_ldap / run_ssi / run_css_injection | 69 each | 0

Every one of those zeros is a BLOCKED REQUEST, not a tested parameter.

This is the Q-092 / Q-093 / Q-097 sentence one layer out: a failed attempt must not be reported as
a clean result. What is new is WHERE the failure happens. `_cmd` had an exit code to discard and
`_http` had a transport outcome to discard; here the interception is on OUR side of the wire, so
nothing inside the process sees an error at all. The request is answered by the middlebox or times
out, and the engine records a legitimate-looking zero.

THE ORACLE IS A DIFFERENTIAL, NOT A VENDOR FINGERPRINT.

Fingerprinting IPS vendors would be a signature list that ages badly and that any unlisted device
defeats silently -- the same false-clean, one layer further in. The general signal is a differential
the engines already produce, and ALL THREE clauses are required:

  1. a benign request to the host SUCCEEDS, and
  2. EVERY payload-bearing request to that host fails at the transport (no response at all), and
  3. the pattern holds across UNRELATED hosts.

Clause 3 is the whole discriminator and the reason this module exists rather than a per-engine
check. ONE host behaving this way is a WAF or a tarpit on the target: that is a FINDING ABOUT THE
TARGET, and reporting it as our own middlebox would be a false alarm on every well-defended site we
ever test. The SAME behaviour across unrelated hosts cannot be a property of any one target, so it
is a FACT ABOUT THE RUN, and it voids every injection result the run produced.

DELIBERATELY OUT OF SCOPE, and this is a limit, not an oversight:

  * A response is a response. A 403 block page counts as `ok` here. Without vendor fingerprinting a
    403 from an inline WAF is indistinguishable from the app's own refusal, and either way it is a
    fact about the target rather than about our uplink. Only a request that got NO response at all
    -- reset, timeout, DNS/connect failure -- counts as a failure for this oracle.
  * Consequently this module cannot see a middlebox that answers instead of dropping. That is
    stated in the handoff rather than papered over with a guess.

PURE BY CONSTRUCTION. No HTTP, no I/O, no sockets, no clock, nothing but stdlib string handling, so
the differential is one testable unit and the negative controls are cheap. `tools.py` feeds it
recorded outcomes and reads the verdict; this module never sends anything.
"""
from urllib.parse import unquote_plus

#: How many payload-bearing requests to one host must have failed before that host is even a
#: candidate. Below this, "every payload request failed" is one or two requests and any flaky
#: link produces it.
MIN_PAYLOAD_ATTEMPTS = 3

#: How many UNRELATED registrable domains must show the pattern before the verdict flips. TWO is
#: the minimum that can distinguish "a property of that target" from "a property of our uplink";
#: at one, this would be a WAF detector wearing a middlebox label.
MIN_UNRELATED_DOMAINS = 2

#: Substrings that mark a request as payload-bearing when the caller does not say. Matched against
#: the URL and body after percent-decoding and lowercasing, because `xt.set_param` percent-encodes
#: everything an injection payload is made of (`1=1` goes out as `1%3D1`) and a matcher that skipped
#: the decode would classify every real payload as benign -- which would empty the payload bucket and
#: silently disable this whole module.
#:
#: CONTENT-BASED AND NOT ENGINE-BASED, which is the correct split rather than a convenience. The
#: middlebox decides by inspecting the URI, so "requests that look like an attack" is exactly the set
#: it drops. An engine-based split ("everything _run_cmdi sent is a payload") would be WRONG in both
#: directions: `_run_nosqli`'s deliberate benign control and `cmdi_tool.argv_payloads`' bare `id`
#: carry nothing an IPS matches, sail straight through, and would land in the payload bucket as a
#: success -- suppressing the verdict for the whole host.
#:
#: GENEROUS WITHIN THAT, and the asymmetry is the reason. Marking a benign request as payload-bearing
#: can only SUPPRESS the verdict (a success in the payload bucket sets `payload_ok > 0`, failing
#: clause 2). Missing a real payload is the dangerous direction: it puts a dropped probe in the
#: benign bucket, where it looks like the control failing. So when in doubt, mark it.
PAYLOAD_MARKERS = (
    # SQL -- the four families the operator's own IPS log named, plus the usual blind oracles
    "1=1", "1=2", "'1'='1", "'1'='2", "union select", "union all select",
    "' or ", "' and ", '" or ', '" and ', " or 1", " and 1",
    "-- -", "--+", "/*", "*/", "@@version", "information_schema",
    "sleep(", "pg_sleep", "waitfor delay", "benchmark(", "extractvalue(", "updatexml(",
    # bare quote/backtick breaks: sqli_tool.ERROR_PROBES and xpath_tool.probes are exactly these
    "'", '"', "`",
    # XPath / LDAP filter metacharacters (xpath_tool.probes, ldap_tool.probes)
    "]|//*[", "count(/", "string-length(", "substring(", "*)(", ")(", "|(", "(&(",
    # SSI (ssi_tool.payload) and template injection
    "<!--#", "{{", "${",
    # command injection: the separator+command shapes cmdi_tool actually emits, and the classic
    # read target. `cmdi_tool.output_payloads` builds "; echo", "| echo", "& echo", "`echo",
    # "$(echo", "%0aecho", "; id"; `time_payloads` builds the same separators with sleep/ping.
    "$(", "$((", "&&", "; echo", "| echo", "& echo", "; id", "|id", ";id",
    "sleep ", ";sleep", "|sleep", "echo ", "curl ", "wget ", "ping -", "/etc/passwd", "%0a",
    # NoSQL operators (nosqli_tool.set_operator_param)
    "[$ne]", "[$gt]", "[$regex]", "$where", '{"$',
    # XSS / CSS injection carriers
    "<script", "onerror=", "javascript:", "</style", "@import",
    # traversal
    "../", "..\\",
)

#: Second-level suffixes under which two names are NOT related. Small and deliberately incomplete:
#: every entry here makes more host pairs count as UNRELATED, which is the direction that produces
#: false alarms, so this list stays at the classic ccTLD registries rather than growing to a full
#: public-suffix list. A missing entry can only make the check more conservative.
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "co.nz", "co.za", "co.in", "co.kr", "co.il", "co.th",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tr", "com.hk", "com.tw",
    "net.au", "org.au", "org.nz",
})


def host_of(url: str) -> str:
    """The host a URL addresses, lowercased, WITHOUT the port.

    Port-stripped because a middlebox filters by content, not by port: two ports on one machine are
    one host for this purpose, and treating them as two would let a single local target satisfy the
    unrelated-hosts clause on its own. A scheme is optional, so a bare `example.com/a?b=c` is still
    attributed rather than discarded. Anything unparseable yields "" and its record is DROPPED
    rather than filed under a made-up host.

    HAND-PARSED RATHER THAN `urlsplit` ON PURPOSE. `urlsplit` raises ValueError on a malformed IPv6
    authority, and this runs on the transport path, so the alternative is a handler that swallows
    and returns a literal -- inside the fix for silent swallows, which is the exact trap this ticket
    is about (and which the repository's own swallow census would rightly count against it). Plain
    string slicing has no failure mode to hide.
    """
    s = (url or "").strip()
    i = s.find("://")
    if i >= 0:
        s = s[i + 3:]
    for sep in ("/", "?", "#"):
        j = s.find(sep)
        if j >= 0:
            s = s[:j]
    at = s.rfind("@")                      # strip userinfo
    if at >= 0:
        s = s[at + 1:]
    if s.startswith("["):                  # IPv6 literal keeps its brackets, drops any port
        end = s.find("]")
        return (s[:end + 1] if end > 0 else s).lower()
    colon = s.find(":")
    if colon >= 0:
        s = s[:colon]
    if " " in s:
        return ""
    return s.strip(".").lower()


def registrable(host: str) -> str:
    """The name two hosts must SHARE to count as related.

    An approximation of the registrable domain: the last two labels, or three when the last two are
    a known ccTLD registry suffix. IP literals and single-label names (localhost, a docker service
    name) are their own domain.

    This is where "unrelated" is decided, so it errs toward RELATED. Under-splitting merges two
    hosts that a full public-suffix list would separate, and merging can only suppress the verdict.
    """
    h = (host or "").lower().strip(".")
    if not h:
        return ""
    if h.replace(".", "").isdigit() or ":" in h:          # IPv4 literal / IPv6 form
        return h
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    if ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def looks_payload_bearing(url: str, body=None) -> bool:
    """Does this request CARRY an attack payload?

    Content-based, because the middlebox's decision is content-based: it matched `1=1` in a URI, not
    the engine that sent it. Callers that KNOW (an engine that built the probe itself) should say so
    explicitly instead of relying on this -- `Ledger.record(payload_bearing=...)` takes precedence.
    """
    text = "%s\n%s" % (url or "", _as_text(body))
    # Two decode passes: `xt.set_param` encodes once, and a payload that already contained a percent
    # sequence comes out double-encoded. Two is enough for everything this codebase emits.
    for _ in range(2):
        nxt = unquote_plus(text)
        if nxt == text:
            break
        text = nxt
    low = text.lower()
    return any(m in low for m in PAYLOAD_MARKERS)


def _as_text(body) -> str:
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        return body.decode("utf-8", "replace")
    if isinstance(body, dict):
        return " ".join("%s=%s" % (k, v) for k, v in body.items())
    return str(body)


def _blank_host(host: str) -> dict:
    return {"host": host, "domain": registrable(host),
            "benign_ok": 0, "benign_fail": 0, "payload_ok": 0, "payload_fail": 0,
            "sample": ""}


class Ledger:
    """Per-host tallies of recorded request outcomes. Append-only, total, and never raises.

    `record` is called from the transport paths, so it must not be able to break a scan. That is a
    requirement on THIS code (no branch in it can raise), not a licence for the caller to wrap it in
    `try/except: pass` -- a swallowed recorder is the exact bug this ticket exists to fix.
    """

    __slots__ = ("hosts", "records")

    def __init__(self):
        self.hosts = {}
        self.records = 0

    def record(self, url: str, ok: bool, payload_bearing=None, body=None, note: str = "") -> None:
        """Book ONE request outcome.

        `ok` is TRANSPORT-level: True when a response came back at all, whatever its status. A 403
        block page is `ok=True` on purpose -- see the module docstring.
        `payload_bearing=None` means "classify by content"; True/False from a caller that knows wins.
        """
        host = host_of(url)
        if not host:
            return                    # never file a record under an invented host
        pb = looks_payload_bearing(url, body) if payload_bearing is None else bool(payload_bearing)
        st = self.hosts.get(host)
        if st is None:
            st = self.hosts[host] = _blank_host(host)
        key = ("payload_" if pb else "benign_") + ("ok" if ok else "fail")
        st[key] += 1
        self.records += 1
        if pb and not ok and not st["sample"]:
            st["sample"] = (note or str(url))[:200]

    def stats(self) -> list:
        """A COPY of the per-host tallies, so `assess` cannot mutate the ledger it reads."""
        return [dict(v) for v in self.hosts.values()]


class Verdict:
    """The answer, plus everything needed to argue with it."""

    __slots__ = ("intercepted", "hosts", "domains", "suspect_hosts", "reason")

    def __init__(self, intercepted, suspect_hosts, domains, reason):
        self.intercepted = bool(intercepted)
        self.suspect_hosts = list(suspect_hosts)
        self.hosts = list(suspect_hosts)          # alias: the hosts the verdict is about
        self.domains = list(domains)
        self.reason = reason

    def __repr__(self):
        return "Verdict(intercepted=%r, hosts=%r, reason=%r)" % (
            self.intercepted, self.hosts, self.reason)

    def note(self) -> str:
        """The line an engine appends to its output. Empty when nothing was intercepted, so a caller
        can use it directly as both the flag and the text."""
        if not self.intercepted:
            return ""
        return (" -- DEGRADED: injection payloads were INTERCEPTED UPSTREAM, on our side of the "
                "wire. %s These injection results are VOID: they are blocked requests, NOT tested "
                "parameters. Re-run over a path that does not filter (VPN/tunnel) before reading "
                "any zero here as a clean target." % self.reason)


def _is_suspect(st: dict) -> bool:
    """Clauses 1 and 2 for ONE host: the benign control works and every payload request died."""
    return (st.get("benign_ok", 0) >= 1
            and st.get("benign_ok", 0) >= st.get("benign_fail", 0)
            and st.get("payload_fail", 0) >= MIN_PAYLOAD_ATTEMPTS
            and st.get("payload_ok", 0) == 0)


def assess(stats) -> Verdict:
    """THE differential. Pure function over recorded outcomes -- no HTTP, no state, no clock.

    Returns a Verdict whose `intercepted` is True only when the pattern holds on at least
    MIN_UNRELATED_DOMAINS unrelated registrable domains. One domain is a WAF on the target and is
    reported as such (`intercepted=False`, `suspect_hosts` non-empty) rather than escalated.
    """
    suspects = [s for s in (stats or []) if _is_suspect(s)]
    suspects.sort(key=lambda s: (s.get("domain", ""), s.get("host", "")))
    domains = []
    for s in suspects:
        d = s.get("domain") or s.get("host") or ""
        if d and d not in domains:
            domains.append(d)
    hosts = [s.get("host", "") for s in suspects]
    if len(domains) < MIN_UNRELATED_DOMAINS:
        why = ""
        if suspects:
            why = ("%d host(s) dropped every payload (%s) but they share one registrable domain, so "
                   "this is a defence on the TARGET, not on our uplink"
                   % (len(suspects), ", ".join(hosts)))
        return Verdict(False, hosts, domains, why)
    detail = "; ".join("%s %d/%d payload requests failed while %d benign request(s) succeeded"
                       % (s.get("host", ""), s.get("payload_fail", 0),
                          s.get("payload_fail", 0) + s.get("payload_ok", 0),
                          s.get("benign_ok", 0))
                       for s in suspects)
    reason = ("On %d UNRELATED hosts (%s) every payload-bearing request failed at the transport "
              "while benign requests to the same hosts succeeded -- %s. No single target can cause "
              "that, so the filter is between us and them."
              % (len(domains), ", ".join(domains), detail))
    return Verdict(True, hosts, domains, reason)
