"""
Scope enforcement engine + multi-format scope-file parsing.

Enforces scope at the tool-wrapper level (deny-overrides-allow, wildcard match)
and parses program scope from HackerOne / Bugcrowd CSV, Burp JSON, and
section/prefix/markdown plain-text. The parser is adapted from OLYMPUS
routers/scope.py; the engine keeps Apolaki's original wildcard semantics and adds a
structured-rules view for web_security.is_url_in_scope.
"""
import csv
import io
import json
import posixpath
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class PermissionLevel(Enum):
    """What an engine DOES TO THE TARGET. The operator's consent axis, and only that.

    This is the answer to "which tier does my new engine belong in", and it is decided by ONE
    question: **does the engine change the target's state?** Not how loud it is, not how slow it
    is, not how alarming the payload looks in a log.

      PASSIVE     Observes. Sends NOTHING to the target. Third-party sources (crt.sh, wayback,
                  DNS, GitHub), offline computation over data already in hand (hash
                  identification, dork generation, decoding a SAMLResponse already captured).
                  If it opens a socket to the target, it is not PASSIVE.

      ACTIVE      Sends requests to the target, INCLUDING PAYLOADS, and only READS the answer.
                  SQLi, NoSQLi, XPath, LDAP, command injection, SSRF, XXE, traversal, content
                  discovery, parameter mining, fuzzing, DAST. This is what every mainstream
                  scanner means by an active scan — Burp and ZAP both send SQLi payloads under
                  this label — and it is the tier for the overwhelming majority of vulnerability
                  detection. Authenticating, or POSTing to a login form, is ACTIVE: an auth
                  attempt reads a decision, it does not write application data.

      INTRUSIVE   CHANGES STATE. Creates, modifies, deletes or persists something on the target:
                  uploads a file, stores a payload that another user will render, creates an
                  object, writes across a trust boundary, poisons a shared cache, races a
                  transaction, sends an arbitrary-method request the engine did not constrain.
                  Reversible is not the test — `confirm_create_object_idor` deletes what it
                  makes and is still INTRUSIVE, because between the create and the delete the
                  target's state was not what its owner left it. INTRUSIVE rides the HITL
                  approval gate and `auto_approve`; ACTIVE does not.

    THE TEST, when a new engine is genuinely ambiguous: if the run were interrupted halfway,
    would the target need cleaning up? Yes -> INTRUSIVE. No -> ACTIVE.

    NOT this axis (Q-052 — the tier bundled these and it cost the product its SQLi surface at
    `active` for the whole life of the project):
      * COST. A slow engine is a budget problem. Express it in `planner._HEAVY_FULL_ONLY`,
        which holds run_sqlmap / run_zap / run_nmap_vuln to `full` on wall-clock grounds while
        leaving them honestly registered ACTIVE.
      * NOISE / DETECTABILITY. Being obvious in a WAF log is not a state change.
      * AUTHENTICATION. Whether an engine needs a session is orthogonal to all three tiers.

    Mode maps onto the tiers cumulatively: `passive` = PASSIVE, `active` = PASSIVE + ACTIVE,
    `full` = all three. Enforced in `planner._allowed` (scheduling) and `agent._run_tool` /
    `agent._exec_internal` (dispatch + HITL).
    """
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"


@dataclass
class ScopeEntry:
    value: str            # bare host (used for host-level scope matching)
    asset_type: str
    base: Optional[str] = None   # explicit scheme://host:port when the operator gave one
    port: str = ""        # explicit non-default port the operator pinned ("" = any port)
    path: str = ""        # explicit path-prefix the operator pinned ("" = whole host)


def _scope_path(d: str) -> str:
    """Normalized path-prefix from a scope entry that pins one, e.g.
    `https://example.com/api/*` or `example.com/api` -> `/api`. Returns '' for a
    host-level entry (no path, bare '/', or a wildcard host) so nothing is enforced.
    Path scope keeps a path-restricted bug-bounty asset from bleeding into the whole host."""
    d = (d or "").strip().lower()
    if not d or d.startswith("*"):
        return ""
    if "://" in d:
        raw = urlparse(d).path
    else:
        parts = d.split("/", 1)
        raw = "/" + parts[1] if len(parts) > 1 else ""
    raw = (raw or "").split("?")[0].split("#")[0].rstrip("*")
    if not raw or raw == "/":
        return ""
    norm = posixpath.normpath("/" + raw.lstrip("/"))
    return "" if norm in ("", ".", "/") else norm


def _path_prefix_match(req_path: str, scope_path: str) -> bool:
    """True when a concrete request path falls under the pinned scope prefix
    (exact, or a `/prefix/...` descendant). Normalized to defeat `/api/../admin`."""
    a = posixpath.normpath("/" + (req_path or "/").lstrip("/"))
    b = posixpath.normpath("/" + (scope_path or "/").lstrip("/"))
    if b in ("", ".", "/"):
        return True
    return a == b or a.startswith(b.rstrip("/") + "/")


def _split_scope_entry(d: str):
    """(bare_host, base_url|None) from a scope entry that may carry a scheme and/or
    port. The bare host drives scope-matching (always port/scheme-free); the base
    carries scheme+port for probing when the operator gave a non-default one, e.g. a
    local app on http://host.docker.internal:42000. Plain hosts and wildcards default
    to https on the standard port and record no explicit base."""
    d = (d or "").strip().lower()
    if not d:
        return "", None
    if d.startswith("*"):
        return d, None                       # wildcard — no single base URL
    scheme = ""
    if "://" in d:
        p = urlparse(d)
        scheme, netloc = p.scheme, p.netloc
    else:
        netloc = d.split("/")[0]
    host = netloc.split(":")[0]
    port = netloc.split(":")[1] if ":" in netloc else ""
    if not scheme and not port:
        return host, None                    # plain host -> default https, no explicit base
    if not scheme:                           # host:port with no scheme -> infer
        scheme = "https" if port == "443" else "http"
    if scheme == "https" and port in ("", "443"):
        return host, None                    # default https:443 needs no explicit base
    base = f"{scheme}://{host}" + (f":{port}" if port else "")
    return host, base


class ScopeConfigurationError(ValueError):
    """The operator declared assets but not one of them can be turned into a target.

    Q-096. Raised by `load_manual` rather than returning an engine that quietly addresses nothing.
    The discipline is already written down at `main.py:3081` for a malformed entry: *"Scope is the
    boundary between authorised testing and hitting something nobody asked us to touch, so an
    exception while BUILDING that boundary can only mean 'the boundary is unknown'. Unknown is not
    permission. The fix is not to make `load_manual` tolerant."* A scope made entirely of patterns is
    the same condition reached by a different road: the boundary is stateable, but there is nothing
    inside it to connect to, and a mission built on it can only produce findings about nothing.
    """


def build_boundary(in_scope, out_of_scope=(), program_name: str = "Program") -> tuple:
    r"""`(ScopeEngine, "")` when these entries build into an ENFORCEABLE boundary; `(None, reason)`
    when they do not. Never raises.

    Q-099. `load_manual` raising is correct and stays correct -- the caller is what mishandled it,
    three times over, each in its own dialect: `findings_gate.off_scope` swallowed the raise and
    ADMITTED the finding, `main._scope_for` let it escape into the UI as a 500, and
    `main.retest_findings` handled it properly but wrote its own sentence for the operator. This is
    that one evaluation and that one sentence, in the module that owns the question, so a mission
    cannot be unstateable at the write gate and fine on the mission record.

    THE REASON IS THE PRODUCT. A bare "scope invalid" sends an operator hunting; the message names
    the exception type and carries `load_manual`'s own text, which already names the offending entry
    verbatim (deliberately NOT `repr()` -- the entry is a regex and repr doubles every backslash, so
    the operator would be told to fix a string they never typed).

    `(None, reason)` rather than an exception because every caller here has to make the SAME
    decision -- refuse -- and a return value keeps that decision at the call site where the reader
    can see it, instead of in a handler that can quietly grow a fall-through.
    """
    eng = ScopeEngine()
    try:
        eng.load_manual(list(in_scope or []), list(out_of_scope or []), program_name)
    except Exception as ex:
        return None, ("this mission's scope could not be parsed into an enforceable boundary "
                      "(%s: %s); fix the offending entry in scope['bases'] / scope['in_scope'] "
                      "and re-run" % (type(ex).__name__, str(ex)[:400]))
    return eng, ""


# ── Target shape: the ingress that decides what may become an ADDRESS (Q-096) ──
# RFC-1123-ish. Deliberately permissive about `_` (real DNS carries it) and about single-label names
# (`juice-shop`, `box`, `dvwa`) because every Apolaki lab is one.
_HOST_RE = re.compile(
    r'^(?=.{1,253}\.?$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?'
    r'(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*\.?$', re.I)

# Deliberate regex syntax: an anchor, a quantifier, an alternation, a group or an escape. A scope
# entry that is neither a hostname nor this is not a boundary anyone can evaluate.
_REGEX_INTENT = re.compile(r'[\^$*+?|()\\]')


def is_host_shaped(value: str) -> bool:
    r"""True when `value` is something a resolver or a socket could actually be handed.

    Q-096 IS THIS PREDICATE. A bug-bounty scope written as anchored regex (`^.*\.shopify\.com$`) is a
    FILTER, not an ADDRESS. `load_manual` typed an entry `wildcard` only when it started with `*`, so
    a regex -- which starts with `^` -- was typed `domain`, survived every wildcard filter, and was
    emitted verbatim as the base URL `https://^.*\.shopify\.com$`. The reproduction command in the
    field report reads, character for character:

        curl -i -sS -k --path-as-is 'https://^.*\.shopifycs\.com$'

    A wildcard is False here too: `*.example.com` is a legitimate scope entry and a legitimate recon
    root, but it is not an address either, and the wildcard branch handles it on its own terms.
    """
    v = (value or "").strip().lower()
    if not v or v.startswith("*"):
        return False
    return bool(_HOST_RE.match(v))


def looks_like_pattern(value: str) -> bool:
    r"""True when a non-hostname entry carries deliberate regex syntax.

    The third state nobody had a word for. An entry is a HOST (`shop.example.com`), a PATTERN
    (`^.*\.shopify\.com$`), or NEITHER — and "neither" needs its own answer, because handing it to
    `re.compile` produces a message about the wrong thing. MEASURED: `_split_scope_entry("[::1]")`
    returns the bare host `"["` (it splits on `:` before it splits on `]`, so IPv6 has never been
    supported here), and `re.compile("[")` raises `unterminated character set at position 0` — true,
    and useless to an operator who typed an IPv6 literal. `"my host.com"` is the same shape of
    mistake. Both now get a refusal that names the entry they actually wrote."""
    return bool(_REGEX_INTENT.search(value or ""))


def compile_pattern(value: str):
    r"""The compiled matcher for a scope entry that is a PATTERN rather than a host.

    Used with `fullmatch`, so an operator's `.*\.example\.com` cannot be satisfied by
    `a.example.com.attacker.tld` even when they forgot the `$`.

    NO try/except, deliberately, and not only to keep the silent-failure ceiling ratcheted: an entry
    that is neither a hostname nor a compilable pattern is a boundary nobody can evaluate, and
    swallowing `re.error` here would hand back an engine whose scope silently matches nothing. Same
    sentence as `main.py:3081` -- unknown is not permission. Compiling at LOAD time also means a
    malformed entry fails where the operator can still fix it, not on the first request."""
    return re.compile(value, re.I)


# Q-100. Everything a real bug-bounty scope authorizes is written in anchored regex, so a scope
# engine that only understands bare hostnames understands nothing an operator actually exports.
# These two answer "what does this pattern DENOTE?" -- deliberately narrowly, because the failure
# mode on this road is INVENTING authorization, which is far worse than declining to derive one.
_PATTERN_META = set(".^$*+?{}[]|()\\")


def literal_host_from_pattern(value: str) -> str:
    r"""The single hostname an ANCHORED LITERAL pattern denotes, or `""` when it denotes anything else.

    `^partners\.shopify\.com$` -> `partners.shopify.com`. That is a hostname wearing punctuation, and
    refusing it costs the operator 8 real assets out of the 15 in their Shopify export.

    UNESCAPING IS NOT GUESSING, and the line between them is the whole point of this function. Only
    `\.` is unescaped; ANY other backslash escape or surviving metacharacter returns `""`. So
    `^a\.b\.com$` resolves and `^a.b\.com$` does NOT -- in the second, `.` is still a metacharacter
    matching any character, so it denotes a SET of hosts and picking one would be inventing
    authorization the operator never wrote. The result is re-checked with `is_host_shaped`, so
    nothing that is not dialable can escape through here."""
    v = (value or "").strip()
    if not (v.startswith("^") and v.endswith("$")) or len(v) < 3:
        return ""
    body, out, i = v[1:-1], [], 0
    while i < len(body):
        c = body[i]
        if c == "\\":
            if i + 1 < len(body) and body[i + 1] == ".":
                out.append(".")
                i += 2
                continue
            return ""                      # any other escape: not a plain literal
        if c in _PATTERN_META:
            return ""                      # a live metacharacter: denotes a set, not a host
        out.append(c)
        i += 1
    host = "".join(out)
    return host if is_host_shaped(host) else ""


def wildcard_host_from_pattern(value: str) -> str:
    r"""The `*.apex` RECON ROOT a subdomain-wildcard pattern denotes, or `""`.

    `^.*\.shopify\.com$` -> `*.shopify.com`, which is this codebase's existing word for the same
    idea, so `agent.py:3758` seeds subfinder/crt.sh from it and `base_urls()` refuses to dial it.

    THE APEX IS NOT A TARGET. `^.*\.shopify\.com$` authorizes the SUBdomains of shopify.com and says
    nothing about shopify.com itself; returning the bare apex here would manufacture authorization
    from a rule that never granted it. Returning the `*.` form keeps that distinction in the type
    rather than in a comment, and every host recon discovers is still validated against the pattern
    before anything is dialled."""
    v = (value or "").strip()
    if not (v.startswith("^") and v.endswith("$")):
        return ""
    body = v[1:-1]
    for prefix in (".*\\.", ".+\\.", "[^.]*\\.", "[^.]+\\."):
        if body.startswith(prefix):
            apex = literal_host_from_pattern("^" + body[len(prefix):] + "$")
            return ("*." + apex) if apex else ""
    return ""


class ScopeEngine:
    def __init__(self):
        self.in_scope: list = []
        self.out_of_scope: list = []
        # Q-096: entries that are PATTERNS, not addresses. Held apart from `in_scope` because
        # `in_scope` is what three drivers in agent.py read as their target list (`:3003` scoped-path
        # seeding, `:3317` graph host observation, `:3758` the recon roots that seed subfinder /
        # crtsh / run_dns / run_asn). They are consulted by `validate()` and reported by `to_dict()`
        # and `to_rules()`, so nothing about the BOUNDARY is lost -- only the ability to dial one.
        self.in_scope_patterns: list = []
        self.out_of_scope_patterns: list = []
        # entry value -> compiled matcher, built once at load time (see compile_pattern).
        self._pattern_rx: dict = {}
        # (raw entry, why) for every entry refused as a target — surfaced in to_dict() so the
        # misconfiguration is nameable in the mission record instead of showing up as silence.
        self.unusable: list = []
        self.program_name: str = ""
        # Extra answer-key surfaces to hard-block, beyond the default. Every benchmark target publishes
        # its ground truth somewhere different — /vulnerabilities for a PortSwigger-style page, an
        # expectedresults index elsewhere — and a keyed target whose key is NOT blocked would have its
        # answers crawled into the mission, silently destroying the blind property while every artifact
        # still reported ordering_ok. Carried on the scope because the choke point is the only place
        # that sees every URL the scanner touches.
        self.answer_key_paths: list = []

    def load_manual(self, in_scope: list, out_of_scope: list, program_name: str = "Program") -> None:
        self.program_name = program_name
        declared = 0
        for d in in_scope:
            host, base = _split_scope_entry(d)
            if host:
                declared += 1
                if not host.startswith("*") and not is_host_shaped(host):
                    if not looks_like_pattern(host):
                        raise ScopeConfigurationError(
                            'scope entry "%s" is neither a hostname nor a pattern, so it can be '
                            "neither connected to nor matched against. (IPv6 literals are not "
                            "supported here: the parser splits on ':' first, so \"[::1]\" arrives "
                            'as "[".)' % (d,))
                    # Q-096: a PATTERN. It keeps its job as a predicate and loses the one it never
                    # had — being an address. Kept out of `in_scope` so no target list can pick it up.
                    self._pattern_rx[host] = compile_pattern(host)
                    self.in_scope_patterns.append(ScopeEntry(host, "pattern"))
                    # Q-100: the pattern stays the predicate, AND we ask what it DENOTES. A real
                    # bug-bounty scope is written entirely in anchored regex, so refusing every one
                    # of them refuses the engagement — Q-096 stopped the harm and left the operator
                    # unable to scan. Both derivations translate into vocabulary this codebase
                    # already has, so nothing downstream needs to learn a new kind of entry:
                    #   ^partners\.shopify\.com$  -> ScopeEntry("partners.shopify.com", "domain")
                    #        an anchored literal is a hostname wearing punctuation; `base_urls()`
                    #        turns a `domain` into a target.
                    #   ^.*\.shopify\.com$        -> ScopeEntry("*.shopify.com", "wildcard")
                    #        a RECON ROOT, never a target. `agent.py:3758` already does
                    #        `.lstrip("*.")` over `in_scope` to seed subfinder/crt.sh, and
                    #        `base_urls()` already skips wildcards — so the apex is searched and
                    #        never dialled. This is the distinction that matters: the rule
                    #        authorized the SUBdomains, so promoting `shopify.com` itself to a
                    #        target would invent authorization the operator never wrote.
                    literal = literal_host_from_pattern(host)
                    if literal:
                        self.in_scope.append(ScopeEntry(literal, "domain"))
                        continue
                    root = wildcard_host_from_pattern(host)
                    if root:
                        self.in_scope.append(ScopeEntry(root, "wildcard"))
                        continue
                    self.unusable.append((str(d), "a scope pattern that denotes neither one literal "
                                                  "host nor one wildcard root, so it stays a filter "
                                                  "only — it still matches, it cannot be a target"))
                    continue
                # capture the explicit port (if the operator pinned one) so validate()
                # can enforce it against concrete request targets — see SEC-1.
                port = ""
                if base and ":" in urlparse(base).netloc:
                    port = urlparse(base).netloc.rsplit(":", 1)[1]
                # SEC-2: capture the path-prefix (if pinned) so a path-restricted asset
                # (https://host/api/*) doesn't silently widen to the whole host.
                path = "" if host.startswith("*") else _scope_path(d)
                self.in_scope.append(ScopeEntry(host, "wildcard" if host.startswith("*") else "domain", base, port, path))
        for d in out_of_scope:
            host, _ = _split_scope_entry(d)
            if host:
                if not host.startswith("*") and not is_host_shaped(host):
                    if not looks_like_pattern(host):
                        raise ScopeConfigurationError(
                            'out-of-scope entry "%s" is neither a hostname nor a pattern, so nothing '
                            "can be excluded by it. An exclusion that matches nothing is an "
                            "exclusion that is not there." % (d,))
                    # An EXCLUSION written as a pattern must keep excluding. Before Q-096 it matched
                    # only itself, so the carve-out the operator wrote was not enforced at all.
                    self._pattern_rx[host] = compile_pattern(host)
                    self.out_of_scope_patterns.append(ScopeEntry(host, "pattern"))
                    continue
                self.out_of_scope.append(ScopeEntry(host, "wildcard" if host.startswith("*") else "domain"))
        if declared and not self.in_scope:
            raise ScopeConfigurationError(
                "no in-scope entry can be a target: %s. A scope pattern matches hosts, it cannot be "
                "connected to — supply at least one concrete host (or a wildcard root) alongside the "
                "pattern(s), or the mission has nothing to address."
                # NOT repr(): the entry is a regex, and repr doubles every backslash, so the operator
                # would be told to fix a string that is not the one they typed.
                % ", ".join('"%s"' % v for v, _why in self.unusable[:8]))

    def validate(self, target: str) -> tuple:
        host, port, is_request = self._parse_target(target)
        if not host:
            return False, "Invalid target"
        req_path = self._target_path(target)
        # BLIND BENCHMARK: a published answer-key / vulnerability-disclosure surface is HARD-BLOCKED
        # from the scanner at the single scope choke point — so crawl, browser, JS-route harvest,
        # candidate generation, credential harvest and report evidence can NEVER learn the answers.
        # The benchmark driver fetches it separately (its own httpx), only AFTER the mission is sealed.
        try:
            import blind_benchmark as _bb
            if _bb.is_answer_key(target, self.answer_key_paths):
                return False, "BLIND BENCHMARK: answer-key surface is blocked from the scanner"
        except Exception:
            pass
        for entry in self.out_of_scope:
            if self._matches(host, entry.value):
                return False, f"{host} is explicitly out of scope"
        for entry in self.out_of_scope_patterns:
            if self._pattern_matches(host, entry):
                return False, f"{host} is explicitly out of scope (pattern {entry.value})"
        host_in_scope, path_pinned = False, False
        for entry in self.in_scope:
            if self._matches(host, entry.value):
                host_in_scope = True
                # SEC-1: when the operator pinned an explicit port, enforce it — but
                # only against a concrete REQUEST target (a URL / host:port an HTTP
                # tool will actually hit). A bare hostname (subdomain / DNS recon,
                # is_request=False) stays host-level so domain recon isn't broken.
                if entry.port and is_request and port != entry.port:
                    continue
                # SEC-2: same for a pinned path-prefix — a concrete request outside the
                # authorized path is out of scope; bare-host recon (is_request=False) is
                # never blocked by path. Another in-scope entry can still allow the host.
                if entry.path and is_request:
                    path_pinned = True
                    if not _path_prefix_match(req_path, entry.path):
                        continue
                suffix = f":{entry.port}" if entry.port else ""
                psuffix = entry.path if entry.path else ""
                return True, f"In scope via {entry.value}{suffix}{psuffix}"
        # Q-096: patterns are consulted AFTER the concrete entries so a pinned port/path still wins
        # where one exists, and they authorise a host by MATCHING it rather than by equalling it.
        # This is the half the ticket calls the trap: scope must keep working as a predicate over
        # real discovered hosts, and before this a pattern matched nothing except itself.
        for entry in self.in_scope_patterns:
            if self._pattern_matches(host, entry):
                return True, f"In scope via pattern {entry.value}"
        if host_in_scope:
            if path_pinned:
                return False, (f"{host}{req_path} not in scope "
                               "(host is in scope, but the request path is outside the pinned scope path)")
            return False, (f"{host}:{port or '?'} not in scope "
                           "(host is in scope, but the operator pinned a different port)")
        return False, f"{host} not in scope"

    def _target_path(self, target: str) -> str:
        """Path of a concrete request target ('/' when none). Scheme-less host:port/path
        is handled too so validate() can enforce a pinned path-prefix."""
        t = (target or "").strip()
        if "://" in t:
            p = urlparse(t).path or "/"
        else:
            after = t.split("?")[0].split("#")[0].split("/", 1)
            p = "/" + after[1] if len(after) > 1 else "/"
        return (p.split("?")[0].split("#")[0]) or "/"

    def _extract_host(self, target: str) -> str:
        if "://" in target:
            return urlparse(target).netloc.split(":")[0].lower()
        return target.split(":")[0].split("/")[0].lower()

    def _parse_target(self, target: str) -> tuple:
        """(host, effective_port, is_request). is_request is True when the target
        carries a scheme or an explicit port — i.e. a concrete HTTP endpoint whose
        port can be enforced. A bare hostname (no scheme, no port) is a recon host:
        is_request=False, so port pinning never blocks domain-level recon."""
        t = (target or "").strip()
        has_scheme = "://" in t
        netloc = urlparse(t).netloc if has_scheme else t.split("/")[0]
        host = netloc.split(":")[0].lower()
        explicit_port = netloc.rsplit(":", 1)[1] if ":" in netloc else ""
        if explicit_port:
            port = explicit_port
        elif has_scheme:
            scheme = urlparse(t).scheme
            port = "443" if scheme == "https" else "80" if scheme == "http" else ""
        else:
            port = ""
        return host, port, (has_scheme or bool(explicit_port))

    def _matches(self, host: str, pattern: str) -> bool:
        clean = pattern.lstrip("*.").lower()
        return host == clean or host.endswith("." + clean)

    def _pattern_matches(self, host: str, entry) -> bool:
        """Q-096: a PATTERN entry authorises (or excludes) a host by MATCHING it, anchored, never by
        equalling it. The literal comparison in `_matches` is what let `^.*\\.shopify\\.com$` be
        in scope as itself while `www.shopify.com` was refused."""
        rx = self._pattern_rx.get(entry.value)
        return bool(rx and rx.fullmatch((host or "").strip().lower()))

    def to_dict(self) -> dict:
        # Q-096: patterns ARE the boundary the operator declared, so they stay in this view — it is
        # the scope the report prints and the model reads, not a target list. `unusable_as_targets`
        # is added only when there is something to say, so a normal mission's dict (and therefore
        # `memory.target_key`) is byte-identical to before.
        d = {
            "program": self.program_name,
            # Q-140: DEDUPED, ORDER PRESERVED. The operator's Shopify scope printed each root FOUR
            # times -- the literal, the bare form and the anchored regex all resolve to the same
            # `value`, and re-importing the Burp JSON appended another copy. `dict.fromkeys` keeps
            # first-seen order, so the operator's own ordering is untouched.
            #
            # Deduped HERE rather than at the three render sites because `to_dict` is also what
            # `memory.target_key` hashes and what the model reads: a scope that lists one host four
            # times is not just ugly, it is a different key and a different prompt.
            "in_scope": list(dict.fromkeys([e.value for e in self.in_scope]
                                           + [e.value for e in self.in_scope_patterns])),
            "out_of_scope": list(dict.fromkeys([e.value for e in self.out_of_scope]
                                               + [e.value for e in self.out_of_scope_patterns])),
            # base URLs carry scheme+port for concrete hosts; consumers like the
            # cross-session memory key use these so apps on the same host but
            # different ports don't collide. Additive — in_scope stays bare hosts.
            "bases": self.base_urls(),
        }
        if self.unusable:
            d["unusable_as_targets"] = [{"entry": v, "why": why} for v, why in self.unusable]
        return d

    def to_rules(self) -> dict:
        """Structured rules view consumed by web_security.is_url_in_scope
        (host/path aware). Every domain/wildcard becomes an identifier rule; a
        path-pinned host is emitted as a full scheme://host/path URL identifier so
        _rule_matches_url binds host AND path together (no cross-host path bleed)."""
        def _ident(e):
            if e.path and e.asset_type != "wildcard":
                base = (e.base or f"https://{e.value}").rstrip("/")
                return base + e.path
            return e.value

        def _type(e):
            if e.asset_type == "pattern":
                # `web_security` has no regex vocabulary, so emit the shape it already saw before
                # Q-096. Its `_host_matches_rule` compares literally and will not match a pattern —
                # exactly as today. Nothing is widened here and nothing is dropped; the enforcing
                # choke point for a pattern is `validate()`, which now genuinely matches.
                return "domain"
            return "url" if (e.path and e.asset_type != "wildcard") else e.asset_type
        return {
            "in_scope": [{"identifier": _ident(e), "type": _type(e)}
                         for e in (self.in_scope + self.in_scope_patterns)],
            "out_of_scope": [{"identifier": e.value, "type": _type(e)}
                             for e in (self.out_of_scope + self.out_of_scope_patterns)],
        }

    def _addressable(self) -> list:
        """The in-scope entries that can be an ADDRESS.

        Q-096: this used to be spelled as a NEGATIVE filter (`if e.asset_type == "wildcard":
        continue`), which admits every shape nobody thought of — and an anchored regex was one, so
        `https://^.*\\.shopify\\.com$` was emitted as a base URL. Stated POSITIVELY, the next
        unforeseen shape is refused by default instead of dialled. `is_host_shaped` is re-checked
        here rather than trusted from `asset_type` alone so an entry appended directly to `in_scope`
        by some other code path cannot skip the ingress."""
        return [e for e in self.in_scope
                if e.asset_type in ("domain", "ip", "url") and is_host_shaped(e.value)]

    def base_urls(self) -> list:
        """Base URLs for concrete (non-wildcard) in-scope hosts — the operator's
        explicit scheme+port when given, else default https."""
        return [e.base or f"https://{e.value}" for e in self._addressable()]

    def base_map(self) -> dict:
        """host -> base URL (scheme+port) for concrete in-scope hosts, so the planner
        probes a non-standard port/scheme instead of assuming https on 443."""
        return {e.value: (e.base or f"https://{e.value}") for e in self._addressable()}


# ── Multi-format scope-file parsing (adapted from OLYMPUS) ────────
def _extract_md_url(line: str) -> Optional[str]:
    m = re.match(r'\[.*?\]\(https?://([^/)\s]+)', line)
    return m.group(1).lstrip("www.") if m else None


def _strip_platform_suffix(line: str):
    m = re.match(r'^(.+?)\s+\((Android|iOS|Apple|Google Play)\)\s*$', line, re.I)
    if m:
        kind = m.group(2).lower().replace("google play", "android").replace("apple", "ios")
        return m.group(1).strip(), kind
    return line.strip(), None


def _classify(identifier: str) -> str:
    i = identifier.strip()
    if re.match(r'^\d+$', i):
        return "ios_app_id"
    if re.match(r'^com\.[a-z]', i.lower()):
        return "android_package"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', i):
        return "ip"
    if re.match(r'^https?://', i, re.I):
        return "url"
    return "domain"


def _parse_target(raw: str) -> Optional[dict]:
    line = raw.strip()
    if not line:
        return None
    md = _extract_md_url(line)
    if md:
        line = md
    line = re.split(r'\s+#\s+', line)[0].strip()
    line, platform = _strip_platform_suffix(line)
    if not line:
        return None
    return {"identifier": line, "type": platform or _classify(line)}


def _parse_sections(content: str) -> dict:
    in_scope, out_of_scope, section = [], [], "in"
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            u = line.upper()
            if any(k in u for k in ("OUT-OF-SCOPE", "OUT OF SCOPE", "INELIGIBLE", "EXCLUDE", "NOT IN SCOPE")):
                section = "out"
            elif any(k in u for k in ("IN-SCOPE", "IN SCOPE", "ELIGIBLE", "INCLUDE")):
                section = "in"
            continue
        if line.startswith("-"):
            entry = _parse_target(line[1:])
            if entry:
                out_of_scope.append(entry)
            continue
        if line.startswith("+"):
            entry = _parse_target(line[1:])
            if entry:
                in_scope.append(entry)
            continue
        entry = _parse_target(line)
        if entry:
            (in_scope if section == "in" else out_of_scope).append(entry)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "section_based"}


def _parse_hackerone_csv(content: str) -> dict:
    in_scope, out_of_scope = [], []
    reader = csv.DictReader(io.StringIO(content))
    hdrs = [h.lower().strip() for h in (reader.fieldnames or [])]
    id_col = next((h for h in hdrs if "identifier" in h or "target" in h), None)
    bounty_col = next((h for h in hdrs if "bounty" in h or "eligible" in h), None)
    type_col = next((h for h in hdrs if "type" in h), None)
    if not id_col:
        return _parse_sections(content)
    skipped = 0
    for row in reader:
        raw = (row.get(id_col) or "").strip()
        if not raw or raw.lower() in ("n/a", "none", "-", ""):
            skipped += 1
            continue
        entry = _parse_target(raw)
        if not entry:
            skipped += 1
            continue
        if type_col:
            entry["type"] = (row.get(type_col) or entry["type"]).strip().lower()
        eligible = (row.get(bounty_col) or "true").strip().lower()
        (in_scope if eligible in ("true", "yes", "1") else out_of_scope).append(entry)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "hackerone_csv", "skipped": skipped}


def _parse_bugcrowd_csv(content: str) -> dict:
    in_scope, out_of_scope = [], []
    reader = csv.DictReader(io.StringIO(content))
    hdrs = [h.lower().strip() for h in (reader.fieldnames or [])]
    target_col = next((h for h in hdrs if "target" in h), None)
    focus_col = next((h for h in hdrs if "focus" in h), None)
    if not target_col:
        return _parse_sections(content)
    skipped = 0
    for row in reader:
        raw = (row.get(target_col) or "").strip()
        if not raw:
            skipped += 1
            continue
        entry = _parse_target(raw)
        if not entry:
            skipped += 1
            continue
        focus = (row.get(focus_col) or "in").strip().lower()
        (out_of_scope if "out" in focus or "excluded" in focus else in_scope).append(entry)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "bugcrowd_csv", "skipped": skipped}


_ID_HINTS = ("identifier", "target", "asset", "endpoint", "url", "domain", "host", "scope", "name")


def _parse_generic_csv(content: str) -> dict:
    """Best-effort CSV for platforms beyond H1/Bugcrowd (Intigriti, YesWeHack,
    plain exports). Heuristically finds an identifier column and an optional
    eligibility/scope column; unparseable/empty rows are counted, not dropped
    silently."""
    in_scope, out_of_scope, skipped = [], [], 0
    reader = csv.DictReader(io.StringIO(content))
    hdrs = [h.lower().strip() for h in (reader.fieldnames or [])]
    if not hdrs:
        return {"in_scope": [], "out_of_scope": [], "format": "csv", "skipped": 0}
    id_col = next((h for h in hdrs if any(k in h for k in _ID_HINTS)), hdrs[0])
    elig_col = next((h for h in hdrs if any(k in h for k in ("eligible", "bounty", "submission"))), None)
    focus_col = next((h for h in hdrs if any(k in h for k in ("focus", "in_scope", "in scope", "out_of_scope", "out of scope"))), None)
    type_col = next((h for h in hdrs if h == "type" or h.endswith("_type") or "asset_type" in h), None)
    for row in reader:
        raw = (row.get(id_col) or "").strip()
        if not raw or raw.lower() in ("n/a", "none", "-"):
            skipped += 1
            continue
        entry = _parse_target(raw)
        if not entry:
            skipped += 1
            continue
        if type_col:
            tv = (row.get(type_col) or "").strip().lower()
            if tv:
                entry["type"] = tv
        is_out = False
        if elig_col is not None:
            v = (row.get(elig_col) or "true").strip().lower()
            is_out = v in ("false", "no", "0", "ineligible", "out")
        elif focus_col is not None:
            is_out = "out" in (row.get(focus_col) or "").strip().lower()
        (out_of_scope if is_out else in_scope).append(entry)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "csv", "skipped": skipped}


def _parse_burp_json(content: str) -> dict:
    data = json.loads(content)
    if "target" in data and "scope" in data.get("target", {}):
        data = data["target"]["scope"]

    def extract(items: list) -> list:
        result, seen = [], set()
        for item in (items or []):
            if isinstance(item, str):
                entry = _parse_target(item)
            elif isinstance(item, dict):
                # Q-100: a rule the operator switched OFF is not a rule. Burp writes `enabled` on
                # every entry and this read it as though every rule were live, which silently
                # widened an INCLUDE the operator had disabled and, worse, honoured a disabled
                # EXCLUDE as if it were protecting them. Absent means enabled (Burp omits it in
                # some exports); only an explicit false is a switch-off.
                if item.get("enabled") is False:
                    continue
                raw = item.get("host") or item.get("url") or item.get("file") or ""
                entry = _parse_target(raw)
            else:
                entry = None
            if entry:
                # Burp writes one rule PER PROTOCOL, so a 15-host scope arrives as 30 entries that
                # are identical once the protocol is dropped. Deduping here keeps the mission's
                # scope list, its report header and its recon roots from carrying every host twice.
                key = entry.get("identifier")
                if key in seen:
                    continue
                seen.add(key)
                result.append(entry)
        return result

    return {
        "in_scope": extract(data.get("include") or data.get("inclusions") or []),
        "out_of_scope": extract(data.get("exclude") or data.get("exclusions") or []),
        "format": "burp_json",
    }


def parse_scope(content: str) -> dict:
    """Auto-detect format and return {in_scope, out_of_scope, format}."""
    content = (content or "").strip()
    if not content:
        return {"in_scope": [], "out_of_scope": [], "format": "empty"}
    if content.startswith("{"):
        try:
            return _parse_burp_json(content)
        except Exception:
            pass
    first = content.splitlines()[0].lower().strip()
    cols = [c.strip() for c in first.split(",")]
    if "," in first and len(cols) >= 2:
        if "asset_identifier" in first or "eligible_for_bounty" in first or ("identifier" in cols and "eligible_for_submission" in first):
            return _parse_hackerone_csv(content)
        if "target" in first and any(k in first for k in ("category", "severity", "focus")):
            return _parse_bugcrowd_csv(content)
        # any other CSV with a recognizable identifier/scope column (Intigriti,
        # YesWeHack, plain exports) -> generic best-effort parser
        if any(any(k in c for k in _ID_HINTS) for c in cols):
            return _parse_generic_csv(content)
    return _parse_sections(content)


# Asset types that are scannable web targets (skip mobile-app ids etc.)
_WEB_TYPES = {"domain", "url", "ip", "wildcard"}


def web_targets(parsed: dict) -> tuple:
    """From a parsed scope, return (in_scope_hosts, out_of_scope_hosts) as plain
    host strings for the scan engine, dropping non-web assets (mobile app ids)."""
    def hosts(entries):
        out = []
        for e in entries:
            if e.get("type", "domain") not in _WEB_TYPES:
                continue
            ident = e["identifier"]
            if ident.startswith("http"):
                ident = urlparse(ident).netloc or ident
            out.append(ident)
        return out
    return hosts(parsed.get("in_scope", [])), hosts(parsed.get("out_of_scope", []))
