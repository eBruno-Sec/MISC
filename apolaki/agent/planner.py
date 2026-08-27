"""
Deterministic scan planner — the non-AI brain.

Sequences Apolaki's existing tools into the standard workflow

    passive recon → live-host discovery → fingerprint → enrich (openapi/graphql/js)
    → surface-driven probes → nuclei → playbook

WITHOUT an LLM. Pure and deterministic: given the mission state it returns the
NEXT batch of tool calls, or [] when the workflow is exhausted. Every step has a
stable dedup key; the executor re-plans after each batch, so a step never repeats
(loop guard) yet newly discovered in-scope assets are picked up on the next pass.

Tool-permission gating mirrors the assessment mode:
    passive → PASSIVE only
    active  → PASSIVE + ACTIVE
    full    → PASSIVE + ACTIVE + INTRUSIVE
The executor still runs every step through the scoped, HITL-gated tool pipeline,
so this module never bypasses scope or the approval gate — it only chooses order.

TWO SEPARATE AXES, and Q-052 exists because they were one. See `scope.PermissionLevel`
for what each tier MEANS; the short version is that the tier is a CONSENT axis — does
this engine change state — and it is not a cost axis. Sending SQLi payloads is not
expensive and is not a state change; a ZAP active scan is enormously expensive and is
still not a state change. Gating an engine to `full` because it is SLOW is a legitimate
budget decision, but it must be spelled with `_HEAVY_FULL_ONLY` below, never by inflating
its permission tier — an over-declared tier makes the operator's consent decision mean
something it does not mean, and it is what made `active` unable to test for SQL injection.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import dns_recon
import surface as surface_mod
from scope import PermissionLevel
# _SESSION_KILL_RE is IMPORTED, not restated. See `is_session_kill_url` — a second copy of this rule
# is how one URL came to sit under two contradictory policies, which is the defect Q-080 closes.
from tools import TOOL_PERMISSIONS, _SESSION_KILL_RE

# per-mode allowed permission tiers
_ALLOWED = {
    "passive": {PermissionLevel.PASSIVE},
    "active": {PermissionLevel.PASSIVE, PermissionLevel.ACTIVE},
    "full": {PermissionLevel.PASSIVE, PermissionLevel.ACTIVE, PermissionLevel.INTRUSIVE},
}

# Q-052 — the COST gate, deliberately separate from the permission tier above.
#
# These three are read-only payload senders, so the tier split puts them in ACTIVE and the
# consent question is genuinely answered "yes, an active scan may do this". They are also the
# three engines that dominate mission wall-clock: a ZAP spider + AJAX spider + active scan per
# host root, an `nmap -sV --script "vuln and not dos"` per host, and a deep/insane sqlmap per
# injection-prone endpoint. Q-052 pre-registers a 2x wall-clock ceiling at `active`; before this
# gate existed they were held out of `active` only as a SIDE EFFECT of being mis-tiered
# INTRUSIVE, so re-tiering them silently removed a budget control that nothing had named.
#
# Naming it makes the tradeoff editable: an operator who wants sqlmap in an `active` mission is
# asking a budget question, and the answer belongs here rather than in a consent tier. `full`
# keeps them. `run_zap` additionally stays behind its own `POST /engage` check, which rejects
# `enable_zap` unless mode == "full" — this gate is not what makes ZAP full-only, it is what
# keeps the PLANNER from scheduling it if that check ever moves.
_HEAVY_FULL_ONLY = {"run_sqlmap", "run_zap", "run_nmap_vuln"}

# caps keep every run bounded + terminating
CAP_HOSTS = 30          # hosts we http_probe / fingerprint
CAP_ENDPOINTS = 25      # parameterized endpoints we actively probe
CAP_REST = 30           # high-value NON-parameterized REST/sensitive endpoints we fetch
CAP_FORM_PAGES = 10     # non-parameterized pages we fetch for form discovery (bounded:
                        # each is a remote round-trip, so keep the amplification small)
CAP_JS = 40             # js urls handed to js_review
CAP_DOM = 6             # HTML pages handed to the (slow) headless DOM audit
CAP_ZAP = 3             # primary host roots handed to the (very slow) ZAP DAST pass
CAP_SQLMAP = 8          # deep-intensity heavy-sqlmap targets (most injection-prone params;
                        # insane runs the full fan-out). Keeps a deep scan completable —
                        # sqlmap on every endpoint is what makes deep run for hours.
CAP_MASS_ASSIGN = 8     # JSON write endpoints handed to run_mass_assign. Each one is a THREE-object
                        # protocol (baseline + ignored-field control + one object per candidate
                        # field), so it is the most expensive step per target in the sweep and the
                        # only one that leaves objects behind. Bounded like every other write engine.


# Q-050. Write methods `_run_mass_assign` accepts — it refuses anything else outright
# ("unsupported write method"), so scheduling a GET/DELETE would be a step that cannot run.
_WRITE_METHODS = ("POST", "PUT", "PATCH")


def _is_json_ct(ct) -> bool:
    """True for a media type that carries a JSON OBJECT body.

    Deliberately narrow. `run_mass_assign` sends `Content-Type: application/json` and its oracle is
    a JSON re-read; pointing it at `application/x-www-form-urlencoded` or `multipart/form-data`
    means the write is rejected, no object is created, and the engine reports a clean it never
    earned. An EMPTY content type is a real observation (an HTML form records none) and reads
    False — `x or DEFAULT` here, with "" as a genuine input, is the recorded falsy-default trap.
    """
    c = str(ct or "").split(";")[0].strip().lower()
    return c == "application/json" or c.endswith("+json")

_URLISH_PARAM = ("url", "uri", "link", "fetch", "redirect", "next", "return", "dest",
                 "target", "proxy", "image", "img", "callback", "webhook", "u", "r")
_FILE_PARAM = ("file", "path", "page", "doc", "document", "template", "include", "load", "read", "dir", "folder")
_CMD_PARAM = ("cmd", "command", "exec", "run", "ping", "host", "ip", "dns", "query", "shell", "code")
# Path signals for endpoints that likely parse an XML/SOAP request body — the XXE
# sinks the GET-param probes never reach (e.g. ginandjuice /catalog/product/stock).
import re as _re
# Strong XML/SOAP body-sink signals only. Deliberately NOT the generic commerce
# words (checkout/order/price/cart) — those are almost always JSON/form endpoints,
# and matching them made run_xxe fire ~14x on non-XML endpoints for zero result.
_XML_SINK = _re.compile(
    r"/(?:soap|xml|wsdl|rss|feed|xmlrpc|import|export|ews|services|b2b|stock|stockcheck)(?:/|$|\?)"
    r"|\.xml(?:$|\?)", _re.I)
# Static assets + docs that never carry injectable forms/params — excluded from the
# bounded form/page injection budget so it is not wasted on README translations,
# licenses, images or bundles (which is what starves the real vuln pages).
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
               ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm", ".pdf", ".zip",
               ".gz", ".tar", ".md", ".markdown", ".rst", ".txt", ".sh", ".yml", ".yaml",
               ".log", ".lock")
_STATIC_NAME = _re.compile(r"/(?:readme|license|licence|changelog|contributing|authors|"
                           r"copying|notice|code_of_conduct)(?:[.\-][a-z0-9]+)*/?$", _re.I)


def _is_static(u: str) -> bool:
    low = (u or "").lower().rstrip("/")
    return low.endswith(_STATIC_EXT) or bool(_STATIC_NAME.search(low))


# High-value NON-parameterized endpoints worth a direct GET: REST/API resource trees
# (the access-control surface) and standalone sensitive paths (info-exposure surface).
# These carry no query string, so the parameterized-only probe filter skips them — yet
# they are exactly where IDOR/BOLA and sensitive-file exposure live on a REST app.
_INTERESTING_EP = _re.compile(
    r"/(?:rest|api|graphql|b2b)/[A-Za-z0-9_{}.\-]"
    r"|/(?:ftp|metrics|snippets|encryptionkeys|dataerasure|redirect|profile|support|"
    r"swagger|\.git|\.env|backup|admin)(?:/|$)", _re.I)


# Login-style endpoints worth a POST/JSON body auth-bypass SQLi probe.
_LOGIN_SINK = _re.compile(r"(?:log[-_]?in|sign[-_]?in|authenticate|authentication)(?:/|$|\?)", _re.I)
# chat/AI-assistant endpoints worth a prompt-injection probe — narrow on purpose so
# it never fires against an unrelated endpoint that merely contains "chat" in a path.
_CHAT_SINK = _re.compile(
    r"/(?:chat(?:bot)?|assistant|copilot|ai[-_]?(?:assistant|chat|bot)|virtual[-_]?assistant|"
    r"support[-_]?bot|llm|conversation|messages?)(?:[/?]|$)", _re.I)
# Well-known login paths, probed directly per host so a critical auth-bypass SQLi
# is tested even when the JS crawler doesn't happen to fire the login XHR.
_LOGIN_PATHS = ("/rest/user/login", "/api/login", "/api/auth/login", "/login",
                "/api/authenticate", "/auth/login", "/user/login", "/api/sessions")

_VALUE_PARAM = set(_URLISH_PARAM + _FILE_PARAM + _CMD_PARAM + (
    "id", "uid", "user", "account", "role", "admin", "search", "filter", "sort", "order",
    "category", "product", "item", "page", "name"))
_VALUE_PATH = _re.compile(
    r"/(?:admin|manage|internal|private|account|profile|users?|auth|login|session|execute|exec|"
    r"command|upload|import|export|graphql|api|rest|debug|config|backup)(?:/|$)", _re.I)


def _url_value(url: str) -> int:
    """Security value visible before probing, used only to decide a bounded prefix."""
    raw = str(url or "").split("#", 1)[0]
    before_query, marker, query = raw.partition("?")
    names = [part.partition("=")[0].lower() for part in query.split("&") if part] if marker else []
    path = before_query.split("://", 1)[-1]
    path = "/" + path.partition("/")[2] if "/" in path else "/"
    score = 1 if names else 0
    score += 4 * sum(name in _VALUE_PARAM for name in names)
    score += 3 if _VALUE_PATH.search(path) else 0
    return score


def _rank_urls(urls) -> list:
    """Highest target-observable security value first; stable for ties."""
    return sorted(list(urls or []), key=_url_value, reverse=True)


def _endpoint_value(endpoint: dict) -> int:
    params = [str(p).lower() for p in (endpoint.get("params") or [])]
    score = 1 if params else 0
    score += 4 * sum(p in _VALUE_PARAM for p in params)
    score += 4 if endpoint.get("body_sink") else 0
    score += 3 if _VALUE_PATH.search(str(endpoint.get("path") or "/")) else 0
    return score


def _rank_endpoints(endpoints) -> list:
    return sorted(list(endpoints or []), key=_endpoint_value, reverse=True)


def _rank_live_hosts(hosts, roots=()) -> list:
    """Operator roots first, then URL security value; stable for ties."""
    root_set = {str(root).lower() for root in (roots or [])}
    ranked = _rank_urls(hosts)
    return sorted(ranked, key=lambda url: _host(url).lower() in root_set, reverse=True)


def _rank_host_names(hosts, roots=()) -> list:
    """Operator roots first; discovered hosts retain deterministic lexical order."""
    root_set = {str(root).lower() for root in (roots or [])}
    unique = sorted({str(host) for host in (hosts or []) if host})
    return sorted(unique, key=lambda host: host.lower() in root_set, reverse=True)


def _form_value(form: dict) -> int:
    names = [str((p or {}).get("name") or "").lower()
             for p in (form.get("body_params") or []) if isinstance(p, dict)]
    return (_url_value(form.get("action") or "")
            + 4 * sum(name in _VALUE_PARAM for name in names)
            + (1 if str(form.get("method") or "").upper() in _WRITE_METHODS else 0))

# Q-050. A real-time transport endpoint the mission OBSERVED. `tools.py:604` recorded that
# `run_ws_hijack` was "implemented, permission-registered and reachable from NOTHING", and held it
# out of the sweep deliberately, pending a measurement -- putting a brand-new confirming engine on
# every mission's always-on path is what produced Q-047's false positive. This is that measurement's
# answer, and the reason the trigger is an observation rather than a probe:
#
#   * Driven live against four labs, `_run_ws_hijack({"url": <root>})` returns "no WebSocket endpoint
#     advertised" on ALL FOUR -- including Juice Shop, which genuinely speaks socket.io. Its
#     index.html is an Angular shell and `main.js` carries 8 `socket.io` references but ZERO `ws://`
#     literals, because a socket.io client builds the URL at runtime. So scheduling it on page
#     content would have bought one wasted GET per page and zero coverage on the whole fleet.
#   * The mission ALREADY observes the endpoint by its HTTP long-polling URL: 262 captured exchanges
#     to `/socket.io/?EIO=4&transport=polling...`, and 6 of the 3,216 recorded endpoint assets are
#     `<host>/socket.io/...`, on the three Juice Shop hosts and NOWHERE ELSE in the corpus.
#
# `ws_tool.COMMON_WS_PATHS` stays the single owner of the transport knowledge (socket.io needs
# `?EIO=4&transport=websocket`); this only decides WHICH of those transports the mission saw.
CAP_WS_ENDPOINTS = 3    # mirrors tools.ToolRegistry._WS_MAX_ENDPOINTS


def _ws_candidate(u: str) -> str:
    """The ws:// upgrade URL for a real-time endpoint the mission OBSERVED, or "" for anything else.

    Deliberately NOT a `ws://`-literal search and NOT a default-path probe: the input is an
    http(s) URL the crawl actually recorded, so the transport is a fact about the target rather
    than a guess about it."""
    import ws_tool as _wst
    try:
        pr = urlparse(u or "")
    except Exception:
        return ""
    if not pr.netloc or pr.scheme not in ("http", "https"):
        return ""
    seg = ((_path(u).strip("/").split("/") or [""])[0]).lower()
    if not seg:
        return ""
    for cand in _wst.COMMON_WS_PATHS:
        if cand.strip("/").split("/")[0].split("?")[0].lower() == seg:
            return "%s://%s%s" % ("wss" if pr.scheme == "https" else "ws", pr.netloc, cand)
    return ""


def _host(u: str) -> str:
    try:
        return (urlparse(u).netloc or "").split("@")[-1]
    except Exception:
        return ""


def _path(u: str) -> str:
    try:
        return urlparse(u).path or "/"
    except Exception:
        return ""


def observed_param_values(urls) -> dict:
    """{(netloc, path): {param: first observed value}} over the discovered URL set.

    D3. `surface.build_inventory` unions the parameter NAMES per endpoint but keeps a single
    `example` URL, and that URL carries only the parameters that happened to ride on it. This
    recovers the VALUE each of the other parameters was actually observed with, so the merged
    probe URL below is built from OBSERVED values only, never invented ones.
    """
    out = {}
    for u in urls or []:
        if not isinstance(u, str) or not u:
            continue
        try:
            p = urlparse(u)
        except Exception:
            continue
        if not p.netloc:
            continue
        seen = out.setdefault((p.netloc, p.path or "/"), {})
        for k, v in parse_qsl(p.query, keep_blank_values=True):
            # first observation wins, but a real value beats a blank one
            if k not in seen or (not seen[k] and v):
                seen[k] = v
    return out


def merge_observed_params(url: str, values: dict) -> str:
    """`url` carrying EVERY parameter observed on its endpoint, not just the ones on this URL.

    D3, and the reason the obvious fix does not work. The planner already knows the full
    parameter set (`ep["params"]`), so the tempting patch is to pass `params=` into the step and
    let the engine iterate it. MEASURED: that patch is inert. `_run_sqli`, `_run_nosqli`,
    `_run_cmdi` and `_run_xss` all build their probe target with `xss_tool.set_param(url, p, v)`,
    which REPLACES an existing parameter and silently returns the url unchanged when the
    parameter is absent -- so probing a known-but-absent parameter sends the baseline URL, the
    baseline and the probe fail identically, and the endpoint is reported clean. (`ssrf_tool`'s
    set_param does append; the two disagree.) Carrying the parameters on the URL instead fixes
    every engine at once, including `run_injection_probes`, `run_web_probes`, `run_sqlmap`,
    `run_dalfox` and `run_xxe`, which never read `inp["params"]` at all, and it leaves
    `_run_xss`'s hidden-parameter discovery (which only runs when `params` is NOT supplied)
    intact.

    Parameters already present keep their own value. Missing ones are appended in sorted order
    so the URL is deterministic across runs.

    A PARAMETER PRESENT WITH A BLANK VALUE IS UPGRADED TO THE OBSERVED ONE (Q-095).
    -------------------------------------------------------------------------------
    `?q` and `?q=apple` are not two spellings of the same request. MEASURED on juice-shop:
    `?q` and `?q=` both return 16572 bytes (the whole UNFILTERED product list) while `?q=apple`
    returns 921. A BASELINE-DEPENDENT engine -- one that fetches the URL as given and compares a
    probe against it (`_run_sqli`, `_run_nosqli`, `_run_cmdi`, `_run_web_probes`, the SSTI branch
    of `_run_injection_probes`, and `run_sqlmap`'s own dynamicity check) -- therefore measures its
    differential against a page the probe can never reproduce, and reports CLEAN on a vulnerable
    field. MEASURED with identical flags on both sides:

        sqlmap -u '.../search?q'       --batch --level 3 --risk 2 --technique=BEUST
            -> "all tested parameters do not appear to be injectable"
               (it tested User-Agent and Referer; `q` itself was dropped as non-dynamic)
        sqlmap -u '.../search?q=apple' --batch --level 3 --risk 2 --technique=BEUST
            -> Parameter: q (GET)  boolean-based blind + time-based blind, back-end DBMS: SQLite

    `have` counted a blank-valued parameter as "already have it", so the value `observed_param_values`
    had ALREADY recovered was dropped on the floor. Worse, `build_inventory` keeps the FIRST URL it
    sees as the endpoint's `example`, so whether a mission probed a working URL or a dead one was
    decided by the order the crawl happened to reach them in.

    NOTHING IS SYNTHESIZED, and that is the load-bearing constraint rather than a nicety. `values`
    comes only from `observed_param_values(urls)`, which reads real discovered URLs; a parameter
    never observed with a value keeps its blank. An INVENTED value can make baseline and probe fail
    identically, which is precisely how an engine reports clean on a vulnerable field -- the failure
    mode that has bitten three engines here in one day. This is also the rule
    `observed_param_values` already applies internally ("a real value beats a blank one",
    line 286): the fix makes the two halves of D3 agree, it does not add a new policy.

    A parameter that already carries a REAL value keeps its own -- no churn on endpoints that were
    never broken, so their dedup keys, exchange ledgers and cached results do not move.
    """
    if not url or not values:
        return url
    try:
        p = urlparse(url)
    except Exception:
        return url
    pairs = parse_qsl(p.query, keep_blank_values=True)
    # Q-095: upgrade in place, preserving position, so only the value moves.
    upgraded = [(k, values[k]) if (not v and values.get(k)) else (k, v) for k, v in pairs]
    have = {k for k, _ in pairs}
    extra = [(k, values[k]) for k in sorted(values) if k not in have]
    if upgraded == pairs and not extra:
        # NOTHING RECOVERED -> RETURN THE URL BYTE-FOR-BYTE. Re-encoding here would rewrite `?q`
        # as `?q=` on all 9873 valueless dispatches: the same request on the wire (MEASURED:
        # both 16572 bytes) but a different STRING, which churns every dedup key, step key and
        # cached result for endpoints this fix does not help. A no-op must be a no-op.
        return url
    return urlunparse(p._replace(query=urlencode(upgraded + extra, doseq=True)))


def _allowed(tool: str, mode: str) -> bool:
    """May this mode SCHEDULE this tool — consent first, then budget.

    Two independent reasons to say no, kept independent on purpose (Q-052). The tier answers
    "would this change state"; `_HEAVY_FULL_ONLY` answers "can this mode afford it". Collapsing
    them is the defect this ticket fixes, so a future reader who wants to make an engine
    full-only must pick which question they are answering.
    """
    if mode != "full" and tool in _HEAVY_FULL_ONLY:
        return False
    tiers = _ALLOWED.get(mode, _ALLOWED["active"])
    return TOOL_PERMISSIONS.get(tool, PermissionLevel.ACTIVE) in tiers


def _step(tool: str, inp: dict, key: str) -> dict:
    return {"tool": tool, "input": inp, "key": key}


# ── Q-080: the session-kill quarantine, at the DOOR ──────────────────────────────────────────────
#
# `tools._add_urls` keeps a session-destroying endpoint OUT of `tools.urls` and parks it in
# `tools.session_kill_urls`, where only `_run_session_lifecycle` may reach it — and only with a
# sacrificial session it minted itself. That quarantine was overruled by every OTHER route from
# discovered surface to a scheduled step, and there were TWO of them, both fed by the same response
# body the quarantine had already read:
#
#   * `recon["forms"]` — `tools._http_probe` appends every in-scope form action to it, filtered on
#     `scope.validate` and nothing else, so the URL `_add_urls` had just quarantined re-entered as
#     probe surface for the form loops below.
#   * `state["urls"]` — `agent._project_form_params` mints that same form action as a graph ENDPOINT
#     node, and `agent._graph_primary_state` turns every endpoint node into a planner URL. This one
#     is worse: it re-admits the URL to EVERY url-driven engine, not to the form loop's four.
#
# MEASURED on the running `sessionlife` lab at HEAD 29d00d2, driving the shipped path end to end
# (raw output in docs/handoff/session_door.md):
#
#     mode=full    113 steps, 6 at the logout URL: http_probe x2, run_csrf, run_race,
#                  run_form_cmdi, run_stored_xss
#     mode=active  103 steps, 3 at the logout URL: http_probe x2, run_csrf   <- the DEFAULT mode
#     mode=passive  29 steps, 0
#
# and a per-engine census on freshly minted sessions: 6/6 ended the mission session on the mount
# that invalidates at logout, 0/6 on the paired mount whose ONLY difference is that it does not, and
# 0/6 on an ordinary change-password form served by the same page. Every one reported success=True,
# and `session_headers` kept the dead cookie, so every authenticated probe afterwards silently tested
# as anonymous while the mission went on reporting.
#
# WHY THE GUARD IS HERE and not in the four engines, or in a better filter on `recon["forms"]`:
# `fresh()` is the ONE function every planner-emitted batch passes through, and it filters on the
# step's TARGET rather than on the state field that produced it. That is what makes it close both
# measured doors with one predicate, and what makes the engine added next year inherit it.
#
# It is deliberately NOT a second copy of the regex. `tools._SESSION_KILL_RE` remains the single
# definition of "this URL ends a session"; this module imports it.
_SESSION_KILL_ENTITLED = frozenset({
    # The one engine that is SUPPOSED to reach a quarantined URL: it mints a sacrificial account and
    # `tools._session_kill_is_safe` re-checks, as a fact, that the credential it is about to destroy
    # is disjoint from every live session. The entitlement is named rather than left to the accident
    # that the planner does not currently schedule it.
    "run_session_lifecycle",
})
# The step-input keys that name a REQUEST TARGET. Same two scalar keys `_addressable` guards, plus
# `target` (run_nuclei/run_nmap_vuln) and the `urls` LIST that run_js_review/run_saml fetch.
_TARGET_KEYS = ("url", "base_url", "target")
_TARGET_LIST_KEYS = ("urls",)
# Q-093(B). The subset of `_TARGET_KEYS` whose value may legitimately be a BARE HOST instead of a
# URL. `run_nmap_vuln` is handed `juice-shop:3000` and `run_dork_gen` a bare domain; only
# `run_nuclei` puts a URL in `target`. Declared HERE, beside the key list it qualifies, because the
# whole of Q-093(B) is that a rule kept away from its declaration drifts away from it.
_BARE_HOST_TARGET_KEYS = ("target",)


def is_session_kill_url(u) -> bool:
    """True when this URL is a session-destroying action (logout/signout/…).

    The single predicate for the quarantine, built on `tools._SESSION_KILL_RE` so the rule has one
    definition. Path AND query are tested, because `?action=logout` is as fatal as `/logout`.
    """
    if not u or not isinstance(u, str):
        return False
    try:
        p = urlparse(u)
    except Exception:
        return False
    return bool(_SESSION_KILL_RE.search((p.path or "") + ("?" + p.query if p.query else "")))


def session_kill_target(step: dict) -> str:
    """The session-destroying URL this step would request, or "" when there is none.

    Public because `agent._execute_plan` applies the same rule at the executor ingress — steps the
    graph produces (`_graph_action_steps`) never pass through `fresh()`, so a guard that lived only
    here would leave that door open.
    """
    if (step or {}).get("tool") in _SESSION_KILL_ENTITLED:
        return ""
    inp = (step or {}).get("input") or {}
    for k in _TARGET_KEYS:
        v = inp.get(k)
        if isinstance(v, str) and is_session_kill_url(v):
            return v
    for k in _TARGET_LIST_KEYS:
        for v in (inp.get(k) or []):
            if isinstance(v, str) and is_session_kill_url(v):
                return v
    return ""


def addressable_target(v, bare_host_ok: bool = False) -> bool:
    """Whether a single step-target value names something that can actually be requested.  Q-093(B).

    ONE definition, used by `_addressable` as the step-level backstop AND by the build sites that
    assemble target LISTS, so a bundle list cannot be filtered by a rule that disagrees with the
    guard that later inspects it.

    `bare_host_ok` is the ONE real distinction between the declared target keys, and it is not
    cosmetic: `run_nmap_vuln` is handed `juice-shop:3000` and `run_dork_gen` a bare domain. Both are
    perfectly addressable and neither is a URL, so demanding a scheme everywhere would silently
    delete those whole phases — a latent gap traded for a live capability loss, which is strictly
    worse than the gap. It defaults to False so the STRICT reading is what a new call site gets by
    not thinking about it.

    An empty string is refused in both modes. `_b("")` returns `""` (Q-019) precisely to say "there
    is no base for this host"; letting it flow on as a target is the same falsy-default failure the
    empty string was introduced to stop.
    """
    if not isinstance(v, str) or not v.strip():
        return False
    p = urlparse(v)
    if bare_host_ok and "://" not in v:
        return True                              # a bare host/domain: nmap and the dork generator
    return p.scheme in ("http", "https") and bool(p.netloc)


def _addressable(step: dict) -> bool:
    """False when a step carries a target it cannot address.

    Q-019's chokepoint. Every URL a step targets is built from a host plus a path, and a host that
    turns out to be empty used to yield `https:///path` — scheme present, netloc empty — which the
    scope engine refused ten times per mission while nothing named the planner as the producer. The
    planner must not emit a target it cannot address; scope is the authorization gate, not the
    spell-checker.

    Q-093(B) — THE KEYS ARE DERIVED, and that is the fix. This read `("url", "base_url")` while the
    module twelve lines above declared FOUR target keys, and `session_kill_target` right next door
    iterated all four correctly. MEASURED against the real `next_batch` over a surface carrying one
    host-less `.js` URL, no stubs: `run_js_review` was still being planned with
    `urls=['/static/app.js', 'https:///static/b.js']` — the Q-019 string, emitted through the one
    key neither this guard nor `agent._reject_hostless_step` inspected. `{"target": _b(h)}` with an
    empty `h` carried `""` for the same reason.

    A hand-maintained second key list is what produced the gap, so there is not another one: adding
    a key to `_TARGET_KEYS` now guards it here by existing, and
    `tests/test_planner_target_addressability.py` parametrizes over the same constants so a new key
    arrives as a test case rather than as a blind spot.

    A LIST key refuses the whole step if ANY entry is unaddressable. That is deliberate and it
    should never fire: the build sites filter with `addressable_target` first, so a mixed list
    reaching here means something upstream is broken, and half-scanning a broken plan is a worse
    answer than dropping it. `fresh()` drops silently by design (the planner is pure); the executor
    ingress is what makes a refusal visible.
    """
    inp = step.get("input") or {}
    for k in _TARGET_KEYS:
        if k not in inp:
            continue
        if not addressable_target(inp.get(k), bare_host_ok=(k in _BARE_HOST_TARGET_KEYS)):
            return False
    for k in _TARGET_LIST_KEYS:
        if k not in inp:
            continue
        for v in (inp.get(k) or []):
            if not addressable_target(v):
                return False
    return True


def estimate(mode: str, roots: list) -> dict:
    """A rough, pre-run estimate of the deterministic workload for the UI."""
    roots = [r for r in (roots or []) if r]
    n = max(1, len(roots))
    passive = 6 * n
    active = (5 * n) if mode in ("active", "full") else 0   # incl. JS-aware katana crawl
    intrusive = 15 if mode == "full" else 0
    return {"passive_steps": passive, "active_steps": active,
            "intrusive_steps": intrusive, "ai_calls": 0}


def next_batch(state: dict) -> list:
    """Return the next batch of steps (earliest incomplete phase), or []."""
    mode = state.get("mode", "active")
    roots = sorted({r.lower().lstrip("*.") for r in (state.get("roots") or []) if r})
    done = state.get("done") or set()
    recon = state.get("recon") or {}
    urls = state.get("urls") or []
    # True when a ZAP daemon is configured (ZAP_ADDR set). When so, Full mode runs a
    # real DAST pass — ZAP is no longer left to the agentic model's discretion.
    zap_on = bool(state.get("zap"))
    # heavyweight nmap NSE vuln scan — opt-in; the COST gate keeps it to Full mode.
    nmap_vuln_on = bool(state.get("nmap_vuln"))
    # heavy nuclei (full vuln template set) — opt-in, Full mode only.
    nuclei_heavy_on = bool(state.get("nuclei_heavy")) and mode == "full"
    # intensity dial — deep/insane adds the heavy sqlmap pass to the injection sweep.
    intensity = str(state.get("intensity", "standard")).lower()
    # host -> base URL (scheme+port). Lets the planner probe a non-standard target
    # (e.g. a local app on http://host:42000) instead of assuming https on 443.
    bases = state.get("bases") or {}

    def _b(h):
        # The base map is keyed by BARE host, but discovered hosts (from the surface
        # inventory / crawl) often carry a :port. Strip it for the lookup so a
        # non-standard target (e.g. an IP or host on :42002) resolves to its real
        # scheme+port base instead of falling back to https:// on a plaintext port.
        #
        # AN EMPTY HOST RETURNS "" (Q-019). It used to return f"https://{h}" == "https://", so
        # `_b(_host(u)) + _path(u)` on a host-less input produced `https:///benchmark/x.html` —
        # scheme, empty netloc — which scope correctly refused, ten times per mission, against
        # exactly the index pages that link the whole corpus. `x or DEFAULT` where the empty value
        # is a REAL input is the recorded falsy-default failure mode; the honest answer is that
        # there is no base URL for a host that does not exist. Callers must skip a "" base.
        if not h:
            return ""
        return bases.get(h) or bases.get(h.split(":")[0]) or f"https://{h}"

    def _b_url(u):
        # Rebuild a discovered URL (e.g. an inventory entry's `example`, which
        # carries the RAW scheme it was crawled/discovered with) against the
        # scope's KNOWN base for its host, preserving path+query. A discovered
        # URL can carry a stale/wrong scheme (e.g. left over from before a
        # non-standard-port base was known), which fails outright on a
        # plaintext-only port — `ep.get("example") or _b(...)` does NOT catch
        # this, since the fallback only fires when `example` is entirely absent,
        # which is rare (inventory entries almost always have one).
        if not u:
            return u
        p = urlparse(u)
        b = _b(p.netloc)
        if not b:                       # host-less input: there is no base to rebuild against
            return ""
        base = urlparse(b)
        return urlunparse((base.scheme, base.netloc, p.path, p.params, p.query, p.fragment))

    def _abs(u):
        """A discovered URL normalized onto the scope's KNOWN base for its host, or "" when it
        carries no host. Q-019: `_b(_host(u)) + _path(u)` written inline at five call sites was what
        turned a host-less graph label into `https:///path`. One helper, one rule: no host, no URL."""
        b = _b(_host(u))
        return (b + _path(u)) if b else ""

    # D3: the observed value of every parameter, per endpoint, so `_ex` can rebuild an example URL
    # that carries the endpoint's whole parameter set instead of the one parameter that happened to
    # be on the inventory's `example`.
    _obs = observed_param_values(urls)

    def _ex(ep):
        """An inventory entry's probe URL: the scope's base + path + EVERY observed parameter.

        Replaces `_b_url(ep["example"]) or (_b(ep["host"]) + ep["path"])`, which delivered only the
        parameters carried by the single example URL. MEASURED before the change, on a 7-URL
        surface: 16 (parameter, engine) pairs the planner knew about were never delivered -- e.g.
        /search?term=x was the example, so `lang` and `url` were never probed by ANY engine, and
        run_ssrf on /fetch was scheduled BECAUSE the inventory saw `target` and was then handed a
        URL containing only `cmd`."""
        merged = merge_observed_params(
            ep.get("example") or "",
            _obs.get((ep.get("host") or "", ep.get("path") or "")) or {})
        return _b_url(merged) or (_b(ep.get("host") or "") + (ep.get("path") or ""))

    def _observed_get_paths(host: str) -> list:
        """Distinct paths OBSERVED on `host`, for `run_mass_assign`'s re-read ranking (Q-050).

        Observed, never invented: these are the URLs the crawl and the API's own spec import put on
        the surface, stripped of their query strings. `mass_assign_tool.read_views` then keeps only
        the ones sharing a leading segment with the write path, ranks them, and applies the actual
        five-request cap. Capping here first made that semantic rank ceremonial: a precise object
        template discovered after thirty generic paths was discarded before the rank could see it.

        Paths the mission observed as WRITES are excluded. `_ma_views` is capped
        (`ToolRegistry._MA_MAX_VIEWS`), so every write path in the list displaces a real read view:
        MEASURED on the VAmPI shape, `/users/v1/register` and `/users/v1/login` took two of the five
        slots for a register write, and both answer a GET with 405. The write endpoint itself is not
        lost by this — `_ma_views` already appends it as the last-resort collection listing.
        """
        skip = {_path(f.get("action") or "") for f in (state.get("recon", {}).get("forms") or [])
                if str(f.get("method") or "").upper() in _WRITE_METHODS
                and _host(f.get("action") or "") == host}
        out, seen = [], set()
        for u in urls:
            if not isinstance(u, str) or _host(u) != host:
                continue
            p = _path(u)
            if not p.startswith("/") or p in seen or p in skip:
                continue
            seen.add(p)
            out.append(p)
        return out

    def fresh(steps):
        # dedup against `done` AND within this freshly built batch (a step's key can
        # be generated twice in one phase, e.g. run_graphql from a URL hint and from
        # a host root) — so the same call never fires twice. A step whose target could not be
        # resolved to an absolute URL (empty string) is dropped here rather than scheduled: it is
        # not a target, and handing scope a `https:///x` to refuse only hides the producer.
        out, seen = [], set()
        for s in steps:
            k = s["key"]
            if k in done or k in seen or not _allowed(s["tool"], mode):
                continue
            if not _addressable(s):
                continue
            # Q-080: a session-destroying target is never scheduled, whichever state field produced
            # it. `recon["forms"]` and `state["urls"]` both re-admitted URLs that `tools._add_urls`
            # had quarantined; filtering on the TARGET here closes both with one rule. Dropped
            # silently on purpose — the planner is pure and records nothing; the executor ingress
            # (`agent._reject_session_kill_step`) is what makes each refusal visible in the mission.
            if session_kill_target(s):
                continue
            seen.add(k)
            out.append(s)
        return out

    # ── phase A: passive recon on each root ──
    a = []
    for root in roots:
        for tool in ("run_subfinder", "run_crtsh", "run_wayback", "run_dns", "run_asn", "run_github_recon"):
            a.append(_step(tool, {"domain": root}, f"{tool}:{root}"))
        # offline, PASSIVE: operator-ready search-dork queries for the root (no scraping)
        a.append(_step("run_dork_gen", {"target": root}, f"run_dork_gen:{root}"))
    a = fresh(a)
    if a:
        return a

    # discovered hosts (registrable + subdomains + live + url hosts), in scope by construction.
    # Drop DNS/parsing artifacts (SOA-RNAME hosts like hostmaster.hostmaster.x) so the deep tools
    # are never scheduled against a non-host that only yields a scope block.
    subs = [s for s in (recon.get("subdomains") or []) if s and not dns_recon.is_junk_host(s)]
    live_hosts = [h.get("url") for h in (recon.get("live_hosts") or []) if h.get("url")]
    url_hosts = sorted({_host(u) for u in urls if _host(u)})

    # ── phase B: live-host discovery ──
    b = []
    targets = _rank_host_names(set(roots) | set(subs), roots)
    if targets:
        # key on target count so a later recon cycle (more subdomains) re-runs httpx
        b.append(_step("run_httpx", {"targets": targets, "bases": bases}, f"run_httpx:{len(targets)}"))
    b.append(_step("check_takeover", {}, "check_takeover"))
    # http_probe each in-scope host root once (extracts links + params → surface)
    host_roots = _rank_host_names(set(roots) | set(subs) | set(url_hosts), roots)
    for h in host_roots[:CAP_HOSTS]:
        b.append(_step("http_probe", {"url": _b(h)}, f"http_probe:{h}"))
    # JS-aware crawl of each in-scope root — essential for SPAs/APIs (e.g. Angular
    # apps) whose real surface, endpoints and params live in JS/XHR, not static
    # HTML that http_probe can parse. ACTIVE, so passive mode skips it via _allowed.
    for h in targets[:CAP_HOSTS]:
        b.append(_step("run_katana", {"url": _b(h)}, f"run_katana:{h}"))
    b = fresh(b)
    if b:
        return b

    # ── phase C: fingerprint live hosts ──
    c = [_step("run_fingerprint", {"url": u}, f"run_fingerprint:{u}")
         for u in _rank_live_hosts(live_hosts, roots)[:CAP_HOSTS]]
    c = fresh(c)
    if c:
        return c

    # ── phase D: enrich (openapi / graphql / js) ──
    d = []
    # Q-093(B). Filtered HERE, not just refused at `fresh()`. `js_urls` comes straight off raw
    # `state["urls"]` and is the only target list the planner builds, so it never passed through
    # `_abs` and was carrying host-less entries (`https:///static/b.js`) into `run_js_review`'s
    # `urls`. Dropping the bad entries keeps the good bundles: the step-level guard has to refuse
    # the WHOLE step, and losing nine addressable bundles to one broken one would be a capability
    # loss dressed up as a fix.
    js_urls = _rank_urls([u for u in urls
                          if u.split("?")[0].lower().endswith(".js") and addressable_target(u)])
    openapi_seen, graphql_seen = set(), set()
    for u in urls:
        low = u.lower()
        # normalize to the scope's known base — a discovered URL can carry a stale/
        # wrong scheme (e.g. https:// left over from before a non-standard-port
        # base was known), which fails outright on a plaintext-only port.
        nu = _abs(u)
        if not nu:
            continue
        if any(k in low for k in ("swagger", "openapi", "api-docs", "/v2/api-docs", "openapi.json")) and nu not in openapi_seen:
            openapi_seen.add(nu)
            d.append(_step("fetch_openapi", {"url": nu}, f"fetch_openapi:{nu}"))
        if "graphql" in low and nu not in graphql_seen:
            graphql_seen.add(nu)
            d.append(_step("run_graphql", {"url": nu}, f"run_graphql:{_host(u)}"))
    # always try graphql discovery once per live host root
    for h in (set(roots) | set(subs)):
        d.append(_step("run_graphql", {"url": _b(h) + "/graphql"}, f"run_graphql:{h}"))
    if js_urls:
        d.append(_step("run_js_review", {"urls": js_urls[:CAP_JS]}, "run_js_review"))
        # ACTIVE: analyse each bundle's source map (hidden routes/APIs/secrets), bounded
        for ju in js_urls[:8]:
            d.append(_step("run_sourcemap", {"url": ju}, f"run_sourcemap:{ju}"))
    # http_probe parameterized/product pages so their POST forms (method + body
    # fields) are captured into recon["forms"] BEFORE phase-E probes run — that is
    # what lets run_xxe reach a POST XML body sink like the stock-check form.
    inv_d = surface_mod.build_inventory(urls, cap=max(1000, len(urls)))
    for ep in _rank_endpoints([e for e in inv_d if e.get("parameterized")])[:CAP_ENDPOINTS]:
        u = _b_url(ep.get("example")) or (_b(ep['host']) + ep['path'])
        d.append(_step("http_probe", {"url": u}, f"http_probe:{ep['host']}{ep['path']}"))
    # Also http_probe a bounded sample of discovered non-asset HTML pages so their
    # forms are captured too — a form on a plain page (e.g. a DVWA exec/upload form)
    # is otherwise never fetched, so body-injection probes never see it.
    page_urls, seen_pg = [], set()
    for u in urls:
        raw = u.split("?")[0]
        if _is_static(raw):
            continue
        pg = _abs(u)                            # normalize to the scope's real base
        if not pg or pg in seen_pg:
            continue
        seen_pg.add(pg)
        page_urls.append(pg)
    for u in _rank_urls(page_urls)[:CAP_FORM_PAGES]:
        d.append(_step("http_probe", {"url": u}, f"http_probe:page:{_host(u)}{_path(u)}"))
    # http_probe high-value NON-parameterized REST/sensitive endpoints (basket, ftp,
    # users, security-questions, 2fa, …). The parameterized filter above skips them, so
    # without this the entire REST access-control + exposure surface is discovered but
    # never fetched. A {id}/${id} placeholder left by JS mining is instantiated to 1 so
    # the URL is concrete. GET only, scope-guarded at the wrapper, bounded by CAP_REST.
    rest_urls, seen_rest = [], set()
    for ep in inv_d:
        if ep.get("parameterized"):
            continue
        path = ep.get("path") or ""
        if not _INTERESTING_EP.search(path) or _is_static(path):
            continue
        real = path.replace("${id}", "1").replace("{id}", "1")
        u = _b(ep["host"]) + real
        if u in seen_rest:
            continue
        seen_rest.add(u)
        rest_urls.append(u)
    for u in _rank_urls(rest_urls)[:CAP_REST]:
        d.append(_step("http_probe", {"url": u}, f"http_probe:rest:{_host(u)}{_path(u)}"))
    d = fresh(d)
    if d:
        return d

    # ── phase E: surface-driven probes ──
    inv = surface_mod.build_inventory(urls, cap=max(1000, len(urls)))
    param_eps = _rank_endpoints([e for e in inv if e.get("parameterized")])[:CAP_ENDPOINTS]
    host_bases = _rank_host_names({e["host"] for e in inv}, roots)[:CAP_HOSTS]
    e_steps = []
    # DOM audit (headless browser, client-side confirmation) — bounded because it
    # is slow: the live-host roots + a few HTML pages, skipping static assets.
    dom_pages, dom_seen = [], set()
    for u in [_b(h) for h in host_bases] + [_ex(e) for e in param_eps]:
        low = u.split("?")[0].lower()
        if any(low.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ttf", ".gif", ".mp4")):
            continue
        if u not in dom_seen:
            dom_seen.add(u)
            dom_pages.append(u)
    for u in dom_pages[:CAP_DOM]:
        e_steps.append(_step("run_dom_audit", {"url": u}, f"run_dom_audit:{u}"))
    # active parameter mining (deep/insane): brute-force hidden params on host roots + key
    # pages so injection probes reach inputs the crawl never saw. Discovered params are
    # added to the surface and picked up by the iterative planner on a later batch.
    if intensity in ("deep", "insane"):
        pm_targets = list(dict.fromkeys(
            [_b(h) for h in host_bases]
            + [_ex(e) for e in param_eps]))[:CAP_SQLMAP]
        for u in pm_targets:
            e_steps.append(_step("run_param_mine", {"url": u}, f"run_param_mine:{u}"))
    # anomaly hunting (intuition leads) on app roots + key endpoints — a cheap active GET
    # + analysis flagging verbose errors / stack traces / debug + version-leak headers as
    # advisory 'dig here' leads (candidate, never confirmed).
    anom_targets = list(dict.fromkeys(
        [_b(h) for h in host_bases]
        + [_ex(e) for e in param_eps[:8]]))[:12]
    for u in anom_targets:
        e_steps.append(_step("run_anomaly_scan", {"url": u}, f"run_anomaly_scan:{u}"))
    # heavy sqlmap is expensive; at deep, target only the most injection-prone endpoints
    # (bounded by CAP_SQLMAP) so the scan completes — insane runs the full fan-out.
    _SQLI_PRONE = ("id", "cat", "category", "search", "q", "query", "filter", "sort",
                   "order", "page", "name", "user", "product", "item", "pid", "uid", "num")
    def _sqli_score(ep):
        pl = [str(p).lower() for p in (ep.get("params") or [])]
        return sum(1 for p in pl if any(h in p for h in _SQLI_PRONE)) + (1 if pl else 0)
    if intensity == "insane":
        sqlmap_eps = {f"{e['host']}{e['path']}" for e in param_eps}
    elif intensity == "deep":
        sqlmap_eps = {f"{e['host']}{e['path']}"
                      for e in sorted(param_eps, key=_sqli_score, reverse=True)[:CAP_SQLMAP]}
    else:
        sqlmap_eps = set()
    # Per-endpoint NATIVE injection probes first (fast, self-confirming with a deterministic
    # oracle). The heavy sqlmap pass is DEFERRED (collected here, appended after XXE below) so
    # a slow deep/insane sqlmap can never STARVE the native confirmations — the earlier failure
    # mode where sqlmap on endpoint #2 blocked run_sqli/run_xxe on every later endpoint. A
    # single run now surfaces the confirmations fast, and sqlmap corroborates afterwards.
    sqlmap_steps = []
    for ep in param_eps:
        u = _ex(ep)
        tag = f"{ep['host']}{ep['path']}"
        params_l = [str(p).lower() for p in (ep.get("params") or [])]
        e_steps.append(_step("run_xss", {"url": u}, f"run_xss:{tag}"))
        e_steps.append(_step("run_sqli", {"url": u}, f"run_sqli:{tag}"))
        e_steps.append(_step("run_nosqli", {"url": u}, f"run_nosqli:{tag}"))
        e_steps.append(_step("run_injection_probes", {"url": u}, f"run_injection_probes:{tag}"))
        e_steps.append(_step("run_web_probes", {"url": u}, f"run_web_probes:{tag}"))   # LFI/traversal + IDOR
        if any(p in _URLISH_PARAM for p in params_l):
            e_steps.append(_step("run_ssrf", {"url": u}, f"run_ssrf:{tag}"))
        if any(p in _CMD_PARAM for p in params_l):
            e_steps.append(_step("run_cmdi", {"url": u}, f"run_cmdi:{tag}"))
        # heavy sqlmap on the same endpoint — bounded to injection-prone endpoints at deep,
        # full fan-out at insane. HEAVY -> _allowed() gates to Full on COST, not on tier
        # (run_sqlmap is ACTIVE: it sends payloads and reads, it does not write). Deferred to the end.
        if tag in sqlmap_eps:
            sqlmap_steps.append(_step("run_sqlmap", {"url": u, "intensity": intensity},
                                      f"run_sqlmap:{tag}"))
    # XXE — POST XML body sinks (fast native timing/OOB oracle), BEFORE the heavy sqlmap pass.
    # Prefer real POST forms captured during enrich (their action + body field names let
    # run_xxe build a schema-shaped XML body, e.g. the stock-check <productId>/<storeId>
    # form); fall back to path-matched / body-sink inventory endpoints. Path-driven.
    xxe_seen = set()
    for fm in (state.get("recon", {}).get("forms") or []):
        act = fm.get("action")
        if act and _XML_SINK.search(_path(act)) and act not in xxe_seen:
            xxe_seen.add(act)
            e_steps.append(_step("run_xxe", {"url": act, "method": "POST",
                                             "fields": fm.get("fields", [])}, f"run_xxe:{act}"))
    xml_eps = _rank_endpoints(
        [e for e in inv if e.get("body_sink") or _XML_SINK.search(e.get("path") or "")])[:CAP_HOSTS]
    for ep in xml_eps:
        u = _ex(ep)
        if u not in xxe_seen:
            e_steps.append(_step("run_xxe", {"url": u}, f"run_xxe:{ep['host']}{ep['path']}"))
    # heavy sqlmap corroboration LAST — the slowest injection tool, so it never blocks the
    # native SQLi/XXE/DOM confirmations that make the report complete.
    e_steps.extend(sqlmap_steps)
    # auth-bypass SQLi on login-style endpoints (POST/JSON body — query probes can't
    # reach it). Prefer captured POST forms; also probe discovered login-ish paths.
    auth_seen = set()
    form_seen = set()
    for fm in (state.get("recon", {}).get("forms") or []):
        act = fm.get("action")
        flds = fm.get("fields") or []
        if act and _LOGIN_SINK.search(_path(act)) and act not in auth_seen:
            auth_seen.add(act)
            e_steps.append(_step("run_auth_sqli", {"url": act, "fields": flds},
                                 f"run_auth_sqli:{act}"))
            e_steps.append(_step("run_form_nosqli", {"url": act, "fields": flds},
                                 f"run_form_nosqli:{act}"))
        # POST/form-body command injection on every captured form (e.g. a DVWA-style
        # exec form) — the body-parameter class query-string cmdi can't reach.
        if act and flds and act not in form_seen:
            form_seen.add(act)
            e_steps.append(_step("run_form_cmdi", {"url": act, "fields": flds},
                                 f"run_form_cmdi:{act}"))
            # second-order / STORED XSS: submit an executing canary, then browser-confirm
            # it fires on a display page (writes a canary -> INTRUSIVE, Full mode only).
            e_steps.append(_step("run_stored_xss", {"url": act, "fields": flds},
                                 f"run_stored_xss:{act}"))
    # ...and self-discover forms on a bounded set of discovered non-asset pages, so a
    # form on a plain page that http_probe never happened to fetch is still tested
    # (run_form_cmdi fetches + parses the page's forms itself).
    seen_page = set()
    for u in _rank_urls(urls):
        raw = u.split("?")[0].split("#")[0]
        if _is_static(raw):
            continue
        # normalize back to the scope's known base so a wrong-scheme/no-port junk URL
        # (https://host/path with the app really on http://host:port) is corrected
        pg = _abs(u)
        if not pg or pg in seen_page or pg in form_seen:
            continue
        seen_page.add(pg)
        if len(seen_page) > CAP_FORM_PAGES:
            break
        e_steps.append(_step("run_form_cmdi", {"url": pg}, f"run_form_cmdi:page:{_host(pg)}{_path(pg)}"))
        # same bounded page set: self-discover a file-upload form and test its
        # extension filter (run_upload_test fetches + parses the page itself).
        e_steps.append(_step("run_upload_test", {"url": pg}, f"run_upload_test:page:{_host(pg)}{_path(pg)}"))
    # prompt-injection probe on any discovered URL that looks like a chat/AI
    # endpoint — narrow path match, so this never fires on unrelated endpoints.
    chat_seen = set()
    for u in urls:
        if _CHAT_SINK.search(_path(u)):
            base = _abs(u)                      # normalize scheme+port to the known base
            if base and base not in chat_seen:
                chat_seen.add(base)
                e_steps.append(_step("run_llm_probe", {"url": base}, f"run_llm_probe:{base}"))
    # Q-050: Cross-Site WebSocket Hijacking, on a real-time endpoint this mission OBSERVED. See
    # `_ws_candidate` for the measurement behind the precondition. `ws_urls` is passed explicitly,
    # so the engine skips its own content-discovery fetch entirely and sends nothing beyond the
    # handshake and its cookie-stripped negative control.
    ws_seen = set()
    ws_candidates = []
    for u in urls:
        cand = _ws_candidate(u)
        if not cand or cand in ws_seen:
            continue
        ws_seen.add(cand)
        ws_candidates.append(cand)
    for cand in _rank_urls(ws_candidates)[:CAP_WS_ENDPOINTS]:
        import ws_tool as _wst
        e_steps.append(_step("run_ws_hijack",
                             {"url": _wst.http_origin_of(cand) + "/", "ws_urls": [cand]},
                             f"run_ws_hijack:{cand}"))
    for ep in inv:
        base = (_b_url(ep.get("example")) or (_b(ep['host']) + ep['path'])).split("?")[0]
        if _LOGIN_SINK.search(_path(base)) and base not in auth_seen:
            auth_seen.add(base)
            e_steps.append(_step("run_auth_sqli", {"url": base}, f"run_auth_sqli:{base}"))
            e_steps.append(_step("run_form_nosqli", {"url": base}, f"run_form_nosqli:{base}"))
    # plus a curated set of well-known login paths per in-scope host root
    for h in targets[:CAP_HOSTS]:
        for lp in _LOGIN_PATHS:
            u = _b(h) + lp
            if u not in auth_seen:
                auth_seen.add(u)
                e_steps.append(_step("run_auth_sqli", {"url": u}, f"run_auth_sqli:{h}{lp}"))
                e_steps.append(_step("run_form_nosqli", {"url": u}, f"run_form_nosqli:{h}{lp}"))
    for h in host_bases:
        e_steps.append(_step("run_content_discovery", {"base_url": _b(h)}, f"run_content_discovery:{h}"))
        e_steps.append(_step("run_exposure", {"base_url": _b(h)}, f"run_exposure:{h}"))
        e_steps.append(_step("run_dir_harvest", {"base_url": _b(h)}, f"run_dir_harvest:{h}"))
        # site-level: one cache-poisoning probe per live host root (unkeyed headers)
        e_steps.append(_step("run_cache_poison", {"url": _b(h)}, f"run_cache_poison:{h}"))
    # ── expanded class coverage (deterministic): schedule the auth / API / logic tools
    # the planner previously left to the AI layer, so ONE Full run also exercises CSRF,
    # BFLA/BOLA, race + rate-limit, insecure deserialization, dalfox XSS confirmation,
    # OAuth abuse, JWT weaknesses and ffuf content discovery. Bounded; the STATE-CHANGING
    # ones (run_race, run_deserialization, run_bfla's method sweep) are gated to Full mode by
    # fresh()/_allowed(); the read-only payload senders beside them (run_dalfox, run_ffuf) are
    # ACTIVE since Q-052. They run after the fast native probes + sqlmap, so they never starve
    # the confirmations that complete the report.
    for ep in param_eps:
        u = _ex(ep)
        tag = f"{ep['host']}{ep['path']}"
        e_steps.append(_step("run_deserialization", {"url": u}, f"run_deserialization:{tag}"))
        # object/function-level authz sweep — SAFE methods only (never DELETE).
        e_steps.append(_step("run_bfla", {"url": u, "allow_delete": False}, f"run_bfla:{tag}"))
    # dalfox — external XSS engine for stronger reflected-XSS confirmation; heavy, so
    # bound to the most injection-prone endpoints at deep, full fan-out at insane.
    dalfox_eps = (sorted(param_eps, key=_sqli_score, reverse=True)[:CAP_SQLMAP]
                  if intensity in ("deep", "insane") else param_eps[:3])
    for ep in dalfox_eps:
        u = _ex(ep)
        e_steps.append(_step("run_dalfox", {"url": u}, f"run_dalfox:{ep['host']}{ep['path']}"))
    # CSRF token check + race/rate-limit on state-changing POST forms.
    sc_seen = set()
    for fm in sorted((state.get("recon", {}).get("forms") or []),
                     key=_form_value, reverse=True):
        act = fm.get("action")
        if act and str(fm.get("method", "GET")).upper() == "POST" and act not in sc_seen:
            sc_seen.add(act)
            body = "&".join(f"{f}=1" for f in (fm.get("fields") or []) if f)
            e_steps.append(_step("run_csrf", {"url": act}, f"run_csrf:{act}"))
            e_steps.append(_step("run_race", {"url": act, "method": "POST", "body": body},
                                 f"run_race:{act}"))
    # ── mass assignment (CWE-915 / OWASP API3:2023 BOPLA / WSTG-INPV-20) on JSON writes ──
    #
    # Q-050. `run_mass_assign` shipped in Q-011 with a working dispatch method, an ASVS objective
    # (`asvs_model` ATHZ-04, `"verifiable": True`) and a WSTG test mapped onto it -- and was named
    # in NO scheduler, so no deterministic mission could ever select it. Q-011 fixed the phantom
    # NAME (`run_mass_assignment` -> `run_mass_assign`); the wiring never existed. Registration is
    # not invocation, and a control catalogue citing an engine the planner cannot select is a
    # coverage claim backed by nothing.
    #
    # THE PRECONDITION IS EVALUATED FROM OBSERVED STATE, and it is three facts, not one:
    #   1. a WRITE method -- the engine only accepts POST/PUT/PATCH, and a GET creates no object;
    #   2. a JSON media type the API ITSELF declared. `_forms_from_graph` carries the graph's
    #      `content_type` prop, which only the OpenAPI producer writes; an HTML form posts
    #      urlencoded and records none, so it does not match here. That is the whole negative
    #      control: a target with no JSON write endpoint gets no step, and the filter is a
    #      property of the surface rather than a rule written to make a test pass.
    #   3. at least one TYPED body parameter. `_run_mass_assign` refuses to invent a body
    #      (`"no base body ... a body invented from nothing would be rejected and read as a
    #      clean"`), so a step carrying only a URL would dispatch and do nothing -- the appearance
    #      of reach. The typed params are also the list of fields that are NOT mass assignment:
    #      `mass_assign_tool.privileged_candidates` excludes every field the endpoint offers.
    #
    # `read_paths` are GET paths the mission ACTUALLY OBSERVED on the same host (never invented --
    # `mass_assign_tool.read_views` ranks them and keeps only paths sharing a leading segment with
    # the write, so a `/books` view is never used to answer for a `/users` object).
    #
    # Login endpoints are excluded on purpose: a login write creates no object, so there is no
    # re-read view and the engine can only ever emit a lead. That is a budget decision, named here
    # rather than left as an accident.
    #
    # INTRUSIVE -- it writes objects -- so `_allowed()` schedules it in Full mode only, the same
    # gate already holding run_stored_xss / run_race / run_deserialization.
    ma_seen = set()
    for fm in sorted((state.get("recon", {}).get("forms") or []),
                     key=_form_value, reverse=True):
        act = fm.get("action")
        meth = str(fm.get("method") or "").upper()
        if not act or act in ma_seen or meth not in _WRITE_METHODS:
            continue
        if not _is_json_ct(fm.get("content_type")):
            continue
        bparams = [p for p in (fm.get("body_params") or [])
                   if isinstance(p, dict) and p.get("name")]
        if not bparams:
            continue
        if _LOGIN_SINK.search(_path(act)) or _path(act) in _LOGIN_PATHS:
            continue
        ma_seen.add(act)
        e_steps.append(_step("run_mass_assign",
                             {"url": act, "method": meth, "params": bparams,
                              "read_paths": _observed_get_paths(_host(act))},
                             f"run_mass_assign:{act}"))
        if len(ma_seen) >= CAP_MASS_ASSIGN:
            break
    # OAuth abuse on the standard OAuth surface per host + any discovered oauth/authorize path.
    oauth_seen = set()
    for h in host_bases:
        for pth in ("/oauth/authorize", "/authorize", "/.well-known/oauth-authorization-server"):
            ou = _b(h) + pth
            if ou not in oauth_seen:
                oauth_seen.add(ou)
                e_steps.append(_step("run_oauth", {"url": ou}, f"run_oauth:{h}{pth}"))
    for u in urls:
        if _re.search(r"(?:oauth|/authorize|openid|/sso)", _path(u), _re.I):
            base = _abs(u)
            if base and base not in oauth_seen:
                oauth_seen.add(base)
                e_steps.append(_step("run_oauth", {"url": base}, f"run_oauth:{base}"))
    # JWT weakness analysis (alg-confusion / weak-secret / kid) — only when the scan
    # carries a bearer/JWT token (authed runs); harmless no-op on unauth scans.
    import json as _json
    _blob = (_json.dumps(state.get("auth_headers") or {})
             + _json.dumps(state.get("recon", {}).get("cookies") or {}))
    _jm = _re.search(r"(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)", _blob)
    if _jm:
        e_steps.append(_step("run_jwt", {"token": _jm.group(1)}, "run_jwt"))
    # ffuf content/dir discovery on host roots (complements run_content_discovery); heavy,
    # so deep/insane only.
    if intensity in ("deep", "insane"):
        for h in host_bases[:CAP_HOSTS]:
            e_steps.append(_step("run_ffuf", {"url": _b(h) + "/FUZZ"}, f"run_ffuf:{h}"))
    e_steps = fresh(e_steps)
    if e_steps:
        return e_steps

    # ── phase F: nuclei (safe tags) per live host ──
    f_steps = []
    for h in sorted(set(roots) | set(subs)):
        f_steps.append(_step("run_nuclei",
                             {"target": _b(h), "tags": "tech,misconfig,exposed-panels,takeovers"},
                             f"run_nuclei:{h}"))
    f_steps = fresh(f_steps)
    if f_steps:
        return f_steps

    # ── phase F2: ZAP DAST (only when a ZAP daemon is configured) ──
    # A full scope-fenced ZAP pass (spider + AJAX spider + active scan) on the
    # primary in-scope host roots, seeded with the discovered surface (incl.
    # katana's crawl — see _run_zap). run_zap is ACTIVE (a DAST pass sends payloads
    # and reads responses), and it is held to FULL mode by `_HEAVY_FULL_ONLY` through
    # fresh()/_allowed() on COST — plus, independently, by `POST /engage`, which rejects
    # `enable_zap` unless mode == "full". Here it is also gated on ZAP actually being
    # configured. It runs LATE (after the fast tools) and is capped to CAP_ZAP
    # roots because a ZAP active scan is very slow. This is what makes Full mode
    # reliably run ZAP when configured + authorized, instead of leaving it to the
    # agentic model's discretion.
    if zap_on:
        _zpol = state.get("zap_policy", "safe_active")
        _zsp = state.get("zap_speed", "normal")
        _zag = state.get("zap_aggression", "normal")
        z_steps = [_step("run_zap", {"url": _b(h), "policy": _zpol, "speed": _zsp, "aggression": _zag},
                         f"run_zap:{h}") for h in host_bases[:CAP_ZAP]]
        z_steps = fresh(z_steps)
        if z_steps:
            return z_steps

    # ── phase F3: heavyweight nmap NSE vuln scan (opt-in) ──
    # The full `vuln` NSE category (minus DoS) on the primary in-scope host roots.
    # run_nmap_vuln is ACTIVE (version/behaviour probes, DoS scripts excluded, nothing
    # written) but very slow, so `_HEAVY_FULL_ONLY` holds it to Full via fresh()/_allowed().
    # It runs late and is capped. Results are truth-first advisory leads.
    if nmap_vuln_on:
        nv_steps = [_step("run_nmap_vuln", {"target": h}, f"run_nmap_vuln:{h}")
                    for h in targets[:CAP_ZAP]]
        nv_steps = fresh(nv_steps)
        if nv_steps:
            return nv_steps

    # ── phase F4: heavy nuclei — full vuln template set (opt-in), truth-first leads ──
    if nuclei_heavy_on:
        hn_steps = [_step("run_nuclei", {"target": _b(h), "heavy": True}, f"run_nuclei:heavy:{h}")
                    for h in targets[:CAP_HOSTS]]
        hn_steps = fresh(hn_steps)
        if hn_steps:
            return hn_steps

    # ── phase G: deterministic playbook (always, even passive) ──
    if "generate_playbook" not in done:
        return [_step("generate_playbook", {}, "generate_playbook")]

    return []
