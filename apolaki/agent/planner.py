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
"""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

import dns_recon
import surface as surface_mod
from scope import PermissionLevel
from tools import TOOL_PERMISSIONS

# per-mode allowed permission tiers
_ALLOWED = {
    "passive": {PermissionLevel.PASSIVE},
    "active": {PermissionLevel.PASSIVE, PermissionLevel.ACTIVE},
    "full": {PermissionLevel.PASSIVE, PermissionLevel.ACTIVE, PermissionLevel.INTRUSIVE},
}

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


def _allowed(tool: str, mode: str) -> bool:
    tiers = _ALLOWED.get(mode, _ALLOWED["active"])
    return TOOL_PERMISSIONS.get(tool, PermissionLevel.ACTIVE) in tiers


def _step(tool: str, inp: dict, key: str) -> dict:
    return {"tool": tool, "input": inp, "key": key}


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
    # heavyweight nmap NSE vuln scan — opt-in; INTRUSIVE gate keeps it to Full mode.
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
        if not h:
            return f"https://{h}"
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
        base = urlparse(_b(p.netloc))
        return urlunparse((base.scheme, base.netloc, p.path, p.params, p.query, p.fragment))

    def fresh(steps):
        # dedup against `done` AND within this freshly built batch (a step's key can
        # be generated twice in one phase, e.g. run_graphql from a URL hint and from
        # a host root) — so the same call never fires twice.
        out, seen = [], set()
        for s in steps:
            k = s["key"]
            if k in done or k in seen or not _allowed(s["tool"], mode):
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
    targets = sorted(set(roots) | set(subs))
    if targets:
        # key on target count so a later recon cycle (more subdomains) re-runs httpx
        b.append(_step("run_httpx", {"targets": targets, "bases": bases}, f"run_httpx:{len(targets)}"))
    b.append(_step("check_takeover", {}, "check_takeover"))
    # http_probe each in-scope host root once (extracts links + params → surface)
    host_roots = []
    for h in sorted(set(roots) | set(subs) | set(url_hosts)):
        host_roots.append(h)
    for h in host_roots[:CAP_HOSTS]:
        b.append(_step("http_probe", {"url": _b(h)}, f"http_probe:{h}"))
    # JS-aware crawl of each in-scope root — essential for SPAs/APIs (e.g. Angular
    # apps) whose real surface, endpoints and params live in JS/XHR, not static
    # HTML that http_probe can parse. ACTIVE, so passive mode skips it via _allowed.
    for h in sorted(set(roots) | set(subs))[:CAP_HOSTS]:
        b.append(_step("run_katana", {"url": _b(h)}, f"run_katana:{h}"))
    b = fresh(b)
    if b:
        return b

    # ── phase C: fingerprint live hosts ──
    c = [_step("run_fingerprint", {"url": u}, f"run_fingerprint:{u}") for u in live_hosts[:CAP_HOSTS]]
    c = fresh(c)
    if c:
        return c

    # ── phase D: enrich (openapi / graphql / js) ──
    d = []
    js_urls = [u for u in urls if u.split("?")[0].lower().endswith(".js")]
    openapi_seen, graphql_seen = set(), set()
    for u in urls:
        low = u.lower()
        # normalize to the scope's known base — a discovered URL can carry a stale/
        # wrong scheme (e.g. https:// left over from before a non-standard-port
        # base was known), which fails outright on a plaintext-only port.
        nu = _b(_host(u)) + _path(u)
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
    inv_d = surface_mod.build_inventory(urls)
    for ep in [e for e in inv_d if e.get("parameterized")][:CAP_ENDPOINTS]:
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
        pg = _b(_host(u)) + _path(u)            # normalize to the scope's real base
        if pg in seen_pg:
            continue
        seen_pg.add(pg)
        page_urls.append(pg)
    for u in page_urls[:CAP_FORM_PAGES]:
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
    for u in rest_urls[:CAP_REST]:
        d.append(_step("http_probe", {"url": u}, f"http_probe:rest:{_host(u)}{_path(u)}"))
    d = fresh(d)
    if d:
        return d

    # ── phase E: surface-driven probes ──
    inv = surface_mod.build_inventory(urls)
    param_eps = [e for e in inv if e.get("parameterized")][:CAP_ENDPOINTS]
    host_bases = sorted({e["host"] for e in inv})[:CAP_HOSTS]
    e_steps = []
    # DOM audit (headless browser, client-side confirmation) — bounded because it
    # is slow: the live-host roots + a few HTML pages, skipping static assets.
    dom_pages, dom_seen = [], set()
    for u in [_b(h) for h in host_bases] + [
            _b_url(e.get("example")) or (_b(e['host']) + e['path']) for e in param_eps]:
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
            + [(_b_url(e.get("example")) or (_b(e['host']) + e['path'])) for e in param_eps]))[:CAP_SQLMAP]
        for u in pm_targets:
            e_steps.append(_step("run_param_mine", {"url": u}, f"run_param_mine:{u}"))
    # anomaly hunting (intuition leads) on app roots + key endpoints — a cheap active GET
    # + analysis flagging verbose errors / stack traces / debug + version-leak headers as
    # advisory 'dig here' leads (candidate, never confirmed).
    anom_targets = list(dict.fromkeys(
        [_b(h) for h in host_bases]
        + [(_b_url(e.get("example")) or (_b(e['host']) + e['path'])) for e in param_eps[:8]]))[:12]
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
        u = _b_url(ep.get("example")) or (_b(ep['host']) + ep['path'])
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
        # full fan-out at insane. INTRUSIVE -> _allowed() gates to Full. Deferred to the end.
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
    xml_eps = [e for e in inv if e.get("body_sink") or _XML_SINK.search(e.get("path") or "")][:CAP_HOSTS]
    for ep in xml_eps:
        u = _b_url(ep.get("example")) or (_b(ep['host']) + ep['path'])
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
    for u in urls:
        raw = u.split("?")[0].split("#")[0]
        if _is_static(raw):
            continue
        # normalize back to the scope's known base so a wrong-scheme/no-port junk URL
        # (https://host/path with the app really on http://host:port) is corrected
        pg = _b(_host(u)) + _path(u)
        if pg in seen_page or pg in form_seen:
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
            base = _b(_host(u)) + _path(u)      # normalize scheme+port to the known base
            if base not in chat_seen:
                chat_seen.add(base)
                e_steps.append(_step("run_llm_probe", {"url": base}, f"run_llm_probe:{base}"))
    for ep in inv:
        base = (_b_url(ep.get("example")) or (_b(ep['host']) + ep['path'])).split("?")[0]
        if _LOGIN_SINK.search(_path(base)) and base not in auth_seen:
            auth_seen.add(base)
            e_steps.append(_step("run_auth_sqli", {"url": base}, f"run_auth_sqli:{base}"))
            e_steps.append(_step("run_form_nosqli", {"url": base}, f"run_form_nosqli:{base}"))
    # plus a curated set of well-known login paths per in-scope host root
    for h in sorted(set(roots) | set(subs))[:CAP_HOSTS]:
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
    # OAuth abuse, JWT weaknesses and ffuf content discovery. Bounded; the INTRUSIVE
    # ones are gated to Full mode by fresh()/_allowed(). They run after the fast native
    # probes + sqlmap, so they never starve the confirmations that complete the report.
    for ep in param_eps:
        u = _b_url(ep.get("example")) or (_b(ep['host']) + ep['path'])
        tag = f"{ep['host']}{ep['path']}"
        e_steps.append(_step("run_deserialization", {"url": u}, f"run_deserialization:{tag}"))
        # object/function-level authz sweep — SAFE methods only (never DELETE).
        e_steps.append(_step("run_bfla", {"url": u, "allow_delete": False}, f"run_bfla:{tag}"))
    # dalfox — external XSS engine for stronger reflected-XSS confirmation; heavy, so
    # bound to the most injection-prone endpoints at deep, full fan-out at insane.
    dalfox_eps = (sorted(param_eps, key=_sqli_score, reverse=True)[:CAP_SQLMAP]
                  if intensity in ("deep", "insane") else param_eps[:3])
    for ep in dalfox_eps:
        u = _b_url(ep.get("example")) or (_b(ep['host']) + ep['path'])
        e_steps.append(_step("run_dalfox", {"url": u}, f"run_dalfox:{ep['host']}{ep['path']}"))
    # CSRF token check + race/rate-limit on state-changing POST forms.
    sc_seen = set()
    for fm in (state.get("recon", {}).get("forms") or []):
        act = fm.get("action")
        if act and str(fm.get("method", "GET")).upper() == "POST" and act not in sc_seen:
            sc_seen.add(act)
            body = "&".join(f"{f}=1" for f in (fm.get("fields") or []) if f)
            e_steps.append(_step("run_csrf", {"url": act}, f"run_csrf:{act}"))
            e_steps.append(_step("run_race", {"url": act, "method": "POST", "body": body},
                                 f"run_race:{act}"))
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
            base = _b(_host(u)) + _path(u)
            if base not in oauth_seen:
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
    # katana's crawl — see _run_zap). run_zap is INTRUSIVE, so fresh()/_allowed()
    # gates it to FULL mode only; here it is also gated on ZAP actually being
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
    # run_nmap_vuln is INTRUSIVE (fresh()/_allowed() gates it to Full) and slow, so
    # it runs late and is capped. Results are truth-first advisory leads.
    if nmap_vuln_on:
        nv_steps = [_step("run_nmap_vuln", {"target": h}, f"run_nmap_vuln:{h}")
                    for h in sorted(set(roots) | set(subs))[:CAP_ZAP]]
        nv_steps = fresh(nv_steps)
        if nv_steps:
            return nv_steps

    # ── phase F4: heavy nuclei — full vuln template set (opt-in), truth-first leads ──
    if nuclei_heavy_on:
        hn_steps = [_step("run_nuclei", {"target": _b(h), "heavy": True}, f"run_nuclei:heavy:{h}")
                    for h in sorted(set(roots) | set(subs))[:CAP_HOSTS]]
        hn_steps = fresh(hn_steps)
        if hn_steps:
            return hn_steps

    # ── phase G: deterministic playbook (always, even passive) ──
    if "generate_playbook" not in done:
        return [_step("generate_playbook", {}, "generate_playbook")]

    return []
