"""
SPA route discovery by DRIVING the rendered controls -- Q-163.

`ToolRegistry._spa_hash_routes` renders the page and harvests `a[href^="#"]`. That finds every route
an ANCHOR points at, and nothing else. MEASURED on juice-shop: the home page yields #/login,
#/contact, #/about, #/chatbot and #/photo-wall -- five routes, NONE carrying a parameter. The sweep
probes PARAMETERIZED endpoints, so all five are correctly skipped and the DOM-XSS chain that Q-161 /
Q-159 / Q-153 built never receives an input.

`#/search?q=` has no anchor anywhere in the application. A user reaches it by TYPING in the search
box and submitting. So this module types.

    read the rendered control surface  ->  type a benign marker  ->  submit
    ->  wait for `location.href` to CHANGE  ->  read the route the APPLICATION navigated to

Both halves of the answer are OBSERVED: the application chooses the route (`#/search`) and the
application chooses the parameter name (`q`). Nothing is invented. That is the whole reason this
mechanism was chosen over seed-probing a guessed list of sink-ish parameter names -- an invented
parameter is an invented-value probe wearing a different hat, and it would also be a
benchmark-specific signature the moment the seed list were tuned until juice-shop passed.

A runtime route TABLE (Angular's `router.config`) was rejected for a harder reason than taste: it
cannot answer the question. A router table lists PATH patterns. `q` is a query parameter -- it is not
in the route table at all, so extracting it yields `#/search` with zero parameters, which the sweep
then skips for exactly the reason above. It moves the gap, it does not close it.

READ-ONLY BY CONSTRUCTION. Two guarantees, both mechanical:
  * `input[type=password]` is never typed into.
  * while the drive is running, every non-GET/HEAD request the page attempts is ABORTED at the
    route layer. A hash-route navigation is pure client-side work and needs no network write, so
    the discovery still succeeds; a login POST or a comment POST cannot leave the browser.
  HONEST LIMITATION, stated because it is the cost of that guarantee: an application that navigates
  only AFTER a successful write will not be followed. That is a false negative, and a false negative
  is the correct side to fail on here.

DETERMINISM, not sleeping. Every wait in this module is a bounded wait for a CONDITION
(`wait_for_function` / `wait_for_load_state`), never `wait_for_timeout`. A fixed settle is
simultaneously too slow on an idle container and too short under mission load -- this cycle lost
three iterations to exactly that, twice with no error to show for it.

Degrades cleanly: no Playwright, no browser, an unreachable host or a page that renders no controls
all return a labelled empty result. Nothing is faked and nothing raises.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import browser_engine

# A benign discovery marker. It is NOT a payload and no oracle ever reads it: its only job is to be
# recognisable in the URL the application navigates to, so the parameter that CARRIED it can be
# named. Lowercase alphanumeric so no application can reject it for shape.
MARKER = "apolakirt7"

# The control surface this module is willing to drive. `password` is deliberately absent, and
# `number`/`file`/`color`/`range` are absent because a text marker cannot be filled into them.
TYPEABLE_TYPES = ("", "text", "search", "url", "tel", "email")

# Same string on both sides of the fence: JS enumerates with it, Playwright indexes into it. A
# different selector in the two places would silently address a different element.
CONTROL_SELECTOR = "input,textarea,[contenteditable='true']"

DEFAULT_MAX_CONTROLS = 8        # per page
DEFAULT_MAX_PAGES = 3           # the seed page plus anchor-linked routes
DEFAULT_NAV_TIMEOUT_MS = 2500   # bound on "did the app navigate?", not a sleep
DEFAULT_TIMEOUT_MS = 15000


# ───────────────────────────────────────────────────────────────── pure: URL shaping
def is_route_fragment(url) -> bool:
    """True when the fragment is a ROUTE ("#/search"), not an in-page anchor ("#top"). Pure.

    Mirrors surface.build_inventory's rule deliberately: treating "#section" links as pages would
    multiply the surface by every in-page link on the site.
    """
    try:
        return urlparse(str(url or "")).fragment.startswith("/")
    except Exception:
        return False


def split_fragment(url) -> tuple:
    """("#/search?q=x") -> ("/search", [("q", "x")]). Pure; blank values are KEPT."""
    try:
        frag = urlparse(str(url or "")).fragment
    except Exception:
        return "", []
    route, sep, q = frag.partition("?")
    return route, (parse_qsl(q, keep_blank_values=True) if sep else [])


def blank_marked_values(url, marker: str = MARKER) -> str:
    """Return `url` with every parameter value that CARRIED the marker emptied. Pure.

    `#/search?q=apolakirt7` -> `#/search?q=`. The marker was a vehicle, not a finding: what we
    learned is that the route takes a parameter named `q`. Leaving the marker in would put a
    meaningless literal into the inventory `example` and into every reproduction step. Values the
    APPLICATION itself put there (a fixed `?lang=en`) are untouched -- those are observed facts.
    """
    m = str(marker or "")
    try:
        p = urlparse(str(url or ""))
    except Exception:
        return str(url or "")

    def _blank(qs):
        pairs = parse_qsl(qs, keep_blank_values=True)
        if not pairs:
            return ""
        return urlencode([(k, "" if (m and m in v) else v) for k, v in pairs])

    route, sep, fq = p.fragment.partition("?")
    fqs = _blank(fq) if sep else ""
    frag = route + ("?" + fqs if fqs else "")
    return urlunparse(p._replace(query=_blank(p.query), fragment=frag))


def inventory_path(url) -> str:
    """The path key `surface.build_inventory` will file this URL under. Pure.

    Kept byte-identical to that function's rule on purpose: a route this module reports as
    discovered and the inventory entry it produces have to be the same page, or the handoff is
    claiming a link that does not exist.
    """
    try:
        p = urlparse(str(url or ""))
    except Exception:
        return "/"
    route, _, _ = p.fragment.partition("?")
    path = p.path or "/"
    if route.startswith("/"):
        return (path.rstrip("/") + "#" + route) if path != "/" else "#" + route
    return path


def route_record(before_href, after_href, marker: str = MARKER, control=None) -> dict:
    """The route the application navigated to, as a fact. Pure; {} when it did not navigate.

    `parameterized` is COMPUTED from the observed URL, never asserted: it is the single field the
    downstream sweep keys on, and a record that claimed it without a parameter to point at would be
    a declaration masquerading as a fact.
    """
    after, before = str(after_href or ""), str(before_href or "")
    if not after or after == before:
        return {}
    canon = blank_marked_values(after, marker)
    _route, fpairs = split_fragment(canon)
    try:
        qpairs = parse_qsl(urlparse(canon).query, keep_blank_values=True)
    except Exception:
        qpairs = []
    params = sorted(dict.fromkeys([k for k, _ in list(fpairs) + list(qpairs) if k]))
    return {"url": canon, "observed_url": after, "before_url": before,
            "path": inventory_path(canon), "params": params, "parameterized": bool(params),
            "hash_route": is_route_fragment(canon), "source": "typed-control",
            "control": dict(control or {})}


def merge_routes(records) -> list:
    """De-duplicate route records by (path, params), keeping the first of each. Pure.

    Two controls that both reach `#/search?q=` are one discovery, and a parameterised record must
    never be displaced by a bare one for the same page.
    """
    out, seen = [], {}
    for r in records or []:
        if not isinstance(r, dict) or not r.get("url"):
            continue
        key = (r.get("path") or "", tuple(r.get("params") or ()))
        if key in seen:
            continue
        seen[key] = True
        out.append(r)
    return out


def parameterized_urls(records) -> list:
    """The URLs worth handing back to the crawl: the ones carrying a parameter. Pure."""
    return [r["url"] for r in merge_routes(records) if r.get("parameterized") and r.get("url")]


# ───────────────────────────────────────────────────────────────── browser plumbing
def available() -> tuple:
    """(usable, note). Never raises."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception as exc:
        return False, "playwright unavailable: %s" % type(exc).__name__
    return True, "playwright + chromium"


def _empty(base: str, note: str) -> dict:
    return {"base": base, "browser": False, "ran": False, "note": note,
            "routes": [], "urls": [], "attempts": [], "pages": [], "errors": []}


# Enumerate the typeable control surface. Returns the DOM-order INDEX into CONTROL_SELECTOR so the
# caller can address the same element through Playwright, plus enough identity to record WHAT was
# driven. Visibility is the same definition BIE uses (displayed AND a non-empty box) -- juice-shop's
# search input is 4px wide when collapsed, so anything stricter would discard the one control that
# matters and this module would report "no controls" on the very app it was written for.
_CONTROL_JS = """(sel) => {
  const out = [];
  const nodes = document.querySelectorAll(sel);
  for (let i = 0; i < nodes.length; i++) {
    const el = nodes[i];
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (tag === 'input' && !%s.includes(type)) continue;
    if (el.disabled === true || el.readOnly === true) continue;
    if (el.getAttribute('aria-disabled') === 'true') continue;
    let cs = {};
    try { cs = getComputedStyle(el); } catch (e) {}
    const r = el.getBoundingClientRect();
    const displayed = cs.display !== 'none' && cs.visibility !== 'hidden' && Number(cs.opacity || 1) > 0;
    if (!displayed || r.width <= 0 || r.height <= 0 || el.hasAttribute('hidden')) continue;
    out.push({index: i, tag: tag, type: type, id: el.id || '',
              name: el.getAttribute('name') || '',
              placeholder: (el.getAttribute('placeholder') || '').slice(0, 60),
              aria: (el.getAttribute('aria-label') || '').slice(0, 60),
              width: Math.round(r.width), height: Math.round(r.height)});
  }
  return out;
}"""


def control_js(typeable=TYPEABLE_TYPES) -> str:
    """The enumeration script with the allowed input types baked in. Pure."""
    import json
    return _CONTROL_JS % json.dumps([str(t) for t in typeable])


# Route-shaped anchors on the page we are standing on. Used only to pick FURTHER pages to drive --
# these routes are already harvested by tools._spa_hash_routes and are not re-reported here.
_ANCHOR_JS = ("() => [...new Set([...document.querySelectorAll('a[href]')]"
              ".map(a => a.getAttribute('href')))].filter(h => h && h.slice(0, 2) === '#/')")


def _read_only_gate(route):
    """Abort every non-GET/HEAD request; defer GETs to the handler chain (browser_engine's rate gate
    lives there, and continue_() here would silently shadow it). Never raises."""
    try:
        method = (route.request.method or "GET").upper()
    except Exception:
        method = "GET"
    try:
        if method in ("GET", "HEAD"):
            fallback = getattr(route, "fallback", None)
            (fallback or route.continue_)()
        else:
            route.abort()
    except Exception:
        pass


# The readiness condition: the number of rendered controls has stopped changing. CONVERGENCE, not a
# duration -- it resolves as soon as the app stops adding controls and keeps waiting while it is
# still rendering, which a fixed settle can do in neither direction. Polled on animation frames.
_STABLE_JS = """(sel) => {
  const n = document.querySelectorAll(sel).length;
  const w = window.__apolaki_ctl || {c: -1, s: 0};
  if (n > 0 && n === w.c) { w.s++; } else { w.s = 0; }
  w.c = n; window.__apolaki_ctl = w;
  return w.s >= 3 ? n : false;
}"""


def _settle(page, timeout_ms: int) -> str:
    """Wait for the CONDITIONS that make the page drivable. Bounded; never raises. Returns how it was
    synchronised, so the evidence records the mechanism instead of hiding a magic number.

    `networkidle` IS NOT USED, and that is a measured decision rather than a preference. MEASURED on
    juice-shop, same page, same browser:

        no route handler installed        1.40s   networkidle+controls
        page.route("**/*", ...) installed 15.28s  networkidle-TIMEOUT+controls   (the full bound)
        ... and again                     25.20s  networkidle-timeout+controls

    Interception (which this module requires to stay read-only) is enough to keep the connection
    count from ever reaching idle, so `networkidle` is a condition that never becomes true here: it
    degrades silently into "wait the entire timeout". Waiting on `load` plus control CONVERGENCE
    instead costs 0.39-0.45s gated and finds the same route.
    """
    reason = "load"
    try:
        page.wait_for_load_state("load", timeout=timeout_ms)
    except Exception:
        reason = "load-timeout"
    try:
        page.evaluate("() => { window.__apolaki_ctl = null; }")     # fresh count per navigation
    except Exception as _apolaki_exc:
        # Coordinator repair: LOAD-BEARING, and it was a bare `pass`. This reset is what makes the
        # control count fresh per navigation; if it fails silently the PREVIOUS page's count
        # survives, the stability wait below can satisfy itself against stale state, and the drive
        # then runs on a page that never settled. Recorded through the active registry, the same
        # way `dns_recon.doh` reaches the ledger from module scope.
        import tools as _tools
        _tools._swallow(_apolaki_exc, "spa_routes._settle:ctl_reset", "")
    try:
        page.wait_for_function("(sel) => document.querySelectorAll(sel).length > 0",
                               arg=CONTROL_SELECTOR, timeout=timeout_ms)
    except Exception:
        return reason + "+no-controls"
    try:
        page.wait_for_function(_STABLE_JS, arg=CONTROL_SELECTOR, polling="raf", timeout=timeout_ms)
        return reason + "+controls-stable"
    except Exception:
        # Controls exist; they were still churning when the bound expired. Drivable, and SAID SO --
        # a run synchronised on a weaker condition must not look identical to one that converged.
        return reason + "+controls-unstable"


def _goto(page, url: str, timeout_ms: int) -> str:
    try:
        browser_engine.rate_limited_goto_sync(page, url, wait_until="domcontentloaded",
                                              timeout=timeout_ms)
    except Exception as exc:
        return "navigation-failed: %s" % type(exc).__name__
    return _settle(page, timeout_ms)


def _href(page) -> str:
    """The browser's current location, or "" when it could not be read -- RECORDED either way.

    Coordinator repair. This was a bare `except: return ""`, which the silent-failure census
    classifies LOAD-BEARING, and it is right to: the route record is a BEFORE/AFTER href pair, so a
    read that fails silently makes a real navigation look like "the app did not move" and the
    discovered route disappears. `_drive_page`'s own docstring three lines below says exactly this
    about `except: return []`, and the same reasoning had not been carried up here.

    Module-level helpers with no `self` reach the ledger through `tools._ACTIVE_REGISTRY`,
    published for the span of `ToolRegistry.execute` -- the pattern `dns_recon.doh` already uses.
    Imported as a statement, not via `sys.modules.get`, because `deadcode_gate` only resolves a
    caller through a RESOLVED import.
    """
    try:
        return str(page.evaluate("() => location.href") or "")
    except Exception as _apolaki_exc:
        import tools as _tools
        _tools._swallow(_apolaki_exc, "spa_routes._href", "")
        return ""


def _drive_page(page, page_url: str, *, marker: str, max_controls: int, timeout_ms: int,
                nav_timeout_ms: int, attempts: list, errors: list) -> list:
    """Type the marker into every typeable control on the page the browser is standing on, submit,
    and record where the application went. Never raises; every failure is APPENDED, because
    `except: return []` would make "this page has no controls" byte-identical to "the read crashed"
    -- the exact shape that produced four false clean results in this codebase already."""
    try:
        controls = list(page.evaluate(control_js(), CONTROL_SELECTOR) or [])
    except Exception as exc:
        errors.append("control-read %s: %s" % (type(exc).__name__, str(exc)[:140]))
        return []
    found = []
    batch = controls[:max_controls]
    for pos, ctl in enumerate(batch):
        idx = int(ctl.get("index", -1))
        if idx < 0:
            continue
        before = _href(page)
        loc = page.locator(CONTROL_SELECTOR).nth(idx)
        attempt = {"page": page_url, "control": ctl, "before": before, "after": before,
                   "changed": False, "failure": ""}
        try:
            loc.fill(str(marker), timeout=min(4000, timeout_ms))
        except Exception as exc:
            attempt["failure"] = "fill: %s" % type(exc).__name__
            attempts.append(attempt)
            continue
        try:
            loc.press("Enter", timeout=min(4000, timeout_ms))
        except Exception as exc:
            attempt["failure"] = "submit: %s" % type(exc).__name__
        # THE CONDITION, bounded: did the application navigate? Resolves the instant it does.
        try:
            page.wait_for_function("(h) => location.href !== h", arg=before, timeout=nav_timeout_ms)
        except Exception:
            pass
        after = _href(page)
        attempt["after"] = after
        rec = route_record(before, after, marker, ctl)
        attempt["changed"] = bool(rec)
        attempts.append(attempt)
        if rec:
            found.append(rec)
            # Back to the page under test: the NEXT control must be driven from the same state, not
            # from wherever the last submission landed. Skipped after the last one -- MEASURED on
            # juice-shop, whose networkidle settle is ~7s, that restore was 40% of a 17.5s discovery
            # and nothing ever read the page it restored.
            if pos < len(batch) - 1:
                _goto(page, page_url, timeout_ms)
    return found


def discover(base: str, *, scope_ok=None, marker: str = MARKER,
             max_controls: int = DEFAULT_MAX_CONTROLS, max_pages: int = DEFAULT_MAX_PAGES,
             timeout_ms: int = DEFAULT_TIMEOUT_MS, nav_timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS,
             headers: dict = None) -> dict:
    """Discover param-bearing SPA routes by driving the application's own rendered controls.

    `scope_ok(url) -> bool` is the caller's scope gate; every URL this touches passes through it.
    Returns {"routes": [record...], "urls": [parameterised url...], ...}. Never raises: this
    AUGMENTS a crawl, and a browser that will not start must not fail a crawl that otherwise
    succeeded -- but every failure is labelled, so "no routes" and "it never ran" stay
    distinguishable in the ledger.
    """
    base = str(base or "").split("#")[0].rstrip("/") or str(base or "")
    if not base:
        return _empty(base, "no base url")
    ok = scope_ok or (lambda _u: True)
    try:
        if not ok(base):
            return _empty(base, "base url is out of scope")
    except Exception:
        return _empty(base, "scope gate raised")
    usable, note = available()
    if not usable:
        return _empty(base, note)

    from playwright.sync_api import sync_playwright
    out = _empty(base, "")
    out.update({"browser": True, "ran": True, "note": ""})
    attempts, errors, routes = out["attempts"], out["errors"], []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers={str(k): str(v) for k, v in (headers or {}).items()})
                page = ctx.new_page()
                # BREAKER F2. Installed BEFORE the first navigation, not after it.
                #
                # This was registered after the boot navigation had completed AND settled, "so the
                # app boots normally" -- which left the entire settle window (bounded by
                # timeout_ms, default 15s) with NO interception at all. MEASURED by the Breaker:
                # two POSTs reached a fixture server through that window, and one real POST reached
                # juice-shop. The module's own docstring promises "a login POST or a comment POST
                # cannot leave the browser", and for that window it could.
                #
                # Booting behind the gate is the correct trade: an application that needs to WRITE
                # in order to render is one this module must not drive anyway, and a lost render is
                # a false negative while an escaped write is a change to someone else's system.
                page.route("**/*", _read_only_gate)
                out["pages"].append({"url": base, "settle": _goto(page, base, timeout_ms)})
                targets = [base]
                if max_pages > 1:
                    try:
                        for h in list(page.evaluate(_ANCHOR_JS) or []):
                            u = base + str(h)
                            if u not in targets and ok(u):
                                targets.append(u)
                    except Exception as exc:
                        errors.append("anchor-read %s: %s" % (type(exc).__name__, str(exc)[:140]))
                for i, turl in enumerate(targets[:max(1, int(max_pages))]):
                    if i:      # the seed page is already loaded and settled
                        out["pages"].append({"url": turl,
                                             "settle": _goto(page, turl, timeout_ms)})
                    routes += _drive_page(page, turl, marker=marker, max_controls=max_controls,
                                          timeout_ms=timeout_ms, nav_timeout_ms=nav_timeout_ms,
                                          attempts=attempts, errors=errors)
                try:
                    page.unroute("**/*", _read_only_gate)
                except Exception:
                    pass
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as exc:
        out["note"] = "browser failed: %s: %s" % (type(exc).__name__, str(exc)[:160])
        out["ran"] = bool(attempts)

    routes = [r for r in merge_routes(routes) if _in_scope(ok, r.get("url"))]
    out["routes"] = routes
    out["urls"] = parameterized_urls(routes)
    if not out["note"]:
        out["note"] = "%d route(s), %d parameterised, from %d control attempt(s)" % (
            len(routes), len(out["urls"]), len(attempts))
    return out


def _in_scope(ok, url) -> bool:
    try:
        return bool(url) and bool(ok(url))
    except Exception:
        return False


async def discover_async(base: str, **kw) -> dict:
    """`discover` off the event loop. The sync Playwright API refuses to run in a thread that owns a
    running loop, so the established pattern here (tools.py: `await asyncio.to_thread(bie....)`) is
    a worker thread. Never raises."""
    import asyncio
    import functools
    try:
        return await asyncio.to_thread(functools.partial(discover, base, **kw))
    except Exception as exc:
        return _empty(str(base or ""), "discover_async failed: %s" % type(exc).__name__)
