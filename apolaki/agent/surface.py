"""Attack-surface inventory.

Turns the flat list of discovered URLs (crawl + archive + param mining) into a
deduplicated endpoint / parameter catalog the analyst can browse and pivot from
into the workbench (fuzz a param) or access-check (test an endpoint per role).
Pure and deterministic — no network, no AI. Ported from OLYMPUS core/surface.py.
"""
import html as _html
import re
from urllib.parse import urlparse, parse_qsl, unquote

# HTML entities that only appear in a URL because it was scraped out of markup
# (e.g. an <a href> value that swallowed the closing tag). Decoded markup chars
# (< > " \) are caught separately after percent-decoding.
# Q-125: `(?!=)` is the whole difference between residue and a parameter. Without it this rejected
# `?lt=1&gt=2` outright -- `lt` and `gt` are ordinary comparison-filter parameter names and also
# entity names, and a semicolon-less `&lt` followed by `=` is a parameter, not swallowed markup. The
# residue this exists to catch (`/users/delete/carlos%3C/a%3E&quot`) is never followed by `=`.
_ENTITY_RE = re.compile(r"&(?:quot|lt|gt|nbsp|amp;lt|amp;gt|#x?[0-9a-f]+);?(?!=)", re.I)
_MARKUP_CHARS_RE = re.compile(r'[<>"\\]')
# Paths that likely accept an XML/SOAP request BODY (XXE sinks) rather than query
# params — kept in sync with the planner's run_xxe trigger.
_XML_SINK_PATH = re.compile(
    r"/(?:soap|xml|wsdl|rss|feed|xmlrpc|import|export|ews|services|b2b|stock|stockcheck)(?:/|$|\?)"
    r"|\.xml(?:$|\?)", re.I)


def clean_url(u) -> bool:
    """True if `u` is a real, testable URL — not an HTML-extraction artifact.

    Wayback / HTML link mining routinely emits fragments like `/%3C/a%3E`,
    `/about%3C/a%3E%3C/span%3E`, `/users/delete/carlos%3C/a%3E&quot`, `/%5C` or a
    bare `/)`. These pollute the surface, topology, memory, playbooks and
    prefills, so we drop them before they are ever stored. Conservative: it only
    rejects clear markup residue, never a normal path/query."""
    if not isinstance(u, str) or not u:
        return False
    if _ENTITY_RE.search(u):
        return False
    # percent-decode once so %3C/%3E/%22/%5C surface as the raw markup chars
    if _MARKUP_CHARS_RE.search(unquote(u)):
        return False
    try:
        p = urlparse(u)
    except Exception:
        return False
    if not p.netloc:
        return False
    first = (p.path or "/").lstrip("/").split("/")[0]
    if first and first[0] in ")(<>&;'\"`,":     # punctuation-led segment = artifact
        return False
    return True


# Q-172. A QUERY PARAMETER WHOSE VALUE NAMES A PAGE IS A ROUTE SELECTOR, and each value it takes is
# a distinct page -- the server-side twin of the hash-route rule below.
#
# MEASURED on mutillidae: 45 distinct `index.php?page=<x>.php` targets are linked directly from the
# home page, one hop from the root. All 45 collapsed into the single inventory key
# ("mutillidae", "/index.php") with params {"page"}, and a mission reached only 10 of them.
# `dns-lookup.php` was never among them -- so its `target_host` command injection, which returns
# `uid=33(www-data)` to `127.0.0.1;id`, was never seen. 78% of the application's surface was
# discarded, and every engine's zero on it was correct and meaningless.
#
# Detected by the VALUE's shape, never by the parameter's name: `page`, `file`, `view`, `module`,
# `do` and friends are all the same construct, and a name list would catch whichever ones somebody
# thought of. A search term is not normally spelled `something.php`, which is what keeps `?q=` out.
#
# ADDITIVE ON PURPOSE. The collapsed entry SURVIVES, carrying the selector as a param, so the
# traversal/LFI probe on `page` itself runs exactly as it does today; the derived per-route entries
# drop the selector from their params so that one probe is not repeated 45 times. New surface, no
# behaviour removed, no extra cost on the parameter that was already covered.
_ROUTE_VALUE = re.compile(r"^[A-Za-z0-9_\-./]{1,80}\.(?:php|asp|aspx|jsp|jspx|cfm|cgi|pl|do|action|html?)$", re.I)


def build_inventory(urls, cap: int = 1000) -> list:
    """Group URLs by (host, path); union the query params seen for each.

    Markup-artifact URLs are filtered here too, so even already-stored / archived
    URL lists render a clean inventory."""
    by_key = {}
    order = []
    for u in urls or []:
        if not isinstance(u, str) or not u or not clean_url(u):
            continue
        try:
            p = urlparse(u)
        except Exception:
            continue
        if not p.netloc:
            continue
        path = p.path or "/"
        params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        # Q-161. A HASH ROUTE IS A DISTINCT PAGE. On a hash-routed SPA the fragment IS the route,
        # and `urlparse("http://h/#/contact").path` is "/" -- so #/contact, #/login and the bare
        # page all collapsed into one inventory entry and every discovered route vanished before
        # the planner could see it. Last link in the chain: the probe source (Q-153), the crawl
        # discovery (Q-157) and the sweep key (Q-159) were all fixed and still nothing was probed.
        #
        # Only a ROUTE-SHAPED fragment ("#/...") counts. A bare "#section" anchor is a position in
        # the SAME document, and treating those as pages would multiply the surface by every
        # in-page link on the site.
        if p.fragment.startswith("/"):
            # The route is the identity; its query string is PARAMS, exactly as for a real path.
            # Carrying `?q=x` into the key would make every search term a separate "page".
            _route, _, _fq = p.fragment.partition("?")
            path = (path.rstrip("/") + "#" + _route) if path != "/" else "#" + _route
            params += [k for k, _ in parse_qsl(_fq, keep_blank_values=True)]
        # Q-172: a route-selector value earns its own identity, in addition to the collapsed
        # entry that keeps the selector itself under test.
        _route_kv = next(((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                          if _ROUTE_VALUE.match(v or "")), None)
        if _route_kv:
            _rk, _rv = _route_kv
            _rpath = "%s?%s=%s" % (path, _rk, _rv)
            _rkey = (p.netloc, _rpath)
            if _rkey not in by_key:
                by_key[_rkey] = {"host": p.netloc, "path": _rpath,
                                 "params": set(), "example": u}
                order.append(_rkey)
            by_key[_rkey]["params"].update(k for k in params if k != _rk)
        key = (p.netloc, path)
        if key not in by_key:
            by_key[key] = {"host": p.netloc, "path": path, "params": set(), "example": u}
            order.append(key)
        by_key[key]["params"].update(params)
        if params and "?" not in by_key[key]["example"]:
            by_key[key]["example"] = u

    out = []
    for key in order[:cap]:
        e = by_key[key]
        body_sink = bool(_XML_SINK_PATH.search(e["path"] or ""))
        out.append({
            "host": e["host"],
            "path": e["path"],
            "params": sorted(e["params"]),
            "parameterized": bool(e["params"]),
            # An XML/SOAP path is a likely POST-body sink even with no query params,
            # so the UI/planner stop treating it as an inert param-free GET endpoint.
            "body_sink": body_sink,
            "content_type": "application/xml" if body_sink else "",
            "example": e["example"],
        })
    return out


def endpoints_from_openapi(spec, base_url: str) -> list:
    """Extract testable endpoint URLs (with query params) from an OpenAPI 3 or
    Swagger 2 spec, anchored to base_url's host.

    Scope-safe: only the base *path* is borrowed from the spec's `servers` /
    `basePath` — the host is always base_url, never a foreign host the spec may
    declare."""
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return []
    base = base_url.rstrip("/")

    bp = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = servers[0].get("url", "") or ""
        bp = urlparse(u).path if u.startswith("http") else (u if u.startswith("/") else "")
    if not bp:
        bp = spec.get("basePath", "") or ""
    root = (base + bp).rstrip("/")

    out = []
    for path, methods in spec["paths"].items():
        if not isinstance(methods, dict):
            continue
        qparams, testable = set(), False
        for m, op in methods.items():
            if m.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            testable = True
            if isinstance(op, dict):
                for p in (op.get("parameters") or []):
                    if isinstance(p, dict) and p.get("in") == "query" and p.get("name"):
                        qparams.add(str(p["name"]))
        if not testable:
            continue
        concrete = re.sub(r"\{[^}]+\}", "1", str(path))
        full = root + "/" + concrete.lstrip("/")
        if qparams:
            full += ("&" if "?" in full else "?") + "&".join(f"{n}=test" for n in sorted(qparams))
        out.append(full)
    return list(dict.fromkeys(out))


_SPEC_METHODS = ("get", "post", "put", "delete", "patch")


def _spec_base(spec, base_url: str) -> str:
    """The spec's base PATH anchored to base_url's host. Scope-safe: only the path is borrowed from
    `servers` / `basePath`; the host is always base_url, never a host the spec declares."""
    bp = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = servers[0].get("url", "") or ""
        bp = urlparse(u).path if u.startswith("http") else (u if u.startswith("/") else "")
    if not bp:
        bp = spec.get("basePath", "") or ""
    return (base_url.rstrip("/") + bp).rstrip("/")


def operations_from_openapi(spec, base_url: str) -> list:
    """Every operation a spec declares, WITH its typed parameters and its method.

    Q-031. `endpoints_from_openapi` (above) answers "what URLs can I fetch" and is deliberately left
    alone -- it has callers and a stable contract. It cannot answer "what parameters does this API
    take", because it reads only `in == "query"`, collapses the method to a bool, and returns bare
    strings. MEASURED on VAmPI: 14 operations / 0 query params / 9 BODY params in, 12 URLs and 0
    parameters out. Body parameters are the largest untested surface class on any JSON API, and the
    planner could not name one.

    Returns [{url, path, method, content_type, params: [{name, location, type, required}]}] covering
    OpenAPI 3 (`requestBody.content.<ct>.schema`) and Swagger 2 (`parameters[in=body].schema`), plus
    query / header / path / cookie parameters. `$ref` is NOT resolved -- an unresolved schema yields
    no properties rather than a guess, which is why `params` can legitimately be empty. Pure.
    """
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return []
    root = _spec_base(spec, base_url)
    out = []
    for path, methods in spec["paths"].items():
        if not isinstance(methods, dict):
            continue
        shared = [p for p in (methods.get("parameters") or []) if isinstance(p, dict)]
        for m, op in methods.items():
            if m.lower() not in _SPEC_METHODS or not isinstance(op, dict):
                continue
            params, ctype = [], ""
            for p in shared + [q for q in (op.get("parameters") or []) if isinstance(q, dict)]:
                loc = str(p.get("in") or "").lower()
                name = p.get("name")
                if not name:
                    continue
                if loc == "body":                      # Swagger 2 body parameter
                    sch = p.get("schema") or {}
                    req = set(sch.get("required") or [])
                    for pn, meta in (sch.get("properties") or {}).items():
                        params.append({"name": str(pn), "location": "body",
                                       "type": str((meta or {}).get("type") or ""),
                                       "required": pn in req})
                    ctype = ctype or "application/json"
                elif loc in ("query", "header", "path", "cookie"):
                    params.append({"name": str(name), "location": loc,
                                   "type": str(((p.get("schema") or {}).get("type"))
                                                or p.get("type") or ""),
                                   "required": bool(p.get("required"))})
            body = op.get("requestBody") or {}         # OpenAPI 3
            for ct, media in ((body.get("content") or {}) if isinstance(body, dict) else {}).items():
                sch = (media or {}).get("schema") or {}
                req = set(sch.get("required") or [])
                for pn, meta in (sch.get("properties") or {}).items():
                    params.append({"name": str(pn), "location": "body",
                                   "type": str((meta or {}).get("type") or ""),
                                   "required": pn in req})
                if (sch.get("properties") or ct) and not ctype:
                    ctype = str(ct)
            concrete = re.sub(r"\{[^}]+\}", "1", str(path))
            out.append({"url": root + "/" + concrete.lstrip("/"), "path": str(path),
                        "method": m.upper(), "content_type": ctype,
                        "params": params})
    return out


def surface_stats(inventory: list) -> dict:
    hosts = {e["host"] for e in inventory}
    params = set()
    for e in inventory:
        params.update(e.get("params") or [])
    return {
        "endpoints": len(inventory),
        "hosts": len(hosts),
        "parameterized": sum(1 for e in inventory if e.get("parameterized")),
        "unique_params": len(params),
    }


#: A named or numeric HTML entity that ENDS IN A SEMICOLON. The semicolon is the whole point -- see
#: `unescape_url_entities`.
_TERMINATED_ENTITY = re.compile(
    r"&(?:[a-zA-Z][a-zA-Z0-9]{1,31}|#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6});")


def unescape_url_entities(s: str) -> str:
    r"""HTML-unescape a URL taken from markup, decoding ONLY semicolon-terminated entities.

    Q-125. `html.unescape` MUST NOT be applied to a URL. It implements the HTML5 rule for text
    content, where a named reference is decoded even WITHOUT its semicolon -- and in a query string
    every parameter name is preceded by `&`, so an ordinary name that happens to start with an entity
    name is silently destroyed. MEASURED, one line, seven casualties:

        in       ?lamp=1&ampersand=2&amplitude=3
        blanket  ?lamp=1&ersand=2&litude=3
        in       ?a=1&times=2&lt=3&gt=4&copy=5&reg=6&sect=7&not=8
        blanket  ?a=1x=2<=3>=4(c)=5(r)=6S=7!=8

    `copy`, `reg`, `sect`, `not`, `times`, `para`, `sup`, `deg` and `micro` are all real parameter
    names and all legacy entities. Q-111/Q-111b shipped the blanket call at two chokepoints, so this
    was corrupting the surface while fixing a different corruption of it.

    Requiring the semicolon IS the HTML5 attribute-value rule: inside an attribute, a reference
    without a semicolon followed by `=` or an alphanumeric is not a reference. Browsers already
    behave this way, which is why `<a href="?ampersand=2">` requests `ampersand`, not `ersand`.

    `&amp;` still decodes, which is the case Q-111 existed for and the only one that ever mattered:
    it is what every HTML escaper emits for a literal `&`.
    """
    return _TERMINATED_ENTITY.sub(lambda m: _html.unescape(m.group(0)), str(s or ""))
