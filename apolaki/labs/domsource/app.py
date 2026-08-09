"""
domsource — a lab for client-side sources that never reach the server.

WHY THIS EXISTS. dom_trace gained the URL FRAGMENT as a source. Everything after '#' is never transmitted:
it is absent from the server's access log, from a proxy capture, and from any request replay. That is
precisely why it needs a lab — the engine cannot be validated by checking what the server received,
because the server received nothing. The only observation point is the rendered DOM.

Routes, paired vulnerable/secure as usual:

    /hash        writes the WHOLE fragment into innerHTML          -> CONFIRMED, and executable (dom_xss)
    /hashparam   parses '#name=value' and writes it into a link    -> CONFIRMED as dom_link_manipulation
    /safehash    reads the fragment and writes it with textContent -> dom_data only, NEVER dom_xss
    /inert       never reads the fragment at all                   -> must yield NOTHING
    /noquery     ignores the query string entirely                 -> proves the finding came from the
                                                                      fragment and not from ?name=

Two controls, and they check different things.

/inert is the true negative: a page that reads no client-side source must produce no finding, or the
engine is reporting the canary rather than the source→sink flow.

/safehash is the SEVERITY control, and it corrected a wrong assumption of mine. `textContent` really is
a DOM-data sink — attacker-controlled rendered content is the definition of dom_data_manipulation, and
PortSwigger classifies it exactly that way — so expecting silence there was wrong. What separates it
from /hash is that the value can never EXECUTE. That is the distinction worth asserting.

/noquery is the attribution control. Without it, a canary appearing in the DOM proves only "the canary
reached a sink", not "the FRAGMENT reached a sink" — and the engine's whole claim is about the source.

Standard library only; no build, no dependency.
"""
import http.server
import socketserver

PORT = 8080

_HEAD = "<!doctype html><html><head><title>domsource lab</title></head><body>"
_TAIL = "</body></html>"

# VULNERABLE: the entire hash goes into innerHTML. Classic fragment_raw source.
_HASH = _HEAD + """<h1>hash sink</h1><div id="out">…</div>
<script>
  var v = decodeURIComponent(location.hash.slice(1));
  document.getElementById("out").innerHTML = v;
</script>""" + _TAIL

# VULNERABLE: the hash is parsed as a query string and one field becomes a link URL.
_HASHPARAM = _HEAD + """<h1>hash param sink</h1><a id="lnk" href="/">link</a>
<script>
  var p = new URLSearchParams(location.hash.slice(1));
  var r = p.get("redirect");
  if (r) { document.getElementById("lnk").setAttribute("href", r); }
</script>""" + _TAIL

# SECURE COUNTERPART: same source, but textContent is not a sink — no markup, no URL, no execution.
_SAFEHASH = _HEAD + """<h1>safe hash</h1><div id="out">…</div>
<script>
  document.getElementById("out").textContent = decodeURIComponent(location.hash.slice(1));
</script>""" + _TAIL

# CONTROL: proves attribution. The query string is never read, so a canary that lands here came from
# the fragment. Any engine reporting a query-sourced finding on this page is wrong.
_NOQUERY = _HEAD + """<h1>query ignored</h1><div id="out">this page never reads location.search</div>
<script>
  var v = decodeURIComponent(location.hash.slice(1));
  if (v) { document.getElementById("out").innerHTML = v; }
</script>""" + _TAIL

# TRUE NEGATIVE: reads no client-side source at all. Any finding here means the engine is reporting the
# presence of the canary rather than a proven source→sink flow.
_INERT = _HEAD + """<h1>inert</h1><div id="out">static content, no script reads any URL component</div>
""" + _TAIL

_ROUTES = {"/hash": _HASH, "/hashparam": _HASHPARAM, "/safehash": _SAFEHASH,
           "/noquery": _NOQUERY, "/inert": _INERT}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def do_GET(self):
        # The fragment is NOT in self.path — the browser strips it before sending. Nothing here can see
        # it, which is the property the lab exists to demonstrate.
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        body = _ROUTES.get(path)
        if body is None:
            body = _HEAD + "<h1>domsource</h1><ul>" + "".join(
                '<li><a href="%s">%s</a></li>' % (r, r) for r in sorted(_ROUTES)) + "</ul>" + _TAIL
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
