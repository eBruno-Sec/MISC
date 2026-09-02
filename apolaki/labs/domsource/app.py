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
import base64
import json
import hashlib
import io
import contextlib
import urllib.parse
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

# AUTHENTICATED-SCAN BLIND SPOT. This page reflects ?redirect= into the DOM, but only for an ANONYMOUS
# visitor: presenting a session cookie bounces the browser to /account, exactly as a real login page
# does. An authenticated scan therefore never renders this page and never sees its DOM bug — measured on
# a live target, where dom_trace found /login's redirect-param finding standalone and missed it
# in-mission while /my-account showed up in the traced paths.
_AUTHBOUNCE = _HEAD + """<h1>login</h1><div id="out">…</div>
<script>
  var p = new URLSearchParams(location.search);
  document.getElementById("out").innerHTML = p.get("redirect") || "no redirect";
</script>""" + _TAIL

_ACCOUNT = _HEAD + "<h1>account</h1><p>signed in; this page has no user-controlled sink</p>" + _TAIL

# Q-148 LIVENESS. A page that leaks key material, so `passive_disclosure` can be proven to fire
# through the REAL dispatch path rather than only in unit tests. Static reachability is not
# liveness: engines have been found silently dead here with the whole suite green.
#
# The key material is DERIVED AT RUNTIME and never stored in the repo. A literal PEM block in
# source is indistinguishable from a real leaked key to a secret scanner -- ours and GitHub push
# protection alike -- and the lab does not need one to be structurally valid. This is
# deterministic, clears the module minimum body length, and is not a key.
_FAKE_KEY_BODY = "\n".join(
    base64.b64encode(hashlib.sha256(("apolaki-domsource-liveness-%d" % i).encode()).digest() * 2
                     ).decode()
    for i in range(3))
# NOT wrapped in <pre>. The first version of this route was, and `passive_disclosure`
# correctly stayed silent: a key inside a display element is a DOCUMENTATION page, which is
# the exact false positive the module suppresses. A real leak is a backup file served as-is,
# so that is what this serves -- the lab has to look like the bug, not like a page about it.
_LEAK = ("-----BEGIN RSA PRIVATE KEY-----\n" + _FAKE_KEY_BODY
         + "\n-----END RSA PRIVATE KEY-----\n")

# Q-147 LIVENESS. The page opens a WebSocket whose HOST comes from the fragment, which is the
# real shape of `websocket_url_poisoning`: the attacker chooses the endpoint, not merely a room
# name inside the app's own socket URL. The fragment never reaches the server, so no
# request/response engine can see this -- only a render can.
_WSOCK = _HEAD + """<h1>live</h1><div id="s">idle</div>
<script>
  var h = location.hash.slice(1);
  if (h) { try { new WebSocket("ws://" + h + "/live");
                 document.getElementById("s").textContent = "connecting"; } catch (e) {} }
</script>""" + _TAIL

_ROUTES = {"/hash": _HASH, "/hashparam": _HASHPARAM, "/safehash": _SAFEHASH,
           "/noquery": _NOQUERY, "/inert": _INERT, "/account": _ACCOUNT,
           "/leak": _LEAK,
           "/wsock": _WSOCK}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a):
        pass

    def do_GET(self):
        # The fragment is NOT in self.path — the browser strips it before sending. Nothing here can see
        # it, which is the property the lab exists to demonstrate.
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/authbounce":
            if "sess=" in (self.headers.get("Cookie") or ""):
                self.send_response(302)
                self.send_header("Location", "/account")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = _AUTHBOUNCE
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        # Q-149 LIVENESS. A JWT-gated endpoint that DECODES the token and never verifies the
        # signature -- the single most common real JWT defect, and the one `_run_jwt` reports as
        # `jwt_signature_not_verified`. It gates on the token's PRESENCE (401 without one), so the
        # three-leg oracle has something to discriminate: authenticated 200, unauthenticated 401,
        # signature-tampered 200. Without that discrimination the correct verdict is `not_tested`,
        # which is exactly what the uncontrolled version could never say.
        if path == "/api/me":
            auth = self.headers.get("Authorization") or ""
            tok = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
            sub = ""
            if tok.count(".") == 2:
                try:
                    mid = tok.split(".")[1]
                    mid += "=" * (-len(mid) % 4)
                    sub = str(json.loads(base64.urlsafe_b64decode(mid.encode()).decode()).get("sub", ""))
                except Exception:
                    sub = ""
            if not sub:
                out = json.dumps({"error": "authentication required"}).encode()
                self.send_response(401)
            else:
                out = json.dumps({"user": sub, "balance": 4210}).encode()
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        # Q-146 LIVENESS. A "formula preview" field that EXECUTES what it is given and echoes what
        # that printed -- a real server-side code-injection sink, and the shape `code_injection`
        # probes for. The namespace is restricted to `print` and `str`: enough for the probe to
        # evaluate, nothing to import or open with. That restriction is realistic (plenty of real
        # sandboxes are exactly this, and exactly this bypassable) and it keeps the lab from being
        # a general execution primitive on the lab network.
        if path == "/calc":
            expr = ""
            if "?" in self.path:
                for pair in self.path.split("?", 1)[1].split("&"):
                    k, _, v = pair.partition("=")
                    if k == "expr":
                        expr = urllib.parse.unquote_plus(v)
            printed = io.StringIO()
            try:
                with contextlib.redirect_stdout(printed):
                    exec(compile(expr, "<formula>", "exec"),
                         {"__builtins__": {"print": print, "str": str}}, {})
                shown = printed.getvalue()
            except Exception as exc:
                shown = "error: %s" % type(exc).__name__
            out = (_HEAD + "<h1>formula preview</h1><pre>" + shown + "</pre>" + _TAIL).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        body = _ROUTES.get(path)
        if body is None:
            body = _HEAD + "<h1>domsource</h1><ul>" + "".join(
                '<li><a href="%s">%s</a></li>' % (r, r) for r in sorted(_ROUTES)) + "</ul>" + _TAIL
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        # Q-145 LIVENESS, ROOT ONLY. `_run_transport_posture` reads `origin + "/"`, never the path
        # it was handed, so the header has to live here. Root only, because a CSP on every response
        # would change what the DOM-XSS routes are allowed to execute and quietly rewrite the
        # meaning of the four cases that already pass.
        #
        # `unsafe-inline` with NO nonce and NO hash is the real weakness: a nonce would neutralise
        # it, and reporting both together would be the bug csp_audit was written to avoid. There is
        # deliberately no frame-ancestors and no form-action, neither of which inherits default-src.
        if path == "/":
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'")
        self.end_headers()
        self.wfile.write(data)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
