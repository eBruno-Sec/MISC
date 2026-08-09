"""
clientauthz — a deliberately vulnerable lab for the two BIE engines that had no validation target.

WHY THIS EXISTS. `client_side_authz` (CWE-602) and `client_supplied_identity_param` both shipped with
`validated_on: []`: written, wired, unit-proven, and never confirmed against a target that actually
exhibits their bug. Juice Shop cannot serve as one — Angular REMOVES privileged controls from the DOM
rather than hiding them, and it identifies objects by path segment rather than by an identity parameter.
So both engines correctly reported zero there, which proves nothing either way.

WHAT MAKES THIS A VALIDATION LAB RATHER THAN A TARGET. It carries a VULNERABLE and a SECURE variant of
each class, deliberately paired:

    /panel      admin button hidden with CSS, server does NOT check   -> must be CONFIRMED
    /panel      audit button hidden with CSS, server DOES check       -> must be REJECTED
    /profile    ?uid= trusted by the server                           -> must be CONFIRMED
    /account    ?uid= present but ignored (session decides)           -> must be REJECTED

The secure halves are the point. An engine that flags the vulnerable case is unproven until it also
declines the safe one — otherwise "it found something" is indistinguishable from "it flags everything".
The reject cases exercise exactly the false-positive guards `judge_client_side_authz` and
`judge_param_swap` were written with.

Standard library only: no dependency to install, no image to build beyond python:slim, so the lab cannot
rot from an upstream change.
"""
import http.server
import json
import socketserver
import urllib.parse

PORT = 8080

# uid -> (username, role, private note). Two users so a cross-user read is observable.
USERS = {
    "1": ("alice", "user", "alice-private-note-AAA"),
    "2": ("bob", "admin", "bob-private-note-BBB"),
}
# session cookie -> uid. Deliberately trivial: the lab is about authorization, not session security.
SESSIONS = {"sess-alice": "1", "sess-bob": "2"}

# The page FETCHES its identity-scoped endpoints itself, with the signed-in user's own uid. This is not
# decoration: phase 3 forms a hypothesis only when it observes two real sessions emitting the SAME endpoint
# with DIFFERENT values for one parameter, and it mutates the request THE APPLICATION EMITS. A lab whose
# uids only appeared in href attributes would never be requested by either browser, so no candidate would
# form and the engine would report nothing — passing the run for the wrong reason.
_PAGE = """<!doctype html><html><head><title>clientauthz lab</title>
<style>.hidden{{display:none}}</style></head><body>
<h1>Account panel</h1><p>Signed in as <b>{user}</b> (role: {role})</p>
<div id="profile">loading…</div>
<div id="account">loading…</div>
{admin_btn}
{audit_btn}
<script>
  fetch("/profile?uid={uid}").then(r => r.text())
    .then(t => document.getElementById("profile").textContent = t);
  fetch("/account?uid={uid}").then(r => r.text())
    .then(t => document.getElementById("account").textContent = t);
</script>
</body></html>"""

# The privileged controls are ANCHORS, not submit buttons, and that is a requirement rather than a style
# choice: `probe_targets` only fires a SAFE GET at a withheld control that has a real href, and deliberately
# refuses anything that would need a state-changing submit (those become operator leads, never auto-clicks).
# A lab whose only hidden control were a <button> would be collected and then skipped, and the phase would
# report zero — again passing for the wrong reason.

# VULNERABLE: rendered for everyone, hidden by CSS for non-admins, and /admin-action does NOT re-check role.
_ADMIN_BTN_HIDDEN = '<a class="hidden" href="/admin-action?do=delete-all">Delete all records (admin)</a>'
_ADMIN_BTN_SHOWN = '<a href="/admin-action?do=delete-all">Delete all records (admin)</a>'

# SECURE COUNTERPART: also hidden by CSS, but /audit-action DOES re-check the session's role.
_AUDIT_BTN_HIDDEN = '<a class="hidden" href="/audit-action?do=export">Export audit log (admin)</a>'
_AUDIT_BTN_SHOWN = '<a href="/audit-action?do=export">Export audit log (admin)</a>'


def _uid_from_cookie(headers):
    raw = headers.get("Cookie") or ""
    for part in raw.split(";"):
        k, _, v = part.strip().partition("=")
        if k == "sid":
            return SESSIONS.get(v.strip())
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_a):
        pass                                   # quiet: the scan's own ledger is the record that matters

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(parts.query)
        session_uid = _uid_from_cookie(self.headers)

        if parts.path == "/login":
            who = (q.get("as") or ["alice"])[0]
            sid = "sess-bob" if who == "bob" else "sess-alice"
            return self._send(200, "logged in as %s" % who,
                              extra={"Set-Cookie": "sid=%s; Path=/" % sid})

        if parts.path in ("/", "/panel"):
            # Deliberately NOT a redirect to /login. A 302 into an endpoint that sets a cookie would log the
            # ANONYMOUS persona in as alice the moment its browser opened the base URL, and every "does
            # anonymous see this too?" control would then be answered by an authenticated session — turning
            # the oracle's negative controls into false rejections. The lab must let the anonymous persona
            # stay anonymous.
            if not session_uid:
                return self._send(200, "<!doctype html><html><body><h1>Not signed in</h1>"
                                       "<p>No session cookie was presented.</p></body></html>")
            user, role, _note = USERS[session_uid]
            is_admin = role == "admin"
            return self._send(200, _PAGE.format(
                user=user, role=role, uid=session_uid,
                admin_btn=_ADMIN_BTN_SHOWN if is_admin else _ADMIN_BTN_HIDDEN,
                audit_btn=_AUDIT_BTN_SHOWN if is_admin else _AUDIT_BTN_HIDDEN))

        # VULNERABLE (CWE-602): the control was only hidden in the browser. No server-side ROLE check.
        #
        # It authenticates but does not authorize, and that distinction is the whole finding. An endpoint
        # with NO check at all is not a broken authorization boundary — it is public content, and the
        # oracle's anonymous control rejects it on exactly that ground. Requiring a session is what makes
        # "a logged-in non-admin reached the admin function" the provable claim.
        if parts.path == "/admin-action":
            if not session_uid:
                return self._send(401, json.dumps({"error": "login required"}),
                                  ctype="application/json")
            return self._send(200, json.dumps({"ok": True, "action": (q.get("do") or [""])[0],
                                               "result": "ADMIN ACTION EXECUTED",
                                               "deleted_records": 4127, "actor": USERS[session_uid][0]}),
                              ctype="application/json")

        # SECURE counterpart: same CSS hiding, but the server re-checks. Must NOT be reported.
        if parts.path == "/audit-action":
            if not session_uid or USERS[session_uid][1] != "admin":
                return self._send(403, json.dumps({"error": "forbidden: admin role required"}),
                                  ctype="application/json")
            return self._send(200, json.dumps({"ok": True, "result": "audit exported"}),
                              ctype="application/json")

        # VULNERABLE (BOLA): authenticated, but identity is taken from the QUERY STRING rather than the
        # session. Same reasoning as /admin-action — without the session requirement anonymous would read
        # it too and the oracle would (correctly) call it public rather than a cross-user read.
        if parts.path == "/profile":
            if not session_uid:
                return self._send(401, json.dumps({"error": "login required"}),
                                  ctype="application/json")
            uid = (q.get("uid") or [session_uid])[0]
            if uid not in USERS:
                return self._send(404, json.dumps({"error": "no such user"}),
                                  ctype="application/json")
            user, role, note = USERS[uid]
            return self._send(200, json.dumps({"uid": uid, "username": user, "role": role,
                                               "private_note": note}),
                              ctype="application/json")

        # SECURE counterpart: the uid parameter is accepted and IGNORED; the session decides.
        if parts.path == "/account":
            if not session_uid:
                return self._send(401, json.dumps({"error": "login required"}),
                                  ctype="application/json")
            user, role, note = USERS[session_uid]
            return self._send(200, json.dumps({"uid": session_uid, "username": user, "role": role,
                                               "private_note": note}),
                              ctype="application/json")

        return self._send(404, json.dumps({"error": "not found"}), ctype="application/json")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
