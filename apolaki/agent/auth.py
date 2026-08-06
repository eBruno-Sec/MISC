"""
Authenticated scanning: heuristic form login.

Two ways to reach the post-login surface:
  1. The operator supplies session headers (Cookie / Authorization) at launch —
     they are threaded into every tool HTTP request.
  2. auto-login: given a login URL + credentials, fetch the form, fill it
     (carrying hidden CSRF fields), submit, and capture the resulting session
     cookie. The form parsing is pure and unit-tested; only login() touches the
     network. Adapted from OLYMPUS auth.py (heuristic, no AI required).
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_form = False
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self.in_form = True
            self._cur = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
        elif tag == "input" and self.in_form and self._cur is not None:
            self._cur["inputs"].append({"name": a.get("name", ""), "type": a.get("type", "text").lower(),
                                        "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form" and self.in_form and self._cur is not None:
            self.forms.append(self._cur)
            self.in_form = False
            self._cur = None


def _guess_field(inputs: list, kind: str) -> str:
    """Pick the username or password field name from a form's inputs."""
    if kind == "password":
        for i in inputs:
            if i["type"] == "password":
                return i["name"]
        for i in inputs:
            if any(h in i["name"].lower() for h in ("pass", "pwd")):
                return i["name"]
        return ""
    # username
    for i in inputs:
        n = i["name"].lower()
        if any(h in n for h in ("user", "email", "login", "uname", "account")) and i["type"] not in ("password", "hidden", "submit"):
            return i["name"]
    for i in inputs:
        if i["type"] in ("text", "email"):
            return i["name"]
    return ""


def parse_login_form(html: str, base_url: str) -> dict | None:
    """Return {action, method, user_field, pass_field, hidden} for the first form
    that has a password field, or None."""
    p = _FormParser()
    try:
        p.feed(html or "")
    except Exception:
        return None
    for form in p.forms:
        pass_field = _guess_field(form["inputs"], "password")
        if not pass_field:
            continue
        user_field = _guess_field(form["inputs"], "username")
        hidden = {i["name"]: i["value"] for i in form["inputs"]
                  if i["type"] == "hidden" and i["name"]}
        return {
            "action": urljoin(base_url, form["action"] or base_url),
            "method": form["method"] or "post",
            "user_field": user_field,
            "pass_field": pass_field,
            "hidden": hidden,
        }
    return None


def _cookie_header(set_cookie_values) -> str:
    """Fold Set-Cookie response header(s) into a single Cookie request header."""
    pairs = []
    for sc in set_cookie_values:
        first = sc.split(";", 1)[0].strip()
        if "=" in first:
            pairs.append(first)
    return "; ".join(dict((p.split("=", 1)[0], p) for p in pairs).values())


def _hidden_and_action(html: str, page_url: str, login_url: str):
    """Extract the hidden fields (CSRF etc.) + action of the LOGIN form on a page whose password field is
    JS-driven / not parseable. Scores each form so the login form (not the register form) wins -- they
    often both carry a CSRF token, and picking the wrong one fails the submit."""
    import re
    from urllib.parse import urljoin
    best_hidden, best_action, best_score = {}, login_url, -1
    for fm in re.finditer(r"<form\b[^>]*>.*?</form>", html, re.I | re.S):
        block = fm.group(0)
        am = re.search(r'action=["\']([^"\']*)["\']', block, re.I)
        action = urljoin(page_url, am.group(1)) if (am and am.group(1)) else login_url
        hidden = {}
        for im in re.finditer(r'<input\b[^>]*type=["\']?hidden["\']?[^>]*>', block, re.I):
            n = re.search(r'name=["\']?([^"\'\s>]+)', im.group(0))
            v = re.search(r'value=(?:"([^"]*)"|\'([^\']*)\'|([^"\'>\s]*))', im.group(0))
            if n:
                hidden[n.group(1)] = (v.group(1) or v.group(2) or v.group(3) or "") if v else ""
        score = 0
        if re.search(r"login|signin|auth|session", action, re.I):
            score += 2
        if re.search(r'name=["\']?(?:username|user|email|login)\b', block, re.I):
            score += 1
        if re.search(r"register|signup|sign-up|create", action, re.I):
            score -= 2
        if score > best_score:
            best_hidden, best_action, best_score = hidden, action, score
    return best_hidden, best_action


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return None


# JSON keys (lowercased, dashes->underscores) that commonly carry a bearer/JWT token in a login response.
_TOKEN_KEYS = {"token", "access_token", "accesstoken", "id_token", "idtoken", "jwt",
               "auth_token", "authtoken", "session_token", "sessiontoken", "bearer"}


def _find_token(obj, _depth: int = 0):
    """Find a plausible bearer/JWT token in a JSON login response — handles common nested shapes like
    Juice Shop's {authentication:{token}}, {data:{token}}, {access_token}. Returns the token or None."""
    if _depth > 4 or obj is None:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and str(k).lower().replace("-", "_") in _TOKEN_KEYS and len(v) >= 20:
                return v
        for v in obj.values():
            t = _find_token(v, _depth + 1)
            if t:
                return t
    elif isinstance(obj, list):
        for v in obj[:10]:
            t = _find_token(v, _depth + 1)
            if t:
                return t
    return None


async def login(login_url: str, username: str, password: str, timeout: int = 15) -> dict:
    """Fetch a login form, submit credentials, return session headers.

    Returns {"headers": {...}, "verified": bool, "note": str}. `headers` is empty
    if login could not be performed; the scan then continues unauthenticated."""
    import httpx
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as c:
            page = await c.get(login_url)
            # don't mint a false session when the login is gated by CAPTCHA / MFA / magic-link — those
            # are manual steps; surface a PAUSE rather than a bogus header (CHAD review #4).
            try:
                import register as _reg
                blk = [b for b in _reg.detect_blockers(page.text) if b in ("captcha", "mfa", "email_verification")]
            except Exception:
                blk = []
            if blk:
                return {"headers": {}, "verified": False, "blocked": blk,
                        "note": "login needs a manual step (%s) — cannot authenticate head-lessly" % ", ".join(blk)}
            form = parse_login_form(page.text, str(page.url))
            if form and form["pass_field"]:
                data = dict(form["hidden"])
                if form["user_field"]:
                    data[form["user_field"]] = username
                data[form["pass_field"]] = password
                action, method = form["action"], form["method"]
            else:
                # Fallback: the password field is JS-driven / not in the parsed form (e.g. Gin & Juice).
                # Carry the page's hidden fields (CSRF) and POST the standard field names to the form action.
                hidden, action = _hidden_and_action(page.text, str(page.url), login_url)
                data = dict(hidden)
                data.update({"username": username, "email": username, "password": password})
                method = "post"
            if method == "get":
                resp = await c.get(action, params=data)
            else:
                resp = await c.post(action, data=data)
            # collect cookies from the client jar (survives redirects)
            cookie = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
            if not cookie:
                raw = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
                cookie = _cookie_header(raw)
            if not cookie:
                # Token-in-JSON API login (very common: SPA/REST APIs return a bearer token in the response
                # body rather than a Set-Cookie — e.g. Juice Shop's {authentication:{token}}). Check the form
                # response, then try an explicit JSON POST of {email/username, password} to the login URL.
                token = _find_token(_safe_json(resp))
                if not token:
                    for body in ({"email": username, "password": password},
                                 {"username": username, "password": password}):
                        try:
                            jr = await c.post(login_url, json=body)
                        except Exception:
                            continue
                        token = _find_token(_safe_json(jr))
                        if token:
                            resp = jr
                            break
                if token:
                    shape = {"method": "POST", "action": login_url, "content_type": "application/json",
                             "user_field": "email", "pass_field": "password"}
                    return {"headers": {"Authorization": "Bearer %s" % token}, "verified": True,
                            "shape": shape, "note": "bearer token captured from JSON login response"}
                return {"headers": {}, "verified": False,
                        "note": "no session cookie or bearer token after submit"}
            # crude verification: a login page that no longer shows the password field
            verified = "password" not in resp.text.lower()[:5000] or resp.status_code in (301, 302)
            # the EXACT winning request shape (redacted at render time) so the report can reproduce a
            # real authentication request, not a bogus GET page-load (CHAD final-audit defect #2).
            shape = {"method": (method or "post").upper(), "action": action,
                     "content_type": "application/x-www-form-urlencoded",
                     "user_field": (form["user_field"] if (form and form.get("user_field")) else "username"),
                     "pass_field": (form["pass_field"] if (form and form.get("pass_field")) else "password")}
            return {"headers": {"Cookie": cookie}, "verified": verified, "shape": shape,
                    "note": "session cookie captured" + ("" if verified else " (login not verified — continuing anyway)")}
    except Exception as e:
        return {"headers": {}, "verified": False, "note": f"login error: {e}"}
