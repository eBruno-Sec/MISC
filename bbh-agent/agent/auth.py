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


async def login(login_url: str, username: str, password: str, timeout: int = 15) -> dict:
    """Fetch a login form, submit credentials, return session headers.

    Returns {"headers": {...}, "verified": bool, "note": str}. `headers` is empty
    if login could not be performed; the scan then continues unauthenticated."""
    import httpx
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as c:
            page = await c.get(login_url)
            form = parse_login_form(page.text, str(page.url))
            if not form or not form["pass_field"]:
                return {"headers": {}, "verified": False, "note": "no login form with a password field found"}
            data = dict(form["hidden"])
            if form["user_field"]:
                data[form["user_field"]] = username
            data[form["pass_field"]] = password
            if form["method"] == "get":
                resp = await c.get(form["action"], params=data)
            else:
                resp = await c.post(form["action"], data=data)
            # collect cookies from the client jar (survives redirects)
            cookie = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
            if not cookie:
                raw = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
                cookie = _cookie_header(raw)
            if not cookie:
                return {"headers": {}, "verified": False, "note": "no session cookie set after submit"}
            # crude verification: a login page that no longer shows the password field
            verified = "password" not in resp.text.lower()[:5000] or resp.status_code in (301, 302)
            return {"headers": {"Cookie": cookie}, "verified": verified,
                    "note": "session cookie captured" + ("" if verified else " (login not verified — continuing anyway)")}
    except Exception as e:
        return {"headers": {}, "verified": False, "note": f"login error: {e}"}
