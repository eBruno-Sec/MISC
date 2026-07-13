"""
Yggdrasil authenticated-scanning engine.

Credentials arrive in the mission scope notes; FRIGG extracts them. This engine
logs into the target web app and returns a session cookie that the crawler and
every scanner reuse, so testing covers the authenticated surface.

The AI decides how to log in: it reads the login form and plans the request
(action, method, field names, CSRF). A deterministic heuristic parser is the
fallback when no AI key is set or the model output is unusable.

Everything is gated on credentials being present and degrades to unauthenticated
scanning on any failure. Passwords are never written to logs or findings.
"""
import os
import re
from urllib.parse import urljoin

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth/login", "/account/login",
    "/users/sign_in", "/user/login", "/admin/login", "/session/new", "/",
]

_CSRF_HINTS = ("csrf", "token", "authenticity", "xsrf", "nonce", "_token")
_LOGGED_IN_HINTS = ("logout", "log out", "sign out", "signout", "my account", "dashboard")


class AuthEngine:
    """Mixed into Ares. Uses self.log, self.add_finding (from BaseAgent)."""

    async def authenticate(self, base_url: str, creds: dict) -> str | None:
        """Return a Cookie header value for the authenticated session, or None."""
        import httpx

        username = (creds or {}).get("username")
        password = (creds or {}).get("password")
        if not username or not password:
            return None

        await self.log(f"Authenticated scan: attempting login as {username}", "info")

        login_url = (creds or {}).get("login_url")
        candidates = []
        if login_url:
            candidates.append(login_url if login_url.startswith("http")
                              else urljoin(base_url.rstrip("/") + "/", login_url.lstrip("/")))
        candidates += [base_url.rstrip("/") + p for p in LOGIN_PATHS]

        try:
            async with httpx.AsyncClient(timeout=12, verify=False, follow_redirects=True) as c:
                page_html, page_url = None, None
                for u in dict.fromkeys(candidates):
                    try:
                        r = await c.get(u)
                    except Exception:
                        continue
                    if r.status_code == 200 and 'type="password"' in r.text.lower().replace("'", '"'):
                        page_html, page_url = r.text, str(r.url)
                        break
                if not page_html:
                    await self.log("Auth: no login form found; continuing unauthenticated", "warn")
                    return None

                form_html = self._extract_form(page_html)
                plan = await self._ai_login_plan(page_url, form_html) or self._heuristic_plan(form_html)
                if not plan or not plan.get("username_field") or not plan.get("password_field"):
                    await self.log("Auth: could not parse login form; continuing unauthenticated", "warn")
                    return None

                action = plan.get("action") or page_url
                action = action if str(action).startswith("http") else urljoin(page_url, str(action))
                method = (plan.get("method") or "post").lower()

                data = {}
                hidden = plan.get("hidden") if isinstance(plan.get("hidden"), dict) else {}
                for name, val in hidden.items():
                    data[str(name)] = str(val)
                csrf_field = plan.get("csrf_field")
                if csrf_field:
                    data[csrf_field] = self._extract_value(page_html, csrf_field) or data.get(csrf_field, "")
                data[plan["username_field"]] = username
                data[plan["password_field"]] = password

                try:
                    if method == "get":
                        await c.get(action, params=data)
                    else:
                        await c.post(action, data=data)
                except Exception as e:
                    await self.log(f"Auth: login request failed ({e}); continuing unauthenticated", "warn")
                    return None

                jar = {k: v for k, v in c.cookies.items()}
                if not jar:
                    await self.log("Auth: login set no session cookie; continuing unauthenticated", "warn")
                    return None
                cookie = "; ".join(f"{k}={v}" for k, v in jar.items())

                if not await self._verify(c, base_url, username):
                    await self.log(f"Auth: could not verify login as {username}; continuing unauthenticated", "warn")
                    return None

                await self.add_finding(
                    title=f"Authenticated scanning active (user: {username})",
                    severity="info",
                    description="Yggdrasil logged in with the supplied credentials and is testing the "
                                "authenticated surface. Findings below may need this session to reproduce.",
                    evidence=f"Login endpoint: {action}\nSession cookies: {', '.join(jar.keys())}",
                    cvss_score=0.0,
                    remediation="Informational. Rotate any test credentials after the engagement.",
                )
                await self.log(f"Auth: logged in as {username}; session shared with all scanners", "success")
                return cookie
        except Exception as e:
            await self.log(f"Auth engine error ({e}); continuing unauthenticated", "warn")
            return None

    # ── Helpers ──────────────────────────────────────────────────
    def _cookie(self) -> str | None:
        return getattr(self, "_auth_cookie", None)

    def _auth_headers(self) -> dict:
        from core.evasion import BROWSER_USER_AGENT
        headers = {"User-Agent": BROWSER_USER_AGENT}
        c = self._cookie()
        if c:
            headers["Cookie"] = c
        return headers

    def _extract_form(self, html: str) -> str:
        forms = re.findall(r"<form\b.*?</form>", html, re.IGNORECASE | re.DOTALL)
        for f in forms:
            if "type=\"password\"" in f.lower() or "type='password'" in f.lower():
                return f[:6000]
        return (forms[0][:6000] if forms else html[:6000])

    def _extract_value(self, html: str, field: str) -> str:
        pat1 = rf'name=["\']{re.escape(field)}["\'][^>]*value=["\']([^"\']*)["\']'
        pat2 = rf'value=["\']([^"\']*)["\'][^>]*name=["\']{re.escape(field)}["\']'
        m = re.search(pat1, html, re.IGNORECASE) or re.search(pat2, html, re.IGNORECASE)
        return m.group(1) if m else ""

    async def _ai_login_plan(self, url: str, form_html: str) -> dict | None:
        if not (os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")):
            return None
        from core.ai_client import complete
        from .athena import _extract_json

        prompt = f"""You are automating login for an AUTHORIZED penetration test. Read this login form
and return STRICT JSON describing how to submit it.

Page URL: {url}
Form HTML:
{form_html}

Return ONLY:
{{"action": "<form action URL or path>", "method": "post|get",
  "username_field": "<input name for the username/email field>",
  "password_field": "<input name for the password field>",
  "csrf_field": "<name of the csrf/anti-forgery hidden input, or empty string>",
  "hidden": {{"<name>": "<value>"}}}}

Include every hidden input in "hidden". No prose, only JSON."""
        try:
            text = await complete(prompt, max_tokens=500)
            plan = _extract_json(text)
            return plan if isinstance(plan, dict) else None
        except Exception:
            return None

    def _heuristic_plan(self, form_html: str) -> dict | None:
        m = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = m.group(1) if m else None
        mm = re.search(r'<form[^>]*method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = mm.group(1).lower() if mm else "post"

        pm = (re.search(r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
              or re.search(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']password["\']', form_html, re.IGNORECASE))
        if not pm:
            return None
        password_field = pm.group(1)

        um = (re.search(r'<input[^>]*type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
              or re.search(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\'](?:text|email)["\']', form_html, re.IGNORECASE))
        username_field = um.group(1) if um else "username"

        hidden, csrf_field = {}, ""
        for hm in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', form_html, re.IGNORECASE):
            tag = hm.group(0)
            nm = re.search(r'name=["\']([^"\']+)["\']', tag)
            if not nm:
                continue
            vm = re.search(r'value=["\']([^"\']*)["\']', tag)
            hidden[nm.group(1)] = vm.group(1) if vm else ""
            if any(t in nm.group(1).lower() for t in _CSRF_HINTS):
                csrf_field = nm.group(1)

        return {
            "action": action, "method": method,
            "username_field": username_field, "password_field": password_field,
            "csrf_field": csrf_field, "hidden": hidden,
        }

    async def _verify(self, client, base_url: str, username: str) -> bool:
        try:
            r = await client.get(base_url)
            body = r.text.lower()
        except Exception:
            return False
        if any(s in body for s in _LOGGED_IN_HINTS):
            return True
        if username.lower() in body:
            return True
        # Still showing a password field on the landing page usually means not logged in.
        if 'type="password"' in body.replace("'", '"'):
            return False
        return True  # cookies were set and no obvious login form remains
