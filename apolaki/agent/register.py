"""
Autonomous account registration for persona-based (multi-user) testing.

Access-control testing needs two same-privilege identities (PortSwigger/OWASP: compare two
users to prove horizontal access control). When a target offers open registration AND it is in
scope, Apolaki mints them through the application's OWN signup flow — this is authorized account
provisioning against an in-scope lab/target, NOT credential attack: it is hard-capped per mission
and never iterates or guesses existing credentials.

Design mirrors auth.py: the form discovery / payload construction / policy adaptation / blocker
detection are PURE and unit-tested; register() is the only function that touches the network.
MFA, CAPTCHA, email-verification and invite-code walls are DETECTED and surfaced as a PAUSE state
(a manual operator step) — never bypassed.
"""
from __future__ import annotations

import re
import secrets
import string

from urllib.parse import urljoin

import auth  # reuse the HTML form parser + field guessing

# Human-facing signals that a signup cannot be completed head-lessly. We stop and hand back a
# manual step rather than trying to defeat any of these.
_BLOCKERS = {
    "captcha": ("g-recaptcha", "h-captcha", "cf-turnstile", "hcaptcha", "recaptcha", "captcha"),
    "mfa": ("two-factor", "2fa", "authenticator app", "verification code", "one-time code", "otp "),
    "email_verification": ("verify your email", "confirmation email", "confirm your email",
                           "activation link", "check your inbox", "verification email"),
    "invite_code": ("invite code", "invitation code", "invite-only", "referral code"),
}

# A password that clears the common policies (>=12, upper+lower+digit+symbol) out of the box; the
# adapter only lengthens/augments it when the page states a stricter rule.
_PW_SYMBOLS = "!@#$%*-_"


def detect_blockers(html: str) -> list:
    """Return the manual-step walls present on a signup page (captcha/mfa/email/invite)."""
    low = (html or "").lower()
    out = []
    for kind, markers in _BLOCKERS.items():
        if any(m in low for m in markers):
            out.append(kind)
    return out


# validation/rejection markers — many apps return HTTP 200 with an error page on a FAILED signup, so
# a sub-400 status alone is not proof the account was created (CHAD review #3).
_REG_FAIL_MARKERS = (
    "already exist", "already registered", "already in use", "already taken", "must be unique",
    "e-mail is already", "email is already", "is required", "must be at least", "password is too",
    "passwords do not match", "password does not match", "invalid email", "not a valid",
    "please correct", "registration failed", "could not create", "validation error",
)


def _registration_rejected(text: str) -> bool:
    low = (text or "").lower()[:4000]
    return any(m in low for m in _REG_FAIL_MARKERS)


def _is_register_form(form: dict) -> int:
    """Score a parsed form for how much it looks like REGISTRATION (vs login). Higher = more likely
    a signup form. A register form typically has a password field plus a second password/confirm
    field, an email field, a register-y action, or a terms checkbox."""
    inputs = form.get("inputs", [])
    pw_fields = [i for i in inputs if i["type"] == "password"
                 or any(h in i["name"].lower() for h in ("pass", "pwd"))]
    if not pw_fields:
        return -1  # no password field at all -> not a credential form
    score = 0
    if len(pw_fields) >= 2:
        score += 3  # password + confirm/repeat is the strongest signup tell
    if any(re.search(r"repeat|confirm|again|verify", i["name"], re.I) for i in inputs):
        score += 2
    if any(i["type"] == "email" or "email" in i["name"].lower() for i in inputs):
        score += 1
    if any(i["type"] == "checkbox" for i in inputs):
        score += 1  # terms/consent checkbox
    action = (form.get("action") or "").lower()
    if re.search(r"regist|signup|sign-up|create|join|account", action):
        score += 2
    if re.search(r"\blog-?in|signin|sign-in|auth\b", action):
        score -= 2
    return score


def parse_register_form(html: str, base_url: str) -> dict | None:
    """Return {action, method, user_field, email_field, pass_field, confirm_field, hidden,
    checkboxes} for the most register-like form on the page, or None. Pure."""
    p = auth._FormParser()
    try:
        p.feed(html or "")
    except Exception:
        return None
    best, best_score = None, 0
    for form in p.forms:
        s = _is_register_form(form)
        if s > best_score:
            best, best_score = form, s
    if best is None:
        return None
    inputs = best["inputs"]
    pw_names = [i["name"] for i in inputs
                if (i["type"] == "password" or any(h in i["name"].lower() for h in ("pass", "pwd")))
                and i["name"]]
    email_field = next((i["name"] for i in inputs
                        if (i["type"] == "email" or "email" in i["name"].lower()) and i["name"]), "")
    user_field = auth._guess_field(inputs, "username")
    if user_field and user_field == email_field:
        # if the only text field IS the email, don't double-map it as username
        user_field = ""
    hidden = {i["name"]: i["value"] for i in inputs if i["type"] == "hidden" and i["name"]}
    checkboxes = [i["name"] for i in inputs if i["type"] == "checkbox" and i["name"]]
    return {
        "action": urljoin(base_url, best["action"] or base_url),
        "method": (best["method"] or "post").lower(),
        "user_field": user_field,
        "email_field": email_field,
        "pass_field": pw_names[0] if pw_names else "",
        "confirm_field": pw_names[1] if len(pw_names) >= 2 else "",
        "hidden": hidden,
        "checkboxes": checkboxes,
    }


def adapt_password(policy_text: str = "", base_len: int = 14) -> str:
    """Generate a random password that satisfies the stated policy. Reads a stricter minimum length
    from text like 'at least 16 characters' and always includes upper/lower/digit/symbol."""
    n = base_len
    m = re.search(r"(?:at least|minimum|min\.?)\s+(\d{1,2})\s+char", (policy_text or "").lower())
    if m:
        n = max(n, int(m.group(1)) + 2)
    m2 = re.search(r"(\d{1,2})\s*(?:-|to)\s*\d{1,2}\s+char", (policy_text or "").lower())
    if m2:
        n = max(n, int(m2.group(1)) + 2)
    n = min(max(n, 12), 40)
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits, _PW_SYMBOLS]
    # one from each required class, then fill from the union
    chars = [secrets.choice(p) for p in pools]
    union = "".join(pools)
    chars += [secrets.choice(union) for _ in range(n - len(chars))]
    # shuffle without bias
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def gen_account(label: str = "user", domain: str = "apolaki-test.local", policy_text: str = "") -> dict:
    """A unique, disposable test account. `label` distinguishes personas (user_a vs user_b). The
    local-part carries a random token so two personas never collide and cleanup is greppable."""
    token = secrets.token_hex(4)
    safe = re.sub(r"[^a-z0-9]", "", (label or "user").lower()) or "user"
    username = f"apolaki_{safe}_{token}"
    return {
        "label": label,
        "username": username,
        "email": f"{username}@{domain}",
        "password": adapt_password(policy_text),
    }


def build_registration_payload(form: dict, account: dict) -> dict:
    """Fill a parsed register form with a generated account: username/email/password(+confirm),
    carry hidden CSRF fields, and tick consent checkboxes (terms). Pure."""
    data = dict(form.get("hidden") or {})
    if form.get("user_field"):
        data[form["user_field"]] = account.get("username", "")
    if form.get("email_field"):
        data[form["email_field"]] = account.get("email", "")
    if form.get("pass_field"):
        data[form["pass_field"]] = account.get("password", "")
    if form.get("confirm_field"):
        data[form["confirm_field"]] = account.get("password", "")
    for cb in form.get("checkboxes") or []:
        data[cb] = "on"  # accept terms/consent to get past client-side required checks
    return data


async def register(register_url: str, label: str = "user", account: dict = None,
                   timeout: int = 15) -> dict:
    """Create ONE account via the target's signup flow. Tries the HTML form first, then a JSON API
    fallback (SPA/REST). Returns {created, headers, identity, account, blocked, verified, note}.

    `headers` is the captured session (Cookie/Bearer) or {} if none was set (the caller may then
    log in with `account`). `blocked` is non-empty when a captcha/mfa/email/invite wall was hit —
    the caller surfaces it as a manual step. Password is NEVER returned to the model layer; the
    caller stores `account` server-side only. Bounded by the caller (hard cap on registrations)."""
    import httpx
    note = ""
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout,
                                     headers={"User-Agent": auth_ua()}) as c:
            page = await c.get(register_url)
            blockers = detect_blockers(page.text)
            if blockers:
                return {"created": False, "headers": {}, "identity": None, "account": None,
                        "blocked": blockers, "verified": False,
                        "note": f"registration needs a manual step ({', '.join(blockers)}) — cannot proceed head-lessly"}
            acct = account or gen_account(label, policy_text=page.text[:4000])
            form = parse_register_form(page.text, str(page.url))
            created = False
            if form and form["pass_field"]:
                data = build_registration_payload(form, acct)
                if form["method"] == "get":
                    resp = await c.get(form["action"], params=data)
                else:
                    resp = await c.post(form["action"], data=data)
                # sub-400 is not enough: a 200 validation-error page is not a created account.
                created = resp.status_code < 400 and not _registration_rejected(resp.text)
                note = f"form signup -> {resp.status_code}" + (" (rejected page)" if not created else "")
            else:
                # JSON API fallback (SPA/REST): POST the common field shapes. A real registration API
                # returns JSON (the created user); an SPA catch-all route returns 200 index.html for
                # ANY path, so require a JSON body — otherwise /register on an Angular app would look
                # "created" without creating anything.
                resp, created = None, False
                for body in ({"email": acct["email"], "password": acct["password"],
                              "passwordRepeat": acct["password"], "username": acct["username"]},
                             {"username": acct["username"], "password": acct["password"]}):
                    try:
                        resp = await c.post(register_url, json=body)
                    except Exception:
                        continue
                    if resp.status_code < 400:
                        ct = (resp.headers.get("content-type") or "").lower()
                        is_json = "json" in ct
                        if not is_json:
                            try:
                                is_json = isinstance(resp.json(), (dict, list))
                            except Exception:
                                is_json = False
                        if is_json and not _registration_rejected(resp.text):
                            created = True
                            break
                note = f"json signup -> {resp.status_code if resp is not None else 'n/a'}"
            # capture any session the signup established
            cookie = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
            headers = {"Cookie": cookie} if cookie else {}
            # bearer token in a JSON response?
            if not headers:
                try:
                    j = resp.json() if resp is not None else {}
                    tok = ((j.get("authentication") or {}).get("token") or j.get("token")
                           or j.get("access_token") or j.get("jwt"))
                    if tok:
                        headers = {"Authorization": "Bearer " + tok}
                except Exception:
                    pass
            return {"created": created, "headers": headers, "identity": acct["email"],
                    "account": acct, "blocked": [], "verified": bool(headers),
                    "note": note + (" (session captured)" if headers else " (no session — login separately)")}
    except Exception as e:
        return {"created": False, "headers": {}, "identity": None, "account": None,
                "blocked": [], "verified": False, "note": f"registration error: {e}"}


def auth_ua() -> str:
    """The shared Apolaki User-Agent (kept in tools._UA; duplicated defensively for standalone use)."""
    try:
        import tools
        return tools._UA
    except Exception:
        return "Apolaki"
