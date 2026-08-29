"""
Target Intelligence Harvester.

Recon historically answered "what is exposed?" and turned answers into REPORT rows. This
module answers a different question: "what did the target just tell us that we can USE?"

It mines the target's own surface — rendered DOM text, JS bundles, JSON API responses,
headers, HTML comments, metadata — for *candidates*: emails, usernames, numeric object ids,
hidden routes/endpoints, encoded blobs (with an offline decode attempt), version strings,
coupon/price-like tokens, secrets, and free-text hints. These candidates become FIXTURES that
exploitation techniques consume at run time.

This is the general-pentest analogue of OSINT + source review: DERIVE the "secret" from the
target instead of hardcoding it. A value produced here is `fixture_source=harvest` — it counts
as transferable capability, unlike a baked-in answer key (labs.py). Same solve; one is a skill,
the other is cheating.

Pure and deterministic: functions take already-fetched material (text / json / js / headers)
and return structured candidates with provenance. No network here — the caller supplies
material fetched by the existing recon / browser / http tools. Safe to import with no target.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html as _html_mod
import json
import re
import surface as _surface

# Candidate kinds the store tracks.
KINDS = ("email", "username", "object_id", "route", "endpoint", "url", "encoded",
         "decoded", "secret", "version", "coupon", "numeric", "hint", "credential", "param", "comment")

_MAX_PER_KIND = 500      # keep the store bounded on large bundles
_MAX_VALUE_LEN = 400

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_SEMVER = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)\b")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")
# a path/href pulled out of markup or code (incl. SPA hash-routes like /#recycle)
_PATH = re.compile(r"""['"(]\s*(/[A-Za-z0-9_\-./%#]+(?:\?[A-Za-z0-9_\-./%=&]*)?)""")
# an absolute URL (external integrations, buckets, subdomains — all intel)
_URL = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./%?=&#]*)?")
# Angular/SPA route declarations: path: 'foo/:id'
_ROUTE = re.compile(r"""path\s*:\s*['"]([^'"]*)['"]""")
# key:value style secret assignment (conservative)
_SECRET_KV = re.compile(
    r"""(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?key|private[_-]?key)\b"""
    r"""\s*[:=]\s*['"]?([A-Za-z0-9_\-./+]{6,})['"]?""")
# free-text hint sentences
_HINT_KW = ("hint", "remember", "password", "secret", "security question", "favorite",
            "backup", "default cred", "todo", "fixme", "do not", "internal only")

_USERKEYS = ("email", "mail")
_NAMEKEYS = ("username", "user", "login", "handle", "account")  # NOT bare "name": pollutes with product/config names
_IDKEYS = ("id", "_id", "uid", "userid", "orderid", "basketid", "productid")
_COUPONKEYS = ("coupon", "voucher", "promo", "discount")
_NUMKEYS = ("price", "amount", "quantity", "qty", "total", "balance", "points")
_SECRETKEYS = ("token", "jwt", "secret", "apikey", "api_key", "password", "hash", "key")


def _clip(v) -> str:
    s = v if isinstance(v, str) else json.dumps(v) if isinstance(v, (dict, list)) else str(v)
    return s[:_MAX_VALUE_LEN]


class IntelStore:
    """Deduplicated candidate store with provenance. `data[kind]` -> {value: [sources]}."""

    def __init__(self):
        self.data = {k: {} for k in KINDS}

    def add(self, kind: str, value, source: str = "") -> None:
        if kind not in self.data or value in (None, "", b""):
            return
        val = _clip(value)
        if not val:
            return
        bucket = self.data[kind]
        if val not in bucket:
            if len(bucket) >= _MAX_PER_KIND:
                return
            bucket[val] = []
        if source and source not in bucket[val]:
            bucket[val].append(source)

    def get(self, kind: str) -> list:
        return sorted(self.data.get(kind, {}).keys())

    def with_sources(self, kind: str) -> dict:
        return dict(self.data.get(kind, {}))

    def count(self) -> int:
        return sum(len(v) for v in self.data.values())

    def to_dict(self, redact_secrets: bool = False) -> dict:
        """Serializable view. With redact_secrets=True the `secret` bucket is masked (length
        hint only) — used for anything at rest / shown to the model / put in a report."""
        def _vals(kind, bucket):
            keys = sorted(bucket.keys())
            if redact_secrets and kind == "secret":
                return ["<redacted:%d>" % len(k) for k in keys]
            if redact_secrets and kind == "credential":
                # keep the username (useful intel) but never expose a password at rest / in a report
                return [(k.split(":", 1)[0] + ":<redacted>") for k in keys]
            return keys
        return {"total": self.count(),
                "by_kind": {k: len(v) for k, v in self.data.items() if v},
                "candidates": {k: _vals(k, v) for k, v in self.data.items() if v}}


_COMMON_LETTERS = set("etaoinshrdlETAOINSHRDL")


def _english_score(s: str) -> float:
    """Fraction of letters drawn from the most common English letters — plaintext scores
    higher than ciphertext. Cheap heuristic used to reject bogus rot13 'decodes'."""
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    return sum(c in _COMMON_LETTERS for c in letters) / len(letters)


def decode_candidate(blob: str):
    """Best-effort OFFLINE decode of an encoded blob (base64 / hex / rot13).

    Returns a printable-ASCII decode when one is confidently recoverable, else None. This is
    the general 'find encoded data -> identify encoding -> decode' technique (e.g. easter-egg
    chains) — deterministic, no network."""
    if not isinstance(blob, str) or len(blob) < 8:
        return None

    def _printable(bs: bytes):
        try:
            s = bs.decode("utf-8")
        except Exception:
            return None
        if s and sum(32 <= ord(c) < 127 or c in "\t\n\r" for c in s) / len(s) >= 0.9:
            return s
        return None

    # base64 (length-based, independent of the 16-char harvest threshold)
    if len(blob) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", blob):
        try:
            out = _printable(base64.b64decode(blob, validate=True))
            if out:
                return out
        except (binascii.Error, ValueError):
            pass
    # hex
    if len(blob) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", blob):
        try:
            out = _printable(bytes.fromhex(blob))
            if out:
                return out
        except ValueError:
            pass
    # rot13 — accept ONLY if the result reads MORE like plaintext than the input, so we never
    # "decode" already-readable text (paths, words) into gibberish.
    if blob.isascii() and sum(c.isalpha() for c in blob) >= 4 and len(blob) <= 200:
        rot = codecs.encode(blob, "rot_13")
        if rot != blob and _english_score(rot) >= _english_score(blob) + 0.15:
            return rot
    return None


def decode_chains(blob: str, depth: int = 4, want=None) -> list:
    """Every value reachable by applying decode steps REPEATEDLY. Returns [(value, recipe)].

    `decode_candidate` handles ONE step, and real applications routinely stack them —
    `base64(strrev(bin2hex(x)))` is an ordinary obfuscation, and each layer alone looks like noise. A
    single-step decoder reports nothing on such a value, which is indistinguishable from "not encoded".

    Reversal is included as a step because it is the cheapest and most common thing put between two
    encodings, and it is free to try.

    Breadth-first to `depth`, deduplicated, and bounded — an unbounded search over a long blob is a
    denial of service against ourselves. `want` optionally filters to results matching a predicate, so a
    caller looking for a specific shape does not wade through intermediates. Pure, no network."""
    seen, out = {blob}, []
    frontier = [(blob, "")]
    for _ in range(max(1, depth)):
        nxt = []
        for value, recipe in frontier:
            if len(value) > 4096:
                continue
            for step, fn in (("b64", lambda s: decode_candidate(s)),
                             ("rev", lambda s: s[::-1]),
                             ("hex", lambda s: (bytes.fromhex(s).decode("utf-8", "strict")
                                                if re.fullmatch(r"[0-9A-Fa-f]+", s) and len(s) % 2 == 0
                                                else None))):
                try:
                    got = fn(value)
                except Exception:
                    got = None
                if not got or got in seen:
                    continue
                seen.add(got)
                rec = (recipe + "+" + step).lstrip("+")
                if want is None or want(got):
                    out.append((got, rec))
                nxt.append((got, rec))
        frontier = nxt
        if not frontier:
            break
    return out[:40]


# Credential DISCOVERY: pairs the target itself publishes/leaks (e.g. a demo app's documented test
# account, a leaked "user: x pass: y" in a comment/page). Zero-width chars are stripped first because
# apps (Gin & Juice Shop) obfuscate published creds with them. This is DISCOVERY of exposed creds, never
# guessing — the auth step uses a single discovered value and never iterates passwords.
_ZW = re.compile(r"[​‌‍⁠﻿­⁣‎‏]")
_TAG = re.compile(r"<[^>]+>")
# username <val> password <val> — the values may be zero-width/space obfuscated (published test creds),
# so capture a bounded window then strip whitespace out of the value (keeps special chars in real passwords).
_CRED = re.compile(r"(?i)\buser(?:name)?\b[\s:=]{0,4}(.{1,100}?)\bpass(?:word)?\b[\s:=]{0,4}(.{1,100}?)"
                   r"(?=\b(?:path|technolog|difficult|vulnerab|host|url|email|account)\b|[\r\n]|$)")
_CRED_STOP = {"username", "user", "password", "pass", "the", "your", "and", "login", "details", "a",
              "can", "may", "will", "must", "should", "cannot", "by", "with", "for", "reset"}
_HWS = re.compile(r"[^\S\r\n]+")   # horizontal whitespace runs (spaces/tabs) — NOT newlines (they terminate)
# a credential-disclosure CONTEXT keyword must sit just before the pair (avoids matching prose like
# "the user can reset a password by email"); the label alone is not enough.
_CRED_CTX = re.compile(r"(?i)\b(log[\s\-]?in|logon|log[\s\-]?on|sign[\s\-]?in|account|credential|"
                       r"default cred|test account|demo account|auth)")
_CRED_SEP = re.compile(r"(?i)\buser(?:name)?\b\s*[:=]|\bpass(?:word)?\b\s*[:=]")


def harvest_credentials(text: str, source: str, store: IntelStore) -> None:
    """Extract published/leaked username+password pairs (de-obfuscating zero-width tricks + HTML tags +
    the per-letter space padding some demo apps use to hide their documented test account). DISCOVERY of
    exposed creds only -- a single value the auth step reuses, never guessed. Gated on a credential
    context keyword or an explicit key:value separator so prose does not produce phantom creds."""
    if not text:
        return
    t = _HWS.sub(" ", _ZW.sub("", _TAG.sub(" ", text)))   # collapse padding, keep newlines as terminators
    for m in _CRED.finditer(t):
        # require a credential context nearby OR an explicit separator in the matched span
        pre = t[max(0, m.start() - 140):m.start()]
        if not _CRED_CTX.search(pre) and not _CRED_SEP.search(m.group(0)):
            continue
        u = re.sub(r"\s+", "", m.group(1))
        p = re.sub(r"\s+", "", m.group(2))
        if 2 <= len(u) <= 40 and 2 <= len(p) <= 60 and u.lower() not in _CRED_STOP and u != p:
            store.add("credential", "%s:%s" % (u, p), source)


def harvest_text(text: str, source: str, store: IntelStore) -> None:
    if not text:
        return
    harvest_credentials(text, source, store)
    for m in _EMAIL.findall(text):
        store.add("email", m, source)
        store.add("username", m.split("@")[0], source)
    for m in _JWT.findall(text):
        store.add("secret", m, source)
    for m in _UUID.findall(text):
        store.add("object_id", m, source)
    for m in _SEMVER.findall(text):
        store.add("version", m, source)
    for m in _URL.findall(text):
        store.add("url", m, source)
        _params_from_url(m, source, store)
    for m in _PATH.findall(text):
        store.add("route", m, source)
    for m in _SECRET_KV.findall(text):
        store.add("secret", m, source)
    # encoded blobs + offline decode (skip path-like fragments that merely share the charset)
    for m in set(_B64.findall(text)) | set(_HEX.findall(text)):
        if len(m) < 20 or m.count("/") >= 2:
            continue
        store.add("encoded", m, source)
        dec = decode_candidate(m)
        if dec and dec.strip() and dec != m:
            store.add("decoded", dec.strip(), source + " (decoded)")
    # hint sentences
    low = text.lower()
    if any(kw in low for kw in _HINT_KW):
        for line in re.split(r"[\r\n.!?]+", text):
            ll = line.lower().strip()
            if ll and len(ll) <= 200 and any(kw in ll for kw in _HINT_KW):
                store.add("hint", line.strip(), source)


def harvest_json(obj, source: str, store: IntelStore, _depth: int = 0) -> None:
    if _depth > 12:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if isinstance(v, (str, int, float)) and v not in (None, ""):
                sval = str(v)
                if any(x in kl for x in _USERKEYS) and _EMAIL.match(sval):
                    store.add("email", sval, source)
                    store.add("username", sval.split("@")[0], source)
                elif any(kl == x or kl.endswith(x) for x in _NAMEKEYS):
                    store.add("username", sval, source)
                elif any(kl == x or kl.endswith(x) for x in _IDKEYS) and re.fullmatch(r"\d{1,10}", sval):
                    store.add("object_id", sval, source)
                elif any(x in kl for x in _COUPONKEYS):
                    store.add("coupon", sval, source)
                elif any(x in kl for x in _NUMKEYS):
                    store.add("numeric", sval, source)
                elif any(x in kl for x in _SECRETKEYS):
                    store.add("secret", sval, source)
            if isinstance(v, str):
                harvest_text(v, source, store)          # descriptions carry hrefs/hints
            elif isinstance(v, (dict, list)):
                harvest_json(v, source, store, _depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            harvest_json(item, source, store, _depth + 1)
    elif isinstance(obj, str):
        harvest_text(obj, source, store)


def harvest_js(js: str, source: str, store: IntelStore) -> None:
    if not js:
        return
    harvest_text(js, source, store)
    for m in _ROUTE.findall(js):
        if m:
            store.add("route", "/" + m.lstrip("/"), source)


# ---- front-facing HTML/CSS mining: forms/params, links, redirects, meta, comments, css url() ----
_FORM = re.compile(r"(?is)<form\b([^>]*)>(.*?)</form>")
_ACTION = re.compile(r'(?i)\baction\s*=\s*["\']([^"\']+)')
_INPUT_NAME = re.compile(r'(?i)<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["\']?([\w\[\].\-]{1,40})')
_HREF_SRC = re.compile(r'(?i)\b(?:href|src|data-url|data-src|action|formaction)\s*=\s*["\']([^"\'\s>]{2,300})')
_META_REFRESH = re.compile(r'(?is)<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\'][^"\']*url\s*=\s*([^"\';]+)')
_META_GEN = re.compile(r'(?is)<meta[^>]+name\s*=\s*["\']?generator["\']?[^>]*content\s*=\s*["\']([^"\']+)')
_COMMENT = re.compile(r"(?s)<!--(.*?)-->")
_CSS_URL = re.compile(r'(?i)url\(\s*["\']?([^"\')]+)')
_CSS_IMPORT = re.compile(r'(?i)@import\s+(?:url\()?["\']([^"\']+)')
_PARAM_STOP = {"submit", "button", "", "csrfmiddlewaretoken"}


def _add_ref(ref: str, source: str, store: IntelStore) -> None:
    """Classify a URL/href/src reference as an external url or an internal route, and mine its params.

    Q-111: the href is HTML-UNESCAPED first. An attribute in real markup is entity-encoded, so
    `?a=1&amp;language=en` was split on the literal text and mined as TWO parameters, `a` and
    **`amp;language`**. Those names do not exist on the server.

    MEASURED on the operator's Shopify run: four findings were raised against `amp;language`,
    `amp;signup_page` and `amp;signup_types[]`, including a **HIGH "Server-side template injection"**
    on a parameter that is not real. Every probe against them was wasted, and every finding from
    them was false.

    The decode belongs HERE, at the one boundary where markup becomes a URL, rather than in each
    consumer -- a decode repeated per-engine is a decode someone forgets.

    Q-125 CORRECTS THE DECODER, not the placement. This was a bare `html.unescape`, which decodes a
    named reference WITHOUT its semicolon. That is the HTML5 rule for TEXT CONTENT and it is wrong
    for an attribute, where the rule is that a reference not followed by `;` is not a reference when
    an `=` or an alphanumeric follows it. Browsers already behave that way, which is why
    `<a href="?ampersand=2">` requests `ampersand`. MEASURED under the old call: `?ampersand=2` ->
    `?ersand=2`, `?times=2` -> mojibake, and the same for `copy`, `reg`, `sect`, `not`, `lt`, `gt` --
    all real parameter names and all legacy entities. The fix for phantom parameters was itself
    minting phantom parameters.
    """
    ref = _surface.unescape_url_entities(ref.strip())
    if not ref or ref.startswith(("#", "javascript:", "mailto:", "data:", "tel:")):
        return
    base = ref.split("?", 1)[0].split("#", 1)[0]
    if ref.startswith(("http://", "https://")):
        store.add("url", base, source)
    elif ref.startswith("/"):
        store.add("route", "/" + base.lstrip("/"), source)
    _params_from_url(ref, source, store)


def _params_from_url(u: str, source: str, store: IntelStore) -> None:
    if "?" not in u:
        return
    for pair in u.split("?", 1)[1].split("&"):
        name = pair.split("=", 1)[0].strip()
        if name and name.lower() not in _PARAM_STOP and len(name) <= 40:
            store.add("param", name, source)


def harvest_html(html: str, source: str, store: IntelStore) -> None:
    """Mine structured intel from a front-facing HTML page: form endpoints + input parameters, hidden
    tokens, links/script sources + their params, meta redirects/generator, and dev comments (which often
    leak credentials, endpoints, and notes). Regex-based, bounded, best-effort."""
    if not html:
        return
    for attrs, inner in _FORM.findall(html):
        am = _ACTION.search(attrs)
        if am:
            store.add("endpoint", am.group(1).strip().split("?", 1)[0], source)
            _params_from_url(am.group(1), source, store)
        for nm in _INPUT_NAME.findall(inner):
            n = nm.strip().strip("[]")
            if n and n.lower() not in _PARAM_STOP:
                store.add("param", n, source)
                if any(t in n.lower() for t in ("csrf", "token", "auth", "nonce", "session")):
                    store.add("secret", "field:" + n, source)
    for ref in _HREF_SRC.findall(html):
        _add_ref(ref, source, store)
    for t in _META_REFRESH.findall(html):
        _add_ref(t.strip(), source + " (meta-refresh)", store)
    for g in _META_GEN.findall(html):
        store.add("version", g.strip(), source)
    for c in _COMMENT.findall(html):
        cc = c.strip()
        if cc:
            store.add("comment", cc[:180], source)
            harvest_text(cc, source + " (html-comment)", store)   # creds/urls/secrets hidden in dev comments


def harvest_css(css: str, source: str, store: IntelStore) -> None:
    """Mine a CSS file: url()/@import references (assets, sometimes internal paths) and /* comments */."""
    if not css:
        return
    for u in _CSS_URL.findall(css) + _CSS_IMPORT.findall(css):
        _add_ref(u, source, store)
    for c in re.findall(r"/\*(.*?)\*/", css, re.S):
        if c.strip():
            harvest_text(c, source + " (css-comment)", store)


def harvest_headers(headers, source: str, store: IntelStore) -> None:
    try:
        items = headers.items() if hasattr(headers, "items") else headers
    except Exception:
        return
    for k, v in items or []:
        kl = str(k).lower()
        if kl in ("server", "x-powered-by"):
            for ver in _SEMVER.findall(str(v)):
                store.add("version", str(v), source)
        if kl == "set-cookie":
            name = str(v).split("=", 1)[0].strip()
            if name:
                store.add("secret", "cookie:" + name, source)


def harvest(material: dict, store: IntelStore | None = None) -> IntelStore:
    """Dispatch a bag of already-fetched material to the right harvester.

    material keys (any subset): text, html, js, headers, and json (parsed OR raw string).
    `source` labels provenance (e.g. a URL). Returns the (possibly pre-existing) store."""
    store = store or IntelStore()
    source = material.get("source", "")
    if material.get("text"):
        harvest_text(material["text"], source, store)
    if material.get("html"):
        harvest_html(material["html"], source, store)
        harvest_text(material["html"], source, store)
    if material.get("css"):
        harvest_css(material["css"], source, store)
        harvest_text(material["css"], source, store)
    if material.get("js"):
        harvest_js(material["js"], source, store)
    if material.get("headers"):
        harvest_headers(material["headers"], source, store)
    if "json" in material and material["json"] not in (None, ""):
        j = material["json"]
        if isinstance(j, str):
            try:
                j = json.loads(j)
            except Exception:
                harvest_text(material["json"], source, store)
                j = None
        if j is not None:
            harvest_json(j, source, store)
    return store
