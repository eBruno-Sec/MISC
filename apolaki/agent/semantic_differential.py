"""Semantic response differentials shared by silent injection oracles.

The comparator deliberately ignores HTTP status, response size, and error text. It confirms only an
observable application-state change: authentication, protected controls, or a strict record-set expansion.
"""
from __future__ import annotations

import html
import json
import re
import re as _re
import secrets
from html.parser import HTMLParser
from urllib.parse import unquote_plus


_WS = re.compile(r"\s+")
_AUTHENTICATED_ROUTES = re.compile(r"(?:^|[/_-])(logout|signout|logoff)(?:$|[/?#_-])", re.I)
_PROTECTED_ROUTES = re.compile(r"(?:^|[/_-])(admin|dashboard|account|profile|settings|secret)(?:$|[/?#_-])", re.I)
_DENIED_TEXT = re.compile(r"\b(?:invalid credentials|login required|sign in required|access denied|unauthorized)\b", re.I)
_RECORD_TAGS = {"tr", "li", "option", "article"}
_RECORD_ID_ATTRS = {"data-record-id", "data-result-id", "data-user-id", "data-entry-id"}
_RECORD_CLASSES = re.compile(r"\b(?:record|result|entry|user)(?:s|[-_][\w-]+)?\b", re.I)
_JSON_RECORD_KEYS = {"records", "results", "entries", "users", "items"}
_VOLATILE_JSON_KEYS = {"csrf", "csrf_token", "nonce", "timestamp", "request_id", "trace_id"}


def _norm(value) -> str:
    return _WS.sub(" ", html.unescape(str(value or ""))).strip().lower()


class _SemanticHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._captures = []
        self.records = set()
        self.protected = set()
        self.has_password = False
        self.has_logout = False
        self.text = []

    def handle_starttag(self, tag, attrs):
        tag = str(tag or "").lower()
        ad = {str(k).lower(): str(v or "") for k, v in attrs}
        if tag == "input" and ad.get("type", "").lower() == "password":
            self.has_password = True
        route = ad.get("href") or ad.get("action") or ""
        if _AUTHENTICATED_ROUTES.search(route):
            self.has_logout = True
        if _PROTECTED_ROUTES.search(route):
            self.protected.add(_norm(route))
        for cap in self._captures:
            if tag == "td":
                cap["has_td"] = True
        if tag in _RECORD_TAGS:
            record_id = next((_norm(ad[k]) for k in _RECORD_ID_ATTRS if ad.get(k)), "")
            recordish = bool(record_id or _RECORD_CLASSES.search(ad.get("class", "")))
            if tag == "option" and ad.get("value"):
                record_id, recordish = _norm(ad["value"]), True
            self._captures.append({"tag": tag, "text": [], "id": record_id,
                                   "recordish": recordish, "has_td": False})

    def handle_data(self, data):
        value = _norm(data)
        if not value:
            return
        self.text.append(value)
        for cap in self._captures:
            cap["text"].append(value)

    def handle_endtag(self, tag):
        tag = str(tag or "").lower()
        for idx in range(len(self._captures) - 1, -1, -1):
            cap = self._captures[idx]
            if cap["tag"] != tag:
                continue
            self._captures.pop(idx)
            text = _norm(" ".join(cap["text"]))
            if cap["recordish"] or cap["has_td"]:
                identity = cap["id"] or text
                if identity:
                    self.records.add(identity)
            break


def _json_identity(value) -> str:
    if isinstance(value, dict):
        for key in ("id", "uid", "username", "name", "dn"):
            if value.get(key) not in (None, ""):
                return "%s=%s" % (key, _norm(value[key]))
        stable = {k: v for k, v in value.items() if str(k).lower() not in _VOLATILE_JSON_KEYS}
        return json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str)
    return _norm(value)


def _json_semantics(value) -> dict:
    out = {"auth": "unknown", "records": set(), "protected": set()}
    if isinstance(value, dict):
        for key in ("authenticated", "logged_in", "is_authenticated"):
            if isinstance(value.get(key), bool):
                out["auth"] = "authenticated" if value[key] else "unauthenticated"
        for key, item in value.items():
            low = str(key).lower()
            if low in _JSON_RECORD_KEYS and isinstance(item, list):
                out["records"].update(x for x in (_json_identity(v) for v in item) if x)
            if low in ("dashboard", "admin", "account", "profile") and item:
                out["protected"].add(low)
    elif isinstance(value, list):
        out["records"].update(x for x in (_json_identity(v) for v in value) if x)
    return out


def _without_payloads(body: str, payloads) -> str:
    clean = str(body or "")
    for payload in payloads or ():
        if not payload:
            continue
        raw = str(payload)
        for form in {raw, html.escape(raw), unquote_plus(raw)}:
            clean = clean.replace(form, "")
    return clean


def snapshot(body: str, payloads=()) -> dict:
    """Extract only application semantics needed by the oracle."""
    clean = _without_payloads(body, payloads)
    try:
        parsed = json.loads(clean)
    except Exception:
        parsed = None
    if parsed is not None:
        return _json_semantics(parsed)

    parser = _SemanticHTML()
    try:
        parser.feed(clean)
    except Exception:
        pass
    text = _norm(" ".join(parser.text))
    auth = "authenticated" if parser.has_logout else (
        "unauthenticated" if parser.has_password or _DENIED_TEXT.search(text) else "unknown")
    return {"auth": auth, "records": parser.records, "protected": parser.protected}


#: Two responses to the same endpoint that share less than this are DIFFERENT PAGES, and a set
#: difference between different pages is a fact about routing, not about the parameter. MEASURED:
#: phpMyAdmin's `db_create.php` answers 1107 bytes to everything, while `main.php` carries a
#: font-size dropdown (`<option value="102%">`); comparing one against the other yielded a "strict
#: record-set superset (102%, 112%, 122%, 132%)" -- a CONFIRMED HIGH built out of a settings menu.
#: Same-page agreement is measured as the JACCARD OVERLAP OF DISTINCT TAG NAMES, and the reason is
#: a measurement, not taste. Sequence similarity -- on the bytes OR on the tag skeleton -- scales
#: with how many rows a page happens to carry, so it conflates "a different page" with "the same
#: view holding more rows". MEASURED, same template, N rows against 0:
#:        rows:      2      8     20     40    200
#:        raw:    0.495  0.197  0.089  0.047   ...     <- collapses
#:        skeleton:0.727  0.400  0.211  0.118   ...     <- also collapses
#:        jaccard: 0.800  0.800  0.800  0.800  0.800    <- constant, which is the point
#: A gate on either sequence metric would have started REJECTING genuine record-set differentials
#: as soon as the result set grew -- trading the false positive for a false negative that appears
#: only on the biggest, most interesting result sets.
#: Against the real pages that produced the false HIGH, jaccard separates cleanly:
#:        main.php vs db_create.php (DIFFERENT)   0.346
#:        same template, any row count (SAME)     0.800
_SAME_PAGE_MIN = 0.55


def _skeleton(body: str) -> str:
    """The document's tag sequence, with text and attribute values discarded."""
    return " ".join(_re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9]*)", body or ""))


def _tag_overlap(a: str, b: str) -> float:
    """Jaccard overlap of the DISTINCT tag names in two documents.

    Two renderings of one template use the same vocabulary of tags however many rows they carry;
    two different templates do not. Distinctness is what makes it independent of result-set size,
    which is exactly the property a same-page test needs and a sequence metric does not have."""
    A = set(_skeleton(a).split())
    B = set(_skeleton(b).split())
    return (len(A & B) / len(A | B)) if (A | B) else 0.0


def evaluate(true_body: str, false_body: str, true_payload: str = "", false_payload: str = "") -> dict:
    """Confirm only a semantic true/contradiction split, never transport or presentation noise.

    Q-179. TWO GUARDS THAT WERE MISSING, both found by replaying a `confirmed` HIGH by hand.

    The engine reported "LDAP injection in form field `new_db`" at CVSS 8.2 against
    `/phpmyadmin/db_create.php` -- a MySQL-only stack. MEASURED, three times each and stable: the
    universally-true probe, the deliberately-impossible contradiction, AND the baseline carrying no
    parameter at all return BYTE-IDENTICAL 1107-byte bodies. The application's own answer is
    `Missing parameter: new_db`, so the field was never processed by anything.

    1. IDENTICAL BODIES CANNOT CARRY A DIFFERENTIAL. If the true and false probes produced the same
       bytes, the parameter changed nothing and there is no verdict to reach. This was previously
       only implicit -- equal snapshots make each `>` comparison false -- and implicit is not a
       guarantee: it depends on every future signal being written as a strict superset test.
    2. THE TWO BODIES MUST BE THE SAME PAGE. This is the one that actually fired. Nothing checked
       that the probes landed on the same document, so a redirect or a different template made the
       whole page's contents look like records the true predicate "gained". The oracle's own words
       -- "a strict record-set superset" -- describe a comparison it never established the terms of.

    A differential oracle is only as good as its negative control, and this one never asked whether
    its control was comparable. Same lesson as the byte-identical URL-override check (Q-166), one
    layer deeper: there the guard existed and was not applied; here it did not exist at all.
    """
    payloads = (true_payload, false_payload)
    if (true_body or "") == (false_body or ""):
        return {"confirmed": False, "signal": "",
                "oracle": "the true predicate and the contradiction returned identical bodies, so "
                          "the parameter changed nothing"}
    yes = snapshot(true_body, payloads)
    no = snapshot(false_body, payloads)
    if yes["auth"] == "authenticated" and no["auth"] == "unauthenticated":
        return {"confirmed": True, "signal": "auth_state",
                "oracle": "the true predicate reached authenticated content while the contradiction remained at login"}
    # THE SAME-PAGE GATE BELONGS HERE AND NOT ABOVE, and the test suite is what taught me that.
    # `auth_state` is BY DESIGN a comparison of two different documents -- a login page against
    # authenticated content -- so gating it on similarity would delete the strongest signal this
    # oracle has. My first version did exactly that and four positive controls went red, including
    # the vulnerable XPath and LDAP fixtures. A guard that silences the engine is a worse defect
    # than the false positive it was written for.
    #
    # A SUPERSET CLAIM IS DIFFERENT. "The true predicate returned a strict record-set superset"
    # asserts that the same view returned MORE ROWS; between two different documents the phrase is
    # meaningless, and that is exactly how phpMyAdmin's font-size dropdown on `main.php` became
    # four "gained records" against `db_create.php`'s 1107-byte error page.
    _same_page = _tag_overlap(_without_payloads(true_body, payloads),
                              _without_payloads(false_body, payloads))
    if _same_page < _SAME_PAGE_MIN:
        return {"confirmed": False, "signal": "",
                "oracle": "the two probes landed on DIFFERENT pages (similarity %.3f), so a "
                          "set-difference verdict would describe routing rather than the parameter"
                          % _same_page}
    if yes["records"] and yes["records"] > no["records"]:
        gained = sorted(yes["records"] - no["records"])
        return {"confirmed": True, "signal": "record_set",
                "oracle": "the true predicate returned a strict record-set superset (%s) while the contradiction did not"
                          % ", ".join(gained[:4])}
    if yes["protected"] and yes["protected"] > no["protected"] and no["auth"] != "authenticated":
        gained = sorted(yes["protected"] - no["protected"])
        return {"confirmed": True, "signal": "protected_content",
                "oracle": "the true predicate exposed protected controls (%s) absent from the contradiction"
                          % ", ".join(gained[:4])}
    return {"confirmed": False, "signal": "", "oracle": ""}


def randomized_pair(true_value: str, false_value: str) -> list:
    """Return labelled probes in random order so request order cannot manufacture the differential."""
    pair = [("true", true_value), ("false", false_value)]
    if secrets.randbits(1):
        pair.reverse()
    return pair
