"""Semantic response differentials shared by silent injection oracles.

The comparator deliberately ignores HTTP status, response size, and error text. It confirms only an
observable application-state change: authentication, protected controls, or a strict record-set expansion.
"""
from __future__ import annotations

import html
import json
import re
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


def evaluate(true_body: str, false_body: str, true_payload: str = "", false_payload: str = "") -> dict:
    """Confirm only a semantic true/contradiction split, never transport or presentation noise."""
    payloads = (true_payload, false_payload)
    yes = snapshot(true_body, payloads)
    no = snapshot(false_body, payloads)
    if yes["auth"] == "authenticated" and no["auth"] == "unauthenticated":
        return {"confirmed": True, "signal": "auth_state",
                "oracle": "the true predicate reached authenticated content while the contradiction remained at login"}
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
