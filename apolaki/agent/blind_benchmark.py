"""Blind benchmark harness (CHAD final mandate).

The scanner must NOT learn the answers from a target's published vulnerability page. This module:
  1. defines the answer-key location(s) so the mission engine can HARD-BLOCK them from every ingestion
     path (crawl, browser, JS-route harvest, wayback/archive, LLM context, candidate generation,
     credential harvest, report evidence) — see `is_answer_key`;
  2. fetches + parses the answer key ONLY after the mission is sealed (the driver enforces ordering);
  3. normalizes the answer key into (path, method, family, context, auth, tech, benchmark_id) entries —
     de-obfuscating anti-scraper tricks (zero-width spaces) generically, not per-target;
  4. matches expected entries against the mission's INDEPENDENTLY produced findings by path + family +
     proof (never by title);
  5. scores recall/precision/coverage with the full breakdown CHAD asked for;
  6. shapes two hashed + timestamped artifacts (the blind mission BEFORE the key was read, and the
     post-mission comparison) so the ordering proves the key did not influence discovery.

Everything here is PURE + deterministic (no network, no target hardcoding). The driver (main.py) does the
I/O: run mission -> seal + hash -> fetch key -> parse -> match -> emit both artifacts.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.parse import urlparse, parse_qs

# ── 1. answer-key location: blocked from the scanner during a mission ──────────
# Generic: any target's "published vulnerabilities / answer key" surface. Extendable per engagement,
# but the DEFAULT covers the PortSwigger-style disclosure page. Matched on PATH so host/scheme-agnostic.
_ANSWER_KEY_PATHS = ("/vulnerabilities",)


def is_answer_key(url: str, extra_paths=None) -> bool:
    """True if `url` is a benchmark answer-key surface that must never reach the scanner. Path-based so
    it blocks the page under any host/scheme and with any query/fragment."""
    try:
        p = urlparse(str(url or "")).path.rstrip("/").lower() or "/"
    except Exception:
        return False
    # EXACT path match only. A published answer key is a single disclosure PAGE (/vulnerabilities);
    # sub-paths like /vulnerabilities/sqli/ are legitimate application surface (e.g. DVWA) and must NOT
    # be over-blocked. An engagement can pass extra_paths for a target whose key lives elsewhere.
    blocked = tuple(_ANSWER_KEY_PATHS) + tuple(extra_paths or ())
    return any(p == b.rstrip("/").lower() for b in blocked)


# ── de-obfuscation: strip anti-scraper zero-width / bidi characters (generic) ──
_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿‎‏‪‫‬⁡⁢⁣"), None)


def _deobfuscate(s: str) -> str:
    return re.sub(r"\s+", " ", str(s or "").translate(_ZW)).strip()


# ── 3. family vocabulary: published wording -> Apolaki canonical family ────────
# Ordered longest/most-specific first so "cross-site scripting (reflected)" wins over a bare "xss".
_FAMILY_RULES = [
    ("request url override", "request_url_override"), ("modifies request", "request_url_override"),
    ("client-side request", "request_url_override"),
    ("dom data manipulation", "dom_data_manipulation"), ("reflected dom data", "dom_data_manipulation"),
    ("dom link manipulation", "dom_link_manipulation"), ("reflected dom link", "dom_link_manipulation"),
    ("link manipulation", "dom_link_manipulation"),
    ("dom-based open redirect", "open_redirect"), ("open redirect", "open_redirect"),
    ("open redirection", "open_redirect"),
    ("dom-based cross-site scripting", "dom_xss"), ("cross-site scripting (dom", "dom_xss"),
    ("dom xss", "dom_xss"), ("dom-based xss", "dom_xss"),
    ("cross-site scripting (reflected", "reflected_xss"), ("reflected cross-site", "reflected_xss"),
    ("cross-site scripting (stored", "stored_xss"), ("stored cross-site", "stored_xss"),
    ("client-side template injection", "csti"), ("template injection", "csti"),
    ("client-side prototype pollution", "prototype_pollution"), ("prototype pollution", "prototype_pollution"),
    ("xml external entity", "xxe"), ("xxe", "xxe"),
    ("response header injection", "header_injection"), ("header injection", "header_injection"),
    ("host header", "header_injection"), ("crlf", "header_injection"),
    ("base64-encoded data", "base64_param"), ("base64", "base64_param"),
    ("sql injection", "sqli"), ("sqli", "sqli"),
    ("cross-site scripting", "reflected_xss"),   # bare XSS fallback
]

# Canonicalise the many family strings Apolaki's own findings emit onto the same benchmark keys, so
# matching is family-vs-family, never title-vs-title.
_FINDING_FAMILY_CANON = {
    "xss": "reflected_xss", "reflected_xss": "reflected_xss", "stored_xss": "stored_xss",
    "dom_xss": "dom_xss", "dom-xss": "dom_xss",
    "csti": "csti", "ssti": "csti", "template_injection": "csti",
    "prototype_pollution": "prototype_pollution",
    "open_redirect": "open_redirect", "dom_open_redirect": "open_redirect",
    "dom_link_manipulation": "dom_link_manipulation", "dom_data_manipulation": "dom_data_manipulation",
    "request_url_override": "request_url_override", "client_side_request": "request_url_override",
    "sqli": "sqli", "sql_injection": "sqli", "nosqli": "sqli",
    "xxe": "xxe", "header_injection": "header_injection", "crlf": "header_injection",
    "response_header_injection": "header_injection", "host_header": "header_injection",
    "base64_param": "base64_param",
    "vulnerable_component": "vulnerable_component", "vuln_component": "vulnerable_component",
}

_CWE_FAMILY = {
    "cwe-79": "reflected_xss", "cwe-89": "sqli", "cwe-611": "xxe", "cwe-601": "open_redirect",
    "cwe-1321": "prototype_pollution", "cwe-94": "csti", "cwe-1336": "csti", "cwe-113": "header_injection",
    "cwe-1035": "vulnerable_component", "cwe-1104": "vulnerable_component",
}


def canon_family(raw: str) -> str:
    """Map a free-text vulnerability name to a canonical family (published-wording side)."""
    t = _deobfuscate(raw).lower()
    for needle, fam in _FAMILY_RULES:
        if needle in t:
            return fam
    return ""


def finding_family(f: dict) -> str:
    """Canonical family of an Apolaki finding (family field, else CWE, else its title wording)."""
    fam = str((f or {}).get("family") or (f or {}).get("vuln_class") or "").strip().lower()
    if fam in _FINDING_FAMILY_CANON:
        return _FINDING_FAMILY_CANON[fam]
    cwe = str((f or {}).get("cwe") or "").strip().lower()
    if cwe in _CWE_FAMILY:
        return _CWE_FAMILY[cwe]
    return canon_family(str((f or {}).get("title") or "")) or fam


def normalize_path(u: str) -> str:
    """Path only, lower-cased, no trailing slash, query/fragment dropped — the matching key."""
    s = _deobfuscate(u)
    try:
        p = urlparse(s if "://" in s else ("http://x" + (s if s.startswith("/") else "/" + s))).path
    except Exception:
        p = s
    p = (p or "/").split("?")[0].split("#")[0].rstrip("/").lower()
    p = re.sub(r"\s+", "", p)   # paths never contain whitespace; the answer key inserts separators
    return p or "/"


# ── 3. parse the published answer key into normalized expected entries ─────────
_AUTH_HINT = re.compile(r"\b(log ?in|logged.?in|authenticat|my-account|session|carlos)\b", re.I)


def parse_answer_key(html: str, host: str = "") -> list:
    """Parse a published-vulnerabilities table into normalized expected entries. Rowspan-aware (a cell
    with rowspan=N applies to the next N data rows), de-obfuscated, generic across targets. Each entry:
      {benchmark_id, path, method, family, family_raw, context, auth, tech, raw}.
    One entry PER (path, family) so a path with several vulns yields several expected instances."""
    html = html or ""
    for ch in ("​", "‌", "‍", "⁠", "﻿"):
        html = html.replace(ch, "")
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S | re.I)
    entries, seen = [], set()
    carry = {}   # column-index -> (remaining_rows, text) for rowspans
    # locate the header row to learn column order (Path / Difficulties / Technologies / Vulnerabilities)
    col_idx = {"path": 0, "family": None, "tech": None, "difficulty": None}
    for r in rows:
        cells = [(_cell_attrs(a), _deobfuscate(re.sub(r"<[^>]+>", " ", c)))
                 for a, c in re.findall(r"<t[dh]([^>]*)>(.*?)</t[dh]>", r, re.S | re.I)]
        headtxt = " ".join(c[1].lower() for c in cells)
        if "path" in headtxt and ("vulnerabilit" in headtxt or "technolog" in headtxt):
            for i, (_, txt) in enumerate(cells):
                t = txt.lower()
                if "path" in t:
                    col_idx["path"] = i
                elif "vulnerabilit" in t:
                    col_idx["family"] = i
                elif "technolog" in t:
                    col_idx["tech"] = i
                elif "difficult" in t:
                    col_idx["difficulty"] = i
            break

    for r in rows:
        raw_cells = re.findall(r"<t[dh]([^>]*)>(.*?)</t[dh]>", r, re.S | re.I)
        if not raw_cells:
            continue
        # rebuild the logical row, injecting any cells still carried from an earlier rowspan
        logical, ci = {}, 0
        n_expl = len(raw_cells)
        max_col = max([col_idx["path"]] + [v for v in col_idx.values() if isinstance(v, int)] + [n_expl + len(carry)])
        expl = iter(raw_cells)
        for col in range(max_col + 1):
            if col in carry and carry[col][0] > 0:
                logical[col] = carry[col][1]
                carry[col] = (carry[col][0] - 1, carry[col][1])
                continue
            try:
                attrs, inner = next(expl)
            except StopIteration:
                continue
            txt = _deobfuscate(re.sub(r"<[^>]+>", " ", inner))
            logical[col] = txt
            rs = re.search(r'rowspan=["\']?(\d+)', attrs)
            if rs and int(rs.group(1)) > 1:
                carry[col] = (int(rs.group(1)) - 1, txt)
        path_txt = logical.get(col_idx["path"], "")
        if not path_txt.startswith("/"):
            continue   # not a data row (header, or the credentials box)
        path = normalize_path(path_txt)
        fam_cell = logical.get(col_idx["family"]) if col_idx["family"] is not None else ""
        diff_cell = logical.get(col_idx["difficulty"]) if col_idx["difficulty"] is not None else ""
        tech = logical.get(col_idx["tech"], "") if col_idx["tech"] is not None else ""
        blob = " ; ".join(x for x in (fam_cell, diff_cell) if x)
        for fam_raw in _split_families(blob):
            fam = canon_family(fam_raw)
            if not fam:
                continue
            key = (path, fam)
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "benchmark_id": "bm-%03d" % (len(entries) + 1),
                "path": path, "method": "GET", "family": fam, "family_raw": fam_raw.strip()[:80],
                "context": _context_of(fam), "tech": tech[:60],
                "auth": "authenticated" if _AUTH_HINT.search(path + " " + blob) else "anonymous",
                "raw": (path_txt.strip()[:40] + " -> " + fam_raw.strip())[:160],
            })
    return entries


def _cell_attrs(a):
    return a or ""


def _split_families(blob: str) -> list:
    """Split a cell that lists several vulnerability names into individual family phrases. Splits on
    known family boundaries so 'Client-side prototype pollution Client-side template injection' yields
    two, without needing punctuation the page omits."""
    t = _deobfuscate(blob)
    if not t:
        return []
    # insert a separator before each known family phrase start, then split
    for needle, _ in sorted(_FAMILY_RULES, key=lambda x: -len(x[0])):
        t = re.sub("(?i)(?<!\\|)(" + re.escape(needle) + ")", r"|\1", t)
    parts = [p.strip(" ;|") for p in t.split("|")]
    return [p for p in parts if p and canon_family(p)]


def _context_of(fam: str) -> str:
    return {
        "reflected_xss": "html/attribute/js (execution)", "dom_xss": "dom sink (execution)",
        "stored_xss": "stored display surface (execution)", "csti": "template expression evaluation",
        "prototype_pollution": "__proto__ gadget (runtime)", "open_redirect": "navigation target",
        "dom_link_manipulation": "anchor href/src (dom)", "dom_data_manipulation": "dom text/data (reflected)",
        "request_url_override": "outbound request (scheme/host/path/method/headers/body)",
        "sqli": "sql query", "xxe": "xml parser (external entity)",
        "header_injection": "http response header (crlf)", "base64_param": "base64-decoded parameter",
        "vulnerable_component": "served library version",
    }.get(fam, "")


# ── 4. match expected vs the mission's independently-produced findings ─────────
def _finding_paths(f: dict) -> set:
    out = set()
    for k in ("target", "surface", "location", "url"):
        v = f.get(k)
        if isinstance(v, str) and v:
            out.add(normalize_path(v))
    for inst in (f.get("instances") or []):
        if isinstance(inst, str):
            out.add(normalize_path(inst))
    return {p for p in out if p}


def _has_proof(f: dict) -> bool:
    """A finding counts as PROOF for benchmark matching only when it is confirmed AND carries an oracle
    or substantive evidence (never a bare title match)."""
    conf = str(f.get("confidence") or "").lower() in ("confirmed", "high") or bool(f.get("confirmed"))
    proof = str(f.get("success_oracle") or "").strip() or str(f.get("evidence") or "").strip()
    return conf and len(proof) >= 12


def _path_match(expected_path: str, found_paths: set) -> bool:
    if expected_path in found_paths:
        return True
    # a finding on a deeper path under the expected route (e.g. /catalog/product vs /catalog/product/1)
    return any(fp == expected_path or fp.startswith(expected_path + "/") or expected_path.startswith(fp + "/")
               for fp in found_paths if fp and fp != "/")


# XSS sub-taxonomies are matched as a GROUP: a browser-executed XSS on the right path satisfies any XSS
# expectation there (dom vs reflected vs stored is an often-ambiguous sub-label, not a different bug).
_FAM_GROUPS = {f: {"reflected_xss", "dom_xss", "stored_xss"} for f in ("reflected_xss", "dom_xss", "stored_xss")}


def _equiv(fam: str) -> set:
    return _FAM_GROUPS.get(fam, {fam})


def match(expected: list, findings: list, candidates: list = None) -> dict:
    """Match by PATH + FAMILY + PROOF. Returns per-expected verdicts + the finding/candidate buckets.
    `candidates` = every testable lead the mission surfaced (confirmed or not), for discovery/recall."""
    findings = findings or []
    candidates = candidates or []
    conf = [f for f in findings if _has_proof(f)]
    # index findings + candidates by family -> list of path-sets
    def _idx(items):
        d = {}
        for it in items:
            fam = finding_family(it)
            if fam:
                d.setdefault(fam, []).append(_finding_paths(it))
        return d
    conf_idx, cand_idx = _idx(conf), _idx(candidates)
    matched_expected, true_pos, missed, discovered_only = [], [], [], []
    used_conf = set()
    for e in expected:
        fam, path = e["family"], e["path"]
        # confirmed true-positive: family(-group) + path + proof
        tp = None
        for efam in _equiv(fam):
            for i, ps in enumerate(conf_idx.get(efam, [])):
                if (efam, i) not in used_conf and _path_match(path, ps):
                    tp = (efam, i)
                    break
            if tp:
                break
        if tp is not None:
            used_conf.add(tp)
            e2 = dict(e, status="confirmed_true_positive")
            true_pos.append(e2)
            matched_expected.append(e2)
            continue
        # discovered-but-unconfirmed: a candidate reached the right path+family(-group) but no proof
        disc = any(_path_match(path, ps) for efam in _equiv(fam) for ps in cand_idx.get(efam, []))
        e2 = dict(e, status="discovered_unconfirmed" if disc else "missed")
        (discovered_only if disc else missed).append(e2)
        matched_expected.append(e2)
    # confirmed findings that matched NO expected entry -> potential false positives (family+path novel)
    exp_keys = {(e["family"], e["path"]) for e in expected}
    false_pos = []
    for f in conf:
        fam = finding_family(f)
        fps = _finding_paths(f)
        if fam and not any(_path_match(ep, fps) for ef, ep in exp_keys if ef in _equiv(fam)):
            false_pos.append({"family": fam, "paths": sorted(fps), "title": str(f.get("title"))[:80]})
    return {"expected": matched_expected, "true_positives": true_pos, "missed": missed,
            "discovered_unconfirmed": discovered_only, "false_positives": false_pos}


# ── 5. score: recall / precision / coverage with the full CHAD breakdown ───────
def score(expected: list, m: dict, candidates: list = None, validations: dict = None) -> dict:
    validations = validations or {}
    n_exp = len(expected)
    tp = len(m["true_positives"])
    missed = len(m["missed"])
    disc_unconf = len(m["discovered_unconfirmed"])
    fp = len(m["false_positives"])
    exp_paths = {e["path"] for e in expected}
    exp_fams = {e["family"] for e in expected}
    tp_paths = {e["path"] for e in m["true_positives"]}
    tp_fams = {e["family"] for e in m["true_positives"]}
    disc_paths = tp_paths | {e["path"] for e in m["discovered_unconfirmed"]}
    disc_fams = tp_fams | {e["family"] for e in m["discovered_unconfirmed"]}
    conf_denom = tp + fp
    return {
        "expected_instances": n_exp,
        "discovered_candidates": len(candidates or []),
        "executed_validations": int(validations.get("executed", 0)),
        "confirmed_true_positives": tp,
        "missed_vulnerabilities": missed,
        "false_positives": fp,
        "dismissed_candidates": int(validations.get("dismissed", 0)),
        "unsupported_techniques": int(validations.get("unsupported", 0)),
        "blocked_validations": int(validations.get("blocked", 0)),
        "path_level_recall": round(100 * len(exp_paths & tp_paths) / len(exp_paths), 1) if exp_paths else 0.0,
        "family_level_recall": round(100 * len(exp_fams & tp_fams) / len(exp_fams), 1) if exp_fams else 0.0,
        "discovery_path_recall": round(100 * len(exp_paths & disc_paths) / len(exp_paths), 1) if exp_paths else 0.0,
        "discovery_family_recall": round(100 * len(exp_fams & disc_fams) / len(exp_fams), 1) if exp_fams else 0.0,
        "precision": round(100 * tp / conf_denom, 1) if conf_denom else 0.0,
        "unsupported_coverage_rate": round(100 * int(validations.get("unsupported", 0)) / n_exp, 1) if n_exp else 0.0,
        "instance_recall": round(100 * tp / n_exp, 1) if n_exp else 0.0,
        "discovered_unconfirmed": disc_unconf,
    }


# ── 6. hashed + timestamped artifacts (ordering proves no influence) ───────────
def _sha256(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def blind_artifact(mission_id: str, target: str, findings: list, candidates: list,
                   validations: dict, code_rev: str = "") -> dict:
    """The SEALED record of what the mission produced, built BEFORE the answer key is fetched. Its
    content_hash + sealed_at timestamp are the proof the scanner's output predates reading the key."""
    body = {
        "kind": "apolaki_blind_mission", "mission_id": mission_id, "target": target,
        "code_rev": code_rev, "findings": findings, "candidates": candidates, "validations": validations,
        "answer_key_read": False,
    }
    h = _sha256(body)
    return {**body, "content_hash": h, "hash_algo": "sha256", "sealed_at": _now_iso(),
            "sealed_at_epoch": time.time()}


def comparison_artifact(blind: dict, expected: list, m: dict, scored: dict,
                        answer_key_sha: str, answer_key_url: str) -> dict:
    """The post-mission comparison, built AFTER + BOUND to the sealed blind artifact by its hash. The
    key is referenced by its own hash + fetch time so the whole chain is auditable."""
    body = {
        "kind": "apolaki_blind_benchmark_comparison",
        "blind_artifact_hash": blind.get("content_hash"),
        "blind_sealed_at": blind.get("sealed_at"), "blind_sealed_epoch": blind.get("sealed_at_epoch"),
        "answer_key_url": answer_key_url, "answer_key_sha256": answer_key_sha,
        "answer_key_fetched_at": _now_iso(), "answer_key_fetched_epoch": time.time(),
        "expected": expected, "match": m, "score": scored,
        "ordering_ok": True,   # set by driver: fetched_epoch must be > sealed_epoch
    }
    body["ordering_ok"] = bool(body["answer_key_fetched_epoch"] > (blind.get("sealed_at_epoch") or 0))
    return {**body, "content_hash": _sha256(body), "hash_algo": "sha256"}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_text(s: str) -> str:
    return hashlib.sha256(str(s or "").encode("utf-8", "ignore")).hexdigest()
