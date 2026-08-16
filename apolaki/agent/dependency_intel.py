"""
Software-composition (SCA) intelligence — deterministic, offline, no network.

Black-box first: fingerprint JS libraries from the content/URLs a target actually
serves (retire.js-style banner + filename signatures, incl. odd separators like
PortSwigger's `angular_1-7-7.js`), then map an EXACT, evidence-backed version to
known CVEs from a bundled table. Pure/deterministic and unit-tested; the transport
lives in tools._run_js_review.

Hard guardrail (ported from Yggdrasil): a CVE is NEVER inferred from a guessed
version. Only CONFIRMED/HIGH confidence fingerprints (exact version from served
content or a filename/CDN path) are CVE-eligible; a bare name with no version is
detected-only and never carries a CVE.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

CONFIRMED = "confirmed"   # exact version proven from served content
HIGH = "high"             # exact version from a filename / CDN path
LOW = "low"               # heuristic / no version — NEVER CVE-eligible
CVE_ELIGIBLE = frozenset({CONFIRMED, HIGH})

# ── Q-021A: version-certainty is NOT exploitability-certainty ────────────────────────────────
# `confidence` used to answer two different questions with one word — "are we sure the served
# version is X?" and "are we sure this is exploitable?" — so a pure database match shipped to the
# client as CONFIRMED while the prose beside it said reachability was never proven. They are now
# separate fields on the finding:
#
#   version_confidence : CONFIRMED / HIGH / LOW      how sure we are of the SERVED VERSION
#   component_status   : AFFECTED / POTENTIALLY_AFFECTED   whether the CVE's OWN behaviour was seen
#   confidence         : the platform-wide proof verdict — `confirmed` ONLY when a CVE-specific
#                        behaviour differential fired; otherwise a lead.
AFFECTED = "affected"                            # the CVE's own behaviour was observed on this target
POTENTIALLY_AFFECTED = "potentially_affected"    # version falls in a published range; behaviour unprobed

# ── Q-021B: the technology-intelligence proof ladder ─────────────────────────────────────────
# DETECTION IS NEVER A VULNERABILITY. Reading "nginx/1.18.0" off a header creates a LEAD; only an
# authorized deterministic test on this target proves anything. The rungs are named so no consumer
# has to invent its own word for "we saw it" vs "we proved it", and so a jump can be spotted:
#
#   DETECTED_TECHNOLOGY     the product is present. No version, or a version we may not act on.
#   VERSION_SUSPECTED       a version string was observed. SUSPECTED, because every version we can
#                           read is something the target said about itself until an artifact proves it.
#   ADVISORY_MATCHED        that version falls in a published range          (Q-021D)
#   APPLICABILITY_CONFIRMED the advisory actually applies to this build/config (Q-021C)
#   SAFELY_PROBED           a safe, scope-gated probe was run                (Q-021E)
#   ORACLE_CONFIRMED        a CVE-specific behaviour differential fired and its negative control
#                           did not                                          (`behaviour_proof_ok`)
#
# Q-021B tops out at VERSION_SUSPECTED by construction: nothing in this module can reach a higher
# rung without evidence that does not exist yet.
DETECTED_TECHNOLOGY = "detected_technology"
VERSION_SUSPECTED = "version_suspected"
ADVISORY_MATCHED = "advisory_matched"
APPLICABILITY_CONFIRMED = "applicability_confirmed"
SAFELY_PROBED = "safely_probed"
ORACLE_CONFIRMED = "oracle_confirmed"
TECH_PROOF_LADDER = (DETECTED_TECHNOLOGY, VERSION_SUSPECTED, ADVISORY_MATCHED,
                     APPLICABILITY_CONFIRMED, SAFELY_PROBED, ORACLE_CONFIRMED)

_VER = r"(\d+\.\d+(?:\.\d+)?(?:[-.]?(?:alpha|beta|rc)\d*)?)"


def _rx(p):
    return re.compile(p, re.IGNORECASE)


LIB_SIGNATURES = [
    {"name": "jquery", "content": _rx(r"jQuery (?:JavaScript Library )?v" + _VER),
     "filename": _rx(r"jquery[-.]" + _VER)},
    {"name": "jquery-ui", "content": _rx(r"jQuery UI[ -]+v?" + _VER),
     "filename": _rx(r"jquery-ui[-.]" + _VER)},
    {"name": "angular", "content": _rx(r"angular.*?version\s*[:=]\s*\{?\s*full\s*[:=]\s*[\"']" + _VER),
     "filename": _rx(r"angular(?:\.min)?[-.]" + _VER)},
    {"name": "bootstrap", "content": _rx(r"Bootstrap v" + _VER),
     "filename": _rx(r"bootstrap[-.]" + _VER)},
    {"name": "lodash", "content": _rx(r"@license lodash " + _VER),
     "filename": _rx(r"lodash[-.]" + _VER)},
    {"name": "moment", "content": _rx(r"//!\s*version\s*:\s*" + _VER),
     "filename": _rx(r"moment[-.]" + _VER)},
    {"name": "handlebars", "content": _rx(r"Handlebars\.VERSION\s*=\s*[\"']" + _VER),
     "filename": _rx(r"handlebars[-.]" + _VER)},
    {"name": "vue", "content": _rx(r"Vue\.version\s*=\s*[\"']" + _VER),
     "filename": _rx(r"vue[-.]" + _VER)},
    {"name": "dompurify", "content": _rx(r"DOMPurify.*?VERSION\s*=\s*[\"']" + _VER),
     "filename": _rx(r"(?:purify|dompurify)[-.]" + _VER)},
]

# Known client-side gadget libraries that don't self-report a version but are a
# vulnerability by their mere presence (filename match). deparam is the classic
# jQuery prototype-pollution gadget shipped by PortSwigger's ginandjuice /blog.
GADGET_LIBS = [
    ("deparam", _rx(r"(?:jquery[.-])?deparam(?:\.min)?\.js"),
     "client-side prototype pollution", "medium",
     "jQuery deparam is a known client-side prototype-pollution gadget; combined with a "
     "sink (e.g. AngularJS) it can escalate to DOM XSS."),
]

_CDN_PATH = _rx(r"/(?:ajax/libs|npm|gh)/([a-z0-9._-]+)/" + _VER + r"/")
_CDN_NAME_FIX = {"angular.js": "angular", "vue.js": "vue", "lodash.js": "lodash", "moment.js": "moment"}
_FLEX_LIBS = ("jquery-ui", "jquery", "angularjs", "angular", "bootstrap", "lodash",
              "moment", "handlebars", "vue", "dompurify")
_FLEX_ALIAS = {"angularjs": "angular"}
_FLEX_BY_LEN = sorted(_FLEX_LIBS, key=len, reverse=True)
_FLEX_VER = r"(\d+[._-]\d+(?:[._-]\d+)?)"


def _norm_ver(v):
    return re.sub(r"[-_]", ".", v or "")


def _norm_cdn(name):
    n = (name or "").lower()
    if n in _CDN_NAME_FIX:
        return _CDN_NAME_FIX[n]
    return n[:-3] if n.endswith(".js") else n


def canon_location(location: str) -> str:
    """Defensive URL normalization: collapse a DUPLICATED host (scheme://host//host/… or a leading
    /host/ that repeats the netloc) into a single well-formed URL. Belt-and-suspenders against the
    doubled-host bug (root cause fixed in the crawler); keeps a component's `location` printable and
    reproducible (CHAD final-audit defect #3)."""
    loc = str(location or "")
    if "://" not in loc:
        return loc
    try:
        scheme, rest = loc.split("://", 1)
        host = rest.split("/", 1)[0]
        path = rest[len(host):]
        h = host.split("@")[-1].split(":")[0]
        # strip one or more immediate repeats of the host at the front of the path
        while h and (path.startswith("//" + h + "/") or path.startswith("/" + h + "/")):
            path = path[path.index(h) + len(h):]
        return scheme + "://" + host + (path or "/")
    except Exception:
        return loc


def make_component(name, version, source, confidence, evidence="", location=""):
    return {"name": (name or "").lower(), "version": version or "", "source": source,
            "confidence": confidence, "evidence": (evidence or "")[:300], "location": canon_location(location)}


# ── Q-021B: the TechnologyFact ────────────────────────────────────────────────────────────────
# One record type for "this product, this version, on this asset, proven this well". It is a
# SUPERSET of the component record above -- `name` / `version` / `confidence` / `location` keep
# their exact meanings, so `cve_eligible`, `assess_component` and `reconcile_components` read a
# TechnologyFact with no second code path. The added fields are the ones the rest of the Q-021
# family cannot be built without: vendor, component (plugin/theme/module), category, detector,
# host, authentication state and first/last seen.

# WHICH SOURCES MAY PROVE A VERSION. The distinction is not "how specific does the string look" but
# "who said it". A `Server:` / `X-Powered-By:` / `<meta generator>` version is a CLAIM the target
# makes about itself: one config line changes it, a reverse proxy rewrites it wholesale, and
# hardened deployments lie on purpose. A library file that carries its own version banner is the
# ARTIFACT declaring itself, and a versioned filename or CDN path is a label an operator can read
# back. So only the latter two may pull CVEs; everything else is LOW and therefore, by
# CVE_ELIGIBLE, never CVE-eligible. This is the single largest false-positive source in this class.
_CONTENT_PROVEN = frozenset({"js-content-banner"})
_PATH_PROVEN = frozenset({"script-filename", "cdn-path", "script src"})


def version_confidence(source) -> str:
    """How sure we are of the SERVED version, from the detection source. FAILS CLOSED: a source this
    table does not know is LOW, so adding a detector can never silently create CVE eligibility."""
    s = str(source or "").strip().lower()
    if s in _CONTENT_PROVEN:
        return CONFIRMED
    if s in _PATH_PROVEN:
        return HIGH
    return LOW


# CPE-style vendor hints for the products the detectors can actually name today. Deliberately tiny
# and only where the vendor is unambiguous -- an unknown product yields "" and NEVER a guess, because
# a wrong vendor is a wrong CPE and a wrong CPE silently matches someone else's CVEs. Canonical
# identity (full CPE / PURL derivation) is Q-021C's job, not this one's.
_VENDOR = {
    "apache": "apache", "nginx": "nginx", "microsoft-iis": "microsoft", "iis": "microsoft",
    "asp.net": "microsoft", "asp.net mvc": "microsoft", "php": "php", "wordpress": "wordpress",
    "drupal": "drupal", "joomla": "joomla", "shopify": "shopify", "wix": "wix",
    "litespeed": "litespeedtech", "jquery": "jquery", "jquery-ui": "jquery",
    "django": "djangoproject", "laravel": "laravel", "openresty": "openresty",
}


def tech_proof_state(fact) -> str:
    """The highest rung this fact reaches ON ITS OWN. A version gets it to VERSION_SUSPECTED; nothing
    detection alone can observe gets it any higher."""
    return VERSION_SUSPECTED if str((fact or {}).get("version") or "").strip() else DETECTED_TECHNOLOGY


def tech_component_status(fact, behaviour_proof=None, cve_ids=()) -> str:
    """AFFECTED only when a CVE-SPECIFIC behaviour differential fired on this target; otherwise
    POTENTIALLY_AFFECTED. Routes through the same `behaviour_proof_ok` gate the SCA finding uses --
    one definition of "proven", not two.

    `cve_eligible` is checked FIRST and on purpose: a behaviour proof attached to a component whose
    version we could not establish proves something about the target, but nothing about THIS
    component, so it may not upgrade this fact."""
    if not cve_eligible(fact):
        return POTENTIALLY_AFFECTED
    ok, _ = behaviour_proof_ok(behaviour_proof, cve_ids)
    return AFFECTED if ok else POTENTIALLY_AFFECTED


def make_tech_fact(product, *, version="", source="", detector="", vendor=None, component="",
                   category="", evidence="", location="", host="", authenticated=False,
                   now=None):
    """One detected technology, with everything needed to act on it later and nothing invented.

    `confidence` is NOT a parameter: it is derived from `source` by `version_confidence`, so a
    detector cannot assert its own trustworthiness. A fact with no version is legal and normal --
    it is a real observation that simply may not pull CVEs."""
    import time as _time
    ts = float(now) if now is not None else _time.time()
    prod = str(product or "").strip()
    conf = version_confidence(source)
    fact = {
        # identity
        "vendor": (vendor if vendor is not None else _VENDOR.get(prod.lower(), "")),
        "product": prod.lower(),
        "component": str(component or "").strip().lower(),
        "category": str(category or ""),
        "label": prod,                       # display casing, for the UI/report
        "name": prod.lower(),                # component-record alias: existing readers use `name`
        # observation
        "version": str(version or "").strip(),
        "source": str(source or ""),
        "detector": str(detector or ""),
        "evidence": str(evidence or "")[:300],
        "location": canon_location(location),
        "host": str(host or ""),
        "authenticated": bool(authenticated),
        "first_seen": ts,
        "last_seen": ts,
        # what may be claimed about it
        "confidence": conf,                  # component-record alias, read by `cve_eligible`
        "version_confidence": conf,
        "version_conflicts": [],
    }
    fact["proof_state"] = tech_proof_state(fact)
    fact["component_status"] = tech_component_status(fact)
    return fact


def tech_fact_key(fact) -> str:
    """The dedupe key: IDENTITY (which product, which sub-component, on which asset) -- deliberately
    NOT the version. Two products that happen to report the same version string share nothing, and a
    key that omitted the product would delete one of two real facts; a key that INCLUDED the version
    would file every re-observation of the same nginx as a new technology."""
    f = fact if isinstance(fact, dict) else {}
    return "|".join([str(f.get("host") or "").lower(),
                     str(f.get("vendor") or "").lower(),
                     str(f.get("product") or f.get("name") or "").lower(),
                     str(f.get("component") or "").lower()])


def merge_tech_facts(facts) -> list:
    """Collapse repeated OBSERVATIONS of one technology identity into one fact. Order-preserving,
    pure, and junk-tolerant (a non-dict is skipped, never crashed on).

    Merge rules, in the order they are applied:
      * stronger version evidence replaces weaker  (the served file beats the filename -- the same
        reconciliation `reconcile_components` performs for JS libraries);
      * at equal strength a versioned reading beats a versionless one;
      * at equal strength two DIFFERENT versions have no principled winner, so the first is kept and
        the other is recorded in `version_conflicts` rather than silently dropped;
      * `first_seen` is the earliest and `last_seen` the latest sighting;
      * `authenticated` is true if the technology was EVER seen while authenticated.
    """
    best, order = {}, []
    for f in (facts or []):
        if not isinstance(f, dict):
            continue
        key = tech_fact_key(f)
        cur = best.get(key)
        if cur is None:
            merged = dict(f)
            merged["version_conflicts"] = list(f.get("version_conflicts") or [])
            best[key] = merged
            order.append(key)
            continue
        rank_new = _EVIDENCE_RANK.get(str(f.get("confidence") or "").lower(), -1)
        rank_cur = _EVIDENCE_RANK.get(str(cur.get("confidence") or "").lower(), -1)
        vnew, vcur = str(f.get("version") or ""), str(cur.get("version") or "")
        if rank_new > rank_cur or (rank_new == rank_cur and vnew and not vcur):
            conflicts = list(cur.get("version_conflicts") or [])
            if vcur and vcur != vnew and vcur not in conflicts:
                conflicts.append(vcur)
            first, seen_auth = cur["first_seen"], cur.get("authenticated")
            cur = dict(f)
            cur["first_seen"] = first
            cur["authenticated"] = bool(seen_auth) or bool(f.get("authenticated"))
            cur["version_conflicts"] = conflicts
            best[key] = cur
        elif rank_new == rank_cur and vnew and vcur and vnew != vcur:
            if vnew not in cur["version_conflicts"]:
                cur["version_conflicts"].append(vnew)
        cur["first_seen"] = min(cur["first_seen"], f.get("first_seen", cur["first_seen"]))
        cur["last_seen"] = max(cur["last_seen"], f.get("last_seen", cur["last_seen"]))
        cur["authenticated"] = bool(cur.get("authenticated")) or bool(f.get("authenticated"))
        cur["proof_state"] = tech_proof_state(cur)
        cur["component_status"] = tech_component_status(cur)
    return [best[k] for k in order]


def extract_script_srcs(html):
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html or "", re.I)


def fingerprint_js_content(content, location=""):
    """Libraries whose self-declared version banner appears in a served JS body
    (CONFIRMED — the file states its own version).

    Q-021C: each detection ALSO carries the applicability probes that ran against THESE bytes.
    They are attached here and not recomputed later, because here is the only place the served
    artifact is in hand — re-deriving it downstream is the Q-046 failure shape (a value parsed
    back out of a rendering it was never meant to survive)."""
    out, seen = [], set()
    for sig in LIB_SIGNATURES:
        rx = sig.get("content")
        if not rx:
            continue
        m = rx.search(content or "")
        if m and (sig["name"], m.group(1)) not in seen:
            seen.add((sig["name"], m.group(1)))
            comp = make_component(sig["name"], m.group(1), "js-content-banner",
                                  CONFIRMED, _snippet(content, m.group(1)), location)
            comp["applicability"] = probe_applicability(comp, content)
            out.append(comp)
    return out


def fingerprint_url(url):
    """One script URL -> component by CDN path or filename version (HIGH)."""
    path = urlparse(url).path if "://" in (url or "") else (url or "")
    cdn = _CDN_PATH.search(url or "")
    if cdn:
        return [make_component(_norm_cdn(cdn.group(1)), cdn.group(2), "cdn-path", HIGH, url, url)]
    for sig in LIB_SIGNATURES:
        rx = sig.get("filename")
        if rx:
            m = rx.search(path)
            if m:
                return [make_component(sig["name"], m.group(1), "script-filename", HIGH, url, url)]
    fname = path.rsplit("/", 1)[-1].lower()
    for known in _FLEX_BY_LEN:                       # catches angular_1-7-7.js etc.
        m = re.search(re.escape(known) + r"[-_.]v?" + _FLEX_VER, fname)
        if m:
            return [make_component(_FLEX_ALIAS.get(known, known), _norm_ver(m.group(1)),
                                   "script-filename", HIGH, url, url)]
    return []


# ── bundled known-vulnerable versions (offline; headline front-end libs) ──────
# Each rule: (name, ceiling_version_exclusive, [cve ids], severity, summary).
# "component version < ceiling" => vulnerable. Kept small + high-signal; extend as
# needed. AngularJS 1.x is entirely EOL, so its ceiling covers the whole 1.x line.
KNOWN_VULN = [
    ("angular", "1.99.99", ["CVE-2023-26118", "CVE-2023-26117", "CVE-2022-25869", "CVE-2020-7676"],
     "high", "AngularJS 1.x is end-of-life and carries multiple XSS/ReDoS/CSTI issues; no fixed release."),
    ("jquery", "3.5.0", ["CVE-2020-11022", "CVE-2020-11023"],
     "medium", "jQuery < 3.5.0: cross-site scripting via HTML containing <option> / self-closing tags."),
    ("jquery", "3.4.0", ["CVE-2019-11358"],
     "medium", "jQuery < 3.4.0: prototype pollution via $.extend deep merge."),
    ("lodash", "4.17.21", ["CVE-2021-23337", "CVE-2020-8203"],
     "high", "lodash < 4.17.21: command-injection template + prototype pollution."),
    ("handlebars", "4.7.7", ["CVE-2021-23369", "CVE-2019-19919"],
     "high", "Handlebars < 4.7.7: remote code execution / prototype pollution via crafted templates."),
    ("bootstrap", "3.4.1", ["CVE-2019-8331", "CVE-2018-14041"],
     "medium", "Bootstrap < 3.4.1: XSS in data-target / tooltip / popover attributes."),
    ("moment", "2.29.4", ["CVE-2022-31129"],
     "medium", "moment < 2.29.4: ReDoS in string-to-date parsing."),
    ("dompurify", "2.4.0", ["CVE-2020-26870"],
     "medium", "DOMPurify < 2.4.0: mutation-XSS sanitizer bypass."),
]


def _ver_tuple(v):
    parts = re.split(r"[.\-]", str(v or ""))
    out = []
    for p in parts:
        m = re.match(r"^(\d+)", p)
        out.append(int(m.group(1)) if m else 0)
    return tuple(out) or (0,)


def _vlt(a, b):
    """Version a < b (tuple compare, zero-padded)."""
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta < tb


# ══════════════════════════════════════════════════════════════════════════════════════════════
# Q-021C — APPLICABILITY: is the advisory's own code in the artifact we were actually served?
# ══════════════════════════════════════════════════════════════════════════════════════════════
# A version number matched against a CVE list is a LEAD. The rung above it on TECH_PROOF_LADDER is
# APPLICABILITY_CONFIRMED, and this is what earns it: the detected library AND VERSION select a
# probe, and the probe reads the bytes the target served for the *specific code the CVE is about*.
#
# This is what makes detection drive testing rather than reporting. Nothing looks for jQuery's
# deep-merge `__proto__` guard until a jQuery version inside CVE-2019-11358's range is detected;
# once it is, that exact question is asked of that exact artifact.
#
# It is NOT exploitation and this module never pretends otherwise. A corroborated probe raises
# `proof_state` to APPLICABILITY_CONFIRMED and leaves `confidence`/`component_status` exactly where
# `behaviour_proof_ok` puts them. The rungs above (SAFELY_PROBED, ORACLE_CONFIRMED) still require a
# live behaviour differential.
#
# The verdict this pipeline needed most is REFUTED. Measured on a live lab: Bootstrap 4.5.3's own
# dependency-check error string ("...requires at least jQuery v1.9.1 but less than v4.0.0") is read
# by LIB_SIGNATURES as jquery 1.9.1 at CONFIRMED, which raises a medium
# `Potentially vulnerable component: jquery@1.9.1 (CVE-2020-11022, +2 more)` on a file containing no
# jQuery at all. A version table cannot see that. Asking the artifact can.

CORROBORATED = "corroborated"     # the CVE's vulnerable code is present in the served artifact
REFUTED = "refuted"               # the patch is present, or the library itself is not in this file
INCONCLUSIVE = "inconclusive"     # the probe ran and could not decide — never treated as either
APPLICABILITY_VERDICTS = (CORROBORATED, REFUTED, INCONCLUSIVE)


def _clip(s, n=200):
    return re.sub(r"\s+", " ", str(s or ""))[:n]


# ── jQuery: is the library REALLY here? ───────────────────────────────────────────────────────
# The negative control for every jQuery probe, and the one that fires on the measured false
# positive. A version banner is a STRING; the library is a RUNTIME. Both markers are required
# (AND, not OR) because a single marker is what made this class of check wrong in the first place:
# `.fn.jquery` was the obvious presence test and it is measurably WORSE than useless here — it is
# present in bootstrap.bundle.min.js (which checks the host page's jQuery version) and ABSENT from
# the minified jQuery 2.1.4/3.4.1/3.5.1 that three live labs actually serve.
#
# Measured over 6 real served artifacts (mutillidae jquery 1.8.3, webgoat 2.1.4, webgoat 3.4.1,
# dvga 3.5.1, dvga bootstrap.bundle 4.5.3, dvga graphql.js): both markers true on 4/4 real jQuery,
# both false on 2/2 non-jQuery.
_JQ_RUNTIME = (
    ("jQuery prototype constructor (`.fn.init`)", _rx(r"[\w$]+\.fn\.init\b")),
    ("jQuery version property (`jquery:`)", _rx(r"\bjquery\s*:\s*[\w\"']")),
)

# `X.extend = X.fn.extend = function()` — the deep-merge CVE-2019-11358 is about. Survives
# minification (measured: `n.extend=n.fn.extend=function`, `k.extend=k.fn.extend=function`,
# `S.extend=S.fn.extend=function`) and reads identically in the unminified source.
_JQ_EXTEND_SITE = _rx(r"[\w$]+\.extend\s*=\s*[\w$]+\.fn\.extend\s*=\s*function")

# The fix shipped in 3.4.0: `if ( name === "__proto__" || target === copy ) { continue; }`.
# Searched ONLY inside the extend body — `__proto__` appears in unrelated code elsewhere (measured:
# once in bootstrap.bundle.min.js, in its prototype-chain helper), so a whole-file search would
# refute a genuinely vulnerable file that happens to mention it.
_JQ_PROTO_GUARD = _rx(r"[\"']__proto__[\"']")

# Widest measured distance from the site to the guard is ~1.1kB (unminified 3.4.1); the minified
# builds put it ~200 bytes in. 2400 is that with margin, and `test_the_extend_window_covers_the_
# unminified_guard` pins it against an unminified-shaped body.
_JQ_EXTEND_WINDOW = 2400

# CVE-2020-11022/11023: `rxhtmlTag` rewrote self-closing tags in htmlPrefilter. jQuery 3.5.0 deleted
# the rewrite outright (`htmlPrefilter: function( html ) { return html; }`), so the regex literal's
# own alternation is a direct read of whether the vulnerable transform is still in this build.
# Measured present in 1.8.3 / 2.1.4 / 3.4.1 and absent in 3.5.1.
_JQ_SELFCLOSE_REWRITE = _rx(r"area\|br\|col\|embed\|hr\|img\|input\|link\|meta\|param")


def _probe_jquery_extend_proto(text):
    """CVE-2019-11358 — prototype pollution via `$.extend` deep merge.

    Returns (verdict, observed, reason, evidence).
    """
    site = _JQ_EXTEND_SITE.search(text)
    if not site:
        # The library IS here (the caller checked) but this artifact does not contain the merge
        # implementation — a split bundle, or a build that exports it from elsewhere. Undecidable,
        # and saying so is the whole point: an INCONCLUSIVE probe drops nothing.
        return (INCONCLUSIVE, "the `X.extend = X.fn.extend = function` deep-merge site is not in "
                              "this artifact", "site_not_located", "")
    window = text[site.start(): site.start() + _JQ_EXTEND_WINDOW]
    guard = _JQ_PROTO_GUARD.search(window)
    if guard:
        return (REFUTED, "the deep-merge loop DOES guard `__proto__` (the fix shipped in 3.4.0)",
                "patched_in_served_artifact",
                _clip(window[max(0, guard.start() - 100): guard.start() + 60]))
    return (CORROBORATED, "the deep-merge loop copies every own key with NO `__proto__` guard",
            "vulnerable_code_present_in_served_artifact", _clip(window[:180]))


def _probe_jquery_selfclosing_rewrite(text):
    """CVE-2020-11022 / CVE-2020-11023 — XSS via jQuery's self-closing-tag HTML rewrite."""
    m = _JQ_SELFCLOSE_REWRITE.search(text)
    if not m:
        return (REFUTED, "the self-closing-tag rewrite regex is absent (removed in 3.5.0)",
                "patched_in_served_artifact", "")
    return (CORROBORATED, "the self-closing-tag rewrite regex is still present and applied to "
                          "untrusted HTML", "vulnerable_code_present_in_served_artifact",
            _clip(text[max(0, m.start() - 70): m.start() + 120]))


#: library -> the probes that may run against its served artifact. `cves` is the ONLY link to the
#: advisory table; the version range is DERIVED from KNOWN_VULN by those ids (`_probe_in_range`) so
#: a probe can never claim to cover a range the table does not actually have. Two hand-maintained
#: copies of the same range is how a gate drifts out of step with its detector.
APPLICABILITY_PROBES = (
    {"id": "jquery-extend-proto-guard", "library": "jquery",
     "cves": ("CVE-2019-11358",),
     "looked_for": "jQuery's `$.extend` deep-merge loop, and the `__proto__` guard added in 3.4.0",
     "probe": _probe_jquery_extend_proto},
    {"id": "jquery-selfclosing-rewrite", "library": "jquery",
     "cves": ("CVE-2020-11022", "CVE-2020-11023"),
     "looked_for": "jQuery's self-closing-tag HTML rewrite (`rxhtmlTag`), removed in 3.5.0",
     "probe": _probe_jquery_selfclosing_rewrite},
)

#: library -> its runtime-presence markers. A library with no entry cannot be probed at all, which
#: is correct: without a presence control the `library_absent` refutation has no basis.
_RUNTIME_MARKERS = {"jquery": _JQ_RUNTIME}

#: How much artifact an ABSENCE argument needs before it means anything.
#:
#: `library_absent_from_artifact` is an absence-of-evidence claim, and it is only decisive when
#: there was somewhere for the evidence to be. 84kB of Bootstrap with no jQuery runtime in it
#: settles the question; a 55-byte body that is nothing but a version comment settles nothing, and
#: refuting on it turns a truncated read into a false negative. Measured smallest real served
#: library artifact across the labs: 13,955 bytes (dvga graphql.js); the four real jQuery files are
#: 84kB-268kB. 2048 sits far below every real artifact and far above every banner stub.
#:
#: Below the floor the verdict is INCONCLUSIVE, which by construction drops nothing.
_MIN_ARTIFACT_FOR_ABSENCE = 2048

#: Reasons a presence check can fail. Named so the probe can tell "this is not the library" from
#: "there was not enough here to tell" — one refutes, the other must not.
_ABSENT = "absent"
_TOO_SMALL = "too_small"


def _library_present(library, text):
    """(state, observed) — is the LIBRARY, not merely its name, in these bytes?

    `state` is True, `_ABSENT` or `_TOO_SMALL`. Fails closed: an unknown library is `_ABSENT` with
    an explicit reason, so adding a probe without a presence control can never silently produce a
    refutation.
    """
    markers = _RUNTIME_MARKERS.get(str(library or "").lower())
    if not markers:
        return _ABSENT, "no runtime marker is defined for this library"
    body = text or ""
    missing = [label for label, rx in markers if not rx.search(body)]
    if not missing:
        return True, "the library's own runtime is present (%s)" % \
            "; ".join(label for label, _ in markers)
    if len(body) < _MIN_ARTIFACT_FOR_ABSENCE:
        return _TOO_SMALL, ("only %d bytes were served — too little for the absence of the "
                            "library's runtime to mean anything" % len(body))
    return _ABSENT, "the library's own runtime is absent from this artifact (missing: %s)" % \
        "; ".join(missing)


def _probe_in_range(component_version, probe):
    """Does this version fall in a KNOWN_VULN range carrying one of the probe's CVE ids?

    DERIVED from KNOWN_VULN rather than restated on the probe — the probe declares WHICH advisory
    it tests, never the boundary of that advisory."""
    ids = {str(c).upper() for c in probe.get("cves") or ()}
    lib = str(probe.get("library") or "").lower()
    for rule_lib, ceiling, cves, _sev, _summary in KNOWN_VULN:
        if rule_lib == lib and ids & {str(c).upper() for c in cves} and _vlt(component_version, ceiling):
            return True
    return False


def probe_applicability(component, artifact_text):
    """Run every in-range applicability probe for this component against the SERVED artifact.

    Returns a list of records — one per probe that was in range — each naming what was looked for,
    what was observed, the presence control and its observation. An EMPTY list means no probe was
    applicable (no version, no artifact, unknown library, or the version is outside every range
    this module has a probe for). That is deliberately distinct from a probe that ran and returned
    INCONCLUSIVE: emptiness must never be read as a verdict.
    """
    name = str((component or {}).get("name") or "").lower()
    ver = str((component or {}).get("version") or "").strip()
    text = artifact_text if isinstance(artifact_text, str) else ""
    if not name or not ver or not text:
        return []
    present, present_obs = _library_present(name, text)
    out = []
    for p in APPLICABILITY_PROBES:
        if p["library"] != name or not _probe_in_range(ver, p):
            continue
        rec = {"probe": p["id"], "library": name, "version": ver,
               "cves": [str(c).upper() for c in p["cves"]],
               "looked_for": p["looked_for"],
               "control": "the artifact carries the library's own runtime, not merely its name",
               "control_observed": present_obs,
               "location": canon_location((component or {}).get("location") or "")}
        if present is True:
            verdict, observed, reason, ev = p["probe"](text)
            rec.update({"verdict": verdict, "observed": observed, "reason": reason, "evidence": ev})
        elif present == _ABSENT:
            # The presence control failed on an artifact large enough for that to mean something,
            # so the version reading did not come from this library. This is the refutation that
            # removes the measured Bootstrap-banner false positive.
            rec.update({"verdict": REFUTED, "reason": "library_absent_from_artifact",
                        "observed": "the version string was read from an artifact that does not "
                                    "contain the library", "evidence": ""})
        else:
            # _TOO_SMALL. There was not enough artifact for absence to argue anything, so this
            # probe decides nothing and (INCONCLUSIVE) drops nothing. MEASURED consequence of
            # getting this wrong: `retest.evaluate` re-fingerprints a replacement body and asks
            # `assess_component` whether the new version is still in range. Refuting on a short
            # body made a still-vulnerable upgrade (3.4.0 -> 3.4.1, still inside <3.5.0) verdict
            # CLOSED -- a remediation lie, and the exact false negative this ladder exists to
            # prevent. Caught by test_q021a_sca_proof::test_retest_upgrade_that_is_still_in_range.
            rec.update({"verdict": INCONCLUSIVE, "reason": "artifact_too_small_to_prove_absence",
                        "observed": "the library's runtime is not in these bytes, but there are "
                                    "too few bytes for that to mean anything", "evidence": ""})
        out.append(rec)
    return out


def applicability_records(component):
    """The probe records carried by a component. `or []` is safe HERE and only here: absent, None
    and empty all mean the same thing — no probe ran. Every verdict is inside a record."""
    recs = (component or {}).get("applicability") or []
    return [r for r in recs if isinstance(r, dict)]


def refuted_cves(component) -> set:
    """CVE ids an applicability probe REFUTED against the served artifact. INCONCLUSIVE is not a
    refutation and never appears here."""
    out = set()
    for r in applicability_records(component):
        if r.get("verdict") == REFUTED:
            out |= {str(c).upper() for c in (r.get("cves") or [])}
    return out


def corroborated_records(component, cve_ids=()) -> list:
    """CORROBORATED probe records, optionally restricted to the CVE ids a finding actually matched."""
    want = {str(c).upper() for c in (cve_ids or ())}
    out = []
    for r in applicability_records(component):
        if r.get("verdict") != CORROBORATED:
            continue
        if want and not (want & {str(c).upper() for c in (r.get("cves") or [])}):
            continue
        out.append(r)
    return out


def cve_eligible(component):
    return bool(component.get("version")) and component.get("confidence") in CVE_ELIGIBLE


def assess_component(component):
    """Return [{"ids", "severity", "summary"}] of known vulns affecting this exact
    component version — ONLY when the version evidence is strong enough (guardrail).
    A component with no matching rule returns [].

    Q-021C: a range whose CVE ids were ALL refuted by an applicability probe against the served
    artifact is dropped. Three properties this keeps:

      * a component with NO applicability records is assessed exactly as before. Absent means "not
        probed", never "refuted" — the version table stays the answer when nothing tested it.
      * only REFUTED drops. INCONCLUSIVE drops nothing, so a split bundle we could not read never
        becomes a false negative.
      * the drop is not invisible: the refuting record was written onto the component by the
        detector that ran the probe and travels with it into the graph and the report.
    """
    if not cve_eligible(component):
        return []
    name, ver = component["name"], component["version"]
    refuted = refuted_cves(component)
    out = []
    for lib, ceiling, cves, sev, summary in KNOWN_VULN:
        if name == lib and _vlt(ver, ceiling):
            if refuted and {str(c).upper() for c in cves} <= refuted:
                continue
            out.append({"ids": cves, "severity": sev, "summary": summary})
    return out


_EVIDENCE_RANK = {CONFIRMED: 2, HIGH: 1, LOW: 0}


def reconcile_components(components) -> list:
    """Collapse CONTRADICTORY fingerprints of the same library at the same location, keeping the one
    with the strongest evidence. Order-preserving and pure.

    The false positive this removes: `/assets/jquery-3.4.0.js` that now SERVES 3.6.0 fingerprints
    twice — 3.6.0 from the body (CONFIRMED, the file states its own version) and 3.4.0 from the path
    (HIGH, a label an in-place upgrade never renames). They are different `(name, version)` keys, so
    both survive the caller's dedupe and the stale one raises a `vulnerable_component` finding for a
    library that was already patched.

    Two deliberate limits. Reconciliation is per LOCATION, because one page really can ship two
    versions from two bundles. And when the two contradictory fingerprints are EQUALLY strong there
    is no principled winner, so both are kept — dropping the vulnerable one would be a false
    negative and dropping the patched one would be the false positive being removed.
    """
    best, order = {}, []
    for c in (components or []):
        if not isinstance(c, dict):
            continue
        key = ((c.get("name") or "").lower(), canon_location(c.get("location") or ""))
        rank = _EVIDENCE_RANK.get(str(c.get("confidence") or "").lower(), -1)
        if key not in best:
            best[key] = [(rank, c)]
            order.append(key)
            continue
        top = max(r for r, _ in best[key])
        if rank > top:
            best[key] = [(rank, c)]           # stronger evidence replaces every weaker reading
        elif rank == top and not any(str(o.get("version") or "") == str(c.get("version") or "")
                                     for _, o in best[key]):
            best[key].append((rank, c))       # equally strong and contradictory -> keep both
    return [c for key in order for _, c in best[key]]


def components_for_artifact(content, location=""):
    """Every component ONE served artifact yields, with contradictory readings reconciled.

    One definition of "what did this file tell us about its libraries". `tools._run_js_review` and
    `retest.evaluate` each hand-rolled `fingerprint_js_content(...) + fingerprint_url(...)`, and
    only ONE of them went on to reconcile. That is why the false positive `reconcile_components`
    was written to remove still shipped on every scan and was removed only at retest time:

        url  = https://t/assets/jquery-3.4.0.js      (the label)
        body = /*! jQuery JavaScript Library v3.6.0  (what is actually served, and patched)

        scan path today   -> Potentially vulnerable component: jquery@3.4.0 (CVE-2020-11022, +1)
        with reconcile    -> (nothing)

    MEASURED on this tree before the fix, and `reconcile_components`'s only production caller was
    `retest.py:123`. Two copies of a composition rule with the guard on only one of them is how a
    tested function ends up never running where it matters.
    """
    return reconcile_components(fingerprint_js_content(content, location)
                                + fingerprint_url(location))


def behaviour_proof_ok(proof, cve_ids=()) -> tuple:
    """(ok, gaps[]) — did a CVE-SPECIFIC BEHAVIOUR DIFFERENTIAL demonstrate this vulnerability?

    A version falling inside a published range is a DATABASE MATCH, not an observation. The only
    thing that upgrades it to a confirmation is: fire the CVE's own trigger and see the vulnerable
    behaviour, then fire a STRUCTURALLY IDENTICAL request with the trigger ABSENT and see that
    behaviour not happen. Both halves are required — without the negative control the "vulnerable
    behaviour" may simply be what the application always does.

    The proof is a dict: {cve, trigger, observed, control, control_observed}. Pure — the caller
    performs the two requests; this only judges what came back.
    """
    p = proof if isinstance(proof, dict) else {}
    if not p:
        return False, ["behaviour_probe_not_run"]
    gaps = []
    cve = str(p.get("cve") or "").strip().upper()
    if not cve:
        gaps.append("cve")
    elif cve_ids and cve not in {str(c).strip().upper() for c in cve_ids}:
        # A grouped range yields several CVEs; a proof for a CVE this component's version did NOT
        # match proves nothing about this component (jQuery 3.4.0 matches <3.5.0 but not <3.4.0).
        gaps.append("cve_not_in_matched_ranges")
    for k in ("trigger", "observed", "control", "control_observed"):
        if not str(p.get(k) or "").strip():
            gaps.append(k)
    obs, ctl = str(p.get("observed") or "").strip(), str(p.get("control_observed") or "").strip()
    if obs and ctl and obs == ctl:
        gaps.append("no_differential")   # trigger-absent control behaved identically => baseline, not a bug
    return (not gaps), gaps


def vulnerable_component_finding(component, vulns, behaviour_proof=None):
    """A 'vulnerable component' finding whose CONFIDENCE states what was PROVEN, not what a version
    table says (Q-021A).

    Without `behaviour_proof` this is a LEAD: the served version is certain (`version_confidence`),
    the component is `potentially_affected`, and nothing about exploitability has been observed.
    With a CVE-specific behaviour differential that passes `behaviour_proof_ok`, and only then, the
    finding becomes `confirmed` / `affected`.

    `CVE_ELIGIBLE` stays the single enforcement point for version evidence: a LOW-confidence
    fingerprint is a guess, so it can never be AFFECTED however many CVEs a feed returns for it.
    """
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst = max((v["severity"] for v in vulns), key=lambda s: order.get(s, 0)) if vulns else "info"
    # Truth-first: SCA is PRESENCE detection — the vulnerable version is confirmed, but
    # exploitability (a reachable sink) is NOT. Cap at MEDIUM so an unverified-reachability
    # component is never rated High/Critical (that is the scanner-inflation pattern). The
    # underlying CVE severity is still stated in the description.
    sev = "medium" if order.get(worst, 0) > order["medium"] else worst
    ids = [c for v in vulns for c in v["ids"]]
    lead = ids[0] if ids else ""
    extra = f", +{len(ids) - 1} more" if len(ids) > 1 else ""
    comp, ver = component["name"], component["version"]
    ver_conf = str(component.get("confidence") or LOW).lower()

    ok, gaps = behaviour_proof_ok(behaviour_proof, ids)
    if not cve_eligible(component):
        ok = False
        gaps = ["version_confidence_too_low"] + [g for g in gaps if g != "behaviour_probe_not_run"]
    status = AFFECTED if ok else POTENTIALLY_AFFECTED
    p = behaviour_proof if isinstance(behaviour_proof, dict) else {}
    base_ev = f"{comp}@{ver} from {component['source']}: {component.get('evidence','')}"[:300]

    # Q-021C — the applicability rung. `corr` are the probes that read the SERVED artifact and found
    # the CVE's own vulnerable code still in it. They do NOT raise `confidence` or
    # `component_status`: locating vulnerable code is not observing exploitation, and the two
    # questions Q-021A separated must stay separated. What they do change is the rung this finding
    # reaches and what its evidence can honestly say.
    corr = corroborated_records(component, ids)
    applic_sentence = ""
    if corr:
        applic_sentence = " | ".join(
            f"applicability probe {r['probe']} read the served artifact: looked for "
            f"{r['looked_for']}; OBSERVED {r['observed']}; control - {r['control_observed']}"
            for r in corr)
    elif applicability_records(component):
        applic_sentence = "; ".join(
            f"applicability probe {r['probe']}: {r['verdict']} ({r.get('reason', '')})"
            for r in applicability_records(component))

    if ok:
        title = f"Vulnerable component: {comp}@{ver} ({lead}{extra})"
        evidence = (f"{base_ev} | {str(p.get('cve')).upper()} behaviour differential: trigger "
                    f"{p.get('trigger')} -> {p.get('observed')}; negative control (trigger absent) "
                    f"{p.get('control')} -> {p.get('control_observed')}"
                    + (f" | {applic_sentence}" if applic_sentence else ""))[:900]
        impact = (f"Exploitable on this target: the {str(p.get('cve')).upper()} behaviour was OBSERVED here and a "
                  f"structurally identical request with the trigger absent did not reproduce it (upstream CVE "
                  f"severity: {worst}). Rated MEDIUM pending a full impact demonstration.")
        oracle = (f"{str(p.get('cve')).upper()}'s own vulnerable behaviour was reproduced on this target "
                  f"({p.get('observed')}) and the trigger-absent negative control did not reproduce it.")
        steps = [f"Load {component.get('location') or 'the served script'}",
                 f"Confirm the version banner/filename reports {comp} {ver}",
                 f"Send the trigger: {p.get('trigger')} -> expect: {p.get('observed')}",
                 f"Send the negative control: {p.get('control')} -> expect: {p.get('control_observed')}"]
    elif corr:
        # ADVISORY_MATCHED + the advisory's own code located in the artifact this target served.
        # Still a lead — but no longer a version-table lead, and the evidence says which bytes.
        title = f"Potentially vulnerable component: {comp}@{ver} ({lead}{extra})"
        evidence = (f"{base_ev} | version-range match against {', '.join(ids)}, and {applic_sentence}"
                    f" | no CVE-specific runtime behaviour differential was run ({', '.join(gaps)})")[:900]
        impact = (f"Known-vulnerable dependency (upstream CVE severity: {worst}). The vulnerable code the CVE "
                  "describes was LOCATED IN THE ARTIFACT THIS TARGET SERVES, so this is not a version-table "
                  "guess — but exploitability still depends on the application reaching that code with "
                  "attacker-controlled input, which was NOT observed. Rated MEDIUM. Run the CVE behaviour "
                  "probe to escalate.")
        oracle = (f"the served artifact reports {comp} {ver} AND an applicability probe read that artifact and "
                  f"found the code {lead or 'the referenced CVE'} describes still present "
                  f"({'; '.join(r['observed'] for r in corr)}), with the control confirming the artifact really "
                  f"contains the library. APPLICABILITY-confirmed only. Confirmation requires a "
                  f"{lead or 'CVE'}-specific behaviour differential: the trigger reproduces the vulnerable "
                  "behaviour and a trigger-absent control does not.")
        steps = [f"Load {component.get('location') or 'the served script'}",
                 f"Confirm the version banner/filename reports {comp} {ver}",
                 *[f"Applicability: search the served bytes for {r['looked_for']} -> expect: {r['observed']}"
                   for r in corr],
                 f"Run a {lead or 'CVE'}-specific behaviour probe plus its trigger-absent control to confirm"]
    else:
        title = f"Potentially vulnerable component: {comp}@{ver} ({lead}{extra})"
        evidence = (f"{base_ev} | version-range match only against {', '.join(ids)}; no CVE-specific "
                    f"behaviour probe confirmed it ({', '.join(gaps)})"
                    + (f" | {applic_sentence}" if applic_sentence else ""))[:900]
        impact = (f"Known-vulnerable dependency (upstream CVE severity: {worst}). Rated MEDIUM here because "
                  "exploitability depends on a reachable sink, which was NOT confirmed in this test — this is a "
                  "version-range match, not an observed exploit. Probe the CVE behaviour to escalate.")
        oracle = (f"the served response/filename reports the exact version {comp} {ver}, which falls in the "
                  f"affected range of {lead or 'the referenced CVE'} — PRESENCE-confirmed only. Confirmation "
                  f"requires a {lead or 'CVE'}-specific behaviour differential: the trigger reproduces the "
                  "vulnerable behaviour and a trigger-absent control does not.")
        steps = [f"Load {component.get('location') or 'the served script'}",
                 f"Confirm the version banner/filename reports {comp} {ver}",
                 f"Cross-reference {lead} for the affected range and a safe PoC",
                 f"Run a {lead or 'CVE'}-specific behaviour probe plus its trigger-absent control to confirm"]

    out = {
        "title": title,
        "severity": sev, "target": component.get("location", ""),
        "description": (f"The target serves {comp} {ver} ({component['source']}), which has known "
                        f"vulnerabilities: {', '.join(ids)}. " + " ".join(v["summary"] for v in vulns)),
        "impact": impact,
        "evidence": evidence,
        "reproduction_steps": steps,
        "cwe": "CWE-1104", "family": "vulnerable_component", "tags": ["sca", "dependency", comp],
        # STRUCTURED identifiers, not prose. KEV/ExploitDB matching reads `cve`/`cves`; these ids
        # used to exist only inside the title and description, so an SCA finding silently missed the
        # KEV catalog. Emitting the list here is the fix — never a consumer-side regex over titles.
        # Exactly the ids of the ranges this version MATCHED (a grouped range it fell outside is
        # not listed).
        "cves": list(dict.fromkeys(ids)),
        # the two questions, answered separately
        "confidence": CONFIRMED if ok else "lead",
        "version_confidence": ver_conf,
        "component_status": status,
        "component": comp, "component_version": ver,
        "success_oracle": oracle,
        # Q-021C — WHICH RUNG. Stated as a field rather than inferred from prose, because a consumer
        # that has to regex a title to learn how well something was proven is the Q-046/Q-051 shape.
        "proof_state": (ORACLE_CONFIRMED if ok else
                        APPLICABILITY_CONFIRMED if corr else
                        ADVISORY_MATCHED),
        # every probe that ran against the served artifact, refutations included
        "applicability": applicability_records(component),
    }
    if not ok:
        out["proof_gap"] = gaps
        out["tags"] = out["tags"] + ["needs-confirmation"]
        if corr:
            out["tags"] = out["tags"] + ["applicability-confirmed"]
    return out


def gadget_findings(url):
    """Known client-side GADGET libraries detected by filename. Presence-only, so
    these are LEADS (candidate) — a gadget is exploitable only once it reaches a
    sink, which needs dynamic confirmation. Names the exact script for the operator."""
    path = urlparse(url).path if "://" in (url or "") else (url or "")
    out = []
    for name, rx, vuln, sev, note in GADGET_LIBS:
        if rx.search(path):
            out.append({
                "title": f"Client-side gadget library: {name} ({vuln})",
                "severity": sev, "target": url, "confidence": "candidate",
                "description": note, "impact": "Client-side prototype pollution can be chained to DOM XSS.",
                "family": "prototype_pollution", "cwe": "CWE-1321",
                "evidence": f"gadget library served at {path}",
                "tags": ["prototype-pollution", "sca", name]})
    return out


def _snippet(text, needle, width=80):
    i = (text or "").find(needle)
    if i < 0:
        return (text or "")[:width]
    return (text or "")[max(0, i - width // 2): i + len(needle) + width // 2].replace("\n", " ")
