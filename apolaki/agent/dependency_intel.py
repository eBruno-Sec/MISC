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


def extract_script_srcs(html):
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html or "", re.I)


def fingerprint_js_content(content, location=""):
    """Libraries whose self-declared version banner appears in a served JS body
    (CONFIRMED — the file states its own version)."""
    out, seen = [], set()
    for sig in LIB_SIGNATURES:
        rx = sig.get("content")
        if not rx:
            continue
        m = rx.search(content or "")
        if m and (sig["name"], m.group(1)) not in seen:
            seen.add((sig["name"], m.group(1)))
            out.append(make_component(sig["name"], m.group(1), "js-content-banner",
                                      CONFIRMED, _snippet(content, m.group(1)), location))
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


def cve_eligible(component):
    return bool(component.get("version")) and component.get("confidence") in CVE_ELIGIBLE


def assess_component(component):
    """Return [{"ids", "severity", "summary"}] of known vulns affecting this exact
    component version — ONLY when the version evidence is strong enough (guardrail).
    A component with no matching rule returns []."""
    if not cve_eligible(component):
        return []
    name, ver = component["name"], component["version"]
    out = []
    for lib, ceiling, cves, sev, summary in KNOWN_VULN:
        if name == lib and _vlt(ver, ceiling):
            out.append({"ids": cves, "severity": sev, "summary": summary})
    return out


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

    if ok:
        title = f"Vulnerable component: {comp}@{ver} ({lead}{extra})"
        evidence = (f"{base_ev} | {str(p.get('cve')).upper()} behaviour differential: trigger "
                    f"{p.get('trigger')} -> {p.get('observed')}; negative control (trigger absent) "
                    f"{p.get('control')} -> {p.get('control_observed')}")[:600]
        impact = (f"Exploitable on this target: the {str(p.get('cve')).upper()} behaviour was OBSERVED here and a "
                  f"structurally identical request with the trigger absent did not reproduce it (upstream CVE "
                  f"severity: {worst}). Rated MEDIUM pending a full impact demonstration.")
        oracle = (f"{str(p.get('cve')).upper()}'s own vulnerable behaviour was reproduced on this target "
                  f"({p.get('observed')}) and the trigger-absent negative control did not reproduce it.")
        steps = [f"Load {component.get('location') or 'the served script'}",
                 f"Confirm the version banner/filename reports {comp} {ver}",
                 f"Send the trigger: {p.get('trigger')} -> expect: {p.get('observed')}",
                 f"Send the negative control: {p.get('control')} -> expect: {p.get('control_observed')}"]
    else:
        title = f"Potentially vulnerable component: {comp}@{ver} ({lead}{extra})"
        evidence = (f"{base_ev} | version-range match only against {', '.join(ids)}; no CVE-specific "
                    f"behaviour probe confirmed it ({', '.join(gaps)})")[:600]
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
    }
    if not ok:
        out["proof_gap"] = gaps
        out["tags"] = out["tags"] + ["needs-confirmation"]
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
