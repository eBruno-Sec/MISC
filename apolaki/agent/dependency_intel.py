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


def make_component(name, version, source, confidence, evidence="", location=""):
    return {"name": (name or "").lower(), "version": version or "", "source": source,
            "confidence": confidence, "evidence": (evidence or "")[:300], "location": location or ""}


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


def vulnerable_component_finding(component, vulns):
    """CONFIRMED 'vulnerable component' finding for a cve-eligible component with
    known vulns. Severity is the worst matched; evidence cites the served version."""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    sev = max((v["severity"] for v in vulns), key=lambda s: order.get(s, 0)) if vulns else "info"
    ids = [c for v in vulns for c in v["ids"]]
    lead = ids[0] if ids else ""
    extra = f", +{len(ids) - 1} more" if len(ids) > 1 else ""
    comp, ver = component["name"], component["version"]
    return {
        "title": f"Vulnerable component: {comp}@{ver} ({lead}{extra})",
        "severity": sev, "target": component.get("location", ""),
        "description": (f"The target serves {comp} {ver} ({component['source']}), which has known "
                        f"vulnerabilities: {', '.join(ids)}. " + " ".join(v["summary"] for v in vulns)),
        "impact": "Known-vulnerable dependency — exposure depends on how the app uses it; verify reachability.",
        "evidence": f"{comp}@{ver} from {component['source']}: {component.get('evidence','')}"[:300],
        "reproduction_steps": [f"Load {component.get('location') or 'the served script'}",
                               f"Confirm the version banner/filename reports {comp} {ver}",
                               f"Cross-reference {lead} for the affected range and a safe PoC"],
        "cwe": "CWE-1104", "family": "vulnerable_component", "tags": ["sca", "dependency", comp],
        "confidence": CONFIRMED,
    }


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
