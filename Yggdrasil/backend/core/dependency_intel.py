"""
Dependency / software-composition intelligence (SCA) for Yggdrasil.

Black-box first: Yggdrasil scans authorized REMOTE web targets, so most of the
signal comes from what the target actually serves; loaded scripts, bundled JS,
banner comments, source maps, response headers, and any dependency manifest
that is publicly reachable. This module turns that raw material into structured
dependency findings and (evidence-gated) CVE matches.

What lives here (all pure/deterministic; no I/O, no subprocess, no DB, so every
function is directly unit-testable):
  - JS library fingerprinting from file content (retire.js-style banner/version
    signatures) and from script URLs/filenames.
  - Framework/server fingerprinting from response headers.
  - Exposed-manifest path list + ecosystem classification + light manifest
    parsing (exact-version entries only, for OSV lookups).
  - Source-map parsing -> packages + original source paths (endpoint hints).
  - OSV query building + response parsing (map component@version -> CVE/GHSA/OSV).
  - Vulnerable-library -> follow-up probe-family mapping (feeds BROKKR).
  - The dependency finding model + title semantics ("vulnerable component
    detected" vs. "validated exploit path").

Hard guardrail baked in: a CVE is NEVER inferred from a guessed version. Only
"confirmed"/"high" confidence fingerprints (exact version from file content,
lockfile, or filename) are eligible for OSV lookup; "low" confidence
fingerprints are reported as detected-only and never carry a CVE.
"""
import json
import re
from urllib.parse import urlparse

# Confidence tiers for a version detection.
CONFIRMED = "confirmed"   # exact version proven from served content / lockfile
HIGH = "high"             # exact version from a filename or CDN path
LOW = "low"               # heuristic / range only; NEVER eligible for CVE claims

# A version detection must be at least this confident before we will look it up
# in a vuln DB or attach a CVE to it (the "never infer a CVE from a guessed
# version" guardrail, enforced in one place).
CVE_ELIGIBLE = frozenset({CONFIRMED, HIGH})

# Validation state of a finding.
PASSIVE = "passive"               # observed only; no request beyond fetching the asset
ACTIVE_SAFE = "active-safe"       # a safe, non-destructive check confirmed it
MANUAL_REQUIRED = "manual-required"  # exploit validation needs explicit human approval

_VER = r"(\d+\.\d+(?:\.\d+)?(?:[-.]?(?:alpha|beta|rc)\d*)?)"


def _rx(pattern):
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# JS library signatures. Each entry: name + ecosystem + optional content regex
# (matched against the served JS body; retire.js relies on exactly these
# banner/version markers) + optional filename regex (matched against the script
# URL). The first capture group is always the version.
# ---------------------------------------------------------------------------
LIB_SIGNATURES = [
    {"name": "jquery", "ecosystem": "npm",
     "content": _rx(r"jQuery (?:JavaScript Library )?v" + _VER),
     "filename": _rx(r"jquery[-.]" + _VER)},
    {"name": "jquery-ui", "ecosystem": "npm",
     "content": _rx(r"jQuery UI[ -]+v?" + _VER),
     "filename": _rx(r"jquery-ui[-.]" + _VER)},
    {"name": "jquery-migrate", "ecosystem": "npm",
     "content": _rx(r"jQuery Migrate[ -]+v?" + _VER),
     "filename": _rx(r"jquery-migrate[-.]" + _VER)},
    {"name": "angular", "ecosystem": "npm",   # AngularJS 1.x
     "content": _rx(r"angular.*?version\s*[:=]\s*\{?\s*full\s*[:=]\s*[\"']" + _VER),
     "filename": _rx(r"angular(?:\.min)?[-.]" + _VER)},
    {"name": "bootstrap", "ecosystem": "npm",
     "content": _rx(r"Bootstrap v" + _VER),
     "filename": _rx(r"bootstrap[-.]" + _VER)},
    {"name": "lodash", "ecosystem": "npm",
     "content": _rx(r"lodash(?:\.js)?\s+" + _VER + r"|@license lodash " + _VER),
     "filename": _rx(r"lodash[-.]" + _VER)},
    {"name": "underscore", "ecosystem": "npm",
     "content": _rx(r"underscore.*?VERSION\s*=\s*[\"']" + _VER),
     "filename": _rx(r"underscore[-.]" + _VER)},
    {"name": "moment", "ecosystem": "npm",
     "content": _rx(r"//!\s*version\s*:\s*" + _VER),
     "filename": _rx(r"moment[-.]" + _VER)},
    {"name": "handlebars", "ecosystem": "npm",
     "content": _rx(r"Handlebars\.VERSION\s*=\s*[\"']" + _VER),
     "filename": _rx(r"handlebars[-.]" + _VER)},
    {"name": "vue", "ecosystem": "npm",
     "content": _rx(r"Vue\.version\s*=\s*[\"']" + _VER),
     "filename": _rx(r"vue[-.]" + _VER)},
    {"name": "react", "ecosystem": "npm",
     "content": _rx(r"react\.production\.min\.js.*?v" + _VER),
     "filename": _rx(r"react[-.]" + _VER)},
    {"name": "dompurify", "ecosystem": "npm",
     "content": _rx(r"DOMPurify.*?VERSION\s*=\s*[\"']" + _VER),
     "filename": _rx(r"(?:purify|dompurify)[-.]" + _VER)},
    {"name": "ckeditor", "ecosystem": "npm",
     "content": _rx(r"CKEDITOR.*?version\s*[:=]\s*[\"']" + _VER),
     "filename": _rx(r"ckeditor[-.]" + _VER)},
    {"name": "tinymce", "ecosystem": "npm",
     "content": _rx(r"tinymce.*?majorVersion\s*[:=]\s*[\"'](\d+)"),
     "filename": _rx(r"tinymce[-.]" + _VER)},
    {"name": "marked", "ecosystem": "npm",
     "filename": _rx(r"marked[-.]" + _VER)},
    {"name": "select2", "ecosystem": "npm",
     "filename": _rx(r"select2[-.]" + _VER)},
    {"name": "d3", "ecosystem": "npm",
     "filename": _rx(r"d3[-.]" + _VER)},
    {"name": "backbone", "ecosystem": "npm",
     "content": _rx(r"Backbone\.VERSION\s*=\s*[\"']" + _VER),
     "filename": _rx(r"backbone[-.]" + _VER)},
    {"name": "knockout", "ecosystem": "npm",
     "content": _rx(r"version\s*[:=]\s*[\"']" + _VER + r"[\"'].{0,40}knockout"),
     "filename": _rx(r"knockout[-.]" + _VER)},
    {"name": "axios", "ecosystem": "npm",
     "filename": _rx(r"axios[-.]" + _VER)},
    {"name": "swiper", "ecosystem": "npm",
     "filename": _rx(r"swiper[-.]" + _VER)},
]

# cdnjs / unpkg / jsdelivr path shape: .../<lib>/<version>/...
_CDN_PATH = _rx(r"/(?:ajax/libs|npm|gh)/([a-z0-9._-]+)/" + _VER + r"/")

# cdnjs uses library ids that append ".js" (lodash.js, moment.js, angular.js)
# where the npm package is the bare name; normalize so OSV lookups hit.
_CDN_NAME_FIX = {"lodash.js": "lodash", "moment.js": "moment",
                 "angular.js": "angular", "vue.js": "vue", "d3.js": "d3"}


def _normalize_cdn_name(name):
    n = (name or "").lower()
    if n in _CDN_NAME_FIX:
        return _CDN_NAME_FIX[n]
    return n[:-3] if n.endswith(".js") else n


def extract_script_srcs(html):
    """Every <script src="..."> URL in an HTML document, in order."""
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html or "", re.I)


def _match_lib_content(content):
    """Yield (name, ecosystem, version) for every library whose content
    signature matches the served JS body."""
    for sig in LIB_SIGNATURES:
        rx = sig.get("content")
        if not rx:
            continue
        m = rx.search(content)
        if m:
            yield sig["name"], sig["ecosystem"], m.group(1)


def fingerprint_js_content(content, location=""):
    """Fingerprint libraries from a served JS body. Content-banner matches are
    CONFIRMED confidence (the file itself declares the version)."""
    out = []
    seen = set()
    for name, ecosystem, version in _match_lib_content(content or ""):
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        out.append(make_component(
            name=name, version=version, ecosystem=ecosystem,
            source="js-content-banner", confidence=CONFIRMED,
            evidence=_snippet_around(content, version), location=location))
    return out


def fingerprint_url(url):
    """Fingerprint a single script URL by its filename / CDN path. A version in
    a filename or CDN path is HIGH confidence (strong, but not the file
    self-declaring it)."""
    out = []
    path = urlparse(url).path if "://" in (url or "") else (url or "")
    cdn = _CDN_PATH.search(url or "")
    if cdn:
        out.append(make_component(
            name=_normalize_cdn_name(cdn.group(1)), version=cdn.group(2), ecosystem="npm",
            source="cdn-path", confidence=HIGH, evidence=url, location=url))
        return out
    for sig in LIB_SIGNATURES:
        rx = sig.get("filename")
        if not rx:
            continue
        m = rx.search(path)
        if m:
            out.append(make_component(
                name=sig["name"], version=m.group(1), ecosystem=sig["ecosystem"],
                source="script-filename", confidence=HIGH, evidence=url, location=url))
            break
    return out


def fingerprint_html(html, base_url=""):
    """Fingerprint libraries from every <script src> in an HTML page (filename/
    CDN based). Deduped by (name, version)."""
    out, seen = [], set()
    for src in extract_script_srcs(html):
        for comp in fingerprint_url(src):
            key = (comp["name"], comp["version"])
            if key not in seen:
                seen.add(key)
                out.append(comp)
    return out


# ---------------------------------------------------------------------------
# Framework / server fingerprinting from response headers.
# ---------------------------------------------------------------------------
_HEADER_VERSION = _rx(r"([a-z0-9_-]+)/" + _VER)


def fingerprint_headers(headers):
    """Detect server/framework components from response headers (Server,
    X-Powered-By, X-AspNet-Version, X-Generator). A bare token with no version
    (e.g. 'nginx' alone) is LOW confidence and not CVE-eligible; a token WITH a
    version (e.g. 'nginx/1.18.0') is HIGH confidence."""
    out = []
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    for hk in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        val = lowered.get(hk)
        if not val:
            continue
        m = _HEADER_VERSION.search(val)
        if m:
            out.append(make_component(
                name=m.group(1).lower(), version=m.group(2), ecosystem="",
                source=f"http-header:{hk}", confidence=HIGH,
                evidence=f"{hk}: {val}", location=""))
        else:
            out.append(make_component(
                name=val.strip().split()[0].lower() if val.strip() else val,
                version="", ecosystem="", source=f"http-header:{hk}",
                confidence=LOW, evidence=f"{hk}: {val}", location=""))
    return out


# ---------------------------------------------------------------------------
# Exposed dependency manifests.
# ---------------------------------------------------------------------------
MANIFEST_PATHS = [
    "/package.json", "/package-lock.json", "/yarn.lock", "/pnpm-lock.yaml",
    "/composer.json", "/composer.lock", "/requirements.txt", "/Pipfile.lock",
    "/poetry.lock", "/Gemfile.lock", "/pom.xml", "/build.gradle", "/go.mod",
    "/go.sum", "/Cargo.lock", "/Cargo.toml",
    "/bom.json", "/sbom.json", "/cyclonedx.json", "/.spdx.json",
]

# filename -> (ecosystem, has_exact_versions). Exact-version manifests
# (lockfiles) are the ones we can safely OSV-query directly; range manifests
# (package.json, composer.json, requirements.txt without ==) are lower-signal.
_MANIFEST_META = {
    "package.json": ("npm", False),
    "package-lock.json": ("npm", True),
    "yarn.lock": ("npm", True),
    "pnpm-lock.yaml": ("npm", True),
    "composer.json": ("Packagist", False),
    "composer.lock": ("Packagist", True),
    "requirements.txt": ("PyPI", False),
    "pipfile.lock": ("PyPI", True),
    "poetry.lock": ("PyPI", True),
    "gemfile.lock": ("RubyGems", True),
    "pom.xml": ("Maven", False),
    "build.gradle": ("Maven", False),
    "go.mod": ("Go", True),
    "go.sum": ("Go", True),
    "cargo.lock": ("crates.io", True),
    "cargo.toml": ("crates.io", False),
    "bom.json": ("SBOM", True),
    "sbom.json": ("SBOM", True),
    "cyclonedx.json": ("SBOM", True),
    ".spdx.json": ("SBOM", True),
}


def classify_manifest(path):
    """Return {"ecosystem", "kind", "exact_versions"} for a manifest path/URL,
    or None if it isn't a recognized manifest."""
    name = urlparse(path).path.rsplit("/", 1)[-1].lower() if path else ""
    meta = _MANIFEST_META.get(name)
    if not meta:
        return None
    ecosystem, exact = meta
    return {"ecosystem": ecosystem, "kind": name, "exact_versions": exact}


def looks_like_manifest_body(kind, body):
    """Cheap sanity check that a 200 for a manifest path returned an ACTUAL
    manifest (not an SPA's index.html fallback). Guards against false 'exposed
    manifest' findings from catch-all routes that 200 everything."""
    b = (body or "").lstrip()
    if not b:
        return False
    if "<html" in b[:200].lower() or "<!doctype" in b[:200].lower():
        return False
    if kind.endswith(".json") or kind in ("package.json", "package-lock.json",
                                          "composer.json", "composer.lock", "bom.json"):
        return b[:1] in ("{", "[")
    return True


def parse_manifest(path, body):
    """Extract exact-pinned {name, version} entries from a manifest body, for
    OSV lookups. Only returns entries with a concrete version (ranges like
    '^1.2.3' are skipped; a range is not evidence of a specific vulnerable
    version). Best-effort and format-specific; unknown formats return []."""
    meta = classify_manifest(path)
    if not meta:
        return []
    kind = meta["kind"]
    out = []
    if kind in ("package-lock.json", "package.json", "composer.json",
                "composer.lock", "bom.json", "sbom.json", "cyclonedx.json"):
        try:
            data = json.loads(body or "")
        except Exception:
            return []
        out = _parse_json_manifest(kind, data)
    elif kind == "requirements.txt":
        for line in (body or "").splitlines():
            m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*==\s*" + _VER, line)
            if m:
                out.append({"name": m.group(1).lower(), "version": m.group(2), "exact": True})
    elif kind == "go.mod":
        for m in re.finditer(r"^\s+([\w./-]+)\s+v" + _VER, body or "", re.M):
            out.append({"name": m.group(1), "version": m.group(2), "exact": True})
    return _dedupe_components(out)


def _parse_json_manifest(kind, data):
    out = []
    if kind == "package-lock.json":
        # v2/v3 "packages" map: keys are "node_modules/<name>".
        for key, meta in (data.get("packages") or {}).items():
            if not key or not isinstance(meta, dict) or "version" not in meta:
                continue
            name = key.split("node_modules/")[-1]
            if name:
                out.append({"name": name.lower(), "version": str(meta["version"]), "exact": True})
        # v1 "dependencies" map.
        for name, meta in (data.get("dependencies") or {}).items():
            if isinstance(meta, dict) and "version" in meta:
                out.append({"name": name.lower(), "version": str(meta["version"]), "exact": True})
    elif kind == "package.json":
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                pinned = re.match(r"^" + _VER + r"$", str(ver))
                out.append({"name": name.lower(),
                            "version": pinned.group(1) if pinned else str(ver),
                            "exact": bool(pinned)})
    elif kind == "composer.lock":
        for pkg in (data.get("packages") or []):
            if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
                out.append({"name": pkg["name"].lower(),
                            "version": str(pkg["version"]).lstrip("v"), "exact": True})
    elif kind in ("bom.json", "sbom.json", "cyclonedx.json"):
        for comp in (data.get("components") or []):
            if isinstance(comp, dict) and comp.get("name") and comp.get("version"):
                out.append({"name": str(comp["name"]).lower(),
                            "version": str(comp["version"]), "exact": True})
    return out


def _dedupe_components(rows):
    seen, out = set(), []
    for r in rows:
        key = (r.get("name"), r.get("version"))
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# Source maps: sources[] -> package names (node_modules) + original source
# file paths (endpoint / internal-structure hints).
# ---------------------------------------------------------------------------
def parse_source_map(body):
    """Return {"packages": [names], "sources": [paths], "endpoints": [paths]}.
    packages come from node_modules/<pkg> entries; endpoints are original source
    paths under src/app/pages/api that hint at internal routes."""
    try:
        data = json.loads(body or "")
    except Exception:
        return {"packages": [], "sources": [], "endpoints": []}
    sources = [str(s) for s in (data.get("sources") or []) if s]
    packages, endpoints = [], []
    pseen, eseen = set(), set()
    for s in sources:
        m = re.search(r"node_modules/((?:@[\w.-]+/)?[\w.-]+)", s)
        if m:
            pkg = m.group(1).lower()
            if pkg not in pseen:
                pseen.add(pkg)
                packages.append(pkg)
            continue
        clean = re.sub(r"^webpack:/*", "", s).lstrip("./")
        if re.search(r"(^|/)(src|app|pages|api|routes|controllers|services)/", "/" + clean):
            if clean not in eseen:
                eseen.add(clean)
                endpoints.append(clean)
    return {"packages": packages, "sources": sources, "endpoints": endpoints}


# ---------------------------------------------------------------------------
# OSV (osv.dev) query build + response parse. Ecosystem strings are OSV's.
# ---------------------------------------------------------------------------
def build_osv_query(name, version, ecosystem="npm"):
    """Build the POST body for https://api.osv.dev/v1/query for one component."""
    return {"version": str(version), "package": {"name": name, "ecosystem": ecosystem}}


def parse_osv_response(data):
    """Parse an OSV /v1/query response into a normalized vuln list:
    [{"id", "aliases", "summary", "severity", "fixed_versions", "references"}].
    id prefers a CVE alias when present (that's what people track), else the OSV
    id. Empty list when the component has no known vulns."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return []
    vulns = (data or {}).get("vulns") or []
    out = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        osv_id = v.get("id", "")
        aliases = [a for a in (v.get("aliases") or []) if a]
        cve = next((a for a in aliases if a.upper().startswith("CVE-")), "")
        primary = cve or osv_id
        fixed = _osv_fixed_versions(v)
        out.append({
            "id": primary,
            "osv_id": osv_id,
            "aliases": sorted(set(aliases + ([osv_id] if osv_id else []))),
            "summary": (v.get("summary") or v.get("details") or "")[:300],
            "severity": _osv_severity(v),
            "fixed_versions": fixed,
        })
    return out


def parse_osv_scanner_output(stdout):
    """Parse `osv-scanner --format json` output into [(component, vulns), ...],
    where component is a make_component() dict (CONFIRMED; osv-scanner read an
    exact version from a lockfile) and vulns is a parse_osv_response-shaped list.
    Non-JSON / empty / vuln-free packages are skipped."""
    try:
        data = json.loads(stdout) if isinstance(stdout, str) else (stdout or {})
    except Exception:
        return []
    out = []
    for res in (data or {}).get("results", []) or []:
        source = ((res.get("source") or {}).get("path") or "")
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package") or {}
            name, version = p.get("name"), p.get("version")
            if not name or not version:
                continue
            raw_vulns = pkg.get("vulnerabilities") or []
            vulns = parse_osv_response({"vulns": raw_vulns})
            comp = make_component(
                name=str(name).lower(), version=str(version),
                ecosystem=p.get("ecosystem", "") or "", source="osv-scanner",
                confidence=CONFIRMED, evidence=f"{name}@{version} ({source})", location=source)
            out.append((comp, vulns))
    return out


def _osv_fixed_versions(v):
    fixed = []
    for aff in (v.get("affected") or []):
        for rng in (aff.get("ranges") or []):
            for ev in (rng.get("events") or []):
                if ev.get("fixed"):
                    fixed.append(str(ev["fixed"]))
    return sorted(set(fixed))


def _osv_severity(v):
    """Best-effort severity label from an OSV record. Prefers a database_specific
    severity string, then a CVSS score bucket, else 'unknown'."""
    ds = v.get("database_specific") or {}
    label = str(ds.get("severity", "")).lower()
    if label in ("critical", "high", "medium", "moderate", "low"):
        return "medium" if label == "moderate" else label
    for sev in (v.get("severity") or []):
        score = str(sev.get("score", ""))
        m = re.search(r"(\d+\.\d+)", score)
        if m:
            n = float(m.group(1))
            if n >= 9.0:
                return "critical"
            if n >= 7.0:
                return "high"
            if n >= 4.0:
                return "medium"
            return "low"
    return "unknown"


# ---------------------------------------------------------------------------
# Vulnerable-library -> follow-up probe families (feeds BROKKR's validation
# plan). These map a KNOWN-vulnerable component to the SAFE test classes worth
# running next; not to any exploit.
# ---------------------------------------------------------------------------
_PROBE_FAMILIES = {
    "jquery": ["dom_xss", "prototype_pollution"],
    "jquery-ui": ["dom_xss"],
    "jquery-migrate": ["dom_xss"],
    "angular": ["dom_xss", "csti"],
    "bootstrap": ["dom_xss"],
    "lodash": ["prototype_pollution"],
    "underscore": ["prototype_pollution"],
    "handlebars": ["ssti", "prototype_pollution"],
    "dompurify": ["dom_xss"],
    "ckeditor": ["stored_xss", "dom_xss"],
    "tinymce": ["stored_xss", "dom_xss"],
    "marked": ["stored_xss", "dom_xss"],
    "express": ["nuclei_cve_template"],
    "spring": ["nuclei_cve_template"],
    "struts": ["nuclei_cve_template"],
    "rails": ["nuclei_cve_template"],
    "django": ["nuclei_cve_template"],
    "laravel": ["nuclei_cve_template"],
    "multer": ["file_upload"],
    "formidable": ["file_upload"],
    "sharp": ["file_upload"],
    "imagemagick": ["file_upload"],
    "jsonwebtoken": ["auth_session"],
    "passport": ["auth_session"],
    "express-session": ["auth_session"],
}


def library_probe_families(name):
    """Safe follow-up test families for a known-vulnerable component (empty if
    none mapped). Never returns an exploit action; only test classes."""
    return list(_PROBE_FAMILIES.get((name or "").lower(), []))


# ---------------------------------------------------------------------------
# Finding model.
# ---------------------------------------------------------------------------
def make_component(name, version, ecosystem, source, confidence, evidence="", location=""):
    """One detected component (before vuln lookup)."""
    return {
        "name": name, "version": version or "", "ecosystem": ecosystem or "",
        "source": source, "confidence": confidence,
        "evidence": (evidence or "")[:400], "location": location or "",
    }


def cve_eligible(component):
    """True when a component's version evidence is strong enough to attach CVEs
    (the 'never infer a CVE from a guessed version' guardrail)."""
    return bool(component.get("version")) and component.get("confidence") in CVE_ELIGIBLE


def make_dependency_finding(component, vulns=None, validation=PASSIVE):
    """Build the full dependency finding model. `vulns` is a parse_osv_response
    list (only attach when cve_eligible(component)). Returns the structured dict
    the agents persist + render."""
    vulns = vulns or []
    ids = [v["id"] for v in vulns if v.get("id")]
    fixed = sorted({fv for v in vulns for fv in v.get("fixed_versions", [])})
    sev = _worst_severity([v.get("severity", "unknown") for v in vulns]) if vulns else "info"
    return {
        "component": component["name"],
        "version": component.get("version", ""),
        "ecosystem": component.get("ecosystem", ""),
        "detection_source": component.get("source", ""),
        "confidence": component.get("confidence", LOW),
        "vuln_ids": ids,
        "vulns": vulns,
        "affected_ranges": [v.get("summary", "") for v in vulns],
        "fixed_versions": fixed,
        "exploitability_notes": _exploitability_note(vulns, validation),
        "evidence": component.get("evidence", ""),
        "location": component.get("location", ""),
        "validation": validation,
        "severity": sev,
    }


_SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1, "info": 0}


def _worst_severity(sevs):
    return max(sevs, key=lambda s: _SEV_ORDER.get(s, 0)) if sevs else "info"


def _exploitability_note(vulns, validation):
    if not vulns:
        return "Component detected; no known vulns matched this version."
    if validation == MANUAL_REQUIRED:
        return ("Known-vulnerable version. Exploit validation requires explicit "
                "approval and safe (non-destructive) checks only.")
    if validation == ACTIVE_SAFE:
        return "Known-vulnerable version; a safe active check corroborated exposure."
    return ("Known-vulnerable version detected from served evidence (passive). "
            "Not yet validated as exploitable in this deployment.")


def dependency_finding_title(finding, validated=False):
    """Title semantics required by the spec: only ever say 'validated ... exploit
    path' when a safe validation actually proved impact; otherwise 'vulnerable
    component detected' / 'component detected'."""
    comp = finding["component"]
    ver = finding.get("version") or "?"
    if finding.get("vuln_ids"):
        lead = f"{comp}@{ver}"
        top = finding["vuln_ids"][0]
        extra = f", +{len(finding['vuln_ids']) - 1} more" if len(finding["vuln_ids"]) > 1 else ""
        if validated:
            return f"Validated Vulnerable Component Exploit Path: {lead} ({top}{extra})"
        return f"Vulnerable Component Detected: {lead} ({top}{extra})"
    return f"Dependency Detected: {comp}@{ver}"


def _snippet_around(text, needle, width=80):
    i = (text or "").find(needle)
    if i < 0:
        return (text or "")[:width]
    start = max(0, i - width // 2)
    return (text or "")[start:i + len(needle) + width // 2].replace("\n", " ")
