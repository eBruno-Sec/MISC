"""
Code Intelligence — pattern-based static review for pentest-relevant sinks.

Reviews a source tree for the high-signal patterns a pentester greps for. The tree can arrive
two ways, same engine either way:
  - WHITE-BOX  : the operator points it at a repo/folder.
  - BLACK-BOX  : recon reconstructs source the target leaked (source maps via run_sourcemap,
                 an exposed .git, backups, GitHub) and feeds that folder in.

Each hit is a LEAD, not a confirmed vuln: a file:line + why + a suggested DYNAMIC confirmation
the live scanner can fire. Source finds the candidate; a request proves it. That white-box ->
dynamic loop is the whole point — most tools can't close it.

This is deliberately the 20% of pattern-matching that catches 80% of the bugs (not a dataflow
SAST engine). Pure/regex, no external deps. Every rule maps to a technique in the registry, so
a code finding links straight into the Taxonomy.
"""
from __future__ import annotations

import os
import re

# rule: (id, technique_id, severity, regex, why, dynamic-confirmation hint)
_RULES = [
    ("commented_auth", "bfla_privileged_action", "high",
     r"(?i)^\s*(//|#)\s*.*\.(get|post|put|delete|patch)\s*\(.*(isauthorized|requireauth|authenticate|ensureloggedin|\bauth\b)",
     "A route's auth guard is COMMENTED OUT — the endpoint may be reachable with no/low privilege.",
     "Call the endpoint directly from a no-auth or low-priv session; check for a privileged effect."),
    ("code_exec_sink", "command_injection", "critical",
     r"(\beval\s*\(|new\s+Function\s*\(|\bchild_process\b|\b(execSync|execFileSync|spawnSync|execFile)\s*\(|subprocess\.(call|run|Popen)|\bos\.system\s*\(|pty\.spawn)",
     "Dynamic code / OS-command execution sink.",
     "Trace whether user input reaches this call; inject a shell metacharacter (; | `) and look for command output."),
    ("sql_string_build", "sqli_union_extract", "high",
     r"(?i)(select|insert into|update |delete from)\b.{0,90}?(\+|\$\{|%s\b|%\(|\.format\(|`[^`]*\$\{|\|\|)",
     "SQL statement appears to be assembled by string concatenation / interpolation.",
     "Inject a single quote into the parameter feeding this query and watch for an error or boolean change."),
    ("unsafe_deser", "insecure_deser", "high",
     r"(?i)(pickle\.loads|yaml\.load\s*\((?![^)]*Loader)|cPickle|unserialize\s*\(|marshal\.loads|readObject\s*\(|node-serialize|__reduce__)",
     "Unsafe deserialization of untrusted data.",
     "Supply a crafted serialized payload to the input that reaches this sink."),
    ("template_injection", "ssti", "high",
     r"(?i)(render_template_string|new Template|Template\(|\.compile\()\s*[^)]*(\+|\$\{|%s|req\.|request\.|params|input)",
     "Template rendered with concatenated / user-controlled input (possible SSTI).",
     "Inject a template expression ({{7*7}} / ${7*7}) and check the response for evaluated output (49)."),
    ("ssrf_sink", "ssrf", "high",
     r"(?i)\b(requests\.(get|post|put)|axios|fetch|http\.get|https\.get|urllib\.request\.urlopen|got\(|node-fetch|curl_exec)\s*\([^)]{0,80}(req\.|request\.|\.query\b|\.body\b|userurl)",
     "Server-side HTTP request whose destination comes from user input (possible SSRF).",
     "Point the URL parameter at an OOB collaborator / internal address and watch for the callback."),
    ("path_from_input", "exposed_files_harvest", "high",
     r"(?i)\b(readFile(Sync)?|createReadStream|sendFile|res\.download|fs\.open|include|require|file_get_contents)\s*\([^)]{0,80}(req\.|request\.|params|\binput\b)",
     "File path built from user input (possible path traversal / LFI).",
     "Send ../ sequences (and a %2500 null byte) in the parameter to reach files outside the intended directory."),
    ("hardcoded_secret", "target_intel_harvest", "high",
     r"""(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*["'][^"'\s${}]{6,}["']""",
     "Possible hardcoded credential / secret in source.",
     "Extract the value; try it as a credential or API key against the live app."),
    ("weak_crypto", "weak_secret_forgery", "medium",
     r"(?i)(createHash\s*\(\s*['\"](md5|sha1)['\"]|\b(md5|sha1)\s*\(|\bECB\b|Math\.random\(\)[^;\n]{0,50}\b(token|secret|session|password|nonce|otp|coupon)\b)",
     "Weak / predictable cryptography or randomness used for a security value.",
     "If it signs a token/coupon/id, try to reproduce the value offline and forge one."),
    ("cors_wildcard", "security_misconfig_errors", "medium",
     r"(?i)(access-control-allow-origin['\"\s:]+\*|origin\s*:\s*true|cors\(\s*\)|allow-origin.{0,10}\*)",
     "Permissive CORS (wildcard or reflect-any-origin).",
     "Check whether a credentialed cross-origin read is allowed from an attacker origin."),
    ("debug_enabled", "security_misconfig_errors", "medium",
     r"(?i)(debug\s*[:=]\s*(true|1)\b|NODE_ENV.{0,6}develop|app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)",
     "Debug mode / verbose errors may be enabled.",
     "Trigger an error and check the response for stack traces / internal paths."),
]
_RULES_C = [(rid, tech, sev, re.compile(rx), why, conf) for rid, tech, sev, rx, why, conf in _RULES]

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "vendor", "__pycache__",
              ".next", "out", "target", ".venv", "venv", "bower_components", ".cache", "tmp",
              # non-runtime / not attack surface — cut review noise
              "test", "tests", "__tests__", "e2e", "cypress", "spec", "specs", "mock", "mocks",
              "fixtures", "codefixes", "i18n", "locales", "examples", "docs", ".github"}
_EXTS = {".ts", ".js", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".php", ".java", ".go",
         ".cs", ".yml", ".yaml", ".json", ".env", ".config", ".conf", ".xml", ".sql"}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _summarize(findings: list, exposed_git: bool, scanned: int) -> dict:
    findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 9), f["file"], f["line"]))
    by_sev, by_rule, by_tech = {}, {}, {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        by_tech[f["technique"]] = by_tech.get(f["technique"], 0) + 1
    return {
        "files_scanned": scanned,
        "exposed_dot_git": exposed_git,
        "total": len(findings),
        "by_severity": by_sev,
        "by_rule": by_rule,
        "by_technique": by_tech,
        "findings": findings,
    }


_SENSITIVE_ROUTE = re.compile(r"(admin|account|manage|internal|debug|config|token|secret|"
                              r"privacy|order|wallet|dashboard|report|api-?key|backup)", re.I)

# Cloud-resource markers mined from client code — hardcoded bucket names / tenants that a
# black-box tester can then check for public access. (DNS-CNAME cloud detection is separate.)
_CLOUD_RX = [
    ("AWS S3", re.compile(r"([a-z0-9.-]{3,63})\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com", re.I)),
    ("AWS S3", re.compile(r"s3://([a-z0-9][a-z0-9.-]{2,62})", re.I)),
    ("AWS key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Firebase", re.compile(r"([a-z0-9-]+)\.firebase(?:io|app)\.com", re.I)),
    ("Firebase", re.compile(r"([a-z0-9-]+)\.firebasestorage\.(?:app|googleapis\.com)", re.I)),
    ("GCP storage", re.compile(r"storage\.googleapis\.com/([a-z0-9._-]+)", re.I)),
    ("GCP appspot", re.compile(r"([a-z0-9-]+)\.appspot\.com", re.I)),
    ("Azure blob", re.compile(r"([a-z0-9]{3,24})\.blob\.core\.windows\.net", re.I)),
    ("Auth0", re.compile(r"([a-z0-9-]+)\.auth0\.com", re.I)),
    ("Okta", re.compile(r"([a-z0-9-]+)\.okta(?:preview)?\.com", re.I)),
    ("Supabase", re.compile(r"([a-z0-9-]+)\.supabase\.co", re.I)),
    ("Cloudfront", re.compile(r"([a-z0-9]+)\.cloudfront\.net", re.I)),
]


def _cloud_markers(text: str) -> dict:
    """Cloud resources referenced in code — {(provider,value): {...}} for dedup."""
    out = {}
    for provider, rx in _CLOUD_RX:
        for m in rx.finditer(text or ""):
            out[(provider, m.group(0))] = {"provider": provider, "value": m.group(0)[:120]}
    return out


def harvest(base_url: str, timeout: int = 15) -> dict:
    """BLACK-BOX code intelligence: curl the target, mine the served JS bundles + exposed vectors
    into ACTIONABLE intel — API endpoints, client routes (including unlinked/sensitive ones),
    leaked versions, and any source the target leaks (source maps -> reconstructed source, which
    then gets the static sink review). No source folder, nothing handed over: recon-phase pure
    automation that feeds PoC / deeper testing / exploitation."""
    try:
        import httpx
    except Exception:
        return {"error": "httpx unavailable", "target": base_url}
    base = base_url.rstrip("/")
    out = {"target": base, "bundles": [], "endpoints": [], "routes": [], "sensitive_routes": [],
           "versions": [], "exposed": [], "source_review": None, "notes": []}
    try:
        c = httpx.Client(base_url=base, timeout=timeout, follow_redirects=True,
                         headers={"User-Agent": "apolaki-codeintel"})
    except Exception as e:
        return {"error": str(e), "target": base}
    try:
        html = c.get("/").text
    except Exception as e:
        c.close()
        return {"error": str(e), "target": base}
    scripts = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
    endpoints, routes, versions, reconstructed = set(), set(), set(), []
    cloud = _cloud_markers(html)
    wasm_refs = set(re.findall(r'["\']([^"\']+\.wasm)["\']', html))
    for s in scripts:
        p = s if s.startswith("/") else "/" + s
        try:
            js = c.get(p).text
        except Exception:
            continue
        out["bundles"].append(p)
        endpoints |= set(re.findall(r'["\'](/(?:rest|api)/[A-Za-z0-9/_-]+)', js))
        routes |= set(re.findall(r'path:\s*["\']([A-Za-z0-9/_:-]+)["\']', js))
        versions |= set(re.findall(r'["\']([a-z0-9][a-z0-9.-]*@\d+\.\d+\.\d+)["\']', js))
        cloud.update(_cloud_markers(js))
        wasm_refs |= set(re.findall(r'["\']([^"\']+\.wasm)["\']', js))
        mm = re.search(r'sourceMappingURL=(\S+\.map)', js)
        if mm:
            try:
                import json as _json
                url = mm.group(1)
                mp = c.get(url if url.startswith("http") else "/" + url.lstrip("/"))
                if mp.status_code == 200:
                    smap = _json.loads(mp.text)
                    for path, content in zip(smap.get("sources", []) or [],
                                             smap.get("sourcesContent", []) or []):
                        if content:
                            reconstructed.append((path, content))
                    out["notes"].append("source map on %s -> %d original sources reconstructed" % (p, len(reconstructed)))
            except Exception:
                pass
    # exposed-source / sensitive-file vectors (validate, don't trust a bare 200 = SPA fallback)
    for probe, label, ok in [("/.git/HEAD", "exposed .git repo", lambda t: t.startswith("ref:")),
                             ("/.env", "exposed .env", lambda t: "=" in t and "<" not in t[:5]),
                             ("/ftp", "browsable /ftp", lambda t: ("package" in t.lower() or "coupon" in t.lower())),
                             ("/.svn/entries", "exposed .svn", lambda t: t[:2].isdigit())]:
        try:
            r = c.get(probe)
            if r.status_code == 200 and ok(r.text):
                out["exposed"].append({"path": probe, "label": label})
        except Exception:
            pass
    # if the target leaked real source (via maps), run the static sink review on it
    if reconstructed:
        import tempfile
        d = tempfile.mkdtemp()
        for path, content in reconstructed[:3000]:
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", (path or "src").replace("/", "__"))[:120]
            try:
                with open(os.path.join(d, safe or "src.js"), "w", encoding="utf-8", errors="ignore") as f:
                    f.write(content)
            except Exception:
                pass
        out["source_review"] = review(d)
    # WebAssembly: pull referenced .wasm modules, lift printable strings (fn/import names, URLs)
    wasm_out = []
    for w in list(wasm_refs)[:5]:
        try:
            r = c.get(w if w.startswith("http") else "/" + w.lstrip("/"))
            if r.status_code == 200 and r.content[:4] == b"\x00asm":
                strs = re.findall(rb"[\x20-\x7e]{5,}", r.content)
                wasm_out.append({"module": w, "bytes": len(r.content),
                                 "strings": [s.decode("ascii", "ignore") for s in strs[:40]]})
        except Exception:
            pass
    # GraphQL: probe common endpoints + introspect (reuse graphql_tool)
    graphql = None
    try:
        import graphql_tool
        for cand in graphql_tool.endpoint_candidates(base + "/graphql")[:6]:
            try:
                j = c.post(cand, json={"query": graphql_tool.INTROSPECTION_QUERY}).json()
            except Exception:
                continue
            if graphql_tool.looks_like_graphql(j):
                graphql = {"endpoint": cand, **graphql_tool.parse_schema(j)}
                break
    except Exception:
        pass
    c.close()
    out["endpoints"] = sorted(endpoints)
    out["routes"] = sorted(routes)
    out["sensitive_routes"] = sorted(r for r in routes if _SENSITIVE_ROUTE.search(r))
    out["versions"] = sorted(versions)[:50]
    out["cloud"] = list(cloud.values())
    out["wasm"] = wasm_out
    out["graphql"] = graphql
    out["counts"] = {"endpoints": len(endpoints), "routes": len(routes),
                     "sensitive_routes": len(out["sensitive_routes"]), "exposed": len(out["exposed"]),
                     "cloud": len(cloud), "wasm": len(wasm_out),
                     "graphql": bool(graphql and graphql.get("introspection"))}
    return out


def review(root: str, max_hits: int = 500, max_file_bytes: int = 1_000_000) -> dict:
    """Statically review a source tree; return leads (file:line + why + dynamic-confirm hint)."""
    if not os.path.isdir(root):
        return {"error": "not a directory: %s" % root, "findings": []}
    findings: list = []
    scanned = 0
    exposed_git = os.path.isdir(os.path.join(root, ".git"))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in _EXTS:
                continue
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > max_file_bytes:
                    continue
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    lines = fh.readlines()
            except Exception:
                continue
            scanned += 1
            rel = os.path.relpath(fp, root).replace("\\", "/")
            for i, line in enumerate(lines, 1):
                if len(line) > 600:
                    continue
                for rid, tech, sev, rx, why, conf in _RULES_C:
                    if rx.search(line):
                        findings.append({"rule": rid, "technique": tech, "severity": sev,
                                         "file": rel, "line": i, "snippet": line.strip()[:180],
                                         "why": why, "confirm": conf})
                        if len(findings) >= max_hits:
                            return _summarize(findings, exposed_git, scanned)
    return _summarize(findings, exposed_git, scanned)
