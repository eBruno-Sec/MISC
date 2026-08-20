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


def _summarize(findings: list, exposed_git: bool, scanned: int, not_maintained: dict) -> dict:
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
        # Q-083. The SAME two keys `review_source_tree` returns, carrying the same meaning, because
        # a second private name for "this is a dependency" is how the first version of this bug got
        # shipped. `not_maintained` is a COMPLETE inventory of the files this walk read, not just
        # the ones that produced a lead -- see the cost measurement at the call site.
        "not_maintained_files": not_maintained,
        "not_maintained_findings": sum(1 for f in findings if f.get("source_kind")),
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
        import browser_engine
        import httpx
    except Exception:
        return {"error": "httpx unavailable", "target": base_url}
    base = base_url.rstrip("/")
    out = {"target": base, "bundles": [], "endpoints": [], "routes": [], "sensitive_routes": [],
           "versions": [], "exposed": [], "source_review": None, "notes": []}
    try:
        c = browser_engine.rate_limited_sync_client(
            httpx, base_url=base, timeout=timeout, follow_redirects=True,
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
    # recon -> exploitation: turn the harvested routes into business-logic abuse hypotheses so the
    # intel is actionable (workflows inferred -> concrete tests to run), not just a list.
    try:
        import bizlogic
        out["logic"] = bizlogic.analyze(sorted(endpoints) + sorted(routes))
        out["counts"]["logic_tests"] = out["logic"].get("test_count", 0)
    except Exception:
        out["logic"] = None
    return out


# ── CODE-ASSISTED (SAST) LANE over a source tree ─────────────────
# `review()` below is the LEAD generator: line-oriented regex, output labelled "confirm this
# dynamically". This is the other half of the same idea and it is deliberately a different shape,
# because its findings are DEFINITIONAL rather than suggestive -- a weak cipher is weak whether or
# not a request ever reaches it, so there is nothing to hand to the dynamic scanner.
#
# Source is an EXPLICIT operator input. It is never fetched from the target and never assumed, and
# its absence is reported as "no source provided" rather than as a clean result.
_PROP_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=:]\s*(.*?)\s*$")


def load_properties(root: str, max_files: int = 200) -> dict:
    """Externalized configuration found in the tree.

    A reviewer asks what the deployed value IS, not what the in-code default claims. `getProperty
    ("hashAlg1", "SHA512")` reads reassuring while the shipped properties file says MD5; resolving
    only the default literal gets that codebase exactly backwards, and resolving only the file gets
    a codebase with no properties file wrong the other way. Both are consulted, file first.
    """
    props: dict = {}
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".properties") or seen >= max_files:
                continue
            seen += 1
            try:
                with open(os.path.join(dirpath, fn), "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        if line.lstrip().startswith(("#", "!")):
                            continue
                        m = _PROP_LINE.match(line)
                        if m and m.group(1) not in props:      # first definition wins
                            props[m.group(1)] = m.group(2)
            except Exception:
                continue
    return props


# Languages the code-assisted lane can analyse. THE GATE IS THE CAPABILITY: this walker used to
# read `if not fn.endswith(".java"): continue`, which meant the detector behind it -- measured at
# 100% TPR / 0% FPR on crypto, hash and weakrand -- contributed exactly nothing to a Python
# codebase, where the same three classes are 41.8% of the OWASP Benchmark Python suite and scored
# 0.0%. A language gate on a language-independent analysis is a capability thrown away by an
# extension check. Adding a language is a row here plus its rules in codereview.
_SOURCE_EXTS = (".java", ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


# ══════════════════════════════════════════════════════════════════════════════════════════════
# NOT-MAINTAINED SOURCE — evidence that a file is a dependency or a build artifact (Q-083)
# ══════════════════════════════════════════════════════════════════════════════════════════════
# Mission 2fb87a3a shipped a client a CONFIRMED MEDIUM against `webapp/js/jquery.min.js` at
# "line 2", because the whole bundle is line 2. Nothing about that row is known to be FALSE --
# whether that `Math.random()` feeds a security-relevant value is still unknown, and proving it
# either way means binding the value's use. The defect is narrower and certain: the lane asserted
# a confidence it had no basis for, at a location the operator cannot act on, in code they do not
# maintain.
#
# What each signal below actually EVIDENCES, which is not the same for all of them:
#
#   * `.min.js` name / minified geometry / sourceMappingURL  ->  THIS IS NOT THE MAINTAINED SOURCE.
#     Provable from the file alone. It is also precisely what makes `line 2` meaningless: the line
#     does not exist in anything anyone can edit.
#   * a preserved licence banner naming a project AND a version, or an `@license`/`@preserve`
#     pragma                                                 ->  THIRD PARTY.
#
# Everything here was calibrated against REAL files pulled from the running labs, and two of them
# exist specifically to stop a lazier rule:
#
#   * `*.min.js` IS NOT A VENDOR HEURISTIC. Juice Shop's 35 bundles are `main.js`, `polyfills.js`,
#     `chunk-<HASH>.js` -- not one ends in `.min.js`. A filename rule catches the 2015 jQuery
#     convention and misses every esbuild/webpack/Vite output.
#   * A BARE `/*!` IS NOT A LICENCE BANNER. OWASP's own first-party
#     `webapp/js/testsuiteutils.js` opens `/*! Test suite JavaScript util functions */`. Requiring
#     a version token alongside the licence claim separates it from `/*! jQuery v2.1.4 | (c) 2005,
#     2015 jQuery Foundation, Inc. | jquery.org/license */` -- measured on both files, not assumed.
#
# The consequence is a DEMOTION plus the evidence, never a deletion. A file wrongly marked here
# loses `confirmed` and keeps its row; a file wrongly excluded from the walk vanishes with no
# trace in the report. Those are not symmetric errors, and the asymmetry is why this is a marker.

#: Minifier output naming: `x.min.js`, `x-min.js`, `x_min.js` (+ .mjs/.cjs).
_MINIFIED_NAME_RX = re.compile(r"[.\-_]min\.(?:js|mjs|cjs)$", re.I)

#: Terser/uglify preserve these through minification; both are build-tool pragmas, not prose.
_LICENCE_PRAGMA_RX = re.compile(r"@(?:licen[cs]e|preserve)\b", re.I)

#: A bang-comment banner: what a minifier keeps at the top of a bundled dependency.
_BANG_BANNER_RX = re.compile(r"^\s*/\*!(.{0,400}?)\*/", re.S)

#: A released-library version token -- `v2.1.4`, `2.1.3`. Present in a dependency's banner, absent
#: from the hand-written first-party banner this rule had to be taught to leave alone.
_BANNER_VERSION_RX = re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b")
_BANNER_LICENCE_RX = re.compile(r"(?i)licen[cs]e|copyright|\(c\)\s*\d{4}|"
                                r"\b(?:MIT|Apache|BSD|GPL|LGPL|MPL|ISC)\b")

#: Generated output declares where its real source went.
_SOURCEMAP_RX = re.compile(r"^//[#@]\s*sourceMappingURL=", re.M)

#: Dependency directories. `node_modules`/`vendor`/`dist`/`build` are already pruned by
#: `_SKIP_DIRS` during the walk; they are repeated here so a tree ROOTED INSIDE one is still
#: classified. `vendors` (plural) is the one this list adds that the walk misses -- DVWA ships
#: `external/phpids/0.6/lib/IDS/vendors/htmlpurifier/`, found in a real tree, not guessed.
_VENDOR_PATH_SEG = {"node_modules", "bower_components", "jspm_packages", "webjars", "vendor",
                    "vendors", "third_party", "third-party", "thirdparty", "site-packages",
                    "dist-packages"}

#: Geometry of machine-generated code. MEASURED separation, not a round number picked by feel:
#:   first-party max observed   maxline  901 (juice-shop lib/insecurity.ts), meanline  51
#:   benchmark Java max observed maxline 163 (2763 files),                   meanline ~45
#:   minified specimens          maxline 8471..219830,                       meanline 391..121231
#: The conjunction is deliberate: ONE long line (an embedded blob, a long i18n string) does not
#: make a file generated, so the MEAN has to move too.
_MINIFIED_MAX_LINE = 2000
_MINIFIED_MEAN_LINE = 200


def not_maintained_source(rel: str, text: str) -> tuple:
    """Classify a source file as a dependency or a build artifact, ON EVIDENCE.

    Returns `(kind, evidence)` where kind is `"third-party"`, `"generated"` or `""` (no evidence).
    `evidence` quotes what was actually observed, so a reader can overrule the call -- a
    medium-reliability signal is only safe when it shows its work. Pure; no I/O.
    """
    name = (rel or "").rsplit("/", 1)[-1]
    segs = set((rel or "").split("/")[:-1])

    # ── THIRD PARTY: the file, or the directory holding it, names its origin ──
    seg = segs & _VENDOR_PATH_SEG
    if seg:
        return "third-party", "dependency directory: %s/" % sorted(seg)[0]
    banner = _BANG_BANNER_RX.match(text or "")
    if banner:
        head = banner.group(1).strip()
        if _BANNER_VERSION_RX.search(head) and _BANNER_LICENCE_RX.search(head):
            return "third-party", "preserved licence banner: /*! %s */" % head[:120]
    head4k = (text or "")[:4096]
    m = _LICENCE_PRAGMA_RX.search(head4k)
    if m:
        line = head4k[head4k.rfind("\n", 0, m.start()) + 1:head4k.find("\n", m.start())].strip()
        return "third-party", "licence pragma in file header: %s" % line[:120]

    # ── GENERATED: not the maintained source, whoever wrote the original ──
    if _MINIFIED_NAME_RX.search(name):
        return "generated", "minifier output naming convention: %s" % name
    if _SOURCEMAP_RX.search(text or ""):
        return "generated", "declares a sourceMappingURL: the maintained source is elsewhere"
    lines = (text or "").splitlines() or [""]
    maxline = max(len(ln) for ln in lines)
    meanline = len(text or "") / len(lines)
    if maxline >= _MINIFIED_MAX_LINE and meanline >= _MINIFIED_MEAN_LINE:
        return "generated", ("minified geometry: longest line %d chars, mean %d chars over %d "
                             "line(s)" % (maxline, meanline, len(lines)))
    return "", ""


def _tag_not_maintained(f: dict, kind: str, evidence: str) -> None:
    """THE MARKER: record on the row what was observed about the file it came from.

    Split out of `_mark_not_maintained` so BOTH walks in this module say the same thing the same
    way. `review_source_tree` adds a retraction on top (below); `review` uses the marker alone.
    A finding is never dropped by either, so a reader can always overrule the call.
    """
    f["source_kind"] = kind
    f["source_kind_evidence"] = evidence
    tag = "third-party" if kind == "third-party" else "generated-source"
    f["tags"] = list(dict.fromkeys((f.get("tags") or []) + [tag, "not-maintained-source"]))


def _mark_not_maintained(f: dict, kind: str, evidence: str) -> None:
    """Demote one finding that landed in a dependency or a build artifact.

    `confidence` moves to `lead`, which is `proof_schema.UNPROVEN_CONFIDENCE` -- the ONE vocabulary
    every surface that renders, counts, scores or exports a finding already consults, so the report
    stops calling it confirmed without a second private definition of the word.

    SEVERITY IS LEFT ALONE ON PURPOSE. Severity describes the class's impact if real; confidence
    describes whether this instance is proven. The ticket's complaint is the second one. Rewriting
    the first would be asserting something new about the bug rather than retracting a claim about
    the proof.
    """
    _tag_not_maintained(f, kind, evidence)
    f["confidence"] = "lead"
    f["proof_gap"] = list(dict.fromkeys((f.get("proof_gap") or []) + [
        "call site is in %s code (%s); the reported line does not identify a location in source "
        "the operator maintains" % (kind, evidence)]))


def review_source_tree(root: str, max_file_bytes: int = 2_000_000) -> dict:
    """CODE-ASSISTED (SAST) review of an operator-supplied source tree (Java and Python).

    Returns findings that are all `provenance: source-derived`. THIS IS NOT A DAST RESULT and the
    number it produces may never be folded into one or compared against a published DAST score.
    """
    import codereview as cr
    blank = {"lane": "code-assisted", "provenance": "source-derived", "root": root or "",
             "files_scanned": 0, "files": [], "properties_resolved": 0, "findings": [],
             "by_cwe": {}, "by_file": {}}
    if not root:
        return dict(blank, error="no source provided")
    if not os.path.isdir(root):
        return dict(blank, error="no source provided: not a directory: %s" % root)
    props = load_properties(root)
    findings, files = [], []
    sources = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(_SOURCE_EXTS):
                continue
            fp = os.path.join(dirpath, fn)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            try:
                if os.path.getsize(fp) > max_file_bytes:
                    continue
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            files.append(rel)
            sources.append((rel, text))
    # PASS 1 -- RETURN PROVENANCE ACROSS THE WHOLE TREE, before any file is judged.
    #
    # The dataflow rule cannot decide a trust-boundary question from one file. A request wrapper is
    # a normal thing to write, and at the call site `scr.getTheValue(name)` and
    # `scr.getTheParameter(name)` are the same three tokens on the same tainted receiver -- one
    # returns a constant, the other returns the client's data, and the difference lives in another
    # file entirely. Summarising every method's return provenance first is what makes the
    # DIFFERENCE visible; without it the analysis has to guess, and either guess is a whole class
    # of error (flag the constant helper, or miss the wrapper).
    #
    # Deliberately not cached across calls: a summary computed from a different tree is a summary
    # about different code.
    summaries = cr.merge_summaries([cr.summarize_units(text, rel) for rel, text in sources])
    # Q-083. The file is still READ and still ANALYSED -- the row survives, carrying the evidence
    # for why it is not a confirmed result. Dropping the file here instead would delete the only
    # place the operator learns the tree ships `jQuery v2.1.4`, and would do it invisibly.
    not_maintained = {}
    for rel, text in sources:
        kind, evidence = not_maintained_source(rel, text)
        if kind:
            not_maintained[rel] = {"kind": kind, "evidence": evidence}
        for f in cr.review_source(text, rel, props, summaries):
            f["file"] = rel
            if kind:
                _mark_not_maintained(f, kind, evidence)
            findings.append(f)
    by_cwe, by_file = {}, {}
    for f in findings:
        by_cwe[f["cwe"]] = by_cwe.get(f["cwe"], 0) + 1
        by_file.setdefault(f["file"], []).append(f["cwe"])
    return {"lane": "code-assisted", "provenance": "source-derived", "root": root, "error": "",
            "files_scanned": len(files), "files": files, "properties_resolved": len(props),
            "findings": findings, "by_cwe": by_cwe, "by_file": by_file,
            # The SPLIT, reported rather than implied: a consumer that wants only the code the
            # operator maintains can filter on it, and one that wants the dependency inventory has
            # it without re-deriving the classification.
            "not_maintained_files": not_maintained,
            "not_maintained_findings": sum(1 for f in findings if f.get("source_kind"))}


def review(root: str, max_hits: int = 500, max_file_bytes: int = 1_000_000) -> dict:
    """Statically review a source tree; return leads (file:line + why + dynamic-confirm hint).

    Q-083 -- THE SECOND WALK. `review_source_tree` learned to say when a row came out of code the
    operator does not maintain; this one had the same blind spot and did not. MEASURED on DVWA
    pulled from `apolaki-dvwa-1`: **14 of 57 leads (24.6%) landed in third-party code and not one
    row said so** -- 175x the 0.141% blast radius on the corpus that raised the ticket. The lead
    that made it undeniable is `vulnerabilities/javascript/source/high_unobfuscated.js`, which is
    a verbatim copy of `js-sha256` v0.9.0 sitting under a first-party-looking name in a
    first-party-looking directory. No path or filename rule could have caught it; the `@license`
    pragma in its header did.

    A LEAD IS MARKED, NEVER DEMOTED OR DROPPED HERE. Two reasons, and the second is the one that
    matters. (1) A `review()` row has no `confidence` key at all -- its contract is that EVERY hit
    is a lead -- so there is no claim to retract, and writing `confidence` onto the marked subset
    alone would make the key's ABSENCE on every other row mean something it does not. (2) DVWA's
    `vulnerabilities/javascript/source/high.js` classifies `generated` and it is *the challenge* --
    obfuscated client-side code the pentester is meant to attack. Filtering or demoting it would
    delete the target. Flagging it tells the operator the maintained source is the file next door,
    which is the useful thing to know and costs no signal.
    """
    if not os.path.isdir(root):
        return {"error": "not a directory: %s" % root, "findings": []}
    findings: list = []
    scanned = 0
    not_maintained: dict = {}
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
            # Classified EAGERLY -- every file read, not only the ones that produce a lead. The
            # lazy version was the obvious way to keep the recon path fast; it was measured instead
            # of assumed and the cost argument did not survive. Classifying everything costs 0.1%
            # of `review()` on the 5484-file benchmark tree and 1.2% on Juice Shop's bundles, while
            # classifying only lead-bearing files loses 227 of DVWA's 239 dependency files from the
            # inventory. The bytes are already in memory; the regexes are not what makes this walk
            # slow. See docs/handoff/vendor_scope.md §6.2.
            kind, evidence = not_maintained_source(rel, "".join(lines))
            if kind:
                not_maintained[rel] = {"kind": kind, "evidence": evidence}
            for i, line in enumerate(lines, 1):
                if len(line) > 600:
                    continue
                for rid, tech, sev, rx, why, conf in _RULES_C:
                    if rx.search(line):
                        f = {"rule": rid, "technique": tech, "severity": sev,
                             "file": rel, "line": i, "snippet": line.strip()[:180],
                             "why": why, "confirm": conf}
                        if kind:
                            _tag_not_maintained(f, kind, evidence)
                        findings.append(f)
                        if len(findings) >= max_hits:
                            return _summarize(findings, exposed_git, scanned, not_maintained)
    return _summarize(findings, exposed_git, scanned, not_maintained)
