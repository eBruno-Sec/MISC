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
