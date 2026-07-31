"""
Benchmark harness -- measure the WHOLE platform against known ground truth, deterministically.

CHAD's ask: treat the intentionally-vulnerable apps as validation FIXTURES, not just CTFs. Load a
fixture's expected-vulnerability manifest, run Apolaki (AI disabled), and score what it actually found:
coverage, confirmed rate, false negatives (expected but missed), unexpected classes (possible FP or
bonus), and a failed-stage hint per miss. This is regression coverage + the honest "does the whole
orchestration actually work together" measurement, at zero tokens.

Pure evaluation (evaluate) is separated from the live driver so it is trivially testable and stable.
The manifests are vuln-CLASS level (not per-challenge) so they measure transferable capability, not a
memorized answer key -- a scan that finds "an SQLi somewhere" counts for the sqli class regardless of
which exact path, which is what real-world transferability means.
"""
from __future__ import annotations

# Expected vulnerability CLASSES per fixture -- known ground truth, curated honestly. Class-level so it
# rewards transferable discovery, not a hardcoded challenge list. (Juice Shop's full board is measured
# separately by the lab solver; this measures what the GENERAL scanner discovers + confirms.)
MANIFESTS = {
    "juiceshop": {
        "name": "OWASP Juice Shop", "url_hint": "juice-shop:3000",
        "expected": ["sqli", "xss", "access_control", "broken_auth", "sensitive_exposure",
                     "business_logic", "xxe", "misconfig", "vulnerable_component", "csrf", "crypto"],
    },
    "dvwa": {
        "name": "DVWA", "url_hint": "dvwa",
        "expected": ["sqli", "xss", "command_injection", "csrf", "path_traversal", "upload", "broken_auth"],
    },
    "ginandjuice": {
        "name": "PortSwigger Gin & Juice Shop", "url_hint": "ginandjuice.shop",
        # from PortSwigger's published vulnerability list at ginandjuice.shop/vulnerabilities
        "expected": ["sqli", "xss", "template_injection", "open_redirect", "xxe", "header_injection",
                     "vulnerable_component", "path_traversal"],
    },
    "bwapp": {
        "name": "bWAPP", "url_hint": "bwapp",
        "expected": ["sqli", "xss", "command_injection", "xxe", "ssrf", "path_traversal", "csrf",
                     "broken_auth", "sensitive_exposure", "open_redirect", "deserialization"],
    },
    "webgoat": {
        "name": "OWASP WebGoat", "url_hint": "webgoat",
        "expected": ["sqli", "xss", "access_control", "broken_auth", "xxe", "deserialization",
                     "path_traversal", "csrf", "vulnerable_component", "sensitive_exposure"],
    },
    "crapi": {
        "name": "OWASP crAPI (API Top 10)", "url_hint": "crapi",
        "expected": ["access_control", "broken_auth", "mass_assignment", "ssrf", "sensitive_exposure",
                     "business_logic"],
    },
    "mutillidae": {
        "name": "OWASP Mutillidae II", "url_hint": "mutillidae",
        "expected": ["sqli", "xss", "command_injection", "path_traversal", "csrf", "broken_auth",
                     "sensitive_exposure", "xxe", "open_redirect"],
    },
    "dvna": {
        "name": "Damn Vulnerable NodeJS Application", "url_hint": "dvna",
        "expected": ["sqli", "xss", "command_injection", "deserialization", "broken_auth",
                     "access_control", "vulnerable_component", "path_traversal"],
    },
    "gruyere": {
        "name": "Google Gruyere", "url_hint": "gruyere",
        "expected": ["xss", "sqli", "csrf", "path_traversal", "access_control", "sensitive_exposure"],
    },
    "securityshepherd": {
        "name": "OWASP Security Shepherd", "url_hint": "shepherd",
        "expected": ["sqli", "xss", "csrf", "broken_auth", "access_control", "sensitive_exposure",
                     "crypto", "command_injection"],
    },
}

# Map the many tool-emitted finding families onto the benchmark's canonical classes.
_CLASS_MAP = {
    "sqli": "sqli", "nosqli": "sqli", "sql_injection": "sqli",
    "xss": "xss", "stored_xss": "xss", "dom_xss": "xss", "reflected_xss": "xss", "csti": "template_injection",
    "ssti": "template_injection", "template_injection": "template_injection",
    "idor": "access_control", "bola": "access_control", "bfla": "access_control",
    "access_control": "access_control", "mass_assignment": "access_control",
    "cmdi": "command_injection", "command_injection": "command_injection",
    "ssrf": "ssrf", "xxe": "xxe", "csrf": "csrf",
    "crlf": "header_injection", "host_header": "header_injection", "response_header_injection": "header_injection",
    "git_exposure": "sensitive_exposure", "backup_exposure": "sensitive_exposure", "exposure": "sensitive_exposure",
    "info_disclosure": "sensitive_exposure", "credential_exposure": "sensitive_exposure",
    "config_exposure": "sensitive_exposure", "sensitive_exposure": "sensitive_exposure",
    "jsonp_info_leak": "sensitive_exposure",
    "vulnerable_component": "vulnerable_component", "prototype_pollution": "vulnerable_component",
    "business_logic": "business_logic", "race": "business_logic",
    "jwt": "broken_auth", "oauth": "broken_auth", "weak_password_reset": "broken_auth", "broken_auth": "broken_auth",
    "deserialization": "deserialization", "crypto": "crypto", "weak_crypto": "crypto",
    "crypto_authz": "crypto", "open_redirect": "open_redirect",
    "misconfig": "misconfig", "security_misconfig": "misconfig", "cors": "misconfig",
    "path_traversal": "path_traversal", "lfi": "path_traversal", "upload": "upload",
}

# CWE fallback so a finding tagged only by CWE still classifies.
_CWE_CLASS = {
    "cwe-89": "sqli", "cwe-79": "xss", "cwe-78": "command_injection", "cwe-22": "path_traversal",
    "cwe-352": "csrf", "cwe-611": "xxe", "cwe-918": "ssrf", "cwe-601": "open_redirect",
    "cwe-502": "deserialization", "cwe-1321": "vulnerable_component", "cwe-434": "upload",
    "cwe-639": "access_control", "cwe-285": "access_control", "cwe-287": "broken_auth", "cwe-347": "broken_auth",
}


def _canon_class(finding):
    fam = str(finding.get("family") or finding.get("vuln_class") or "").strip().lower()
    if fam in _CLASS_MAP:
        return _CLASS_MAP[fam]
    cwe = str(finding.get("cwe") or "").strip().lower()
    return _CWE_CLASS.get(cwe)


def _is_confirmed(f):
    return bool(f.get("confirmed")) or str(f.get("confidence", "")).lower() in ("confirmed", "high")


def evaluate(fixture, findings, leads=None):
    """Pure. Score `findings` (a scan's confirmed findings) + optional `leads` against the fixture
    manifest. Returns coverage / confirmed / false-negatives / unexpected / per-class / metrics."""
    man = MANIFESTS.get(fixture)
    if not man:
        return {"error": "unknown fixture %r" % fixture, "fixtures": sorted(MANIFESTS)}
    expected = list(man["expected"])
    found_cls, confirmed_cls, count = {}, set(), {}
    for f in (findings or []):
        c = _canon_class(f)
        if not c:
            continue
        count[c] = count.get(c, 0) + 1
        found_cls.setdefault(c, True)
        if _is_confirmed(f):
            confirmed_cls.add(c)
    # leads count toward DISCOVERY (a class was surfaced) but never toward CONFIRMED
    lead_cls = set()
    for l in (leads or []):
        c = _canon_class(l)
        if c:
            lead_cls.add(c)
    discovered = set(found_cls) | lead_cls
    exp = set(expected)
    fn = sorted(exp - discovered)                 # expected but never surfaced
    unexpected = sorted(discovered - exp)          # found outside the manifest (bonus or FP to review)
    per_class = []
    for c in expected:
        per_class.append({"class": c, "discovered": c in discovered, "confirmed": c in confirmed_cls,
                          "findings": count.get(c, 0), "as_lead_only": c in lead_cls and c not in found_cls})
    cov = len(exp & discovered)
    conf = len(exp & confirmed_cls)
    metrics = {
        "class_coverage_pct": round(100 * cov / len(exp), 1) if exp else 0.0,
        "confirmed_coverage_pct": round(100 * conf / len(exp), 1) if exp else 0.0,
        "expected_classes": len(exp), "discovered_classes": cov, "confirmed_classes": conf,
        "false_negatives": len(fn), "unexpected_classes": len(unexpected),
        "findings_total": len(findings or []), "leads_total": len(leads or []),
    }
    return {
        "fixture": fixture, "name": man["name"], "expected": expected,
        "discovered": sorted(discovered), "confirmed": sorted(exp & confirmed_cls),
        "false_negatives": fn, "unexpected": unexpected, "per_class": per_class, "metrics": metrics,
        # honest per-miss hint: which stage most likely dropped it
        "failed_stage": [{"class": c, "hint": _stage_hint(c)} for c in fn],
    }


def _stage_hint(cls):
    """Best-effort, honest hint about which stage likely missed an expected class."""
    if cls in ("access_control", "broken_auth", "business_logic"):
        return "needs authenticated + stateful testing (creds/roles) or the differential authz/bizlogic engine; a passive general scan can't reach it."
    if cls in ("xxe", "ssrf", "deserialization", "template_injection"):
        return "blind/second-order class: needs an OOB collaborator or the intrusive (Full-mode) probes, plus technique-matching on the right input."
    if cls in ("vulnerable_component",):
        return "needs dependency/version intel (SCA) on served JS + KEV cross-reference."
    return "expected class not discovered -- check recon coverage (was the input surfaced?) then technique matching for this class."


def list_fixtures():
    return {"fixtures": [{"id": k, "name": v["name"], "expected_classes": len(v["expected"]),
                          "url_hint": v["url_hint"]} for k, v in MANIFESTS.items()]}
