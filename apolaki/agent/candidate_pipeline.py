"""General candidate-validation pipeline (target-agnostic).

Every testable lead is NORMALIZED to a common shape, its family is derived from the raw
signals, and it is ROUTED to a concrete validator + the real targets to run it against.
The cardinal rule (never hardcode a single lab): a STATIC hit inside a library file is not
an application vulnerability. A JS-file sink lead is retargeted at the APPLICATION PAGES that
use the library, and the runtime oracle (a canary that must actually fire in a real browser)
is what decides confirmed vs dismissed — so vendor-only matches self-dismiss.

Pure functions only (no I/O) so the routing is unit-testable; the agent executes the plan.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

# ── terminal states: every candidate must end in exactly one ──────────────────
CONFIRMED = "confirmed"          # runtime oracle fired -> a finding
DISMISSED = "dismissed"          # validator ran, no impact (e.g. vendor-only, canary never fired)
BLOCKED = "blocked"              # a named external prerequisite is missing (browser, low-priv session)
SCHEDULED = "scheduled"          # a validator is assigned + will run this cycle
UNSUPPORTED = "unsupported"      # no validator exists yet for this family (explicit debt, never silent)

# ── canonical families derived from noisy raw signals ─────────────────────────
def canonical_family(lead: dict) -> str:
    t = (str(lead.get("title") or "") + " " + " ".join(str(x) for x in (lead.get("tags") or []))).lower()
    fam = str(lead.get("family") or "").lower()
    cwe = str(lead.get("cwe") or "").upper()
    if "prototype pollution" in t or "__proto__" in t or "deparam" in t or "CWE-1321" in cwe or fam == "prototype_pollution":
        return "prototype_pollution"
    if "ng-app" in t or "angular" in t and "template" in t or "csti" in t or (cwe == "CWE-94" and "template" in t):
        return "csti"
    if "jsonp" in t:
        return "jsonp"
    if "exposed cred" in t or "credential" in t or cwe == "CWE-522" or fam == "exposed_credentials":
        return "exposed_credentials"
    if "exposed file" in t or "harvest" in t and "file" in t or cwe in ("CWE-527", "CWE-538", "CWE-540") or ".git" in t or ".env" in t:
        return "exposed_files"
    if "bfla" in t or "function-level" in t or "privileged action" in t or cwe == "CWE-285":
        return "bfla"
    if "math.random" in t or "weak random" in t or "insecure random" in t or cwe in ("CWE-330", "CWE-338"):
        return "weak_random"
    if "developer comment" in t or "revealing comment" in t or cwe == "CWE-615":
        return "dev_comments"
    if "stored xss" in t or "stored cross-site" in t:
        return "stored_xss"
    if "eval" in t and "sink" in t:
        return "eval_sink"
    if "innerhtml" in t or ("dom" in t and "xss" in t) or "dom-xss" in t:
        return "dom_xss"
    if "79" in cwe or "xss" in t or fam == "xss":
        return "reflected_xss"
    return fam or "unknown"


# family -> (validator name, oracle description, external prerequisite or None). A DOM-class
# family runs its runtime browser oracle against application pages; a JS-file target is never
# tested as itself.
_ROUTES = {
    "prototype_pollution": ("run_dom_audit", "browser prototype-pollution canary (__proto__ write observed at runtime)", "browser"),
    "csti":                ("run_dom_audit", "AngularJS expression arithmetic proof in a real DOM", "browser"),
    "dom_xss":             ("run_dom_audit", "source-to-sink DOM canary executes in the browser", "browser"),
    "eval_sink":           ("run_dom_audit", "source-to-sink execution canary in the browser", "browser"),
    "reflected_xss":       ("run_xss", "context-aware payload executes (browser-confirmed alert)", "browser"),
    "stored_xss":          ("run_stored_xss", "unique canary submitted, re-read on a display surface, executes", "browser"),
    "exposed_credentials": ("exposed_credentials_oracle", "harvested credential yields a valid authenticated session", None),
    "exposed_files":       ("run_exposure", "path returns a content/type signature match (not a soft 200/404 page)", None),
    "bfla":                ("run_bfla", "low-privilege session performs a prohibited privileged action/data read", "low_priv_session"),
    "jsonp":               ("run_jsonp", "callback param returns an executable JS wrapper carrying sensitive data, usable cross-origin", None),
    "weak_random":         ("weak_random_trace", "output controls a token/secret/reset/session/security decision", None),
    "dev_comments":        ("comment_fact_extract", "a route/credential/filename derived from the comment validates", None),
}


# families whose CONFIRMATION is owned by a dedicated PRIMARY-scan probe (not this pipeline). A lead
# of these is not "unsupported" — it is deferred to that probe, which runs in the same engagement.
PRIMARY_HANDLED = {
    "sql_injection": "the SQLi oracle (run_sqli / run_auth_sqli)",
    "sqli": "the SQLi oracle (run_sqli / run_auth_sqli)",
    "access_control": "the two-user authorization matrix",
    "idor": "the two-user authorization matrix (confirm_idor)",
    "broken_auth": "the authentication artery + SQLi auth-bypass oracle",
    "anomaly": "run_anomaly_scan",
    "ssrf": "run_ssrf", "xxe": "run_xxe", "command_injection": "run_cmdi",
    "nosql_injection": "run_nosqli", "open_redirect": "the injection probes",
}


def _is_js_file(url: str) -> bool:
    p = urlparse(url).path.lower()
    return p.endswith(".js") or p.endswith(".mjs") or "/js/" in p or "/vendor/" in p


def normalize(lead: dict) -> dict:
    """One common shape: family, source_file, consuming page, route, param/source, suspected
    sink, prerequisite, validator, and the runtime oracle that must fire to confirm."""
    fam = canonical_family(lead)
    target = str(lead.get("target") or "")
    params = list(parse_qs(urlparse(target).query).keys())
    validator, oracle, prereq = _ROUTES.get(fam, (None, "no validator implemented yet", None))
    src_is_js = _is_js_file(target)
    tags = " ".join(str(x) for x in (lead.get("tags") or [])).lower()
    sink = None
    for s in ("innerhtml", "eval", "__proto__", "deparam", "ng-app", "document.write", "settimeout"):
        if s in (str(lead.get("title") or "").lower() + " " + tags):
            sink = s
            break
    return {
        "family": fam,
        "source_file": target if src_is_js else (lead.get("source_file") or None),
        "consuming_page": None if src_is_js else (target or None),  # resolved later for JS-file leads
        "route": urlparse(target).path or "/",
        "param": params[0] if params else (lead.get("param") or None),
        "sink": sink,
        "static_js_hit": src_is_js,      # true => retarget at application pages, not this URL
        "validator": validator,
        "oracle": oracle,
        "prerequisite": prereq,
        "raw_target": target,
        "title": lead.get("title"),
        "cwe": lead.get("cwe"),
    }


def application_pages(urls: list) -> list:
    """In-scope APPLICATION pages (HTML routes) a library-file lead should actually be tested
    against — never the .js/.css/asset URLs. Deduped by path, bounded by the caller."""
    seen, out = set(), []
    for u in urls or []:
        u = str(u)
        p = urlparse(u)
        path = p.path or "/"
        if _is_js_file(u):
            continue
        if re.search(r"\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|json|xml|pdf|zip)$", path, re.I):
            continue
        key = (p.netloc, path)
        if key in seen:
            continue
        seen.add(key)
        out.append(u.split("#")[0])
    return out


def plan_targets(norm: dict, app_pages: list, param_targets: list = None) -> list:
    """Concrete URLs to run the validator against. A static-JS DOM lead is retargeted at the
    application pages (runtime reachability decides truth); a parameterized lead keeps its URL."""
    fam = norm["family"]
    if fam in ("prototype_pollution", "csti", "dom_xss", "eval_sink"):
        if norm["static_js_hit"] or not norm["raw_target"]:
            return list(app_pages)          # test the pages that USE the lib, not the .js file
        return [norm["raw_target"]]
    if fam in ("reflected_xss",):
        return [norm["raw_target"]] if "?" in norm["raw_target"] else list(param_targets or [])
    if fam in ("exposed_credentials", "exposed_files", "bfla", "jsonp", "weak_random", "dev_comments"):
        return [norm["raw_target"]] if norm["raw_target"] else list(app_pages[:1])
    return []
