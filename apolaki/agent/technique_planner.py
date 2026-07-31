"""
Deterministic technique planner -- CHAD's evidence-driven core, zero LLM tokens.

    observed evidence -> technique matching -> PRECONDITION EVALUATION -> ordered plan of next actions

The planner selects techniques whose PRECONDITIONS are satisfied by what recon/harvest actually
observed, gates out the rest, ranks the survivors (confidence x real-world weight), and emits an
ordered plan. This is how the platform decides what to try next WITHOUT asking an LLM to invent a step:
if the evidence says there's a login form, the login-SQLi technique becomes applicable; if there's no
XML input, XXE never even enters the plan.

Observations are a small deterministic vocabulary derived from gathered info (surface + harvest + code
intel + findings/leads). Each planner technique declares the observations it REQUIRES; it is applicable
only when every one is present -- a gate, not a guess. Confidence + CISA-KEV weight order the plan.
"""
from __future__ import annotations

# The deterministic observation vocabulary -- what recon/harvest can establish about a target.
OBSERVATIONS = (
    "serves_js", "has_api", "has_search_param", "has_login", "has_object_id", "has_file_upload",
    "has_xml_input", "has_redirect_param", "has_versions", "has_coupon", "reflects_input",
    "sql_error_seen", "authenticated", "has_sensitive_route", "has_workflow",
)

# technique_id -> observations that must ALL hold for the technique to be applicable (the precondition gate).
_PRECONDITIONS = {
    "sqli_auth_bypass":        ["has_login"],
    "sqli_union_extract":      ["has_search_param"],
    "nosql_injection":         ["has_api"],
    "reflected_xss":           ["reflects_input"],
    "stored_xss":              ["has_api"],
    "idor_bola_read":          ["has_object_id"],
    "bfla_privileged_action":  ["has_sensitive_route"],
    "mass_assignment":         ["has_api"],
    "excessive_data_exposure": ["has_api"],
    "xxe_file_ssrf":           ["has_xml_input"],
    "ssrf":                    ["has_api"],
    "open_redirect":           ["has_redirect_param"],
    "business_logic_abuse":    ["has_workflow"],
    "weak_secret_forgery":     ["has_coupon"],
    "exposed_files_harvest":   ["serves_js"],
    "target_intel_harvest":    ["serves_js"],
    "path_traversal":          ["has_api"],
    "command_injection":       ["has_api"],
    "csrf":                    ["has_login"],
    "jwt_forge":               ["authenticated"],
    "weak_2fa_bypass":         ["authenticated"],
    "weak_password_reset":     ["has_login"],
}


def derive_observations(surface=None, harvest=None, findings=None, leads=None, code_intel=None,
                        authenticated=False):
    """Deterministically compute the observation set from everything recon gathered. Pure, no LLM."""
    obs = set()
    urls = [str(u).lower() for u in (surface or [])]
    ci = code_intel or {}
    ci_eps = [str(x).lower() for x in (ci.get("endpoints") or [])]
    ci_routes = [str(x).lower() for x in (ci.get("sensitive_routes") or [])]
    allpaths = " ".join(urls + ci_eps + ci_routes)

    if ci.get("bundles") or (ci.get("counts") or {}).get("js_bundles"):
        obs.add("serves_js")
    if "/api" in allpaths or "/rest" in allpaths:
        obs.add("has_api")
    if "search" in allpaths or "q=" in allpaths or "?q" in allpaths:
        obs.add("has_search_param")
    if "login" in allpaths or "signin" in allpaths or "authenticate" in allpaths:
        obs.add("has_login")
    if "upload" in allpaths or "/file" in allpaths:
        obs.add("has_file_upload")
    if any(w in allpaths for w in ("xml", "soap", "xxe")):
        obs.add("has_xml_input")
    if any(w in allpaths for w in ("redirect", "url=", "return=", "next=", "returnto")):
        obs.add("has_redirect_param")
    if ci_routes:
        obs.add("has_sensitive_route")
    if ((ci.get("logic") or {}).get("detail")):
        obs.add("has_workflow")

    by_kind = ((harvest or {}).get("by_kind")) or {}
    if by_kind.get("object_id"):
        obs.add("has_object_id")
    if by_kind.get("version"):
        obs.add("has_versions")
    if by_kind.get("coupon"):
        obs.add("has_coupon")

    fams = {str(x.get("family", "")).lower() for x in ((findings or []) + (leads or []))}
    if fams & {"xss", "reflected_xss", "stored_xss", "dom_xss"}:
        obs.add("reflects_input")
    if fams & {"sqli", "nosqli"}:
        obs.add("sql_error_seen")
    if any(str(x.get("family", "")).lower() == "attack_surface" for x in (leads or [])):
        obs.add("has_sensitive_route")
    if authenticated:
        obs.add("authenticated")
    return obs


def plan(observations, techniques, kev_cwes=None):
    """Ordered plan: only techniques whose preconditions ALL hold, ranked by confidence x KEV x proven.
    Deterministic and explainable -- each entry says which preconditions matched. Returns [] if the
    evidence supports nothing (an honest 'exhausted path', not an invented action)."""
    obs = set(observations or [])
    kev_cwes = {str(c).upper() for c in (kev_cwes or [])}
    out = []
    for t in techniques:
        pre = _PRECONDITIONS.get(t.get("id"))
        if pre is None:
            continue                                  # not a planner-driven technique
        if any(p not in obs for p in pre):
            continue                                  # precondition GATE: every required observation must hold
        conf = (t.get("confidence") or {}).get("score", 0)
        tcwes = {str(c).upper() for c in (t.get("cwe") or [])}
        score = conf * 0.5 + (15 if tcwes & kev_cwes else 0) + (10 if t.get("status") == "proven" else 0)
        out.append({"id": t.get("id"), "name": t.get("name") or t.get("id"), "score": round(score, 1),
                    "family": t.get("vuln_class", ""), "preconditions_met": pre,
                    "action": t.get("try_it") or ((t.get("payloads") or [{}])[0].get("payload", "")),
                    "oracle": (t.get("detection_logic") or [""])[0]})
    out.sort(key=lambda x: x["score"], reverse=True)
    return out
