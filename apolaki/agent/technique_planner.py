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
    "sql_error_seen", "authenticated", "has_sensitive_route", "has_workflow", "credentials_exposed",
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
    "archive_slip":            ["has_file_upload"],
    "soft_deleted_login":      ["has_login"],
    "command_injection":       ["has_api"],
    "csrf":                    ["has_login"],
    "jwt_forge":               ["authenticated"],
    "weak_2fa_bypass":         ["authenticated"],
    "weak_password_reset":     ["has_login"],
    "exposed_credentials":     ["credentials_exposed"],
}


def derive_observations(surface=None, harvest=None, findings=None, leads=None, code_intel=None,
                        authenticated=False, graph=None):
    """Deterministically compute the observation set from everything recon gathered. Pure, no LLM.
    When a live canonical asset graph is supplied, its projected observations are ALSO merged in.
    NOTE: the mission planner now leads with plan_graph_authoritative() (the graph IS the authority,
    since all recon/intel is projected into it); this flat path is retained as a compatibility
    projection and for callers without a graph. Keep both in sync via the graph's to_observations()."""
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
    # ANY query parameter on the surface is an injectable input — derive the observations that gate the
    # injection techniques from the surface URLs' query strings, not just search-NAMED params. Without
    # this, a client-rendered param the JS-rendered crawl surfaced (a SPA's ?category=/?searchTerm=/
    # ?productId=) never reaches run_sqli / run_xss because no observation gated the technique on.
    from urllib.parse import urlparse as _up, parse_qs as _pq
    _surf_params = set()
    for _u in (surface or []):
        try:
            _surf_params |= {k.lower() for k in _pq(_up(str(_u)).query).keys()}
        except Exception:
            pass
    if _surf_params:
        obs.add("reflects_input")     # reflected-input candidate — run_xss confirms or denies it
        obs.add("has_search_param")   # injectable query input — run_sqli / union confirms or denies it
    if any(t in p for p in _surf_params for t in ("redirect", "return", "next", "goto", "dest", "callback", "url")):
        obs.add("has_redirect_param")
    if any(t in p for p in _surf_params for t in ("id", "productid", "userid", "orderid", "uid", "account")):
        obs.add("has_object_id")
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
    if by_kind.get("credential"):
        obs.add("credentials_exposed")
    # parameters mined from HTML forms / links / query strings become attack-surface observations:
    # redirect-ish params -> open_redirect, search/q -> injection surface, id/object -> IDOR.
    hk = harvest if isinstance(harvest, dict) else {}
    params = [str(p).lower() for p in (hk.get("candidates", {}) or {}).get("param", [])]
    pj = " ".join(params)
    if any(t in pj for t in ("redirect", "return", "returnurl", "next", "goto", "dest", "url", "continue", "callback")):
        obs.add("has_redirect_param")
    if any(p in ("q", "query", "search", "s", "keyword", "term") for p in params) or "search" in pj:
        obs.add("has_search_param")
    if any(t in pj for t in ("id", "userid", "orderid", "productid", "uid", "account")):
        obs.add("has_object_id")

    fams = {str(x.get("family", "")).lower() for x in ((findings or []) + (leads or []))}
    if fams & {"xss", "reflected_xss", "stored_xss", "dom_xss"}:
        obs.add("reflects_input")
    if fams & {"sqli", "nosqli"}:
        obs.add("sql_error_seen")
    if any(str(x.get("family", "")).lower() == "attack_surface" for x in (leads or [])):
        obs.add("has_sensitive_route")
    if authenticated:
        obs.add("authenticated")
    # merge observations projected straight from the LIVE canonical graph (planner-authoritative)
    if graph is not None:
        try:
            obs |= graph.to_observations()
        except Exception:
            pass
    return obs


def plan_graph_authoritative(graph, techniques=None, kev_cwes=None):
    """Plan with the canonical asset graph as the SOLE authority (CHAD capability B). Observations
    come ONLY from graph.to_observations(); the ranked action list ONLY from graph.next_best_actions().
    This entry point takes NO surface/harvest argument, so flat recon CANNOT independently drive it —
    an empty graph yields an empty plan no matter what recon found elsewhere. That is the proof the
    graph is the brain: facts must be projected INTO the graph to influence the plan. The flat-recon
    derive_observations() path remains as a compatibility projection, not the authority."""
    if graph is None:
        return {"observations": [], "techniques": [], "next_best_actions": [], "graph_authoritative": True}
    techniques = techniques if techniques is not None else registry_seed()
    obs = set(graph.to_observations())
    techs = plan(obs, techniques, kev_cwes=kev_cwes)
    return {"observations": sorted(obs), "techniques": techs,
            "next_best_actions": graph.next_best_actions(), "graph_authoritative": True}


def registry_seed(enrich=None):
    """Project the techniques.py registry into the minimal canonical shape plan() consumes (id / name /
    vuln_class / cwe list / status / confidence.score / try_it / detection_logic), so the SAME deterministic
    planner can run INSIDE a scan without the heavy technique_model projection the /plan endpoint uses.
    Confidence rides the transferability ladder: generalized(>=2 labs) > lab-proven > catalogued. Pure."""
    import techniques as T
    enrich = enrich or {}
    out = []
    for r in T.TECHNIQUES.values():
        vo = list(dict.fromkeys(r.get("validated_on") or []))
        score = 60 if len(vo) >= 2 else (40 if vo else 20)
        cwe = r.get("cwe")
        cwes = [cwe] if cwe else []
        cwes += [c for c in (enrich.get(r["id"], {}).get("kev_cwes") or []) if c not in cwes]
        out.append({"id": r["id"], "name": r["id"], "vuln_class": r.get("vuln_class", ""),
                    "cwe": cwes, "status": "proven" if vo else "catalogued",
                    "confidence": {"score": score}, "try_it": r.get("detect", ""),
                    "payloads": [], "detection_logic": [r.get("oracle", "")]})
    return out


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
        entry = {"id": t.get("id"), "name": t.get("name") or t.get("id"), "score": round(score, 1),
                 "family": t.get("vuln_class", ""), "preconditions_met": pre,
                 "action": t.get("try_it") or ((t.get("payloads") or [{}])[0].get("payload", "")),
                 "oracle": (t.get("detection_logic") or [""])[0]}
        # Retire the mutation-engine island: attach the concrete filter/WAF-bypass ladder for injection
        # classes, so every planner consumer (the /plan dashboard, the scan's next-best-action, the report,
        # the workbench) hands the operator the exact ordered payloads to try -- not just "test SQLi here".
        bl = _bypass_ladder(entry["family"])
        if bl:
            entry["bypass_ladder"] = bl
        out.append(entry)
    out.sort(key=lambda x: x["score"], reverse=True)
    return out


# class -> mutation family (the payload-mutation engine keys on these)
_MUT_FAMILY = {
    "sql_injection": "sqli", "sqli": "sqli", "nosql_injection": "nosqli", "xss": "xss",
    "template_injection": "ssti", "command_injection": "command_injection",
    "path_traversal": "path_traversal", "redirect": "open_redirect", "xxe": "xxe", "injection": "crlf",
}


def _bypass_ladder(vuln_class, limit=6):
    """Ordered filter/WAF-bypass payloads for an injection class, from the deterministic mutation engine
    (encodings, case toggles, comment/whitespace tricks). Empty for non-injection classes. Pure."""
    fam = _MUT_FAMILY.get(str(vuln_class or "").lower())
    if not fam:
        return []
    try:
        import mutation
        return mutation.variants(fam, limit=limit)
    except Exception:
        return []
