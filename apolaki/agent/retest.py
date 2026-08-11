"""Retest / remediation-revalidation closure loop (Picus discipline).

A finding is not 'closed' because a ticket says so — re-fire its confirming check and let the ORACLE
decide: still-vulnerable = OPEN, gone = CLOSED, can't tell = INCONCLUSIVE (never a false closure).

The verdict logic here is PURE + deterministic; the caller performs the (read-only) re-send. Apolaki's
persisted findings carry a target URL + family + evidence, not a full request/marker recipe, so an honest
v1 auto-retests ONLY the families whose confirming oracle is a safe, idempotent GET to the finding's
target (a served-resource check, an off-site-redirect check, or a URL-borne reflection check). Anything
state-changing, or lacking a replayable request, is transparently INCONCLUSIVE and left for operator
retest — better an honest 'unknown' than a false 'closed'. No LLM.
"""
from __future__ import annotations

from urllib.parse import urlparse

# family -> the GET-oracle used to re-confirm it. Only these are auto-retestable (idempotent read).
_GET_ORACLE = {
    "exposure": "reachable", "sensitive_exposure": "reachable", "git_exposure": "reachable",
    "exposed_files": "reachable", "exposed_credentials": "reachable",
    # NOT "reachable" (Q-021A): a patched library is still served from the same URL and still
    # returns a non-empty 2xx, so the reachability oracle called every fix OPEN — telling a client
    # their remediation did not work, which is worse than missing the bug. The question is not
    # "is a file still served here" but "is the AFFECTED VERSION still served here".
    "vulnerable_component": "component_version",
    "cors": "reachable", "jsonp_info_leak": "reachable", "excessive_data_exposure": "reachable",
    "open_redirect": "offsite_redirect", "redirect": "offsite_redirect",
    "reflected_xss": "reflects", "xss": "reflects", "csti": "reflects", "ssti": "reflects",
}


def _host(u: str) -> str:
    try:
        return urlparse(u).netloc
    except Exception:
        return ""


def _payload_from_url(url: str) -> str:
    """Best-effort: the crafted value a reflection finding carries in its target query string."""
    try:
        q = urlparse(url).query
    except Exception:
        return ""
    cand = ""
    for part in q.split("&"):
        v = part.split("=", 1)[1] if "=" in part else ""
        if len(v) > len(cand):
            cand = v
    from urllib.parse import unquote
    return unquote(cand)


def plan(finding: dict) -> dict:
    """Whether + how a finding can be safely auto-retested. Returns {retestable, method, url, family,
    oracle, reason}. Deterministic; no network."""
    fam = str(finding.get("family") or "").lower()
    url = str(finding.get("target") or finding.get("url") or "").strip()
    if not url.lower().startswith("http"):
        return {"retestable": False, "family": fam, "reason": "no replayable http(s) target on the finding"}
    # A finding the Browser Intelligence Engine confirmed carries a FROZEN RECIPE — the exact request, the
    # persona that made it, and a hash of the response that proved the bug. That is precisely the
    # "persisted request/marker" whose absence makes every other access-control family inconclusive here,
    # so these ARE safely auto-retestable by an idempotent re-send as the same persona.
    if (finding.get("browser_evidence") or {}):
        import bie
        recipe = bie.retest_recipe(finding)
        if recipe.get("url") and recipe.get("method") == "GET":
            return {"retestable": True, "method": "GET", "url": recipe["url"], "family": fam,
                    "oracle": "bie_frozen_recipe", "recipe": recipe,
                    "as_persona": recipe.get("as_persona")}
    oracle = _GET_ORACLE.get(fam)
    if not oracle:
        return {"retestable": False, "family": fam, "url": url,
                "reason": "family %r has no safe GET-retest oracle; needs a persisted request/marker or "
                          "operator-approved replay (state-changing or non-idempotent)" % fam}
    return {"retestable": True, "method": "GET", "url": url, "family": fam, "oracle": oracle}


def _v(verdict: str, detail: str, url: str = "") -> dict:
    return {"verdict": verdict, "detail": detail, "url": url}


def evaluate(finding: dict, status, body: str = "", headers: dict = None, payload_hint: str = "") -> dict:
    """Deterministic OPEN / CLOSED / INCONCLUSIVE from a fresh GET response, per the family oracle.
    OPEN = the confirming signal still holds; CLOSED = it is gone; INCONCLUSIVE = can't tell (honest)."""
    p = plan(finding)
    url = p.get("url", "")
    if not p.get("retestable"):
        return _v("inconclusive", p.get("reason", "not retestable"), url)
    if status is None:
        return _v("inconclusive", "target unreachable on retest", url)
    if p.get("oracle") == "bie_frozen_recipe":
        import bie
        v = bie.retest_verdict(p.get("recipe") or {}, {"status": int(status), "body": body or ""})
        return _v(str(v["state"]).lower(), v["reason"], url)
    oracle, body, headers = p["oracle"], (body or ""), (headers or {})
    status = int(status)

    if oracle == "reachable":
        # the exposed resource is confirmed still-serving content; a 404/403/410 or empty body = gone.
        if 200 <= status < 300 and len(body.strip()) > 0:
            return _v("open", "resource still served (HTTP %s, %d bytes)" % (status, len(body)), url)
        return _v("closed", "resource no longer served (HTTP %s)" % status, url)

    if oracle == "component_version":
        # Re-FINGERPRINT the replacement instead of pinging the URL. CONTENT first, filename second:
        # a stale bundle name (/assets/jquery-3.4.0.js now serving 3.6.0) must never keep a fixed
        # finding OPEN — the body states the truth, the path is only a label and an in-place patch
        # does not rename the file.
        name = str(finding.get("component") or "").strip().lower()
        want = str(finding.get("component_version") or "").strip()
        if not (name and want):
            return _v("inconclusive", "finding carries no structured component/version to re-check "
                                      "(persisted before the SCA fields existed); operator retest", url)
        if not (200 <= status < 300) or not body.strip():
            return _v("closed", "%s no longer served (HTTP %s)" % (name, status), url)
        import dependency_intel as dep
        served = [c for c in dep.fingerprint_js_content(body, url) if c["name"] == name]
        if not served:
            # The only evidence left is the URL, which is byte-identical to the one we detected on —
            # it cannot distinguish "unpatched" from "patched in place". Saying OPEN here would be
            # the remediation lie itself, and saying CLOSED would be a false closure.
            return _v("inconclusive", "%s is still served but the replacement declares no version "
                                      "(only the unchanged filename, which an in-place patch does not "
                                      "update); operator retest" % name, url)
        now = served[0]
        if dep._norm_ver(now["version"]) == dep._norm_ver(want):
            return _v("open", "%s %s still served (version banner in the served body)"
                      % (name, now["version"]), url)
        if dep.assess_component(now):
            return _v("open", "%s upgraded %s -> %s, but the new version is still inside a "
                              "known-vulnerable range" % (name, want, now["version"]), url)
        return _v("closed", "%s upgraded %s -> %s, no longer inside a known-vulnerable range"
                  % (name, want, now["version"]), url)

    if oracle == "offsite_redirect":
        loc = next((str(v) for k, v in headers.items() if str(k).lower() == "location"), "")
        if loc and _host(loc) and _host(loc) != _host(url):
            return _v("open", "still redirects off-site to %s" % _host(loc), url)
        if 300 <= status < 400 or loc:
            return _v("closed", "no off-site redirect (Location=%r)" % loc, url)
        return _v("closed", "no redirect issued (HTTP %s)" % status, url)

    if oracle == "reflects":
        hint = payload_hint or _payload_from_url(url)
        if not hint:
            return _v("inconclusive", "no crafted payload recoverable from the target to re-check", url)
        if hint in body:
            return _v("open", "crafted payload still reflected in the response: %r" % hint[:60], url)
        return _v("closed", "crafted payload no longer reflected", url)

    return _v("inconclusive", "unknown oracle", url)


# retest verdict -> attack_chain outcome, so a closure feeds the cross-run memory (OPEN re-confirms,
# CLOSED dismisses the dead technique, INCONCLUSIVE records an attempt).
_OUTCOME = {"open": "confirmed", "closed": "dismissed", "inconclusive": "attempted"}


def chain_outcome(verdict: str) -> str:
    return _OUTCOME.get(verdict, "attempted")
