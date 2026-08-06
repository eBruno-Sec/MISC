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
    "exposed_files": "reachable", "exposed_credentials": "reachable", "vulnerable_component": "reachable",
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
    oracle, body, headers = p["oracle"], (body or ""), (headers or {})
    status = int(status)

    if oracle == "reachable":
        # the exposed resource is confirmed still-serving content; a 404/403/410 or empty body = gone.
        if 200 <= status < 300 and len(body.strip()) > 0:
            return _v("open", "resource still served (HTTP %s, %d bytes)" % (status, len(body)), url)
        return _v("closed", "resource no longer served (HTTP %s)" % status, url)

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
