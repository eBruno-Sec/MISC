"""Request workbench: deterministic replay, response diff, single-parameter
fuzzing, and cross-role access-control checking.

The manual "Repeater + Intruder" that finds the high-value and access-control
bugs scanners miss. No AI: the analyst supplies the request; the engine sends
it, mutates one parameter across a payload list, and ranks results by anomaly.
Ported from OLYMPUS core/replay.py.
"""
import difflib
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

MAX_PAYLOADS = 500

ERROR_SIGNATURES = (
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "ora-0", "psql:", "sqlite", "sqlstate", "pdoexception",
    "microsoft ole db", "odbc", "unterminated", "syntax error",
    "traceback (most recent call last)", "stacktrace", "java.lang.",
    "warning: ", "fatal error", "call stack",
)


def client(follow_redirects: bool = False, timeout: int = 15):
    """An httpx client configured for manual testing (no cert verify)."""
    import httpx
    return httpx.AsyncClient(verify=False, follow_redirects=follow_redirects, timeout=timeout)


async def send(c, method: str, url: str, headers: dict = None, body: str = None) -> dict:
    """Send one request; return a response summary with timing."""
    content = body.encode("utf-8", "replace") if isinstance(body, str) and body else None
    t0 = time.perf_counter()
    r = await c.request(method.upper(), url, headers=(headers or None), content=content)
    dur = int((time.perf_counter() - t0) * 1000)
    try:
        text = r.text
    except Exception:
        text = ""
    return {
        "status": r.status_code,
        "length": len(r.content),
        "duration_ms": dur,
        "headers": dict(r.headers),
        "body": text,
    }


# ── Diff ─────────────────────────────────────────────────────────
def _header_diff(ha: dict, hb: dict) -> dict:
    ka = {str(k).lower(): v for k, v in (ha or {}).items()}
    kb = {str(k).lower(): v for k, v in (hb or {}).items()}
    return {
        "added": sorted(k for k in kb if k not in ka),
        "removed": sorted(k for k in ka if k not in kb),
        "changed": sorted(k for k in ka if k in kb and ka[k] != kb[k]),
    }


def _body_diff(a: str, b: str, max_lines: int = 200) -> str:
    diff = difflib.unified_diff((a or "").splitlines(), (b or "").splitlines(),
                                lineterm="", n=2)
    return "\n".join(list(diff)[:max_lines])


def diff_responses(a: dict, b: dict, body_lines: int = 200) -> dict:
    la, lb = a.get("length", 0) or 0, b.get("length", 0) or 0
    return {
        "status": {"a": a.get("status"), "b": b.get("status"),
                   "changed": a.get("status") != b.get("status")},
        "length": {"a": la, "b": lb, "delta": lb - la},
        "duration_ms": {"a": a.get("duration_ms"), "b": b.get("duration_ms")},
        "headers": _header_diff(a.get("headers", {}), b.get("headers", {})),
        "body_diff": _body_diff(a.get("body", "") or "", b.get("body", "") or "", body_lines),
    }


# ── Fuzz (single-parameter, Intruder-style) ──────────────────────
def mutate(url: str, body: str, param: str, param_in: str, payload: str):
    """Return (url, body, extra_headers) with `param` set to `payload`.
    param_in: query | body (form-encoded) | header."""
    if param_in == "query":
        p = urlparse(url)
        q = parse_qs(p.query, keep_blank_values=True)
        q[param] = [payload]
        return urlunparse(p._replace(query=urlencode(q, doseq=True))), body, {}
    if param_in == "body":
        q = parse_qs(body or "", keep_blank_values=True)
        q[param] = [payload]
        return url, urlencode(q, doseq=True), {}
    if param_in == "header":
        return url, body, {param: payload}
    return url, body, {}


def score_result(baseline: dict, res: dict) -> int:
    score = 0
    b_status = baseline.get("status") or 0
    r_status = res.get("status") or 0
    if r_status != b_status:
        score += 3
    # A status-CLASS jump is a top-tier anomaly; benign -> 5xx server error is the
    # strongest single signal (SQLi/parser break). This must never rank low.
    if r_status // 100 != b_status // 100:
        score += 2
    if r_status >= 500 and b_status < 500:
        score += 4
    b_len = baseline.get("length") or 0
    delta = abs((res.get("length") or 0) - b_len)
    if delta > 40:
        score += 1
    if b_len and delta / b_len > 0.5:
        score += 2   # large relative length change
    if res.get("reflected"):
        score += 2
    if res.get("error_signatures"):
        score += 4
    if (res.get("duration_ms") or 0) > (baseline.get("duration_ms") or 0) + 4000:
        score += 3  # time-based (blind SQLi / SSRF timeout)
    return score


def anomaly_label(score: int) -> str:
    """Human/UI label for a fuzz row's score — never None (a scored row is always
    classified, so an obvious 5xx anomaly can't render as 'nothing')."""
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    if score >= 1:
        return "low"
    return "none"


# ── Cross-role access control (IDOR / BOLA / BFLA) ───────────────
def _similar(a: int, b: int, tol: float = 0.15) -> bool:
    a, b = a or 0, b or 0
    if a == 0 and b == 0:
        return True
    return abs(a - b) / (max(a, b) or 1) <= tol


_PROTECTED_HINT_RE = re.compile(
    r"/(admin|account|accounts|settings|dashboard|internal|manage|management|users?|"
    r"orders?|profile|invoices?|billing|me|private|owner|secret|config|api/(?:v\d+/)?\w)",
    re.I)
_OBJECT_ID_RE = re.compile(r"/[A-Za-z0-9_-]+/(\d+|[0-9a-fA-F]{8,})(?:/|$|\?)")


def looks_protected(url: str) -> bool:
    """Heuristic: does this URL look like a resource that SHOULD require auth?

    Used so a plain public page (e.g. `/`, `/?ref=x`) returning 200 to an
    anonymous request is NOT mislabelled broken access control. A protected look
    means an admin/account/api path or an object-scoped resource (`/orders/42`)."""
    if not url:
        return False
    try:
        path = urlparse(url).path or "/"
    except Exception:
        return False
    return bool(_PROTECTED_HINT_RE.search(path) or _OBJECT_ID_RE.search(path))


def access_verdict(results: list, url: str = None) -> dict:
    """Compare the same request sent under different roles and flag broken access
    control. `results` items: {role, status, length, is_owner, is_anon}.

    With a registered owner, a non-owner receiving the owner's response is the
    real BOLA signal. Without any roles, an anonymous 200 is only suspicious when
    the URL looks like it should be protected — otherwise it is just a public
    page, and flagging it produces the false positive Codex hit on `/?ref=…`."""
    owner = next((r for r in results if r.get("is_owner")), None)
    protected = looks_protected(url)
    flags = []
    for r in results:
        if r.get("is_owner") or r.get("error"):
            continue
        status = r.get("status") or 0
        ok = 200 <= status < 300
        if owner:
            o_status = owner.get("status") or 0
            if ok and 200 <= o_status < 300 and _similar(r.get("length"), owner.get("length")):
                r["flag"] = (f"BROKEN_ACCESS_CONTROL: '{r.get('role')}' received the owner's "
                             f"response (status {status}, ~{r.get('length')}B)")
                flags.append(r.get("role"))
        elif r.get("is_anon") and ok and (r.get("length") or 0) > 200 and protected:
            r["flag"] = (f"UNAUTHENTICATED_ACCESS: anonymous request reached a protected-looking "
                         f"resource ({status}, ~{r.get('length')}B) — verify it should require auth")
            flags.append(r.get("role"))
    if flags:
        verdict = "Possible broken access control — " + ", ".join(str(f) for f in flags)
    elif not owner and not protected:
        verdict = "Public resource — no auth expected; register roles to test cross-role access"
    else:
        verdict = "No cross-role access-control anomaly detected"
    return {"flags": flags, "verdict": verdict, "anomaly": bool(flags)}


async def fuzz(c, method: str, url: str, headers: dict, body: str,
               param: str, param_in: str, payloads: list, baseline: dict = None) -> dict:
    """Fire each payload at one parameter, rank results by anomaly score."""
    payloads = list(payloads)[:MAX_PAYLOADS]
    if baseline is None:
        baseline = await send(c, method, url, headers, body)

    results = []
    for pl in payloads:
        u, b, extra = mutate(url, body, param, param_in, pl)
        h = dict(headers or {})
        h.update(extra)
        try:
            r = await send(c, method, u, h, b)
        except Exception as e:
            # A transport error is itself notable — surface it, don't drop it to a
            # scoreless row that renders as "no anomaly".
            results.append({"payload": pl, "error": str(e), "score": 2, "anomaly": "error"})
            continue
        low = (r["body"] or "").lower()
        res = {
            "payload": pl,
            "status": r["status"],
            "length": r["length"],
            "duration_ms": r["duration_ms"],
            "reflected": pl in (r["body"] or ""),
            "error_signatures": [s for s in ERROR_SIGNATURES if s in low],
        }
        res["score"] = score_result(baseline, res)
        res["anomaly"] = anomaly_label(res["score"])
        results.append(res)

    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    return {
        "baseline": {"status": baseline["status"], "length": baseline["length"],
                     "duration_ms": baseline["duration_ms"]},
        "param": param, "param_in": param_in,
        "count": len(results), "results": results,
    }
