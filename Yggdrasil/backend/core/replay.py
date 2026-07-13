"""Request workbench: deterministic replay, response diff, and single-parameter
fuzzing. The manual "Repeater + Intruder" that finds the high-value and
access-control bugs scanners miss.

No AI: the analyst supplies the request (method / url / headers / body); the
engine sends it, captures the response, mutates one parameter across a payload
list, and ranks the results by anomaly (status change, error signatures,
reflection, time delay). Every send is authorized, analyst-initiated testing.
"""
import difflib
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

MAX_PAYLOADS = 500

# Response substrings that strongly suggest an injection / server error was hit.
ERROR_SIGNATURES = (
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "ora-0", "psql:", "sqlite", "sqlstate", "pdoexception",
    "microsoft ole db", "odbc", "unterminated", "syntax error",
    "traceback (most recent call last)", "stacktrace", "java.lang.",
    "warning: ", "fatal error", "call stack", "nikto",
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
    """Compare two response summaries: status / length / header / body deltas."""
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
    """Anomaly score for a fuzz result vs the baseline (higher = more interesting)."""
    score = 0
    if res.get("status") != baseline.get("status"):
        score += 3
    if abs((res.get("length") or 0) - (baseline.get("length") or 0)) > 40:
        score += 1
    if res.get("reflected"):
        score += 2
    if res.get("error_signatures"):
        score += 4
    if (res.get("duration_ms") or 0) > (baseline.get("duration_ms") or 0) + 4000:
        score += 3  # time-based (blind SQLi / SSRF timeout)
    return score


# ── Cross-role access control (IDOR / BOLA / BFLA) ───────────────
def _similar(a: int, b: int, tol: float = 0.15) -> bool:
    a, b = a or 0, b or 0
    if a == 0 and b == 0:
        return True
    return abs(a - b) / (max(a, b) or 1) <= tol


def access_verdict(results: list) -> dict:
    """Compare the same request sent under different roles and flag broken access
    control. `results` items: {role, status, length, is_owner, is_anon}.

    Strong signal (annotates the offending entry with a `flag`):
      - a NON-owner role gets the SAME 2xx and a response ~as large as the owner's
        -> it reached the owner's object/function (BOLA / BFLA);
      - with no owner designated, an anonymous role getting a 2xx with real content
        -> unauthenticated access.
    Access control looks intact when other roles get 401/403 or empty bodies."""
    owner = next((r for r in results if r.get("is_owner")), None)
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
        elif r.get("is_anon") and ok and (r.get("length") or 0) > 200:
            r["flag"] = f"UNAUTHENTICATED_ACCESS: '{r.get('role')}' received a {status} with content"
            flags.append(r.get("role"))
    verdict = ("Possible broken access control — " + ", ".join(str(f) for f in flags)) if flags \
        else "No cross-role access-control anomaly detected"
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
            results.append({"payload": pl, "error": str(e), "score": 0})
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
        results.append(res)

    results.sort(key=lambda x: x.get("score", 0), reverse=True)
    return {
        "baseline": {"status": baseline["status"], "length": baseline["length"],
                     "duration_ms": baseline["duration_ms"]},
        "param": param, "param_in": param_in,
        "count": len(results), "results": results,
    }
