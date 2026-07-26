"""
Optional lab-solver adapters + completion oracles.

SEPARATE from the general detection engine on purpose: these modules only supply
target-specific fingerprints and a completion check for benchmark SCORING (Juice Shop,
DVWA, …). They are never merged into the scanners and never hardcode answers into
detection — they let a general technique pack be scored against a lab's own oracle so we
can measure coverage without overfitting the product.
"""
from __future__ import annotations

import json
import urllib.request


def _http_json(url: str, timeout: int = 8):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _juiceshop_completion(base_url: str) -> dict:
    """OWASP Juice Shop tracks solved challenges at /api/Challenges."""
    try:
        d = _http_json(base_url.rstrip("/") + "/api/Challenges/")
        ch = d.get("data", d)
        solved = [c.get("name") for c in ch if c.get("solved")]
        return {"lab": "juiceshop", "total": len(ch), "solved": len(solved),
                "percent": round(100 * len(solved) / max(1, len(ch)), 1), "solved_names": solved}
    except Exception as e:
        return {"lab": "juiceshop", "error": str(e)}


def _dvwa_completion(base_url: str) -> dict:
    # DVWA has no machine-readable scoreboard; completion is per-module + manual.
    return {"lab": "dvwa", "note": "DVWA has no scoreboard API; score via per-module oracles/manual"}


LABS = {
    "juiceshop": {"fingerprint": ["OWASP Juice Shop", "juice-shop", "juice-sh.op"],
                  "completion": _juiceshop_completion},
    "dvwa": {"fingerprint": ["Damn Vulnerable Web Application", "DVWA"],
             "completion": _dvwa_completion},
}


def detect(html: str) -> str | None:
    """Best-effort lab id from a page body (fingerprint match)."""
    low = (html or "").lower()
    for lab_id, spec in LABS.items():
        if any(fp.lower() in low for fp in spec["fingerprint"]):
            return lab_id
    return None


def list_labs() -> list:
    return list(LABS.keys())


def benchmark(lab_id: str, base_url: str) -> dict:
    spec = LABS.get(lab_id)
    if not spec:
        return {"error": f"unknown lab '{lab_id}'", "available": list_labs()}
    return spec["completion"](base_url)
