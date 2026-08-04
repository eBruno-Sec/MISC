"""
Technique advisor -- turns the first-class Technique knowledge model into scan-time recommendations.

Given what recon established and what the scan confirmed (findings), it ranks the applicable techniques
and returns the highest-priority ones to test next. This is how a scan CONSUMES the technique registry
instead of it sitting there as a static library: proven techniques become prioritized, parameterized
leads that flow into the same leads pipeline the report and operator already use.

Pure + deterministic: the ranking is an explainable score (relevance to THIS target x real-world weight
x actionability), each contribution attributed to a named reason.
"""
from __future__ import annotations


def _norm(s):
    return str(s or "").strip().lower()


def recommend(findings, techniques, kev_cwes=None, signals=None, top=8):
    """Rank canonical Technique dicts for the current scan. Returns [{technique, score, reasons}],
    most relevant first. Deterministic and explainable. `signals` = vuln-class hints derived from ALL
    gathered intel (harvested object-ids/versions/coupons, code-intel routes, leads) so the advisor is
    driven by everything recon collected, not just confirmed findings -- the orchestration contract."""
    kev_cwes = {str(c).upper() for c in (kev_cwes or [])}
    signals = {_norm(s) for s in (signals or set())}
    found_families = {_norm(f.get("family")) for f in (findings or []) if f.get("family")}
    found_cwes = {str(f.get("cwe") or "").upper() for f in (findings or []) if f.get("cwe")}
    out = []
    for t in techniques:
        if t.get("status") in ("rejected", "deprecated") or not t.get("transferable", True):
            continue
        reasons, score = [], 0.0
        conf = (t.get("confidence") or {}).get("score", 0)
        score += conf * 0.4
        fam = _norm(t.get("vuln_class"))
        tcwes = {str(c).upper() for c in (t.get("cwe") or [])}
        # relevance to what the scan already CONFIRMED: same class/CWE means "go deeper right here"
        if fam and fam in found_families:
            score += 30
            reasons.append("matches a confirmed %s finding" % fam)
        if tcwes & found_cwes:
            score += 25
            reasons.append("same CWE as a confirmed finding")
        # relevance to GATHERED INTEL (harvest + code-intel): weaker than a confirmed finding, but this
        # is how "all gathered info becomes intel for the next phase" -- recon evidence steers technique choice
        if fam and fam in signals:
            score += 12
            reasons.append("matches gathered-intel signal (%s)" % fam)
        # real-world weight. A CWE class appearing in CISA KEV is a CONTEXTUAL prior (this weakness
        # family HAS known-exploited instances in the wild) — it is NOT proof that this exact technique
        # or its CVE is itself known-exploited. KEV is CVE-indexed; "known-exploited in the wild" is
        # only ever claimed from an EXACT-CVE match (see report.py KEV section). Never launder a
        # CWE-class intersection into a "known-exploited" claim (CHAD final-audit defect #1).
        if tcwes & kev_cwes:
            score += 8
            reasons.append("weakness class is represented in CISA KEV (contextual prior, not an exact-CVE match)")
        # actionability + demonstrated reliability
        if t.get("payloads") or t.get("try_it"):
            score += 5
        if t.get("status") == "proven":
            score += 10
            reasons.append("proven on a lab")
        if conf:
            reasons.append("confidence %d" % conf)
        out.append({"technique": t, "score": round(score, 1), "reasons": reasons})
    out.sort(key=lambda x: x["score"], reverse=True)
    return out[:top]


def as_leads(recs, target):
    """Project advisor recommendations into the scan's lead schema (candidate leads, never findings)."""
    leads = []
    for r in recs:
        t = r["technique"]
        payload = t.get("try_it") or ((t.get("payloads") or [{}])[0].get("payload", ""))
        steps = [x for x in [(t.get("discovery_methods") or [""])[0], payload] if x]
        leads.append({
            "severity": "info", "confidence": "candidate", "family": t.get("vuln_class") or "technique",
            "tags": ["technique-advisor"] + (["kev"] if any("KEV" in x for x in r["reasons"]) else []),
            "cwe": (t.get("cwe") or [""])[0], "target": target,
            "title": "Technique to test — %s" % (t.get("name") or t.get("id")),
            "evidence": "; ".join(r["reasons"]) or (t.get("summary") or ""),
            "reproduction_steps": steps,
            "analyst_notes": "Advisor pick (score %s). %s" % (
                r["score"], (t.get("detection_logic") or [""])[0] or "Confirm with the technique's oracle."),
        })
    return leads
