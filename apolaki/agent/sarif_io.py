"""SARIF 2.1.0 import/export boundary (Codex cross-check Tier-1 #2).

SARIF is the standard interchange for static-analysis results. This is a BOUNDARY, not a new source of
truth:

  * IMPORT: a SARIF result becomes an Apolaki `candidate` (confidence="candidate",
    requires_runtime_validation=True) — NEVER an auto-confirmed vulnerability. Most SAST output is a lead
    until runtime proof exists. Producer suppression/baseline state is preserved as external metadata but
    NOT blindly trusted as Apolaki triage. Secret-looking snippets are redacted before storage.
  * EXPORT: Apolaki's ATOMIC findings become SARIF results for toolchain use. Attack CHAINS are never
    exported as SARIF (SARIF has no faithful chain semantics — chain severity stays Apolaki's own model).
    Snippets/evidence are redacted.

Pure + dependency-free. Reuses codereview's secret patterns for redaction so it matches the rest of Apolaki.
"""
from __future__ import annotations

import hashlib
import re

SARIF_VERSION = "2.1.0"
FP_KEY = "apolakiSemanticFingerprint/v1"

# finding severity -> SARIF result level + GitHub-style numeric security-severity
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "informational": "note"}
_SEC_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "3.0", "informational": "1.0"}
_CWE_RX = re.compile(r"(?i)cwe[-/_ ]?(\d{1,5})")


# ── secret redaction (reuse codereview patterns; over-redaction is the safe direction) ──
def redact_snippet(text) -> str:
    """Mask any secret-looking substring in a code snippet/message before it is stored or exported."""
    if not text:
        return text
    s = str(text)
    try:
        import codereview
        for _name, rx, _sev in codereview._SECRET_PATTERNS:
            s = rx.sub("«redacted-secret»", s)
        s = codereview._ASSIGN.sub(lambda m: m.group(0).replace(m.group(2), "«redacted-secret»"), s)
    except Exception:
        pass
    return s


def _sha(*parts) -> str:
    return hashlib.sha1("|".join("" if p is None else str(p) for p in parts).encode("utf-8", "replace")).hexdigest()[:16]


def _norm_location(uri: str) -> str:
    """Location key stable across query-string/order noise: scheme+host+path, no query/fragment."""
    u = str(uri or "").strip()
    u = u.split("#", 1)[0].split("?", 1)[0]
    return u.rstrip("/").lower()


def apolaki_fingerprint(family=None, cwe=None, location=None, sink=None, source=None) -> str:
    """Deterministic semantic fingerprint from family + CWE + normalized location (+ sink/source when known).
    Depends only on the finding's own fields, so it is identical regardless of import/export order."""
    cwe_n = None
    m = _CWE_RX.search(str(cwe or ""))
    if m:
        cwe_n = "CWE-%s" % m.group(1)
    return _sha(str(family or "").lower(), cwe_n, _norm_location(location), sink, source)


# ── EXPORT: atomic findings -> SARIF ──
def _location(uri: str, start_line=None) -> dict:
    phys = {"artifactLocation": {"uri": str(uri or "")}}
    if start_line:
        phys["region"] = {"startLine": int(start_line)}
    return {"physicalLocation": phys}


def export_sarif(findings: list, tool_name: str = "Apolaki") -> dict:
    """Emit a SARIF 2.1.0 run for ATOMIC findings only. Chains are intentionally not exported."""
    rules, rule_index, results = [], {}, []
    for i, f in enumerate(findings or []):
        f = f or {}
        family = str(f.get("family") or "").lower()
        cwe = str(f.get("cwe") or "")
        rule_id = family or (cwe or "apolaki.finding")
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            tags = [t for t in ("security", family) if t]
            if cwe:
                tags.append("external/cwe/%s" % cwe.lower())
            rules.append({"id": rule_id, "name": (f.get("title") or rule_id),
                          "properties": {"tags": tags, **({"cwe": cwe} if cwe else {})}})
        sev = str(f.get("severity") or "informational").lower()
        target = str(f.get("target") or f.get("url") or "")
        msg = redact_snippet(" — ".join(x for x in (str(f.get("title") or ""), str(f.get("description") or "")) if x))
        results.append({
            "ruleId": rule_id, "ruleIndex": rule_index[rule_id],
            "level": _LEVEL.get(sev, "note"),
            "message": {"text": msg or rule_id},
            "locations": [_location(target)] if target else [],
            "partialFingerprints": {FP_KEY: apolaki_fingerprint(family, cwe, target)},
            "properties": {"family": family, "cwe": cwe, "confidence": f.get("confidence"),
                           "owasp": f.get("owasp"), "security-severity": _SEC_SEVERITY.get(sev, "1.0"),
                           "apolaki_finding_id": f.get("id") or "finding-%d" % i, "atomic": True},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": SARIF_VERSION,
        "runs": [{"tool": {"driver": {"name": tool_name, "informationUri": "https://apolaki.local",
                                      "rules": rules}}, "results": results}],
    }


# ── IMPORT: SARIF -> Apolaki candidates ──
def _extract_cwe(rule: dict, result: dict) -> str:
    for src in (((rule or {}).get("properties") or {}).get("tags") or []):
        m = _CWE_RX.search(str(src))
        if m:
            return "CWE-%s" % m.group(1)
    for holder in ((rule or {}).get("properties") or {}), ((result or {}).get("properties") or {}):
        m = _CWE_RX.search(str(holder.get("cwe") or ""))
        if m:
            return "CWE-%s" % m.group(1)
    return ""


def _first_location(result: dict) -> tuple:
    for loc in (result.get("locations") or []):
        phys = (loc or {}).get("physicalLocation") or {}
        uri = ((phys.get("artifactLocation") or {}).get("uri")) or ""
        line = (phys.get("region") or {}).get("startLine")
        if uri or line:
            return uri, line
    return "", None


def _code_flow(result: dict) -> list:
    steps = []
    for cf in (result.get("codeFlows") or []):
        for tf in (cf.get("threadFlows") or []):
            for loc in (tf.get("locations") or []):
                phys = ((loc.get("location") or {}).get("physicalLocation")) or {}
                uri = ((phys.get("artifactLocation") or {}).get("uri")) or ""
                line = (phys.get("region") or {}).get("startLine")
                if uri or line:
                    steps.append({"uri": uri, "start_line": line})
    return steps


def import_sarif(data: dict) -> list:
    """Turn a SARIF document into Apolaki CANDIDATES (never confirmed findings). Each result requires runtime
    validation. Producer suppression/baseline state is preserved as external metadata, not trusted triage."""
    out = []
    if not isinstance(data, dict):
        return out
    for run in (data.get("runs") or []):
        driver = (((run or {}).get("tool") or {}).get("driver") or {})
        producer = str(driver.get("name") or "unknown").strip()
        rules_by_id = {r.get("id"): r for r in (driver.get("rules") or []) if isinstance(r, dict)}
        rules_list = driver.get("rules") or []
        for res in (run.get("results") or []):
            if not isinstance(res, dict):
                continue
            rid = res.get("ruleId")
            rule = rules_by_id.get(rid)
            if rule is None and isinstance(res.get("ruleIndex"), int) and 0 <= res["ruleIndex"] < len(rules_list):
                rule = rules_list[res["ruleIndex"]]
            cwe = _extract_cwe(rule, res)
            uri, line = _first_location(res)
            level = str(res.get("level") or "warning").lower()
            msg = redact_snippet(((res.get("message") or {}).get("text")) or "")
            supp = res.get("suppressions") or []
            producer_fp = None
            for fpsrc in (res.get("fingerprints"), res.get("partialFingerprints")):
                if isinstance(fpsrc, dict) and fpsrc:
                    producer_fp = next(iter(fpsrc.values()))
                    break
            out.append({
                "title": "SAST candidate: %s" % (msg[:80] or rid or "finding"),
                "confidence": "candidate", "source": "sarif", "producer": producer,
                "rule_id": rid, "cwe": cwe, "sarif_level": level,
                "location": {"uri": uri, "start_line": line},
                "code_flow": _code_flow(res),
                "producer_fingerprint": producer_fp,
                "apolaki_fingerprint": apolaki_fingerprint(None, cwe, uri,
                                                           sink=(_code_flow(res)[-1]["uri"] if _code_flow(res) else None)),
                # external metadata: preserved, NOT auto-applied as Apolaki triage
                "external_suppression": {"suppressed": bool(supp), "raw": supp} if supp else None,
                "requires_runtime_validation": True,
            })
    return out
