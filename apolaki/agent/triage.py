"""
Advisory triage (the METIS role).

Correlates and annotates findings: CWE/OWASP mapping, deterministic
false-positive *advisories*, and attack-path chain synthesis. HARD CONSTRAINT
(inherited from OLYMPUS): triage is advisory-only. It appends analyst notes and
proposes chains; it NEVER deletes a finding or tags it false_positive on its own
authority. Deterministic; AI is an optional narrative layer only.
"""
import re

# ── CWE / OWASP mapping by keyword ───────────────────────────────
_CWE_MAP = [
    (re.compile(r"sql\s*inj|sqli", re.I), "CWE-89", "A03:2021 Injection"),
    (re.compile(r"\bxss\b|cross.site.script", re.I), "CWE-79", "A03:2021 Injection"),
    (re.compile(r"ssrf|server.side request", re.I), "CWE-918", "A10:2021 SSRF"),
    (re.compile(r"traversal|lfi|local file", re.I), "CWE-22", "A01:2021 Broken Access Control"),
    (re.compile(r"idor|bola|bfla|broken access|access control", re.I), "CWE-639", "A01:2021 Broken Access Control"),
    (re.compile(r"open.redirect", re.I), "CWE-601", "A01:2021 Broken Access Control"),
    (re.compile(r"\bcors\b", re.I), "CWE-942", "A05:2021 Security Misconfiguration"),
    (re.compile(r"host.header", re.I), "CWE-644", "A05:2021 Security Misconfiguration"),
    (re.compile(r"ssti|template inj", re.I), "CWE-1336", "A03:2021 Injection"),
    (re.compile(r"command inj|rce|remote code", re.I), "CWE-78", "A03:2021 Injection"),
    (re.compile(r"xxe|xml external", re.I), "CWE-611", "A05:2021 Security Misconfiguration"),
    (re.compile(r"takeover", re.I), "CWE-350", "A05:2021 Security Misconfiguration"),
    (re.compile(r"\.env|secret|api.?key|credential|exposed.*(file|config|backup)|\.git", re.I),
     "CWE-200", "A01:2021 Broken Access Control"),
    (re.compile(r"csrf", re.I), "CWE-352", "A01:2021 Broken Access Control"),
    (re.compile(r"clickjack|frame", re.I), "CWE-1021", "A05:2021 Security Misconfiguration"),
    (re.compile(r"cookie|session", re.I), "CWE-614", "A05:2021 Security Misconfiguration"),
    (re.compile(r"header|hsts|csp", re.I), "CWE-693", "A05:2021 Security Misconfiguration"),
    (re.compile(r"version|banner|fingerprint|disclos", re.I), "CWE-200", "A06:2021 Vulnerable Components"),
]

# ── Heuristic false-positive advisories (never auto-applied) ─────
_FP_HINTS = [
    (re.compile(r"missing.*(hsts|header|x-frame|x-content)", re.I),
     "Header-only finding — confirm it materially affects a sensitive flow before reporting; many programs consider bare header gaps informational."),
    (re.compile(r"self.signed|certificate", re.I),
     "TLS/cert notes are frequently out of scope or low value; verify program rules."),
    (re.compile(r"version|banner|fingerprint", re.I),
     "Version disclosure alone is low value; escalate only if a reachable CVE is confirmed for that build."),
]


def classify(finding: dict) -> dict:
    """Return {cwe, owasp} for a finding based on its title/description/tags."""
    hay = " ".join(str(finding.get(k, "")) for k in ("title", "description", "category")).lower()
    hay += " " + " ".join(finding.get("tags") or [])
    for rx, cwe, owasp in _CWE_MAP:
        if rx.search(hay):
            return {"cwe": cwe, "owasp": owasp}
    return {"cwe": finding.get("cwe") or "", "owasp": ""}


def fp_advisory(finding: dict) -> str:
    """A non-binding note when a finding looks like a common false positive."""
    hay = " ".join(str(finding.get(k, "")) for k in ("title", "description")).lower()
    for rx, note in _FP_HINTS:
        if rx.search(hay):
            return note
    return ""


_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1}


def _host_of(finding: dict) -> str:
    """Best-effort host for a finding, from its target/surface field."""
    from urllib.parse import urlparse
    raw = str(finding.get("target") or finding.get("surface") or "").strip()
    if not raw:
        return "unknown"
    if "://" in raw:
        return (urlparse(raw).hostname or raw).lower()
    return raw.split("/")[0].split(":")[0].lower()


def build_chains(findings: list, max_chains: int = 6) -> list:
    """Synthesize plausible attack-path chains from >=2 findings on the same host.

    Deterministic: groups by host, orders by severity, and narrates recon ->
    foothold -> escalation. Every chain references at least two findings.
    """
    by_host: dict = {}
    for f in findings:
        host = _host_of(f)
        by_host.setdefault(host, []).append(f)

    chains = []
    for host, group in by_host.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda f: -_SEV_RANK.get((f.get("severity") or "info").lower(), 0))
        titles = [f.get("title", "finding") for f in ordered[:4]]
        top_sev = (ordered[0].get("severity") or "info").lower()
        chains.append({
            "host": host,
            "severity": top_sev,
            "finding_ids": [f.get("id") for f in ordered[:4] if f.get("id")],
            "narrative": " -> ".join(titles),
            "summary": (f"On {host}, {len(group)} findings compose an attack path: "
                        f"{titles[0]} provides the entry point"
                        + (f", then {titles[1]} enables escalation." if len(titles) > 1 else ".")),
        })
        if len(chains) >= max_chains:
            break
    return chains


def triage(findings: list) -> dict:
    """Run the full advisory pass over findings.

    Returns {annotations: {id: {cwe, owasp, fp_advisory, analyst_notes}}, chains,
    verdict}. Callers MERGE annotations into findings as notes — they never drop
    or overwrite a finding's severity based on this output.
    """
    annotations = {}
    for f in findings:
        fid = f.get("id")
        if not fid:
            continue
        cls = classify(f)
        note_bits = [f"METIS classification: {cls['cwe']} / {cls['owasp']}".strip(" /")]
        fp = fp_advisory(f)
        if fp:
            note_bits.append(f"FP advisory: {fp}")
        annotations[fid] = {
            "cwe": cls["cwe"],
            "owasp": cls["owasp"],
            "fp_advisory": fp,
            "analyst_notes": " | ".join(b for b in note_bits if b),
        }

    chains = build_chains(findings)
    counts = {}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        counts[s] = counts.get(s, 0) + 1
    high = counts.get("critical", 0) + counts.get("high", 0)
    verdict = (
        f"Triage complete: {len(findings)} findings ({high} critical/high), "
        f"{len(chains)} attack-path chain(s) synthesized. "
        "All findings preserved; annotations are advisory only."
    )
    return {"annotations": annotations, "chains": chains, "verdict": verdict}
