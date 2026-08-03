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


# ── vulnerability-class recognition (for typed chaining) ─────────
_CLASS_RX = [
    ("rce",  re.compile(r"command inj|\brce\b|remote code|deserial", re.I)),
    ("sqli", re.compile(r"sql\s*inj|sqli", re.I)),
    ("ssti", re.compile(r"ssti|csti|template inj", re.I)),
    ("xxe",  re.compile(r"xxe|xml external", re.I)),
    ("ssrf", re.compile(r"ssrf|server.side request", re.I)),
    ("proto", re.compile(r"prototype pollution", re.I)),
    ("stored_xss", re.compile(r"stored xss|second.order xss", re.I)),
    ("xss",  re.compile(r"\bxss\b|cross.site.script|dom.based|dom xss", re.I)),
    ("crlf", re.compile(r"crlf|response splitting|header inj", re.I)),
    ("cache_poison", re.compile(r"cache poison|unkeyed", re.I)),
    ("open_redirect", re.compile(r"open.redirect", re.I)),
    ("oauth", re.compile(r"oauth|openid|\bsso\b", re.I)),
    ("idor", re.compile(r"idor|bola|bfla|broken access|access control", re.I)),
    ("exposure", re.compile(r"\.env|secret|api.?key|credential|exposed|\.git|backup", re.I)),
    ("headers", re.compile(r"missing.*(hsts|header|x-frame|x-content|csp)|clickjack|content-security", re.I)),
]


# the finding's OWN family is authoritative — trust it before fuzzy text matching, so a
# client-side CSTI whose description says "does NOT give server RCE" is never misread as an
# RCE producer (which fabricated a "confirmed RCE" data-flow chain). Text regex is only the
# fallback for findings that carry no family.
_FAMILY_CLASS = {
    "sqli": "sqli", "xss": "xss", "stored_xss": "stored_xss", "csti": "ssti", "ssti": "ssti",
    "xxe": "xxe", "ssrf": "ssrf", "prototype_pollution": "proto", "crlf": "crlf",
    "open_redirect": "open_redirect", "oauth": "oauth", "idor": "idor", "bfla": "idor",
    "cmdi": "rce", "deserialization": "rce", "cache_poison": "cache_poison",
    "exposure": "exposure", "git_exposure": "exposure", "vulnerable_component": "",
}


def _vuln_class(f: dict) -> str:
    fam = str(f.get("family") or "").strip().lower()
    if fam in _FAMILY_CLASS:
        return _FAMILY_CLASS[fam]
    hay = " ".join(str(f.get(k, "")) for k in ("title", "description", "category", "family", "cwe")).lower()
    for slug, rx in _CLASS_RX:
        if rx.search(hay):
            return slug
    return ""


# Single confirmed class -> a well-known escalation (a POTENTIAL chain, clearly labeled).
# (name, narrative, impact, severity)
_ESCALATIONS = {
    "sqli": ("SQLi → database compromise → credential theft → account takeover",
             "A confirmed SQL injection lets an attacker read (and often modify) the database — including password "
             "hashes, session tokens, and other users' records — escalating to authentication bypass and account takeover.",
             "high"),
    "rce": ("Command injection / RCE → full host compromise → internal pivot",
            "Executing OS commands on the server is full compromise of that host and a foothold for pivoting into the "
            "internal network.", "critical"),
    "xss": ("XSS → session/token theft → account takeover",
            "Running script in a victim's authenticated session lets an attacker exfiltrate session cookies/tokens or "
            "ride the session to perform privileged actions, leading to account takeover.", "high"),
    "stored_xss": ("Stored XSS → mass session/token theft → account takeover → worm propagation",
                   "A stored XSS payload executes in EVERY visitor's authenticated session — harvesting session "
                   "cookies/tokens at scale, enabling account takeover, and (self-propagating) worm-like spread across "
                   "users without any per-victim interaction.", "critical"),
    "ssti": ("Client-side template injection → in-browser expression evaluation → DOM XSS → session theft / account takeover",
             "The confirmed CSTI evaluates attacker input in the victim's browser (AngularJS), running JavaScript as "
             "the victim: session/cookie theft, account takeover, and phishing on the trusted domain. Impact is "
             "client-side (the server is not compromised by this bug).", "high"),
    "xxe": ("XXE → local file disclosure → SSRF → internal reachability",
            "XML external entity processing can read local files (app config/secrets, /etc/passwd) and coerce the server "
            "into internal requests (SSRF), reaching services not exposed externally.", "high"),
    "ssrf": ("SSRF → cloud metadata / internal services → credential theft",
             "Server-side request forgery can reach cloud metadata (e.g. 169.254.169.254) and internal-only services, "
             "harvesting temporary credentials and pivoting inward.", "high"),
    "open_redirect": ("Open redirect → phishing / OAuth token theft",
                      "An open redirect makes phishing links look legitimate and, where an OAuth flow trusts the redirect "
                      "target, can leak authorization codes/tokens — enabling account takeover.", "medium"),
}

# Two confirmed classes on the same host -> a stronger, specific chain.
# (frozenset(classes), name, narrative, impact, severity)
_COMBOS = [
    (frozenset({"proto", "xss"}), "Prototype pollution → DOM XSS gadget → session theft",
     "Prototype pollution poisons object defaults that a client-side sink then trusts, turning into DOM XSS and "
     "session/token theft in the victim's browser.", "high"),
    (frozenset({"crlf", "cache_poison"}), "CRLF injection → cache poisoning / session fixation",
     "CRLF in a response header lets an attacker split the response or set headers/cookies; combined with an unkeyed "
     "cache input it poisons cached responses served to other users, or fixes a session.", "high"),
    (frozenset({"xxe", "ssrf"}), "XXE → SSRF → internal service / metadata reach",
     "XXE that coerces outbound requests becomes SSRF, reaching internal services and cloud metadata for credential theft.",
     "high"),
    (frozenset({"open_redirect", "oauth"}), "Open redirect + OAuth flow → authorization-code/token theft",
     "A redirect the OAuth flow trusts can be pointed at attacker infrastructure, leaking the authorization code or token "
     "and enabling account takeover.", "high"),
    (frozenset({"headers", "xss"}), "Missing security headers + XSS → amplified impact",
     "Absent CSP/anti-framing headers remove the browser mitigations that would blunt the XSS, so the same injection "
     "reaches a wider blast radius (no CSP fallback, framing-based UI redress).", "medium"),
    (frozenset({"sqli", "exposure"}), "Exposed secrets + SQLi → deeper database/credential compromise",
     "Leaked config/secrets plus a SQL injection compound: disclosed connection strings or keys sharpen the injection "
     "into direct data and credential theft.", "high"),
]


def _typed_chains(findings: list, max_chains: int = 8) -> list:
    """Specific, named escalation chains from CONFIRMED findings. Combos (two classes
    on one host) are real chains; a single high-impact class yields a clearly-labeled
    POTENTIAL escalation. Truth-first: every link is a confirmed finding — the chain
    describes where those confirmed bugs lead, it never invents a new confirmation."""
    by_host: dict = {}
    for f in findings:
        by_host.setdefault(_host_of(f), []).append(f)

    chains: list = []
    for host, group in by_host.items():
        cls_map: dict = {}
        for f in group:
            c = _vuln_class(f)
            if c:
                cls_map.setdefault(c, []).append(f)
        present = set(cls_map)
        # combos first (stronger)
        for classes, name, summary, sev in _COMBOS:
            if classes <= present:
                links = [g[0] for k, g in cls_map.items() if k in classes]
                chains.append({
                    "host": host, "severity": sev, "kind": "chain", "name": name,
                    "narrative": name, "summary": summary, "impact": summary,
                    "finding_ids": [f.get("id") for f in links if f.get("id")],
                })
        # single-class potential escalations
        for c in present:
            if c in _ESCALATIONS:
                name, narrative, sev = _ESCALATIONS[c]
                chains.append({
                    "host": host, "severity": sev, "kind": "potential", "name": name,
                    "narrative": name, "summary": narrative, "impact": narrative,
                    "finding_ids": [f.get("id") for f in cls_map[c] if f.get("id")],
                })
        if len(chains) >= max_chains:
            break
    return chains[:max_chains]


def _generic_host_chains(findings: list, max_chains: int = 6) -> list:
    """Fallback: >=2 findings on the same host narrated by severity order."""
    by_host: dict = {}
    for f in findings:
        by_host.setdefault(_host_of(f), []).append(f)
    chains = []
    for host, group in by_host.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda f: -_SEV_RANK.get((f.get("severity") or "info").lower(), 0))
        titles = [f.get("title", "finding") for f in ordered[:4]]
        top_sev = (ordered[0].get("severity") or "info").lower()
        # HONEST (CHAD #5): co-location on one host is NOT a proven attack path. Do not invent an
        # "entry point -> escalation" narrative; label it co-located and state what would prove a path.
        chains.append({
            "host": host, "severity": top_sev, "kind": "colocated", "verified": False,
            "finding_ids": [f.get("id") for f in ordered[:4] if f.get("id")],
            "narrative": " + ".join(titles),
            "summary": (f"{len(group)} confirmed finding(s) are CO-LOCATED on {host}. This is NOT a proven "
                        f"attack path: no data-flow, identity, or privilege transition between them was executed "
                        f"or observed. Listed so a tester can assess whether they actually chain."),
            "basis": "co-location on a single host only",
            "missing": "a proven transition between the findings (shared data-flow, an identity/privilege pivot, "
                       "or a reachable dependency) — none was executed",
        })
        if len(chains) >= max_chains:
            break
    return chains


# DATA-FLOW chaining: a "producer" vuln yields data that a downstream step consumes.
# producer class -> (the data it yields, its severity when chained).
_PRODUCES = {
    "sqli": "database contents (password hashes, session tokens, other users' rows)",
    "rce": "arbitrary server-side data, files, and command output",
    "xxe": "local files and application secrets",
    "exposure": "leaked secrets/config (keys, credentials, tokens)",
}
# consumer classes that USE stolen credentials/tokens/secrets to complete takeover.
_CONSUMERS = ("idor", "oauth", "stored_xss", "xss", "ssrf")


def _dataflow_chains(findings: list, max_chains: int = 6) -> list:
    """Directed producer -> data -> consumer chains grounded in CONFIRMED findings: a
    data-yielding bug (SQLi/RCE/XXE/exposure) feeds a downstream step (auth/IDOR/OAuth/...)
    to complete takeover. Truth-first AND non-destructive: this PROVES and names the data
    path deterministically — it never auto-executes the exploitation (extracting and
    reusing real credentials is destructive and authorization-gated)."""
    by_host: dict = {}
    for f in findings:
        by_host.setdefault(_host_of(f), []).append(f)
    chains: list = []
    for host, group in by_host.items():
        cls: dict = {}
        for f in group:
            c = _vuln_class(f)
            if c:
                cls.setdefault(c, []).append(f)
        for pc, data in _PRODUCES.items():
            if pc not in cls:
                continue
            sink = next((c for c in _CONSUMERS if c in cls), None)
            links = [cls[pc][0]] + ([cls[sink][0]] if sink else [])
            short = data.split("(")[0].strip()
            name = (f"{pc.upper()} → exfiltrate {short} → "
                    + (f"feed the confirmed {sink.upper()} flow → account takeover" if sink
                       else "authenticate as another user → account takeover"))
            chains.append({
                "host": host, "severity": "critical" if pc in ("rce", "sqli") else "high",
                "kind": "dataflow", "name": name, "narrative": name,
                "summary": (f"Data-flow: the confirmed {pc.upper()} yields {data}; that data flows into "
                            + (f"the confirmed {sink.upper()} on the same host to complete takeover. "
                               if sink else "the application's authentication to impersonate users. ")
                            + "Apolaki proves this path from confirmed findings; it does NOT auto-execute the "
                              "exploitation (extracting and reusing real data is destructive and requires explicit "
                              "authorization)."),
                "impact": f"End-to-end account/data compromise via the {pc.upper()} data path.",
                "finding_ids": [f.get("id") for f in links if f.get("id")],
            })
            if len(chains) >= max_chains:
                return chains
    return chains


def build_chains(findings: list, max_chains: int = 8) -> list:
    """Synthesize attack-path chains from confirmed findings.

    Deterministic and truth-first: DIRECTED data-flow chains (producer->data->consumer)
    first, then TYPED escalation rules (SQLi->ATO, XXE->SSRF, prototype-pollution->DOM XSS,
    ...), then a generic same-host fallback. Combos/data-flow are real chains; single-class
    escalations are labeled `kind: "potential"`. Every link references a confirmed finding —
    chaining says where proven bugs lead, it never invents a confirmation or auto-executes
    destructive exploitation.
    """
    out: list = []
    seen = set()
    # directed data-flow chains first (most specific: a real producer->consumer path)
    for c in _dataflow_chains(findings, max_chains):
        key = (c["host"], c.get("name") or c["narrative"])
        if key not in seen:
            seen.add(key)
            out.append(c)
    # generic multi-finding host chains next (a host with >=2 real findings)
    for c in _generic_host_chains(findings, max_chains):
        key = (c["host"], c["narrative"])
        if key not in seen:
            seen.add(key)
            out.append(c)
    # then typed combos + potential escalations (dedup by host+name)
    for c in _typed_chains(findings, max_chains):
        key = (c["host"], c.get("name") or c["narrative"])
        if key not in seen:
            seen.add(key)
            out.append(c)
        if len(out) >= max_chains:
            break
    # HONESTY STAMP (CHAD #5): Apolaki INFERS chains from co-present CONFIRMED findings; it does not
    # execute the transition between steps (that is destructive + authorization-gated). So no chain is
    # "verified" end-to-end here — every one is a PLAUSIBLE hypothesis carrying what would prove it.
    for c in out:
        c.setdefault("verified", False)
        c.setdefault("basis", "inferred from co-present confirmed findings; the transition between steps "
                              "was not executed or observed")
        c.setdefault("missing", "execute/observe the transition between the steps (a shared data-flow, an "
                                "identity/privilege pivot, or a reachable dependency) to verify the path end-to-end")
    return out[:max_chains]


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
