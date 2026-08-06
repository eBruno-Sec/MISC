"""
The first-class Technique -- Apolaki's canonical offensive-knowledge entity.

Everything the platform learns normalizes into a Technique. Scanners, recon, exploit planning,
reporting, and autonomous reasoning query TECHNIQUES, not articles or raw CVEs. A CVE, a CAPEC
pattern, a disclosed report, a blog -- each is only a SOURCE that contributes fields (and provenance)
to a technique; the technique is what persists.

One schema, many sources:
  - hand-authored, oracle-proven techniques (techniques.py = the proven seed)
  - deterministically extracted candidates (CAPEC/KEV -> from_capec, no LLM)
  - LLM-extracted candidates from trusted prose (Phase 1 extractor, sandboxed, pending review)

Each Technique carries lifecycle status, source provenance, an auditable confidence score, version
history, and parent/child relationships. Confidence is DETERMINISTIC and explainable (a list of
scored factors) -- never an opaque model output. Nothing is ever silently overwritten: an improved
technique is versioned, a conflicting one is flagged, a wrong one is deprecated but kept (legacy
systems still exist).

This module is pure and dependency-light: it defines the schema, adapts other sources into it, and
scores confidence. Persistence + lifecycle transitions live in technique_store.py; ingestion lives in
the extractors. Consumers depend on THIS shape.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------- schema
# The canonical field set. Every Technique is a plain JSON-serializable dict with exactly these keys
# (keeps the codebase's dict-first style, trivial to serialize over the API, easy to diff/version).
FIELDS = (
    "id", "name", "summary", "vuln_class",
    # taxonomy lenses (lists -- a technique can map to several)
    "cwe", "owasp", "wstg", "capec", "attack",
    # applicability
    "applicable_products", "product_versions",
    # the offensive method
    "preconditions", "discovery_methods", "payloads", "detection_logic", "mitigations",
    # executable-knowledge proof contract (Nuclei-style) — the FP-safety + evidence obligations, made
    # explicit + machine-checkable instead of buried in engine code.
    "negative_control", "evidence_requirements", "replayable", "safety", "cleanup",
    # trust + lineage
    "evidence", "provenance", "confidence", "status", "version", "version_history",
    "success_metrics", "parents", "children",
    # operational
    "transferable", "permission", "try_it", "tags",
)

# Lifecycle. Knowledge is never deleted, only reclassified -- historical techniques stay valuable
# because legacy systems keep existing.
STATUSES = (
    "proven",          # oracle-confirmed on a lab (highest trust)
    "catalogued",      # known/documented, not yet demonstrated here
    "pending_review",  # ingested candidate awaiting human promotion
    "experimental",    # promoted but unproven, in trial
    "superseded",      # replaced by a higher-confidence version (kept)
    "deprecated",      # no longer effective, retained for legacy targets
    "historical",      # old technique, kept for old systems
    "conflicting",     # sources disagree -- needs human resolution
    "rejected",        # reviewed and discarded (kept for audit, never surfaced to scanners)
)

_LIST_FIELDS = ("cwe", "owasp", "wstg", "capec", "attack", "applicable_products", "product_versions",
                "preconditions", "discovery_methods", "payloads", "detection_logic", "mitigations",
                "evidence_requirements",
                "evidence", "provenance", "version_history", "parents", "children", "tags")


def blank(id, name=""):
    """A fully-formed canonical Technique with every field defaulted. Callers fill what they know."""
    t = {f: [] for f in _LIST_FIELDS}
    t.update({"id": id, "name": name or _humanize(id), "summary": "", "vuln_class": "",
              "confidence": {"score": 0, "tier": "low", "factors": []}, "status": "catalogued",
              "version": 1, "success_metrics": {}, "transferable": True, "permission": "auto",
              "try_it": None, "negative_control": "", "replayable": True, "safety": "active-safe",
              "cleanup": "None — non-destructive read/probe; no target state is modified."})
    return t


def _humanize(tid):
    return str(tid or "").replace("_", " ").replace("-", " ").strip().title()


def _as_list(v):
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


# ---------------------------------------------------------------------------- proof contract (executable knowledge)
# The Nuclei-style contract every technique carries so its FALSE-POSITIVE-safety differential and its
# EVIDENCE obligations are explicit + machine-checkable — not buried in engine code. Derived
# deterministically from the technique's vuln_class + oracle; any record may pre-set a field to override.
# This is what turns "we have an oracle" into a declared, testable proof discipline: which negative
# control must FAIL, and what a confirmed finding MUST retain to be believed + replayed. No LLM.
_NEG_CONTROL_BY_CLASS = [   # (vuln_class substring, negative-control text) — MOST SPECIFIC FIRST
    ("nosql", "A literal (non-operator) value in the same field does NOT change the result set the way the "
              "injected $-operator ($ne/$gt/$regex) does."),
    ("sql", "An inert control of the same shape but without SQL metacharacters does NOT reproduce the "
            "error/boolean/time differential; the unmodified baseline behaves normally."),
    ("template", "An arithmetic control evaluates server-side ({{7*7}}->49) while a non-evaluating control "
                 "({{7*'7'}}) does not — proving evaluation, not mere reflection."),
    ("xpath", "A control value without XPath metacharacters does not alter the node-set the query returns."),
    ("ldap", "A control value without LDAP filter metacharacters ()(|&* does not change the directory result set."),
    ("ssi", "A control string without SSI directives is echoed literally; only the <!--#exec/#include--> "
            "directive is evaluated by the server."),
    ("css", "A benign style value neither exfiltrates data nor alters state; only the injected selector does."),
    ("prototype", "A control property that is NOT a prototype key leaves object behaviour unchanged; only "
                  "__proto__/constructor pollution changes a downstream default."),
    ("command", "A control input without the shell separator yields the baseline output/latency; only the "
                "injected command changes the computed output or adds delay above the measured noise floor."),
    ("xxe", "A request without the external entity does NOT return file contents or trigger the OOB callback."),
    ("deser", "A well-formed (non-corrupted) serialized blob does NOT raise the parser-specific error the "
              "corrupt-and-watch oracle keys on."),
    ("traversal", "A control path inside the web root returns normal content; only the ../ escape reveals "
                  "out-of-root file contents."),
    ("path", "A control path inside the web root returns normal content; only the ../ escape reveals "
             "out-of-root file contents."),
    ("ssrf", "A control URL to a non-existent internal host does NOT return the internal-only signal; only the "
             "targeted internal resource (or the unique OOB correlation token) does."),
    ("redirect", "A same-origin control value keeps the response on-site (no external Location); only the "
                 "crafted external value redirects off-site."),
    ("csrf", "The same state-change WITH the anti-CSRF token / SameSite protection is rejected cross-site; "
             "only the token-less cross-site request succeeds."),
    ("xss", "A unique benign marker in the same sink is neutralised/encoded on a control request; only the "
            "payload request produces unencoded execution of that marker."),
    ("session", "Freshly minted control tokens do NOT fit the predicted sequence, and a token is not accepted "
                "after its session is invalidated."),
    ("crypto", "A token signed with the wrong/again-modified key is REJECTED; only the forgery that exploits "
               "the algorithm-confusion / none / weak-secret flaw is accepted."),
    ("access_control", "The authorized/owner persona sees only its own object and the attacker persona is "
                       "DENIED the same object on the negative-control request (no foreign data without the "
                       "identifier change)."),
    ("authentication", "Valid credentials succeed and invalid ones are rejected on the baseline; only the "
                       "tested bypass yields an authenticated session without valid credentials."),
    ("broken_auth", "Valid credentials succeed and invalid ones are rejected on the baseline; only the tested "
                    "bypass yields an authenticated session without valid credentials."),
    ("cache", "A clean re-request from an unpoisoned cache key returns the normal response; only the "
              "unkeyed-input request re-serves the injected canary."),
    ("network_service", "A securely-configured control (auth required / signing enforced / anonymous access "
                        "disabled) does NOT expose the same data — the finding reflects the target's actual "
                        "read-only configuration, not a probe artifact."),
    ("sensitive_exposure", "A request to a benign/non-existent control path does NOT return the sensitive "
                           "artifact; only the exposed resource does, matched by a content signature."),
    ("vuln_component", "The detected version banner/marker falls in a KNOWN-vulnerable range; a patched-version "
                       "control does not match the signature."),
    ("business_logic", "The workflow executed in the intended order / within limits is enforced on the "
                       "baseline; only the abused sequence (skipped step, replayed action, tampered value) "
                       "produces the unauthorized outcome, reproducibly."),
    ("llm", "A benign control prompt does NOT produce the injected marker or behaviour; only the "
            "instruction-override payload yields exact marker compliance."),
    ("prompt", "A benign control prompt does NOT produce the injected marker or behaviour; only the "
               "instruction-override payload yields exact marker compliance."),
    ("ics", "READ-ONLY: a benign read function returns the same data; NO write/coil/register command is ever "
            "issued to the target — exposure is proven by unauthenticated read alone."),
]
_DEFAULT_NEG = ("A negative-control request WITHOUT the trigger does NOT reproduce the confirming signal "
                "(differential measured over a stable baseline).")
# classes that can create/modify target state -> their cleanup obligation differs from pure read probes.
_WRITE_CLASSES = ("mass_assignment", "csrf", "business_logic", "upload", "deserialization", "command")


def _neg_control_for(vuln_class):
    vc = str(vuln_class or "").lower()
    for key, text in _NEG_CONTROL_BY_CLASS:
        if key in vc:
            return text
    return _DEFAULT_NEG


def proof_contract(rec):
    """Derive a technique's executable-knowledge proof contract (negative_control, evidence_requirements,
    safety, cleanup, replayable) from its class + oracle. Deterministic; a record may pre-set any field to
    override the derivation. Used by techniques._t() (so the registry + API carry it) and by the guard test
    that enforces every proven technique declares its FP-safety differential + evidence obligations."""
    vc = str(rec.get("vuln_class") or "").lower()
    _dl = rec.get("detection_logic")
    oracle = str(rec.get("oracle") or (_dl[0] if isinstance(_dl, list) and _dl else "") or "").strip()
    perm = str(rec.get("permission") or "").upper()
    execu = str(rec.get("execution") or "").lower()
    neg = rec.get("negative_control") or _neg_control_for(vc)
    ev = list(rec.get("evidence_requirements") or [])
    if not ev:
        if oracle:
            ev.append("Oracle satisfied: " + oracle)
        ev.append("Negative control captured showing the confirming signal is ABSENT without the trigger.")
        ev.append("Baseline + mutation request/response retained for deterministic replay.")
        if any(k in vc for k in ("ssrf", "xxe")):
            ev.append("Unique out-of-band correlation token that only a server-side fetch could return.")
        if any(k in vc for k in ("command", "sql", "race", "timing")):
            ev.append("Timing/repetition samples exceeding the measured noise floor across trials (where timing-based).")
    safety = rec.get("safety") or ("operator-gated" if (perm == "INTRUSIVE" or execu == "operator")
                                   else "passive-readonly" if perm == "PASSIVE" else "active-safe")
    cleanup = rec.get("cleanup") or (
        "Revert or flag any test artifact created (record/object/state) for operator cleanup; never destructive."
        if any(k in vc for k in _WRITE_CLASSES) else
        "None — non-destructive read/probe; no target state is modified.")
    replay = rec.get("replayable")
    return {"negative_control": neg, "evidence_requirements": ev, "safety": safety,
            "cleanup": cleanup, "replayable": True if replay is None else bool(replay)}


# ---------------------------------------------------------------------------- confidence (deterministic)
# Reliability scoring is a transparent sum of named factors -- reproducible, auditable, and tunable in
# one place. Higher confidence wins during dedup/merge; newer never auto-beats higher-confidence.
_STATUS_BASE = {"proven": 55, "experimental": 30, "catalogued": 22, "pending_review": 12,
                "superseded": 20, "deprecated": 10, "historical": 15, "conflicting": 10, "rejected": 0}


def confidence_score(t):
    """Return {'score': 0..100, 'tier': high|medium|low, 'factors': [{name, points}]} for a technique.
    Deterministic and explainable: every point is attributed to a named factor."""
    factors = []

    def add(name, pts):
        if pts:
            factors.append({"name": name, "points": pts})

    add("status:" + str(t.get("status", "catalogued")), _STATUS_BASE.get(t.get("status"), 10))
    labs = {e.get("lab") for e in (t.get("evidence") or []) if isinstance(e, dict) and e.get("lab")}
    add("oracle-validated x%d" % len(labs), min(24, 12 * len(labs)))
    if len(labs) >= 2:
        add("cross-lab generalized", 8)
    if any(p.get("known_exploited") for p in (t.get("provenance") or []) if isinstance(p, dict)):
        add("CISA KEV known-exploited", 15)
    sources = {p.get("source") for p in (t.get("provenance") or []) if isinstance(p, dict) and p.get("source")}
    add("multi-source corroboration", min(15, 5 * max(0, len(sources) - 1)))
    add("has payload", 3 if t.get("payloads") else 0)
    add("has detection logic", 3 if t.get("detection_logic") else 0)
    m = t.get("success_metrics") or {}
    succ, att = m.get("successes", 0), m.get("attempts", 0)
    if att:
        rate = succ / att
        add("execution success %d%%" % int(rate * 100), int(round((rate - 0.5) * 20)))  # +/-10 around 50%
    score = max(0, min(100, sum(f["points"] for f in factors)))
    tier = "high" if score >= 70 else ("medium" if score >= 40 else "low")
    return {"score": score, "tier": tier, "factors": factors}


# ---------------------------------------------------------------------------- adapters (source -> canonical)
def from_registry(rec, try_it=None, known_exploited=False, kev_cves=None, capec=None):
    """Adapt a techniques.py record + optional intel-feeds enrichment into a canonical Technique.
    The proven registry is the authoritative seed; this projects it into the first-class shape."""
    t = blank(rec.get("id", ""), _humanize(rec.get("id", "")))
    validated = rec.get("validated_on") or []
    t.update({
        "summary": rec.get("summary", ""),
        "vuln_class": rec.get("vuln_class", ""),
        "cwe": _as_list(rec.get("cwe")),
        "owasp": _as_list(rec.get("owasp")),
        "wstg": _as_list(rec.get("wstg")),
        "attack": _as_list(rec.get("mitre")),
        "capec": [c.get("id") if isinstance(c, dict) else c for c in (capec or [])],
        "discovery_methods": _as_list(rec.get("detect")),
        "detection_logic": _as_list(rec.get("oracle")),
        "payloads": ([{"name": "reference", "payload": try_it}] if try_it else []),
        "preconditions": _as_list(rec.get("preconditions")),
        "status": "proven" if validated else "catalogued",
        "transferable": bool(rec.get("transferable", True)),
        "permission": rec.get("permission", rec.get("execution", "auto")),
        "try_it": try_it,
    })
    # executable-knowledge proof contract (FP-safety differential + evidence obligations) — from the
    # record if it declares them, else derived deterministically from class + oracle.
    t.update(proof_contract(rec))
    # evidence: which labs/challenges proved it
    maps = rec.get("maps_to") or {}
    for lab in validated:
        t["evidence"].append({"lab": lab, "challenges": maps.get(lab, [])})
    # provenance: internal, authoritative, carrying the real-world KEV signal for confidence
    prov = {"source": "apolaki-registry", "tier": "internal", "ref": rec.get("id", "")}
    if known_exploited:
        prov["known_exploited"] = True
        prov["kev_cves"] = list(kev_cves or [])[:8]
    t["provenance"].append(prov)
    if capec:
        t["provenance"].append({"source": "mitre-capec", "tier": "A",
                                "ref": ",".join(c.get("id") if isinstance(c, dict) else c for c in capec[:6])})
    t["confidence"] = confidence_score(t)
    return t


def from_capec(capec_id, pattern, fetched_at=None):
    """Deterministically extract a CANDIDATE Technique from one MITRE CAPEC attack pattern.
    No LLM: CAPEC already IS a structured catalog of attack techniques. Lands as pending_review."""
    t = blank("capec_" + str(capec_id).replace("CAPEC-", ""), pattern.get("name", ""))
    t.update({
        "summary": pattern.get("name", ""),
        "cwe": list(pattern.get("cwes") or []),
        "capec": [capec_id],
        "preconditions": list(pattern.get("prerequisites") or []),
        "mitigations": list(pattern.get("mitigations") or []),
        "attack": list(pattern.get("attack") or []),
        "parents": ["capec_" + str(p).replace("CAPEC-", "") for p in (pattern.get("parents") or [])],
        "children": ["capec_" + str(c).replace("CAPEC-", "") for c in (pattern.get("children") or [])],
        # Tier-A deterministic extraction from an authoritative catalog -> trusted-but-unproven, no human
        # gate needed. (LLM-extracted prose lands as pending_review instead.)
        "status": "catalogued",
        "tags": [x for x in ("abstraction:" + pattern.get("abstraction", ""),
                             "severity:" + pattern.get("severity", ""),
                             "likelihood:" + pattern.get("likelihood", "")) if not x.endswith(":")],
        "provenance": [{"source": "mitre-capec", "tier": "A", "ref": capec_id, "fetched_at": fetched_at}],
    })
    t["confidence"] = confidence_score(t)
    return t


def validate(t):
    """Return a list of schema violations (empty = valid). Cheap deterministic gate before storing."""
    errs = []
    if not t.get("id"):
        errs.append("missing id")
    if t.get("status") not in STATUSES:
        errs.append("bad status: %r" % t.get("status"))
    for f in _LIST_FIELDS:
        if f in t and not isinstance(t[f], list):
            errs.append("field %s must be a list" % f)
    return errs
