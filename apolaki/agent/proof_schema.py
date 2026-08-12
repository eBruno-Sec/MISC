"""
Family-specific PROOF requirements for a CONFIRMED finding (CHAD re-audit #5).

The old rule — "any text in `evidence` makes a confirmed finding pass" — does not prove
exploitability. A finding may only be labelled `confirmed` when it carries the structured proof
its vulnerability class actually requires:

  - request + response evidence (the oracle saw the real exchange, not a guess)
  - the identity / session role under which it was observed (for auth classes)
  - a CONTROL request that rules out the benign explanation (anon-denied, id+1 differs, ...)
  - an observed security impact
  - reproducible steps (or an evidence string a human can replay)

This is the truth-first gate: if the family's proof is absent, the finding is a LEAD, not a
confirmation. `validate_confirmed` returns (ok, missing[]) so callers can (a) refuse to store a
weak confirm, (b) fail a benchmark that produced one, and (c) demote it to a lead. Pure; no I/O.
"""
from __future__ import annotations

# CWE -> family fallback so a finding that carries only a CWE still gets the right proof rules.
_CWE_FAMILY = {
    "CWE-639": "idor", "CWE-566": "idor", "CWE-284": "access_control", "CWE-285": "access_control",
    "CWE-862": "access_control", "CWE-863": "access_control", "CWE-306": "missing_authentication",
    "CWE-89": "sql_injection", "CWE-79": "xss", "CWE-200": "sensitive_exposure",
    "CWE-201": "sensitive_exposure", "CWE-264": "sensitive_exposure", "CWE-918": "ssrf",
    "CWE-1104": "vulnerable_component", "CWE-1035": "vulnerable_component",
}

# Per-family proof contract. `signals` = groups of interchangeable substrings; the evidence must
# contain at least one substring FROM EACH group (AND across groups, OR within a group). This encodes
# "you must show BOTH an accepted request AND the control that rules out the benign case", etc.
_FAMILY = {
    # access-control classes: an ownership/authorization proof is mandatory (CHAD: "Confirmed
    # access-control findings need ownership or authorization proof").
    "idor": {"impact": True, "signals": [
        ["owner", "ownership", "cross-user", "identical", "same object", "owner-created"],   # the cross-user access
        # the control that proves it isn't a benign/shared resource: an anon-denied control, an
        # id+1 differential, OR definitive ownership by creation (we created it with our marker).
        ["denied", "401", "403", "anon", "different data", "object-specific",
         "owner-created", "created object", "our marker", "marker"],
    ]},
    "access_control": {"impact": True, "signals": [
        ["owner", "ownership", "role", "persona", "privileg", "cross-user", "unauthor", "owner-created"],
        ["denied", "401", "403", "200", "anon", "differ", "owner-created", "created object", "marker"],
    ]},
    "missing_authentication": {"impact": True, "signals": [
        ["anon", "unauthenticated", "without auth", "no session"],
        ["200", "same", "identical", "protected", "authed"],
    ]},
    "sql_injection": {"impact": True, "signals": [
        ["union", "extracted", "sql", "sqlstate", "ora-", "syntax", "database"],
        ["payload", "'", "injected", "boolean", "time-based", "error-based"],
    ]},
    "xss": {"impact": True, "signals": [
        ["reflect", "executed", "alert", "script", "marker", "dom"],
        ["<", "payload", "context", "unencoded", "injected"],
    ]},
    "ssrf": {"impact": True, "signals": [
        ["ssrf", "internal", "metadata", "169.254", "localhost", "oob", "callback"],
        ["request", "fetched", "response", "reached"],
    ]},
    "sensitive_exposure": {"impact": True, "signals": [
        ["exposed", "leak", "listing", "public", "disclosed", "readable"],
        ["200", "bucket", "file", "key", "token", "data", "response"],
    ]},
    # exposed/verified credentials (CWE-522) — the proof is "a discovered credential yielded a valid
    # authenticated session", NOT an anon-access control (so it must never inherit the access_control
    # rule). Requires the credential noun AND the verification/exposure signal.
    "exposed_credentials": {"impact": True, "signals": [
        ["credential", "password", "login", "account", "api key", "apikey", "secret", "token"],
        ["valid", "authenticated session", "session cookie", "token issued", "session issued",
         "logged in", "working", "issued", "exposed", "harvested", "reused"],
    ]},
    # SCA (Q-021A). A version falling inside a published range is a DATABASE MATCH, not an
    # observation — the old producer stamped `confirmed` on exactly that while its own impact text
    # said reachability was never proven. The proof here is the CVE's OWN BEHAVIOUR: the exact CVE,
    # a behaviour differential, and the structurally identical TRIGGER-ABSENT control that did not
    # reproduce it. Presence evidence ("angular@1.7.7 from script-filename: …") carries none of
    # these three and is correctly demoted to a lead.
    "vulnerable_component": {"impact": True, "signals": [
        ["cve-"],                                                   # the exact CVE exercised
        ["behaviour differential", "behavior differential", "negative control", "trigger-absent",
         "trigger absent"],                                         # a probe, not a table lookup
        ["trigger", "observed", "reproduced", "fired"],             # what was actually seen
    ]},
}

# Default for any other family: still require a non-trivial evidence string + an impact.
_DEFAULT = {"impact": True, "signals": [["->", "http", "200", "request", "response", "payload", "status"]]}

_MIN_EVIDENCE_LEN = 20


# Normalize the family names Apolaki's various tools emit to the canonical proof-rule keys.
_ALIAS = {"sqli": "sql_injection", "nosqli": "sql_injection", "bola_idor": "idor", "bola": "idor",
          "broken_auth": "access_control", "broken_access_control": "access_control",
          "information_disclosure": "sensitive_exposure", "info_disclosure": "sensitive_exposure",
          "vuln_component": "vulnerable_component", "sca": "vulnerable_component"}


def family_of(finding: dict) -> str:
    f = finding or {}
    cwe = str(f.get("cwe") or "").upper().strip()
    # CWE-522 (Insufficiently Protected Credentials) is an EXPOSED-CREDENTIALS class, not an
    # access-control / auth-bypass class. It must NOT inherit broken_auth→access_control, whose proof
    # rule demands anon-access signals a credential-exposure proof can never carry — that mis-mapping
    # wrongly demoted a genuinely-verified credential to a lead (evidence said "verified working" while
    # the status read "lead", a self-contradiction). Give the unambiguous CWE precedence over the
    # coarse family label; auth-BYPASS findings carry CWE-287/305/306 and still route to access_control.
    if cwe == "CWE-522":
        return "exposed_credentials"
    fam = str(f.get("family") or "").strip().lower()
    if not fam:
        fam = _CWE_FAMILY.get(cwe, "")
    return _ALIAS.get(fam, fam)


def validate_confirmed(finding: dict) -> tuple:
    """(ok, missing[]). A non-confirmed finding is vacuously ok (leads carry no proof burden).
    A confirmed finding must have a substantive evidence string, an impact (when the family needs
    one), reproducible steps or replayable evidence, and the family's required proof signals."""
    f = finding or {}
    if str(f.get("confidence") or "").lower() != "confirmed":
        return True, []
    missing = []
    ev = str(f.get("evidence") or "")
    evl = ev.lower()
    if len(ev.strip()) < _MIN_EVIDENCE_LEN:
        missing.append("evidence(substantive)")
    # reproducible steps OR an evidence string a human can replay (an exchange, a payload, a verb)
    import re as _re
    has_repro = (bool(str(f.get("reproduction_steps") or "").strip())
                 or "->" in ev or "http" in evl or "payload" in evl
                 or bool(_re.search(r"\b(get|post|put|delete|select|union|curl)\b", evl)))
    if not has_repro:
        missing.append("reproduction_or_request_response")

    rules = _FAMILY.get(family_of(f), _DEFAULT)
    if rules.get("impact") and not str(f.get("impact") or "").strip():
        missing.append("impact")
    for group in rules.get("signals", []):
        if not any(tok in evl for tok in group):
            missing.append("evidence_signal:%s" % group[0])
    return (len(missing) == 0), missing


# The access-control classes CHAD named explicitly ("Confirmed access-control findings need ownership
# or authorization proof") — enforced live BY DEFAULT because a false cross-user/privilege confirm is
# the most damaging, and Apolaki's real producers for these already emit the required proof. Other
# families are validated by the benchmark asserter but only demoted live when APOLAKI_ENFORCE_PROOF=all,
# so a producer whose evidence phrasing isn't yet audited can't be silently downgraded (no new FN bug).
#
# `vulnerable_component` joins the set (Q-021A). The narrow default is a sequencing rule, not a
# permanent one: a family is enforceable once its producers' evidence phrasing HAS been audited. This
# family has exactly one production producer (`dependency_intel.vulnerable_component_finding`), it was
# audited in slice 1, and it now emits the behaviour-differential evidence on the confirmed path and a
# `lead` otherwise. So enforcement cannot manufacture a false negative here — the only row it can
# demote is one claiming `confirmed` on presence evidence alone, which is precisely the defect. The
# set is widened by ONE entry; every other family keeps the deliberate no-new-FN default.
_DEFAULT_ENFORCE = ("idor", "access_control", "missing_authentication", "bola_idor", "bfla",
                    "vulnerable_component")


#: The vocabulary of a confidence value that is NOT a proof. `demote_unproven` writes "lead" into this
#: set; producers elsewhere use the neighbouring words. Anything that renders, counts, scores or exports
#: a finding must consult ONE definition of "confirmed" — three private copies is how the HTML report
#: came to stamp CONFIRMED on rows the proof gate had already demoted.
UNPROVEN_CONFIDENCE = frozenset({"lead", "candidate", "unconfirmed", "informational", "info", "tentative"})


def is_confirmed(finding: dict) -> bool:
    """True when this finding still carries a confirmed verdict. A finding with no `confidence` key at
    all is confirmed by convention (most engines only set the field when demoting). Pure."""
    if not isinstance(finding, dict):
        return False
    return str(finding.get("confidence") or "confirmed").strip().lower() not in UNPROVEN_CONFIDENCE


# ══════════════════════════════════════════════════════════════════════════════════════════════
# PROOF KIND — the SHAPE of evidence a finding class can have (#123, Breaker item 1)
# ══════════════════════════════════════════════════════════════════════════════════════════════
# The evidence contract assumed ONE shape for every finding: baseline + mutation + differential +
# replay. `837b1f0` fixed the case where that experiment was AVAILABLE and not run — the claim was
# unproven. This is the other case, and it is a different error: for a source-derived finding the
# experiment CANNOT EXIST. `Cipher.getInstance("DES")` at a known file and line has no request, no
# baseline and no mutation. Demanding a request differential of it is a category error, and
# answering "not recorded" is wrong too — that says the experiment was available and skipped.
#
# So the contract is per proof kind, and the control question gets a THIRD answer. Same move
# `dependency_intel` already makes with `version_confidence` (how sure of the version) vs
# `component_status` (was the CVE's own behaviour seen): two questions, two named fields, rather
# than one overloaded word. This lives here, beside `is_confirmed`, because every surface that
# renders a proof claim must read the SAME predicate — three private copies of "confirmed" is how
# the HTML report came to stamp CONFIRMED on rows the proof gate had already demoted.

BEHAVIOURAL = "behavioural"          # DAST: a request/response differential over a stable baseline
SOURCE_DERIVED = "source-derived"    # SAST: a static call site; no request exists, even in principle

#: Answers "was the benign explanation ruled out?" — and the third value is the point.
CONTROL_RECORDED = "recorded"                # an artifact from a control that actually ran
CONTROL_NOT_RECORDED = "not_recorded"        # the experiment applies to this kind and was not run
CONTROL_NOT_APPLICABLE = "not_applicable"    # no request-differential can exist for this proof kind

#: Keys under which a producer records that a negative control ACTUALLY RAN. `report.control_ran`
#: reads this list through `control_status` so the set has ONE definition; a finding carrying none of
#: these has no control artifact, whatever its family's contract says such a control would look like.
CONTROL_KEYS = ("negative_controls", "controls", "control", "control_evidence", "control_response")

#: The sibling clean call site a source rule must NOT match — the counter-example that would falsify
#: the finding. This is a real negative control; it is simply not a request. It is the same discipline
#: `agent/tests/test_codeassisted_negative_controls.py` enforces on the code-assisted lane: a rule
#: that fires on the clean sibling is a signature, not a detector.
#:
#: The authority on what is weak is `codereview`, so this table is a FALLBACK, not the design — a
#: producer that states its own `counter_example` on the finding wins (see docs/handoff/evidence.md
#: patch 6b). An unknown family yields None and the prose degrades to the generic shape; it must
#: never invent a specific sibling it cannot name, which is the exact failure being fixed here.
COUNTER_EXAMPLE = {
    "weak_crypto": 'Cipher.getInstance("AES/GCM/NoPadding") — the same receiver, one different '
                   'argument, and the rule must not fire',
    "weak_hash": 'MessageDigest.getInstance("SHA-256") — the same receiver, one different argument, '
                 'and the rule must not fire',
    "weak_random": "SecureRandom() / random.SystemRandom() — the same method name behind a CSPRNG "
                   "receiver, and the rule must not fire",
}
_COUNTER_EXAMPLE_BY_CWE = {"CWE-327": "weak_crypto", "CWE-328": "weak_hash",
                           "CWE-330": "weak_random", "CWE-338": "weak_random",
                           "CWE-337": "weak_random"}

#: Markers a producer stamps on a source-derived finding. `codereview._source_finding` writes all
#: three; matching any one of them is deliberate, so a lane that adopts only part of the vocabulary
#: is still classified honestly rather than defaulting to "behavioural" and inheriting a request
#: contract it cannot satisfy.
_SOURCE_MARKERS = (("provenance", "source-derived"), ("lane", "code-assisted"),
                   ("analysis", "static-call-site"))


def proof_kind(finding: dict) -> str:
    """The SHAPE of evidence this finding can have: BEHAVIOURAL or SOURCE_DERIVED. Pure.

    Defaults to BEHAVIOURAL: every HTTP probe emits a finding with no lane marker at all, and the
    request-differential contract is the right one for them. Only an explicit source-derived marker
    moves a finding out of it — a default that silently declared findings exempt from the request
    contract would be a way to lose the control requirement, not to state it honestly."""
    if not isinstance(finding, dict):
        return BEHAVIOURAL
    for key, want in _SOURCE_MARKERS:
        if str(finding.get(key) or "").strip().lower() == want:
            return SOURCE_DERIVED
    return BEHAVIOURAL


def control_status(finding: dict) -> str:
    """Was the benign explanation ruled out, and could it have been? Three-valued. Pure.

    THE ARTIFACT IS CHECKED FIRST, ON PURPOSE. Deciding NOT_APPLICABLE from the lane label before
    looking would be a guard that checks a DECLARATION instead of a fact: a finding that is
    source-derived AND carries a recorded control (a SAST lead later confirmed by a probe) would
    have had its real artifact suppressed by its own label. If an experiment was actually recorded,
    it was evidently applicable. No producer emits that shape today, so this is latent rather than
    live -- which is exactly when it is cheap to get right, and it is what keeps `report.control_ran`
    byte-for-byte unchanged for EVERY input rather than only for the ones in the fixtures.

    Deliberately strict on the artifact: an empty list or a blank string is a producer recording
    that it ran NO control, not that it ran some."""
    if not isinstance(finding, dict):
        return CONTROL_NOT_RECORDED
    for k in CONTROL_KEYS:
        v = finding.get(k)
        if isinstance(v, (list, tuple, dict)) and len(v):
            return CONTROL_RECORDED
        if isinstance(v, str) and v.strip():
            return CONTROL_RECORDED
    if proof_kind(finding) == SOURCE_DERIVED:
        return CONTROL_NOT_APPLICABLE
    return CONTROL_NOT_RECORDED


def counter_example(finding: dict):
    """The sibling clean call site that would falsify this source rule, or None when unknown. Pure.
    A producer-supplied `counter_example` beats the table; an unknown family returns None so the
    caller can say "the sibling clean call site" instead of naming one that may not exist."""
    if not isinstance(finding, dict):
        return None
    own = str(finding.get("counter_example") or "").strip()
    if own:
        return own
    fam = str(finding.get("family") or "").strip().lower()
    if fam not in COUNTER_EXAMPLE:
        fam = _COUNTER_EXAMPLE_BY_CWE.get(str(finding.get("cwe") or "").upper().strip(), "")
    return COUNTER_EXAMPLE.get(fam)


#: The CANONICAL key for a finding's machine-checkable success oracle. Measured across the platform:
#: 38 modules mention `success_oracle` and 87 sites write a plain `oracle`, and the two CONSUMERS
#: disagreed with each other — `poc_bundle` read only `oracle` (so every family whose producer chose
#: `success_oracle` reached the PoC bundle with an empty oracle) while `report_integrity_check` read
#: only `success_oracle` (so every family that chose `oracle` was invisible to its has-an-oracle
#: check). Neither spelling is dead, so neither is deleted: producers keep writing whichever they
#: already write, and everything that READS an oracle goes through `oracle_of` / the normalisation
#: below. Note `oracle` is also a key on techniques, candidate-validation records and retest plans —
#: different objects with their own meaning. This is about FINDINGS only.
ORACLE_KEY = "success_oracle"
_ORACLE_ALIASES = (ORACLE_KEY, "oracle")


def oracle_of(finding: dict) -> str:
    """This finding's success oracle, whichever spelling its producer used. The canonical key wins.
    Pure; returns "" when the finding has neither."""
    if not isinstance(finding, dict):
        return ""
    for k in _ORACLE_ALIASES:
        v = str(finding.get(k) or "").strip()
        if v:
            return v
    return ""


def normalize_oracle(finding: dict) -> dict:
    """Return the finding with the CANONICAL oracle key populated from whichever spelling it has.
    Non-destructive (copies only when something actually changes) and additive — the legacy `oracle`
    key is left in place, so a producer or consumer still using it keeps working."""
    if not isinstance(finding, dict):
        return finding
    v = oracle_of(finding)
    if not v or str(finding.get(ORACLE_KEY) or "").strip():
        return finding
    g = dict(finding)
    g[ORACLE_KEY] = v
    return g


def demote_unproven(findings: list, enforce_families=None) -> list:
    """Return findings with any confirmed-but-unproven item demoted to a lead + tagged, so a weak
    'confirmed' can never reach a report. Non-destructive: copies, never drops. `enforce_families`
    limits which families are enforced ('all' or None = the default access-control set; the string
    'all' enforces every family)."""
    import os
    mode = enforce_families if enforce_families is not None else os.environ.get("APOLAKI_ENFORCE_PROOF", "")
    out = []
    for f in findings or []:
        # ONE chokepoint for the oracle-key vocabulary. `db.get_findings_gated` routes everything
        # that PRESENTS a finding through here, so normalising the canonical key once means no
        # consumer has to know which spelling its producer happened to pick.
        f = normalize_oracle(f)
        fam = family_of(f)
        enforce = (mode == "all") or (fam in _DEFAULT_ENFORCE)
        if not enforce:
            out.append(f)
            continue
        ok, missing = validate_confirmed(f)
        if not ok:
            g = dict(f)
            g["confidence"] = "lead"
            g["tags"] = list(dict.fromkeys((g.get("tags") or []) + ["needs-confirmation", "proof-incomplete"]))
            g["proof_gap"] = missing
            out.append(g)
        else:
            out.append(f)
    return out
