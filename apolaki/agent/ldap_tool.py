"""LDAP injection engine (CWE-90), distilled from *Beginner Web Application Pentester* (Ali Abdollahi,
"Testing for LDAP injection"). Apps that authenticate or look users up against a directory build an LDAP
search filter by concatenating input, e.g. `(&(uid=USER)(userPassword=PASS))`. Unsanitised input lets an
attacker inject filter metacharacters ( ) * & | ! and break or subvert the filter.

CONFIRMATION IS LDAP-SPECIFIC. An exposed directory error remains proof. A silent directory gets an LDAP
filter predicate that is universally true and an otherwise identical impossible assertion, accepted only
when application semantics change (authenticated state, protected controls, or a strict record-set
superset). Status, response size, and error text do not participate in that boolean decision.

Pure logic here (payloads + LDAP-error oracle + finding); the HTTP transport lives in tools.
"""
from __future__ import annotations

import re

import semantic_differential as sd


def probes(orig: str) -> dict:
    """Filter-metacharacter breaks: an unbalanced parenthesis / stray operator makes the LDAP filter
    un-parseable, so a directory that concatenates input emits a filter/parse error."""
    o = orig or ""
    return {"paren": o + ")", "star_group": o + "*)(", "amp": o + "(", "pipe": o + "|("}


def boolean_pairs(orig: str, token: str) -> list:
    """LDAP filter truth/contradiction pairs for servers that suppress directory errors.

    The grouped pair targets the common `(&(uid=INPUT)(objectClass=person))` shape: it adds a second
    objectClass predicate that is universally true or deliberately impossible. The value pair covers the
    simple `(cn=INPUT)` search-filter shape. In each pair only one assertion value changes.
    """
    missing = "apolaki-never-%s" % re.sub(r"[^a-zA-Z0-9_-]", "", token or "missing")
    return [
        {"name": "and_group", "true": "*)(objectClass=*", "false": "*)(objectClass=%s" % missing},
        {"name": "value", "true": "*", "false": missing},
    ]


# Error signatures emitted by real LDAP stacks — present in a broken-filter response, absent from a normal
# one AND from SQL/XPath errors (which their own engines own). This is what makes the finding LDAP-SPECIFIC.
LDAP_ERRORS = [
    r"javax\.naming\.NamingException", r"javax\.naming\.directory", r"com\.sun\.jndi\.ldap",
    r"LDAPException", r"LDAP:\s*error code\s*\d+", r"error code 3\d\s*-\s*", r"Invalid DN syntax",
    r"Bad search filter", r"Protocol error", r"Object class violation", r"Invalid filter",
    r"ldap_search(?:_[a-z]+)?\(\)", r"ldap_(?:bind|modify|add|result)\(\)",
    r"supplied argument is not a valid ldap", r"AcceptSecurityContext error",
    r"System\.DirectoryServices", r"DirectoryServicesCOMException", r"OpenLDAP",
    r"IntStringPair", r"NDS error", r"Filter error", r"unbalanced parentheses",
]
_LDAP_RE = [re.compile(p, re.IGNORECASE) for p in LDAP_ERRORS]


def ldap_error(body: str) -> str:
    """The first LDAP-directory error signature in `body`, or '' — the confirming signal."""
    b = body or ""
    for rx in _LDAP_RE:
        m = rx.search(b)
        if m:
            return m.group(0)[:80]
    return ""


def evaluate(baseline_body: str, probe_body: str) -> dict:
    """Confirmed ONLY when a metacharacter break makes an LDAP-directory error appear that was NOT in the
    baseline. A generic 500 or a SQL/XPath error does NOT confirm (that would collide with those engines)."""
    sig = ldap_error(probe_body)
    if sig and not ldap_error(baseline_body):
        # PROTOCOL EVIDENCE: a directory error string the baseline did not carry. This is what
        # entitles the finding to name LDAP and to be graded `confirmed` (Q-187).
        return {"confirmed": True, "protocol_evidence": True,
                "oracle": "an LDAP directory error signature appeared after an unbalanced "
                "filter break ('%s') — the input is concatenated into an LDAP search filter" % sig}
    return {"confirmed": False, "oracle": "", "protocol_evidence": False}


def evaluate_boolean(true_body: str, false_body: str, true_payload: str, false_payload: str) -> dict:
    """Q-187. A BOOLEAN DIFFERENTIAL IS PROTOCOL-AGNOSTIC, so it cannot name LDAP on its own.

    `sd.evaluate` proves one thing: the parameter CHANGED the application's answer. That is real and
    worth reporting. It says nothing about the value being concatenated into an LDAP filter, and
    this function used to wrap that protocol-agnostic verdict in LDAP prose and hand it to
    `finding()`, which hardcodes `confidence: confirmed`, CWE-90 and CVSS 8.2.

    MEASURED: that produced "LDAP injection in form field 'new_db'", HIGH, confirmed, against
    `/phpmyadmin/db_create.php` -- a MySQL-only stack with no directory server anywhere near it. It
    recurred in five consecutive acceptance missions with byte-identical evidence.

    An endpoint that CREATES an object is the worst case for this oracle: any accepted value adds a
    record, so a record-set superset is guaranteed and means only "the write succeeded".

    `evaluate` above is different and keeps its confirmation, because it HAS protocol evidence: an
    LDAP directory error signature that is absent from the baseline. The rule is the general one --
    a protocol-specific claim needs protocol-specific evidence -- and it is the reason the two
    functions now return different `protocol_evidence`.
    """
    ev = sd.evaluate(true_body, false_body, true_payload, false_payload)
    if not ev["confirmed"]:
        return {"confirmed": False, "oracle": "", "protocol_evidence": False}
    return {"confirmed": True, "protocol_evidence": False, "signal": ev.get("signal", ""),
            "oracle": ("an LDAP boolean differential changed only one filter assertion from universally "
                       "true to an impossible value; %s" % ev["oracle"])}


def may_claim_ldap(ev: dict, where: str) -> bool:
    """Q-187. Is this verdict entitled to NAME LDAP, or has it only shown a differential?

    The decision lives HERE, not spelled out at each call site, because three mutation tests proved
    an inline expression is unpinnable: a test that re-derives the caller's expression passes while
    the caller does something else entirely. One function, one rule, one place to test.

      * protocol evidence (an LDAP directory error the baseline lacked) -> always entitled
      * a record-set superset on a FORM BODY -> NOT entitled. That path POSTs to a write endpoint,
        and an endpoint that CREATES an object gains a record for ANY value it accepts, so the
        superset means the write succeeded. MEASURED: this produced "LDAP injection in form field
        'new_db'" HIGH/confirmed against /phpmyadmin/db_create.php -- a MySQL-only stack -- in five
        consecutive missions, citing phpMyAdmin's own font-size dropdown as the gained records.
      * anything else (auth_state on a form, any signal on a query parameter) -> entitled. A silent
        LDAP server suppresses its errors and is detectable ONLY by the record differential on a
        search, which is the whole reason `boolean_pairs` exists; refusing that would trade a false
        positive for a false negative on the real bug.
    """
    if ev.get("protocol_evidence"):
        return True
    return not (where == "form field" and ev.get("signal") == "record_set")


def finding(url: str, param: str, where: str, oracle: str, protocol_evidence: bool = True) -> dict:
    """Q-187. `protocol_evidence` decides whether this may CLAIM LDAP and be graded `confirmed`.

    Default True so every existing caller keeps its behaviour; the boolean-differential path passes
    False and gets a lead that describes what was actually observed. A finding that names a protocol
    it has no evidence for is the false-positive shape this whole cycle has been removing.
    """
    if not protocol_evidence:
        return {
            "title": "Parameter reaches a server-side decision in %s '%s'" % (where, param),
            "param": param, "severity": "medium", "family": "boolean_differential",
            "confidence": "candidate", "target": url, "cwe": "CWE-20",
            "evidence": "The %s '%s' changed the application's answer between a universally-true and "
                        "an impossible assertion. %s" % (where, param, oracle),
            "success_oracle": oracle,
            "proof_gap": ["no protocol evidence: nothing observed identifies the sink as an LDAP "
                          "filter, so the sink could equally be SQL, XPath, a template, or ordinary "
                          "application branching"],
            "reproduction_steps": ["Send the true/false assertion pair in '%s'" % param,
                                   "Compare the two responses on the same page",
                                   "Identify the sink before claiming a protocol"],
            "impact": "A parameter that changes a server-side decision may reach an injectable sink; "
                      "which sink is not yet established.",
            "remediation": "Identify the sink, then apply the encoder for that sink.",
            "tags": ["differential"]}
    return {
        "title": "LDAP injection in %s '%s'" % (where, param),
        # Q-046: carry the parameter as DATA. This builder is the one that proved why -- `where`
        # sits between `in` and the quote, so a reader recovering the name from this title gets
        # nothing, and five distinct findings deduped into one.
        "param": param,
        "severity": "high", "family": "ldap_injection", "confidence": "confirmed", "target": url,
        "cwe": "CWE-90", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "cvss_score": 8.2,
        "evidence": "The %s '%s' is concatenated into an LDAP search filter. %s" % (where, param, oracle),
        "success_oracle": oracle,
        "reproduction_steps": ["Send the recorded LDAP filter probe in '%s'" % param,
                               "Replay its structurally identical impossible assertion as a negative control",
                               "Confirm the recorded directory error or semantic auth/record-set split"],
        "impact": ("LDAP injection lets an attacker subvert the directory query to bypass authentication (filter "
                   "tautology), enumerate directory objects, or read attributes they should not see."),
        "remediation": ("Escape LDAP filter metacharacters per RFC 4515 (use the platform's LDAP encoder), bind "
                        "with parameterised filters, and validate input against a strict allowlist."),
        "tags": ["ldap", "injection", "cwe-90"],
    }
