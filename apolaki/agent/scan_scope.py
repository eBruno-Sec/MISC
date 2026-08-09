"""
Operator-selected assessment scope (#34) — include/exclude that actually gates, and says what it cost.

An operator scoping a scan needs three things, and most tools give only the first:

1. a short list of vulnerability CATEGORIES, not 39 internal `vuln_class` strings
2. **the consequences of excluding one** — engines do not stand alone, and turning one off can silently
   disable others downstream. That relationship is computable now: `engine_descriptor` knows which
   engines establish the observations other engines require
3. the exclusion recorded in the REPORT, because an untested class is not a clean one

Point 2 is the one that is usually guesswork. Excluding the engines that establish `authenticated` also
disables `cache_deception`, `jwt_forge`, `jwt_key_confusion`, `session_fixation` and `weak_2fa_bypass` —
not because anyone wrote that down, but because the effects model says so.

Pure throughout: no I/O, no network. The caller applies the decision.
"""
from __future__ import annotations

# Ten operator-facing categories over the 39 internal vuln_class values. Grouped by what an operator
# would think of as "one kind of testing", not by how the engines happen to be organised.
CATEGORIES = {
    "injection": {
        "label": "Injection (SQL, NoSQL, command, template, LDAP, XPath)",
        "classes": ("injection", "sql_injection", "nosql_injection", "command_injection",
                    "template_injection", "ldap_injection", "xpath_injection", "ssi_injection",
                    "css_injection"),
    },
    "access_control": {
        "label": "Broken access control (IDOR/BOLA, privilege, forced browsing)",
        "classes": ("access_control",),
    },
    "authentication": {
        "label": "Authentication & session",
        "classes": ("authentication", "broken_auth", "session", "cache_deception"),
    },
    "xss": {
        "label": "Cross-site scripting & client-side execution",
        "classes": ("xss", "client_side", "prototype_pollution"),
    },
    "ssrf_traversal": {
        "label": "SSRF, path traversal & XXE",
        "classes": ("ssrf", "path_traversal", "xxe"),
    },
    "crypto": {
        "label": "Cryptography & token handling",
        "classes": ("crypto_authz", "crypto_obscurity", "crypto_transport"),
    },
    "exposure": {
        "label": "Sensitive data exposure & misconfiguration",
        "classes": ("sensitive_exposure", "misconfig", "misconfiguration", "protection_failure",
                    "intelligence"),
    },
    "business_logic": {
        "label": "Business logic & workflow abuse",
        "classes": ("business_logic", "csrf", "redirect", "upload", "deserialization"),
    },
    "components": {
        "label": "Vulnerable & outdated components",
        "classes": ("vuln_component",),
    },
    "infrastructure": {
        "label": "Network services & OT/ICS (read-only)",
        "classes": ("network_service", "ics_ot"),
    },
    "llm": {
        "label": "LLM prompt injection & unsafe output handling",
        "classes": ("llm_prompt_injection", "llm_output_handling"),
    },
    # `misc` is the registry's own catch-all and deliberately has its own bucket rather than being
    # scattered: a category an operator cannot name is a category they cannot knowingly exclude, and
    # silently leaving it ungrouped means excluding "everything" would still run it.
    "other": {
        "label": "Other / uncategorised checks",
        "classes": ("misc",),
    },
}


def category_of(vuln_class: str) -> str:
    """Which operator category a vuln_class belongs to, or "" when it is not grouped. Pure."""
    v = (vuln_class or "").strip().lower()
    for name, spec in CATEGORIES.items():
        if v in spec["classes"]:
            return name
    return ""


def technique_ids_in(categories, all_techniques) -> list:
    """Technique ids belonging to any of `categories`. Pure — caller supplies the registry."""
    wanted = {c for c in (categories or []) if c in CATEGORIES}
    return sorted(t["id"] for t in (all_techniques or [])
                  if t.get("id") and category_of(t.get("vuln_class", "")) in wanted)


def resolve(excluded, all_techniques) -> dict:
    """Turn an operator's exclusions into the concrete set of technique ids to skip. Pure.

    Unknown category names are REPORTED, not ignored: a typo that silently excludes nothing would let an
    operator believe they had narrowed a scan when they had not."""
    excluded = [str(c).strip().lower() for c in (excluded or []) if str(c).strip()]
    unknown = sorted({c for c in excluded if c not in CATEGORIES})
    known = [c for c in excluded if c in CATEGORIES]
    skip = technique_ids_in(known, all_techniques)
    return {"excluded_categories": sorted(set(known)), "unknown_categories": unknown,
            "skipped_technique_ids": skip, "skipped_count": len(skip)}


def consequences(excluded, all_techniques, descriptors=None) -> dict:
    """What ELSE stops working, derived from the effects model rather than guessed. Pure.

    An engine that is not excluded can still be starved: if every engine that establishes an observation
    is switched off, everything gated on that observation can never fire. Presenting an exclusion without
    this is how an operator ends up believing a class was tested when nothing could reach it."""
    import engine_descriptor as ed
    d = descriptors if descriptors is not None else ed.build()
    skipped = set(resolve(excluded, all_techniques)["skipped_technique_ids"])
    if not skipped:
        return {"starved_observations": [], "unreachable_engines": []}

    # Which observations lose ALL of their producers?
    producers = {}
    for tid, desc in d.items():
        for obs in desc.get("establishes", ()):
            producers.setdefault(obs, set()).add(tid)
    starved = sorted(o for o, prod in producers.items() if prod and prod <= skipped)

    # Engines gated on a starved observation, that are not themselves excluded, and that have no other
    # route in (an always-on engine is reached without the observation).
    unreachable = sorted(
        tid for tid, desc in d.items()
        if tid not in skipped and not desc.get("always_on")
        and desc.get("requires") and any(r in starved for r in desc["requires"]))
    return {"starved_observations": starved, "unreachable_engines": unreachable}


def report_block(excluded, all_techniques) -> list:
    """Report lines recording what was excluded. UNTESTED IS NOT CLEAN, and a report that omits the
    operator's own scoping decision invites exactly that misreading. Pure."""
    r = resolve(excluded, all_techniques)
    if not r["excluded_categories"] and not r["unknown_categories"]:
        return []
    lines = ["**Excluded from this assessment (operator scoping)**", ""]
    for c in r["excluded_categories"]:
        lines.append("- %s — not tested. Absence of findings in this class means nothing."
                     % CATEGORIES[c]["label"])
    con = consequences(excluded, all_techniques)
    if con["unreachable_engines"]:
        lines += ["", "Excluding the above also left these engines unreachable, because nothing "
                      "remaining establishes what they require: %s."
                  % ", ".join("`%s`" % e for e in con["unreachable_engines"][:10])]
    if r["unknown_categories"]:
        lines += ["", "⚠ Unrecognised exclusion(s) ignored: %s. These excluded NOTHING — verify the "
                      "scope was what you intended." % ", ".join(r["unknown_categories"])]
    lines.append("")
    return lines
