"""
Shared triage/actionability rules used by BROKKR (Hephaestus) gating, SKULD
(Hades) gating, and MIMIR (Metis) overclaim guarding.

Pure and deterministic — no I/O, no DB. Keeping "is this finding worth acting
on" and "can this be called confirmed" in one place means every agent applies
the same rule instead of re-deriving it ad hoc.
"""
import re

# Titles that indicate a real, testable injection/access-control class — the
# vulnerability classes BROKKR should forge payloads for and SKULD should treat
# as grounds for post-exploitation analysis, even at medium confidence. Plain
# hygiene findings (SPF/DMARC/staging exposure) never match this pattern, so
# they stay non-actionable on their own — unless MIMIR chains them into an
# "Attack Path:" finding, which is always actionable regardless of this pattern.
INJECTION_TITLE_RE = re.compile(
    r"(sql injection|cross-site scripting|\bxss\b|parameter injection signal|"
    r"server-side template injection|\bssti\b|path traversal|local file inclusion|\blfi\b|"
    r"server-side request forgery|\bssrf\b|open redirect|\bidor\b|\bbola\b|"
    r"broken object level|broken access control|access control|cross-role access|"
    r"os command injection|command injection|crlf injection|response splitting|"
    r"http parameter pollution|cors misconfiguration|host header injection|"
    r"potential idor|graphql introspection)",
    re.IGNORECASE,
)

# ZAP ran real active tests against the target (not a passive/recon note) — a
# medium-or-higher ZAP alert is actionable as its own class even when its exact
# title doesn't happen to match the injection-keyword list above (ZAP's alert
# names are open-ended, e.g. "Missing Anti-clickjacking Header" wouldn't match
# INJECTION_TITLE_RE, but it's still real, tool-confirmed evidence, not a guess).
ZAP_ALERT_TITLE_RE = re.compile(r"^\[zap\]", re.IGNORECASE)

# Sensitive-file exposure titles (matches core.web_security.classify_sensitive_path_hit
# output) — used by SKULD's "confirmed sensitive file exposure" trigger.
SENSITIVE_FILE_TITLE_RE = re.compile(
    r"(environment file exposed|git (?:repository|config) exposed|"
    r"spring actuator environment exposed|configuration file exposed|backup/archive exposed)",
    re.IGNORECASE,
)

# A finding whose own title admits it is unconfirmed. These must never be treated
# as "confirmed" evidence by SKULD gating or MIMIR's attack-path severity, no
# matter how high a severity was attached to them.
HEDGE_TITLE_RE = re.compile(
    r"(suspected|possible|pending validation|\bsignal\b|candidate|manual confirm)",
    re.IGNORECASE,
)

# Titles that DO carry their own strong, independent proof (sqlmap's confirmed
# output, an out-of-band callback, execution confirmation, or differential
# boolean/time/UNION proof) even without external validation.
CONFIRMED_PROOF_TITLE_RE = re.compile(
    r"(sqlmap-confirmed|out-of-band confirmed|execution confirmed|dalfox confirmed|"
    r"union-based|boolean-based blind|time-based blind)",
    re.IGNORECASE,
)


def is_actionable_finding(title: str, severity: str) -> bool:
    """True when BROKKR should forge payloads for this finding.

    - critical/high: always actionable.
    - medium: actionable when the title is a real injection/access-control
      signal (SPF/DMARC/staging-exposure hygiene items never match and stay
      excluded), OR the finding came from OWASP ZAP's active scan — ZAP already
      ran a real test against the target, not a passive/recon guess, so a
      medium ZAP alert is real tool-confirmed evidence even when its specific
      alert name (open-ended, ZAP-defined text) doesn't match a known injection
      keyword.
    - "Attack Path:" (MIMIR-synthesized, correlated) findings are always
      actionable regardless of severity — that's the whole point of correlation.
    """
    t = (title or "").strip()
    sev = (severity or "").lower()
    if t.lower().startswith("attack path:"):
        return True
    if sev in ("critical", "high"):
        return True
    if sev == "medium" and (INJECTION_TITLE_RE.search(t) or ZAP_ALERT_TITLE_RE.search(t)):
        return True
    return False


def _is_confirmed_signal(title: str, severity: str, pattern: re.Pattern) -> bool:
    """True when a finding is both high-confidence (critical/high severity) AND
    not self-described as merely suspected/pending/a signal, AND matches the
    given category pattern. Used for SKULD's 'confirmed X' triggers, which must
    mean genuinely confirmed, not a relabeled suspicion."""
    t = title or ""
    if HEDGE_TITLE_RE.search(t):
        return False
    return (severity or "").lower() in ("critical", "high") and bool(pattern.search(t))


def skuld_trigger_reasons(exploitable_count: int, mimir_chains: int, findings: list) -> list:
    """Reasons SKULD (post-exploitation analysis) should run. `findings` is a list
    of {"title":..., "severity":...}-shaped dicts (typically the mission's current
    critical/high findings). Returns an empty list when none of the trigger
    conditions hold, meaning SKULD should be skipped — e.g. for a mission with
    only SPF/DMARC hygiene findings or a generic informational AI-surface note."""
    reasons = []
    if exploitable_count > 0:
        reasons.append(f"{exploitable_count} exploitable target(s) confirmed by BROKKR")
    if mimir_chains > 0:
        reasons.append(f"{mimir_chains} MIMIR attack path(s) correlated")
    if any(_is_confirmed_signal(f.get("title"), f.get("severity"), SENSITIVE_FILE_TITLE_RE)
           for f in findings):
        reasons.append("confirmed sensitive file exposure")
    if any(_is_confirmed_signal(f.get("title"), f.get("severity"), INJECTION_TITLE_RE)
           for f in findings):
        reasons.append("confirmed injection evidence")
    return reasons


def _is_confirmed_tier(finding: dict) -> bool:
    title = finding.get("title") or ""
    sev = (finding.get("severity") or "").lower()
    if HEDGE_TITLE_RE.search(title):
        return False
    return sev in ("critical", "high") or bool(CONFIRMED_PROOF_TITLE_RE.search(title))


def sanitize_attack_path(path: dict, source_findings: dict) -> dict:
    """Defend against MIMIR (an LLM) upgrading a suspected/signal-tier finding's
    certainty into 'confirmed SQL injection', 'RCE', or 'full compromise' language
    in an attack-path narrative or severity.

    `path` is one MIMIR attack_paths entry (title/severity/narrative/finding_ids).
    `source_findings` maps finding id -> {"title":..., "severity":...} for the
    findings this path references.

    If NONE of the referenced findings are confirmed-tier (proven by their own
    title/severity, not by what the model claims), the path's severity is
    unconditionally capped at medium and a disclaimer is prepended to the
    narrative — regardless of what certainty language the model used. This is a
    deterministic code guard, not a request to the model to behave; it holds even
    if the model ignores the prompt's instructions entirely."""
    refs = [source_findings.get(fid) for fid in (path.get("finding_ids") or [])]
    refs = [r for r in refs if r]
    any_confirmed = any(_is_confirmed_tier(r) for r in refs)

    out = dict(path)
    narrative = str(out.get("narrative") or "")
    if not any_confirmed:
        out["severity"] = "medium"
        if not narrative.lower().startswith("unconfirmed"):
            out["narrative"] = (
                "Unconfirmed — based on suspected/signal-tier findings only; none "
                "independently confirmed. " + narrative
            ).strip()
    return out
