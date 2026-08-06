"""CVSS v4.0 support (Codex cross-check Tier-2 #6), PARALLEL to the existing v3.1 path — never a replacement.

What is AUTHORITATIVE here (exact, deterministic, verifiable):
  * A full CVSS:4.0 vector PARSER + VALIDATOR (all Base metrics required; Threat/Environmental/Supplemental
    optional and value-checked).
  * The CVSS 4.0 MacroVector (EQ1..EQ6 equivalence classes) — these are documented RULES, computed exactly.
  * Nomenclature (CVSS-B / -BT / -BE / -BTE) from which metric groups are present.
  * The vulnerable-system (VC/VI/VA) vs subsequent-system (SC/SI/SA) impact split — the v4 feature that fits
    Apolaki's chain discipline.

What is an HONEST ESTIMATE (clearly labelled, NOT the FIRST normative calculator):
  * The 0-10 base SCORE. The official CVSS 4.0 score is a MacroVector lookup table we do not ship, so we do
    NOT fabricate the normative decimal. `base_score()` returns a deterministic, monotonic Apolaki estimate
    with `estimated=True` and `method="apolaki_macrovector_estimate"`, and always returns the parsed vector so
    an authoritative calculator can produce the normative score. Monotonic: a strictly-worse vector never
    scores lower.

RULES: CVSS scores ATOMIC vulnerabilities only. A chain severity is Apolaki impact-path severity, NEVER a
CVSS vector (see report_integrity.reject_chain_cvss).
"""
from __future__ import annotations

PREFIX = "CVSS:4.0"

# metric -> allowed values. Base metrics are mandatory; the rest optional.
_BASE = {
    "AV": ("N", "A", "L", "P"), "AC": ("L", "H"), "AT": ("N", "P"), "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"), "VC": ("H", "L", "N"), "VI": ("H", "L", "N"), "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"), "SI": ("H", "L", "N"), "SA": ("H", "L", "N"),
}
_THREAT = {"E": ("X", "A", "P", "U")}
_ENV = {
    "CR": ("X", "H", "M", "L"), "IR": ("X", "H", "M", "L"), "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"), "MAC": ("X", "L", "H"), "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"), "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"), "MVI": ("X", "H", "L", "N"), "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"), "MSI": ("X", "S", "H", "L", "N"), "MSA": ("X", "S", "H", "L", "N"),
}
_SUPP = {"S": ("X", "N", "P"), "AU": ("X", "N", "Y"), "R": ("X", "A", "U", "I"),
         "V": ("X", "D", "C"), "RE": ("X", "L", "M", "H"), "U": ("X", "Clear", "Green", "Amber", "Red")}
_ALL = {**_BASE, **_THREAT, **_ENV, **_SUPP}


def parse_vector(vector: str) -> dict:
    """Parse + VALIDATE a CVSS:4.0 vector string. Returns the metrics dict (raises ValueError on anything
    malformed: bad prefix, unknown metric, illegal value, duplicate, or a missing mandatory Base metric)."""
    s = str(vector or "").strip()
    if not s.startswith(PREFIX + "/"):
        raise ValueError("not a CVSS:4.0 vector (missing '%s/' prefix)" % PREFIX)
    metrics: dict = {}
    for part in s[len(PREFIX) + 1:].split("/"):
        if not part:
            raise ValueError("empty metric segment")
        if ":" not in part:
            raise ValueError("malformed metric segment %r" % part)
        k, v = part.split(":", 1)
        if k not in _ALL:
            raise ValueError("unknown metric %r" % k)
        if v not in _ALL[k]:
            raise ValueError("illegal value %r for metric %r" % (v, k))
        if k in metrics:
            raise ValueError("duplicate metric %r" % k)
        metrics[k] = v
    missing = [k for k in _BASE if k not in metrics]
    if missing:
        raise ValueError("missing mandatory Base metric(s): %s" % ",".join(missing))
    return metrics


def is_valid(vector: str) -> bool:
    try:
        parse_vector(vector)
        return True
    except Exception:
        return False


def _eff(metrics: dict, key: str, default: str = "X") -> str:
    """Effective value honouring a Modified (Mxx) override when present and not X."""
    mod = metrics.get("M" + key, "X")
    if mod and mod != "X":
        return mod
    return metrics.get(key, default)


def macrovector(metrics: dict) -> str:
    """The CVSS 4.0 MacroVector as a 6-char string EQ1..EQ6 (lower digit = more severe). Computed from the
    documented equivalence-class RULES (exact, not a lookup table)."""
    av, pr, ui = _eff(metrics, "AV"), _eff(metrics, "PR"), _eff(metrics, "UI")
    ac, at = _eff(metrics, "AC"), _eff(metrics, "AT")
    vc, vi, va = _eff(metrics, "VC"), _eff(metrics, "VI"), _eff(metrics, "VA")
    sc, si, sa = _eff(metrics, "SC"), _eff(metrics, "SI"), _eff(metrics, "SA")
    e = metrics.get("E", "X"); e = "A" if e == "X" else e
    cr = metrics.get("CR", "X"); cr = "H" if cr == "X" else cr
    ir = metrics.get("IR", "X"); ir = "H" if ir == "X" else ir
    ar = metrics.get("AR", "X"); ar = "H" if ar == "X" else ar
    msi, msa = metrics.get("MSI", "X"), metrics.get("MSA", "X")

    # EQ1: AV/PR/UI
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2
    # EQ2: AC/AT
    eq2 = 0 if (ac == "L" and at == "N") else 1
    # EQ3: VC/VI/VA
    if vc == "H" and vi == "H":
        eq3 = 0
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = 1
    else:
        eq3 = 2
    # EQ4: SC/SI/SA (+ modified Safety)
    if msi == "S" or msa == "S":
        eq4 = 0
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = 1
    else:
        eq4 = 2
    # EQ5: Exploit maturity (X->A)
    eq5 = {"A": 0, "P": 1, "U": 2}.get(e, 0)
    # EQ6: environmental requirement paired with impact
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = 0
    else:
        eq6 = 1
    return "%d%d%d%d%d%d" % (eq1, eq2, eq3, eq4, eq5, eq6)


def severity_rating(score: float) -> str:
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def nomenclature(metrics: dict) -> str:
    """CVSS-B / -BT / -BE / -BTE from which metric groups carry non-default values."""
    has_t = metrics.get("E", "X") != "X"
    has_e = any(metrics.get(k, "X") != "X" for k in _ENV)
    if has_t and has_e:
        return "CVSS-BTE"
    if has_t:
        return "CVSS-BT"
    if has_e:
        return "CVSS-BE"
    return "CVSS-B"


# per-EQ severity weights (lower macrovector digit = worse). Used ONLY for the transparent estimate.
_EQ_WEIGHT = ((2.7, 1.35, 0.0), (1.6, 0.0), (2.6, 1.3, 0.0), (1.9, 0.95, 0.0), (0.9, 0.45, 0.0), (0.3, 0.0))


def base_score(vector: str) -> dict:
    """Deterministic Apolaki ESTIMATE of the CVSS 4.0 base score (NOT the FIRST normative calculator — the
    official score is a MacroVector lookup table we do not ship). Monotonic in severity. Returns the parsed
    vector + macrovector + nomenclature + impact split so an authoritative tool can compute the normative
    value. `estimated` is always True."""
    metrics = parse_vector(vector)
    mv = macrovector(metrics)
    total = 0.0
    for i, digit in enumerate(int(c) for c in mv):
        weights = _EQ_WEIGHT[i]
        total += weights[digit] if digit < len(weights) else 0.0
    score = round(min(10.0, total), 1)
    # a vector with zero impact on both systems is a 0.0 by definition
    if all(_eff(metrics, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):
        score = 0.0
    return {
        "version": "4.0", "vector": PREFIX + "/" + "/".join("%s:%s" % (k, metrics[k]) for k in metrics),
        "metrics": metrics, "macrovector": mv, "nomenclature": nomenclature(metrics),
        "base_score": score, "base_severity": severity_rating(score),
        "vulnerable_system_impact": {"C": _eff(metrics, "VC"), "I": _eff(metrics, "VI"), "A": _eff(metrics, "VA")},
        "subsequent_system_impact": {"C": _eff(metrics, "SC"), "I": _eff(metrics, "SI"), "A": _eff(metrics, "SA")},
        "estimated": True, "method": "apolaki_macrovector_estimate",
        "note": ("Apolaki estimate from the CVSS 4.0 MacroVector — NOT the FIRST normative score. The parsed "
                 "vector is authoritative; use an official CVSS 4.0 calculator for the normative decimal."),
    }
