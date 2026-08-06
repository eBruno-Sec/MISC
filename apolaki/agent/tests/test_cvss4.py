"""CVSS v4.0 (Codex Tier-2 #6): the PARSER + MacroVector are authoritative/exact; the base SCORE is an
honestly-labelled deterministic Apolaki estimate (monotonic; not the FIRST normative decimal)."""
import pytest

import cvss4 as V

_MAX = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
_MIN = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"


def test_parse_valid_vector():
    m = V.parse_vector(_MAX)
    assert m["AV"] == "N" and m["VC"] == "H" and m["SA"] == "H"
    assert V.is_valid(_MAX) and V.is_valid("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A")


@pytest.mark.parametrize("bad", [
    "",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",          # wrong version
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H",  # missing SA (mandatory base)
    "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",  # illegal value
    "CVSS:4.0/XX:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",  # unknown metric
    "CVSS:4.0/AV:N/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",  # duplicate
])
def test_reject_malformed(bad):
    assert V.is_valid(bad) is False
    with pytest.raises(ValueError):
        V.parse_vector(bad)


def test_macrovector_is_exact():
    # documented equivalence-class rules -> deterministic macrovector
    assert V.macrovector(V.parse_vector(_MAX)) == "000100"
    # all-none impact, worst exploitability chars -> high EQ digits
    assert V.macrovector(V.parse_vector(_MIN)) == "212201"


def test_score_boundaries_and_bands():
    hi = V.base_score(_MAX)
    assert hi["estimated"] is True and hi["method"] == "apolaki_macrovector_estimate"
    assert hi["base_severity"] == "critical" and hi["base_score"] >= 9.0
    lo = V.base_score(_MIN)
    assert lo["base_score"] == 0.0 and lo["base_severity"] == "none"    # zero impact => 0.0 by definition


def test_score_is_monotonic_in_severity():
    weaker = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    stronger = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"   # VI:N -> VI:H (worse)
    assert V.base_score(stronger)["base_score"] >= V.base_score(weaker)["base_score"]


def test_impact_split_and_nomenclature():
    b = V.base_score(_MAX)
    assert b["vulnerable_system_impact"] == {"C": "H", "I": "H", "A": "H"}
    assert b["subsequent_system_impact"] == {"C": "H", "I": "H", "A": "H"}
    assert b["nomenclature"] == "CVSS-B"
    assert V.base_score(_MAX + "/E:P")["nomenclature"] == "CVSS-BT"
    assert V.base_score(_MAX + "/CR:H")["nomenclature"] == "CVSS-BE"


def test_pinned_fixture_scores_are_stable():
    # regression pins of the DETERMINISTIC estimate (Apolaki estimate, not FIRST-normative)
    assert V.base_score(_MAX)["base_score"] == 9.1
    assert V.base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")["base_score"] == 6.8
