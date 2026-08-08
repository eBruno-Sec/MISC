"""Capability preflight (#125): the report must state what it could NOT test.

Motivated by a measured failure: the sealed blind benchmark missed XXE at /catalog/product/stock. The
XXE engine was fine — blind XXE needs an out-of-band callback, BBH_OOB_BASE was unset, so the class was
untestable and the report said nothing. Untested and clean looked identical.
"""
import capability_preflight as cp


def test_every_capability_declares_what_it_blocks_and_how_to_enable_it():
    for c in cp.check():
        assert c["capability"] and isinstance(c["available"], bool)
        assert c["blocks"], "%s blocks nothing — then why gate on it?" % c["capability"]
        assert len(c["how_to_enable"]) > 10 and len(c["why_it_matters"]) > 20


def test_oob_absence_makes_the_blind_classes_untestable(monkeypatch):
    monkeypatch.delenv("BBH_OOB_BASE", raising=False)
    monkeypatch.delenv("BBH_OOB_DOMAIN", raising=False)
    debt = cp.coverage_debt()
    assert "oob_collaborator" in debt["capabilities_missing"]
    assert any("blind XXE" in c for c in debt["untestable_classes"])
    assert debt["complete"] is False


def test_configuring_oob_removes_it_from_the_debt(monkeypatch):
    monkeypatch.setenv("BBH_OOB_BASE", "http://oob.example")
    debt = cp.coverage_debt()
    assert "oob_collaborator" not in debt["capabilities_missing"]
    assert not any("blind XXE" == c for c in debt["untestable_classes"])


def test_the_statement_refuses_to_let_untested_read_as_clean(monkeypatch):
    """The anti-WYSIATI requirement, asserted on the wording rather than trusted to reviewers."""
    monkeypatch.delenv("BBH_OOB_BASE", raising=False)
    d = cp.coverage_debt()
    assert "NOT TESTED" in d["statement"] or "not tested" in d["statement"].lower()
    assert "not evidence of absence" in d["statement"]


def test_report_section_names_each_untested_class(monkeypatch):
    monkeypatch.delenv("BBH_OOB_BASE", raising=False)
    monkeypatch.delenv("CDP_BROWSER_URL", raising=False)
    md = cp.report_section()
    assert "COULD NOT TEST" in md
    assert "blind XXE" in md and "DOM XSS" in md
    assert "not a statement that they are secure" in md


def test_a_fully_configured_run_says_so_plainly(monkeypatch):
    monkeypatch.setattr(cp, "_CAPABILITIES", (
        ("everything", lambda: True, ("x",), "n/a", "n/a is a sufficiently long explanation"),))
    d = cp.coverage_debt()
    assert d["complete"] is True and d["untestable_classes"] == []
    md = cp.report_section(d)
    assert "no vulnerability class was skipped" in md
    assert "COULD NOT TEST" not in md


def test_coverage_debt_counts_are_consistent():
    ch = cp.check()
    d = cp.coverage_debt(ch)
    assert d["capabilities_total"] == len(ch)
    assert d["capabilities_available"] + len(d["capabilities_missing"]) == len(ch)
