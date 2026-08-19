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
    """Simulates a run missing capabilities and asserts the report NAMES what it could not test.

    Q-062: the headless-browser row no longer reads an env var. It asks `bie.available()`, the same
    check the browser engines themselves gate on, because the old predicate reported the capability
    MISSING whenever CDP_BROWSER_URL was unset while the platform went on confirming DOM XSS through
    a local Playwright chromium. Deleting the variable therefore no longer simulates "no browser",
    and this test has to patch the real dependency instead. That is the simulation catching up with
    the code, not a loosened assertion: the report must still name a class it genuinely could not
    test, which is exactly what is asserted below.
    """
    monkeypatch.delenv("BBH_OOB_BASE", raising=False)
    monkeypatch.delenv("CDP_BROWSER_URL", raising=False)
    import bie
    monkeypatch.setattr(bie, "available", lambda: (False, "patched: no browser in this run"))
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


# ── OOB availability is a question about the TARGET, not about configuration ─────────────────────

def _oob(target="", base="http://agent:8000", domain=""):
    import os
    import capability_preflight as cp
    old = (os.environ.get("BBH_OOB_BASE"), os.environ.get("BBH_OOB_DOMAIN"))
    os.environ["BBH_OOB_BASE"] = base
    os.environ["BBH_OOB_DOMAIN"] = domain
    try:
        return [c for c in cp.check(target=target) if c["capability"] == "oob_collaborator"][0]
    finally:
        for k, v in zip(("BBH_OOB_BASE", "BBH_OOB_DOMAIN"), old):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_in_network_collaborator_serves_a_local_lab():
    """The in-network default is what unlocks blind SSRF/XXE/cmdi against the local labs out of the box —
    verified end to end: a lab container reached /oob/<token> and the hit was recorded with source IP."""
    assert _oob("http://juice-shop:3000")["available"] is True


def test_in_network_collaborator_is_NOT_claimed_for_an_external_target():
    """THE honesty check. `http://agent:8000` is invisible from the internet. Treating "configured" as
    "available" would inject probes whose callback could never arrive, and report the resulting silence
    as "not vulnerable" — the exact misreading this module exists to prevent."""
    r = _oob("https://acme.example.com")
    assert r["available"] is False
    assert "cannot reach it" in r.get("unreachable_note", "")


def test_a_public_collaborator_is_not_claimed_for_an_internal_target():
    """The failure runs both ways: a public collaborator may be blocked from an internal host."""
    assert _oob("http://internal-app:8080", base="https://oob.public.example")["available"] is False


def test_a_dns_collaborator_is_reachable_from_anywhere():
    """A wildcard domain resolves from either side, so it is exempt from the reachability question."""
    assert _oob("https://acme.example.com", domain="oob.example.net")["available"] is True


def test_without_a_target_the_configured_state_is_reported():
    """No target means no reachability claim can be made; reporting the configured state is the most
    that can honestly be said."""
    assert _oob("")["available"] is True


def test_no_collaborator_configured_is_unavailable_everywhere():
    assert _oob("http://juice-shop:3000", base="")["available"] is False
