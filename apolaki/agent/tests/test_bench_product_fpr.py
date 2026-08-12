"""A within-family scorer cannot measure a whole-product false-positive rate.

`_detected` credits a finding only when it claims the case's OWN family. That is the official
CWE-matching convention and it is correct for TPR. Applied to clean cases it silently forgives every
finding of a *different* family — which is how 22 clean `securecookie` cases carrying CONFIRMED
`path_traversal` findings all scored as true negatives, and how the platform published 0.0% FPR while
a client's report for those same cases would have carried 22 false positives.

Both numbers are now computed. These tests pin the distinction so it cannot silently collapse back
into one.
"""
import owasp_bench as ob


def _row(test, cat, families, conf=None):
    return {"test": test, "category": cat, "families": list(families),
            "conf": list(conf) if conf else ["confirmed"] * len(families)}


def test_official_convention_forgives_a_cross_family_finding():
    """The behaviour we are NOT changing — the published figure keeps its published meaning."""
    r = _row("BenchmarkTest1", "securecookie", ["path_traversal"])
    assert ob._detected(r, "securecookie") is False        # not securecookie's family
    assert ob._any_confirmed(r) is True                    # ...but the tool did report something


def test_a_lead_is_not_a_finding_under_either_convention():
    """The proof gate demotes these, so the tool would never claim them. Counting one as a detection
    invents a false positive out of thin air — which already happened once, on the first Python run."""
    for word in ("lead", "candidate", "unconfirmed", "info"):
        r = _row("t", "securecookie", ["path_traversal"], [word])
        assert ob._any_confirmed(r) is False, word
        assert ob._detected(r, "securecookie") is False, word


def test_clean_case_with_a_foreign_confirmed_finding_scores_TN_officially_and_FP_for_the_product():
    key = {"C1": ("securecookie", False)}
    run = {"target": "java", "results": [_row("C1", "securecookie", ["path_traversal"])]}
    s = ob.score(run, key)
    b = s["per_category"]["securecookie"]
    assert (b["fp"], b["tn"]) == (0, 1), "official convention: not this family, so a true negative"
    assert (b["fp_any"], b["tn_any"]) == (1, 0), "product view: the client would have seen this"
    assert b["cross_family_fp"] == 1
    assert s["cross_family_fp"] == 1
    assert b["fpr"] == 0.0 and b["fpr_any"] == 1.0


def test_the_two_macros_diverge_exactly_when_cross_family_FPs_exist():
    key = {"V1": ("securecookie", True), "C1": ("securecookie", False)}
    run = {"target": "java", "results": [
        _row("V1", "securecookie", ["insecure_cookie"]),          # a real hit
        _row("C1", "securecookie", ["path_traversal"]),        # a foreign FP on a clean case
    ]}
    s = ob.score(run, key)
    b = s["per_category"]["securecookie"]
    assert b["tpr"] == 1.0
    assert b["youden"] == 1.0, "official: TPR 1.0 - FPR 0.0"
    assert b["youden_product"] == 0.0, "product: TPR 1.0 - FPR 1.0"
    assert s["official_macro"] == 1.0 and s["product_macro"] == 0.0


def test_they_agree_when_the_tool_is_actually_clean():
    """The negative control for the whole mechanism: with no cross-family findings the product number
    must equal the official one. If these ever diverge on a clean run, the new metric is wrong."""
    key = {"V1": ("securecookie", True), "C1": ("securecookie", False)}
    run = {"target": "java", "results": [
        _row("V1", "securecookie", ["insecure_cookie"]),
        _row("C1", "securecookie", []),                        # nothing reported on the clean case
    ]}
    s = ob.score(run, key)
    b = s["per_category"]["securecookie"]
    assert b["fpr"] == b["fpr_any"] == 0.0
    assert s["official_macro"] == s["product_macro"] == 1.0
    assert s["cross_family_fp"] == 0


def test_report_prints_both_numbers_and_labels_which_is_which():
    key = {"V1": ("securecookie", True), "C1": ("securecookie", False)}
    run = {"target": "java", "results": [
        _row("V1", "securecookie", ["insecure_cookie"]),
        _row("C1", "securecookie", ["path_traversal"]),
    ]}
    txt = ob.report(ob.score(run, key))
    assert "OFFICIAL SUITE SCORE" in txt and "PRODUCT SUITE SCORE" in txt
    assert "how good is Apolaki" in txt
    assert "cross-family false positives" in txt


def test_a_row_with_no_finding_cannot_book_a_false_positive():
    """The `x or DEFAULT` trap, in the one place it would corrupt a published number.

    `confs[:len(fams)] or confs` returned the FULL confidence list when `fams` was empty, because
    `confs[:0]` is `[]` and `[]` is falsy. A row carrying no finding at all then read as confirmed and
    booked a product false positive out of nothing. Latent (scan() builds both lists together), but a
    scorer that can invent an FP decides the numbers we publish.
    """
    assert ob._any_confirmed({"families": [], "conf": ["confirmed"]}) is False
    assert ob._any_confirmed({"families": [], "conf": []}) is False
    assert ob._any_confirmed({}) is False
    # ...while a real finding is still counted, and the truncation still guards a ragged pair.
    assert ob._any_confirmed({"families": ["sqli"], "conf": ["confirmed"]}) is True
    assert ob._any_confirmed({"families": ["sqli"], "conf": ["lead", "confirmed"]}) is False


def test_an_empty_row_on_a_clean_case_scores_TN_not_FP():
    """End to end: the defect's actual consequence, not just the predicate."""
    key = {"C1": ("securecookie", False)}
    run = {"target": "java", "results": [
        {"test": "C1", "category": "securecookie", "families": [], "conf": ["confirmed"]}]}
    s = ob.score(run, key)
    b = s["per_category"]["securecookie"]
    assert (b["fp_any"], b["tn_any"]) == (0, 1)
    assert s["cross_family_fp"] == 0
