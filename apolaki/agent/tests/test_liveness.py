"""The engine-liveness ratchet (#125).

`validated_on` records that an engine was once proven; nothing re-checked it. Three engines were found
silently dead in one night with the whole suite green, because the suite tests pure helpers and the
wiring is untested by construction. This gate asks one question per engine — did the shipping code path
carry a real target all the way to a confirmed finding — and refuses to let a previously-live engine go
quiet without failing.

The scoring is pure and tested here; the end-to-end run lives in liveness_run.py and needs the labs up.
"""
import json
import os

import liveness as lv


def _r(tech, verdict, lab="lab"):
    return {"technique": tech, "lab": lab, "verdict": verdict, "detail": ""}


# ── the ratchet ───────────────────────────────────────────────────────────────
def test_an_engine_that_was_live_and_is_now_dead_fails_the_gate():
    ev = lv.evaluate([_r("a", lv.CONFIRMED), _r("b", lv.DEAD)], ["a", "b"])
    assert ev["regressions"] == ["b"] and ev["ok"] is False
    assert "REGRESSION" in ev["statement"]


def test_a_newly_confirmed_engine_raises_the_baseline():
    ev = lv.evaluate([_r("a", lv.CONFIRMED), _r("b", lv.CONFIRMED)], ["a"])
    assert ev["ok"] is True and ev["gained"] == ["b"]
    assert ev["new_baseline"] == ["a", "b"]


def test_a_skipped_lab_does_not_clear_a_regression():
    """THE load-bearing property. If a down lab counted as a pass, the whole gate could be silenced by
    stopping a container — the exact declaration-instead-of-fact failure it exists to catch."""
    ev = lv.evaluate([_r("a", lv.SKIPPED)], ["a"])
    assert ev["regressions"] == ["a"] and ev["ok"] is False


def test_a_skipped_lab_for_an_engine_never_proven_is_not_a_failure():
    """Honest the other way too: not asking a question about an engine with no baseline is not a
    regression, and must not block the gate."""
    ev = lv.evaluate([_r("a", lv.CONFIRMED), _r("z", lv.SKIPPED)], ["a"])
    assert ev["ok"] is True and ev["regressions"] == []
    assert "z" not in ev["new_baseline"]


def test_a_harness_error_fails_the_gate_rather_than_being_read_as_dead():
    """An engine reported dead when the HARNESS broke would send someone hunting a bug that isn't there
    — and worse, an error silently treated as a pass would hide a real one."""
    ev = lv.evaluate([_r("a", lv.ERROR)], [])
    assert ev["ok"] is False and ev["errors"] == ["a"]


def test_the_baseline_never_shrinks_through_evaluate():
    ev = lv.evaluate([_r("a", lv.CONFIRMED)], ["a", "b"])
    assert "b" in ev["new_baseline"]          # still recorded…
    assert ev["regressions"] == ["b"]         # …and still failing


# ── what counts as proof ──────────────────────────────────────────────────────
_CHECK = {"technique": "t", "lab": "l", "family": "sqli"}


def test_only_a_confirmed_finding_with_real_evidence_satisfies_a_check():
    ok = {"family": "sqli", "confidence": "confirmed", "evidence": "a DBMS error absent from baseline"}
    assert lv._match(ok, _CHECK) is True


def test_a_lead_never_satisfies_a_liveness_check():
    """The point is that the ORACLE still fires. A lead means it did not."""
    assert lv._match({"family": "sqli", "confidence": "lead", "evidence": "x" * 40}, _CHECK) is False


def test_a_confirmed_finding_with_no_evidence_does_not_count():
    """This is not hypothetical: the GraphQL introspection finding shipped confirmed-by-construction with
    no confidence and no evidence field, so every proof filter silently dropped it."""
    assert lv._match({"family": "sqli", "confidence": "confirmed"}, _CHECK) is False
    assert lv._match({"family": "sqli", "confidence": "confirmed", "evidence": "short"}, _CHECK) is False


def test_the_wrong_family_does_not_satisfy_a_check():
    assert lv._match({"family": "xss", "confidence": "confirmed", "evidence": "x" * 40}, _CHECK) is False


def test_a_cwe_keyed_check_matches_on_cwe_not_family():
    chk = {"technique": "t", "lab": "l", "cwe": "CWE-602"}
    f = {"cwe": "CWE-602", "family": "access_control", "confidence": "confirmed", "evidence": "x" * 40}
    assert lv._match(f, chk) is True
    assert lv._match({**f, "cwe": "CWE-639"}, chk) is False


def test_verdict_reports_a_down_lab_as_skipped_never_confirmed():
    v = lv.verdict(_CHECK, [], lab_up=False)
    assert v["verdict"] == lv.SKIPPED and "NOT a pass" in v["detail"]


# ── the checks table itself ───────────────────────────────────────────────────
def test_every_check_names_a_real_technique():
    """Engine checks must name a technique that exists. A `surface` check is exempt because it proves
    REACH, not a vulnerability class — but it is not exempt from accountability; see the test below."""
    import techniques as T
    for c in lv.CHECKS:
        if c["kind"] == "surface":
            continue
        assert c["technique"] in T.TECHNIQUES, c["technique"]


def test_every_check_has_a_lab_the_runner_can_reach():
    """A check whose lab has no address would be unreachable forever and skip silently — a gate entry
    that can never run is worse than no entry, because it looks like coverage."""
    import liveness_run as lr
    for c in lv.CHECKS:
        assert c["lab"] in lr._LAB_ADDR, c["lab"]


def test_every_check_states_what_would_prove_it():
    """Every entry declares its own success condition up front, so a check can never be scored against
    a bar invented after the fact. Engine checks say which family/CWE would prove them; a surface check
    says how much reach is enough AND that the reach is addressable — a URL with no host is refused by
    scope, so counting it as coverage is exactly the Q-019 defect."""
    for c in lv.CHECKS:
        assert c["kind"] in ("tool", "call", "surface"), c["technique"]
        if c["kind"] == "surface":
            assert c.get("seed"), c["technique"]
            assert int(c.get("min_urls") or 0) > 0, c["technique"]
            assert c.get("max_hostless") is not None, c["technique"]
            continue
        assert c.get("family") or c.get("cwe"), c["technique"]


def test_the_committed_baseline_only_names_techniques_the_table_checks():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "liveness_baseline.json")
    live = json.load(open(path, encoding="utf8"))["live"]
    covered = {c["technique"] for c in lv.CHECKS}
    assert set(live) <= covered, sorted(set(live) - covered)


def test_the_baseline_records_the_engines_proven_so_far():
    """A ratchet with an empty baseline enforces nothing."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "liveness_baseline.json")
    live = json.load(open(path, encoding="utf8"))["live"]
    assert len(live) >= 15, live


# ── family alone is not enough to identify an engine ──────────────────────────
_GQL_CHECK = {"technique": "graphql_introspection", "lab": "dvga", "family": "graphql",
              "title": "introspection enabled"}


def test_a_sibling_finding_in_the_same_family_cannot_satisfy_the_check():
    """REGRESSION, and the gate's own false pass. GraphQL introspection, field-suggestion leakage and
    batching all carry family "graphql". Matching on family alone let the BATCHING finding satisfy the
    graphql_introspection check — so the gate reported that engine green while introspection was in fact
    emitting no evidence and being dropped by every proof filter. A gate that cannot tell two engines
    apart is not checking either of them."""
    batching = {"title": "GraphQL request batching enabled", "family": "graphql",
                "confidence": "confirmed", "evidence": "x" * 40}
    assert lv._match(batching, _GQL_CHECK) is False


def test_the_right_finding_still_satisfies_it():
    intro = {"title": "GraphQL introspection enabled", "family": "graphql",
             "confidence": "confirmed", "evidence": "y" * 40}
    assert lv._match(intro, _GQL_CHECK) is True


def test_the_right_finding_without_evidence_still_fails():
    intro = {"title": "GraphQL introspection enabled", "family": "graphql", "confidence": "confirmed"}
    assert lv._match(intro, _GQL_CHECK) is False


def test_checks_sharing_a_family_must_disambiguate_by_title():
    """Guard the table itself: if two checks share a family and neither names a title, one of them is
    provable by the other's finding and at least one engine is unguarded."""
    from collections import defaultdict
    by_family = defaultdict(list)
    for c in lv.CHECKS:
        if c.get("family"):
            by_family[c["family"]].append(c)
    for fam, checks in by_family.items():
        if len(checks) > 1:
            untitled = [c["technique"] for c in checks if not c.get("title")]
            assert len(untitled) <= 1, (
                "family %r is claimed by %d checks with no title to tell them apart: %s"
                % (fam, len(untitled), untitled))


def test_graphql_findings_all_carry_proof():
    """All three GraphQL findings are confirmed BY CONSTRUCTION — each branch is only reached after its
    oracle already matched — so all three must carry confidence AND evidence or they are silently
    unreportable."""
    import graphql_tool as gql
    src = open(gql.__file__, encoding="utf8").read()
    for marker in ("GraphQL introspection enabled", "GraphQL field suggestions leak schema",
                   "GraphQL request batching enabled"):
        i = src.find(marker)
        assert i > 0, marker
        block = src[i:i + 1600]
        block = block[:block.find("})") if "})" in block else 1600]
        assert '"confidence"' in block, "%s has no confidence" % marker
        assert '"evidence"' in block, "%s has no evidence" % marker
