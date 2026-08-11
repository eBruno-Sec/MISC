"""Tests for owasp_bench.merge_runs -- the DAST + code-assisted union.

The merge is the only place a hybrid number is constructed, so it is also the only place a hybrid
number can be fabricated. Each test below is a way a merge could quietly lie:

  * dropping one lane's false positives (a hybrid that unions detections must union FPs too)
  * booking a case UNSCORED because one lane could not see it, which narrows the denominator
  * losing the lane labels, which is how a code-assisted result gets reported as a DAST one
  * losing a `lead` confidence, which promotes an unproven row into a detection
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import owasp_bench as ob


def _dast(test, cat, fams=(), confs=(), error=""):
    return {"test": test, "category": cat, "url": "u", "engine": "_run_sqli", "lane": "dast",
            "families": list(fams), "conf": list(confs), "error": error}


def _sast(test, cat, fams=(), confs=(), error=""):
    return {"test": test, "category": cat, "url": "u", "lane": "code-assisted",
            "engine": "codeintel.review_source_tree",
            "families": list(fams), "conf": list(confs), "error": error}


def test_union_carries_both_lanes_detections():
    m = ob.merge_runs([{"results": [_dast("T1", "weakrand", [], [])]},
                       {"results": [_sast("T1", "weakrand", ["weak_random"], ["confirmed"])]}])
    row = m["results"][0]
    assert row["families"] == ["weak_random"]
    assert ob._detected(row, "weakrand") is True
    assert row["lane"] == "hybrid"
    assert sorted(row["lanes"]) == ["code-assisted", "dast"]


def test_union_carries_the_other_lanes_false_positive_too():
    """A hybrid that unions detections MUST union false positives, or the number is a fiction."""
    key = {"T1": ("weakrand", False)}
    m = ob.merge_runs([{"results": [_dast("T1", "weakrand", [], [])]},
                       {"results": [_sast("T1", "weakrand", ["weak_random"], ["confirmed"])]}])
    m["target"] = "java"
    s = ob.score(m, key)
    assert s["per_category"]["weakrand"]["fp"] == 1
    assert s["per_category"]["weakrand"]["tn"] == 0


def test_case_one_lane_could_not_see_is_still_measured():
    """DAST cannot see crypto; the code-assisted lane can. The case is MEASURED, not unscored."""
    m = ob.merge_runs([{"results": [_dast("T2", "crypto", [], [], error="no engine mapped")]},
                       {"results": [_sast("T2", "crypto", ["weak_crypto"], ["confirmed"])]}])
    row = m["results"][0]
    assert row["error"] == ""
    s = ob.score(dict(m, target="java"), {"T2": ("crypto", True)})
    assert s["unscored"] == []
    assert s["per_category"]["crypto"]["tp"] == 1


def test_case_no_lane_could_see_stays_unscored():
    """The converse. An unmeasured case is not a miss -- it must never enter a rate."""
    m = ob.merge_runs([{"results": [_dast("T3", "trustbound", [], [], error="no engine mapped")]},
                       {"results": [_sast("T3", "trustbound", [], [], error="no source provided")]}])
    # VERBATIM. `score` matches the START of this string to decide a case was never analysed; an
    # earlier version prefixed it with the lane name and score booked the case as a FALSE NEGATIVE.
    assert m["results"][0]["error"] == "no engine mapped"
    assert m["results"][0]["unmeasured_by"] == ["dast: no engine mapped",
                                                "code-assisted: no source provided"]
    s = ob.score(dict(m, target="java"), {"T3": ("trustbound", True)})
    assert s["unscored"] == ["T3"]
    assert "trustbound" not in s["per_category"]
    # the negative control for the guard above: it must ALSO hold for the source lane's wording
    m2 = ob.merge_runs([{"results": [_sast("T3b", "crypto", [], [], error="no source provided")]}])
    assert m2["results"][0]["error"] == "no source provided"
    assert ob.score(dict(m2, target="java"), {"T3b": ("crypto", True)})["unscored"] == ["T3b"]


def test_lead_confidence_survives_the_merge():
    """A lead is not a detection on either side of the ratio, before or after merging."""
    m = ob.merge_runs([{"results": [_dast("T4", "pathtraver", ["path_traversal"], ["lead"])]},
                       {"results": [_sast("T4", "pathtraver", [], [])]}])
    row = m["results"][0]
    assert row["conf"] == ["lead"]
    assert ob._detected(row, "pathtraver") is False
    assert ob._any_confirmed(row) is False


def test_confidences_stay_aligned_when_a_lane_omits_them():
    """An older artifact has families but no `conf`. Padding must not shift the other lane's leads."""
    old = {"test": "T5", "category": "sqli", "url": "u", "families": ["sqli"], "error": ""}
    m = ob.merge_runs([{"results": [old]},
                       {"results": [_dast("T5", "sqli", ["xss"], ["lead"])]}])
    row = m["results"][0]
    assert row["families"] == ["sqli", "xss"]
    assert row["conf"] == ["confirmed", "lead"]
    assert ob._detected(row, "sqli") is True


def test_hybrid_lanes_reach_the_banner():
    """The banner is the only label that survives a copy/paste; it must name both lanes."""
    m = ob.merge_runs([{"results": [_dast("T6", "crypto", [], [], error="no engine mapped")]},
                       {"results": [_sast("T6", "crypto", ["weak_crypto"], ["confirmed"])]}])
    s = ob.score(dict(m, target="java"), {"T6": ("crypto", True)})
    assert s["lanes"] == ["code-assisted"]
    text = ob.report(s)
    assert "CODE-ASSISTED" in text

    m2 = ob.merge_runs([{"results": [_dast("T7", "sqli", ["sqli"], ["confirmed"])]},
                        {"results": [_sast("T7", "sqli", ["sqli"], ["confirmed"])]}])
    s2 = ob.score(dict(m2, target="java"), {"T7": ("sqli", True)})
    assert s2["lanes"] == ["code-assisted", "dast"]
    assert "HYBRID RESULT" in ob.report(s2)


def test_suite_macro_still_divides_by_all_eleven_categories():
    """The denominator is the SUITE, never the categories a merge happened to cover."""
    m = ob.merge_runs([{"results": [_dast("T8", "sqli", ["sqli"], ["confirmed"]),
                                    _dast("T9", "sqli", [], [])]}])
    s = ob.score(dict(m, target="java"), {"T8": ("sqli", True), "T9": ("sqli", False)})
    assert s["suite_size"] == 11
    # one category at a perfect 1.0, ten categories at 0 -> 1/11
    assert abs(s["suite_macro"] - 1.0 / 11) < 1e-9
    assert len(s["suite_missing"]) == 10


def test_shards_partition_the_same_sample_exactly_once():
    """N workers must cover exactly what one worker would, with no case run twice or dropped."""
    picked = ["c%02d" % i for i in range(23)]
    shards = 4
    seen = []
    for k in range(shards):
        seen += picked[k::shards]
    assert sorted(seen) == picked
    assert len(seen) == len(picked)
    # and no shard gets a contiguous block, so a dead shard leaves a spread gap, not a hole
    assert picked[0::shards] != picked[:len(picked) // shards]


def test_load_run_reads_a_truncated_checkpoint(tmp_path):
    p = tmp_path / "ck.jsonl"
    p.write_text('{"test": "A", "category": "sqli", "families": [], "error": ""}\n{"test": "B", "cat',
                 encoding="utf8")
    run = ob.load_run(str(p), "java")
    assert [r["test"] for r in run["results"]] == ["A"]
    assert run["target"] == "java"
