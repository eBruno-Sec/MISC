"""Operator scan scoping (#34) — selection that GATES, and reports what it cost.

The requirement was "functional too, not just for show". Three things make it functional rather than
decorative: every technique must be selectable, an exclusion must produce a concrete skip list, and the
report must record the decision — because an untested class is not a clean one.
"""
import scan_scope as s
import techniques as T


def _techs():
    return [T.get(t["id"]) for t in T.list_techniques()]


def test_every_technique_is_selectable():
    """A vuln_class in no category is a technique an operator cannot knowingly exclude — and excluding
    'everything' would silently still run it."""
    ungrouped = sorted({t.get("vuln_class", "") for t in _techs()
                        if t.get("vuln_class") and not s.category_of(t["vuln_class"])})
    assert not ungrouped, "vuln_class values in no category: %s" % ungrouped


def test_categories_do_not_overlap():
    """A class in two categories makes exclusion ambiguous — which switch turns it off?"""
    seen = {}
    for name, spec in s.CATEGORIES.items():
        for c in spec["classes"]:
            assert c not in seen, "%s is in both %s and %s" % (c, seen.get(c), name)
            seen[c] = name


def test_every_category_has_a_label_an_operator_can_read():
    for name, spec in s.CATEGORIES.items():
        assert len(spec["label"]) > 12, name
        assert spec["classes"], name


def test_exclusion_produces_a_concrete_skip_list():
    """THE functional requirement. An exclusion that resolves to nothing is decoration."""
    r = s.resolve(["injection"], _techs())
    assert r["skipped_count"] > 5, r
    assert "sqli_auth_bypass" in r["skipped_technique_ids"]
    assert r["excluded_categories"] == ["injection"]


def test_excluding_nothing_skips_nothing():
    r = s.resolve([], _techs())
    assert r["skipped_count"] == 0 and r["excluded_categories"] == []


def test_an_unknown_category_is_reported_not_ignored():
    """A typo that silently excludes nothing would let an operator believe they narrowed a scan when
    they had not — the worst kind of scoping bug, because it is invisible."""
    r = s.resolve(["injektion", "injection"], _techs())
    assert r["unknown_categories"] == ["injektion"]
    assert r["excluded_categories"] == ["injection"]


# ── consequences, from the effects model rather than guesswork ──────────────────────────────────

def _synthetic():
    """A registry where the collateral case DOES arise, so the logic is proven rather than assumed."""
    return {
        "producer": {"id": "producer", "requires": ["seed"], "establishes": ["authenticated"],
                     "invalidates": [], "always_on": False, "vuln_class": "injection",
                     "permission": "active", "oracle": "o", "auto": True, "transferable": True,
                     "reached_by": ""},
        "consumer": {"id": "consumer", "requires": ["authenticated"], "establishes": [],
                     "invalidates": [], "always_on": False, "vuln_class": "xss",
                     "permission": "active", "oracle": "o", "auto": True, "transferable": True,
                     "reached_by": ""},
    }


def test_excluding_a_producer_starves_its_consumer_in_another_category():
    """The case the effects model exists to surface: `consumer` was NOT excluded, but nothing left can
    establish what it requires. Presenting an exclusion without this is how an operator concludes a class
    was tested when nothing could reach it."""
    techs = [{"id": "producer", "vuln_class": "injection"}, {"id": "consumer", "vuln_class": "xss"}]
    c = s.consequences(["injection"], techs, descriptors=_synthetic())
    assert c["starved_observations"] == ["authenticated"]
    assert c["unreachable_engines"] == ["consumer"]


def test_an_engine_that_is_itself_excluded_is_not_double_counted():
    techs = [{"id": "producer", "vuln_class": "injection"}, {"id": "consumer", "vuln_class": "xss"}]
    c = s.consequences(["injection", "xss"], techs, descriptors=_synthetic())
    assert c["unreachable_engines"] == [], "an excluded engine is not ALSO collateral damage"


def test_excluding_nothing_has_no_consequences():
    assert s.consequences([], _techs())["unreachable_engines"] == []


def test_on_the_real_registry_category_exclusions_are_largely_self_contained():
    """Measured, not assumed: every consumer of a starvable observation currently sits in a category that
    also contains one of its producers. Worth pinning — if a future engine breaks that, an operator's
    exclusion starts causing collateral damage and they should be told."""
    techs = _techs()
    c = s.consequences(["injection", "access_control", "authentication", "crypto"], techs)
    assert "authenticated" in c["starved_observations"]
    assert c["unreachable_engines"] == [], c["unreachable_engines"]


# ── the report must record the decision ─────────────────────────────────────────────────────────

def test_the_report_records_exclusions_as_untested_not_clean():
    lines = "\n".join(s.report_block(["injection"], _techs()))
    assert "Excluded from this assessment" in lines
    assert "not tested" in lines and "Absence of findings" in lines


def test_the_report_flags_an_unrecognised_exclusion():
    lines = "\n".join(s.report_block(["nonsense"], _techs()))
    assert "Unrecognised" in lines and "excluded NOTHING" in lines


def test_no_exclusions_means_no_report_block():
    assert s.report_block([], _techs()) == []


def test_scoping_helpers_are_pure():
    techs = _techs()
    assert s.resolve(["xss"], techs) == s.resolve(["xss"], techs)
    assert s.report_block(["xss"], techs) == s.report_block(["xss"], techs)
