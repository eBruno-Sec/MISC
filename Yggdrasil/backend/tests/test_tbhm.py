"""Tests for the TBHM integration (core.tbhm) + its bundled data catalogs.

Covers the requirements for a clean, bounded, attributed integration:
- the marker corpus (v4/all2.txt HOSTMARKER/PORTMAKER format) normalizes to bare
  deduped parameter names, with the markers themselves never leaking through;
- the param catalog is tiered (small curated default vs. bounded deep) and deep
  is opt-in via env, so default scans don't explode;
- dangerous payload families (RCE) are NOT default and are authorization-gated;
- the Fast Testing Checklist loads with coverage tiers and carries attribution.
"""
import importlib.util
import os
import unittest

HAS_YAML = importlib.util.find_spec("yaml") is not None


@unittest.skipUnless(HAS_YAML, "PyYAML not installed in this local test environment")
class MarkerWordlistTests(unittest.TestCase):
    def setUp(self):
        from core import tbhm
        self.tbhm = tbhm

    def test_extracts_bare_param_names_from_marker_lines(self):
        text = (
            "/?=//HOSTMARKER:PORTMAKER/&debug=//HOSTMARKER:PORTMAKER/"
            "&redirect=//HOSTMARKER:PORTMAKER/&file=//HOSTMARKER:PORTMAKER/\n"
            "/.//HOSTMARKER:PORTMAKER//passwd\n"
        )
        names = self.tbhm.parse_marker_wordlist(text)
        self.assertEqual(names, ["debug", "redirect", "file"])

    def test_marker_placeholders_never_leak_as_param_names(self):
        text = "&url=//HOSTMARKER:PORTMAKER/&next=//HOSTMARKER:PORTMARKER/\n"
        names = self.tbhm.parse_marker_wordlist(text)
        self.assertIn("url", names)
        self.assertIn("next", names)
        self.assertNotIn("hostmarker", names)
        self.assertNotIn("portmaker", names)
        self.assertNotIn("portmarker", names)

    def test_dedupes_repeated_names_first_seen_order(self):
        text = "&id=//X/&page=//X/&id=//X/&page=//X/&search=//X/\n"
        self.assertEqual(self.tbhm.parse_marker_wordlist(text), ["id", "page", "search"])

    def test_empty_name_tokens_are_skipped(self):
        # `?=` / `&=` have no name; they must not produce an empty entry.
        self.assertEqual(self.tbhm.parse_marker_wordlist("/?=//X/&=//X/"), [])

    def test_classified_only_keeps_family_params_drops_unknown(self):
        # redirect -> ssrf/open_redirect (kept); zznotarealparam -> no family (dropped).
        text = "&redirect=//X/&zznotarealparam=//X/&file=//X/\n"
        names = self.tbhm.parse_marker_wordlist(text, classified_only=True)
        self.assertIn("redirect", names)
        self.assertIn("file", names)
        self.assertNotIn("zznotarealparam", names)


@unittest.skipUnless(HAS_YAML, "PyYAML not installed in this local test environment")
class ParamCatalogTests(unittest.TestCase):
    def setUp(self):
        from core import tbhm
        self.tbhm = tbhm
        self._saved = os.environ.get("YGGDRASIL_TBHM_DEEP")
        os.environ.pop("YGGDRASIL_TBHM_DEEP", None)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("YGGDRASIL_TBHM_DEEP", None)
        else:
            os.environ["YGGDRASIL_TBHM_DEEP"] = self._saved

    def test_default_catalog_is_curated_and_smaller_than_deep(self):
        default = self.tbhm.param_catalog("default")
        deep = self.tbhm.param_catalog("deep")
        self.assertTrue(default)
        self.assertLess(len(default), len(deep))

    def test_default_has_high_signal_names(self):
        default = self.tbhm.param_catalog("default")
        for name in ("id", "redirect", "url", "cmd", "file"):
            self.assertIn(name, default)

    def test_deep_only_name_absent_from_default_present_in_deep(self):
        # "gameid" is in the deep catalog but not the curated default subset.
        self.assertNotIn("gameid", self.tbhm.param_catalog("default"))
        self.assertIn("gameid", self.tbhm.param_catalog("deep"))

    def test_no_duplicate_names_in_either_tier(self):
        for mode in ("default", "deep"):
            cat = self.tbhm.param_catalog(mode)
            self.assertEqual(len(cat), len(set(cat)), f"{mode} catalog has duplicates")

    def test_deep_mode_env_flag_switches_default_none_to_deep(self):
        self.assertNotIn("gameid", self.tbhm.param_catalog(None))  # deep off
        os.environ["YGGDRASIL_TBHM_DEEP"] = "1"
        self.assertTrue(self.tbhm.deep_mode_enabled())
        self.assertIn("gameid", self.tbhm.param_catalog(None))     # deep on


@unittest.skipUnless(HAS_YAML, "PyYAML not installed in this local test environment")
class ChecklistTests(unittest.TestCase):
    def setUp(self):
        from core import tbhm
        self.tbhm = tbhm

    def test_checklist_loads_with_categories_and_items(self):
        cats = self.tbhm.checklist()
        self.assertTrue(cats)
        self.assertTrue(all("items" in c for c in cats))
        # Known TBHM categories are present.
        titles = {c.get("title") for c in cats}
        self.assertIn("Handling of Input", titles)

    def test_coverage_summary_counts_add_up(self):
        s = self.tbhm.checklist_coverage_summary()
        self.assertEqual(s["automated"] + s["partial"] + s["manual"], s["total"])
        self.assertGreater(s["total"], 0)
        self.assertGreater(s["automated"], 0)

    def test_sql_injection_item_is_automated(self):
        items = {i["id"]: i for i in self.tbhm.checklist_items()}
        self.assertEqual(items["sql-injection"]["coverage"], "automated")
        # Logic flaws stay manual — automation must not over-claim them.
        self.assertEqual(items["transaction-logic"]["coverage"], "manual")


@unittest.skipUnless(HAS_YAML, "PyYAML not installed in this local test environment")
class PayloadPolicyAndAttributionTests(unittest.TestCase):
    def setUp(self):
        from core import tbhm
        self.tbhm = tbhm

    def test_rce_is_not_default_and_requires_authorization(self):
        fams = self.tbhm.payload_profiles()
        self.assertIn("rce", fams)
        self.assertFalse(fams["rce"]["default"])
        self.assertTrue(fams["rce"]["requires_authorization"])

    def test_safe_families_are_default(self):
        fams = self.tbhm.payload_profiles()
        for fam in ("xss", "sqli", "lfi", "open_redirect"):
            self.assertTrue(fams[fam]["default"], f"{fam} should be default")

    def test_ssrf_gated_but_present(self):
        fams = self.tbhm.payload_profiles()
        self.assertTrue(fams["ssrf"]["requires_authorization"])

    def test_attribution_credits_haddix_tbhm(self):
        line = self.tbhm.attribution_line()
        self.assertIn("TBHM", line)
        self.assertIn("Haddix", line)


if __name__ == "__main__":
    unittest.main()
