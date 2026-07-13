from types import SimpleNamespace
import unittest

from core.web_security import (
    analyze_idor_pair,
    analyze_traversal_pair,
    build_idor_probes,
    build_traversal_probes,
    generate_discovery_words,
    is_url_in_scope,
)


class WebSecurityTests(unittest.TestCase):
    def response(self, status, text):
        return SimpleNamespace(status_code=status, text=text, content=text.encode())

    def test_scope_defaults_to_same_host(self):
        self.assertTrue(is_url_in_scope("https://example.com/a", "https://example.com"))
        self.assertFalse(is_url_in_scope("https://evil.test/a", "https://example.com"))

    def test_scope_rules_allow_wildcards_and_exclusions(self):
        rules = {
            "in_scope": [{"identifier": "*.example.com"}],
            "out_of_scope": [{"identifier": "admin.example.com"}],
        }
        self.assertTrue(is_url_in_scope("https://api.example.com/a", "https://example.com", rules))
        self.assertFalse(is_url_in_scope("https://admin.example.com/a", "https://example.com", rules))
        self.assertFalse(is_url_in_scope("https://other.test/a", "https://example.com", rules))

    def test_path_scope_rules_do_not_filter_out_base_host(self):
        rules = {
            "in_scope": [
                {"identifier": "/catalog", "type": "path"},
                {"identifier": "/login", "type": "path"},
            ],
            "out_of_scope": [],
        }
        self.assertTrue(is_url_in_scope("https://example.com/catalog?search=gin", "https://example.com", rules))
        self.assertTrue(is_url_in_scope("https://example.com/login", "https://example.com", rules))
        self.assertFalse(is_url_in_scope("https://example.com/admin", "https://example.com", rules))
        self.assertFalse(is_url_in_scope("https://evil.test/catalog", "https://example.com", rules))

    def test_dirty_scope_notes_do_not_become_host_allowlist(self):
        rules = {
            "in_scope": [
                {"identifier": "ACCOUNT LOGIN DETAILS", "type": "domain"},
                {"identifier": "SQL injection", "type": "domain"},
                {"identifier": "/catalog", "type": "domain"},
            ],
            "out_of_scope": [],
        }
        self.assertTrue(is_url_in_scope("https://ginandjuice.shop/catalog?search=gin", "https://ginandjuice.shop", rules))
        self.assertFalse(is_url_in_scope("https://ginandjuice.shop/login", "https://ginandjuice.shop", rules))
        self.assertFalse(is_url_in_scope("https://evil.test/catalog", "https://ginandjuice.shop", rules))

    def test_traversal_probes_only_for_pathlike_params(self):
        probes = build_traversal_probes("https://example.com/download?file=report.pdf&id=1")
        self.assertTrue(probes)
        self.assertEqual({p.parameter for p in probes}, {"file"})
        self.assertTrue(all("/etc/passwd" not in p.payload for p in probes))

    def test_traversal_lab_mode_adds_lab_payloads(self):
        probes = build_traversal_probes(
            "https://example.com/download?file=report.pdf",
            lab_mode=True,
            max_probes=20,
        )
        self.assertTrue(any("etc" in p.payload.lower() for p in probes))

    def test_traversal_analysis_detects_file_signature(self):
        baseline = self.response(200, "normal page")
        probe = self.response(200, "root:x:0:0:root:/root:/bin/bash")
        hit = analyze_traversal_pair(baseline, probe, "../../../../etc/passwd", lab_mode=True)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["severity"], "high")

    def test_idor_probe_numeric_query_and_path(self):
        probes = build_idor_probes("https://example.com/api/users/10?account_id=99")
        params = {p.parameter for p in probes}
        self.assertIn("account_id", params)
        self.assertTrue(any(p.parameter.startswith("path[") for p in probes))

    def test_idor_cross_role_analysis(self):
        baseline = self.response(200, '{"user_id":123,"email":"a@example.com","role":"user"}')
        replay = self.response(200, '{"user_id":123,"email":"a@example.com","role":"user"}')
        hit = analyze_idor_pair(baseline, replay, cross_role=True)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["severity"], "high")

    def test_discovery_words_include_generated_route_tokens(self):
        words = generate_discovery_words(
            "https://example.com",
            ["https://example.com/api/v1/users?account_id=1"],
        )
        self.assertIn("api", words)
        self.assertIn("users", words)
        self.assertIn("account_id", words)

    def test_parameter_brute_words_use_routes_and_scope_hints(self):
        from agents.offensive import OffensiveEngine

        engine = OffensiveEngine()
        names = engine._candidate_parameter_names(
            ["https://example.com/catalog/product?id=1"],
            [
                {"path": "/catalog/product/stock", "hints": ["XML external entity injection"]},
                {"path": "/catalog", "hints": ["SQL injection", "Cross-site scripting (reflected)"]},
            ],
        )
        self.assertIn("id", names)
        self.assertIn("catalog", names)
        self.assertIn("xml", names)
        self.assertIn("search", names)
        self.assertIn("callback", names)

    def test_generated_parameter_urls_prioritize_catalog_searchterm(self):
        from agents.offensive import OffensiveEngine

        engine = OffensiveEngine()
        urls = engine.generate_parameter_test_urls(
            "https://ginandjuice.shop",
            ["https://ginandjuice.shop/catalog"],
            declared_paths=[
                {"path": "/catalog", "hints": ["SQL injection", "Cross-site scripting (reflected)"]},
            ],
            scope_rules=None,
            max_routes=5,
            max_urls=80,
        )
        self.assertIn("https://ginandjuice.shop/catalog?searchTerm=yggdrasil", urls)
        self.assertTrue(any("productId=" in url for url in urls))

    def test_generated_parameter_urls_use_stock_and_xxe_hints(self):
        from agents.offensive import OffensiveEngine

        engine = OffensiveEngine()
        urls = engine.generate_parameter_test_urls(
            "https://ginandjuice.shop",
            ["https://ginandjuice.shop/catalog/product/stock"],
            declared_paths=[
                {"path": "/catalog/product/stock", "hints": ["XML external entity injection"]},
            ],
            scope_rules=None,
            max_routes=5,
            max_urls=80,
        )
        self.assertIn("https://ginandjuice.shop/catalog/product/stock?stockApi=yggdrasil", urls)
        self.assertTrue(any("xml=" in url for url in urls))


if __name__ == "__main__":
    unittest.main()
