from types import SimpleNamespace
import unittest

from core.web_security import (
    analyze_idor_pair,
    analyze_traversal_pair,
    build_idor_probes,
    build_traversal_probes,
    classify_sensitive_path_hit,
    generate_discovery_words,
    is_url_in_scope,
)

GENERIC_SPA_SHELL = (
    '<!DOCTYPE html><html><head><title>App</title></head>'
    '<body><div id="root">Loading...</div><script src="/app.js"></script></body></html>'
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


class SensitivePathValidationTests(unittest.TestCase):
    """Item 7: HTTP 200 alone must never mean 'high severity'. A catch-all SPA
    router returning the same generic shell for every path must be rejected or
    downgraded, never reported as a confirmed .env/.git/config/backup exposure."""

    def test_generic_spa_200_rejected_for_env(self):
        self.assertIsNone(
            classify_sensitive_path_hit("/.env", 200, GENERIC_SPA_SHELL))

    def test_generic_spa_200_rejected_for_git_head(self):
        self.assertIsNone(
            classify_sensitive_path_hit("/.git/HEAD", 200, GENERIC_SPA_SHELL))

    def test_generic_spa_200_rejected_for_git_config(self):
        self.assertIsNone(
            classify_sensitive_path_hit("/.git/config", 200, GENERIC_SPA_SHELL))

    def test_generic_spa_200_rejected_for_config_php(self):
        self.assertIsNone(
            classify_sensitive_path_hit("/config.php", 200, GENERIC_SPA_SHELL))

    def test_generic_spa_200_rejected_for_backup(self):
        self.assertIsNone(
            classify_sensitive_path_hit("/backup.zip", 200, GENERIC_SPA_SHELL,
                                        content_type="text/html"))

    def test_non_200_always_suppressed(self):
        self.assertIsNone(classify_sensitive_path_hit("/.env", 404, "KEY=value"))
        self.assertIsNone(classify_sensitive_path_hit("/.env", 403, "KEY=value"))

    def test_real_env_kv_content_is_high(self):
        body = "DB_PASSWORD=hunter2\nAPI_KEY=sk-abc123\nDEBUG=true\n"
        hit = classify_sensitive_path_hit("/.env", 200, body)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["severity"], "high")
        self.assertIn("Environment", hit["title"])

    def test_real_git_head_content_is_high(self):
        hit = classify_sensitive_path_hit("/.git/HEAD", 200, "ref: refs/heads/main\n")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["severity"], "high")

    def test_real_git_config_content_is_high(self):
        body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
        hit = classify_sensitive_path_hit("/.git/config", 200, body)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["severity"], "high")

    def test_real_php_config_content_is_high(self):
        body = "<?php\ndefine('DB_HOST', 'localhost');\n$config = ['debug' => true];\n"
        hit = classify_sensitive_path_hit("/config.php", 200, body)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["severity"], "high")

    def test_real_directory_listing_backup_is_high(self):
        body = "<html><title>Index of /backup</title><body>backup-2024.tar.gz</body></html>"
        hit = classify_sensitive_path_hit("/backup/", 200, body)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["severity"], "high")

    def test_baseline_differential_suppresses_catch_all(self):
        # Even a body that isn't the "generic SPA" pattern is suppressed if it's
        # near-identical to a definitely-nonexistent baseline path on the same host.
        weird_but_consistent_shell = "<pre>404 page not found, try again</pre>" * 5
        hit = classify_sensitive_path_hit(
            "/.env", 200, weird_but_consistent_shell,
            baseline_body=weird_but_consistent_shell)
        self.assertIsNone(hit)

    def test_unrecognized_path_generic_html_suppressed(self):
        self.assertIsNone(classify_sensitive_path_hit("/debug", 200, GENERIC_SPA_SHELL))

    def test_unrecognized_path_non_generic_becomes_low_candidate(self):
        hit = classify_sensitive_path_hit("/debug", 200, "DEBUG MODE: verbose=true, trace=on")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["severity"], "low")


if __name__ == "__main__":
    unittest.main()
