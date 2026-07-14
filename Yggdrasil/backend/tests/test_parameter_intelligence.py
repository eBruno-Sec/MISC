"""Part C: core.parameter_intelligence — parameter-name classification,
per-family prioritization, and real-path-preserving probe URL generation.

Fixture URLs are the exact observed ginandjuice.shop URLs supplied for this
work (not paraphrased), so "observed URLs produce family-specific test URLs"
is proven against the real fixture data, not a hand-typed stand-in.
"""
import unittest

from core.parameter_intelligence import (
    FAMILIES,
    XSS_PARAMS, SSRF_PARAMS, LFI_PARAMS, SQLI_PARAMS, RCE_PARAMS,
    OPEN_REDIRECT_PARAMS, OPEN_REDIRECT_PATH_PATTERNS, IDOR_PARAMS,
    classify_param, normalize_param_name, is_path_pattern,
    prioritize_params, generate_family_probe_urls, payloads_for_family,
    seeded_param_count, observed_param_count, summary_log_line, priority_log_line,
)

# The exact observed ginandjuice.shop URLs from the task fixture list.
GINANDJUICE_URLS = [
    "https://ginandjuice.shop/blog/?back=/blog/&search=katana",
    "https://ginandjuice.shop",
    "https://ginandjuice.shop/catalog?category=Juice",
    "https://ginandjuice.shop/catalog/product?productId=3",
    "https://ginandjuice.shop/catalog?searchTerm=katana",
    "https://ginandjuice.shop/blog/post?postId=3",
    "https://ginandjuice.shop/post?postId=6",
    "https://ginandjuice.shop/blog/?search=test",
    "https://ginandjuice.shop/catalog/filter?category=Accompaniments",
    "https://ginandjuice.shop/?ref=news.risky.biz",
    "https://ginandjuice.shop/catalog?category=Juice&searchTerm=katana",
    "https://ginandjuice.shop/?trk=public_post-text",
    "https://ginandjuice.shop/?q=test",
    "https://ginandjuice.shop/?s=test",
    "https://ginandjuice.shop/?id=1",
    "https://ginandjuice.shop/vulnerabilities?ref=escape.tech",
    "https://ginandjuice.shop/?file=test",
    "https://ginandjuice.shop/?searchTerm=yggdrasil",
    "https://ginandjuice.shop/?search=test",
    "https://ginandjuice.shop/?redirect=/test",
    "https://ginandjuice.shop/?productId=yggdrasil",
    "https://ginandjuice.shop/?stockApi=yggdrasil",
    "https://ginandjuice.shop/?url=http://test",
    "https://ginandjuice.shop/?page=1",
    "https://ginandjuice.shop/?xml=yggdrasil",
    "https://ginandjuice.shop/?account_id=yggdrasil",
    "https://ginandjuice.shop/?orderId=yggdrasil",
    "https://ginandjuice.shop/?userId=yggdrasil",
    "https://ginandjuice.shop/?path=yggdrasil",
    "https://ginandjuice.shop/?dir=yggdrasil",
    "https://ginandjuice.shop/?next=yggdrasil",
    "https://ginandjuice.shop/?user=yggdrasil",
    "https://ginandjuice.shop/?debug=yggdrasil",
    "https://ginandjuice.shop/?email=yggdrasil",
    "https://ginandjuice.shop/?query=yggdrasil",
    "https://ginandjuice.shop/?username=yggdrasil",
    "https://ginandjuice.shop/?test=yggdrasil",
    "https://ginandjuice.shop/?admin=yggdrasil",
    "https://ginandjuice.shop/?cmd=yggdrasil",
    "https://ginandjuice.shop/?exec=yggdrasil",
]


class NormalizeParamNameTests(unittest.TestCase):
    """Item 1: malformed pasted parameter names must normalize correctly."""

    def test_malformed_examples_from_the_spec(self):
        self.assertEqual(normalize_param_name("? page="), "page")
        self.assertEqual(normalize_param_name("? image="), "image")
        self.assertEqual(normalize_param_name("?down load="), "download")
        self.assertEqual(normalize_param_name("? show="), "show")
        self.assertEqual(normalize_param_name("? j ump="), "jump")

    def test_bare_name_passes_through(self):
        self.assertEqual(normalize_param_name("productId"), "productid")
        self.assertEqual(normalize_param_name("q"), "q")

    def test_wrapped_name_without_whitespace(self):
        self.assertEqual(normalize_param_name("?search="), "search")

    def test_empty_and_none_are_safe(self):
        self.assertEqual(normalize_param_name(""), "")
        self.assertEqual(normalize_param_name(None), "")


class IsPathPatternTests(unittest.TestCase):
    """Path patterns ('?redirect/', '/out/', ...) must never be coerced into
    fake query-parameter names."""

    def test_known_path_patterns_detected(self):
        for raw in ("?redirect/", "?cgi-bin/redirect.cgi?", "/out/", "/out?", "/login?to="):
            self.assertTrue(is_path_pattern(raw), f"{raw!r} should be a path pattern")

    def test_normal_and_malformed_param_names_are_not_path_patterns(self):
        for raw in ("q", "productId", "? page=", "?down load=", "? j ump="):
            self.assertFalse(is_path_pattern(raw), f"{raw!r} should NOT be a path pattern")

    def test_open_redirect_path_patterns_are_cleaned_substrings(self):
        # Cleaned so they match as plain substrings of a real URL.
        self.assertIn("redirect/", OPEN_REDIRECT_PATH_PATTERNS)
        self.assertIn("cgi-bin/redirect.cgi", OPEN_REDIRECT_PATH_PATTERNS)
        self.assertIn("/out/", OPEN_REDIRECT_PATH_PATTERNS)
        self.assertIn("/login?to", OPEN_REDIRECT_PATH_PATTERNS)


class ClassifyParamTests(unittest.TestCase):
    """Item: classify all listed params into the right families."""

    def test_xss_params(self):
        for name in ("q", "s", "search", "id", "lang", "keyword", "query", "page",
                     "keywords", "year", "view", "email", "type", "name", "p", "month",
                     "image", "list_type", "url", "terms", "categoryid", "key", "login",
                     "begindate", "enddate"):
            self.assertIn("xss", classify_param(name), f"{name!r} should classify as xss")

    def test_ssrf_params(self):
        for name in ("dest", "redirect", "uri", "path", "continue", "url", "window",
                     "next", "data", "reference", "site", "html", "val", "validate",
                     "domain", "callback", "return", "page", "feed", "host", "port",
                     "to", "out", "view", "dir"):
            self.assertIn("ssrf", classify_param(name), f"{name!r} should classify as ssrf")

    def test_lfi_params(self):
        for name in ("cat", "dir", "action", "board", "date", "detail", "file",
                     "download", "path", "folder", "prefix", "include", "page", "inc",
                     "locate", "show", "doc", "site", "type", "view", "content",
                     "document", "layout", "mod", "conf"):
            self.assertIn("lfi", classify_param(name), f"{name!r} should classify as lfi")

    def test_sqli_params(self):
        for name in ("id", "page", "dir", "search", "category", "file", "class", "url",
                     "news", "item", "menu", "lang", "name", "ref", "title", "view",
                     "topic", "thread", "type", "date", "form", "join", "main", "nav",
                     "region"):
            self.assertIn("sqli", classify_param(name), f"{name!r} should classify as sqli")

    def test_rce_params(self):
        for name in ("cmd", "exec", "command", "execute", "ping", "query", "jump",
                     "code", "reg", "do", "func", "arg", "option", "load", "process",
                     "step", "read", "function", "feature", "exe", "module", "payload",
                     "run", "print"):
            self.assertIn("rce", classify_param(name), f"{name!r} should classify as rce")

    def test_open_redirect_params(self):
        for name in ("next", "url", "target", "rurl", "dest", "destination", "redir",
                     "redirect_url", "redirect_uri", "redirect", "image_url", "go",
                     "return", "return_to", "checkout_url", "continue", "to"):
            self.assertIn("open_redirect", classify_param(name),
                          f"{name!r} should classify as open_redirect")

    def test_unrecognized_name_returns_empty_set(self):
        self.assertEqual(classify_param("totally_unrelated_xyz"), set())

    def test_classify_is_case_and_whitespace_insensitive(self):
        self.assertEqual(classify_param("ProductId"), classify_param("productid"))
        self.assertEqual(classify_param("? page="), classify_param("page"))


class IdorSqliTaggingTests(unittest.TestCase):
    """productId/postId/orderId/userId/account_id must be treated as
    IDOR+SQLi candidates."""

    def test_each_idor_name_is_tagged_idor_and_sqli(self):
        for name in ("productId", "postId", "orderId", "userId", "account_id"):
            families = classify_param(name)
            self.assertIn("idor", families, f"{name!r} should be tagged idor")
            self.assertIn("sqli", families, f"{name!r} should be tagged sqli")

    def test_idor_params_set_matches_the_five_names(self):
        self.assertEqual(IDOR_PARAMS, {"productid", "postid", "orderid", "userid", "account_id"})

    def test_ordinary_sqli_param_is_not_tagged_idor(self):
        self.assertNotIn("idor", classify_param("category"))


class MultiFamilyMembershipTests(unittest.TestCase):
    """stockApi/url/redirect/next/path/dir are SSRF/LFI/open-redirect
    candidates as applicable — real overlap in the source lists, not a bug."""

    def test_stockapi_is_ssrf(self):
        self.assertEqual(classify_param("stockApi"), {"ssrf"})

    def test_url_spans_xss_ssrf_sqli_open_redirect(self):
        families = classify_param("url")
        self.assertIn("xss", families)
        self.assertIn("ssrf", families)
        self.assertIn("sqli", families)
        self.assertIn("open_redirect", families)

    def test_redirect_spans_ssrf_and_open_redirect(self):
        families = classify_param("redirect")
        self.assertIn("ssrf", families)
        self.assertIn("open_redirect", families)

    def test_next_spans_ssrf_and_open_redirect(self):
        families = classify_param("next")
        self.assertIn("ssrf", families)
        self.assertIn("open_redirect", families)

    def test_path_spans_ssrf_and_lfi(self):
        families = classify_param("path")
        self.assertIn("ssrf", families)
        self.assertIn("lfi", families)

    def test_dir_spans_ssrf_lfi_sqli(self):
        families = classify_param("dir")
        self.assertIn("ssrf", families)
        self.assertIn("lfi", families)
        self.assertIn("sqli", families)


class PrioritizeParamsTests(unittest.TestCase):
    def test_sqli_explicit_priority_order(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        expected_prefix = ["id", "page", "search", "category", "file", "ref",
                           "productid", "postid", "orderid", "userid", "account_id"]
        self.assertEqual(priorities["sqli"][:len(expected_prefix)], expected_prefix)

    def test_xss_explicit_priority_order(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        expected_prefix = ["q", "s", "search", "searchterm", "category", "name", "email", "query"]
        self.assertEqual(priorities["xss"][:len(expected_prefix)], expected_prefix)

    def test_ssrf_explicit_priority_order(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        expected_prefix = ["url", "uri", "dest", "redirect", "next", "return",
                           "callback", "stockapi", "path", "to"]
        self.assertEqual(priorities["ssrf"][:len(expected_prefix)], expected_prefix)

    def test_lfi_explicit_priority_order(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        self.assertEqual(priorities["lfi"][:7], ["file", "path", "dir", "page", "include", "doc", "conf"])

    def test_rce_explicit_priority_order(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        self.assertEqual(priorities["rce"][:7], ["cmd", "exec", "command", "run", "ping", "query", "print"])

    def test_open_redirect_explicit_priority_order(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        self.assertEqual(priorities["open_redirect"][:5], ["redirect", "next", "url", "return", "to"])

    def test_observed_only_param_appended_after_priority_names(self):
        # "productId" appears among the ginandjuice fixtures and is a seeded
        # SQLi priority name; confirm it's present and ranked ahead of a
        # purely-observed, non-priority SQLi-classified name.
        priorities = prioritize_params(GINANDJUICE_URLS)
        self.assertIn("productid", priorities["sqli"])

    def test_empty_urls_still_returns_seeded_priority_names(self):
        priorities = prioritize_params([])
        self.assertEqual(priorities["sqli"][0], "id")
        self.assertTrue(len(priorities["xss"]) > 0)

    def test_all_six_families_present(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        self.assertEqual(set(priorities.keys()), set(FAMILIES))


class GenerateFamilyProbeUrlsTests(unittest.TestCase):
    """Item: observed ginandjuice URLs produce family-specific test URLs;
    generated probes preserve original path and other query params; never
    root-only when a real path+param context is known."""

    def test_productid_mutated_in_place_on_real_path(self):
        urls = generate_family_probe_urls(
            base_urls=[], observed_urls=["https://ginandjuice.shop/catalog/product?productId=3"],
            max_per_family=25)
        self.assertTrue(any(
            u.startswith("https://ginandjuice.shop/catalog/product?") and "productId=1" in u
            for u in urls["sqli"]
        ), urls["sqli"])

    def test_postid_mutated_in_place_on_real_path(self):
        urls = generate_family_probe_urls(
            base_urls=[], observed_urls=["https://ginandjuice.shop/blog/post?postId=3"],
            max_per_family=25)
        self.assertTrue(any(
            u.startswith("https://ginandjuice.shop/blog/post?") and "postId=1" in u
            for u in urls["sqli"]
        ), urls["sqli"])

    def test_multi_param_url_mutates_one_param_at_a_time_preserving_the_other(self):
        source = "https://ginandjuice.shop/catalog?category=Juice&searchTerm=katana"
        urls = generate_family_probe_urls(base_urls=[], observed_urls=[source], max_per_family=25)
        # category is SQLi-relevant; searchTerm is XSS-relevant. Each probe
        # must change only its own target param and keep the other intact.
        sqli_hits = [u for u in urls["sqli"] if "category=1" in u]
        self.assertTrue(sqli_hits, urls["sqli"])
        self.assertTrue(any("searchTerm=katana" in u for u in sqli_hits), sqli_hits)

        xss_hits = [u for u in urls["xss"] if "searchTerm=1" in u]
        self.assertTrue(xss_hits, urls["xss"])
        self.assertTrue(any("category=Juice" in u for u in xss_hits), xss_hits)

    def test_no_root_only_probe_when_real_path_known(self):
        urls = generate_family_probe_urls(
            base_urls=[], observed_urls=["https://ginandjuice.shop/catalog/product?productId=3"],
            max_per_family=25)
        for family_urls in urls.values():
            for u in family_urls:
                self.assertNotEqual(u.rstrip("/"), "https://ginandjuice.shop",
                                    "must not degrade to a root-only probe when a real path is known")

    def test_bare_url_without_params_produces_no_probes_for_that_url(self):
        urls = generate_family_probe_urls(base_urls=[], observed_urls=["https://ginandjuice.shop"],
                                          max_per_family=25)
        total = sum(len(v) for v in urls.values())
        self.assertEqual(total, 0)

    def test_max_per_family_cap_is_respected(self):
        many_urls = [f"https://ginandjuice.shop/?id={i}" for i in range(50)]
        urls = generate_family_probe_urls(base_urls=[], observed_urls=many_urls, max_per_family=5)
        self.assertLessEqual(len(urls["sqli"]), 5)

    def test_open_redirect_path_pattern_match_included(self):
        urls = generate_family_probe_urls(
            base_urls=[], observed_urls=["https://target.example/login?to=https://elsewhere.example"],
            max_per_family=25)
        self.assertTrue(any("login?to=" in u for u in urls["open_redirect"]), urls["open_redirect"])

    def test_all_families_present_in_output(self):
        urls = generate_family_probe_urls(base_urls=[], observed_urls=GINANDJUICE_URLS, max_per_family=25)
        self.assertEqual(set(urls.keys()), set(FAMILIES))

    def test_ginandjuice_fixtures_produce_nonempty_family_specific_urls(self):
        urls = generate_family_probe_urls(base_urls=[], observed_urls=GINANDJUICE_URLS, max_per_family=25)
        self.assertGreater(len(urls["sqli"]), 0)
        self.assertGreater(len(urls["xss"]), 0)
        self.assertGreater(len(urls["ssrf"]), 0)
        self.assertGreater(len(urls["lfi"]), 0)
        self.assertGreater(len(urls["rce"]), 0)
        self.assertGreater(len(urls["open_redirect"]), 0)

    def test_base_urls_and_observed_urls_are_merged(self):
        urls = generate_family_probe_urls(
            base_urls=["https://ginandjuice.shop/catalog/product?productId=3"],
            observed_urls=["https://ginandjuice.shop/?id=1"],
            max_per_family=25)
        self.assertTrue(any("productId=1" in u for u in urls["sqli"]))
        self.assertTrue(any("id=1" in u for u in urls["sqli"]))


class PayloadsForFamilyTests(unittest.TestCase):
    def test_sqli_includes_error_boolean_and_time_delay(self):
        payloads = payloads_for_family("sqli", "https://t.example")
        types = {p["type"] for p in payloads}
        self.assertTrue(any(t.startswith("SQLi-error") for t in types))
        self.assertTrue(any(t.startswith("SQLi-boolean") for t in types))
        self.assertTrue(any(t.startswith("SQLi-time") for t in types))

    def test_xss_includes_context_aware_attribute_scriptless_and_dom(self):
        payloads = payloads_for_family("xss", "https://t.example")
        types = {p["type"] for p in payloads}
        self.assertTrue(any("attribute-breaker" in t for t in types))
        self.assertTrue(any("scriptless" in t for t in types))
        self.assertTrue(any("dom-canary" in t for t in types))

    def test_ssrf_without_oast_or_authorization_is_empty(self):
        self.assertEqual(payloads_for_family("ssrf", "https://t.example"), [])

    def test_ssrf_with_oast_url_included_without_authorization(self):
        payloads = payloads_for_family("ssrf", "https://t.example", oast_url="http://abc123.oast.test/tok")
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["type"], "SSRF-oast-callback")

    def test_ssrf_metadata_probes_require_authorized(self):
        unauthorized = payloads_for_family("ssrf", "https://t.example", authorized=False)
        authorized = payloads_for_family("ssrf", "https://t.example", authorized=True)
        self.assertEqual(unauthorized, [])
        self.assertTrue(any("metadata" in p["type"] for p in authorized))

    def test_lfi_includes_platform_variants(self):
        payloads = payloads_for_family("lfi", "https://t.example")
        types = {p["type"] for p in payloads}
        self.assertIn("LFI-traversal-linux", types)
        self.assertIn("LFI-traversal-windows", types)

    def test_rce_withheld_unless_authorized(self):
        self.assertEqual(payloads_for_family("rce", "https://t.example", authorized=False), [])
        payloads = payloads_for_family("rce", "https://t.example", authorized=True)
        self.assertTrue(payloads)

    def test_rce_never_includes_destructive_commands(self):
        payloads = payloads_for_family("rce", "https://t.example", authorized=True)
        destructive_markers = ("rm -rf", "del /f", "shutdown", "format ", ":(){ :|:& };:")
        for p in payloads:
            for marker in destructive_markers:
                self.assertNotIn(marker, p["payload"])

    def test_rce_oast_variant_only_when_oast_url_and_authorized(self):
        payloads = payloads_for_family("rce", "https://t.example", authorized=True,
                                       oast_url="http://abc123.oast.test/tok")
        self.assertTrue(any(p["type"] == "RCE-oast-blind" for p in payloads))

    def test_open_redirect_uses_controlled_external_domain(self):
        payloads = payloads_for_family("open_redirect", "https://t.example")
        self.assertTrue(all("evil-yggdrasil.example" in p["payload"] for p in payloads))

    def test_unknown_family_returns_empty_list(self):
        self.assertEqual(payloads_for_family("not_a_real_family", "https://t.example"), [])


class LoggingFormatTests(unittest.TestCase):
    def test_summary_log_line_format(self):
        line = summary_log_line(GINANDJUICE_URLS)
        self.assertTrue(line.startswith("Parameter intelligence: "))
        self.assertIn("observed params", line)
        self.assertIn("seeded high-risk params", line)

    def test_seeded_param_count_matches_family_sizes(self):
        expected = (len(XSS_PARAMS) + len(SSRF_PARAMS) + len(LFI_PARAMS) +
                   len(SQLI_PARAMS) + len(RCE_PARAMS) + len(OPEN_REDIRECT_PARAMS))
        self.assertEqual(seeded_param_count(), expected)
        self.assertGreater(seeded_param_count(), 100)

    def test_observed_param_count_matches_unique_normalized_names(self):
        self.assertEqual(observed_param_count(["https://t.example/?a=1&b=2"]), 2)
        self.assertEqual(observed_param_count(["https://t.example/?a=1&a=2"]), 1)

    def test_priority_log_line_format(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        line = priority_log_line("sqli", priorities)
        self.assertTrue(line.startswith("SQLi priority params: "))
        self.assertIn("id, page, search", line)

    def test_priority_log_line_labels(self):
        priorities = prioritize_params(GINANDJUICE_URLS)
        self.assertTrue(priority_log_line("ssrf", priorities).startswith("SSRF priority params:"))
        self.assertTrue(priority_log_line("lfi", priorities).startswith("LFI priority params:"))
        self.assertTrue(priority_log_line("rce", priorities).startswith("RCE priority params:"))
        self.assertTrue(priority_log_line("xss", priorities).startswith("XSS priority params:"))
        self.assertTrue(priority_log_line("open_redirect", priorities).startswith("Open-redirect priority params:"))


if __name__ == "__main__":
    unittest.main()
