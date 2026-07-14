"""Tests for core.spa_detect: catch-all/SPA detection. Pure module (no deps),
so these run anywhere. Guards the Juice Shop false-positive class where every
path returns an identical app shell."""
import unittest

import core.spa_detect as sd


def _shell(n=9900):
    return "<html><head><title>App</title></head><body><app-root>" + ("x" * n) + "</app-root></body></html>"


class DetectCatchAllTests(unittest.TestCase):
    def test_uniform_shell_is_detected(self):
        s = _shell()
        ca = sd.detect_catch_all([(200, s), (200, s + " "), (200, s)])
        self.assertIsNotNone(ca)
        self.assertEqual(ca.status, 200)

    def test_shell_response_matches(self):
        s = _shell()
        ca = sd.detect_catch_all([(200, s), (200, s)])
        self.assertTrue(ca.matches(200, s))
        self.assertTrue(ca.matches(200, s + "\n\n"))   # whitespace-insensitive

    def test_real_json_api_does_not_match_shell(self):
        s = _shell()
        ca = sd.detect_catch_all([(200, s), (200, s)])
        self.assertFalse(ca.matches(200, '{"status":"success","data":[{"id":1}]}'))

    def test_different_status_does_not_match(self):
        s = _shell()
        ca = sd.detect_catch_all([(200, s), (200, s)])
        self.assertFalse(ca.matches(404, s))

    def test_non_uniform_samples_return_none(self):
        self.assertIsNone(sd.detect_catch_all([(200, "aaaa" * 40), (200, "zzzz" * 200)]))

    def test_mixed_statuses_return_none(self):
        s = _shell()
        self.assertIsNone(sd.detect_catch_all([(200, s), (404, s)]))

    def test_too_few_samples_return_none(self):
        self.assertIsNone(sd.detect_catch_all([(200, _shell())]))

    def test_trivially_short_bodies_ignored(self):
        # A 3-byte "ok" repeated is not a meaningful shell to suppress.
        self.assertIsNone(sd.detect_catch_all([(200, "ok"), (200, "ok")]))


class LooksLikeJsonTests(unittest.TestCase):
    def test_json_content_type(self):
        self.assertTrue(sd.looks_like_json("whatever", "application/json; charset=utf-8"))

    def test_json_body_shape(self):
        self.assertTrue(sd.looks_like_json('   {"a":1}'))
        self.assertTrue(sd.looks_like_json("[1,2,3]"))

    def test_html_is_not_json(self):
        self.assertFalse(sd.looks_like_json("<html><body>x</body></html>"))


if __name__ == "__main__":
    unittest.main()
