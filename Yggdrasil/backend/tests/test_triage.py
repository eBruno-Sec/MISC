"""Tests for core.triage: BROKKR actionability, SKULD gating, and MIMIR's
deterministic overclaim guard on attack-path severity/narrative."""
import unittest

from core.triage import (
    is_actionable_finding,
    sanitize_attack_path,
    skuld_trigger_reasons,
)


class ActionableFindingTests(unittest.TestCase):
    """Item 3: BROKKR must not starve on critical/high alone."""

    def test_critical_and_high_always_actionable(self):
        self.assertTrue(is_actionable_finding("Anything at all", "critical"))
        self.assertTrue(is_actionable_finding("Anything at all", "high"))

    def test_medium_injection_signal_is_actionable(self):
        self.assertTrue(is_actionable_finding(
            "Suspected SQL Injection (sqlmap heuristic, pending validation)", "medium"))
        self.assertTrue(is_actionable_finding("Reflected XSS on search", "medium"))
        self.assertTrue(is_actionable_finding("Path Traversal / LFI (file read)", "medium"))
        self.assertTrue(is_actionable_finding("Server-Side Request Forgery (cloud metadata)", "medium"))
        self.assertTrue(is_actionable_finding("Server-Side Template Injection", "medium"))
        self.assertTrue(is_actionable_finding("Potential IDOR: /api/orders/43", "medium"))
        self.assertTrue(is_actionable_finding("HTTP Parameter Pollution -> SQL Injection: id", "medium"))

    def test_medium_hygiene_findings_are_not_actionable(self):
        self.assertFalse(is_actionable_finding("SPF Record Missing", "medium"))
        self.assertFalse(is_actionable_finding("DMARC Record Missing", "medium"))
        self.assertFalse(is_actionable_finding("Dev/Staging Environments Exposed (1 subdomains)", "medium"))

    def test_low_and_info_are_not_actionable_even_if_injection_titled(self):
        # A LOW/INFO injection-adjacent note (e.g. a raw candidate) isn't strong
        # enough for BROKKR unless it's at least medium.
        self.assertFalse(is_actionable_finding("Reflected Input (possible reflected XSS): q", "low"))
        self.assertFalse(is_actionable_finding("AI / LLM Attack Surface Detected", "info"))

    def test_attack_path_always_actionable_regardless_of_severity(self):
        self.assertTrue(is_actionable_finding("Attack Path: Staging leak -> admin takeover", "medium"))
        self.assertTrue(is_actionable_finding("attack path: lowercase title", "medium"))


class SkuldTriggerTests(unittest.TestCase):
    """Item 4: SKULD must not run for mere SPF/DMARC or a generic AI-surface note."""

    def test_no_triggers_for_hygiene_only_findings(self):
        findings = [
            {"title": "SPF Record Missing", "severity": "medium"},
            {"title": "DMARC Record Missing", "severity": "medium"},
            {"title": "AI / LLM Attack Surface Detected (3 endpoint(s))", "severity": "info"},
        ]
        self.assertEqual(skuld_trigger_reasons(0, 0, findings), [])

    def test_exploitable_targets_trigger(self):
        reasons = skuld_trigger_reasons(2, 0, [])
        self.assertTrue(any("exploitable target" in r for r in reasons))

    def test_mimir_chains_trigger(self):
        reasons = skuld_trigger_reasons(0, 1, [])
        self.assertTrue(any("attack path" in r for r in reasons))

    def test_confirmed_sensitive_file_exposure_triggers(self):
        findings = [{"title": "Environment file exposed", "severity": "high"}]
        reasons = skuld_trigger_reasons(0, 0, findings)
        self.assertTrue(any("sensitive file" in r for r in reasons))

    def test_confirmed_injection_evidence_triggers(self):
        findings = [{"title": "SQL Injection (sqlmap-confirmed): id (GET)", "severity": "critical"}]
        reasons = skuld_trigger_reasons(0, 0, findings)
        self.assertTrue(any("injection evidence" in r for r in reasons))

    def test_suspected_signal_tier_injection_does_not_trigger(self):
        # A hedge-worded finding, even at high severity, must not count as
        # "confirmed injection evidence" — only genuinely confirmed findings do.
        findings = [{"title": "Suspected SQL Injection (sqlmap heuristic, pending validation)",
                    "severity": "high"}]
        self.assertEqual(skuld_trigger_reasons(0, 0, findings), [])

    def test_medium_severity_sensitive_file_does_not_trigger(self):
        findings = [{"title": "Environment file exposed", "severity": "medium"}]
        self.assertEqual(skuld_trigger_reasons(0, 0, findings), [])


class SanitizeAttackPathTests(unittest.TestCase):
    """Item 5: MIMIR must not turn medium error-smell into confirmed SQLi/RCE/
    full-compromise language, even if the model tries to."""

    def test_unconfirmed_source_caps_severity_and_disclaims(self):
        source = {
            "f1": {"title": "Suspected SQL Injection (sqlmap heuristic, pending validation)",
                   "severity": "medium"},
        }
        path = {
            "title": "Full database compromise",
            "severity": "critical",
            "narrative": "This confirmed SQL injection leads to full compromise of the database.",
            "finding_ids": ["f1"],
        }
        out = sanitize_attack_path(path, source)
        self.assertEqual(out["severity"], "medium")
        self.assertTrue(out["narrative"].lower().startswith("unconfirmed"))

    def test_sqli_error_signal_alone_cannot_reach_confirmed_tier(self):
        # The exact scenario named in the spec: sqlmap found 0 confirmed
        # injection points, only a single error-based signal exists.
        source = {
            "f1": {"title": "Suspected SQL Injection (error-based signal)", "severity": "high"},
        }
        path = {
            "title": "RCE via SQLi",
            "severity": "critical",
            "narrative": "Confirmed RCE achieved through this SQL injection.",
            "finding_ids": ["f1"],
        }
        out = sanitize_attack_path(path, source)
        self.assertEqual(out["severity"], "medium")
        self.assertIn("Unconfirmed", out["narrative"])

    def test_genuinely_confirmed_source_is_not_downgraded(self):
        source = {
            "f1": {"title": "SQL Injection (sqlmap-confirmed): id (GET)", "severity": "critical"},
            "f2": {"title": "Exposed .git Directory on host", "severity": "high"},
        }
        path = {
            "title": "Source code leak enables SQLi",
            "severity": "critical",
            "narrative": "Confirmed SQL injection extracted via sqlmap chains with source exposure.",
            "finding_ids": ["f1", "f2"],
        }
        out = sanitize_attack_path(path, source)
        self.assertEqual(out["severity"], "critical")
        self.assertFalse(out["narrative"].lower().startswith("unconfirmed"))

    def test_differential_proof_titles_count_as_confirmed_without_hedge_words(self):
        source = {"f1": {"title": "SQL Injection (boolean-based blind): id", "severity": "high"}}
        path = {"title": "Blind SQLi chain", "severity": "high",
                "narrative": "Blind boolean SQLi confirmed.", "finding_ids": ["f1"]}
        out = sanitize_attack_path(path, source)
        self.assertEqual(out["severity"], "high")

    def test_no_finding_ids_treated_as_unconfirmed(self):
        path = {"title": "Vague path", "severity": "critical", "narrative": "Full compromise.",
                "finding_ids": []}
        out = sanitize_attack_path(path, {})
        self.assertEqual(out["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
