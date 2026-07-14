"""Tests for core.dependency_intel (the SCA brains). Pure module: imports only
json/re/urllib, so these run without SQLAlchemy or PyYAML.

Covers the spec's finding-model + guardrail requirements directly:
- vulnerable JS library fixture maps to CVE/GHSA/OSV ids,
- source map fixture extracts package + endpoints,
- a weak tech fingerprint never becomes a confirmed vuln (no CVE from a guess),
- exploit validation for dependency CVEs is manual-only (never default-executed),
- detected vulnerable component vs. validated exploit path are titled distinctly.
"""
import unittest

import core.dependency_intel as di


class JsFingerprintTests(unittest.TestCase):
    def test_content_banner_is_confirmed(self):
        comps = di.fingerprint_js_content(
            "/*! jQuery JavaScript Library v3.4.1 | (c) JS Foundation */", "https://t/js/app.js")
        self.assertEqual(len(comps), 1)
        self.assertEqual(comps[0]["name"], "jquery")
        self.assertEqual(comps[0]["version"], "3.4.1")
        self.assertEqual(comps[0]["confidence"], di.CONFIRMED)

    def test_filename_version_is_high(self):
        comps = di.fingerprint_url("https://t/assets/jquery-1.12.4.min.js")
        self.assertEqual((comps[0]["name"], comps[0]["version"]), ("jquery", "1.12.4"))
        self.assertEqual(comps[0]["confidence"], di.HIGH)

    def test_cdn_path_normalizes_name(self):
        comps = di.fingerprint_url(
            "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.11/lodash.min.js")
        self.assertEqual((comps[0]["name"], comps[0]["version"]), ("lodash", "4.17.11"))


class HeaderFingerprintTests(unittest.TestCase):
    def test_versioned_header_is_high(self):
        comps = di.fingerprint_headers({"Server": "nginx/1.18.0"})
        self.assertEqual((comps[0]["name"], comps[0]["version"], comps[0]["confidence"]),
                         ("nginx", "1.18.0", di.HIGH))

    def test_bare_header_is_low_and_versionless(self):
        # Scenario: a weak tech fingerprint (no version) must stay LOW confidence
        # and carry no version, so it can never be turned into a CVE claim.
        comps = di.fingerprint_headers({"Server": "cloudflare"})
        self.assertEqual(comps[0]["confidence"], di.LOW)
        self.assertEqual(comps[0]["version"], "")


class CveEligibilityGuardrailTests(unittest.TestCase):
    def test_low_confidence_is_never_cve_eligible(self):
        weak = di.make_component("nginx", "", "", "http-header:server", di.LOW)
        self.assertFalse(di.cve_eligible(weak))

    def test_versionless_high_is_not_eligible(self):
        # HIGH confidence but no concrete version -> still not eligible.
        c = di.make_component("bootstrap", "", "npm", "script-filename", di.HIGH)
        self.assertFalse(di.cve_eligible(c))

    def test_confirmed_with_version_is_eligible(self):
        c = di.make_component("jquery", "3.4.1", "npm", "js-content-banner", di.CONFIRMED)
        self.assertTrue(di.cve_eligible(c))

    def test_weak_fingerprint_finding_has_no_cve(self):
        weak = di.make_component("cloudflare", "", "", "http-header:server", di.LOW)
        finding = di.make_dependency_finding(weak, vulns=[])
        self.assertEqual(finding["vuln_ids"], [])
        self.assertEqual(finding["severity"], "info")


class OsvMappingTests(unittest.TestCase):
    def test_vulnerable_lib_maps_to_cve_alias(self):
        # Scenario: vulnerable JS library fixture -> CVE/GHSA/OSV.
        osv = {"vulns": [{
            "id": "GHSA-gxr4-xjj5-5px2",
            "aliases": ["CVE-2020-11022"],
            "summary": "jQuery XSS in htmlPrefilter",
            "database_specific": {"severity": "MEDIUM"},
            "affected": [{"ranges": [{"events": [{"introduced": "1.2.0"}, {"fixed": "3.5.0"}]}]}],
        }]}
        vulns = di.parse_osv_response(osv)
        self.assertEqual(vulns[0]["id"], "CVE-2020-11022")
        self.assertIn("GHSA-gxr4-xjj5-5px2", vulns[0]["aliases"])
        self.assertEqual(vulns[0]["fixed_versions"], ["3.5.0"])
        self.assertEqual(vulns[0]["severity"], "medium")

    def test_osv_query_shape(self):
        q = di.build_osv_query("lodash", "4.17.11", "npm")
        self.assertEqual(q, {"version": "4.17.11", "package": {"name": "lodash", "ecosystem": "npm"}})

    def test_osv_scanner_output_parsed(self):
        out = {"results": [{"source": {"path": "/package-lock.json"}, "packages": [{
            "package": {"name": "lodash", "version": "4.17.11", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "GHSA-p6mc-m468-83gg", "aliases": ["CVE-2019-10744"],
                                 "summary": "Prototype pollution"}]}]}]}
        parsed = di.parse_osv_scanner_output(out)
        self.assertEqual(len(parsed), 1)
        comp, vulns = parsed[0]
        self.assertEqual((comp["name"], comp["version"], comp["confidence"]),
                         ("lodash", "4.17.11", di.CONFIRMED))
        self.assertEqual(vulns[0]["id"], "CVE-2019-10744")

    def test_no_vulns_is_empty(self):
        self.assertEqual(di.parse_osv_response({"vulns": []}), [])


class ManifestTests(unittest.TestCase):
    def test_classify_known_manifests(self):
        self.assertEqual(di.classify_manifest("/package-lock.json")["ecosystem"], "npm")
        self.assertTrue(di.classify_manifest("/package-lock.json")["exact_versions"])
        self.assertFalse(di.classify_manifest("/package.json")["exact_versions"])
        self.assertIsNone(di.classify_manifest("/index.html"))

    def test_lockfile_body_accepted_html_rejected(self):
        self.assertTrue(di.looks_like_manifest_body("package-lock.json", '{"packages":{}}'))
        self.assertFalse(di.looks_like_manifest_body(
            "package-lock.json", "<!doctype html><html>SPA fallback</html>"))

    def test_parse_lockfile_exact_versions(self):
        import json
        body = json.dumps({"packages": {
            "node_modules/lodash": {"version": "4.17.11"},
            "node_modules/jquery": {"version": "3.4.1"}}})
        rows = di.parse_manifest("/package-lock.json", body)
        self.assertIn({"name": "lodash", "version": "4.17.11", "exact": True}, rows)
        self.assertIn({"name": "jquery", "version": "3.4.1", "exact": True}, rows)

    def test_requirements_only_pinned(self):
        rows = di.parse_manifest("/requirements.txt", "django==2.2.0\nrequests>=2.0\nflask")
        names = {r["name"] for r in rows}
        self.assertIn("django", names)
        self.assertNotIn("requests", names)   # a range/>= is not exact evidence
        self.assertNotIn("flask", names)


class SourceMapTests(unittest.TestCase):
    def test_extracts_packages_and_endpoints(self):
        # Scenario: source map fixture -> package/version + endpoints.
        import json
        sm = json.dumps({"sources": [
            "webpack:///./node_modules/lodash/lodash.js",
            "webpack:///./node_modules/@angular/core/index.js",
            "webpack:///./src/app/api/users.service.js",
            "webpack:///./src/routes/admin.js",
        ]})
        parsed = di.parse_source_map(sm)
        self.assertIn("lodash", parsed["packages"])
        self.assertIn("@angular/core", parsed["packages"])
        self.assertIn("src/app/api/users.service.js", parsed["endpoints"])
        self.assertIn("src/routes/admin.js", parsed["endpoints"])

    def test_bad_json_is_safe(self):
        self.assertEqual(di.parse_source_map("not json"),
                         {"packages": [], "sources": [], "endpoints": []})


class ProbeFamilyAndTitleTests(unittest.TestCase):
    def test_library_probe_families(self):
        self.assertEqual(set(di.library_probe_families("jQuery")), {"dom_xss", "prototype_pollution"})
        self.assertEqual(di.library_probe_families("lodash"), ["prototype_pollution"])
        self.assertEqual(di.library_probe_families("express"), ["nuclei_cve_template"])
        self.assertEqual(di.library_probe_families("totally-unknown-lib"), [])

    def test_manual_validation_note_requires_approval(self):
        # Scenario: exploit validation for dependency CVEs is manual-only.
        vulns = di.parse_osv_response({"vulns": [{"id": "GHSA-x", "aliases": ["CVE-2019-10744"]}]})
        comp = di.make_component("lodash", "4.17.11", "npm", "manifest:package-lock.json", di.CONFIRMED)
        f = di.make_dependency_finding(comp, vulns, validation=di.MANUAL_REQUIRED)
        self.assertIn("approval", f["exploitability_notes"].lower())

    def test_title_distinguishes_detected_vs_validated(self):
        # Scenario: report separates detected vulnerable component from confirmed
        # exploitation (title semantics enforce it).
        vulns = di.parse_osv_response({"vulns": [{"id": "G", "aliases": ["CVE-2020-11022"]}]})
        comp = di.make_component("jquery", "3.4.1", "npm", "js-content-banner", di.CONFIRMED)
        f = di.make_dependency_finding(comp, vulns)
        detected = di.dependency_finding_title(f, validated=False)
        validated = di.dependency_finding_title(f, validated=True)
        self.assertIn("Vulnerable Component Detected", detected)
        self.assertNotIn("Validated", detected)
        self.assertIn("Validated Vulnerable Component Exploit Path", validated)
        self.assertIn("CVE-2020-11022", detected)


if __name__ == "__main__":
    unittest.main()
