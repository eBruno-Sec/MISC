"""Engine-side SCA tests: the TYR manifest-exposure pass, the BROKKR
dependency validation plan, the SAGA reporting split, and the finding emitter.
Need SQLAlchemy for the real Ares/Hephaestus/Apollo, so they skip when it's
absent (they run in the container, which is what ships)."""
import importlib.util
import json
import unittest
from unittest.mock import patch

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, _stmt):
        return None

    async def commit(self):
        pass

    async def get(self, *_a, **_k):
        return None


class FakeResp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.request = None

    def json(self):
        return json.loads(self.text)


class FakeClient:
    """Minimal async httpx.AsyncClient stand-in driven by a url->FakeResp router."""
    def __init__(self, router):
        self._router = router

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def get(self, url, **_k):
        return self._router(url)

    async def post(self, url, **_k):
        return self._router(url)


if HAS_SQLALCHEMY:
    def _make(agent_cls):
        return agent_cls(FakeSession(), "m-sca")

    def _ares():
        from agents.ares import Ares
        return _make(Ares)

    def _heph():
        from agents.hephaestus import Hephaestus
        return _make(Hephaestus)

    def _apollo():
        from agents.apollo import Apollo
        return _make(Apollo)


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class ExposedManifestTests(unittest.IsolatedAsyncioTestCase):
    async def test_exposed_lockfile_creates_finding_and_components(self):
        from core.models import Finding
        ares = _ares()
        lock = json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.11"}}})

        def router(url, **_k):
            if url.endswith("/package-lock.json"):
                return FakeResp(200, lock)
            return FakeResp(404, "")

        with patch("httpx.AsyncClient", new=lambda *a, **k: FakeClient(router)):
            findings, components = await ares.detect_exposed_manifests("https://t.example", deep=False)

        self.assertTrue(any(f["path"] == "/package-lock.json" for f in findings))
        self.assertTrue(any(c["name"] == "lodash" and c["version"] == "4.17.11" for c in components))
        persisted = [o for o in ares.session.added if isinstance(o, Finding)]
        self.assertTrue(any("Exposed Dependency Manifest" in f.title for f in persisted))

    async def test_html_fallback_is_not_treated_as_manifest(self):
        ares = _ares()

        def router(url, **_k):
            # A catch-all SPA that 200s everything with index.html.
            return FakeResp(200, "<!doctype html><html><body>app</body></html>")

        with patch("httpx.AsyncClient", new=lambda *a, **k: FakeClient(router)):
            findings, components = await ares.detect_exposed_manifests("https://t.example", deep=False)
        self.assertEqual(findings, [])
        self.assertEqual(components, [])


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class EmitDependencyFindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_vulnerable_component_finding_created(self):
        import core.dependency_intel as di
        from core.models import Finding
        ares = _ares()
        comp = di.make_component("jquery", "3.4.1", "npm", "js-content-banner", di.CONFIRMED)
        vulns = di.parse_osv_response({"vulns": [{"id": "G", "aliases": ["CVE-2020-11022"]}]})
        finding = di.make_dependency_finding(comp, vulns)

        async def fake_capture(*_a, **_k):
            return None

        with patch.object(ares, "_capture_proof", side_effect=fake_capture):
            await ares._emit_dependency_finding(finding)

        persisted = [o for o in ares.session.added if isinstance(o, Finding)]
        self.assertEqual(len(persisted), 1)
        self.assertIn("Vulnerable Component Detected", persisted[0].title)
        self.assertIn("CVE-2020-11022", persisted[0].evidence)
        self.assertNotIn("Validated", persisted[0].title)


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class BrokkrValidationPlanTests(unittest.TestCase):
    def _dep(self, **over):
        base = {"component": "jquery", "version": "3.4.1", "confidence": "confirmed",
                "vuln_ids": ["CVE-2020-11022"], "probe_families": ["dom_xss", "prototype_pollution"],
                "location": "https://t.example/js/jquery.js", "fixed_versions": ["3.5.0"]}
        base.update(over)
        return base

    def test_vulnerable_dep_creates_plan_and_targets(self):
        heph = _heph()
        payloads, targets, plans = heph._dependency_validation_plans([self._dep()])
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0]["component"], "jquery")
        self.assertIn("dom_xss", plans[0]["families"])
        self.assertIn("https://t.example/js/jquery.js", targets)
        self.assertTrue(any(p["type"].startswith("DepValidation") for p in payloads))
        # Exploit validation stays approval-gated (safe-only plan).
        self.assertIn("approval", plans[0]["validation"].lower())

    def test_no_exploit_payloads_only_safe_probes(self):
        heph = _heph()
        payloads, _, _ = heph._dependency_validation_plans([self._dep()])
        joined = " ".join(p["payload"] for p in payloads).lower()
        for bad in ("nc ", "wget ", "curl ", "/etc/passwd", "rm -rf", "; id"):
            self.assertNotIn(bad, joined)

    def test_low_confidence_makes_no_plan(self):
        # Not enough evidence -> no exploitable target created.
        heph = _heph()
        _, targets, plans = heph._dependency_validation_plans([self._dep(confidence="low")])
        self.assertEqual(plans, [])
        self.assertEqual(targets, [])

    def test_no_cve_makes_no_plan(self):
        heph = _heph()
        _, _, plans = heph._dependency_validation_plans([self._dep(vuln_ids=[])])
        self.assertEqual(plans, [])

    def test_unmapped_library_makes_no_plan(self):
        heph = _heph()
        _, _, plans = heph._dependency_validation_plans([self._dep(component="obscure", probe_families=[])])
        self.assertEqual(plans, [])


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class SagaDependencySectionTests(unittest.TestCase):
    def _ctx(self, deps):
        return {"ares": {"offensive": {"dependencies": deps}}}

    def test_section_separates_detected_from_validated(self):
        apollo = _apollo()
        deps = [
            {"component": "jquery", "version": "3.4.1", "vuln_ids": ["CVE-2020-11022"],
             "fixed_versions": ["3.5.0"], "detection_source": "js-content-banner",
             "confidence": "confirmed", "severity": "medium"},
            {"component": "react", "version": "17.0.0", "vuln_ids": [],
             "detection_source": "cdn-path", "confidence": "high", "severity": "info"},
        ]
        html = apollo._dependency_section(self._ctx(deps))
        self.assertIn("Vulnerable Dependencies", html)
        self.assertIn("CVE-2020-11022", html)
        self.assertIn("Vulnerable component detected (not validated)", html)
        # react has no vulns -> shown as a detected-only component, not a vuln row.
        self.assertIn("react@17.0.0", html)
        # nothing was validated, so the validated-exploit status never appears.
        self.assertNotIn("Validated exploit path", html)

    def test_empty_when_no_dependencies(self):
        apollo = _apollo()
        self.assertEqual(apollo._dependency_section(self._ctx([])), "")


if __name__ == "__main__":
    unittest.main()
