"""Item 1: OWASP ZAP service wiring in docker-compose.yml.

Parsed as raw text rather than via a YAML library so this test carries no new
dependency (PyYAML isn't in requirements.txt) — it verifies the literal content
the spec asked for: a zap service on the stable image, daemon on 8090, the
backend's ZAP_URL, and a non-blocking depends_on relationship.
"""
import os
import unittest

COMPOSE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "docker-compose.yml")
)


class DockerComposeZapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
            cls.text = f.read()

    def test_zap_service_defined(self):
        self.assertIn("\n  zap:\n", self.text)

    def test_zap_uses_stable_image(self):
        self.assertIn("ghcr.io/zaproxy/zaproxy:stable", self.text)

    def test_zap_daemon_on_internal_port_8090(self):
        self.assertIn("-daemon", self.text)
        self.assertIn("8090", self.text)
        self.assertIn('-port 8090', self.text)

    def test_backend_gets_zap_url_env(self):
        self.assertIn("ZAP_URL: http://zap:8090", self.text)

    def test_zap_api_key_is_optional_env(self):
        self.assertIn("ZAP_API_KEY", self.text)

    def test_backend_depends_on_zap_without_blocking(self):
        # Must reference zap in backend's depends_on, and use service_started
        # (not service_healthy) so a slow/unhealthy ZAP daemon never blocks
        # backend startup indefinitely.
        depends_idx = self.text.index("depends_on:", self.text.index("backend:"))
        backend_depends_block = self.text[depends_idx:depends_idx + 700]
        self.assertIn("zap:", backend_depends_block)
        zap_idx = backend_depends_block.index("zap:")
        after_zap = backend_depends_block[zap_idx:zap_idx + 60]
        self.assertIn("service_started", after_zap)
        self.assertNotIn("service_healthy", after_zap)

    def test_zap_has_no_published_host_port(self):
        # Same "internal-network-only" posture as backend: expose, not ports.
        zap_idx = self.text.index("\n  zap:\n")
        zap_block = self.text[zap_idx:zap_idx + 900]
        next_service_idx = zap_block.find("\n  backend:")
        if next_service_idx != -1:
            zap_block = zap_block[:next_service_idx]
        self.assertIn("expose:", zap_block)
        self.assertNotIn("ports:", zap_block)


if __name__ == "__main__":
    unittest.main()
