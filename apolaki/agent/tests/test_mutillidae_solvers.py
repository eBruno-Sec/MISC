"""Tests for the Mutillidae lab prover -- structure, lab wiring, and response-oracle behaviour. No live
Mutillidae needed (graceful degrade covers the network path)."""
from __future__ import annotations

import httpx
import labs
import mutillidae_solvers


_VULNERABLE_RESPONSES = {
    ("GET", "/index.php", (("page", "/etc/passwd"),), ()):
        "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    ("POST", "/index.php", (("page", "dns-lookup.php"),),
     (("dns-lookup-php-submit-button", "Lookup DNS"), ("target_host", "127.0.0.1;id"))):
        "uid=33(www-data) gid=33(www-data)",
    ("POST", "/index.php", (("page", "dns-lookup.php"),),
     (("dns-lookup-php-submit-button", "Lookup DNS"),
      ("target_host", "<script>alert(1)</script>"))):
        "Lookup result: <script>alert(1)</script>",
    ("GET", "/index.php",
     (("forwardurl", "http://evil.example/"), ("page", "redirectandlog.php")), ()):
        "Redirecting to http://evil.example/",
}


class _ResponseClient:
    def __init__(self, responses):
        self.responses = responses

    @staticmethod
    def _key(method, path, params=None, data=None):
        return method, path, tuple(sorted((params or {}).items())), tuple(sorted((data or {}).items()))

    def get(self, path, params=None, **_kwargs):
        text = self.responses.get(self._key("GET", path, params=params), "clean response")
        return type("Response", (), {"text": text})()

    def post(self, path, params=None, data=None, **_kwargs):
        text = self.responses.get(self._key("POST", path, params=params, data=data), "clean response")
        return type("Response", (), {"text": text})()

    def close(self):
        pass


def test_prove_degrades_when_unreachable():
    r = mutillidae_solvers.prove("http://127.0.0.1:1")
    assert r["lab"] == "mutillidae"
    assert r.get("confirmed") == [] or "error" in r


def test_probes_cover_the_target_classes():
    classes = {p[0] for p in mutillidae_solvers._PROBES}
    assert {"open_redirect", "path_traversal", "command_injection", "reflected_xss"} <= classes


def test_mutillidae_registered_as_a_lab():
    assert "mutillidae" in labs.list_labs()
    r = labs.solve("mutillidae", "http://127.0.0.1:1")
    assert r.get("lab") == "mutillidae"


def test_synthetic_vulnerable_responses_fire_each_oracle(monkeypatch):
    monkeypatch.setattr(httpx, "Client", lambda **_kwargs: _ResponseClient(_VULNERABLE_RESPONSES))
    result = mutillidae_solvers.prove("http://mutillidae.test")
    assert result["probes"] == {
        "path_traversal": True,
        "command_injection": True,
        "reflected_xss": True,
        "open_redirect": True,
    }
    assert result["confirmed"] == ["command_injection", "open_redirect", "path_traversal", "reflected_xss"]


def test_clean_responses_fire_no_oracle(monkeypatch):
    monkeypatch.setattr(httpx, "Client", lambda **_kwargs: _ResponseClient({}))
    result = mutillidae_solvers.prove("http://mutillidae.test")
    assert result["probes"] == {
        "path_traversal": False,
        "command_injection": False,
        "reflected_xss": False,
        "open_redirect": False,
    }
    assert result["confirmed"] == []
