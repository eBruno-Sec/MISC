"""Default-credentials analyzer (WAHH ch18, CWE-1392 / WSTG-ATHN-02). Confirms only a recognised product interface
that (1) issued a Basic challenge and (2) accepted its ONE documented default pair with the product marker. A
changed credential, an open interface, or a non-product path all yield nothing (no FP). Single known value, never
a brute-force."""
import blind_benchmark as bb
import default_creds_tool as dc


def test_match_only_known_product_paths():
    assert dc.match("/manager/html")["product"].startswith("Apache Tomcat")
    assert dc.match("/jmx-console/")["product"].startswith("JBoss")
    assert dc.match("/admin") is None and dc.match("/manager/status") is None


def test_challenged_requires_basic_401():
    assert dc.challenged(401, {"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'}) is True
    assert dc.challenged(200, {}) is False                       # open interface -> not this engine
    assert dc.challenged(401, {"WWW-Authenticate": "Bearer"}) is False   # not Basic


def test_confirmed_needs_marker_and_200():
    e = dc.match("/manager/html")
    assert dc.confirmed(200, "<title>Tomcat Web Application Manager</title>", e) is True
    assert dc.confirmed(200, "<h1>Unrelated page</h1>", e) is False      # 200 but no admin marker
    assert dc.confirmed(403, "Tomcat Web Application Manager", e) is False   # creds changed -> forbidden


def test_finding_is_proof_with_cvss_and_rce_severity():
    from report import cvss31_base_score
    f = dc.finding("http://h/manager/html", dc.match("/manager/html"))
    assert f["family"] == "default_credentials" and f["severity"] == "critical" and bb._has_proof(f)
    assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
