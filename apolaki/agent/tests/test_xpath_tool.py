"""XPath injection oracle (CWE-643), distilled from *Beginner Web Application Pentester*. Confirmation is
XPath-SPECIFIC — it requires an XPath-processor error signature to appear on a quote/function break — so it
does NOT collide with SQLi (a bare 500 or boolean split, which SQLi also causes, must NOT confirm XPath).
This precision fix was made after the first cut false-positived on SQLi-vulnerable endpoints."""
import blind_benchmark as bb
import xpath_tool as xp


def test_probes_are_quote_and_function_breaks():
    p = xp.probes("admin")
    assert p["sq"] == "admin'" and p["dq"] == 'admin"'
    assert "|//*[" in p["fn"]          # an XPath-specific function/step break


def test_confirms_only_on_xpath_error_signature():
    base = "<html>results for admin</html>"
    # a real XPath processor error appears on the break -> confirmed
    err = "org.jaxen.saxpath.XPathSyntaxException: Expected token ')' at XPath ..."
    assert xp.evaluate(base, err)["confirmed"]
    err2 = "System.Xml.XPath.XPathException: '//user[' has an invalid token."
    assert xp.evaluate(base, err2)["confirmed"]


def test_does_NOT_confirm_on_sqli_or_generic_error():
    base = "<html>results</html>"
    # a SQL error must NOT be claimed as XPath (this was the false-positive bug)
    assert not xp.evaluate(base, "You have an error in your SQL syntax near ''' at line 1")["confirmed"]
    # a bare 500 / generic error page -> not XPath
    assert not xp.evaluate(base, "<html><h1>500 Internal Server Error</h1></html>")["confirmed"]
    # normal content -> not XPath
    assert not xp.evaluate(base, "<html>no results found</html>")["confirmed"]


def test_no_confirm_when_baseline_already_has_the_signature():
    # if the XPath error is present in the BASELINE too, the probe didn't cause it -> not confirmed
    noisy = "debug: net.sf.saxon trace enabled"
    assert not xp.evaluate(noisy, noisy + " and more")["confirmed"]


def test_xpath_error_extractor():
    assert xp.xpath_error("... javax.xml.xpath.XPathExpressionException ...")
    assert xp.xpath_error("xmlXPathEval: evaluation failed")
    assert not xp.xpath_error("all good, no results")


def test_finding_is_benchmark_proof():
    f = xp.finding("https://x/login", "username", "form field", "XPath-processor error signature appeared")
    assert f["family"] == "xpath_injection" and f["cwe"] == "CWE-643"
    assert f["confidence"] == "confirmed" and f["cvss_score"] == 8.2
    assert bb._has_proof(f)
