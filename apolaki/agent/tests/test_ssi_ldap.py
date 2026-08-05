"""SSI (CWE-97) + LDAP (CWE-90) injection engines, distilled from *Beginner Web Application Pentester*.
Both confirm precisely: SSI via a marker-sandwich that only a real SSI execution can fill with a date;
LDAP via a directory-specific error signature that does NOT collide with SQLi/XPath."""
import blind_benchmark as bb
import ldap_tool as lp
import ssi_tool as si


# ---- SSI ----
def test_ssi_payload_is_benign_echo_between_markers():
    p = si.payload("dead")
    assert p.count("mkdeadmk") == 2 and '#echo var="DATE_GMT"' in p
    assert "#exec" not in p and "#include" not in p          # never destructive


def test_ssi_confirms_only_when_directive_executed_to_a_date():
    t = "dead"
    m = si.marker(t)
    # server EXECUTED the include -> a real date sits between our markers
    executed = "<html>hello %sMonday, 04-Aug-2026 12:00:00 GMT%s bye</html>" % (m, m)
    assert si.evaluate(executed, t)["confirmed"]
    # literal reflection (not executed) -> still the directive between the markers
    reflected = "<html>%s<!--#echo var=\"DATE_GMT\" -->%s</html>" % (m, m)
    assert not si.evaluate(reflected, t)["confirmed"]
    # HTML-encoded (output-encoded, safe) -> still contains #echo
    encoded = "<html>%s&lt;!--#echo var=\"DATE_GMT\" --&gt;%s</html>" % (m, m)
    assert not si.evaluate(encoded, t)["confirmed"]
    # a date elsewhere but NOT between our markers -> no confirmation
    assert not si.evaluate("date 2026-08-04 but markers absent", t)["confirmed"]
    # a non-date string between markers (server transformed it but not to a date) -> conservative: no
    assert not si.evaluate("%sHELLO%s" % (m, m), t)["confirmed"]


def test_ssi_finding_is_proof():
    f = si.finding("https://x/page", "parameter", "q", "the directive executed to a live date")
    assert f["family"] == "ssi_injection" and f["cwe"] == "CWE-97" and f["confidence"] == "confirmed"
    assert bb._has_proof(f)


# ---- LDAP ----
def test_ldap_probes_are_filter_metachar_breaks():
    p = lp.probes("admin")
    assert p["paren"] == "admin)" and p["star_group"] == "admin*)(" and p["amp"] == "admin("


def test_ldap_confirms_only_on_directory_error_signature():
    base = "<html>results for admin</html>"
    for err in ("javax.naming.directory.InvalidSearchFilterException: bad filter",
                "com.sun.jndi.ldap.LdapCtx failure",
                "LDAP: error code 34 - invalid DN syntax",
                "Bad search filter"):
        assert lp.evaluate(base, err)["confirmed"], err


def test_ldap_does_not_confirm_on_sqli_xpath_or_generic_error():
    base = "<html>results</html>"
    assert not lp.evaluate(base, "You have an error in your SQL syntax near ''' at line 1")["confirmed"]
    assert not lp.evaluate(base, "org.jaxen.saxpath.XPathSyntaxException: bad xpath")["confirmed"]
    assert not lp.evaluate(base, "<h1>500 Internal Server Error</h1>")["confirmed"]
    assert not lp.evaluate(base, "no results found")["confirmed"]


def test_ldap_no_confirm_when_baseline_already_has_signature():
    noisy = "debug: com.sun.jndi.ldap trace enabled"
    assert not lp.evaluate(noisy, noisy + " and more")["confirmed"]


def test_ldap_finding_is_proof():
    f = lp.finding("https://x/login", "user", "parameter", "an LDAP directory error appeared")
    assert f["family"] == "ldap_injection" and f["cwe"] == "CWE-90" and f["confidence"] == "confirmed"
    assert f["cvss_score"] == 8.2 and bb._has_proof(f)
