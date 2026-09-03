"""Q-176 - Host-header injection was graded by REFLECTION when the claim is about LANDING SITE.

THE DETECTION WAS RIGHT AND IS UNCHANGED. Every body reflection that fired before still fires. What
was wrong is that 62 of 65 rows on one mutillidae mission carried the same LOW and the same
`success_oracle` -- "the injected host appears in the response body ... so the app trusts the Host
header" -- while a replay showed the host landing in three structurally different places:

    /javascript/jQuery/?C=N;O=D  Host 200  <address>Apache/2.4.7 (Ubuntu) Server at HOST Port 80</address>
    /nope-404-page               Host 404  <address>...Server at HOST Port 80</address>
    /webservices/soap/ws-user-account.php?wsdl  Host 200  <soap:address location="http://HOST/..."/>
    /phpmyadmin/server_databases.php  Host 200  parent.document.title = 'HOST / 127.0.0.1 | phpMyAdmin'
    /phpmyadmin/main.php         Host 200  document.title AND <a href="http://HOST/phpmyadmin/chk_rel.php...">
    /index.php  and  /           Host 200  THE HOST DOES NOT APPEAR AT ALL

The last line is the negative control that decides it: the APPLICATION never reflects the Host. Only
Apache's own generated documents do (404 page, mod_autoindex listing), in an inert `<address>` text
node, because `UseCanonicalName Off` + `ServerSignature On` is the stock Ubuntu default. Reporting
that as an application defect is a wrong claim, 40 times, and it buries the 4 rows where the host
becomes a WSDL `soap:address` that redirects every SOAP client to the attacker.

BOTH DIRECTIONS ARE TESTED, because "downgrade everything" satisfies the downgrade half perfectly
and is a worse oracle than the one it replaces. The WSDL body, the phpMyAdmin href, a form action, a
password-reset URL and a protocol-relative link must all still grade LOW.

Every fixture below is a VERBATIM excerpt of a real response captured from the local mutillidae lab
with `Host: <probe host>` (the probe host substituted for ws._EVIL_HOST), not an invention.
"""
import web_security as ws


EVIL = ws._EVIL_HOST

# -- verbatim lab captures -----------------------------------------------------

#: http://mutillidae/javascript/jQuery/?C=N;O=D -- mod_autoindex listing, HTTP 200.
AUTOINDEX = ('<html><head><title>Index of /javascript/jQuery</title></head><body>'
             '<h1>Index of /javascript/jQuery</h1><table><tr><th colspan="5"><hr></th></tr>\n'
             '</table>\n<address>Apache/2.4.7 (Ubuntu) Server at %s Port 80</address>\n'
             '</body></html>\n' % EVIL)

#: http://mutillidae/nope-404-page -- Apache's own error document, HTTP 404.
APACHE_404 = ('<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
              '<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n'
              '<p>The requested URL was not found on this server.</p>\n<hr>\n'
              '<address>Apache/2.4.7 (Ubuntu) Server at %s Port 80</address>\n'
              '</body></html>\n' % EVIL)

#: http://mutillidae/webservices/soap/ws-user-account.php?wsdl -- THE REAL ONE.
WSDL = ('<?xml version="1.0"?><definitions>'
        '<port name="ws-user-accountPort" binding="tns:ws-user-accountBinding">\n'
        '    <soap:address location="http://%s/webservices/soap/ws-user-account.php"/>'
        '</port></definitions>' % EVIL)

#: http://mutillidae/phpmyadmin/server_databases.php -- inert JS title assignment, nothing else.
PMA_DOC_TITLE = ("<script type=\"text/javascript\">\nif (typeof(parent.document.title) == 'string') "
                 "{\n    parent.document.title = '%s / 127.0.0.1 | phpMyAdmin 3.5.2.2';\n}\n"
                 "</script>\n" % EVIL)

#: http://mutillidae/phpmyadmin/main.php -- BOTH the inert title AND a real link. Must stay LOW.
PMA_MAIN = (PMA_DOC_TITLE + '<p>...have been deactivated. To find out why click '
            '<a href="http://%s/phpmyadmin/chk_rel.php?lang=en">here</a>.</p>' % EVIL)

#: http://mutillidae/phpmyadmin/ -- a JS variable phpMyAdmin builds its own navigation URLs from.
PMA_ABSOLUTE_URI = ("<title>phpMyAdmin 3.5.2.2 -\n    %s</title>\n<script>\n"
                    "    var text_dir = 'ltr';\n    var pma_absolute_uri = 'http://%s/phpmyadmin/';"
                    "\n</script>" % (EVIL, EVIL))

#: http://mutillidae/index.php -- the APPLICATION. occurrences of the spoofed host: 0.
MUTILLIDAE_APP = ('<html><head><title>Mutillidae: Deliberately Vulnerable Web Pen-Testing '
                  'Application</title></head><body><a href="index.php?page=home.php">Home</a>'
                  '</body></html>')


# == the downgrade half ========================================================

def test_the_apache_autoindex_signature_is_informational_not_low():
    got = ws.analyze_host_header(AUTOINDEX, "")
    assert got, "detection must NOT be deleted -- the reflection is real"
    assert got["severity"] == "INFORMATIONAL", got
    assert got["landing"] == "server_signature", got


def test_the_apache_404_signature_is_informational_not_low():
    got = ws.analyze_host_header(APACHE_404, "")
    assert got and got["severity"] == "INFORMATIONAL", got
    assert got["landing"] == "server_signature", got


def test_the_signature_evidence_says_server_generated_in_words():
    """A reader who is told 'the app reflects Host' goes looking in the app and finds nothing. The
    evidence has to name Apache's footer and say the application never ran."""
    for body, marker in ((AUTOINDEX, "autoindex"), (APACHE_404, "error page")):
        got = ws.analyze_host_header(body, "")
        low = got["detail"].lower()
        assert got["server_generated"] is True, got
        assert "server-generated" in low, got["detail"]
        assert "serversignature" in low and "<address>" in low, got["detail"]
        assert "usecanonicalname" in low, got["detail"]
        assert marker in low, (marker, got["detail"])


def test_the_signature_evidence_says_it_is_not_one_finding_per_url():
    """40 rows for one `ServerSignature On` is the multiplicity half of the defect. The oracle cannot
    dedup by itself, but it must tell the reader the fact is host-level."""
    got = ws.analyze_host_header(APACHE_404, "")
    assert "not one finding per url" in got["detail"].lower(), got["detail"]


def test_the_phpmyadmin_document_title_is_inert_and_informational():
    got = ws.analyze_host_header(PMA_DOC_TITLE, "")
    assert got and got["severity"] == "INFORMATIONAL", got
    assert got["landing"] == "inert", got
    assert "document.title" in got["detail"], got["detail"]


def test_an_inert_landing_is_not_reported_as_server_generated():
    """The two downgrades are different claims. phpMyAdmin DID run and DID reflect the Host; blaming
    Apache for it would be as wrong as the thing this ticket fixes, in the other direction."""
    got = ws.analyze_host_header(PMA_DOC_TITLE, "")
    assert got["server_generated"] is False, got
    assert "apache" not in got["detail"].lower(), got["detail"]


def test_a_page_title_reflection_is_inert():
    got = ws.analyze_host_header("<title>Welcome to %s</title>" % EVIL, "")
    assert got["severity"] == "INFORMATIONAL" and got["landing"] == "inert", got
    assert "<title>" in got["detail"], got["detail"]


def test_a_bare_text_node_is_inert():
    got = ws.analyze_host_header("<p>You are browsing %s today</p>" % EVIL, "")
    assert got["severity"] == "INFORMATIONAL" and got["landing"] == "inert", got
    assert "no link semantics" in got["detail"], got["detail"]


# == the negative controls -- the half that keeps this an oracle ===============

def test_THE_WSDL_SOAP_ADDRESS_IS_STILL_LOW():
    """THE ONE THAT MATTERS. 4 of the 65 were real and this is the shape. An over-correction that
    downgrades everything is a worse oracle than the unconditional LOW it replaced."""
    got = ws.analyze_host_header(WSDL, "")
    assert got and got["severity"] == "LOW", got
    assert got["landing"] == "url_authority", got
    assert "soap:address" in got["detail"], got["detail"]


def test_the_phpmyadmin_page_that_has_BOTH_stays_low():
    """main.php carries the inert document.title AND a real link. The actionable landing wins -- an
    inert reflection elsewhere on the page cannot launder away a live one."""
    got = ws.analyze_host_header(PMA_MAIN, "")
    assert got["severity"] == "LOW" and got["landing"] == "url_authority", got
    assert "href" in got["detail"], got["detail"]


def test_a_javascript_absolute_url_variable_is_actionable():
    """`pma_absolute_uri` is a JS string, not an attribute, and phpMyAdmin builds its navigation from
    it. Grading by ATTRIBUTE NAME would call this inert; grading by URL authority does not."""
    got = ws.analyze_host_header(PMA_ABSOLUTE_URI, "")
    assert got["severity"] == "LOW" and got["landing"] == "url_authority", got


def test_a_protocol_relative_link_is_still_low():
    """The pre-existing oracle tests feed exactly this. A scheme is not required for a client to
    resolve the authority."""
    got = ws.analyze_host_header("<a href='//%s/x'>" % EVIL, "")
    assert got["severity"] == "LOW" and got["landing"] == "url_authority", got


def test_a_form_action_is_still_low():
    got = ws.analyze_host_header('<form action="https://%s/login" method="post">' % EVIL, "")
    assert got["severity"] == "LOW", got
    assert "form action" in got["detail"], got["detail"]


def test_a_password_reset_url_is_still_low():
    body = '<a href="https://%s/account/reset?token=9f1c">reset your password</a>' % EVIL
    got = ws.analyze_host_header(body, "")
    assert got["severity"] == "LOW", got
    assert "password-reset" in got["detail"], got["detail"]


def test_a_meta_refresh_is_still_low():
    body = '<meta http-equiv="refresh" content="0;url=http://%s/next">' % EVIL
    got = ws.analyze_host_header(body, "")
    assert got["severity"] == "LOW" and got["landing"] == "url_authority", got


def test_a_script_src_is_still_low():
    got = ws.analyze_host_header('<script src="//%s/a.js"></script>' % EVIL, "")
    assert got["severity"] == "LOW", got
    assert "src" in got["detail"], got["detail"]


def test_an_unnamed_url_sink_is_still_low():
    """The named sinks only supply wording. A shape nobody enumerated must still be graded by the
    authority test, or the oracle is a whitelist and every new sink is a silent false negative."""
    got = ws.analyze_host_header('<my-widget endpoint="https://%s/rpc"></my-widget>' % EVIL, "")
    assert got["severity"] == "LOW" and got["landing"] == "url_authority", got
    assert "absolute URL" in got["detail"], got["detail"]


# == the authority test must stay structural ===================================

def test_a_lookalike_subdomain_is_not_our_host():
    """`//bbh-evil.example.attacker.tld` resolves at the attacker's parent domain, not at the host we
    injected. Without the delimiter lookahead this is a substring test wearing a regex."""
    got = ws.analyze_host_header('<a href="https://%s.attacker.tld/p">x</a>' % EVIL, "")
    assert got["severity"] == "INFORMATIONAL", got
    assert got["landing"] == "inert", got


def test_a_host_in_a_query_value_is_not_a_url_authority():
    got = ws.analyze_host_header('<a href="https://legit.example/go?to=%s">x</a>' % EVIL, "")
    assert got["severity"] == "INFORMATIONAL" and got["landing"] == "inert", got


def test_a_signature_plus_an_extra_reflection_is_not_signature_only():
    """`sig == occ` is the whole claim: if one occurrence is somewhere else, the application MAY have
    seen the Host and 'the application never ran' is no longer supportable."""
    body = APACHE_404 + "<p>host was %s</p>" % EVIL
    got = ws.analyze_host_header(body, "")
    assert got["landing"] == "inert", got
    assert got["server_generated"] is False, got


def test_a_signature_page_that_also_links_the_host_stays_low():
    body = AUTOINDEX + '<a href="http://%s/next">n</a>' % EVIL
    got = ws.analyze_host_header(body, "")
    assert got["severity"] == "LOW" and got["landing"] == "url_authority", got


# == nothing else moved ========================================================

def test_the_application_that_does_not_reflect_is_silent():
    """The negative control from the lab: mutillidae's own index.php, occurrences 0."""
    assert ws.analyze_host_header(MUTILLIDAE_APP, "") is None
    assert ws.host_header_landing(MUTILLIDAE_APP)["class"] == "none"


def test_the_location_branch_is_untouched():
    """Q-114's MEDIUM/INFORMATIONAL split was measured CORRECT and must not move. Note the body here
    is a ServerSignature page: a redirect primitive outranks the body landing entirely."""
    assert ws.analyze_host_header("", "https://%s/reset" % EVIL)["severity"] == "MEDIUM"
    got = ws.analyze_host_header(APACHE_404, "https://%s/p" % EVIL,
                                 resp_headers={"Age": "0"}, xfh_location="")
    assert got["severity"] == "MEDIUM", got


def test_a_clean_response_is_still_silent():
    assert ws.analyze_host_header("", "") is None
    assert ws.analyze_host_header("<html>ok</html>", "https://legit.example/home") is None


def test_every_landing_class_is_reachable_and_labelled():
    """A census, so a future edit cannot collapse two classes into one and still pass."""
    seen = {ws.host_header_landing(b)["class"]
            for b in (MUTILLIDAE_APP, AUTOINDEX, PMA_DOC_TITLE, WSDL)}
    assert seen == {"none", "server_signature", "inert", "url_authority"}, seen
