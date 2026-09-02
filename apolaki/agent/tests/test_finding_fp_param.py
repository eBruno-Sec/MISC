"""Q-046 - `finding_fp` recovered the tested parameter by parsing the rendered title.

This is the defect that cost four true positives in the published baseline, so the measurement comes
first. `finding_fp` built its key with:

    m = title.rsplit(" in '", 1)

Every injection builder renders `... in '<param>'`, EXCEPT `ldap_tool.finding`, which renders
`LDAP injection in <where> '<param>'` - a word between `in` and the quote. The split therefore
matched nothing, `param` fell to `""`, and `""` is indistinguishable from "this finding has no
parameter". Five ldap_injection findings on five different OWASP Benchmark cases collapsed into one
key. Mission `ebd96f45` was published as 22 true positives; re-scored against the key it is 26, and
all five of those ldapi cases are true.

The fix is the standing rule, not a better regex: BIND THE VALUE AT THE POINT IT IS KNOWN. Every
builder already had `param` as a local variable and threw it away after formatting it into a
sentence. The title parse remains only as a fallback for the ~1052 findings already stored without
the field.
"""
import memory


def _f(title, param=None, family="ldap_injection", target="http://h/a", cwe="CWE-90"):
    f = {"title": title, "family": family, "target": target, "cwe": cwe}
    if param is not None:
        f["param"] = param
    return f


# ── the exact defect, reproduced ───────────────────────────────────────────────────────────────
def test_five_ldap_findings_on_one_path_used_to_share_one_key():
    """The historical failure, with the path held CONSTANT so the collision is visible.

    In the real baseline the five cases sat at five different paths, and the path in the key masked
    the collapse under today's fingerprint. Hold the path fixed and the defect is exactly what it
    always was: the family collapses to a single key with no parameter to tell the findings apart.
    """
    olds = [_f("LDAP injection in form field 'user%d'" % i) for i in range(5)]
    assert len({memory.finding_fp(f) for f in olds}) == 1, "precondition: this is the bug"

    news = [_f("LDAP injection in form field 'user%d'" % i, param="user%d" % i) for i in range(5)]
    assert len({memory.finding_fp(f) for f in news}) == 5, "five parameters, five findings"


def test_an_unparseable_title_no_longer_means_no_parameter():
    """The general statement of the defect: failure-to-parse and genuinely-absent produced the same
    key. A finding whose title the split cannot read must still be distinguishable by its data."""
    a = _f("Injection detected (see evidence)", param="username")
    b = _f("Injection detected (see evidence)", param="password")
    assert memory.finding_fp(a) != memory.finding_fp(b)


# ── negative controls ──────────────────────────────────────────────────────────────────────────
def test_stored_findings_keep_the_key_they_already_had():
    """THE control that decides whether this is safe to ship. ~1052 findings are already stored with
    no `param` field; if the fallback did not survive, every one of their fingerprints would move and
    every historical diff would break. The parsed value must equal the bound value, lowercased."""
    parsed = memory.finding_fp(_f("SQL injection (boolean-blind) in 'userid'", family="sqli",
                                  cwe="CWE-89"))
    bound = memory.finding_fp(_f("SQL injection (boolean-blind) in 'userid'", param="userid",
                                 family="sqli", cwe="CWE-89"))
    assert parsed == bound
    assert "|userid|" in parsed


def test_the_bound_value_wins_over_the_rendered_one():
    """Precedence is not arbitrary: the title is a rendering and the field is the fact. If a title is
    ever reworded, the key must follow the parameter, not the prose."""
    f = _f("SQL injection (error-based) in 'OLD_RENDERED_NAME'", param="real_param", family="sqli")
    assert "|real_param|" in memory.finding_fp(f)
    assert "old_rendered_name" not in memory.finding_fp(f)


def test_case_and_whitespace_are_normalised_like_the_parsed_path_always_was():
    a = memory.finding_fp(_f("t", param="  UserId  ", family="sqli"))
    b = memory.finding_fp(_f("t", param="userid", family="sqli"))
    assert a == b


def test_an_empty_param_field_falls_back_rather_than_blanking_the_key():
    """A falsy explicit value is not an answer -- `param: ""` must not beat a title that does carry
    the name. This is the `x or DEFAULT` trap that has bitten this codebase twice."""
    f = _f("SQL injection (error-based) in 'userid'", param="", family="sqli")
    assert "|userid|" in memory.finding_fp(f)


def test_distinct_families_at_one_location_still_do_not_merge():
    """Don't destroy the property the key already had while fixing the one it lacked."""
    a = _f("Reflected XSS (html) in 'q'", param="q", family="xss", cwe="CWE-79")
    b = _f("SQL injection (error-based) in 'q'", param="q", family="sqli", cwe="CWE-89")
    assert memory.finding_fp(a) != memory.finding_fp(b)


# ── the producers actually carry it (registration is not invocation) ───────────────────────────
def test_every_injection_builder_emits_the_field_it_renders():
    """A fix in `finding_fp` alone would be an island: the key can only use `param` if the builders
    write it. Each of these is called the way its module calls it, and the assertion is on the
    RETURNED RECORD, not on the presence of a line of code."""
    import ldap_tool
    rec = ldap_tool.finding("http://h/a", "uid", "form field", "an oracle")
    assert rec.get("param") == "uid", "ldap_tool is the builder that proved the defect"
    assert rec["title"] == "LDAP injection in form field 'uid'", "title unchanged"

    import sqli_tool
    rec = sqli_tool.error_finding("http://h/a?id=1", "id", "'", [{"dbms": "MySQL"}])
    assert rec.get("param") == "id"

    import cmdi_tool
    rec = cmdi_tool.output_finding("http://h/a?c=1", "c", ";id", {"kind": "uid", "match": "uid=0"})
    assert rec.get("param") == "c"

    import nosqli_tool
    rec = nosqli_tool.error_finding("http://h/a", "q", "[$ne]", [{"store": "MongoDB"}])
    assert rec.get("param") == "q"

    import xss_tool
    rec = xss_tool.reflection_finding("http://h/a?q=1", "q", "html", evidence="<b>x</b>")
    assert rec.get("param") == "q"


def test_the_fingerprint_of_a_freshly_built_finding_actually_uses_it():
    """End to end, because a builder writing the field and a key reading it are two facts, and only
    the pair of them fixes anything. Two real ldap_tool records differing ONLY in parameter, at one
    path -- the historical collision -- must now produce two keys."""
    import ldap_tool
    a = ldap_tool.finding("http://h/search", "uid", "form field", "an oracle")
    b = ldap_tool.finding("http://h/search", "cn", "form field", "an oracle")
    assert memory.finding_fp(a) != memory.finding_fp(b)


# =================================================================================================
# Q-160. "Reflected XSS (html)" on a JSON API response.
#
# `contexts_of` classifies a reflection by the bytes AROUND it and assumes the body is HTML, so a
# canary echoed into a JSON error body classifies as "html" and the finding graded
# `confidence=confirmed, severity=high`.
#
# MEASURED on juice-shop `/api/Challenges/?sort=`: the value reflects unescaped, angle brackets
# intact, into {"message":"Sorting not allowed...","errors":["<canary>"]} -- served as HTTP 400
# `application/json` with `X-Content-Type-Options: nosniff`. A real browser navigated there with
# three separate executing payloads fired NO dialog. Every API that echoes a bad parameter into a
# JSON error was a HIGH.
# =================================================================================================

import xss_tool as _xt


def test_a_json_response_with_nosniff_cannot_execute_markup():
    assert _xt.markup_executable("application/json; charset=utf-8", nosniff=True) is False
    assert _xt.markup_executable("text/plain", nosniff=True) is False


def test_html_is_still_executable_and_so_is_an_undeclared_type():
    """The true-positive path, which a fix that simply silenced this family would break. A missing
    content-type stays executable because the browser may sniff it."""
    assert _xt.markup_executable("text/html; charset=utf-8") is True
    assert _xt.markup_executable("application/xhtml+xml") is True
    assert _xt.markup_executable("") is True


def test_a_non_html_type_without_nosniff_stays_executable():
    """Deliberate. Sniffing varies by browser and type, so refusing these would trade a false
    positive for a false negative on the commoner case. The nosniff header is the clear signal."""
    assert _xt.markup_executable("application/json", nosniff=False) is True


def test_the_finding_is_downgraded_not_deleted_when_the_body_is_not_markup():
    """The reflection is a REAL observation -- the value came back unencoded. What changes is the
    CLAIM. Deleting it would lose a true fact; calling it XSS asserts a false one."""
    f = _xt.reflection_finding("http://h/api?p=1", "p", "html", evidence="<mark>", renderable=False)
    assert f["severity"] == "informational" and f["confidence"] == "lead"
    assert "not parsed as HTML" in f["title"]
    assert "NOT as XSS" in f["description"]


def test_a_genuine_html_reflection_is_still_a_confirmed_high():
    f = _xt.reflection_finding("http://h/p?p=1", "p", "html", evidence="<mark>")
    assert f["severity"] == "high" and f["confidence"] == "confirmed"
    assert f["title"].startswith("Reflected XSS")
