"""Q-179. A differential oracle is only as good as its negative control -- and this one never
asked whether its control was comparable.

FOUND BY REPLAYING A `confirmed` FINDING BY HAND. The engine reported "LDAP injection in form field
`new_db`", confidence=confirmed, CVSS 8.2, against `/phpmyadmin/db_create.php` -- on a MySQL-only
stack with no LDAP anywhere.

MEASURED, three times each and stable: the universally-true probe, the deliberately-impossible
contradiction, AND the baseline carrying no parameter at all return BYTE-IDENTICAL 1107-byte
bodies (sha256 e5161d6313ceb1ec). The application's own answer is `Missing parameter: new_db`, so
the field was never processed.

The cited evidence was "a strict record-set superset (102%, 112%, 122%, 132%)". Those are
phpMyAdmin's FONT-SIZE DROPDOWN options, `<option value="102%">`, on a different page (`main.php`).
Two things were missing:

  1. identical bodies cannot carry a differential -- previously only IMPLICIT, since equal
     snapshots make each `>` comparison false, and implicit is not a guarantee: it holds only while
     every future signal is written as a strict superset test;
  2. the two bodies must be THE SAME PAGE for a SUPERSET claim to mean anything. `set > set` is a
     strict-superset test, so a superset over an EMPTY set is trivially satisfied -- an error page
     with no records at all makes every record on the other page look "gained".

WHERE THE GATE GOES MATTERS AS MUCH AS HAVING IT. `auth_state` is BY DESIGN a comparison of two
different documents (a login page against authenticated content). My first version gated the whole
function on similarity and turned four positive controls red, including the vulnerable XPath and
LDAP fixtures. A guard that silences the engine is a worse defect than the false positive it was
written for, so the gate sits below auth_state and above the set-difference signals only.

The comparison is on the TAG SKELETON, not the bytes, and the threshold comes from measuring both
sides rather than taste:

    main.php vs db_create.php (DIFFERENT pages)     raw 0.044   skeleton 0.044
    2 rows vs 0 rows, same template (SAME page)     raw 0.527   skeleton 0.727

A raw threshold that rejects 0.044 also rejects 0.527 -- on a small document the rows ARE most of
the bytes.
"""
import semantic_differential as sem


# Structurally faithful to the real pages, because a toy fixture is not the thing that was
# measured. MEASURED skeletons on the live host:
#     db_create.php error : html head meta link link title link link link meta body p a img br
#     main.php            : a full frame with nav tables and selects
# My first version of these fixtures was two four-tag documents scoring 0.657 -- above the gate --
# while the real pair scores 0.044. The fixture was wrong, not the threshold.
ERROR_PAGE = (
    "<!DOCTYPE html><html><head>"
    "<meta charset='utf-8'><link rel='stylesheet' href='a.css'><link rel='icon' href='f.ico'>"
    "<title>phpMyAdmin</title>"
    "<link rel='stylesheet' href='b.css'><link rel='stylesheet' href='c.css'>"
    "<link rel='stylesheet' href='d.css'><meta name='robots' content='noindex'>"
    "</head><body><p>Missing parameter: new_db</p>"
    "<a href='index.php'><img src='logo.png'></a><br></body></html>")

SETTINGS_PAGE = (
    "<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body>"
    "<div id='nav'><ul><li><a href='#'>Databases</a></li><li><a href='#'>SQL</a></li>"
    "<li><a href='#'>Status</a></li><li><a href='#'>Export</a></li></ul></div>"
    "<form method='post'><fieldset><legend>Appearance</legend>"
    "<select name='fontsize'>"
    "<option value='102%'>102%</option><option value='112%'>112%</option>"
    "<option value='122%'>122%</option><option value='132%'>132%</option>"
    "</select></fieldset></form>"
    "<table><tbody><tr><td>server</td><td>localhost</td></tr>"
    "<tr><td>charset</td><td>utf8</td></tr></tbody></table>"
    "</body></html>")

LOGIN = "<html><form action='/login'><input name='username'><input type='password'></form></html>"
DASHBOARD = "<html><h1>Dashboard</h1><a href='/logout'>Logout</a></html>"


def _records(items):
    rows = "".join("<tr data-record-id='%s'><td>%s</td></tr>" % (x, x) for x in items)
    return "<html><table><tr><th>uid</th></tr>%s</table></html>" % rows


def test_identical_bodies_cannot_confirm_anything():
    """THE reproduction: probe, contradiction and baseline were the same 1107 bytes."""
    v = sem.evaluate(ERROR_PAGE, ERROR_PAGE, "x*", "x)(!(objectClass=*)")
    assert not v["confirmed"], v
    assert "identical" in v["oracle"], v["oracle"]


def test_a_superset_across_two_different_pages_is_refused():
    """THE false positive: a settings menu on one page vs an error page on another."""
    v = sem.evaluate(SETTINGS_PAGE, ERROR_PAGE, "x*", "x)(!(objectClass=*)")
    assert not v["confirmed"], (
        "a font-size dropdown on a different page was reported as a gained record set: %r" % v)
    assert "DIFFERENT pages" in v["oracle"], v["oracle"]


def test_a_real_record_superset_on_one_page_still_confirms():
    """POSITIVE CONTROL. Same template, more rows -- the signal this oracle exists for."""
    v = sem.evaluate(_records(["alice", "bob"]), _records([]))
    assert v["confirmed"] and v["signal"] == "record_set", v


def test_auth_state_is_not_gated_on_page_similarity():
    """POSITIVE CONTROL, and the reason the gate sits where it does. A login page and authenticated
    content are SUPPOSED to be different documents."""
    v = sem.evaluate(DASHBOARD, LOGIN)
    assert v["confirmed"] and v["signal"] == "auth_state", v


def test_the_skeleton_ignores_text_but_keeps_structure():
    assert sem._skeleton("<html><table><tr><th>uid</th></tr></table></html>") == "html table tr th"
    assert sem._skeleton("") == ""


def test_same_page_agreement_is_independent_of_result_set_size():
    """THE reason the metric is a tag-set overlap and not a sequence ratio.

    A mutant that compares raw bytes (or the tag SEQUENCE) survives every test above, because at
    two rows those metrics still clear the gate. They collapse as the result set grows:

        rows:      2      8     20     40    200
        raw:    0.495  0.197  0.089  0.047   ...
        skeleton:0.727  0.400  0.211  0.118   ...
        jaccard: 0.800  0.800  0.800  0.800  0.800

    So a sequence gate would start REJECTING genuine record-set differentials exactly as the result
    set got bigger and more interesting -- trading a false positive for a false negative that only
    shows up on the findings worth having.
    """
    for n in (2, 8, 20, 40, 200):
        many = _records(["user%03d" % i for i in range(n)])
        v = sem.evaluate(many, _records([]))
        assert v["confirmed"] and v["signal"] == "record_set", (
            "a %d-row superset over an empty result was refused: %r" % (n, v))
    assert abs(sem._tag_overlap(_records(["a", "b"]), _records([]))
               - sem._tag_overlap(_records(["u%03d" % i for i in range(200)]), _records([]))) < 1e-9, (
        "same-page agreement moved with row count; the metric is not size-independent")
