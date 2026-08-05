"""Structural / ORDER BY SQL injection (CWE-89, WAHH ch9). Confirms via a subquery differential a non-SQL
context cannot fake: valid subquery clean, invalid subquery errors."""
import blind_benchmark as bb
import sqli_tool as sq


def test_probes_are_valid_and_invalid_subqueries():
    p = sq.structural_probes()
    assert p["ok"] == "(SELECT 1)" and "FROM" in p["bad"].upper()


def test_confirms_on_subquery_error_differential():
    base = "<html>rows a,b,c</html>"
    ok = "<html>rows a,b,c</html>"                                  # valid subquery -> clean
    bad = "<html>You have an error in your SQL syntax near 'FROM apolnope'</html>"
    confirmed, hits = sq.structural_confirmed(base, ok, bad)
    assert confirmed and hits[0]["dbms"] == "MySQL"


def test_no_fp_when_both_error_or_neither():
    base = "<html>ok</html>"
    # a context that errors on ANY invalid column errors on BOTH -> no differential
    assert not sq.structural_confirmed(base, "ORA-00904 invalid identifier", "ORA-00904 invalid identifier")[0]
    # a reflect/ignore context returns normal for both -> not SQL
    assert not sq.structural_confirmed(base, "<html>ok</html>", "<html>ok</html>")[0]
    # only the VALID subquery erroring (baseline noise) must not confirm either
    assert not sq.structural_confirmed(base, "You have an error in your SQL syntax", "<html>ok</html>")[0]


def test_finding_is_benchmark_proof():
    _, hits = sq.structural_confirmed("x", "x", "You have an error in your SQL syntax near FROM apolnope")
    f = sq.structural_finding("https://x/?sort=name", "sort", hits)
    assert f["family"] == "sqli" and f["cwe"] == "CWE-89" and f["confidence"] == "confirmed"
    assert "structural" in f["title"].lower() or "ORDER BY" in f["description"]
    assert bb._has_proof(f)
