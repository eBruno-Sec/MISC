"""A comment that cites `module.function` must cite one that EXISTS.

MEASURED: three modules (`ws_tool`, `session_lifecycle_tool`, `mass_assign_tool`) carried comments
asserting that `report.check_report_honesty` recomputes a CVSS base score from its vector and rejects
a disagreement. No such function exists anywhere in the tree.

The guarantee itself turned out to be REAL -- it is `report.report_integrity_check`, it runs live at
report.py:2800, and a finding scored 2.0 against an AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H vector does
produce "CVSS score 2.0 disagrees with its vector (computes to 9.8)". So the defect was a stale NAME,
not a missing guard. That distinction is the reason this test is narrow: one is a comment fix, the
other would have been 241 unchecked scores, and a lane reported the second when the first was true.

Why it is worth a test at all: this codebase's recurring defect is a declaration that no longer
matches a fact -- six instances in the gates alone. A comment naming a function that does not exist is
the same defect in prose, and prose is where nobody looks. It also actively misleads: the next author
reads "nothing in the report pipeline does" and rebuilds a guard that already exists.
"""
import ast
import os
import re

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Modules whose cited attributes we resolve. Kept to the ones that carry cross-module guarantees in
#: prose; widening it is welcome, but a citation of a THIRD-PARTY module is not ours to verify.
_CITED = ("report", "proof_schema", "web_security", "report_integrity", "mutation_gate")
#: `report.py` is a FILENAME, not an attribute reference, and matching it would drown the real signal
#: in false positives -- which is how a scan like this gets deleted instead of fixed.
_FILE_SUFFIXES = ("py", "md", "json", "csv", "html", "sh", "txt", "yml", "yaml")
_CITE_RE = re.compile(r"`?\b(%s)\.(?!(?:%s)\b)([a-z_][a-z0-9_]*)\b"
                      % ("|".join(_CITED), "|".join(_FILE_SUFFIXES)))


def _comment_and_docstring_text(path):
    """Every comment line plus every docstring in a module. Comments are where stale citations rot,
    because no import and no test ever touches them."""
    src = open(path, encoding="utf8").read()
    out = [ln.split("#", 1)[1] for ln in src.splitlines() if "#" in ln]
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node)
            if doc:
                out.append(doc)
    return out


def _modules():
    for fn in sorted(os.listdir(AGENT_DIR)):
        if fn.endswith(".py") and not fn.startswith("test_"):
            yield fn, os.path.join(AGENT_DIR, fn)


def test_every_cited_function_resolves():
    import importlib
    loaded, missing = {}, []
    for fname, path in _modules():
        for text in _comment_and_docstring_text(path):
            for mod, attr in _CITE_RE.findall(text):
                if mod not in loaded:
                    try:
                        loaded[mod] = importlib.import_module(mod)
                    except Exception as exc:                       # recorded, never skipped
                        missing.append("%s: cannot import %s (%s)" % (fname, mod, exc))
                        loaded[mod] = None
                m = loaded.get(mod)
                if m is not None and not hasattr(m, attr):
                    missing.append("%s cites %s.%s which does not exist" % (fname, mod, attr))
    assert not missing, "stale citations:\n  " + "\n  ".join(sorted(set(missing)))


def test_the_scan_is_not_vacuous():
    """Guard the guard. If the regex stopped matching, the test above would pass for free -- which is
    exactly how the citation it was written for survived in the first place."""
    hits = 0
    for _fname, path in _modules():
        for text in _comment_and_docstring_text(path):
            hits += len(_CITE_RE.findall(text))
    assert hits >= 10, "the citation scan found only %d references; it has stopped seeing them" % hits


def test_the_specific_citation_that_started_this_is_gone():
    """`report.check_report_honesty` never existed. Named explicitly so it cannot quietly return."""
    import report
    assert not hasattr(report, "check_report_honesty")
    for _fname, path in _modules():
        assert "check_report_honesty" not in open(path, encoding="utf8").read(), path


def test_the_guarantee_those_comments_described_is_real():
    """The other half, and the reason this file does not claim a missing guard: the CVSS-vs-vector
    check EXISTS and fires. Without this, the fix above would read as if the guarantee were lost."""
    import report
    lie = {"title": "X", "severity": "high", "family": "sqli", "confidence": "confirmed",
           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cvss_score": 2.0}
    issues = report.report_integrity_check([lie])
    assert any("disagrees with its vector" in i for i in issues), issues
    honest = dict(lie, cvss_score=9.8)
    assert not any("disagrees with its vector" in i for i in report.report_integrity_check([honest]))
