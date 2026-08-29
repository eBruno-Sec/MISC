"""Q-123 -- the ledger's "Findings" column did not contain findings.

MEASURED, from a real report against a 23-finding total:

    | run_subfinder | executed | 25 | 37725 | 1 subdomains found      |
    | http_probe    | executed | 280 | 279  | 403 403 Forbidden ...   |
    | run_dom_trace | executed | 39  | 25   | 1 DOM source-to-sink finding(s) |

The column sums `main._tool_ledger`'s per-call `count` -- the length of the RAW
`ToolResult.findings` list each dispatch returned (subdomains, probe rows, DOM-trace candidate
sinks, a no-confirmation sqlmap log-tail carrier) -- against a header that says "Findings", and
the number on each row visibly disagrees with the tool's own note on the SAME line. It is not
reconcilable with the report's confirmed-findings total: most of what it counts (recon items,
candidate sinks) never reaches the confirmation/gating pipeline that produces a report finding.

The ticket's own escape hatch is exercised here rather than a doomed reconciliation: the column
is renamed to what it counts ("Items"), and this pins that meaning in both renderers so a future
edit cannot quietly relabel it "Findings" again.
"""
import report


def _ledger(tools, **kw):
    return {"strategy": "deterministic", "mode": "active", "tools": tools, **kw}


_TOOLS = [
    {"tool": "run_subfinder", "status": "executed", "calls": 25, "findings": 37725,
     "note": "1 subdomains found"},
    {"tool": "http_probe", "status": "executed", "calls": 280, "findings": 279,
     "note": "403 Forbidden"},
]


def test_the_markdown_ledger_no_longer_labels_the_column_findings():
    md = "\n".join(report._ledger_md(_ledger(_TOOLS)))
    assert "| Tool | Status | Calls | Items | Note |" in md
    assert "| Tool | Status | Calls | Findings | Note |" not in md


def test_the_markdown_ledger_explains_what_items_counts():
    md = "\n".join(report._ledger_md(_ledger(_TOOLS)))
    assert "raw result count" in md
    assert "not confirmed" in md


def test_the_html_ledger_no_longer_labels_the_column_findings():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, tool_ledger=_ledger(_TOOLS))
    assert "<th>Items</th>" in html
    assert "<th>Findings</th>" not in html


def test_the_html_ledger_explains_what_items_counts():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, tool_ledger=_ledger(_TOOLS))
    assert "raw result count" in html


def test_the_raw_count_still_reaches_the_row_unchanged():
    """The rename is a display fix, not a data fix -- the underlying per-tool count (used by
    `arsenal_gap`, `ledger_finding_disagreement` and the JSON export) must not move."""
    md = "\n".join(report._ledger_md(_ledger(_TOOLS)))
    assert "| run_subfinder | executed | 25 | 37725 | 1 subdomains found |" in md
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, tool_ledger=_ledger(_TOOLS))
    assert ">37725<" in html
