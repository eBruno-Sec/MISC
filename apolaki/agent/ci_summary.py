"""CI gate summary (Strix-borrow #111) — turn a completed Apolaki mission report into a PR-check VERDICT +
an EVIDENCE-FIRST PR-comment, so a scan can run on a PR/deploy and fail the check when it introduces a
confirmed vuln.

The gate FAILS only on a CONFIRMED finding at/above the configured severity (default high/critical): a PR
that introduces a proven high/critical turns the check red. LEADS never fail the gate (unproven by design).
The comment carries each gating finding's own EVIDENCE + reproduction steps (the deterministic oracle's
proof), never an LLM narrative — matching Apolaki's truth-first contract and Strix's "save the proof" idea.

Pure decision core (`summarize`) + a thin CLI (`main`) the CI entrypoint calls after the scan completes:
    python ci_summary.py <base_url> <session_id> [--out comment.md] [--fail-on critical,high]
Exit code 0 = gate PASS, 1 = gate FAIL (a confirmed gating finding), 2 = could not evaluate.
"""
from __future__ import annotations

import json
import sys

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "": 0}


def _sev(f) -> str:
    return str((f or {}).get("severity") or "info").strip().lower()


def _repro_lines(f) -> list:
    """The finding's own reproduction — a LIST after the canonical normalizer; tolerate a legacy string."""
    rs = (f or {}).get("reproduction_steps")
    if isinstance(rs, list):
        return [str(x) for x in rs if str(x).strip()]
    if isinstance(rs, str) and rs.strip():
        return [rs.strip()]
    return []


def summarize(report: dict, fail_on=("critical", "high"), max_rows: int = 25) -> dict:
    """Decide the CI gate from a mission report. Returns
    {verdict, exit_code, confirmed, leads, gating, counts, markdown}. `fail_on` is the set of severities that,
    when CONFIRMED, fail the gate. Pure — no I/O."""
    report = report or {}
    fail_set = {str(s).strip().lower() for s in (fail_on or ()) if str(s).strip()}
    confirmed = [f for f in (report.get("findings") or []) if (f or {}).get("confidence") == "confirmed"]
    leads = report.get("leads") or []
    gating = [f for f in confirmed if _sev(f) in fail_set]
    gating.sort(key=lambda f: _SEV_ORDER.get(_sev(f), 0), reverse=True)
    counts = {}
    for f in confirmed:
        counts[_sev(f)] = counts.get(_sev(f), 0) + 1
    verdict = "fail" if gating else "pass"
    md = _render(report, confirmed, leads, gating, counts, verdict, fail_set, max_rows)
    return {"verdict": verdict, "exit_code": 1 if gating else 0, "confirmed": len(confirmed),
            "leads": len(leads), "gating": len(gating), "counts": counts, "markdown": md}


def _render(report, confirmed, leads, gating, counts, verdict, fail_set, max_rows) -> str:
    sid = report.get("report_id") or report.get("id") or "?"
    art = report.get("auth_artery") or {}
    icon = "❌" if verdict == "fail" else "✅"
    head = "%s **Apolaki security gate: %s**" % (icon, verdict.upper())
    csum = ", ".join("%d %s" % (n, s) for s, n in
                     sorted(counts.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 0), reverse=True)) or "none"
    lines = [
        head, "",
        "- Confirmed findings: **%d** (%s)" % (len(confirmed), csum),
        "- Unconfirmed leads: %d" % len(leads),
        "- Gate fails on a CONFIRMED: %s" % (", ".join(sorted(fail_set)) or "(nothing)"),
    ]
    if art.get("ran"):
        lines.append("- Authenticated scan: %d persona(s), %d authenticated, matrix %s op(s)"
                     % (len(art.get("personas") or []), art.get("auth_success") or 0,
                        (art.get("matrix") or {}).get("operations") or 0))
    lines.append("")
    if gating:
        lines.append("### Gating findings (must fix)")
        for f in gating[:max_rows]:
            lines.append("")
            lines.append("**%s** — `%s` / %s" % (f.get("title") or "finding", _sev(f), f.get("family") or "?"))
            if f.get("target"):
                lines.append("- target: `%s`" % f.get("target"))
            if f.get("cwe"):
                lines.append("- %s%s" % (f.get("cwe"), (" · " + f.get("owasp")) if f.get("owasp") else ""))
            ev = str(f.get("evidence") or "").strip()
            if ev:
                lines.append("- evidence: %s" % ev[:300])
            steps = _repro_lines(f)
            if steps:
                lines.append("- reproduction:")
                for s in steps[:8]:
                    lines.append("  1. %s" % s)
        if len(gating) > max_rows:
            lines.append("")
            lines.append("_…and %d more._" % (len(gating) - max_rows))
    else:
        lines.append("No confirmed %s finding — gate passes." % ("/".join(sorted(fail_set)) or "gating"))
    lines += ["", "_Full report + downloadable per-finding PoC bundles: `/report/%s/html`, "
              "`/mission/%s/poc-bundle`._" % (sid, sid)]
    return "\n".join(lines)


# ── thin CLI: fetch the report over HTTP, summarize, write the comment, exit with the gate code ──
def _get_json(base: str, path: str):
    import urllib.request
    with urllib.request.urlopen(base.rstrip("/") + path, timeout=30) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _arg(argv, flag, default=None):
    return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else default


def main(argv) -> int:
    if len(argv) < 3:
        print("usage: python ci_summary.py <base_url> <session_id> [--out comment.md] [--fail-on critical,high]")
        return 2
    base, sid = argv[1], argv[2]
    fail_on = tuple((_arg(argv, "--fail-on", "critical,high") or "").split(","))
    out = _arg(argv, "--out")
    try:
        rep = _get_json(base, "/report/%s/json" % sid)
    except Exception as e:
        print("ci_summary: could not fetch report: %s" % e)
        return 2
    res = summarize(rep, fail_on=fail_on)
    if out:
        try:
            with open(out, "w", encoding="utf-8") as fh:
                fh.write(res["markdown"])
        except Exception as e:
            print("ci_summary: could not write %s: %s" % (out, e))
    print(res["markdown"])
    print("\nci_summary: verdict=%s confirmed=%d gating=%d" % (res["verdict"], res["confirmed"], res["gating"]))
    return res["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
