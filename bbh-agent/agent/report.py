from datetime import datetime

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def generate_report(program: str, findings: list[dict], scope: dict) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    if not findings:
        return (
            f"# Bug Bounty Report: {program}\n\n"
            f"**Date:** {now}\n"
            f"**Scope:** {', '.join(scope.get('in_scope', []))}\n\n"
            "No confirmed vulnerabilities found during this engagement.\n"
        )

    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f.get("severity", "informational"), 5))

    counts: dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "informational")
        counts[s] = counts.get(s, 0) + 1

    lines = [
        f"# Bug Bounty Report: {program}",
        "",
        f"**Date:** {now}",
        f"**Scope:** {', '.join(scope.get('in_scope', []))}",
        f"**Total Findings:** {len(findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "informational"]:
        if sev in counts:
            lines.append(f"| {sev.capitalize()} | {counts[sev]} |")

    lines += ["", "---", "", "## Findings", ""]

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "informational").upper()
        title = f.get("title", "Untitled")
        target = f.get("target", "")
        description = f.get("description", "")
        impact = f.get("impact", "")
        steps = f.get("reproduction_steps", [])
        cvss_score = f.get("cvss_score", "N/A")
        cvss_vector = f.get("cvss_vector", "")
        cwe = f.get("cwe", "N/A")
        evidence = f.get("evidence", "")

        lines += [
            f"### Finding {i}: {title}",
            "",
            "**Summary**",
            "",
            description,
            "",
            f"**Severity:** {sev}",
            f"**Target:** `{target}`",
            f"**CVSS:** {cvss_score}{(' ' + cvss_vector) if cvss_vector else ''}",
            f"**CWE:** {cwe}",
            "",
            "**Steps to Reproduce**",
            "",
        ]
        for j, step in enumerate(steps, 1):
            lines.append(f"{j}. {step}")

        lines += [
            "",
            "**Impact**",
            "",
            impact,
            "",
        ]

        if evidence:
            lines += [
                "**Supporting Material**",
                "",
                "```",
                evidence,
                "```",
                "",
            ]

        lines += ["---", ""]

    return "\n".join(lines)
