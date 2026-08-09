"""
Capability preflight — what this configuration CANNOT test, stated out loud (#125).

Three books converge on the same requirement:

  * *Essential Cybersecurity Science*, "Human Cognitive Biases" — Kahneman's **WYSIATI**, "what you see is
    all there is": *"we often fail to allow for the possibility that evidence that should be critical to
    our judgment is missing."* A clean pentest report does exactly this to a reader; absence of detection
    reads as absence of risk.
  * *Model-Based Testing Essentials* §8.1.1 — coverage criteria are a **budget mechanism**, not a
    completeness claim ("full path coverage… will ruin your company").
  * *Automated Planning* §4.2.1 — a pruning technique should be declared **safe** or not; an unexamined
    cutoff is an unstated assumption.

The concrete case that motivated this: the sealed blind benchmark missed XXE at
`/catalog/product/stock`. There is nothing wrong with the XXE engine — blind XXE needs an out-of-band
callback, `BBH_OOB_BASE` was unset, so the class was **untestable in that run** and the report said
nothing. Silence and "we checked and it's fine" looked identical.

This module inspects the live configuration and reports, per capability: whether it is available, which
vulnerability classes go untested without it, and how to enable it. Pure inspection — no network, no
findings, never raises.
"""
from __future__ import annotations

import os
import shutil


def _env(name: str) -> str:
    return (os.getenv(name) or "").strip()


# capability -> (probe, classes blocked when unavailable, how to enable)
# `classes` names what CANNOT BE CONFIRMED, which is the honest unit — not "we skipped a tool".
_CAPABILITIES = (
    ("oob_collaborator",
     lambda: bool(_env("BBH_OOB_BASE")),
     ("blind XXE", "blind SSRF", "blind command injection", "second-order injection",
      "blind SQL injection (out-of-band)"),
     "set BBH_OOB_BASE to a reachable collaborator URL (and BBH_OOB_DOMAIN for DNS-triggerable probes)",
     "These classes have no in-band signal by definition: the only proof is a callback arriving from the "
     "target. Without a collaborator they cannot be confirmed OR ruled out."),
    ("oob_dns",
     lambda: bool(_env("BBH_OOB_DOMAIN")),
     ("DNS-only exfiltration", "blind XXE via DNS", "SSRF to a non-HTTP scheme"),
     "set BBH_OOB_DOMAIN to a wildcard DNS domain you control",
     "Some targets block outbound HTTP but resolve DNS. Without a DNS collaborator those paths are "
     "invisible."),
    ("headless_browser",
     lambda: bool(_env("CDP_BROWSER_URL")),
     ("DOM XSS", "client-side prototype pollution", "runtime persona-swap BOLA",
      "client-side-only authorization (CWE-602)", "SPA-rendered attack surface"),
     "docker compose --profile browser up -d headless-chrome",
     "Anything that only exists after JavaScript runs is unreachable to an HTTP-only scan."),
    ("intercept_proxy",
     lambda: bool(_env("PROXY_URL")),
     ("request/response tampering replay", "full-traffic HAR capture"),
     "docker compose --profile proxy up -d mitmproxy",
     "Without it the traffic ledger holds only what Apolaki's own engines sent."),
    ("exploitdb_feed",
     lambda: _env("INTEL_FEEDS_EXPLOITDB") == "1",
     ("public-exploit availability on findings",),
     "set INTEL_FEEDS_EXPLOITDB=1 and refresh the intel feeds",
     "Findings will not be annotated with whether a public exploit exists."),
    ("nuclei",
     lambda: bool(shutil.which("nuclei")),
     ("templated CVE checks",),
     "install nuclei in the agent image",
     "Known-CVE template coverage is absent."),
    ("nmap",
     lambda: bool(shutil.which("nmap")),
     ("service/version fingerprinting", "beyond-web service discovery"),
     "install nmap in the agent image",
     "Non-web services are discovered only by Apolaki's own bounded socket sweep."),
)


def check(env_only: bool = False, target: str = "") -> list:
    """Per-capability availability. Pure inspection; never raises.

    `target` makes the OOB verdict HONEST rather than merely configured. A collaborator URL is useless
    unless the TARGET can reach it: the in-network default (`http://agent:8000`) works for a local lab
    and is unreachable from an external host. Treating "configured" as "available" would inject probes
    whose callback could never arrive, and report the resulting silence as "not vulnerable" — the exact
    misreading this module exists to prevent. Without a target the configured state is reported, which
    is the most that can be said."""
    out = []
    for name, probe, classes, how, why in _CAPABILITIES:
        try:
            ok = bool(probe())
        except Exception:
            ok = False
        note = ""
        if ok and target and name == "oob_collaborator":
            try:
                import collaborator
                if not collaborator.reachable_from(target):
                    ok = False
                    note = ("a collaborator IS configured (%s) but this target cannot reach it — an "
                            "in-network callback URL is invisible to an external host, and a public one "
                            "may be blocked from an internal target. Set BBH_OOB_BASE to a collaborator "
                            "reachable FROM this target, or BBH_OOB_DOMAIN for a DNS probe."
                            % collaborator.base())
            except Exception:
                pass
        rec = {"capability": name, "available": ok, "blocks": list(classes),
               "how_to_enable": how, "why_it_matters": why}
        if note:
            rec["unreachable_note"] = note
        out.append(rec)
    return out


def coverage_debt(checks=None) -> dict:
    """The classes this configuration cannot confirm OR rule out. Pure.

    `untestable_classes` is the number that belongs next to the finding count in any honest report: a
    scan reporting zero findings with six untestable classes has not said the same thing as a scan
    reporting zero findings with none."""
    ch = checks if checks is not None else check()
    missing = [c for c in ch if not c["available"]]
    classes = []
    for c in missing:
        for k in c["blocks"]:
            if k not in classes:
                classes.append(k)
    return {
        "capabilities_total": len(ch),
        "capabilities_available": len(ch) - len(missing),
        "capabilities_missing": [c["capability"] for c in missing],
        "untestable_classes": classes,
        "complete": not missing,
        "statement": ("all capabilities available — no class was skipped for want of configuration"
                      if not missing else
                      "%d capability(ies) unavailable, so %d vulnerability class(es) were NOT TESTED in "
                      "this run: %s. Absence of findings in these classes is not evidence of absence."
                      % (len(missing), len(classes), ", ".join(classes))),
    }


def report_section(debt=None) -> str:
    """Markdown for the report. Deliberately phrased so a reader cannot mistake untested for clean."""
    d = debt or coverage_debt()
    if d["complete"]:
        return ("## Testing Capability\n\nAll %d assessment capabilities were available; no vulnerability "
                "class was skipped for want of configuration.\n" % d["capabilities_total"])
    lines = ["## Testing Capability — WHAT THIS ASSESSMENT COULD NOT TEST", "",
             "%d of %d capabilities were unavailable in this run. The classes below were **not tested**. "
             "This is not a statement that they are secure — it is a statement that they were not "
             "examined." % (len(d["capabilities_missing"]), d["capabilities_total"]), ""]
    for cls in d["untestable_classes"]:
        lines.append("- %s" % cls)
    lines.append("")
    return "\n".join(lines)
