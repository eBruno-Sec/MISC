"""
Mutation gate over Apolaki's ORACLES (#125, Robust Python Ch.24).

A test suite's size says nothing about its strength. Ch.24's warning is the reason this exists: *"A safety
net with fraying, brittle strands is worse than no safety net at all; it gives the illusion of safety and
provides false confidence."* Apolaki has >1200 tests, which is exactly the number that produces that
illusion.

So this does not measure coverage. It takes each **false-positive guard** — the specific line that stops a
confirmation from being issued without proof — deliberately breaks it, and requires the test suite to
notice. A mutant the suite fails to kill is a hole in the platform's central claim, sitting exactly where
it does the most damage.

Precedent: the first run of this found one. `blind_benchmark._has_proof` could be weakened to accept a
"confirmed" finding carrying no evidence at all, and the entire suite still passed — which would have
silently inflated every benchmark score Apolaki has ever reported.

THE GATE: no mutant listed here may survive. Adding an oracle means adding its mutant.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# (module, description, pattern, replacement, tests-that-must-catch-it)
# Each mutant WEAKENS an FP guard. `tests` narrows the run so the gate stays fast enough to use.
MUTANTS = [
    ("bie.py", "judge: drop the anonymous control — public data would confirm as BOLA",
     r'if _s\(anon\) == 200 and _b\(anon\) == base_b:', 'if False:', "tests/test_bie.py"),
    ("bie.py", "judge: drop the implausible-id control — an SPA shell would confirm as BOLA",
     r'if _s\(nonexistent\) == 200 and _b\(nonexistent\) == base_b:', 'if False:', "tests/test_bie.py"),
    ("bie.py", "judge: accept a non-matching body as proof of a cross-user read",
     r'if _b\(mutation\) != base_b:', 'if False:', "tests/test_bie.py"),
    ("bie.py", "judge: let a MISSING negative control still produce a confirmation",
     r'if missing:', 'if False:', "tests/test_bie.py"),
    ("bie.py", "judge_param_swap: remove the SECURE-case rejection (server ignoring the parameter)",
     r'if _b\(mutation\) == _b\(self_baseline\):', 'if False:', "tests/test_bie.py"),
    ("bie.py", "judge_client_side_authz: stop rejecting the SPA shell",
     r'if _b\(shell\) == _b\(persona\):', 'if False:', "tests/test_bie.py"),
    ("transport_posture.py", "analyze_protocols: trust a probe that accepts every pinned version",
     r'trustworthy = not \(tested and all\(sup\.get\(p\) for p in tested\) and len\(tested\) >= 4\)',
     'trustworthy = True', "tests/test_transport_posture.py"),
    ("transport_posture.py", "analyze_methods: confirm TRACE without the echoed marker",
     r'if trace_marker and int\(trace_status or 0\) == 200 and trace_marker in str\(trace_body or ""\):',
     'if int(trace_status or 0) == 200:', "tests/test_transport_posture.py"),
    ("transport_posture.py", "analyze_cookies: demand Secure even on a plaintext origin (false positive)",
     r'if is_https and not c\["secure"\]:', 'if not c["secure"]:', "tests/test_transport_posture.py"),
    ("ics_dnp3_s7.py", "is_write_frame: default to ALLOW instead of refuse for an unknown protocol",
     r'    return True                                           # unknown protocol -> refuse',
     '    return False', "tests/test_ics_dnp3_s7.py"),
    ("blind_benchmark.py", "_has_proof: accept a finding carrying no evidence",
     r'return conf and len\(proof\) >= 12', 'return conf', "tests/test_blind_benchmark.py"),
    ("proof_schema.py", "demote_unproven: stop demoting confirmed-but-unproven findings",
     r'if not ok:', 'if False:', "tests/test_proof_schema.py"),
]


def _apply(path: str, pattern: str, repl: str) -> bool:
    src = open(path, encoding="utf8").read()
    new, n = re.subn(pattern, repl, src, count=1)
    if n != 1:
        return False
    shutil.copy(path, path + ".mutbak")
    open(path, "w", encoding="utf8").write(new)
    return True


def _restore(path: str) -> None:
    if os.path.exists(path + ".mutbak"):
        shutil.move(path + ".mutbak", path)


def run(mutants=None, app_dir: str = None, timeout: int = 900) -> dict:
    """Apply each mutant, run its tests, restore. A mutant is KILLED when the tests fail.

    Returns {killed, survived, not_applied, results}. `survived` MUST be empty — a survivor means the
    suite does not defend that guard."""
    app = app_dir or APP_DIR
    out = {"killed": [], "survived": [], "not_applied": [], "results": []}
    for module, desc, pattern, repl, tests in (mutants or MUTANTS):
        path = os.path.join(app, module)
        if not os.path.exists(path):
            out["not_applied"].append({"module": module, "desc": desc, "why": "module missing"})
            continue
        if not _apply(path, pattern, repl):
            # A pattern that no longer matches means the guard was refactored. That is NOT a pass —
            # the mutant must be updated, or an unguarded rewrite slips through unnoticed.
            out["not_applied"].append({"module": module, "desc": desc,
                                       "why": "pattern not found — guard changed, mutant is stale"})
            continue
        try:
            p = subprocess.run([sys.executable, "-m", "pytest", tests, "-x", "-q", "-p", "no:warnings",
                                "--tb=no"], cwd=app, capture_output=True, text=True, timeout=timeout)
            killed = p.returncode != 0
        except Exception:
            killed = False
        finally:
            _restore(path)
        rec = {"module": module, "desc": desc, "tests": tests, "killed": killed}
        out["results"].append(rec)
        (out["killed"] if killed else out["survived"]).append(rec)
    out["passed"] = not out["survived"] and not out["not_applied"]
    out["summary"] = ("%d/%d mutants killed" % (len(out["killed"]), len(out["results"]))
                      + ("" if out["passed"] else " — GATE FAILED"))
    return out


def main() -> int:
    res = run()
    print("%-9s %-24s %s" % ("VERDICT", "MODULE", "MUTANT"))
    print("-" * 108)
    for r in res["results"]:
        print("%-9s %-24s %s" % ("killed" if r["killed"] else "SURVIVED", r["module"], r["desc"]))
    for r in res["not_applied"]:
        print("%-9s %-24s %s [%s]" % ("STALE", r["module"], r["desc"], r["why"]))
    print("\n" + res["summary"])
    if res["survived"]:
        print("\nA SURVIVING MUTANT IS A HOLE IN A FALSE-POSITIVE GUARD:")
        for r in res["survived"]:
            print("  -", r["module"], "::", r["desc"])
    return 0 if res["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
