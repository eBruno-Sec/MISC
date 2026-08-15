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

# (module, description, pattern, replacement, exact-test-that-must-catch-it)
# Each mutant WEAKENS an FP guard. The exact node id is load-bearing: a collection error, broken fixture,
# or unrelated failing test must not be credited with killing the mutant.
MUTANTS = [
    # Q-011. Added when mass_assign_tool.py landed, keeping the ceiling at 46 by earning it. This is
    # the guard that separates "the server BOUND my privileged attribute" from "the server echoes any
    # attribute it is handed": an invented control field coming back on the re-read means persistence
    # proves nothing. Drop it and every echoing endpoint confirms as mass assignment.
    ("mass_assign_tool.py", "evaluate: drop the echo control — an endpoint that round-trips any "
                            "attribute would confirm as mass assignment",
     r'if control\.get\("found"\):', 'if False:',
     "tests/test_mass_assign_tool.py::test_an_endpoint_that_echoes_the_control_attribute_is_clean"),
    # Q-011, the SECOND guard the engine rests on, and the one with a MEASURED live victim. Juice
    # Shop creates every user with `isActive: true`; inject `isActive: true` and the re-read shows
    # exactly the confirming shape. Only the baseline object -- created without the injection, read
    # through the same view -- separates "we set this" from "it was always this". Drop this and
    # Apolaki reports a mass assignment on Juice Shop's `isActive` today. Measured 2026-08-15:
    # verdicts {'confirmed': 1, 'clean': 1}; the clean IS this guard firing on `isActive`.
    ("mass_assign_tool.py", "evaluate: drop the baseline control — a field that ALREADY held the "
                            "injected value would confirm as mass assignment",
     r'if baseline\.get\("found"\) and same_value\(sent_value, baseline\.get\("value"\)\):',
     'if False:',
     "tests/test_mass_assign_tool.py::test_a_field_that_already_held_the_value_is_clean"),
    # Q-002. Added when ws_tool.py landed, so the confirmed-producer ceiling stays 46 by EARNING it
    # rather than by raising it. This is the guard that separates CSWSH from "a WebSocket exists":
    # drop it and a socket pushing PUBLIC data confirms as a hijack, which is precisely the class of
    # error that made the traversal engine confirm on reflective endpoints.
    ("ws_tool.py", "evaluate: drop the cookie-stripped control — public pushed data would confirm as CSWSH",
     r'if c_hit:', 'if False:',
     "tests/test_ws_tool.py::test_a_public_socket_is_clean_because_the_control_got_the_same_marker"),
    ("bie.py", "judge: drop the anonymous control — public data would confirm as BOLA",
     r'if _s\(anon\) == 200 and _b\(anon\) == base_b:', 'if False:',
     "tests/test_bie.py::test_rejects_public_resource"),
    ("bie.py", "judge: drop the implausible-id control — an SPA shell would confirm as BOLA",
     r'if _s\(nonexistent\) == 200 and _b\(nonexistent\) == base_b:', 'if False:',
     "tests/test_bie.py::test_rejects_spa_shell_catch_all"),
    ("bie.py", "judge: accept a non-matching body as proof of a cross-user read",
     r'if _b\(mutation\) != base_b:', 'if False:',
     "tests/test_bie.py::test_rejects_when_attacker_body_differs"),
    ("bie.py", "judge: let a MISSING negative control still produce a confirmation",
     r'if missing:', 'if False:',
     "tests/test_bie.py::test_missing_negative_control_is_a_lead_never_a_confirmation"),
    ("bie.py", "judge_param_swap: remove the SECURE-case rejection (server ignoring the parameter)",
     r'if _b\(mutation\) == _b\(self_baseline\):', 'if False:',
     "tests/test_bie.py::test_param_swap_rejects_the_SECURE_case_of_a_server_ignoring_the_param"),
    ("bie.py", "judge_client_side_authz: stop rejecting the SPA shell",
     r'if _b\(shell\) == _b\(persona\):', 'if False:',
     "tests/test_bie.py::test_client_side_authz_rejects_the_spa_shell"),
    ("transport_posture.py", "analyze_protocols: trust a probe that accepts every pinned version",
     r'trustworthy = not \(tested and all\(sup\.get\(p\) for p in tested\) and len\(tested\) >= 4\)',
     'trustworthy = True',
     "tests/test_transport_posture.py::test_a_probe_that_accepts_everything_is_not_trusted"),
    ("transport_posture.py", "analyze_methods: confirm TRACE without the echoed marker",
     r'if trace_marker and int\(trace_status or 0\) == 200 and trace_marker in str\(trace_body or ""\):',
     'if int(trace_status or 0) == 200:',
     "tests/test_transport_posture.py::test_trace_confirmed_only_by_the_echoed_marker"),
    ("transport_posture.py", "analyze_cookies: demand Secure even on a plaintext origin (false positive)",
     r'if is_https and not c\["secure"\]:', 'if not c["secure"]:',
     "tests/test_transport_posture.py::test_secure_is_not_demanded_on_a_plaintext_origin"),
    ("ics_dnp3_s7.py", "is_write_frame: default to ALLOW instead of refuse for an unknown protocol",
     r'    return True                                           # unknown protocol -> refuse',
     '    return False', "tests/test_ics_dnp3_s7.py::test_the_rail_is_strict_by_default"),
    ("blind_benchmark.py", "_has_proof: accept a finding carrying no evidence",
     r'return conf and len\(proof\) >= 12', 'return conf',
     "tests/test_blind_benchmark.py::test_a_finding_without_evidence_is_never_benchmark_proof"),
    ("proof_schema.py", "demote_unproven: stop demoting confirmed-but-unproven findings",
     r'if not ok:', 'if False:',
     "tests/test_proof_schema.py::test_demote_downgrades_weak_access_control_confirm"),
    # Appended, not prepended: the crash-recovery self-tests read MUTANTS[0] while hardcoding bie.py as
    # the file they restore, so inserting at the front breaks them.
    ("prng_disclosure.py", "drop the strong-generator control — SecureRandom would confirm as weak",
     r'if _STRONG\.search\(text\):', 'if False:',
     "tests/test_prng_disclosure.py::test_strong_generator_suppresses_the_finding"),
    ("cookie_flags.py", "treat an unparseable Set-Cookie field as vulnerable instead of skipping it",
     r"if not ck:", "if False:",
     "tests/test_cookie_flags.py::test_nothing_is_invented_from_absent_or_unparseable_headers"),
    ("prng_disclosure.py", "drop the security-context gate — a display-only PRNG would confirm",
     r'if not ctx:', 'if False:',
     "tests/test_prng_disclosure.py::test_weak_generator_without_security_meaning_is_not_a_vulnerability"),
    # The traversal oracle. Its FP guard is the redaction: two responses to two different payloads
    # ALWAYS differ, and until 2026-08-10 that difference was accepted as proof of a file read.
    ("web_security.py", "traversal: compare responses WITHOUT redacting the echo — reflection confirms again",
     r'    a = redact_payload_echo\(text_a, payloads\)\n    b = redact_payload_echo\(text_b, payloads\)',
     '    a = text_a or ""\n    b = text_b or ""',
     "tests/test_traversal_oracle.py::test_unexplained_divergence_ignores_pure_echo_and_catches_real_text"),
    ("web_security.py", "traversal: drop the determinism control — a page with a request id confirms",
     r'if a_st != b_st or unexplained_divergence\(a_text, b_text, payloads\):', 'if False:',
     "tests/test_traversal_oracle.py::test_a_nondeterministic_endpoint_cannot_confirm"),
    ("web_security.py", "traversal: promote a reflected payload back to a confirmation",
     r'return \{"severity": "info", "confidence": "lead", "oracle": "reflection",',
     'return {"severity": "high", "confidence": "confirmed", "oracle": "reflection",',
     "tests/test_traversal_oracle.py::test_reflected_traversal_payload_alone_is_not_a_confirmation"),
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


def recover(app_dir: str = None) -> list:
    """Undo any mutation a previous run left behind. MUST run before applying anything.

    A run killed between `_apply` and `_restore` leaves the source weakened and a `.mutbak` holding the
    original. Without this, the next run is actively harmful: `_apply` cannot match its pattern against
    the already-mutated source, so the gate reports "pattern not found — guard changed, mutant is stale"
    and points the operator at updating the mutant — which would cement the weakened guard as the new
    baseline. The gate would then pass while defending nothing.

    Worse in the container: `make mutation-gate` runs `docker exec` against the LIVE agent, so an
    interrupted run leaves the running scanner with a disabled false-positive guard until someone
    rebuilds. Returns the files it restored, so a recovery is reported rather than silent."""
    app = app_dir or APP_DIR
    restored = []
    for fn in sorted(os.listdir(app)):
        if fn.endswith(".mutbak"):
            target = os.path.join(app, fn[:-len(".mutbak")])
            shutil.move(os.path.join(app, fn), target)
            restored.append(os.path.basename(target))
    return restored


def _expected_test_failed(stdout: str, stderr: str, expected_test: str) -> bool:
    """True only when pytest reports the selected test itself as FAILED.

    Collection, import, fixture, and infrastructure failures are reported as ERROR even though they
    return non-zero. Requiring the exact FAILED node id stops those failures impersonating an oracle kill.
    """
    expected = expected_test.replace("\\", "/")
    for raw in (str(stdout or "") + "\n" + str(stderr or "")).splitlines():
        line = raw.strip().replace("\\", "/")
        if line == "FAILED " + expected or line.startswith("FAILED " + expected + " - "):
            return True
    return False


def run(mutants=None, app_dir: str = None, timeout: int = 900) -> dict:
    """Apply each mutant, run its exact test, restore.

    A mutant is KILLED only when that test's call phase fails. A non-zero pytest exit by itself is not
    evidence: import, collection, setup, teardown, and infrastructure errors all return non-zero too.

    Returns {killed, survived, not_applied, results}. `survived` MUST be empty — a survivor means the
    suite does not defend that guard."""
    app = app_dir or APP_DIR
    out = {"killed": [], "survived": [], "not_applied": [], "results": [],
           "recovered": recover(app)}
    # `is None`, NOT `or`: an empty list means "run no mutants" (recovery only). With `mutants or MUTANTS`
    # an empty list is falsy and silently expands to the FULL gate — which re-runs the whole suite twelve
    # times. A caller asking for nothing would get the most expensive thing the module can do.
    for module, desc, pattern, repl, expected_test in (MUTANTS if mutants is None else mutants):
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
        returncode = None
        outcome = "pytest did not run"
        try:
            p = subprocess.run([sys.executable, "-m", "pytest", expected_test, "-x", "-q",
                                "-p", "no:warnings",
                                "--tb=no"], cwd=app, capture_output=True, text=True, timeout=timeout)
            returncode = p.returncode
            killed = _expected_test_failed(p.stdout, p.stderr, expected_test)
            outcome = "expected test failed" if killed else "expected test did not fail"
        except subprocess.TimeoutExpired:
            killed = False
            outcome = "pytest timed out"
        except Exception as e:
            killed = False
            outcome = "pytest invocation failed: %s" % str(e)[:160]
        finally:
            _restore(path)
        rec = {"module": module, "desc": desc, "tests": expected_test, "killed": killed,
               "pytest_returncode": returncode, "outcome": outcome}
        out["results"].append(rec)
        (out["killed"] if killed else out["survived"]).append(rec)
    out["passed"] = not out["survived"] and not out["not_applied"]
    out["summary"] = ("%d/%d mutants killed" % (len(out["killed"]), len(out["results"]))
                      + ("" if out["passed"] else " — GATE FAILED")
                      + ("" if not out["recovered"] else
                         "  [recovered %d file(s) a previous run left mutated: %s]"
                         % (len(out["recovered"]), ", ".join(out["recovered"]))))
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
