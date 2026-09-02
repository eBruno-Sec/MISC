#!/usr/bin/env bash
# The PINNED-RATCHET tests, as one fast group.
#
# WHY THIS EXISTS. Declaring six techniques in cycle 18 moved seventeen pinned numbers across eight
# files. Each was found by a separate ~20-minute full-suite run, one layer at a time: register the
# techniques -> discover the liveness ids need records -> discover the records need WSTG keys ->
# discover the routing set moved -> discover the descriptor count moved -> discover the WSTG
# coverage total moved. Every one of those was knowable in two minutes.
#
# These are the tests that assert a MEASURED CONSTANT rather than a behaviour, so they are exactly
# the ones a vocabulary or registry change disturbs. Run this after touching techniques.py,
# engine_descriptor.py, wstg_catalog.py, liveness.py, or adding a module to agent/.
#
# This is NOT a substitute for the full suite. It is the thing to run FIRST, so the full suite has
# a chance of passing on its first attempt instead of its seventh.
set -uo pipefail

cd "$(dirname "$0")/.."
AGENT="$(pwd)/agent"

# Windows path for the -v mount: a Git-Bash path silently mounts an EMPTY volume and pytest then
# reports success having collected nothing.
WIN_AGENT="$(cd "$AGENT" && pwd -W 2>/dev/null || echo "$AGENT")"

GATES=(
  tests/test_techniques.py                    # technique records: required fields, WSTG mapping
  tests/test_liveness.py                      # every check names a real technique + reachable lab
  tests/test_validated_on.py                  # validated_on is run-derived, not hand-written
  tests/test_engine_routing.py                # routed/unrouted sets and the routed COUNT
  tests/test_engine_descriptor.py             # registry validation, descriptor count
  tests/test_t7_zero_delta.py                 # ALWAYS_ON / PRECONDITIONS snapshot + sizes
  tests/test_technique_planner.py             # no confirming technique is an orchestration island
  tests/test_scan_scope.py                    # every technique is selectable (vuln_class vocabulary)
  tests/test_wstg_key_reachability.py         # claimed-but-unmapped WSTG keys
  tests/test_wstg_coverage_claim.py           # the 86/109 coverage constant
  tests/test_coverage_block_epistemics.py     # the sentence that number appears in
  tests/test_negative_effects_reach.py        # effects table reach + descriptor count
  tests/test_effects_negative_half.py         # negative effects on unrouted engines
  tests/test_deadcode_gate.py                 # dead-function ceiling and dispositions
  tests/test_mutation_gate.py                 # confirmed-producers-without-a-mutant ceiling
  tests/test_silent_failure_invariant.py      # module count + per-module except caps
  tests/test_rate_policy.py                   # every target call goes through the shared policy
)

echo "running ${#GATES[@]} pinned-ratchet test files against $AGENT"
echo

MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v "${WIN_AGENT}:/app" -w /app apolaki-agent \
  python -m pytest "${GATES[@]}" -p no:cacheprovider -q -rfE --tb=line
rc=$?

echo
if [ "$rc" -eq 0 ]; then
  echo "all pinned ratchets hold. The full suite is now worth running."
else
  echo "ratchets moved. Each failure above prints its MEASURED value -- decide whether the number"
  echo "moved for a real reason before updating it, and say which reason in the commit. A ratchet"
  echo "updated without one is just a test edited until it passed."
fi
exit "$rc"
