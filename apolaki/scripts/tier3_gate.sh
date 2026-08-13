#!/bin/sh
# Tier-3 adversarial-control ratchet. The runner may return nonzero for a known
# strict xfail; the gate artifact, not a generic process code, decides regression.
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
AGENT_ROOT=${TIER3_AGENT_ROOT:-"$ROOT/agent"}
BASELINE=${TIER3_BASELINE:-"$AGENT_ROOT/tier3/baseline.json"}
CURRENT=${TIER3_CURRENT:-"$AGENT_ROOT/tier3/artifacts/current.json"}
GATE_ARTIFACT=${TIER3_GATE_ARTIFACT:-"$AGENT_ROOT/tier3/artifacts/gate.json"}
PYTHON_BIN=${PYTHON_BIN:-python}
TIMEOUT=${TIER3_TIMEOUT:-120}

mkdir -p "$(dirname -- "$CURRENT")" "$(dirname -- "$GATE_ARTIFACT")"
if [ -n "${APOLAKI_GIT_SHA:-}" ]; then
  GIT_SHA=$APOLAKI_GIT_SHA
else
  GIT_SHA=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf unknown)
fi

cd "$AGENT_ROOT" || exit 2
runner_rc=0
"$PYTHON_BIN" -m tier3.runner --repo-root . --output "$CURRENT" \
  --timeout "$TIMEOUT" --git-sha "$GIT_SHA" || runner_rc=$?

if [ ! -s "$CURRENT" ]; then
  echo "Tier-3 runner failed before writing an artifact (exit $runner_rc)" >&2
  if [ "$runner_rc" -eq 0 ]; then runner_rc=2; fi
  exit "$runner_rc"
fi

"$PYTHON_BIN" -m tier3.gate --baseline "$BASELINE" --current "$CURRENT" \
  --output "$GATE_ARTIFACT"
