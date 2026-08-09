#!/usr/bin/env bash
# Engine liveness gate: does every engine that was once proven STILL confirm, right now?
#
# The unit suite tests pure helpers; the wiring is untested by construction. Three engines were found
# silently dead in one night with 1500 tests green. This is the missing half — it runs the shipping code
# path against a standing lab and fails when an engine that used to confirm stops confirming.
#
#   scripts/liveness.sh              check against the committed baseline (exit 1 on regression)
#   scripts/liveness.sh --update     accept the current result as the new baseline (only ever adds)
set -euo pipefail

echo "bringing up the validation labs (labs profile)…"
docker compose --profile labs up -d clientauthz domsource conpot dvga openldap smb snmpd >/dev/null
sleep 8
# No leading slash: Git Bash on Windows rewrites /app/... into a host path before docker sees it.
MSYS_NO_PATHCONV=1 docker exec -w /app apolaki-agent-1 python liveness_run.py "$@"
