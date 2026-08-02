#!/bin/sh
# FULL-MISSION benchmark (NO MOCKS, the REAL path): POST /engage -> POST /run -> poll /status ->
# GET /report + /graph. Exercises recon -> planner -> oracles -> auth artery -> finalize -> report
# through the ACTUAL HTTP API (not _do_persona_authz directly), so it catches phase-handoff seams
# that the mechanism-level benchmark cannot (CHAD re-audit #7). Requires: make up (agent + juice-shop).
set -u
A="http://localhost:8000"
pass=0; fail=0
ck() { if [ "$2" = "PASS" ]; then echo "  PASS  $1"; pass=$((pass + 1)); else echo "  FAIL  $1"; fail=$((fail + 1)); fi; }

echo "[full-mission] 1. engage a deterministic authenticated scan of Juice Shop"
sid=$(curl -s -X POST "$A/engage" -H 'Content-Type: application/json' \
  -d '{"program_name":"benchmark","in_scope":["http://juice-shop:3000"],"mode":"active","strategy":"deterministic","authenticated_scan":true}' \
  | grep -oE '"session_id":"[a-f0-9]+"' | head -1 | cut -d'"' -f4)
if [ -z "$sid" ]; then ck "engage returned a session" FAIL; echo "[full-mission] cannot continue"; exit 1; fi
ck "engage returned a session ($sid)" PASS

echo "[full-mission] 2. start the run + poll /status (a full deterministic scan takes ~6 min)"
curl -s -X POST "$A/run/$sid" >/dev/null 2>&1
status=""; i=0
while [ "$i" -lt 240 ]; do          # up to ~8 min
  status=$(curl -s "$A/status/$sid" | grep -oE '"status":"[a-z_]+"' | head -1 | cut -d'"' -f4)
  case "$status" in complete | stopped | failed) break ;; esac
  i=$((i + 1)); sleep 2
done
echo "    final status: ${status:-timeout}"
[ "$status" = "complete" ] && ck "mission ran to completion through the API" PASS || ck "mission completion (status=${status:-timeout})" FAIL

echo "[full-mission] 3. report + graph consistency"
# retry the report fetch a few times to ride out the finalize write
rep=""; fcount=0
j=0; while [ "$j" -lt 5 ]; do
  rep=$(curl -s "$A/report/$sid/json")
  fcount=$(echo "$rep" | grep -oE '"cwe": *"CWE-[0-9]+"' | wc -l | tr -d ' ')
  [ "${fcount:-0}" -ge 1 ] && break
  j=$((j + 1)); sleep 2
done
echo "$rep" | grep -q '"findings"' && ck "report JSON generated (no 500)" PASS || ck "report JSON generated" FAIL
echo "    findings rendered in report: $fcount"
[ "${fcount:-0}" -ge 1 ] && ck "report renders the mission's findings (>=1)" PASS || ck "report renders findings" FAIL
gnodes=$(curl -s "$A/graph/canonical/$sid" | grep -oE '"nodes":[0-9]+' | head -1 | cut -d: -f2)
echo "    canonical graph nodes: ${gnodes:-0}"
[ "${gnodes:-0}" -ge 1 ] && ck "canonical graph populated from the mission" PASS || ck "canonical graph populated" FAIL

echo "[full-mission] 4. no 5xx on the mission's report/graph endpoints"
sweep_ok=1
for ep in "report/$sid" "report/$sid/md" "report/$sid/html" "graph/$sid" "graph/canonical/$sid" "missions/$sid"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$A/$ep")
  if [ "$code" -ge 500 ]; then echo "    5xx on /$ep ($code)"; sweep_ok=0; fi
done
[ "$sweep_ok" = "1" ] && ck "no 5xx across report/graph/mission endpoints" PASS || ck "no 5xx across endpoints" FAIL

echo "[full-mission] ==== $pass passed, $fail failed ===="
[ "$fail" -eq 0 ]
