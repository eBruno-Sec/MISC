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

echo "[full-mission] 2. start the run + poll /status (a full AUTHENTICATED scan takes ~10 min:"
echo "                  base crawl + register 2 personas + authz matrix + authenticated recrawl)"
curl -s -X POST "$A/run/$sid" >/dev/null 2>&1
status=""; i=0
while [ "$i" -lt 540 ]; do          # up to ~18 min — measured ~9.5 min on reference hw, 2x margin
  status=$(curl -s "$A/status/$sid" | grep -oE '"status":"[a-z_]+"' | head -1 | cut -d'"' -f4)
  case "$status" in complete | stopped | failed) break ;; esac
  i=$((i + 1)); sleep 2
done
echo "    final status: ${status:-timeout}"
[ "$status" = "complete" ] && ck "mission ran to completion through the API" PASS || ck "mission completion (status=${status:-timeout})" FAIL

echo "[full-mission] 3. report + graph consistency"
# Count confirmed vs unconfirmed SEPARATELY — never conflate the two (truth-first). A
# confirmed finding is a proven bug; a lead/candidate is an advisory signal. Reporting one
# blended number is exactly the overclaim Apolaki exists to avoid, so the harness models it.
# Retry the fetch a few times to ride out the finalize write.
rep=""; confirmed=0; unconf=0
j=0; while [ "$j" -lt 5 ]; do
  rep=$(curl -s "$A/report/$sid/json")
  confirmed=$(echo "$rep" | grep -oE '"confidence": *"confirmed"' | wc -l | tr -d ' ')
  unconf=$(echo "$rep" | grep -oE '"confidence": *"(lead|candidate)"' | wc -l | tr -d ' ')
  [ "$((confirmed + unconf))" -ge 1 ] && break
  j=$((j + 1)); sleep 2
done
echo "$rep" | grep -q '"findings"' && ck "report JSON generated (no 500)" PASS || ck "report JSON generated" FAIL
echo "    report entries -> confirmed: $confirmed | unconfirmed (leads/candidates): $unconf"
# Non-empty is the smoke test; we do NOT assert a confirmed count — a deterministic Juice
# Shop pass legitimately confirms little, and asserting >0 confirmed would reward false
# positives. What must hold: the mission produced SOME rendered signal end-to-end.
[ "$((confirmed + unconf))" -ge 1 ] && ck "report renders the mission's signal (confirmed+leads >=1)" PASS || ck "report renders signal" FAIL
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
