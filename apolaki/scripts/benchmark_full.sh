#!/bin/sh
# FULL-MISSION benchmark (NO MOCKS, the REAL path): POST /engage -> POST /run -> poll /status ->
# then a DEEP CORRECTNESS asserter over the real /report + /graph surfaces. The smoke legs here only
# prove the mission RAN; benchmark_assert.py proves it ran CORRECTLY — the auth artery actually fired
# (personas>=2, matrix ran), the graph carries the expected node kinds, the report has family breadth,
# every endpoint is 200 + schema-valid (401/404 fail), session ids match, and no confirmed finding
# lacks proof. This closes the gap CHAD's audit named: 6/6 was a smoke test, not a correctness proof.
#
# Usage: sh scripts/benchmark_full.sh [--fresh-lab]
#   --fresh-lab   recreate juice-shop first so prior accounts/state never bleed into results (CHAD #6)
set -u
A="http://localhost:8000"
COMPOSE="${COMPOSE:-docker compose}"
MAX_RUNTIME="${BENCH_MAX_RUNTIME:-1200}"   # seconds; a run beyond this is flagged as a perf regression
FRESH_LAB=0; BASELINE=""
# --baseline enforces determinism vs a stored golden signature (first run writes it, later runs
# compare within a documented variance). Kept on the agent's persistent data volume across runs.
for arg in "$@"; do case "$arg" in
  --fresh-lab) FRESH_LAB=1 ;;
  --baseline)  BASELINE="/app/data/benchmark_baseline.json" ;;
esac; done
pass=0; fail=0
ck() { if [ "$2" = "PASS" ]; then echo "  PASS  $1"; pass=$((pass + 1)); else echo "  FAIL  $1"; fail=$((fail + 1)); fi; }

# ── 0. optional GENUINELY isolated lab state (CHAD #1) ──
# Default target is the shared juice-shop; --fresh-lab targets a DEDICATED juice-shop-bench that is
# recreated with its OWN volume (no account/state bleed) and never touches the user's normal lab.
TARGET="http://juice-shop:3000"
if [ "$FRESH_LAB" = "1" ]; then
  echo "[full-mission] 0. --fresh-lab: provision an ISOLATED fresh juice-shop-bench"
  if sh scripts/fresh_lab.sh; then
    TARGET="http://juice-shop-bench:3000"
    ck "isolated fresh juice-shop-bench provisioned (normal lab untouched)" PASS
  else
    ck "isolated fresh lab provisioned" FAIL
  fi
fi

echo "[full-mission] 1. engage a deterministic AUTHENTICATED scan of $TARGET"
sid=$(curl -s -X POST "$A/engage" -H 'Content-Type: application/json' \
  -d "{\"program_name\":\"benchmark\",\"in_scope\":[\"$TARGET\"],\"mode\":\"active\",\"strategy\":\"deterministic\",\"authenticated_scan\":true}" \
  | grep -oE '"session_id":"[a-f0-9]+"' | head -1 | cut -d'"' -f4)
if [ -z "$sid" ]; then ck "engage returned a session" FAIL; echo "[full-mission] cannot continue"; exit 1; fi
ck "engage returned a session ($sid)" PASS

echo "[full-mission] 2. start the run + poll /status (a full AUTHENTICATED scan takes ~10 min:"
echo "                  base crawl + register 2 personas + authz matrix + authenticated recrawl)"
t0=$(date +%s)
curl -s -X POST "$A/run/$sid" >/dev/null 2>&1
status=""; i=0
while [ "$i" -lt 540 ]; do          # up to ~18 min — measured ~9.5 min on reference hw, 2x margin
  status=$(curl -s "$A/status/$sid" | grep -oE '"status":"[a-z_]+"' | head -1 | cut -d'"' -f4)
  case "$status" in complete | stopped | failed) break ;; esac
  i=$((i + 1)); sleep 2
done
t1=$(date +%s); elapsed=$((t1 - t0))
echo "    final status: ${status:-timeout}   (elapsed ${elapsed}s)"
[ "$status" = "complete" ] && ck "mission ran to completion through the API" PASS || ck "mission completion (status=${status:-timeout})" FAIL
# runtime regression signal (CHAD #7): the scan completed but took longer than expected
if [ "$status" = "complete" ]; then
  [ "$elapsed" -le "$MAX_RUNTIME" ] && ck "runtime within budget (${elapsed}s <= ${MAX_RUNTIME}s)" PASS \
    || ck "RUNTIME REGRESSION (${elapsed}s > ${MAX_RUNTIME}s)" FAIL
fi

# ── 3. DEEP correctness assertions over the real report/graph surfaces (the actual proof) ──
if [ "$status" = "complete" ]; then
  echo "[full-mission] 3. deep correctness assertions (benchmark_assert.py, in-container)"
  bflag=""
  [ -n "$BASELINE" ] && bflag="--baseline $BASELINE"
  # Provenance the artifact/baseline are BOUND to (CHAD #4/#7): the host can see git + docker, so it
  # gathers the code + lab identity and passes it into the container as env.
  GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "")
  IMG_DIGEST=$(docker image inspect apolaki-agent:latest --format '{{.Id}}' 2>/dev/null || echo "")
  JS_DIGEST=$(docker inspect "$($COMPOSE ps -q juice-shop 2>/dev/null | head -1)" \
              --format '{{index .Image}}' 2>/dev/null || echo "")
  [ "$FRESH_LAB" = "1" ] && JS_DIGEST=$(docker inspect "$($COMPOSE --profile bench ps -q juice-shop-bench 2>/dev/null | head -1)" --format '{{index .Image}}' 2>/dev/null || echo "$JS_DIGEST")
  ART="/app/data/benchmark_artifacts/${sid}.json"
  MSYS_NO_PATHCONV=1 $COMPOSE exec -T agent sh -c 'mkdir -p /app/data/benchmark_artifacts' >/dev/null 2>&1
  # MSYS_NO_PATHCONV=1 stops Git Bash (Windows) rewriting the CONTAINER paths into host paths.
  if MSYS_NO_PATHCONV=1 $COMPOSE exec -T \
       -e APOLAKI_GIT_COMMIT="$GIT_COMMIT" -e APOLAKI_IMAGE_DIGEST="$IMG_DIGEST" \
       -e APOLAKI_JUICESHOP_DIGEST="$JS_DIGEST" \
       agent python benchmark_assert.py "$A" "$sid" $bflag --artifact "$ART"; then
    ck "deep correctness assertions all passed" PASS
  else
    ck "deep correctness assertions" FAIL
  fi
  # copy the artifact out to benchmark_results/ for retention — via a temp so a FAILED copy never
  # leaves a zero-byte file behind (CHAD #2). Only a non-empty artifact is retained.
  mkdir -p benchmark_results 2>/dev/null
  _tmp="benchmark_results/.${sid}.json.part"
  MSYS_NO_PATHCONV=1 $COMPOSE exec -T agent cat "$ART" > "$_tmp" 2>/dev/null
  if [ -s "$_tmp" ]; then
    mv "$_tmp" "benchmark_results/${sid}.json"
    ck "benchmark artifact retained (benchmark_results/${sid}.json)" PASS
  else
    rm -f "$_tmp" "benchmark_results/${sid}.json"
    ck "benchmark artifact retained" FAIL
  fi
fi

echo "[full-mission] ==== $pass passed, $fail failed ===="
[ "$fail" -eq 0 ]
