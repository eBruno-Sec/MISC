#!/bin/sh
# REPEAT determinism benchmark (CHAD re-audit #3/F): run TWO fully-independent authenticated missions,
# each against a GENUINELY fresh isolated juice-shop-bench, deep-assert both, then compare their
# signatures and FAIL on drift. This proves determinism across two real end-to-end runs (not one run
# vs a stored file). Volatile fields (mission ids, timestamps) never enter the signature; families /
# persona-count / auth_success must match EXACTLY, numeric counts within a documented variance.
#
# Usage: sh scripts/benchmark_repeat.sh
set -u
A="http://localhost:8000"
COMPOSE="${COMPOSE:-docker compose}"
pass=0; fail=0
ck() { if [ "$2" = "PASS" ]; then echo "  PASS  $1"; pass=$((pass + 1)); else echo "  FAIL  $1"; fail=$((fail + 1)); fi; }

GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "")   # FULL hash (CHAD #4)
IMG_DIGEST=$(docker image inspect apolaki-agent:latest --format '{{.Id}}' 2>/dev/null || echo "")

# Provision a fresh isolated bench, engage + run + poll ONE authenticated mission. Progress goes to
# stderr; the mission id is the ONLY thing on stdout so the caller can capture it.
run_mission() {
  sh scripts/fresh_lab.sh 1>&2 || { echo ""; return 1; }
  JS_DIGEST=$(docker inspect "$($COMPOSE --profile bench ps -q juice-shop-bench 2>/dev/null | head -1)" --format '{{index .Image}}' 2>/dev/null || echo "")
  sid=$(curl -s -X POST "$A/engage" -H 'Content-Type: application/json' \
    -d '{"program_name":"benchmark-repeat","in_scope":["http://juice-shop-bench:3000"],"mode":"active","strategy":"deterministic","authenticated_scan":true}' \
    | grep -oE '"session_id":"[a-f0-9]+"' | head -1 | cut -d'"' -f4)
  [ -z "$sid" ] && { echo ""; return 1; }
  echo "  engaged mission $sid; running (~5-10 min)..." 1>&2
  curl -s -X POST "$A/run/$sid" >/dev/null 2>&1
  i=0
  while [ "$i" -lt 540 ]; do
    st=$(curl -s "$A/status/$sid" | grep -oE '"status":"[a-z_]+"' | head -1 | cut -d'"' -f4)
    case "$st" in complete | stopped | failed) break ;; esac
    i=$((i + 1)); sleep 2
  done
  [ "$st" != "complete" ] && { echo ""; return 1; }
  echo "$sid"
}

echo "[repeat] mission A (fresh isolated lab)"
sidA=$(run_mission)
[ -n "$sidA" ] && ck "mission A completed ($sidA)" PASS || { ck "mission A completed" FAIL; echo "[repeat] cannot continue"; exit 1; }

echo "[repeat] deep-assert A + write its signature as the determinism baseline"
JS_A=$(docker inspect "$($COMPOSE --profile bench ps -q juice-shop-bench 2>/dev/null | head -1)" --format '{{index .Image}}' 2>/dev/null || echo "")
MSYS_NO_PATHCONV=1 $COMPOSE exec -T agent sh -c 'mkdir -p /app/data/benchmark_artifacts; rm -f /app/data/repeat_baseline.json' >/dev/null 2>&1
MSYS_NO_PATHCONV=1 $COMPOSE exec -T -e APOLAKI_GIT_COMMIT="$GIT_COMMIT" -e APOLAKI_IMAGE_DIGEST="$IMG_DIGEST" -e APOLAKI_JUICESHOP_DIGEST="$JS_A" \
  agent python benchmark_assert.py "$A" "$sidA" --baseline /app/data/repeat_baseline.json --artifact "/app/data/benchmark_artifacts/repeat_${sidA}.json" \
  && ck "mission A deep assertions passed" PASS || ck "mission A deep assertions" FAIL

echo "[repeat] mission B (second fresh isolated lab)"
sidB=$(run_mission)
[ -n "$sidB" ] && ck "mission B completed ($sidB)" PASS || { ck "mission B completed" FAIL; echo "[repeat] cannot continue"; exit 1; }

echo "[repeat] deep-assert B + compare its signature against A (determinism across two real runs)"
JS_B=$(docker inspect "$($COMPOSE --profile bench ps -q juice-shop-bench 2>/dev/null | head -1)" --format '{{index .Image}}' 2>/dev/null || echo "")
ARTB="/app/data/benchmark_artifacts/repeat_${sidB}.json"
if MSYS_NO_PATHCONV=1 $COMPOSE exec -T -e APOLAKI_GIT_COMMIT="$GIT_COMMIT" -e APOLAKI_IMAGE_DIGEST="$IMG_DIGEST" -e APOLAKI_JUICESHOP_DIGEST="$JS_B" \
     agent python benchmark_assert.py "$A" "$sidB" --baseline /app/data/repeat_baseline.json --artifact "$ARTB"; then
  ck "mission B deep assertions + determinism vs A all passed" PASS
else
  ck "mission B deep assertions / determinism vs A" FAIL
fi

# Retain B's artifact (it embeds the A-vs-B comparison + both signatures via the baseline) — via a
# temp so a failed copy never leaves a zero-byte file (CHAD #2). Only a non-empty artifact is kept.
mkdir -p benchmark_results 2>/dev/null
_rt="benchmark_results/.repeat_${sidA}_${sidB}.json.part"
MSYS_NO_PATHCONV=1 $COMPOSE exec -T agent cat "$ARTB" > "$_rt" 2>/dev/null
if [ -s "$_rt" ]; then
  mv "$_rt" "benchmark_results/repeat_${sidA}_${sidB}.json"
  ck "repeat artifact retained (benchmark_results/repeat_${sidA}_${sidB}.json)" PASS
else
  rm -f "$_rt" "benchmark_results/repeat_${sidA}_${sidB}.json"
  ck "repeat artifact retained" FAIL
fi

echo "[repeat] missions: A=$sidA  B=$sidB"
echo "[repeat] ==== $pass passed, $fail failed ===="
[ "$fail" -eq 0 ]
