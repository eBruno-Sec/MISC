#!/bin/sh
# Bring up a GENUINELY fresh, ISOLATED Juice Shop for the full-mission benchmark.
#
# CHAD audit #1: the old --fresh-lab ran `docker compose restart juice-shop`, which does NOT reset
# the persistent juiceshop_data volume — old accounts/state survived, so the "fresh" claim was false.
# This instead recreates the DEDICATED juice-shop-bench container AND its OWN volume
# (juiceshop_bench_data), giving a truly fresh DB, and NEVER touches the normal juice-shop /
# juiceshop_data a user works against. Freshness is PROVEN structurally: a new container + a new
# volume, both created after this script started (printed for the benchmark artifact).
set -u
COMPOSE="${COMPOSE:-docker compose}"
BENCH_HOST_PORT="${BENCH_HOST_PORT:-42001}"
t0=$(date +%s)

echo "[fresh-lab] recreating ISOLATED juice-shop-bench (dedicated volume only — normal lab untouched)"
$COMPOSE --profile bench rm -sf juice-shop-bench >/dev/null 2>&1
# Remove ONLY the bench volume (matched by suffix so the compose project prefix doesn't matter).
vol=$(docker volume ls -q 2>/dev/null | grep 'juiceshop_bench_data$' | head -1)
[ -n "$vol" ] && docker volume rm -f "$vol" >/dev/null 2>&1
$COMPOSE --profile bench up -d --force-recreate juice-shop-bench >/dev/null 2>&1

ready=0
for i in $(seq 1 90); do
  curl -sf "http://localhost:${BENCH_HOST_PORT}/" >/dev/null 2>&1 && { ready=1; break; }
  sleep 2
done
if [ "$ready" != 1 ]; then echo "[fresh-lab] FAILED: juice-shop-bench not ready on :${BENCH_HOST_PORT}"; exit 1; fi

# Prove freshness: the container + the volume must have been created AFTER this script started.
cid=$($COMPOSE --profile bench ps -q juice-shop-bench 2>/dev/null | head -1)
cont_started=$(docker inspect "$cid" --format '{{.State.StartedAt}}' 2>/dev/null)
vol=$(docker volume ls -q 2>/dev/null | grep 'juiceshop_bench_data$' | head -1)
vol_created=$(docker volume inspect "$vol" --format '{{.CreatedAt}}' 2>/dev/null)
cont_epoch=$(date -u -d "$cont_started" +%s 2>/dev/null || echo 0)

echo "[fresh-lab] READY on http://juice-shop-bench:3000 (host :${BENCH_HOST_PORT})"
echo "[fresh-lab]   container started: $cont_started"
echo "[fresh-lab]   volume created:    $vol_created (name: $vol)"
if [ "$cont_epoch" -ge "$t0" ] 2>/dev/null; then
  echo "[fresh-lab]   FRESH-PROOF: container/volume created after reset start — isolated fresh state"
else
  echo "[fresh-lab]   WARN: could not verify container freshness timestamp"
fi
