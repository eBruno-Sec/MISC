#!/bin/sh
# Bring up a GENUINELY fresh, ISOLATED Juice Shop for the full-mission benchmark, SAFELY.
#
# CHAD re-audit #1: the old version (a) ran `docker compose restart` which kept the persistent
# volume, and its rewrite (b) picked the volume by name-suffix grep — which could match a DIFFERENT
# Compose project's volume and delete it. This version resolves the EXACT volume by Docker Compose
# labels scoped to THIS project, verifies ownership before deleting, treats a deletion failure as
# fatal, and FAILS (exit 1) unless the dedicated volume was provably recreated after this script
# started (t0). It NEVER touches the normal juice-shop / juiceshop_data a user works against.
set -u
COMPOSE="${COMPOSE:-docker compose}"
BENCH_HOST_PORT="${BENCH_HOST_PORT:-42001}"
t0=$(date +%s)

# Ground-truth the Compose project name from a currently-running service (never a guess), so the
# volume label filter cannot select another project's volume.
_running=$($COMPOSE ps -q juice-shop 2>/dev/null | head -1)
PROJECT=$(docker inspect "$_running" --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null)
[ -z "$PROJECT" ] && PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$(pwd)" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')}"

# The dedicated bench volume, identified by Compose's own labels — unambiguous, project-scoped.
_bench_vol() {
  docker volume ls -q \
    --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.volume=juiceshop_bench_data" 2>/dev/null | head -1
}
_epoch() { date -u -d "$1" +%s 2>/dev/null || echo 0; }

echo "[fresh-lab] project=$PROJECT — recreating ISOLATED juice-shop-bench (dedicated volume only)"
$COMPOSE --profile bench rm -sf juice-shop-bench >/dev/null 2>&1

# Delete ONLY the project-scoped, label-verified bench volume. A deletion FAILURE is fatal (we must
# not proceed on stale data). Absence is fine (first run) — `up` will create it fresh.
vol=$(_bench_vol)
had_volume=0
if [ -n "$vol" ]; then
  had_volume=1
  # double-check the volume's own labels before removal (defense in depth)
  vproj=$(docker volume inspect "$vol" --format '{{index .Labels "com.docker.compose.project"}}' 2>/dev/null)
  vname=$(docker volume inspect "$vol" --format '{{index .Labels "com.docker.compose.volume"}}' 2>/dev/null)
  if [ "$vproj" != "$PROJECT" ] || [ "$vname" != "juiceshop_bench_data" ]; then
    echo "[fresh-lab] FAILED: refusing to delete '$vol' — labels (project=$vproj volume=$vname) do not match"
    exit 1
  fi
  if ! docker volume rm "$vol" >/dev/null 2>&1; then
    echo "[fresh-lab] FAILED: could not remove bench volume '$vol' (in use?) — not proceeding on stale data"
    exit 1
  fi
fi

$COMPOSE --profile bench up -d --force-recreate juice-shop-bench >/dev/null 2>&1

ready=0
for i in $(seq 1 90); do
  curl -sf "http://localhost:${BENCH_HOST_PORT}/" >/dev/null 2>&1 && { ready=1; break; }
  sleep 2
done
if [ "$ready" != 1 ]; then echo "[fresh-lab] FAILED: juice-shop-bench not ready on :${BENCH_HOST_PORT}"; exit 1; fi

# Enforce freshness: the dedicated volume must now EXIST and have been created after t0, and the
# container must have started after t0. Printing alone is not proof — these are hard gates.
cid=$($COMPOSE --profile bench ps -q juice-shop-bench 2>/dev/null | head -1)
cont_started=$(docker inspect "$cid" --format '{{.State.StartedAt}}' 2>/dev/null)
newvol=$(_bench_vol)
vol_created=$(docker volume inspect "$newvol" --format '{{.CreatedAt}}' 2>/dev/null)
cont_epoch=$(_epoch "$cont_started")
vol_epoch=$(_epoch "$vol_created")

echo "[fresh-lab] container=$cid started=$cont_started"
echo "[fresh-lab] volume=$newvol created=$vol_created (prior volume removed: $had_volume)"
if [ -z "$newvol" ]; then
  echo "[fresh-lab] FAILED: dedicated bench volume does not exist after recreate"; exit 1
fi
if [ "$cont_epoch" -lt "$t0" ] 2>/dev/null || [ "$vol_epoch" -lt "$t0" ] 2>/dev/null; then
  echo "[fresh-lab] FAILED: freshness not proven — container($cont_epoch)/volume($vol_epoch) not both >= t0($t0)"
  exit 1
fi
echo "[fresh-lab] READY on http://juice-shop-bench:3000 (host :${BENCH_HOST_PORT})"
echo "[fresh-lab] FRESH-PROOF: label-verified dedicated volume + container BOTH created after t0 — isolated"
