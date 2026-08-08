#!/bin/sh
# Bake-drift gate (#125).
#
# Apolaki's agent code is BAKED into the image, but fast iteration uses `docker cp` into the running
# container. Those two states drift silently, and the failure is invisible: no error, no failing test,
# nothing in git — the tests pass because they run against the patched container. Then a
# `docker compose up` recreates it from the image and the platform quietly reverts.
#
# This happened for real on 2026-08-08: five engines (transport_posture, ics_dnp3_s7 and the technique
# entries for them) existed only in the running container. Everything was committed to git, so nothing was
# lost permanently, but the deployed platform was a day behind its own test suite.
#
# The check compares the RUNNING container against a fresh container from the BAKED image. Any difference
# means: rebuild before believing your results.
set -e

CONTAINER="${APOLAKI_CONTAINER:-apolaki-agent-1}"
IMAGE="${APOLAKI_IMAGE:-apolaki-agent}"

probe='
import json, os, sys
sys.path.insert(0, "/app")
mods = sorted(f for f in os.listdir("/app") if f.endswith(".py"))
out = {"modules": len(mods), "module_list": mods}
try:
    import techniques as T
    out["techniques"] = len(T.TECHNIQUES)
    out["technique_ids"] = sorted(T.TECHNIQUES)
except Exception as e:
    out["techniques"] = -1
    out["error"] = str(e)[:80]
print(json.dumps(out))
'

running=$(docker exec "$CONTAINER" python -c "$probe")
baked=$(docker run --rm "$IMAGE" python -c "$probe")

# The comparison runs INSIDE the container too: the host is not guaranteed to have a python3 on PATH
# (it does not on the Windows workstation this is developed on), and a gate that cannot run is not a gate.
docker exec -i "$CONTAINER" python - "$running" "$baked" <<'PY'
import json, sys
run, bake = json.loads(sys.argv[1]), json.loads(sys.argv[2])
drift = []
if run["techniques"] != bake["techniques"]:
    drift.append("techniques: running=%s baked=%s" % (run["techniques"], bake["techniques"]))
only_run = sorted(set(run["module_list"]) - set(bake["module_list"]))
only_bake = sorted(set(bake["module_list"]) - set(run["module_list"]))
if only_run:
    drift.append("modules ONLY in the running container (never baked): %s" % ", ".join(only_run))
if only_bake:
    drift.append("modules only in the image (deleted from the container): %s" % ", ".join(only_bake))
t_run, t_bake = set(run.get("technique_ids") or []), set(bake.get("technique_ids") or [])
if t_run - t_bake:
    drift.append("techniques never baked: %s" % ", ".join(sorted(t_run - t_bake)))

if drift:
    print("BAKE DRIFT — the running container does not match the image:")
    for d in drift:
        print("  !", d)
    print("\nYour tests are passing against code that a `docker compose up` would discard.")
    print("Fix: docker compose build agent && docker compose up -d agent")
    sys.exit(1)
print("bake OK — running container matches the baked image (%d modules, %d techniques)"
      % (run["modules"], run["techniques"]))
PY
