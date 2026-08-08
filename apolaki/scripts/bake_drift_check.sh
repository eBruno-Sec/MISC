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
import hashlib, json, os, sys
sys.path.insert(0, "/app")
mods = sorted(f for f in os.listdir("/app") if f.endswith(".py"))
# CONTENT hashes, not just names. The first version of this gate compared module NAMES and technique IDs,
# so editing the body of an existing module changed neither and the drift was invisible. That is not
# hypothetical: _do_header_trust was added to agent.py, the image was rebuilt correctly, the container was
# NOT recreated, and this check printed "bake OK" while the running platform lacked the method entirely.
# Most changes edit an existing file, so the old check was blind to the common case.
digests = {}
for f in mods:
    try:
        digests[f] = hashlib.sha256(open(os.path.join("/app", f), "rb").read()).hexdigest()[:16]
    except Exception:
        digests[f] = "unreadable"
out = {"modules": len(mods), "module_list": mods, "digests": digests}
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

# THE load-bearing comparison: same filename, different CONTENT. This is the common case (editing an
# existing module) and the one the name-only check could never see.
d_run, d_bake = run.get("digests") or {}, bake.get("digests") or {}
changed = sorted(f for f in set(d_run) & set(d_bake) if d_run[f] != d_bake[f])
if changed:
    drift.append("%d module(s) differ in CONTENT between container and image: %s"
                 % (len(changed), ", ".join(changed[:8]) + (" ..." if len(changed) > 8 else "")))

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
