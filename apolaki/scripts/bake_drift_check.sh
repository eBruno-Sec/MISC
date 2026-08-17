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

# THE THIRD EDGE (Q-059). The two probes above answer "does the container match the image?" and can
# both be perfectly consistent while the IMAGE ITSELF is months behind the source tree. That is not
# hypothetical: on 2026-08-17 the deployed agent was 59 commits behind `agent/`, the entire Q-051
# report-rendering surface was missing from the running binary, and three engines deleted from the
# tree were still registered and dispatchable in the deployment. This gate printed nothing, because
# container and image agreed exactly. A gate that checks two of three edges reports on the
# relationship it can see and stays silent about the one that mattered.
#
# Mounting the tree over /app makes the SAME probe read the working copy, so the comparison is
# identical in kind and there is no second implementation to drift.
# `pwd -W` yields a Windows-style path (C:/...). This is load-bearing on the Git Bash workstation this
# runs on: a POSIX-style /c/... or /tmp/... path handed to `docker -v` mounts an EMPTY volume without
# error, so the probe reads an empty /app, reports 0 modules, and every comparison below trivially
# "passes". That is the silent-success shape this gate exists to prevent, so it is also asserted.
REPO_DIR=$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })
tree=$(MSYS_NO_PATHCONV=1 docker run --rm -v "$REPO_DIR/agent:/app" -w /app "$IMAGE" python -c "$probe")

# POSITIVE CONTROL: the tree probe must have actually seen the source. An empty or unreadable mount
# is an inconclusive run, never a clean one.
tree_mods=$(printf '%s' "$tree" | tr ',' '\n' | grep -c '"modules"' || true)
case "$tree" in
  *'"modules": 0'*|"")
    echo "GATE INCONCLUSIVE — the source-tree probe saw 0 modules, so the tree/image comparison"
    echo "could not run. Almost always a mount that resolved to nothing: check that"
    echo "  $REPO_DIR/agent"
    echo "is a Windows-style path visible to Docker. Refusing to report 'bake OK' from no data."
    exit 2 ;;
esac

# The comparison runs INSIDE the container too: the host is not guaranteed to have a python3 on PATH
# (it does not on the Windows workstation this is developed on), and a gate that cannot run is not a gate.
# The three probe results are passed as FILES, not argv. Passing them as arguments worked with two
# probes and broke the moment a third was added: Windows caps a command line at ~32KB and three
# content-digest maps over ~100 modules exceed it, and `docker.exe` reports only "Argument list too
# long" -- with `sh` still exiting 0, so the gate silently stopped gating. A gate whose failure mode
# is a clean exit is the failure mode this whole file exists to catch.
# Created INSIDE the repo, not in /tmp, for the same empty-mount reason described above.
PROBE_DIR=$(mktemp -d "$REPO_DIR/.bakeprobe.XXXXXX")
trap 'rm -rf "$PROBE_DIR"' EXIT
printf '%s' "$running" > "$PROBE_DIR/running.json"
printf '%s' "$baked"   > "$PROBE_DIR/baked.json"
printf '%s' "$tree"    > "$PROBE_DIR/tree.json"

MSYS_NO_PATHCONV=1 docker run --rm -i -v "$PROBE_DIR:/probes:ro" "$IMAGE" python - <<'PY'
import json, sys
run  = json.load(open("/probes/running.json"))
bake = json.load(open("/probes/baked.json"))
try:
    tree = json.load(open("/probes/tree.json"))
except Exception:
    tree = None
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

# Edge 3: image vs source tree. Reported separately from the container/image drift above, because the
# two have DIFFERENT fixes -- that one needs `up -d` to recreate a container, this one needs a
# `build` because the image itself is behind. Merging them would hand the reader one message for two
# problems, which is the same class of error as the report merging blocked_by_mode into not_selected.
stale = []
if tree:
    d_tree, d_bake = tree.get("digests") or {}, bake.get("digests") or {}
    behind = sorted(f for f in set(d_tree) & set(d_bake) if d_tree[f] != d_bake[f])
    only_tree = sorted(set(tree["module_list"]) - set(bake["module_list"]))
    only_img = sorted(set(bake["module_list"]) - set(tree["module_list"]))
    if behind:
        stale.append("%d module(s) differ in CONTENT between the SOURCE TREE and the image: %s"
                     % (len(behind), ", ".join(behind[:8]) + (" ..." if len(behind) > 8 else "")))
    if only_tree:
        stale.append("modules in the tree that were NEVER BAKED (cannot run in any mission): %s"
                     % ", ".join(only_tree))
    if only_img:
        stale.append("modules DELETED from the tree but still live in the image (still dispatchable "
                     "in a real scan): %s" % ", ".join(only_img))
    if tree.get("techniques", -1) != bake.get("techniques", -1):
        stale.append("techniques: tree=%s image=%s" % (tree.get("techniques"), bake.get("techniques")))

# BOTH classes are reported before exiting. They have different fixes -- container/image drift needs
# `up -d` to recreate a container, image/tree drift needs a `build` because the image itself is behind
# -- and stopping at the first would hand the reader one message for two problems, then let them
# re-run and discover the second only after fixing the first.
if drift:
    print("EDGE 1 — BAKE DRIFT: the running container does not match the image:")
    for d in drift:
        print("  !", d)
    print("  Your tests are passing against code that a `docker compose up` would discard.")
    print("")

if stale:
    print("EDGE 2 — IMAGE IS BEHIND THE SOURCE TREE: the deployed platform is not the code you are "
          "writing:")
    for s in stale:
        print("  !", s)
    print("  This edge went UNCHECKED until Q-059. Container and image can agree perfectly while the")
    print("  image is months behind HEAD, and this gate printed 'bake OK' in exactly that state on")
    print("  2026-08-17 -- the deployed agent was 59 commits behind, missing the entire Q-051 report")
    print("  rendering surface, and still carried three engines that had been deleted from the tree.")
    print("  A mission run in this state does NOT exercise the tree.")
    print("")

if drift or stale:
    print("Fix: docker compose build agent && docker compose up -d agent")
    print("(check `curl -s http://localhost:8000/missions` first — a build SIGKILLs a running mission,")
    print(" and three have died that way)")
    sys.exit(1)

print("bake OK — running container matches the baked image, and the image matches the source tree "
      "(%d modules, %d techniques)" % (run["modules"], run["techniques"]))
PY
