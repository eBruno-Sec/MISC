# Measurement harnesses — RESCUED FROM A RUNNING CONTAINER, 2026-08-17

These four scripts existed **only inside `apolaki-agent-1`** and were in no commit. They were
`docker cp`-ed in during the throughput-diagnosis lane and never landed in git, so the next
`docker compose build agent && docker compose up -d agent` would have destroyed them permanently.
Found by the Q-059 drift gate, which now checks image-vs-tree and reports modules that live in the
container but nowhere else.

They are kept here rather than in `agent/` on purpose: they are operator harnesses, not engines, and
adding four never-imported modules to the engine namespace would give the dead-code and island gates
real work to do for no reason.

Verified before committing: no credentials, no tokens, no machine-specific paths. The only hosts they
reference are local lab services (`domsource:8080`, `owaspbench:8443`).

## Running them

Each does `sys.path.insert(0, "/app")`, so the agent tree must be mounted at `/app` — that is the only
requirement, and it is why they work unchanged from this directory:

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" \
  -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/scripts/measure:/measure" \
  -w /app apolaki-agent python /measure/measure_cost.py
```

`--network apolaki_default` is required for anything that touches a lab: off that network the compose
DNS names do not resolve and the failure looks like a code regression rather than a missing network.

## What each one answers

| script | question |
|---|---|
| `measure_cost.py` | Throughput diagnosis: where do the seconds actually go? |
| `measure_browser.py` | Splits `run_xss`'s wall clock into playwright start, chromium launch, context/page setup |
| `mission_breakdown.py` | Per-tool wall-clock breakdown of a real mission, from the log timestamps (reads the mission sqlite directly) |
| `acceptance.py` | Same target, same mode: wall clock must DROP while the finding set stays IDENTICAL — the shape any performance change has to satisfy before it can be called an improvement rather than a regression that finishes sooner |

`acceptance.py` is the one worth keeping deliberately: it encodes the rule that a speedup which changes
the finding set is not a speedup. That is a standing discipline in this project, and it had no
committed executable form until now.
