# MISC // Practice Targets

A small **isolated lab** of deliberately-vulnerable apps for **authorized** local
testing of the tools in this repo (Round Table, etc.). Runs as its own compose
project, so rebuilding any app never takes these down.

> ⚠️ These apps are intentionally insecure. Bound to `127.0.0.1` only — never
> expose them to a network or the internet.

## Run

```bash
# from the MISC repo root
docker compose -f targets/docker-compose.yml up -d      # start
docker compose -f targets/docker-compose.yml ps         # status
docker compose -f targets/docker-compose.yml down       # stop
```

## Targets

| App | Scan as (from a tool container) | Open in browser |
|---|---|---|
| OWASP Juice Shop | `host.docker.internal:42000` | http://localhost:42000 |
| DVWA | `host.docker.internal:42001` | http://localhost:42001 |
| VAmPI (vulnerable API) | `host.docker.internal:42002` | http://localhost:42002 |

## Always-on alternative (no setup)

PortSwigger hosts **`ginandjuice.shop`** as a publicly authorized scan target —
just launch a mission against `ginandjuice.shop`, nothing to run locally.
