# Yggdrasil

Yggdrasil is a self-hosted, Docker-native security assessment workspace for authorized testing. Give it a target, choose an assessment mode, approve active phases when needed, and Yggdrasil coordinates reconnaissance, active checks, payload preparation, impact review, notes, findings, exports, and reporting.

> Authorized testing only. By using Yggdrasil you confirm you have written authorization to test the specified target.

## Stages

| Stage | Role | What it does |
| --- | --- | --- |
| Odin | Orchestration | Coordinates the run, state changes, and approval gates |
| Frigg | Strategy | Builds the mission plan and AI-assisted summary when configured |
| Heimdall | Recon | CT logs, RDAP/WHOIS, DNS, liveness, vendors, and fingerprints |
| Tyr | Active assessment | Nmap, Nuclei, web checks, traversal, IDOR/BOLA, and discovery |
| Brokkr | Payload forge | Target-aware payloads and custom wordlists |
| Skuld | Impact review | Post-exploit impact analysis when exploitable targets exist |
| Saga | Reporting | HTML report, CSV export, JSON export, and executive summary |

The internal API still uses the original stage keys for compatibility with existing missions.

## Run

```bash
./yggdrasil.sh
```

Direct Docker usage still works:

```bash
docker compose up --build -d
```

Open:

```text
http://localhost:3000
```

Stop:

```bash
./yggdrasil.sh --stop
```

## Environment

Copy `.env.example` to `.env` if present, then set what you need.

| Variable | Notes |
| --- | --- |
| `DB_NAME` | PostgreSQL database name. Defaults to `yggdrasil`. |
| `YGGDRASIL_API_KEY` | Optional API key for `/api` and `/ws`. |
| `OLYMPUS_API_KEY` | Backward-compatible fallback for existing installs. |
| `YGGDRASIL_AUTO_APPROVE` | Optional global pre-authorization for all HITL gates. Prefer the per-mission launch switch. |
| `YGGDRASIL_APPROVAL_TIMEOUT` | `0` waits indefinitely. Positive seconds auto-denies after timeout. |
| `YGGDRASIL_OFFENSIVE_MAX_HOSTS` | Active scan host cap. Defaults to `5`. |
| `YGGDRASIL_CIDR_MAX_HOSTS` | CIDR expansion cap. Defaults to `1024`. |
| `YGGDRASIL_HEARTBEAT_SECONDS` | Mission heartbeat interval. Defaults to `300`; `0` disables. |
| `AI_PROVIDER` | `anthropic` or `openrouter`. |
| `AI_API_KEY` | Enables Frigg strategy enrichment and Saga summaries. |
| `AI_MODEL` | Optional model override. |
| `SECRET_KEY` | Change before exposing beyond localhost. |
| `DB_USER` / `DB_PASSWORD` | PostgreSQL credentials. Existing defaults are preserved for local compatibility. |

## Assessment Modes

| Mode | Flow | Approval gates |
| --- | --- | --- |
| Passive | Frigg -> Heimdall -> Saga | None |
| Active | Frigg -> Heimdall -> Tyr -> Saga | 1 gate before Tyr |
| Full | Frigg -> Heimdall -> Tyr -> Brokkr -> Skuld -> Saga | Up to 3 gates |

Approval gates do not auto-deny or auto-continue. They wait until an operator explicitly authorizes or denies the stage.

## Mission Health

Running assessments publish a five-minute heartbeat by default. The mission header shows the last function check, the active stage, and the current hold-up. The activity feed also receives heartbeat entries during long scans, so a quiet scan is distinguishable from a failed or stuck backend.

## Scope

Yggdrasil accepts scope entries directly in the launch form. It also supports pasted or uploaded scope files from common bug bounty platforms. In-scope and out-of-scope rules are enforced before active testing.

## Reports, Evidence, And Exports

Completed assessments expose:

- HTML report from the assessment header
- CSV export with quoted multiline evidence fields
- JSON export
- Download Workspace Backup (.json) using `YGGDRASIL_backup_[YYYY-MM-DD]_[workspace-id].json`
- Import Workspace Backup (.json), which validates the file, shows a summary, and creates a fresh assessment row
- Relaunch from the archive, which creates a fresh assessment row using the same target, mode, scope, and scope rules

Yggdrasil stores HTTP exchange evidence with sensitive request and response headers redacted. The mission Workbench tab exposes replay, parameter fuzzing, cross-role access checks, and Markdown PoC viewing. Workbench actions enforce the mission scope guard before sending requests.

## Notes

Legacy `OLYMPUS_API_KEY` remains supported so existing local installs do not break.
