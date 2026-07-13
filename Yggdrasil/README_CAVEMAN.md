# Yggdrasil Quick Guide

Yggdrasil runs authorized security assessments from a local web UI.

## Start

```bash
./yggdrasil.sh
```

Then open:

```text
http://localhost:3000
```

## Stop

```bash
./yggdrasil.sh --stop
```

## The Stages

- Odin coordinates the assessment.
- Frigg prepares the strategy.
- Heimdall performs recon.
- Tyr runs active assessment checks after approval.
- Brokkr prepares payloads and wordlists.
- Skuld reviews impact when exploitable targets exist.
- Saga creates the report.

## Basic Use

1. Click `New Assessment`.
2. Enter a target you are authorized to test.
3. Choose `Passive`, `Active`, or `Full`.
4. Add scope notes or scope files if needed.
5. Read approval prompts before allowing active stages.
6. Review findings, notes, targets, exports, and the final report.

Approval prompts wait for you. They do not auto-deny or move ahead without a decision.

The mission screen performs a one-minute function check while a scan is running. If the scanner is quiet, the header and activity log will still tell you whether Yggdrasil is alive, waiting on approval, or spending time in a specific stage.

## Important

Only test systems where you have written authorization.
