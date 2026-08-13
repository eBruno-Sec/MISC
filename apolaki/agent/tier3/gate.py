"""Ratchet Tier-3 control coverage against a measured JSON baseline."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

from .runner import ERROR, FAIL, NOT_RUN, PASS, SKIPPED, STATUSES, write_artifact


TOOL_VERSION = "apolaki-tier3-gate/1"


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf8")


def _entries(artifact: dict, label: str) -> dict[str, dict]:
    out = {}
    for row in artifact.get("per_entry") or []:
        control_id = str(row.get("control_id") or "").strip()
        status = str(row.get("status") or "").strip()
        if not control_id:
            raise ValueError("%s artifact contains an entry without control_id" % label)
        if control_id in out:
            raise ValueError("%s artifact contains duplicate control_id %s" % (label, control_id))
        if status not in STATUSES:
            raise ValueError("%s artifact has invalid status %r for %s" % (label, status, control_id))
        out[control_id] = row
    return out


def evaluate(current: dict, baseline: dict) -> dict:
    base = _entries(baseline, "baseline")
    now = _entries(current, "current")
    all_ids = sorted(set(base) | set(now))
    comparisons = []
    regressions = []
    gained = []
    known_gaps = []
    new_nonpasses = []

    for control_id in all_ids:
        before = base.get(control_id)
        after = now.get(control_id)
        before_status = str((before or {}).get("status") or NOT_RUN)
        current_status = str((after or {}).get("status") or NOT_RUN)
        baseline_required = before_status == PASS
        regression = baseline_required and current_status != PASS
        row = {
            "control_id": control_id,
            "vulnerability_class": str((after or before or {}).get("vulnerability_class") or ""),
            "baseline_status": before_status,
            "current_status": current_status,
            "baseline_required": baseline_required,
            "regression": regression,
        }
        comparisons.append(row)
        if regression:
            regressions.append(row)
        elif current_status == PASS and before_status != PASS:
            gained.append(control_id)
        elif current_status != PASS:
            if before is not None:
                known_gaps.append(control_id)
            else:
                new_nonpasses.append(control_id)

    base_classes = {}
    current_classes = {}
    for row in base.values():
        if row["status"] == PASS:
            base_classes.setdefault(str(row.get("vulnerability_class") or ""), set()).add(row["control_id"])
    for row in now.values():
        if row["status"] == PASS:
            current_classes.setdefault(str(row.get("vulnerability_class") or ""), set()).add(row["control_id"])
    class_names = sorted(set(base_classes) | set(current_classes))
    per_class = {}
    class_regressions = []
    for name in class_names:
        had = sorted(base_classes.get(name) or ())
        has = sorted(current_classes.get(name) or ())
        regression = bool(had) and not has
        per_class[name] = {
            "baseline_passing": had,
            "current_passing": has,
            "regression": regression,
        }
        if regression:
            class_regressions.append(name)

    environment_failures = list(current.get("environment_failures") or [])
    fatal_statuses = sorted(row["control_id"] for row in now.values()
                            if row["status"] in (FAIL, ERROR, NOT_RUN))
    current_pass = sorted(control_id for control_id, row in now.items() if row["status"] == PASS)
    baseline_pass = sorted(control_id for control_id, row in base.items() if row["status"] == PASS)
    ok = not regressions and not class_regressions and not environment_failures and not fatal_statuses
    semantic = {
        "per_entry": comparisons,
        "per_class": per_class,
        "regressions": regressions,
        "class_regressions": class_regressions,
        "gained": gained,
        "known_gaps": known_gaps,
        "new_nonpasses": new_nonpasses,
        "fatal_statuses": fatal_statuses,
        "environment_failures": environment_failures,
        "baseline_pass": baseline_pass,
        "current_pass": current_pass,
        "ok": ok,
    }
    statement = (
        "%d Tier-3 control(s) pass; no regression against a baseline of %d"
        % (len(current_pass), len(baseline_pass))
        if ok else
        "TIER-3 REGRESSION: controls=%d classes=%d fatal=%d environment=%d"
        % (len(regressions), len(class_regressions), len(fatal_statuses), len(environment_failures))
    )
    return {
        "tool_version": TOOL_VERSION,
        "git_sha": str(current.get("git_sha") or "unknown"),
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        **semantic,
        "baseline_semantic_sha256": str(baseline.get("semantic_sha256") or ""),
        "current_semantic_sha256": str(current.get("semantic_sha256") or ""),
        "candidate_baseline_pass": sorted(set(baseline_pass) | set(current_pass)),
        "summary": {
            "baseline_passing": len(baseline_pass),
            "current_passing": len(current_pass),
            "regressions": len(regressions),
            "class_regressions": len(class_regressions),
            "gained": len(gained),
            "known_gaps": len(known_gaps),
            "new_nonpasses": len(new_nonpasses),
        },
        "statement": statement,
        "semantic_sha256": hashlib.sha256(_canonical(semantic)).hexdigest(),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf8"))
    current = json.loads(Path(args.current).read_text(encoding="utf8"))
    result = evaluate(current, baseline)
    if args.output:
        digest = write_artifact(args.output, result)
        print("gate_artifact_sha256=%s" % digest)
    print(result["statement"])
    if result["known_gaps"]:
        print("known non-passes (not credited): %s" % ", ".join(result["known_gaps"]))
    if result["regressions"]:
        print("regressed controls: %s" % ", ".join(r["control_id"] for r in result["regressions"]))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
