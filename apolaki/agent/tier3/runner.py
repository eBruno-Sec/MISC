"""Execute registered Tier-3 controls and emit a machine-readable artifact."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from .registry import CONTROLS, SAFE, ControlSpec, validate_registry


TOOL_VERSION = "apolaki-tier3/1"
PASS, FAIL, SKIPPED, ERROR, NOT_RUN = "PASS", "FAIL", "SKIPPED", "ERROR", "NOT_RUN"
STATUSES = (PASS, FAIL, SKIPPED, ERROR, NOT_RUN)
_PRIORITY = {PASS: 0, NOT_RUN: 1, SKIPPED: 2, FAIL: 3, ERROR: 4}


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf8")


def _match_collected(node_id: str, collected: list[str]) -> list[str]:
    return [n for n in collected if n == node_id or n.startswith(node_id + "[")]


def _node_status(node_id: str, capture: dict) -> tuple[str, str, list[str]]:
    matched = _match_collected(node_id, list(capture.get("collected") or []))
    if not matched:
        return NOT_RUN, "pytest did not collect the registered node", []

    statuses = []
    details = []
    for child in matched:
        reports = list((capture.get("reports") or {}).get(child) or [])
        failed_setup = any(r.get("outcome") == "failed" and r.get("when") in ("setup", "teardown")
                           for r in reports)
        call = next((r for r in reports if r.get("when") == "call"), None)
        skipped = any(r.get("outcome") == "skipped" for r in reports)
        xstate = next((r.get("wasxfail") for r in reports if r.get("wasxfail")), "")
        if failed_setup:
            status = ERROR
        elif call and call.get("outcome") == "failed":
            status = FAIL
        elif xstate:
            status = SKIPPED if skipped else FAIL
        elif skipped:
            status = SKIPPED
        elif call and call.get("outcome") == "passed":
            status = PASS
        else:
            status = NOT_RUN
        statuses.append(status)
        details.extend(r.get("detail") for r in reports if r.get("detail"))
    status = max(statuses, key=lambda s: _PRIORITY[s])
    return status, (details[0][:500] if details else "%d pytest item(s)" % len(matched)), matched


def _execute_one(spec: ControlSpec, repo_root: Path, timeout_s: int) -> tuple[dict, list[dict]]:
    with tempfile.TemporaryDirectory(prefix="apolaki-tier3-") as td:
        capture_path = Path(td) / "capture.json"
        env = dict(os.environ)
        agent_root = str(Path(__file__).resolve().parents[1])
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONPATH"] = agent_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        cmd = [
            sys.executable, "-m", "pytest", "-p", "no:cacheprovider",
            "-p", "tier3.pytest_capture", "--tier3-capture=%s" % capture_path,
            spec.node_id,
        ]
        try:
            proc = subprocess.run(cmd, cwd=str(repo_root), env=env, capture_output=True,
                                  text=True, timeout=timeout_s)
        except subprocess.TimeoutExpired as exc:
            row = spec.to_dict()
            row.update({"status": ERROR, "detail": "control timed out after %ds" % timeout_s,
                        "pytest_nodes": [], "pytest_returncode": None})
            return row, [{"control_id": spec.control_id, "kind": "timeout",
                          "detail": str(exc)[:500]}]

        if capture_path.exists():
            try:
                capture = json.loads(capture_path.read_text(encoding="utf8"))
            except Exception as exc:
                capture = {}
                capture_error = "invalid pytest capture: %s" % exc
            else:
                capture_error = ""
        else:
            capture, capture_error = {}, "pytest capture artifact was not written"

        status, detail, matched = _node_status(spec.node_id, capture)
        environment = []
        if capture_error:
            status, detail = ERROR, capture_error
            environment.append({"control_id": spec.control_id, "kind": "capture",
                                "detail": capture_error})
        for err in capture.get("collection_errors") or []:
            environment.append({"control_id": spec.control_id, "kind": "collection",
                                "detail": str(err.get("detail") or "")[:500]})
        row = spec.to_dict()
        row.update({
            "status": status,
            "detail": detail,
            "pytest_nodes": matched,
            "pytest_returncode": proc.returncode,
            "stdout_tail": proc.stdout[-500:],
            "stderr_tail": proc.stderr[-500:],
        })
        return row, environment


def _rollup(entries: list[dict]) -> tuple[dict, dict]:
    per_class = {}
    status_counts = {s: 0 for s in STATUSES}
    for row in entries:
        status_counts[row["status"]] += 1
        name = row["vulnerability_class"]
        bucket = per_class.setdefault(name, {
            "registered": 0,
            "passed": 0,
            "status_counts": {s: 0 for s in STATUSES},
            "control_kinds": {},
            "passing_control_kinds": {},
            "has_passing_safe_control": False,
        })
        bucket["registered"] += 1
        bucket["status_counts"][row["status"]] += 1
        kind = row["control_kind"]
        bucket["control_kinds"][kind] = bucket["control_kinds"].get(kind, 0) + 1
        if row["status"] == PASS:
            bucket["passed"] += 1
            bucket["passing_control_kinds"][kind] = bucket["passing_control_kinds"].get(kind, 0) + 1
            if kind == SAFE:
                bucket["has_passing_safe_control"] = True
    for bucket in per_class.values():
        bucket["safe_control_gap"] = not bucket["has_passing_safe_control"]
    coverage = {
        "registered": len(entries),
        "passed": status_counts[PASS],
        "status_counts": status_counts,
        "classes": len(per_class),
        "classes_with_passing_safe_control": sum(
            1 for b in per_class.values() if b["has_passing_safe_control"]),
        "classes_without_passing_safe_control": sorted(
            name for name, b in per_class.items() if not b["has_passing_safe_control"]),
    }
    return dict(sorted(per_class.items())), coverage


def build_artifact(entries: list[dict], environment_failures: list[dict],
                   git_sha: str = "") -> dict:
    per_class, coverage = _rollup(entries)
    semantic_entries = [{
        key: row.get(key) for key in (
            "control_id", "vulnerability_class", "cwe", "control_kind", "node_id",
            "proof_kind", "naive_failure", "source_file", "status", "pytest_nodes",
            "pytest_returncode",
        )
    } for row in entries]
    semantic_failures = [{"control_id": row.get("control_id"), "kind": row.get("kind")}
                         for row in environment_failures]
    semantic = {
        # Keep diagnostic tails and volatile durations in the artifact, but outside the semantic
        # identity. Two runs with the same control outcomes must have the same digest.
        "per_entry": semantic_entries,
        "per_class": per_class,
        "coverage": coverage,
        "environment_failures": semantic_failures,
    }
    artifact = {
        "tool_version": TOOL_VERSION,
        "git_sha": git_sha or os.environ.get("APOLAKI_GIT_SHA") or "unknown",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "per_entry": entries,
        "per_class": per_class,
        "coverage": coverage,
        "environment_failures": environment_failures,
    }
    artifact["semantic_sha256"] = hashlib.sha256(_canonical(semantic)).hexdigest()
    return artifact


def run_controls(controls=CONTROLS, repo_root: str | Path = ".", timeout_s: int = 120,
                 git_sha: str = "") -> dict:
    errors = validate_registry(controls, require_all_sources=(controls is CONTROLS))
    if errors:
        raise ValueError("invalid Tier-3 registry: %s" % "; ".join(errors))
    entries, environment = [], []
    root = Path(repo_root).resolve()
    for spec in controls:
        row, failures = _execute_one(spec, root, timeout_s)
        entries.append(row)
        environment.extend(failures)
    return build_artifact(entries, environment, git_sha)


def write_artifact(path: str | Path, artifact: dict) -> str:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    tmp = dest.with_name(dest.name + ".tmp")
    with open(tmp, "w", encoding="utf8", newline="\n") as fh:
        fh.write(body)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, dest)
    return hashlib.sha256(body.encode("utf8")).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--git-sha", default="")
    args = parser.parse_args(argv)
    artifact = run_controls(repo_root=args.repo_root, timeout_s=args.timeout, git_sha=args.git_sha)
    digest = write_artifact(args.output, artifact)
    c = artifact["coverage"]
    print("Tier-3: %d/%d controls passed across %d classes; semantic_sha256=%s; artifact_sha256=%s"
          % (c["passed"], c["registered"], c["classes"], artifact["semantic_sha256"], digest))
    return 0 if c["passed"] == c["registered"] and not artifact["environment_failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
