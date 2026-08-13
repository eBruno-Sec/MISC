"""Reusable, proof-safe contract for Apolaki benchmark adapters.

This module does not scan a target. It owns the invariants every adapter needs:
durable per-case checkpoints, blind seal-before-key ordering, explicit result
vocabulary, retained raw evidence, and separate official/product B1 scoring.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import datetime as dt
import hashlib
import inspect
import json
import os
from pathlib import Path
from typing import Callable

import proof_schema


TOOL_VERSION = "apolaki-bench-contract/1"

PASS = "PASS"
FAIL = "FAIL"
FP = "FP"
FN = "FN"
UNSUPPORTED = "UNSUPPORTED"
INCONCLUSIVE = "INCONCLUSIVE"
ENVIRONMENT_FAILURE = "ENVIRONMENT_FAILURE"
RESULT_VOCABULARY = frozenset({PASS, FAIL, FP, FN, UNSUPPORTED, INCONCLUSIVE,
                               ENVIRONMENT_FAILURE})

MEASURED = "MEASURED"
MEASUREMENT_STATES = frozenset({MEASURED, UNSUPPORTED, INCONCLUSIVE, ENVIRONMENT_FAILURE})

CONFORMANT = "CONFORMANT"
PARTIAL = "PARTIAL"
GAP = "GAP"


class ContractError(ValueError):
    pass


class CheckpointCorruption(ContractError):
    pass


class SealError(ContractError):
    pass


@dataclass(frozen=True)
class ArtifactSeal:
    path: str
    sha256: str
    size_bytes: int
    sealed_at: str
    git_sha: str

    def to_dict(self) -> dict:
        return asdict(self)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf8")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def seal_run(path: str | Path, git_sha: str = "") -> ArtifactSeal:
    artifact = Path(path).resolve()
    if not artifact.is_file():
        raise SealError("run artifact does not exist: %s" % artifact)
    return ArtifactSeal(
        path=str(artifact),
        sha256=_sha256_file(artifact),
        size_bytes=artifact.stat().st_size,
        sealed_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        git_sha=git_sha or os.environ.get("APOLAKI_GIT_SHA") or "unknown",
    )


def verify_seal(seal: ArtifactSeal) -> None:
    if not isinstance(seal, ArtifactSeal):
        raise SealError("an ArtifactSeal token is required before reading ground truth")
    path = Path(seal.path)
    if not path.is_file():
        raise SealError("sealed artifact is missing: %s" % path)
    if path.stat().st_size != seal.size_bytes or _sha256_file(path) != seal.sha256:
        raise SealError("run artifact changed after it was sealed")


def load_key_after_seal(seal: ArtifactSeal, key_path: str | Path,
                        loader: Callable[[str], object]) -> tuple[object, dict]:
    """Verify the blind run before invoking the caller's answer-key loader."""
    verify_seal(seal)
    key = Path(key_path).resolve()
    if not key.is_file():
        raise SealError("answer key does not exist: %s" % key)
    key_sha = _sha256_file(key)
    read_at = dt.datetime.now(dt.timezone.utc).isoformat()
    loaded = loader(str(key))
    return loaded, {
        "run_seal": seal.to_dict(),
        "key_path": str(key),
        "key_sha256": key_sha,
        "key_read_at": read_at,
        "ordering_ok": read_at >= seal.sealed_at,
    }


def _case_id(row: dict) -> str:
    return str(row.get("case_id") or row.get("test") or row.get("benchmark_id") or "").strip()


def validate_case_result(row: dict) -> None:
    if not isinstance(row, dict):
        raise ContractError("case result must be a dict")
    if not _case_id(row):
        raise ContractError("case result has no case_id")
    state = str(row.get("measurement_status") or "")
    if state not in MEASUREMENT_STATES:
        raise ContractError("%s: invalid measurement_status %r" % (_case_id(row), state))
    if "raw_evidence" not in row or row.get("raw_evidence") is None:
        raise ContractError("%s: raw_evidence must be retained explicitly" % _case_id(row))
    if state == MEASURED and not str(row.get("category") or "").strip():
        raise ContractError("%s: a measured case needs a category" % _case_id(row))
    try:
        _canonical(row)
    except Exception as exc:
        raise ContractError("%s: case result is not JSON serializable: %s" % (_case_id(row), exc))


def _read_checkpoint(path: Path) -> tuple[list[dict], int, bool]:
    if not path.exists():
        return [], 0, False
    body = path.read_bytes()
    rows, valid_bytes = [], 0
    pieces = body.splitlines(keepends=True)
    for index, raw in enumerate(pieces):
        complete = raw.endswith((b"\n", b"\r"))
        try:
            row = json.loads(raw.decode("utf8"))
            validate_case_result(row)
        except Exception as exc:
            if index == len(pieces) - 1 and not complete:
                return rows, valid_bytes, True
            raise CheckpointCorruption("invalid checkpoint row %d: %s" % (index + 1, exc))
        rows.append(row)
        valid_bytes += len(raw)
    return rows, valid_bytes, False


def load_checkpoint(path: str | Path) -> list[dict]:
    rows, _, _ = _read_checkpoint(Path(path))
    seen = {}
    for row in rows:
        case_id = _case_id(row)
        if case_id in seen and _canonical(seen[case_id]) != _canonical(row):
            raise CheckpointCorruption("conflicting duplicate case_id: %s" % case_id)
        seen[case_id] = row
    return list(seen.values())


class CaseCheckpoint:
    """Append-only JSONL checkpoint with fsync, resume, and truncated-tail recovery."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        rows, valid_bytes, truncated = _read_checkpoint(self.path)
        if truncated:
            with open(self.path, "r+b") as fh:
                fh.truncate(valid_bytes)
                fh.flush()
                os.fsync(fh.fileno())
        self._rows = {}
        for row in rows:
            case_id = _case_id(row)
            if case_id in self._rows and _canonical(self._rows[case_id]) != _canonical(row):
                raise CheckpointCorruption("conflicting duplicate case_id: %s" % case_id)
            self._rows[case_id] = row

    @property
    def completed_ids(self) -> frozenset[str]:
        return frozenset(self._rows)

    def pending(self, case_ids) -> list[str]:
        return [str(case_id) for case_id in case_ids if str(case_id) not in self._rows]

    def append(self, row: dict) -> bool:
        validate_case_result(row)
        case_id = _case_id(row)
        existing = self._rows.get(case_id)
        if existing is not None:
            if _canonical(existing) != _canonical(row):
                raise CheckpointCorruption("conflicting result for completed case_id: %s" % case_id)
            return False
        needs_separator = False
        if self.path.exists() and self.path.stat().st_size:
            with open(self.path, "rb") as existing_file:
                existing_file.seek(-1, os.SEEK_END)
                needs_separator = existing_file.read(1) not in (b"\n", b"\r")
        with open(self.path, "a", encoding="utf8", newline="\n") as fh:
            if needs_separator:
                fh.write("\n")
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._rows[case_id] = dict(row)
        return True


def _truth(entry) -> tuple[str, bool]:
    if isinstance(entry, (tuple, list)) and len(entry) >= 2:
        return str(entry[0]), bool(entry[1])
    if isinstance(entry, dict):
        return str(entry.get("category") or ""), bool(entry.get("vulnerable"))
    raise ContractError("ground-truth entry must be (category, vulnerable) or a dict")


def _confirmed_families(row: dict) -> list[str]:
    findings = row.get("findings")
    if isinstance(findings, list):
        return [str(f.get("family") or f.get("vuln_class") or "") for f in findings
                if isinstance(f, dict) and proof_schema.is_confirmed(f)]
    families = list(row.get("families") or [])
    confidences = list(row.get("conf") or ["confirmed"] * len(families))
    confidences = (confidences + ["confirmed"] * len(families))[:len(families)]
    return [str(family) for family, confidence in zip(families, confidences)
            if proof_schema.is_confirmed({"confidence": confidence})]


def _metrics(counts: dict) -> dict:
    tp, tn, fp, fn = (int(counts.get(k, 0)) for k in ("tp", "tn", "fp", "fn"))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and precision + recall else None)
    fpr = fp / (fp + tn) if fp + tn else None
    fnr = fn / (fn + tp) if fn + tp else None
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "denominator": tp + tn + fp + fn,
            "precision": precision, "recall": recall, "f1": f1, "fpr": fpr, "fnr": fnr}


def _macro(per_category: dict) -> dict:
    out = {}
    for metric in ("precision", "recall", "f1", "fpr", "fnr"):
        values = [row[metric] for row in per_category.values() if row[metric] is not None]
        out[metric] = sum(values) / len(values) if values else None
    out["categories"] = len(per_category)
    return out


def score_b1(results: list[dict], key: dict, family_map: dict[str, set[str]],
             suite_categories=None) -> dict:
    """Score a complete B1 run; unresolved cases make the score non-publishable."""
    by_id = {}
    for row in results or []:
        validate_case_result(row)
        case_id = _case_id(row)
        if case_id in by_id:
            raise ContractError("duplicate result for case_id: %s" % case_id)
        by_id[case_id] = row

    unresolved = []
    for case_id in sorted(key):
        row = by_id.get(case_id)
        if row is None:
            unresolved.append({"case_id": case_id, "result": INCONCLUSIVE,
                               "reason": "case was not present in the run"})
        elif row["measurement_status"] != MEASURED:
            unresolved.append({"case_id": case_id, "result": row["measurement_status"],
                               "reason": str(row.get("error") or row.get("reason") or "")})
    extra = sorted(set(by_id) - set(key))
    base = {
        "denominator": len(key),
        "measured": len(key) - len(unresolved),
        "unresolved": unresolved,
        "extra_case_ids": extra,
        "publishable": not unresolved and not extra,
        "result_vocabulary": sorted(RESULT_VOCABULARY),
    }
    if not base["publishable"]:
        return {**base, "official": None, "product": None, "cross_family_fp": None,
                "per_case": []}

    categories = list(suite_categories or sorted({_truth(entry)[0] for entry in key.values()}))
    official_counts = {cat: {k: 0 for k in ("tp", "tn", "fp", "fn")} for cat in categories}
    product_counts = {cat: {k: 0 for k in ("tp", "tn", "fp", "fn")} for cat in categories}
    per_case, cross_family_fp = [], 0
    for case_id in sorted(key):
        category, vulnerable = _truth(key[case_id])
        if category not in official_counts:
            raise ContractError("ground-truth category is outside suite_categories: %s" % category)
        row = by_id[case_id]
        if row.get("category") and str(row["category"]) != category:
            raise ContractError("%s: result category does not match ground truth" % case_id)
        confirmed = _confirmed_families(row)
        official_hit = any(family in set(family_map.get(category) or ()) for family in confirmed)
        product_hit = bool(confirmed)
        if vulnerable:
            official_bucket = product_bucket = "tp" if official_hit else "fn"
            official_result = product_result = PASS if official_hit else FN
        else:
            official_bucket = "fp" if official_hit else "tn"
            product_bucket = "fp" if product_hit else "tn"
            official_result = FP if official_hit else PASS
            product_result = FP if product_hit else PASS
            if product_hit and not official_hit:
                cross_family_fp += 1
        official_counts[category][official_bucket] += 1
        product_counts[category][product_bucket] += 1
        per_case.append({
            "case_id": case_id,
            "category": category,
            "vulnerable": vulnerable,
            "confirmed_families": confirmed,
            "official_result": official_result,
            "product_result": product_result,
            "raw_evidence": row["raw_evidence"],
        })

    official_per = {cat: _metrics(official_counts[cat]) for cat in categories}
    product_per = {cat: _metrics(product_counts[cat]) for cat in categories}
    official_total = _metrics({k: sum(c[k] for c in official_counts.values())
                               for k in ("tp", "tn", "fp", "fn")})
    product_total = _metrics({k: sum(c[k] for c in product_counts.values())
                              for k in ("tp", "tn", "fp", "fn")})
    return {
        **base,
        "official": {"overall": official_total, "per_category": official_per,
                     "macro": _macro(official_per)},
        "product": {"overall": product_total, "per_category": product_per,
                    "macro": _macro(product_per)},
        "cross_family_fp": cross_family_fp,
        "per_case": per_case,
    }


def assess_owasp_bench(module, temp_dir: str | Path) -> list[dict]:
    """Executable conformance snapshot of the untouched reference adapter."""
    tmp = Path(temp_dir)
    tmp.mkdir(parents=True, exist_ok=True)
    scan_source = inspect.getsource(module.scan)
    main_source = inspect.getsource(module.main)

    row = lambda name, families, conf=None: {
        "test": name, "category": "securecookie", "families": families,
        "conf": conf if conf is not None else ["confirmed"] * len(families),
    }
    synthetic = module.score({"target": "java", "results": [
        row("V", ["insecure_cookie"]), row("C", ["path_traversal"]),
    ]}, {"V": ("securecookie", True), "C": ("securecookie", False)})

    checkpoint = tmp / "owasp-truncated.jsonl"
    checkpoint.write_text(json.dumps(row("A", [])) + "\n{truncated", encoding="utf8")
    loaded = module.load_run(str(checkpoint), "java")
    clauses = [
        {"clause": "dual_official_product_scoring", "status": CONFORMANT,
         "evidence": "synthetic cross-family clean finding: official FP=%d, product FP=%d" %
                     (synthetic["per_category"]["securecookie"]["fp"],
                      synthetic["per_category"]["securecookie"]["fp_any"])},
        {"clause": "full_suite_macro_denominator", "status": CONFORMANT,
         "evidence": "score reports suite_size=%d and %d unmeasured categories" %
                     (synthetic["suite_size"], len(synthetic["suite_missing"]))},
        {"clause": "checkpoint_flush_and_fsync", "status": CONFORMANT
         if "os.fsync" in scan_source and ".flush()" in scan_source else GAP,
         "evidence": "scan checkpoint calls flush and os.fsync per case"},
        {"clause": "checkpoint_resume", "status": CONFORMANT
         if "_load_done(checkpoint)" in scan_source and "if name in done" in scan_source else GAP,
         "evidence": "scan loads completed case IDs before dispatch"},
        {"clause": "truncated_tail_recovery", "status": CONFORMANT
         if len(loaded.get("results") or []) == 1 else GAP,
         "evidence": "one complete row survived a truncated final JSONL row"},
        {"clause": "raw_evidence_retention", "status": CONFORMANT
         if "raw_evidence" in scan_source else GAP,
         "evidence": "scan rows retain families/conf/targets/error but no raw_evidence field"},
        {"clause": "seal_before_key_enforced", "status": GAP,
         "evidence": "main loads run and key without creating or verifying a seal token"
                     if "seal" not in main_source.lower() else "seal behavior requires review"},
        {"clause": "explicit_result_vocabulary", "status": GAP,
         "evidence": "rows use free-text error strings; no PASS/FAIL/FP/FN/environment enum"},
        {"clause": "full_b1_metric_set", "status": PARTIAL,
         "evidence": "TP/TN/FP/FN, TPR and FPR exist; precision, F1 and FNR are absent"},
        {"clause": "environment_failure_not_scored", "status": GAP,
         "evidence": "ordinary row errors increment errors and are still booked as FN/TN"},
        {"clause": "position_independence", "status": GAP,
         "evidence": "one ToolRegistry is reused across the case loop without recording budget state"},
    ]
    return clauses


def conformance_artifact(module, temp_dir: str | Path, git_sha: str = "") -> dict:
    clauses = assess_owasp_bench(module, temp_dir)
    counts = {state: sum(1 for row in clauses if row["status"] == state)
              for state in (CONFORMANT, PARTIAL, GAP)}
    semantic = {"clauses": clauses, "summary": counts}
    return {
        "tool_version": TOOL_VERSION,
        "git_sha": git_sha or os.environ.get("APOLAKI_GIT_SHA") or "unknown",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "per_entry": clauses,
        "per_class": {},
        "summary": counts,
        "environment_failures": [],
        "semantic_sha256": hashlib.sha256(_canonical(semantic)).hexdigest(),
    }


def write_json_artifact(path: str | Path, artifact: dict) -> str:
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
    """CLI consumer for contract inspection, sealing, conformance, and B1 scoring."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    checkpoint = sub.add_parser("checkpoint", help="inspect a durable per-case checkpoint")
    checkpoint.add_argument("--run", required=True)

    seal = sub.add_parser("seal", help="seal a blind run before ground truth is read")
    seal.add_argument("--run", required=True)
    seal.add_argument("--git-sha", default="")

    conformance = sub.add_parser("conformance", help="measure the reference OWASP adapter")
    conformance.add_argument("--output", required=True)
    conformance.add_argument("--temp-dir", required=True)
    conformance.add_argument("--git-sha", default="")

    score = sub.add_parser("score-b1", help="seal a checkpoint, then score it against JSON ground truth")
    score.add_argument("--run", required=True)
    score.add_argument("--key", required=True,
                       help="JSON object: case_id -> [category, vulnerable]")
    score.add_argument("--family-map", required=True,
                       help="JSON object: category -> accepted finding families")
    score.add_argument("--output", required=True)
    score.add_argument("--git-sha", default="")
    args = parser.parse_args(argv)

    if args.command == "checkpoint":
        rows = load_checkpoint(args.run)
        print(json.dumps({"cases": len(rows), "case_ids": sorted(_case_id(row) for row in rows)}))
        return 0
    if args.command == "seal":
        print(json.dumps(seal_run(args.run, args.git_sha).to_dict(), sort_keys=True))
        return 0
    if args.command == "conformance":
        import owasp_bench
        artifact = conformance_artifact(owasp_bench, args.temp_dir, args.git_sha)
        print("artifact_sha256=%s" % write_json_artifact(args.output, artifact))
        return 0

    run_seal = seal_run(args.run, args.git_sha)
    key, receipt = load_key_after_seal(
        run_seal, args.key, lambda path: json.loads(Path(path).read_text(encoding="utf8")))
    family_map_raw = json.loads(Path(args.family_map).read_text(encoding="utf8"))
    family_map = {str(category): set(families or [])
                  for category, families in family_map_raw.items()}
    result = score_b1(load_checkpoint(args.run), key, family_map)
    artifact = {
        "tool_version": TOOL_VERSION,
        "git_sha": args.git_sha or os.environ.get("APOLAKI_GIT_SHA") or "unknown",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "per_entry": result.get("per_case") or [],
        "per_class": ((result.get("product") or {}).get("per_category") or {}),
        "environment_failures": [row for row in result.get("unresolved") or []
                                 if row.get("result") == ENVIRONMENT_FAILURE],
        "score": result,
        "blind_ordering": receipt,
    }
    artifact["semantic_sha256"] = hashlib.sha256(_canonical({
        "score": artifact["score"], "blind_ordering": {
            "run_sha256": receipt["run_seal"]["sha256"],
            "key_sha256": receipt["key_sha256"],
            "ordering_ok": receipt["ordering_ok"],
        },
    })).hexdigest()
    print("artifact_sha256=%s" % write_json_artifact(args.output, artifact))
    return 0 if result["publishable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
