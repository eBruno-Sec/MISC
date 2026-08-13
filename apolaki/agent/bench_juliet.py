"""Blind NIST Juliet Java adapter for Apolaki's code-assisted (SAST) lane.

The production scanner sees source text and an opaque Java filename. It never sees
Juliet's manifest, expected result, or a benchmark case label. Ground truth is read
only by the scoring phase after ``bench_contract.seal_run`` has sealed this scan.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import datetime as dt
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import zipfile

import bench_contract as contract
import codereview


TOOL_VERSION = "apolaki-bench-juliet/1"


class JulietEnvironmentFailure(RuntimeError):
    """The pinned corpus is absent, corrupt, or structurally unusable."""


@dataclass(frozen=True)
class SuiteSpec:
    name: str
    version: str
    upstream: str
    author: str
    language: str
    license: str
    archive_name: str
    archive_bytes: int
    archive_sha256: str
    manifest_entry: str
    cwe_prefixes: tuple[tuple[str, str], ...]
    expected_files: tuple[tuple[str, int], ...]
    expected_case_files: tuple[tuple[str, int], ...] = ()
    manifest_recovery_lines: tuple[int, ...] = ()

    def metadata(self) -> dict:
        row = asdict(self)
        row["cwe_prefixes"] = dict(self.cwe_prefixes)
        row["expected_files"] = dict(self.expected_files)
        return row


# Counts were measured from the digest-pinned archive on 2026-08-12. They are a
# corpus-integrity guard, not an estimate or a desired benchmark score.
JULIET_JAVA_13 = SuiteSpec(
    name="NIST SARD Juliet Java",
    version="1.3 (2017-10-01)",
    upstream="https://samate.nist.gov/SARD/test-suites/111",
    author="NSA Center for Assured Software; distributed by NIST SARD",
    language="Java",
    license="US public domain; CC0-1.0 for any NIST foreign rights",
    archive_name="2017-10-01-juliet-test-suite-for-java-v1-3.zip",
    archive_bytes=76_798_417,
    archive_sha256="d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60",
    manifest_entry="Java/manifest.xml",
    cwe_prefixes=(
        ("CWE-327", "Java/src/testcases/CWE327_Use_Broken_Crypto/"),
        ("CWE-328", "Java/src/testcases/CWE328_Reversible_One_Way_Hash/"),
        ("CWE-338", "Java/src/testcases/CWE338_Weak_PRNG/"),
    ),
    expected_files=(("CWE-327", 38), ("CWE-328", 55), ("CWE-338", 38)),
    expected_case_files=(("CWE-327", 34), ("CWE-328", 51), ("CWE-338", 34)),
    manifest_recovery_lines=(50084, 66737),
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_archive(path: str | Path, suite: SuiteSpec = JULIET_JAVA_13) -> Path:
    archive = Path(path).resolve()
    if not archive.is_file():
        raise JulietEnvironmentFailure("pinned Juliet archive is missing: %s" % archive)
    size = archive.stat().st_size
    if size != suite.archive_bytes:
        raise JulietEnvironmentFailure(
            "Juliet archive size mismatch: expected %d, measured %d" % (suite.archive_bytes, size))
    measured = _sha256_file(archive)
    if measured != suite.archive_sha256:
        raise JulietEnvironmentFailure(
            "Juliet archive SHA-256 mismatch: expected %s, measured %s"
            % (suite.archive_sha256, measured))
    if not zipfile.is_zipfile(archive):
        raise JulietEnvironmentFailure("digest-matched Juliet input is not a ZIP archive")
    return archive


def _selected_entries(zipped: zipfile.ZipFile, suite: SuiteSpec) -> list[tuple[str, str]]:
    prefixes = dict(suite.cwe_prefixes)
    selected = []
    for info in zipped.infolist():
        if info.is_dir() or not info.filename.endswith(".java"):
            continue
        for cwe, prefix in prefixes.items():
            if info.filename.startswith(prefix):
                selected.append((cwe, info.filename))
                break
    selected.sort(key=lambda row: row[1])
    measured = {cwe: 0 for cwe in prefixes}
    for cwe, _ in selected:
        measured[cwe] += 1
    expected = dict(suite.expected_files)
    if measured != expected:
        raise JulietEnvironmentFailure(
            "Juliet corpus shape mismatch: expected %s, measured %s" % (expected, measured))
    return selected


def _case_id(entry: str) -> str:
    return "source-" + hashlib.sha256(entry.encode("utf8")).hexdigest()[:24]


def _semantic_sha256(value) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode("utf8")).hexdigest()


def scan_archive(archive_path: str | Path, checkpoint_path: str | Path,
                 suite: SuiteSpec = JULIET_JAVA_13) -> list[dict]:
    """Scan the selected source files without opening Juliet's answer manifest."""
    archive = verify_archive(archive_path, suite)
    checkpoint = contract.CaseCheckpoint(checkpoint_path)
    with zipfile.ZipFile(archive) as zipped:
        selected = _selected_entries(zipped, suite)
        for cwe, entry in selected:
            case_id = _case_id(entry)
            if case_id in checkpoint.completed_ids:
                continue
            raw = zipped.read(entry)
            source_hash = hashlib.sha256(raw).hexdigest()
            source = raw.decode("utf8", errors="replace")
            opaque_name = case_id + ".java"
            try:
                findings = codereview.review_source(source, opaque_name)
                status, error = contract.MEASURED, ""
            except Exception as exc:
                findings = []
                status = contract.ENVIRONMENT_FAILURE
                error = "%s: %s" % (type(exc).__name__, exc)
            row = {
                "case_id": case_id,
                "measurement_status": status,
                "category": cwe,
                "findings": findings,
                "error": error,
                "raw_evidence": {
                    "archive_sha256": suite.archive_sha256,
                    "source_entry": entry,
                    "source_sha256": source_hash,
                    "source_bytes": len(raw),
                    "scanner": "codereview.review_source",
                    "scanner_input_name": opaque_name,
                    "findings": findings,
                },
            }
            checkpoint.append(row)
    return contract.load_checkpoint(checkpoint_path)


def build_scan_artifact(rows: list[dict], seal: contract.ArtifactSeal,
                        suite: SuiteSpec = JULIET_JAVA_13, git_sha: str = "") -> dict:
    per_entry = []
    per_class = {}
    environment_failures = []
    for row in sorted(rows, key=lambda item: item["case_id"]):
        summary = {
            "case_id": row["case_id"],
            "category": row.get("category"),
            "measurement_status": row.get("measurement_status"),
            "finding_count": len(row.get("findings") or []),
            "source_sha256": (row.get("raw_evidence") or {}).get("source_sha256"),
        }
        per_entry.append(summary)
        bucket = per_class.setdefault(row.get("category"), {
            "files": 0, "measured": 0, "environment_failures": 0, "findings": 0})
        bucket["files"] += 1
        bucket["findings"] += summary["finding_count"]
        if row.get("measurement_status") == contract.MEASURED:
            bucket["measured"] += 1
        else:
            bucket["environment_failures"] += 1
            environment_failures.append(summary)
    semantic = {
        "suite": suite.metadata(),
        "per_entry": per_entry,
        "per_class": per_class,
        "environment_failures": environment_failures,
        "run_sha256": seal.sha256,
    }
    return {
        "tool_version": TOOL_VERSION,
        "git_sha": git_sha or os.environ.get("APOLAKI_GIT_SHA") or "unknown",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "suite": suite.metadata(),
        "lane": "code-assisted (SAST)",
        "scope": sorted(dict(suite.cwe_prefixes)),
        "per_entry": per_entry,
        "per_class": per_class,
        "environment_failures": environment_failures,
        "run_seal": seal.to_dict(),
        "semantic_sha256": _semantic_sha256(semantic),
    }


def run_blind(archive_path: str | Path, checkpoint_path: str | Path,
              artifact_path: str | Path, suite: SuiteSpec = JULIET_JAVA_13,
              git_sha: str = "") -> dict:
    rows = scan_archive(archive_path, checkpoint_path, suite)
    seal = contract.seal_run(checkpoint_path, git_sha)
    artifact = build_scan_artifact(rows, seal, suite, git_sha)
    artifact["artifact_sha256"] = contract.write_json_artifact(artifact_path, artifact)
    return artifact


class _ManifestParser(HTMLParser):
    """Structured, bounded recovery for NIST's malformed XML manifest.

    The pinned archive has one duplicated ``</testcase>`` at line 50084. HTMLParser
    gives us proper tag/attribute tokenisation while tolerating that close tag; the
    caller rejects any recovery that is not explicitly pinned by SuiteSpec.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.files = {}
        self.current_file = None
        self.testcase_depth = 0
        self.unexpected_testcase_ends = []

    @staticmethod
    def _attrs(attrs) -> dict:
        return {str(key): str(value or "") for key, value in attrs}

    def handle_starttag(self, tag, attrs):
        values = self._attrs(attrs)
        if tag == "testcase":
            self.testcase_depth += 1
        elif tag == "file":
            self.current_file = values.get("path") or ""
            self.files.setdefault(self.current_file, [])
        elif tag == "flaw" and self.current_file:
            try:
                line = int(values.get("line") or 0)
            except ValueError:
                line = 0
            self.files[self.current_file].append({
                "line": line,
                "name": values.get("name") or "",
            })

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag == "file":
            self.current_file = None

    def handle_endtag(self, tag):
        if tag == "file":
            self.current_file = None
        elif tag == "testcase":
            if self.testcase_depth:
                self.testcase_depth -= 1
            else:
                self.unexpected_testcase_ends.append(self.getpos()[0])


def _load_manifest(archive_path: str | Path,
                   suite: SuiteSpec = JULIET_JAVA_13) -> dict:
    with zipfile.ZipFile(archive_path) as zipped:
        try:
            body = zipped.read(suite.manifest_entry).decode("utf8")
        except (KeyError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
            raise JulietEnvironmentFailure("Juliet manifest is unavailable: %s" % exc) from exc
    parser = _ManifestParser()
    parser.feed(body)
    parser.close()
    recoveries = tuple(parser.unexpected_testcase_ends)
    if recoveries != tuple(suite.manifest_recovery_lines):
        raise JulietEnvironmentFailure(
            "Juliet manifest recovery mismatch: expected %s, measured %s"
            % (tuple(suite.manifest_recovery_lines), recoveries))
    if parser.testcase_depth or parser.current_file is not None:
        raise JulietEnvironmentFailure("Juliet manifest ended with unclosed structural tags")
    return {
        "files": parser.files,
        "unexpected_testcase_end_lines": list(recoveries),
    }


_METHOD_DECL = re.compile(
    r"(?m)^[ \t]*(?:(?:public|protected|private|static|final|synchronized|native|abstract|strictfp)\s+)*"
    r"(?:<[^>\n]+>\s*)?(?:[A-Za-z_$][\w$.[\]<>?,]*\s+)+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^;{]+)?\{")


def _method_spans(source: str) -> list[dict]:
    skeleton, _ = codereview.mask_source(source)
    methods = []
    for match in _METHOD_DECL.finditer(skeleton):
        open_brace = skeleton.find("{", match.start(), match.end())
        if open_brace < 0:
            continue
        depth, close_brace = 0, None
        for index in range(open_brace, len(skeleton)):
            if skeleton[index] == "{":
                depth += 1
            elif skeleton[index] == "}":
                depth -= 1
                if depth == 0:
                    close_brace = index
                    break
        if close_brace is None:
            raise JulietEnvironmentFailure("unbalanced Java method body at offset %d" % match.start())
        methods.append({
            "name": match.group("name"),
            "start_line": source.count("\n", 0, match.start()) + 1,
            "end_line": source.count("\n", 0, close_brace) + 1,
        })
    return methods


def _method_case_id(entry: str, method: dict) -> str:
    identity = "%s:%d:%d" % (entry, method["start_line"], method["end_line"])
    return "method-" + hashlib.sha256(identity.encode("utf8")).hexdigest()[:24]


def _build_method_cases(archive_path: str | Path, rows: list[dict], manifest: dict,
                        suite: SuiteSpec = JULIET_JAVA_13) -> tuple[list[dict], dict, dict]:
    """Build direct-method B1 cases from an already sealed whole-source run."""
    by_entry = {(row.get("raw_evidence") or {}).get("source_entry"): row for row in rows}
    cases = []
    case_files = {cwe: 0 for cwe in dict(suite.cwe_prefixes)}
    with zipfile.ZipFile(archive_path) as zipped:
        for cwe, entry in _selected_entries(zipped, suite):
            row = by_entry.get(entry)
            if row is None:
                raise JulietEnvironmentFailure("sealed run is missing baseline source: %s" % entry)
            raw = zipped.read(entry)
            if hashlib.sha256(raw).hexdigest() != (row.get("raw_evidence") or {}).get("source_sha256"):
                raise JulietEnvironmentFailure("source changed after the blind run: %s" % entry)
            source = raw.decode("utf8", errors="replace")
            methods = [method for method in _method_spans(source)
                       if method["name"] == "bad" or re.fullmatch(r"good[0-9]+", method["name"])]
            if not methods:
                continue  # generated Main/ServletMain harness, not a testcase
            names = [method["name"] for method in methods]
            if names.count("bad") != 1 or "good1" not in names:
                raise JulietEnvironmentFailure(
                    "%s does not contain one bad() and at least one direct safe helper" % entry)
            case_files[cwe] += 1
            basename = Path(entry).name
            flaws = list((manifest.get("files") or {}).get(basename) or [])
            if not flaws:
                raise JulietEnvironmentFailure("manifest has no flaw annotation for %s" % basename)
            for method in methods:
                method_name = method["name"]
                vulnerable = method_name == "bad"
                expected_lines = sorted({int(flaw["line"]) for flaw in flaws
                                         if method["start_line"] <= int(flaw["line"]) <= method["end_line"]})
                if vulnerable and not expected_lines:
                    raise JulietEnvironmentFailure(
                        "manifest flaw does not fall inside bad() for %s" % basename)
                if not vulnerable and expected_lines:
                    raise JulietEnvironmentFailure(
                        "manifest marks the good1() control as flawed for %s" % basename)
                findings = [finding for finding in row.get("findings") or []
                            if method["start_line"] <= int(finding.get("line") or 0) <= method["end_line"]]
                case_id = _method_case_id(entry, method)
                cases.append((cwe, entry, method_name, vulnerable, method,
                              expected_lines, findings, row, case_id))

    if case_files != dict(suite.expected_case_files):
        raise JulietEnvironmentFailure(
            "testcase file shape mismatch: expected %s, measured %s"
            % (dict(suite.expected_case_files), case_files))

    results, key = [], {}
    for cwe, entry, method_name, vulnerable, method, expected_lines, findings, row, case_id in cases:
        results.append({
            "case_id": case_id,
            "measurement_status": row["measurement_status"],
            "category": cwe,
            "findings": findings,
            "error": row.get("error") or "",
            "raw_evidence": {
                "parent_case_id": row["case_id"],
                "source_entry": entry,
                "source_sha256": (row.get("raw_evidence") or {}).get("source_sha256"),
                "method": method_name,
                "method_lines": [method["start_line"], method["end_line"]],
                "manifest_flaw_lines_in_method": expected_lines,
                "findings": findings,
            },
        })
        key[case_id] = {"category": cwe, "vulnerable": vulnerable}
    scope = {
        "variant": "01-17 direct bad()/goodN() methods",
        "source_files": sum(dict(suite.expected_case_files).values()),
        "method_cases": len(key),
        "positive_cases": sum(1 for value in key.values() if value["vulnerable"]),
        "negative_cases": sum(1 for value in key.values() if not value["vulnerable"]),
        "skipped_cases": 0,
        "excluded": "generated launchers and non-oracle good()/main() dispatch wrappers",
    }
    return results, key, scope


def score_blind_run(archive_path: str | Path, checkpoint_path: str | Path,
                    scan_artifact_path: str | Path, output_path: str | Path,
                    suite: SuiteSpec = JULIET_JAVA_13, git_sha: str = "") -> dict:
    archive = verify_archive(archive_path, suite)
    scan_artifact = json.loads(Path(scan_artifact_path).read_text(encoding="utf8"))
    recorded = dict(scan_artifact.get("run_seal") or {})
    seal = contract.ArtifactSeal(
        path=str(Path(checkpoint_path).resolve()),
        sha256=str(recorded.get("sha256") or ""),
        size_bytes=int(recorded.get("size_bytes") or 0),
        sealed_at=str(recorded.get("sealed_at") or ""),
        git_sha=str(recorded.get("git_sha") or ""),
    )
    contract.verify_seal(seal)
    manifest, receipt = contract.load_key_after_seal(
        seal, archive, lambda path: _load_manifest(path, suite))
    rows = contract.load_checkpoint(checkpoint_path)
    results, key, scope = _build_method_cases(archive, rows, manifest, suite)
    family_map = {
        "CWE-327": {"weak_crypto"},
        "CWE-328": {"weak_hash"},
        "CWE-338": {"weak_random"},
    }
    categories = sorted(dict(suite.cwe_prefixes))
    score = contract.score_b1(results, key, family_map, suite_categories=categories)
    artifact = {
        "tool_version": TOOL_VERSION,
        "git_sha": git_sha or os.environ.get("APOLAKI_GIT_SHA") or "unknown",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "suite": suite.metadata(),
        "lane": "code-assisted (SAST)",
        "scope": scope,
        "per_entry": score.get("per_case") or [],
        "per_class": ((score.get("product") or {}).get("per_category") or {}),
        "environment_failures": [item for item in score.get("unresolved") or []
                                 if item.get("result") == contract.ENVIRONMENT_FAILURE],
        "score": score,
        "blind_ordering": receipt,
        "ground_truth": {
            "source": suite.manifest_entry,
            "manifest_recovery_lines": manifest["unexpected_testcase_end_lines"],
            "method_labels": "Juliet bad() is vulnerable; direct good1() is its safe twin",
        },
    }
    artifact["semantic_sha256"] = _semantic_sha256({
        "suite": artifact["suite"],
        "scope": scope,
        "score": score,
        "run_sha256": receipt["run_seal"]["sha256"],
        "key_sha256": receipt["key_sha256"],
        "manifest_recovery_lines": manifest["unexpected_testcase_end_lines"],
    })
    artifact["artifact_sha256"] = contract.write_json_artifact(output_path, artifact)
    return artifact


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="blind-scan the digest-pinned archive; never opens ground truth")
    scan.add_argument("--archive", required=True)
    scan.add_argument("--checkpoint", required=True)
    scan.add_argument("--artifact", required=True)
    scan.add_argument("--git-sha", default="")
    score = sub.add_parser("score", help="score the sealed direct-method slice against the manifest")
    score.add_argument("--archive", required=True)
    score.add_argument("--checkpoint", required=True)
    score.add_argument("--scan-artifact", required=True)
    score.add_argument("--artifact", required=True)
    score.add_argument("--git-sha", default="")
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            artifact = run_blind(args.archive, args.checkpoint, args.artifact,
                                 JULIET_JAVA_13, args.git_sha)
        except JulietEnvironmentFailure as exc:
            print("ENVIRONMENT_FAILURE: %s" % exc)
            return 2
        print(json.dumps({
            "artifact": str(Path(args.artifact).resolve()),
            "artifact_sha256": artifact["artifact_sha256"],
            "run_sha256": artifact["run_seal"]["sha256"],
            "files": len(artifact["per_entry"]),
            "environment_failures": len(artifact["environment_failures"]),
        }, sort_keys=True))
        return 0 if not artifact["environment_failures"] else 2
    if args.command == "score":
        try:
            artifact = score_blind_run(
                args.archive, args.checkpoint, args.scan_artifact, args.artifact,
                JULIET_JAVA_13, args.git_sha)
        except (JulietEnvironmentFailure, contract.ContractError) as exc:
            print("ENVIRONMENT_FAILURE: %s" % exc)
            return 2
        overall = ((artifact.get("score") or {}).get("product") or {}).get("overall") or {}
        print(json.dumps({
            "artifact": str(Path(args.artifact).resolve()),
            "artifact_sha256": artifact["artifact_sha256"],
            "semantic_sha256": artifact["semantic_sha256"],
            "publishable": artifact["score"]["publishable"],
            "denominator": artifact["score"]["denominator"],
            "tp": overall.get("tp"), "tn": overall.get("tn"),
            "fp": overall.get("fp"), "fn": overall.get("fn"),
        }, sort_keys=True))
        return 0 if artifact["score"]["publishable"] else 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
