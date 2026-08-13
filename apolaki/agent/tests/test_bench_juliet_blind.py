import hashlib
import json
from pathlib import Path
import zipfile

import pytest

import bench_contract as contract
import bench_juliet as juliet


def _suite(path: Path, entries: dict[str, str]) -> juliet.SuiteSpec:
    size = path.stat().st_size
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    counts = {}
    prefixes = []
    for cwe in sorted(entries):
        prefix = "Java/src/testcases/%s/" % cwe.replace("-", "")
        prefixes.append((cwe, prefix))
        counts[cwe] = sum(1 for name in entries[cwe] if name.endswith(".java"))
    return juliet.SuiteSpec(
        name="synthetic Juliet", version="test", upstream="local", author="test",
        language="Java", license="test", archive_name=path.name,
        archive_bytes=size, archive_sha256=digest, manifest_entry="Java/manifest.xml",
        cwe_prefixes=tuple(prefixes), expected_files=tuple(sorted(counts.items())))


def _archive(tmp_path: Path) -> tuple[Path, juliet.SuiteSpec]:
    archive = tmp_path / "juliet.zip"
    entries = {
        "CWE-327": ["one.java", "two.java"],
        "CWE-338": ["three.java"],
    }
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("Java/manifest.xml", "<manifest>ground truth must stay sealed</manifest>")
        zipped.writestr("Java/src/testcases/CWE327/one.java",
                        'class NamedBad { void bad() { Cipher.getInstance("DES"); } }')
        zipped.writestr("Java/src/testcases/CWE327/two.java",
                        'class NamedGood { void good() { Cipher.getInstance("AES"); } }')
        zipped.writestr("Java/src/testcases/CWE338/three.java",
                        "class RandomUse { void run() { new java.util.Random(); } }")
    return archive, _suite(archive, entries)


def test_official_pin_is_exact_and_measured():
    suite = juliet.JULIET_JAVA_13
    assert suite.archive_bytes == 76_798_417
    assert suite.archive_sha256 == "d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60"
    assert dict(suite.expected_files) == {"CWE-327": 38, "CWE-328": 55, "CWE-338": 38}
    assert sum(dict(suite.expected_files).values()) == 131
    assert dict(suite.expected_case_files) == {"CWE-327": 34, "CWE-328": 51, "CWE-338": 34}
    assert sum(dict(suite.expected_case_files).values()) == 119
    assert suite.manifest_recovery_lines == (50084, 66737)


def test_blind_scan_never_opens_manifest_and_uses_opaque_scanner_names(tmp_path, monkeypatch):
    archive, suite = _archive(tmp_path)
    opened = []
    seen_names = []
    real_open = zipfile.ZipFile.open
    real_review = juliet.codereview.review_source

    def guarded_open(self, name, *args, **kwargs):
        entry = name.filename if isinstance(name, zipfile.ZipInfo) else str(name)
        opened.append(entry)
        if entry == suite.manifest_entry:
            raise AssertionError("blind scan opened ground truth")
        return real_open(self, name, *args, **kwargs)

    def recording_review(source, name, props=None):
        seen_names.append(name)
        return real_review(source, name, props)

    monkeypatch.setattr(zipfile.ZipFile, "open", guarded_open)
    monkeypatch.setattr(juliet.codereview, "review_source", recording_review)
    rows = juliet.scan_archive(archive, tmp_path / "run.jsonl", suite)

    assert len(rows) == 3
    assert suite.manifest_entry not in opened
    assert all(name.startswith("source-") and name.endswith(".java") for name in seen_names)
    assert not any("CWE" in name or "good" in name.lower() or "bad" in name.lower()
                   for name in seen_names)
    assert all(row["raw_evidence"]["source_sha256"] for row in rows)
    assert all(row["measurement_status"] == contract.MEASURED for row in rows)


def test_blind_scan_resumes_without_rescanning_completed_sources(tmp_path, monkeypatch):
    archive, suite = _archive(tmp_path)
    checkpoint = tmp_path / "run.jsonl"
    first = juliet.scan_archive(archive, checkpoint, suite)

    def must_not_run(*args, **kwargs):
        raise AssertionError("resume rescanned a completed source")

    monkeypatch.setattr(juliet.codereview, "review_source", must_not_run)
    second = juliet.scan_archive(archive, checkpoint, suite)
    assert second == first
    assert len(checkpoint.read_text(encoding="utf8").splitlines()) == 3


def test_corpus_shape_mismatch_is_an_environment_failure(tmp_path):
    archive, suite = _archive(tmp_path)
    broken = juliet.SuiteSpec(**{
        **suite.__dict__,
        "expected_files": (("CWE-327", 99), ("CWE-338", 1)),
    })
    with pytest.raises(juliet.JulietEnvironmentFailure, match="corpus shape mismatch"):
        juliet.scan_archive(archive, tmp_path / "run.jsonl", broken)


def test_digest_mismatch_is_an_environment_failure_not_a_result(tmp_path):
    archive, suite = _archive(tmp_path)
    with zipfile.ZipFile(archive) as zipped:
        entries = [(info.filename, zipped.read(info)) for info in zipped.infolist()]
    with zipfile.ZipFile(archive, "w") as zipped:
        for name, body in entries:
            if name.endswith("one.java"):
                body = body.replace(b"NamedBad", b"NamedMad")
            zipped.writestr(name, body)
    assert archive.stat().st_size == suite.archive_bytes
    with pytest.raises(juliet.JulietEnvironmentFailure, match="SHA-256 mismatch"):
        juliet.scan_archive(archive, tmp_path / "run.jsonl", suite)
    assert not (tmp_path / "run.jsonl").exists()


def test_blind_artifact_seals_checkpoint_and_retains_raw_evidence(tmp_path):
    archive, suite = _archive(tmp_path)
    checkpoint = tmp_path / "run.jsonl"
    output = tmp_path / "scan.json"
    artifact = juliet.run_blind(archive, checkpoint, output, suite, "abc123")

    contract.verify_seal(contract.ArtifactSeal(**artifact["run_seal"]))
    assert artifact["lane"] == "code-assisted (SAST)"
    assert artifact["git_sha"] == "abc123"
    assert len(artifact["per_entry"]) == 3
    assert artifact["environment_failures"] == []
    assert json.loads(output.read_text(encoding="utf8"))["semantic_sha256"] == artifact["semantic_sha256"]
