import hashlib
import json
from pathlib import Path
import zipfile

import pytest

import bench_contract as contract
import bench_juliet as juliet


def _line(source: str, needle: str) -> int:
    return source[:source.index(needle)].count("\n") + 1


def _fixture(tmp_path: Path, unsafe_safe_twin: bool = False, juliet_legacy_safe: bool = False):
    crypto_safe = ("DES" if unsafe_safe_twin else
                   "AES" if juliet_legacy_safe else "AES/GCM/NoPadding")
    crypto = """import javax.crypto.Cipher;
class CryptoCase {
    public void bad() throws Throwable {
        Cipher.getInstance("DES");
    }
    public void good() throws Throwable { good1(); }
    private void good1() throws Throwable {
        Cipher.getInstance("%s");
    }
}
""" % crypto_safe
    random = """import java.security.SecureRandom;
class RandomCase {
    public void bad() throws Throwable {
        new java.util.Random();
    }
    public void good() throws Throwable { good1(); }
    private void good1() throws Throwable {
        new SecureRandom();
    }
}
"""
    names = {
        "CWE-327": "CWE327_Use_Broken_Crypto__DES_01.java",
        "CWE-338": "CWE338_Weak_PRNG__util_01.java",
    }
    sources = {"CWE-327": crypto, "CWE-338": random}
    prefixes = {
        "CWE-327": "Java/src/testcases/CWE327_Use_Broken_Crypto/",
        "CWE-338": "Java/src/testcases/CWE338_Weak_PRNG/",
    }
    manifest = """<container>
  <testcase>
    <file path="%s"><flaw line="%d" name="CWE-327: weak crypto"/></file>
  </testcase>
  </testcase>
  <testcase>
    <file path="%s"><flaw line="%d" name="CWE-338: weak PRNG"/></file>
  </testcase>
</container>
""" % (names["CWE-327"], _line(crypto, 'Cipher.getInstance("DES")'),
       names["CWE-338"], _line(random, "new java.util.Random()"))

    archive = tmp_path / "juliet.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("Java/manifest.xml", manifest)
        for cwe, source in sources.items():
            zipped.writestr(prefixes[cwe] + names[cwe], source)
    suite = juliet.SuiteSpec(
        name="synthetic Juliet", version="test", upstream="local", author="test",
        language="Java", license="test", archive_name=archive.name,
        archive_bytes=archive.stat().st_size,
        archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        manifest_entry="Java/manifest.xml",
        cwe_prefixes=tuple(sorted(prefixes.items())),
        expected_files=(("CWE-327", 1), ("CWE-338", 1)),
        expected_case_files=(("CWE-327", 1), ("CWE-338", 1)),
        manifest_recovery_lines=(5,),
    )
    checkpoint = tmp_path / "run.jsonl"
    scan_artifact = tmp_path / "scan.json"
    juliet.run_blind(archive, checkpoint, scan_artifact, suite, "test-sha")
    return archive, suite, checkpoint, scan_artifact


def test_direct_bad_and_safe_twins_produce_a_full_b1_denominator(tmp_path):
    archive, suite, checkpoint, scan_artifact = _fixture(tmp_path)
    artifact = juliet.score_blind_run(
        archive, checkpoint, scan_artifact, tmp_path / "score.json", suite, "test-sha")

    score = artifact["score"]
    assert score["publishable"] is True
    assert score["denominator"] == 4
    assert artifact["scope"] == {
        "variant": "01-17 direct bad()/goodN() methods",
        "source_files": 2,
        "method_cases": 4,
        "positive_cases": 2,
        "negative_cases": 2,
        "skipped_cases": 0,
        "excluded": "generated launchers and non-oracle good()/main() dispatch wrappers",
    }
    assert score["official"]["overall"] == score["product"]["overall"]
    assert score["product"]["overall"]["tp"] == 2
    assert score["product"]["overall"]["tn"] == 2
    assert score["product"]["overall"]["fp"] == 0
    assert score["product"]["overall"]["fn"] == 0
    assert artifact["blind_ordering"]["ordering_ok"] is True


def test_a_detection_inside_the_safe_twin_is_counted_as_a_false_positive(tmp_path):
    archive, suite, checkpoint, scan_artifact = _fixture(tmp_path, unsafe_safe_twin=True)
    artifact = juliet.score_blind_run(
        archive, checkpoint, scan_artifact, tmp_path / "score.json", suite, "test-sha")
    overall = artifact["score"]["product"]["overall"]
    assert overall["tp"] == 2
    assert overall["tn"] == 1
    assert overall["fp"] == 1
    assert overall["fn"] == 0


def test_juliets_legacy_aes_safe_label_is_not_silently_special_cased(tmp_path):
    archive, suite, checkpoint, scan_artifact = _fixture(tmp_path, juliet_legacy_safe=True)
    artifact = juliet.score_blind_run(
        archive, checkpoint, scan_artifact, tmp_path / "score.json", suite, "test-sha")
    overall = artifact["score"]["product"]["overall"]
    assert overall["tp"] == 2
    assert overall["tn"] == 1
    assert overall["fp"] == 1
    assert overall["fn"] == 0


def test_checkpoint_tampering_is_rejected_before_ground_truth_is_loaded(tmp_path, monkeypatch):
    archive, suite, checkpoint, scan_artifact = _fixture(tmp_path)
    with open(checkpoint, "a", encoding="utf8") as handle:
        handle.write("tampered\n")
    called = False

    def key_must_not_be_read(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("ground truth loaded before seal verification")

    monkeypatch.setattr(juliet, "_load_manifest", key_must_not_be_read)
    with pytest.raises(contract.SealError, match="changed after it was sealed"):
        juliet.score_blind_run(
            archive, checkpoint, scan_artifact, tmp_path / "score.json", suite, "test-sha")
    assert called is False


def test_manifest_recovery_is_bounded_by_the_pinned_line(tmp_path):
    archive, suite, checkpoint, scan_artifact = _fixture(tmp_path)
    wrong = juliet.SuiteSpec(**{**suite.__dict__, "manifest_recovery_lines": ()})
    with pytest.raises(juliet.JulietEnvironmentFailure, match="recovery mismatch"):
        juliet.score_blind_run(
            archive, checkpoint, scan_artifact, tmp_path / "score.json", wrong, "test-sha")


def test_scored_testcase_file_count_is_a_measured_ratchet(tmp_path):
    archive, suite, checkpoint, scan_artifact = _fixture(tmp_path)
    wrong = juliet.SuiteSpec(**{
        **suite.__dict__,
        "expected_case_files": (("CWE-327", 99), ("CWE-338", 1)),
    })
    with pytest.raises(juliet.JulietEnvironmentFailure, match="testcase file shape mismatch"):
        juliet.score_blind_run(
            archive, checkpoint, scan_artifact, tmp_path / "score.json", wrong, "test-sha")


def test_score_artifact_retains_method_level_raw_evidence(tmp_path):
    archive, suite, checkpoint, scan_artifact = _fixture(tmp_path)
    output = tmp_path / "score.json"
    artifact = juliet.score_blind_run(
        archive, checkpoint, scan_artifact, output, suite, "test-sha")
    persisted = json.loads(output.read_text(encoding="utf8"))

    assert persisted["lane"] == "code-assisted (SAST)"
    assert persisted["semantic_sha256"] == artifact["semantic_sha256"]
    for row in persisted["per_entry"]:
        raw = row["raw_evidence"]
        assert raw["method"] in ("bad", "good1")
        assert len(raw["method_lines"]) == 2
        assert raw["source_sha256"]
