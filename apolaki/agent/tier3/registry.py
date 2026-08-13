"""Declarative inventory of Apolaki's existing Tier-3 controls.

Every entry points at an executable pytest node. A filename, marker, or prose claim
is not coverage; the runner records coverage only after that node reaches PASS.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

import proof_schema


VULNERABLE = "VULNERABLE"
SAFE = "SAFE"
NOISE = "NOISE/LOOKALIKE"
AMBIGUOUS = "AMBIGUOUS"
FILTERED = "FILTERED/WAF"
NETWORK_FAILURE = "NETWORK-FAILURE"
UNSUPPORTED = "UNSUPPORTED"
REGRESSION = "REGRESSION"

CONTROL_KINDS = frozenset({
    VULNERABLE, SAFE, NOISE, AMBIGUOUS, FILTERED,
    NETWORK_FAILURE, UNSUPPORTED, REGRESSION,
})

SOURCE_FILES = frozenset({
    "tests/test_proof_gate_surfaces.py",
    "tests/test_bench_product_fpr.py",
    "tests/test_proof_claim_matches_artifact.py",
    "tests/test_codeassisted_negative_controls.py",
    "tests/test_sqli_oracle_negative_controls.py",
    "tests/test_liveness_hostless_negative_control.py",
    "tests/test_bie_errored_control.py",
    "tests/test_technique_contract.py",
    "tests/test_evidence_contract_by_proof_kind.py",
    "tests/test_set_param_contract.py",
    "tests/test_cmdi_shapes.py",
})


@dataclass(frozen=True)
class ControlSpec:
    control_id: str
    vulnerability_class: str
    cwe: tuple[str, ...]
    control_kind: str
    node_id: str
    proof_kind: str
    naive_failure: str

    @property
    def source_file(self) -> str:
        return self.node_id.split("::", 1)[0]

    def to_dict(self) -> dict:
        out = asdict(self)
        out["cwe"] = list(self.cwe)
        out["source_file"] = self.source_file
        return out


def _proof(source_derived: bool = False) -> str:
    marker = {"lane": "code-assisted"} if source_derived else {}
    return proof_schema.proof_kind(marker)


def _c(control_id: str, vulnerability_class: str, control_kind: str,
       node_id: str, naive_failure: str, *cwe: str,
       source_derived: bool = False) -> ControlSpec:
    return ControlSpec(
        control_id=control_id,
        vulnerability_class=vulnerability_class,
        cwe=tuple(cwe),
        control_kind=control_kind,
        node_id=node_id,
        proof_kind=_proof(source_derived),
        naive_failure=naive_failure,
    )


CONTROLS = (
    _c(
        "proof-gate-all-report-surfaces", "proof_gate", REGRESSION,
        "tests/test_proof_gate_surfaces.py::test_risk_score_and_counts_agree_about_what_confirmed_means",
        "A consumer can count a demoted lead as confirmed even though the canonical proof gate rejected it.",
    ),
    _c(
        "benchmark-product-cross-family-fp", "benchmark_scoring", REGRESSION,
        "tests/test_bench_product_fpr.py::test_clean_case_with_a_foreign_confirmed_finding_scores_TN_officially_and_FP_for_the_product",
        "A within-family scorer can report zero false positives while the product would show a client a foreign-family finding.",
    ),
    _c(
        "report-does-not-invent-control", "proof_reporting", AMBIGUOUS,
        "tests/test_proof_claim_matches_artifact.py::test_a_finding_with_no_control_does_not_assert_one",
        "A report can claim a negative control ran merely because the finding family declares one.",
    ),
    _c(
        "weak-crypto-aead-clean-twin", "weak_crypto", SAFE,
        "tests/test_codeassisted_negative_controls.py::test_negative_control_aead_cipher_is_not_weak_crypto",
        "A source signature can flag every Cipher.getInstance call without resolving the secure algorithm.",
        "CWE-327", source_derived=True,
    ),
    _c(
        "weak-hash-sha2-clean-twin", "weak_hash", SAFE,
        "tests/test_codeassisted_negative_controls.py::test_negative_control_sha256_and_sha512_are_not_weak_hashes",
        "A source signature can treat every digest construction as a weak hash.",
        "CWE-328", source_derived=True,
    ),
    _c(
        "weak-random-secure-random-clean-twin", "weak_random", SAFE,
        "tests/test_codeassisted_negative_controls.py::test_negative_control_securerandom_is_not_weak_randomness",
        "A method-name detector can ignore the receiver and flag cryptographically secure randomness.",
        "CWE-330", "CWE-337", source_derived=True,
    ),
    _c(
        "code-assisted-inert-text", "code_assisted_analysis", NOISE,
        "tests/test_codeassisted_negative_controls.py::test_inert_text_is_never_a_call_site",
        "A text search can report comments, strings, annotations, and malformed masking residue as executable call sites.",
        source_derived=True,
    ),
    _c(
        "sqli-identical-response-clean", "sqli", SAFE,
        "tests/test_sqli_oracle_negative_controls.py::test_identical_responses_never_confirm_blind_sqli",
        "A boolean oracle can confirm without proving any semantic difference between predicates.",
        "CWE-89",
    ),
    _c(
        "sqli-unstable-page-noise", "sqli", NOISE,
        "tests/test_sqli_oracle_negative_controls.py::test_an_unstable_page_must_not_confirm_blind_sqli",
        "One baseline sample can make ordinary response instability look like a true/false differential.",
        "CWE-89",
    ),
    _c(
        "sqli-reflection-noise", "sqli", NOISE,
        "tests/test_sqli_oracle_negative_controls.py::test_a_parameter_that_merely_echoes_cannot_confirm_blind_sqli",
        "Payload reflection can be mistaken for a database predicate changing the selected records.",
        "CWE-89",
    ),
    _c(
        "sqli-nonce-noise", "sqli", NOISE,
        "tests/test_sqli_oracle_negative_controls.py::test_a_page_with_a_per_response_nonce_cannot_confirm_blind_sqli",
        "Per-response nonces can create a body delta on every request and masquerade as boolean SQL injection.",
        "CWE-89",
    ),
    _c(
        "sqli-always-error-noise", "sqli", NOISE,
        "tests/test_sqli_oracle_negative_controls.py::test_a_page_that_errors_on_every_input_is_not_error_recovery",
        "A generic error page can be credited as payload-induced query breakage without a recovery leg.",
        "CWE-89",
    ),
    _c(
        "sqli-uniform-latency-noise", "sqli", NOISE,
        "tests/test_sqli_oracle_negative_controls.py::test_an_endpoint_that_is_slow_for_everything_cannot_confirm_time_blind",
        "Uniform server latency can be credited as a time-based payload delay when the paired control is ignored.",
        "CWE-89",
    ),
    _c(
        "sqli-error-recovery-positive", "sqli", VULNERABLE,
        "tests/test_sqli_oracle_negative_controls.py::test_error_recovery_needs_both_legs",
        "A negative-only oracle can become a mute button that rejects the real break-and-recovery signal too.",
        "CWE-89",
    ),
    _c(
        "hostless-surface-regression", "surface_discovery", REGRESSION,
        "tests/test_liveness_hostless_negative_control.py::test_a_hostless_url_fails_the_reach_check_DEAD",
        "A liveness guard can count discovered URLs that have no host and can never pass scope validation.",
    ),
    _c(
        "access-control-dead-control", "access_control", NETWORK_FAILURE,
        "tests/test_bie_errored_control.py::test_judge_treats_an_errored_anonymous_control_as_missing",
        "An exception-shaped control object can satisfy an is-not-None check and let an untested authorization claim confirm.",
        "CWE-639",
    ),
    _c(
        "access-control-public-resource", "access_control", SAFE,
        "tests/test_bie_errored_control.py::test_client_side_authz_keeps_rejecting_the_genuinely_public_resource",
        "A stricter dead-control gate can accidentally promote or obscure a resource proven public by a live anonymous control.",
        "CWE-639",
    ),
    _c(
        "access-control-cross-user-positive", "access_control", VULNERABLE,
        "tests/test_bie_errored_control.py::test_judge_still_confirms_a_real_cross_user_read_with_live_controls",
        "A negative-control fix can silence a real owner/non-owner authorization differential.",
        "CWE-639",
    ),
    _c(
        "technique-proof-contract-ratchet", "technique_contract", REGRESSION,
        "tests/test_technique_contract.py::test_every_technique_record_carries_a_contract",
        "A technique can be added without a stated negative control or evidence obligation and still look registered.",
    ),
    _c(
        "source-proof-control-not-applicable", "evidence_contract", SAFE,
        "tests/test_evidence_contract_by_proof_kind.py::test_source_finding_does_not_claim_a_request_negative_control",
        "A source-derived finding can fabricate a request differential that cannot exist for a static call site.",
        source_derived=True,
    ),
    _c(
        "behavioural-proof-without-control", "evidence_contract", AMBIGUOUS,
        "tests/test_evidence_contract_by_proof_kind.py::test_behavioural_without_control_says_so_in_the_bundle_too",
        "A behavioural finding without a recorded control can be rendered as deterministically confirmed.",
    ),
    _c(
        "behavioural-proof-with-control", "evidence_contract", VULNERABLE,
        "tests/test_evidence_contract_by_proof_kind.py::test_behavioural_with_control_is_unchanged",
        "Separating proof kinds can erase the genuine request control on an honestly confirmed behavioural finding.",
    ),
    _c(
        "set-param-missing-parameter-regression", "probe_delivery", REGRESSION,
        "tests/test_set_param_contract.py::test_missing_parameter_is_appended_not_dropped",
        "A probe helper can return its baseline URL unchanged, so no payload is sent and a false negative looks clean.",
    ),
    _c(
        "cmdi-command-output-positive", "command_injection", VULNERABLE,
        "tests/test_cmdi_shapes.py::test_argv_output_confirms_only_on_real_command_output",
        "A reflection-resistant oracle can become too strict and reject real command output.",
        "CWE-78",
    ),
    _c(
        "cmdi-bare-value-noise", "command_injection", NOISE,
        "tests/test_cmdi_shapes.py::test_argv_bare_noncommand_is_the_negative_control",
        "An argv-shaped value can confirm merely because the application echoes an execution error string.",
        "CWE-78",
    ),
    _c(
        "cmdi-uniform-latency-noise", "command_injection", NOISE,
        "tests/test_cmdi_shapes.py::test_time_oracle_declines_a_uniformly_slow_endpoint",
        "A slow endpoint can confirm command execution when payload and zero-delay control are not compared.",
        "CWE-78",
    ),
    _c(
        "cmdi-blind-time-positive", "command_injection", VULNERABLE,
        "tests/test_cmdi_shapes.py::test_real_blind_sink_confirms_through_the_time_shape",
        "A bounded timing budget can prevent the real per-endpoint differential from ever reaching confirmation.",
        "CWE-78",
    ),
    _c(
        "cmdi-no-oob-callback-clean", "command_injection", SAFE,
        "tests/test_cmdi_shapes.py::test_oob_callback_that_never_arrives_is_a_non_detection",
        "A timeout or absent collaborator interaction can be converted into timeout-shaped proof.",
        "CWE-78",
    ),
    _c(
        "cmdi-oob-callback-positive", "command_injection", VULNERABLE,
        "tests/test_cmdi_shapes.py::test_oob_confirms_when_the_target_actually_calls_back",
        "A no-callback safety check can suppress a real correlated collaborator interaction.",
        "CWE-78",
    ),
    _c(
        "xss-encoded-reflection-noise", "xss", NOISE,
        "tests/test_cmdi_shapes.py::test_xss_header_carrier_declines_a_correctly_encoded_reflection",
        "A new request-header carrier can turn context-safe reflection into an XSS confirmation.",
        "CWE-79",
    ),
    _c(
        "xss-static-endpoint-clean", "xss", SAFE,
        "tests/test_cmdi_shapes.py::test_xss_header_carrier_declines_an_endpoint_that_reflects_nothing",
        "A carrier can report XSS even though the payload never reaches the response.",
        "CWE-79",
    ),
    _c(
        "cmdi-cookie-carrier-positive", "command_injection", VULNERABLE,
        "tests/test_cmdi_shapes.py::test_cmdi_reaches_a_sink_fed_only_by_a_cookie",
        "A probe repertoire can omit cookie delivery and report a vulnerable cookie-only sink clean.",
        "CWE-78",
    ),
    _c(
        "cmdi-cookie-echo-noise", "command_injection", NOISE,
        "tests/test_cmdi_shapes.py::test_cookie_carrier_does_not_confirm_on_an_endpoint_that_only_echoes",
        "Adding cookie delivery can confuse reflected payload text with command execution.",
        "CWE-78",
    ),
)


def validate_registry(controls=CONTROLS, require_all_sources: bool = True) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for spec in controls:
        if not spec.control_id or spec.control_id in seen:
            errors.append("duplicate or empty control_id: %s" % spec.control_id)
        seen.add(spec.control_id)
        if spec.control_kind not in CONTROL_KINDS:
            errors.append("%s: unknown control kind %s" % (spec.control_id, spec.control_kind))
        if spec.proof_kind not in (proof_schema.BEHAVIOURAL, proof_schema.SOURCE_DERIVED):
            errors.append("%s: unknown proof kind %s" % (spec.control_id, spec.proof_kind))
        if "::test_" not in spec.node_id:
            errors.append("%s: node_id must name an exact test function" % spec.control_id)
        if not spec.naive_failure.strip():
            errors.append("%s: missing naive_failure" % spec.control_id)
    if require_all_sources:
        missing_files = sorted(SOURCE_FILES - {s.source_file for s in controls})
        if missing_files:
            errors.append("unregistered source files: %s" % ", ".join(missing_files))
    return errors
