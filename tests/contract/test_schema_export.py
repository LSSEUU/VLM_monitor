import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from labcourt.config_loader import load_config
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import FrameBundle
from labcourt.contracts.events import CandidateEvent, SafetySignal
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import REFERENCE_TOKEN_PATTERN
from labcourt.schema_export import expected_schema_files, export_schemas
from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

EXPECTED_SCHEMA_MODES = {
    "acquisition-execution-claim-authority": "serialization",
    "acquisition-execution-publication": "serialization",
    "acquisition-request": "serialization",
    "acquisition-request-payload": "validation",
    "alert-channel-capability-authority": "serialization",
    "alert-cooldown-authority": "serialization",
    "alert-cooldown-key": "serialization",
    "alert-decision": "serialization",
    "alert-dispatch-attempt": "serialization",
    "alert-dispatch-receipt": "serialization",
    "alert-outbox-item": "serialization",
    "alert-policy-authority": "serialization",
    "alert-policy-request": "serialization",
    "affected-citation-report": "serialization",
    "appeal": "serialization",
    "appeal-resolution-command": "validation",
    "appeal-resolution-precedent-snapshot": "serialization",
    "appeal-resolution-side-effect-intent": "serialization",
    "appeal-review-command": "validation",
    "appeal-submission-command": "validation",
    "appeal-version-authority": "serialization",
    "app-config": "validation",
    "association-result": "serialization",
    "artifact-ref": "serialization",
    "artifact-validation-report": "serialization",
    "artifact-verification": "serialization",
    "audit-chain-report": "serialization",
    "audit-entry": "serialization",
    "backlog-completion-receipt": "serialization",
    "backlog-item": "serialization",
    "backlog-lease-identity": "serialization",
    "backlog-retry-context": "serialization",
    "backlog-retry-failure": "serialization",
    "backlog-retry-report": "serialization",
    "backlog-retry-success": "serialization",
    "backlog-strict-parse-failure-proof": "serialization",
    "candidate-event": "serialization",
    "case": "serialization",
    "closure-report": "serialization",
    "closed-case-appeal-authority": "serialization",
    "coco-dataset-export-command": "validation",
    "crop": "serialization",
    "crop-request": "serialization",
    "defender-model-payload": "validation",
    "dataset-export-report": "serialization",
    "evidence-citation": "serialization",
    "emergency-safety-incident": "serialization",
    "evidence-pack": "serialization",
    "evidence-pack-derivation": "serialization",
    "frame-bundle": "serialization",
    "frame-ref": "serialization",
    "hearing-backlog-completion-receipt": "serialization",
    "hearing-backlog-retry-failure": "serialization",
    "hearing-backlog-retry-success": "serialization",
    "hearing-checkpoint": "serialization",
    "hearing-cycle-scope": "serialization",
    "hearing-human-review-receipt": "serialization",
    "hearing-model-cache-entry": "serialization",
    "hearing-model-call-failure-authority": "serialization",
    "hearing-model-parse-receipt": "serialization",
    "hearing-model-request": "serialization",
    "hearing-model-response": "serialization",
    "hearing-model-response-recovery-report": "serialization",
    "hearing-precedent-retrieval-outcome": "serialization",
    "hearing-precedent-retrieval-query": "serialization",
    "hearing-precedent-retrieval-receipt": "serialization",
    "hearing-precedent-retrieval-result": "serialization",
    "hearing-record": "serialization",
    "hearing-rework-receipt": "serialization",
    "hearing-role-output": "serialization",
    "hearing-round": "serialization",
    "hearing-session": "serialization",
    "hearing-strict-parse-failure-attempt": "serialization",
    "hearing-initial-strict-parse-failure-proof": "serialization",
    "hearing-strict-parse-failure-proof": "serialization",
    "hearing-usage-receipt": "serialization",
    "hearing-unknown-reference-attempt": "serialization",
    "hearing-verdict-binding": "serialization",
    "immediate-safety-delivery-authority": "serialization",
    "judge-model-payload": "validation",
    "fake-vlm-fixture-bundle": "validation",
    "maintenance-recovery-report": "serialization",
    "m3-backlog-retry-command-report": "serialization",
    "m3-process-command-report": "serialization",
    "m3-process-report": "serialization",
    "m4-projection-current-pointer": "serialization",
    "m4-projection-generation-manifest": "serialization",
    "m4-backlog-retry-command-report": "serialization",
    "m4-backlog-retry-report": "serialization",
    "m4-fake-vlm-fixture-bundle": "validation",
    "m4-process-command-report": "serialization",
    "m4-process-report": "serialization",
    "m5-appeal-window-snapshot": "serialization",
    "m5-appeal-training-label-input": "validation",
    "m5-artifact-validation-report": "serialization",
    "m5-appeal-resolution-command-report": "serialization",
    "m5-appeal-resolution-commit-receipt": "serialization",
    "m5-appeal-review-command-report": "serialization",
    "m5-appeal-submission-command-report": "serialization",
    "m5-close-case-outcome": "serialization",
    "m5-dispatch-command-report": "serialization",
    "m5-dataset-crop-snapshot-authority": "serialization",
    "m5-dataset-label-snapshot-receipt": "serialization",
    "m5-dataset-registration-snapshot-authority": "serialization",
    "m5-embedding-request": "serialization",
    "m5-embedding-vector": "serialization",
    "m5-finalize-command-report": "serialization",
    "m5-precedent-activation-command-report": "serialization",
    "m5-precedent-activation-receipt": "serialization",
    "m5-precedent-activation-result": "serialization",
    "m5-precedent-application-batch-authority": "serialization",
    "m5-precedent-application-citation-commit": "serialization",
    "m5-precedent-authority": "serialization",
    "m5-precedent-causal-event": "serialization",
    "m5-precedent-candidate-evaluation": "serialization",
    "m5-precedent-citation-authority": "serialization",
    "m5-precedent-citation-commit": "serialization",
    "m5-precedent-citation-snapshot": "serialization",
    "m5-precedent-conflict-batch-authority": "serialization",
    "m5-precedent-conflict-batch-receipt": "serialization",
    "m5-precedent-conflict-batch-resolution": "serialization",
    "m5-precedent-conflict-causal-cut": "serialization",
    "m5-precedent-conflict-receipt": "serialization",
    "m5-precedent-conflict-resolution": "serialization",
    "m5-precedent-conflict-snapshot": "serialization",
    "m5-precedent-exposure-batch-authority": "serialization",
    "m5-precedent-conflict-command-report": "serialization",
    "m5-precedent-import-report": "serialization",
    "m5-precedent-policy": "serialization",
    "m5-precedent-retrieval-query": "serialization",
    "m5-precedent-retrieval-result": "serialization",
    "m5-precedent-revocation-receipt": "serialization",
    "m5-precedent-revocation-result": "serialization",
    "m5-projection-current-pointer": "serialization",
    "m5-projection-generation-manifest": "serialization",
    "m5-strong-training-label-provenance-receipt": "serialization",
    "m5-training-label-authority": "serialization",
    "m5-training-causal-event": "serialization",
    "m5-training-causal-watermark": "serialization",
    "m6-case-replay-snapshot": "serialization",
    "m6-appeal-gold-truth-authority": "serialization",
    "m6-challenge-designation-authority": "serialization",
    "m6-provider-trap-authority": "serialization",
    "m6-replay-input-authority": "serialization",
    "m6-replay-input-closure-authority": "serialization",
    "m6-replay-locked-candidate-case-binding": "serialization",
    "m6-replay-locked-execution-component-authority": "serialization",
    "m6-replay-locked-execution-seal-authority": "serialization",
    "m6-replay-locked-execution-scope-authority": "serialization",
    "m6-replay-locked-pending-sample-commitment": "serialization",
    "m6-replay-locked-run-trap-seal-authority": "serialization",
    "m6-replay-locked-sample-execution-record": "serialization",
    "m6-replay-locked-alert-policy-causal-cut": "serialization",
    "m6-replay-locked-closed-candidate-binding-authority": "serialization",
    "m6-replay-locked-closed-policy-execution-component-authority-v2": "serialization",
    "m6-replay-locked-closed-policy-execution-seal-authority-v2": "serialization",
    "m6-replay-locked-closed-policy-execution-scope-authority-v2": "serialization",
    "m6-replay-locked-closed-policy-publication-seal-authority-v2": "serialization",
    "m6-replay-locked-closed-policy-pending-sample-commitment-v2": "serialization",
    "m6-replay-locked-closed-policy-run-trap-seal-authority-v2": "serialization",
    "m6-replay-locked-closed-policy-sample-execution-record-v2": "serialization",
    "m6-replay-locked-closed-policy-source-binding-authority": "serialization",
    "m6-replay-locked-source-determinism-authority": "serialization",
    "m6-offline-demo-manifest-authority-v1": "serialization",
    "m6-offline-demo-publication-seal-authority-v1": "serialization",
    "m6-offline-demo-scenario-artifact-receipt-v1": "serialization",
    "m6-offline-demo-scenario-result-authority-v1": "serialization",
    "m6-regression-dataset-snapshot": "serialization",
    "m6-regression-eligibility-policy": "serialization",
    "m6-regression-execution-dataset-snapshot": "serialization",
    "m6-regression-execution-source-catalog": "serialization",
    "m6-regression-report": "serialization",
    "m6-regression-publication-seal": "serialization",
    "m6-regression-run-command": "serialization",
    "m6-regression-source-inventory-cut": "serialization",
    "m6-regression-selection-inventory": "serialization",
    "m6-regression-selection-receipt": "serialization",
    "m6-privacy-safe-static-report-manifest-authority-v1": "serialization",
    "m6-privacy-safe-static-report-publication-seal-authority-v1": "serialization",
    "m6-synthetic-challenge-scenario-authority": "serialization",
    "m6-upgrade-candidate-output-inventory-authority": "serialization",
    "m6-upgrade-candidate-output-inventory-authority-v2": "serialization",
    "m6-upgrade-candidate-output-inventory-authority-v3": "serialization",
    "m6-upgrade-candidate-run-cut-authority": "serialization",
    "m6-upgrade-candidate-sample-output-authority": "serialization",
    "m6-upgrade-execution-component-authority": "serialization",
    "m6-upgrade-execution-ledger-seal": "serialization",
    "m6-upgrade-execution-ledger-seal-v2": "serialization",
    "m6-upgrade-execution-scope-authority": "serialization",
    "m6-upgrade-physical-artifact-ref": "serialization",
    "m6-upgrade-pending-sample-commitment-authority": "serialization",
    "m6-upgrade-sample-execution-observation-authority": "serialization",
    "m6-upgrade-sample-execution-observation-authority-v2": "serialization",
    "m6-upgrade-sample-execution-record": "serialization",
    "m6-upgrade-sample-execution-record-v2": "serialization",
    "m6-upgrade-selected-case-audit-anchor": "serialization",
    "m6-source-authority-seal": "serialization",
    "m8-campus-location": "serialization",
    "m8-campus-topology-authority-v1": "serialization",
    "m8-actor-authority-v1": "serialization",
    "m8-actor-authority-commit-receipt-v1": "serialization",
    "m8-authority-reference": "serialization",
    "m8-operational-case-audit-intent-v1": "serialization",
    "m8-operational-case-audit-event-v1": "serialization",
    "m8-operational-case-authority-v1": "serialization",
    "m8-operational-case-commit-receipt-v1": "serialization",
    "m8-operational-case-create-command-v1": "serialization",
    "m8-operational-case-transition-command-v1": "serialization",
    "m8-operational-source": "serialization",
    "m8-operational-source-catalog-authority-v1": "serialization",
    "m8-sensor-adapter-capability-authority-v1": "serialization",
    "m8-sensor-poll-request-v1": "serialization",
    "m8-sensor-poll-result-v1": "serialization",
    "m8-sensor-risk-assessment-v1": "serialization",
    "m8-sensor-risk-policy-authority-v1": "serialization",
    "m8-sensor-sample": "serialization",
    "m8-simulated-sensor-scenario-authority-v1": "serialization",
    "m3-artifact-validation-report": "serialization",
    "m4-artifact-validation-report": "serialization",
    "model-cache-entry": "serialization",
    "model-call-failure-authority": "serialization",
    "model-parse-receipt": "serialization",
    "model-response-recovery-report": "serialization",
    "observability-score": "serialization",
    "parsed-screening-output": "serialization",
    "pilot-a2-report": "serialization",
    "pilot-a3-report": "serialization",
    "pilot-a4-case-view": "serialization",
    "pilot-a4-close-report": "serialization",
    "pilot-a4-media-view": "serialization",
    "pilot-a4-metrics": "serialization",
    "pilot-a4-model-version": "serialization",
    "pilot-a4-publication-report": "serialization",
    "pilot-a4-review-report": "serialization",
    "pilot-a5-run-report": "serialization",
    "pilot-evidence-pack-summary": "serialization",
    "pilot-local-alert-document": "serialization",
    "pilot-perception-artifact-receipt": "serialization",
    "pilot-perception-completion-manifest": "serialization",
    "pilot-perception-execution-manifest": "serialization",
    "pilot-perception-frame-receipt": "serialization",
    "pilot-perception-report": "serialization",
    "pilot-perception-worker-failure": "validation",
    "pilot-perception-worker-ready": "validation",
    "pilot-perception-worker-request": "validation",
    "pilot-perception-worker-response": "validation",
    "pilot-perception-worker-startup-failure": "validation",
    "pilot-run-request": "validation",
    "pilot-ui-dashboard": "serialization",
    "pilot-ui-error-response": "serialization",
    "pilot-ui-job-start-request": "validation",
    "pilot-ui-job-status": "serialization",
    "precedent": "serialization",
    "precedent-lookup-query": "serialization",
    "precedent-resolution": "serialization",
    "privacy-receipt": "serialization",
    "prosecutor-model-payload": "validation",
    "projection-current-pointer": "serialization",
    "projection-generation-manifest": "serialization",
    "procedural-defect": "serialization",
    "procedural-review": "serialization",
    "prompt-manifest": "serialization",
    "purge-item-result": "serialization",
    "recovery-report": "serialization",
    "retention-hold": "serialization",
    "resolved-app-config": "serialization",
    "run-manifest": "serialization",
    "safety-signal": "serialization",
    "screening-result": "serialization",
    "screening-model-payload": "validation",
    "soft-reminder": "serialization",
    "stream-manifest": "serialization",
    "startup-recovery-report": "serialization",
    "structure-repair-request": "serialization",
    "training-label": "serialization",
    "training-crop-authority": "serialization",
    "tool-execution-manifest": "serialization",
    "tool-execution-receipt": "serialization",
    "tool-result": "serialization",
    "verdict": "serialization",
    "vlm-request": "serialization",
    "vlm-response": "serialization",
}


def test_schema_registry_has_the_explicit_public_contract_set_and_modes() -> None:
    assert set(SCHEMA_MODELS) == set(EXPECTED_SCHEMA_MODES)
    assert {
        name for name, mode in EXPECTED_SCHEMA_MODES.items() if mode == "validation"
    } == SCHEMA_VALIDATION_MODELS


def test_schemas_use_draft_2020_12_and_stable_ids() -> None:
    schemas = expected_schema_files()
    expected_files = {f"{name}.schema.json" for name in EXPECTED_SCHEMA_MODES} | {"index.json"}
    assert set(schemas) == expected_files
    for filename, content in schemas.items():
        payload = json.loads(content)
        assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert payload["$id"] == f"https://schemas.labcourt.local/v2/{filename}"
        Draft202012Validator.check_schema(payload)


def test_schema_index_exposes_each_contract_mode() -> None:
    index = json.loads(expected_schema_files()["index.json"])
    entries = {entry["name"]: entry for entry in index["schemas"]}
    assert set(entries) == set(EXPECTED_SCHEMA_MODES)
    for name, mode in EXPECTED_SCHEMA_MODES.items():
        assert entries[name]["file"] == f"{name}.schema.json"
        assert entries[name].get("mode") == mode


def test_authored_and_resolved_config_schemas_have_distinct_hash_contracts() -> None:
    schemas = expected_schema_files()
    authored = json.loads(schemas["app-config.schema.json"])
    resolved = json.loads(schemas["resolved-app-config.schema.json"])
    assert "config_sha256" not in authored["properties"]
    assert "config_sha256" not in authored["required"]
    assert resolved["properties"]["config_sha256"]["readOnly"] is True
    assert "config_sha256" in resolved["required"]


def test_serialization_schemas_require_read_only_computed_identity_fields() -> None:
    schemas = expected_schema_files()
    frame = json.loads(schemas["frame-ref.schema.json"])
    manifest = json.loads(schemas["run-manifest.schema.json"])
    for field_name in ("frame_id", "timestamp_ms"):
        assert frame["properties"][field_name]["readOnly"] is True
        assert field_name in frame["required"]
    assert manifest["properties"]["manifest_id"]["readOnly"] is True
    assert "manifest_id" in manifest["required"]


def test_m5_causal_event_schema_freezes_required_nullable_kind_matrix() -> None:
    event = json.loads(expected_schema_files()["m5-precedent-causal-event.schema.json"])

    assert event["$defs"]["M5PrecedentCausalEventKind"]["enum"] == [
        "PRECEDENT_AUTHORITY_APPENDED",
        "PRECEDENT_CITATION_APPENDED",
        "PRECEDENT_CONFLICT_BATCH_COMMITTED",
        "PRECEDENT_REVOCATION_COMMITTED",
        "APPEAL_RESOLUTION_COMMITTED",
    ]
    nullable_binding_fields = {
        "precedent_id",
        "precedent_authority_id",
        "precedent_revision",
        "citation_kind",
    }
    assert nullable_binding_fields <= set(event["required"])
    for field_name in nullable_binding_fields:
        alternatives = event["properties"][field_name]["anyOf"]
        assert {item.get("type") for item in alternatives} >= {"null"}


def test_m5_strong_training_provenance_schema_is_constant_size_and_root_only() -> None:
    receipt = json.loads(
        expected_schema_files()["m5-strong-training-label-provenance-receipt.schema.json"]
    )

    assert {
        "terminal_appeal_authority",
        "resolution_intent",
        "resolution_commit_receipt",
    }.isdisjoint(receipt["properties"])
    for field_name in (
        "label_document_sha256",
        "review_authority_sha256",
        "terminal_authority_sha256",
        "resolution_intent_id",
        "resolution_document_sha256",
        "resolution_commit_receipt_id",
        "resolution_commit_effect_root_sha256",
        "provenance_id",
    ):
        assert field_name in receipt["required"]
    assert receipt["properties"]["provenance_id"]["readOnly"] is True


def test_m1_output_schemas_preserve_anonymous_and_non_gating_boundaries() -> None:
    schemas = expected_schema_files()
    reminder = json.loads(schemas["soft-reminder.schema.json"])
    association = json.loads(schemas["association-result.schema.json"])
    observability = json.loads(schemas["observability-score.schema.json"])

    assert set(reminder["properties"]) == {"zone_id", "ppe_type", "message", "channel"}
    assert "track_ref" not in reminder["properties"]
    assert {
        "present",
        "anchor_bbox",
        "matched_detection_ids",
        "method",
        "quality_flags",
    } == set(association["properties"])
    assert set(observability["properties"]) == {"total", "components", "source"}
    assert "trigger_allowed" not in observability["properties"]


def test_m3_model_payload_schema_contains_no_system_authority_fields() -> None:
    payload = json.loads(expected_schema_files()["screening-model-payload.schema.json"])
    assert set(payload["properties"]) == {
        "violation_type",
        "evidence_class",
        "violation_probability",
        "frame_observations",
        "evidence_citations",
        "objective_claims",
        "prosecution_summary",
        "rationale_summary",
    }
    assert payload["additionalProperties"] is False
    assert "claim_id" not in payload["$defs"]["ObjectiveClaim"]["properties"]
    assert "citation_id" not in payload["$defs"]["EvidenceCitation"]["properties"]


def test_frame_bundle_schema_requires_reference_token_detection_ids() -> None:
    frame_bundle = json.loads(expected_schema_files()["frame-bundle.schema.json"])
    detection = frame_bundle["$defs"]["Detection"]

    assert detection["properties"]["detection_id"]["pattern"] == REFERENCE_TOKEN_PATTERN


def test_schema_check_detects_drift(tmp_path: Path) -> None:
    assert export_schemas(tmp_path, check=False) == []
    assert export_schemas(tmp_path, check=True) == []
    schema = tmp_path / "frame-ref.schema.json"
    schema.write_text("{}\n", encoding="utf-8", newline="\n")
    assert "schema drift: frame-ref.schema.json" in export_schemas(tmp_path, check=True)


def test_committed_schemas_match_models() -> None:
    project_root = Path(__file__).parents[2]
    assert export_schemas(project_root / "schemas", check=True) == []


def test_json_schema_validates_authored_resolved_and_fixture_artifacts() -> None:
    project_root = Path(__file__).parents[2]
    fixture_root = project_root / "tests" / "fixtures" / "m0"
    m2_fixture_root = project_root / "tests" / "fixtures" / "m2"
    schemas = {
        name: json.loads(content)
        for name, content in expected_schema_files().items()
        if name != "index.json"
    }

    authored = yaml.safe_load((project_root / "configs" / "demo.yaml").read_text(encoding="utf-8"))
    Draft202012Validator(schemas["app-config.schema.json"]).validate(authored)

    resolved = load_config(project_root / "configs" / "demo.yaml")
    Draft202012Validator(schemas["resolved-app-config.schema.json"]).validate(
        resolved.model_dump(mode="json")
    )

    fixtures = {
        "frame-ref.schema.json": ("frame-ref-ntsc.json", FrameRef),
        "frame-bundle.schema.json": ("frame-bundle-presence.json", FrameBundle),
        "candidate-event.schema.json": (
            m2_fixture_root / "candidate-event-presence.json",
            CandidateEvent,
        ),
        "safety-signal.schema.json": (
            "safety-signal-certified.json",
            SafetySignal,
        ),
        "run-manifest.schema.json": (
            m2_fixture_root / "run-manifest-fake.json",
            RunManifest,
        ),
    }
    for schema_name, (fixture_path, model) in fixtures.items():
        path = fixture_path if isinstance(fixture_path, Path) else fixture_root / fixture_path
        artifact = model.model_validate_json(path.read_text(encoding="utf-8"))
        Draft202012Validator(schemas[schema_name]).validate(artifact.model_dump(mode="json"))


def test_schema_and_python_agree_on_expressible_security_boundaries() -> None:
    project_root = Path(__file__).parents[2]
    authored = yaml.safe_load((project_root / "configs" / "demo.yaml").read_text(encoding="utf-8"))
    schema = json.loads(expected_schema_files()["app-config.schema.json"])
    validator = Draft202012Validator(schema)

    unsafe_workspace = deepcopy(authored)
    unsafe_workspace["run"]["workspace"] = "../outside"
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(unsafe_workspace)
    with pytest.raises(PydanticValidationError):
        AppConfig.model_validate(unsafe_workspace)

    external_full_frame = deepcopy(authored)
    profile = external_full_frame["providers"]["fake-screening"]
    profile.update(
        {
            "provider": "remote-fixture",
            "execution_location": "EXTERNAL",
            "transport": "HTTP",
            "allow_full_frame": True,
            "endpoint_env": "FIXTURE_ENDPOINT",
            "api_key_env": "FIXTURE_API_KEY",
        }
    )
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(external_full_frame)
    with pytest.raises(PydanticValidationError):
        AppConfig.model_validate(external_full_frame)

    external_unpriced = deepcopy(authored)
    profile = external_unpriced["providers"]["fake-screening"]
    profile.update(
        {
            "provider": "remote-fixture",
            "execution_location": "EXTERNAL",
            "transport": "HTTP",
            "allow_full_frame": False,
            "endpoint_env": "FIXTURE_ENDPOINT",
            "api_key_env": "FIXTURE_API_KEY",
        }
    )
    for field in (
        "pricing_currency",
        "input_cost_per_million_tokens",
        "output_cost_per_million_tokens",
    ):
        profile.pop(field)
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(external_unpriced)
    with pytest.raises(PydanticValidationError):
        AppConfig.model_validate(external_unpriced)
