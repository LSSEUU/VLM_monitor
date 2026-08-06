from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    PrivacyPolicy,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
    MAX_MODEL_RESPONSE_RECOVERY_ITEMS,
    MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
    MaintenanceRecoveryReport,
    ModelResponseArtifactPhase,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryItem,
    ModelResponseRecoveryReason,
    ModelResponseRecoveryReport,
)
from labcourt.contracts.recovery import (
    RecoveryReport,
    StartupRecoveryReport,
    recovery_source_token,
)
from labcourt.contracts.screening import (
    VLMMediaRef,
    VLMRequest,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.model_response_artifacts import (
    ModelResponseArtifactCandidate,
    ModelResponseEmptyOperationCandidate,
)
from labcourt.ports.model_response_recovery import (
    ModelCallRecoveryCandidate,
    ModelCallRecoveryScan,
    ModelCallRecoveryScanAnomaly,
    ModelCallRecoveryScanFailureCode,
    PersistedModelCallStatus,
)

RUN_ID = "run-model-recovery-01"
STARTED_AT = datetime(2026, 7, 28, 1, tzinfo=UTC)
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64
SHA_8 = "8" * 64
SHA_9 = "9" * 64
STARTUP_SCHEMA_SHA256 = "45aa1799da31ab1a551e6a5e73824b9c532f1a02d2ed779fa5240938040a518b"


def _storage_report(*, run_id: str = RUN_ID) -> StartupRecoveryReport:
    return StartupRecoveryReport(
        run_id=run_id,
        started_at=STARTED_AT,
        orphan_report=RecoveryReport(
            run_id=run_id,
            not_modified_after=STARTED_AT - timedelta(minutes=5),
        ),
    )


def _model_report(
    *,
    items: tuple[ModelResponseRecoveryItem, ...] = (),
    claims_scanned: int = 0,
    claim_scan_complete: bool = True,
    artifacts_scanned: int = 0,
    artifact_scan_complete: bool = True,
    artifact_phase: ModelResponseArtifactPhase = ModelResponseArtifactPhase.COMPLETED,
) -> ModelResponseRecoveryReport:
    return ModelResponseRecoveryReport(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        artifact_not_modified_after=STARTED_AT - timedelta(minutes=5),
        claim_limit=max(1, claims_scanned),
        claims_scanned=claims_scanned,
        claim_scan_complete=claim_scan_complete,
        artifact_limit=max(1, artifacts_scanned),
        artifacts_scanned=artifacts_scanned,
        artifact_file_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        artifact_total_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
        artifact_bytes_scanned=0,
        artifact_scan_complete=artifact_scan_complete,
        artifact_phase=artifact_phase,
        items=items,
    )


def _claim_item(
    reason: ModelResponseRecoveryReason,
    disposition: ModelResponseRecoveryDisposition,
    *,
    response_id: str | None = None,
    response_content_sha256: str | None = None,
) -> ModelResponseRecoveryItem:
    return ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.MODEL_CALL,
        request_id=SHA_1,
        response_id=response_id,
        response_content_sha256=response_content_sha256,
        disposition=disposition,
        reason_code=reason,
    )


def _artifact_item(
    reason: ModelResponseRecoveryReason,
    disposition: ModelResponseRecoveryDisposition,
    *,
    area: ModelResponseRecoveryArea = ModelResponseRecoveryArea.FINAL_RESPONSE,
    content_sha256: str | None = None,
) -> ModelResponseRecoveryItem:
    return ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=area,
        source_token=SHA_2,
        content_sha256=content_sha256,
        disposition=disposition,
        reason_code=reason,
    )


def _request() -> VLMRequest:
    prompt = PromptManifest(
        prompt_id="screening-v1",
        role=VlmRole.SCREENING,
        template_sha256=SHA_1,
        output_schema_sha256=SHA_2,
        prompt_bundle_sha256=SHA_3,
        renderer_version="jinja-3-1",
    )
    media = VLMMediaRef(
        crop_id=SHA_4,
        media_sha256=SHA_5,
        local_path=f"{RUN_ID}/frames/{SHA_5}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=10,
        height=10,
    )
    budget = VlmCallBudget(
        max_images=1,
        max_input_pixels=100,
        max_output_tokens=64,
        pricing_currency="USD",
        input_cost_per_million_tokens=0.1,
        output_cost_per_million_tokens=0.2,
        max_estimated_cost=1.0,
        max_response_bytes=4096,
        max_json_depth=8,
        max_json_fields=64,
        max_string_chars=1024,
        timeout_seconds=5.0,
        claim_completion_grace_seconds=2.0,
    )
    return VLMRequest(
        run_id=RUN_ID,
        case_id="case-01",
        evidence_pack_id=SHA_6,
        evidence_pack_version=1,
        provider_profile="fake-screening",
        provider="fixture",
        model="fixture-vlm",
        revision="1.0.0",
        model_manifest_id=SHA_7,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=prompt,
        rendered_prompt_sha256=SHA_8,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        rule_summary="Apply the configured rule.",
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id),),
        objective_summary={},
        temperature=0.0,
        seed=7,
        budget=budget,
        manifest_id=SHA_9,
    )


def test_clean_model_and_maintenance_reports_round_trip_with_computed_status() -> None:
    model = _model_report()
    maintenance = MaintenanceRecoveryReport(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        storage_report=_storage_report(),
        model_response_report=model,
    )

    assert model.passed is True
    assert maintenance.passed is True
    assert (
        MaintenanceRecoveryReport.model_validate(maintenance.model_dump(mode="json")) == maintenance
    )


def test_serialized_status_claims_cannot_be_forged() -> None:
    model = _model_report()
    payload = model.model_dump(mode="json")
    with pytest.raises(ValidationError, match="attention conflicts"):
        ModelResponseRecoveryReport.model_validate({**payload, "requires_attention": True})
    with pytest.raises(ValidationError, match="passed conflicts"):
        ModelResponseRecoveryReport.model_validate({**payload, "passed": False})

    maintenance = MaintenanceRecoveryReport(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        storage_report=_storage_report(),
        model_response_report=model,
    )
    maintenance_payload = maintenance.model_dump(mode="json")
    with pytest.raises(ValidationError, match="passed conflicts"):
        MaintenanceRecoveryReport.model_validate({**maintenance_payload, "passed": False})


@pytest.mark.parametrize(
    "reason",
    (
        ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
        ModelResponseRecoveryReason.CLAIM_RACE_LOST,
    ),
)
def test_any_unresolved_active_claim_safely_defers_artifact_mutation(
    reason: ModelResponseRecoveryReason,
) -> None:
    item = _claim_item(reason, ModelResponseRecoveryDisposition.DEFERRED)
    report = _model_report(
        items=(item,),
        claims_scanned=1,
        artifacts_scanned=0,
        artifact_scan_complete=False,
        artifact_phase=ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM,
    )

    assert report.passed is True
    assert report.artifact_scan_complete is False


def test_expired_claim_without_journal_requires_attention() -> None:
    item = _claim_item(
        ModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL,
        ModelResponseRecoveryDisposition.DEFERRED,
    )
    report = _model_report(
        items=(item,),
        claims_scanned=1,
        artifact_scan_complete=False,
        artifact_phase=ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM,
    )

    assert report.requires_attention is True
    assert report.passed is False


def test_claim_or_artifact_anomaly_requires_integrity_suppression_and_attention() -> None:
    item = _claim_item(
        ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE,
        ModelResponseRecoveryDisposition.ANOMALY,
    )
    report = _model_report(
        items=(item,),
        claims_scanned=1,
        artifact_scan_complete=False,
        artifact_phase=ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE,
    )
    assert report.requires_attention is True

    with pytest.raises(ValidationError, match="typed anomaly must suppress"):
        _model_report(items=(item,), claims_scanned=1)


def test_incomplete_claim_inventory_suppresses_all_artifact_work() -> None:
    valid_but_deferred = _claim_item(
        ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE,
        ModelResponseRecoveryDisposition.DEFERRED,
    )
    malformed = ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.MODEL_CALL,
        source_token=SHA_2,
        disposition=ModelResponseRecoveryDisposition.ANOMALY,
        reason_code=ModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID,
    )
    items = tuple(sorted((valid_but_deferred, malformed), key=lambda item: item.sort_key))
    report = ModelResponseRecoveryReport(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        artifact_not_modified_after=STARTED_AT - timedelta(minutes=5),
        claim_limit=2,
        claims_scanned=2,
        claim_scan_complete=False,
        artifact_limit=1,
        artifacts_scanned=0,
        artifact_file_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        artifact_total_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
        artifact_bytes_scanned=0,
        artifact_scan_complete=False,
        artifact_phase=ModelResponseArtifactPhase.SUPPRESSED_CLAIM_SCAN_INCOMPLETE,
        items=items,
    )
    assert report.requires_attention is True

    with pytest.raises(ValidationError, match="incomplete claim scan"):
        ModelResponseRecoveryReport.model_validate(
            {
                **report.model_dump(mode="json"),
                "artifact_scan_complete": True,
            }
        )


def test_complete_claim_inventory_anomaly_suppresses_artifact_scan() -> None:
    item = _claim_item(
        ModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID,
        ModelResponseRecoveryDisposition.ANOMALY,
    )
    report = ModelResponseRecoveryReport(
        run_id=RUN_ID,
        started_at=STARTED_AT,
        artifact_not_modified_after=STARTED_AT - timedelta(minutes=5),
        claim_limit=1,
        claims_scanned=1,
        claim_scan_complete=True,
        artifact_limit=1,
        artifacts_scanned=0,
        artifact_file_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
        artifact_total_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
        artifact_bytes_scanned=0,
        artifact_scan_complete=False,
        artifact_phase=ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE,
        items=(item,),
    )
    assert report.requires_attention is True


def test_report_counts_must_match_typed_outcomes_and_booleans_are_strict() -> None:
    retained = _artifact_item(
        ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET,
        ModelResponseRecoveryDisposition.RETAINED,
        content_sha256=SHA_4,
    )
    with pytest.raises(ValidationError, match="artifact scan count"):
        _model_report(
            items=(retained,),
            artifacts_scanned=0,
            artifact_scan_complete=False,
            artifact_phase=ModelResponseArtifactPhase.BUDGET_EXHAUSTED,
        )

    payload = _model_report().model_dump(mode="json")
    with pytest.raises(ValidationError):
        ModelResponseRecoveryReport.model_validate({**payload, "claim_scan_complete": 1})


def test_recovery_item_matrix_excludes_paths_owner_tokens_and_response_bytes() -> None:
    completed = _claim_item(
        ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
        ModelResponseRecoveryDisposition.VERIFIED,
        response_id=derive_model_response_id(RUN_ID, SHA_1, SHA_2),
        response_content_sha256=SHA_2,
    )
    assert set(completed.model_dump(mode="json")) == {
        "run_id",
        "area",
        "request_id",
        "response_id",
        "response_content_sha256",
        "source_token",
        "content_sha256",
        "quarantine_relative_path",
        "disposition",
        "reason_code",
    }
    with pytest.raises(ValidationError, match="exactly one canonical or opaque"):
        ModelResponseRecoveryItem(
            run_id=RUN_ID,
            area=ModelResponseRecoveryArea.MODEL_CALL,
            request_id=SHA_1,
            source_token=SHA_2,
            disposition=ModelResponseRecoveryDisposition.DEFERRED,
            reason_code=ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
        )
    opaque = ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.MODEL_CALL,
        source_token=SHA_3,
        disposition=ModelResponseRecoveryDisposition.ANOMALY,
        reason_code=ModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID,
    )
    assert opaque.request_id is None
    with pytest.raises(ValidationError, match="requires a response id"):
        _claim_item(
            ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
            ModelResponseRecoveryDisposition.VERIFIED,
        )
    with pytest.raises(ValidationError, match="conflicts with its area"):
        _artifact_item(
            ModelResponseRecoveryReason.ORPHAN_STAGE_QUARANTINED,
            ModelResponseRecoveryDisposition.QUARANTINED,
        )


def test_quarantine_result_binds_source_content_and_controlled_destination() -> None:
    response_id = SHA_3
    content_sha256 = SHA_4
    source = f"{RUN_ID}/model_responses/{response_id}.json"
    item = ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.FINAL_RESPONSE,
        source_token=recovery_source_token(source),
        content_sha256=content_sha256,
        quarantine_relative_path=(
            f".quarantine/{RUN_ID}/model_responses/final/{response_id}-{content_sha256}.json"
        ),
        disposition=ModelResponseRecoveryDisposition.QUARANTINED,
        reason_code=ModelResponseRecoveryReason.ORPHAN_FINAL_QUARANTINED,
    )
    report = _model_report(
        items=(item,),
        artifacts_scanned=1,
    )
    assert report.passed is True

    with pytest.raises(ValidationError, match="source token"):
        ModelResponseRecoveryItem.model_validate(
            {**item.model_dump(mode="json"), "source_token": SHA_5}
        )
    with pytest.raises(ValidationError, match="content identity"):
        ModelResponseRecoveryItem.model_validate(
            {
                **item.model_dump(mode="json"),
                "quarantine_relative_path": (
                    f".quarantine/{RUN_ID}/model_responses/final/{response_id}-{SHA_5}.json"
                ),
            }
        )


def test_artifact_reason_area_matrix_is_explicit() -> None:
    with pytest.raises(ValidationError, match="conflicts with its area"):
        _artifact_item(
            ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT,
            ModelResponseRecoveryDisposition.RETAINED,
            area=ModelResponseRecoveryArea.JOURNAL,
        )
    with pytest.raises(ValidationError, match="conflicts with its area"):
        _artifact_item(
            ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE,
            ModelResponseRecoveryDisposition.ANOMALY,
            area=ModelResponseRecoveryArea.FINAL_RESPONSE,
        )


def test_file_and_aggregate_byte_limits_have_typed_attention_outcomes() -> None:
    oversized = _artifact_item(
        ModelResponseRecoveryReason.ARTIFACT_FILE_BYTES_EXCEEDED,
        ModelResponseRecoveryDisposition.ANOMALY,
        content_sha256=None,
    )
    oversized_report = _model_report(
        items=(oversized,),
        artifacts_scanned=1,
        artifact_phase=ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE,
    )
    assert oversized_report.requires_attention is True

    aggregate = _artifact_item(
        ModelResponseRecoveryReason.ARTIFACT_TOTAL_BYTES_EXHAUSTED,
        ModelResponseRecoveryDisposition.RETAINED,
        content_sha256=None,
    )
    aggregate_report = _model_report(
        items=(aggregate,),
        artifacts_scanned=1,
        artifact_scan_complete=False,
        artifact_phase=ModelResponseArtifactPhase.BUDGET_EXHAUSTED,
    )
    assert aggregate_report.requires_attention is True
    assert aggregate_report.passed is False


def test_empty_model_response_operation_cleanup_is_explicit_and_area_scoped() -> None:
    cleaned = _artifact_item(
        ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED,
        ModelResponseRecoveryDisposition.CLEANED,
        area=ModelResponseRecoveryArea.STAGED_RESPONSE,
    )
    report = _model_report(items=(cleaned,), artifacts_scanned=1)

    assert report.passed is True
    with pytest.raises(ValidationError, match="conflicts with its area"):
        _artifact_item(
            ModelResponseRecoveryReason.EMPTY_OPERATION_CLEANED,
            ModelResponseRecoveryDisposition.CLEANED,
            area=ModelResponseRecoveryArea.FINAL_RESPONSE,
        )
    with pytest.raises(ValidationError, match="empty operation"):
        ModelResponseRecoveryItem.model_validate(
            {**cleaned.model_dump(mode="json"), "content_sha256": SHA_4}
        )

    with pytest.raises(ValidationError, match="content-free age retention"):
        _artifact_item(
            ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET,
            ModelResponseRecoveryDisposition.RETAINED,
            area=ModelResponseRecoveryArea.FINAL_RESPONSE,
        )

    source = f".staging/{RUN_ID}/model-request-{SHA_3}"
    candidate = ModelResponseEmptyOperationCandidate(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.JOURNAL,
        authority_id=SHA_3,
        source_token=recovery_source_token(source),
    )
    assert candidate.source_token == recovery_source_token(source)
    with pytest.raises(ValueError, match="bind its controlled locator"):
        ModelResponseEmptyOperationCandidate(
            run_id=RUN_ID,
            area=ModelResponseRecoveryArea.JOURNAL,
            authority_id=SHA_3,
            source_token=SHA_4,
        )

    with pytest.raises(ValueError, match="bind its controlled locator"):
        ModelResponseArtifactCandidate(
            run_id=RUN_ID,
            area=ModelResponseRecoveryArea.FINAL_RESPONSE,
            authority_id=SHA_3,
            source_token=SHA_4,
            content_sha256=SHA_5,
            size_bytes=1,
        )


def test_incomplete_artifact_scan_uses_exact_candidate_suppression_reasons() -> None:
    wrong_budget_reason = _artifact_item(
        ModelResponseRecoveryReason.MINIMUM_AGE_NOT_MET,
        ModelResponseRecoveryDisposition.RETAINED,
        content_sha256=SHA_4,
    )
    with pytest.raises(ValidationError, match="incomplete clean artifact scan"):
        _model_report(
            items=(wrong_budget_reason,),
            artifacts_scanned=1,
            artifact_scan_complete=False,
            artifact_phase=ModelResponseArtifactPhase.BUDGET_EXHAUSTED,
        )

    candidate = _artifact_item(
        ModelResponseRecoveryReason.ARTIFACT_SCAN_INCOMPLETE,
        ModelResponseRecoveryDisposition.RETAINED,
    )
    anomaly = ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.JOURNAL,
        source_token=SHA_3,
        disposition=ModelResponseRecoveryDisposition.ANOMALY,
        reason_code=ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE,
    )
    items = tuple(sorted((candidate, anomaly), key=lambda item: item.sort_key))
    with pytest.raises(ValidationError, match="incomplete unsafe artifact scan"):
        _model_report(
            items=items,
            artifacts_scanned=2,
            artifact_scan_complete=False,
            artifact_phase=ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE,
        )


def test_incomplete_or_unsafe_artifact_scan_cannot_claim_quarantine() -> None:
    response_id = SHA_3
    source = f"{RUN_ID}/model_responses/{response_id}.json"
    quarantined = ModelResponseRecoveryItem(
        run_id=RUN_ID,
        area=ModelResponseRecoveryArea.FINAL_RESPONSE,
        source_token=recovery_source_token(source),
        content_sha256=SHA_4,
        quarantine_relative_path=(
            f".quarantine/{RUN_ID}/model_responses/final/{response_id}-{SHA_4}.json"
        ),
        disposition=ModelResponseRecoveryDisposition.QUARANTINED,
        reason_code=ModelResponseRecoveryReason.ORPHAN_FINAL_QUARANTINED,
    )
    with pytest.raises(ValidationError, match="complete safe claim and artifact scans"):
        _model_report(
            items=(quarantined,),
            artifacts_scanned=1,
            artifact_scan_complete=False,
            artifact_phase=ModelResponseArtifactPhase.BUDGET_EXHAUSTED,
        )

    suppressed = _artifact_item(
        ModelResponseRecoveryReason.ORPHAN_MUTATION_SUPPRESSED,
        ModelResponseRecoveryDisposition.RETAINED,
    )
    with pytest.raises(ValidationError, match="cannot be reported as complete"):
        _model_report(items=(suppressed,), artifacts_scanned=1)


def test_model_response_identity_is_derived_from_request_and_content() -> None:
    with pytest.raises(ValidationError, match="request/content bound"):
        _claim_item(
            ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
            ModelResponseRecoveryDisposition.VERIFIED,
            response_id=SHA_3,
            response_content_sha256=SHA_4,
        )


def test_maintenance_report_enforces_exact_scope_and_startup_time() -> None:
    with pytest.raises(ValidationError, match="belong to its run"):
        MaintenanceRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT,
            storage_report=_storage_report(run_id="other-run"),
            model_response_report=_model_report(),
        )
    with pytest.raises(ValidationError, match="share one startup time"):
        MaintenanceRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT + timedelta(seconds=1),
            storage_report=_storage_report(),
            model_response_report=_model_report(),
        )
    with pytest.raises(ValidationError, match="timezone-aware UTC"):
        ModelResponseRecoveryReport(
            run_id=RUN_ID,
            started_at=STARTED_AT.replace(tzinfo=None),
            artifact_not_modified_after=STARTED_AT - timedelta(minutes=5),
            claim_limit=1,
            claims_scanned=0,
            claim_scan_complete=True,
            artifact_limit=1,
            artifacts_scanned=0,
            artifact_file_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES,
            artifact_total_bytes_limit=MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES,
            artifact_bytes_scanned=0,
            artifact_scan_complete=True,
            artifact_phase=ModelResponseArtifactPhase.COMPLETED,
        )


def test_recovery_report_enforces_real_item_and_byte_hard_limits() -> None:
    payload = _model_report().model_dump(mode="json")
    with pytest.raises(ValidationError):
        ModelResponseRecoveryReport.model_validate(
            {**payload, "artifact_limit": MAX_MODEL_RESPONSE_RECOVERY_ITEMS + 1}
        )
    with pytest.raises(ValidationError):
        ModelResponseRecoveryReport.model_validate(
            {
                **payload,
                "artifact_file_bytes_limit": MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES + 1,
            }
        )
    with pytest.raises(ValidationError):
        ModelResponseRecoveryReport.model_validate(
            {
                **payload,
                "artifact_total_bytes_limit": MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES + 1,
            }
        )
    schema = ModelResponseRecoveryReport.model_json_schema(mode="serialization")
    properties = schema["properties"]
    assert properties["artifact_limit"]["maximum"] == MAX_MODEL_RESPONSE_RECOVERY_ITEMS
    assert properties["artifact_file_bytes_limit"]["maximum"] == (
        MAX_MODEL_RESPONSE_RECOVERY_FILE_BYTES
    )
    assert properties["artifact_total_bytes_limit"]["maximum"] == (
        MAX_MODEL_RESPONSE_RECOVERY_TOTAL_BYTES
    )
    assert {
        "artifact_file_bytes_limit",
        "artifact_total_bytes_limit",
        "artifact_bytes_scanned",
    } <= set(schema["required"])


def test_recovery_candidate_and_bounded_scan_are_canonical_and_stable() -> None:
    request = _request()
    active = ModelCallRecoveryCandidate(
        request=request,
        status=PersistedModelCallStatus.ACTIVE,
        lease_expires_at=STARTED_AT + timedelta(seconds=10),
        takeover_count=0,
    )
    scan = ModelCallRecoveryScan(
        run_id=RUN_ID,
        max_items=1,
        candidates=(active,),
        complete=False,
    )
    assert scan.claims_scanned == 1

    with pytest.raises(ValueError, match="cannot bind a response"):
        ModelCallRecoveryCandidate(
            request=request,
            status=PersistedModelCallStatus.ACTIVE,
            lease_expires_at=STARTED_AT,
            takeover_count=0,
            response_id=SHA_1,
        )
    with pytest.raises(ValueError, match="requires a SHA-256 response id"):
        ModelCallRecoveryCandidate(
            request=request,
            status=PersistedModelCallStatus.COMPLETED,
            lease_expires_at=STARTED_AT,
            takeover_count=0,
        )
    with pytest.raises(ValueError, match="full bounded page"):
        ModelCallRecoveryScan(
            run_id=RUN_ID,
            max_items=2,
            candidates=(active,),
            complete=False,
        )

    anomaly = ModelCallRecoveryScanAnomaly(
        run_id=RUN_ID,
        source_token=SHA_2,
        failure_code=ModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID,
    )
    anomaly_scan = ModelCallRecoveryScan(
        run_id=RUN_ID,
        max_items=1,
        candidates=(),
        anomalies=(anomaly,),
        complete=False,
    )
    assert anomaly_scan.claims_scanned == 1


def test_m2_startup_recovery_schema_remains_byte_frozen() -> None:
    schema = Path(__file__).parents[2] / "schemas" / "startup-recovery-report.schema.json"
    assert hashlib.sha256(schema.read_bytes()).hexdigest() == STARTUP_SCHEMA_SHA256
