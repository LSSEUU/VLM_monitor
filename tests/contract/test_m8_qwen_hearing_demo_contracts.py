from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    ExecutionLocation,
    ProviderTransport,
    VlmRole,
)
from labcourt.contracts.m8_hearing_api import (
    M8HearingL5Status,
    M8HearingModelMode,
    M8HearingProviderSelectionV1,
    M8HearingStartRequestV1,
)
from labcourt.contracts.m8_qwen_hearing_demo import (
    M8QwenHearingDemoAttemptOutcome,
    M8QwenHearingDemoAttemptReceiptV1,
    M8QwenHearingDemoDeliveryState,
    M8QwenHearingDemoEvidenceRole,
    M8QwenHearingDemoEvidenceV1,
    M8QwenHearingDemoPreparationV1,
    M8QwenHearingProviderReceiptV1,
)
from labcourt.contracts.storage import ArtifactRef


def _sha(character: str) -> str:
    return character * 64


def _providers() -> tuple[M8HearingProviderSelectionV1, ...]:
    return tuple(
        M8HearingProviderSelectionV1(
            role=role,
            provider_profile=f"qwen-{role.value.lower()}",
            provider="openai-compatible",
            model="qwen3.7-plus-2026-05-26",
            revision="2026-05-26",
            model_manifest_id=character * 64,
            execution_location=ExecutionLocation.EXTERNAL,
            transport=ProviderTransport.HTTP,
        )
        for role, character in (
            (VlmRole.PROSECUTOR, "1"),
            (VlmRole.DEFENDER, "2"),
            (VlmRole.JUDGE, "3"),
        )
    )


def _evidence() -> tuple[M8QwenHearingDemoEvidenceV1, ...]:
    return (
        M8QwenHearingDemoEvidenceV1(
            role=M8QwenHearingDemoEvidenceRole.PRIMARY,
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=_sha("4")),
            source_file_sha256=_sha("5"),
            canonical_media_sha256=_sha("6"),
            prompt_sha256=_sha("7"),
            width=1024,
            height=768,
            size_bytes=1234,
            preauthorized_acquisition_catalog=False,
        ),
        M8QwenHearingDemoEvidenceV1(
            role=M8QwenHearingDemoEvidenceRole.SUPPLEMENTARY,
            artifact_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=_sha("8")),
            source_file_sha256=_sha("9"),
            canonical_media_sha256=_sha("a"),
            prompt_sha256=_sha("b"),
            width=1024,
            height=768,
            size_bytes=1235,
            preauthorized_acquisition_catalog=True,
        ),
    )


def _preparation() -> M8QwenHearingDemoPreparationV1:
    request = M8HearingStartRequestV1(
        run_id="m8-qwen-demo-run",
        case_id="m8-qwen-demo-case",
        source_status=CaseStatus.ESCALATED,
        source_screening_id=_sha("c"),
        source_evidence_pack_id=_sha("d"),
        source_evidence_pack_version=1,
        model_mode=M8HearingModelMode.OPENAI_COMPATIBLE_QWEN,
        request_manifest_id=_sha("e"),
    )
    return M8QwenHearingDemoPreparationV1(
        run_id=request.run_id,
        case_id=request.case_id,
        config_sha256=_sha("f"),
        manifest_id=request.request_manifest_id,
        provider_selections=_providers(),
        evidence=_evidence(),
        start_request=request,
    )


def test_preparation_freezes_synthetic_gray_case_and_real_role_bindings() -> None:
    preparation = _preparation()

    assert preparation.screening_probability == 0.5
    assert preparation.case_status == CaseStatus.ESCALATED
    assert preparation.machine_weak_labels_are_ground_truth is False
    assert preparation.evidence[1].preauthorized_acquisition_catalog is True
    assert preparation.start_request.clear_case_forcing_permitted is False
    assert len({item.provider_profile for item in preparation.provider_selections}) == 3

    forged = deepcopy(preparation.model_dump(mode="json"))
    forged["preparation_id"] = _sha("0")
    with pytest.raises(ValidationError):
        M8QwenHearingDemoPreparationV1.model_validate(forged)


def test_attempt_receipt_distinguishes_completion_configuration_and_recovery() -> None:
    preparation = _preparation()
    responses = (_sha("3"), _sha("4"), _sha("5"))
    provider_receipts = tuple(
        M8QwenHearingProviderReceiptV1(
            role=role,
            provider_profile=f"qwen-{role.value.lower()}",
            provider_response_id=f"chatcmpl-{role.value.lower()}",
            labcourt_response_id=response_id,
            raw_response_ref=f"m8-qwen-demo-run/model_responses/{response_id}.json",
            content_sha256=character * 64,
            input_tokens=10,
            output_tokens=20,
            latency_ms=30,
            estimated_cost_cny=0.00018,
        )
        for role, response_id, character in zip(
            (VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE),
            responses,
            ("6", "7", "8"),
            strict=True,
        )
    )
    completed = M8QwenHearingDemoAttemptReceiptV1(
        preparation_id=preparation.preparation_id,
        attempted_at=datetime(2026, 8, 13, tzinfo=UTC),
        outcome=M8QwenHearingDemoAttemptOutcome.COMPLETED,
        delivery_state=M8QwenHearingDemoDeliveryState.COMPLETED,
        api_http_status=200,
        view_id=_sha("1"),
        hearing_session_id=_sha("2"),
        role_response_ids=responses,
        provider_receipts=provider_receipts,
        l5_status=M8HearingL5Status.PASSED,
        external_call_attempted=True,
    )
    configuration = M8QwenHearingDemoAttemptReceiptV1(
        preparation_id=preparation.preparation_id,
        attempted_at=datetime(2026, 8, 13, tzinfo=UTC),
        outcome=M8QwenHearingDemoAttemptOutcome.CONFIGURATION_FAILED,
        delivery_state=M8QwenHearingDemoDeliveryState.DEFINITELY_NOT_SENT,
        reason_code="API_KEY_ENV_MISSING",
        l5_status=M8HearingL5Status.NOT_RUN,
        external_call_attempted=False,
    )
    recovery = M8QwenHearingDemoAttemptReceiptV1(
        preparation_id=preparation.preparation_id,
        attempted_at=datetime(2026, 8, 13, tzinfo=UTC),
        outcome=M8QwenHearingDemoAttemptOutcome.RECOVERY_REQUIRED,
        delivery_state=M8QwenHearingDemoDeliveryState.UNKNOWN,
        api_http_status=400,
        reason_code="UNKNOWN_DELIVERY",
        view_id=_sha("6"),
        hearing_session_id=_sha("7"),
        role_response_ids=(_sha("8"),),
        l5_status=M8HearingL5Status.NOT_RUN,
        external_call_attempted=True,
    )
    provider_receipt_failure = M8QwenHearingDemoAttemptReceiptV1(
        preparation_id=preparation.preparation_id,
        attempted_at=datetime(2026, 8, 13, tzinfo=UTC),
        outcome=M8QwenHearingDemoAttemptOutcome.AUDITABLE_FAILURE,
        delivery_state=M8QwenHearingDemoDeliveryState.COMPLETED,
        api_http_status=200,
        reason_code="PROVIDER_RECEIPT_INCOMPLETE",
        view_id=_sha("1"),
        hearing_session_id=_sha("2"),
        role_response_ids=responses,
        l5_status=M8HearingL5Status.PASSED,
        external_call_attempted=True,
    )

    assert completed.silent_fallback_used is False
    assert configuration.external_call_attempted is False
    assert recovery.delivery_state == M8QwenHearingDemoDeliveryState.UNKNOWN
    assert provider_receipt_failure.delivery_state == M8QwenHearingDemoDeliveryState.COMPLETED

    forged = deepcopy(configuration.model_dump(mode="json"))
    forged["external_call_attempted"] = True
    with pytest.raises(ValidationError):
        M8QwenHearingDemoAttemptReceiptV1.model_validate(forged)
