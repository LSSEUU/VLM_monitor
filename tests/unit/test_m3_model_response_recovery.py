from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from labcourt.application.model_response_recovery import (
    ModelCallRecoveryCoordinator,
    ModelCallRecoveryError,
    ModelCallRecoveryErrorCode,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    PrivacyPolicy,
    ViolationType,
    VlmCallPurpose,
    VlmRole,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.model_response_recovery import (
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryReason,
)
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelCacheEntry,
    VLMCallRequest,
    VLMMediaRef,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.model_response_recovery import (
    ModelCallRecoveryCandidate,
    ModelCallRecoveryScan,
    ModelCallRecoveryScanAnomaly,
    ModelCallRecoveryScanFailureCode,
    ModelResponseRecoveryIdentity,
    PersistedModelCallStatus,
)
from labcourt.ports.vlm import ModelResponseStoreError, ModelResponseStoreFailureCode

RUN_ID = "run-01"
STARTED_AT = datetime(2026, 7, 28, 8, 0, tzinfo=UTC)
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64


def _request(case_id: str = "case-01") -> VLMRequest:
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
    return VLMRequest(
        run_id=RUN_ID,
        case_id=case_id,
        evidence_pack_id=SHA_6,
        evidence_pack_version=1,
        provider_profile="fake-v1",
        provider="fixture",
        model="fixture-vlm",
        revision="1",
        model_manifest_id=SHA_7,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id="screening-v1",
            role=VlmRole.SCREENING,
            template_sha256=SHA_1,
            output_schema_sha256=SHA_2,
            prompt_bundle_sha256=SHA_3,
            renderer_version="jinja-3-1",
        ),
        rendered_prompt_sha256=SHA_1,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        rule_summary="Apply the configured rule.",
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id),),
        objective_summary={},
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=100,
            max_output_tokens=128,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=1024,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=1024,
            timeout_seconds=5.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=SHA_2,
    )


def _response(request: VLMCallRequest, raw: bytes = b'{"ok":true}') -> VLMResponse:
    content_sha256 = hashlib.sha256(raw).hexdigest()
    response_id = derive_model_response_id(request.run_id, request.request_id, content_sha256)
    return VLMResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        purpose=request.purpose,
        attempt_index=0 if request.purpose == VlmCallPurpose.SCREENING else 1,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=len(raw),
        input_tokens=11,
        output_tokens=7,
        latency_ms=13,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _cached(request: VLMCallRequest, response: VLMResponse) -> CachedModelResponse:
    return CachedModelResponse(
        entry=ModelCacheEntry(
            run_id=request.run_id,
            case_id=request.case_id,
            evidence_pack_id=request.evidence_pack_id,
            evidence_pack_version=request.evidence_pack_version,
            cache_key=request.cache_key,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            response_id=response.response_id,
            response_content_sha256=response.content_sha256,
            model_manifest_id=request.model_manifest_id,
            prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
            output_schema_sha256=request.prompt_manifest.output_schema_sha256,
            manifest_id=request.manifest_id,
        ),
        response=response,
    )


def _active(
    request: VLMCallRequest,
    *,
    lease_expires_at: datetime | None = None,
    takeover_count: int = 2,
) -> ModelCallRecoveryCandidate:
    return ModelCallRecoveryCandidate(
        request=request,
        status=PersistedModelCallStatus.ACTIVE,
        lease_expires_at=lease_expires_at or STARTED_AT - timedelta(seconds=1),
        takeover_count=takeover_count,
    )


def _completed(
    request: VLMCallRequest,
    response: VLMResponse,
) -> ModelCallRecoveryCandidate:
    return ModelCallRecoveryCandidate(
        request=request,
        status=PersistedModelCallStatus.COMPLETED,
        lease_expires_at=STARTED_AT - timedelta(seconds=30),
        takeover_count=3,
        response_id=response.response_id,
    )


def _scan(
    candidates: tuple[ModelCallRecoveryCandidate, ...],
    *,
    anomalies: tuple[ModelCallRecoveryScanAnomaly, ...] = (),
    complete: bool = True,
    limit: int = 10,
) -> ModelCallRecoveryScan:
    return ModelCallRecoveryScan(
        run_id=RUN_ID,
        max_items=limit,
        candidates=tuple(sorted(candidates, key=lambda item: item.sort_key)),
        anomalies=tuple(sorted(anomalies, key=lambda item: item.sort_key)),
        complete=complete,
    )


class _Repository:
    def __init__(
        self,
        scan: ModelCallRecoveryScan,
        timeline: list[tuple[object, ...]],
    ) -> None:
        self.scan_result: ModelCallRecoveryScan | Exception = scan
        self.recovery_complete_result: CachedModelResponse | Exception | None = None
        self.get_result: CachedModelResponse | Exception | None = None
        self.raw_result: VLMResponse | Exception | None = None
        self.timeline = timeline

    def scan_model_call_recovery_candidates(
        self,
        run_id: str,
        max_items: int,
    ) -> ModelCallRecoveryScan:
        self.timeline.append(("scan", run_id, max_items))
        if isinstance(self.scan_result, Exception):
            raise self.scan_result
        return self.scan_result

    def complete_expired_model_call_from_recovery(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
        observed_lease_expires_at: datetime,
        observed_takeover_count: int,
    ) -> CachedModelResponse:
        self.timeline.append(
            (
                "recovery_complete",
                run_id,
                request.request_id,
                response.response_id,
                observed_lease_expires_at,
                observed_takeover_count,
            )
        )
        if isinstance(self.recovery_complete_result, Exception):
            raise self.recovery_complete_result
        assert isinstance(self.recovery_complete_result, CachedModelResponse)
        return self.recovery_complete_result

    def get(
        self,
        run_id: str,
        request: VLMCallRequest,
    ) -> CachedModelResponse | None:
        self.timeline.append(("get", run_id, request.request_id))
        if isinstance(self.get_result, Exception):
            raise self.get_result
        return self.get_result

    def load_raw_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> VLMResponse | None:
        self.timeline.append(("load_raw", run_id, request_id))
        if isinstance(self.raw_result, Exception):
            raise self.raw_result
        return self.raw_result


class _Responses:
    def __init__(self, timeline: list[tuple[object, ...]]) -> None:
        self.timeline = timeline
        self.probe_result: VLMResponse | None = None
        self.probe_error: Exception | None = None
        self.recover_result: VLMResponse | None = None
        self.recover_error: Exception | None = None
        self.verify_raw_result: VLMResponse | None = None
        self.verify_raw_error: Exception | None = None
        self.acknowledge_error: Exception | None = None

    def probe_recovery(self, request: VLMCallRequest) -> VLMResponse | None:
        self.timeline.append(("probe", request.request_id))
        if self.probe_error is not None:
            raise self.probe_error
        return self.probe_result

    def recover(self, request: VLMCallRequest) -> VLMResponse | None:
        self.timeline.append(("recover", request.request_id))
        if self.recover_error is not None:
            raise self.recover_error
        return self.recover_result

    def acknowledge(self, request: VLMCallRequest, response: VLMResponse) -> None:
        self.timeline.append(("acknowledge", request.request_id, response.response_id))
        if self.acknowledge_error is not None:
            raise self.acknowledge_error

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse:
        self.timeline.append(("verify_raw", run_id, request.request_id, response.response_id))
        if self.verify_raw_error is not None:
            raise self.verify_raw_error
        return self.verify_raw_result or response

    def verify(self, run_id: str, response: VLMResponse) -> VLMResponse:
        raise AssertionError((run_id, response.response_id))

    def read_bytes(self, run_id: str, response: VLMResponse, max_bytes: int) -> bytes:
        raise AssertionError((run_id, response.response_id, max_bytes))

    def read_json(self, run_id: str, response: VLMResponse, max_bytes: int) -> str:
        raise AssertionError((run_id, response.response_id, max_bytes))


def _coordinator(
    scan: ModelCallRecoveryScan,
) -> tuple[
    ModelCallRecoveryCoordinator,
    _Repository,
    _Responses,
    list[tuple[object, ...]],
]:
    timeline: list[tuple[object, ...]] = []
    repository = _Repository(scan, timeline)
    responses = _Responses(timeline)
    coordinator = ModelCallRecoveryCoordinator(
        repository,
        responses,
        limit=scan.max_items,
    )
    return coordinator, repository, responses, timeline


def test_incomplete_scan_reports_every_observation_and_performs_no_mutation() -> None:
    first = _request("case-01")
    second = _request("case-02")
    anomaly = ModelCallRecoveryScanAnomaly(
        run_id=RUN_ID,
        source_token="f" * 64,
        failure_code=ModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID,
    )
    scan = _scan((_active(first), _active(second)), anomalies=(anomaly,), complete=False, limit=3)
    coordinator, _, _, timeline = _coordinator(scan)

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.scanned == result.limit == 3
    assert result.scan_complete is False
    assert len(result.items) == 3
    by_authority = {item.request_id or item.source_token: item for item in result.items}
    assert by_authority[first.request_id].reason_code == (
        ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE
    )
    assert by_authority[second.request_id].reason_code == (
        ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE
    )
    assert by_authority[anomaly.source_token].reason_code == (
        ModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID
    )
    assert tuple(item.sort_key for item in result.items) == tuple(
        sorted(item.sort_key for item in result.items)
    )
    assert timeline == [("scan", RUN_ID, 3)]


def test_complete_scan_anomaly_suppresses_other_claim_recovery() -> None:
    request = _request()
    anomaly = ModelCallRecoveryScanAnomaly(
        run_id=RUN_ID,
        source_token="f" * 64,
        failure_code=ModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID,
    )
    coordinator, _, _, timeline = _coordinator(_scan((_active(request),), anomalies=(anomaly,)))

    result = coordinator.recover(RUN_ID, STARTED_AT)

    by_authority = {item.request_id or item.source_token: item for item in result.items}
    assert by_authority[request.request_id].reason_code == (
        ModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED
    )
    assert by_authority[anomaly.source_token].reason_code == (
        ModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID
    )
    assert timeline == [("scan", RUN_ID, 10)]


def test_active_unexpired_claim_is_deferred_without_journal_probe() -> None:
    request = _request()
    scan = _scan(
        (_active(request, lease_expires_at=STARTED_AT + timedelta(microseconds=1)),),
    )
    coordinator, _, _, timeline = _coordinator(scan)

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].disposition == ModelResponseRecoveryDisposition.DEFERRED
    assert result.items[0].reason_code == ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED
    assert timeline == [("scan", RUN_ID, 10)]


def test_active_expired_claim_without_journal_is_deferred_before_cas() -> None:
    request = _request()
    scan = _scan((_active(request, lease_expires_at=STARTED_AT),))
    coordinator, _, _, timeline = _coordinator(scan)

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].reason_code == ModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL
    assert timeline == [("scan", RUN_ID, 10), ("probe", request.request_id)]


def test_expired_journal_recovers_then_atomically_completes_verifies_and_acks() -> None:
    request = _request()
    response = _response(request)
    candidate = _active(request, lease_expires_at=STARTED_AT, takeover_count=4)
    coordinator, repository, responses, timeline = _coordinator(_scan((candidate,)))
    responses.probe_result = response
    responses.recover_result = response
    repository.recovery_complete_result = _cached(request, response)

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].disposition == ModelResponseRecoveryDisposition.ACKNOWLEDGED
    assert result.items[0].reason_code == ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED
    assert result.items[0].response_id == response.response_id
    assert result.items[0].response_content_sha256 == response.content_sha256
    assert timeline == [
        ("scan", RUN_ID, 10),
        ("probe", request.request_id),
        ("recover", request.request_id),
        (
            "recovery_complete",
            RUN_ID,
            request.request_id,
            response.response_id,
            candidate.lease_expires_at,
            candidate.takeover_count,
        ),
        ("verify_raw", RUN_ID, request.request_id, response.response_id),
        ("acknowledge", request.request_id, response.response_id),
    ]


def test_journal_acknowledged_after_probe_still_converges_verified_final() -> None:
    request = _request()
    response = _response(request)
    candidate = _active(request, lease_expires_at=STARTED_AT)
    coordinator, repository, responses, timeline = _coordinator(_scan((candidate,)))
    responses.probe_result = response
    responses.recover_result = None
    repository.recovery_complete_result = _cached(request, response)

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].disposition == ModelResponseRecoveryDisposition.ACKNOWLEDGED
    assert [entry[0] for entry in timeline] == [
        "scan",
        "probe",
        "recover",
        "recovery_complete",
        "verify_raw",
        "acknowledge",
    ]


def test_missing_during_acknowledgement_is_anomaly_if_final_raw_disappeared() -> None:
    request = _request()
    response = _response(request)
    coordinator, repository, responses, _ = _coordinator(_scan((_active(request),)))
    responses.probe_result = response
    responses.recover_result = response
    repository.recovery_complete_result = _cached(request, response)
    responses.acknowledge_error = ModelResponseStoreError(
        ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
    )
    raw_verifications = 0

    def verify_raw(
        run_id: str,
        candidate_request: VLMCallRequest,
        candidate_response: VLMResponse,
    ) -> VLMResponse:
        nonlocal raw_verifications
        del run_id, candidate_request
        raw_verifications += 1
        if raw_verifications == 2:
            raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND)
        return candidate_response

    responses.verify_raw_response = verify_raw  # type: ignore[method-assign]

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert result.items[0].reason_code == ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE


def test_lost_exact_completion_cas_does_not_acknowledge_journal() -> None:
    request = _request()
    response = _response(request)
    candidate = _active(request)
    coordinator, repository, responses, timeline = _coordinator(_scan((candidate,)))
    responses.probe_result = response
    responses.recover_result = response
    repository.recovery_complete_result = ConcurrentModification("changed")

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].reason_code == ModelResponseRecoveryReason.CLAIM_RACE_LOST
    assert [entry[0] for entry in timeline] == [
        "scan",
        "probe",
        "recover",
        "recovery_complete",
    ]


@pytest.mark.parametrize("journal_present", [False, True])
def test_completed_claim_physically_verifies_then_handles_exact_journal(
    journal_present: bool,
) -> None:
    request = _request()
    response = _response(request)
    coordinator, repository, responses, timeline = _coordinator(
        _scan((_completed(request, response),))
    )
    repository.get_result = _cached(request, response)
    repository.raw_result = response
    responses.probe_result = response if journal_present else None

    result = coordinator.recover(RUN_ID, STARTED_AT)

    expected_disposition = (
        ModelResponseRecoveryDisposition.ACKNOWLEDGED
        if journal_present
        else ModelResponseRecoveryDisposition.VERIFIED
    )
    expected_reason = (
        ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED
        if journal_present
        else ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT
    )
    assert result.items[0].disposition == expected_disposition
    assert result.items[0].reason_code == expected_reason
    expected_operations = ["scan", "get", "load_raw", "verify_raw", "probe"]
    if journal_present:
        expected_operations.append("acknowledge")
    assert [entry[0] for entry in timeline] == expected_operations


@pytest.mark.parametrize("failure_at", ["get", "raw_missing"])
def test_completed_database_observation_conflict_fails_closed(failure_at: str) -> None:
    request = _request()
    response = _response(request)
    coordinator, repository, _, timeline = _coordinator(_scan((_completed(request, response),)))
    repository.get_result = _cached(request, response)
    repository.raw_result = response
    if failure_at == "get":
        repository.get_result = ContractViolation("private database detail")
    else:
        repository.raw_result = None

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert result.items[0].reason_code == (
        ModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT
    )
    assert all(entry[0] not in {"probe", "acknowledge"} for entry in timeline)


def test_store_conflict_is_typed_and_prevents_database_completion() -> None:
    request = _request()
    coordinator, _, responses, timeline = _coordinator(_scan((_active(request),)))
    responses.probe_error = ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_CONFLICT)

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].reason_code == ModelResponseRecoveryReason.RESPONSE_CONFLICT
    assert [entry[0] for entry in timeline] == ["scan", "probe"]


def test_completed_physical_verification_failure_never_probes_or_acks_journal() -> None:
    request = _request()
    response = _response(request)
    coordinator, repository, responses, timeline = _coordinator(
        _scan((_completed(request, response),))
    )
    repository.get_result = _cached(request, response)
    repository.raw_result = response
    responses.verify_raw_error = ModelResponseStoreError(
        ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
    )

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].reason_code == (ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE)
    assert [entry[0] for entry in timeline] == ["scan", "get", "load_raw", "verify_raw"]


def test_acknowledgement_failure_is_journal_anomaly_not_success() -> None:
    request = _request()
    response = _response(request)
    coordinator, repository, responses, _ = _coordinator(_scan((_completed(request, response),)))
    repository.get_result = _cached(request, response)
    repository.raw_result = response
    responses.probe_result = response
    responses.acknowledge_error = ModelResponseStoreError(
        ModelResponseStoreFailureCode.WORKSPACE_REJECTED
    )

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].disposition == ModelResponseRecoveryDisposition.ANOMALY
    assert result.items[0].reason_code == ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE
    assert result.items[0].response_id is None


def test_exact_missing_journal_during_acknowledgement_is_idempotent_success() -> None:
    request = _request()
    response = _response(request)
    coordinator, repository, responses, timeline = _coordinator(_scan((_active(request),)))
    responses.probe_result = response
    responses.recover_result = response
    repository.recovery_complete_result = _cached(request, response)
    responses.acknowledge_error = ModelResponseStoreError(
        ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
    )

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].disposition == ModelResponseRecoveryDisposition.ACKNOWLEDGED
    assert result.items[0].reason_code == ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED
    assert result.items[0].response_id == response.response_id
    assert [entry[0] for entry in timeline] == [
        "scan",
        "probe",
        "recover",
        "recovery_complete",
        "verify_raw",
        "acknowledge",
        "verify_raw",
    ]


def test_mismatched_journal_response_fails_before_cas() -> None:
    request = _request()
    other_response = _response(_request("case-02"))
    coordinator, _, responses, timeline = _coordinator(_scan((_active(request),)))
    responses.probe_result = other_response

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].reason_code == (ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE)
    assert [entry[0] for entry in timeline] == ["scan", "probe"]


def test_invalid_completion_cache_observation_fails_closed() -> None:
    request = _request()
    response = _response(request)
    coordinator, repository, responses, timeline = _coordinator(_scan((_active(request),)))
    responses.probe_result = response
    responses.recover_result = response
    other_request = _request("case-02")
    repository.recovery_complete_result = _cached(other_request, _response(other_request))

    result = coordinator.recover(RUN_ID, STARTED_AT)

    assert result.items[0].reason_code == (
        ModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT
    )
    assert [entry[0] for entry in timeline] == [
        "scan",
        "probe",
        "recover",
        "recovery_complete",
    ]


def test_unexpected_dependency_failure_is_sanitized_and_has_no_implicit_cause() -> None:
    request = _request()
    coordinator, _, responses, timeline = _coordinator(_scan((_active(request),)))
    secret = r"C:\private\journal.json api-key=secret"
    responses.probe_error = RuntimeError(secret)

    with pytest.raises(ModelCallRecoveryError) as captured:
        coordinator.recover(RUN_ID, STARTED_AT)

    assert captured.value.code == ModelCallRecoveryErrorCode.UNEXPECTED_DEPENDENCY_FAILURE
    assert str(captured.value) == ModelCallRecoveryErrorCode.UNEXPECTED_DEPENDENCY_FAILURE.value
    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    assert [entry[0] for entry in timeline] == ["scan", "probe"]


def test_typed_scan_failure_is_sanitized() -> None:
    request = _request()
    coordinator, repository, _, timeline = _coordinator(_scan((_active(request),)))
    repository.scan_result = ContractViolation(r"C:\private\claims.sqlite")

    with pytest.raises(ModelCallRecoveryError) as captured:
        coordinator.recover(RUN_ID, STARTED_AT)

    assert captured.value.code == ModelCallRecoveryErrorCode.DATABASE_SCAN_FAILED
    assert "private" not in str(captured.value)
    assert timeline == [("scan", RUN_ID, 10)]


def test_result_is_frozen_and_contains_no_owner_or_provider_state() -> None:
    request = _request()
    coordinator, _, _, _ = _coordinator(
        _scan(
            (
                _active(
                    request,
                    lease_expires_at=STARTED_AT + timedelta(seconds=1),
                ),
            )
        )
    )

    result = coordinator.recover(RUN_ID, STARTED_AT)

    with pytest.raises(FrozenInstanceError):
        result.scanned = 2  # type: ignore[misc]
    assert not hasattr(result, "owner_token")
    assert not hasattr(result, "provider")


def test_recovery_identity_is_opaque_and_does_not_expose_repository_capabilities() -> None:
    request = _request()
    identity = ModelResponseRecoveryIdentity()
    timeline: list[tuple[object, ...]] = []
    repository = _Repository(_scan((_active(request),)), timeline)
    coordinator = ModelCallRecoveryCoordinator(
        repository,
        _Responses(timeline),
        recovery_identity=identity,
    )

    assert coordinator.recovery_identity is identity
    assert not hasattr(coordinator, "recovery_authority")
    for forbidden in (
        "claim_model_call",
        "complete_model_call",
        "commit_screening",
        "commit_verdict_review",
    ):
        assert not hasattr(coordinator.recovery_identity, forbidden)
