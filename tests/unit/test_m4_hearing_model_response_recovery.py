from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest

from labcourt.application.hearing_model_response_recovery import (
    HearingModelCallRecoveryService,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import VlmRole
from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelRequest,
    HearingModelResponse,
    HearingModelResponseRecoveryDisposition,
    HearingModelResponseRecoveryReason,
    derive_hearing_model_response_id,
)
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.hearing_model_response_recovery import (
    HearingModelCallRecoveryCandidate,
    HearingModelCallRecoveryScan,
    HearingModelCallRecoveryScanAnomaly,
    HearingModelCallRecoveryScanFailureCode,
    HearingRecoveryResponseStore,
    PersistedHearingModelCallStatus,
)
from labcourt.ports.hearing_vlm import (
    HearingModelResponseStoreError,
    HearingModelResponseStoreFailureCode,
)
from tests.unit.test_m4_hearing_request import _prepare, _scenario

STARTED = datetime(2026, 7, 28, 8, 0, tzinfo=UTC)


def _request() -> HearingModelRequest:
    scenario = _scenario()
    return _prepare(scenario, VlmRole.PROSECUTOR).request


def _response(request: HearingModelRequest, raw: bytes = b'{"ok":true}') -> HearingModelResponse:
    content = hashlib.sha256(raw).hexdigest()
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content,
    )
    return HearingModelResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        role=request.role,
        attempt_index=request.attempt_index,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content,
        size_bytes=len(raw),
        input_tokens=2,
        output_tokens=3,
        latency_ms=4,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _cache(
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> HearingModelCacheEntry:
    return HearingModelCacheEntry(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        cache_key=request.cache_key,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        model_manifest_id=request.model_manifest_id,
        prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        manifest_id=request.manifest_id,
    )


class _Repository:
    def __init__(self, scan: HearingModelCallRecoveryScan) -> None:
        self.scan = scan
        self.completed: list[tuple[object, ...]] = []
        self.cache: HearingModelCacheEntry | None = None
        self.response: HearingModelResponse | None = None
        self.race = False

    def scan_hearing_model_call_recovery_candidates(
        self,
        run_id: str,
        max_items: int,
    ) -> HearingModelCallRecoveryScan:
        assert run_id == self.scan.run_id
        assert max_items == self.scan.max_items
        return self.scan

    def complete_expired_hearing_model_call_from_recovery(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
        observed_lease_expires_at: datetime,
        observed_takeover_count: int,
    ) -> HearingModelCacheEntry:
        self.completed.append(
            (
                run_id,
                request,
                response,
                observed_lease_expires_at,
                observed_takeover_count,
            )
        )
        if self.race:
            raise ConcurrentModification("test race")
        self.response = response
        self.cache = _cache(request, response)
        return self.cache

    def load_hearing_model_cache_entry_for_recovery(
        self,
        run_id: str,
        request: HearingModelRequest,
    ) -> HearingModelCacheEntry | None:
        assert run_id == request.run_id
        return self.cache

    def load_hearing_model_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> HearingModelResponse | None:
        assert self.response is None or self.response.run_id == run_id
        assert self.response is None or self.response.request_id == request_id
        return self.response


class _Responses:
    def __init__(self, response: HearingModelResponse | None) -> None:
        self.response = response
        self.verified_response = response
        self.probe_calls = 0
        self.recover_calls = 0
        self.verify_calls = 0
        self.ack_calls = 0
        self.probe_error: HearingModelResponseStoreError | None = None

    def probe_recovery(self, request: HearingModelRequest) -> HearingModelResponse | None:
        self.probe_calls += 1
        if self.probe_error is not None:
            raise self.probe_error
        return self.response

    def recover(self, request: HearingModelRequest) -> HearingModelResponse | None:
        self.recover_calls += 1
        return self.response

    def verify_raw_response(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelResponse:
        self.verify_calls += 1
        assert run_id == request.run_id
        assert response == self.verified_response
        return response

    def acknowledge(
        self,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> None:
        self.ack_calls += 1
        assert response == self.response
        self.response = None


def _active_scan(
    request: HearingModelRequest,
    *,
    expiry: datetime,
    limit: int = 10,
) -> HearingModelCallRecoveryScan:
    return HearingModelCallRecoveryScan(
        run_id=request.run_id,
        max_items=limit,
        candidates=(
            HearingModelCallRecoveryCandidate(
                request=request,
                status=PersistedHearingModelCallStatus.ACTIVE,
                lease_expires_at=expiry,
                takeover_count=2,
            ),
        ),
        complete=True,
    )


def test_expired_claim_converges_journal_cache_usage_and_ack_only() -> None:
    request = _request()
    response = _response(request)
    expiry = STARTED - timedelta(seconds=1)
    repository = _Repository(_active_scan(request, expiry=expiry))
    responses = _Responses(response)

    report = HearingModelCallRecoveryService(
        repository=repository,
        responses=responses,
        limit=10,
    ).recover(request.run_id, STARTED)

    assert report.passed
    assert report.items[0].reason_code == HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED
    assert report.items[0].disposition == HearingModelResponseRecoveryDisposition.ACKNOWLEDGED
    assert repository.completed == [(request.run_id, request, response, expiry, 2)]
    assert (responses.probe_calls, responses.recover_calls) == (1, 1)
    assert (responses.verify_calls, responses.ack_calls) == (1, 1)


def test_unexpired_claim_never_touches_journal_or_database_completion() -> None:
    request = _request()
    repository = _Repository(_active_scan(request, expiry=STARTED + timedelta(seconds=1)))
    responses = _Responses(_response(request))

    report = HearingModelCallRecoveryService(
        repository=repository,
        responses=responses,
        limit=10,
    ).recover(request.run_id, STARTED)

    assert report.items[0].reason_code == HearingModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED
    assert repository.completed == []
    assert (responses.probe_calls, responses.recover_calls, responses.ack_calls) == (0, 0, 0)


def test_incomplete_scan_suppresses_all_mutation() -> None:
    request = _request()
    candidates = tuple(
        HearingModelCallRecoveryCandidate(
            request=request.model_copy(update={"seed": request.seed + index}),
            status=PersistedHearingModelCallStatus.ACTIVE,
            lease_expires_at=STARTED - timedelta(seconds=1),
            takeover_count=0,
        )
        for index in range(2)
    )
    candidates = tuple(sorted(candidates, key=lambda item: item.sort_key))
    scan = HearingModelCallRecoveryScan(
        run_id=request.run_id,
        max_items=2,
        candidates=candidates,
        complete=False,
    )
    repository = _Repository(scan)
    responses = _Responses(_response(request))

    report = HearingModelCallRecoveryService(
        repository=repository,
        responses=responses,
        limit=2,
    ).recover(request.run_id, STARTED)

    assert not report.scan_complete
    assert {item.reason_code for item in report.items} == {
        HearingModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE
    }
    assert repository.completed == []
    assert responses.probe_calls == 0


def test_claim_anomaly_suppresses_other_valid_candidates() -> None:
    request = _request()
    anomaly = HearingModelCallRecoveryScanAnomaly(
        run_id=request.run_id,
        source_token=sha256_hex("malformed-hearing-claim"),
        failure_code=HearingModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID,
    )
    scan = HearingModelCallRecoveryScan(
        run_id=request.run_id,
        max_items=10,
        candidates=(
            HearingModelCallRecoveryCandidate(
                request=request,
                status=PersistedHearingModelCallStatus.ACTIVE,
                lease_expires_at=STARTED - timedelta(seconds=1),
                takeover_count=0,
            ),
        ),
        complete=True,
        anomalies=(anomaly,),
    )
    repository = _Repository(scan)
    responses = _Responses(_response(request))

    report = HearingModelCallRecoveryService(
        repository=repository,
        responses=responses,
        limit=10,
    ).recover(request.run_id, STARTED)

    assert report.requires_attention
    assert {item.reason_code for item in report.items} == {
        HearingModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID,
        HearingModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED,
    }
    assert repository.completed == []
    assert responses.probe_calls == 0


def test_completed_claim_with_absent_journal_is_only_verified() -> None:
    request = _request()
    response = _response(request)
    scan = HearingModelCallRecoveryScan(
        run_id=request.run_id,
        max_items=10,
        candidates=(
            HearingModelCallRecoveryCandidate(
                request=request,
                status=PersistedHearingModelCallStatus.COMPLETED,
                takeover_count=1,
                response_id=response.response_id,
            ),
        ),
        complete=True,
    )
    repository = _Repository(scan)
    repository.response = response
    repository.cache = _cache(request, response)
    responses = _Responses(None)
    responses.verified_response = response

    report = HearingModelCallRecoveryService(
        repository=repository,
        responses=responses,
        limit=10,
    ).recover(request.run_id, STARTED)

    assert report.items[0].reason_code == HearingModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT
    assert repository.completed == []
    assert responses.verify_calls == 1
    assert responses.ack_calls == 0


def test_claim_cas_race_never_acknowledges_the_journal() -> None:
    request = _request()
    response = _response(request)
    repository = _Repository(_active_scan(request, expiry=STARTED - timedelta(seconds=1)))
    repository.race = True
    responses = _Responses(response)

    report = HearingModelCallRecoveryService(
        repository=repository,
        responses=responses,
        limit=10,
    ).recover(request.run_id, STARTED)

    assert report.items[0].reason_code == HearingModelResponseRecoveryReason.CLAIM_RACE_LOST
    assert responses.ack_calls == 0


def test_tampered_journal_is_typed_and_never_committed() -> None:
    request = _request()
    repository = _Repository(_active_scan(request, expiry=STARTED - timedelta(seconds=1)))
    responses = _Responses(_response(request))
    responses.probe_error = HearingModelResponseStoreError(
        HearingModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE
    )

    report = HearingModelCallRecoveryService(
        repository=repository,
        responses=responses,
        limit=10,
    ).recover(request.run_id, STARTED)

    assert report.requires_attention
    assert (
        report.items[0].reason_code == HearingModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE
    )
    assert repository.completed == []


def test_recovery_store_protocol_exposes_no_publish_parse_or_case_progress() -> None:
    public = {name for name in HearingRecoveryResponseStore.__dict__ if not name.startswith("_")}
    assert public == {
        "probe_recovery",
        "recover",
        "verify_raw_response",
        "acknowledge",
    }
    assert not {"publish", "read_bytes", "parse", "execute_tool", "commit_case"} & public


@pytest.mark.parametrize("offset", [timedelta(hours=8), None])
def test_recovery_rejects_non_utc_start_time(offset: timedelta | None) -> None:
    request = _request()
    repository = _Repository(_active_scan(request, expiry=STARTED - timedelta(seconds=1)))
    responses = _Responses(_response(request))
    invalid = datetime(
        2026,
        7,
        28,
        8,
        0,
        tzinfo=None if offset is None else timezone(offset),
    )
    with pytest.raises(ValueError, match="UTC"):
        HearingModelCallRecoveryService(
            repository=repository,
            responses=responses,
            limit=10,
        ).recover(request.run_id, invalid)
