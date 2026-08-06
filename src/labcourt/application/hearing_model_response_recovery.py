"""Provider-free convergence of durable M4 hearing response journals."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelRequest,
    HearingModelResponse,
)
from labcourt.contracts.hearing_recovery import (
    MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS,
    HearingModelResponseRecoveryDisposition,
    HearingModelResponseRecoveryItem,
    HearingModelResponseRecoveryReason,
    HearingModelResponseRecoveryReport,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, LabCourtError
from labcourt.ports.hearing_model_response_recovery import (
    HearingModelCallRecoveryCandidate,
    HearingModelCallRecoveryRepository,
    HearingModelCallRecoveryScan,
    HearingModelCallRecoveryScanAnomaly,
    HearingModelCallRecoveryScanFailureCode,
    HearingModelResponseRecoveryIdentity,
    HearingRecoveryResponseStore,
    PersistedHearingModelCallStatus,
)
from labcourt.ports.hearing_vlm import (
    HearingModelResponseStoreError,
    HearingModelResponseStoreFailureCode,
)


class HearingModelCallRecoveryErrorCode(StrEnum):
    DATABASE_SCAN_FAILED = "DATABASE_SCAN_FAILED"
    INVALID_SCAN_RESULT = "INVALID_SCAN_RESULT"
    UNEXPECTED_DEPENDENCY_FAILURE = "UNEXPECTED_DEPENDENCY_FAILURE"


class HearingModelCallRecoveryError(RuntimeError):
    """Sanitized maintenance failure without dependency text or raw content."""

    def __init__(self, code: HearingModelCallRecoveryErrorCode) -> None:
        if not isinstance(code, HearingModelCallRecoveryErrorCode):
            raise TypeError("code must be a HearingModelCallRecoveryErrorCode")
        self.code = code
        super().__init__(code.value)


class HearingModelCallRecoveryService:
    """Converge journal/claim acknowledgement and nothing else."""

    __slots__ = ("_identity", "_limit", "_repository", "_responses")

    def __init__(
        self,
        *,
        repository: HearingModelCallRecoveryRepository,
        responses: HearingRecoveryResponseStore,
        limit: int = MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS,
        recovery_identity: HearingModelResponseRecoveryIdentity | None = None,
    ) -> None:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS
        ):
            raise ValueError("hearing model recovery limit is invalid")
        for dependency, methods, name in (
            (
                repository,
                (
                    "scan_hearing_model_call_recovery_candidates",
                    "complete_expired_hearing_model_call_from_recovery",
                    "load_hearing_model_cache_entry_for_recovery",
                    "load_hearing_model_response_for_request",
                ),
                "repository",
            ),
            (
                responses,
                ("probe_recovery", "recover", "verify_raw_response", "acknowledge"),
                "responses",
            ),
        ):
            for method in methods:
                if not callable(getattr(dependency, method, None)):
                    raise TypeError(f"{name} does not implement {method}")
        if recovery_identity is not None and not isinstance(
            recovery_identity, HearingModelResponseRecoveryIdentity
        ):
            raise TypeError("recovery_identity must be an opaque M4 recovery identity")
        self._repository = repository
        self._responses = responses
        self._limit = limit
        self._identity = recovery_identity or HearingModelResponseRecoveryIdentity()

    @property
    def recovery_identity(self) -> HearingModelResponseRecoveryIdentity:
        return self._identity

    def recover(
        self,
        run_id: str,
        started_at: datetime,
    ) -> HearingModelResponseRecoveryReport:
        controlled_run_id = require_reference_token(run_id, "hearing recovery run reference")
        self._require_utc(started_at)
        scan = self._scan(controlled_run_id)
        items = [self._scan_anomaly_item(item) for item in scan.anomalies]
        if not scan.complete:
            items.extend(
                self._request_item(
                    candidate,
                    disposition=HearingModelResponseRecoveryDisposition.DEFERRED,
                    reason=HearingModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE,
                )
                for candidate in scan.candidates
            )
        elif scan.anomalies:
            items.extend(
                self._request_item(
                    candidate,
                    disposition=HearingModelResponseRecoveryDisposition.DEFERRED,
                    reason=HearingModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED,
                )
                for candidate in scan.candidates
            )
        else:
            items.extend(
                self._recover_candidate(candidate, started_at) for candidate in scan.candidates
            )
        try:
            return HearingModelResponseRecoveryReport(
                run_id=controlled_run_id,
                started_at=started_at,
                claim_limit=self._limit,
                claims_scanned=scan.claims_scanned,
                scan_complete=scan.complete,
                items=tuple(sorted(items, key=lambda item: item.sort_key)),
            )
        except (TypeError, ValueError):
            raise HearingModelCallRecoveryError(
                HearingModelCallRecoveryErrorCode.INVALID_SCAN_RESULT
            ) from None

    def _scan(self, run_id: str) -> HearingModelCallRecoveryScan:
        try:
            scan = self._repository.scan_hearing_model_call_recovery_candidates(
                run_id,
                self._limit,
            )
        except LabCourtError:
            raise HearingModelCallRecoveryError(
                HearingModelCallRecoveryErrorCode.DATABASE_SCAN_FAILED
            ) from None
        except Exception:
            self._raise_unexpected()
        if (
            not isinstance(scan, HearingModelCallRecoveryScan)
            or scan.run_id != run_id
            or scan.max_items != self._limit
        ):
            raise HearingModelCallRecoveryError(
                HearingModelCallRecoveryErrorCode.INVALID_SCAN_RESULT
            )
        return scan

    def _recover_candidate(
        self,
        candidate: HearingModelCallRecoveryCandidate,
        started_at: datetime,
    ) -> HearingModelResponseRecoveryItem:
        if candidate.status == PersistedHearingModelCallStatus.COMPLETED:
            return self._recover_completed(candidate)
        if candidate.status != PersistedHearingModelCallStatus.ACTIVE:
            return self._database_anomaly(candidate)
        expiry = candidate.lease_expires_at
        if expiry is None:
            return self._database_anomaly(candidate)
        if expiry > started_at:
            return self._request_item(
                candidate,
                disposition=HearingModelResponseRecoveryDisposition.DEFERRED,
                reason=HearingModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
            )

        probed = self._probe(candidate)
        if isinstance(probed, HearingModelResponseRecoveryItem):
            return probed
        if probed is None:
            return self._request_item(
                candidate,
                disposition=HearingModelResponseRecoveryDisposition.DEFERRED,
                reason=HearingModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL,
            )
        recovered = self._recover_response(candidate, probed)
        if isinstance(recovered, HearingModelResponseRecoveryItem):
            return recovered
        try:
            cached = self._repository.complete_expired_hearing_model_call_from_recovery(
                candidate.request.run_id,
                candidate.request,
                recovered,
                expiry,
                candidate.takeover_count,
            )
        except ConcurrentModification:
            return self._request_item(
                candidate,
                disposition=HearingModelResponseRecoveryDisposition.DEFERRED,
                reason=HearingModelResponseRecoveryReason.CLAIM_RACE_LOST,
            )
        except LabCourtError:
            return self._database_anomaly(candidate)
        except Exception:
            self._raise_unexpected()
        if not self._cache_matches(candidate.request, recovered, cached):
            return self._database_anomaly(candidate)
        verified = self._verify(candidate, recovered)
        if isinstance(verified, HearingModelResponseRecoveryItem):
            return verified
        acknowledged = self._acknowledge(candidate, recovered)
        if acknowledged is not None:
            return acknowledged
        return self._terminal_item(
            candidate,
            recovered,
            disposition=HearingModelResponseRecoveryDisposition.ACKNOWLEDGED,
            reason=HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED,
        )

    def _recover_completed(
        self,
        candidate: HearingModelCallRecoveryCandidate,
    ) -> HearingModelResponseRecoveryItem:
        try:
            cached = self._repository.load_hearing_model_cache_entry_for_recovery(
                candidate.request.run_id,
                candidate.request,
            )
            response = self._repository.load_hearing_model_response_for_request(
                candidate.request.run_id,
                candidate.request.request_id,
            )
        except LabCourtError:
            return self._database_anomaly(candidate)
        except Exception:
            self._raise_unexpected()
        if (
            type(response) is not HearingModelResponse
            or response.response_id != candidate.response_id
            or not self._response_matches(candidate.request, response)
            or not self._cache_matches(candidate.request, response, cached)
        ):
            return self._database_anomaly(candidate)
        verified = self._verify(candidate, response)
        if isinstance(verified, HearingModelResponseRecoveryItem):
            return verified
        probed = self._probe(candidate)
        if isinstance(probed, HearingModelResponseRecoveryItem):
            return probed
        if probed is None:
            return self._terminal_item(
                candidate,
                response,
                disposition=HearingModelResponseRecoveryDisposition.VERIFIED,
                reason=HearingModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
            )
        if probed != response:
            return self._response_anomaly(candidate)
        acknowledged = self._acknowledge(candidate, response)
        if acknowledged is not None:
            return acknowledged
        return self._terminal_item(
            candidate,
            response,
            disposition=HearingModelResponseRecoveryDisposition.ACKNOWLEDGED,
            reason=HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED,
        )

    def _probe(
        self,
        candidate: HearingModelCallRecoveryCandidate,
    ) -> HearingModelResponse | HearingModelResponseRecoveryItem | None:
        try:
            response = self._responses.probe_recovery(candidate.request)
        except HearingModelResponseStoreError as error:
            return self._store_anomaly(candidate, error)
        except Exception:
            self._raise_unexpected()
        if response is None:
            return None
        if type(response) is not HearingModelResponse or not self._response_matches(
            candidate.request, response
        ):
            return self._response_anomaly(candidate)
        return response

    def _recover_response(
        self,
        candidate: HearingModelCallRecoveryCandidate,
        probed: HearingModelResponse,
    ) -> HearingModelResponse | HearingModelResponseRecoveryItem:
        try:
            recovered = self._responses.recover(candidate.request)
        except HearingModelResponseStoreError as error:
            return self._store_anomaly(candidate, error)
        except Exception:
            self._raise_unexpected()
        if recovered is None:
            return probed
        if (
            type(recovered) is not HearingModelResponse
            or recovered != probed
            or not self._response_matches(candidate.request, recovered)
        ):
            return self._response_anomaly(candidate)
        return recovered

    def _verify(
        self,
        candidate: HearingModelCallRecoveryCandidate,
        response: HearingModelResponse,
    ) -> HearingModelResponse | HearingModelResponseRecoveryItem:
        try:
            verified = self._responses.verify_raw_response(
                candidate.request.run_id,
                candidate.request,
                response,
            )
        except HearingModelResponseStoreError as error:
            return self._store_anomaly(candidate, error)
        except Exception:
            self._raise_unexpected()
        if type(verified) is not HearingModelResponse or verified != response:
            return self._response_anomaly(candidate)
        return verified

    def _acknowledge(
        self,
        candidate: HearingModelCallRecoveryCandidate,
        response: HearingModelResponse,
    ) -> HearingModelResponseRecoveryItem | None:
        try:
            self._responses.acknowledge(candidate.request, response)
        except HearingModelResponseStoreError as error:
            if error.reason_code == HearingModelResponseStoreFailureCode.RESPONSE_NOT_FOUND:
                verified = self._verify(candidate, response)
                return verified if isinstance(verified, HearingModelResponseRecoveryItem) else None
            return self._store_anomaly(candidate, error, acknowledging=True)
        except Exception:
            self._raise_unexpected()
        return None

    @staticmethod
    def _response_matches(
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> bool:
        fields = (
            "run_id",
            "case_id",
            "hearing_session_id",
            "round_index",
            "prior_acquisition_rounds",
            "prior_rework_rounds",
            "current_evidence_pack_id",
            "current_evidence_pack_version",
            "role",
            "attempt_index",
            "request_id",
            "request_sha256",
            "cache_key",
            "model_manifest_id",
            "manifest_id",
        )
        return all(getattr(response, field) == getattr(request, field) for field in fields)

    @classmethod
    def _cache_matches(
        cls,
        request: HearingModelRequest,
        response: HearingModelResponse,
        cached: object,
    ) -> bool:
        if type(cached) is not HearingModelCacheEntry:
            return False
        expected = HearingModelCacheEntry(
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
        return cached == expected and cls._response_matches(request, response)

    @staticmethod
    def _scan_anomaly_item(
        anomaly: HearingModelCallRecoveryScanAnomaly,
    ) -> HearingModelResponseRecoveryItem:
        reason = {
            HearingModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID: (
                HearingModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID
            ),
            HearingModelCallRecoveryScanFailureCode.DATABASE_OBSERVATION_CONFLICT: (
                HearingModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT
            ),
        }[anomaly.failure_code]
        return HearingModelResponseRecoveryItem(
            run_id=anomaly.run_id,
            source_token=anomaly.source_token,
            disposition=HearingModelResponseRecoveryDisposition.ANOMALY,
            reason_code=reason,
        )

    @staticmethod
    def _request_item(
        candidate: HearingModelCallRecoveryCandidate,
        *,
        disposition: HearingModelResponseRecoveryDisposition,
        reason: HearingModelResponseRecoveryReason,
    ) -> HearingModelResponseRecoveryItem:
        return HearingModelResponseRecoveryItem(
            run_id=candidate.request.run_id,
            request_id=candidate.request.request_id,
            disposition=disposition,
            reason_code=reason,
        )

    @staticmethod
    def _terminal_item(
        candidate: HearingModelCallRecoveryCandidate,
        response: HearingModelResponse,
        *,
        disposition: HearingModelResponseRecoveryDisposition,
        reason: HearingModelResponseRecoveryReason,
    ) -> HearingModelResponseRecoveryItem:
        return HearingModelResponseRecoveryItem(
            run_id=candidate.request.run_id,
            request_id=candidate.request.request_id,
            response_id=response.response_id,
            response_content_sha256=response.content_sha256,
            disposition=disposition,
            reason_code=reason,
        )

    @classmethod
    def _database_anomaly(
        cls,
        candidate: HearingModelCallRecoveryCandidate,
    ) -> HearingModelResponseRecoveryItem:
        return cls._request_item(
            candidate,
            disposition=HearingModelResponseRecoveryDisposition.ANOMALY,
            reason=HearingModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT,
        )

    @classmethod
    def _response_anomaly(
        cls,
        candidate: HearingModelCallRecoveryCandidate,
    ) -> HearingModelResponseRecoveryItem:
        return cls._request_item(
            candidate,
            disposition=HearingModelResponseRecoveryDisposition.ANOMALY,
            reason=HearingModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE,
        )

    @classmethod
    def _store_anomaly(
        cls,
        candidate: HearingModelCallRecoveryCandidate,
        error: HearingModelResponseStoreError,
        *,
        acknowledging: bool = False,
    ) -> HearingModelResponseRecoveryItem:
        if error.reason_code == HearingModelResponseStoreFailureCode.RESPONSE_CONFLICT:
            reason = HearingModelResponseRecoveryReason.RESPONSE_CONFLICT
        elif acknowledging:
            reason = HearingModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE
        else:
            reason = HearingModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE
        return cls._request_item(
            candidate,
            disposition=HearingModelResponseRecoveryDisposition.ANOMALY,
            reason=reason,
        )

    @staticmethod
    def _require_utc(value: datetime) -> None:
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("hearing recovery start time must use timezone-aware UTC")

    @staticmethod
    def _raise_unexpected() -> NoReturn:
        raise HearingModelCallRecoveryError(
            HearingModelCallRecoveryErrorCode.UNEXPECTED_DEPENDENCY_FAILURE
        ) from None


__all__ = [
    "HearingModelCallRecoveryError",
    "HearingModelCallRecoveryErrorCode",
    "HearingModelCallRecoveryService",
]
