"""Provider-free recovery of durable M3 model-call claims."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.enums import VlmCallPurpose
from labcourt.contracts.model_response_recovery import (
    MAX_MODEL_CALL_RECOVERY_ITEMS,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryItem,
    ModelResponseRecoveryReason,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    CachedModelResponse,
    VLMCallRequest,
    VLMResponse,
)
from labcourt.exceptions import ConcurrentModification, LabCourtError
from labcourt.ports.model_response_recovery import (
    ModelCallRecoveryCandidate,
    ModelCallRecoveryRepository,
    ModelCallRecoveryScan,
    ModelCallRecoveryScanAnomaly,
    ModelCallRecoveryScanFailureCode,
    ModelResponseRecoveryIdentity,
    PersistedModelCallStatus,
)
from labcourt.ports.vlm import (
    ModelResponseStore,
    ModelResponseStoreError,
    ModelResponseStoreFailureCode,
)


class ModelCallRecoveryErrorCode(StrEnum):
    DATABASE_SCAN_FAILED = "DATABASE_SCAN_FAILED"
    INVALID_SCAN_RESULT = "INVALID_SCAN_RESULT"
    UNEXPECTED_DEPENDENCY_FAILURE = "UNEXPECTED_DEPENDENCY_FAILURE"


class ModelCallRecoveryError(RuntimeError):
    """Sanitized orchestration failure without dependency messages or secrets."""

    def __init__(self, code: ModelCallRecoveryErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class ModelCallRecoveryResult:
    """Internal bounded result consumed by the later maintenance composition root."""

    run_id: str
    started_at: datetime
    limit: int
    scanned: int
    scan_complete: bool
    items: tuple[ModelResponseRecoveryItem, ...]

    def __post_init__(self) -> None:
        require_reference_token(self.run_id, "model call recovery result run reference")
        if (
            not isinstance(self.started_at, datetime)
            or self.started_at.tzinfo is None
            or self.started_at.utcoffset() is None
            or self.started_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("model call recovery result time must use timezone-aware UTC")
        if (
            not isinstance(self.limit, int)
            or isinstance(self.limit, bool)
            or not 1 <= self.limit <= MAX_MODEL_CALL_RECOVERY_ITEMS
        ):
            raise ValueError("model call recovery result limit is invalid")
        if (
            not isinstance(self.scanned, int)
            or isinstance(self.scanned, bool)
            or not 0 <= self.scanned <= self.limit
        ):
            raise ValueError("model call recovery result scan count is invalid")
        if type(self.scan_complete) is not bool:
            raise TypeError("model call recovery result completion flag must be a boolean")
        if not isinstance(self.items, tuple) or any(
            not isinstance(item, ModelResponseRecoveryItem) for item in self.items
        ):
            raise TypeError("model call recovery result items must be a typed tuple")
        if len(self.items) != self.scanned:
            raise ValueError("model call recovery result must cover every scan observation")
        if any(
            item.run_id != self.run_id or item.area != ModelResponseRecoveryArea.MODEL_CALL
            for item in self.items
        ):
            raise ValueError("model call recovery result items are outside its run or area")
        keys = tuple(item.sort_key for item in self.items)
        authorities = tuple(key[:2] for key in keys)
        if len(authorities) != len(set(authorities)):
            raise ValueError("model call recovery result authorities must be unique")
        if keys != tuple(sorted(keys)):
            raise ValueError("model call recovery result items must use stable order")
        if not self.scan_complete and (
            self.scanned != self.limit
            or any(
                item.disposition != ModelResponseRecoveryDisposition.ANOMALY
                and item.reason_code != ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE
                for item in self.items
            )
        ):
            raise ValueError("incomplete model call scan cannot claim a recovery mutation")


class ModelCallRecoveryCoordinator:
    """Recover exact request claims without provider access or business-state writes."""

    __slots__ = ("_limit", "_recovery_identity", "_repository", "_responses")

    def __init__(
        self,
        repository: ModelCallRecoveryRepository,
        responses: ModelResponseStore,
        *,
        limit: int = MAX_MODEL_CALL_RECOVERY_ITEMS,
        recovery_identity: ModelResponseRecoveryIdentity | None = None,
    ) -> None:
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_MODEL_CALL_RECOVERY_ITEMS
        ):
            raise ValueError(
                f"model call recovery limit must be in [1, {MAX_MODEL_CALL_RECOVERY_ITEMS}]"
            )
        self._repository = repository
        self._responses = responses
        self._limit = limit
        if recovery_identity is not None and not isinstance(
            recovery_identity,
            ModelResponseRecoveryIdentity,
        ):
            raise TypeError("recovery_identity must be an opaque recovery identity")
        self._recovery_identity = recovery_identity or ModelResponseRecoveryIdentity()

    @property
    def recovery_identity(self) -> ModelResponseRecoveryIdentity:
        """Return a capability-free token for composition identity checks."""

        return self._recovery_identity

    def recover(
        self,
        run_id: str,
        started_at: datetime,
    ) -> ModelCallRecoveryResult:
        controlled_run_id = require_reference_token(run_id, "model call recovery run reference")
        self._require_utc(started_at)
        scan = self._scan(controlled_run_id)

        items = [self._scan_anomaly_item(anomaly) for anomaly in scan.anomalies]
        if not scan.complete:
            items.extend(
                self._request_item(
                    candidate,
                    disposition=ModelResponseRecoveryDisposition.DEFERRED,
                    reason=ModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE,
                )
                for candidate in scan.candidates
            )
        elif scan.anomalies:
            items.extend(
                self._request_item(
                    candidate,
                    disposition=ModelResponseRecoveryDisposition.DEFERRED,
                    reason=ModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED,
                )
                for candidate in scan.candidates
            )
        else:
            items.extend(
                self._recover_candidate(candidate, started_at) for candidate in scan.candidates
            )

        stable_items = tuple(sorted(items, key=lambda item: item.sort_key))
        try:
            return ModelCallRecoveryResult(
                run_id=controlled_run_id,
                started_at=started_at,
                limit=self._limit,
                scanned=scan.claims_scanned,
                scan_complete=scan.complete,
                items=stable_items,
            )
        except (TypeError, ValueError):
            raise ModelCallRecoveryError(ModelCallRecoveryErrorCode.INVALID_SCAN_RESULT) from None

    def _scan(self, run_id: str) -> ModelCallRecoveryScan:
        try:
            scan = self._repository.scan_model_call_recovery_candidates(
                run_id,
                self._limit,
            )
        except LabCourtError:
            raise ModelCallRecoveryError(ModelCallRecoveryErrorCode.DATABASE_SCAN_FAILED) from None
        except Exception:
            self._raise_unexpected()
        if (
            not isinstance(scan, ModelCallRecoveryScan)
            or scan.run_id != run_id
            or scan.max_items != self._limit
        ):
            raise ModelCallRecoveryError(ModelCallRecoveryErrorCode.INVALID_SCAN_RESULT)
        candidate_keys = {candidate.request.request_id for candidate in scan.candidates}
        anomaly_keys = {anomaly.source_token for anomaly in scan.anomalies}
        if candidate_keys & anomaly_keys:
            raise ModelCallRecoveryError(ModelCallRecoveryErrorCode.INVALID_SCAN_RESULT)
        return scan

    def _recover_candidate(
        self,
        candidate: ModelCallRecoveryCandidate,
        started_at: datetime,
    ) -> ModelResponseRecoveryItem:
        if candidate.status == PersistedModelCallStatus.COMPLETED:
            return self._recover_completed(candidate)
        if candidate.status != PersistedModelCallStatus.ACTIVE:
            return self._database_anomaly(candidate)
        if candidate.lease_expires_at > started_at:
            return self._request_item(
                candidate,
                disposition=ModelResponseRecoveryDisposition.DEFERRED,
                reason=ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED,
            )

        probed = self._probe(candidate)
        if isinstance(probed, ModelResponseRecoveryItem):
            return probed
        if probed is None:
            return self._request_item(
                candidate,
                disposition=ModelResponseRecoveryDisposition.DEFERRED,
                reason=ModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL,
            )

        recovered = self._recover_response(candidate, probed)
        if isinstance(recovered, ModelResponseRecoveryItem):
            return recovered
        try:
            cached = self._repository.complete_expired_model_call_from_recovery(
                candidate.request.run_id,
                candidate.request,
                recovered,
                candidate.lease_expires_at,
                candidate.takeover_count,
            )
        except ConcurrentModification:
            return self._claim_race_item(candidate)
        except LabCourtError:
            return self._database_anomaly(candidate)
        except Exception:
            self._raise_unexpected()
        if not self._cache_matches(candidate.request, recovered, cached):
            return self._database_anomaly(candidate)

        verified = self._verify_response(candidate, recovered)
        if isinstance(verified, ModelResponseRecoveryItem):
            return verified
        acknowledged = self._acknowledge(candidate, recovered)
        if isinstance(acknowledged, ModelResponseRecoveryItem):
            return acknowledged
        return self._terminal_item(
            candidate,
            recovered,
            disposition=ModelResponseRecoveryDisposition.ACKNOWLEDGED,
            reason=ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED,
        )

    def _recover_completed(
        self,
        candidate: ModelCallRecoveryCandidate,
    ) -> ModelResponseRecoveryItem:
        try:
            cached = self._repository.get(candidate.request.run_id, candidate.request)
            raw = self._repository.load_raw_response_for_request(
                candidate.request.run_id,
                candidate.request.request_id,
            )
        except LabCourtError:
            return self._database_anomaly(candidate)
        except Exception:
            self._raise_unexpected()
        if (
            type(raw) is not VLMResponse
            or candidate.response_id != raw.response_id
            or not self._response_matches_request(candidate.request, raw)
            or not self._cache_matches(candidate.request, raw, cached)
        ):
            return self._database_anomaly(candidate)

        verified = self._verify_response(candidate, raw)
        if isinstance(verified, ModelResponseRecoveryItem):
            return verified
        probed = self._probe(candidate)
        if isinstance(probed, ModelResponseRecoveryItem):
            return probed
        if probed is None:
            return self._terminal_item(
                candidate,
                raw,
                disposition=ModelResponseRecoveryDisposition.VERIFIED,
                reason=ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT,
            )
        if probed != raw:
            return self._response_anomaly(candidate)
        acknowledged = self._acknowledge(candidate, raw)
        if isinstance(acknowledged, ModelResponseRecoveryItem):
            return acknowledged
        return self._terminal_item(
            candidate,
            raw,
            disposition=ModelResponseRecoveryDisposition.ACKNOWLEDGED,
            reason=ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED,
        )

    def _probe(
        self,
        candidate: ModelCallRecoveryCandidate,
    ) -> VLMResponse | ModelResponseRecoveryItem | None:
        try:
            response = self._responses.probe_recovery(candidate.request)
        except ModelResponseStoreError as error:
            return self._store_anomaly(candidate, error)
        except Exception:
            self._raise_unexpected()
        if response is None:
            return None
        if type(response) is not VLMResponse or not self._response_matches_request(
            candidate.request,
            response,
        ):
            return self._response_anomaly(candidate)
        return response

    def _recover_response(
        self,
        candidate: ModelCallRecoveryCandidate,
        probed: VLMResponse,
    ) -> VLMResponse | ModelResponseRecoveryItem:
        try:
            recovered = self._responses.recover(candidate.request)
        except ModelResponseStoreError as error:
            return self._store_anomaly(candidate, error)
        except Exception:
            self._raise_unexpected()
        if recovered is None:
            # Another maintenance process may have completed SQLite and
            # acknowledged the exact journal after this process probed it.
            # Continue only with the already verified receipt; the repository
            # must still re-open and verify the final raw file before commit.
            return probed
        if (
            type(recovered) is not VLMResponse
            or recovered != probed
            or not self._response_matches_request(candidate.request, recovered)
        ):
            return self._response_anomaly(candidate)
        return recovered

    def _verify_response(
        self,
        candidate: ModelCallRecoveryCandidate,
        response: VLMResponse,
    ) -> VLMResponse | ModelResponseRecoveryItem:
        try:
            verified = self._responses.verify_raw_response(
                candidate.request.run_id,
                candidate.request,
                response,
            )
        except ModelResponseStoreError as error:
            return self._store_anomaly(candidate, error)
        except Exception:
            self._raise_unexpected()
        if type(verified) is not VLMResponse or verified != response:
            return self._response_anomaly(candidate)
        return verified

    def _acknowledge(
        self,
        candidate: ModelCallRecoveryCandidate,
        response: VLMResponse,
    ) -> ModelResponseRecoveryItem | None:
        try:
            self._responses.acknowledge(candidate.request, response)
        except ModelResponseStoreError as error:
            if error.reason_code == ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND:
                # SQLite completion/cache and the final raw response were
                # already reverified before this method is reached.  Re-open it
                # once more so RESPONSE_NOT_FOUND can only mean another
                # maintenance process acknowledged the exact journal, not that
                # the final response disappeared in the acknowledgement race.
                verified = self._verify_response(candidate, response)
                return verified if isinstance(verified, ModelResponseRecoveryItem) else None
            return self._store_anomaly(candidate, error, acknowledging=True)
        except Exception:
            self._raise_unexpected()
        return None

    @staticmethod
    def _scan_anomaly_item(
        anomaly: ModelCallRecoveryScanAnomaly,
    ) -> ModelResponseRecoveryItem:
        reason = {
            ModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID: (
                ModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID
            ),
            ModelCallRecoveryScanFailureCode.DATABASE_OBSERVATION_CONFLICT: (
                ModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT
            ),
        }[anomaly.failure_code]
        return ModelResponseRecoveryItem(
            run_id=anomaly.run_id,
            area=ModelResponseRecoveryArea.MODEL_CALL,
            source_token=anomaly.source_token,
            disposition=ModelResponseRecoveryDisposition.ANOMALY,
            reason_code=reason,
        )

    @staticmethod
    def _request_item(
        candidate: ModelCallRecoveryCandidate,
        *,
        disposition: ModelResponseRecoveryDisposition,
        reason: ModelResponseRecoveryReason,
    ) -> ModelResponseRecoveryItem:
        return ModelResponseRecoveryItem(
            run_id=candidate.request.run_id,
            area=ModelResponseRecoveryArea.MODEL_CALL,
            request_id=candidate.request.request_id,
            disposition=disposition,
            reason_code=reason,
        )

    @classmethod
    def _terminal_item(
        cls,
        candidate: ModelCallRecoveryCandidate,
        response: VLMResponse,
        *,
        disposition: ModelResponseRecoveryDisposition,
        reason: ModelResponseRecoveryReason,
    ) -> ModelResponseRecoveryItem:
        return ModelResponseRecoveryItem(
            run_id=candidate.request.run_id,
            area=ModelResponseRecoveryArea.MODEL_CALL,
            request_id=candidate.request.request_id,
            response_id=response.response_id,
            response_content_sha256=response.content_sha256,
            disposition=disposition,
            reason_code=reason,
        )

    @classmethod
    def _database_anomaly(
        cls,
        candidate: ModelCallRecoveryCandidate,
    ) -> ModelResponseRecoveryItem:
        return cls._request_item(
            candidate,
            disposition=ModelResponseRecoveryDisposition.ANOMALY,
            reason=ModelResponseRecoveryReason.DATABASE_OBSERVATION_CONFLICT,
        )

    @classmethod
    def _response_anomaly(
        cls,
        candidate: ModelCallRecoveryCandidate,
    ) -> ModelResponseRecoveryItem:
        return cls._request_item(
            candidate,
            disposition=ModelResponseRecoveryDisposition.ANOMALY,
            reason=ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE,
        )

    @classmethod
    def _claim_race_item(
        cls,
        candidate: ModelCallRecoveryCandidate,
    ) -> ModelResponseRecoveryItem:
        return cls._request_item(
            candidate,
            disposition=ModelResponseRecoveryDisposition.DEFERRED,
            reason=ModelResponseRecoveryReason.CLAIM_RACE_LOST,
        )

    @classmethod
    def _store_anomaly(
        cls,
        candidate: ModelCallRecoveryCandidate,
        error: ModelResponseStoreError,
        *,
        acknowledging: bool = False,
    ) -> ModelResponseRecoveryItem:
        if error.reason_code == ModelResponseStoreFailureCode.RESPONSE_CONFLICT:
            reason = ModelResponseRecoveryReason.RESPONSE_CONFLICT
        elif acknowledging:
            reason = ModelResponseRecoveryReason.JOURNAL_INTEGRITY_FAILURE
        else:
            reason = ModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE
        return cls._request_item(
            candidate,
            disposition=ModelResponseRecoveryDisposition.ANOMALY,
            reason=reason,
        )

    @staticmethod
    def _response_matches_request(
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> bool:
        return (
            response.run_id == request.run_id
            and response.case_id == request.case_id
            and response.evidence_pack_id == request.evidence_pack_id
            and response.evidence_pack_version == request.evidence_pack_version
            and response.request_id == request.request_id
            and response.request_sha256 == request.request_sha256
            and response.cache_key == request.cache_key
            and response.purpose == request.purpose
            and response.attempt_index == (0 if request.purpose == VlmCallPurpose.SCREENING else 1)
            and response.model_manifest_id == request.model_manifest_id
            and response.manifest_id == request.manifest_id
        )

    @classmethod
    def _cache_matches(
        cls,
        request: VLMCallRequest,
        response: VLMResponse,
        cached: object,
    ) -> bool:
        if type(cached) is not CachedModelResponse or cached.response != response:
            return False
        entry = cached.entry
        return (
            cls._response_matches_request(request, response)
            and entry.run_id == request.run_id
            and entry.case_id == request.case_id
            and entry.evidence_pack_id == request.evidence_pack_id
            and entry.evidence_pack_version == request.evidence_pack_version
            and entry.cache_key == request.cache_key
            and entry.request_id == request.request_id
            and entry.request_sha256 == request.request_sha256
            and entry.response_id == response.response_id
            and entry.response_content_sha256 == response.content_sha256
            and entry.model_manifest_id == request.model_manifest_id
            and entry.prompt_manifest_id == request.prompt_manifest.prompt_manifest_id
            and entry.output_schema_sha256 == request.prompt_manifest.output_schema_sha256
            and entry.manifest_id == request.manifest_id
        )

    @staticmethod
    def _require_utc(value: datetime) -> None:
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
            or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("model call recovery start time must use timezone-aware UTC")

    @staticmethod
    def _raise_unexpected() -> NoReturn:
        raise ModelCallRecoveryError(
            ModelCallRecoveryErrorCode.UNEXPECTED_DEPENDENCY_FAILURE
        ) from None


__all__ = [
    "MAX_MODEL_CALL_RECOVERY_ITEMS",
    "ModelCallRecoveryCoordinator",
    "ModelCallRecoveryError",
    "ModelCallRecoveryErrorCode",
    "ModelCallRecoveryResult",
]
