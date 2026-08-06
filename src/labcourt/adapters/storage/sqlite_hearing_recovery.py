"""Provider-free SQLite recovery for M4 hearing model responses.

This adapter intentionally exposes only the four operations required by
``HearingModelCallRecoveryRepository``.  It cannot claim a call, invoke a
provider, parse model bytes, execute an acquisition, or advance a Case.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta

from pydantic import ValidationError

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelRequest,
    HearingModelResponse,
    HearingUsageReceipt,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    EvidenceMissing,
)
from labcourt.ports.hearing_model_response_recovery import (
    HearingModelCallRecoveryCandidate,
    HearingModelCallRecoveryScan,
    HearingModelCallRecoveryScanAnomaly,
    HearingModelCallRecoveryScanFailureCode,
    PersistedHearingModelCallStatus,
)
from labcourt.ports.hearing_vlm import HearingRawModelResponseVerifier

from .sqlite_hearing_repository import SQLiteHearingRepository
from .sqlite_repository import (
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
    _canonical_utc_timestamp,
    _parse_utc_timestamp,
    _row_int,
    _row_optional_str,
    _row_str,
    _utc_timestamp,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECOVERY_REQUEST_JSON_BYTES = 1024 * 1024
_RECOVERY_SCAN_PAGE_SIZE = 256
_RECOVERY_PAGE_COLUMNS = """
    run_id, request_id, request_sha256, cache_key,
    hearing_id, cycle_scope_id, cycle_scope_sha256, case_id,
    role, purpose, attempt_index, call_generation,
    backlog_item_id, retry_generation, reserved_images, reserved_pixels,
    evidence_pack_id, evidence_pack_version,
    model_manifest_id, prompt_manifest_id, manifest_id,
    CASE
        WHEN length(CAST(request_json AS BLOB)) <= ?
        THEN request_json
        ELSE NULL
    END AS request_json,
    length(CAST(request_json AS BLOB)) AS request_json_bytes,
    request_document_sha256, status, owner_token_sha256,
    lease_expires_at, takeover_count, created_at,
    response_id, completed_at
"""


class SQLiteHearingModelCallRecoveryRepository:
    """Capability-minimal recovery view over one M4 SQLite authority."""

    __slots__ = ("_hearing", "_host", "_raw_response_verifier")

    def __init__(
        self,
        host: SQLiteEvidenceRepository,
        raw_response_verifier: HearingRawModelResponseVerifier,
    ) -> None:
        if not isinstance(host, SQLiteEvidenceRepository):
            raise TypeError("host must be a SQLiteEvidenceRepository")
        if not callable(getattr(raw_response_verifier, "verify_raw_response", None)):
            raise TypeError("raw_response_verifier must verify exact hearing responses")
        self._host = host
        self._hearing = SQLiteHearingRepository(host)
        self._raw_response_verifier = raw_response_verifier

    def scan_hearing_model_call_recovery_candidates(
        self,
        run_id: str,
        max_items: int,
    ) -> HearingModelCallRecoveryScan:
        """Return one bounded, stable, fully reconstructed claim inventory."""

        controlled_run_id = require_reference_token(run_id, "hearing recovery run_id")
        self._require_scan_limit(max_items)
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            connection.execute("BEGIN")
            count_row = connection.execute(
                "SELECT COUNT(*) AS claim_count FROM m4_model_call_claims WHERE run_id = ?",
                (controlled_run_id,),
            ).fetchone()
            total_claims = _row_int(count_row, "claim_count")
            scan_budget = min(total_claims, max_items)
            candidates: list[HearingModelCallRecoveryCandidate] = []
            anomalies: list[HearingModelCallRecoveryScanAnomaly] = []
            last_request_id: str | None = None
            observed = 0
            while observed < scan_budget:
                page_size = min(_RECOVERY_SCAN_PAGE_SIZE, scan_budget - observed)
                query = f"""
                    SELECT {_RECOVERY_PAGE_COLUMNS}
                    FROM m4_model_call_claims
                    WHERE run_id = ?
                    {"" if last_request_id is None else "AND request_id > ?"}
                    ORDER BY request_id
                    LIMIT ?
                """
                parameters: tuple[object, ...]
                if last_request_id is None:
                    parameters = (
                        _MAX_RECOVERY_REQUEST_JSON_BYTES,
                        controlled_run_id,
                        page_size,
                    )
                else:
                    parameters = (
                        _MAX_RECOVERY_REQUEST_JSON_BYTES,
                        controlled_run_id,
                        last_request_id,
                        page_size,
                    )
                rows = connection.execute(query, parameters).fetchall()
                if len(rows) != page_size:
                    raise RepositoryIntegrityError(
                        "hearing recovery snapshot count conflicts with its keyset page"
                    )
                for row in rows:
                    observed_request_id = _row_str(row, "request_id")
                    rebuilt = self._candidate_from_row(connection, row)
                    if isinstance(rebuilt, HearingModelCallRecoveryCandidate):
                        candidates.append(rebuilt)
                    else:
                        anomalies.append(
                            HearingModelCallRecoveryScanAnomaly(
                                run_id=controlled_run_id,
                                source_token=sha256_hex(
                                    [
                                        "hearing-model-call-recovery-claim-source",
                                        1,
                                        controlled_run_id,
                                        observed_request_id,
                                    ]
                                ),
                                failure_code=rebuilt,
                            )
                        )
                    last_request_id = observed_request_id
                observed += len(rows)
            return HearingModelCallRecoveryScan(
                run_id=controlled_run_id,
                max_items=max_items,
                candidates=tuple(sorted(candidates, key=lambda item: item.sort_key)),
                anomalies=tuple(sorted(anomalies, key=lambda item: item.sort_key)),
                complete=total_claims <= max_items,
            )
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    def complete_expired_hearing_model_call_from_recovery(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
        observed_lease_expires_at: datetime,
        observed_takeover_count: int,
    ) -> HearingModelCacheEntry:
        """Complete one expired exact claim without reserving or calling again."""

        controlled_run_id = require_reference_token(run_id, "hearing recovery run_id")
        validated_request = HearingModelRequest.model_validate(request.model_dump(mode="json"))
        validated_response = HearingModelResponse.model_validate(response.model_dump(mode="json"))
        if validated_request.run_id != controlled_run_id:
            raise ContractViolation("hearing recovery request belongs to another run")
        self._require_observed_epoch(
            observed_lease_expires_at,
            observed_takeover_count,
        )
        observed_expiry_text = _canonical_utc_timestamp(
            observed_lease_expires_at,
            "observed hearing claim expiry",
        )
        now_text = _utc_timestamp(self._host._clock)
        now = _parse_utc_timestamp(now_text, "hearing recovery clock")

        try:
            with self._host._immediate(require_m4=True) as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM m4_model_call_claims
                    WHERE run_id = ? AND (request_id = ? OR cache_key = ?)
                    """,
                    (
                        controlled_run_id,
                        validated_request.request_id,
                        validated_request.cache_key,
                    ),
                ).fetchall()
                if not rows:
                    raise ContractViolation(
                        "hearing recovery completion requires an existing claim"
                    )
                if len(rows) != 1:
                    raise RepositoryIntegrityError(
                        "hearing recovery identities select multiple claims"
                    )
                row = rows[0]
                stored_request = self._hearing._hearing_model_request_from_claim_row(row)
                if stored_request != validated_request:
                    raise RepositoryIntegrityError(
                        "hearing recovery request differs from its durable claim"
                    )
                status = _row_str(row, "status")
                takeover_count = _row_int(row, "takeover_count")
                usage = self._usage_for(
                    validated_request,
                    validated_response,
                    retry_count=takeover_count,
                )
                self._hearing._validate_hearing_model_completion(
                    validated_request,
                    validated_response,
                    usage,
                )

                if status == PersistedHearingModelCallStatus.COMPLETED.value:
                    return self._validate_completed_call(
                        connection,
                        row,
                        validated_request,
                        validated_response,
                        usage,
                        verify_raw=True,
                    )
                if status != PersistedHearingModelCallStatus.ACTIVE.value:
                    raise RepositoryIntegrityError("hearing recovery claim has an invalid status")
                current_expiry_text = _row_str(row, "lease_expires_at")
                current_expiry = _parse_utc_timestamp(
                    current_expiry_text,
                    "hearing recovery claim expiry",
                )
                if (
                    current_expiry_text != observed_expiry_text
                    or takeover_count != observed_takeover_count
                    or current_expiry > now
                    or row["response_id"] is not None
                    or row["completed_at"] is not None
                ):
                    raise ConcurrentModification(
                        "hearing recovery observation changed before completion"
                    )

                self._reverify_raw_response(
                    controlled_run_id,
                    validated_request,
                    validated_response,
                )
                self._hearing._insert_hearing_model_response(
                    connection,
                    validated_request,
                    validated_response,
                )
                self._host._fault("hearing.model.recovery.after_response")
                updated = connection.execute(
                    """
                    UPDATE m4_model_call_claims
                    SET status = 'COMPLETED', response_id = ?, completed_at = ?
                    WHERE run_id = ? AND request_id = ?
                      AND status = 'ACTIVE'
                      AND lease_expires_at = ? AND lease_expires_at <= ?
                      AND takeover_count = ?
                      AND response_id IS NULL AND completed_at IS NULL
                    """,
                    (
                        validated_response.response_id,
                        now_text,
                        controlled_run_id,
                        validated_request.request_id,
                        observed_expiry_text,
                        now_text,
                        observed_takeover_count,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrentModification("hearing recovery completion CAS was lost")
                cache = self._hearing._insert_hearing_model_cache_entry(
                    connection,
                    validated_request,
                    validated_response,
                )
                self._hearing._insert_hearing_usage_receipt(
                    connection,
                    validated_request,
                    validated_response,
                    usage,
                    accounted_at=now_text,
                )
                self._host._fault("hearing.model.recovery.before_commit")
                return cache
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing recovery authority was rejected") from exc

    def load_hearing_model_cache_entry_for_recovery(
        self,
        run_id: str,
        request: HearingModelRequest,
    ) -> HearingModelCacheEntry | None:
        controlled_run_id = require_reference_token(run_id, "hearing recovery run_id")
        validated_request = HearingModelRequest.model_validate(request.model_dump(mode="json"))
        if validated_request.run_id != controlled_run_id:
            raise ContractViolation("hearing recovery request belongs to another run")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            row = connection.execute(
                "SELECT * FROM m4_model_call_claims WHERE run_id = ? AND request_id = ?",
                (controlled_run_id, validated_request.request_id),
            ).fetchone()
            if row is None:
                return None
            stored_request = self._hearing._hearing_model_request_from_claim_row(row)
            if stored_request != validated_request:
                raise RepositoryIntegrityError(
                    "hearing recovery cache request conflicts with its claim"
                )
            entry = self._hearing._load_hearing_model_cache_entry(
                connection,
                controlled_run_id,
                validated_request.cache_key,
            )
            if entry is None:
                return None
            response = self._hearing._load_hearing_model_response(
                connection,
                controlled_run_id,
                entry.response_id,
            )
            if entry != self._hearing._hearing_cache_entry(validated_request, response):
                raise RepositoryIntegrityError(
                    "hearing recovery cache differs from its request and response"
                )
            return entry
        finally:
            connection.close()

    def load_hearing_model_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> HearingModelResponse | None:
        controlled_run_id = require_reference_token(run_id, "hearing recovery run_id")
        self._require_sha256(request_id, "hearing recovery request_id")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            row = connection.execute(
                "SELECT * FROM m4_model_call_claims WHERE run_id = ? AND request_id = ?",
                (controlled_run_id, request_id),
            ).fetchone()
            if row is None:
                return None
            request = self._hearing._hearing_model_request_from_claim_row(row)
            response_id = _row_optional_str(row, "response_id")
            if _row_str(row, "status") == "ACTIVE":
                if response_id is not None or row["completed_at"] is not None:
                    raise RepositoryIntegrityError(
                        "active hearing recovery claim contains completion data"
                    )
                return None
            if response_id is None:
                raise RepositoryIntegrityError("completed hearing recovery claim lacks a response")
            response = self._hearing._load_hearing_model_response(
                connection,
                controlled_run_id,
                response_id,
            )
            self._require_response_binding(request, response)
            return response
        finally:
            connection.close()

    def _candidate_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> HearingModelCallRecoveryCandidate | HearingModelCallRecoveryScanFailureCode:
        try:
            request_bytes = _row_int(row, "request_json_bytes")
            if not 0 <= request_bytes <= _MAX_RECOVERY_REQUEST_JSON_BYTES:
                raise RepositoryIntegrityError("hearing recovery request exceeds its byte bound")
            request_raw = _row_str(row, "request_json")
            if len(request_raw.encode("utf-8")) != request_bytes:
                raise RepositoryIntegrityError("hearing recovery request byte count changed")
            request = HearingModelRequest.model_validate_json(request_raw)
            stored_request = self._hearing._hearing_model_request_from_claim_row(row)
            if stored_request != request:
                raise RepositoryIntegrityError("hearing recovery request reconstruction changed")
        except (
            RepositoryIntegrityError,
            ValidationError,
            TypeError,
            ValueError,
            UnicodeError,
        ):
            return HearingModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID

        try:
            self._require_sha256(
                _row_str(row, "owner_token_sha256"),
                "hearing claim owner digest",
            )
            _parse_utc_timestamp(
                _row_str(row, "created_at"),
                "hearing claim creation time",
            )
            expiry = _parse_utc_timestamp(
                _row_str(row, "lease_expires_at"),
                "hearing claim expiry",
            )
            takeover_count = _row_int(row, "takeover_count")
            if takeover_count < 0:
                raise RepositoryIntegrityError("hearing claim takeover count is negative")
            status = _row_str(row, "status")
            response_id = _row_optional_str(row, "response_id")
            completed_at = _row_optional_str(row, "completed_at")
            if status == PersistedHearingModelCallStatus.ACTIVE.value:
                if response_id is not None or completed_at is not None:
                    raise RepositoryIntegrityError("active hearing claim contains completion data")
                self._require_no_completed_rows(connection, request)
                return HearingModelCallRecoveryCandidate(
                    request=request,
                    status=PersistedHearingModelCallStatus.ACTIVE,
                    takeover_count=takeover_count,
                    lease_expires_at=expiry,
                )
            if (
                status != PersistedHearingModelCallStatus.COMPLETED.value
                or response_id is None
                or completed_at is None
            ):
                raise RepositoryIntegrityError("hearing claim has an invalid durable state")
            self._require_sha256(response_id, "hearing claim response_id")
            _parse_utc_timestamp(completed_at, "hearing claim completion time")
            response = self._hearing._load_hearing_model_response(
                connection,
                request.run_id,
                response_id,
            )
            usage = self._usage_for(request, response, retry_count=takeover_count)
            self._validate_completed_call(
                connection,
                row,
                request,
                response,
                usage,
                verify_raw=False,
            )
            return HearingModelCallRecoveryCandidate(
                request=request,
                status=PersistedHearingModelCallStatus.COMPLETED,
                takeover_count=takeover_count,
                response_id=response_id,
            )
        except (
            ContractViolation,
            EvidenceMissing,
            RepositoryIntegrityError,
            ValidationError,
            TypeError,
            ValueError,
        ):
            return HearingModelCallRecoveryScanFailureCode.DATABASE_OBSERVATION_CONFLICT

    def _validate_completed_call(
        self,
        connection: sqlite3.Connection,
        claim_row: sqlite3.Row,
        request: HearingModelRequest,
        response: HearingModelResponse,
        usage: HearingUsageReceipt,
        *,
        verify_raw: bool,
    ) -> HearingModelCacheEntry:
        if (
            _row_str(claim_row, "status") != "COMPLETED"
            or _row_optional_str(claim_row, "response_id") != response.response_id
            or claim_row["completed_at"] is None
        ):
            raise RepositoryIntegrityError("completed hearing recovery claim is inconsistent")
        _parse_utc_timestamp(
            _row_str(claim_row, "completed_at"),
            "hearing recovery completion time",
        )
        self._require_response_binding(request, response)
        stored_response = self._hearing._load_hearing_model_response(
            connection,
            request.run_id,
            response.response_id,
        )
        if stored_response != response:
            raise RepositoryIntegrityError(
                "completed hearing recovery response differs from its claim"
            )
        cache = self._hearing._load_hearing_model_cache_entry(
            connection,
            request.run_id,
            request.cache_key,
        )
        if cache is None or cache != self._hearing._hearing_cache_entry(request, response):
            raise RepositoryIntegrityError("completed hearing recovery claim lacks its exact cache")
        usage_rows = connection.execute(
            """
            SELECT * FROM m4_hearing_usage_receipts
            WHERE run_id = ? AND (request_id = ? OR response_id = ?)
            """,
            (request.run_id, request.request_id, response.response_id),
        ).fetchall()
        if (
            len(usage_rows) != 1
            or self._hearing._hearing_usage_receipt_from_row(usage_rows[0]) != usage
        ):
            raise RepositoryIntegrityError("completed hearing recovery claim lacks its exact usage")
        _parse_utc_timestamp(
            _row_str(usage_rows[0], "accounted_at"),
            "hearing recovery usage accounting time",
        )
        if verify_raw:
            self._reverify_raw_response(request.run_id, request, response)
        return cache

    @staticmethod
    def _require_no_completed_rows(
        connection: sqlite3.Connection,
        request: HearingModelRequest,
    ) -> None:
        for table in (
            "m4_model_responses",
            "m4_model_cache",
            "m4_hearing_usage_receipts",
        ):
            count = connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE run_id = ? AND request_id = ?",
                (request.run_id, request.request_id),
            ).fetchone()[0]
            if count != 0:
                raise RepositoryIntegrityError(
                    "active hearing claim already has completed-call rows"
                )

    def _reverify_raw_response(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> None:
        verified = self._raw_response_verifier.verify_raw_response(
            run_id,
            request,
            response,
        )
        if type(verified) is not HearingModelResponse or verified != response:
            raise ContractViolation("hearing recovery raw verifier must return the exact response")

    @staticmethod
    def _usage_for(
        request: HearingModelRequest,
        response: HearingModelResponse,
        *,
        retry_count: int,
    ) -> HearingUsageReceipt:
        return HearingUsageReceipt(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            round_index=request.round_index,
            role=request.role,
            request_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_REQUEST,
                artifact_id=request.request_id,
            ),
            response_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=response.response_id,
            ),
            input_images=len(request.media),
            input_pixels=sum(item.width * item.height for item in request.media),
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            latency_ms=response.latency_ms,
            retry_count=retry_count,
            estimated_cost=request.budget.estimate_cost(
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            ),
            manifest_id=request.manifest_id,
        )

    @staticmethod
    def _require_response_binding(
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> None:
        usage = SQLiteHearingModelCallRecoveryRepository._usage_for(
            request,
            response,
            retry_count=0,
        )
        # Retry count is not part of request/response binding.  The shared
        # validator checks every other field and all per-call budgets.
        SQLiteHearingRepository._validate_hearing_model_completion(
            request,
            response,
            usage,
        )

    @staticmethod
    def _require_scan_limit(max_items: int) -> None:
        from labcourt.contracts.hearing_recovery import (
            MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS,
        )

        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or not 1 <= max_items <= MAX_HEARING_MODEL_CALL_RECOVERY_ITEMS
        ):
            raise ValueError("hearing recovery max_items must be a bounded positive integer")

    @staticmethod
    def _require_observed_epoch(
        expiry: datetime,
        takeover_count: int,
    ) -> None:
        if (
            not isinstance(expiry, datetime)
            or expiry.tzinfo is None
            or expiry.utcoffset() is None
            or expiry.utcoffset() != timedelta(0)
        ):
            raise ValueError("observed hearing claim expiry must use UTC")
        if (
            not isinstance(takeover_count, int)
            or isinstance(takeover_count, bool)
            or takeover_count < 0
        ):
            raise ValueError("observed hearing claim takeover count is invalid")

    @staticmethod
    def _require_sha256(value: str, name: str) -> str:
        if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
            raise RepositoryIntegrityError(f"{name} is not a lowercase SHA-256 digest")
        return value


__all__ = ["SQLiteHearingModelCallRecoveryRepository"]
