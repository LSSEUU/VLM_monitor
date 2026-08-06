"""Durable model-call, raw-response, parse, cache, and usage authority."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from typing import cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.backlog import (
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryContext,
    BacklogStrictParseFailureProof,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import UsageSummary
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
    ModelParseStatus,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.exceptions import (
    BudgetExceeded,
    ConcurrentModification,
    ContractViolation,
)
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.ports.model_response_recovery import (
    ModelCallRecoveryCandidate,
    ModelCallRecoveryScan,
    ModelCallRecoveryScanAnomaly,
    ModelCallRecoveryScanFailureCode,
    PersistedModelCallStatus,
)
from labcourt.ports.screening_repository import (
    ModelCallClaim,
    ModelCallClaimStatus,
)
from labcourt.ports.vlm import (
    ModelResponseStoreError,
)

from .sqlite_m3_repository_host import SQLiteM3RepositoryHost
from .sqlite_m3_repository_support import (
    _BACKLOG_PROVABLE_RAW_FAILURES,
    _MAX_RECOVERY_REQUEST_JSON_BYTES,
    _MODEL_CALL_RECOVERY_KEYSET_PAGE_QUERY,
    _MODEL_CALL_RECOVERY_PAGE_QUERY,
    _REQUEST_ADAPTER,
    _load_document,
    _owner_token_sha256,
    _request_matches_retry_generation,
    _require_sha256,
    _runtime_model_call_recovery_item_limit,
    _runtime_model_call_recovery_page_size,
    _same_semantic_model_call_identity,
    _validated_copy,
    _validated_request,
)
from .sqlite_repository import (
    RepositoryIntegrityError,
    _document,
    _parse_utc_timestamp,
    _row_int,
    _row_optional_str,
    _row_str,
)


class SQLiteM3ModelRepository(SQLiteM3RepositoryHost):
    """Durable model-call, raw-response, parse, cache, and usage authority."""

    def append_raw_response(self, response: VLMResponse) -> VLMResponse:
        """Reject the legacy response-only T1 write that cannot prove request binding."""

        del response
        raise ContractViolation("raw responses may only be committed through complete_model_call")

    def load_raw_response(self, run_id: str, response_id: str) -> VLMResponse:
        require_reference_token(run_id, "repository run_id")
        _require_sha256(response_id, "response_id")
        with self._read() as connection:
            return self._load_response(connection, run_id, response_id)

    def load_raw_response_for_request(
        self,
        run_id: str,
        request_id: str,
    ) -> VLMResponse | None:
        """Load the response bound to one completed atomic model call, if present."""

        require_reference_token(run_id, "repository run_id")
        _require_sha256(request_id, "request_id")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM model_responses
                WHERE run_id = ? AND request_id = ?
                """,
                (run_id, request_id),
            ).fetchall()
            if not rows:
                return None
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "request_id must bind at most one raw response receipt"
                )
            response = self._response_from_row(rows[0])
            if response.request_id != request_id:
                raise RepositoryIntegrityError(
                    "raw response request index differs from canonical binding"
                )
            return response

    def model_response_is_referenced(
        self,
        run_id: str,
        response_id: str,
        content_sha256: str,
    ) -> bool:
        """Return whether one exact canonical response receipt references an artifact."""

        require_reference_token(run_id, "repository run_id")
        _require_sha256(response_id, "response_id")
        _require_sha256(content_sha256, "response content_sha256")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM model_responses
                WHERE run_id = ? AND response_id = ?
                """,
                (run_id, response_id),
            ).fetchall()
            if not rows:
                if self._has_durable_model_response_reference(
                    connection,
                    run_id,
                    response_id,
                ):
                    raise RepositoryIntegrityError(
                        "model response has a dangling durable database reference"
                    )
                return False
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "model response reference selects multiple durable receipts"
                )
            response = self._response_from_row(rows[0])
            if (
                response.run_id != run_id
                or response.response_id != response_id
                or response.content_sha256 != content_sha256
            ):
                raise RepositoryIntegrityError(
                    "model response artifact differs from its durable receipt binding"
                )
            return True

    def claim_model_call(
        self,
        run_id: str,
        request: VLMCallRequest,
        owner_token: str,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> ModelCallClaim:
        """Acquire or observe one exact claim; unknown expiry never grants work."""

        require_reference_token(run_id, "repository run_id")
        validated_request = _validated_request(request)
        if validated_request.run_id != run_id:
            raise ContractViolation("model call claim request belongs to another run")
        owner_sha256 = _owner_token_sha256(owner_token)
        context = validated_request.backlog_retry_context
        if context is None:
            if backlog_lease is not None:
                raise ContractViolation("direct model call cannot carry a backlog lease")
        elif (
            not isinstance(backlog_lease, BacklogLeaseIdentity)
            or backlog_lease.run_id != run_id
            or backlog_lease.item_id != context.backlog_item_id
            or backlog_lease.retry_generation != context.retry_generation
        ):
            raise ContractViolation("retry model call requires its exact backlog lease identity")
        now_text = self._recorded_at()
        now = _parse_utc_timestamp(now_text, "repository clock")
        expiry = now + timedelta(seconds=validated_request.budget.claim_lease_seconds)
        expiry_text = self._canonical_timestamp(expiry, "model call lease expiry")
        request_json, request_document_sha256 = _document(cast(BaseModel, validated_request))
        if len(request_json.encode("utf-8")) > _MAX_RECOVERY_REQUEST_JSON_BYTES:
            raise ContractViolation(
                "canonical model call request exceeds the durable recovery byte limit"
            )

        with self._immediate() as connection:
            self._require_case_pack_scope(
                connection,
                run_id=run_id,
                case_id=validated_request.case_id,
                pack_id=validated_request.evidence_pack_id,
                pack_version=validated_request.evidence_pack_version,
                manifest_id=validated_request.manifest_id,
            )
            if backlog_lease is not None:
                self._require_active_backlog_lease(
                    connection,
                    run_id=run_id,
                    lease=backlog_lease,
                    manifest_id=validated_request.manifest_id,
                )
            rows = connection.execute(
                """
                SELECT * FROM model_call_claims
                WHERE run_id = ? AND (request_id = ? OR cache_key = ?)
                """,
                (run_id, validated_request.request_id, validated_request.cache_key),
            ).fetchall()
            if len(rows) > 1:
                raise RepositoryIntegrityError(
                    "model call request identities select multiple durable claims"
                )
            if not rows:
                claim_count = _row_int(
                    connection.execute(
                        """
                        SELECT COUNT(*) AS claim_count
                        FROM model_call_claims
                        WHERE run_id = ?
                        """,
                        (run_id,),
                    ).fetchone(),
                    "claim_count",
                )
                if claim_count >= _runtime_model_call_recovery_item_limit():
                    raise BudgetExceeded("run reached the durable model-call recovery capacity")
                connection.execute(
                    """
                    INSERT INTO model_call_claims(
                        run_id, request_id, request_sha256, cache_key, case_id,
                        evidence_pack_id, evidence_pack_version, purpose,
                        model_manifest_id, manifest_id,
                        request_json, request_document_sha256,
                        status, owner_token_sha256, lease_expires_at,
                        takeover_count, created_at, response_id, completed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              'ACTIVE', ?, ?, 0, ?, NULL, NULL)
                    """,
                    (
                        run_id,
                        validated_request.request_id,
                        validated_request.request_sha256,
                        validated_request.cache_key,
                        validated_request.case_id,
                        validated_request.evidence_pack_id,
                        validated_request.evidence_pack_version,
                        validated_request.purpose.value,
                        validated_request.model_manifest_id,
                        validated_request.manifest_id,
                        request_json,
                        request_document_sha256,
                        owner_sha256,
                        expiry_text,
                        now_text,
                    ),
                )
                return ModelCallClaim(
                    status=ModelCallClaimStatus.ACQUIRED,
                    request_id=validated_request.request_id,
                    lease_expires_at=expiry,
                    takeover_count=0,
                )

            row = rows[0]
            claim = self._claim_from_row(row, validated_request)
            if claim.status == ModelCallClaimStatus.COMPLETED:
                return claim
            assert claim.lease_expires_at is not None
            if self._known_failure_authorizes_retry(
                connection,
                row=row,
                request=validated_request,
                backlog_lease=backlog_lease,
            ):
                previous_owner = _row_str(row, "owner_token_sha256")
                previous_expiry = _row_str(row, "lease_expires_at")
                previous_takeover_count = _row_int(row, "takeover_count")
                updated = connection.execute(
                    """
                    UPDATE model_call_claims
                    SET owner_token_sha256 = ?, lease_expires_at = ?,
                        takeover_count = takeover_count + 1
                    WHERE run_id = ? AND request_id = ? AND status = 'ACTIVE'
                      AND owner_token_sha256 = ? AND lease_expires_at = ?
                      AND takeover_count = ?
                      AND response_id IS NULL AND completed_at IS NULL
                    """,
                    (
                        owner_sha256,
                        expiry_text,
                        run_id,
                        validated_request.request_id,
                        previous_owner,
                        previous_expiry,
                        previous_takeover_count,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrentModification("known-failure model call retry CAS was lost")
                return ModelCallClaim(
                    status=ModelCallClaimStatus.ACQUIRED,
                    request_id=validated_request.request_id,
                    lease_expires_at=expiry,
                    takeover_count=previous_takeover_count + 1,
                )
            if claim.lease_expires_at <= now:
                return ModelCallClaim(
                    status=ModelCallClaimStatus.EXPIRED_REQUIRES_RECOVERY,
                    request_id=validated_request.request_id,
                    lease_expires_at=claim.lease_expires_at,
                    takeover_count=claim.takeover_count,
                )
            return claim

    def _known_failure_authorizes_retry(
        self,
        connection: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        request: VLMCallRequest,
        backlog_lease: BacklogLeaseIdentity | None,
    ) -> bool:
        """Require one exact aggregate-closed provider outcome and active queue lease."""

        context = request.backlog_retry_context
        if context is None or backlog_lease is None:
            return False
        rows = connection.execute(
            """
            SELECT * FROM model_call_failure_authorities
            WHERE run_id = ? AND request_id = ?
              AND claim_owner_sha256 = ?
              AND claim_lease_expires_at = ?
              AND claim_takeover_count = ?
            """,
            (
                request.run_id,
                request.request_id,
                _row_str(row, "owner_token_sha256"),
                _row_str(row, "lease_expires_at"),
                _row_int(row, "takeover_count"),
            ),
        ).fetchall()
        if not rows:
            return False
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "model call claim epoch has multiple failure authorities"
            )
        authority = self._model_call_failure_authority_from_row(rows[0])
        if (
            authority.backlog_status != BacklogStatus.PENDING
            or authority.backlog_item_id != context.backlog_item_id
            or authority.retry_generation != context.retry_generation
            or not _same_semantic_model_call_identity(authority.request, request)
        ):
            return False
        current, snapshot = self._require_active_backlog_lease(
            connection,
            run_id=request.run_id,
            lease=backlog_lease,
            manifest_id=request.manifest_id,
        )
        return (
            current.status == BacklogStatus.LEASED
            and current.item_id == authority.backlog_item_id
            and current.case_id == authority.request.case_id
            and current.retry_generation == authority.retry_generation
            and current.attempt_count > authority.backlog_attempt_count
            and current.lease_id is not None
            and snapshot.case.status == CaseStatus.BACKLOGGED
            and snapshot.case.current_backlog_item_id == current.item_id
        )

    def scan_model_call_recovery_candidates(
        self,
        run_id: str,
        max_items: int,
    ) -> ModelCallRecoveryScan:
        """Read one bounded full inventory from a stable snapshot.

        ``max_items`` is the total run budget, never a page size.  Keyset pages
        are an internal I/O detail and all share one SQLite read transaction;
        recovery is authorized only when the observed count fits the budget
        and every page has been reconstructed without an anomaly.
        """

        require_reference_token(run_id, "repository run_id")
        if (
            not isinstance(max_items, int)
            or isinstance(max_items, bool)
            or not 1 <= max_items <= _runtime_model_call_recovery_item_limit()
        ):
            raise ValueError(
                "model call recovery max_items must be in "
                f"[1, {_runtime_model_call_recovery_item_limit()}]"
            )
        with self._read() as connection:
            count_row = connection.execute(
                """
                SELECT COUNT(*) AS claim_count
                FROM model_call_claims
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            total_claims = _row_int(count_row, "claim_count")
            scan_budget = min(total_claims, max_items)
            candidates: list[ModelCallRecoveryCandidate] = []
            anomalies: list[ModelCallRecoveryScanAnomaly] = []
            last_request_id: str | None = None
            observed = 0
            while observed < scan_budget:
                page_size = min(
                    _runtime_model_call_recovery_page_size(),
                    scan_budget - observed,
                )
                if last_request_id is None:
                    rows = connection.execute(
                        _MODEL_CALL_RECOVERY_PAGE_QUERY,
                        (
                            _MAX_RECOVERY_REQUEST_JSON_BYTES,
                            run_id,
                            page_size,
                        ),
                    ).fetchall()
                else:
                    rows = connection.execute(
                        _MODEL_CALL_RECOVERY_KEYSET_PAGE_QUERY,
                        (
                            _MAX_RECOVERY_REQUEST_JSON_BYTES,
                            run_id,
                            last_request_id,
                            page_size,
                        ),
                    ).fetchall()
                if len(rows) != page_size:
                    raise RepositoryIntegrityError(
                        "model call recovery snapshot count conflicts with its keyset page"
                    )
                for row in rows:
                    observed_request_id = _row_str(row, "request_id")
                    result = self._model_call_recovery_candidate_from_row(row)
                    if isinstance(result, ModelCallRecoveryCandidate):
                        candidates.append(result)
                    else:
                        anomalies.append(
                            ModelCallRecoveryScanAnomaly(
                                run_id=run_id,
                                source_token=sha256_hex(
                                    [
                                        "model-call-recovery-claim-source",
                                        1,
                                        run_id,
                                        observed_request_id,
                                    ]
                                ),
                                failure_code=result,
                            )
                        )
                    last_request_id = observed_request_id
                observed += len(rows)
            return ModelCallRecoveryScan(
                run_id=run_id,
                max_items=max_items,
                candidates=tuple(sorted(candidates, key=lambda item: item.sort_key)),
                anomalies=tuple(sorted(anomalies, key=lambda item: item.sort_key)),
                complete=total_claims <= max_items,
            )

    def complete_expired_model_call_from_recovery(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
        observed_lease_expires_at: datetime,
        observed_takeover_count: int,
    ) -> CachedModelResponse:
        """Complete an expired claim without ever granting provider authority.

        The application must first recover the exact journaled publication.
        This transaction independently verifies the canonical request,
        response, physical raw file, observed expiry, and takeover count before
        atomically appending the response/cache and completing the claim.  It
        never returns an owner token or an ``ACQUIRED`` claim state.
        """

        require_reference_token(run_id, "repository run_id")
        validated_request = _validated_request(request)
        validated_response = _validated_copy(response, VLMResponse)
        if validated_request.run_id != run_id:
            raise ContractViolation("model call recovery request belongs to another run")
        self._validate_request_response_binding(
            run_id,
            validated_request,
            validated_response,
        )
        if (
            not isinstance(observed_lease_expires_at, datetime)
            or observed_lease_expires_at.tzinfo is None
            or observed_lease_expires_at.utcoffset() is None
            or observed_lease_expires_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("observed model call lease expiry must use timezone-aware UTC")
        if (
            not isinstance(observed_takeover_count, int)
            or isinstance(observed_takeover_count, bool)
            or observed_takeover_count < 0
        ):
            raise ValueError("observed model call takeover count must be non-negative")
        observed_expiry_text = self._canonical_timestamp(
            observed_lease_expires_at,
            "observed model call lease expiry",
        )
        now_text = self._recorded_at()
        now = _parse_utc_timestamp(now_text, "repository clock")

        with self._immediate() as connection:
            rows = connection.execute(
                """
                SELECT * FROM model_call_claims
                WHERE run_id = ? AND (request_id = ? OR cache_key = ?)
                """,
                (run_id, validated_request.request_id, validated_request.cache_key),
            ).fetchall()
            if not rows:
                raise ContractViolation(
                    "model call recovery completion requires an existing durable claim"
                )
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "model call recovery request selects multiple durable claims"
                )
            row = rows[0]
            claim = self._claim_from_row(row, validated_request)
            if claim.status == ModelCallClaimStatus.COMPLETED:
                if claim.response_id != validated_response.response_id:
                    raise RepositoryIntegrityError(
                        "completed model call claim binds another recovery response"
                    )
                cache_row = connection.execute(
                    "SELECT * FROM model_cache WHERE run_id = ? AND request_id = ?",
                    (run_id, validated_request.request_id),
                ).fetchone()
                if cache_row is None:
                    raise RepositoryIntegrityError(
                        "completed model call recovery is missing its cache binding"
                    )
                cached = self._cached_response_from_row(
                    connection,
                    cache_row,
                    validated_request,
                )
                if cached.response != validated_response:
                    raise RepositoryIntegrityError(
                        "completed model call cache binds different recovery content"
                    )
                self._reverify_raw_response(
                    run_id=run_id,
                    request=validated_request,
                    response=validated_response,
                )
                return cached
            current_expiry_text = _row_str(row, "lease_expires_at")
            current_expiry = _parse_utc_timestamp(
                current_expiry_text,
                "model call recovery lease expiry",
            )
            current_takeover_count = _row_int(row, "takeover_count")
            if (
                current_expiry_text != observed_expiry_text
                or current_takeover_count != observed_takeover_count
                or current_expiry > now
            ):
                raise ConcurrentModification(
                    "model call recovery observation changed before completion"
                )

            self._reverify_raw_response(
                run_id=run_id,
                request=validated_request,
                response=validated_response,
            )
            stored_response = self._append_raw_response_in_transaction(
                connection,
                validated_response,
            )
            cached = self._put_in_transaction(
                connection,
                run_id,
                validated_request,
                stored_response,
            )

            updated = connection.execute(
                """
                UPDATE model_call_claims
                SET status = 'COMPLETED', response_id = ?, completed_at = ?
                WHERE run_id = ? AND request_id = ?
                  AND status = 'ACTIVE'
                  AND lease_expires_at = ? AND lease_expires_at <= ?
                  AND takeover_count = ?
                  AND response_id IS NULL AND completed_at IS NULL
                """,
                (
                    stored_response.response_id,
                    now_text,
                    run_id,
                    validated_request.request_id,
                    observed_expiry_text,
                    now_text,
                    observed_takeover_count,
                ),
            )
            if updated.rowcount != 1:
                raise ConcurrentModification("model call recovery completion CAS was lost")
            return cached

    def complete_model_call(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
        owner_token: str,
    ) -> CachedModelResponse:
        """Atomically converge one owner-authorized response and cache receipt.

        This does not advance a Case or charge usage.  A backlog worker whose
        queue lease expired may still preserve the exact already-authorized
        response; all later business commits remain fenced by the current
        backlog lease and Case revision.
        """

        require_reference_token(run_id, "repository run_id")
        validated_request = _validated_request(request)
        validated_response = _validated_copy(response, VLMResponse)
        self._validate_request_response_binding(
            run_id,
            validated_request,
            validated_response,
        )
        owner_sha256 = _owner_token_sha256(owner_token)
        completed_at = self._recorded_at()
        with self._immediate() as connection:
            rows = connection.execute(
                """
                SELECT * FROM model_call_claims
                WHERE run_id = ? AND (request_id = ? OR cache_key = ?)
                """,
                (run_id, validated_request.request_id, validated_request.cache_key),
            ).fetchall()
            if len(rows) != 1:
                raise ContractViolation(
                    "model call completion requires exactly one durable request claim"
                )
            row = rows[0]
            claim = self._claim_from_row(row, validated_request)
            if claim.status == ModelCallClaimStatus.COMPLETED:
                if claim.response_id != validated_response.response_id:
                    raise RepositoryIntegrityError(
                        "completed model call claim binds another response"
                    )
                cache_row = connection.execute(
                    "SELECT * FROM model_cache WHERE run_id = ? AND request_id = ?",
                    (run_id, validated_request.request_id),
                ).fetchone()
                if cache_row is None:
                    raise RepositoryIntegrityError(
                        "completed model call claim is missing its cache binding"
                    )
                cached = self._cached_response_from_row(
                    connection,
                    cache_row,
                    validated_request,
                )
                if cached.response != validated_response:
                    raise RepositoryIntegrityError(
                        "completed model call cache binds different response content"
                    )
                self._reverify_raw_response(
                    run_id=run_id,
                    request=validated_request,
                    response=validated_response,
                )
                return cached
            if _row_str(row, "owner_token_sha256") != owner_sha256:
                raise ConcurrentModification("model call completion owner no longer holds claim")

            self._reverify_raw_response(
                run_id=run_id,
                request=validated_request,
                response=validated_response,
            )
            stored_response = self._append_raw_response_in_transaction(
                connection,
                validated_response,
            )
            cached = self._put_in_transaction(
                connection,
                run_id,
                validated_request,
                stored_response,
            )
            updated = connection.execute(
                """
                UPDATE model_call_claims
                SET status = 'COMPLETED', response_id = ?, completed_at = ?
                WHERE run_id = ? AND request_id = ? AND status = 'ACTIVE'
                  AND owner_token_sha256 = ?
                  AND response_id IS NULL AND completed_at IS NULL
                """,
                (
                    stored_response.response_id,
                    completed_at,
                    run_id,
                    validated_request.request_id,
                    owner_sha256,
                ),
            )
            if updated.rowcount != 1:
                raise ConcurrentModification("model call completion CAS was lost")
            return cached

    def append_parse_receipt(
        self,
        receipt: ModelParseReceipt,
        parsed_output: ParsedScreeningOutput | None = None,
    ) -> ModelParseReceipt:
        """Atomically append a parse receipt, optional parsed output, and parser defects."""

        validated_receipt = _validated_copy(receipt, ModelParseReceipt)
        validated_output = (
            _validated_copy(parsed_output, ParsedScreeningOutput)
            if parsed_output is not None
            else None
        )
        self._validate_parse_binding(validated_receipt, validated_output)
        receipt_json, receipt_sha256 = _document(validated_receipt)
        with self._immediate() as connection:
            response = self._load_response(
                connection,
                validated_receipt.run_id,
                validated_receipt.response_id,
            )
            self._require_receipt_response_binding(validated_receipt, response)
            request = self._request_for_response(connection, response)
            self._reverify_raw_response(
                run_id=validated_receipt.run_id,
                request=request,
                response=response,
            )
            existing_rows = connection.execute(
                """
                SELECT * FROM model_parse_receipts
                WHERE run_id = ? AND (parse_receipt_id = ? OR response_id = ?)
                """,
                (
                    validated_receipt.run_id,
                    validated_receipt.parse_receipt_id,
                    validated_receipt.response_id,
                ),
            ).fetchall()
            if existing_rows:
                if len(existing_rows) != 1:
                    raise RepositoryIntegrityError(
                        "parse receipt identity indexes select multiple receipts"
                    )
                stored = self._parse_receipt_from_row(connection, existing_rows[0])
                if stored != validated_receipt:
                    raise RepositoryIntegrityError(
                        "response already binds a different parse receipt"
                    )
                if validated_output is not None:
                    stored_output = self._load_parsed_output(
                        connection,
                        validated_output.run_id,
                        validated_output.parsed_output_id,
                    )
                    if stored_output != validated_output:
                        raise RepositoryIntegrityError(
                            "parsed output identity already binds different content"
                        )
                return stored

            if validated_output is not None:
                self._insert_parsed_output(connection, validated_output)
            connection.execute(
                """
                INSERT INTO model_parse_receipts(
                    run_id, parse_receipt_id, case_id,
                    evidence_pack_id, evidence_pack_version,
                    request_id, response_id, attempt_index, status,
                    parsed_output_id, parsed_output_sha256, repair_request_id,
                    manifest_id, receipt_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    validated_receipt.run_id,
                    validated_receipt.parse_receipt_id,
                    validated_receipt.case_id,
                    validated_receipt.evidence_pack_id,
                    validated_receipt.evidence_pack_version,
                    validated_receipt.request_id,
                    validated_receipt.response_id,
                    validated_receipt.attempt_index,
                    validated_receipt.status.value,
                    validated_receipt.parsed_output_id,
                    validated_receipt.parsed_output_sha256,
                    validated_receipt.repair_request_id,
                    validated_receipt.manifest_id,
                    receipt_json,
                    receipt_sha256,
                ),
            )
            self._insert_defects(
                connection,
                run_id=validated_receipt.run_id,
                owner_kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                owner_id=validated_receipt.parse_receipt_id,
                defects=validated_receipt.defects,
            )
        return validated_receipt

    def load_parse_receipt(self, run_id: str, parse_receipt_id: str) -> ModelParseReceipt:
        require_reference_token(run_id, "repository run_id")
        _require_sha256(parse_receipt_id, "parse_receipt_id")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM model_parse_receipts
                WHERE run_id = ? AND parse_receipt_id = ?
                """,
                (run_id, parse_receipt_id),
            ).fetchone()
            if row is None:
                raise ContractViolation("unknown model parse receipt")
            return self._parse_receipt_from_row(connection, row)

    def load_parse_receipt_for_output(
        self,
        run_id: str,
        parsed_output_id: str,
    ) -> ModelParseReceipt:
        """Resolve the sole successful parse receipt for a persisted output."""

        require_reference_token(run_id, "repository run_id")
        _require_sha256(parsed_output_id, "parsed_output_id")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM model_parse_receipts
                WHERE run_id = ? AND parsed_output_id = ?
                """,
                (run_id, parsed_output_id),
            ).fetchall()
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "parsed output must bind exactly one model parse receipt"
                )
            receipt = self._parse_receipt_from_row(connection, rows[0])
            if (
                receipt.status != ModelParseStatus.PARSED
                or receipt.parsed_output_id != parsed_output_id
            ):
                raise RepositoryIntegrityError(
                    "parsed output resolved a non-successful parse receipt"
                )
            return receipt

    def load_parse_history_for_output(
        self,
        run_id: str,
        parsed_output_id: str,
    ) -> tuple[ModelParseReceipt, ...]:
        """Recover the complete direct-parse or repair-parse history for L5."""

        require_reference_token(run_id, "repository run_id")
        _require_sha256(parsed_output_id, "parsed_output_id")
        with self._read() as connection:
            return self._load_parse_history_for_output(
                connection,
                run_id,
                parsed_output_id,
            )

    def load_parsed_output(self, run_id: str, parsed_output_id: str) -> ParsedScreeningOutput:
        require_reference_token(run_id, "repository run_id")
        _require_sha256(parsed_output_id, "parsed_output_id")
        with self._read() as connection:
            return self._load_parsed_output(connection, run_id, parsed_output_id)

    def get(
        self,
        run_id: str,
        request: VLMCallRequest,
    ) -> CachedModelResponse | None:
        """Return an exact request-level cache hit after all bindings are revalidated."""

        require_reference_token(run_id, "repository run_id")
        validated_request = _validated_request(request)
        if validated_request.run_id != run_id:
            raise ContractViolation("cache request belongs to another run")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM model_cache WHERE run_id = ? AND cache_key = ?",
                (run_id, validated_request.cache_key),
            ).fetchone()
            if row is None:
                return None
            return self._cached_response_from_row(connection, row, validated_request)

    def put(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> CachedModelResponse:
        """Revalidate an already completed atomic call; never create a cache row."""

        require_reference_token(run_id, "repository run_id")
        validated_request = _validated_request(request)
        validated_response = _validated_copy(response, VLMResponse)
        self._validate_request_response_binding(
            run_id,
            validated_request,
            validated_response,
        )
        with self._immediate() as connection:
            self._reverify_raw_response(
                run_id=run_id,
                request=validated_request,
                response=validated_response,
            )
            claim_rows = connection.execute(
                """
                SELECT * FROM model_call_claims
                WHERE run_id = ? AND (request_id = ? OR cache_key = ?)
                """,
                (run_id, validated_request.request_id, validated_request.cache_key),
            ).fetchall()
            if len(claim_rows) != 1:
                raise ContractViolation("cache replay requires one completed atomic model call")
            claim = self._claim_from_row(claim_rows[0], validated_request)
            if (
                claim.status != ModelCallClaimStatus.COMPLETED
                or claim.response_id != validated_response.response_id
            ):
                raise ContractViolation(
                    "cache replay requires the exact completed model call response"
                )
            cache_rows = connection.execute(
                """
                SELECT * FROM model_cache
                WHERE run_id = ? AND (cache_key = ? OR request_id = ?)
                """,
                (run_id, validated_request.cache_key, validated_request.request_id),
            ).fetchall()
            if len(cache_rows) != 1:
                raise RepositoryIntegrityError(
                    "completed model call must bind exactly one cache entry"
                )
            cached = self._cached_response_from_row(
                connection,
                cache_rows[0],
                validated_request,
            )
            if cached.response != validated_response:
                raise RepositoryIntegrityError("cache replay response differs from completed call")
            return cached

    def _model_call_recovery_candidate_from_row(
        self,
        row: sqlite3.Row,
    ) -> ModelCallRecoveryCandidate | ModelCallRecoveryScanFailureCode:
        """Reconstruct one bounded claim without exposing malformed authority bytes."""

        try:
            request_json_bytes = _row_int(row, "request_json_bytes")
            if request_json_bytes < 0 or request_json_bytes > _MAX_RECOVERY_REQUEST_JSON_BYTES:
                raise RepositoryIntegrityError(
                    "model call recovery request document exceeds its byte limit"
                )
            request_raw = _row_str(row, "request_json")
            if len(request_raw.encode("utf-8")) != request_json_bytes:
                raise RepositoryIntegrityError(
                    "model call recovery request byte count changed during scan"
                )
            request = _REQUEST_ADAPTER.validate_json(request_raw)
            canonical_request, request_document_sha256 = _document(cast(BaseModel, request))
            if canonical_request != request_raw or request_document_sha256 != _row_str(
                row, "request_document_sha256"
            ):
                raise RepositoryIntegrityError(
                    "model call recovery request document is not canonical"
                )
        except (
            RepositoryIntegrityError,
            ValidationError,
            TypeError,
            ValueError,
            UnicodeError,
        ):
            return ModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID

        try:
            claim = self._claim_from_row(row, request)
            persisted_status = PersistedModelCallStatus(_row_str(row, "status"))
            expected_claim_status = (
                ModelCallClaimStatus.COMPLETED
                if persisted_status == PersistedModelCallStatus.COMPLETED
                else ModelCallClaimStatus.WAITING
            )
            if claim.status != expected_claim_status:
                raise RepositoryIntegrityError(
                    "model call recovery status differs from claim reconstruction"
                )
            candidate = ModelCallRecoveryCandidate(
                request=request,
                status=persisted_status,
                lease_expires_at=_parse_utc_timestamp(
                    _row_str(row, "lease_expires_at"),
                    "model call recovery lease expiry",
                ),
                takeover_count=_row_int(row, "takeover_count"),
                response_id=_row_optional_str(row, "response_id"),
            )
        except (
            RepositoryIntegrityError,
            ContractViolation,
            ValidationError,
            TypeError,
            ValueError,
        ):
            return ModelCallRecoveryScanFailureCode.DATABASE_OBSERVATION_CONFLICT
        return candidate

    def _claim_from_row(
        self,
        row: sqlite3.Row,
        request: VLMCallRequest,
    ) -> ModelCallClaim:
        request_raw = _row_str(row, "request_json")
        try:
            stored_request = _REQUEST_ADAPTER.validate_json(request_raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored model call claim request is invalid") from exc
        canonical_request, document_sha256 = _document(cast(BaseModel, stored_request))
        if (
            canonical_request != request_raw
            or document_sha256 != _row_str(row, "request_document_sha256")
            or not _same_semantic_model_call_identity(stored_request, request)
        ):
            raise RepositoryIntegrityError(
                "model call claim differs from the complete canonical request"
            )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "request_id"),
            _row_str(row, "request_sha256"),
            _row_str(row, "cache_key"),
            _row_str(row, "case_id"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "purpose"),
            _row_str(row, "model_manifest_id"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            stored_request.run_id,
            stored_request.request_id,
            stored_request.request_sha256,
            stored_request.cache_key,
            stored_request.case_id,
            stored_request.evidence_pack_id,
            stored_request.evidence_pack_version,
            stored_request.purpose.value,
            stored_request.model_manifest_id,
            stored_request.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "model call claim indexes differ from its canonical request"
            )
        _require_sha256(_row_str(row, "owner_token_sha256"), "owner_token_sha256")
        lease_expiry = _parse_utc_timestamp(
            _row_str(row, "lease_expires_at"),
            "model call claim lease expiry",
        )
        _parse_utc_timestamp(_row_str(row, "created_at"), "model call claim creation time")
        takeover_count = _row_int(row, "takeover_count")
        if takeover_count < 0:
            raise RepositoryIntegrityError("model call claim takeover count is negative")
        status = _row_str(row, "status")
        response_id = _row_optional_str(row, "response_id")
        completed_at = _row_optional_str(row, "completed_at")
        if status == "ACTIVE":
            if response_id is not None or completed_at is not None:
                raise RepositoryIntegrityError("active model call claim contains completion data")
            return ModelCallClaim(
                status=ModelCallClaimStatus.WAITING,
                request_id=stored_request.request_id,
                lease_expires_at=lease_expiry,
                takeover_count=takeover_count,
            )
        if status != "COMPLETED" or response_id is None or completed_at is None:
            raise RepositoryIntegrityError("model call claim has an invalid durable status")
        _require_sha256(response_id, "claim response_id")
        _parse_utc_timestamp(completed_at, "model call claim completion time")
        return ModelCallClaim(
            status=ModelCallClaimStatus.COMPLETED,
            request_id=stored_request.request_id,
            response_id=response_id,
            takeover_count=takeover_count,
        )

    def _append_raw_response_in_transaction(
        self,
        connection: sqlite3.Connection,
        response: VLMResponse,
    ) -> VLMResponse:
        response_json, response_sha256 = _document(response)
        self._require_case_pack_scope(
            connection,
            run_id=response.run_id,
            case_id=response.case_id,
            pack_id=response.evidence_pack_id,
            pack_version=response.evidence_pack_version,
            manifest_id=response.manifest_id,
        )
        rows = connection.execute(
            """
            SELECT * FROM model_responses
            WHERE run_id = ? AND (response_id = ? OR request_id = ?)
            """,
            (response.run_id, response.response_id, response.request_id),
        ).fetchall()
        if rows:
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "model response identity indexes select multiple receipts"
                )
            stored = self._response_from_row(rows[0])
            if stored != response:
                raise RepositoryIntegrityError(
                    "request_id or response_id already binds different response content"
                )
            return stored
        connection.execute(
            """
            INSERT INTO model_responses(
                run_id, response_id, case_id,
                evidence_pack_id, evidence_pack_version,
                request_id, request_sha256, cache_key,
                purpose, attempt_index, raw_response_ref,
                content_sha256, size_bytes, model_manifest_id, manifest_id,
                response_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                response.run_id,
                response.response_id,
                response.case_id,
                response.evidence_pack_id,
                response.evidence_pack_version,
                response.request_id,
                response.request_sha256,
                response.cache_key,
                response.purpose.value,
                response.attempt_index,
                response.raw_response_ref,
                response.content_sha256,
                response.size_bytes,
                response.model_manifest_id,
                response.manifest_id,
                response_json,
                response_sha256,
            ),
        )
        return response

    def _put_in_transaction(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> CachedModelResponse:
        entry = ModelCacheEntry(
            run_id=run_id,
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
        )
        entry_json, entry_sha256 = _document(entry)
        request_json, request_sha256 = _document(cast(BaseModel, request))
        existing_rows = connection.execute(
            """
            SELECT * FROM model_cache
            WHERE run_id = ? AND (cache_key = ? OR request_id = ?)
            """,
            (run_id, entry.cache_key, entry.request_id),
        ).fetchall()
        if existing_rows:
            if len(existing_rows) != 1:
                raise RepositoryIntegrityError(
                    "cache request identity indexes select multiple entries"
                )
            existing = existing_rows[0]
            existing_hash = _row_str(existing, "response_content_sha256")
            if existing_hash != response.content_sha256:
                raise RepositoryIntegrityError(
                    "cache key already binds a different response content hash"
                )
            cached = self._cached_response_from_row(connection, existing, request)
            if cached.entry != entry or cached.response != response:
                raise RepositoryIntegrityError(
                    "cache key already binds different request or response content"
                )
            return cached
        stored_response = self._load_response(connection, run_id, response.response_id)
        if stored_response != response:
            raise RepositoryIntegrityError("cache response differs from its persisted raw receipt")
        connection.execute(
            """
            INSERT INTO model_cache(
                run_id, cache_key, cache_entry_id, case_id,
                evidence_pack_id, evidence_pack_version,
                request_id, request_sha256,
                response_id, response_content_sha256,
                model_manifest_id, prompt_manifest_id,
                output_schema_sha256, manifest_id,
                request_json, request_document_sha256,
                entry_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                entry.cache_key,
                entry.cache_entry_id,
                entry.case_id,
                entry.evidence_pack_id,
                entry.evidence_pack_version,
                entry.request_id,
                entry.request_sha256,
                entry.response_id,
                entry.response_content_sha256,
                entry.model_manifest_id,
                entry.prompt_manifest_id,
                entry.output_schema_sha256,
                entry.manifest_id,
                request_json,
                request_sha256,
                entry_json,
                entry_sha256,
            ),
        )
        return CachedModelResponse(entry=entry, response=response)

    def _load_response(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        response_id: str,
    ) -> VLMResponse:
        row = connection.execute(
            "SELECT * FROM model_responses WHERE run_id = ? AND response_id = ?",
            (run_id, response_id),
        ).fetchone()
        if row is None:
            raise ContractViolation("unknown model response")
        return self._response_from_row(row)

    @staticmethod
    def _has_durable_model_response_reference(
        connection: sqlite3.Connection,
        run_id: str,
        response_id: str,
    ) -> bool:
        row = connection.execute(
            """
            SELECT 1 FROM model_call_claims
            WHERE run_id = :run_id AND response_id = :response_id
            UNION ALL
            SELECT 1 FROM parsed_screening_outputs
            WHERE run_id = :run_id AND response_id = :response_id
            UNION ALL
            SELECT 1 FROM model_parse_receipts
            WHERE run_id = :run_id AND response_id = :response_id
            UNION ALL
            SELECT 1 FROM model_cache
            WHERE run_id = :run_id AND response_id = :response_id
            UNION ALL
            SELECT 1 FROM model_call_usage_accounting
            WHERE run_id = :run_id AND response_id = :response_id
            UNION ALL
            SELECT 1 FROM procedural_defects
            WHERE run_id = :run_id
              AND artifact_kind = 'MODEL_RESPONSE'
              AND artifact_id = :response_id
            UNION ALL
            SELECT 1 FROM backlog_items
            WHERE run_id = :run_id
              AND stage_input_kind = 'MODEL_RESPONSE'
              AND stage_input_id = :response_id
            LIMIT 1
            """,
            {"run_id": run_id, "response_id": response_id},
        ).fetchone()
        return row is not None

    def _response_from_row(self, row: sqlite3.Row) -> VLMResponse:
        response = _load_document(
            row,
            json_key="response_json",
            sha256_key="document_sha256",
            model_type=VLMResponse,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "response_id"),
            _row_str(row, "case_id"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "request_id"),
            _row_str(row, "request_sha256"),
            _row_str(row, "cache_key"),
            _row_str(row, "purpose"),
            _row_int(row, "attempt_index"),
            _row_str(row, "raw_response_ref"),
            _row_str(row, "content_sha256"),
            _row_int(row, "size_bytes"),
            _row_str(row, "model_manifest_id"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            response.run_id,
            response.response_id,
            response.case_id,
            response.evidence_pack_id,
            response.evidence_pack_version,
            response.request_id,
            response.request_sha256,
            response.cache_key,
            response.purpose.value,
            response.attempt_index,
            response.raw_response_ref,
            response.content_sha256,
            response.size_bytes,
            response.model_manifest_id,
            response.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "model response index columns differ from its canonical document"
            )
        return response

    @staticmethod
    def _validate_parse_binding(
        receipt: ModelParseReceipt,
        output: ParsedScreeningOutput | None,
    ) -> None:
        if receipt.status == ModelParseStatus.PARSED:
            if output is None:
                raise ContractViolation("PARSED receipt requires its parsed output")
            if (
                receipt.parsed_output_id != output.parsed_output_id
                or receipt.parsed_output_sha256 != output.parsed_output_sha256
                or receipt.run_id != output.run_id
                or receipt.case_id != output.case_id
                or receipt.evidence_pack_id != output.evidence_pack_id
                or receipt.evidence_pack_version != output.evidence_pack_version
                or receipt.request_id != output.request_id
                or receipt.response_id != output.response_id
                or receipt.response_content_sha256 != output.response_content_sha256
                or receipt.output_schema_sha256 != output.output_schema_sha256
                or receipt.manifest_id != output.manifest_id
            ):
                raise ContractViolation("parse receipt and parsed output bindings differ")
        elif output is not None:
            raise ContractViolation("non-PARSED receipt cannot persist a parsed output")

    @staticmethod
    def _require_receipt_response_binding(
        receipt: ModelParseReceipt,
        response: VLMResponse,
    ) -> None:
        if (
            receipt.run_id != response.run_id
            or receipt.case_id != response.case_id
            or receipt.evidence_pack_id != response.evidence_pack_id
            or receipt.evidence_pack_version != response.evidence_pack_version
            or receipt.request_id != response.request_id
            or receipt.request_sha256 != response.request_sha256
            or receipt.response_id != response.response_id
            or receipt.response_content_sha256 != response.content_sha256
            or receipt.attempt_index != response.attempt_index
            or receipt.manifest_id != response.manifest_id
        ):
            raise ContractViolation("parse receipt differs from its persisted response")

    def _insert_parsed_output(
        self,
        connection: sqlite3.Connection,
        output: ParsedScreeningOutput,
    ) -> None:
        existing = connection.execute(
            """
            SELECT * FROM parsed_screening_outputs
            WHERE run_id = ? AND (parsed_output_id = ? OR response_id = ?)
            """,
            (output.run_id, output.parsed_output_id, output.response_id),
        ).fetchall()
        if existing:
            if len(existing) != 1:
                raise RepositoryIntegrityError(
                    "parsed output identity indexes select multiple rows"
                )
            stored = self._parsed_output_from_row(existing[0])
            if stored != output:
                raise RepositoryIntegrityError(
                    "parsed output identity already binds different content"
                )
            return
        output_json, output_document_sha256 = _document(output)
        connection.execute(
            """
            INSERT INTO parsed_screening_outputs(
                run_id, parsed_output_id, case_id,
                evidence_pack_id, evidence_pack_version,
                request_id, response_id, response_content_sha256,
                output_schema_sha256, model_payload_sha256,
                parsed_output_sha256, manifest_id,
                output_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                output.run_id,
                output.parsed_output_id,
                output.case_id,
                output.evidence_pack_id,
                output.evidence_pack_version,
                output.request_id,
                output.response_id,
                output.response_content_sha256,
                output.output_schema_sha256,
                output.model_payload_sha256,
                output.parsed_output_sha256,
                output.manifest_id,
                output_json,
                output_document_sha256,
            ),
        )

    def _load_parsed_output(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        parsed_output_id: str,
    ) -> ParsedScreeningOutput:
        row = connection.execute(
            """
            SELECT * FROM parsed_screening_outputs
            WHERE run_id = ? AND parsed_output_id = ?
            """,
            (run_id, parsed_output_id),
        ).fetchone()
        if row is None:
            raise ContractViolation("unknown parsed screening output")
        output = self._parsed_output_from_row(row)
        response = self._load_response(connection, run_id, output.response_id)
        if (
            output.case_id != response.case_id
            or output.evidence_pack_id != response.evidence_pack_id
            or output.evidence_pack_version != response.evidence_pack_version
            or output.request_id != response.request_id
            or output.response_content_sha256 != response.content_sha256
            or output.manifest_id != response.manifest_id
        ):
            raise RepositoryIntegrityError(
                "parsed output differs from its persisted response binding"
            )
        return output

    @staticmethod
    def _parsed_output_from_row(row: sqlite3.Row) -> ParsedScreeningOutput:
        output = _load_document(
            row,
            json_key="output_json",
            sha256_key="document_sha256",
            model_type=ParsedScreeningOutput,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "parsed_output_id"),
            _row_str(row, "case_id"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "request_id"),
            _row_str(row, "response_id"),
            _row_str(row, "response_content_sha256"),
            _row_str(row, "output_schema_sha256"),
            _row_str(row, "model_payload_sha256"),
            _row_str(row, "parsed_output_sha256"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            output.run_id,
            output.parsed_output_id,
            output.case_id,
            output.evidence_pack_id,
            output.evidence_pack_version,
            output.request_id,
            output.response_id,
            output.response_content_sha256,
            output.output_schema_sha256,
            output.model_payload_sha256,
            output.parsed_output_sha256,
            output.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "parsed output indexes differ from its canonical document"
            )
        return output

    def _parse_receipt_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> ModelParseReceipt:
        receipt = _load_document(
            row,
            json_key="receipt_json",
            sha256_key="document_sha256",
            model_type=ModelParseReceipt,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "parse_receipt_id"),
            _row_str(row, "case_id"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "request_id"),
            _row_str(row, "response_id"),
            _row_int(row, "attempt_index"),
            _row_str(row, "status"),
            _row_optional_str(row, "parsed_output_id"),
            _row_optional_str(row, "parsed_output_sha256"),
            _row_optional_str(row, "repair_request_id"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            receipt.run_id,
            receipt.parse_receipt_id,
            receipt.case_id,
            receipt.evidence_pack_id,
            receipt.evidence_pack_version,
            receipt.request_id,
            receipt.response_id,
            receipt.attempt_index,
            receipt.status.value,
            receipt.parsed_output_id,
            receipt.parsed_output_sha256,
            receipt.repair_request_id,
            receipt.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "parse receipt indexes differ from its canonical document"
            )
        response = self._load_response(connection, receipt.run_id, receipt.response_id)
        self._require_receipt_response_binding(receipt, response)
        if receipt.status == ModelParseStatus.PARSED:
            assert receipt.parsed_output_id is not None
            output = self._load_parsed_output(
                connection,
                receipt.run_id,
                receipt.parsed_output_id,
            )
            self._validate_parse_binding(receipt, output)
        self._verify_defect_rows(
            connection,
            run_id=receipt.run_id,
            owner_kind=ArtifactKind.MODEL_PARSE_RECEIPT,
            owner_id=receipt.parse_receipt_id,
            expected=receipt.defects,
        )
        return receipt

    def _load_parse_history_for_output(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        parsed_output_id: str,
    ) -> tuple[ModelParseReceipt, ...]:
        rows = connection.execute(
            """
            SELECT * FROM model_parse_receipts
            WHERE run_id = ? AND parsed_output_id = ?
            """,
            (run_id, parsed_output_id),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "parsed output must bind exactly one successful parse receipt"
            )
        final = self._parse_receipt_from_row(connection, rows[0])
        if final.status != ModelParseStatus.PARSED or final.parsed_output_id != parsed_output_id:
            raise RepositoryIntegrityError("parsed output resolved a non-successful parse receipt")
        if final.attempt_index == 0:
            return (final,)

        request_rows = connection.execute(
            """
            SELECT * FROM model_cache
            WHERE run_id = ? AND request_id = ?
            """,
            (run_id, final.request_id),
        ).fetchall()
        if len(request_rows) != 1:
            raise RepositoryIntegrityError(
                "repair parse receipt must bind exactly one persisted repair request"
            )
        repair_request = self._request_from_cache_row(request_rows[0])
        if not isinstance(repair_request, StructureRepairRequest):
            raise RepositoryIntegrityError(
                "repair parse receipt request is not a StructureRepairRequest"
            )
        if (
            repair_request.request_id != final.request_id
            or repair_request.run_id != final.run_id
            or repair_request.case_id != final.case_id
            or repair_request.evidence_pack_id != final.evidence_pack_id
            or repair_request.evidence_pack_version != final.evidence_pack_version
            or repair_request.manifest_id != final.manifest_id
        ):
            raise RepositoryIntegrityError(
                "persisted repair request differs from final parse receipt scope"
            )
        first_rows = connection.execute(
            """
            SELECT * FROM model_parse_receipts
            WHERE run_id = ? AND response_id = ?
            """,
            (run_id, repair_request.original_response_id),
        ).fetchall()
        if len(first_rows) != 1:
            raise RepositoryIntegrityError(
                "repair history must bind exactly one first-attempt receipt"
            )
        first = self._parse_receipt_from_row(connection, first_rows[0])
        if (
            first.attempt_index != 0
            or first.status != ModelParseStatus.REPAIR_REQUIRED
            or first.repair_request_id != repair_request.request_id
            or first.response_id != repair_request.original_response_id
            or first.response_content_sha256 != repair_request.original_response_sha256
            or first.request_id != repair_request.original_request_id
            or first.request_sha256 != repair_request.original_request_sha256
            or first.run_id != final.run_id
            or first.case_id != final.case_id
            or first.evidence_pack_id != final.evidence_pack_id
            or first.evidence_pack_version != final.evidence_pack_version
            or first.manifest_id != final.manifest_id
        ):
            raise RepositoryIntegrityError(
                "repair history first receipt does not bind the repair request"
            )
        return first, final

    @staticmethod
    def _validate_request_response_binding(
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> None:
        expected_attempt = 0 if request.purpose.value == "SCREENING" else 1
        if (
            request.run_id != run_id
            or response.run_id != run_id
            or request.case_id != response.case_id
            or request.evidence_pack_id != response.evidence_pack_id
            or request.evidence_pack_version != response.evidence_pack_version
            or request.request_id != response.request_id
            or request.request_sha256 != response.request_sha256
            or request.cache_key != response.cache_key
            or request.purpose != response.purpose
            or response.attempt_index != expected_attempt
            or request.model_manifest_id != response.model_manifest_id
            or request.manifest_id != response.manifest_id
        ):
            raise ContractViolation("cache request and response bindings differ")

    def _cached_response_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        request: VLMCallRequest,
    ) -> CachedModelResponse:
        entry = _load_document(
            row,
            json_key="entry_json",
            sha256_key="document_sha256",
            model_type=ModelCacheEntry,
        )
        stored_request = self._request_from_cache_row(row)
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "cache_key"),
            _row_str(row, "cache_entry_id"),
            _row_str(row, "case_id"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "request_id"),
            _row_str(row, "request_sha256"),
            _row_str(row, "response_id"),
            _row_str(row, "response_content_sha256"),
            _row_str(row, "model_manifest_id"),
            _row_str(row, "prompt_manifest_id"),
            _row_str(row, "output_schema_sha256"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            entry.run_id,
            entry.cache_key,
            entry.cache_entry_id,
            entry.case_id,
            entry.evidence_pack_id,
            entry.evidence_pack_version,
            entry.request_id,
            entry.request_sha256,
            entry.response_id,
            entry.response_content_sha256,
            entry.model_manifest_id,
            entry.prompt_manifest_id,
            entry.output_schema_sha256,
            entry.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("model cache indexes differ from its canonical entry")
        if not _same_semantic_model_call_identity(stored_request, request):
            raise RepositoryIntegrityError(
                "cache key hit does not match the semantic model call identity"
            )
        response = self._load_response(connection, entry.run_id, entry.response_id)
        self._validate_request_response_binding(entry.run_id, request, response)
        cached = CachedModelResponse(entry=entry, response=response)
        if response.content_sha256 != entry.response_content_sha256:
            raise RepositoryIntegrityError("cache response content hash does not match entry")
        return cached

    def _request_from_cache_row(self, row: sqlite3.Row) -> VLMCallRequest:
        """Load and cross-check the canonical request retained for recovery."""

        request_raw = _row_str(row, "request_json")
        try:
            stored_request = _REQUEST_ADAPTER.validate_json(request_raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored cache request is invalid") from exc
        canonical_request, request_document_sha256 = _document(cast(BaseModel, stored_request))
        if canonical_request != request_raw or request_document_sha256 != _row_str(
            row, "request_document_sha256"
        ):
            raise RepositoryIntegrityError("stored cache request is not canonical")
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "cache_key"),
            _row_str(row, "case_id"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "request_id"),
            _row_str(row, "request_sha256"),
            _row_str(row, "model_manifest_id"),
            _row_str(row, "prompt_manifest_id"),
            _row_str(row, "output_schema_sha256"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            stored_request.run_id,
            stored_request.cache_key,
            stored_request.case_id,
            stored_request.evidence_pack_id,
            stored_request.evidence_pack_version,
            stored_request.request_id,
            stored_request.request_sha256,
            stored_request.model_manifest_id,
            stored_request.prompt_manifest.prompt_manifest_id,
            stored_request.prompt_manifest.output_schema_sha256,
            stored_request.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "model cache request indexes differ from canonical request content"
            )
        return stored_request

    def _request_for_response(
        self,
        connection: sqlite3.Connection,
        response: VLMResponse,
    ) -> VLMCallRequest:
        rows = connection.execute(
            """
            SELECT * FROM model_cache
            WHERE run_id = ? AND request_id = ?
            """,
            (response.run_id, response.request_id),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "physical raw response verification requires one exact request binding"
            )
        request = self._request_from_cache_row(rows[0])
        cached = self._cached_response_from_row(connection, rows[0], request)
        if cached.response != response:
            raise RepositoryIntegrityError(
                "physical raw response differs from its exact cache request binding"
            )
        return request

    def _reverify_raw_response(
        self,
        *,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> None:
        verifier = self._raw_response_verifier
        if verifier is None:
            raise ContractViolation("M3 model response writes require a raw_response_verifier")
        verified = verifier.verify_raw_response(run_id, request, response)
        if not isinstance(verified, VLMResponse) or verified != response:
            raise ContractViolation("raw_response_verifier must return the exact VLMResponse")

    def _reverify_parse_history_raw(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        parse_history: tuple[ModelParseReceipt, ...],
    ) -> None:
        if not parse_history:
            raise RepositoryIntegrityError("screening parse history is empty")
        for receipt in parse_history:
            response = self._load_response(connection, run_id, receipt.response_id)
            self._require_receipt_response_binding(receipt, response)
            request = self._request_for_response(connection, response)
            self._reverify_raw_response(
                run_id=run_id,
                request=request,
                response=response,
            )

    def _reverify_backlog_responses(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        response_ids: tuple[str, ...],
        reason_code: BacklogReasonCode,
    ) -> None:
        for response_id in response_ids:
            response = self._load_response(connection, run_id, response_id)
            request = self._request_for_response(connection, response)
            try:
                self._reverify_raw_response(
                    run_id=run_id,
                    request=request,
                    response=response,
                )
            except ModelResponseStoreError as error:
                if (
                    reason_code == BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
                    and error.reason_code in _BACKLOG_PROVABLE_RAW_FAILURES
                ):
                    continue
                raise

    def _strict_failure_history(
        self,
        connection: sqlite3.Connection,
        *,
        item: BacklogItem,
        response_ids: tuple[str, ...],
        expected_context: BacklogRetryContext | None,
    ) -> tuple[tuple[ModelParseReceipt, VLMCallRequest, VLMResponse], ...]:
        """Load and prove the exact bounded two-call strict-parser failure."""

        if len(response_ids) != 2 or len(set(response_ids)) != 2:
            raise ContractViolation(
                "MODEL_OUTPUT_INVALID requires exactly two distinct response receipts"
            )
        stage_pack = self._load_pack(
            connection,
            item.run_id,
            item.stage_input_ref.artifact_id,
        )
        records: list[tuple[ModelParseReceipt, VLMCallRequest, VLMResponse]] = []
        for response_id in response_ids:
            rows = connection.execute(
                """
                SELECT * FROM model_parse_receipts
                WHERE run_id = ? AND response_id = ?
                """,
                (item.run_id, response_id),
            ).fetchall()
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "strict parse failure response must bind exactly one parse receipt"
                )
            receipt = self._parse_receipt_from_row(connection, rows[0])
            response = self._load_response(connection, item.run_id, response_id)
            request = self._request_for_response(connection, response)
            if (
                receipt.run_id != item.run_id
                or receipt.case_id != item.case_id
                or receipt.evidence_pack_id != item.stage_input_ref.artifact_id
                or receipt.evidence_pack_version != stage_pack.version
                or receipt.manifest_id != item.manifest_id
                or (
                    request.backlog_retry_context is not None
                    if expected_context is None
                    else not _request_matches_retry_generation(request, expected_context)
                )
            ):
                raise ContractViolation(
                    "strict parse failure does not bind the backlog stage generation"
                )
            self._reverify_raw_response(
                run_id=item.run_id,
                request=request,
                response=response,
            )
            records.append((receipt, request, response))
        records.sort(key=lambda record: record[0].attempt_index)
        first, final = records
        first_receipt, first_request, first_response = first
        final_receipt, final_request, final_response = final
        if (
            first_receipt.attempt_index != 0
            or first_receipt.status != ModelParseStatus.REPAIR_REQUIRED
            or not isinstance(first_request, VLMRequest)
            or first_request.role.value != "SCREENING"
            or final_receipt.attempt_index != 1
            or final_receipt.status != ModelParseStatus.INVALID_FINAL
            or not isinstance(final_request, StructureRepairRequest)
            or first_receipt.repair_request_id != final_request.request_id
            or final_request.original_request_id != first_request.request_id
            or final_request.original_request_sha256 != first_request.request_sha256
            or final_request.original_response_id != first_response.response_id
            or final_request.original_response_sha256 != first_response.content_sha256
            or final_response.request_id != final_request.request_id
        ):
            raise ContractViolation("strict parse failure repair chain is invalid")
        return tuple(records)

    def _require_strict_parse_failure_proof(
        self,
        connection: sqlite3.Connection,
        *,
        item: BacklogItem,
        proof: BacklogStrictParseFailureProof,
    ) -> None:
        records = self._strict_failure_history(
            connection,
            item=item,
            response_ids=tuple(attempt.response_ref.artifact_id for attempt in proof.attempts),
            expected_context=proof.retry_context,
        )
        for evidence, (receipt, request, response) in zip(
            proof.attempts,
            records,
            strict=True,
        ):
            if (
                evidence.attempt_index != receipt.attempt_index
                or evidence.request_ref.artifact_id != request.request_id
                or evidence.response_ref.artifact_id != response.response_id
                or evidence.parse_receipt_ref.artifact_id != receipt.parse_receipt_id
                or evidence.role.value != request.role.value
            ):
                raise ContractViolation(
                    "strict parse-failure proof differs from persisted request history"
                )

    def _new_backlog_usage_response_ids(
        self,
        connection: sqlite3.Connection,
        *,
        snapshot: CaseSnapshot,
        response_ids: tuple[str, ...],
        backlog_item_id: str | None = None,
    ) -> tuple[str, ...]:
        """Return only calls not already charged to valid Case retry authority."""

        latest_screening = (
            snapshot.case.screening_results[-1] if snapshot.case.screening_results else None
        )
        screening_response_ids: frozenset[str] = frozenset()
        if latest_screening is not None:
            history = self._load_parse_history_for_output(
                connection,
                snapshot.case.run_id,
                latest_screening.parsed_output.parsed_output_id,
            )
            screening_response_ids = frozenset(receipt.response_id for receipt in history)

        unaccounted: list[str] = []
        for response_id in response_ids:
            rows = connection.execute(
                """
                SELECT * FROM model_call_usage_accounting
                WHERE run_id = ? AND response_id = ?
                """,
                (snapshot.case.run_id, response_id),
            ).fetchall()
            if not rows:
                unaccounted.append(response_id)
                continue
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "backlog response selects multiple model call usage rows"
                )
            row = rows[0]
            case_revision = _row_int(row, "case_revision")
            consumer_kind_value = _row_str(row, "consumer_kind")
            consumer_id = _row_str(row, "consumer_id")
            screening_consumption = (
                latest_screening is not None
                and response_id in screening_response_ids
                and consumer_kind_value == ArtifactKind.SCREENING_RESULT.value
                and consumer_id == latest_screening.screening_id
            )
            backlog_consumption = (
                backlog_item_id is not None
                and consumer_kind_value == ArtifactKind.BACKLOG_ITEM.value
                and consumer_id == backlog_item_id
            )
            if _row_str(row, "case_id") != snapshot.case.case_id or not (
                screening_consumption or backlog_consumption
            ):
                raise RepositoryIntegrityError(
                    "backlog response usage was consumed outside retry authority"
                )
            # Reuse the strict accounting validator under its original consumer.
            # Existing rows contribute zero delta, so the backlog cannot double-charge.
            self._consume_model_call_usage(
                connection,
                run_id=snapshot.case.run_id,
                case_id=snapshot.case.case_id,
                response_ids=(response_id,),
                case_revision=case_revision,
                consumer_kind=ArtifactKind(consumer_kind_value),
                consumer_id=consumer_id,
            )
        return tuple(unaccounted)

    def _usage_delta_for_output(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        parsed_output_id: str,
    ) -> UsageSummary:
        """Derive auditable provider usage from immutable request/response history."""

        history = self._load_parse_history_for_output(
            connection,
            run_id,
            parsed_output_id,
        )
        input_images = 0
        input_pixels = 0
        input_tokens = 0
        output_tokens = 0
        latency_ms = 0
        estimated_cost = 0.0
        for receipt in history:
            response = self._load_response(connection, run_id, receipt.response_id)
            request_rows = connection.execute(
                """
                SELECT * FROM model_cache
                WHERE run_id = ? AND request_id = ?
                """,
                (run_id, receipt.request_id),
            ).fetchall()
            if len(request_rows) != 1:
                raise RepositoryIntegrityError(
                    "screening usage requires exactly one persisted request binding"
                )
            request = self._request_from_cache_row(request_rows[0])
            self._validate_request_response_binding(run_id, request, response)
            if isinstance(request, VLMRequest):
                input_images += len(request.media)
                input_pixels += sum(item.width * item.height for item in request.media)
            input_tokens += response.input_tokens
            output_tokens += response.output_tokens
            latency_ms += response.latency_ms
            estimated_cost += request.budget.estimate_cost(
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            )
        return UsageSummary(
            input_images=input_images,
            input_pixels=input_pixels,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            provider_latency_ms=latency_ms,
            retries=len(history) - 1,
            estimated_cost=estimated_cost,
        )

    def _consume_model_call_usage(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        response_ids: tuple[str, ...],
        case_revision: int,
        consumer_kind: ArtifactKind,
        consumer_id: str,
    ) -> UsageSummary:
        """Append exactly-once usage rows rooted in completed call claims."""

        if consumer_kind not in {
            ArtifactKind.SCREENING_RESULT,
            ArtifactKind.BACKLOG_ITEM,
        }:
            raise ValueError("unsupported model call usage consumer kind")
        if not isinstance(case_revision, int) or isinstance(case_revision, bool):
            raise TypeError("model call usage case_revision must be an integer")
        if case_revision <= 0:
            raise ValueError("model call usage case_revision must be positive")
        if len(set(response_ids)) != len(response_ids):
            raise ContractViolation("model call usage response ids must be unique")

        total = UsageSummary()
        for response_id in response_ids:
            _require_sha256(response_id, "usage response_id")
            response = self._load_response(connection, run_id, response_id)
            if response.case_id != case_id:
                raise ContractViolation("usage response belongs to another Case")
            request_rows = connection.execute(
                "SELECT * FROM model_cache WHERE run_id = ? AND request_id = ?",
                (run_id, response.request_id),
            ).fetchall()
            if len(request_rows) != 1:
                raise RepositoryIntegrityError(
                    "model call usage requires one exact persisted request/cache binding"
                )
            request = self._request_from_cache_row(request_rows[0])
            self._validate_request_response_binding(run_id, request, response)
            claim_rows = connection.execute(
                "SELECT * FROM model_call_claims WHERE run_id = ? AND request_id = ?",
                (run_id, request.request_id),
            ).fetchall()
            if len(claim_rows) != 1:
                raise RepositoryIntegrityError(
                    "model call usage requires one durable completed claim"
                )
            claim = self._claim_from_row(claim_rows[0], request)
            if (
                claim.status != ModelCallClaimStatus.COMPLETED
                or claim.response_id != response.response_id
            ):
                raise RepositoryIntegrityError(
                    "model call usage claim is not completed by the exact response"
                )

            usage = UsageSummary(
                input_images=(len(request.media) if isinstance(request, VLMRequest) else 0),
                input_pixels=(
                    sum(item.width * item.height for item in request.media)
                    if isinstance(request, VLMRequest)
                    else 0
                ),
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                provider_latency_ms=response.latency_ms,
                retries=response.attempt_index,
                estimated_cost=request.budget.estimate_cost(
                    input_tokens=response.input_tokens,
                    output_tokens=response.output_tokens,
                ),
            )
            existing_rows = connection.execute(
                """
                SELECT * FROM model_call_usage_accounting
                WHERE run_id = ? AND (request_id = ? OR response_id = ?)
                """,
                (run_id, request.request_id, response.response_id),
            ).fetchall()
            if existing_rows:
                if len(existing_rows) != 1:
                    raise RepositoryIntegrityError(
                        "model call usage identities select multiple accounting rows"
                    )
                existing = existing_rows[0]
                stored_usage = _load_document(
                    existing,
                    json_key="usage_json",
                    sha256_key="document_sha256",
                    model_type=UsageSummary,
                )
                stored_revision = _row_int(existing, "case_revision")
                stored_consumer_kind = _row_str(existing, "consumer_kind")
                stored_consumer_id = _row_str(existing, "consumer_id")
                if (
                    stored_revision != case_revision
                    or stored_consumer_kind != consumer_kind.value
                    or stored_consumer_id != consumer_id
                ):
                    raise RepositoryIntegrityError(
                        "model call usage was already consumed by another Case transition"
                    )
                _require_sha256(stored_consumer_id, "usage consumer_id")
                _parse_utc_timestamp(
                    _row_str(existing, "accounted_at"),
                    "model call usage accounting time",
                )
                authority_table = {
                    ArtifactKind.SCREENING_RESULT.value: (
                        "screening_results",
                        "screening_id",
                    ),
                    ArtifactKind.BACKLOG_ITEM.value: ("backlog_items", "item_id"),
                }.get(stored_consumer_kind)
                if authority_table is None:
                    raise RepositoryIntegrityError(
                        "model call usage accounting has an unsupported consumer"
                    )
                table, identity_column = authority_table
                consumer_row = connection.execute(
                    f"""
                    SELECT 1 FROM {table}
                    WHERE run_id = ? AND case_id = ? AND {identity_column} = ?
                    """,
                    (run_id, case_id, stored_consumer_id),
                ).fetchone()
                case_version_row = connection.execute(
                    """
                    SELECT 1 FROM case_versions
                    WHERE run_id = ? AND case_id = ? AND revision = ?
                    """,
                    (run_id, case_id, stored_revision),
                ).fetchone()
                if consumer_row is None or case_version_row is None:
                    raise RepositoryIntegrityError(
                        "model call usage accounting consumer authority is missing"
                    )
                indexed = (
                    _row_str(existing, "run_id"),
                    _row_str(existing, "request_id"),
                    _row_str(existing, "response_id"),
                    _row_str(existing, "case_id"),
                    _row_int(existing, "input_images"),
                    _row_int(existing, "input_pixels"),
                    _row_int(existing, "input_tokens"),
                    _row_int(existing, "output_tokens"),
                    _row_int(existing, "provider_latency_ms"),
                    _row_int(existing, "retries"),
                    float(existing["estimated_cost"]),
                )
                expected = (
                    run_id,
                    request.request_id,
                    response.response_id,
                    case_id,
                    usage.input_images,
                    usage.input_pixels,
                    usage.input_tokens,
                    usage.output_tokens,
                    usage.provider_latency_ms,
                    usage.retries,
                    usage.estimated_cost,
                )
                if indexed != expected or stored_usage != usage:
                    raise RepositoryIntegrityError(
                        "model call usage accounting differs from completed claim metrics"
                    )
                continue

            usage_json, usage_sha256 = _document(usage)
            connection.execute(
                """
                INSERT INTO model_call_usage_accounting(
                    run_id, request_id, response_id, case_id, case_revision,
                    consumer_kind, consumer_id, accounted_at,
                    input_images, input_pixels, input_tokens, output_tokens,
                    provider_latency_ms, retries, estimated_cost,
                    usage_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    request.request_id,
                    response.response_id,
                    case_id,
                    case_revision,
                    consumer_kind.value,
                    consumer_id,
                    self._recorded_at(),
                    usage.input_images,
                    usage.input_pixels,
                    usage.input_tokens,
                    usage.output_tokens,
                    usage.provider_latency_ms,
                    usage.retries,
                    usage.estimated_cost,
                    usage_json,
                    usage_sha256,
                ),
            )
            total = self._add_usage(total, usage)
        return total
