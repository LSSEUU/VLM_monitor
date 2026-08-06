"""Cross-table authority validation for reconstructed M3 SQLite artifacts.

Row decoding and duplicated-index checks happen before this validator runs.
This module only proves durable reference, history, audit, and transaction
bindings and reports failures through the repository-owned callback.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from itertools import pairwise
from typing import TYPE_CHECKING, cast

from pydantic import ValidationError

from labcourt.contracts.artifact_validation import M3ArtifactInventoryKind
from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogRetryFailure,
)
from labcourt.contracts.cases import UsageSummary
from labcourt.contracts.enums import ArtifactKind, BacklogStatus, ModelParseStatus
from labcourt.contracts.model_call_failures import (
    ModelCallFailureAuthority,
    ModelCallFailureClosureKind,
)
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.verdicts import ProceduralDefect, ProceduralReview, Verdict

from ._readonly_m3_artifact_codec import (
    _SHA256,
    _canonical_timestamp,
    _HeadRecord,
    _IndexFailure,
    _integer,
    _operational_context_is_authorized,
    _optional_text,
    _Record,
    _same_backlog_identity,
    _same_request_response,
    _same_semantic_request,
    _text,
)

if TYPE_CHECKING:
    from .readonly_m3_artifacts import M3ArtifactAuthorityFailure

_ReferenceFailure = Callable[
    [list["M3ArtifactAuthorityFailure"], _Record | _HeadRecord, str],
    None,
]


class M3ArtifactReferenceValidator:
    """Validate all M3 cross-table bindings for one read transaction."""

    __slots__ = ("_report_reference_failure",)

    def __init__(self, report_reference_failure: _ReferenceFailure) -> None:
        self._report_reference_failure = report_reference_failure

    @staticmethod
    def _record_map(records: list[_Record]) -> dict[str, _Record]:
        return {record.artifact_id: record for record in records if record.artifact_id is not None}

    def _reference_failure(
        self,
        failures: list[M3ArtifactAuthorityFailure],
        record: _Record | _HeadRecord,
        reason_code: str,
    ) -> None:
        self._report_reference_failure(failures, record, reason_code)

    @staticmethod
    def _legal_backlog_transition(previous: BacklogItem, current: BacklogItem) -> bool:
        """Validate one adjacent queue transition without trusting its head row."""

        if previous.status == BacklogStatus.PENDING:
            return (
                current.status == BacklogStatus.LEASED
                and current.attempt_count == previous.attempt_count + 1
                and current.retry_generation == previous.retry_generation
            )
        if previous.status != BacklogStatus.LEASED:
            return False
        if current.status not in {
            BacklogStatus.PENDING,
            BacklogStatus.COMPLETED,
            BacklogStatus.EXHAUSTED,
        }:
            return False
        if current.attempt_count != previous.attempt_count:
            return False
        return current.retry_generation == previous.retry_generation or (
            current.status == BacklogStatus.PENDING
            and current.retry_generation == previous.retry_generation + 1
        )

    @staticmethod
    def _repair_history_matches(
        repair: StructureRepairRequest,
        claims: dict[str, _Record],
        responses: dict[str, _Record],
        receipts_by_response: dict[str, _Record],
    ) -> bool:
        original_request_record = claims.get(repair.original_request_id)
        original_response_record = responses.get(repair.original_response_id)
        first_receipt_record = receipts_by_response.get(repair.original_response_id)
        if (
            original_request_record is None
            or original_response_record is None
            or first_receipt_record is None
            or not isinstance(original_request_record.document, VLMRequest)
            or not isinstance(original_response_record.document, VLMResponse)
            or not isinstance(first_receipt_record.document, ModelParseReceipt)
        ):
            return False
        original_request = original_request_record.document
        original_response = original_response_record.document
        first_receipt = first_receipt_record.document
        original_context_id = (
            original_request.backlog_retry_context.context_id
            if original_request.backlog_retry_context is not None
            else None
        )
        return (
            _same_request_response(original_request, original_response)
            and repair.run_id == original_request.run_id
            and repair.case_id == original_request.case_id
            and repair.evidence_pack_id == original_request.evidence_pack_id
            and repair.evidence_pack_version == original_request.evidence_pack_version
            and repair.original_request_sha256 == original_request.request_sha256
            and repair.original_response_sha256 == original_response.content_sha256
            and repair.manifest_id == original_request.manifest_id
            and repair.backlog_retry_context == original_request.backlog_retry_context
            and repair.original_backlog_retry_context_id == original_context_id
            and first_receipt.attempt_index == 0
            and first_receipt.status == ModelParseStatus.REPAIR_REQUIRED
            and first_receipt.repair_request_id == repair.request_id
            and first_receipt.request_id == original_request.request_id
            and first_receipt.request_sha256 == original_request.request_sha256
            and first_receipt.response_id == original_response.response_id
            and first_receipt.response_content_sha256 == original_response.content_sha256
            and first_receipt.output_schema_sha256
            == original_request.prompt_manifest.output_schema_sha256
            and first_receipt.run_id == repair.run_id
            and first_receipt.case_id == repair.case_id
            and first_receipt.evidence_pack_id == repair.evidence_pack_id
            and first_receipt.evidence_pack_version == repair.evidence_pack_version
            and first_receipt.manifest_id == repair.manifest_id
            and tuple(defect.code for defect in first_receipt.defects) == repair.parse_defect_codes
        )

    def _parse_history_for_output(
        self,
        output: ParsedScreeningOutput,
        claims: dict[str, _Record],
        responses: dict[str, _Record],
        receipts_by_response: dict[str, _Record],
    ) -> tuple[ModelParseReceipt, ...] | None:
        final_record = receipts_by_response.get(output.response_id)
        if final_record is None or not isinstance(
            final_record.document,
            ModelParseReceipt,
        ):
            return None
        final = final_record.document
        if (
            final.status != ModelParseStatus.PARSED
            or final.parsed_output_id != output.parsed_output_id
            or final.parsed_output_sha256 != output.parsed_output_sha256
        ):
            return None
        if final.attempt_index == 0:
            return (final,)
        repair_record = claims.get(final.request_id)
        if repair_record is None or not isinstance(
            repair_record.document,
            StructureRepairRequest,
        ):
            return None
        repair = repair_record.document
        if not self._repair_history_matches(
            repair,
            claims,
            responses,
            receipts_by_response,
        ):
            return None
        first_record = receipts_by_response.get(repair.original_response_id)
        if first_record is None or not isinstance(
            first_record.document,
            ModelParseReceipt,
        ):
            return None
        return first_record.document, final

    def validate(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        heads: tuple[_HeadRecord, ...],
        cache_requests: dict[str, VLMCallRequest],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        claims = self._record_map(records[M3ArtifactInventoryKind.MODEL_CALL_CLAIM])
        failure_authorities = records[M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY]
        responses = self._record_map(records[M3ArtifactInventoryKind.MODEL_RESPONSE])
        outputs = self._record_map(records[M3ArtifactInventoryKind.PARSED_SCREENING_OUTPUT])
        receipts = self._record_map(records[M3ArtifactInventoryKind.MODEL_PARSE_RECEIPT])
        cache_entries = self._record_map(records[M3ArtifactInventoryKind.MODEL_CACHE_ENTRY])
        screenings = self._record_map(records[M3ArtifactInventoryKind.SCREENING_RESULT])
        verdicts = self._record_map(records[M3ArtifactInventoryKind.VERDICT])
        reviews = self._record_map(records[M3ArtifactInventoryKind.PROCEDURAL_REVIEW])
        backlog_items = self._record_map(records[M3ArtifactInventoryKind.BACKLOG_ITEM])

        cache_by_request = {
            cast(ModelCacheEntry, record.document).request_id: record
            for record in cache_entries.values()
        }
        response_by_request = {
            cast(VLMResponse, record.document).request_id: record for record in responses.values()
        }
        receipt_by_response = {
            cast(ModelParseReceipt, record.document).response_id: record
            for record in receipts.values()
        }
        failure_authorities_by_request: dict[str, list[ModelCallFailureAuthority]] = {}
        for authority_record in failure_authorities:
            authority = cast(ModelCallFailureAuthority, authority_record.document)
            failure_authorities_by_request.setdefault(
                authority.request.request_id,
                [],
            ).append(authority)

        cases = {
            (_text(row, "case_id"), _text(row, "manifest_id"))
            for row in connection.execute(
                "SELECT case_id, manifest_id FROM cases WHERE run_id = ?",
                (run_id,),
            ).fetchall()
        }
        packs = {
            (
                _text(row, "case_id"),
                _text(row, "pack_id"),
                _integer(row, "version"),
                _text(row, "manifest_id"),
            )
            for row in connection.execute(
                """
                SELECT case_id, pack_id, version, manifest_id
                FROM evidence_packs WHERE run_id = ?
                """,
                (run_id,),
            ).fetchall()
        }

        def has_scope(
            case_id: str,
            pack_id: str,
            pack_version: int,
            manifest_id: str,
        ) -> bool:
            return (case_id, manifest_id) in cases and (
                case_id,
                pack_id,
                pack_version,
                manifest_id,
            ) in packs

        self._validate_failure_authority_references(
            connection,
            run_id,
            records,
            claims,
            backlog_items,
            has_scope,
            failures,
        )

        for record in claims.values():
            request = cast(VLMCallRequest, record.document)
            if not has_scope(
                request.case_id,
                request.evidence_pack_id,
                request.evidence_pack_version,
                request.manifest_id,
            ):
                self._reference_failure(failures, record, "CASE_PACK_SCOPE_MISSING")
                continue
            if isinstance(request, StructureRepairRequest) and not self._repair_history_matches(
                request,
                claims,
                responses,
                receipt_by_response,
            ):
                self._reference_failure(
                    failures,
                    record,
                    "REPAIR_REQUEST_HISTORY_MISMATCH",
                )
            status = _text(record.row, "status")
            response_record = response_by_request.get(request.request_id)
            cache_record = cache_by_request.get(request.request_id)
            if status == "ACTIVE":
                if response_record is not None or cache_record is not None:
                    self._reference_failure(
                        failures,
                        record,
                        "ACTIVE_CLAIM_HAS_DURABLE_COMPLETION",
                    )
                continue
            response_id = _text(record.row, "response_id")
            if (
                response_record is None
                or cache_record is None
                or response_record.artifact_id != response_id
                or not _same_request_response(
                    request,
                    cast(VLMResponse, response_record.document),
                )
            ):
                self._reference_failure(
                    failures,
                    record,
                    "COMPLETED_CLAIM_BINDING_MISSING",
                )

        for record in responses.values():
            response = cast(VLMResponse, record.document)
            claim_record = claims.get(response.request_id)
            cache_record = cache_by_request.get(response.request_id)
            if not has_scope(
                response.case_id,
                response.evidence_pack_id,
                response.evidence_pack_version,
                response.manifest_id,
            ):
                self._reference_failure(failures, record, "CASE_PACK_SCOPE_MISSING")
            elif (
                claim_record is None
                or _text(claim_record.row, "status") != "COMPLETED"
                or _optional_text(claim_record.row, "response_id") != response.response_id
                or cache_record is None
            ):
                self._reference_failure(
                    failures,
                    record,
                    "ATOMIC_CALL_BINDING_MISSING",
                )

        for record in cache_entries.values():
            entry = cast(ModelCacheEntry, record.document)
            cache_request = cache_requests.get(entry.cache_entry_id)
            response_record = responses.get(entry.response_id)
            claim_record = claims.get(entry.request_id)
            if cache_request is None or response_record is None or claim_record is None:
                self._reference_failure(failures, record, "CACHE_REFERENCE_MISSING")
                continue
            response = cast(VLMResponse, response_record.document)
            claim_request = cast(VLMCallRequest, claim_record.document)
            operational_context_authorized = _operational_context_is_authorized(
                claim_request,
                cache_request,
                failure_authorities_by_request.get(entry.request_id, []),
            )
            try:
                CachedModelResponse(entry=entry, response=response)
            except ValidationError:
                self._reference_failure(failures, record, "CACHE_RESPONSE_BINDING_MISMATCH")
                continue
            if (
                not _same_request_response(cache_request, response)
                or not operational_context_authorized
                or _text(claim_record.row, "status") != "COMPLETED"
                or _optional_text(claim_record.row, "response_id") != response.response_id
            ):
                self._reference_failure(failures, record, "CACHE_REQUEST_BINDING_MISMATCH")

        for record in outputs.values():
            output = cast(ParsedScreeningOutput, record.document)
            response_record = responses.get(output.response_id)
            if response_record is None:
                self._reference_failure(failures, record, "PARSED_RESPONSE_MISSING")
                continue
            response = cast(VLMResponse, response_record.document)
            receipt_record = receipt_by_response.get(output.response_id)
            receipt = (
                cast(ModelParseReceipt, receipt_record.document)
                if receipt_record is not None
                else None
            )
            if (
                output.case_id != response.case_id
                or output.evidence_pack_id != response.evidence_pack_id
                or output.evidence_pack_version != response.evidence_pack_version
                or output.request_id != response.request_id
                or output.response_content_sha256 != response.content_sha256
                or output.manifest_id != response.manifest_id
                or receipt is None
                or receipt.status != ModelParseStatus.PARSED
                or receipt.parsed_output_id != output.parsed_output_id
                or receipt.parsed_output_sha256 != output.parsed_output_sha256
            ):
                self._reference_failure(failures, record, "PARSED_RESPONSE_BINDING_MISMATCH")

        defects_by_owner: dict[tuple[str, str], list[_Record]] = {}
        for defect_record in records[M3ArtifactInventoryKind.PROCEDURAL_DEFECT]:
            key = (
                _text(defect_record.row, "owner_kind"),
                _text(defect_record.row, "owner_id"),
            )
            defects_by_owner.setdefault(key, []).append(defect_record)

        for record in receipts.values():
            receipt = cast(ModelParseReceipt, record.document)
            response_record = responses.get(receipt.response_id)
            if response_record is None:
                self._reference_failure(failures, record, "PARSE_RESPONSE_MISSING")
                continue
            response = cast(VLMResponse, response_record.document)
            if (
                receipt.run_id != response.run_id
                or receipt.case_id != response.case_id
                or receipt.evidence_pack_id != response.evidence_pack_id
                or receipt.evidence_pack_version != response.evidence_pack_version
                or receipt.request_id != response.request_id
                or receipt.request_sha256 != response.request_sha256
                or receipt.response_content_sha256 != response.content_sha256
                or receipt.attempt_index != response.attempt_index
                or receipt.manifest_id != response.manifest_id
            ):
                self._reference_failure(failures, record, "PARSE_RESPONSE_BINDING_MISMATCH")
                continue
            request_record = claims.get(receipt.request_id)
            receipt_request = (
                cast(VLMCallRequest, request_record.document)
                if request_record is not None
                else None
            )
            request_type_matches = (
                isinstance(receipt_request, VLMRequest)
                if receipt.attempt_index == 0
                else isinstance(receipt_request, StructureRepairRequest)
            )
            if (
                receipt_request is None
                or not request_type_matches
                or not _same_request_response(receipt_request, response)
            ):
                self._reference_failure(failures, record, "PARSE_REQUEST_BINDING_MISMATCH")
                continue
            if isinstance(
                receipt_request,
                StructureRepairRequest,
            ) and not self._repair_history_matches(
                receipt_request,
                claims,
                responses,
                receipt_by_response,
            ):
                self._reference_failure(failures, record, "PARSE_REPAIR_HISTORY_MISMATCH")
            if receipt.status == ModelParseStatus.REPAIR_REQUIRED:
                repair_record = (
                    claims.get(receipt.repair_request_id)
                    if receipt.repair_request_id is not None
                    else None
                )
                repair = repair_record.document if repair_record is not None else None
                if not isinstance(
                    repair,
                    StructureRepairRequest,
                ) or not self._repair_history_matches(
                    repair,
                    claims,
                    responses,
                    receipt_by_response,
                ):
                    self._reference_failure(
                        failures,
                        record,
                        "PARSE_REPAIR_HISTORY_MISMATCH",
                    )
            if receipt.status == ModelParseStatus.PARSED:
                output_record = (
                    outputs.get(receipt.parsed_output_id)
                    if receipt.parsed_output_id is not None
                    else None
                )
                if (
                    output_record is None
                    or cast(
                        ParsedScreeningOutput,
                        output_record.document,
                    ).parsed_output_sha256
                    != receipt.parsed_output_sha256
                ):
                    self._reference_failure(
                        failures,
                        record,
                        "PARSE_OUTPUT_BINDING_MISMATCH",
                    )
                    continue
            owner_defects = sorted(
                defects_by_owner.get(
                    (ArtifactKind.MODEL_PARSE_RECEIPT.value, receipt.parse_receipt_id),
                    [],
                ),
                key=lambda item: _integer(item.row, "ordinal"),
            )
            if tuple(cast(ProceduralDefect, item.document) for item in owner_defects) != (
                receipt.defects
            ):
                self._reference_failure(failures, record, "PARSE_DEFECT_SET_MISMATCH")

        self._validate_screening_verdict_review_references(
            connection,
            records,
            claims,
            responses,
            receipt_by_response,
            outputs,
            screenings,
            verdicts,
            reviews,
            defects_by_owner,
            has_scope,
            failures,
        )
        self._validate_usage_references(
            connection,
            records,
            claims,
            responses,
            receipt_by_response,
            screenings,
            cache_by_request,
            cache_requests,
            failure_authorities_by_request,
            failures,
        )
        self._validate_backlog_references(
            connection,
            run_id,
            records,
            heads,
            backlog_items,
            screenings,
            reviews,
            failures,
        )

        for defect_record in records[M3ArtifactInventoryKind.PROCEDURAL_DEFECT]:
            owner_kind = _text(defect_record.row, "owner_kind")
            owner_id = _text(defect_record.row, "owner_id")
            owner = (
                receipts.get(owner_id)
                if owner_kind == "MODEL_PARSE_RECEIPT"
                else reviews.get(owner_id)
            )
            if owner is None:
                self._reference_failure(failures, defect_record, "DEFECT_OWNER_MISSING")

    def _validate_failure_authority_references(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        claims: dict[str, _Record],
        backlog_items: dict[str, _Record],
        has_scope: Callable[[str, str, int, str], bool],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        versions_by_key = {
            (
                cast(BacklogItem, record.document).item_id,
                _integer(record.row, "version"),
            ): record
            for record in records[M3ArtifactInventoryKind.BACKLOG_ITEM_VERSION]
        }
        completion_receipts = self._record_map(
            records[M3ArtifactInventoryKind.BACKLOG_COMPLETION_RECEIPT]
        )
        for record in records[M3ArtifactInventoryKind.MODEL_CALL_FAILURE_AUTHORITY]:
            authority = cast(ModelCallFailureAuthority, record.document)
            request = authority.request
            claim_record = claims.get(request.request_id)
            identity_record = backlog_items.get(authority.backlog_item_id)
            version_record = versions_by_key.get(
                (authority.backlog_item_id, authority.backlog_version)
            )
            if claim_record is None or identity_record is None or version_record is None:
                self._reference_failure(
                    failures,
                    record,
                    "MODEL_CALL_FAILURE_AUTHORITY_REFERENCE_MISSING",
                )
                continue
            claim_request = cast(VLMCallRequest, claim_record.document)
            initial = cast(BacklogItem, identity_record.document)
            version = cast(BacklogItem, version_record.document)
            current_takeover_count = -1
            try:
                current_takeover_count = _integer(claim_record.row, "takeover_count")
                current_epoch_matches = authority.claim_takeover_count < current_takeover_count or (
                    authority.claim_takeover_count == current_takeover_count
                    and _text(claim_record.row, "status") == "ACTIVE"
                    and _text(claim_record.row, "owner_token_sha256")
                    == authority.claim_owner_sha256
                    and _text(claim_record.row, "lease_expires_at")
                    == _canonical_timestamp(authority.claim_lease_expires_at)
                )
            except _IndexFailure:
                current_epoch_matches = False
            audit_row = connection.execute(
                """
                SELECT cv.audit_sequence, ae.entry_hash, ae.manifest_id,
                       ae.object_kind, ae.object_id
                FROM case_versions AS cv
                JOIN audit_entries AS ae
                  ON ae.run_id = cv.run_id AND ae.sequence = cv.audit_sequence
                WHERE cv.run_id = ? AND cv.case_id = ? AND cv.revision = ?
                      AND ae.sequence = ?
                """,
                (
                    run_id,
                    request.case_id,
                    authority.closure_case_revision,
                    authority.closure_audit_sequence,
                ),
            ).fetchone()
            audit_matches = False
            if audit_row is not None:
                try:
                    audit_matches = (
                        _integer(audit_row, "audit_sequence") == authority.closure_audit_sequence
                        and _text(audit_row, "entry_hash") == authority.closure_audit_entry_hash
                        and _text(audit_row, "manifest_id") == authority.manifest_id
                        and _text(audit_row, "object_kind") == ArtifactKind.BACKLOG_ITEM.value
                        and _text(audit_row, "object_id") == authority.backlog_item_id
                    )
                except _IndexFailure:
                    audit_matches = False
            receipt_matches = authority.completion_receipt_id is None
            if authority.closure_kind == ModelCallFailureClosureKind.RETRY_FAILURE:
                receipt_record = (
                    completion_receipts.get(authority.completion_receipt_id)
                    if authority.completion_receipt_id is not None
                    else None
                )
                receipt = (
                    cast(BacklogCompletionReceipt, receipt_record.document)
                    if receipt_record is not None
                    else None
                )
                if isinstance(receipt, BacklogCompletionReceipt) and isinstance(
                    receipt.outcome,
                    BacklogRetryFailure,
                ):
                    outcome = receipt.outcome
                    receipt_matches = (
                        outcome.reason_code == authority.backlog_reason_code
                        and outcome.lease.item_id == authority.backlog_item_id
                        and outcome.lease.retry_generation == authority.retry_generation
                        and outcome.lease.attempt_count == authority.backlog_attempt_count
                        and receipt.backlog_status == authority.backlog_status
                        and receipt.completion_case_revision == authority.closure_case_revision
                        and receipt.completion_audit_sequence == authority.closure_audit_sequence
                        and receipt.completion_audit_entry_hash
                        == authority.closure_audit_entry_hash
                        and receipt.manifest_id == authority.manifest_id
                    )
                else:
                    receipt_matches = False
            if (
                not _same_semantic_request(claim_request, request)
                or authority.claim_takeover_count > current_takeover_count
                or not current_epoch_matches
                or not has_scope(
                    request.case_id,
                    request.evidence_pack_id,
                    request.evidence_pack_version,
                    request.manifest_id,
                )
                or initial.case_id != request.case_id
                or initial.reason_code != authority.backlog_reason_code
                or initial.role != request.role
                or initial.manifest_id != authority.manifest_id
                or not _same_backlog_identity(initial, version)
                or version.status != authority.backlog_status
                or version.attempt_count != authority.backlog_attempt_count
                or version.retry_generation != authority.retry_generation
                or not audit_matches
                or not receipt_matches
            ):
                self._reference_failure(
                    failures,
                    record,
                    "MODEL_CALL_FAILURE_AUTHORITY_BINDING_MISMATCH",
                )

    @staticmethod
    def _audit_case_binding(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        manifest_id: str,
        audit_sequence: int,
        accepted_objects: set[tuple[str, str]],
    ) -> bool:
        row = connection.execute(
            """
            SELECT ae.manifest_id, ae.object_kind, ae.object_id, ae.after_sha256,
                   ae.entry_hash, cv.case_id, cv.document_sha256
            FROM audit_entries AS ae
            JOIN case_versions AS cv
              ON cv.run_id = ae.run_id AND cv.audit_sequence = ae.sequence
            WHERE ae.run_id = ? AND ae.sequence = ?
            """,
            (run_id, audit_sequence),
        ).fetchone()
        if row is None:
            return False
        try:
            return (
                _text(row, "manifest_id") == manifest_id
                and _text(row, "case_id") == case_id
                and (
                    _text(row, "object_kind"),
                    _text(row, "object_id"),
                )
                in accepted_objects
                and _text(row, "after_sha256") == _text(row, "document_sha256")
                and _SHA256.fullmatch(_text(row, "entry_hash")) is not None
            )
        except _IndexFailure:
            return False

    def _validate_screening_verdict_review_references(
        self,
        connection: sqlite3.Connection,
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        claims: dict[str, _Record],
        responses: dict[str, _Record],
        receipts_by_response: dict[str, _Record],
        outputs: dict[str, _Record],
        screenings: dict[str, _Record],
        verdicts: dict[str, _Record],
        reviews: dict[str, _Record],
        defects_by_owner: dict[tuple[str, str], list[_Record]],
        has_scope: Callable[[str, str, int, str], bool],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        review_by_verdict = {
            cast(ProceduralReview, record.document).reviewed_verdict_id: record
            for record in reviews.values()
        }
        reviews_by_screening: dict[str, list[_Record]] = {}
        for review_record in reviews.values():
            review = cast(ProceduralReview, review_record.document)
            verdict_record = verdicts.get(review.reviewed_verdict_id)
            if verdict_record is None:
                continue
            verdict = cast(Verdict, verdict_record.document)
            reviews_by_screening.setdefault(verdict.screening_id, []).append(review_record)

        for record in screenings.values():
            screening = cast(ScreeningResult, record.document)
            output_record = outputs.get(screening.parsed_output.parsed_output_id)
            accepted_objects = {(ArtifactKind.SCREENING_RESULT.value, screening.screening_id)}
            accepted_objects.update(
                (
                    ArtifactKind.PROCEDURAL_REVIEW.value,
                    cast(ProceduralReview, review.document).review_id,
                )
                for review in reviews_by_screening.get(screening.screening_id, [])
                if _integer(review.row, "audit_sequence") == _integer(record.row, "audit_sequence")
            )
            if (
                output_record is None
                or cast(ParsedScreeningOutput, output_record.document) != screening.parsed_output
                or not has_scope(
                    screening.case_id,
                    screening.evidence_pack_id,
                    screening.evidence_pack_version,
                    screening.manifest_id,
                )
                or not self._audit_case_binding(
                    connection,
                    run_id=screening.run_id,
                    case_id=screening.case_id,
                    manifest_id=screening.manifest_id,
                    audit_sequence=_integer(record.row, "audit_sequence"),
                    accepted_objects=accepted_objects,
                )
            ):
                self._reference_failure(
                    failures,
                    record,
                    "SCREENING_AUTHORITY_BINDING_MISMATCH",
                )

        for record in verdicts.values():
            verdict = cast(Verdict, record.document)
            screening_record = screenings.get(verdict.screening_id)
            bound_review = review_by_verdict.get(verdict.verdict_id)
            screening_matches = False
            if screening_record is not None:
                screening = cast(ScreeningResult, screening_record.document)
                history = self._parse_history_for_output(
                    screening.parsed_output,
                    claims,
                    responses,
                    receipts_by_response,
                )
                expected_response_ids = (
                    tuple(sorted(receipt.response_id for receipt in history))
                    if history is not None
                    else ()
                )
                screening_matches = (
                    verdict.run_id == screening.run_id
                    and verdict.case_id == screening.case_id
                    and verdict.evidence_pack_id == screening.evidence_pack_id
                    and verdict.evidence_pack_version == screening.evidence_pack_version
                    and verdict.manifest_id == screening.manifest_id
                    and verdict.violation_type == screening.parsed_output.violation_type
                    and verdict.decision.value == screening.decision.value
                    and tuple(reference.artifact_id for reference in verdict.model_response_refs)
                    == expected_response_ids
                )
            if (
                not screening_matches
                or bound_review is None
                or not has_scope(
                    verdict.case_id,
                    verdict.evidence_pack_id,
                    verdict.evidence_pack_version,
                    verdict.manifest_id,
                )
                or _integer(bound_review.row, "audit_sequence")
                != _integer(record.row, "audit_sequence")
            ):
                self._reference_failure(
                    failures,
                    record,
                    "VERDICT_AUTHORITY_BINDING_MISMATCH",
                )

        for record in reviews.values():
            review = cast(ProceduralReview, record.document)
            verdict_record = verdicts.get(review.reviewed_verdict_id)
            owner_defects = sorted(
                defects_by_owner.get(
                    (ArtifactKind.PROCEDURAL_REVIEW.value, review.review_id),
                    [],
                ),
                key=lambda item: _integer(item.row, "ordinal"),
            )
            verdict_matches = False
            if verdict_record is not None:
                verdict = cast(Verdict, verdict_record.document)
                verdict_matches = (
                    verdict.case_id == review.case_id
                    and verdict.version == review.reviewed_verdict_version
                    and verdict.verdict_sha256 == review.reviewed_verdict_sha256
                    and verdict.evidence_pack_id == review.evidence_pack_id
                    and verdict.evidence_pack_version == review.evidence_pack_version
                    and verdict.manifest_id == review.manifest_id
                )
            if (
                not verdict_matches
                or tuple(cast(ProceduralDefect, item.document) for item in owner_defects)
                != review.defects
                or not has_scope(
                    review.case_id,
                    review.evidence_pack_id,
                    review.evidence_pack_version,
                    review.manifest_id,
                )
                or not self._audit_case_binding(
                    connection,
                    run_id=review.run_id,
                    case_id=review.case_id,
                    manifest_id=review.manifest_id,
                    audit_sequence=_integer(record.row, "audit_sequence"),
                    accepted_objects={(ArtifactKind.PROCEDURAL_REVIEW.value, review.review_id)},
                )
            ):
                self._reference_failure(
                    failures,
                    record,
                    "REVIEW_AUTHORITY_BINDING_MISMATCH",
                )

        del records

    def _validate_usage_references(
        self,
        connection: sqlite3.Connection,
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        claims: dict[str, _Record],
        responses: dict[str, _Record],
        receipts_by_response: dict[str, _Record],
        screenings: dict[str, _Record],
        cache_by_request: dict[str, _Record],
        cache_requests: dict[str, VLMCallRequest],
        failure_authorities_by_request: dict[str, list[ModelCallFailureAuthority]],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        for record in records[M3ArtifactInventoryKind.MODEL_CALL_USAGE]:
            usage = cast(UsageSummary, record.document)
            request_id = _text(record.row, "request_id")
            response_id = _text(record.row, "response_id")
            claim_record = claims.get(request_id)
            response_record = responses.get(response_id)
            cache_record = cache_by_request.get(request_id)
            if claim_record is None or response_record is None or cache_record is None:
                self._reference_failure(failures, record, "USAGE_CALL_BINDING_MISSING")
                continue
            entry = cast(ModelCacheEntry, cache_record.document)
            request = cache_requests.get(entry.cache_entry_id)
            response = cast(VLMResponse, response_record.document)
            if request is None:
                self._reference_failure(failures, record, "USAGE_REQUEST_MISSING")
                continue
            expected = UsageSummary(
                input_images=len(request.media) if isinstance(request, VLMRequest) else 0,
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
            consumer_kind = _text(record.row, "consumer_kind")
            consumer_id = _text(record.row, "consumer_id")
            case_revision = _integer(record.row, "case_revision")
            expected_audit_sequence: int | None = None
            response_is_consumed = False
            if consumer_kind == ArtifactKind.SCREENING_RESULT.value:
                screening_record = screenings.get(consumer_id)
                if screening_record is not None:
                    screening = cast(ScreeningResult, screening_record.document)
                    history = self._parse_history_for_output(
                        screening.parsed_output,
                        claims,
                        responses,
                        receipts_by_response,
                    )
                    response_is_consumed = history is not None and response.response_id in {
                        receipt.response_id for receipt in history
                    }
                    expected_audit_sequence = _integer(
                        screening_record.row,
                        "audit_sequence",
                    )
            else:
                matching_completions = []
                for completion_record in records[
                    M3ArtifactInventoryKind.BACKLOG_COMPLETION_RECEIPT
                ]:
                    completion = cast(
                        BacklogCompletionReceipt,
                        completion_record.document,
                    )
                    if (
                        isinstance(completion.outcome, BacklogRetryFailure)
                        and completion.outcome.lease.item_id == consumer_id
                        and any(
                            reference.artifact_id == response.response_id
                            for reference in completion.outcome.response_refs
                        )
                        and completion.completion_case_revision == case_revision
                    ):
                        matching_completions.append(completion)
                if len(matching_completions) == 1:
                    response_is_consumed = True
                    expected_audit_sequence = matching_completions[0].completion_audit_sequence
            consumer_table, identity_column = (
                ("screening_results", "screening_id")
                if consumer_kind == ArtifactKind.SCREENING_RESULT.value
                else ("backlog_items", "item_id")
            )
            consumer_exists = connection.execute(
                f"""
                SELECT 1 FROM {consumer_table}
                WHERE run_id = ? AND case_id = ? AND {identity_column} = ?
                """,
                (
                    _text(record.row, "run_id"),
                    _text(record.row, "case_id"),
                    consumer_id,
                ),
            ).fetchone()
            case_version = connection.execute(
                """
                SELECT audit_sequence FROM case_versions
                WHERE run_id = ? AND case_id = ? AND revision = ?
                """,
                (
                    _text(record.row, "run_id"),
                    _text(record.row, "case_id"),
                    case_revision,
                ),
            ).fetchone()
            case_version_matches = False
            if case_version is not None and expected_audit_sequence is not None:
                try:
                    case_version_matches = (
                        _integer(case_version, "audit_sequence") == expected_audit_sequence
                    )
                except _IndexFailure:
                    case_version_matches = False
            if (
                usage != expected
                or not _same_request_response(request, response)
                or not _operational_context_is_authorized(
                    cast(VLMCallRequest, claim_record.document),
                    request,
                    failure_authorities_by_request.get(request_id, []),
                )
                or _text(claim_record.row, "status") != "COMPLETED"
                or _optional_text(claim_record.row, "response_id") != response.response_id
                or _text(record.row, "case_id") != response.case_id
                or not response_is_consumed
                or consumer_exists is None
                or not case_version_matches
            ):
                self._reference_failure(
                    failures,
                    record,
                    "USAGE_AUTHORITY_BINDING_MISMATCH",
                )

    @staticmethod
    def _backlog_stage_input_matches(
        connection: sqlite3.Connection,
        item: BacklogItem,
    ) -> bool:
        if item.stage_input_ref.kind == ArtifactKind.EVENT:
            row = connection.execute(
                """
                SELECT 1 FROM cases
                WHERE run_id = ? AND case_id = ? AND event_id = ?
                  AND event_sha256 = ?
                """,
                (
                    item.run_id,
                    item.case_id,
                    item.stage_input_ref.artifact_id,
                    item.stage_input_sha256,
                ),
            ).fetchone()
        else:
            binding = {
                ArtifactKind.CASE: ("case_versions", "case_id"),
                ArtifactKind.EVIDENCE_PACK: ("evidence_packs", "pack_id"),
                ArtifactKind.MODEL_RESPONSE: ("model_responses", "response_id"),
                ArtifactKind.SCREENING_RESULT: ("screening_results", "screening_id"),
                ArtifactKind.VERDICT: ("verdicts", "verdict_id"),
                ArtifactKind.PROCEDURAL_REVIEW: ("procedural_reviews", "review_id"),
            }.get(item.stage_input_ref.kind)
            if binding is None:
                return False
            table, identity_column = binding
            query = (
                f"SELECT 1 FROM {table} "
                f"WHERE run_id = ? AND case_id = ? AND {identity_column} = ? "
                "AND document_sha256 = ?"
            )
            row = connection.execute(
                query,
                (
                    item.run_id,
                    item.case_id,
                    item.stage_input_ref.artifact_id,
                    item.stage_input_sha256,
                ),
            ).fetchone()
        return row is not None

    def _validate_backlog_references(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        records: dict[M3ArtifactInventoryKind, list[_Record]],
        heads: tuple[_HeadRecord, ...],
        backlog_items: dict[str, _Record],
        screenings: dict[str, _Record],
        reviews: dict[str, _Record],
        failures: list[M3ArtifactAuthorityFailure],
    ) -> None:
        version_records = records[M3ArtifactInventoryKind.BACKLOG_ITEM_VERSION]
        versions_by_item: dict[str, list[_Record]] = {}
        version_by_key: dict[tuple[str, int], _Record] = {}
        for record in version_records:
            item = cast(BacklogItem, record.document)
            version = _integer(record.row, "version")
            versions_by_item.setdefault(item.item_id, []).append(record)
            version_by_key[(item.item_id, version)] = record

        completion_records = records[M3ArtifactInventoryKind.BACKLOG_COMPLETION_RECEIPT]
        completion_records_by_exit: dict[tuple[str, int], list[_Record]] = {}
        for record in completion_records:
            completion_records_by_exit.setdefault(
                (
                    _text(record.row, "item_id"),
                    _integer(record.row, "backlog_version"),
                ),
                [],
            ).append(record)

        heads_by_item = {
            _text(head.row, "item_id"): head for head in heads if head.artifact_id is not None
        }
        for item_id, identity_record in backlog_items.items():
            initial = cast(BacklogItem, identity_record.document)
            versions = sorted(
                versions_by_item.get(item_id, []),
                key=lambda record: _integer(record.row, "version"),
            )
            head = heads_by_item.get(item_id)
            expected_versions = list(range(1, len(versions) + 1))
            observed_versions = [_integer(record.row, "version") for record in versions]
            identity_ok = all(
                _same_backlog_identity(initial, cast(BacklogItem, record.document))
                for record in versions
            )
            first_ok = (
                initial.status == BacklogStatus.PENDING
                and initial.attempt_count == 0
                and bool(versions)
                and cast(BacklogItem, versions[0].document) == initial
            )
            head_ok = (
                head is not None
                and bool(versions)
                and _integer(head.row, "current_version") == observed_versions[-1]
            )
            if (
                observed_versions != expected_versions
                or not identity_ok
                or not first_ok
                or not head_ok
                or not self._backlog_stage_input_matches(connection, initial)
            ):
                self._reference_failure(
                    failures,
                    identity_record,
                    "BACKLOG_HISTORY_BINDING_MISMATCH",
                )
            for version_record in versions:
                if not _same_backlog_identity(
                    initial,
                    cast(BacklogItem, version_record.document),
                ):
                    self._reference_failure(
                        failures,
                        version_record,
                        "BACKLOG_IDENTITY_BINDING_MISMATCH",
                    )
            for previous_record, exited_record in pairwise(versions):
                leased = cast(BacklogItem, previous_record.document)
                exited = cast(BacklogItem, exited_record.document)
                if not self._legal_backlog_transition(leased, exited):
                    self._reference_failure(
                        failures,
                        exited_record,
                        "BACKLOG_HISTORY_TRANSITION_INVALID",
                    )
                if leased.status != BacklogStatus.LEASED or exited.status == BacklogStatus.LEASED:
                    continue
                exit_key = (item_id, _integer(exited_record.row, "version"))
                receipt_count = len(completion_records_by_exit.get(exit_key, ()))
                if receipt_count != 1:
                    self._reference_failure(
                        failures,
                        exited_record,
                        (
                            "BACKLOG_LEASE_EXIT_RECEIPT_MISSING"
                            if receipt_count == 0
                            else "BACKLOG_LEASE_EXIT_RECEIPT_MULTIPLE"
                        ),
                    )

        for item_id, versions in versions_by_item.items():
            if item_id in backlog_items:
                continue
            for record in versions:
                self._reference_failure(failures, record, "BACKLOG_IDENTITY_MISSING")
        for item_id, head in heads_by_item.items():
            versions = versions_by_item.get(item_id, [])
            if (
                item_id not in backlog_items
                or not versions
                or _integer(head.row, "current_version")
                != max(_integer(record.row, "version") for record in versions)
            ):
                self._reference_failure(failures, head, "BACKLOG_HEAD_BINDING_MISMATCH")

        for record in completion_records:
            receipt = cast(BacklogCompletionReceipt, record.document)
            outcome = receipt.outcome
            item_id = outcome.lease.item_id
            backlog_version = _integer(record.row, "backlog_version")
            completed_record = version_by_key.get((item_id, backlog_version))
            leased_record = version_by_key.get((item_id, backlog_version - 1))
            if completed_record is None or leased_record is None:
                self._reference_failure(
                    failures,
                    record,
                    "BACKLOG_RECEIPT_VERSION_MISSING",
                )
                continue
            completed = cast(BacklogItem, completed_record.document)
            leased = cast(BacklogItem, leased_record.document)
            expected_generation = (
                outcome.next_retry_generation
                if isinstance(outcome, BacklogRetryFailure)
                else outcome.lease.retry_generation
            )
            completion_exists = False
            if receipt.completion_ref.kind == ArtifactKind.BACKLOG_ITEM:
                completion_exists = receipt.completion_ref.artifact_id in backlog_items
            elif receipt.completion_ref.kind == ArtifactKind.SCREENING_RESULT:
                completion_exists = receipt.completion_ref.artifact_id in screenings
            elif receipt.completion_ref.kind == ArtifactKind.PROCEDURAL_REVIEW:
                completion_exists = receipt.completion_ref.artifact_id in reviews
            case_row = connection.execute(
                """
                SELECT status, document_sha256, audit_sequence FROM case_versions
                WHERE run_id = ? AND case_id = ? AND revision = ?
                """,
                (
                    run_id,
                    completed.case_id,
                    receipt.completion_case_revision,
                ),
            ).fetchone()
            audit_ok = self._audit_case_binding(
                connection,
                run_id=run_id,
                case_id=completed.case_id,
                manifest_id=receipt.manifest_id,
                audit_sequence=receipt.completion_audit_sequence,
                accepted_objects={
                    (
                        receipt.completion_ref.kind.value,
                        receipt.completion_ref.artifact_id,
                    )
                },
            )
            if case_row is not None:
                try:
                    audit_ok = (
                        audit_ok
                        and _text(case_row, "status") == receipt.completion_case_status.value
                        and _integer(case_row, "audit_sequence")
                        == receipt.completion_audit_sequence
                    )
                except _IndexFailure:
                    audit_ok = False
            if (
                completed.run_id != outcome.lease.run_id
                or completed.item_id != item_id
                or completed.attempt_count != outcome.lease.attempt_count
                or completed.retry_generation != expected_generation
                or completed.manifest_id != receipt.manifest_id
                or completed.status != receipt.backlog_status
                or leased.status != BacklogStatus.LEASED
                or leased.lease_id != outcome.lease.lease_id
                or leased.attempt_count != outcome.lease.attempt_count
                or leased.retry_generation != outcome.lease.retry_generation
                or _text(record.row, "case_id") != completed.case_id
                or not completion_exists
                or case_row is None
                or not audit_ok
            ):
                self._reference_failure(
                    failures,
                    record,
                    "BACKLOG_RECEIPT_AUTHORITY_MISMATCH",
                )


__all__ = ["M3ArtifactReferenceValidator"]
