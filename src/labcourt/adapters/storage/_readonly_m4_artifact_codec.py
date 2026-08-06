"""Strict canonical decoding and duplicated-index checks for M4 rows."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

from pydantic import BaseModel, TypeAdapter, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.evidence import Crop
from labcourt.contracts.hearing import (
    AcquisitionExecutionClaimAuthority,
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    EvidencePackDerivation,
    HearingBacklogCompletionReceipt,
    HearingBacklogRetryOutcome,
    HearingCheckpoint,
    HearingCycleScope,
    HearingHumanReviewReceipt,
    HearingInitialStrictParseFailureProof,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingReworkReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
    HearingUsageReceipt,
    HearingVerdictBinding,
    ToolExecutionManifest,
    ToolExecutionReceipt,
)
from labcourt.contracts.hearing_common import (
    _hearing_cycle_scope_id,
    _hearing_cycle_scope_projection,
    _hearing_cycle_scope_sha256,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind


class M4DocumentFailure(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class M4IndexFailure(ValueError):
    def __init__(self, reason_code: str = "INDEX_BINDING_MISMATCH") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class M4Record:
    kind: M4ProjectionArtifactKind
    table: str
    identity: str
    artifact_id: str
    row: sqlite3.Row
    document: BaseModel
    canonical_document: str


ModelT = TypeVar("ModelT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class M4TableSpec(Generic[ModelT]):
    table: str
    kind: M4ProjectionArtifactKind
    id_column: str
    json_column: str
    model: type[ModelT] | TypeAdapter[ModelT]
    hash_column: str | None = "document_sha256"
    semantic_hash_attribute: str | None = None
    order_by: str | None = None


_OUTCOME_ADAPTER: TypeAdapter[HearingBacklogRetryOutcome] = TypeAdapter(HearingBacklogRetryOutcome)
_STRICT_FAILURE_PROOF_ADAPTER: TypeAdapter[
    HearingInitialStrictParseFailureProof | HearingStrictParseFailureProof
] = TypeAdapter(HearingInitialStrictParseFailureProof | HearingStrictParseFailureProof)


M4_TYPED_TABLES: tuple[M4TableSpec[Any], ...] = (
    M4TableSpec(
        "m4_hearings",
        M4ProjectionArtifactKind.HEARING_SESSION,
        "hearing_id",
        "hearing_json",
        HearingSession,
        semantic_hash_attribute="session_sha256",
    ),
    M4TableSpec(
        "m4_hearing_cycles",
        M4ProjectionArtifactKind.HEARING_CYCLE,
        "cycle_id",
        "cycle_json",
        HearingCycleScope,
        hash_column=None,
        semantic_hash_attribute="cycle_sha256",
        order_by="hearing_id, cycle_index",
    ),
    M4TableSpec(
        "m4_precedent_retrieval_receipts",
        M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
        "retrieval_receipt_id",
        "receipt_json",
        HearingPrecedentRetrievalReceipt,
        semantic_hash_attribute="receipt_sha256",
    ),
    M4TableSpec(
        "m4_model_call_claims",
        M4ProjectionArtifactKind.MODEL_REQUEST,
        "request_id",
        "request_json",
        HearingModelRequest,
        hash_column="request_document_sha256",
    ),
    M4TableSpec(
        "m4_model_responses",
        M4ProjectionArtifactKind.MODEL_RESPONSE,
        "response_id",
        "response_json",
        HearingModelResponse,
    ),
    M4TableSpec(
        "m4_model_parse_receipts",
        M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
        "parse_receipt_id",
        "receipt_json",
        HearingModelParseReceipt,
    ),
    M4TableSpec(
        "m4_parsed_hearing_outputs",
        M4ProjectionArtifactKind.ROLE_OUTPUT,
        "parsed_output_id",
        "output_json",
        HearingRoleOutput,
    ),
    M4TableSpec(
        "m4_model_cache",
        M4ProjectionArtifactKind.MODEL_CACHE_ENTRY,
        "cache_entry_id",
        "entry_json",
        HearingModelCacheEntry,
    ),
    M4TableSpec(
        "m4_hearing_usage_receipts",
        M4ProjectionArtifactKind.USAGE_RECEIPT,
        "usage_receipt_id",
        "usage_json",
        HearingUsageReceipt,
    ),
    M4TableSpec(
        "m4_acquisition_requests",
        M4ProjectionArtifactKind.ACQUISITION_REQUEST,
        "acquisition_request_id",
        "request_json",
        AcquisitionRequest,
    ),
    M4TableSpec(
        "m4_acquisition_execution_claims",
        M4ProjectionArtifactKind.ACQUISITION_EXECUTION_CLAIM,
        "acquisition_request_id",
        "claim_json",
        AcquisitionExecutionClaimAuthority,
    ),
    M4TableSpec(
        "m4_hearing_rounds",
        M4ProjectionArtifactKind.HEARING_ROUND,
        "round_id",
        "round_json",
        HearingRound,
        hash_column=None,
        order_by="hearing_id, round_index",
    ),
    M4TableSpec(
        "m4_tool_execution_manifests",
        M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST,
        "execution_manifest_id",
        "manifest_json",
        ToolExecutionManifest,
    ),
    M4TableSpec(
        "m4_acquisition_execution_publications",
        M4ProjectionArtifactKind.ACQUISITION_EXECUTION_PUBLICATION,
        "execution_publication_id",
        "publication_json",
        AcquisitionExecutionPublication,
    ),
    M4TableSpec(
        "m4_acquired_crops",
        M4ProjectionArtifactKind.ACQUIRED_CROP,
        "crop_id",
        "crop_json",
        Crop,
    ),
    M4TableSpec(
        "m4_tool_execution_receipts",
        M4ProjectionArtifactKind.TOOL_EXECUTION_RECEIPT,
        "receipt_id",
        "receipt_json",
        ToolExecutionReceipt,
    ),
    M4TableSpec(
        "m4_evidence_pack_derivations",
        M4ProjectionArtifactKind.EVIDENCE_PACK_DERIVATION,
        "derivation_id",
        "derivation_json",
        EvidencePackDerivation,
    ),
    M4TableSpec(
        "m4_hearing_verdict_bindings",
        M4ProjectionArtifactKind.VERDICT_BINDING,
        "binding_id",
        "binding_json",
        HearingVerdictBinding,
    ),
    M4TableSpec(
        "m4_rework_receipts",
        M4ProjectionArtifactKind.REWORK_RECEIPT,
        "rework_receipt_id",
        "receipt_json",
        HearingReworkReceipt,
    ),
    M4TableSpec(
        "m4_backlog_completion_receipts",
        M4ProjectionArtifactKind.HEARING_BACKLOG_COMPLETION,
        "receipt_id",
        "receipt_json",
        HearingBacklogCompletionReceipt,
        hash_column="receipt_sha256",
        semantic_hash_attribute="receipt_sha256",
    ),
    M4TableSpec(
        "m4_model_call_failure_authorities",
        M4ProjectionArtifactKind.MODEL_CALL_FAILURE_AUTHORITY,
        "authority_id",
        "authority_json",
        HearingModelCallFailureAuthority,
    ),
    M4TableSpec(
        "m4_hearing_checkpoints",
        M4ProjectionArtifactKind.HEARING_CHECKPOINT,
        "checkpoint_id",
        "checkpoint_json",
        HearingCheckpoint,
        hash_column="checkpoint_sha256",
        semantic_hash_attribute="checkpoint_sha256",
        order_by="hearing_id, version",
    ),
    M4TableSpec(
        "m4_hearing_human_review_receipts",
        M4ProjectionArtifactKind.HUMAN_REVIEW_RECEIPT,
        "receipt_id",
        "receipt_json",
        HearingHumanReviewReceipt,
        hash_column="receipt_sha256",
        semantic_hash_attribute="receipt_sha256",
    ),
    M4TableSpec(
        "m4_hearing_strict_parse_failure_attempts",
        M4ProjectionArtifactKind.STRICT_PARSE_FAILURE_ATTEMPT,
        "attempt_id",
        "attempt_json",
        HearingStrictParseFailureAttempt,
    ),
    M4TableSpec(
        "m4_hearing_strict_parse_failure_proofs",
        M4ProjectionArtifactKind.STRICT_PARSE_FAILURE_PROOF,
        "proof_id",
        "proof_json",
        _STRICT_FAILURE_PROOF_ADAPTER,
    ),
    M4TableSpec(
        "m4_hearing_backlog_retry_outcomes",
        M4ProjectionArtifactKind.BACKLOG_RETRY_OUTCOME,
        "outcome_id",
        "outcome_json",
        _OUTCOME_ADAPTER,
    ),
)


M4_UNTYPED_TABLES: tuple[tuple[str, M4ProjectionArtifactKind], ...] = ()


def load_m4_record(row: sqlite3.Row, spec: M4TableSpec[Any]) -> M4Record:
    raw = row[spec.json_column]
    artifact_id = row[spec.id_column]
    if not isinstance(raw, str) or not isinstance(artifact_id, str):
        raise M4DocumentFailure("DOCUMENT_COLUMN_TYPE_INVALID")
    try:
        if isinstance(spec.model, TypeAdapter):
            document = spec.model.validate_json(raw)
        else:
            document = spec.model.model_validate_json(raw)
    except (ValidationError, TypeError, ValueError, UnicodeError):
        raise M4DocumentFailure("DOCUMENT_CONTRACT_INVALID") from None
    canonical = canonical_json(document.model_dump(mode="json"))
    if raw != canonical:
        raise M4DocumentFailure("DOCUMENT_NOT_CANONICAL")
    if spec.hash_column is not None:
        stored_hash = row[spec.hash_column]
        if not isinstance(stored_hash, str):
            raise M4DocumentFailure("DOCUMENT_COLUMN_TYPE_INVALID")
        expected_hash = (
            cast(str, getattr(document, spec.semantic_hash_attribute))
            if spec.semantic_hash_attribute is not None
            else hashlib.sha256(raw.encode("utf-8")).hexdigest()
        )
        if stored_hash != expected_hash:
            raise M4DocumentFailure("DOCUMENT_HASH_MISMATCH")
    identity = hashlib.sha256(
        canonical_json(["m4-sqlite-record", 1, spec.table, spec.kind.value, artifact_id]).encode(
            "utf-8"
        )
    ).hexdigest()
    record = M4Record(
        kind=spec.kind,
        table=spec.table,
        identity=identity,
        artifact_id=artifact_id,
        row=row,
        document=document,
        canonical_document=canonical,
    )
    validate_m4_index(record)
    return record


def _equal(row: sqlite3.Row, key: str, expected: object) -> None:
    actual = row[key]
    if isinstance(expected, bool):
        expected = int(expected)
    if actual != expected:
        raise M4IndexFailure()


def _optional_ref_id(value: object) -> str | None:
    return None if value is None else cast(Any, value).artifact_id


def validate_m4_index(record: M4Record) -> None:
    """Recompute the security-relevant duplicated columns from typed content."""

    row = record.row
    document = record.document
    _equal(row, _id_column(record), record.artifact_id)

    if isinstance(document, HearingSession):
        for key, expected in (
            ("run_id", document.run_id),
            ("hearing_id", document.session_id),
            ("case_id", document.case_id),
            ("screening_id", document.screening_id),
            ("entry_status", document.entry_status.value),
            ("trigger_review_id", _optional_ref_id(document.initial_trigger_review_ref)),
            (
                "initial_defect_codes_json",
                canonical_json([code.value for code in document.initial_defect_codes]),
            ),
            ("initial_pack_id", document.initial_evidence_pack_id),
            ("initial_pack_version", document.initial_evidence_pack_version),
            ("max_acquisition_rounds", document.acquisition_round_limit),
            ("max_rework_rounds", document.rework_round_limit),
            ("max_total_images", document.max_total_images),
            ("max_total_output_tokens", document.max_total_output_tokens),
            ("max_judge_cycles", document.max_total_judge_cycles),
            ("hearing_prompt_bundle_sha256", document.hearing_prompt_bundle_sha256),
            ("prosecutor_model_manifest_id", document.prosecutor_model_manifest_id),
            ("defender_model_manifest_id", document.defender_model_manifest_id),
            ("judge_model_manifest_id", document.judge_model_manifest_id),
            ("manifest_id", document.manifest_id),
        ):
            _equal(row, key, expected)
    elif isinstance(document, HearingCycleScope):
        _equal(row, "run_id", document.run_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "cycle_id", document.cycle_id)
        _equal(row, "cycle_sha256", document.cycle_sha256)
        _equal(row, "cycle_index", document.cycle_index)
        _equal(row, "prior_acquisition_rounds", document.prior_acquisition_rounds)
        _equal(row, "prior_rework_rounds", document.prior_rework_rounds)
        _equal(row, "cycle_pack_id", document.cycle_evidence_pack_id)
        _equal(row, "cycle_pack_version", document.cycle_evidence_pack_version)
        _equal(
            row,
            "initial_trigger_review_id",
            _optional_ref_id(document.initial_trigger_review_ref),
        )
        _equal(
            row,
            "initial_defect_codes_json",
            canonical_json([code.value for code in document.initial_defect_codes]),
        )
        _equal(row, "rework_review_id", _optional_ref_id(document.rework_review_ref))
        _equal(
            row,
            "rework_defect_codes_json",
            canonical_json([code.value for code in document.rework_defect_codes]),
        )
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingPrecedentRetrievalReceipt):
        _validate_cycle_scope_columns(row, document)
        _equal(row, "retrieval_receipt_id", document.receipt_id)
        _equal(row, "current_pack_id", document.current_evidence_pack_id)
        _equal(row, "current_pack_version", document.current_evidence_pack_version)
        _equal(row, "retrieval_status", document.status.value)
        _equal(row, "precedent_retrieval_degraded", document.status.value == "DEGRADED")
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingModelRequest):
        _validate_cycle_scope_columns(row, document)
        retry_context = document.backlog_retry_context
        _equal(row, "request_id", document.request_id)
        _equal(row, "request_sha256", document.request_sha256)
        _equal(row, "cache_key", document.cache_key)
        _equal(row, "role", document.role.value)
        _equal(
            row,
            "purpose",
            "ROLE_CALL" if document.attempt_index == 0 else "STRUCTURE_REPAIR",
        )
        _equal(row, "attempt_index", document.attempt_index)
        _equal(row, "call_generation", "BACKLOG" if retry_context is not None else "INITIAL")
        _equal(
            row,
            "backlog_item_id",
            retry_context.backlog_item_id if retry_context is not None else None,
        )
        _equal(
            row,
            "retry_generation",
            retry_context.retry_generation if retry_context is not None else 0,
        )
        _equal(row, "evidence_pack_id", document.current_evidence_pack_id)
        _equal(row, "evidence_pack_version", document.current_evidence_pack_version)
        _equal(row, "model_manifest_id", document.model_manifest_id)
        _equal(row, "prompt_manifest_id", document.prompt_manifest.prompt_manifest_id)
        _equal(row, "manifest_id", document.manifest_id)
        _equal(row, "reserved_images", len(document.media))
        _equal(row, "reserved_pixels", sum(item.width * item.height for item in document.media))
    elif isinstance(document, HearingModelResponse):
        _equal(row, "run_id", document.run_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "response_id", document.response_id)
        _equal(row, "request_id", document.request_id)
        _equal(row, "request_sha256", document.request_sha256)
        _equal(row, "cache_key", document.cache_key)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "role", document.role.value)
        _equal(
            row,
            "purpose",
            "ROLE_CALL" if document.attempt_index == 0 else "STRUCTURE_REPAIR",
        )
        _equal(row, "attempt_index", document.attempt_index)
        _equal(row, "raw_response_ref", document.raw_response_ref)
        _equal(row, "content_sha256", document.content_sha256)
        _equal(row, "size_bytes", document.size_bytes)
        _equal(row, "model_manifest_id", document.model_manifest_id)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingModelParseReceipt):
        _equal(row, "run_id", document.run_id)
        _equal(row, "parse_receipt_id", document.parse_receipt_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "role", document.role.value)
        _equal(row, "request_id", document.request_id)
        _equal(row, "request_sha256", document.request_sha256)
        _equal(row, "response_id", document.response_id)
        _equal(row, "response_content_sha256", document.response_content_sha256)
        _equal(row, "attempt_index", document.attempt_index)
        _equal(row, "parser_version", document.parser_version)
        _equal(row, "output_schema_sha256", document.output_schema_sha256)
        _equal(row, "status", document.status.value)
        _equal(
            row,
            "defects_json",
            canonical_json([item.model_dump(mode="json") for item in document.defects]),
        )
        _equal(row, "repair_request_id", document.repair_request_id)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingRoleOutput):
        _validate_cycle_scope_columns(row, document)
        _equal(row, "parsed_output_id", document.output_id)
        _equal(row, "role", document.role.value)
        payload_kind = {
            "PROSECUTOR": "PROSECUTION",
            "DEFENDER": "DEFENSE",
        }.get(document.role.value)
        if payload_kind is None:
            payload_kind = (
                "JUDGE_ACQUISITION"
                if getattr(cast(Any, document.payload), "outcome", None) is not None
                and getattr(cast(Any, document.payload).outcome, "outcome_type", None)
                == "ACQUISITION"
                else "JUDGE_VERDICT"
            )
        _equal(row, "payload_kind", payload_kind)
        _equal(row, "request_id", document.request_ref.artifact_id)
        _equal(row, "response_id", document.response_ref.artifact_id)
        _equal(row, "parse_receipt_id", document.parse_receipt_ref.artifact_id)
        _equal(row, "output_schema_sha256", document.prompt_manifest.output_schema_sha256)
        _equal(row, "prompt_manifest_id", document.prompt_manifest.prompt_manifest_id)
        _equal(row, "model_manifest_id", document.model_manifest_id)
        _equal(row, "prosecutor_output_id", document.prosecutor_output_id)
        _equal(row, "defender_output_id", document.defender_output_id)
        _equal(row, "precedent_retrieval_degraded", document.precedent_retrieval_degraded)
        _equal(row, "precedent_retrieval_receipt_id", document.precedent_retrieval_receipt_id)
        _equal(
            row,
            "precedent_retrieval_receipt_sha256",
            document.precedent_retrieval_receipt_sha256,
        )
        _equal(
            row,
            "initial_trigger_review_id",
            _optional_ref_id(document.initial_trigger_review_ref),
        )
        _equal(
            row,
            "initial_defect_codes_json",
            canonical_json([item.value for item in document.initial_defect_codes]),
        )
        _equal(
            row,
            "rework_review_id",
            _optional_ref_id(document.rework_review_ref),
        )
        _equal(
            row,
            "rework_defect_codes_json",
            canonical_json([item.value for item in document.rework_defect_codes]),
        )
        _equal(row, "payload_sha256", document.payload.payload_sha256)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingModelCacheEntry):
        _equal(row, "run_id", document.run_id)
        _equal(row, "cache_key", document.cache_key)
        _equal(row, "cache_entry_id", document.cache_entry_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "role", document.role.value)
        _equal(row, "request_id", document.request_id)
        _equal(row, "request_sha256", document.request_sha256)
        _equal(row, "response_id", document.response_id)
        _equal(row, "response_content_sha256", document.response_content_sha256)
        _equal(row, "model_manifest_id", document.model_manifest_id)
        _equal(row, "prompt_manifest_id", document.prompt_manifest_id)
        _equal(row, "output_schema_sha256", document.output_schema_sha256)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingUsageReceipt):
        _equal(row, "run_id", document.run_id)
        _equal(row, "usage_receipt_id", document.usage_receipt_id)
        _equal(row, "request_id", document.request_ref.artifact_id)
        _equal(row, "response_id", document.response_ref.artifact_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "role", document.role.value)
        _equal(row, "input_images", document.input_images)
        _equal(row, "input_pixels", document.input_pixels)
        _equal(row, "input_tokens", document.input_tokens)
        _equal(row, "output_tokens", document.output_tokens)
        _equal(row, "provider_latency_ms", document.latency_ms)
        _equal(row, "retries", document.retry_count)
        _equal(row, "estimated_cost", document.estimated_cost)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, AcquisitionExecutionClaimAuthority):
        request = document.request
        _equal(row, "run_id", request.run_id)
        _equal(row, "acquisition_request_id", request.request_id)
        _equal(
            row,
            "request_json",
            canonical_json(request.model_dump(mode="json")),
        )
        _equal(
            row,
            "request_document_sha256",
            hashlib.sha256(
                canonical_json(request.model_dump(mode="json")).encode("utf-8")
            ).hexdigest(),
        )
        _equal(row, "hearing_id", request.hearing_session_id)
        _equal(row, "case_id", request.case_id)
        _equal(row, "execution_mode", document.execution_mode.value)
        _equal(row, "idempotency_key", document.idempotency_key)
        _equal(row, "status", document.status.value)
        _equal(row, "owner_token_sha256", document.owner_token_sha256)
        _equal(row, "owner_fence", document.owner_fence)
        _equal(row, "lease_expires_at", document.lease_expires_at)
        _equal(row, "execution_publication_id", document.execution_publication_id)
        _equal(row, "created_at", document.created_at)
        _equal(row, "updated_at", document.updated_at)
    elif isinstance(document, AcquisitionRequest):
        _equal(row, "run_id", document.run_id)
        _equal(row, "acquisition_request_id", document.request_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "round_index", document.round_index)
        _equal(row, "prior_acquisition_rounds", document.prior_acquisition_rounds)
        _equal(row, "prior_rework_rounds", document.prior_rework_rounds)
        _equal(row, "evidence_pack_id", document.current_evidence_pack_id)
        _equal(row, "evidence_pack_version", document.current_evidence_pack_version)
        _equal(row, "judge_output_id", document.source_judge_output_id)
        _equal(row, "source_model_request_id", document.source_model_request_ref.artifact_id)
        _equal(row, "source_model_response_id", document.source_model_response_ref.artifact_id)
        _equal(row, "action", document.action.value)
        _equal(
            row,
            "validated_parameters_sha256",
            hashlib.sha256(
                canonical_json(document.validated_parameters.model_dump(mode="json")).encode(
                    "utf-8"
                )
            ).hexdigest(),
        )
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, AcquisitionExecutionPublication):
        request = document.request
        _equal(row, "run_id", request.run_id)
        _equal(row, "execution_publication_id", document.publication_id)
        _equal(row, "acquisition_request_id", request.request_id)
        _equal(
            row,
            "request_document_sha256",
            hashlib.sha256(
                canonical_json(request.model_dump(mode="json")).encode("utf-8")
            ).hexdigest(),
        )
        _equal(row, "case_id", request.case_id)
        _equal(row, "hearing_id", request.hearing_session_id)
        _equal(
            row,
            "execution_manifest_id",
            document.execution_manifest.execution_manifest_id,
        )
        _equal(row, "tool_result_id", document.tool_result.tool_result_id)
        _equal(row, "execution_mode", document.execution_mode.value)
        _equal(row, "idempotency_key", document.idempotency_key)
        _equal(row, "claim_owner_sha256", document.claim_owner_sha256)
        _equal(row, "claim_fence", document.claim_fence)
    elif isinstance(document, HearingRound):
        _validate_cycle_scope_columns(row, document)
        _equal(row, "round_id", document.round_id)
        _equal(row, "current_pack_id", document.current_evidence_pack_id)
        _equal(row, "current_pack_version", document.current_evidence_pack_version)
        _equal(row, "prosecutor_output_id", document.prosecutor_output.output_id)
        _equal(row, "defender_output_id", document.defender_output.output_id)
        _equal(row, "judge_output_id", document.judge_output.output_id)
        _equal(row, "resulting_pack_id", document.resulting_evidence_pack_id)
        _equal(row, "resulting_pack_version", document.resulting_evidence_pack_version)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, ToolExecutionManifest):
        _equal(row, "run_id", document.run_id)
        _equal(row, "execution_manifest_id", document.execution_manifest_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "acquisition_request_id", document.acquisition_request_id)
        _equal(row, "action", document.action.value)
        _equal(row, "tool_id", document.tool_id)
        _equal(row, "tool_revision", document.tool_revision)
        _equal(row, "parameters_schema_sha256", document.parameters_schema_sha256)
        _equal(row, "component_manifest_id", document.component_manifest_id)
        _equal(row, "model_manifest_id", document.model_manifest_id)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, Crop):
        _equal(row, "crop_id", document.crop_id)
        _equal(row, "frame_id", document.frame_id)
        _equal(row, "media_sha256", document.media_sha256)
        _equal(row, "source_media_sha256", document.source_media_sha256)
        _equal(row, "pixel_sha256", document.pixel_sha256)
    elif isinstance(document, ToolExecutionReceipt):
        request = document.request
        _equal(row, "run_id", request.run_id)
        _equal(row, "receipt_id", document.receipt_id)
        _equal(row, "acquisition_request_id", request.request_id)
        _equal(row, "hearing_id", request.hearing_session_id)
        _equal(row, "case_id", request.case_id)
        _equal(row, "action", request.action.value)
        _equal(row, "execution_manifest_id", document.execution_manifest.execution_manifest_id)
        _equal(row, "tool_result_id", document.tool_result.tool_result_id)
        _equal(row, "resulting_pack_id", document.resulting_evidence_pack_id)
        _equal(row, "resulting_pack_version", document.resulting_evidence_pack_version)
    elif isinstance(document, EvidencePackDerivation):
        _equal(row, "run_id", document.run_id)
        _equal(row, "derivation_id", document.derivation_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "source_cycle_scope_id", document.source_cycle_scope_id)
        _equal(row, "source_cycle_scope_sha256", document.source_cycle_scope_sha256)
        _equal(row, "previous_pack_id", document.previous_evidence_pack_id)
        _equal(row, "previous_pack_version", document.previous_evidence_pack_version)
        _equal(row, "new_pack_id", document.new_evidence_pack_id)
        _equal(row, "new_pack_version", document.new_evidence_pack_version)
        _equal(row, "tool_receipt_id", document.tool_execution_receipt_id)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingCheckpoint):
        _validate_cycle_scope_columns(row, document)
        retrieval = document.precedent_retrieval_receipt
        for key, expected in (
            ("checkpoint_id", document.checkpoint_id),
            ("checkpoint_sha256", document.checkpoint_sha256),
            ("hearing_sha256", document.hearing_session_sha256),
            ("version", document.version),
            ("phase", document.phase.value),
            ("current_pack_id", document.current_evidence_pack_id),
            ("current_pack_version", document.current_evidence_pack_version),
            ("previous_checkpoint_id", document.previous_checkpoint_id),
            ("previous_checkpoint_sha256", document.previous_checkpoint_sha256),
            (
                "previous_phase",
                document.previous_phase.value if document.previous_phase is not None else None,
            ),
            ("initial_trigger_review_id", _optional_ref_id(document.initial_trigger_review_ref)),
            (
                "initial_defect_codes_json",
                canonical_json([code.value for code in document.initial_defect_codes]),
            ),
            ("cycle_trigger_review_id", _optional_ref_id(document.cycle_trigger_review_ref)),
            (
                "cycle_trigger_defect_codes_json",
                canonical_json([code.value for code in document.cycle_trigger_defect_codes]),
            ),
            ("retrieval_receipt_id", retrieval.receipt_id if retrieval is not None else None),
            (
                "retrieval_receipt_sha256",
                retrieval.receipt_sha256 if retrieval is not None else None,
            ),
            (
                "prosecutor_output_id",
                document.prosecutor_output.output_id
                if document.prosecutor_output is not None
                else None,
            ),
            (
                "defender_output_id",
                document.defender_output.output_id
                if document.defender_output is not None
                else None,
            ),
            (
                "judge_output_id",
                document.judge_output.output_id if document.judge_output is not None else None,
            ),
            (
                "acquisition_request_id",
                document.acquisition_request.request_id
                if document.acquisition_request is not None
                else None,
            ),
            (
                "tool_receipt_id",
                document.tool_execution_receipt.receipt_id
                if document.tool_execution_receipt is not None
                else None,
            ),
            ("procedural_review_id", _optional_ref_id(document.procedural_review_ref)),
            ("human_review_receipt_id", document.human_review_receipt_id),
            ("human_review_receipt_sha256", document.human_review_receipt_sha256),
            (
                "human_review_reason",
                document.human_review_reason.value
                if document.human_review_reason is not None
                else None,
            ),
            (
                "model_request_refs_json",
                canonical_json(
                    [ref.model_dump(mode="json") for ref in document.model_request_refs]
                ),
            ),
            (
                "model_response_refs_json",
                canonical_json(
                    [ref.model_dump(mode="json") for ref in document.model_response_refs]
                ),
            ),
            (
                "parse_receipt_refs_json",
                canonical_json(
                    [ref.model_dump(mode="json") for ref in document.parse_receipt_refs]
                ),
            ),
            (
                "usage_receipt_ids_json",
                canonical_json([item.usage_receipt_id for item in document.usage_receipts]),
            ),
            (
                "failure_authority_ids_json",
                canonical_json([item.authority_id for item in document.failure_authorities]),
            ),
            ("manifest_id", document.manifest_id),
        ):
            _equal(row, key, expected)
    elif isinstance(document, HearingHumanReviewReceipt):
        _equal(row, "run_id", document.run_id)
        _equal(row, "receipt_id", document.receipt_id)
        _equal(row, "receipt_sha256", document.receipt_sha256)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "current_pack_id", document.current_evidence_pack_id)
        _equal(row, "current_pack_version", document.current_evidence_pack_version)
        _equal(row, "judge_cycle", document.judge_cycle)
        _equal(row, "reason", document.reason.value)
        _equal(row, "source_checkpoint_id", document.source_checkpoint_id)
        _equal(row, "source_checkpoint_sha256", document.source_checkpoint_sha256)
        _equal(row, "source_checkpoint_version", document.source_checkpoint_version)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingReworkReceipt):
        _equal(row, "run_id", document.run_id)
        _equal(row, "rework_receipt_id", document.receipt_id)
        _equal(row, "hearing_id", document.hearing_session_id)
        _equal(row, "case_id", document.case_id)
        _equal(row, "failed_review_id", document.failed_review_id)
        _equal(row, "prior_round_id", document.prior_round_id)
        _equal(row, "next_cycle_scope_id", document.next_cycle_scope_id)
        _equal(row, "next_cycle_scope_sha256", document.next_cycle_scope_sha256)
        _equal(row, "rework_index", document.rework_index)
        _equal(row, "defect_set_sha256", document.defect_set_sha256)
        _equal(
            row,
            "defect_codes_json",
            canonical_json([code.value for code in document.defect_codes]),
        )
        _equal(row, "prompt_defect_summary_sha256", document.prompt_defect_summary_sha256)
        _equal(row, "manifest_id", document.manifest_id)
    elif isinstance(document, HearingVerdictBinding):
        for key, expected in (
            ("run_id", document.run_id),
            ("binding_id", document.binding_id),
            ("hearing_id", document.hearing_session_id),
            ("hearing_record_id", document.hearing_record_id),
            ("hearing_record_version", document.hearing_record_version),
            ("hearing_record_sha256", document.hearing_record_sha256),
            ("round_id", document.judge_round_id),
            ("judge_round_index", document.judge_round_index),
            ("case_id", document.case_id),
            ("evidence_pack_id", document.evidence_pack_id),
            ("evidence_pack_version", document.evidence_pack_version),
            ("verdict_id", document.verdict_id),
            ("verdict_version", document.verdict_version),
            ("verdict_input_sha256", document.verdict_input_sha256),
            ("verdict_sha256", document.verdict_sha256),
            ("prosecutor_output_id", document.prosecutor_output_id),
            ("defender_output_id", document.defender_output_id),
            ("judge_output_id", document.judge_output_id),
            (
                "model_request_refs_json",
                canonical_json(
                    [item.model_dump(mode="json") for item in document.model_request_refs]
                ),
            ),
            (
                "model_response_refs_json",
                canonical_json(
                    [item.model_dump(mode="json") for item in document.model_response_refs]
                ),
            ),
            (
                "parse_receipt_refs_json",
                canonical_json(
                    [item.model_dump(mode="json") for item in document.parse_receipt_refs]
                ),
            ),
            ("manifest_id", document.manifest_id),
        ):
            _equal(row, key, expected)
    elif isinstance(document, HearingBacklogCompletionReceipt):
        completion_outcome = document.outcome
        completion_lease = completion_outcome.lease
        completion_request = completion_outcome.request
        for key, authority_value in (
            ("run_id", completion_request.run_id),
            ("receipt_id", document.receipt_id),
            ("receipt_sha256", document.receipt_sha256),
            ("item_id", completion_lease.item_id),
            ("case_id", completion_request.case_id),
            ("hearing_id", completion_request.hearing_session_id),
            ("role", completion_request.role.value),
            ("outcome_kind", completion_outcome.outcome_kind),
            ("outcome_id", completion_outcome.outcome_id),
            ("lease_identity_sha256", completion_lease.lease_identity_sha256),
            ("lease_id", completion_lease.lease_id),
            ("attempt_count", completion_lease.attempt_count),
            ("retry_generation", completion_lease.retry_generation),
            ("backlog_status", document.backlog_status.value),
            ("source_checkpoint_id", document.source_checkpoint_id),
            ("source_checkpoint_sha256", document.source_checkpoint_sha256),
            ("source_checkpoint_version", document.source_checkpoint_version),
            ("resulting_checkpoint_id", document.resulting_checkpoint_id),
            ("resulting_checkpoint_sha256", document.resulting_checkpoint_sha256),
            ("resulting_checkpoint_version", document.resulting_checkpoint_version),
            ("completion_case_status", document.completion_case_status.value),
            ("completion_case_revision", document.completion_case_revision),
            ("completion_audit_sequence", document.completion_audit_sequence),
            ("completion_audit_entry_hash", document.completion_audit_entry_hash),
            ("manifest_id", document.manifest_id),
        ):
            _equal(row, key, authority_value)
    elif isinstance(document, HearingModelCallFailureAuthority):
        authority_request = document.request
        authority_lease = document.lease
        for key, proof_value in (
            ("run_id", document.run_id),
            ("authority_id", document.authority_id),
            ("request_id", authority_request.request_id),
            ("request_sha256", authority_request.request_sha256),
            ("request_document_sha256", document.request_document_sha256),
            ("cache_key", authority_request.cache_key),
            ("hearing_id", document.hearing_session_id),
            ("cycle_scope_id", authority_request.cycle_scope_id),
            ("cycle_scope_sha256", authority_request.cycle_scope_sha256),
            ("case_id", document.case_id),
            ("role", document.role.value),
            ("source_checkpoint_id", document.source_checkpoint_id),
            ("source_checkpoint_sha256", document.source_checkpoint_sha256),
            ("source_checkpoint_version", document.source_checkpoint_version),
            (
                "lease_identity_sha256",
                authority_lease.lease_identity_sha256 if authority_lease else None,
            ),
            ("lease_id", authority_lease.lease_id if authority_lease else None),
            ("backlog_attempt_count", document.backlog_attempt_count),
            ("retry_generation", document.retry_generation),
            ("claim_owner_sha256", document.claim_owner_sha256),
            (
                "claim_lease_expires_at",
                document.claim_lease_expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            ),
            ("claim_takeover_count", document.claim_takeover_count),
            ("failure_code", document.failure_code.value),
            ("delivery_certainty", document.delivery_certainty.value),
            ("provider_response_content_sha256", document.provider_response_content_sha256),
            ("reserved_images", document.reserved_images),
            ("reserved_pixels", document.reserved_pixels),
            ("disclosed_images", document.disclosed_images),
            ("disclosed_pixels", document.disclosed_pixels),
            ("input_tokens", document.input_tokens),
            ("output_tokens", document.output_tokens),
            ("latency_ms", document.latency_ms),
            ("estimated_cost", document.estimated_cost),
            ("backlog_item_id", document.backlog_item_id),
            ("backlog_reason_code", document.backlog_reason_code.value),
            ("backlog_version", document.backlog_version),
            ("backlog_status", document.backlog_status.value),
            ("closure_kind", document.closure_kind.value),
            ("completion_receipt_id", document.completion_receipt_id),
            ("closure_case_revision", document.closure_case_revision),
            ("closure_audit_sequence", document.closure_audit_sequence),
            ("closure_audit_entry_hash", document.closure_audit_entry_hash),
            ("manifest_id", document.manifest_id),
            ("recorded_at", document.recorded_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
        ):
            _equal(row, key, proof_value)
    elif isinstance(document, HearingStrictParseFailureAttempt):
        attempt_request = document.request
        attempt_response = document.response
        attempt_parse = document.parse_receipt
        context = attempt_request.backlog_retry_context
        for key, outcome_value in (
            ("run_id", attempt_request.run_id),
            ("attempt_id", document.attempt_id),
            ("hearing_id", attempt_request.hearing_session_id),
            ("cycle_scope_id", attempt_request.cycle_scope_id),
            ("cycle_scope_sha256", attempt_request.cycle_scope_sha256),
            ("case_id", attempt_request.case_id),
            ("role", attempt_request.role.value),
            ("attempt_index", attempt_request.attempt_index),
            ("retry_generation", context.retry_generation if context is not None else 0),
            ("request_id", attempt_request.request_id),
            ("request_sha256", attempt_request.request_sha256),
            ("response_id", attempt_response.response_id),
            ("response_content_sha256", attempt_response.content_sha256),
            ("parse_receipt_id", attempt_parse.parse_receipt_id),
            ("manifest_id", attempt_request.manifest_id),
        ):
            _equal(row, key, outcome_value)
        if context is not None:
            _equal(row, "backlog_item_id", context.backlog_item_id)
    elif isinstance(
        document,
        (HearingInitialStrictParseFailureProof, HearingStrictParseFailureProof),
    ):
        primary, repair = document.attempts
        proof_request = primary.request
        initial = isinstance(document, HearingInitialStrictParseFailureProof)
        if initial:
            initial_proof = cast(HearingInitialStrictParseFailureProof, document)
            backlog_item_id = initial_proof.backlog_item_id
            lease_identity_sha256 = None
            lease_id = None
            lease_attempt_count = None
            retry_generation = 0
        else:
            retry_proof = cast(HearingStrictParseFailureProof, document)
            backlog_item_id = retry_proof.lease.item_id
            lease_identity_sha256 = retry_proof.lease.lease_identity_sha256
            lease_id = retry_proof.lease.lease_id
            lease_attempt_count = retry_proof.lease.attempt_count
            retry_generation = retry_proof.lease.retry_generation
        for key, strict_proof_value in (
            ("run_id", proof_request.run_id),
            ("proof_id", document.proof_id),
            ("hearing_id", proof_request.hearing_session_id),
            ("case_id", proof_request.case_id),
            ("source_checkpoint_id", document.source_checkpoint_id),
            ("source_checkpoint_sha256", document.source_checkpoint_sha256),
            ("source_checkpoint_version", document.source_checkpoint_version),
            ("backlog_item_id", backlog_item_id),
            ("closure_kind", "INITIAL_BACKLOG" if initial else "RETRY_FAILURE"),
            ("lease_identity_sha256", lease_identity_sha256),
            ("lease_id", lease_id),
            ("lease_attempt_count", lease_attempt_count),
            ("retry_generation", retry_generation),
            ("role", document.role.value),
            ("primary_attempt_id", primary.attempt_id),
            ("repair_attempt_id", repair.attempt_id),
        ):
            _equal(row, key, strict_proof_value)
    elif hasattr(document, "outcome_id") and hasattr(document, "outcome_kind"):
        outcome = cast(Any, document)
        outcome_request = outcome.request
        outcome_lease = outcome.lease
        success = outcome.outcome_kind == "SUCCESS"
        outcome_response = outcome.response if success else None
        outcome_parse = outcome.parse_receipt if success else None
        output = outcome.parsed_role_output if success else None
        checkpoint = outcome.next_checkpoint if success else None
        failure_proof = outcome.strict_parse_failure if not success else None
        human = outcome.human_review_receipt
        response_refs = () if success else outcome.response_refs
        for key, retry_outcome_value in (
            ("run_id", outcome_request.run_id),
            ("outcome_id", outcome.outcome_id),
            ("outcome_kind", outcome.outcome_kind),
            ("hearing_id", outcome_request.hearing_session_id),
            ("cycle_scope_id", outcome_request.cycle_scope_id),
            ("cycle_scope_sha256", outcome_request.cycle_scope_sha256),
            ("case_id", outcome_request.case_id),
            ("role", outcome_request.role.value),
            ("backlog_item_id", outcome_lease.item_id),
            ("lease_identity_sha256", outcome_lease.lease_identity_sha256),
            ("lease_id", outcome_lease.lease_id),
            ("lease_attempt_count", outcome_lease.attempt_count),
            ("retry_generation", outcome_lease.retry_generation),
            ("source_checkpoint_id", outcome.source_checkpoint_id),
            ("source_checkpoint_sha256", outcome.source_checkpoint_sha256),
            ("source_checkpoint_version", outcome.source_checkpoint_version),
            ("request_id", outcome_request.request_id),
            ("request_sha256", outcome_request.request_sha256),
            ("response_id", outcome_response.response_id if outcome_response else None),
            ("parse_receipt_id", outcome_parse.parse_receipt_id if outcome_parse else None),
            ("parsed_output_id", output.output_id if output else None),
            ("next_checkpoint_id", checkpoint.checkpoint_id if checkpoint else None),
            ("next_checkpoint_sha256", checkpoint.checkpoint_sha256 if checkpoint else None),
            ("next_checkpoint_version", checkpoint.version if checkpoint else None),
            ("reason_code", outcome.reason_code.value if not success else None),
            ("next_status", outcome.next_status.value if not success else None),
            (
                "response_refs_json",
                canonical_json([item.model_dump(mode="json") for item in response_refs]),
            ),
            ("strict_parse_failure_proof_id", failure_proof.proof_id if failure_proof else None),
            ("human_review_receipt_id", human.receipt_id if human else None),
            (
                "next_retry_generation",
                outcome_lease.retry_generation if success else outcome.next_retry_generation,
            ),
            ("manifest_id", outcome.manifest_id),
        ):
            _equal(row, key, retry_outcome_value)
    else:
        _validate_identity_only(record)


def _id_column(record: M4Record) -> str:
    return next(spec.id_column for spec in M4_TYPED_TABLES if spec.table == record.table)


def _validate_cycle_scope_columns(row: sqlite3.Row, document: Any) -> None:
    _equal(row, "run_id", document.run_id)
    _equal(row, "case_id", document.case_id)
    _equal(row, "hearing_id", document.hearing_session_id)
    if hasattr(document, "cycle_scope_id") and hasattr(document, "cycle_scope_sha256"):
        cycle_scope_id = document.cycle_scope_id
        cycle_scope_sha256 = document.cycle_scope_sha256
    else:
        projection = _hearing_cycle_scope_projection(
            run_id=document.run_id,
            case_id=document.case_id,
            hearing_session_id=document.hearing_session_id,
            cycle_index=document.round_index,
            prior_acquisition_rounds=document.prior_acquisition_rounds,
            prior_rework_rounds=document.prior_rework_rounds,
            cycle_evidence_pack_id=document.current_evidence_pack_id,
            cycle_evidence_pack_version=document.current_evidence_pack_version,
            initial_trigger_review_ref=document.initial_trigger_review_ref,
            initial_defect_codes=document.initial_defect_codes,
            rework_review_ref=document.rework_review_ref,
            rework_defect_codes=document.rework_defect_codes,
            manifest_id=document.manifest_id,
        )
        cycle_scope_id = _hearing_cycle_scope_id(projection)
        cycle_scope_sha256 = _hearing_cycle_scope_sha256(projection)
    _equal(row, "cycle_scope_id", cycle_scope_id)
    _equal(row, "cycle_scope_sha256", cycle_scope_sha256)
    if _has_column(row, "cycle_index"):
        cycle_column: str | None = "cycle_index"
    elif _has_column(row, "round_index"):
        cycle_column = "round_index"
    elif _has_column(row, "judge_cycle"):
        cycle_column = "judge_cycle"
    else:
        cycle_column = None
    if cycle_column is not None:
        if hasattr(document, "cycle_index"):
            cycle_index = document.cycle_index
        elif hasattr(document, "round_index"):
            cycle_index = document.round_index
        else:
            cycle_index = document.judge_cycle
        _equal(row, cycle_column, cycle_index)
    if _has_column(row, "prior_acquisition_rounds"):
        _equal(row, "prior_acquisition_rounds", document.prior_acquisition_rounds)
    if _has_column(row, "prior_rework_rounds"):
        _equal(row, "prior_rework_rounds", document.prior_rework_rounds)
    pack_id_column = next(
        (
            column
            for column in ("cycle_pack_id", "current_pack_id", "evidence_pack_id")
            if _has_column(row, column)
        ),
        None,
    )
    pack_version_column = next(
        (
            column
            for column in (
                "cycle_pack_version",
                "current_pack_version",
                "evidence_pack_version",
            )
            if _has_column(row, column)
        ),
        None,
    )
    pack_id = (
        document.cycle_evidence_pack_id
        if hasattr(document, "cycle_evidence_pack_id")
        else document.current_evidence_pack_id
    )
    pack_version = (
        document.cycle_evidence_pack_version
        if hasattr(document, "cycle_evidence_pack_version")
        else document.current_evidence_pack_version
    )
    if pack_id_column is not None:
        _equal(row, pack_id_column, pack_id)
    if pack_version_column is not None:
        _equal(row, pack_version_column, pack_version)


def _validate_identity_only(record: M4Record) -> None:
    document = cast(Any, record.document)
    common = (
        ("run_id", "run_id"),
        ("case_id", "case_id"),
        ("hearing_id", "hearing_session_id"),
        ("manifest_id", "manifest_id"),
    )
    for column, attribute in common:
        if _has_column(record.row, column) and hasattr(document, attribute):
            _equal(record.row, column, getattr(document, attribute))
    possible_ids = (
        "binding_id",
        "receipt_id",
        "authority_id",
        "attempt_id",
        "proof_id",
        "outcome_id",
    )
    if not any(
        hasattr(document, attribute) and getattr(document, attribute) == record.artifact_id
        for attribute in possible_ids
    ):
        raise M4IndexFailure("INDEX_IDENTITY_MISMATCH")


def _has_column(row: sqlite3.Row, column: str) -> bool:
    return column in tuple(row.keys())


__all__ = [
    "M4_TYPED_TABLES",
    "M4_UNTYPED_TABLES",
    "M4DocumentFailure",
    "M4IndexFailure",
    "M4Record",
    "M4TableSpec",
    "load_m4_record",
]
