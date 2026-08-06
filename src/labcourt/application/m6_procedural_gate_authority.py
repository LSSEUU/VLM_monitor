"""Reconstruct every M6 Gate invocation from sealed source and full M4 history."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar, cast

from pydantic import BaseModel, ValidationError

from labcourt.application.hearing_history import (
    HearingHistoryBuildError,
    build_hearing_call_history,
    derive_hearing_evidence_grant,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
    HearingProceduralReviewVerificationError,
)
from labcourt.application.m6_source_authority import M6ValidatedSourceAuthority
from labcourt.application.m6_source_authority_sealing import (
    M6SealedGateSource,
    M6SourceAuthoritySealingError,
    seal_m6_gate_current_closures,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
)
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRecord,
    HearingRoleOutput,
    HearingUnknownReferenceAttempt,
    HearingUnknownReferenceSource,
    HearingUsageReceipt,
    HearingVerdictBinding,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
)
from labcourt.contracts.m3_models import UnknownReferenceAttempt
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_regression_execution import M6UpgradeCandidateRunCutAuthority
from labcourt.contracts.m6_source_authority import M6GateCurrentClosureReceipt
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.hearing_fsm import HearingCallClosure
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
    build_m6_gate_precedent_resolutions,
)
from labcourt.exceptions import LabCourtError
from labcourt.ports.evidence_repository import EvidenceRepository
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument
from labcourt.ports.m6_procedural_gate_authority import (
    M6ProceduralGateHistorySnapshot,
)
from labcourt.ports.m6_source_authority_sealing import (
    M6CurrentPackObservation,
    M6GateSourceObservation,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ProceduralGateAuthorityErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_IDENTITY_MISMATCH = "SNAPSHOT_IDENTITY_MISMATCH"
    SOURCE_AUTHORITY_ROOT_MISMATCH = "SOURCE_AUTHORITY_ROOT_MISMATCH"
    SOURCE_SCOPE_MISMATCH = "SOURCE_SCOPE_MISMATCH"
    SOURCE_CONFIG_MISMATCH = "SOURCE_CONFIG_MISMATCH"
    M4_AUTHORITY_INVALID = "M4_AUTHORITY_INVALID"
    M4_DOCUMENT_INVALID = "M4_DOCUMENT_INVALID"
    M4_DOCUMENT_MISSING = "M4_DOCUMENT_MISSING"
    M4_DOCUMENT_AMBIGUOUS = "M4_DOCUMENT_AMBIGUOUS"
    SOURCE_DOCUMENT_MISMATCH = "SOURCE_DOCUMENT_MISMATCH"
    CALL_HISTORY_INVALID = "CALL_HISTORY_INVALID"
    EVIDENCE_GRANT_INVALID = "EVIDENCE_GRANT_INVALID"
    MEDIA_AUTHORITY_MISMATCH = "MEDIA_AUTHORITY_MISMATCH"
    CURRENT_CLOSURE_AUTHORITY_INVALID = "CURRENT_CLOSURE_AUTHORITY_INVALID"
    DERIVED_GATE_INPUT_INVALID = "DERIVED_GATE_INPUT_INVALID"
    INDEPENDENT_M4_VERIFICATION_FAILED = "INDEPENDENT_M4_VERIFICATION_FAILED"
    SOURCE_REVIEW_MISMATCH = "SOURCE_REVIEW_MISMATCH"
    CASE_GATE_AUTHORITY_INVALID = "CASE_GATE_AUTHORITY_INVALID"


class M6ProceduralGateAuthorityError(LabCourtError):
    """The sealed history cannot prove one exact deterministic Gate input."""

    def __init__(self, code: M6ProceduralGateAuthorityErrorCode) -> None:
        if not isinstance(code, M6ProceduralGateAuthorityErrorCode):
            raise TypeError("code must be an M6ProceduralGateAuthorityErrorCode")
        self.code = code
        super().__init__(f"M6 procedural Gate authority failed: {code.value}")


def _fail(code: M6ProceduralGateAuthorityErrorCode) -> NoReturn:
    raise M6ProceduralGateAuthorityError(code)


_MODEL_BY_KIND: dict[M4ProjectionArtifactKind, type[BaseModel]] = {
    M4ProjectionArtifactKind.MODEL_REQUEST: HearingModelRequest,
    M4ProjectionArtifactKind.MODEL_RESPONSE: HearingModelResponse,
    M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT: HearingModelParseReceipt,
    M4ProjectionArtifactKind.USAGE_RECEIPT: HearingUsageReceipt,
    M4ProjectionArtifactKind.ACQUIRED_CROP: Crop,
    M4ProjectionArtifactKind.HEARING_RECORD: HearingRecord,
    M4ProjectionArtifactKind.VERDICT_BINDING: HearingVerdictBinding,
    M4ProjectionArtifactKind.EVIDENCE_PACK: EvidencePack,
    M4ProjectionArtifactKind.VERDICT: Verdict,
    M4ProjectionArtifactKind.PROCEDURAL_REVIEW: ProceduralReview,
}

_ID_ATTRIBUTE_BY_KIND = {
    M4ProjectionArtifactKind.MODEL_REQUEST: "request_id",
    M4ProjectionArtifactKind.MODEL_RESPONSE: "response_id",
    M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT: "parse_receipt_id",
    M4ProjectionArtifactKind.USAGE_RECEIPT: "usage_receipt_id",
    M4ProjectionArtifactKind.ACQUIRED_CROP: "crop_id",
    M4ProjectionArtifactKind.HEARING_RECORD: "record_id",
    M4ProjectionArtifactKind.VERDICT_BINDING: "binding_id",
    M4ProjectionArtifactKind.EVIDENCE_PACK: "pack_id",
    M4ProjectionArtifactKind.VERDICT: "verdict_id",
    M4ProjectionArtifactKind.PROCEDURAL_REVIEW: "review_id",
}

_M3_SOURCE_BY_HEARING_SOURCE = {
    HearingUnknownReferenceSource.ARGUMENT_EVIDENCE_REF: (
        UnknownReferenceSource.ARGUMENT_EVIDENCE_REF
    ),
    HearingUnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF: (
        UnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF
    ),
    HearingUnknownReferenceSource.JUDGE_CITATION_REF: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
    HearingUnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF: (
        UnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF
    ),
    HearingUnknownReferenceSource.OBSERVATION_CROP_ID: (
        UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID
    ),
    HearingUnknownReferenceSource.PRECEDENT_APPLICATION_ID: (
        UnknownReferenceSource.PRECEDENT_APPLICATION_ID
    ),
    HearingUnknownReferenceSource.PRECEDENT_FACT_DIFFERENCE_REF: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
    HearingUnknownReferenceSource.ACQUISITION_SUPPORTING_EVIDENCE_REF: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
    HearingUnknownReferenceSource.ACQUISITION_PARAMETER_FRAME_ID: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
    HearingUnknownReferenceSource.ACQUISITION_PARAMETER_CROP_ID: (
        UnknownReferenceSource.EVIDENCE_CITATION_REF
    ),
}


@dataclass(frozen=True, slots=True)
class _ParsedM4Document:
    authority: M6HistoricalAuthorityDocument
    document: BaseModel


class _PinnedEvidenceAuthority:
    """Minimal in-memory port used only by the independent frozen M4 verifier."""

    def __init__(
        self,
        *,
        case: Case,
        manifest: RunManifest,
        gate_current_closures: tuple[M6GateCurrentClosureReceipt, ...],
    ) -> None:
        self._manifest = manifest
        self._run_id = case.run_id
        self._packs = {pack.pack_id: pack for pack in case.evidence_packs}
        self._closures: dict[str, ClosureReport] = {}
        reviews = {item.review_id: item for item in case.procedural_reviews}
        packs = {(item.pack_id, item.version): item for item in case.evidence_packs}
        for receipt in gate_current_closures:
            review = reviews.get(receipt.source_review_id)
            if review is None:
                _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)
            pack = packs.get((review.evidence_pack_id, review.evidence_pack_version))
            if pack is None or pack.pack_id != receipt.evidence_pack_id:
                _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)
            previous = self._closures.get(pack.pack_id)
            if previous is not None and previous != receipt.current_closure:
                _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)
            self._closures[pack.pack_id] = receipt.current_closure

    def load_run_manifest(self, run_id: str) -> RunManifest:
        if run_id != self._run_id:
            raise ValueError("foreign run")
        return self._manifest

    def load_pack(self, run_id: str, pack_id: str) -> EvidencePack:
        pack = self._packs.get(pack_id)
        if pack is None or pack.run_id != run_id:
            raise ValueError("foreign evidence pack")
        return pack

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport:
        pack = self._packs.get(pack_id)
        closure = self._closures.get(pack_id)
        if pack is None or closure is None or pack.run_id != run_id:
            raise ValueError("missing current closure")
        return closure


def _controlled_config(value: object) -> AppConfig:
    if not isinstance(value, AppConfig):
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        controlled = AppConfig.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)
    return controlled


def _controlled_snapshot(value: object) -> M6ProceduralGateHistorySnapshot:
    if not isinstance(value, M6ProceduralGateHistorySnapshot):
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        return M6ProceduralGateHistorySnapshot(
            source_identity_sha256=value.source_identity_sha256,
            run_id=value.run_id,
            source_m4_authority_root_sha256=value.source_m4_authority_root_sha256,
            documents=tuple(
                M6HistoricalAuthorityDocument(
                    kind=item.kind,
                    artifact_id=item.artifact_id,
                    canonical_document=item.canonical_document,
                )
                for item in value.documents
            ),
            failure_count=value.failure_count,
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)


def _parse_m4_documents(
    snapshot: M6ProceduralGateHistorySnapshot,
) -> dict[M4ProjectionArtifactKind, tuple[_ParsedM4Document, ...]]:
    parsed: dict[M4ProjectionArtifactKind, list[_ParsedM4Document]] = {
        kind: [] for kind in _MODEL_BY_KIND
    }
    for authority in snapshot.documents:
        kind = cast(M4ProjectionArtifactKind, authority.kind)
        model_type = _MODEL_BY_KIND.get(kind)
        if model_type is None:
            continue
        try:
            document = model_type.model_validate_json(authority.canonical_document)
        except (TypeError, ValueError, ValidationError):
            _fail(M6ProceduralGateAuthorityErrorCode.M4_DOCUMENT_INVALID)
        if (
            canonical_json(document.model_dump(mode="json")) != authority.canonical_document
            or getattr(document, _ID_ATTRIBUTE_BY_KIND[kind], None) != authority.artifact_id
            or getattr(document, "run_id", None) != snapshot.run_id
        ):
            _fail(M6ProceduralGateAuthorityErrorCode.M4_DOCUMENT_INVALID)
        parsed[kind].append(_ParsedM4Document(authority, document))
    return {kind: tuple(values) for kind, values in parsed.items()}


def _case_inventory(
    *,
    case: Case,
    parsed: dict[M4ProjectionArtifactKind, tuple[_ParsedM4Document, ...]],
    kind: M4ProjectionArtifactKind,
    expected: tuple[_ModelT, ...],
) -> None:
    actual = tuple(
        item.document
        for item in parsed[kind]
        if getattr(item.document, "case_id", None) == case.case_id
    )
    id_attribute = _ID_ATTRIBUTE_BY_KIND[kind]
    actual_by_id = {getattr(item, id_attribute): item for item in actual}
    expected_by_id = {getattr(item, id_attribute): item for item in expected}
    if actual_by_id != expected_by_id:
        _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_DOCUMENT_MISMATCH)
    if any(getattr(item, "manifest_id", None) != case.manifest_id for item in actual):
        _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_SCOPE_MISMATCH)


def _one(
    values: tuple[_ParsedM4Document, ...],
    *,
    field: str,
    identity: str,
) -> _ParsedM4Document:
    matches = tuple(item for item in values if getattr(item.document, field, None) == identity)
    if not matches:
        _fail(M6ProceduralGateAuthorityErrorCode.M4_DOCUMENT_MISSING)
    if len(matches) != 1:
        _fail(M6ProceduralGateAuthorityErrorCode.M4_DOCUMENT_AMBIGUOUS)
    return matches[0]


def _artifact_ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _hearing_attempt(
    namespace: UnknownReferenceNamespace,
    source: HearingUnknownReferenceSource,
    raw_value: object,
) -> HearingUnknownReferenceAttempt:
    return HearingUnknownReferenceAttempt(
        namespace=namespace,
        source=source,
        value_sha256=sha256_hex(
            [
                "unknown-hearing-model-reference",
                1,
                namespace.value,
                source.value,
                raw_value,
            ]
        ),
    )


def _evidence_attempt(
    source: HearingUnknownReferenceSource,
    ref: ArtifactRef,
) -> HearingUnknownReferenceAttempt:
    return _hearing_attempt(
        UnknownReferenceNamespace.EVIDENCE,
        source,
        ref.model_dump(mode="json"),
    )


def _precedent_attempt(
    source: HearingUnknownReferenceSource,
    ref: ArtifactRef,
) -> HearingUnknownReferenceAttempt:
    return _hearing_attempt(
        UnknownReferenceNamespace.PRECEDENT,
        source,
        ref.model_dump(mode="json"),
    )


def _output_reference_attempts(
    output: HearingRoleOutput,
    request: HearingModelRequest,
) -> tuple[HearingUnknownReferenceAttempt, ...]:
    """Pin M6 to the frozen M4 role-whitelist comparison without a private import."""

    allowed_evidence = frozenset(request.allowed_evidence_refs)
    allowed_precedents = frozenset(request.allowed_precedent_refs)
    attempts: dict[tuple[str, str, str], HearingUnknownReferenceAttempt] = {}

    def evidence(source: HearingUnknownReferenceSource, refs: Iterable[ArtifactRef]) -> None:
        for ref in refs:
            if ref not in allowed_evidence:
                attempt = _evidence_attempt(source, ref)
                attempts[attempt.sort_key] = attempt

    payload = output.payload
    if isinstance(payload, (ProsecutorModelPayload, DefenderModelPayload)):
        for argument in payload.arguments:
            evidence(
                HearingUnknownReferenceSource.ARGUMENT_EVIDENCE_REF,
                argument.evidence_refs,
            )
    elif isinstance(payload, JudgeModelPayload):
        for response in payload.judge_responses:
            evidence(
                HearingUnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF,
                response.evidence_refs,
            )
        for application in payload.precedent_applications:
            if application.precedent_ref not in allowed_precedents:
                attempt = _precedent_attempt(
                    HearingUnknownReferenceSource.PRECEDENT_APPLICATION_ID,
                    application.precedent_ref,
                )
                attempts[attempt.sort_key] = attempt
            evidence(
                HearingUnknownReferenceSource.PRECEDENT_FACT_DIFFERENCE_REF,
                application.fact_difference_refs,
            )
        outcome = payload.outcome
        if isinstance(outcome, JudgeFinalDecisionPayload):
            evidence(
                HearingUnknownReferenceSource.JUDGE_CITATION_REF,
                (citation.evidence_ref for citation in outcome.evidence_citations),
            )
            evidence(
                HearingUnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF,
                (claim.evidence_ref for claim in outcome.objective_claims),
            )
            if outcome.observation_sufficiency is not None:
                evidence(
                    HearingUnknownReferenceSource.OBSERVATION_CROP_ID,
                    (
                        _artifact_ref(ArtifactKind.CROP, observation.crop_id)
                        for observation in outcome.observation_sufficiency.observations
                    ),
                )
        elif isinstance(outcome, JudgeAcquisitionDecisionPayload):
            evidence(
                HearingUnknownReferenceSource.ACQUISITION_SUPPORTING_EVIDENCE_REF,
                outcome.request.supporting_evidence_refs,
            )
        else:  # pragma: no cover - discriminated contracts prevent this
            _fail(M6ProceduralGateAuthorityErrorCode.DERIVED_GATE_INPUT_INVALID)
    else:  # pragma: no cover - discriminated contracts prevent this
        _fail(M6ProceduralGateAuthorityErrorCode.DERIVED_GATE_INPUT_INVALID)
    return tuple(attempts[key] for key in sorted(attempts))


def _derive_unknown_reference_attempts(
    *,
    record: HearingRecord,
    history: tuple[HearingCallClosure, ...],
) -> tuple[UnknownReferenceAttempt, ...]:
    calls_by_request = {call.request.request_id: call for call in history}
    hearing_attempts: dict[
        tuple[str, str, str],
        HearingUnknownReferenceAttempt,
    ] = {}
    for call in history:
        for attempt in call.parse_receipt.unknown_reference_attempts:
            hearing_attempts[attempt.sort_key] = attempt
    try:
        for hearing_round in record.rounds:
            for output in (
                hearing_round.prosecutor_output,
                hearing_round.defender_output,
                hearing_round.judge_output,
            ):
                call = calls_by_request[output.request_ref.artifact_id]
                for attempt in _output_reference_attempts(output, call.request):
                    hearing_attempts[attempt.sort_key] = attempt
        converted = {
            (
                attempt.namespace.value,
                _M3_SOURCE_BY_HEARING_SOURCE[attempt.source].value,
                attempt.value_sha256,
            ): UnknownReferenceAttempt(
                namespace=attempt.namespace,
                source=_M3_SOURCE_BY_HEARING_SOURCE[attempt.source],
                value_sha256=attempt.value_sha256,
            )
            for attempt in hearing_attempts.values()
        }
    except (KeyError, TypeError, ValueError):
        _fail(M6ProceduralGateAuthorityErrorCode.DERIVED_GATE_INPUT_INVALID)
    return tuple(converted[key] for key in sorted(converted))


def _history_for_record(
    *,
    record: HearingRecord,
    parsed: dict[M4ProjectionArtifactKind, tuple[_ParsedM4Document, ...]],
) -> tuple[HearingCallClosure, ...]:
    def referenced(
        kind: M4ProjectionArtifactKind,
        refs: tuple[ArtifactRef, ...],
        expected_type: type[_ModelT],
    ) -> tuple[_ModelT, ...]:
        values: list[_ModelT] = []
        for ref in refs:
            match = _one(parsed[kind], field=_ID_ATTRIBUTE_BY_KIND[kind], identity=ref.artifact_id)
            if not isinstance(match.document, expected_type):
                _fail(M6ProceduralGateAuthorityErrorCode.M4_DOCUMENT_INVALID)
            values.append(match.document)
        return tuple(values)

    requests = referenced(
        M4ProjectionArtifactKind.MODEL_REQUEST,
        record.model_request_refs,
        HearingModelRequest,
    )
    responses = referenced(
        M4ProjectionArtifactKind.MODEL_RESPONSE,
        record.model_response_refs,
        HearingModelResponse,
    )
    parse_receipts = referenced(
        M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
        record.parse_receipt_refs,
        HearingModelParseReceipt,
    )
    usage_receipts = tuple(
        cast(
            HearingUsageReceipt,
            _one(
                parsed[M4ProjectionArtifactKind.USAGE_RECEIPT],
                field="usage_receipt_id",
                identity=item.usage_receipt_id,
            ).document,
        )
        for item in record.usage_receipts
    )
    try:
        return build_hearing_call_history(
            record,
            requests=requests,
            responses=responses,
            parse_receipts=parse_receipts,
            usage_receipts=usage_receipts,
        )
    except HearingHistoryBuildError:
        _fail(M6ProceduralGateAuthorityErrorCode.CALL_HISTORY_INVALID)


def _document_sha256(value: BaseModel) -> str:
    return hashlib.sha256(canonical_json(value.model_dump(mode="json")).encode("utf-8")).hexdigest()


def _require_exact_media_authority(
    *,
    case: Case,
    record: HearingRecord,
    history: tuple[HearingCallClosure, ...],
    parsed: dict[M4ProjectionArtifactKind, tuple[_ParsedM4Document, ...]],
) -> None:
    crops: dict[str, Crop] = {}
    for crop in (
        *(item for pack in case.evidence_packs for item in pack.crops),
        *(cast(Crop, item.document) for item in parsed[M4ProjectionArtifactKind.ACQUIRED_CROP]),
    ):
        previous = crops.get(crop.crop_id)
        if previous is not None and previous != crop:
            _fail(M6ProceduralGateAuthorityErrorCode.MEDIA_AUTHORITY_MISMATCH)
        crops[crop.crop_id] = crop
    requests = {call.request.request_id: call.request for call in history if call.request.media}
    for failure in record.failure_authorities:
        if failure.disclosed_images:
            requests[failure.request.request_id] = failure.request
    for request in requests.values():
        for media in request.media:
            authoritative_crop = crops.get(media.crop_id)
            if authoritative_crop is None or (
                media.media_sha256 != authoritative_crop.media_sha256
                or media.local_path != authoritative_crop.local_path
                or media.source != authoritative_crop.source
                or media.media_access != authoritative_crop.privacy_receipt.media_access
                or media.privacy_policy != authoritative_crop.privacy_receipt.policy
                or media.privacy_transform_version
                != authoritative_crop.privacy_receipt.transform_version
                or media.width != authoritative_crop.output_width
                or media.height != authoritative_crop.output_height
            ):
                _fail(M6ProceduralGateAuthorityErrorCode.MEDIA_AUTHORITY_MISMATCH)


def _assemble_m6_case_procedural_gate_authority_core(
    *,
    case: Case,
    manifest: RunManifest,
    source_identity_sha256: str,
    source_m4_authority_root_sha256: str,
    gate_current_closures: tuple[M6GateCurrentClosureReceipt, ...],
    snapshot: M6ProceduralGateHistorySnapshot,
    config: AppConfig,
) -> M6CaseProceduralGateAuthority:
    """Shared exact Gate reconstruction after a wrapper proves its trust cut."""

    authority = _controlled_snapshot(snapshot)
    controlled_config = _controlled_config(config)
    if authority.failure_count:
        _fail(M6ProceduralGateAuthorityErrorCode.M4_AUTHORITY_INVALID)
    if authority.source_identity_sha256 != source_identity_sha256:
        _fail(M6ProceduralGateAuthorityErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
    if authority.source_m4_authority_root_sha256 != source_m4_authority_root_sha256:
        _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_AUTHORITY_ROOT_MISMATCH)
    if authority.run_id != case.run_id or manifest.manifest_id != case.manifest_id:
        _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_SCOPE_MISMATCH)
    if controlled_config.config_sha256 != manifest.config_sha256:
        _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_CONFIG_MISMATCH)

    parsed = _parse_m4_documents(authority)
    _case_inventory(
        case=case,
        parsed=parsed,
        kind=M4ProjectionArtifactKind.EVIDENCE_PACK,
        expected=case.evidence_packs,
    )
    _case_inventory(
        case=case,
        parsed=parsed,
        kind=M4ProjectionArtifactKind.VERDICT,
        expected=case.verdicts,
    )
    _case_inventory(
        case=case,
        parsed=parsed,
        kind=M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
        expected=case.procedural_reviews,
    )

    verdicts = {item.verdict_id: item for item in case.verdicts}
    packs = {(item.pack_id, item.version): item for item in case.evidence_packs}
    pinned_repository = _PinnedEvidenceAuthority(
        case=case,
        manifest=manifest,
        gate_current_closures=gate_current_closures,
    )
    receipts_by_review = {item.source_review_id: item for item in gate_current_closures}
    if len(receipts_by_review) != len(gate_current_closures):
        _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)
    verifier = DeterministicHearingProceduralReviewVerifier(
        controlled_config,
        cast(EvidenceRepository, pinned_repository),
    )
    inputs: list[M6ProceduralGateExecutionInput] = []
    for review in case.procedural_reviews:
        review_document = _one(
            parsed[M4ProjectionArtifactKind.PROCEDURAL_REVIEW],
            field="review_id",
            identity=review.review_id,
        )
        verdict = verdicts.get(review.reviewed_verdict_id)
        pack = packs.get((review.evidence_pack_id, review.evidence_pack_version))
        if verdict is None or pack is None:
            _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_DOCUMENT_MISMATCH)
        binding_document = _one(
            parsed[M4ProjectionArtifactKind.VERDICT_BINDING],
            field="verdict_id",
            identity=verdict.verdict_id,
        )
        if not isinstance(binding_document.document, HearingVerdictBinding):
            _fail(M6ProceduralGateAuthorityErrorCode.M4_DOCUMENT_INVALID)
        binding = binding_document.document
        record_document = _one(
            parsed[M4ProjectionArtifactKind.HEARING_RECORD],
            field="record_id",
            identity=binding.hearing_record_id,
        )
        if not isinstance(record_document.document, HearingRecord):
            _fail(M6ProceduralGateAuthorityErrorCode.M4_DOCUMENT_INVALID)
        record = record_document.document
        if any(
            getattr(item, "run_id", None) != case.run_id
            or getattr(item, "case_id", None) != case.case_id
            or getattr(item, "manifest_id", None) != case.manifest_id
            for item in (binding, record)
        ):
            _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_SCOPE_MISMATCH)
        history = _history_for_record(record=record, parsed=parsed)
        _require_exact_media_authority(
            case=case,
            record=record,
            history=history,
            parsed=parsed,
        )
        try:
            grant = derive_hearing_evidence_grant(record, history)
        except HearingHistoryBuildError:
            _fail(M6ProceduralGateAuthorityErrorCode.EVIDENCE_GRANT_INVALID)
        unknown_attempts = _derive_unknown_reference_attempts(
            record=record,
            history=history,
        )
        try:
            receipt = receipts_by_review[review.review_id]
            precedent_resolutions = build_m6_gate_precedent_resolutions(
                evidence_pack=pack,
                receipt=record.rounds[-1].precedent_retrieval_receipt,
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)
        try:
            execution = M6ProceduralGateExecutionInput(
                source_review_id=review.review_id,
                source_review_document_sha256=review_document.authority.document_sha256,
                verdict=verdict,
                evidence_pack=pack,
                current_closure=receipt.current_closure,
                gate_config=controlled_config.procedural_gate,
                alert_config=controlled_config.alerts,
                review_version=review.version,
                unknown_reference_attempts=unknown_attempts,
                precedent_resolutions=precedent_resolutions,
                artifact_bounds=grant.artifact_bounds,
            )
        except (AttributeError, TypeError, ValueError, ValidationError):
            _fail(M6ProceduralGateAuthorityErrorCode.DERIVED_GATE_INPUT_INVALID)
        try:
            independently_rebuilt = verifier.rebuild_review(
                record=record,
                verdict=verdict,
                binding=binding,
                evidence_pack=pack,
                current_closure=receipt.current_closure,
                call_history=history,
                evidence_grant=grant,
                review_version=review.version,
            )
        except (HearingProceduralReviewVerificationError, TypeError, ValueError):
            _fail(M6ProceduralGateAuthorityErrorCode.INDEPENDENT_M4_VERIFICATION_FAILED)
        if execution.rebuild_review() != independently_rebuilt:
            _fail(M6ProceduralGateAuthorityErrorCode.DERIVED_GATE_INPUT_INVALID)
        if (
            independently_rebuilt != review
            or review_document.document != review
            or review_document.authority.document_sha256 != _document_sha256(review)
            or receipt.source_review_document_sha256 != _document_sha256(review)
        ):
            _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_REVIEW_MISMATCH)
        inputs.append(execution)

    try:
        return M6CaseProceduralGateAuthority(
            source_identity_sha256=source_identity_sha256,
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            inputs=tuple(sorted(inputs, key=lambda item: item.sort_key)),
        )
    except (AttributeError, TypeError, ValueError):
        _fail(M6ProceduralGateAuthorityErrorCode.CASE_GATE_AUTHORITY_INVALID)


def assemble_m6_case_procedural_gate_authority(
    *,
    source: M6ValidatedSourceAuthority,
    snapshot: M6ProceduralGateHistorySnapshot,
    config: AppConfig,
) -> M6CaseProceduralGateAuthority:
    """Rebuild Gate inputs from one independently sealed historical source."""

    if not isinstance(source, M6ValidatedSourceAuthority):
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)
    input_authority = source.input_authority
    return _assemble_m6_case_procedural_gate_authority_core(
        case=source.source_case,
        manifest=source.source_manifest,
        source_identity_sha256=source.source_identity_sha256,
        source_m4_authority_root_sha256=(input_authority.source_m4_authority_root_sha256),
        gate_current_closures=input_authority.gate_current_closures,
        snapshot=snapshot,
        config=config,
    )


def _candidate_gate_source_observation(
    gate_source: M6SealedGateSource,
) -> M6GateSourceObservation:
    case = gate_source.source_case
    packs = {(item.pack_id, item.version): item for item in case.evidence_packs}
    observations: dict[tuple[str, int], M6CurrentPackObservation] = {}
    try:
        for receipt in gate_source.gate_current_closures:
            key = (receipt.evidence_pack_id, receipt.evidence_pack_version)
            pack = packs[key]
            observation = M6CurrentPackObservation(
                pack=pack,
                current_closure=receipt.current_closure,
                crop_verifications=receipt.crop_verifications,
            )
            previous = observations.get(key)
            if previous is not None and previous != observation:
                _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)
            observations[key] = observation
        return M6GateSourceObservation(
            source_case=case,
            source_case_revision=gate_source.source_case_revision,
            source_case_document_sha256=gate_source.source_case_document_sha256,
            audit_head_sequence=gate_source.audit_head_sequence,
            audit_head_hash=gate_source.audit_head_hash,
            packs=tuple(observations[key] for key in sorted(observations)),
        )
    except M6ProceduralGateAuthorityError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError):
        _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)


def assemble_m6_candidate_case_procedural_gate_authority(
    *,
    run_cut: M6UpgradeCandidateRunCutAuthority,
    selected_case: Case,
    selected_case_revision: int,
    selected_case_document_sha256: str,
    source_identity_sha256: str,
    gate_source: M6SealedGateSource,
    snapshot: M6ProceduralGateHistorySnapshot,
) -> M6CaseProceduralGateAuthority:
    """Rebuild candidate Gate inputs from the exact terminal run and current cut."""

    if (
        type(run_cut) is not M6UpgradeCandidateRunCutAuthority
        or type(selected_case) is not Case
        or type(gate_source) is not M6SealedGateSource
        or type(selected_case_revision) is not int
        or selected_case_revision <= 0
    ):
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        controlled_cut = M6UpgradeCandidateRunCutAuthority.model_validate(
            run_cut.model_dump(mode="json", exclude_computed_fields=True)
        )
        controlled_case = Case.model_validate(
            selected_case.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)
    if controlled_cut != run_cut or controlled_case != selected_case:
        _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)
    for value in (selected_case_document_sha256, source_identity_sha256):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            _fail(M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT)

    m4_report = controlled_cut.validation_report.predecessor_report
    if (
        not isinstance(m4_report, M4ArtifactValidationReport)
        or m4_report.authority_root_sha256 is None
        or controlled_case.run_id != controlled_cut.candidate_run_id
        or controlled_case.manifest_id != controlled_cut.candidate_manifest.manifest_id
        or _document_sha256(controlled_case) != selected_case_document_sha256
        or gate_source.source_case != controlled_case
        or gate_source.source_case_revision != selected_case_revision
        or gate_source.source_case_document_sha256 != selected_case_document_sha256
        or gate_source.audit_head_sequence != controlled_cut.audit_head_sequence
        or gate_source.audit_head_hash != controlled_cut.audit_head_hash
    ):
        _fail(M6ProceduralGateAuthorityErrorCode.SOURCE_SCOPE_MISMATCH)

    try:
        resealed = seal_m6_gate_current_closures(
            observation=_candidate_gate_source_observation(gate_source)
        )
    except M6SourceAuthoritySealingError:
        _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)
    if resealed != gate_source:
        _fail(M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID)

    return _assemble_m6_case_procedural_gate_authority_core(
        case=controlled_case,
        manifest=controlled_cut.candidate_manifest,
        source_identity_sha256=source_identity_sha256,
        source_m4_authority_root_sha256=m4_report.authority_root_sha256,
        gate_current_closures=gate_source.gate_current_closures,
        snapshot=snapshot,
        config=controlled_cut.candidate_config,
    )


__all__ = [
    "M6ProceduralGateAuthorityError",
    "M6ProceduralGateAuthorityErrorCode",
    "assemble_m6_candidate_case_procedural_gate_authority",
    "assemble_m6_case_procedural_gate_authority",
]
