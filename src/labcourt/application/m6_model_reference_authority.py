"""Resolve exact model-reference scopes from validated M3 and M4 snapshots."""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_model_call_authority import (
    M6ModelCallAuthorityError,
    assemble_m6_locked_screening_model_calls,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ArtifactKind, ScreeningDecision, VlmRole
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingModelRequest,
    HearingRecord,
    HearingRoleOutput,
    HearingRound,
    HearingVerdictBinding,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.screening import StructureRepairRequest, VLMRequest
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Verdict
from labcourt.domain.hearing_verdict_builder import (
    HearingVerdictBuildError,
    validate_hearing_verdict_binding,
)
from labcourt.domain.m6_model_reference_authority import (
    M6CaseModelReferenceAuthority,
    M6FastVerdictModelReferenceBinding,
    M6HearingRoleModelReferenceBinding,
    M6ModelReferenceScope,
    M6ScreeningModelReferenceBinding,
    M6VerdictModelReferenceBinding,
)
from labcourt.domain.screening_router import FastVerdictBuilder, ScreeningRouteError
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_acquisition_authority import M6ValidatedM4ReplayAuthoritySnapshot
from labcourt.ports.m6_model_calls import M6M3ModelCallAuthoritySnapshot

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ModelReferenceAuthorityErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_CASE_INVALID = "SOURCE_CASE_INVALID"
    SNAPSHOT_IDENTITY_MISMATCH = "SNAPSHOT_IDENTITY_MISMATCH"
    M3_AUTHORITY_INVALID = "M3_AUTHORITY_INVALID"
    M3_SCREENING_OUTPUT_MISSING = "M3_SCREENING_OUTPUT_MISSING"
    M3_SCREENING_OUTPUT_AMBIGUOUS = "M3_SCREENING_OUTPUT_AMBIGUOUS"
    M3_FINAL_REQUEST_MISSING = "M3_FINAL_REQUEST_MISSING"
    M3_REPAIR_ORIGINAL_REQUEST_MISSING = "M3_REPAIR_ORIGINAL_REQUEST_MISSING"
    M3_SCOPE_CLOSURE_MISMATCH = "M3_SCOPE_CLOSURE_MISMATCH"
    M3_FAST_VERDICT_CLOSURE_INVALID = "M3_FAST_VERDICT_CLOSURE_INVALID"
    M4_AUTHORITY_DOCUMENT_INVALID = "M4_AUTHORITY_DOCUMENT_INVALID"
    M4_VERDICT_DOCUMENT_MISSING = "M4_VERDICT_DOCUMENT_MISSING"
    M4_VERDICT_BINDING_MISSING = "M4_VERDICT_BINDING_MISSING"
    M4_RECORD_MISSING = "M4_RECORD_MISSING"
    M4_ROUND_MISSING = "M4_ROUND_MISSING"
    M4_ROLE_OUTPUT_MISSING = "M4_ROLE_OUTPUT_MISSING"
    M4_ROLE_REQUEST_MISSING = "M4_ROLE_REQUEST_MISSING"
    M4_CROSS_MAPPING = "M4_CROSS_MAPPING"
    M4_SCOPE_CLOSURE_MISMATCH = "M4_SCOPE_CLOSURE_MISMATCH"
    M4_VERDICT_CLOSURE_INVALID = "M4_VERDICT_CLOSURE_INVALID"
    RESOLVED_AUTHORITY_INVALID = "RESOLVED_AUTHORITY_INVALID"


class M6ModelReferenceAuthorityError(LabCourtError):
    """One request-to-model-output reference scope could not be proven."""

    def __init__(self, code: M6ModelReferenceAuthorityErrorCode) -> None:
        if not isinstance(code, M6ModelReferenceAuthorityErrorCode):
            raise TypeError("code must be an M6ModelReferenceAuthorityErrorCode")
        self.code = code
        super().__init__(f"M6 model reference authority failed: {code.value}")


def _fail(code: M6ModelReferenceAuthorityErrorCode) -> NoReturn:
    raise M6ModelReferenceAuthorityError(code)


def _controlled_case(value: object) -> Case:
    if not isinstance(value, Case):
        _fail(M6ModelReferenceAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        controlled = Case.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ModelReferenceAuthorityErrorCode.SOURCE_CASE_INVALID)
    if controlled != value:
        _fail(M6ModelReferenceAuthorityErrorCode.SOURCE_CASE_INVALID)
    return controlled


def _require_m3_scope_closure(pack: EvidencePack, request: VLMRequest) -> None:
    crops_by_id = {crop.crop_id: crop for crop in pack.crops}
    for media in request.media:
        crop = crops_by_id.get(media.crop_id)
        if crop is None or (
            media.media_sha256 != crop.media_sha256
            or media.local_path != crop.local_path
            or media.source != crop.source
            or media.media_access != crop.privacy_receipt.media_access
            or media.privacy_policy != crop.privacy_receipt.policy
            or media.privacy_transform_version != crop.privacy_receipt.transform_version
            or media.width != crop.output_width
            or media.height != crop.output_height
        ):
            _fail(M6ModelReferenceAuthorityErrorCode.M3_SCOPE_CLOSURE_MISMATCH)
    closure_kinds = frozenset(
        {
            ArtifactKind.FRAME,
            ArtifactKind.OBJECTIVE_FACT,
            ArtifactKind.TOOL_RESULT,
        }
    )
    available = {
        ref.sort_key: ref for ref in pack.expected_closure_refs() if ref.kind in closure_kinds
    }
    for media in request.media:
        ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id)
        available[ref.sort_key] = ref
    if any(ref.sort_key not in available for ref in request.allowed_evidence_refs):
        _fail(M6ModelReferenceAuthorityErrorCode.M3_SCOPE_CLOSURE_MISMATCH)


def _require_m4_scope_closure(
    pack: EvidencePack,
    request: HearingModelRequest,
    hearing_round: HearingRound,
) -> None:
    if (
        request.current_evidence_pack_id != pack.pack_id
        or request.current_evidence_pack_version != pack.version
        or hearing_round.current_evidence_pack_id != pack.pack_id
        or hearing_round.current_evidence_pack_version != pack.version
    ):
        _fail(M6ModelReferenceAuthorityErrorCode.M4_SCOPE_CLOSURE_MISMATCH)
    crops_by_id = {crop.crop_id: crop for crop in pack.crops}
    for media in request.media:
        crop = crops_by_id.get(media.crop_id)
        if crop is None or (
            media.media_sha256 != crop.media_sha256
            or media.local_path != crop.local_path
            or media.source != crop.source
            or media.media_access != crop.privacy_receipt.media_access
            or media.privacy_policy != crop.privacy_receipt.policy
            or media.privacy_transform_version != crop.privacy_receipt.transform_version
            or media.width != crop.output_width
            or media.height != crop.output_height
        ):
            _fail(M6ModelReferenceAuthorityErrorCode.M4_SCOPE_CLOSURE_MISMATCH)
    available_kinds = frozenset(
        {
            ArtifactKind.CROP,
            ArtifactKind.OBJECTIVE_FACT,
            ArtifactKind.TOOL_RESULT,
        }
    )
    available = {
        ref.sort_key for ref in pack.expected_closure_refs() if ref.kind in available_kinds
    }
    retrieval = hearing_round.precedent_retrieval_receipt
    expected_precedents = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.PRECEDENT,
                    artifact_id=item.precedent.precedent_id,
                )
                for item in retrieval.scored_precedents
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    if (
        any(ref.sort_key not in available for ref in request.allowed_evidence_refs)
        or request.cycle_scope_id != retrieval.cycle_scope_id
        or request.precedent_retrieval_receipt_id != retrieval.receipt_id
        or request.precedent_retrieval_receipt_sha256 != retrieval.receipt_sha256
        or request.allowed_precedent_refs != expected_precedents
    ):
        _fail(M6ModelReferenceAuthorityErrorCode.M4_SCOPE_CLOSURE_MISMATCH)


def resolve_m6_screening_model_reference_bindings(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[M6ScreeningModelReferenceBinding, ...]:
    """Bind every Case screening to its final request and original evidence scope."""

    case = _controlled_case(source_case)
    if not isinstance(snapshot, M6M3ModelCallAuthoritySnapshot):
        _fail(M6ModelReferenceAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        assemble_m6_locked_screening_model_calls(source_case=case, snapshot=snapshot)
    except M6ModelCallAuthorityError:
        _fail(M6ModelReferenceAuthorityErrorCode.M3_AUTHORITY_INVALID)

    requests_by_id = {item.request.request_id: item.request for item in snapshot.requests}
    packs_by_key = {(pack.pack_id, pack.version): pack for pack in case.evidence_packs}
    outputs_by_id: dict[str, list[object]] = {}
    for document in snapshot.parsed_outputs:
        outputs_by_id.setdefault(document.output.parsed_output_id, []).append(document.output)

    bindings: list[M6ScreeningModelReferenceBinding] = []
    for screening in case.screening_results:
        candidates = outputs_by_id.get(screening.parsed_output.parsed_output_id, [])
        if not candidates:
            _fail(M6ModelReferenceAuthorityErrorCode.M3_SCREENING_OUTPUT_MISSING)
        if len(candidates) != 1:
            _fail(M6ModelReferenceAuthorityErrorCode.M3_SCREENING_OUTPUT_AMBIGUOUS)
        output = candidates[0]
        if output != screening.parsed_output:
            _fail(M6ModelReferenceAuthorityErrorCode.M3_SCREENING_OUTPUT_AMBIGUOUS)
        final_request = requests_by_id.get(screening.parsed_output.request_id)
        if not isinstance(final_request, VLMRequest | StructureRepairRequest):
            _fail(M6ModelReferenceAuthorityErrorCode.M3_FINAL_REQUEST_MISSING)
        scope_request: VLMRequest | None = (
            final_request if isinstance(final_request, VLMRequest) else None
        )
        if isinstance(final_request, StructureRepairRequest):
            original = requests_by_id.get(final_request.original_request_id)
            scope_request = original if isinstance(original, VLMRequest) else None
            if not isinstance(scope_request, VLMRequest):
                _fail(M6ModelReferenceAuthorityErrorCode.M3_REPAIR_ORIGINAL_REQUEST_MISSING)
        assert isinstance(scope_request, VLMRequest)
        pack = packs_by_key.get(
            (scope_request.evidence_pack_id, scope_request.evidence_pack_version)
        )
        if pack is None:
            _fail(M6ModelReferenceAuthorityErrorCode.M3_SCOPE_CLOSURE_MISMATCH)
        _require_m3_scope_closure(pack, scope_request)
        try:
            bindings.append(
                M6ScreeningModelReferenceBinding(
                    screening_id=screening.screening_id,
                    parsed_output_id=screening.parsed_output.parsed_output_id,
                    final_request_id=final_request.request_id,
                    scope=M6ModelReferenceScope(
                        request_id=scope_request.request_id,
                        evidence_pack_id=scope_request.evidence_pack_id,
                        evidence_pack_version=scope_request.evidence_pack_version,
                        cycle_scope_id=None,
                        allowed_evidence_refs=scope_request.allowed_evidence_refs,
                    ),
                )
            )
        except (TypeError, ValueError):
            _fail(M6ModelReferenceAuthorityErrorCode.RESOLVED_AUTHORITY_INVALID)
    return tuple(sorted(bindings, key=lambda item: item.screening_id))


def resolve_m6_fast_verdict_model_reference_bindings(
    *,
    source_case: Case,
    screening_bindings: tuple[M6ScreeningModelReferenceBinding, ...],
    hearing_verdict_ids: tuple[str, ...] = (),
) -> tuple[M6FastVerdictModelReferenceBinding, ...]:
    """Prove every non-hearing Verdict from its deterministic M3 route."""

    case = _controlled_case(source_case)
    if not isinstance(screening_bindings, tuple) or any(
        not isinstance(item, M6ScreeningModelReferenceBinding) for item in screening_bindings
    ):
        _fail(M6ModelReferenceAuthorityErrorCode.INVALID_ARGUMENT)
    if (
        not isinstance(hearing_verdict_ids, tuple)
        or any(not isinstance(item, str) or not item for item in hearing_verdict_ids)
        or hearing_verdict_ids != tuple(sorted(hearing_verdict_ids))
        or len(hearing_verdict_ids) != len(set(hearing_verdict_ids))
    ):
        _fail(M6ModelReferenceAuthorityErrorCode.INVALID_ARGUMENT)
    hearing_ids = set(hearing_verdict_ids)
    bindings_by_screening = {item.screening_id: item for item in screening_bindings}
    screenings = {item.screening_id: item for item in case.screening_results}
    packs = {(item.pack_id, item.version): item for item in case.evidence_packs}
    resolved: list[M6FastVerdictModelReferenceBinding] = []
    for verdict in case.verdicts:
        if verdict.verdict_id in hearing_ids:
            continue
        screening = screenings.get(verdict.screening_id)
        if screening is None:
            _fail(M6ModelReferenceAuthorityErrorCode.M3_FAST_VERDICT_CLOSURE_INVALID)
        if screening.decision == ScreeningDecision.ESCALATE:
            _fail(M6ModelReferenceAuthorityErrorCode.M3_FAST_VERDICT_CLOSURE_INVALID)
        pack = packs.get((verdict.evidence_pack_id, verdict.evidence_pack_version))
        screening_binding = bindings_by_screening.get(screening.screening_id)
        if pack is None or screening_binding is None:
            _fail(M6ModelReferenceAuthorityErrorCode.M3_FAST_VERDICT_CLOSURE_INVALID)
        try:
            rebuilt = FastVerdictBuilder().build(
                screening,
                pack,
                version=verdict.version,
                model_response_refs=verdict.model_response_refs,
            )
            if rebuilt != verdict:
                _fail(M6ModelReferenceAuthorityErrorCode.M3_FAST_VERDICT_CLOSURE_INVALID)
            resolved.append(
                M6FastVerdictModelReferenceBinding(
                    verdict_id=verdict.verdict_id,
                    screening_id=screening.screening_id,
                    response_ids=tuple(
                        sorted(item.artifact_id for item in verdict.model_response_refs)
                    ),
                    scope=screening_binding.scope,
                )
            )
        except (ScreeningRouteError, TypeError, ValueError):
            _fail(M6ModelReferenceAuthorityErrorCode.M3_FAST_VERDICT_CLOSURE_INVALID)
    return tuple(sorted(resolved, key=lambda item: item.verdict_id))


_M4_MODELS: dict[M4ProjectionArtifactKind, type[BaseModel]] = {
    M4ProjectionArtifactKind.MODEL_REQUEST: HearingModelRequest,
    M4ProjectionArtifactKind.ROLE_OUTPUT: HearingRoleOutput,
    M4ProjectionArtifactKind.HEARING_ROUND: HearingRound,
    M4ProjectionArtifactKind.HEARING_RECORD: HearingRecord,
    M4ProjectionArtifactKind.VERDICT_BINDING: HearingVerdictBinding,
    M4ProjectionArtifactKind.VERDICT: Verdict,
}

_M4_ID_FIELDS: dict[M4ProjectionArtifactKind, str] = {
    M4ProjectionArtifactKind.MODEL_REQUEST: "request_id",
    M4ProjectionArtifactKind.ROLE_OUTPUT: "output_id",
    M4ProjectionArtifactKind.HEARING_ROUND: "round_id",
    M4ProjectionArtifactKind.HEARING_RECORD: "record_id",
    M4ProjectionArtifactKind.VERDICT_BINDING: "binding_id",
    M4ProjectionArtifactKind.VERDICT: "verdict_id",
}


def _m4_documents(
    snapshot: M6ValidatedM4ReplayAuthoritySnapshot,
) -> dict[M4ProjectionArtifactKind, tuple[BaseModel, ...]]:
    values: dict[M4ProjectionArtifactKind, list[BaseModel]] = {kind: [] for kind in _M4_MODELS}
    for authority in snapshot.documents:
        if not isinstance(authority.kind, M4ProjectionArtifactKind):
            _fail(M6ModelReferenceAuthorityErrorCode.M4_AUTHORITY_DOCUMENT_INVALID)
        kind = authority.kind
        model_type = _M4_MODELS.get(kind)
        if model_type is None:
            continue
        try:
            document = model_type.model_validate_json(authority.canonical_document)
        except (TypeError, ValueError, ValidationError):
            _fail(M6ModelReferenceAuthorityErrorCode.M4_AUTHORITY_DOCUMENT_INVALID)
        if (
            canonical_json(document.model_dump(mode="json")) != authority.canonical_document
            or getattr(document, _M4_ID_FIELDS[kind], None) != authority.artifact_id
        ):
            _fail(M6ModelReferenceAuthorityErrorCode.M4_AUTHORITY_DOCUMENT_INVALID)
        values[kind].append(document)
    return {kind: tuple(documents) for kind, documents in values.items()}


def _one_matching(
    values: tuple[_ModelT, ...],
    *,
    field: str,
    identity: str,
    missing: M6ModelReferenceAuthorityErrorCode,
) -> _ModelT:
    matches = tuple(item for item in values if getattr(item, field, None) == identity)
    if not matches:
        _fail(missing)
    if len(matches) != 1:
        _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)
    return matches[0]


def _verdict_payloads_match(
    verdict: Verdict,
    prosecutor: HearingRoleOutput,
    defender: HearingRoleOutput,
    judge: HearingRoleOutput,
) -> bool:
    if (
        not isinstance(prosecutor.payload, ProsecutorModelPayload)
        or not isinstance(defender.payload, DefenderModelPayload)
        or not isinstance(judge.payload, JudgeModelPayload)
        or not isinstance(judge.payload.outcome, JudgeFinalDecisionPayload)
    ):
        return False
    final = judge.payload.outcome
    return (
        prosecutor.payload.arguments == verdict.prosecution_arguments
        and defender.payload.arguments == verdict.defense_arguments
        and judge.payload.judge_responses == verdict.judge_responses
        and judge.payload.precedent_applications == verdict.precedent_applications
        and final.decision == verdict.decision
        and final.confidence == verdict.confidence
        and final.recommended_alert_level == verdict.recommended_alert_level
        and final.rationale_summary == verdict.rationale_summary
        and final.evidence_citations == verdict.evidence_citations
        and final.objective_claims == verdict.objective_claims
        and final.observation_sufficiency == verdict.observation_sufficiency
    )


def resolve_m6_hearing_model_reference_bindings(
    *,
    source_case: Case,
    snapshot: M6ValidatedM4ReplayAuthoritySnapshot,
) -> tuple[M6VerdictModelReferenceBinding, ...]:
    """Resolve every Verdict through its exact binding, record, terminal round, and requests."""

    case = _controlled_case(source_case)
    if not isinstance(snapshot, M6ValidatedM4ReplayAuthoritySnapshot):
        _fail(M6ModelReferenceAuthorityErrorCode.INVALID_ARGUMENT)
    if snapshot.run_id != case.run_id:
        _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)
    documents = _m4_documents(snapshot)
    verdict_documents = documents[M4ProjectionArtifactKind.VERDICT]
    bindings = documents[M4ProjectionArtifactKind.VERDICT_BINDING]
    records = documents[M4ProjectionArtifactKind.HEARING_RECORD]
    rounds = documents[M4ProjectionArtifactKind.HEARING_ROUND]
    outputs = documents[M4ProjectionArtifactKind.ROLE_OUTPUT]
    requests = documents[M4ProjectionArtifactKind.MODEL_REQUEST]
    packs_by_key = {(pack.pack_id, pack.version): pack for pack in case.evidence_packs}
    resolved: list[M6VerdictModelReferenceBinding] = []
    for verdict in case.verdicts:
        stored_verdict_matches = tuple(
            item
            for item in verdict_documents
            if getattr(item, "verdict_id", None) == verdict.verdict_id
        )
        if not stored_verdict_matches:
            continue
        stored_verdict = _one_matching(
            verdict_documents,
            field="verdict_id",
            identity=verdict.verdict_id,
            missing=M6ModelReferenceAuthorityErrorCode.M4_VERDICT_DOCUMENT_MISSING,
        )
        if stored_verdict != verdict:
            _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)
        binding = _one_matching(
            bindings,
            field="verdict_id",
            identity=verdict.verdict_id,
            missing=M6ModelReferenceAuthorityErrorCode.M4_VERDICT_BINDING_MISSING,
        )
        assert isinstance(binding, HearingVerdictBinding)
        record = _one_matching(
            records,
            field="record_id",
            identity=binding.hearing_record_id,
            missing=M6ModelReferenceAuthorityErrorCode.M4_RECORD_MISSING,
        )
        hearing_round = _one_matching(
            rounds,
            field="round_id",
            identity=binding.judge_round_id,
            missing=M6ModelReferenceAuthorityErrorCode.M4_ROUND_MISSING,
        )
        assert isinstance(record, HearingRecord)
        assert isinstance(hearing_round, HearingRound)
        if not record.rounds or record.rounds[-1] != hearing_round:
            _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)

        judge = _one_matching(
            outputs,
            field="output_id",
            identity=binding.judge_output_id,
            missing=M6ModelReferenceAuthorityErrorCode.M4_ROLE_OUTPUT_MISSING,
        )
        assert isinstance(judge, HearingRoleOutput)
        if judge.prosecutor_output_id is None or judge.defender_output_id is None:
            _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)
        prosecutor = _one_matching(
            outputs,
            field="output_id",
            identity=judge.prosecutor_output_id,
            missing=M6ModelReferenceAuthorityErrorCode.M4_ROLE_OUTPUT_MISSING,
        )
        defender = _one_matching(
            outputs,
            field="output_id",
            identity=judge.defender_output_id,
            missing=M6ModelReferenceAuthorityErrorCode.M4_ROLE_OUTPUT_MISSING,
        )
        assert isinstance(prosecutor, HearingRoleOutput)
        assert isinstance(defender, HearingRoleOutput)
        role_outputs = (prosecutor, defender, judge)
        if (
            tuple(item.role for item in role_outputs)
            != (VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE)
            or tuple(item.output_id for item in role_outputs)
            != (
                binding.prosecutor_output_id,
                binding.defender_output_id,
                binding.judge_output_id,
            )
            or role_outputs
            != (
                hearing_round.prosecutor_output,
                hearing_round.defender_output,
                hearing_round.judge_output,
            )
        ):
            _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)
        try:
            validate_hearing_verdict_binding(
                record,
                verdict,
                binding,
                violation_type=verdict.violation_type,
            )
        except (TypeError, ValueError, HearingVerdictBuildError):
            _fail(M6ModelReferenceAuthorityErrorCode.M4_VERDICT_CLOSURE_INVALID)
        verdict_response_refs = set(verdict.model_response_refs)
        if not _verdict_payloads_match(verdict, prosecutor, defender, judge) or any(
            output.response_ref not in verdict_response_refs for output in role_outputs
        ):
            _fail(M6ModelReferenceAuthorityErrorCode.M4_VERDICT_CLOSURE_INVALID)

        role_bindings: list[M6HearingRoleModelReferenceBinding] = []
        for output in role_outputs:
            final_request = _one_matching(
                requests,
                field="request_id",
                identity=output.request_ref.artifact_id,
                missing=M6ModelReferenceAuthorityErrorCode.M4_ROLE_REQUEST_MISSING,
            )
            assert isinstance(final_request, HearingModelRequest)
            if (
                final_request.role != output.role
                or final_request.run_id != case.run_id
                or final_request.case_id != case.case_id
                or final_request.manifest_id != case.manifest_id
            ):
                _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)
            scope_request = final_request
            if final_request.attempt_index == 1:
                if final_request.original_request_id is None:
                    _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)
                primary_request = _one_matching(
                    requests,
                    field="request_id",
                    identity=final_request.original_request_id,
                    missing=M6ModelReferenceAuthorityErrorCode.M4_ROLE_REQUEST_MISSING,
                )
                if not isinstance(primary_request, HearingModelRequest):
                    _fail(M6ModelReferenceAuthorityErrorCode.M4_ROLE_REQUEST_MISSING)
                scope_request = primary_request
                if scope_request.attempt_index != 0 or scope_request.role != output.role:
                    _fail(M6ModelReferenceAuthorityErrorCode.M4_CROSS_MAPPING)
            pack = packs_by_key.get(
                (
                    scope_request.current_evidence_pack_id,
                    scope_request.current_evidence_pack_version,
                )
            )
            if pack is None:
                _fail(M6ModelReferenceAuthorityErrorCode.M4_SCOPE_CLOSURE_MISMATCH)
            _require_m4_scope_closure(pack, scope_request, hearing_round)
            try:
                role_bindings.append(
                    M6HearingRoleModelReferenceBinding(
                        role=output.role,
                        output_id=output.output_id,
                        response_id=output.response_ref.artifact_id,
                        final_request_id=final_request.request_id,
                        scope=M6ModelReferenceScope(
                            request_id=scope_request.request_id,
                            evidence_pack_id=scope_request.current_evidence_pack_id,
                            evidence_pack_version=(scope_request.current_evidence_pack_version),
                            cycle_scope_id=scope_request.cycle_scope_id,
                            allowed_evidence_refs=scope_request.allowed_evidence_refs,
                            allowed_precedent_refs=scope_request.allowed_precedent_refs,
                        ),
                    )
                )
            except (TypeError, ValueError):
                _fail(M6ModelReferenceAuthorityErrorCode.RESOLVED_AUTHORITY_INVALID)
        try:
            resolved.append(
                M6VerdictModelReferenceBinding(
                    verdict_id=verdict.verdict_id,
                    hearing_record_id=record.record_id,
                    judge_round_id=hearing_round.round_id,
                    role_bindings=tuple(role_bindings),
                )
            )
        except (TypeError, ValueError):
            _fail(M6ModelReferenceAuthorityErrorCode.RESOLVED_AUTHORITY_INVALID)
    return tuple(sorted(resolved, key=lambda item: item.verdict_id))


def assemble_m6_case_model_reference_authority(
    *,
    source_case: Case,
    m3_snapshot: M6M3ModelCallAuthoritySnapshot,
    m4_snapshot: M6ValidatedM4ReplayAuthoritySnapshot,
) -> M6CaseModelReferenceAuthority:
    """Assemble case-wide reference scopes tied to one immutable source identity."""

    case = _controlled_case(source_case)
    if not isinstance(m3_snapshot, M6M3ModelCallAuthoritySnapshot) or not isinstance(
        m4_snapshot, M6ValidatedM4ReplayAuthoritySnapshot
    ):
        _fail(M6ModelReferenceAuthorityErrorCode.INVALID_ARGUMENT)
    if m3_snapshot.source_identity_sha256 != m4_snapshot.source_identity_sha256:
        _fail(M6ModelReferenceAuthorityErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
    screening = resolve_m6_screening_model_reference_bindings(
        source_case=case,
        snapshot=m3_snapshot,
    )
    verdicts = resolve_m6_hearing_model_reference_bindings(
        source_case=case,
        snapshot=m4_snapshot,
    )
    fast_verdicts = resolve_m6_fast_verdict_model_reference_bindings(
        source_case=case,
        screening_bindings=screening,
        hearing_verdict_ids=tuple(item.verdict_id for item in verdicts),
    )
    resolved_verdict_ids = {item.verdict_id for item in verdicts} | {
        item.verdict_id for item in fast_verdicts
    }
    if resolved_verdict_ids != {item.verdict_id for item in case.verdicts}:
        _fail(M6ModelReferenceAuthorityErrorCode.RESOLVED_AUTHORITY_INVALID)
    try:
        return M6CaseModelReferenceAuthority(
            source_identity_sha256=m3_snapshot.source_identity_sha256,
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            screening_bindings=screening,
            verdict_bindings=verdicts,
            fast_verdict_bindings=fast_verdicts,
        )
    except (TypeError, ValueError):
        _fail(M6ModelReferenceAuthorityErrorCode.RESOLVED_AUTHORITY_INVALID)


__all__ = [
    "M6ModelReferenceAuthorityError",
    "M6ModelReferenceAuthorityErrorCode",
    "assemble_m6_case_model_reference_authority",
    "resolve_m6_fast_verdict_model_reference_bindings",
    "resolve_m6_hearing_model_reference_bindings",
    "resolve_m6_screening_model_reference_bindings",
]
