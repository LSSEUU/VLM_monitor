from __future__ import annotations

import hashlib

import pytest

from labcourt.application.hearing_model_parser import (
    HearingModelParserInputError,
    HearingModelParserInputErrorCode,
    finalize_hearing_parse,
    inspect_hearing_response,
)
from labcourt.application.hearing_role_output import (
    HearingRoleOutputBuildError,
    HearingRoleOutputBuildFailureCode,
    build_hearing_role_output,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    JudgeDisposition,
    MediaAccess,
    ModelParseStatus,
    ObjectiveFactKind,
    PrecedentApplicationMode,
    PrivacyPolicy,
    ProceduralDefectCode,
    ProceduralReasonCode,
    UnknownReferenceNamespace,
    VerdictDecision,
    ViolationType,
    VlmRole,
    WearStatus,
)
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingModelRequest,
    HearingModelResponse,
    HearingUnknownReferenceSource,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
    derive_hearing_model_response_id,
)
from labcourt.contracts.m3_models import EvidenceCitation, PromptManifest, VlmCallBudget
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import (
    Argument,
    JudgeResponse,
    ObjectiveClaim,
    ObservationLabel,
    ObservationSufficiency,
    PrecedentApplication,
)

RUN_ID = "run-01"
CASE_ID = "case-01"
SESSION_ID = "1" * 64
PACK_ID = "2" * 64
MANIFEST_ID = "3" * 64
MODEL_ID = "4" * 64
PROMPT_BUNDLE = "5" * 64
KNOWN_CROP = "6" * 64
KNOWN_FACT = "7" * 64
KNOWN_TOOL = "8" * 64
KNOWN_PRECEDENT = "9" * 64
UNKNOWN = "f" * 64


def _ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _request(
    role: VlmRole,
    *,
    attempt_index: int = 0,
    original: tuple[str, str, str] | None = None,
) -> HearingModelRequest:
    media = VLMMediaRef(
        crop_id=KNOWN_CROP,
        media_sha256="a" * 64,
        local_path=f"{RUN_ID}/frames/{'a' * 64}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=8,
        height=8,
    )
    evidence_refs = tuple(
        sorted(
            (
                _ref(ArtifactKind.CROP, KNOWN_CROP),
                _ref(ArtifactKind.OBJECTIVE_FACT, KNOWN_FACT),
                _ref(ArtifactKind.TOOL_RESULT, KNOWN_TOOL),
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    budget = VlmCallBudget(
        max_images=0 if attempt_index else 1,
        max_input_pixels=0 if attempt_index else 64,
        max_output_tokens=256,
        pricing_currency="USD",
        input_cost_per_million_tokens=0.0,
        output_cost_per_million_tokens=0.0,
        max_estimated_cost=0.0,
        max_response_bytes=4_096,
        max_json_depth=12,
        max_json_fields=256,
        max_string_chars=8_192,
        timeout_seconds=5.0,
        claim_completion_grace_seconds=5.0,
    )
    original_request_id, original_response_id, original_content_sha = (
        original if original is not None else (None, None, None)
    )
    return HearingModelRequest(
        attempt_index=attempt_index,
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=SESSION_ID,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=PACK_ID,
        current_evidence_pack_version=1,
        screening_ref=_ref(ArtifactKind.SCREENING_RESULT, "b" * 64),
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        role=role,
        provider_profile=f"fake-{role.value.lower()}",
        provider="fake",
        model=f"deterministic-{role.value.lower()}",
        revision="1.0.0",
        model_manifest_id=MODEL_ID,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id=f"hearing_{role.value.lower()}_v1",
            role=role,
            template_sha256="c" * 64,
            output_schema_sha256="d" * 64,
            prompt_bundle_sha256=PROMPT_BUNDLE,
            renderer_version="jinja-3-1",
        ),
        hearing_prompt_bundle_sha256=PROMPT_BUNDLE,
        rendered_prompt_sha256="e" * 64,
        hearing_context_sha256="0" * 64,
        media=() if attempt_index else (media,),
        allowed_evidence_refs=evidence_refs,
        allowed_precedent_refs=(_ref(ArtifactKind.PRECEDENT, KNOWN_PRECEDENT),),
        prosecutor_output_ref=(
            _ref(ArtifactKind.PARSED_MODEL_OUTPUT, "1" * 64)
            if role in {VlmRole.DEFENDER, VlmRole.JUDGE}
            else None
        ),
        defender_output_ref=(
            _ref(ArtifactKind.PARSED_MODEL_OUTPUT, "2" * 64) if role == VlmRole.JUDGE else None
        ),
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt_id="3" * 64,
        precedent_retrieval_receipt_sha256="4" * 64,
        original_request_id=original_request_id,
        original_response_id=original_response_id,
        original_response_content_sha256=original_content_sha,
        repair_context_sha256="5" * 64 if attempt_index else None,
        temperature=0.0,
        seed=7,
        budget=budget,
        manifest_id=MANIFEST_ID,
    )


def _response(
    request: HearingModelRequest,
    raw: bytes,
) -> HearingModelResponse:
    content_sha256 = hashlib.sha256(raw).hexdigest()
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
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
        content_sha256=content_sha256,
        size_bytes=len(raw),
        input_tokens=2,
        output_tokens=3,
        latency_ms=4,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _payload_bytes(
    payload: ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
) -> bytes:
    return canonical_bytes(payload.model_dump(mode="json", exclude_computed_fields=True))


def _argument(
    stance: ArgumentStance,
    artifact_id: str = KNOWN_CROP,
) -> Argument:
    return Argument(
        stance=stance,
        claim="A concise, auditable argument.",
        evidence_refs=(_ref(ArtifactKind.CROP, artifact_id),),
        uncertainty=0.2,
    )


def _valid_payload(
    role: VlmRole,
) -> ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload:
    if role == VlmRole.PROSECUTOR:
        return ProsecutorModelPayload(
            arguments=(_argument(ArgumentStance.PROSECUTION),),
            case_summary="The prosecution cites only disclosed evidence.",
        )
    if role == VlmRole.DEFENDER:
        return DefenderModelPayload(
            arguments=(_argument(ArgumentStance.DEFENSE),),
            case_summary="The defense preserves uncertainty.",
        )
    return JudgeModelPayload(
        outcome=JudgeFinalDecisionPayload(
            decision=VerdictDecision.NOT_ESTABLISHED,
            confidence=0.6,
            recommended_alert_level=AlertLevel.ADVISORY,
            rationale_summary="The disclosed evidence does not establish the allegation.",
        )
    )


@pytest.mark.parametrize(
    "role",
    [VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE],
)
def test_each_role_parses_only_its_strict_payload_and_binds_exact_bytes(
    role: VlmRole,
) -> None:
    request = _request(role)
    payload = _valid_payload(role)
    raw = _payload_bytes(payload)

    inspection = inspect_hearing_response(
        raw,
        request=request,
        response=_response(request, raw),
    )
    result = finalize_hearing_parse(inspection)

    assert result.payload == payload
    assert result.receipt.status == ModelParseStatus.PARSED
    assert result.receipt.parsed_payload_sha256 == payload.payload_sha256
    assert result.receipt.unknown_reference_attempts == ()
    assert result.receipt.request_id == request.request_id


@pytest.mark.parametrize(
    "role",
    [VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE],
)
def test_parsed_payload_receives_only_exact_call_scope(role: VlmRole) -> None:
    request = _request(role)
    payload = _valid_payload(role)
    raw = _payload_bytes(payload)
    response = _response(request, raw)
    parsed = finalize_hearing_parse(
        inspect_hearing_response(raw, request=request, response=response)
    )
    assert parsed.payload is not None

    output = build_hearing_role_output(
        request=request,
        response=response,
        parse_receipt=parsed.receipt,
        payload=parsed.payload,
    )

    assert output.role == role
    assert output.request_ref.artifact_id == request.request_id
    assert output.response_ref.artifact_id == response.response_id
    assert output.parse_receipt_ref.artifact_id == parsed.receipt.parse_receipt_id
    assert output.prosecutor_output_id == (
        request.prosecutor_output_ref.artifact_id
        if request.prosecutor_output_ref is not None
        else None
    )
    assert output.defender_output_id == (
        request.defender_output_ref.artifact_id if request.defender_output_ref is not None else None
    )


def test_role_output_builder_rejects_cross_call_and_payload_tampering() -> None:
    request = _request(VlmRole.PROSECUTOR)
    payload = _valid_payload(VlmRole.PROSECUTOR)
    raw = _payload_bytes(payload)
    response = _response(request, raw)
    parsed = finalize_hearing_parse(
        inspect_hearing_response(raw, request=request, response=response)
    )
    assert parsed.payload is not None

    cases = (
        (
            {"response": response.model_copy(update={"case_id": "other-case"})},
            HearingRoleOutputBuildFailureCode.REQUEST_RESPONSE_MISMATCH,
        ),
        (
            {
                "parse_receipt": parsed.receipt.model_copy(
                    update={"response_content_sha256": "0" * 64}
                )
            },
            HearingRoleOutputBuildFailureCode.PARSE_RECEIPT_MISMATCH,
        ),
        (
            {
                "parse_receipt": parsed.receipt.model_copy(
                    update={"parsed_payload_sha256": "0" * 64}
                )
            },
            HearingRoleOutputBuildFailureCode.PAYLOAD_MISMATCH,
        ),
        (
            {"payload": _valid_payload(VlmRole.DEFENDER)},
            HearingRoleOutputBuildFailureCode.ROLE_MISMATCH,
        ),
    )
    baseline = {
        "request": request,
        "response": response,
        "parse_receipt": parsed.receipt,
        "payload": parsed.payload,
    }
    for updates, expected in cases:
        with pytest.raises(HearingRoleOutputBuildError) as captured:
            build_hearing_role_output(**{**baseline, **updates})
        assert captured.value.reason_code == expected


def test_unknown_argument_reference_is_hashed_not_corrected_or_leaked() -> None:
    request = _request(VlmRole.PROSECUTOR)
    payload = ProsecutorModelPayload(
        arguments=(_argument(ArgumentStance.PROSECUTION, UNKNOWN),),
        case_summary="This fixture deliberately emits one unknown citation.",
    )
    raw = _payload_bytes(payload)

    result = finalize_hearing_parse(
        inspect_hearing_response(raw, request=request, response=_response(request, raw))
    )

    assert result.payload == payload
    assert len(result.receipt.unknown_reference_attempts) == 1
    attempt = result.receipt.unknown_reference_attempts[0]
    assert attempt.namespace == UnknownReferenceNamespace.EVIDENCE
    assert attempt.source == HearingUnknownReferenceSource.ARGUMENT_EVIDENCE_REF
    assert UNKNOWN not in result.receipt.model_dump_json()


def test_judge_reference_paths_are_independently_diagnosed() -> None:
    request = _request(VlmRole.JUDGE)
    unknown_crop = _ref(ArtifactKind.CROP, UNKNOWN)
    unknown_fact = _ref(ArtifactKind.OBJECTIVE_FACT, UNKNOWN)
    payload = JudgeModelPayload(
        judge_responses=(
            JudgeResponse(
                defense_argument_id="a" * 64,
                disposition=JudgeDisposition.PARTIALLY_ACCEPTED,
                response_summary="The defense point remains partly persuasive.",
                evidence_refs=(unknown_crop,),
            ),
        ),
        precedent_applications=(
            PrecedentApplication(
                precedent_ref=_ref(ArtifactKind.PRECEDENT, UNKNOWN),
                mode=PrecedentApplicationMode.FOLLOWED,
                similarity_score=0.8,
                fact_difference_refs=(unknown_fact,),
            ),
        ),
        outcome=JudgeFinalDecisionPayload(
            decision=VerdictDecision.INSUFFICIENT_EVIDENCE,
            confidence=0.4,
            recommended_alert_level=AlertLevel.ADVISORY,
            rationale_summary="The current evidence is insufficient.",
            evidence_citations=(EvidenceCitation(evidence_ref=unknown_crop),),
            objective_claims=(
                ObjectiveClaim(
                    kind=ObjectiveFactKind.PERSON_COUNT,
                    value=1,
                    evidence_ref=unknown_fact,
                ),
            ),
            observation_sufficiency=ObservationSufficiency(
                clear_threshold=0.7,
                required_clear_count=2,
                observations=(
                    ObservationLabel(
                        crop_id=UNKNOWN,
                        wear_status=WearStatus.UNCLEAR,
                    ),
                ),
            ),
        ),
    )
    raw = _payload_bytes(payload)

    result = finalize_hearing_parse(
        inspect_hearing_response(raw, request=request, response=_response(request, raw))
    )

    assert result.receipt.status == ModelParseStatus.PARSED
    assert {item.source for item in result.receipt.unknown_reference_attempts} == {
        HearingUnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF,
        HearingUnknownReferenceSource.JUDGE_CITATION_REF,
        HearingUnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF,
        HearingUnknownReferenceSource.OBSERVATION_CROP_ID,
        HearingUnknownReferenceSource.PRECEDENT_APPLICATION_ID,
        HearingUnknownReferenceSource.PRECEDENT_FACT_DIFFERENCE_REF,
    }
    assert UNKNOWN not in result.receipt.model_dump_json()


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"{", ProceduralReasonCode.MALFORMED_JSON),
        (b"[]", ProceduralReasonCode.ROOT_NOT_OBJECT),
        (b'{"role":"PROSECUTOR","role":"JUDGE"}', ProceduralReasonCode.MALFORMED_JSON),
    ],
)
def test_malformed_primary_requires_one_explicit_repair_identity(
    raw: bytes,
    reason: ProceduralReasonCode,
) -> None:
    request = _request(VlmRole.PROSECUTOR)
    inspection = inspect_hearing_response(
        raw,
        request=request,
        response=_response(request, raw),
    )

    assert inspection.payload is None
    assert inspection.defects[0].reason_code == reason
    with pytest.raises(HearingModelParserInputError) as missing:
        finalize_hearing_parse(inspection)
    assert missing.value.reason_code == HearingModelParserInputErrorCode.REPAIR_REQUEST_ID_REQUIRED

    result = finalize_hearing_parse(inspection, repair_request_id="a" * 64)
    assert result.payload is None
    assert result.receipt.status == ModelParseStatus.REPAIR_REQUIRED
    assert result.receipt.repair_request_id == "a" * 64


def test_validation_defects_are_aggregated_to_the_three_code_contract() -> None:
    request = _request(VlmRole.PROSECUTOR)
    raw = canonical_bytes(
        {
            "role": "UNKNOWN",
            "unexpected": object.__name__,
        }
    )
    inspection = inspect_hearing_response(
        raw,
        request=request,
        response=_response(request, raw),
    )

    assert len(inspection.defects) <= 3
    assert tuple(item.code for item in inspection.defects) == (
        ProceduralDefectCode.MALFORMED_STRUCTURE,
        ProceduralDefectCode.INVALID_ENUM,
        ProceduralDefectCode.MISSING_REQUIRED_FIELD,
    )


def test_invalid_repair_is_terminal_and_valid_repair_does_not_create_a_cycle() -> None:
    primary = _request(VlmRole.DEFENDER)
    malformed = b"{"
    primary_response = _response(primary, malformed)
    repair = _request(
        VlmRole.DEFENDER,
        attempt_index=1,
        original=(
            primary.request_id,
            primary_response.response_id,
            primary_response.content_sha256,
        ),
    )

    invalid = b"{}"
    invalid_result = finalize_hearing_parse(
        inspect_hearing_response(
            invalid,
            request=repair,
            response=_response(repair, invalid),
        )
    )
    assert invalid_result.receipt.status == ModelParseStatus.INVALID_FINAL
    assert invalid_result.receipt.round_index == primary.round_index
    assert invalid_result.receipt.role == primary.role

    payload = _valid_payload(VlmRole.DEFENDER)
    valid = _payload_bytes(payload)
    valid_result = finalize_hearing_parse(
        inspect_hearing_response(
            valid,
            request=repair,
            response=_response(repair, valid),
        )
    )
    assert valid_result.receipt.status == ModelParseStatus.PARSED
    assert valid_result.payload == payload
    assert repair.media == ()
    assert repair.budget.max_images == 0


@pytest.mark.parametrize(
    ("mutation", "raw_override", "expected"),
    [
        ("size", None, HearingModelParserInputErrorCode.RESPONSE_SIZE_MISMATCH),
        ("scope", None, HearingModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH),
        ("content", b"", HearingModelParserInputErrorCode.RESPONSE_CONTENT_MISMATCH),
    ],
)
def test_application_authority_tamper_raises_only_controlled_input_errors(
    mutation: str,
    raw_override: bytes | None,
    expected: HearingModelParserInputErrorCode,
) -> None:
    request = _request(VlmRole.JUDGE)
    raw = _payload_bytes(_valid_payload(VlmRole.JUDGE))
    response = _response(request, raw)
    if mutation == "size":
        response = response.model_copy(update={"size_bytes": response.size_bytes + 1})
    elif mutation == "scope":
        response = response.model_copy(update={"case_id": "other-case"})
    supplied = raw_override if raw_override is not None else raw
    if mutation == "content":
        supplied = b"x" * len(raw)

    with pytest.raises(HearingModelParserInputError) as captured:
        inspect_hearing_response(supplied, request=request, response=response)
    assert captured.value.reason_code == expected
    assert supplied.decode("utf-8", errors="replace") not in str(captured.value)
