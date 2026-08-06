import hashlib
import json
from collections.abc import Mapping, Sequence

import pytest
from hypothesis import given
from hypothesis import strategies as st

from labcourt.application.model_parser import (
    ModelParserInputError,
    ModelParserInputErrorCode,
    finalize_screening_parse,
    inspect_screening_response,
    parse_screening_response,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    ModelParseStatus,
    PrivacyPolicy,
    ProceduralDefectCode,
    ProceduralReasonCode,
    UnknownReferenceSource,
    ViolationType,
    VlmCallPurpose,
    VlmRole,
)
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.screening import (
    StructureRepairRequest,
    VLMMediaRef,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef

RUN_ID = "run-01"
CASE_ID = "case-01"
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64
SHA_8 = "8" * 64
SHA_9 = "9" * 64
SHA_A = "a" * 64
SHA_B = "b" * 64


def _budget(
    *,
    max_response_bytes: int = 65_536,
    max_json_depth: int = 8,
    max_json_fields: int = 128,
    max_string_chars: int = 8_192,
) -> VlmCallBudget:
    return VlmCallBudget(
        max_images=4,
        max_input_pixels=100_000,
        max_output_tokens=1_024,
        pricing_currency="USD",
        input_cost_per_million_tokens=0.0,
        output_cost_per_million_tokens=0.0,
        max_estimated_cost=0.0,
        max_response_bytes=max_response_bytes,
        max_json_depth=max_json_depth,
        max_json_fields=max_json_fields,
        max_string_chars=max_string_chars,
        timeout_seconds=15.0,
        claim_completion_grace_seconds=5.0,
    )


def _request(*, budget: VlmCallBudget | None = None) -> VLMRequest:
    media = VLMMediaRef(
        crop_id=SHA_4,
        media_sha256=SHA_5,
        local_path=f"{RUN_ID}/frames/{SHA_5}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version="privacy-v1",
        width=100,
        height=100,
    )
    allowed = tuple(
        sorted(
            (
                ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_4),
                ArtifactRef(kind=ArtifactKind.FRAME, artifact_id="cam-01:stream-01:7"),
                ArtifactRef(
                    kind=ArtifactKind.OBJECTIVE_FACT,
                    artifact_id="person-count-01",
                ),
            ),
            key=lambda reference: reference.sort_key,
        )
    )
    return VLMRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        evidence_pack_id=SHA_6,
        evidence_pack_version=1,
        provider_profile="fake-screening",
        provider="fixture",
        model="fixture-vlm",
        revision="1.0.0",
        model_manifest_id=SHA_7,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id="screening-v1",
            role=VlmRole.SCREENING,
            template_sha256=SHA_1,
            output_schema_sha256=SHA_2,
            prompt_bundle_sha256=SHA_3,
            renderer_version="jinja-3-1",
        ),
        rendered_prompt_sha256=SHA_8,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        rule_summary="Apply the configured laboratory rule.",
        media=(media,),
        allowed_evidence_refs=allowed,
        objective_summary={"duration_frames": 91},
        temperature=0.0,
        seed=7,
        budget=budget or _budget(),
        manifest_id=SHA_9,
    )


def _payload() -> dict[str, object]:
    return {
        "violation_type": "REAGENT_CONTAINER_OPEN",
        "evidence_class": "PRESENCE",
        "violation_probability": 0.92,
        "frame_observations": [
            {
                "crop_id": SHA_4,
                "wear_status": "UNCLEAR",
                "reason_summary": "The crop is not relevant to PPE.",
            }
        ],
        "evidence_citations": [
            {
                "evidence_ref": {"kind": "CROP", "artifact_id": SHA_4},
                "bbox": None,
                "coordinate_space": None,
            }
        ],
        "objective_claims": [
            {
                "kind": "PERSON_COUNT",
                "value": 2,
                "evidence_ref": {
                    "kind": "OBJECTIVE_FACT",
                    "artifact_id": "person-count-01",
                },
            }
        ],
        "prosecution_summary": "The structured observations support screening.",
        "rationale_summary": "Only typed fields are used by deterministic code.",
    }


def _raw(payload: object | None = None) -> bytes:
    return json.dumps(
        _payload() if payload is None else payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _response(
    request: VLMRequest,
    raw: bytes,
) -> VLMResponse:
    content_sha256 = hashlib.sha256(raw).hexdigest()
    response_id = derive_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
    )
    return VLMResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        purpose=VlmCallPurpose.SCREENING,
        attempt_index=0,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=len(raw),
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _repair(
    request: VLMRequest,
    original_response: VLMResponse,
) -> StructureRepairRequest:
    return StructureRepairRequest(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        provider_profile=request.provider_profile,
        provider=request.provider,
        model=request.model,
        revision=request.revision,
        model_manifest_id=request.model_manifest_id,
        execution_location=request.execution_location,
        prompt_manifest=PromptManifest(
            prompt_id="screening-structure-repair-v1",
            role=VlmRole.STRUCTURE_REPAIR,
            template_sha256=SHA_1,
            output_schema_sha256=request.prompt_manifest.output_schema_sha256,
            prompt_bundle_sha256=request.prompt_manifest.prompt_bundle_sha256,
            renderer_version="jinja-3-1",
        ),
        rendered_prompt_sha256=SHA_8,
        original_request_id=request.request_id,
        original_request_sha256=request.request_sha256,
        original_response_id=original_response.response_id,
        original_response_sha256=original_response.content_sha256,
        parse_defect_codes=(ProceduralDefectCode.MALFORMED_STRUCTURE,),
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=0,
            max_input_pixels=0,
            max_output_tokens=1_024,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=65_536,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=8_192,
            timeout_seconds=15.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=request.manifest_id,
    )


def _repair_response(
    repair: StructureRepairRequest,
    raw: bytes,
) -> VLMResponse:
    content_sha256 = hashlib.sha256(raw).hexdigest()
    response_id = derive_model_response_id(
        repair.run_id,
        repair.request_id,
        content_sha256,
    )
    return VLMResponse(
        run_id=repair.run_id,
        case_id=repair.case_id,
        evidence_pack_id=repair.evidence_pack_id,
        evidence_pack_version=repair.evidence_pack_version,
        request_id=repair.request_id,
        request_sha256=repair.request_sha256,
        cache_key=repair.cache_key,
        purpose=VlmCallPurpose.STRUCTURE_REPAIR,
        attempt_index=1,
        raw_response_ref=f"{repair.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=len(raw),
        model_manifest_id=repair.model_manifest_id,
        manifest_id=repair.manifest_id,
    )


def _inspect(
    raw: bytes,
    *,
    request: VLMRequest | None = None,
    attempt_index: int = 0,
):
    authority = request or _request()
    if attempt_index == 1:
        original_response = _response(authority, b"not-json")
        repair = _repair(authority, original_response)
        return inspect_screening_response(
            raw,
            request=authority,
            response=_repair_response(repair, raw),
            repair_request=repair,
            original_response=original_response,
        )
    return inspect_screening_response(
        raw,
        request=authority,
        response=_response(authority, raw),
    )


def _total_json_string_chars(value: object) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, Mapping):
        return sum(len(key) + _total_json_string_chars(item) for key, item in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return sum(_total_json_string_chars(item) for item in value)
    return 0


def test_valid_response_builds_system_envelope_and_parsed_receipt() -> None:
    request = _request()
    raw = _raw()
    response = _response(request, raw)

    result = parse_screening_response(raw, request=request, response=response)

    assert result.output is not None
    assert result.output.request_id == request.request_id
    assert result.output.response_id == response.response_id
    assert result.output.payload.violation_probability == 0.92
    assert result.receipt.status == ModelParseStatus.PARSED
    assert result.receipt.defects == ()
    assert result.receipt.parsed_output_id == result.output.parsed_output_id
    assert result.receipt.parsed_output_sha256 == result.output.parsed_output_sha256


def test_inspection_then_finalization_binds_exactly_one_repair() -> None:
    inspection = _inspect(b"not-json")
    assert inspection.defect_codes == (ProceduralDefectCode.MALFORMED_STRUCTURE,)

    result = finalize_screening_parse(inspection, repair_request_id=SHA_A)
    assert result.output is None
    assert result.receipt.status == ModelParseStatus.REPAIR_REQUIRED
    assert result.receipt.repair_request_id == SHA_A

    with pytest.raises(ModelParserInputError) as missing:
        finalize_screening_parse(inspection)
    assert missing.value.code == ModelParserInputErrorCode.REPAIR_REQUEST_ID_REQUIRED
    with pytest.raises(ModelParserInputError) as invalid:
        finalize_screening_parse(inspection, repair_request_id="raw-secret")
    assert invalid.value.code == ModelParserInputErrorCode.INVALID_REPAIR_REQUEST_ID
    assert "raw-secret" not in str(invalid.value)


def test_repair_attempt_failure_is_final_and_cannot_request_another_repair() -> None:
    inspection = _inspect(b"{}", attempt_index=1)
    result = finalize_screening_parse(inspection)
    assert result.output is None
    assert result.receipt.status == ModelParseStatus.INVALID_FINAL
    assert result.receipt.repair_request_id is None

    with pytest.raises(ModelParserInputError) as forbidden:
        finalize_screening_parse(inspection, repair_request_id=SHA_A)
    assert forbidden.value.code == ModelParserInputErrorCode.REPAIR_REQUEST_ID_FORBIDDEN


@pytest.mark.parametrize(
    "raw,reason",
    [
        (b"", ProceduralReasonCode.MALFORMED_JSON),
        (b"{}{}", ProceduralReasonCode.MALFORMED_JSON),
        (b"```json\n{}\n```", ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":1} trailing', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":NaN}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":Infinity}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":1e999}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"nested":[-1e999]}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":"\\ud800"}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":"\\ud800\\uZZZZ"}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":"\\ud800\\u0041"}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":"\\udc00"}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":"\\q"}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":"\\uZZZZ"}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":"\\', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":"raw\x01control"}', ProceduralReasonCode.MALFORMED_JSON),
        (b'{"x":' + (b"9" * 5_000) + b"}", ProceduralReasonCode.MALFORMED_JSON),
        (b"\xff", ProceduralReasonCode.MALFORMED_JSON),
        (b"[]", ProceduralReasonCode.ROOT_NOT_OBJECT),
    ],
)
def test_malformed_inputs_are_never_guessed(raw: bytes, reason: ProceduralReasonCode) -> None:
    inspection = _inspect(raw)
    assert inspection.payload is None
    assert len(inspection.defects) == 1
    assert inspection.defects[0].code == ProceduralDefectCode.MALFORMED_STRUCTURE
    assert inspection.defects[0].reason_code == reason


def test_duplicate_keys_are_rejected_in_every_object_scope() -> None:
    top_level = (
        _raw()
        .decode("utf-8")
        .replace(
            '"violation_type":"REAGENT_CONTAINER_OPEN",',
            '"violation_type":"REAGENT_CONTAINER_OPEN","violation_type":"REAGENT_CONTAINER_OPEN",',
            1,
        )
    )
    nested = (
        _raw()
        .decode("utf-8")
        .replace(
            f'"kind":"CROP","artifact_id":"{SHA_4}"',
            f'"kind":"CROP","kind":"CROP","artifact_id":"{SHA_4}"',
            1,
        )
    )
    for text in (top_level, nested):
        inspection = _inspect(text.encode("utf-8"))
        assert inspection.defect_codes == (ProceduralDefectCode.MALFORMED_STRUCTURE,)


def test_valid_unicode_and_a_well_formed_surrogate_pair_are_accepted() -> None:
    payload = _payload()
    payload["rationale_summary"] = "Typed result 😀"
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    inspection = _inspect(raw)
    assert inspection.payload is not None
    assert inspection.payload.rationale_summary == "Typed result 😀"

    payload["rationale_summary"] = 'A quote: " and a slash: \\'
    escaped = _inspect(_raw(payload))
    assert escaped.payload is not None


def test_missing_and_invalid_enum_defects_are_both_precise_and_stable() -> None:
    payload = _payload()
    payload.pop("prosecution_summary")
    payload["violation_type"] = "reagent_container_open"
    raw = _raw(payload)

    first = _inspect(raw)
    second = _inspect(raw)

    assert first.defect_codes == (
        ProceduralDefectCode.INVALID_ENUM,
        ProceduralDefectCode.MISSING_REQUIRED_FIELD,
    )
    assert tuple(defect.defect_id for defect in first.defects) == tuple(
        defect.defect_id for defect in second.defects
    )
    public = json.dumps(
        [defect.model_dump(mode="json") for defect in first.defects],
        sort_keys=True,
    )
    assert "reagent_container_open" not in public
    assert "prosecution_summary" not in public


def test_non_enum_contract_errors_remain_malformed_structure() -> None:
    for field, value in (
        ("violation_probability", "0.92"),
        ("unexpected_provider_field", "private-provider-text"),
    ):
        payload = _payload()
        payload[field] = value
        inspection = _inspect(_raw(payload))
        assert inspection.defect_codes == (ProceduralDefectCode.MALFORMED_STRUCTURE,)


def test_all_model_reference_positions_are_prescanned_and_only_hashed() -> None:
    payload = _payload()
    unknown_crop = "c" * 64
    unknown_citation = "d" * 64
    unknown_fact = "unknown-fact-01"
    observations = payload["frame_observations"]
    citations = payload["evidence_citations"]
    claims = payload["objective_claims"]
    assert isinstance(observations, list)
    assert isinstance(citations, list)
    assert isinstance(claims, list)
    observations[0]["crop_id"] = unknown_crop
    citations[0]["evidence_ref"] = {"kind": "CROP", "artifact_id": unknown_citation}
    claims[0]["evidence_ref"] = {
        "kind": "OBJECTIVE_FACT",
        "artifact_id": unknown_fact,
    }
    raw = _raw(payload)
    request = _request()
    result = parse_screening_response(
        raw,
        request=request,
        response=_response(request, raw),
    )

    assert result.output is not None
    assert tuple(attempt.source for attempt in result.receipt.unknown_reference_attempts) == (
        UnknownReferenceSource.EVIDENCE_CITATION_REF,
        UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID,
        UnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF,
    )
    serialized = json.dumps(result.receipt.model_dump(mode="json"), sort_keys=True)
    for raw_reference in (unknown_crop, unknown_citation, unknown_fact):
        assert raw_reference not in serialized


def test_malformed_reference_shapes_are_hashed_before_contract_failure() -> None:
    payload = _payload()
    observations = payload["frame_observations"]
    citations = payload["evidence_citations"]
    claims = payload["objective_claims"]
    assert isinstance(observations, list)
    assert isinstance(citations, list)
    assert isinstance(claims, list)
    observations[0]["crop_id"] = 123
    citations[0]["evidence_ref"] = "private-reference-text"
    claims[0]["evidence_ref"] = {"kind": "OBJECTIVE_FACT"}

    inspection = _inspect(_raw(payload))

    assert inspection.payload is None
    assert len(inspection.unknown_reference_attempts) == 3
    serialized = json.dumps(
        [attempt.model_dump(mode="json") for attempt in inspection.unknown_reference_attempts]
    )
    assert "private-reference-text" not in serialized


def test_unknown_reference_attempts_are_deduplicated_by_source_and_digest() -> None:
    payload = _payload()
    observations = payload["frame_observations"]
    assert isinstance(observations, list)
    observations.extend([dict(observations[0]), dict(observations[0])])
    observations[0]["crop_id"] = SHA_A
    observations[1]["crop_id"] = SHA_A
    observations[2]["crop_id"] = SHA_A
    inspection = _inspect(_raw(payload))
    assert len(inspection.unknown_reference_attempts) == 1
    assert inspection.payload is None  # duplicate observations still fail the strict contract


def test_bytes_depth_fields_and_string_budgets_accept_boundary_then_reject_one_less() -> None:
    payload = {
        "violation_type": "REAGENT_CONTAINER_OPEN",
        "evidence_class": "PRESENCE",
        "violation_probability": 0.5,
        "frame_observations": [],
        "evidence_citations": [],
        "objective_claims": [],
        "prosecution_summary": "p",
        "rationale_summary": "r",
    }
    raw = _raw(payload)
    fields = len(payload)
    string_chars = _total_json_string_chars(payload)
    boundary = _request(
        budget=_budget(
            max_response_bytes=len(raw),
            max_json_depth=2,
            max_json_fields=fields,
            max_string_chars=string_chars,
        )
    )
    assert _inspect(raw, request=boundary).payload is not None

    limits = (
        _budget(
            max_response_bytes=len(raw) - 1,
            max_json_depth=2,
            max_json_fields=fields,
            max_string_chars=string_chars,
        ),
        _budget(
            max_response_bytes=len(raw),
            max_json_depth=1,
            max_json_fields=fields,
            max_string_chars=string_chars,
        ),
        _budget(
            max_response_bytes=len(raw),
            max_json_depth=2,
            max_json_fields=fields - 1,
            max_string_chars=string_chars,
        ),
        _budget(
            max_response_bytes=len(raw),
            max_json_depth=2,
            max_json_fields=fields,
            max_string_chars=string_chars - 1,
        ),
    )
    for budget in limits:
        inspection = _inspect(raw, request=_request(budget=budget))
        assert inspection.defects[0].reason_code == (ProceduralReasonCode.RESPONSE_LIMIT_EXCEEDED)


def test_receipt_binding_failures_use_constant_non_sensitive_errors() -> None:
    request = _request()
    raw = _raw()
    response = _response(request, raw)

    with pytest.raises(ModelParserInputError) as wrong_type:
        inspect_screening_response(  # type: ignore[arg-type]
            bytearray(raw), request=request, response=response
        )
    assert wrong_type.value.code == ModelParserInputErrorCode.RAW_RESPONSE_NOT_BYTES

    with pytest.raises(ModelParserInputError) as wrong_size:
        inspect_screening_response(raw + b"x", request=request, response=response)
    assert wrong_size.value.code == ModelParserInputErrorCode.RESPONSE_SIZE_MISMATCH

    same_size_tamper = b"x" * len(raw)
    with pytest.raises(ModelParserInputError) as wrong_hash:
        inspect_screening_response(same_size_tamper, request=request, response=response)
    assert wrong_hash.value.code == ModelParserInputErrorCode.RESPONSE_CONTENT_MISMATCH
    assert raw.decode("utf-8") not in str(wrong_hash.value)

    other_request = request.model_copy(update={"case_id": "case-02"})
    with pytest.raises(ModelParserInputError) as wrong_scope:
        inspect_screening_response(
            raw,
            request=other_request,
            response=response,
        )
    assert wrong_scope.value.code == ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH

    successful = _inspect(raw, request=request)
    with pytest.raises(ModelParserInputError) as unnecessary_repair:
        finalize_screening_parse(successful, repair_request_id=SHA_A)
    assert unnecessary_repair.value.code == ModelParserInputErrorCode.REPAIR_REQUEST_ID_FORBIDDEN


def test_repair_response_requires_exact_four_way_request_binding() -> None:
    request = _request()
    original_response = _response(request, b"not-json")
    repair = _repair(request, original_response)
    raw = _raw()
    repair_response = _repair_response(repair, raw)

    inspection = inspect_screening_response(
        raw,
        request=request,
        response=repair_response,
        repair_request=repair,
        original_response=original_response,
    )
    assert inspection.payload is not None
    assert inspection.request_id == repair.request_id

    missing_bindings = (
        {"repair_request": None, "original_response": None},
        {"repair_request": repair, "original_response": None},
        {"repair_request": None, "original_response": original_response},
    )
    for bindings in missing_bindings:
        with pytest.raises(ModelParserInputError) as missing:
            inspect_screening_response(
                raw,
                request=request,
                response=repair_response,
                **bindings,  # type: ignore[arg-type]
            )
        assert missing.value.code == ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH

    other_original = _response(request, b"different-invalid-response")
    with pytest.raises(ModelParserInputError) as wrong_original:
        inspect_screening_response(
            raw,
            request=request,
            response=repair_response,
            repair_request=repair,
            original_response=other_original,
        )
    assert wrong_original.value.code == ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH

    other_repair = repair.model_copy(update={"rendered_prompt_sha256": SHA_7})
    with pytest.raises(ModelParserInputError) as wrong_repair:
        inspect_screening_response(
            raw,
            request=request,
            response=repair_response,
            repair_request=other_repair,
            original_response=original_response,
        )
    assert wrong_repair.value.code == ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH

    with pytest.raises(ModelParserInputError) as unexpected_repair_for_first_attempt:
        inspect_screening_response(
            b"not-json",
            request=request,
            response=original_response,
            repair_request=repair,
            original_response=original_response,
        )
    assert (
        unexpected_repair_for_first_attempt.value.code
        == ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH
    )


@given(
    suffix=st.text(
        alphabet=st.characters(
            min_codepoint=33,
            max_codepoint=126,
            blacklist_characters=[" ", "\t", "\r", "\n"],
        ),
        min_size=1,
        max_size=24,
    )
)
def test_any_non_whitespace_tail_is_rejected(suffix: str) -> None:
    inspection = _inspect(_raw() + suffix.encode("ascii"))
    assert inspection.defect_codes == (ProceduralDefectCode.MALFORMED_STRUCTURE,)


@given(unknown_id=st.from_regex(r"[0-9a-f]{64}", fullmatch=True).filter(lambda x: x != SHA_4))
def test_unknown_crop_values_are_stably_hashed_without_echo(unknown_id: str) -> None:
    payload = _payload()
    observations = payload["frame_observations"]
    assert isinstance(observations, list)
    observations[0]["crop_id"] = unknown_id
    raw = _raw(payload)

    first = _inspect(raw)
    second = _inspect(raw)

    assert first.payload is not None
    assert first.unknown_reference_attempts == second.unknown_reference_attempts
    assert len(first.unknown_reference_attempts) == 1
    diagnostic = json.dumps(first.unknown_reference_attempts[0].model_dump(mode="json"))
    assert unknown_id not in diagnostic
