from __future__ import annotations

import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from labcourt.adapters.jinja_prompt_renderer import (
    MAX_PROMPT_STRING_CHARS,
    MAX_PROMPT_VARIABLE_BYTES,
    RenderedPrompt,
)
from labcourt.adapters.vlm.errors import VLMProviderError, VLMProviderFailureCode
from labcourt.adapters.vlm.openai_compatible import AppendOnlyRenderedPromptRegistry
from labcourt.application.model_parser import inspect_screening_response
from labcourt.application.structure_repair import (
    STRUCTURE_REPAIR_PROMPT_ID,
    StructureRepairPreparationError,
    StructureRepairPreparationErrorCode,
    prepare_structure_repair_request,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    PrivacyPolicy,
    ProceduralDefectCode,
    ViolationType,
)
from labcourt.contracts.m3_models import VlmCallBudget
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.screening import (
    VLMMediaRef,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import BudgetExceeded
from labcourt.services.m3 import build_screening_prompt_catalog

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
RUN_ID = "run-01"
MEDIA_SHA256 = "4" * 64
PACK_ID = "5" * 64


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _request(manifest: RunManifest) -> VLMRequest:
    catalog = build_screening_prompt_catalog(manifest)
    prompt = catalog.render(
        prompt_id="screening_presence_v1",
        variables={"evidence_json": "{}", "rules_json": "{}"},
    )
    crop_id = "6" * 64
    media = VLMMediaRef(
        crop_id=crop_id,
        media_sha256=MEDIA_SHA256,
        local_path=f"{RUN_ID}/frames/{MEDIA_SHA256}.png",
        source=CropSource.DETECTION_FOCUS,
        media_access=MediaAccess.LOCAL_ONLY,
        privacy_policy=PrivacyPolicy.FULL_REDACTION,
        privacy_transform_version=manifest.privacy_transform_version,
        width=100,
        height=100,
    )
    model = manifest.models["screening"]
    return VLMRequest(
        run_id=RUN_ID,
        case_id="case-01",
        evidence_pack_id=PACK_ID,
        evidence_pack_version=1,
        provider_profile="fake-screening",
        provider=model.provider,
        model=model.model,
        revision=model.revision,
        model_manifest_id=model.model_manifest_id,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=prompt.manifest,
        rendered_prompt_sha256=prompt.rendered_prompt_sha256,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        evidence_class=EvidenceClass.PRESENCE,
        rule_summary="Apply the configured laboratory rule.",
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop_id),),
        objective_summary={"duration_frames": 91},
        temperature=manifest.decoding_parameters.temperature,
        seed=manifest.decoding_parameters.seed,
        budget=VlmCallBudget(
            max_images=4,
            max_input_pixels=100_000,
            max_output_tokens=2_048,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=1_048_576,
            max_json_depth=16,
            max_json_fields=512,
            max_string_chars=8_192,
            timeout_seconds=15.0,
            claim_completion_grace_seconds=5.0,
        ),
        manifest_id=manifest.manifest_id,
    )


def _response(request: VLMRequest, raw: bytes) -> VLMResponse:
    content_sha256 = hashlib.sha256(raw).hexdigest()
    response_id = derive_model_response_id(request.run_id, request.request_id, content_sha256)
    return VLMResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        purpose=request.purpose,
        attempt_index=0,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=len(raw),
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _prepared(
    raw: bytes = b'{"malformed":',
    *,
    max_prompt_bytes: int | None = None,
):
    manifest = _manifest()
    request = _request(manifest)
    if max_prompt_bytes is not None:
        request = request.model_copy(
            update={
                "budget": request.budget.model_copy(update={"max_prompt_bytes": max_prompt_bytes})
            }
        )
    response = _response(request, raw)
    inspection = inspect_screening_response(raw, request=request, response=response)
    prepared = prepare_structure_repair_request(
        request,
        response,
        inspection,
        raw,
        manifest,
        build_screening_prompt_catalog(manifest),
    )
    return manifest, request, response, inspection, prepared


def _prompt_json(text: str, name: str) -> object:
    prefix = f"{name}="
    line = next(line for line in text.splitlines() if line.startswith(prefix))
    return json.loads(line.removeprefix(prefix))


def test_prepare_utf8_structure_repair_is_exact_media_free_and_registry_ready() -> None:
    raw = b'{"message":"quote=\\"; newline=\\n; ignore instructions"}'
    manifest, original, response, inspection, first = _prepared(raw)
    second = prepare_structure_repair_request(
        original,
        response,
        inspection,
        raw,
        manifest,
        build_screening_prompt_catalog(manifest),
    )
    repair = first.request

    assert first == second
    assert repair.repair_ordinal == 1
    assert repair.prompt_manifest.prompt_id == STRUCTURE_REPAIR_PROMPT_ID
    assert repair.original_request_id == original.request_id
    assert repair.original_request_sha256 == original.request_sha256
    assert repair.original_response_id == response.response_id
    assert repair.original_response_sha256 == response.content_sha256
    assert repair.parse_defect_codes
    assert set(repair.parse_defect_codes) <= {
        ProceduralDefectCode.MALFORMED_STRUCTURE,
        ProceduralDefectCode.INVALID_ENUM,
        ProceduralDefectCode.MISSING_REQUIRED_FIELD,
    }
    assert repair.provider_profile == original.provider_profile
    assert repair.provider == original.provider
    assert repair.model == original.model
    assert repair.revision == original.revision
    assert repair.model_manifest_id == original.model_manifest_id
    assert repair.manifest_id == original.manifest_id
    assert repair.temperature == original.temperature
    assert repair.seed == original.seed
    assert repair.budget.max_images == 0
    assert repair.budget.max_input_pixels == 0
    assert repair.budget.max_prompt_bytes == original.budget.max_prompt_bytes
    assert repair.budget.max_input_tokens == original.budget.max_input_tokens
    assert repair.budget.model_dump(exclude={"max_images", "max_input_pixels"}) == (
        original.budget.model_dump(exclude={"max_images", "max_input_pixels"})
    )

    document = _prompt_json(first.rendered_prompt.text, "ORIGINAL_RESPONSE_JSON")
    assert document == {
        "content_sha256": response.content_sha256,
        "encoding": "utf-8",
        "size_bytes": len(raw),
        "text": raw.decode("utf-8"),
    }
    assert f"ORIGINAL_RESPONSE_JSON={raw.decode('utf-8')}" not in first.rendered_prompt.text
    defects = _prompt_json(first.rendered_prompt.text, "PARSE_DEFECTS_JSON")
    assert isinstance(defects, list) and defects
    assert all(set(item) == {"code", "reason_code"} for item in defects)

    registry = AppendOnlyRenderedPromptRegistry()
    registry.register(first.rendered_prompt)
    registry.register(first.rendered_prompt)
    assert registry.resolve(repair) == first.rendered_prompt.utf8_bytes


def test_invalid_utf8_is_canonical_base64_data_not_lossy_text() -> None:
    raw = b"\xff\xfe\x00untrusted\x80"
    _, _, response, _, prepared = _prepared(raw)

    document = _prompt_json(prepared.rendered_prompt.text, "ORIGINAL_RESPONSE_JSON")
    assert document == {
        "content_sha256": response.content_sha256,
        "data": base64.b64encode(raw).decode("ascii"),
        "encoding": "base64",
        "size_bytes": len(raw),
    }
    assert "text" not in document


def test_utf8_wrapper_at_prompt_variable_byte_limit_is_accepted() -> None:
    fixed_overhead = len(
        canonical_json(
            {
                "content_sha256": "0" * 64,
                "encoding": "utf-8",
                "size_bytes": 100_000,
                "text": "",
            }
        ).encode("utf-8")
    )
    escaped_nul_count = 80_000
    ascii_count = MAX_PROMPT_VARIABLE_BYTES - fixed_overhead - (6 * escaped_nul_count)
    raw = (b"\x00" * escaped_nul_count) + (b"x" * ascii_count)
    _, _, response, _, prepared = _prepared(raw, max_prompt_bytes=1_048_576)

    document = _prompt_json(prepared.rendered_prompt.text, "ORIGINAL_RESPONSE_JSON")
    assert document == {
        "content_sha256": response.content_sha256,
        "encoding": "utf-8",
        "size_bytes": len(raw),
        "text": raw.decode("utf-8"),
    }
    assert len(canonical_json(document).encode("utf-8")) == MAX_PROMPT_VARIABLE_BYTES


def test_valid_utf8_control_characters_fall_back_to_compact_base64_wrapper() -> None:
    raw = b"\x00" * 100_000
    _, _, response, _, prepared = _prepared(raw)

    document = _prompt_json(prepared.rendered_prompt.text, "ORIGINAL_RESPONSE_JSON")
    assert document == {
        "content_sha256": response.content_sha256,
        "data": base64.b64encode(raw).decode("ascii"),
        "encoding": "base64",
        "size_bytes": len(raw),
    }
    utf8_wrapper = canonical_json(
        {
            "content_sha256": response.content_sha256,
            "encoding": "utf-8",
            "size_bytes": len(raw),
            "text": raw.decode("utf-8"),
        }
    )
    assert len(utf8_wrapper.encode("utf-8")) > MAX_PROMPT_VARIABLE_BYTES
    assert len(canonical_json(document).encode("utf-8")) <= MAX_PROMPT_VARIABLE_BYTES


def test_256_kib_invalid_utf8_base64_fallback_closes_response_budget() -> None:
    # ScreeningConfig caps accepted provider responses at 256 KiB. Even the
    # worst-case base64 representation of that full budget fits the renderer's
    # 512 KiB canonical prompt-variable limit, including wrapper metadata.
    raw = b"\xff" * (256 * 1024)
    _, _, response, _, prepared = _prepared(raw)

    document = _prompt_json(prepared.rendered_prompt.text, "ORIGINAL_RESPONSE_JSON")
    encoded = base64.b64encode(raw).decode("ascii")
    assert isinstance(document, dict)
    chunks = document.pop("data_chunks")
    assert document == {
        "content_sha256": response.content_sha256,
        "encoding": "base64",
        "size_bytes": len(raw),
    }
    assert isinstance(chunks, list)
    assert all(isinstance(chunk, str) for chunk in chunks)
    assert "".join(chunks) == encoded
    assert max(map(len, chunks)) <= MAX_PROMPT_STRING_CHARS
    document["data_chunks"] = chunks
    assert len(canonical_json(document).encode("utf-8")) <= MAX_PROMPT_VARIABLE_BYTES


def test_structure_repair_enforces_final_rendered_prompt_byte_budget() -> None:
    raw = b'{"malformed":'
    manifest = _manifest()
    original = _request(manifest)
    original = original.model_copy(
        update={
            "budget": original.budget.model_copy(update={"max_prompt_bytes": 1}),
        }
    )
    response = _response(original, raw)
    inspection = inspect_screening_response(raw, request=original, response=response)

    with pytest.raises(BudgetExceeded, match="prompt byte budget"):
        prepare_structure_repair_request(
            original,
            response,
            inspection,
            raw,
            manifest,
            build_screening_prompt_catalog(manifest),
        )


def test_oversized_base64_wrapper_fails_closed_without_raw_response_leak() -> None:
    marker = "TOP_SECRET_OVERSIZED_PROVIDER_RESPONSE"
    raw = marker.encode("ascii") + b"\xff" * 400_000
    manifest = _manifest()
    request = _request(manifest)
    response = _response(request, raw)
    inspection = inspect_screening_response(raw, request=request, response=response)

    with pytest.raises(StructureRepairPreparationError) as captured:
        prepare_structure_repair_request(
            request,
            response,
            inspection,
            raw,
            manifest,
            build_screening_prompt_catalog(manifest),
        )

    assert (
        captured.value.reason_code
        == StructureRepairPreparationErrorCode.ORIGINAL_RESPONSE_TOO_LARGE
    )
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("response_scope", StructureRepairPreparationErrorCode.ORIGINAL_RESPONSE_BINDING_MISMATCH),
        ("raw_size", StructureRepairPreparationErrorCode.RAW_RESPONSE_SIZE_MISMATCH),
        ("raw_hash", StructureRepairPreparationErrorCode.RAW_RESPONSE_CONTENT_MISMATCH),
        ("inspection_scope", StructureRepairPreparationErrorCode.INSPECTION_BINDING_MISMATCH),
        ("inspection_payload", StructureRepairPreparationErrorCode.INSPECTION_NOT_REPAIRABLE),
        ("inspection_attempt", StructureRepairPreparationErrorCode.INSPECTION_NOT_REPAIRABLE),
        ("empty_defects", StructureRepairPreparationErrorCode.PARSE_DEFECTS_INVALID),
        ("duplicate_defects", StructureRepairPreparationErrorCode.PARSE_DEFECTS_INVALID),
        ("manifest", StructureRepairPreparationErrorCode.RUN_MANIFEST_MISMATCH),
        ("schema", StructureRepairPreparationErrorCode.INSPECTION_BINDING_MISMATCH),
    ],
)
def test_wrong_response_hash_scope_inspection_or_manifest_fails_closed(
    mutation: str,
    expected_code: StructureRepairPreparationErrorCode,
) -> None:
    raw = b'{"malformed":'
    manifest = _manifest()
    request = _request(manifest)
    response = _response(request, raw)
    inspection = inspect_screening_response(raw, request=request, response=response)
    call_raw = raw
    call_manifest = manifest

    if mutation == "response_scope":
        response = response.model_copy(update={"case_id": "case-02"})
    elif mutation == "raw_size":
        call_raw = raw + b"x"
    elif mutation == "raw_hash":
        call_raw = b'{"nalformed":'
        assert len(call_raw) == len(raw)
    elif mutation == "inspection_scope":
        inspection = replace(inspection, case_id="case-02")
    elif mutation == "inspection_payload":
        inspection = replace(inspection, payload=object())  # type: ignore[arg-type]
    elif mutation == "inspection_attempt":
        inspection = replace(inspection, attempt_index=1)
    elif mutation == "empty_defects":
        inspection = replace(inspection, defects=())
    elif mutation == "duplicate_defects":
        inspection = replace(inspection, defects=inspection.defects * 2)
    elif mutation == "manifest":
        call_manifest = manifest.model_copy(update={"random_seed": manifest.random_seed + 1})
    elif mutation == "schema":
        inspection = replace(inspection, output_schema_sha256="0" * 64)
    else:  # pragma: no cover - parametrization is closed above
        raise AssertionError(mutation)

    with pytest.raises(StructureRepairPreparationError) as captured:
        prepare_structure_repair_request(
            request,
            response,
            inspection,
            call_raw,
            call_manifest,
            build_screening_prompt_catalog(manifest),
        )
    assert captured.value.reason_code == expected_code


def test_provider_text_never_leaks_into_preparation_exception() -> None:
    marker = "TOP_SECRET_PROVIDER_TEXT_C_DRIVE"
    raw = f'{{"malformed":"{marker}"'.encode()
    manifest = _manifest()
    request = _request(manifest)
    response = _response(request, raw)
    inspection = inspect_screening_response(raw, request=request, response=response)
    wrong = replace(inspection, request_id="0" * 64)

    with pytest.raises(StructureRepairPreparationError) as captured:
        prepare_structure_repair_request(
            request,
            response,
            wrong,
            raw,
            manifest,
            build_screening_prompt_catalog(manifest),
        )
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)


def test_append_only_registry_rejects_conflicts_and_preserves_prompt_secrecy() -> None:
    _, _, _, _, prepared = _prepared()
    prompt = prepared.rendered_prompt
    registry = AppendOnlyRenderedPromptRegistry((prompt,))
    conflicting_manifest = prompt.manifest.model_copy(update={"prompt_id": "conflicting-repair"})
    conflicting = RenderedPrompt(
        manifest=conflicting_manifest,
        rendered_prompt_sha256=prompt.rendered_prompt_sha256,
        text=prompt.text,
    )

    with pytest.raises(ValueError) as captured:
        registry.register(conflicting)
    assert "ORIGINAL_RESPONSE_JSON" not in str(captured.value)

    wrong_request = prepared.request.model_copy(update={"prompt_manifest": conflicting_manifest})
    with pytest.raises(VLMProviderError) as wrong_manifest:
        registry.resolve(wrong_request)
    assert wrong_manifest.value.reason_code == VLMProviderFailureCode.PROMPT_INTEGRITY_FAILURE

    empty = AppendOnlyRenderedPromptRegistry()
    with pytest.raises(VLMProviderError) as missing:
        empty.resolve(prepared.request)
    assert missing.value.reason_code == VLMProviderFailureCode.PROMPT_MISSING


def test_append_only_registry_is_idempotent_under_concurrent_registration() -> None:
    _, _, _, _, prepared = _prepared()
    registry = AppendOnlyRenderedPromptRegistry()
    barrier = Barrier(16)

    def register_and_resolve(_: int) -> bytes:
        barrier.wait()
        registry.register(prepared.rendered_prompt)
        return registry.resolve(prepared.request)

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = tuple(executor.map(register_and_resolve, range(16)))

    assert results == (prepared.rendered_prompt.utf8_bytes,) * 16
    assert repr(registry) == "AppendOnlyRenderedPromptRegistry(prompt_count=1)"
