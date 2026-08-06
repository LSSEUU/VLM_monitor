from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    MediaType,
    VerificationStatus,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.m6_source_authority import (
    M6GateCurrentClosureBasis,
    M6GateCurrentClosureReceipt,
    M6ReplayInputAuthority,
)
from labcourt.contracts.storage import (
    ArtifactRef,
    ArtifactVerification,
    ClosureReport,
)
from labcourt.schema_export import expected_schema_files


def _sha(character: str) -> str:
    return character * 64


def _crop_verification() -> ArtifactVerification:
    return ArtifactVerification(
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=_sha("c")),
        status=VerificationStatus.CURRENT_MEDIA_VERIFIED,
        availability=MediaAvailability.AVAILABLE,
        media_type=MediaType.IMAGE_PNG,
        expected_source_pixel_sha256=_sha("1"),
        expected_output_pixel_sha256=_sha("2"),
        actual_output_pixel_sha256=_sha("2"),
        expected_media_sha256=_sha("3"),
        actual_media_sha256=_sha("3"),
        expected_width=32,
        actual_width=32,
        expected_height=24,
        actual_height=24,
        expected_size_bytes=128,
        actual_size_bytes=128,
    )


def _current_closure(*, with_crop: bool = False) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=_sha("a"))
    checked = [root]
    if with_crop:
        checked.append(_crop_verification().artifact_ref)
    return ClosureReport(
        run_id="run-source",
        root_ref=root,
        manifest_id=_sha("b"),
        input_sha256=_sha("4"),
        checked_refs=tuple(sorted(checked, key=lambda item: item.sort_key)),
    )


def _receipt(*, with_crop: bool = False) -> M6GateCurrentClosureReceipt:
    return M6GateCurrentClosureReceipt(
        run_id="run-source",
        case_id="case-source",
        manifest_id=_sha("b"),
        review_version=1,
        source_review_id=_sha("5"),
        source_review_document_sha256=_sha("6"),
        evidence_pack_id=_sha("a"),
        evidence_pack_version=1,
        evidence_pack_document_sha256=_sha("7"),
        basis=(
            M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED
            if with_crop
            else M6GateCurrentClosureBasis.SEMANTIC_ONLY_NO_CROPS
        ),
        current_closure=_current_closure(with_crop=with_crop),
        crop_verifications=(_crop_verification(),) if with_crop else (),
    )


def _base_closure() -> M6ReplayInputClosureAuthority:
    return M6ReplayInputClosureAuthority(
        sample_id="sample-source",
        source_run_id="run-source",
        source_case_id="case-source",
        source_case_revision=1,
        source_case_document_sha256=_sha("8"),
        source_manifest_id=_sha("b"),
        source_manifest_document_sha256=_sha("9"),
        input_authority_id=_sha("0"),
        input_authority_document_sha256=_sha("1"),
        source_validation_report_id=_sha("2"),
        source_validation_report_document_sha256=_sha("3"),
        frames=(
            M6LockedFrameInput(
                frame_id="camera-01:stream-01:1",
                document_sha256=_sha("4"),
                content_sha256=_sha("5"),
            ),
        ),
    )


def _authority(*, receipts: tuple[M6GateCurrentClosureReceipt, ...] | None = None):
    closure = _base_closure()
    return M6ReplayInputAuthority(
        sample_id=closure.sample_id,
        source_run_id=closure.source_run_id,
        source_case_id=closure.source_case_id or "",
        source_case_revision=closure.source_case_revision or 0,
        source_case_document_sha256=closure.source_case_document_sha256 or "",
        source_manifest_id=closure.source_manifest_id,
        source_manifest_document_sha256=closure.source_manifest_document_sha256,
        source_config_sha256=_sha("d"),
        source_m4_authority_root_sha256=_sha("e"),
        source_m5_authority_root_sha256=_sha("a"),
        source_validation_report_id=closure.source_validation_report_id,
        source_validation_report_document_sha256=(closure.source_validation_report_document_sha256),
        frame_inventory_root_sha256=closure.frame_inventory_root_sha256,
        detection_inventory_root_sha256=closure.detection_inventory_root_sha256,
        model_call_inventory_root_sha256=closure.model_call_inventory_root_sha256,
        embedding_inventory_root_sha256=closure.embedding_inventory_root_sha256,
        tool_result_inventory_root_sha256=closure.tool_result_inventory_root_sha256,
        historical_causal_cut_id=closure.historical_cut.causal_cut_id,
        gate_current_closures=(_receipt(),) if receipts is None else receipts,
    )


def test_replay_input_authority_round_trips_and_closes_existing_reference() -> None:
    authority = _authority()
    base = _base_closure()
    closure = M6ReplayInputClosureAuthority.model_validate(
        {
            **base.model_dump(mode="json", exclude_computed_fields=True),
            "input_authority_id": authority.input_authority_id,
            "input_authority_document_sha256": authority.input_authority_document_sha256,
        }
    )

    assert M6ReplayInputAuthority.model_validate(authority.model_dump(mode="json")) == authority
    assert closure.input_authority_id == authority.input_authority_id
    assert closure.input_authority_document_sha256 == authority.input_authority_document_sha256
    assert authority.gate_current_closure_count == 1


@pytest.mark.parametrize(
    "field",
    (
        "gate_current_closure_count",
        "gate_current_closure_inventory_root_sha256",
        "input_authority_id",
        "input_authority_document_sha256",
    ),
)
def test_replay_input_authority_rejects_forged_derived_claim(field: str) -> None:
    payload = _authority().model_dump(mode="json")
    payload[field] = 2 if field.endswith("count") else _sha("f")

    with pytest.raises(ValidationError):
        M6ReplayInputAuthority.model_validate(payload)


def test_gate_receipt_requires_pack_root_and_honest_media_basis() -> None:
    semantic = _receipt()
    payload = semantic.model_dump(mode="json", exclude_computed_fields=True)
    payload["current_closure"]["root_ref"] = {
        "kind": ArtifactKind.CASE.value,
        "artifact_id": "case-source",
    }
    payload["current_closure"]["checked_refs"] = [payload["current_closure"]["root_ref"]]
    with pytest.raises(ValidationError):
        M6GateCurrentClosureReceipt.model_validate(payload)

    payload = semantic.model_dump(mode="json", exclude_computed_fields=True)
    payload["basis"] = M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED.value
    with pytest.raises(ValidationError):
        M6GateCurrentClosureReceipt.model_validate(payload)

    with pytest.raises(ValidationError):
        M6GateCurrentClosureReceipt.model_validate(
            {
                **_receipt(with_crop=True).model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                ),
                "basis": M6GateCurrentClosureBasis.SEMANTIC_ONLY_NO_CROPS.value,
            }
        )


def test_input_authority_rejects_duplicate_or_foreign_review_receipts() -> None:
    receipt = _receipt()
    with pytest.raises(ValidationError):
        M6ReplayInputAuthority.model_validate(
            {
                **_authority(receipts=()).model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                ),
                "gate_current_closures": [
                    receipt.model_dump(mode="json"),
                    receipt.model_dump(mode="json"),
                ],
            }
        )
    foreign = M6GateCurrentClosureReceipt.model_validate(
        {
            **receipt.model_dump(mode="json", exclude_computed_fields=True),
            "case_id": "case-foreign",
        }
    )
    with pytest.raises(ValidationError):
        _authority(receipts=(foreign,))


def test_public_m6_replay_input_authority_schema_validates_document() -> None:
    schema = json.loads(expected_schema_files()["m6-replay-input-authority.schema.json"])
    Draft202012Validator(schema).validate(_authority().model_dump(mode="json"))
