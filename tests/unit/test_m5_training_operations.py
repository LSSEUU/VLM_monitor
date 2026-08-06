from __future__ import annotations

import json

import pytest

from labcourt.application.m5_dataset_retention import m5_dataset_retention_holds
from labcourt.application.m5_training_operations import (
    M5TrainingExportCoordinator,
    M5TrainingExportError,
    M5TrainingExportFailureCode,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    AppealStatus,
    ArtifactKind,
    RetentionHoldKind,
    TrainingLabelQuality,
    VerificationStatus,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_training import CocoDatasetExportCommand, DatasetExportReport
from labcourt.contracts.m5_training_provenance import (
    M5StrongTrainingLabelProvenanceReceipt,
    M5TrainingLabelAuthority,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport
from labcourt.contracts.training import DatasetArtifact, TrainingLabel
from labcourt.ports.evidence_repository import CaseSnapshot
from tests.unit.test_m5_alert_policy import _manifest_with_stream, _ready_case


def _command() -> CocoDatasetExportCommand:
    manifest = _manifest_with_stream()
    return CocoDatasetExportCommand(
        run_id="run-01",
        relative_path="run-01/datasets/reviewed.coco.json",
        detector_manifest_id=manifest.models["detector"].model_manifest_id,
        manifest_id=manifest.manifest_id,
        rule_version=manifest.rule_version,
        purpose="DETECTOR_TRAINING_FROM_REVIEWED_LABELS",
        retention_hold_kind=RetentionHoldKind.GOLD_SET,
        retention_policy_version="m5-gold-set-retention-v1",
        retention_period="UNTIL_EXPLICIT_RELEASE",
    )


def _label(
    label_id: str,
    quality: TrainingLabelQuality,
    *,
    crop_id: str | None = None,
    excluded_reason: str | None = None,
) -> TrainingLabel:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    crop = case.evidence_packs[-1].crops[0]
    bbox = BBoxXYXY(x1=0, y1=0, x2=10, y2=10)
    strong = quality in _SELECTED
    terminal_status = (
        AppealStatus.OVERTURNED
        if quality == TrainingLabelQuality.APPEAL_CONFIRMED
        else AppealStatus.UPHELD
    )
    review_authority_sha256 = sha256_hex(["unit-review", label_id])
    authored_input = M5AppealTrainingLabelInput(
        crop_id=crop_id or crop.crop_id,
        bbox=bbox,
        label_name=f"reviewed-{label_id}",
        label_value=True,
    )
    actual_label_id = (
        sha256_hex(
            [
                "m5-appeal-training-label",
                1,
                review_authority_sha256,
                terminal_status,
                "reviewer-1",
                authored_input.input_id,
            ]
        )
        if strong
        else label_id
    )
    return TrainingLabel(
        label_id=actual_label_id,
        case_id=case.case_id,
        crop_id=crop_id or crop.crop_id,
        bbox=bbox,
        label_name=f"reviewed-{label_id}",
        label_value=True,
        quality=quality,
        source=f"appeal-review:appeal-{label_id}" if strong else "machine-review",
        reviewer_id="reviewer-1" if strong else None,
        rule_version=manifest.rule_version,
        detector_manifest_id=manifest.models["detector"].model_manifest_id,
        excluded_reason=excluded_reason,
    )


def _label_authority(label: TrainingLabel) -> M5TrainingLabelAuthority:
    if label.quality not in _SELECTED:
        return M5TrainingLabelAuthority(label=label)
    alias = label.label_name.removeprefix("reviewed-")
    status = (
        AppealStatus.OVERTURNED
        if label.quality == TrainingLabelQuality.APPEAL_CONFIRMED
        else AppealStatus.UPHELD
    )
    authored_input = M5AppealTrainingLabelInput(
        crop_id=label.crop_id,
        bbox=label.bbox,
        label_name=label.label_name,
        label_value=label.label_value,
    )
    effect_root = sha256_hex(["unit-appeal-effect", alias])
    provenance = M5StrongTrainingLabelProvenanceReceipt(
        run_id="run-01",
        case_id=label.case_id,
        appeal_id=f"appeal-{alias}",
        label_id=label.label_id,
        label_document_sha256=sha256_hex(label.model_dump(mode="json")),
        crop_id=label.crop_id,
        reviewer_id="reviewer-1",
        quality=label.quality,
        authored_input=authored_input,
        review_authority_sha256=sha256_hex(["unit-review", alias]),
        terminal_authority_sha256=sha256_hex(["unit-terminal", alias]),
        terminal_status=status,
        resolution_intent_id=sha256_hex(["unit-intent", alias]),
        resolution_document_sha256=sha256_hex(["unit-intent-document", alias]),
        resolution_commit_receipt_id=sha256_hex(
            ["m5-appeal-resolution-commit-receipt", 1, effect_root]
        ),
        resolution_commit_effect_root_sha256=effect_root,
        manifest_id=_manifest_with_stream().manifest_id,
        rule_version=label.rule_version,
        detector_manifest_id=label.detector_manifest_id,
    )
    return M5TrainingLabelAuthority(label=label, strong_provenance=provenance)


_SELECTED = {
    TrainingLabelQuality.HUMAN_CONFIRMED,
    TrainingLabelQuality.APPEAL_CONFIRMED,
}


def _current_closure(*, include_crop: bool = True) -> ClosureReport:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    pack = case.evidence_packs[-1]
    pack_ref = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    refs = {ref.sort_key: ref for ref in pack.expected_closure_refs()}
    refs[pack_ref.sort_key] = pack_ref
    if not include_crop:
        crop_ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=pack.crops[0].crop_id)
        refs.pop(crop_ref.sort_key)
    return ClosureReport(
        run_id=case.run_id,
        root_ref=pack_ref,
        manifest_id=manifest.manifest_id,
        input_sha256=pack.closure_input_sha256,
        checked_refs=tuple(refs[key] for key in sorted(refs)),
    )


def _verification(
    status: VerificationStatus = VerificationStatus.CURRENT_MEDIA_VERIFIED,
) -> ArtifactVerification:
    manifest = _manifest_with_stream()
    crop = _ready_case(manifest).evidence_packs[-1].crops[0]
    actual_media = (
        crop.media_sha256 if status == VerificationStatus.CURRENT_MEDIA_VERIFIED else "0" * 64
    )
    return ArtifactVerification(
        artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
        status=status,
        availability=crop.availability,
        media_type=crop.media_type,
        expected_source_pixel_sha256=crop.source_media_sha256,
        expected_output_pixel_sha256=crop.pixel_sha256,
        actual_output_pixel_sha256=crop.pixel_sha256,
        expected_media_sha256=crop.media_sha256,
        actual_media_sha256=actual_media,
        expected_width=crop.output_width,
        actual_width=crop.output_width,
        expected_height=crop.output_height,
        actual_height=crop.output_height,
        expected_size_bytes=crop.size_bytes,
        actual_size_bytes=crop.size_bytes,
    )


class _Repository:
    def __init__(self, labels: tuple[TrainingLabel, ...]) -> None:
        self.labels = labels
        self.calls: list[tuple[str, int]] = []

    def list_training_label_authorities(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[M5TrainingLabelAuthority, ...]:
        self.calls.append((run_id, limit))
        return tuple(_label_authority(label) for label in self.labels)

    def register_dataset_artifact(
        self,
        report: DatasetExportReport,
        content: bytes,
    ) -> DatasetArtifact:
        del content
        return report.dataset


class _Evidence:
    def __init__(
        self,
        *,
        closure: ClosureReport | None = None,
        changed: bool = False,
    ) -> None:
        case = _ready_case(_manifest_with_stream())
        self.before = CaseSnapshot(case=case, revision=4)
        self.after = CaseSnapshot(case=case, revision=5 if changed else 4)
        self.closure = closure or _current_closure()
        self.load_calls: list[tuple[str, str]] = []
        self.verify_calls: list[tuple[str, str]] = []

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot:
        self.load_calls.append((run_id, case_id))
        return self.before if len(self.load_calls) == 1 else self.after

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport:
        self.verify_calls.append((run_id, pack_id))
        return self.closure


class _CropVerifier:
    def __init__(self, verification: ArtifactVerification | None = None) -> None:
        self.verification = verification or _verification()
        self.calls: list[str] = []

    def verify_crop(self, crop: object) -> ArtifactVerification:
        self.calls.append(crop.crop_id)  # type: ignore[attr-defined]
        return self.verification


class _Publisher:
    def __init__(self, *, wrong_result: bool = False) -> None:
        self.wrong_result = wrong_result
        self.calls: list[tuple[DatasetExportReport, bytes]] = []

    def publish(self, report: DatasetExportReport, content: bytes) -> DatasetArtifact:
        self.calls.append((report, content))
        if self.wrong_result:
            return report.dataset.model_copy(update={"dataset_id": "another-dataset"})
        return report.dataset


def _coordinator(
    labels: tuple[TrainingLabel, ...],
    *,
    evidence: _Evidence | None = None,
    verifier: _CropVerifier | None = None,
    publisher: _Publisher | None = None,
) -> tuple[M5TrainingExportCoordinator, _Repository, _Evidence, _CropVerifier, _Publisher]:
    repository = _Repository(labels)
    actual_evidence = evidence or _Evidence()
    actual_verifier = verifier or _CropVerifier()
    actual_publisher = publisher or _Publisher()
    coordinator = M5TrainingExportCoordinator(
        repository=repository,
        evidence=actual_evidence,
        crop_verifier=actual_verifier,
        publisher=actual_publisher,
        manifest=_manifest_with_stream(),
    )
    return coordinator, repository, actual_evidence, actual_verifier, actual_publisher


def test_export_reads_complete_inventory_but_verifies_only_human_selected_crop() -> None:
    weak = _label("weak-1", TrainingLabelQuality.WEAK_AUTO)
    human = _label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED)
    appeal = _label("appeal-1", TrainingLabelQuality.APPEAL_CONFIRMED)
    consensus = _label("consensus-1", TrainingLabelQuality.CONSENSUS_REVIEWED)
    excluded = _label(
        "excluded-1",
        TrainingLabelQuality.WEAK_AUTO,
        excluded_reason="privacy-review-pending",
    )
    labels = tuple(
        sorted(
            (weak, human, appeal, consensus, excluded),
            key=lambda item: item.label_id,
        )
    )
    coordinator, repository, evidence, verifier, publisher = _coordinator(labels)

    report = coordinator.export(_command())

    assert repository.calls == [("run-01", 10_000)]
    assert report.input_label_count == 5
    expected_exported = tuple(sorted((appeal.label_id, human.label_id)))
    expected_quarantined = tuple(sorted((consensus.label_id, excluded.label_id, weak.label_id)))
    assert report.exported_label_ids == expected_exported
    assert report.quarantined_label_ids == expected_quarantined
    assert report.weak_auto_count == 2
    assert report.consensus_reviewed_count == 1
    assert report.excluded_reason_count == 1
    assert len(evidence.load_calls) == 2
    assert len(evidence.verify_calls) == 1
    assert len(verifier.calls) == 1
    assert len(publisher.calls) == 1
    holds = m5_dataset_retention_holds(report)
    assert len(holds) == 1
    assert holds[0].target_ref.ref.kind == ArtifactKind.CROP
    assert holds[0].target_ref.ref.artifact_id == report.crop_receipts[0].crop_id
    assert holds[0].owner_ref.ref.kind == ArtifactKind.DATASET
    assert holds[0].owner_ref.ref.artifact_id == report.dataset.dataset_id
    assert holds[0].policy_version == "m5-gold-set-retention-v1"
    assert m5_dataset_retention_holds(report) == holds
    payload = json.loads(publisher.calls[0][1])
    assert payload["labcourt"]["purpose"] == "DETECTOR_TRAINING_FROM_REVIEWED_LABELS"
    assert payload["labcourt"]["retention_hold_kind"] == "GOLD_SET"
    assert payload["labcourt"]["retention_policy_version"] == "m5-gold-set-retention-v1"
    assert payload["labcourt"]["retention_period"] == "UNTIL_EXPLICIT_RELEASE"
    assert [item["labcourt_label_id"] for item in payload["annotations"]] == list(expected_exported)


def test_weak_only_inventory_never_loads_or_verifies_media() -> None:
    label = _label(
        "weak-1",
        TrainingLabelQuality.WEAK_AUTO,
        crop_id="0" * 64,
    )
    coordinator, _, evidence, verifier, _ = _coordinator((label,))

    report = coordinator.export(_command())

    assert report.exported_label_ids == ()
    assert report.quarantined_label_ids == ("weak-1",)
    assert evidence.load_calls == []
    assert evidence.verify_calls == []
    assert verifier.calls == []


@pytest.mark.parametrize(
    ("coordinator_factory", "expected_code"),
    [
        (
            lambda: _coordinator(
                (
                    _label(
                        "human-1",
                        TrainingLabelQuality.HUMAN_CONFIRMED,
                        crop_id="0" * 64,
                    ),
                )
            )[0],
            M5TrainingExportFailureCode.LABEL_CROP_NOT_IN_LATEST_PACK,
        ),
        (
            lambda: _coordinator(
                (_label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED),),
                evidence=_Evidence(closure=_current_closure(include_crop=False)),
            )[0],
            M5TrainingExportFailureCode.CURRENT_PACK_CROP_NOT_CHECKED,
        ),
        (
            lambda: _coordinator(
                (_label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED),),
                verifier=_CropVerifier(_verification(VerificationStatus.MEDIA_HASH_MISMATCH)),
            )[0],
            M5TrainingExportFailureCode.CROP_VERIFICATION_FAILED,
        ),
        (
            lambda: _coordinator(
                (_label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED),),
                evidence=_Evidence(changed=True),
            )[0],
            M5TrainingExportFailureCode.CASE_CHANGED_DURING_EXPORT,
        ),
        (
            lambda: _coordinator(
                (_label("human-1", TrainingLabelQuality.HUMAN_CONFIRMED),),
                publisher=_Publisher(wrong_result=True),
            )[0],
            M5TrainingExportFailureCode.PUBLISH_RESULT_MISMATCH,
        ),
    ],
)
def test_export_fails_closed_on_authority_or_publication_drift(
    coordinator_factory: object,
    expected_code: M5TrainingExportFailureCode,
) -> None:
    coordinator = coordinator_factory()  # type: ignore[operator]
    with pytest.raises(M5TrainingExportError) as failure:
        coordinator.export(_command())
    assert failure.value.code == expected_code


def test_command_must_match_loaded_manifest_authority() -> None:
    coordinator, *_ = _coordinator(())
    command = _command().model_copy(update={"manifest_id": "0" * 64})

    with pytest.raises(M5TrainingExportError) as failure:
        coordinator.export(command)

    assert failure.value.code == M5TrainingExportFailureCode.MANIFEST_SCOPE_MISMATCH
