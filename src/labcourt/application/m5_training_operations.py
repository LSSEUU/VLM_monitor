"""Trusted, bounded orchestration for reviewed-label COCO publication."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from pydantic import ValidationError

from labcourt.application.dataset_export import build_coco_dataset
from labcourt.contracts.enums import ArtifactKind, TrainingLabelQuality, VerificationStatus
from labcourt.contracts.m5_training import (
    CocoDatasetExportCommand,
    DatasetExportReport,
    TrainingCropAuthority,
)
from labcourt.contracts.m5_training_provenance import M5TrainingLabelAuthority
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport
from labcourt.contracts.training import DatasetArtifact, TrainingLabel
from labcourt.exceptions import LabCourtError
from labcourt.ports.dataset_export import (
    DatasetArtifactPublisher,
    M5TrainingCropVerifier,
    TrainingDatasetRepository,
)
from labcourt.ports.evidence_repository import CaseSnapshot


class M5TrainingExportFailureCode(StrEnum):
    """Fail-closed reasons owned by the training-export operation boundary."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    CONFIG_MANIFEST_MISMATCH = "CONFIG_MANIFEST_MISMATCH"
    UNSAFE_TRAINING_POLICY = "UNSAFE_TRAINING_POLICY"
    PATH_SCOPE_MISMATCH = "PATH_SCOPE_MISMATCH"
    MANIFEST_SCOPE_MISMATCH = "MANIFEST_SCOPE_MISMATCH"
    LABEL_AUTHORITY_MISMATCH = "LABEL_AUTHORITY_MISMATCH"
    CASE_AUTHORITY_MISMATCH = "CASE_AUTHORITY_MISMATCH"
    LATEST_EVIDENCE_PACK_MISSING = "LATEST_EVIDENCE_PACK_MISSING"
    LATEST_EVIDENCE_PACK_INCOMPLETE = "LATEST_EVIDENCE_PACK_INCOMPLETE"
    LABEL_CROP_NOT_IN_LATEST_PACK = "LABEL_CROP_NOT_IN_LATEST_PACK"
    CROP_SCOPE_CONFLICT = "CROP_SCOPE_CONFLICT"
    CURRENT_PACK_AUTHORITY_MISMATCH = "CURRENT_PACK_AUTHORITY_MISMATCH"
    CURRENT_PACK_VERIFICATION_FAILED = "CURRENT_PACK_VERIFICATION_FAILED"
    CURRENT_PACK_CROP_NOT_CHECKED = "CURRENT_PACK_CROP_NOT_CHECKED"
    CROP_VERIFICATION_FAILED = "CROP_VERIFICATION_FAILED"
    CASE_CHANGED_DURING_EXPORT = "CASE_CHANGED_DURING_EXPORT"
    PUBLISH_RESULT_MISMATCH = "PUBLISH_RESULT_MISMATCH"
    REGISTERED_DATASET_REPLAY_FAILED = "REGISTERED_DATASET_REPLAY_FAILED"


class M5TrainingExportError(LabCourtError):
    """A typed authority or integrity failure during one training export."""

    def __init__(self, code: M5TrainingExportFailureCode) -> None:
        if not isinstance(code, M5TrainingExportFailureCode):
            raise TypeError("code must be an M5TrainingExportFailureCode")
        self.code = code
        super().__init__(f"M5 training export failed: {code.value}")


class M5TrainingEvidenceReader(Protocol):
    """Narrow evidence authority needed by training export."""

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot: ...

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport: ...


_SELECTED_QUALITIES = {
    TrainingLabelQuality.HUMAN_CONFIRMED,
    TrainingLabelQuality.APPEAL_CONFIRMED,
}


def _selected_labels(labels: tuple[TrainingLabel, ...]) -> tuple[TrainingLabel, ...]:
    return tuple(
        sorted(
            (
                label
                for label in labels
                if label.quality in _SELECTED_QUALITIES and label.excluded_reason is None
            ),
            key=lambda item: item.label_id,
        )
    )


def _labels_from_authorities(
    authorities: tuple[M5TrainingLabelAuthority, ...],
) -> tuple[TrainingLabel, ...]:
    validated: list[M5TrainingLabelAuthority] = []
    try:
        for item in authorities:
            if not isinstance(item, M5TrainingLabelAuthority):
                raise TypeError("training label authority has another type")
            rebuilt = M5TrainingLabelAuthority.model_validate(
                item.model_dump(
                    mode="python",
                    exclude_computed_fields=True,
                    round_trip=True,
                )
            )
            if rebuilt != item:
                raise ValueError("training label authority changed during validation")
            validated.append(rebuilt)
    except (AttributeError, TypeError, ValueError) as exc:
        raise M5TrainingExportError(M5TrainingExportFailureCode.LABEL_AUTHORITY_MISMATCH) from exc
    labels = tuple(item.label for item in validated)
    authority_ids = tuple(item.authority_sha256 for item in validated)
    if tuple(label.label_id for label in labels) != tuple(
        sorted(label.label_id for label in labels)
    ) or len(authority_ids) != len(set(authority_ids)):
        raise M5TrainingExportError(M5TrainingExportFailureCode.LABEL_AUTHORITY_MISMATCH)
    return labels


def _require_manifest_scope(
    command: CocoDatasetExportCommand,
    manifest: RunManifest,
) -> None:
    detector = manifest.models.get("detector")
    if (
        detector is None
        or command.manifest_id != manifest.manifest_id
        or command.detector_manifest_id != detector.model_manifest_id
        or command.rule_version != manifest.rule_version
    ):
        raise M5TrainingExportError(M5TrainingExportFailureCode.MANIFEST_SCOPE_MISMATCH)


def _require_label_scope(
    labels: tuple[TrainingLabel, ...],
    command: CocoDatasetExportCommand,
) -> None:
    if any(not isinstance(label, TrainingLabel) for label in labels):
        raise M5TrainingExportError(M5TrainingExportFailureCode.LABEL_AUTHORITY_MISMATCH)
    label_ids = tuple(label.label_id for label in labels)
    if label_ids != tuple(sorted(label_ids)) or len(label_ids) != len(set(label_ids)):
        raise M5TrainingExportError(M5TrainingExportFailureCode.LABEL_AUTHORITY_MISMATCH)
    if any(
        label.rule_version != command.rule_version
        or label.detector_manifest_id != command.detector_manifest_id
        for label in labels
    ):
        raise M5TrainingExportError(M5TrainingExportFailureCode.LABEL_AUTHORITY_MISMATCH)


def _require_current_pack_closure(
    *,
    command: CocoDatasetExportCommand,
    case: CaseSnapshot,
    pack_id: str,
    pack_input_sha256: str,
    crop_ref: ArtifactRef,
    closure: ClosureReport,
) -> None:
    if (
        not isinstance(closure, ClosureReport)
        or closure.run_id != command.run_id
        or closure.root_ref != ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack_id)
        or closure.manifest_id != command.manifest_id
        or closure.input_sha256 != pack_input_sha256
    ):
        raise M5TrainingExportError(M5TrainingExportFailureCode.CURRENT_PACK_AUTHORITY_MISMATCH)
    if not closure.passed:
        raise M5TrainingExportError(M5TrainingExportFailureCode.CURRENT_PACK_VERIFICATION_FAILED)
    if crop_ref not in closure.checked_refs:
        raise M5TrainingExportError(M5TrainingExportFailureCode.CURRENT_PACK_CROP_NOT_CHECKED)
    if case.case.evidence_packs[-1].pack_id != pack_id:
        raise M5TrainingExportError(M5TrainingExportFailureCode.CURRENT_PACK_AUTHORITY_MISMATCH)


def _build_crop_authorities(
    *,
    command: CocoDatasetExportCommand,
    selected: tuple[TrainingLabel, ...],
    evidence: M5TrainingEvidenceReader,
    crop_verifier: M5TrainingCropVerifier,
) -> tuple[TrainingCropAuthority, ...]:
    labels_by_case: dict[str, list[TrainingLabel]] = {}
    for label in selected:
        labels_by_case.setdefault(label.case_id, []).append(label)

    authorities_by_crop: dict[str, TrainingCropAuthority] = {}
    for case_id in sorted(labels_by_case):
        before = evidence.load_case(command.run_id, case_id)
        if not isinstance(before, CaseSnapshot) or before.revision <= 0:
            raise M5TrainingExportError(M5TrainingExportFailureCode.CASE_AUTHORITY_MISMATCH)
        case = before.case
        if (
            case.run_id != command.run_id
            or case.case_id != case_id
            or case.manifest_id != command.manifest_id
        ):
            raise M5TrainingExportError(M5TrainingExportFailureCode.CASE_AUTHORITY_MISMATCH)
        if not case.evidence_packs:
            raise M5TrainingExportError(M5TrainingExportFailureCode.LATEST_EVIDENCE_PACK_MISSING)
        latest_pack = case.evidence_packs[-1]
        if not latest_pack.complete:
            raise M5TrainingExportError(M5TrainingExportFailureCode.LATEST_EVIDENCE_PACK_INCOMPLETE)
        crops = {crop.crop_id: crop for crop in latest_pack.crops}
        requested_crop_ids = tuple(sorted({label.crop_id for label in labels_by_case[case_id]}))

        for crop_id in requested_crop_ids:
            crop = crops.get(crop_id)
            if crop is None:
                raise M5TrainingExportError(
                    M5TrainingExportFailureCode.LABEL_CROP_NOT_IN_LATEST_PACK
                )
            crop_ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
            closure = evidence.verify_current_pack(command.run_id, latest_pack.pack_id)
            _require_current_pack_closure(
                command=command,
                case=before,
                pack_id=latest_pack.pack_id,
                pack_input_sha256=latest_pack.closure_input_sha256,
                crop_ref=crop_ref,
                closure=closure,
            )
            verification = crop_verifier.verify_crop(crop)
            if (
                not isinstance(verification, ArtifactVerification)
                or verification.artifact_ref != crop_ref
                or verification.status != VerificationStatus.CURRENT_MEDIA_VERIFIED
            ):
                raise M5TrainingExportError(M5TrainingExportFailureCode.CROP_VERIFICATION_FAILED)
            try:
                authority = TrainingCropAuthority(
                    run_id=command.run_id,
                    case_id=case_id,
                    crop=crop,
                    verification=verification,
                    detector_manifest_id=command.detector_manifest_id,
                    manifest_id=command.manifest_id,
                    rule_version=command.rule_version,
                )
            except ValidationError:
                raise M5TrainingExportError(
                    M5TrainingExportFailureCode.CROP_VERIFICATION_FAILED
                ) from None
            existing = authorities_by_crop.get(crop_id)
            if existing is not None and existing != authority:
                raise M5TrainingExportError(M5TrainingExportFailureCode.CROP_SCOPE_CONFLICT)
            authorities_by_crop[crop_id] = authority

        after = evidence.load_case(command.run_id, case_id)
        if after != before:
            raise M5TrainingExportError(M5TrainingExportFailureCode.CASE_CHANGED_DURING_EXPORT)

    return tuple(authorities_by_crop[key] for key in sorted(authorities_by_crop))


class M5TrainingExportCoordinator:
    """Build and publish one immutable default-policy COCO dataset."""

    def __init__(
        self,
        *,
        repository: TrainingDatasetRepository,
        evidence: M5TrainingEvidenceReader,
        crop_verifier: M5TrainingCropVerifier,
        publisher: DatasetArtifactPublisher,
        manifest: RunManifest,
    ) -> None:
        if not isinstance(manifest, RunManifest):
            raise M5TrainingExportError(M5TrainingExportFailureCode.INVALID_ARGUMENT)
        required_methods = (
            (repository, "list_training_label_authorities"),
            (evidence, "load_case"),
            (evidence, "verify_current_pack"),
            (crop_verifier, "verify_crop"),
            (publisher, "publish"),
        )
        if any(not callable(getattr(owner, method, None)) for owner, method in required_methods):
            raise M5TrainingExportError(M5TrainingExportFailureCode.INVALID_ARGUMENT)
        self._repository = repository
        self._evidence = evidence
        self._crop_verifier = crop_verifier
        self._publisher = publisher
        self._manifest = manifest

    def export(self, command: CocoDatasetExportCommand) -> DatasetExportReport:
        if not isinstance(command, CocoDatasetExportCommand):
            raise M5TrainingExportError(M5TrainingExportFailureCode.INVALID_ARGUMENT)
        _require_manifest_scope(command, self._manifest)

        authorities = self._repository.list_training_label_authorities(
            command.run_id,
            command.max_input_labels,
        )
        if not isinstance(authorities, tuple):
            raise M5TrainingExportError(M5TrainingExportFailureCode.LABEL_AUTHORITY_MISMATCH)
        labels = _labels_from_authorities(authorities)
        _require_label_scope(labels, command)
        crop_authorities = _build_crop_authorities(
            command=command,
            selected=_selected_labels(labels),
            evidence=self._evidence,
            crop_verifier=self._crop_verifier,
        )
        built = build_coco_dataset(
            command=command,
            labels=labels,
            crop_authorities=crop_authorities,
        )
        published = self._publisher.publish(built.report, built.content)
        if not isinstance(published, DatasetArtifact) or published != built.report.dataset:
            raise M5TrainingExportError(M5TrainingExportFailureCode.PUBLISH_RESULT_MISMATCH)
        return built.report


__all__ = [
    "M5TrainingCropVerifier",
    "M5TrainingEvidenceReader",
    "M5TrainingExportCoordinator",
    "M5TrainingExportError",
    "M5TrainingExportFailureCode",
]
