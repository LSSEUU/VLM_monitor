"""Pure construction and replay verification for M5 training causal history."""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.m5_training import DatasetExportReport, TrainingCropAuthority
from labcourt.contracts.m5_training_history import (
    M5_TRAINING_CAUSAL_GENESIS_SHA256,
    MAX_M5_TRAINING_CAUSAL_EVENTS,
    M5DatasetCropSnapshotAuthority,
    M5DatasetLabelSnapshotReceipt,
    M5DatasetLabelSnapshotRole,
    M5DatasetRegistrationSnapshotAuthority,
    M5TrainingCausalEvent,
    M5TrainingCausalEventKind,
    M5TrainingCausalWatermark,
    m5_dataset_crop_inventory_root_sha256,
    m5_dataset_label_inventory_root_sha256,
)
from labcourt.contracts.m5_training_provenance import M5TrainingLabelAuthority
from labcourt.contracts.training import TrainingLabel
from labcourt.exceptions import LabCourtError

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M5TrainingHistoryErrorCode(StrEnum):
    CHAIN_INVALID = "CHAIN_INVALID"
    LABEL_SOURCE_INVALID = "LABEL_SOURCE_INVALID"
    CUT_INVALID = "CUT_INVALID"
    REPORT_SCOPE_INVALID = "REPORT_SCOPE_INVALID"
    REGISTRATION_MARKER_INVALID = "REGISTRATION_MARKER_INVALID"
    LABEL_ROOT_INVALID = "LABEL_ROOT_INVALID"
    CROP_ROOT_INVALID = "CROP_ROOT_INVALID"


class M5TrainingHistoryError(LabCourtError):
    def __init__(self, code: M5TrainingHistoryErrorCode) -> None:
        if not isinstance(code, M5TrainingHistoryErrorCode):
            raise TypeError("code must be an M5TrainingHistoryErrorCode")
        self.code = code
        super().__init__(f"M5 training history failed: {code.value}")


def _fail(code: M5TrainingHistoryErrorCode, cause: Exception | None = None) -> NoReturn:
    error = M5TrainingHistoryError(code)
    if cause is None:
        raise error
    raise error from cause


def _validated_model(
    value: object,
    model_type: type[_ModelT],
    code: M5TrainingHistoryErrorCode,
) -> _ModelT:
    try:
        if not isinstance(value, model_type):
            raise TypeError(f"expected {model_type.__name__}")
        rebuilt = model_type.model_validate(
            value.model_dump(
                mode="python",
                exclude_computed_fields=True,
                round_trip=True,
            )
        )
        if rebuilt != value:
            raise ValueError(f"{model_type.__name__} changed during validation")
        return rebuilt
    except (AttributeError, TypeError, ValueError) as exc:
        _fail(code, exc)


def _document_sha256(value: BaseModel) -> str:
    return sha256_hex(value.model_dump(mode="json"))


def build_m5_training_label_causal_event(
    *,
    run_id: str,
    manifest_id: str,
    authority: M5TrainingLabelAuthority,
    sequence: int,
    previous_event_sha256: str,
) -> M5TrainingCausalEvent:
    """Append one exact label authority to a caller-selected chain position."""

    validated = _validated_model(
        authority,
        M5TrainingLabelAuthority,
        M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID,
    )
    try:
        return M5TrainingCausalEvent(
            run_id=run_id,
            sequence=sequence,
            event_kind=M5TrainingCausalEventKind.TRAINING_LABEL_APPENDED,
            source_id=validated.authority_sha256,
            source_document_sha256=_document_sha256(validated),
            manifest_id=manifest_id,
            previous_event_sha256=previous_event_sha256,
            label_id=validated.label.label_id,
        )
    except (TypeError, ValueError) as exc:
        _fail(M5TrainingHistoryErrorCode.CHAIN_INVALID, exc)


def _validated_event_chain(
    *,
    run_id: str,
    manifest_id: str,
    events: tuple[M5TrainingCausalEvent, ...],
) -> tuple[M5TrainingCausalEvent, ...]:
    if not isinstance(events, tuple):
        _fail(M5TrainingHistoryErrorCode.CHAIN_INVALID)
    validated = tuple(
        _validated_model(
            event,
            M5TrainingCausalEvent,
            M5TrainingHistoryErrorCode.CHAIN_INVALID,
        )
        for event in events
    )
    if len(validated) > MAX_M5_TRAINING_CAUSAL_EVENTS:
        _fail(M5TrainingHistoryErrorCode.CHAIN_INVALID)
    expected_previous = M5_TRAINING_CAUSAL_GENESIS_SHA256
    event_ids: set[str] = set()
    source_identities: set[str] = set()
    for expected_sequence, event in enumerate(validated, start=1):
        if (
            event.run_id != run_id
            or event.manifest_id != manifest_id
            or event.sequence != expected_sequence
            or event.previous_event_sha256 != expected_previous
            or event.event_id in event_ids
            or event.source_identity in source_identities
        ):
            _fail(M5TrainingHistoryErrorCode.CHAIN_INVALID)
        event_ids.add(event.event_id)
        source_identities.add(event.source_identity)
        expected_previous = event.event_sha256
    return validated


def _validated_label_authorities(
    authorities: tuple[M5TrainingLabelAuthority, ...],
) -> tuple[M5TrainingLabelAuthority, ...]:
    if not isinstance(authorities, tuple):
        _fail(M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID)
    validated = tuple(
        _validated_model(
            authority,
            M5TrainingLabelAuthority,
            M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID,
        )
        for authority in authorities
    )
    label_ids = tuple(item.label.label_id for item in validated)
    authority_ids = tuple(item.authority_sha256 for item in validated)
    if (
        label_ids != tuple(sorted(label_ids))
        or len(label_ids) != len(set(label_ids))
        or len(authority_ids) != len(set(authority_ids))
    ):
        _fail(M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID)
    return validated


def require_m5_training_causal_chain(
    *,
    run_id: str,
    manifest_id: str,
    events: tuple[M5TrainingCausalEvent, ...],
    label_authorities: tuple[M5TrainingLabelAuthority, ...],
) -> tuple[M5TrainingCausalEvent, ...]:
    """Require a complete chain and exactly one append event per label authority."""

    validated_events = _validated_event_chain(
        run_id=run_id,
        manifest_id=manifest_id,
        events=events,
    )
    validated_authorities = _validated_label_authorities(label_authorities)
    authority_by_label = {item.label.label_id: item for item in validated_authorities}
    label_events: dict[str, M5TrainingCausalEvent] = {}
    for event in validated_events:
        if event.event_kind != M5TrainingCausalEventKind.TRAINING_LABEL_APPENDED:
            continue
        label_id = event.label_id
        if label_id is None or label_id in label_events:
            _fail(M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID)
        authority = authority_by_label.get(label_id)
        if authority is None or (
            event.source_id != authority.authority_sha256
            or event.source_document_sha256 != _document_sha256(authority)
        ):
            _fail(M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID)
        provenance = authority.strong_provenance
        if provenance is not None and (
            provenance.run_id != run_id or provenance.manifest_id != manifest_id
        ):
            _fail(M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID)
        label_events[label_id] = event
    if set(label_events) != set(authority_by_label):
        _fail(M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID)
    return validated_events


def build_m5_training_causal_watermark(
    *,
    run_id: str,
    manifest_id: str,
    events: tuple[M5TrainingCausalEvent, ...],
) -> M5TrainingCausalWatermark:
    """Build the head of one already complete structural event chain."""

    validated = _validated_event_chain(
        run_id=run_id,
        manifest_id=manifest_id,
        events=events,
    )
    if not validated:
        return M5TrainingCausalWatermark(
            run_id=run_id,
            sequence=0,
            event_sha256=M5_TRAINING_CAUSAL_GENESIS_SHA256,
        )
    head = validated[-1]
    return M5TrainingCausalWatermark(
        run_id=run_id,
        sequence=head.sequence,
        event_id=head.event_id,
        event_sha256=head.event_sha256,
    )


def _require_cut(
    *,
    run_id: str,
    cut: M5TrainingCausalWatermark,
    events: tuple[M5TrainingCausalEvent, ...],
) -> M5TrainingCausalWatermark:
    validated = _validated_model(
        cut,
        M5TrainingCausalWatermark,
        M5TrainingHistoryErrorCode.CUT_INVALID,
    )
    if validated.run_id != run_id:
        _fail(M5TrainingHistoryErrorCode.CUT_INVALID)
    if validated.sequence == 0:
        return validated
    if validated.sequence > len(events):
        _fail(M5TrainingHistoryErrorCode.CUT_INVALID)
    head = events[validated.sequence - 1]
    if head.event_id != validated.event_id or head.event_sha256 != validated.event_sha256:
        _fail(M5TrainingHistoryErrorCode.CUT_INVALID)
    return validated


def _validated_report(report: DatasetExportReport) -> DatasetExportReport:
    return _validated_model(
        report,
        DatasetExportReport,
        M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID,
    )


def build_m5_dataset_label_snapshot_receipts(
    *,
    report: DatasetExportReport,
    causal_cut: M5TrainingCausalWatermark,
    events: tuple[M5TrainingCausalEvent, ...],
    label_authorities: tuple[M5TrainingLabelAuthority, ...],
) -> tuple[M5DatasetLabelSnapshotReceipt, ...]:
    """Capture exactly the labels visible at ``causal_cut`` and no later labels."""

    validated_report = _validated_report(report)
    validated_events = require_m5_training_causal_chain(
        run_id=validated_report.run_id,
        manifest_id=validated_report.manifest_id,
        events=events,
        label_authorities=label_authorities,
    )
    cut = _require_cut(
        run_id=validated_report.run_id,
        cut=causal_cut,
        events=validated_events,
    )
    authorities = _validated_label_authorities(label_authorities)
    authority_by_label = {item.label.label_id: item for item in authorities}
    prefix_events = tuple(
        item
        for item in validated_events[: cut.sequence]
        if item.event_kind == M5TrainingCausalEventKind.TRAINING_LABEL_APPENDED
    )
    prefix_label_ids = tuple(
        sorted(item.label_id for item in prefix_events if item.label_id is not None)
    )
    accounted = tuple(
        sorted(validated_report.exported_label_ids + validated_report.quarantined_label_ids)
    )
    if prefix_label_ids != accounted or len(prefix_label_ids) != validated_report.input_label_count:
        _fail(M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID)
    event_by_label = {item.label_id: item for item in prefix_events}
    exported = set(validated_report.exported_label_ids)
    receipts: list[M5DatasetLabelSnapshotReceipt] = []
    for label_id in prefix_label_ids:
        authority = authority_by_label[label_id]
        label = authority.label
        if (
            label.rule_version != validated_report.rule_version
            or label.detector_manifest_id != validated_report.detector_manifest_id
        ):
            _fail(M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID)
        event = event_by_label[label_id]
        receipts.append(
            M5DatasetLabelSnapshotReceipt(
                label_id=label_id,
                role=(
                    M5DatasetLabelSnapshotRole.EXPORTED
                    if label_id in exported
                    else M5DatasetLabelSnapshotRole.QUARANTINED
                ),
                authority_sha256=authority.authority_sha256,
                causal_event_id=event.event_id,
                causal_event_sequence=event.sequence,
                causal_event_sha256=event.event_sha256,
            )
        )
    return tuple(receipts)


def _validated_receipts(
    receipts: tuple[M5DatasetLabelSnapshotReceipt, ...],
) -> tuple[M5DatasetLabelSnapshotReceipt, ...]:
    if not isinstance(receipts, tuple):
        _fail(M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID)
    validated = tuple(
        _validated_model(
            item,
            M5DatasetLabelSnapshotReceipt,
            M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID,
        )
        for item in receipts
    )
    keys = tuple(item.label_id for item in validated)
    event_ids = tuple(item.causal_event_id for item in validated)
    if (
        keys != tuple(sorted(keys))
        or len(keys) != len(set(keys))
        or len(event_ids) != len(set(event_ids))
    ):
        _fail(M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID)
    return validated


def _validated_crop_snapshots(
    snapshots: tuple[M5DatasetCropSnapshotAuthority, ...],
) -> tuple[M5DatasetCropSnapshotAuthority, ...]:
    if not isinstance(snapshots, tuple):
        _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID)
    validated = tuple(
        _validated_model(
            item,
            M5DatasetCropSnapshotAuthority,
            M5TrainingHistoryErrorCode.CROP_ROOT_INVALID,
        )
        for item in snapshots
    )
    keys = tuple(item.sort_key for item in validated)
    if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
        _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID)
    return validated


def build_m5_dataset_registration_snapshot(
    *,
    report: DatasetExportReport,
    causal_cut: M5TrainingCausalWatermark,
    label_receipts: tuple[M5DatasetLabelSnapshotReceipt, ...],
    crop_snapshots: tuple[M5DatasetCropSnapshotAuthority, ...],
) -> M5DatasetRegistrationSnapshotAuthority:
    """Build fixed-size roots after validating every normalized snapshot row."""

    validated_report = _validated_report(report)
    cut = _validated_model(
        causal_cut,
        M5TrainingCausalWatermark,
        M5TrainingHistoryErrorCode.CUT_INVALID,
    )
    if cut.run_id != validated_report.run_id:
        _fail(M5TrainingHistoryErrorCode.CUT_INVALID)
    receipts = _validated_receipts(label_receipts)
    accounted_roles = {
        **{
            item: M5DatasetLabelSnapshotRole.EXPORTED
            for item in validated_report.exported_label_ids
        },
        **{
            item: M5DatasetLabelSnapshotRole.QUARANTINED
            for item in validated_report.quarantined_label_ids
        },
    }
    if (
        len(receipts) != validated_report.input_label_count
        or {item.label_id for item in receipts} != set(accounted_roles)
        or any(item.role != accounted_roles.get(item.label_id) for item in receipts)
        or any(item.causal_event_sequence > cut.sequence for item in receipts)
    ):
        _fail(M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID)
    crops = _validated_crop_snapshots(crop_snapshots)
    report_crop_receipts = {item.crop_id: item for item in validated_report.crop_receipts}
    if len(crops) != validated_report.exported_image_count or {
        item.sort_key for item in crops
    } != set(report_crop_receipts):
        _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID)
    for item in crops:
        crop = item.crop_authority
        if (
            item.run_id != validated_report.run_id
            or item.dataset_id != validated_report.dataset.dataset_id
            or item.report_id != validated_report.report_id
            or crop.authority_sha256 != report_crop_receipts[item.sort_key].authority_sha256
            or crop.manifest_id != validated_report.manifest_id
            or crop.rule_version != validated_report.rule_version
            or crop.detector_manifest_id != validated_report.detector_manifest_id
        ):
            _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID)
    try:
        label_root = m5_dataset_label_inventory_root_sha256(
            run_id=validated_report.run_id,
            dataset_id=validated_report.dataset.dataset_id,
            report_id=validated_report.report_id,
            receipts=receipts,
        )
    except (TypeError, ValueError) as exc:
        _fail(M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID, exc)
    try:
        crop_root = m5_dataset_crop_inventory_root_sha256(
            run_id=validated_report.run_id,
            dataset_id=validated_report.dataset.dataset_id,
            report_id=validated_report.report_id,
            authorities=crops,
        )
    except (TypeError, ValueError) as exc:
        _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID, exc)
    try:
        return M5DatasetRegistrationSnapshotAuthority(
            run_id=validated_report.run_id,
            dataset_id=validated_report.dataset.dataset_id,
            report_id=validated_report.report_id,
            command_id=validated_report.command_id,
            report_document_sha256=_document_sha256(validated_report),
            causal_cut=cut,
            label_count=len(receipts),
            label_inventory_root_sha256=label_root,
            crop_count=len(crops),
            crop_inventory_root_sha256=crop_root,
            manifest_id=validated_report.manifest_id,
            rule_version=validated_report.rule_version,
            detector_manifest_id=validated_report.detector_manifest_id,
        )
    except (TypeError, ValueError) as exc:
        _fail(M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID, exc)


def build_m5_dataset_registration_commit_event(
    snapshot: M5DatasetRegistrationSnapshotAuthority,
) -> M5TrainingCausalEvent:
    """Build the dataset marker that must immediately succeed its captured cut."""

    validated = _validated_model(
        snapshot,
        M5DatasetRegistrationSnapshotAuthority,
        M5TrainingHistoryErrorCode.REGISTRATION_MARKER_INVALID,
    )
    if validated.causal_cut.sequence >= MAX_M5_TRAINING_CAUSAL_EVENTS:
        _fail(M5TrainingHistoryErrorCode.REGISTRATION_MARKER_INVALID)
    try:
        return M5TrainingCausalEvent(
            run_id=validated.run_id,
            sequence=validated.causal_cut.sequence + 1,
            event_kind=M5TrainingCausalEventKind.DATASET_REGISTRATION_COMMITTED,
            source_id=validated.authority_id,
            source_document_sha256=_document_sha256(validated),
            manifest_id=validated.manifest_id,
            previous_event_sha256=validated.causal_cut.event_sha256,
        )
    except (TypeError, ValueError) as exc:
        _fail(M5TrainingHistoryErrorCode.REGISTRATION_MARKER_INVALID, exc)


def _require_snapshot_report_scope(
    *,
    report: DatasetExportReport,
    snapshot: M5DatasetRegistrationSnapshotAuthority,
    cut: M5TrainingCausalWatermark,
) -> None:
    if snapshot.causal_cut != cut:
        _fail(M5TrainingHistoryErrorCode.CUT_INVALID)
    if (
        snapshot.run_id != report.run_id
        or snapshot.dataset_id != report.dataset.dataset_id
        or snapshot.report_id != report.report_id
        or snapshot.command_id != report.command_id
        or snapshot.report_document_sha256 != _document_sha256(report)
        or snapshot.manifest_id != report.manifest_id
        or snapshot.rule_version != report.rule_version
        or snapshot.detector_manifest_id != report.detector_manifest_id
    ):
        _fail(M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID)


def resolve_m5_dataset_historical_replay(
    *,
    report: DatasetExportReport,
    snapshot: M5DatasetRegistrationSnapshotAuthority,
    registration_marker: M5TrainingCausalEvent,
    events: tuple[M5TrainingCausalEvent, ...],
    label_authorities: tuple[M5TrainingLabelAuthority, ...],
    label_receipts: tuple[M5DatasetLabelSnapshotReceipt, ...],
    crop_snapshots: tuple[M5DatasetCropSnapshotAuthority, ...],
) -> tuple[tuple[TrainingLabel, ...], tuple[TrainingCropAuthority, ...]]:
    """Resolve one immutable registration without consulting later current inventory."""

    validated_report = _validated_report(report)
    if not isinstance(snapshot, M5DatasetRegistrationSnapshotAuthority):
        _fail(M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID)
    if (
        snapshot.run_id != validated_report.run_id
        or snapshot.dataset_id != validated_report.dataset.dataset_id
        or snapshot.report_id != validated_report.report_id
        or snapshot.command_id != validated_report.command_id
        or snapshot.report_document_sha256 != _document_sha256(validated_report)
        or snapshot.manifest_id != validated_report.manifest_id
        or snapshot.rule_version != validated_report.rule_version
        or snapshot.detector_manifest_id != validated_report.detector_manifest_id
    ):
        _fail(M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID)
    supplied_receipts = _validated_receipts(label_receipts)
    supplied_crops = _validated_crop_snapshots(crop_snapshots)
    try:
        supplied_label_root = m5_dataset_label_inventory_root_sha256(
            run_id=validated_report.run_id,
            dataset_id=validated_report.dataset.dataset_id,
            report_id=validated_report.report_id,
            receipts=supplied_receipts,
        )
    except (TypeError, ValueError) as exc:
        _fail(M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID, exc)
    if (
        snapshot.label_count != len(supplied_receipts)
        or snapshot.label_inventory_root_sha256 != supplied_label_root
    ):
        _fail(M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID)
    try:
        supplied_crop_root = m5_dataset_crop_inventory_root_sha256(
            run_id=validated_report.run_id,
            dataset_id=validated_report.dataset.dataset_id,
            report_id=validated_report.report_id,
            authorities=supplied_crops,
        )
    except (TypeError, ValueError) as exc:
        _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID, exc)
    if (
        snapshot.crop_count != len(supplied_crops)
        or snapshot.crop_inventory_root_sha256 != supplied_crop_root
    ):
        _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID)
    validated_snapshot = _validated_model(
        snapshot,
        M5DatasetRegistrationSnapshotAuthority,
        M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID,
    )
    validated_events = require_m5_training_causal_chain(
        run_id=validated_report.run_id,
        manifest_id=validated_report.manifest_id,
        events=events,
        label_authorities=label_authorities,
    )
    cut = _require_cut(
        run_id=validated_report.run_id,
        cut=validated_snapshot.causal_cut,
        events=validated_events,
    )
    _require_snapshot_report_scope(
        report=validated_report,
        snapshot=validated_snapshot,
        cut=cut,
    )
    expected_receipts = build_m5_dataset_label_snapshot_receipts(
        report=validated_report,
        causal_cut=cut,
        events=validated_events,
        label_authorities=label_authorities,
    )
    if supplied_receipts != expected_receipts:
        _fail(M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID)
    rebuilt_snapshot = build_m5_dataset_registration_snapshot(
        report=validated_report,
        causal_cut=cut,
        label_receipts=supplied_receipts,
        crop_snapshots=supplied_crops,
    )
    if (
        rebuilt_snapshot.label_inventory_root_sha256
        != (validated_snapshot.label_inventory_root_sha256)
        or rebuilt_snapshot.label_count != validated_snapshot.label_count
    ):
        _fail(M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID)
    if (
        rebuilt_snapshot.crop_inventory_root_sha256
        != (validated_snapshot.crop_inventory_root_sha256)
        or rebuilt_snapshot.crop_count != validated_snapshot.crop_count
    ):
        _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID)
    if rebuilt_snapshot != validated_snapshot:
        _fail(M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID)

    marker = _validated_model(
        registration_marker,
        M5TrainingCausalEvent,
        M5TrainingHistoryErrorCode.REGISTRATION_MARKER_INVALID,
    )
    expected_marker = build_m5_dataset_registration_commit_event(validated_snapshot)
    if marker != expected_marker or marker.sequence > len(validated_events):
        _fail(M5TrainingHistoryErrorCode.REGISTRATION_MARKER_INVALID)
    if validated_events[marker.sequence - 1] != marker:
        _fail(M5TrainingHistoryErrorCode.REGISTRATION_MARKER_INVALID)

    authorities = _validated_label_authorities(label_authorities)
    authority_by_label = {item.label.label_id: item for item in authorities}
    labels = tuple(authority_by_label[item.label_id].label for item in supplied_receipts)
    exported_ids = set(validated_report.exported_label_ids)
    selected_crop_ids = {label.crop_id for label in labels if label.label_id in exported_ids}
    if selected_crop_ids != {item.sort_key for item in supplied_crops}:
        _fail(M5TrainingHistoryErrorCode.CROP_ROOT_INVALID)
    return labels, tuple(item.crop_authority for item in supplied_crops)


__all__ = [
    "M5TrainingHistoryError",
    "M5TrainingHistoryErrorCode",
    "build_m5_dataset_label_snapshot_receipts",
    "build_m5_dataset_registration_commit_event",
    "build_m5_dataset_registration_snapshot",
    "build_m5_training_causal_watermark",
    "build_m5_training_label_causal_event",
    "require_m5_training_causal_chain",
    "resolve_m5_dataset_historical_replay",
]
