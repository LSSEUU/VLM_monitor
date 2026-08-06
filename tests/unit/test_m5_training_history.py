from __future__ import annotations

from dataclasses import dataclass

import pytest

from labcourt.application.dataset_export import build_coco_dataset
from labcourt.application.m5_training_history import (
    M5TrainingHistoryError,
    M5TrainingHistoryErrorCode,
    build_m5_dataset_label_snapshot_receipts,
    build_m5_dataset_registration_commit_event,
    build_m5_dataset_registration_snapshot,
    build_m5_training_causal_watermark,
    build_m5_training_label_causal_event,
    require_m5_training_causal_chain,
    resolve_m5_dataset_historical_replay,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import TrainingLabelQuality
from labcourt.contracts.m5_training import DatasetExportReport, TrainingCropAuthority
from labcourt.contracts.m5_training_history import (
    M5_TRAINING_CAUSAL_GENESIS_SHA256,
    M5DatasetCropSnapshotAuthority,
    M5DatasetLabelSnapshotReceipt,
    M5DatasetLabelSnapshotRole,
    M5DatasetRegistrationSnapshotAuthority,
    M5TrainingCausalEvent,
    M5TrainingCausalEventKind,
    M5TrainingCausalWatermark,
)
from labcourt.contracts.m5_training_provenance import M5TrainingLabelAuthority
from tests.unit.test_m5_alert_policy import _manifest_with_stream, _ready_case
from tests.unit.test_m5_training_operations import (
    _command,
    _label,
    _label_authority,
    _verification,
)


@dataclass(frozen=True, slots=True)
class _HistoryFixture:
    report: DatasetExportReport
    initial_authorities: tuple[M5TrainingLabelAuthority, ...]
    all_authorities: tuple[M5TrainingLabelAuthority, ...]
    cut: M5TrainingCausalWatermark
    receipts: tuple[M5DatasetLabelSnapshotReceipt, ...]
    crops: tuple[M5DatasetCropSnapshotAuthority, ...]
    snapshot: M5DatasetRegistrationSnapshotAuthority
    marker: M5TrainingCausalEvent
    events: tuple[M5TrainingCausalEvent, ...]


def _sorted_authorities(*authorities: M5TrainingLabelAuthority):
    return tuple(sorted(authorities, key=lambda item: item.label.label_id))


def _crop_authority() -> TrainingCropAuthority:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    return TrainingCropAuthority(
        run_id=case.run_id,
        case_id=case.case_id,
        crop=case.evidence_packs[-1].crops[0],
        verification=_verification(),
        detector_manifest_id=manifest.models["detector"].model_manifest_id,
        manifest_id=manifest.manifest_id,
        rule_version=manifest.rule_version,
    )


def _crop_snapshot(report: DatasetExportReport) -> M5DatasetCropSnapshotAuthority:
    manifest = _manifest_with_stream()
    case = _ready_case(manifest)
    pack = case.evidence_packs[-1]
    return M5DatasetCropSnapshotAuthority(
        run_id=report.run_id,
        dataset_id=report.dataset.dataset_id,
        report_id=report.report_id,
        crop_authority=_crop_authority(),
        case_revision=4,
        case_document_sha256=sha256_hex(case.model_dump(mode="json")),
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        evidence_pack_document_sha256=sha256_hex(pack.model_dump(mode="json")),
    )


def _event_for(
    authority: M5TrainingLabelAuthority,
    *,
    sequence: int,
    previous: str,
) -> M5TrainingCausalEvent:
    manifest = _manifest_with_stream()
    return build_m5_training_label_causal_event(
        run_id="run-01",
        manifest_id=manifest.manifest_id,
        authority=authority,
        sequence=sequence,
        previous_event_sha256=previous,
    )


def _history(*, prior_marker: bool = False, tail_label: bool = False) -> _HistoryFixture:
    manifest = _manifest_with_stream()
    strong = _label_authority(_label("strong", TrainingLabelQuality.HUMAN_CONFIRMED))
    weak = _label_authority(_label("weak", TrainingLabelQuality.WEAK_AUTO))
    initial = _sorted_authorities(strong, weak)
    built = build_coco_dataset(
        command=_command(),
        labels=tuple(item.label for item in initial),
        crop_authorities=(_crop_authority(),),
    )

    events: list[M5TrainingCausalEvent] = []
    previous = M5_TRAINING_CAUSAL_GENESIS_SHA256
    first = _event_for(initial[0], sequence=1, previous=previous)
    events.append(first)
    previous = first.event_sha256
    if prior_marker:
        marker = M5TrainingCausalEvent(
            run_id="run-01",
            sequence=2,
            event_kind=M5TrainingCausalEventKind.DATASET_REGISTRATION_COMMITTED,
            source_id="9" * 64,
            source_document_sha256="8" * 64,
            manifest_id=manifest.manifest_id,
            previous_event_sha256=previous,
        )
        events.append(marker)
        previous = marker.event_sha256
    second = _event_for(initial[1], sequence=len(events) + 1, previous=previous)
    events.append(second)
    cut = build_m5_training_causal_watermark(
        run_id="run-01",
        manifest_id=manifest.manifest_id,
        events=tuple(events),
    )
    receipts = build_m5_dataset_label_snapshot_receipts(
        report=built.report,
        causal_cut=cut,
        events=tuple(events),
        label_authorities=initial,
    )
    crops = (_crop_snapshot(built.report),)
    snapshot = build_m5_dataset_registration_snapshot(
        report=built.report,
        causal_cut=cut,
        label_receipts=receipts,
        crop_snapshots=crops,
    )
    registration_marker = build_m5_dataset_registration_commit_event(snapshot)
    events.append(registration_marker)

    all_authorities = initial
    if tail_label:
        tail = _label_authority(_label("tail", TrainingLabelQuality.WEAK_AUTO))
        all_authorities = _sorted_authorities(*initial, tail)
        tail_event = _event_for(
            tail,
            sequence=len(events) + 1,
            previous=events[-1].event_sha256,
        )
        events.append(tail_event)
    return _HistoryFixture(
        report=built.report,
        initial_authorities=initial,
        all_authorities=all_authorities,
        cut=cut,
        receipts=receipts,
        crops=crops,
        snapshot=snapshot,
        marker=registration_marker,
        events=tuple(events),
    )


def _resolve(fixture: _HistoryFixture):
    return resolve_m5_dataset_historical_replay(
        report=fixture.report,
        snapshot=fixture.snapshot,
        registration_marker=fixture.marker,
        events=fixture.events,
        label_authorities=fixture.all_authorities,
        label_receipts=fixture.receipts,
        crop_snapshots=fixture.crops,
    )


def test_historical_replay_accepts_prior_marker_and_ignores_legal_tail_label() -> None:
    fixture = _history(prior_marker=True, tail_label=True)

    labels, crops = _resolve(fixture)

    assert tuple(item.label_id for item in labels) == tuple(
        sorted(fixture.report.exported_label_ids + fixture.report.quarantined_label_ids)
    )
    assert {item.label_id for item in labels} == set(fixture.report.exported_label_ids) | set(
        fixture.report.quarantined_label_ids
    )
    assert tuple(item.crop.crop_id for item in crops) == tuple(
        item.crop_id for item in fixture.report.crop_receipts
    )
    assert all(item.label_id != "tail" for item in labels)


def test_genesis_empty_dataset_closes_and_replays() -> None:
    manifest = _manifest_with_stream()
    built = build_coco_dataset(command=_command(), labels=(), crop_authorities=())
    cut = build_m5_training_causal_watermark(
        run_id="run-01",
        manifest_id=manifest.manifest_id,
        events=(),
    )
    receipts = build_m5_dataset_label_snapshot_receipts(
        report=built.report,
        causal_cut=cut,
        events=(),
        label_authorities=(),
    )
    snapshot = build_m5_dataset_registration_snapshot(
        report=built.report,
        causal_cut=cut,
        label_receipts=receipts,
        crop_snapshots=(),
    )
    marker = build_m5_dataset_registration_commit_event(snapshot)

    assert resolve_m5_dataset_historical_replay(
        report=built.report,
        snapshot=snapshot,
        registration_marker=marker,
        events=(marker,),
        label_authorities=(),
        label_receipts=(),
        crop_snapshots=(),
    ) == ((), ())


def test_complete_chain_rejects_gap_broken_predecessor_and_model_construct() -> None:
    fixture = _history()
    events = fixture.events
    forged = M5TrainingCausalEvent.model_construct(
        **{
            **events[1].model_dump(mode="python", exclude_computed_fields=True),
            "sequence": 3,
        }
    )

    for attacked in (
        (events[0], forged),
        (events[1], events[0]),
        (events[0], events[1].model_copy(update={"previous_event_sha256": "f" * 64})),
    ):
        with pytest.raises(M5TrainingHistoryError) as failure:
            require_m5_training_causal_chain(
                run_id="run-01",
                manifest_id=_manifest_with_stream().manifest_id,
                events=attacked,
                label_authorities=fixture.initial_authorities,
            )
        assert failure.value.code == M5TrainingHistoryErrorCode.CHAIN_INVALID


def test_chain_rejects_forged_or_missing_label_source_and_model_construct() -> None:
    fixture = _history()
    forged_event = fixture.events[1].model_copy(update={"source_id": "f" * 64})
    malformed_authority = M5TrainingLabelAuthority.model_construct(
        label=fixture.initial_authorities[0].label,
        strong_provenance=None,
    )

    attacks = (
        ((fixture.events[0], forged_event), fixture.initial_authorities),
        (fixture.events, fixture.initial_authorities[:-1]),
        (fixture.events, (malformed_authority, *fixture.initial_authorities[1:])),
    )
    for events, authorities in attacks:
        with pytest.raises(M5TrainingHistoryError) as failure:
            require_m5_training_causal_chain(
                run_id="run-01",
                manifest_id=_manifest_with_stream().manifest_id,
                events=events,
                label_authorities=authorities,
            )
        assert failure.value.code == M5TrainingHistoryErrorCode.LABEL_SOURCE_INVALID


def test_receipt_builder_rejects_forged_cut_and_omitted_pre_cut_inventory() -> None:
    fixture = _history()
    forged_cut = fixture.cut.model_copy(update={"event_sha256": "f" * 64})
    incomplete_report = build_coco_dataset(
        command=_command(),
        labels=(fixture.initial_authorities[0].label,),
        crop_authorities=(_crop_authority(),),
    ).report

    with pytest.raises(M5TrainingHistoryError) as cut_failure:
        build_m5_dataset_label_snapshot_receipts(
            report=fixture.report,
            causal_cut=forged_cut,
            events=fixture.events,
            label_authorities=fixture.initial_authorities,
        )
    assert cut_failure.value.code == M5TrainingHistoryErrorCode.CUT_INVALID

    with pytest.raises(M5TrainingHistoryError) as inventory_failure:
        build_m5_dataset_label_snapshot_receipts(
            report=incomplete_report,
            causal_cut=fixture.cut,
            events=fixture.events,
            label_authorities=fixture.initial_authorities,
        )
    assert inventory_failure.value.code == M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID


def test_snapshot_builder_rejects_report_scope_label_root_and_crop_root() -> None:
    fixture = _history()
    wrong_role = fixture.receipts[0].model_copy(
        update={
            "role": (
                M5DatasetLabelSnapshotRole.QUARANTINED
                if fixture.receipts[0].role.value == "EXPORTED"
                else M5DatasetLabelSnapshotRole.EXPORTED
            )
        }
    )
    wrong_crop = fixture.crops[0].model_copy(update={"report_id": "f" * 64})
    malformed_report = DatasetExportReport.model_construct(
        **{
            **{name: getattr(fixture.report, name) for name in DatasetExportReport.model_fields},
            "input_label_count": 99,
        }
    )

    with pytest.raises(M5TrainingHistoryError) as report_failure:
        build_m5_dataset_registration_snapshot(
            report=malformed_report,
            causal_cut=fixture.cut,
            label_receipts=fixture.receipts,
            crop_snapshots=fixture.crops,
        )
    assert report_failure.value.code == M5TrainingHistoryErrorCode.REPORT_SCOPE_INVALID
    with pytest.raises(M5TrainingHistoryError) as label_failure:
        build_m5_dataset_registration_snapshot(
            report=fixture.report,
            causal_cut=fixture.cut,
            label_receipts=(wrong_role, *fixture.receipts[1:]),
            crop_snapshots=fixture.crops,
        )
    assert label_failure.value.code == M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID
    with pytest.raises(M5TrainingHistoryError) as crop_failure:
        build_m5_dataset_registration_snapshot(
            report=fixture.report,
            causal_cut=fixture.cut,
            label_receipts=fixture.receipts,
            crop_snapshots=(wrong_crop,),
        )
    assert crop_failure.value.code == M5TrainingHistoryErrorCode.CROP_ROOT_INVALID


def test_replay_rejects_forged_marker_and_marker_not_immediately_after_cut() -> None:
    fixture = _history()
    forged_marker = fixture.marker.model_copy(update={"source_id": "f" * 64})
    delayed_marker = fixture.marker.model_copy(
        update={
            "sequence": fixture.marker.sequence + 1,
            "previous_event_sha256": fixture.marker.event_sha256,
        }
    )

    for marker in (forged_marker, delayed_marker):
        with pytest.raises(M5TrainingHistoryError) as failure:
            resolve_m5_dataset_historical_replay(
                report=fixture.report,
                snapshot=fixture.snapshot,
                registration_marker=marker,
                events=fixture.events,
                label_authorities=fixture.all_authorities,
                label_receipts=fixture.receipts,
                crop_snapshots=fixture.crops,
            )
        assert failure.value.code == M5TrainingHistoryErrorCode.REGISTRATION_MARKER_INVALID


def test_replay_rejects_forged_snapshot_label_and_crop_roots() -> None:
    fixture = _history()
    forged_label_snapshot = M5DatasetRegistrationSnapshotAuthority.model_construct(
        **{
            **{
                name: getattr(fixture.snapshot, name)
                for name in M5DatasetRegistrationSnapshotAuthority.model_fields
            },
            "label_inventory_root_sha256": "f" * 64,
        }
    )
    forged_crop_snapshot = M5DatasetRegistrationSnapshotAuthority.model_construct(
        **{
            **{
                name: getattr(fixture.snapshot, name)
                for name in M5DatasetRegistrationSnapshotAuthority.model_fields
            },
            "crop_inventory_root_sha256": "f" * 64,
        }
    )

    for snapshot, expected in (
        (forged_label_snapshot, M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID),
        (forged_crop_snapshot, M5TrainingHistoryErrorCode.CROP_ROOT_INVALID),
    ):
        with pytest.raises(M5TrainingHistoryError) as failure:
            resolve_m5_dataset_historical_replay(
                report=fixture.report,
                snapshot=snapshot,
                registration_marker=fixture.marker,
                events=fixture.events,
                label_authorities=fixture.all_authorities,
                label_receipts=fixture.receipts,
                crop_snapshots=fixture.crops,
            )
        assert failure.value.code == expected


def test_replay_rejects_forged_receipt_and_historical_crop_closure() -> None:
    fixture = _history()
    forged_receipt = fixture.receipts[0].model_copy(update={"authority_sha256": "f" * 64})
    forged_crop = fixture.crops[0].model_copy(update={"case_document_sha256": "f" * 64})

    with pytest.raises(M5TrainingHistoryError) as label_failure:
        resolve_m5_dataset_historical_replay(
            report=fixture.report,
            snapshot=fixture.snapshot,
            registration_marker=fixture.marker,
            events=fixture.events,
            label_authorities=fixture.all_authorities,
            label_receipts=(forged_receipt, *fixture.receipts[1:]),
            crop_snapshots=fixture.crops,
        )
    assert label_failure.value.code == M5TrainingHistoryErrorCode.LABEL_ROOT_INVALID

    with pytest.raises(M5TrainingHistoryError) as crop_failure:
        resolve_m5_dataset_historical_replay(
            report=fixture.report,
            snapshot=fixture.snapshot,
            registration_marker=fixture.marker,
            events=fixture.events,
            label_authorities=fixture.all_authorities,
            label_receipts=fixture.receipts,
            crop_snapshots=(forged_crop,),
        )
    assert crop_failure.value.code == M5TrainingHistoryErrorCode.CROP_ROOT_INVALID
