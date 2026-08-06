from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import cast

import pytest

from labcourt.adapters.storage._readonly_m5_artifact_codec import (
    M5_AUTHORITY_DOCUMENT_COLUMNS,
    M5_TABLE_SPECS,
    M5DocumentFailure,
    M5IndexFailure,
    M5Record,
    M5TableSpec,
    load_m5_record,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import AppealStatus, TrainingLabelQuality
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_appeals import M5AppealResolutionCommitReceipt
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m5_training_provenance import (
    M5StrongTrainingLabelProvenanceReceipt,
)
from tests.contract.test_m5_training_history_contracts import (
    MANIFEST_ID,
    _crop_snapshot,
    _label_event,
    _registration,
)


def _commit_receipt() -> M5AppealResolutionCommitReceipt:
    return M5AppealResolutionCommitReceipt(
        run_id="run-1",
        resolution_intent_id="a" * 64,
        resolution_document_sha256="b" * 64,
        appeal_id="appeal-1",
        appeal_authority_sha256="c" * 64,
        case_id="case-1",
        source_case_revision=8,
        resulting_case_revision=11,
        resulting_case_document_sha256="d" * 64,
        verdict_rescission_ids=("e" * 64,),
        alert_rescission_ids=("1" * 64,),
        precedent_revocation_receipt_ids=("2" * 64,),
        replacement_precedent_authority_id="3" * 64,
        training_label_ids=("label-1",),
        affected_citation_report_sha256="4" * 64,
        manifest_id="5" * 64,
    )


def _commit_spec() -> M5TableSpec:
    return next(
        spec for spec in M5_TABLE_SPECS if spec.table == "appeal_resolution_commit_receipts"
    )


def _provenance_receipt() -> M5StrongTrainingLabelProvenanceReceipt:
    review_authority_sha256 = "6" * 64
    reviewer_id = "reviewer-1"
    authored = M5AppealTrainingLabelInput(
        crop_id="7" * 64,
        bbox=BBoxXYXY(x1=1, y1=2, x2=11, y2=12),
        label_name="reagent_container_closed",
        label_value=True,
    )
    terminal_status = AppealStatus.OVERTURNED
    effect_root_sha256 = "8" * 64
    return M5StrongTrainingLabelProvenanceReceipt(
        run_id="run-1",
        case_id="case-1",
        appeal_id="appeal-1",
        label_id=sha256_hex(
            [
                "m5-appeal-training-label",
                1,
                review_authority_sha256,
                terminal_status,
                reviewer_id,
                authored.input_id,
            ]
        ),
        label_document_sha256="9" * 64,
        crop_id=authored.crop_id,
        reviewer_id=reviewer_id,
        quality=TrainingLabelQuality.APPEAL_CONFIRMED,
        authored_input=authored,
        review_authority_sha256=review_authority_sha256,
        terminal_authority_sha256="a" * 64,
        terminal_status=terminal_status,
        resolution_intent_id="b" * 64,
        resolution_document_sha256="c" * 64,
        resolution_commit_receipt_id=sha256_hex(
            ["m5-appeal-resolution-commit-receipt", 1, effect_root_sha256]
        ),
        resolution_commit_effect_root_sha256=effect_root_sha256,
        manifest_id="d" * 64,
        rule_version="laboratory-v1",
        detector_manifest_id="e" * 64,
    )


def _provenance_spec() -> M5TableSpec:
    return next(
        spec for spec in M5_TABLE_SPECS if spec.table == "strong_training_label_provenance_receipts"
    )


def _provenance_row(
    receipt: M5StrongTrainingLabelProvenanceReceipt,
    *,
    terminal_authority_sha256: str | None = None,
    raw_json: str | None = None,
) -> sqlite3.Row:
    raw = raw_json or canonical_json(receipt.model_dump(mode="json"))
    values: dict[str, object] = {
        "run_id": receipt.run_id,
        "provenance_id": receipt.provenance_id,
        "case_id": receipt.case_id,
        "appeal_id": receipt.appeal_id,
        "label_id": receipt.label_id,
        "label_document_sha256": receipt.label_document_sha256,
        "crop_id": receipt.crop_id,
        "reviewer_id": receipt.reviewer_id,
        "quality": receipt.quality.value,
        "authored_input_id": receipt.authored_input.input_id,
        "review_authority_sha256": receipt.review_authority_sha256,
        "terminal_authority_sha256": (
            terminal_authority_sha256 or receipt.terminal_authority_sha256
        ),
        "terminal_status": receipt.terminal_status.value,
        "resolution_intent_id": receipt.resolution_intent_id,
        "resolution_document_sha256": receipt.resolution_document_sha256,
        "resolution_commit_receipt_id": receipt.resolution_commit_receipt_id,
        "resolution_commit_effect_root_sha256": (receipt.resolution_commit_effect_root_sha256),
        "manifest_id": receipt.manifest_id,
        "rule_version": receipt.rule_version,
        "detector_manifest_id": receipt.detector_manifest_id,
        "provenance_json": raw,
        "document_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    }
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    columns = tuple(values)
    row = cast(
        sqlite3.Row | None,
        connection.execute(
            "SELECT " + ", ".join(f'? AS "{column}"' for column in columns),
            tuple(values[column] for column in columns),
        ).fetchone(),
    )
    connection.close()
    assert row is not None
    return row


def _commit_row(
    receipt: M5AppealResolutionCommitReceipt,
    *,
    effect_root_sha256: str | None = None,
) -> sqlite3.Row:
    raw = canonical_json(receipt.model_dump(mode="json"))
    values: dict[str, object] = {
        "run_id": receipt.run_id,
        "receipt_id": receipt.receipt_id,
        "effect_root_sha256": effect_root_sha256 or receipt.effect_root_sha256,
        "resolution_intent_id": receipt.resolution_intent_id,
        "resolution_document_sha256": receipt.resolution_document_sha256,
        "appeal_id": receipt.appeal_id,
        "appeal_authority_sha256": receipt.appeal_authority_sha256,
        "case_id": receipt.case_id,
        "source_case_revision": receipt.source_case_revision,
        "resulting_case_revision": receipt.resulting_case_revision,
        "resulting_case_document_sha256": receipt.resulting_case_document_sha256,
        "verdict_rescission_ids_json": canonical_json(list(receipt.verdict_rescission_ids)),
        "alert_rescission_ids_json": canonical_json(list(receipt.alert_rescission_ids)),
        "precedent_revocation_receipt_ids_json": canonical_json(
            list(receipt.precedent_revocation_receipt_ids)
        ),
        "replacement_precedent_authority_id": receipt.replacement_precedent_authority_id,
        "training_label_ids_json": canonical_json(list(receipt.training_label_ids)),
        "affected_citation_report_sha256": receipt.affected_citation_report_sha256,
        "manifest_id": receipt.manifest_id,
        "receipt_json": raw,
        "document_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    }
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    columns = tuple(values)
    row = cast(
        sqlite3.Row | None,
        connection.execute(
            "SELECT " + ", ".join(f'? AS "{column}"' for column in columns),
            tuple(values[column] for column in columns),
        ).fetchone(),
    )
    connection.close()
    assert row is not None
    return row


def _history_spec(table: str) -> M5TableSpec:
    return next(spec for spec in M5_TABLE_SPECS if spec.table == table)


def _row_from_values(values: dict[str, object]) -> sqlite3.Row:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    columns = tuple(values)
    row = cast(
        sqlite3.Row | None,
        connection.execute(
            "SELECT " + ", ".join(f'? AS "{column}"' for column in columns),
            tuple(values[column] for column in columns),
        ).fetchone(),
    )
    connection.close()
    assert row is not None
    return row


def _training_event_row(*, event_id: str | None = None) -> sqlite3.Row:
    event = _label_event()
    raw = canonical_json(event.model_dump(mode="json"))
    return _row_from_values(
        {
            "run_id": event.run_id,
            "sequence": event.sequence,
            "event_id": event_id or event.event_id,
            "source_identity": event.source_identity,
            "event_kind": event.event_kind.value,
            "source_id": event.source_id,
            "source_document_sha256": event.source_document_sha256,
            "manifest_id": event.manifest_id,
            "previous_event_sha256": event.previous_event_sha256,
            "event_sha256": event.event_sha256,
            "label_id": event.label_id,
            "event_json": raw,
            "document_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }
    )


def _registration_snapshot_row(*, label_count: int | None = None) -> sqlite3.Row:
    snapshot = _registration()
    raw = canonical_json(snapshot.model_dump(mode="json"))
    return _row_from_values(
        {
            "run_id": snapshot.run_id,
            "authority_id": snapshot.authority_id,
            "dataset_id": snapshot.dataset_id,
            "report_id": snapshot.report_id,
            "command_id": snapshot.command_id,
            "report_document_sha256": snapshot.report_document_sha256,
            "causal_cut_sequence": snapshot.causal_cut.sequence,
            "causal_cut_event_id": snapshot.causal_cut.event_id,
            "causal_cut_event_sha256": snapshot.causal_cut.event_sha256,
            "label_count": snapshot.label_count if label_count is None else label_count,
            "label_inventory_root_sha256": snapshot.label_inventory_root_sha256,
            "crop_count": snapshot.crop_count,
            "crop_inventory_root_sha256": snapshot.crop_inventory_root_sha256,
            "manifest_id": snapshot.manifest_id,
            "rule_version": snapshot.rule_version,
            "detector_manifest_id": snapshot.detector_manifest_id,
            "snapshot_json": raw,
            "document_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }
    )


def _crop_snapshot_row(*, case_revision: int | None = None) -> sqlite3.Row:
    snapshot = _crop_snapshot()
    crop = snapshot.crop_authority
    raw = canonical_json(snapshot.model_dump(mode="json"))
    return _row_from_values(
        {
            "run_id": snapshot.run_id,
            "authority_id": snapshot.authority_id,
            "registration_snapshot_authority_id": _registration().authority_id,
            "dataset_id": snapshot.dataset_id,
            "report_id": snapshot.report_id,
            "crop_id": crop.crop.crop_id,
            "crop_authority_sha256": crop.authority_sha256,
            "case_id": crop.case_id,
            "case_revision": snapshot.case_revision if case_revision is None else case_revision,
            "case_document_sha256": snapshot.case_document_sha256,
            "evidence_pack_id": snapshot.evidence_pack_id,
            "evidence_pack_version": snapshot.evidence_pack_version,
            "evidence_pack_document_sha256": snapshot.evidence_pack_document_sha256,
            "authority_json": raw,
            "document_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }
    )


def test_appeal_resolution_commit_receipt_is_strictly_decoded_for_projection() -> None:
    receipt = _commit_receipt()
    spec = _commit_spec()

    record = load_m5_record(_commit_row(receipt), spec, receipt.manifest_id)

    assert spec.kind is M5AuthorityKind.APPEAL_RESOLUTION_COMMIT
    assert M5_AUTHORITY_DOCUMENT_COLUMNS[spec.table] == ("receipt_json",)
    assert record == M5Record(
        kind=M5AuthorityKind.APPEAL_RESOLUTION_COMMIT,
        table="appeal_resolution_commit_receipts",
        artifact_id=receipt.receipt_id,
        row=record.row,
        document=receipt,
        canonical_document=canonical_json(receipt.model_dump(mode="json")),
    )


def test_appeal_resolution_commit_receipt_rejects_duplicated_index_tamper() -> None:
    receipt = _commit_receipt()

    with pytest.raises(M5IndexFailure, match="INDEX_BINDING_MISMATCH"):
        load_m5_record(
            _commit_row(receipt, effect_root_sha256="f" * 64),
            _commit_spec(),
            receipt.manifest_id,
        )


def test_strong_training_label_provenance_is_strictly_decoded_for_projection() -> None:
    receipt = _provenance_receipt()
    spec = _provenance_spec()

    record = load_m5_record(_provenance_row(receipt), spec, receipt.manifest_id)

    assert spec.kind is M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE
    assert M5_AUTHORITY_DOCUMENT_COLUMNS[spec.table] == ("provenance_json",)
    assert record == M5Record(
        kind=M5AuthorityKind.STRONG_TRAINING_LABEL_PROVENANCE,
        table="strong_training_label_provenance_receipts",
        artifact_id=receipt.provenance_id,
        row=record.row,
        document=receipt,
        canonical_document=canonical_json(receipt.model_dump(mode="json")),
    )


def test_strong_training_label_provenance_rejects_duplicated_index_tamper() -> None:
    receipt = _provenance_receipt()

    with pytest.raises(M5IndexFailure, match="INDEX_BINDING_MISMATCH"):
        load_m5_record(
            _provenance_row(receipt, terminal_authority_sha256="f" * 64),
            _provenance_spec(),
            receipt.manifest_id,
        )


def test_strong_training_label_provenance_rejects_noncanonical_json() -> None:
    receipt = _provenance_receipt()
    pretty = json.dumps(receipt.model_dump(mode="json"), indent=2)

    with pytest.raises(M5DocumentFailure, match="CANONICAL_DOCUMENT_INVALID"):
        load_m5_record(
            _provenance_row(receipt, raw_json=pretty),
            _provenance_spec(),
            receipt.manifest_id,
        )


@pytest.mark.parametrize(
    ("table", "row", "kind", "document_column"),
    [
        (
            "m5_training_causal_events",
            _training_event_row,
            M5AuthorityKind.TRAINING_CAUSAL_EVENT,
            "event_json",
        ),
        (
            "dataset_registration_snapshots",
            _registration_snapshot_row,
            M5AuthorityKind.DATASET_REGISTRATION_SNAPSHOT,
            "snapshot_json",
        ),
        (
            "dataset_crop_snapshots",
            _crop_snapshot_row,
            M5AuthorityKind.DATASET_CROP_SNAPSHOT,
            "authority_json",
        ),
    ],
)
def test_training_history_authorities_are_strictly_decoded_for_projection(
    table: str,
    row,
    kind: M5AuthorityKind,
    document_column: str,
) -> None:
    record = load_m5_record(row(), _history_spec(table), MANIFEST_ID)

    assert record.kind is kind
    assert M5_AUTHORITY_DOCUMENT_COLUMNS[table] == (document_column,)
    assert json.loads(record.canonical_document) == record.document.model_dump(mode="json")


@pytest.mark.parametrize(
    ("table", "row"),
    [
        ("m5_training_causal_events", lambda: _training_event_row(event_id="f" * 64)),
        ("dataset_registration_snapshots", lambda: _registration_snapshot_row(label_count=2)),
        ("dataset_crop_snapshots", lambda: _crop_snapshot_row(case_revision=8)),
    ],
)
def test_training_history_authorities_reject_duplicated_index_tamper(
    table: str,
    row,
) -> None:
    with pytest.raises(M5IndexFailure, match="INDEX_BINDING_MISMATCH"):
        load_m5_record(row(), _history_spec(table), MANIFEST_ID)
