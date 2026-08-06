"""Strict SQLite codecs for the M5 training-history authority graph.

The public helpers in this module deliberately do not own transactions.  M5
label append and dataset registration span several authority tables, so callers
must open the surrounding ``BEGIN IMMEDIATE`` transaction before inserting any
row.  Reads are bounded and validate canonical documents, duplicated indexes,
causal order, and normalized dataset snapshot roots.
"""

from __future__ import annotations

import hashlib
import sqlite3
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m5_training_history import (
    M5TrainingHistoryError,
    build_m5_dataset_registration_commit_event,
)
from labcourt.contracts.m5_training_history import (
    M5_TRAINING_CAUSAL_GENESIS_SHA256,
    MAX_M5_DATASET_SNAPSHOT_CROPS,
    MAX_M5_TRAINING_CAUSAL_EVENTS,
    M5DatasetCropSnapshotAuthority,
    M5DatasetRegistrationSnapshotAuthority,
    M5TrainingCausalEvent,
    M5TrainingCausalEventKind,
    m5_dataset_crop_inventory_root_sha256,
)

from .sqlite_repository import (
    RepositoryIntegrityError,
    _contract_document,
    _row_int,
    _row_optional_str,
    _row_str,
    _verify_contract_document,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def load_m5_training_causal_events(
    connection: sqlite3.Connection,
    run_id: str,
) -> tuple[M5TrainingCausalEvent, ...]:
    """Load and structurally validate one complete, bounded per-run ledger."""

    _require_text(run_id, "M5 training causal run_id")
    rows = connection.execute(
        """
        SELECT *
        FROM m5_training_causal_events
        WHERE run_id = ?
        ORDER BY sequence
        LIMIT ?
        """,
        (run_id, MAX_M5_TRAINING_CAUSAL_EVENTS + 1),
    ).fetchall()
    if len(rows) > MAX_M5_TRAINING_CAUSAL_EVENTS:
        raise RepositoryIntegrityError("M5 training causal event scan exceeds its hard limit")

    events = tuple(_training_event_from_row(row) for row in rows)
    expected_previous = M5_TRAINING_CAUSAL_GENESIS_SHA256
    manifest_id: str | None = None
    event_ids: set[str] = set()
    event_hashes: set[str] = set()
    source_identities: set[str] = set()
    source_keys: set[tuple[M5TrainingCausalEventKind, str]] = set()
    label_ids: set[str] = set()
    for expected_sequence, event in enumerate(events, start=1):
        source_key = (event.event_kind, event.source_id)
        if (
            event.run_id != run_id
            or event.sequence != expected_sequence
            or event.previous_event_sha256 != expected_previous
            or event.event_id in event_ids
            or event.event_sha256 in event_hashes
            or event.source_identity in source_identities
            or source_key in source_keys
        ):
            raise RepositoryIntegrityError("M5 training causal event chain is invalid")
        if manifest_id is None:
            manifest_id = event.manifest_id
        elif event.manifest_id != manifest_id:
            raise RepositoryIntegrityError("M5 training causal ledger crosses manifest scope")
        if event.label_id is not None:
            if event.label_id in label_ids:
                raise RepositoryIntegrityError("M5 training causal ledger repeats a label")
            label_ids.add(event.label_id)
        event_ids.add(event.event_id)
        event_hashes.add(event.event_sha256)
        source_identities.add(event.source_identity)
        source_keys.add(source_key)
        expected_previous = event.event_sha256
    return events


def insert_m5_training_causal_event(
    connection: sqlite3.Connection,
    event: M5TrainingCausalEvent,
) -> M5TrainingCausalEvent:
    """Append one already-constructed event inside a caller-owned transaction."""

    _require_transaction(connection, "M5 training causal event append")
    validated, raw, document_sha256 = _canonical_model(
        event,
        M5TrainingCausalEvent,
        "M5 training causal event",
    )
    prior = load_m5_training_causal_events(connection, validated.run_id)
    expected_sequence = len(prior) + 1
    expected_previous = M5_TRAINING_CAUSAL_GENESIS_SHA256 if not prior else prior[-1].event_sha256
    if (
        validated.sequence != expected_sequence
        or validated.previous_event_sha256 != expected_previous
        or (prior and validated.manifest_id != prior[-1].manifest_id)
    ):
        raise RepositoryIntegrityError("M5 training causal event is not the exact next append")

    try:
        connection.execute(
            """
            INSERT INTO m5_training_causal_events(
                run_id, sequence, event_id, source_identity, event_kind,
                source_id, source_document_sha256, manifest_id,
                previous_event_sha256, event_sha256, label_id,
                event_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                validated.run_id,
                validated.sequence,
                validated.event_id,
                validated.source_identity,
                validated.event_kind.value,
                validated.source_id,
                validated.source_document_sha256,
                validated.manifest_id,
                validated.previous_event_sha256,
                validated.event_sha256,
                validated.label_id,
                raw,
                document_sha256,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise RepositoryIntegrityError("M5 training causal event could not be appended") from exc

    replayed = load_m5_training_causal_events(connection, validated.run_id)
    if replayed != (*prior, validated):
        raise RepositoryIntegrityError("M5 training causal event append did not replay exactly")
    return validated


def load_m5_dataset_registration_snapshot(
    connection: sqlite3.Connection,
    run_id: str,
    authority_id: str,
) -> M5DatasetRegistrationSnapshotAuthority:
    """Require one exact registration header and validate its historical cut."""

    _require_text(run_id, "M5 dataset registration run_id")
    _require_text(authority_id, "M5 dataset registration authority_id")
    rows = connection.execute(
        """
        SELECT *
        FROM dataset_registration_snapshots
        WHERE run_id = ? AND authority_id = ?
        LIMIT 2
        """,
        (run_id, authority_id),
    ).fetchall()
    if len(rows) != 1:
        raise RepositoryIntegrityError(
            "M5 dataset registration snapshot does not resolve to exactly one row"
        )
    snapshot = _registration_snapshot_from_row(rows[0])
    if snapshot.run_id != run_id or snapshot.authority_id != authority_id:
        raise RepositoryIntegrityError("M5 dataset registration snapshot lookup is inconsistent")
    _require_valid_snapshot_cut(connection, snapshot, require_current_head=False)
    return snapshot


def insert_m5_dataset_registration_snapshot(
    connection: sqlite3.Connection,
    snapshot: M5DatasetRegistrationSnapshotAuthority,
) -> M5DatasetRegistrationSnapshotAuthority:
    """Insert a fixed-size registration header at the current causal head."""

    _require_transaction(connection, "M5 dataset registration snapshot insert")
    validated, raw, document_sha256 = _canonical_model(
        snapshot,
        M5DatasetRegistrationSnapshotAuthority,
        "M5 dataset registration snapshot",
    )
    _require_valid_snapshot_cut(connection, validated, require_current_head=True)
    cut = validated.causal_cut
    try:
        connection.execute(
            """
            INSERT INTO dataset_registration_snapshots(
                run_id, authority_id, dataset_id, report_id, command_id,
                report_document_sha256, causal_cut_sequence,
                causal_cut_event_id, causal_cut_event_sha256,
                label_count, label_inventory_root_sha256,
                crop_count, crop_inventory_root_sha256,
                manifest_id, rule_version, detector_manifest_id,
                snapshot_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                validated.run_id,
                validated.authority_id,
                validated.dataset_id,
                validated.report_id,
                validated.command_id,
                validated.report_document_sha256,
                cut.sequence,
                cut.event_id,
                cut.event_sha256,
                validated.label_count,
                validated.label_inventory_root_sha256,
                validated.crop_count,
                validated.crop_inventory_root_sha256,
                validated.manifest_id,
                validated.rule_version,
                validated.detector_manifest_id,
                raw,
                document_sha256,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise RepositoryIntegrityError(
            "M5 dataset registration snapshot could not be inserted"
        ) from exc
    replayed = load_m5_dataset_registration_snapshot(
        connection,
        validated.run_id,
        validated.authority_id,
    )
    if replayed != validated:
        raise RepositoryIntegrityError("M5 dataset registration snapshot did not replay exactly")
    return validated


def list_m5_dataset_crop_snapshots(
    connection: sqlite3.Connection,
    run_id: str,
    registration_snapshot_authority_id: str,
) -> tuple[M5DatasetCropSnapshotAuthority, ...]:
    """Load one complete normalized Crop inventory and verify its header root."""

    snapshot = load_m5_dataset_registration_snapshot(
        connection,
        run_id,
        registration_snapshot_authority_id,
    )
    rows = connection.execute(
        """
        SELECT *
        FROM dataset_crop_snapshots
        WHERE run_id = ? AND registration_snapshot_authority_id = ?
        ORDER BY crop_id
        LIMIT ?
        """,
        (run_id, registration_snapshot_authority_id, MAX_M5_DATASET_SNAPSHOT_CROPS + 1),
    ).fetchall()
    if len(rows) > MAX_M5_DATASET_SNAPSHOT_CROPS:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot scan exceeds its hard limit")
    authorities = tuple(
        _crop_snapshot_from_row(
            row,
            registration_snapshot_authority_id=registration_snapshot_authority_id,
        )
        for row in rows
    )
    _require_canonical_crop_inventory(authorities)
    if len(authorities) != snapshot.crop_count:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot count differs from its header")
    _require_crop_snapshot_scope(snapshot, authorities)
    try:
        observed_root = m5_dataset_crop_inventory_root_sha256(
            run_id=snapshot.run_id,
            dataset_id=snapshot.dataset_id,
            report_id=snapshot.report_id,
            authorities=authorities,
        )
    except (TypeError, ValueError) as exc:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot root is invalid") from exc
    if observed_root != snapshot.crop_inventory_root_sha256:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot root differs from its header")
    return authorities


def insert_m5_dataset_crop_snapshot(
    connection: sqlite3.Connection,
    registration_snapshot_authority_id: str,
    authority: M5DatasetCropSnapshotAuthority,
) -> M5DatasetCropSnapshotAuthority:
    """Insert one normalized Crop row; verify the root when the inventory closes."""

    _require_transaction(connection, "M5 dataset Crop snapshot insert")
    _require_text(
        registration_snapshot_authority_id,
        "M5 dataset registration snapshot authority_id",
    )
    validated, raw, document_sha256 = _canonical_model(
        authority,
        M5DatasetCropSnapshotAuthority,
        "M5 dataset Crop snapshot",
    )
    snapshot = load_m5_dataset_registration_snapshot(
        connection,
        validated.run_id,
        registration_snapshot_authority_id,
    )
    _require_crop_snapshot_scope(snapshot, (validated,))
    existing_rows = connection.execute(
        """
        SELECT *
        FROM dataset_crop_snapshots
        WHERE run_id = ? AND registration_snapshot_authority_id = ?
        ORDER BY crop_id
        LIMIT ?
        """,
        (
            validated.run_id,
            registration_snapshot_authority_id,
            MAX_M5_DATASET_SNAPSHOT_CROPS + 1,
        ),
    ).fetchall()
    if len(existing_rows) > MAX_M5_DATASET_SNAPSHOT_CROPS:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot scan exceeds its hard limit")
    existing = tuple(
        _crop_snapshot_from_row(
            row,
            registration_snapshot_authority_id=registration_snapshot_authority_id,
        )
        for row in existing_rows
    )
    _require_canonical_crop_inventory(existing)
    _require_crop_snapshot_scope(snapshot, existing)
    if len(existing) >= snapshot.crop_count:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot inventory is already complete")

    crop = validated.crop_authority.crop
    try:
        connection.execute(
            """
            INSERT INTO dataset_crop_snapshots(
                run_id, authority_id, registration_snapshot_authority_id,
                dataset_id, report_id, crop_id, crop_authority_sha256,
                case_id, case_revision, case_document_sha256,
                evidence_pack_id, evidence_pack_version,
                evidence_pack_document_sha256, authority_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                validated.run_id,
                validated.authority_id,
                registration_snapshot_authority_id,
                validated.dataset_id,
                validated.report_id,
                crop.crop_id,
                validated.crop_authority.authority_sha256,
                validated.crop_authority.case_id,
                validated.case_revision,
                validated.case_document_sha256,
                validated.evidence_pack_id,
                validated.evidence_pack_version,
                validated.evidence_pack_document_sha256,
                raw,
                document_sha256,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot could not be inserted") from exc

    rows = connection.execute(
        """
        SELECT *
        FROM dataset_crop_snapshots
        WHERE run_id = ? AND authority_id = ?
        LIMIT 2
        """,
        (validated.run_id, validated.authority_id),
    ).fetchall()
    if len(rows) != 1:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot insert is ambiguous")
    replayed = _crop_snapshot_from_row(
        rows[0],
        registration_snapshot_authority_id=registration_snapshot_authority_id,
    )
    if replayed != validated:
        raise RepositoryIntegrityError("M5 dataset Crop snapshot did not replay exactly")
    if len(existing) + 1 == snapshot.crop_count:
        closed = list_m5_dataset_crop_snapshots(
            connection,
            validated.run_id,
            registration_snapshot_authority_id,
        )
        if validated not in closed:
            raise RepositoryIntegrityError("M5 dataset Crop snapshot closure lost its append")
    return validated


def require_m5_dataset_registration_marker(
    connection: sqlite3.Connection,
    snapshot: M5DatasetRegistrationSnapshotAuthority,
) -> M5TrainingCausalEvent:
    """Require the unique causal marker immediately following ``snapshot``."""

    validated, _, _ = _canonical_model(
        snapshot,
        M5DatasetRegistrationSnapshotAuthority,
        "M5 dataset registration snapshot",
    )
    stored = load_m5_dataset_registration_snapshot(
        connection,
        validated.run_id,
        validated.authority_id,
    )
    if stored != validated:
        raise RepositoryIntegrityError("M5 dataset registration marker uses another snapshot")
    try:
        expected = build_m5_dataset_registration_commit_event(stored)
    except M5TrainingHistoryError as exc:
        raise RepositoryIntegrityError("M5 dataset registration marker cannot be derived") from exc
    events = load_m5_training_causal_events(connection, stored.run_id)
    matches = tuple(
        event
        for event in events
        if event.event_kind == M5TrainingCausalEventKind.DATASET_REGISTRATION_COMMITTED
        and event.source_id == stored.authority_id
    )
    if len(matches) != 1 or matches[0] != expected:
        raise RepositoryIntegrityError(
            "M5 dataset registration snapshot does not have its exact unique marker"
        )
    return matches[0]


def _training_event_from_row(row: sqlite3.Row) -> M5TrainingCausalEvent:
    raw = _row_str(row, "event_json")
    try:
        event = M5TrainingCausalEvent.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError("stored M5 training causal event is invalid") from exc
    _verify_contract_document(raw, event)
    indexed = (
        _row_str(row, "run_id") == event.run_id,
        _row_int(row, "sequence") == event.sequence,
        _row_str(row, "event_id") == event.event_id,
        _row_str(row, "source_identity") == event.source_identity,
        _row_str(row, "event_kind") == event.event_kind.value,
        _row_str(row, "source_id") == event.source_id,
        _row_str(row, "source_document_sha256") == event.source_document_sha256,
        _row_str(row, "manifest_id") == event.manifest_id,
        _row_str(row, "previous_event_sha256") == event.previous_event_sha256,
        _row_str(row, "event_sha256") == event.event_sha256,
        _row_optional_str(row, "label_id") == event.label_id,
        _row_str(row, "document_sha256") == _raw_sha256(raw),
    )
    if not all(indexed):
        raise RepositoryIntegrityError(
            "M5 training causal event indexes differ from canonical content"
        )
    return event


def _registration_snapshot_from_row(
    row: sqlite3.Row,
) -> M5DatasetRegistrationSnapshotAuthority:
    raw = _row_str(row, "snapshot_json")
    try:
        snapshot = M5DatasetRegistrationSnapshotAuthority.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError(
            "stored M5 dataset registration snapshot is invalid"
        ) from exc
    _verify_contract_document(raw, snapshot)
    cut = snapshot.causal_cut
    indexed = (
        _row_str(row, "run_id") == snapshot.run_id,
        _row_str(row, "authority_id") == snapshot.authority_id,
        _row_str(row, "dataset_id") == snapshot.dataset_id,
        _row_str(row, "report_id") == snapshot.report_id,
        _row_str(row, "command_id") == snapshot.command_id,
        _row_str(row, "report_document_sha256") == snapshot.report_document_sha256,
        _row_int(row, "causal_cut_sequence") == cut.sequence,
        _row_optional_str(row, "causal_cut_event_id") == cut.event_id,
        _row_str(row, "causal_cut_event_sha256") == cut.event_sha256,
        _row_int(row, "label_count") == snapshot.label_count,
        _row_str(row, "label_inventory_root_sha256") == snapshot.label_inventory_root_sha256,
        _row_int(row, "crop_count") == snapshot.crop_count,
        _row_str(row, "crop_inventory_root_sha256") == snapshot.crop_inventory_root_sha256,
        _row_str(row, "manifest_id") == snapshot.manifest_id,
        _row_str(row, "rule_version") == snapshot.rule_version,
        _row_str(row, "detector_manifest_id") == snapshot.detector_manifest_id,
        _row_str(row, "document_sha256") == _raw_sha256(raw),
    )
    if not all(indexed):
        raise RepositoryIntegrityError(
            "M5 dataset registration snapshot indexes differ from canonical content"
        )
    return snapshot


def _crop_snapshot_from_row(
    row: sqlite3.Row,
    *,
    registration_snapshot_authority_id: str,
) -> M5DatasetCropSnapshotAuthority:
    raw = _row_str(row, "authority_json")
    try:
        authority = M5DatasetCropSnapshotAuthority.model_validate_json(raw)
    except ValidationError as exc:
        raise RepositoryIntegrityError("stored M5 dataset Crop snapshot is invalid") from exc
    _verify_contract_document(raw, authority)
    crop_authority = authority.crop_authority
    indexed = (
        _row_str(row, "run_id") == authority.run_id,
        _row_str(row, "authority_id") == authority.authority_id,
        _row_str(row, "registration_snapshot_authority_id") == registration_snapshot_authority_id,
        _row_str(row, "dataset_id") == authority.dataset_id,
        _row_str(row, "report_id") == authority.report_id,
        _row_str(row, "crop_id") == crop_authority.crop.crop_id,
        _row_str(row, "crop_authority_sha256") == crop_authority.authority_sha256,
        _row_str(row, "case_id") == crop_authority.case_id,
        _row_int(row, "case_revision") == authority.case_revision,
        _row_str(row, "case_document_sha256") == authority.case_document_sha256,
        _row_str(row, "evidence_pack_id") == authority.evidence_pack_id,
        _row_int(row, "evidence_pack_version") == authority.evidence_pack_version,
        _row_str(row, "evidence_pack_document_sha256") == authority.evidence_pack_document_sha256,
        _row_str(row, "document_sha256") == _raw_sha256(raw),
    )
    if not all(indexed):
        raise RepositoryIntegrityError(
            "M5 dataset Crop snapshot indexes differ from canonical content"
        )
    return authority


def _require_valid_snapshot_cut(
    connection: sqlite3.Connection,
    snapshot: M5DatasetRegistrationSnapshotAuthority,
    *,
    require_current_head: bool,
) -> None:
    events = load_m5_training_causal_events(connection, snapshot.run_id)
    cut = snapshot.causal_cut
    if cut.sequence > len(events):
        raise RepositoryIntegrityError("M5 dataset registration causal cut is outside the ledger")
    if require_current_head and cut.sequence != len(events):
        raise RepositoryIntegrityError("M5 dataset registration causal cut is not the current head")
    if cut.sequence > 0:
        head = events[cut.sequence - 1]
        if head.event_id != cut.event_id or head.event_sha256 != cut.event_sha256:
            raise RepositoryIntegrityError("M5 dataset registration causal cut is not exact")
    prefix_label_count = sum(
        event.event_kind == M5TrainingCausalEventKind.TRAINING_LABEL_APPENDED
        for event in events[: cut.sequence]
    )
    if snapshot.label_count != prefix_label_count:
        raise RepositoryIntegrityError(
            "M5 dataset registration label count differs from its causal cut"
        )


def _require_crop_snapshot_scope(
    snapshot: M5DatasetRegistrationSnapshotAuthority,
    authorities: tuple[M5DatasetCropSnapshotAuthority, ...],
) -> None:
    for authority in authorities:
        crop = authority.crop_authority
        if (
            authority.run_id != snapshot.run_id
            or authority.dataset_id != snapshot.dataset_id
            or authority.report_id != snapshot.report_id
            or crop.run_id != snapshot.run_id
            or crop.manifest_id != snapshot.manifest_id
            or crop.rule_version != snapshot.rule_version
            or crop.detector_manifest_id != snapshot.detector_manifest_id
        ):
            raise RepositoryIntegrityError("M5 dataset Crop snapshot crosses header scope")


def _require_canonical_crop_inventory(
    authorities: tuple[M5DatasetCropSnapshotAuthority, ...],
) -> None:
    crop_ids = tuple(item.sort_key for item in authorities)
    authority_ids = tuple(item.authority_id for item in authorities)
    crop_authority_hashes = tuple(item.crop_authority.authority_sha256 for item in authorities)
    if (
        crop_ids != tuple(sorted(crop_ids))
        or len(crop_ids) != len(set(crop_ids))
        or len(authority_ids) != len(set(authority_ids))
        or len(crop_authority_hashes) != len(set(crop_authority_hashes))
    ):
        raise RepositoryIntegrityError("M5 dataset Crop snapshot inventory is not canonical")


def _canonical_model(
    value: object,
    model_type: type[_ModelT],
    name: str,
) -> tuple[_ModelT, str, str]:
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
        raw = _contract_document(rebuilt)
    except (AttributeError, TypeError, ValueError) as exc:
        raise RepositoryIntegrityError(f"{name} is invalid") from exc
    return rebuilt, raw, _raw_sha256(raw)


def _require_transaction(connection: sqlite3.Connection, operation: str) -> None:
    if not connection.in_transaction:
        raise RepositoryIntegrityError(f"{operation} requires a caller-owned transaction")


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise RepositoryIntegrityError(f"{name} must contain text")
    return value


def _raw_sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


__all__ = [
    "insert_m5_dataset_crop_snapshot",
    "insert_m5_dataset_registration_snapshot",
    "insert_m5_training_causal_event",
    "list_m5_dataset_crop_snapshots",
    "load_m5_dataset_registration_snapshot",
    "load_m5_training_causal_events",
    "require_m5_dataset_registration_marker",
]
