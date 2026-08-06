import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_repository import MigrationRunner
from labcourt.adapters.storage.sqlite_schema import (
    M5_AUTHORITY_INDEXES,
    M5_AUTHORITY_OBJECTS,
    M5_AUTHORITY_TABLES,
    M5_AUTHORITY_TRIGGERS,
    m5_authority_installed,
)

MIGRATIONS = Path(__file__).parents[2] / "src" / "labcourt" / "adapters" / "storage" / "migrations"
BUSY_TIMEOUT_MS = 5_000


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _install(tmp_path: Path) -> Path:
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, MIGRATIONS).apply_all() == tuple(range(1, 19))
    return database


def test_migration_0009_installs_the_complete_m5_authority_set(tmp_path: Path) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        observed = {
            (str(row[0]), str(row[1]))
            for row in connection.execute("SELECT type, name FROM sqlite_master")
        }
        assert m5_authority_installed(connection)
        assert {("table", name) for name in M5_AUTHORITY_TABLES} <= observed
        assert {("index", name) for name in M5_AUTHORITY_INDEXES} <= observed
        assert {("trigger", name) for name in M5_AUTHORITY_TRIGGERS} <= observed
        assert len(M5_AUTHORITY_OBJECTS) == 167
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("object_type", "object_name"),
    [
        ("table", "precedents"),
        ("table", "appeal_resolution_commit_receipts"),
        ("table", "strong_training_label_provenance_receipts"),
        ("table", "m5_training_causal_events"),
        ("table", "dataset_registration_snapshots"),
        ("table", "dataset_crop_snapshots"),
        ("index", "uq_alert_dispatch_receipts_success_outbox"),
        ("index", "uq_case_versions_revision_document_sha256"),
        ("index", "uq_training_labels_strong_provenance_binding"),
        ("index", "uq_m5_training_causal_events_exact_head"),
        ("index", "uq_evidence_packs_version_document_sha256"),
        ("index", "uq_precedent_lifecycle_appeal_present_prior"),
        ("trigger", "appeals_validate_contiguous_version"),
        ("trigger", "m5_immediate_safety_deliveries_no_update"),
        ("trigger", "precedent_conflict_batch_receipts_no_delete"),
        ("trigger", "m5_precedent_causal_events_validate_source"),
        ("trigger", "appeal_resolution_commit_receipts_no_delete"),
        ("trigger", "m5_training_causal_events_validate_source"),
        ("trigger", "dataset_artifacts_validate_registration_snapshot"),
        (
            "trigger",
            "appeal_resolution_commit_receipts_validate_training_provenance_closure",
        ),
    ],
)
def test_m5_connection_guard_rejects_any_missing_safety_object(
    tmp_path: Path,
    object_type: str,
    object_name: str,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        connection.execute(f'DROP {object_type.upper()} "{object_name}"')
        assert not m5_authority_installed(connection)
    finally:
        connection.close()


def _insert_precedent(
    connection: sqlite3.Connection,
    revision: int,
    *,
    citation_count: int = 0,
    status: str = "ACTIVE",
) -> None:
    connection.execute(
        """
        INSERT INTO precedents(
            run_id, precedent_id, revision, authority_id, status, source,
            evidence_class, violation_type, decision_direction, rule_version,
            source_case_id, citation_count, text_embedding_id,
            visual_embedding_ids_json, created_at, activation_not_before,
            activated_at, manifest_id, authority_json, document_sha256
        ) VALUES (
            'run-m5-migration', 'precedent-m5-migration', ?, ?, ?, 'PRESET',
            'PRESENCE', 'OPEN_FLAME', 'ESTABLISHED', 'rule-v1',
            NULL, ?, NULL, '[]', '2026-08-02T00:00:00.000000Z', NULL,
            '2026-08-02T00:00:00.000000Z', ?, '{}', ?
        )
        """,
        (
            revision,
            _sha(f"precedent-authority-{revision}"),
            status,
            citation_count,
            _sha("run-manifest"),
            _sha(f"precedent-document-{revision}"),
        ),
    )


def test_precedent_revisions_are_contiguous_and_rows_are_append_only(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="contiguous"):
            _insert_precedent(connection, 2)
        _insert_precedent(connection, 1)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE precedents SET status = 'REVOKED' WHERE run_id = ?",
                ("run-m5-migration",),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM precedents WHERE run_id = ?",
                ("run-m5-migration",),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO precedents
                SELECT * FROM precedents WHERE run_id = ?
                """,
                ("run-m5-migration",),
            )
    finally:
        connection.close()


def test_citation_migration_freezes_semantic_count_and_has_no_successor_columns(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        citation_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(precedent_citations)")
        }
        assert "retrieval_result_id" in citation_columns
        assert "resulting_authority_id" not in citation_columns
        assert "resulting_revision" not in citation_columns
        with pytest.raises(sqlite3.IntegrityError, match="citation_count = 0"):
            _insert_precedent(connection, 1, citation_count=1)
    finally:
        connection.close()


def test_appeal_present_activation_receipt_is_unique_per_exact_prior(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    values = (
        "run-m5-migration",
        _sha("activation-receipt-1"),
        "precedent-m5-migration",
        _sha("activation-prior"),
        _sha("activation-result"),
        _sha("run-manifest"),
        _sha("activation-context-1"),
        _sha("activation-document-1"),
    )
    try:
        connection.execute(
            """
            INSERT INTO precedent_lifecycle_receipts(
                run_id, receipt_id, receipt_kind, outcome,
                primary_precedent_id, primary_prior_authority_id,
                primary_prior_revision, primary_resulting_authority_id,
                primary_resulting_revision, manifest_id, receipt_json,
                context_json, context_sha256, document_sha256
            ) VALUES (?, ?, 'ACTIVATION', 'APPEAL_PRESENT', ?, ?, 1, ?, 1, ?, '{}', '{}', ?, ?)
            """,
            values,
        )
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint failed"):
            connection.execute(
                """
                INSERT INTO precedent_lifecycle_receipts(
                    run_id, receipt_id, receipt_kind, outcome,
                    primary_precedent_id, primary_prior_authority_id,
                    primary_prior_revision, primary_resulting_authority_id,
                    primary_resulting_revision, manifest_id, receipt_json,
                    context_json, context_sha256, document_sha256
                ) VALUES (?, ?, 'ACTIVATION', 'APPEAL_PRESENT', ?, ?, 1, ?, 1, ?, '{}', '{}', ?, ?)
                """,
                (
                    values[0],
                    _sha("activation-receipt-2"),
                    values[2],
                    values[3],
                    values[4],
                    values[5],
                    _sha("activation-context-2"),
                    _sha("activation-document-2"),
                ),
            )
    finally:
        connection.close()


def test_conflict_batch_authority_and_receipt_rows_are_append_only(tmp_path: Path) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    batch_id = _sha("conflict-batch")
    receipt_id = _sha("conflict-batch-receipt")
    causal_cut_id = _sha("conflict-causal-cut")
    try:
        connection.execute(
            """
            INSERT INTO precedent_conflict_batches(
                run_id, batch_authority_id, policy_id, config_sha256,
                causal_cut_id, authority_event_sequence,
                authority_event_sha256, active_head_root_sha256,
                scan_limit, candidate_count, evaluated_pair_count, edge_count,
                manifest_id, authority_json, policy_json, policy_sha256,
                document_sha256
            ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, 3, 0, 0, 0, ?, '{}', '{}', ?, ?)
            """,
            (
                "run-m5-migration",
                batch_id,
                _sha("conflict-policy"),
                _sha("config"),
                causal_cut_id,
                "0" * 64,
                _sha("active-head-root"),
                _sha("run-manifest"),
                _sha("policy-document"),
                _sha("batch-document"),
            ),
        )
        connection.execute(
            """
            INSERT INTO precedent_conflict_batch_receipts(
                run_id, receipt_id, batch_authority_id, causal_cut_id, result_count,
                changed_count, manifest_id, receipt_json, document_sha256
            ) VALUES (?, ?, ?, ?, 0, 0, ?, '{}', ?)
            """,
            (
                "run-m5-migration",
                receipt_id,
                batch_id,
                causal_cut_id,
                _sha("run-manifest"),
                _sha("receipt-document"),
            ),
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE precedent_conflict_batches SET scan_limit = 2 WHERE run_id = ?",
                ("run-m5-migration",),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM precedent_conflict_batch_receipts WHERE run_id = ?",
                ("run-m5-migration",),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO precedent_conflict_batch_receipts
                SELECT * FROM precedent_conflict_batch_receipts WHERE run_id = ?
                """,
                ("run-m5-migration",),
            )
    finally:
        connection.close()


def _insert_attempt(
    connection: sqlite3.Connection,
    *,
    attempt_number: int,
) -> str:
    attempt_id = _sha(f"attempt-{attempt_number}")
    connection.execute(
        """
        INSERT INTO alert_dispatch_attempts(
            run_id, attempt_id, outbox_id, alert_id, case_id,
            attempt_number, fence, lease_owner_sha256, started_at,
            lease_expires_at, channel_capability_id, idempotency_key,
            attempt_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)
        """,
        (
            "run-m5-migration",
            attempt_id,
            _sha("outbox"),
            "alert-m5-migration",
            "case-m5-migration",
            attempt_number,
            attempt_number,
            _sha("worker-m5-migration"),
            f"2026-08-02T12:00:0{attempt_number}.000000Z",
            f"2026-08-02T12:01:0{attempt_number}.000000Z",
            _sha("fake-alert-capability"),
            "alert-m5-migration",
            _sha(f"attempt-document-{attempt_number}"),
        ),
    )
    return attempt_id


def test_dispatch_attempts_require_contiguous_retry_receipts_and_one_terminal(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """
            INSERT INTO alert_outbox(
                run_id, outbox_id, alert_authority_id, alert_id, case_id,
                case_authority_sha256, policy_request_id, priority,
                idempotency_key, manifest_id, outbox_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'HIGH', ?, ?, '{}', ?)
            """,
            (
                "run-m5-migration",
                _sha("outbox"),
                _sha("alert-authority"),
                "alert-m5-migration",
                "case-m5-migration",
                _sha("case-authority"),
                _sha("policy-request"),
                "alert-m5-migration",
                _sha("run-manifest"),
                _sha("outbox-document"),
            ),
        )
        with pytest.raises(sqlite3.IntegrityError, match="contiguous"):
            _insert_attempt(connection, attempt_number=2)
        first_attempt_id = _insert_attempt(connection, attempt_number=1)

        def insert_receipt(
            attempt_id: str,
            attempt_number: int,
            *,
            disposition: str,
            continuation: str,
            suffix: str = "",
        ) -> None:
            connection.execute(
                """
                INSERT INTO alert_dispatch_receipts(
                    run_id, receipt_id, attempt_id, outbox_id, alert_id, case_id,
                    attempt_number, fence, lease_owner_sha256,
                    channel_capability_id, idempotency_key, disposition, continuation,
                    receipt_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)
                """,
                (
                    "run-m5-migration",
                    _sha(f"receipt-{attempt_number}-{suffix}"),
                    attempt_id,
                    _sha("outbox"),
                    "alert-m5-migration",
                    "case-m5-migration",
                    attempt_number,
                    attempt_number,
                    _sha("worker-m5-migration"),
                    _sha("fake-alert-capability"),
                    "alert-m5-migration",
                    disposition,
                    continuation,
                    _sha(f"receipt-document-{attempt_number}-{suffix}"),
                ),
            )

        with pytest.raises(sqlite3.IntegrityError, match="retry authority"):
            _insert_attempt(connection, attempt_number=2)
        insert_receipt(
            first_attempt_id,
            1,
            disposition="RETRYABLE_FAILURE",
            continuation="RETRY_ALLOWED",
        )
        second_attempt_id = _insert_attempt(connection, attempt_number=2)
        insert_receipt(
            second_attempt_id,
            2,
            disposition="SUCCEEDED",
            continuation="CLOSED",
        )
        with pytest.raises(sqlite3.IntegrityError, match="retry authority"):
            _insert_attempt(connection, attempt_number=3)
        with pytest.raises(sqlite3.IntegrityError):
            insert_receipt(
                second_attempt_id,
                2,
                disposition="SUCCEEDED",
                continuation="CLOSED",
                suffix="duplicate",
            )
    finally:
        connection.close()


def _insert_appeal_resolution_commit_receipt(
    connection: sqlite3.Connection,
    *,
    suffix: str = "",
    precedent_revocation_receipt_ids: tuple[str, ...] = (),
) -> tuple[str, str]:
    receipt_id = _sha(f"appeal-commit-receipt{suffix}")
    document_sha256 = _sha(f"appeal-commit-document{suffix}")
    overturned = bool(precedent_revocation_receipt_ids)
    verdict_rescission_ids = [_sha(f"verdict-rescission{suffix}")] if overturned else []
    replacement_precedent_authority_id = (
        _sha(f"replacement-precedent-authority{suffix}") if overturned else None
    )
    training_label_ids = [f"appeal-training-label{suffix}"] if overturned else []
    connection.execute(
        """
        INSERT INTO appeal_resolution_commit_receipts(
            run_id, receipt_id, effect_root_sha256, resolution_intent_id,
            resolution_document_sha256, appeal_id, appeal_authority_sha256,
            case_id, source_case_revision, resulting_case_revision,
            resulting_case_document_sha256, verdict_rescission_ids_json,
            alert_rescission_ids_json, precedent_revocation_receipt_ids_json,
            replacement_precedent_authority_id, training_label_ids_json,
            affected_citation_report_sha256, manifest_id, receipt_json,
            document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 4, ?, ?, '[]', ?, ?, ?, ?, ?, '{}', ?)
        """,
        (
            "run-m5-migration",
            receipt_id,
            _sha(f"appeal-effect-root{suffix}"),
            _sha(f"appeal-resolution-intent{suffix}"),
            _sha(f"appeal-resolution-document{suffix}"),
            f"appeal-m5-migration{suffix}",
            _sha(f"appeal-authority{suffix}"),
            f"case-m5-migration{suffix}",
            _sha(f"resulting-case-document{suffix}"),
            json.dumps(verdict_rescission_ids),
            json.dumps(precedent_revocation_receipt_ids),
            replacement_precedent_authority_id,
            json.dumps(training_label_ids),
            _sha(f"affected-citation-report{suffix}"),
            _sha("run-manifest"),
            document_sha256,
        ),
    )
    return receipt_id, document_sha256


def _insert_causal_event(
    connection: sqlite3.Connection,
    *,
    sequence: int,
    event_kind: str,
    source_id: str,
    source_document_sha256: str,
    previous_event_sha256: str,
    precedent_id: str | None = None,
    precedent_authority_id: str | None = None,
    precedent_revision: int | None = None,
    citation_kind: str | None = None,
    tag: str = "",
    run_id: str = "run-m5-migration",
    manifest_id: str | None = None,
) -> str:
    resolved_manifest_id = manifest_id or _sha("run-manifest")
    event_id = _sha(f"causal-event-id-{sequence}-{event_kind}-{source_id}-{tag}")
    event_sha256 = _sha(f"causal-event-sha-{sequence}-{event_kind}-{source_id}-{tag}")
    source_identity_sha256 = _sha(f"causal-source-{event_kind}-{source_id}")
    payload = {
        "schema_version": "m5-precedent-causal-event-v1",
        "run_id": run_id,
        "sequence": sequence,
        "event_id": event_id,
        "source_identity_sha256": source_identity_sha256,
        "event_kind": event_kind,
        "source_id": source_id,
        "precedent_id": precedent_id,
        "precedent_authority_id": precedent_authority_id,
        "precedent_revision": precedent_revision,
        "citation_kind": citation_kind,
        "manifest_id": resolved_manifest_id,
        "source_document_sha256": source_document_sha256,
        "previous_event_sha256": previous_event_sha256,
        "event_sha256": event_sha256,
    }
    connection.execute(
        """
        INSERT INTO m5_precedent_causal_events(
            run_id, sequence, event_id, source_identity_sha256, event_kind,
            source_id, precedent_id, precedent_authority_id,
            precedent_revision, citation_kind, manifest_id,
            source_document_sha256, previous_event_sha256, event_sha256,
            event_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            sequence,
            event_id,
            source_identity_sha256,
            event_kind,
            source_id,
            precedent_id,
            precedent_authority_id,
            precedent_revision,
            citation_kind,
            resolved_manifest_id,
            source_document_sha256,
            previous_event_sha256,
            event_sha256,
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            _sha(f"causal-event-document-{sequence}-{event_kind}-{source_id}-{tag}"),
        ),
    )
    return event_sha256


def test_appeal_commit_receipt_schema_has_exact_durable_bindings(tmp_path: Path) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(appeal_resolution_commit_receipts)")
        }
        assert columns == {
            "run_id",
            "receipt_id",
            "effect_root_sha256",
            "resolution_intent_id",
            "resolution_document_sha256",
            "appeal_id",
            "appeal_authority_sha256",
            "case_id",
            "source_case_revision",
            "resulting_case_revision",
            "resulting_case_document_sha256",
            "verdict_rescission_ids_json",
            "alert_rescission_ids_json",
            "precedent_revocation_receipt_ids_json",
            "replacement_precedent_authority_id",
            "training_label_ids_json",
            "affected_citation_report_sha256",
            "manifest_id",
            "receipt_json",
            "document_sha256",
        }

        grouped_foreign_keys: dict[tuple[int, str], list[tuple[int, str, str]]] = {}
        for row in connection.execute("PRAGMA foreign_key_list(appeal_resolution_commit_receipts)"):
            grouped_foreign_keys.setdefault((int(row[0]), str(row[2])), []).append(
                (int(row[1]), str(row[3]), str(row[4]))
            )
        observed_foreign_keys = {
            (
                parent,
                tuple((source, target) for _, source, target in sorted(bindings)),
            )
            for (_, parent), bindings in grouped_foreign_keys.items()
        }
        assert observed_foreign_keys == {
            ("runs", (("run_id", "run_id"), ("manifest_id", "manifest_id"))),
            (
                "case_versions",
                (
                    ("run_id", "run_id"),
                    ("case_id", "case_id"),
                    ("resulting_case_revision", "revision"),
                    ("resulting_case_document_sha256", "document_sha256"),
                ),
            ),
            (
                "case_versions",
                (
                    ("run_id", "run_id"),
                    ("case_id", "case_id"),
                    ("source_case_revision", "revision"),
                ),
            ),
            (
                "appeals",
                (
                    ("run_id", "run_id"),
                    ("appeal_id", "appeal_id"),
                    ("appeal_authority_sha256", "authority_sha256"),
                ),
            ),
            (
                "appeal_resolution_receipts",
                (
                    ("run_id", "run_id"),
                    ("resolution_intent_id", "intent_id"),
                    ("resolution_document_sha256", "document_sha256"),
                ),
            ),
        }
    finally:
        connection.close()


def test_appeal_commit_receipt_is_append_only_and_a_strict_causal_source(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        receipt_id, document_sha256 = _insert_appeal_resolution_commit_receipt(connection)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE appeal_resolution_commit_receipts SET receipt_json = '{}'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM appeal_resolution_commit_receipts")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO appeal_resolution_commit_receipts
                SELECT * FROM appeal_resolution_commit_receipts
                """
            )

        with pytest.raises(sqlite3.IntegrityError, match="source or index binding"):
            _insert_causal_event(
                connection,
                sequence=1,
                event_kind="APPEAL_RESOLUTION_COMMITTED",
                source_id=receipt_id,
                source_document_sha256=_sha("wrong-appeal-commit-document"),
                previous_event_sha256="0" * 64,
                tag="wrong-source-document",
            )
        _insert_causal_event(
            connection,
            sequence=1,
            event_kind="APPEAL_RESOLUTION_COMMITTED",
            source_id=receipt_id,
            source_document_sha256=document_sha256,
            previous_event_sha256="0" * 64,
        )
    finally:
        connection.close()


def test_appeal_commit_marker_rejects_uncommitted_revocation_inventory(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    missing_revocation_receipt_id = _sha("missing-revocation-receipt")
    try:
        values = _seed_strong_provenance_authorities(
            connection,
            terminal_status="OVERTURNED",
        )
        connection.execute("BEGIN")
        _insert_strong_provenance(connection, values)
        _insert_strong_training_label(connection, values)
        _insert_strong_provenance_commit(
            connection,
            values,
            precedent_revocation_receipt_ids=(missing_revocation_receipt_id,),
        )
        connection.commit()
        with pytest.raises(sqlite3.IntegrityError, match="semantic order"):
            _insert_causal_event(
                connection,
                sequence=1,
                event_kind="APPEAL_RESOLUTION_COMMITTED",
                source_id=values["resolution_commit_receipt_id"],
                source_document_sha256=_sha("provenance-commit-document"),
                previous_event_sha256="0" * 64,
                run_id=values["run_id"],
                manifest_id=values["manifest_id"],
            )
    finally:
        connection.close()


def test_revocation_marker_is_strictly_bound_and_adjacent_to_revoked_authority(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    precedent_id = "precedent-m5-migration"
    prior_authority_id = _sha("precedent-authority-1")
    revoked_authority_id = _sha("precedent-authority-2")
    revocation_receipt_id = _sha("revocation-receipt")
    revocation_document_sha256 = _sha("revocation-document")
    try:
        _insert_precedent(connection, 1)
        _insert_precedent(connection, 2, status="REVOKED")
        _insert_precedent(connection, 3)
        connection.execute(
            """
            INSERT INTO precedent_lifecycle_receipts(
                run_id, receipt_id, receipt_kind, outcome,
                primary_precedent_id, primary_prior_authority_id,
                primary_prior_revision, primary_resulting_authority_id,
                primary_resulting_revision, manifest_id, receipt_json,
                context_json, context_sha256, document_sha256
            ) VALUES (?, ?, 'REVOCATION', 'REVOKED', ?, ?, 1, ?, 2, ?, '{}', '{}', ?, ?)
            """,
            (
                "run-m5-migration",
                revocation_receipt_id,
                precedent_id,
                prior_authority_id,
                revoked_authority_id,
                _sha("run-manifest"),
                _sha("revocation-context"),
                revocation_document_sha256,
            ),
        )
        first_event_sha256 = _insert_causal_event(
            connection,
            sequence=1,
            event_kind="PRECEDENT_AUTHORITY_APPENDED",
            source_id=prior_authority_id,
            source_document_sha256=_sha("precedent-document-1"),
            previous_event_sha256="0" * 64,
            precedent_id=precedent_id,
            precedent_authority_id=prior_authority_id,
            precedent_revision=1,
        )
        revoked_event_sha256 = _insert_causal_event(
            connection,
            sequence=2,
            event_kind="PRECEDENT_AUTHORITY_APPENDED",
            source_id=revoked_authority_id,
            source_document_sha256=_sha("precedent-document-2"),
            previous_event_sha256=first_event_sha256,
            precedent_id=precedent_id,
            precedent_authority_id=revoked_authority_id,
            precedent_revision=2,
        )

        with pytest.raises(sqlite3.IntegrityError, match="semantic order"):
            _insert_causal_event(
                connection,
                sequence=3,
                event_kind="PRECEDENT_AUTHORITY_APPENDED",
                source_id=_sha("precedent-authority-3"),
                source_document_sha256=_sha("precedent-document-3"),
                previous_event_sha256=revoked_event_sha256,
                precedent_id=precedent_id,
                precedent_authority_id=_sha("precedent-authority-3"),
                precedent_revision=3,
                tag="skipped-revocation-marker",
            )
        with pytest.raises(sqlite3.IntegrityError, match="source or index binding"):
            _insert_causal_event(
                connection,
                sequence=3,
                event_kind="PRECEDENT_REVOCATION_COMMITTED",
                source_id=revocation_receipt_id,
                source_document_sha256=_sha("wrong-revocation-document"),
                previous_event_sha256=revoked_event_sha256,
                precedent_id=precedent_id,
                precedent_authority_id=revoked_authority_id,
                precedent_revision=2,
                tag="wrong-source-document",
            )
        _insert_causal_event(
            connection,
            sequence=3,
            event_kind="PRECEDENT_REVOCATION_COMMITTED",
            source_id=revocation_receipt_id,
            source_document_sha256=revocation_document_sha256,
            previous_event_sha256=revoked_event_sha256,
            precedent_id=precedent_id,
            precedent_authority_id=revoked_authority_id,
            precedent_revision=2,
        )
    finally:
        connection.close()


def _seed_strong_provenance_authorities(
    connection: sqlite3.Connection,
    *,
    terminal_status: str = "UPHELD",
) -> dict[str, str]:
    quality = "APPEAL_CONFIRMED" if terminal_status == "OVERTURNED" else "HUMAN_CONFIRMED"
    values = {
        "run_id": "run-m5-provenance",
        "manifest_id": _sha("provenance-manifest"),
        "case_id": "case-m5-provenance",
        "appeal_id": "appeal-m5-provenance",
        "reviewer_id": "reviewer-m5-provenance",
        "review_authority_sha256": _sha("provenance-review-authority"),
        "terminal_authority_sha256": _sha("provenance-terminal-authority"),
        "resolution_intent_id": _sha("provenance-resolution-intent"),
        "resolution_document_sha256": _sha("provenance-resolution-document"),
        "resolution_commit_receipt_id": _sha("provenance-commit-receipt"),
        "resolution_commit_effect_root_sha256": _sha("provenance-commit-effect"),
        "label_id": _sha("provenance-label"),
        "label_document_sha256": _sha("provenance-label-document"),
        "crop_id": _sha("provenance-crop"),
        "authored_input_id": _sha("provenance-authored-input"),
        "provenance_id": _sha("provenance-receipt"),
        "rule_version": "rule-v1",
        "detector_manifest_id": _sha("provenance-detector"),
        "evidence_pack_id": _sha("provenance-evidence-pack"),
        "evidence_pack_document_sha256": _sha("provenance-evidence-pack-document"),
        "resulting_case_document_sha256": _sha("provenance-resulting-case"),
        "terminal_status": terminal_status,
        "quality": quality,
    }
    connection.execute(
        """
        INSERT INTO runs(
            run_id, manifest_id, revision, audit_head_sequence,
            audit_head_hash, registered_at
        ) VALUES (?, ?, 0, -1, ?, '2026-08-03T00:00:00.000000Z')
        """,
        (values["run_id"], values["manifest_id"], "0" * 64),
    )
    connection.execute(
        """
        INSERT INTO cases(
            run_id, case_id, event_id, manifest_id, status, current_revision,
            latest_pack_id, latest_pack_version, event_json, event_sha256,
            created_audit_sequence
        ) VALUES (?, ?, ?, ?, 'APPEAL_RESOLVED', 4, NULL, NULL, '{}', ?, 0)
        """,
        (
            values["run_id"],
            values["case_id"],
            _sha("provenance-case-event"),
            values["manifest_id"],
            _sha("provenance-case-event-document"),
        ),
    )
    connection.executemany(
        """
        INSERT INTO case_versions(
            run_id, case_id, revision, status, case_json, document_sha256,
            audit_sequence
        ) VALUES (?, ?, ?, 'APPEAL_RESOLVED', '{}', ?, ?)
        """,
        (
            (
                values["run_id"],
                values["case_id"],
                1,
                _sha("provenance-source-case"),
                1,
            ),
            (
                values["run_id"],
                values["case_id"],
                4,
                values["resulting_case_document_sha256"],
                4,
            ),
        ),
    )
    connection.execute(
        """
        INSERT INTO evidence_packs(
            run_id, pack_id, case_id, manifest_id, version, complete,
            pack_input_sha256, closure_input_sha256, pack_json,
            document_sha256, created_audit_sequence
        ) VALUES (?, ?, ?, ?, 1, 1, ?, ?, '{}', ?, 0)
        """,
        (
            values["run_id"],
            values["evidence_pack_id"],
            values["case_id"],
            values["manifest_id"],
            _sha("provenance-pack-input"),
            _sha("provenance-pack-closure-input"),
            values["evidence_pack_document_sha256"],
        ),
    )
    first_authority = _sha("provenance-submitted-authority")
    appeal_rows = (
        (1, first_authority, None, "SUBMITTED", None),
        (
            2,
            values["review_authority_sha256"],
            first_authority,
            "UNDER_REVIEW",
            values["reviewer_id"],
        ),
        (
            3,
            values["terminal_authority_sha256"],
            values["review_authority_sha256"],
            terminal_status,
            values["reviewer_id"],
        ),
    )
    for version, authority_sha256, previous, status, reviewer in appeal_rows:
        connection.execute(
            """
            INSERT INTO appeals(
                run_id, appeal_id, version, authority_sha256,
                previous_authority_sha256, case_id, status,
                assigned_reviewer_id, source_case_revision,
                source_case_authority_sha256, source_verdict_id,
                source_verdict_version, source_verdict_sha256, source_decision,
                text_embedding_manifest_id, visual_embedding_manifest_id,
                manifest_id, rule_version, authority_json, document_sha256
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?, 'ESTABLISHED',
                ?, ?, ?, ?, '{}', ?
            )
            """,
            (
                values["run_id"],
                values["appeal_id"],
                version,
                authority_sha256,
                previous,
                values["case_id"],
                status,
                reviewer,
                _sha("provenance-source-case-authority"),
                _sha("provenance-source-verdict"),
                _sha("provenance-source-verdict-document"),
                _sha("provenance-text-embedding"),
                _sha("provenance-visual-embedding"),
                values["manifest_id"],
                values["rule_version"],
                _sha(f"provenance-appeal-document-{version}"),
            ),
        )
    intent_json = json.dumps(
        {
            "training_labels": [
                {
                    "label_id": values["label_id"],
                    "case_id": values["case_id"],
                    "crop_id": values["crop_id"],
                    "reviewer_id": values["reviewer_id"],
                    "quality": quality,
                    "rule_version": values["rule_version"],
                    "detector_manifest_id": values["detector_manifest_id"],
                    "source": f"appeal-review:{values['appeal_id']}",
                    "excluded_reason": None,
                }
            ]
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    connection.execute(
        """
        INSERT INTO appeal_resolution_receipts(
            run_id, intent_id, appeal_id, appeal_authority_sha256, case_id,
            final_decision, final_decision_changed,
            affected_citation_report_sha256, manifest_id, intent_json,
            document_sha256
        ) VALUES (?, ?, ?, ?, ?, 'ESTABLISHED', 0, ?, ?, ?, ?)
        """,
        (
            values["run_id"],
            values["resolution_intent_id"],
            values["appeal_id"],
            values["terminal_authority_sha256"],
            values["case_id"],
            _sha("provenance-citation-report"),
            values["manifest_id"],
            intent_json,
            values["resolution_document_sha256"],
        ),
    )
    connection.commit()
    connection.execute("PRAGMA foreign_keys = ON")
    assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
    return values


def _insert_strong_provenance(
    connection: sqlite3.Connection,
    values: dict[str, str],
) -> None:
    provenance = {
        "schema_version": "m5-strong-training-label-provenance-receipt-v1",
        "run_id": values["run_id"],
        "case_id": values["case_id"],
        "appeal_id": values["appeal_id"],
        "label_id": values["label_id"],
        "label_document_sha256": values["label_document_sha256"],
        "crop_id": values["crop_id"],
        "reviewer_id": values["reviewer_id"],
        "quality": values["quality"],
        "authored_input": {
            "crop_id": values["crop_id"],
            "bbox": {"x1": 0, "y1": 0, "x2": 1, "y2": 1},
            "label_name": "helmet",
            "label_value": True,
            "input_id": values["authored_input_id"],
        },
        "review_authority_sha256": values["review_authority_sha256"],
        "terminal_authority_sha256": values["terminal_authority_sha256"],
        "terminal_status": values["terminal_status"],
        "resolution_intent_id": values["resolution_intent_id"],
        "resolution_document_sha256": values["resolution_document_sha256"],
        "resolution_commit_receipt_id": values["resolution_commit_receipt_id"],
        "resolution_commit_effect_root_sha256": values["resolution_commit_effect_root_sha256"],
        "manifest_id": values["manifest_id"],
        "rule_version": values["rule_version"],
        "detector_manifest_id": values["detector_manifest_id"],
        "provenance_id": values["provenance_id"],
    }
    connection.execute(
        """
        INSERT INTO strong_training_label_provenance_receipts(
            run_id, provenance_id, case_id, appeal_id, label_id,
            label_document_sha256, crop_id, reviewer_id, quality,
            authored_input_id, review_authority_sha256,
            terminal_authority_sha256, terminal_status,
            resolution_intent_id, resolution_document_sha256,
            resolution_commit_receipt_id,
            resolution_commit_effect_root_sha256, manifest_id, rule_version,
            detector_manifest_id, provenance_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            values["run_id"],
            values["provenance_id"],
            values["case_id"],
            values["appeal_id"],
            values["label_id"],
            values["label_document_sha256"],
            values["crop_id"],
            values["reviewer_id"],
            values["quality"],
            values["authored_input_id"],
            values["review_authority_sha256"],
            values["terminal_authority_sha256"],
            values["terminal_status"],
            values["resolution_intent_id"],
            values["resolution_document_sha256"],
            values["resolution_commit_receipt_id"],
            values["resolution_commit_effect_root_sha256"],
            values["manifest_id"],
            values["rule_version"],
            values["detector_manifest_id"],
            json.dumps(provenance, separators=(",", ":"), sort_keys=True),
            _sha("provenance-receipt-document"),
        ),
    )


def _insert_training_causal_event(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    manifest_id: str,
    event_kind: str,
    source_id: str,
    source_document_sha256: str,
    label_id: str | None = None,
    sequence: int | None = None,
    previous_event_sha256: str | None = None,
    tag: str = "",
    payload_source_id: str | None = None,
) -> dict[str, str | int | None]:
    if sequence is None:
        row = connection.execute(
            """
            SELECT sequence, event_sha256
            FROM m5_training_causal_events
            WHERE run_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        sequence = 1 if row is None else int(row[0]) + 1
        if previous_event_sha256 is None:
            previous_event_sha256 = "0" * 64 if row is None else str(row[1])
    if previous_event_sha256 is None:
        previous_event_sha256 = "0" * 64
    source_identity = _sha(f"training-source-{run_id}-{event_kind}-{source_id}-{label_id}-{tag}")
    event_id = _sha(f"training-event-{source_identity}")
    event_sha256 = _sha(f"training-chain-{previous_event_sha256}-{sequence}-{event_id}-{tag}")
    payload: dict[str, object] = {
        "schema_version": "m5-training-causal-event-v1",
        "run_id": run_id,
        "sequence": sequence,
        "event_kind": event_kind,
        "source_id": payload_source_id or source_id,
        "source_document_sha256": source_document_sha256,
        "manifest_id": manifest_id,
        "previous_event_sha256": previous_event_sha256,
        "label_id": label_id,
        "source_identity": source_identity,
        "event_id": event_id,
        "event_sha256": event_sha256,
    }
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
            run_id,
            sequence,
            event_id,
            source_identity,
            event_kind,
            source_id,
            source_document_sha256,
            manifest_id,
            previous_event_sha256,
            event_sha256,
            label_id,
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            _sha(f"training-event-document-{event_id}"),
        ),
    )
    return {
        "sequence": sequence,
        "event_id": event_id,
        "event_sha256": event_sha256,
        "document_sha256": _sha(f"training-event-document-{event_id}"),
    }


def _insert_strong_training_label(
    connection: sqlite3.Connection,
    values: dict[str, str],
    *,
    document_sha256: str | None = None,
    create_causal_event: bool = True,
) -> None:
    if create_causal_event:
        _insert_training_causal_event(
            connection,
            run_id=values["run_id"],
            manifest_id=values["manifest_id"],
            event_kind="TRAINING_LABEL_APPENDED",
            source_id=_sha(f"training-label-authority-{values['label_id']}"),
            source_document_sha256=_sha(f"training-label-authority-document-{values['label_id']}"),
            label_id=values["label_id"],
        )
    connection.execute(
        """
        INSERT INTO training_labels(
            run_id, label_id, case_id, crop_id, quality, source, reviewer_id,
            rule_version, detector_manifest_id, manifest_id,
            strong_provenance_id, label_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?)
        """,
        (
            values["run_id"],
            values["label_id"],
            values["case_id"],
            values["crop_id"],
            values["quality"],
            f"appeal-review:{values['appeal_id']}",
            values["reviewer_id"],
            values["rule_version"],
            values["detector_manifest_id"],
            values["manifest_id"],
            values["provenance_id"],
            document_sha256 or values["label_document_sha256"],
        ),
    )


def _insert_strong_provenance_commit(
    connection: sqlite3.Connection,
    values: dict[str, str],
    *,
    label_ids: tuple[str, ...] | None = None,
    precedent_revocation_receipt_ids: tuple[str, ...] = (),
) -> None:
    inventory = (values["label_id"],) if label_ids is None else label_ids
    overturned = bool(precedent_revocation_receipt_ids)
    verdict_rescission_ids = [_sha("provenance-verdict-rescission")] if overturned else []
    replacement_precedent_authority_id = (
        _sha("provenance-replacement-authority") if overturned else None
    )
    connection.execute(
        """
        INSERT INTO appeal_resolution_commit_receipts(
            run_id, receipt_id, effect_root_sha256, resolution_intent_id,
            resolution_document_sha256, appeal_id, appeal_authority_sha256,
            case_id, source_case_revision, resulting_case_revision,
            resulting_case_document_sha256, verdict_rescission_ids_json,
            alert_rescission_ids_json, precedent_revocation_receipt_ids_json,
            replacement_precedent_authority_id, training_label_ids_json,
            affected_citation_report_sha256, manifest_id, receipt_json,
            document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 4, ?, ?, '[]', ?, ?, ?, ?, ?, '{}', ?)
        """,
        (
            values["run_id"],
            values["resolution_commit_receipt_id"],
            values["resolution_commit_effect_root_sha256"],
            values["resolution_intent_id"],
            values["resolution_document_sha256"],
            values["appeal_id"],
            values["terminal_authority_sha256"],
            values["case_id"],
            values["resulting_case_document_sha256"],
            json.dumps(verdict_rescission_ids),
            json.dumps(precedent_revocation_receipt_ids),
            replacement_precedent_authority_id,
            json.dumps(inventory),
            _sha("provenance-citation-report"),
            values["manifest_id"],
            _sha("provenance-commit-document"),
        ),
    )


def test_strong_training_provenance_schema_is_strict_and_bidirectional(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        provenance_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(strong_training_label_provenance_receipts)"
            )
        }
        assert provenance_columns == {
            "run_id",
            "provenance_id",
            "case_id",
            "appeal_id",
            "label_id",
            "label_document_sha256",
            "crop_id",
            "reviewer_id",
            "quality",
            "authored_input_id",
            "review_authority_sha256",
            "terminal_authority_sha256",
            "terminal_status",
            "resolution_intent_id",
            "resolution_document_sha256",
            "resolution_commit_receipt_id",
            "resolution_commit_effect_root_sha256",
            "manifest_id",
            "rule_version",
            "detector_manifest_id",
            "provenance_json",
            "document_sha256",
        }
        training_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(training_labels)")
        }
        assert "strong_provenance_id" in training_columns
        table_sql = str(
            connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'strong_training_label_provenance_receipts'
                """
            ).fetchone()[0]
        )
        assert table_sql.rstrip().endswith("STRICT")
        assert table_sql.count("DEFERRABLE INITIALLY DEFERRED") == 2
    finally:
        connection.close()


def test_strong_training_provenance_closes_label_and_final_commit_atomically(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        values = _seed_strong_provenance_authorities(connection)
        connection.execute("BEGIN")
        _insert_strong_provenance(connection, values)
        _insert_strong_training_label(connection, values)
        _insert_strong_provenance_commit(connection, values)
        connection.commit()

        assert connection.execute(
            "SELECT COUNT(*) FROM strong_training_label_provenance_receipts"
        ).fetchone() == (1,)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE strong_training_label_provenance_receipts SET rule_version = 'rule-v2'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM strong_training_label_provenance_receipts")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO strong_training_label_provenance_receipts
                SELECT * FROM strong_training_label_provenance_receipts
                """
            )
    finally:
        connection.close()


def test_strong_training_provenance_rejects_orphans_and_incomplete_inventory(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        values = _seed_strong_provenance_authorities(connection)
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            _insert_strong_training_label(connection, values)
        connection.rollback()

        connection.execute("BEGIN")
        _insert_strong_provenance(connection, values)
        _insert_strong_training_label(connection, values)
        with pytest.raises(sqlite3.IntegrityError, match="provenance closure"):
            _insert_strong_provenance_commit(connection, values, label_ids=())
        connection.rollback()

        connection.execute("BEGIN")
        _insert_strong_provenance(connection, values)
        _insert_strong_training_label(connection, values)
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            connection.commit()
        connection.rollback()
        assert connection.execute(
            "SELECT COUNT(*) FROM strong_training_label_provenance_receipts"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM training_labels WHERE quality = 'HUMAN_CONFIRMED'"
        ).fetchone() == (0,)

        connection.execute("BEGIN")
        _insert_strong_provenance(connection, values)
        _insert_strong_training_label(
            connection,
            values,
            document_sha256=_sha("wrong-provenance-label-document"),
        )
        _insert_strong_provenance_commit(connection, values)
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            connection.commit()
        connection.rollback()
    finally:
        connection.close()


def test_training_label_quality_matrix_rejects_unwrapped_strong_and_wrapped_weak(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        values = _seed_strong_provenance_authorities(connection)

        def insert_label(quality: str, provenance_id: str | None, suffix: str) -> None:
            label_id = _sha(f"quality-matrix-label-{suffix}")
            _insert_training_causal_event(
                connection,
                run_id=values["run_id"],
                manifest_id=values["manifest_id"],
                event_kind="TRAINING_LABEL_APPENDED",
                source_id=_sha(f"quality-matrix-authority-{suffix}"),
                source_document_sha256=_sha(f"quality-matrix-authority-document-{suffix}"),
                label_id=label_id,
            )
            connection.execute(
                """
                INSERT INTO training_labels(
                    run_id, label_id, case_id, crop_id, quality, source,
                    reviewer_id, rule_version, detector_manifest_id, manifest_id,
                    strong_provenance_id, label_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, '{}', ?)
                """,
                (
                    values["run_id"],
                    label_id,
                    values["case_id"],
                    values["crop_id"],
                    quality,
                    f"quality-matrix-{suffix}",
                    values["rule_version"],
                    values["detector_manifest_id"],
                    values["manifest_id"],
                    provenance_id,
                    _sha(f"quality-matrix-document-{suffix}"),
                ),
            )

        connection.execute("SAVEPOINT unwrapped_strong")
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            insert_label("HUMAN_CONFIRMED", None, "unwrapped-strong")
        connection.execute("ROLLBACK TO unwrapped_strong")
        connection.execute("RELEASE unwrapped_strong")
        connection.execute("SAVEPOINT wrapped_weak")
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint failed"):
            insert_label("WEAK_AUTO", values["provenance_id"], "wrapped-weak")
        connection.execute("ROLLBACK TO wrapped_weak")
        connection.execute("RELEASE wrapped_weak")
        insert_label("WEAK_AUTO", None, "unwrapped-weak")
        connection.commit()
    finally:
        connection.close()


def _insert_dataset_registration_snapshot(
    connection: sqlite3.Connection,
    values: dict[str, str],
    *,
    causal_cut_sequence: int,
    causal_cut_event_id: str | None,
    causal_cut_event_sha256: str,
    label_count: int,
    crop_count: int,
    suffix: str = "",
    payload_authority_id: str | None = None,
) -> dict[str, str]:
    snapshot = {
        "authority_id": _sha(f"dataset-snapshot-authority{suffix}"),
        "dataset_id": f"dataset-m5-snapshot{suffix}",
        "report_id": _sha(f"dataset-report{suffix}"),
        "command_id": _sha(f"dataset-command{suffix}"),
        "report_document_sha256": _sha(f"dataset-report-document{suffix}"),
        "label_inventory_root_sha256": _sha(f"dataset-label-root{suffix}"),
        "crop_inventory_root_sha256": _sha(f"dataset-crop-root{suffix}"),
        "document_sha256": _sha(f"dataset-snapshot-document{suffix}"),
    }
    payload = {
        "schema_version": "m5-dataset-registration-snapshot-authority-v1",
        "run_id": values["run_id"],
        "dataset_id": snapshot["dataset_id"],
        "report_id": snapshot["report_id"],
        "command_id": snapshot["command_id"],
        "report_document_sha256": snapshot["report_document_sha256"],
        "causal_cut": {
            "schema_version": "m5-training-causal-watermark-v1",
            "run_id": values["run_id"],
            "sequence": causal_cut_sequence,
            "event_id": causal_cut_event_id,
            "event_sha256": causal_cut_event_sha256,
            "watermark_id": _sha(f"dataset-watermark{suffix}"),
        },
        "label_count": label_count,
        "label_inventory_root_sha256": snapshot["label_inventory_root_sha256"],
        "crop_count": crop_count,
        "crop_inventory_root_sha256": snapshot["crop_inventory_root_sha256"],
        "manifest_id": values["manifest_id"],
        "rule_version": values["rule_version"],
        "detector_manifest_id": values["detector_manifest_id"],
        "authority_id": payload_authority_id or snapshot["authority_id"],
    }
    connection.execute(
        """
        INSERT INTO dataset_registration_snapshots(
            run_id, authority_id, dataset_id, report_id, command_id,
            report_document_sha256, causal_cut_sequence, causal_cut_event_id,
            causal_cut_event_sha256, label_count, label_inventory_root_sha256,
            crop_count, crop_inventory_root_sha256, manifest_id, rule_version,
            detector_manifest_id, snapshot_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            values["run_id"],
            snapshot["authority_id"],
            snapshot["dataset_id"],
            snapshot["report_id"],
            snapshot["command_id"],
            snapshot["report_document_sha256"],
            causal_cut_sequence,
            causal_cut_event_id,
            causal_cut_event_sha256,
            label_count,
            snapshot["label_inventory_root_sha256"],
            crop_count,
            snapshot["crop_inventory_root_sha256"],
            values["manifest_id"],
            values["rule_version"],
            values["detector_manifest_id"],
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            snapshot["document_sha256"],
        ),
    )
    return snapshot


def _insert_dataset_crop_snapshot(
    connection: sqlite3.Connection,
    values: dict[str, str],
    snapshot: dict[str, str],
    *,
    suffix: str = "",
) -> dict[str, str]:
    crop_authority_sha256 = _sha(f"dataset-crop-authority{suffix}")
    authority_id = _sha(f"dataset-crop-snapshot-authority{suffix}")
    payload = {
        "schema_version": "m5-dataset-crop-snapshot-authority-v1",
        "run_id": values["run_id"],
        "dataset_id": snapshot["dataset_id"],
        "report_id": snapshot["report_id"],
        "crop_authority": {
            "run_id": values["run_id"],
            "case_id": values["case_id"],
            "crop": {"crop_id": values["crop_id"]},
            "authority_sha256": crop_authority_sha256,
        },
        "case_revision": 4,
        "case_document_sha256": values["resulting_case_document_sha256"],
        "evidence_pack_id": values["evidence_pack_id"],
        "evidence_pack_version": 1,
        "evidence_pack_document_sha256": values["evidence_pack_document_sha256"],
        "authority_id": authority_id,
    }
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
            values["run_id"],
            authority_id,
            snapshot["authority_id"],
            snapshot["dataset_id"],
            snapshot["report_id"],
            values["crop_id"],
            crop_authority_sha256,
            values["case_id"],
            4,
            values["resulting_case_document_sha256"],
            values["evidence_pack_id"],
            1,
            values["evidence_pack_document_sha256"],
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            _sha(f"dataset-crop-snapshot-document{suffix}"),
        ),
    )
    return {"crop_id": values["crop_id"], "authority_sha256": crop_authority_sha256}


def _insert_dataset_artifact(
    connection: sqlite3.Connection,
    values: dict[str, str],
    snapshot: dict[str, str],
    *,
    exported_label_ids: tuple[str, ...],
    quarantined_label_ids: tuple[str, ...] = (),
    crop_receipts: tuple[dict[str, str], ...] = (),
) -> None:
    report = {
        "input_label_count": len(exported_label_ids) + len(quarantined_label_ids),
        "exported_label_ids": list(exported_label_ids),
        "quarantined_label_ids": list(quarantined_label_ids),
        "exported_image_count": len(crop_receipts),
        "crop_receipts": list(crop_receipts),
    }
    connection.execute(
        """
        INSERT INTO dataset_artifacts(
            run_id, dataset_id, report_id, command_id, format,
            relative_path, content_sha256, content_size_bytes,
            label_count, minimum_quality, rule_version,
            detector_manifest_id, manifest_id,
            registration_snapshot_authority_id,
            artifact_json, report_json, document_sha256
        ) VALUES (?, ?, ?, ?, 'COCO', ?, ?, 2, ?, 'HUMAN_CONFIRMED', ?, ?, ?, ?, '{}', ?, ?)
        """,
        (
            values["run_id"],
            snapshot["dataset_id"],
            snapshot["report_id"],
            snapshot["command_id"],
            f"datasets/{snapshot['dataset_id']}.json",
            _sha(f"dataset-content-{snapshot['dataset_id']}"),
            len(exported_label_ids),
            values["rule_version"],
            values["detector_manifest_id"],
            values["manifest_id"],
            snapshot["authority_id"],
            json.dumps(report, separators=(",", ":"), sort_keys=True),
            snapshot["report_document_sha256"],
        ),
    )


def test_training_causal_ledger_rejects_gaps_wrong_predecessors_and_orphans(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        values = _seed_strong_provenance_authorities(connection)
        with pytest.raises(sqlite3.IntegrityError, match=r"not contiguous|predecessor"):
            _insert_training_causal_event(
                connection,
                run_id=values["run_id"],
                manifest_id=values["manifest_id"],
                event_kind="TRAINING_LABEL_APPENDED",
                source_id=_sha("gap-label-authority"),
                source_document_sha256=_sha("gap-label-authority-document"),
                label_id="gap-label",
                sequence=2,
                previous_event_sha256="0" * 64,
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="predecessor"):
            _insert_training_causal_event(
                connection,
                run_id=values["run_id"],
                manifest_id=values["manifest_id"],
                event_kind="TRAINING_LABEL_APPENDED",
                source_id=_sha("wrong-predecessor-authority"),
                source_document_sha256=_sha("wrong-predecessor-document"),
                label_id="wrong-predecessor-label",
                sequence=1,
                previous_event_sha256="f" * 64,
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="source or index binding"):
            _insert_training_causal_event(
                connection,
                run_id=values["run_id"],
                manifest_id=values["manifest_id"],
                event_kind="TRAINING_LABEL_APPENDED",
                source_id=_sha("indexed-event-authority"),
                source_document_sha256=_sha("indexed-event-document"),
                label_id="indexed-event-label",
                payload_source_id=_sha("forged-indexed-event-authority"),
            )
        connection.rollback()

        connection.execute("BEGIN")
        _insert_training_causal_event(
            connection,
            run_id=values["run_id"],
            manifest_id=values["manifest_id"],
            event_kind="TRAINING_LABEL_APPENDED",
            source_id=_sha("orphan-label-authority"),
            source_document_sha256=_sha("orphan-label-authority-document"),
            label_id="orphan-label",
        )
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            connection.commit()
        connection.rollback()

        with pytest.raises(sqlite3.IntegrityError, match="requires its causal"):
            connection.execute(
                """
                INSERT INTO training_labels(
                    run_id, label_id, case_id, crop_id, quality, source,
                    reviewer_id, rule_version, detector_manifest_id, manifest_id,
                    strong_provenance_id, label_json, document_sha256
                ) VALUES (?, 'label-without-event', ?, ?, 'WEAK_AUTO', 'fixture',
                    NULL, ?, ?, ?, NULL, '{}', ?)
                """,
                (
                    values["run_id"],
                    values["case_id"],
                    values["crop_id"],
                    values["rule_version"],
                    values["detector_manifest_id"],
                    values["manifest_id"],
                    _sha("label-without-event-document"),
                ),
            )
    finally:
        connection.close()


def test_training_causal_ledger_and_empty_dataset_snapshot_are_append_only(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        values = _seed_strong_provenance_authorities(connection)
        connection.execute("BEGIN")
        snapshot = _insert_dataset_registration_snapshot(
            connection,
            values,
            causal_cut_sequence=0,
            causal_cut_event_id=None,
            causal_cut_event_sha256="0" * 64,
            label_count=0,
            crop_count=0,
            suffix="-empty",
        )
        _insert_training_causal_event(
            connection,
            run_id=values["run_id"],
            manifest_id=values["manifest_id"],
            event_kind="DATASET_REGISTRATION_COMMITTED",
            source_id=snapshot["authority_id"],
            source_document_sha256=snapshot["document_sha256"],
        )
        _insert_dataset_artifact(
            connection,
            values,
            snapshot,
            exported_label_ids=(),
        )
        connection.commit()

        for table in (
            "m5_training_causal_events",
            "dataset_registration_snapshots",
            "dataset_artifacts",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(f"UPDATE {table} SET document_sha256 = document_sha256")
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(f"DELETE FROM {table}")
            connection.rollback()
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}")
            connection.rollback()
    finally:
        connection.close()


def test_nonempty_dataset_snapshot_binds_label_cut_crop_history_and_commit_event(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        values = _seed_strong_provenance_authorities(connection)
        connection.execute("BEGIN")
        _insert_strong_provenance(connection, values)
        _insert_strong_training_label(connection, values)
        _insert_strong_provenance_commit(connection, values)
        connection.commit()
        label_event = connection.execute(
            """
            SELECT sequence, event_id, event_sha256
            FROM m5_training_causal_events
            WHERE run_id = ? AND label_id = ?
            """,
            (values["run_id"], values["label_id"]),
        ).fetchone()
        assert label_event is not None

        connection.execute("BEGIN")
        snapshot = _insert_dataset_registration_snapshot(
            connection,
            values,
            causal_cut_sequence=int(label_event[0]),
            causal_cut_event_id=str(label_event[1]),
            causal_cut_event_sha256=str(label_event[2]),
            label_count=1,
            crop_count=1,
            suffix="-nonempty",
        )
        crop_receipt = _insert_dataset_crop_snapshot(
            connection,
            values,
            snapshot,
            suffix="-nonempty",
        )
        _insert_training_causal_event(
            connection,
            run_id=values["run_id"],
            manifest_id=values["manifest_id"],
            event_kind="DATASET_REGISTRATION_COMMITTED",
            source_id=snapshot["authority_id"],
            source_document_sha256=snapshot["document_sha256"],
        )
        _insert_dataset_artifact(
            connection,
            values,
            snapshot,
            exported_label_ids=(values["label_id"],),
            crop_receipts=(crop_receipt,),
        )
        connection.commit()
        assert connection.execute("SELECT COUNT(*) FROM dataset_artifacts").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM dataset_crop_snapshots").fetchone() == (1,)

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE dataset_crop_snapshots SET authority_json = authority_json")
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM dataset_crop_snapshots")
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO dataset_crop_snapshots
                SELECT * FROM dataset_crop_snapshots
                """
            )
        connection.rollback()
    finally:
        connection.close()


def test_dataset_snapshot_rejects_wrong_counts_orphan_and_incomplete_closure(
    tmp_path: Path,
) -> None:
    database = _install(tmp_path)
    connection = sqlite3.connect(database)
    try:
        values = _seed_strong_provenance_authorities(connection)
        with pytest.raises(sqlite3.IntegrityError, match="source or index binding"):
            _insert_dataset_registration_snapshot(
                connection,
                values,
                causal_cut_sequence=0,
                causal_cut_event_id=None,
                causal_cut_event_sha256="0" * 64,
                label_count=1,
                crop_count=0,
                suffix="-wrong-count",
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="source or index binding"):
            _insert_dataset_registration_snapshot(
                connection,
                values,
                causal_cut_sequence=0,
                causal_cut_event_id=None,
                causal_cut_event_sha256="0" * 64,
                label_count=0,
                crop_count=0,
                suffix="-forged-json",
                payload_authority_id=_sha("forged-snapshot-json-authority"),
            )
        connection.rollback()

        connection.execute("BEGIN")
        _insert_strong_provenance(connection, values)
        _insert_strong_training_label(connection, values)
        _insert_strong_provenance_commit(connection, values)
        connection.commit()
        label_event = connection.execute(
            """
            SELECT sequence, event_id, event_sha256
            FROM m5_training_causal_events
            WHERE run_id = ? AND label_id = ?
            """,
            (values["run_id"], values["label_id"]),
        ).fetchone()
        assert label_event is not None
        connection.execute("BEGIN")
        incomplete_report = _insert_dataset_registration_snapshot(
            connection,
            values,
            causal_cut_sequence=int(label_event[0]),
            causal_cut_event_id=str(label_event[1]),
            causal_cut_event_sha256=str(label_event[2]),
            label_count=1,
            crop_count=0,
            suffix="-omitted-label",
        )
        _insert_training_causal_event(
            connection,
            run_id=values["run_id"],
            manifest_id=values["manifest_id"],
            event_kind="DATASET_REGISTRATION_COMMITTED",
            source_id=incomplete_report["authority_id"],
            source_document_sha256=incomplete_report["document_sha256"],
        )
        with pytest.raises(sqlite3.IntegrityError, match="snapshot closure"):
            _insert_dataset_artifact(
                connection,
                values,
                incomplete_report,
                exported_label_ids=(),
            )
        connection.rollback()

        connection.execute("BEGIN")
        orphan = _insert_dataset_registration_snapshot(
            connection,
            values,
            causal_cut_sequence=int(label_event[0]),
            causal_cut_event_id=str(label_event[1]),
            causal_cut_event_sha256=str(label_event[2]),
            label_count=1,
            crop_count=0,
            suffix="-orphan",
        )
        _insert_training_causal_event(
            connection,
            run_id=values["run_id"],
            manifest_id=values["manifest_id"],
            event_kind="DATASET_REGISTRATION_COMMITTED",
            source_id=orphan["authority_id"],
            source_document_sha256=orphan["document_sha256"],
        )
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            connection.commit()
        connection.rollback()

        connection.execute("BEGIN")
        incomplete = _insert_dataset_registration_snapshot(
            connection,
            values,
            causal_cut_sequence=0,
            causal_cut_event_id=None,
            causal_cut_event_sha256="0" * 64,
            label_count=0,
            crop_count=0,
            suffix="-no-commit",
        )
        with pytest.raises(sqlite3.IntegrityError, match="snapshot closure"):
            _insert_dataset_artifact(
                connection,
                values,
                incomplete,
                exported_label_ids=(),
            )
        connection.rollback()
    finally:
        connection.close()
