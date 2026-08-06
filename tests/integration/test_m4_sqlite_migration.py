import hashlib
import json
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_repository import (
    MigrationIntegrityError,
    MigrationRunner,
)
from labcourt.adapters.storage.sqlite_schema import (
    M4_AUTHORITY_INDEXES,
    M4_AUTHORITY_OBJECTS,
    M4_AUTHORITY_TABLES,
    M4_AUTHORITY_TRIGGERS,
    m4_hearing_authority_installed,
)
from labcourt.contracts.hearing import HearingCycleScope, HearingRound

MIGRATIONS = Path(__file__).parents[2] / "src" / "labcourt" / "adapters" / "storage" / "migrations"
ROUND_FIXTURE = Path(__file__).parents[1] / "fixtures" / "m4_hearing_round_v1.json"
BUSY_TIMEOUT_MS = 5_000
NOW = "2026-07-28T01:02:03.000000Z"
RUN_ID = "m4-migration-run"
CASE_ID = "case-m4-migration"
MANIFEST_ID = "a" * 64


def _clock() -> datetime:
    return datetime(2026, 7, 28, 1, 2, 3, tzinfo=UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _copy_migrations(destination: Path, *, through: int) -> None:
    destination.mkdir()
    for version in range(1, through + 1):
        source = next(MIGRATIONS.glob(f"{version:04d}_*.sql"))
        shutil.copy2(source, destination / source.name)


def _install_v7(tmp_path: Path) -> tuple[Path, Path]:
    copied = tmp_path / "migrations"
    _copy_migrations(copied, through=7)
    database = tmp_path / "labcourt.sqlite3"
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied, _clock).apply_all() == tuple(
        range(1, 8)
    )
    return database, copied


def _populate_v7_authority(database: Path) -> None:
    manifest_json = '{"fixture":"populated-v7"}'
    event_json = '{"event_id":"event-m4-migration"}'
    case_json = '{"case_id":"case-m4-migration","status":"OPEN"}'
    entry_json = '{"action":"CREATE","object_id":"case-m4-migration"}'
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO run_manifests(
                manifest_id, schema_version, document_json,
                document_sha256, registered_at
            ) VALUES (?, '1.0', ?, ?, ?)
            """,
            (MANIFEST_ID, manifest_json, _digest(manifest_json), NOW),
        )
        connection.execute(
            """
            INSERT INTO runs(
                run_id, manifest_id, revision,
                audit_head_sequence, audit_head_hash, registered_at
            ) VALUES (?, ?, 0, -1, ?, ?)
            """,
            (RUN_ID, MANIFEST_ID, "0" * 64, NOW),
        )
        connection.execute(
            """
            INSERT INTO audit_entries(
                run_id, sequence, manifest_id, actor, action,
                object_kind, object_id, before_sha256, after_sha256,
                recorded_at, prev_entry_hash, entry_hash,
                entry_json, document_sha256
            ) VALUES (?, 0, ?, 'MIGRATION_TEST', 'CREATE',
                      'CASE', ?, NULL, ?, ?, ?, ?, ?, ?)
            """,
            (
                RUN_ID,
                MANIFEST_ID,
                CASE_ID,
                _digest(case_json),
                NOW,
                "0" * 64,
                _digest(entry_json),
                entry_json,
                _digest(entry_json),
            ),
        )
        connection.execute(
            """
            UPDATE runs
            SET revision = 1, audit_head_sequence = 0, audit_head_hash = ?
            WHERE run_id = ?
            """,
            (_digest(entry_json), RUN_ID),
        )
        connection.execute(
            """
            INSERT INTO cases(
                run_id, case_id, event_id, manifest_id, status,
                current_revision, latest_pack_id, latest_pack_version,
                event_json, event_sha256, created_audit_sequence
            ) VALUES (?, ?, 'event-m4-migration', ?, 'OPEN',
                      1, NULL, NULL, ?, ?, 0)
            """,
            (RUN_ID, CASE_ID, MANIFEST_ID, event_json, _digest(event_json)),
        )
        connection.execute(
            """
            INSERT INTO case_versions(
                run_id, case_id, revision, status,
                case_json, document_sha256, audit_sequence
            ) VALUES (?, ?, 1, 'OPEN', ?, ?, 0)
            """,
            (RUN_ID, CASE_ID, case_json, _digest(case_json)),
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def _legacy_snapshot(database: Path) -> dict[str, list[tuple[object, ...]]]:
    with sqlite3.connect(database) as connection:
        tables = [
            str(row[0])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table'
                  AND name <> 'schema_migrations'
                  AND name NOT LIKE 'sqlite_%'
                  AND name NOT LIKE 'm4_%'
                ORDER BY name
                """
            )
        ]
        return {
            table: [tuple(row) for row in connection.execute(f'SELECT * FROM "{table}"')]
            for table in tables
        }


def _add_legacy_hearing_backlog_item(database: Path) -> None:
    item_id = _digest("legacy-hearing-backlog-item")
    item_json = '{"retry_generation":0}'
    item_sha256 = _digest(item_json)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO backlog_items(
                run_id, item_id, case_id, stage, role, reason_code,
                stage_input_kind, stage_input_id, stage_input_sha256,
                max_attempts, manifest_id, initial_json, initial_document_sha256
            ) VALUES (?, ?, ?, 'HEARING', 'JUDGE', 'LEGACY_SPECULATION',
                      'CASE', ?, ?, 3, ?, ?, ?)
            """,
            (
                RUN_ID,
                item_id,
                CASE_ID,
                CASE_ID,
                _digest(CASE_ID),
                MANIFEST_ID,
                item_json,
                item_sha256,
            ),
        )
        connection.execute(
            """
            INSERT INTO backlog_item_versions(
                run_id, item_id, version, status, attempt_count,
                lease_id, lease_owner_sha256, lease_expires_at,
                item_json, document_sha256, retry_generation
            ) VALUES (?, ?, 1, 'PENDING', 0, NULL, NULL, NULL, ?, ?, 0)
            """,
            (RUN_ID, item_id, item_json, item_sha256),
        )
        connection.execute(
            """
            INSERT INTO backlog_heads(run_id, item_id, current_version)
            VALUES (?, ?, 1)
            """,
            (RUN_ID, item_id),
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def _seed_m4_cycle_roots(database: Path) -> dict[str, str]:
    hearing_id = _digest("checkpoint-hearing")
    pack_id = _digest("checkpoint-pack")
    cycle = HearingCycleScope(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=hearing_id,
        cycle_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_evidence_pack_id=pack_id,
        cycle_evidence_pack_version=1,
        manifest_id=MANIFEST_ID,
    )
    roots = {
        "hearing_id": hearing_id,
        "hearing_sha256": _digest("checkpoint-hearing-document"),
        "cycle_scope_id": cycle.cycle_id,
        "cycle_scope_sha256": cycle.cycle_sha256,
        "cycle_json": cycle.model_dump_json(),
        "pack_id": pack_id,
    }
    with sqlite3.connect(database) as connection:
        # This fixture isolates checkpoint/call authority.  The two root
        # validators are removed only after their own installation was tested.
        connection.execute("DROP TRIGGER m4_hearings_validate_scope")
        connection.execute("DROP TRIGGER m4_hearing_cycles_validate_transition")
        connection.execute(
            """
            INSERT INTO m4_hearings(
                run_id, hearing_id, case_id, screening_id, entry_status,
                trigger_review_id, initial_defect_codes_json,
                initial_pack_id, initial_pack_version,
                max_acquisition_rounds, max_rework_rounds,
                max_total_images, max_total_output_tokens, max_judge_cycles,
                hearing_prompt_bundle_sha256,
                prosecutor_model_manifest_id, defender_model_manifest_id,
                judge_model_manifest_id,
                manifest_id, created_audit_sequence, hearing_json, document_sha256
            ) VALUES (
                :run_id, :hearing_id, :case_id, :screening_id, 'ESCALATED',
                NULL, '[]', :pack_id, 1, 2, 2, 64, 1000, 5,
                :prompt_bundle_sha256,
                :prosecutor_model_manifest_id, :defender_model_manifest_id,
                :judge_model_manifest_id,
                :manifest_id, 0, '{}', :hearing_sha256
            )
            """,
            {
                **roots,
                "run_id": RUN_ID,
                "case_id": CASE_ID,
                "screening_id": _digest("checkpoint-screening"),
                "prompt_bundle_sha256": _digest("hearing-prompt-bundle"),
                "prosecutor_model_manifest_id": _digest("prosecutor-model"),
                "defender_model_manifest_id": _digest("defender-model"),
                "judge_model_manifest_id": _digest("judge-model"),
                "manifest_id": MANIFEST_ID,
            },
        )
        connection.execute(
            """
            INSERT INTO m4_hearing_cycles(
                run_id, cycle_id, cycle_sha256, hearing_id, case_id,
                cycle_index, prior_acquisition_rounds, prior_rework_rounds,
                cycle_pack_id, cycle_pack_version,
                initial_trigger_review_id, initial_defect_codes_json,
                rework_review_id, rework_defect_codes_json,
                manifest_id, created_audit_sequence, cycle_json
            ) VALUES (
                :run_id, :cycle_scope_id, :cycle_scope_sha256,
                :hearing_id, :case_id, 1, 0, 0, :pack_id, 1,
                NULL, '[]', NULL, '[]', :manifest_id, 0, :cycle_json
            )
            """,
            {
                **roots,
                "run_id": RUN_ID,
                "case_id": CASE_ID,
                "manifest_id": MANIFEST_ID,
            },
        )
    return roots


def _insert_checkpoint(
    connection: sqlite3.Connection,
    roots: dict[str, str],
    *,
    checkpoint_id: str,
    checkpoint_sha256: str,
    version: int,
    phase: str,
    previous_checkpoint_id: str | None = None,
    previous_checkpoint_sha256: str | None = None,
    previous_phase: str | None = None,
    human_review_receipt_id: str | None = None,
    human_review_receipt_sha256: str | None = None,
    human_review_reason: str | None = None,
) -> None:
    connection.execute(
        """
        INSERT INTO m4_hearing_checkpoints(
            run_id, checkpoint_id, checkpoint_sha256,
            hearing_id, hearing_sha256,
            cycle_scope_id, cycle_scope_sha256, case_id,
            version, phase, judge_cycle,
            prior_acquisition_rounds, prior_rework_rounds,
            cycle_pack_id, cycle_pack_version,
            current_pack_id, current_pack_version,
            previous_checkpoint_id, previous_checkpoint_sha256, previous_phase,
            initial_trigger_review_id, initial_defect_codes_json,
            cycle_trigger_review_id, cycle_trigger_defect_codes_json,
            retrieval_receipt_id, retrieval_receipt_sha256,
            prosecutor_output_id, defender_output_id, judge_output_id,
            acquisition_request_id, tool_receipt_id, procedural_review_id,
            human_review_receipt_id, human_review_receipt_sha256,
            human_review_reason,
            model_request_refs_json, model_response_refs_json,
            parse_receipt_refs_json, usage_receipt_ids_json,
            failure_authority_ids_json,
            manifest_id, checkpoint_json
        ) VALUES (
            :run_id, :checkpoint_id, :checkpoint_sha256,
            :hearing_id, :hearing_sha256,
            :cycle_scope_id, :cycle_scope_sha256, :case_id,
            :version, :phase, 1, 0, 0,
            :pack_id, 1, :pack_id, 1,
            :previous_checkpoint_id, :previous_checkpoint_sha256, :previous_phase,
            NULL, '[]', NULL, '[]',
            NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            :human_review_receipt_id, :human_review_receipt_sha256,
            :human_review_reason,
            '[]', '[]', '[]', '[]', '[]', :manifest_id, '{}'
        )
        """,
        {
            **roots,
            "run_id": RUN_ID,
            "case_id": CASE_ID,
            "checkpoint_id": checkpoint_id,
            "checkpoint_sha256": checkpoint_sha256,
            "version": version,
            "phase": phase,
            "previous_checkpoint_id": previous_checkpoint_id,
            "previous_checkpoint_sha256": previous_checkpoint_sha256,
            "previous_phase": previous_phase,
            "human_review_receipt_id": human_review_receipt_id,
            "human_review_receipt_sha256": human_review_receipt_sha256,
            "human_review_reason": human_review_reason,
            "manifest_id": MANIFEST_ID,
        },
    )


def test_m4_migration_installs_complete_authority_on_a_fresh_database(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all() == tuple(
        range(1, 19)
    )

    with sqlite3.connect(database) as connection:
        assert m4_hearing_authority_installed(connection)
        observed = {
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                """
                SELECT type, name FROM sqlite_master
                WHERE name LIKE 'm4_%'
                   OR name LIKE 'idx_m4_%'
                   OR name LIKE 'uq_m4_%'
                """
            )
        }
        assert observed == M4_AUTHORITY_OBJECTS
        assert len(M4_AUTHORITY_TABLES) == 26
        assert len(M4_AUTHORITY_INDEXES) == 29
        assert len(M4_AUTHORITY_TRIGGERS) == 105
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_backlog_receipts_keep_semantic_and_raw_hash_authority_distinct(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()

    with sqlite3.connect(database) as connection:
        columns = {
            str(row[1])
            for row in connection.execute('PRAGMA table_info("m4_backlog_completion_receipts")')
        }
        assert {
            "receipt_sha256",
            "document_sha256",
            "completion_case_status",
        } <= columns
        outcome_trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm4_hearing_backlog_retry_outcomes_validate_authority'
            """
        ).fetchone()
        completion_trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm4_backlog_completion_receipts_validate_authority'
            """
        ).fetchone()
        unique_failure_bindings = {
            tuple(
                str(column[2])
                for column in connection.execute(f'PRAGMA index_info("{index[1]!s}")')
            )
            for index in connection.execute(
                'PRAGMA index_list("m4_model_call_failure_authorities")'
            )
            if int(index[2]) == 1
        }

    assert outcome_trigger is not None and completion_trigger is not None
    normalized_outcome = " ".join(str(outcome_trigger[0]).split())
    normalized_completion = " ".join(str(completion_trigger[0]).split())
    assert "human.receipt_sha256 = json_extract(" in normalized_outcome
    assert "human.document_sha256 = NEW.human_review_receipt_sha256" not in normalized_outcome
    assert "$.receipt_sha256') = NEW.receipt_sha256" in normalized_completion
    assert ("run_id", "completion_receipt_id") in unique_failure_bindings


def test_m4_migration_preserves_populated_v7_rows_and_documents(tmp_path: Path) -> None:
    database, copied = _install_v7(tmp_path)
    _populate_v7_authority(database)
    before = _legacy_snapshot(database)
    with sqlite3.connect(database) as connection:
        migration_rows = connection.execute(
            "SELECT * FROM schema_migrations ORDER BY version"
        ).fetchall()

    shutil.copy2(
        MIGRATIONS / "0008_m4_hearing_and_acquisition.sql",
        copied / "0008_m4_hearing_and_acquisition.sql",
    )
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, copied, _clock).apply_all() == (8,)

    assert _legacy_snapshot(database) == before
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT * FROM schema_migrations WHERE version <= 7 ORDER BY version"
            ).fetchall()
            == migration_rows
        )
        assert m4_hearing_authority_installed(connection)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_hearing_cycle_scope_is_stored_as_a_reloadable_typed_document(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    _populate_v7_authority(database)
    roots = _seed_m4_cycle_roots(database)

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT cycle_id, cycle_sha256, cycle_json
            FROM m4_hearing_cycles
            WHERE run_id = ? AND cycle_id = ?
            """,
            (RUN_ID, roots["cycle_scope_id"]),
        ).fetchone()

    assert row is not None
    reloaded = HearingCycleScope.model_validate_json(str(row[2]))
    assert reloaded.cycle_id == str(row[0]) == roots["cycle_scope_id"]
    assert reloaded.cycle_sha256 == str(row[1]) == roots["cycle_scope_sha256"]


def test_cycle_bound_authorities_and_verdict_use_canonical_foreign_keys(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    cycle_bound_tables = (
        "m4_precedent_retrieval_receipts",
        "m4_model_responses",
        "m4_model_call_claims",
        "m4_parsed_hearing_outputs",
        "m4_model_parse_receipts",
        "m4_model_cache",
        "m4_hearing_usage_receipts",
        "m4_acquisition_requests",
        "m4_hearing_rounds",
        "m4_tool_execution_receipts",
        "m4_model_call_failure_authorities",
        "m4_hearing_checkpoints",
        "m4_hearing_strict_parse_failure_attempts",
        "m4_hearing_backlog_retry_outcomes",
    )
    expected_cycle_binding = (
        ("run_id", "run_id"),
        ("cycle_scope_id", "cycle_id"),
        ("cycle_scope_sha256", "cycle_sha256"),
        ("hearing_id", "hearing_id"),
    )

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'm4_hearing_round_completions'"
            ).fetchone()
            is None
        )
        for table in cycle_bound_tables:
            rows = connection.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()
            grouped: dict[int, list[tuple[int, str, str]]] = {}
            for row in rows:
                if str(row[2]) == "m4_hearing_cycles":
                    grouped.setdefault(int(row[0]), []).append(
                        (int(row[1]), str(row[3]), str(row[4]))
                    )
            bindings = {
                tuple((source, target) for _seq, source, target in sorted(parts))
                for parts in grouped.values()
            }
            assert expected_cycle_binding in bindings, table

        verdict_foreign_keys = connection.execute(
            'PRAGMA foreign_key_list("m4_hearing_verdict_bindings")'
        ).fetchall()
        assert any(
            str(row[2]) == "m4_hearing_rounds"
            and str(row[3]) == "round_id"
            and str(row[4]) == "round_id"
            for row in verdict_foreign_keys
        )
        verdict_columns = {
            str(row[1])
            for row in connection.execute('PRAGMA table_info("m4_hearing_verdict_bindings")')
        }
        assert "round_id" in verdict_columns
        assert "round_completion_id" not in verdict_columns


def test_completed_hearing_round_is_stored_as_a_reloadable_typed_document(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    hearing_round = HearingRound.model_validate_json(ROUND_FIXTURE.read_text(encoding="utf-8"))
    round_json = hearing_round.model_dump_json()

    with sqlite3.connect(database) as connection:
        # Upstream row closure has dedicated trigger tests. This assertion
        # isolates the canonical persisted document shape and typed reload.
        connection.execute("DROP TRIGGER m4_hearing_rounds_validate_authority")
        connection.execute(
            """
            INSERT INTO m4_hearing_rounds(
                run_id, round_id, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id,
                round_index, prior_acquisition_rounds, prior_rework_rounds,
                current_pack_id, current_pack_version,
                precedent_retrieval_degraded,
                retrieval_receipt_id, retrieval_receipt_sha256,
                initial_trigger_review_id, initial_defect_codes_json,
                rework_review_id, rework_defect_codes_json,
                prosecutor_output_id, defender_output_id, judge_output_id,
                acquisition_request_id, tool_receipt_id,
                resulting_pack_id, resulting_pack_version,
                manifest_id, round_json
            ) VALUES (
                :run_id, :round_id, :hearing_id,
                :cycle_scope_id, :cycle_scope_sha256, :case_id,
                :round_index, :prior_acquisition_rounds, :prior_rework_rounds,
                :current_pack_id, :current_pack_version,
                :precedent_retrieval_degraded,
                :retrieval_receipt_id, :retrieval_receipt_sha256,
                :initial_trigger_review_id, :initial_defect_codes_json,
                :rework_review_id, :rework_defect_codes_json,
                :prosecutor_output_id, :defender_output_id, :judge_output_id,
                :acquisition_request_id, :tool_receipt_id,
                :resulting_pack_id, :resulting_pack_version,
                :manifest_id, :round_json
            )
            """,
            {
                "run_id": hearing_round.run_id,
                "round_id": hearing_round.round_id,
                "hearing_id": hearing_round.hearing_session_id,
                "cycle_scope_id": hearing_round.cycle_scope_id,
                "cycle_scope_sha256": hearing_round.cycle_scope_sha256,
                "case_id": hearing_round.case_id,
                "round_index": hearing_round.round_index,
                "prior_acquisition_rounds": hearing_round.prior_acquisition_rounds,
                "prior_rework_rounds": hearing_round.prior_rework_rounds,
                "current_pack_id": hearing_round.current_evidence_pack_id,
                "current_pack_version": hearing_round.current_evidence_pack_version,
                "precedent_retrieval_degraded": int(hearing_round.precedent_retrieval_degraded),
                "retrieval_receipt_id": (hearing_round.precedent_retrieval_receipt.receipt_id),
                "retrieval_receipt_sha256": (
                    hearing_round.precedent_retrieval_receipt.receipt_sha256
                ),
                "initial_trigger_review_id": (
                    hearing_round.initial_trigger_review_ref.artifact_id
                    if hearing_round.initial_trigger_review_ref is not None
                    else None
                ),
                "initial_defect_codes_json": json.dumps(
                    [code.value for code in hearing_round.initial_defect_codes]
                ),
                "rework_review_id": (
                    hearing_round.rework_review_ref.artifact_id
                    if hearing_round.rework_review_ref is not None
                    else None
                ),
                "rework_defect_codes_json": json.dumps(
                    [code.value for code in hearing_round.rework_defect_codes]
                ),
                "prosecutor_output_id": hearing_round.prosecutor_output.output_id,
                "defender_output_id": hearing_round.defender_output.output_id,
                "judge_output_id": hearing_round.judge_output.output_id,
                "acquisition_request_id": None,
                "tool_receipt_id": None,
                "resulting_pack_id": hearing_round.resulting_evidence_pack_id,
                "resulting_pack_version": hearing_round.resulting_evidence_pack_version,
                "manifest_id": hearing_round.manifest_id,
                "round_json": round_json,
            },
        )
        stored_json = connection.execute(
            "SELECT round_json FROM m4_hearing_rounds WHERE run_id = ? AND round_id = ?",
            (hearing_round.run_id, hearing_round.round_id),
        ).fetchone()

    assert stored_json is not None
    reloaded = HearingRound.model_validate_json(str(stored_json[0]))
    assert reloaded == hearing_round
    assert reloaded.round_id == hearing_round.round_id


def test_m4_migration_atomically_rejects_legacy_hearing_backlog(tmp_path: Path) -> None:
    database, copied = _install_v7(tmp_path)
    _populate_v7_authority(database)
    _add_legacy_hearing_backlog_item(database)
    before = _legacy_snapshot(database)
    shutil.copy2(
        MIGRATIONS / "0008_m4_hearing_and_acquisition.sql",
        copied / "0008_m4_hearing_and_acquisition.sql",
    )

    with pytest.raises(
        MigrationIntegrityError,
        match=r"0008_m4_hearing_and_acquisition\.sql failed",
    ):
        MigrationRunner(database, BUSY_TIMEOUT_MS, copied, _clock).apply_all()

    assert _legacy_snapshot(database) == before
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, 8)]
        assert (
            connection.execute(
                """
            SELECT name FROM sqlite_master
            WHERE name = 'm4_authority_preflight'
               OR name LIKE 'm4_%'
               OR name LIKE 'idx_m4_%'
               OR name LIKE 'uq_m4_%'
            """
            ).fetchall()
            == []
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize(
    ("object_type", "object_name"),
    [
        ("trigger", "m4_hearing_checkpoints_validate_transition"),
        ("trigger", "m4_acquired_crops_validate_authority"),
        ("index", "idx_m4_model_claims_active_expiry"),
        ("table", "m4_rework_receipts"),
    ],
)
def test_m4_authority_gate_fails_closed_when_any_safety_object_is_missing(
    tmp_path: Path,
    object_type: str,
    object_name: str,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    with sqlite3.connect(database) as connection:
        assert m4_hearing_authority_installed(connection)
        connection.execute(f'DROP {object_type.upper()} "{object_name}"')
        assert not m4_hearing_authority_installed(connection)


def test_m4_authority_tables_are_append_only(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    _populate_v7_authority(database)
    roots = _seed_m4_cycle_roots(database)
    checkpoint_id = _digest("append-only-checkpoint")
    checkpoint_sha256 = _digest("append-only-checkpoint-document")
    with sqlite3.connect(database) as connection:
        _insert_checkpoint(
            connection,
            roots,
            checkpoint_id=checkpoint_id,
            checkpoint_sha256=checkpoint_sha256,
            version=1,
            phase="PRECEDENT_RETRIEVAL_PENDING",
        )
        connection.commit()

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                UPDATE m4_hearing_checkpoints
                SET checkpoint_json = '{"tampered":true}'
                WHERE run_id = ? AND checkpoint_id = ?
                """,
                (RUN_ID, checkpoint_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                DELETE FROM m4_hearing_checkpoints
                WHERE run_id = ? AND checkpoint_id = ?
                """,
                (RUN_ID, checkpoint_id),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO m4_hearing_checkpoints
                SELECT * FROM m4_hearing_checkpoints
                WHERE run_id = ? AND checkpoint_id = ?
                """,
                (RUN_ID, checkpoint_id),
            )


def test_checkpoint_chain_and_human_review_are_bidirectionally_bound(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    _populate_v7_authority(database)
    roots = _seed_m4_cycle_roots(database)
    first_id = _digest("checkpoint-v1")
    first_sha256 = _digest("checkpoint-v1-document")
    receipt_id = _digest("human-review-receipt")
    receipt_sha256 = _digest("human-review-receipt-document")

    with sqlite3.connect(database) as connection:
        _insert_checkpoint(
            connection,
            roots,
            checkpoint_id=first_id,
            checkpoint_sha256=first_sha256,
            version=1,
            phase="PRECEDENT_RETRIEVAL_PENDING",
        )
        with pytest.raises(sqlite3.IntegrityError, match="checkpoint transition"):
            _insert_checkpoint(
                connection,
                roots,
                checkpoint_id=_digest("checkpoint-gap"),
                checkpoint_sha256=_digest("checkpoint-gap-document"),
                version=3,
                phase="PRECEDENT_RETRIEVAL_PENDING",
                previous_checkpoint_id=first_id,
                previous_checkpoint_sha256=first_sha256,
                previous_phase="PRECEDENT_RETRIEVAL_PENDING",
            )

        receipt_values = {
            **roots,
            "run_id": RUN_ID,
            "receipt_id": receipt_id,
            "receipt_sha256": receipt_sha256,
            "case_id": CASE_ID,
            "source_checkpoint_id": first_id,
            "source_checkpoint_sha256": first_sha256,
            "manifest_id": MANIFEST_ID,
            "document_sha256": receipt_sha256,
        }
        with pytest.raises(sqlite3.IntegrityError, match="human-review authority"):
            connection.execute(
                """
                INSERT INTO m4_hearing_human_review_receipts(
                    run_id, receipt_id, receipt_sha256, hearing_id, case_id,
                    current_pack_id, current_pack_version, judge_cycle, reason,
                    source_checkpoint_id, source_checkpoint_sha256,
                    source_checkpoint_version, procedural_review_id,
                    backlog_item_id, acquisition_model_request_id,
                    manifest_id, receipt_json, document_sha256
                ) VALUES (
                    :run_id, :receipt_id, :receipt_sha256, :hearing_id, 'wrong-case',
                    :pack_id, 1, 1, 'HEARING_BUDGET_EXHAUSTED',
                    :source_checkpoint_id, :source_checkpoint_sha256,
                    1, NULL, NULL, NULL, :manifest_id, '{}', :document_sha256
                )
                """,
                receipt_values,
            )
        connection.execute(
            """
            INSERT INTO m4_hearing_human_review_receipts(
                run_id, receipt_id, receipt_sha256, hearing_id, case_id,
                current_pack_id, current_pack_version, judge_cycle, reason,
                source_checkpoint_id, source_checkpoint_sha256,
                source_checkpoint_version, procedural_review_id,
                backlog_item_id, acquisition_model_request_id,
                manifest_id, receipt_json, document_sha256
            ) VALUES (
                :run_id, :receipt_id, :receipt_sha256, :hearing_id, :case_id,
                :pack_id, 1, 1, 'HEARING_BUDGET_EXHAUSTED',
                :source_checkpoint_id, :source_checkpoint_sha256,
                1, NULL, NULL, NULL, :manifest_id, '{}', :document_sha256
            )
            """,
            receipt_values,
        )
        terminal_id = _digest("checkpoint-v2-human")
        _insert_checkpoint(
            connection,
            roots,
            checkpoint_id=terminal_id,
            checkpoint_sha256=_digest("checkpoint-v2-human-document"),
            version=2,
            phase="HUMAN_REVIEW",
            previous_checkpoint_id=first_id,
            previous_checkpoint_sha256=first_sha256,
            previous_phase="PRECEDENT_RETRIEVAL_PENDING",
            human_review_receipt_id=receipt_id,
            human_review_receipt_sha256=receipt_sha256,
            human_review_reason="HEARING_BUDGET_EXHAUSTED",
        )
        assert connection.execute(
            """
            SELECT previous_checkpoint_id, human_review_receipt_id
            FROM m4_hearing_checkpoints
            WHERE run_id = ? AND checkpoint_id = ?
            """,
            (RUN_ID, terminal_id),
        ).fetchone() == (first_id, receipt_id)


def test_recrop_registry_requires_exact_request_manifest_frame_and_media(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    _populate_v7_authority(database)
    roots = _seed_m4_cycle_roots(database)
    frame_id = "cam-rec:stream-rec:7"
    crop_id = _digest("acquired-recropicrop")
    media_sha256 = _digest("acquired-recropicrop-media")
    pixel_sha256 = _digest("acquired-recropicrop-pixels")
    source_media_sha256 = _digest("acquired-recropicrop-source")
    acquisition_request_id = _digest("recrop-acquisition-request")
    execution_manifest_id = _digest("recrop-execution-manifest")
    request_json = json.dumps(
        {
            "request_payload": {
                "validated_parameters": {
                    "action": "RECROP",
                    "frame_id": frame_id,
                    "bbox": {"x1": 2, "y1": 3, "x2": 12, "y2": 13},
                }
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    def crop_json(*, x2: int = 12) -> str:
        return json.dumps(
            {
                "crop_id": crop_id,
                "frame_id": frame_id,
                "source": "RECROP",
                "bbox": {"x1": 2, "y1": 3, "x2": x2, "y2": 13},
                "source_refs": [
                    {"kind": "CROP", "artifact_id": _digest("source-crop")},
                    {"kind": "FRAME", "artifact_id": frame_id},
                ],
                "source_media_sha256": source_media_sha256,
                "pixel_sha256": pixel_sha256,
                "media_sha256": media_sha256,
                "output_width": x2 - 2,
                "output_height": 10,
                "size_bytes": 100,
                "media_type": "IMAGE_PNG",
                "encoding_version": "png-v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    with sqlite3.connect(database) as connection:
        # Upstream validators have their own tests.  This fixture isolates the
        # acquired-Crop closure trigger while retaining all referenced rows.
        connection.execute("DROP TRIGGER m4_acquisition_requests_validate_authority")
        connection.execute("DROP TRIGGER m4_tool_execution_manifests_validate_authority")
        connection.execute(
            """
            INSERT INTO frames(
                run_id, frame_id, manifest_id, camera_id, stream_id,
                frame_index, fps_num, fps_den, width, height,
                content_sha256, document_json, document_sha256
            ) VALUES (?, ?, ?, 'cam-rec', 'stream-rec', 7, 25, 1, 20, 20, ?, '{}', ?)
            """,
            (RUN_ID, frame_id, MANIFEST_ID, source_media_sha256, _digest("frame-document")),
        )
        connection.execute(
            """
            INSERT INTO media_assets(
                run_id, media_sha256, manifest_id, local_path, availability,
                pixel_sha256, width, height, size_bytes, media_type,
                encoding_version, ttl_expires_at, purged_at
            ) VALUES (?, ?, ?, 'runs/recrop.png', 'AVAILABLE', ?, 10, 10, 100,
                      'IMAGE_PNG', 'png-v1', NULL, NULL)
            """,
            (RUN_ID, media_sha256, MANIFEST_ID, pixel_sha256),
        )
        connection.execute(
            """
            INSERT INTO m4_acquisition_requests(
                run_id, acquisition_request_id, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id,
                round_index, prior_acquisition_rounds, prior_rework_rounds,
                evidence_pack_id, evidence_pack_version, judge_output_id,
                source_model_request_id, source_model_response_id, action,
                validated_parameters_sha256, manifest_id,
                request_json, document_sha256
            ) VALUES (
                :run_id, :request_id, :hearing_id,
                :cycle_scope_id, :cycle_scope_sha256, :case_id,
                1, 0, 0, :pack_id, 1, :judge_output_id,
                :model_request_id, :model_response_id, 'RECROP',
                :parameters_sha256, :manifest_id, :request_json, :document_sha256
            )
            """,
            {
                **roots,
                "run_id": RUN_ID,
                "case_id": CASE_ID,
                "request_id": acquisition_request_id,
                "judge_output_id": _digest("recrop-judge-output"),
                "model_request_id": _digest("recrop-model-request"),
                "model_response_id": _digest("recrop-model-response"),
                "parameters_sha256": _digest("recrop-parameters"),
                "manifest_id": MANIFEST_ID,
                "request_json": request_json,
                "document_sha256": _digest("recrop-request-document"),
            },
        )
        connection.execute(
            """
            INSERT INTO m4_tool_execution_manifests(
                run_id, execution_manifest_id, case_id, hearing_id,
                acquisition_request_id, action, tool_id, tool_revision,
                parameters_schema_sha256, component_manifest_id,
                model_manifest_id, manifest_id, manifest_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, 'RECROP', 'recrop-tool', 'v1', ?, ?,
                      NULL, ?, '{}', ?)
            """,
            (
                RUN_ID,
                execution_manifest_id,
                CASE_ID,
                roots["hearing_id"],
                acquisition_request_id,
                _digest("recrop-parameter-schema"),
                _digest("recrop-component"),
                MANIFEST_ID,
                _digest("recrop-manifest-document"),
            ),
        )
        insert_crop = """
            INSERT INTO m4_acquired_crops(
                run_id, crop_id, case_id, hearing_id, acquisition_request_id,
                execution_manifest_id, frame_id, media_sha256,
                source_media_sha256, pixel_sha256, source_pack_id,
                source_pack_version, manifest_id, crop_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        """
        common = (
            RUN_ID,
            crop_id,
            CASE_ID,
            roots["hearing_id"],
            acquisition_request_id,
            execution_manifest_id,
            frame_id,
            media_sha256,
            source_media_sha256,
            pixel_sha256,
            roots["pack_id"],
            MANIFEST_ID,
        )
        with pytest.raises(sqlite3.IntegrityError, match="acquired crop authority"):
            connection.execute(
                insert_crop,
                (*common, crop_json(x2=11), _digest("wrong-crop-document")),
            )
        connection.execute(
            insert_crop,
            (*common, crop_json(), _digest("crop-document")),
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m4_acquired_crops SET crop_json = crop_json WHERE run_id = ?",
                (RUN_ID,),
            )


def test_claim_reservations_and_usage_are_exactly_once(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    _populate_v7_authority(database)
    roots = _seed_m4_cycle_roots(database)
    request_id = _digest("initial-provider-request")
    response_id = _digest("initial-provider-response")
    request_sha256 = _digest("initial-provider-request-body")
    cache_key = _digest("initial-provider-cache-key")
    model_manifest_id = _digest("prosecutor-model")
    prompt_manifest_id = _digest("provider-prompt-manifest")
    owner_sha256 = _digest("provider-owner-one")

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO m4_model_call_claims(
                run_id, request_id, request_sha256, cache_key,
                hearing_id, cycle_scope_id, cycle_scope_sha256,
                case_id, role, purpose, attempt_index,
                call_generation, backlog_item_id, retry_generation,
                reserved_images, reserved_pixels,
                evidence_pack_id, evidence_pack_version,
                model_manifest_id, prompt_manifest_id, manifest_id,
                request_json, request_document_sha256,
                status, owner_token_sha256, lease_expires_at,
                takeover_count, created_at, response_id, completed_at
            ) VALUES (
                :run_id, :request_id, :request_sha256, :cache_key,
                :hearing_id, :cycle_scope_id, :cycle_scope_sha256,
                :case_id, 'PROSECUTOR', 'ROLE_CALL', 0,
                'INITIAL', NULL, 0, 5, 5000, :pack_id, 1,
                :model_manifest_id, :prompt_manifest_id, :manifest_id,
                '{}', :request_document_sha256,
                'ACTIVE', :owner_sha256, :lease_expires_at,
                0, :created_at, NULL, NULL
            )
            """,
            {
                **roots,
                "run_id": RUN_ID,
                "case_id": CASE_ID,
                "request_id": request_id,
                "request_sha256": request_sha256,
                "cache_key": cache_key,
                "model_manifest_id": model_manifest_id,
                "prompt_manifest_id": prompt_manifest_id,
                "manifest_id": MANIFEST_ID,
                "request_document_sha256": _digest("request-document"),
                "owner_sha256": owner_sha256,
                "lease_expires_at": "2026-07-28T01:03:00.000000Z",
                "created_at": NOW,
            },
        )
        takeover_owner = _digest("provider-owner-two")
        connection.execute(
            """
            UPDATE m4_model_call_claims
            SET owner_token_sha256 = ?, lease_expires_at = ?, takeover_count = 1
            WHERE run_id = ? AND request_id = ?
            """,
            (
                takeover_owner,
                "2026-07-28T01:04:00.000000Z",
                RUN_ID,
                request_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO m4_model_responses(
                run_id, response_id, request_id, request_sha256, cache_key,
                hearing_id, cycle_scope_id, cycle_scope_sha256,
                case_id, role, purpose, attempt_index,
                retry_generation, raw_response_ref, content_sha256, size_bytes,
                model_manifest_id, manifest_id, response_json, document_sha256
            ) VALUES (
                :run_id, :response_id, :request_id, :request_sha256, :cache_key,
                :hearing_id, :cycle_scope_id, :cycle_scope_sha256,
                :case_id, 'PROSECUTOR', 'ROLE_CALL', 0,
                0, 'runs/raw-response.json', :content_sha256, 2,
                :model_manifest_id, :manifest_id, '{}', :document_sha256
            )
            """,
            {
                **roots,
                "run_id": RUN_ID,
                "case_id": CASE_ID,
                "response_id": response_id,
                "request_id": request_id,
                "request_sha256": request_sha256,
                "cache_key": cache_key,
                "content_sha256": _digest("response-content"),
                "model_manifest_id": model_manifest_id,
                "manifest_id": MANIFEST_ID,
                "document_sha256": _digest("response-document"),
            },
        )
        connection.execute(
            """
            UPDATE m4_model_call_claims
            SET status = 'COMPLETED', response_id = ?, completed_at = ?
            WHERE run_id = ? AND request_id = ?
            """,
            (response_id, NOW, RUN_ID, request_id),
        )
        usage_id = _digest("provider-usage")
        usage_values = {
            **roots,
            "run_id": RUN_ID,
            "usage_receipt_id": usage_id,
            "request_id": request_id,
            "response_id": response_id,
            "case_id": CASE_ID,
            "manifest_id": MANIFEST_ID,
            "document_sha256": _digest("usage-document"),
        }
        connection.execute(
            """
            INSERT INTO m4_hearing_usage_receipts(
                run_id, usage_receipt_id, request_id, response_id,
                hearing_id, cycle_scope_id, cycle_scope_sha256,
                case_id, role, accounted_at,
                input_images, input_pixels, input_tokens, output_tokens,
                provider_latency_ms, retries, estimated_cost,
                manifest_id, usage_json, document_sha256
            ) VALUES (
                :run_id, :usage_receipt_id, :request_id, :response_id,
                :hearing_id, :cycle_scope_id, :cycle_scope_sha256,
                :case_id, 'PROSECUTOR', :accounted_at,
                5, 5000, 100, 20, 50, 0, 0.01,
                :manifest_id, '{}', :document_sha256
            )
            """,
            {**usage_values, "accounted_at": NOW},
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT INTO m4_hearing_usage_receipts(
                    run_id, usage_receipt_id, request_id, response_id,
                    hearing_id, cycle_scope_id, cycle_scope_sha256,
                    case_id, role, accounted_at,
                    input_images, input_pixels, input_tokens, output_tokens,
                    provider_latency_ms, retries, estimated_cost,
                    manifest_id, usage_json, document_sha256
                ) VALUES (
                    :run_id, :usage_receipt_id, :request_id, :response_id,
                    :hearing_id, :cycle_scope_id, :cycle_scope_sha256,
                    :case_id, 'PROSECUTOR', :accounted_at,
                    5, 5000, 100, 20, 50, 0, 0.01,
                    :manifest_id, '{}', :document_sha256
                )
                """,
                {
                    **usage_values,
                    "usage_receipt_id": _digest("duplicate-usage"),
                    "accounted_at": NOW,
                },
            )

        assert connection.execute(
            "SELECT COUNT(*), SUM(reserved_images) FROM m4_model_call_claims"
        ).fetchone() == (1, 5)
        with pytest.raises(sqlite3.IntegrityError, match="image reservation"):
            connection.execute(
                """
                INSERT INTO m4_model_call_claims(
                    run_id, request_id, request_sha256, cache_key,
                    hearing_id, cycle_scope_id, cycle_scope_sha256,
                    case_id, role, purpose, attempt_index,
                    call_generation, backlog_item_id, retry_generation,
                    reserved_images, reserved_pixels,
                    evidence_pack_id, evidence_pack_version,
                    model_manifest_id, prompt_manifest_id, manifest_id,
                    request_json, request_document_sha256,
                    status, owner_token_sha256, lease_expires_at,
                    takeover_count, created_at, response_id, completed_at
                )
                SELECT
                    run_id, ?, ?, ?, hearing_id, cycle_scope_id,
                    cycle_scope_sha256, case_id,
                    'DEFENDER', 'ROLE_CALL', 0, 'INITIAL', NULL, 0, 60, 60000,
                    evidence_pack_id, evidence_pack_version,
                    ?, prompt_manifest_id, manifest_id,
                    request_json, ?, 'ACTIVE', ?, ?, 0, created_at, NULL, NULL
                FROM m4_model_call_claims
                WHERE run_id = ? AND request_id = ?
                """,
                (
                    _digest("over-budget-request"),
                    _digest("over-budget-request-body"),
                    _digest("over-budget-cache-key"),
                    _digest("defender-model"),
                    _digest("over-budget-request-document"),
                    _digest("over-budget-owner"),
                    "2026-07-28T01:06:00.000000Z",
                    RUN_ID,
                    request_id,
                ),
            )
