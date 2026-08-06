"""Adversarial integration tests for the M5 conflict causal cut.

These tests deliberately exercise the trust boundary independently from the
ordinary happy-path integration coverage.  Shared M5 fixtures stay in the
canonical SQLite precedent integration module so this file contains only the
causality-specific arrangements and attacks.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    record_m5_precedent_citation,
    resolve_m5_precedent_conflict,
    resolve_m5_precedent_conflict_batch,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import EvidenceClass, VerdictDecision, ViolationType
from labcourt.contracts.m5_artifact_validation import (
    M5PrecedentCausalLedgerReasonCode,
    M5PrecedentConflictHistoryReasonCode,
)
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
)
from labcourt.contracts.m5_precedents import (
    M5PrecedentAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictCausalCut,
    M5PrecedentConflictResolution,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
    m5_precedent_active_head_root_sha256,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.exceptions import ConcurrentModification, ContractViolation, ManifestMismatch
from tests.integration.test_m5_sqlite_precedents import (
    BUSY_TIMEOUT_MS,
    RUN_ID,
    SQLiteM5Repository,
    _authority,
    _clock,
    _config,
    _install,
    _policy,
    _query,
)


def _append_active_authorities(
    repository: SQLiteM5Repository,
    manifest: RunManifest,
    *precedent_ids: str,
    opposed: bool = True,
) -> tuple[M5PrecedentAuthority, ...]:
    authorities = tuple(
        _authority(
            manifest,
            precedent_id,
            direction=(
                VerdictDecision.NOT_ESTABLISHED
                if opposed and ordinal % 2
                else VerdictDecision.ESTABLISHED
            ),
        )
        for ordinal, precedent_id in enumerate(precedent_ids)
    )
    for authority in authorities:
        repository.append_authority(authority, None)
    return authorities


def _batch_resolution(
    repository: SQLiteM5Repository,
    *,
    limit: int,
    policy: M5PrecedentPolicy | None = None,
) -> M5PrecedentConflictBatchResolution:
    snapshot = repository.load_conflict_snapshot(RUN_ID, limit)
    return resolve_m5_precedent_conflict_batch(
        snapshot=snapshot,
        policy=policy or _policy(),
        scan_limit=limit,
    )


def _commit_direct_citation(
    repository: SQLiteM5Repository,
    *,
    manifest: RunManifest,
    case_id: str,
    precedent_id: str,
) -> M5PrecedentCitationCommit:
    query = _query(manifest, case_id)
    result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    citation = record_m5_precedent_citation(
        result=result,
        precedent_id=precedent_id,
        cited_at=_clock(),
    )
    return repository.commit_citation(citation)


def _causal_counts(database: Path) -> tuple[int, int, int, int]:
    with sqlite3.connect(database) as connection:
        return (
            connection.execute("SELECT COUNT(*) FROM precedents").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM precedent_conflict_batches").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM precedent_conflict_batch_receipts").fetchone()[
                0
            ],
            connection.execute(
                """
                SELECT COUNT(*) FROM m5_precedent_causal_events
                WHERE event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
                """
            ).fetchone()[0],
        )


def _readonly_reasons(database: Path) -> set[str]:
    snapshot = ReadonlyM5ArtifactRepository(
        database,
        config=_config(),  # type: ignore[no-untyped-call]
    ).scan(RUN_ID)
    return {failure.reason_code for failure in snapshot.failures}


def _rewrite_causal_event_order(
    database: Path,
    reorder: Callable[
        [tuple[M5PrecedentCausalEvent, ...]],
        tuple[M5PrecedentCausalEvent, ...],
    ],
) -> None:
    """Rechain every event after an adversarial semantic reorder.

    Every row and computed digest remains canonical.  This prevents a test from
    passing merely because the attacker forgot to repair a duplicated index or
    hash after changing causal order.
    """

    with sqlite3.connect(database) as connection:
        raw_rows = connection.execute(
            """
            SELECT event_json FROM m5_precedent_causal_events
            WHERE run_id = ? ORDER BY sequence
            """,
            (RUN_ID,),
        ).fetchall()
        original = tuple(M5PrecedentCausalEvent.model_validate_json(row[0]) for row in raw_rows)
        ordered = reorder(original)
        assert len(ordered) == len(original)
        assert {item.event_id for item in ordered} == {item.event_id for item in original}

        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'm5_precedent_causal_events_no_update'
            """
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute("DROP TRIGGER m5_precedent_causal_events_no_update")
        connection.execute(
            "UPDATE m5_precedent_causal_events SET sequence = sequence + 10000 WHERE run_id = ?",
            (RUN_ID,),
        )
        previous = M5_PRECEDENT_CAUSAL_GENESIS_SHA256
        for sequence, event in enumerate(ordered, start=1):
            rewritten = M5PrecedentCausalEvent.model_validate(
                {
                    **event.model_dump(
                        mode="python",
                        exclude={"source_identity_sha256", "event_id", "event_sha256"},
                    ),
                    "sequence": sequence,
                    "previous_event_sha256": previous,
                }
            )
            raw = canonical_json(rewritten.model_dump(mode="json"))
            cursor = connection.execute(
                """
                UPDATE m5_precedent_causal_events
                SET sequence = ?, previous_event_sha256 = ?, event_sha256 = ?,
                    event_json = ?, document_sha256 = ?
                WHERE run_id = ? AND event_id = ?
                """,
                (
                    rewritten.sequence,
                    rewritten.previous_event_sha256,
                    rewritten.event_sha256,
                    raw,
                    hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                    RUN_ID,
                    event.event_id,
                ),
            )
            assert cursor.rowcount == 1
            previous = rewritten.event_sha256
        connection.execute(trigger[0])


def _rewrite_marker_binding(
    database: Path,
    *,
    source_id: str | None = None,
    source_document_sha256: str | None = None,
) -> None:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT event_json FROM m5_precedent_causal_events
            WHERE run_id = ?
              AND event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
            """,
            (RUN_ID,),
        ).fetchone()
        assert row is not None
        marker = M5PrecedentCausalEvent.model_validate_json(row[0])
        forged = M5PrecedentCausalEvent.model_validate(
            {
                **marker.model_dump(
                    mode="python",
                    exclude={"source_identity_sha256", "event_id", "event_sha256"},
                ),
                "source_id": source_id or marker.source_id,
                "source_document_sha256": (source_document_sha256 or marker.source_document_sha256),
            }
        )
        raw = canonical_json(forged.model_dump(mode="json"))
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'm5_precedent_causal_events_no_update'
            """
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute("DROP TRIGGER m5_precedent_causal_events_no_update")
        cursor = connection.execute(
            """
            UPDATE m5_precedent_causal_events
            SET event_id = ?, source_identity_sha256 = ?, source_id = ?,
                source_document_sha256 = ?, event_sha256 = ?, event_json = ?,
                document_sha256 = ?
            WHERE run_id = ? AND event_id = ?
            """,
            (
                forged.event_id,
                forged.source_identity_sha256,
                forged.source_id,
                forged.source_document_sha256,
                forged.event_sha256,
                raw,
                hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                RUN_ID,
                marker.event_id,
            ),
        )
        assert cursor.rowcount == 1
        connection.execute(trigger[0])


def _replace_committed_batch_documents(
    database: Path,
    replacement: M5PrecedentConflictBatchResolution,
) -> None:
    """Synchronize every content-addressed batch/receipt/marker document.

    This models an attacker who knows how to recompute all public digests.  The
    remaining rejection therefore has to come from trusted configuration or
    historical causal reconstruction, not a stale denormalized column.
    """

    batch = replacement.batch_authority
    receipt = replacement.receipt
    batch_raw = canonical_json(batch.model_dump(mode="json"))
    policy_raw = canonical_json(replacement.policy.model_dump(mode="json"))
    receipt_raw = canonical_json(receipt.model_dump(mode="json"))
    batch_sha256 = hashlib.sha256(batch_raw.encode("utf-8")).hexdigest()
    policy_sha256 = hashlib.sha256(policy_raw.encode("utf-8")).hexdigest()
    receipt_sha256 = hashlib.sha256(receipt_raw.encode("utf-8")).hexdigest()
    changed_count = sum(
        node.prior_authority_id != node.resulting_authority_id for node in receipt.results
    )

    with sqlite3.connect(database) as connection:
        batch_trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'precedent_conflict_batches_no_update'
            """
        ).fetchone()
        receipt_trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'precedent_conflict_batch_receipts_no_update'
            """
        ).fetchone()
        assert batch_trigger is not None and isinstance(batch_trigger[0], str)
        assert receipt_trigger is not None and isinstance(receipt_trigger[0], str)
        connection.execute("DROP TRIGGER precedent_conflict_batches_no_update")
        connection.execute("DROP TRIGGER precedent_conflict_batch_receipts_no_update")
        batch_cursor = connection.execute(
            """
            UPDATE precedent_conflict_batches
            SET batch_authority_id = ?, policy_id = ?, config_sha256 = ?,
                causal_cut_id = ?, authority_event_sequence = ?,
                authority_event_sha256 = ?, active_head_root_sha256 = ?,
                scan_limit = ?, candidate_count = ?, evaluated_pair_count = ?,
                edge_count = ?, manifest_id = ?, authority_json = ?, policy_json = ?,
                policy_sha256 = ?, document_sha256 = ?
            WHERE run_id = ?
            """,
            (
                batch.batch_authority_id,
                batch.policy_id,
                batch.config_sha256,
                batch.causal_cut.cut_id,
                batch.causal_cut.authority_event_sequence,
                batch.causal_cut.authority_event_sha256,
                batch.causal_cut.active_head_root_sha256,
                batch.scan_limit,
                len(batch.candidates),
                batch.evaluated_pair_count,
                len(batch.edges),
                batch.causal_cut.manifest_id,
                batch_raw,
                policy_raw,
                policy_sha256,
                batch_sha256,
                RUN_ID,
            ),
        )
        assert batch_cursor.rowcount == 1
        receipt_cursor = connection.execute(
            """
            UPDATE precedent_conflict_batch_receipts
            SET receipt_id = ?, batch_authority_id = ?, causal_cut_id = ?,
                result_count = ?, changed_count = ?, manifest_id = ?,
                receipt_json = ?, document_sha256 = ?
            WHERE run_id = ?
            """,
            (
                receipt.receipt_id,
                receipt.batch_authority_id,
                receipt.causal_cut_id,
                len(receipt.results),
                changed_count,
                batch.causal_cut.manifest_id,
                receipt_raw,
                receipt_sha256,
                RUN_ID,
            ),
        )
        assert receipt_cursor.rowcount == 1
        connection.execute(batch_trigger[0])
        connection.execute(receipt_trigger[0])

    _rewrite_marker_binding(
        database,
        source_id=receipt.receipt_id,
        source_document_sha256=receipt_sha256,
    )


def _replace_batch_roots_with_legacy_pair_receipt(
    database: Path,
    *,
    pairwise: M5PrecedentConflictResolution,
    policy: M5PrecedentPolicy,
    manifest_id: str,
) -> None:
    """Build the immutable legacy shape left by the retired pairwise writer."""

    trigger_names = (
        "m5_precedent_causal_events_no_delete",
        "precedent_conflict_batch_receipts_no_delete",
        "precedent_conflict_batches_no_delete",
    )
    with sqlite3.connect(database) as connection:
        trigger_sql: dict[str, str] = {}
        for name in trigger_names:
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (name,),
            ).fetchone()
            assert row is not None and isinstance(row[0], str)
            trigger_sql[name] = row[0]
            connection.execute(f'DROP TRIGGER "{name}"')
        assert (
            connection.execute(
                """
                DELETE FROM m5_precedent_causal_events
                WHERE run_id = ?
                  AND event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
                """,
                (RUN_ID,),
            ).rowcount
            == 1
        )
        assert (
            connection.execute(
                "DELETE FROM precedent_conflict_batch_receipts WHERE run_id = ?",
                (RUN_ID,),
            ).rowcount
            == 1
        )
        assert (
            connection.execute(
                "DELETE FROM precedent_conflict_batches WHERE run_id = ?",
                (RUN_ID,),
            ).rowcount
            == 1
        )
        for name in trigger_names:
            connection.execute(trigger_sql[name])

        receipt = pairwise.receipt
        receipt_raw = canonical_json(receipt.model_dump(mode="json"))
        context_raw = canonical_json(policy.model_dump(mode="json"))
        connection.execute(
            """
            INSERT INTO precedent_lifecycle_receipts(
                run_id, receipt_id, receipt_kind, outcome,
                primary_precedent_id, primary_prior_authority_id,
                primary_prior_revision, primary_resulting_authority_id,
                primary_resulting_revision, secondary_precedent_id,
                secondary_prior_authority_id, secondary_prior_revision,
                secondary_resulting_authority_id, secondary_resulting_revision,
                manifest_id, receipt_json, context_json, context_sha256,
                document_sha256
            ) VALUES (?, ?, 'CONFLICT', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.run_id,
                receipt.receipt_id,
                receipt.outcome.value,
                receipt.existing_precedent_id,
                receipt.existing_prior_authority_id,
                receipt.existing_prior_revision,
                receipt.existing_resulting_authority_id,
                receipt.existing_resulting_revision,
                receipt.new_precedent_id,
                receipt.new_prior_authority_id,
                receipt.new_prior_revision,
                receipt.new_resulting_authority_id,
                receipt.new_resulting_revision,
                manifest_id,
                receipt_raw,
                context_raw,
                hashlib.sha256(context_raw.encode("utf-8")).hexdigest(),
                hashlib.sha256(receipt_raw.encode("utf-8")).hexdigest(),
            ),
        )


def _commit_changed_three_node_batch(
    tmp_path: Path,
) -> tuple[
    Path,
    str,
    RunManifest,
    SQLiteM5Repository,
    M5PrecedentConflictBatchResolution,
]:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-interval-a",
        "precedent-interval-b",
        "precedent-interval-c",
    )
    resolution = _batch_resolution(repository, limit=3)
    assert all(
        result.prior_authority_id != result.resulting_authority_id
        for result in resolution.receipt.results
    )
    assert repository.commit_conflict_batch(resolution) == resolution
    assert _readonly_reasons(database) == set()
    return database, case_id, manifest, repository, resolution


def test_authority_change_makes_old_conflict_snapshot_stale_without_partial_writes(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, second = _append_active_authorities(
        repository,
        manifest,
        "precedent-stale-authority-a",
        "precedent-stale-authority-b",
    )
    stale = _batch_resolution(repository, limit=3)

    later = _authority(
        manifest,
        "precedent-stale-authority-c",
        evidence_class=EvidenceClass.ABSENCE,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
    )
    repository.append_authority(later, None)

    with pytest.raises(ConcurrentModification, match="causal cut changed"):
        repository.commit_conflict_batch(stale)

    assert repository.get_precedent(RUN_ID, first.precedent.precedent_id) == first
    assert repository.get_precedent(RUN_ID, second.precedent.precedent_id) == second
    assert repository.get_precedent(RUN_ID, later.precedent.precedent_id) == later
    assert _causal_counts(database) == (3, 0, 0, 0)


def test_citation_only_after_snapshot_does_not_stale_authority_watermark(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, _second = _append_active_authorities(
        repository,
        manifest,
        "precedent-citation-only-a",
        "precedent-citation-only-b",
    )
    resolution = _batch_resolution(repository, limit=2)

    citation = _commit_direct_citation(
        repository,
        manifest=manifest,
        case_id=case_id,
        precedent_id=first.precedent.precedent_id,
    )
    assert repository.commit_conflict_batch(resolution) == resolution

    with sqlite3.connect(database) as connection:
        marker = connection.execute(
            """
            SELECT sequence, source_id FROM m5_precedent_causal_events
            WHERE event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
            """
        ).fetchone()
        citation_event = connection.execute(
            """
            SELECT sequence FROM m5_precedent_causal_events
            WHERE event_kind = 'PRECEDENT_CITATION_APPENDED' AND source_id = ?
            """,
            (citation.citation.citation_id,),
        ).fetchone()
    assert marker is not None and citation_event is not None
    assert marker[0] > citation_event[0]
    assert marker[1] == resolution.receipt.receipt_id
    assert _readonly_reasons(database) == set()


def test_noop_batch_has_one_marker_and_exact_replay_never_appends_another(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-noop-a",
        "precedent-noop-b",
        opposed=False,
    )
    resolution = _batch_resolution(repository, limit=2)
    assert all(
        result.prior_authority_id == result.resulting_authority_id
        for result in resolution.receipt.results
    )

    assert repository.commit_conflict_batch(resolution) == resolution
    assert repository.commit_conflict_batch(resolution) == resolution
    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert restarted.commit_conflict_batch(resolution) == resolution

    assert _causal_counts(database) == (2, 1, 1, 1)
    with sqlite3.connect(database) as connection:
        marker = connection.execute(
            """
            SELECT source_id FROM m5_precedent_causal_events
            WHERE event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
            """
        ).fetchone()
    assert marker == (resolution.receipt.receipt_id,)


@pytest.mark.parametrize(
    "fault_scope",
    (
        "precedent.conflict_batch.commit_marker.before_causal_event",
        "precedent.conflict_batch.commit_marker.after_causal_event",
    ),
)
def test_fault_on_either_side_of_marker_rolls_back_receipt_batch_and_event(
    tmp_path: Path,
    fault_scope: str,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-marker-fault-a",
        "precedent-marker-fault-b",
        opposed=False,
    )
    resolution = _batch_resolution(repository, limit=2)

    def fail_at(scope: str) -> None:
        if scope == fault_scope:
            raise RuntimeError("injected conflict marker fault")

    faulted = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        _clock,
        fault_injector=fail_at,
    )
    with pytest.raises(RuntimeError, match="injected conflict marker fault"):
        faulted.commit_conflict_batch(resolution)

    assert _causal_counts(database) == (2, 0, 0, 0)
    recovered = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert recovered.commit_conflict_batch(resolution) == resolution


def test_exact_historical_replay_survives_later_authority_and_citation_events(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, _second = _append_active_authorities(
        repository,
        manifest,
        "precedent-history-a",
        "precedent-history-b",
        opposed=False,
    )
    resolution = _batch_resolution(repository, limit=3)
    assert repository.commit_conflict_batch(resolution) == resolution

    later = _authority(
        manifest,
        "precedent-history-c",
        evidence_class=EvidenceClass.ABSENCE,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
    )
    repository.append_authority(later, None)
    _commit_direct_citation(
        repository,
        manifest=manifest,
        case_id=case_id,
        precedent_id=first.precedent.precedent_id,
    )
    before_replay = _causal_counts(database)

    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert restarted.commit_conflict_batch(resolution) == resolution
    assert _causal_counts(database) == before_replay == (3, 1, 1, 1)
    assert _readonly_reasons(database) == set()


def test_contract_valid_older_or_non_authority_cut_is_rejected(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, _second = _append_active_authorities(
        repository,
        manifest,
        "precedent-cut-anchor-a",
        "precedent-cut-anchor-b",
        opposed=False,
    )
    current = repository.load_conflict_snapshot(RUN_ID, 2)
    _commit_direct_citation(
        repository,
        manifest=manifest,
        case_id=case_id,
        precedent_id=first.precedent.precedent_id,
    )

    with sqlite3.connect(database) as connection:
        first_authority = connection.execute(
            """
            SELECT sequence, event_sha256 FROM m5_precedent_causal_events
            WHERE event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
            ORDER BY sequence LIMIT 1
            """
        ).fetchone()
        citation = connection.execute(
            """
            SELECT sequence, event_sha256 FROM m5_precedent_causal_events
            WHERE event_kind = 'PRECEDENT_CITATION_APPENDED'
            ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
    assert first_authority is not None and citation is not None

    for sequence, event_sha256 in (first_authority, citation):
        forged_cut = M5PrecedentConflictCausalCut.model_validate(
            {
                **current.causal_cut.model_dump(mode="python", exclude={"cut_id"}),
                "authority_event_sequence": sequence,
                "authority_event_sha256": event_sha256,
            }
        )
        forged_snapshot = M5PrecedentConflictSnapshot(
            causal_cut=forged_cut,
            authorities=current.authorities,
        )
        forged = resolve_m5_precedent_conflict_batch(
            snapshot=forged_snapshot,
            policy=_policy(),
            scan_limit=2,
        )
        with pytest.raises(ConcurrentModification, match="causal cut changed"):
            repository.commit_conflict_batch(forged)

    assert _causal_counts(database) == (2, 0, 0, 0)


def test_complete_active_candidate_deletion_with_recomputed_root_is_rejected(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-active-root-a",
        "precedent-active-root-b",
        "precedent-active-root-c",
        opposed=False,
    )
    current = repository.load_conflict_snapshot(RUN_ID, 3)
    truncated = current.authorities[:-1]
    forged_root = m5_precedent_active_head_root_sha256(
        run_id=RUN_ID,
        heads=tuple(
            (
                authority.precedent.precedent_id,
                authority.authority_id,
                authority.revision,
            )
            for authority in truncated
        ),
    )
    forged_cut = M5PrecedentConflictCausalCut.model_validate(
        {
            **current.causal_cut.model_dump(mode="python", exclude={"cut_id"}),
            "active_head_count": len(truncated),
            "active_head_root_sha256": forged_root,
        }
    )
    forged_snapshot = M5PrecedentConflictSnapshot(
        causal_cut=forged_cut,
        authorities=truncated,
    )
    forged = resolve_m5_precedent_conflict_batch(
        snapshot=forged_snapshot,
        policy=_policy(),
        scan_limit=3,
    )

    with pytest.raises(ConcurrentModification, match="causal cut changed"):
        repository.commit_conflict_batch(forged)
    assert _causal_counts(database) == (3, 0, 0, 0)


def test_pairwise_conflict_write_is_typed_rejected_without_writes(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, second = _append_active_authorities(
        repository,
        manifest,
        "precedent-legacy-pair-a",
        "precedent-legacy-pair-b",
    )
    pairwise = resolve_m5_precedent_conflict(
        existing=first,
        new=second,
        policy=_policy(),
    )

    with pytest.raises(ContractViolation, match=r"pair-wise.*disabled"):
        repository.commit_conflict(pairwise)
    assert _causal_counts(database) == (2, 0, 0, 0)


def test_forged_policy_and_matching_cut_are_rejected_by_trusted_config(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-forged-policy-a",
        "precedent-forged-policy-b",
        opposed=False,
    )
    current = repository.load_conflict_snapshot(RUN_ID, 2)
    trusted = _policy()
    forged_policy = trusted.model_copy(
        update={"conflict_similarity": trusted.conflict_similarity - 0.125}
    )
    forged_cut = M5PrecedentConflictCausalCut.model_validate(
        {
            **current.causal_cut.model_dump(mode="python", exclude={"cut_id"}),
            "policy_id": forged_policy.policy_id,
        }
    )
    forged_snapshot = M5PrecedentConflictSnapshot(
        causal_cut=forged_cut,
        authorities=current.authorities,
    )
    forged = resolve_m5_precedent_conflict_batch(
        snapshot=forged_snapshot,
        policy=forged_policy,
        scan_limit=2,
    )

    with pytest.raises(ManifestMismatch, match="trusted AppConfig"):
        repository.commit_conflict_batch(forged)
    assert _causal_counts(database) == (2, 0, 0, 0)


@pytest.mark.parametrize(
    "attack",
    ("missing", "forged_source", "wrong_receipt_hash"),
)
def test_readonly_rejects_missing_or_self_consistently_forged_marker(
    tmp_path: Path,
    attack: str,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        f"precedent-marker-{attack}-a",
        f"precedent-marker-{attack}-b",
        opposed=False,
    )
    repository.commit_conflict_batch(_batch_resolution(repository, limit=2))
    assert _readonly_reasons(database) == set()

    if attack == "missing":
        with sqlite3.connect(database) as connection:
            trigger = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger' AND name = 'm5_precedent_causal_events_no_delete'
                """
            ).fetchone()
            assert trigger is not None and isinstance(trigger[0], str)
            connection.execute("DROP TRIGGER m5_precedent_causal_events_no_delete")
            cursor = connection.execute(
                """
                DELETE FROM m5_precedent_causal_events
                WHERE run_id = ?
                  AND event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
                """,
                (RUN_ID,),
            )
            assert cursor.rowcount == 1
            connection.execute(trigger[0])
    elif attack == "forged_source":
        _rewrite_marker_binding(database, source_id="a" * 64)
    else:
        _rewrite_marker_binding(database, source_document_sha256="b" * 64)

    assert (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_MARKER_MISSING_OR_INVALID.value
        in _readonly_reasons(database)
    )


def test_readonly_rejects_synchronized_policy_cut_receipt_and_marker_forgery(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-readonly-policy-a",
        "precedent-readonly-policy-b",
        opposed=False,
    )
    original = _batch_resolution(repository, limit=2)
    repository.commit_conflict_batch(original)
    assert _readonly_reasons(database) == set()

    trusted = _policy()
    forged_policy = trusted.model_copy(
        update={"conflict_similarity": trusted.conflict_similarity - 0.125}
    )
    forged_cut = M5PrecedentConflictCausalCut.model_validate(
        {
            **original.batch_authority.causal_cut.model_dump(mode="python", exclude={"cut_id"}),
            "policy_id": forged_policy.policy_id,
        }
    )
    forged_snapshot = M5PrecedentConflictSnapshot(
        causal_cut=forged_cut,
        authorities=original.prior_authorities,
    )
    forged = resolve_m5_precedent_conflict_batch(
        snapshot=forged_snapshot,
        policy=forged_policy,
        scan_limit=2,
    )
    _replace_committed_batch_documents(database, forged)

    assert (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_TRUSTED_POLICY_MISMATCH.value
        in _readonly_reasons(database)
    )


def test_readonly_rejects_synchronized_non_authority_cut_anchor(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, _second = _append_active_authorities(
        repository,
        manifest,
        "precedent-readonly-cut-a",
        "precedent-readonly-cut-b",
        opposed=False,
    )
    original = _batch_resolution(repository, limit=2)
    _commit_direct_citation(
        repository,
        manifest=manifest,
        case_id=case_id,
        precedent_id=first.precedent.precedent_id,
    )
    repository.commit_conflict_batch(original)
    assert _readonly_reasons(database) == set()

    with sqlite3.connect(database) as connection:
        citation_anchor = connection.execute(
            """
            SELECT sequence, event_sha256 FROM m5_precedent_causal_events
            WHERE run_id = ? AND event_kind = 'PRECEDENT_CITATION_APPENDED'
            """,
            (RUN_ID,),
        ).fetchone()
    assert citation_anchor is not None
    forged_cut = M5PrecedentConflictCausalCut.model_validate(
        {
            **original.batch_authority.causal_cut.model_dump(mode="python", exclude={"cut_id"}),
            "authority_event_sequence": citation_anchor[0],
            "authority_event_sha256": citation_anchor[1],
        }
    )
    forged = resolve_m5_precedent_conflict_batch(
        snapshot=M5PrecedentConflictSnapshot(
            causal_cut=forged_cut,
            authorities=original.prior_authorities,
        ),
        policy=_policy(),
        scan_limit=2,
    )
    _replace_committed_batch_documents(database, forged)

    assert (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_CAUSAL_CUT_INVALID.value
        in _readonly_reasons(database)
    )


def test_readonly_rejects_candidate_deletion_even_after_recomputing_every_batch_digest(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-readonly-root-a",
        "precedent-readonly-root-b",
        "precedent-readonly-root-c",
        opposed=False,
    )
    original = _batch_resolution(repository, limit=3)
    repository.commit_conflict_batch(original)
    assert _readonly_reasons(database) == set()

    truncated = original.prior_authorities[:-1]
    forged_root = m5_precedent_active_head_root_sha256(
        run_id=RUN_ID,
        heads=tuple(
            (item.precedent.precedent_id, item.authority_id, item.revision) for item in truncated
        ),
    )
    forged_cut = M5PrecedentConflictCausalCut.model_validate(
        {
            **original.batch_authority.causal_cut.model_dump(mode="python", exclude={"cut_id"}),
            "active_head_count": len(truncated),
            "active_head_root_sha256": forged_root,
        }
    )
    forged = resolve_m5_precedent_conflict_batch(
        snapshot=M5PrecedentConflictSnapshot(
            causal_cut=forged_cut,
            authorities=truncated,
        ),
        policy=_policy(),
        scan_limit=3,
    )
    _replace_committed_batch_documents(database, forged)

    assert (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_ACTIVE_ROOT_MISMATCH.value
        in _readonly_reasons(database)
    )


@pytest.mark.parametrize("attack", ("extra", "missing", "reordered"))
def test_readonly_rejects_self_consistent_cut_to_marker_authority_interval_attack(
    tmp_path: Path,
    attack: str,
) -> None:
    database, _case_id, manifest, repository, _resolution = _commit_changed_three_node_batch(
        tmp_path
    )
    if attack == "extra":
        repository.append_authority(
            _authority(
                manifest,
                "precedent-interval-extra",
                evidence_class=EvidenceClass.ABSENCE,
                violation_type=ViolationType.PPE_GOGGLES_MISSING,
            ),
            None,
        )

    def reorder(
        events: tuple[M5PrecedentCausalEvent, ...],
    ) -> tuple[M5PrecedentCausalEvent, ...]:
        values = list(events)
        marker_index = next(
            index
            for index, event in enumerate(values)
            if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CONFLICT_BATCH_COMMITTED
        )
        changed_indexes = [
            index
            for index, event in enumerate(values)
            if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_AUTHORITY_APPENDED
            and event.precedent_revision == 2
        ]
        assert len(changed_indexes) == 3
        if attack == "reordered":
            left, right = changed_indexes[:2]
            values[left], values[right] = values[right], values[left]
        elif attack == "missing":
            marker = values.pop(marker_index)
            last_changed_index = next(
                index
                for index, event in enumerate(values)
                if event.event_id == events[changed_indexes[-1]].event_id
            )
            values.insert(last_changed_index, marker)
        else:
            assert marker_index == len(values) - 2
            values[marker_index], values[-1] = values[-1], values[marker_index]
        return tuple(values)

    _rewrite_causal_event_order(database, reorder)

    assert (
        M5PrecedentConflictHistoryReasonCode.CONFLICT_BATCH_CAUSAL_INTERVAL_INVALID.value
        in _readonly_reasons(database)
    )


def test_self_consistent_citation_reorder_before_its_authority_fails_closed(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, _second = _append_active_authorities(
        repository,
        manifest,
        "precedent-temporal-citation-a",
        "precedent-temporal-citation-b",
        opposed=False,
    )
    _commit_direct_citation(
        repository,
        manifest=manifest,
        case_id=case_id,
        precedent_id=first.precedent.precedent_id,
    )

    def citation_first(
        events: tuple[M5PrecedentCausalEvent, ...],
    ) -> tuple[M5PrecedentCausalEvent, ...]:
        citation = next(
            event
            for event in events
            if event.event_kind == M5PrecedentCausalEventKind.PRECEDENT_CITATION_APPENDED
        )
        return (citation, *(event for event in events if event != citation))

    _rewrite_causal_event_order(database, citation_first)

    with pytest.raises(RepositoryIntegrityError, match=r"causal|precedent|ledger"):
        repository.load_conflict_snapshot(RUN_ID, 2)
    assert (
        M5PrecedentCausalLedgerReasonCode.PRECEDENT_CAUSAL_EVENT_CHAIN_INVALID.value
        in _readonly_reasons(database)
    )


def test_complete_snapshot_limit_fails_before_any_conflict_write(tmp_path: Path) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-limit-a",
        "precedent-limit-b",
        "precedent-limit-c",
        opposed=False,
    )

    with pytest.raises(ContractViolation, match="complete snapshot budget"):
        repository.load_conflict_snapshot(RUN_ID, 2)
    assert _causal_counts(database) == (3, 0, 0, 0)


def test_marker_trigger_rejects_each_missing_required_nullable_json_key(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    _append_active_authorities(
        repository,
        manifest,
        "precedent-trigger-marker-a",
        "precedent-trigger-marker-b",
        opposed=False,
    )
    repository.commit_conflict_batch(_batch_resolution(repository, limit=2))

    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        marker = connection.execute(
            """
            SELECT * FROM m5_precedent_causal_events
            WHERE run_id = ?
              AND event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
            """,
            (RUN_ID,),
        ).fetchone()
        assert marker is not None
        connection.execute("DROP TRIGGER m5_precedent_causal_events_no_delete")
        connection.execute(
            "DELETE FROM m5_precedent_causal_events WHERE run_id = ? AND sequence = ?",
            (RUN_ID, marker["sequence"]),
        )
        for key in (
            "precedent_id",
            "precedent_authority_id",
            "precedent_revision",
            "citation_kind",
        ):
            payload = M5PrecedentCausalEvent.model_validate_json(marker["event_json"]).model_dump(
                mode="json"
            )
            payload.pop(key)
            forged_raw = canonical_json(payload)
            with pytest.raises(sqlite3.IntegrityError, match="source or index binding"):
                connection.execute(
                    """
                    INSERT INTO m5_precedent_causal_events(
                        run_id, sequence, event_id, source_identity_sha256,
                        event_kind, source_id, precedent_id, precedent_authority_id,
                        precedent_revision, citation_kind, manifest_id,
                        source_document_sha256, previous_event_sha256, event_sha256,
                        event_json, document_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        marker["run_id"],
                        marker["sequence"],
                        marker["event_id"],
                        marker["source_identity_sha256"],
                        marker["event_kind"],
                        marker["source_id"],
                        marker["precedent_id"],
                        marker["precedent_authority_id"],
                        marker["precedent_revision"],
                        marker["citation_kind"],
                        marker["manifest_id"],
                        marker["source_document_sha256"],
                        marker["previous_event_sha256"],
                        marker["event_sha256"],
                        forged_raw,
                        hashlib.sha256(forged_raw.encode("utf-8")).hexdigest(),
                    ),
                )

        connection.execute(
            """
            INSERT INTO m5_precedent_causal_events(
                run_id, sequence, event_id, source_identity_sha256,
                event_kind, source_id, precedent_id, precedent_authority_id,
                precedent_revision, citation_kind, manifest_id,
                source_document_sha256, previous_event_sha256, event_sha256,
                event_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(marker),
        )


def test_readonly_accepts_legacy_pair_receipt_but_rejects_its_forged_policy_context(
    tmp_path: Path,
) -> None:
    database, _case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, second = _append_active_authorities(
        repository,
        manifest,
        "precedent-legacy-readonly-a",
        "precedent-legacy-readonly-b",
    )
    policy = _policy()
    pairwise = resolve_m5_precedent_conflict(
        existing=first,
        new=second,
        policy=policy,
    )
    batch = _batch_resolution(repository, limit=2)
    assert batch.resulting_authorities == (
        pairwise.existing_authority,
        pairwise.new_authority,
    )
    repository.commit_conflict_batch(batch)
    _replace_batch_roots_with_legacy_pair_receipt(
        database,
        pairwise=pairwise,
        policy=policy,
        manifest_id=manifest.manifest_id,
    )

    assert _readonly_reasons(database) == set()

    forged_policy = policy.model_copy(
        update={"conflict_similarity": policy.conflict_similarity - 0.125}
    )
    forged_pairwise = resolve_m5_precedent_conflict(
        existing=first,
        new=second,
        policy=forged_policy,
    )
    assert forged_pairwise.existing_authority == pairwise.existing_authority
    assert forged_pairwise.new_authority == pairwise.new_authority
    forged_raw = canonical_json(forged_policy.model_dump(mode="json"))
    forged_receipt_raw = canonical_json(forged_pairwise.receipt.model_dump(mode="json"))
    with sqlite3.connect(database) as connection:
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'precedent_lifecycle_receipts_no_update'
            """
        ).fetchone()
        assert trigger is not None and isinstance(trigger[0], str)
        connection.execute("DROP TRIGGER precedent_lifecycle_receipts_no_update")
        assert (
            connection.execute(
                """
                UPDATE precedent_lifecycle_receipts
                SET receipt_id = ?, receipt_json = ?, document_sha256 = ?,
                    context_json = ?, context_sha256 = ?
                WHERE run_id = ? AND receipt_kind = 'CONFLICT'
                """,
                (
                    forged_pairwise.receipt.receipt_id,
                    forged_receipt_raw,
                    hashlib.sha256(forged_receipt_raw.encode("utf-8")).hexdigest(),
                    forged_raw,
                    hashlib.sha256(forged_raw.encode("utf-8")).hexdigest(),
                    RUN_ID,
                ),
            ).rowcount
            == 1
        )
        connection.execute(trigger[0])

    assert "LEGACY_CONFLICT_POLICY_REPLAY_INVALID" in _readonly_reasons(database)


def test_readonly_allows_citation_and_noop_marker_between_authority_cut_and_marker(
    tmp_path: Path,
) -> None:
    database, case_id, manifest = _install(tmp_path)
    repository = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    first, _second = _append_active_authorities(
        repository,
        manifest,
        "precedent-allowed-interval-a",
        "precedent-allowed-interval-b",
        opposed=False,
    )
    first_batch = _batch_resolution(repository, limit=2)
    _commit_direct_citation(
        repository,
        manifest=manifest,
        case_id=case_id,
        precedent_id=first.precedent.precedent_id,
    )
    repository.commit_conflict_batch(first_batch)

    second_batch = _batch_resolution(repository, limit=3)
    assert second_batch.batch_authority.causal_cut == first_batch.batch_authority.causal_cut
    assert second_batch.batch_authority.batch_authority_id != (
        first_batch.batch_authority.batch_authority_id
    )
    repository.commit_conflict_batch(second_batch)

    assert _readonly_reasons(database) == set()
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT COUNT(*) FROM m5_precedent_causal_events
            WHERE event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
            """
        ).fetchone() == (2,)
