from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.fake_alert_channel import DeterministicFakeAlertChannel
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.adapters.storage.secure_dataset_publisher import (
    SecureDatasetArtifactPublisher,
    SecureDatasetArtifactVerifier,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_m5_repository_appeals import (
    MAX_M5_TRAINING_LABELS,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.appeal_resolution import build_appeal_resolution_intent
from labcourt.application.dataset_export import build_coco_dataset
from labcourt.application.m5_appeal_precedent import build_appeal_overturn_precedent
from labcourt.application.m5_automatic_precedent import (
    build_automatic_precedent_authority,
)
from labcourt.application.m5_embedding_integrity import build_m5_controlled_fake_embedding
from labcourt.application.m5_human_labels import build_m5_appeal_training_labels
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    evaluate_m5_automatic_activation,
    m5_precedent_policy_from_config,
    record_m5_precedent_citation,
    revoke_m5_precedent,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    AppealStatus,
    CaseStatus,
    PrecedentStatus,
    RetentionHoldKind,
    RunMode,
    VerdictDecision,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m5_appeals import (
    AppealResolutionCommand,
    AppealResolutionSideEffectIntent,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
)
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_precedents import (
    M5EmbeddingChannel,
    M5EmbeddingVector,
    M5PrecedentAuthority,
    M5PrecedentRetrievalQuery,
)
from labcourt.contracts.m5_training import CocoDatasetExportCommand
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.appeal_fsm import begin_appeal_review, submit_appeal
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    RECORDED_AT,
    RUN_ID,
)
from tests.integration.test_m5_sqlite_alert_repository import _MutableClock, _prepare_ready_case


def _clock() -> datetime:
    return RECORDED_AT + timedelta(days=30)


def _table_counts(database: Path, *tables: str) -> tuple[int, ...]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in tables
        )


def _embed(
    manifest: RunManifest,
    *,
    situation_text: str,
) -> M5EmbeddingVector:
    return build_m5_controlled_fake_embedding(
        channel=M5EmbeddingChannel.TEXT,
        situation_text=situation_text,
        model_manifest=manifest.models["text_embedding"],
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
    )


def _prepare_closed_case(
    tmp_path: Path,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> tuple[
    Path,
    SQLiteM5Repository,
    CaseSnapshot,
    RunManifest,
    AppConfig,
    M5PrecedentAuthority,
]:
    clock = _MutableClock()
    database, _, repository, ready, manifest, config = _prepare_ready_case(
        tmp_path,
        fault_injector=fault_injector,
        clock=clock,
    )
    alert_authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    automatic = build_automatic_precedent_authority(
        case=ready.case,
        manifest=manifest,
        alert_authority=alert_authority,
        config=config,
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        created_at=RECORDED_AT,
    )
    closed = repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        alert_authority,
        automatic,
    )
    clock.advance(days=30)
    assert closed.case.status == CaseStatus.CLOSED
    return database, repository, closed, manifest, config, automatic


def _append_review(
    repository: SQLiteM5Repository,
    case_id: str,
) -> tuple[ClosedCaseAppealAuthority, AppealVersionAuthority, AppealVersionAuthority]:
    source = repository.load_closed_case_authority(RUN_ID, case_id)
    submitted = submit_appeal(
        source,
        AppealSubmissionCommand(
            run_id=source.run_id,
            case_id=source.case_id,
            appeal_id="appeal-sqlite-1",
            expected_case_revision=source.case_revision,
            expected_case_authority_sha256=source.authority_sha256,
            reason="The adjudication conflicts with the reviewed evidence.",
            submitted_by="subject-1",
        ),
        None,
    )
    assert repository.append_appeal_version(submitted, None) == submitted
    reviewed = begin_appeal_review(
        submitted,
        AppealReviewCommand(
            run_id=source.run_id,
            case_id=source.case_id,
            appeal_id=submitted.appeal.appeal_id,
            expected_appeal_authority_sha256=submitted.authority_sha256,
            reviewer_id="reviewer-1",
        ),
    )
    assert repository.append_appeal_version(reviewed, submitted.authority_sha256) == reviewed
    return source, submitted, reviewed


def _record_current_citation(
    repository: SQLiteM5Repository,
    source: ClosedCaseAppealAuthority,
    manifest: RunManifest,
    config: AppConfig,
) -> None:
    situation_text = "A current query that cites the automatic precedent."
    query = M5PrecedentRetrievalQuery(
        run_id=source.run_id,
        case_id=source.case_id,
        evidence_class=source.evidence_class,
        rule_version=source.rule_version,
        situation_text=situation_text,
        text_embedding_model_manifest_id=source.text_embedding_manifest_id,
        visual_embedding_model_manifest_id=source.visual_embedding_manifest_id,
        text_embedding=_embed(
            manifest,
            situation_text=situation_text,
        ),
        policy=m5_precedent_policy_from_config(config),
        top_k=10,
        run_mode=RunMode.STANDARD,
        include_provisional_experiment=False,
    )
    result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        repository.list_for_retrieval(query),
    )
    automatic_id = source.automatic_precedents[0].precedent_id
    selected = next(
        item
        for item in result.scored_precedents
        if item.authority.precedent.precedent_id == automatic_id
    )
    assert selected.authority.activated_at is not None
    commit = record_m5_precedent_citation(
        result=result,
        precedent_id=automatic_id,
        cited_at=selected.authority.activated_at,
    )
    assert repository.commit_citation(commit) == commit


def _activate_automatic_precedent(
    repository: SQLiteM5Repository,
    automatic: M5PrecedentAuthority,
) -> M5PrecedentAuthority:
    assert automatic.activation_not_before is not None
    assert automatic.precedent.source_case_id is not None
    eligible_at = automatic.activation_not_before
    snapshot = repository.load_appeal_window_snapshot(
        automatic.run_id,
        automatic.precedent.source_case_id,
        eligible_at,
    )
    assert snapshot.run_id == automatic.run_id
    assert snapshot.source_case_id == automatic.precedent.source_case_id
    assert snapshot.source_case_revision > 0
    assert len(snapshot.source_case_document_sha256) == 64
    assert snapshot.observed_through == eligible_at
    assert snapshot.appeal_ids == ()
    activation = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=snapshot,
        evaluated_at=eligible_at,
    )
    return repository.commit_activation(activation).authority


def _replacement_precedent(
    source: ClosedCaseAppealAuthority,
    manifest: RunManifest,
    config: AppConfig,
    appeal_id: str,
) -> M5PrecedentAuthority:
    situation_text = "Human appeal established that the cited crop does not show a violation."
    return build_appeal_overturn_precedent(
        case_authority=source,
        manifest=manifest,
        appeal_id=appeal_id,
        situation_text=situation_text,
        resolved_decision=VerdictDecision.NOT_ESTABLISHED,
        config=config,
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        created_at=RECORDED_AT,
    )


def _overturn_intent(
    repository: SQLiteM5Repository,
    closed: CaseSnapshot,
    source: ClosedCaseAppealAuthority,
    reviewed: AppealVersionAuthority,
    manifest: RunManifest,
    config: AppConfig,
) -> AppealResolutionSideEffectIntent:
    crop = closed.case.evidence_packs[-1].crops[0]
    labels = build_m5_appeal_training_labels(
        appeal_authority=reviewed,
        terminal_status=AppealStatus.OVERTURNED,
        authored_inputs=(
            M5AppealTrainingLabelInput(
                crop_id=crop.crop_id,
                bbox=BBoxXYXY(x1=0, y1=0, x2=10, y2=10),
                label_name="reagent_container_closed",
                label_value=True,
            ),
        ),
    )
    command = AppealResolutionCommand(
        run_id=source.run_id,
        case_id=source.case_id,
        appeal_id=reviewed.appeal.appeal_id,
        expected_appeal_authority_sha256=reviewed.authority_sha256,
        status=AppealStatus.OVERTURNED,
        reviewer_id="reviewer-1",
        resolution_summary="Human review overturned the original decision.",
        resolved_decision=VerdictDecision.NOT_ESTABLISHED,
        appeal_precedent_authority=_replacement_precedent(
            source,
            manifest,
            config,
            reviewed.appeal.appeal_id,
        ),
        training_labels=labels,
    )
    return build_appeal_resolution_intent(
        case_authority=source,
        appeal_authority=reviewed,
        precedent_snapshot=repository.load_resolution_precedent_snapshot(
            source.run_id,
            source.case_id,
        ),
        command=command,
    )


def _prepare_overturn(
    tmp_path: Path,
    *,
    fault_injector: Callable[[str], None] | None = None,
    with_citation: bool = True,
) -> tuple[
    Path,
    SQLiteM5Repository,
    CaseSnapshot,
    RunManifest,
    AppConfig,
    M5PrecedentAuthority,
    ClosedCaseAppealAuthority,
    AppealVersionAuthority,
    AppealVersionAuthority,
    AppealResolutionSideEffectIntent,
]:
    database, repository, closed, manifest, config, automatic = _prepare_closed_case(
        tmp_path,
        fault_injector=fault_injector,
    )
    automatic = _activate_automatic_precedent(repository, automatic)
    source = repository.load_closed_case_authority(RUN_ID, closed.case.case_id)
    if with_citation:
        _record_current_citation(repository, source, manifest, config)
    source, submitted, reviewed = _append_review(repository, closed.case.case_id)
    intent = _overturn_intent(repository, closed, source, reviewed, manifest, config)
    return (
        database,
        repository,
        closed,
        manifest,
        config,
        automatic,
        source,
        submitted,
        reviewed,
        intent,
    )


def test_overturn_commits_every_root_once_and_replays_without_case_revision(
    tmp_path: Path,
) -> None:
    (
        database,
        repository,
        closed,
        manifest,
        config,
        automatic,
        source,
        submitted,
        reviewed,
        intent,
    ) = _prepare_overturn(tmp_path)

    assert source.case_revision == closed.revision
    assert repository.load_current_appeal(RUN_ID, source.case_id) == reviewed
    pending_outbox = repository.list_pending_outbox(RUN_ID, 10)
    assert len(pending_outbox) == 1
    assert intent.affected_citations.citations[0].source_citation_id
    assert repository.commit_resolution(intent) == intent

    terminal = intent.appeal_authority
    assert repository.load_resolution(RUN_ID, terminal.appeal.appeal_id) == intent
    resolved = repository.load_case(RUN_ID, source.case_id)
    assert resolved.revision == source.case_revision + 3
    assert resolved.case.status == CaseStatus.APPEAL_RESOLVED
    assert resolved.case.final_decision == VerdictDecision.NOT_ESTABLISHED
    assert all(alert.rescinded for alert in resolved.case.alerts)
    assert repository.list_pending_outbox(RUN_ID, 10) == ()
    with pytest.raises(ContractViolation, match="rescinded alert"):
        repository.begin_dispatch(
            pending_outbox[0],
            "a" * 64,
            DeterministicFakeAlertChannel().capability_authority(
                run_id=RUN_ID,
                manifest_id=manifest.manifest_id,
                config_sha256=config.config_sha256,
            ),
        )
    assert repository.load_current_appeal(RUN_ID, source.case_id) == terminal
    assert repository.load_appeal_by_id(RUN_ID, terminal.appeal.appeal_id) == terminal
    assert repository.load_appeal_by_id(RUN_ID, "appeal-does-not-exist") is None
    assert repository.load_closed_case_authority(RUN_ID, source.case_id) == source
    revoked = repository.get_precedent(RUN_ID, automatic.precedent.precedent_id)
    assert revoked is not None and revoked.precedent.status == PrecedentStatus.REVOKED
    replacement = intent.appeal_precedent_authority
    assert replacement is not None
    assert repository.get_precedent(RUN_ID, replacement.precedent.precedent_id) == replacement

    tables = (
        "appeals",
        "appeal_resolution_receipts",
        "verdict_rescissions",
        "alert_rescissions",
        "precedents",
        "precedent_lifecycle_receipts",
        "strong_training_label_provenance_receipts",
        "training_labels",
        "case_versions",
        "audit_entries",
        "m5_precedent_causal_events",
    )
    committed_counts = _table_counts(database, *tables)
    assert repository.commit_resolution(intent) == intent
    assert _table_counts(database, *tables) == committed_counts
    assert repository.load_case(RUN_ID, source.case_id).revision == source.case_revision + 3

    with pytest.raises(ConcurrentModification, match="predecessor"):
        repository.append_appeal_version(reviewed, submitted.authority_sha256)

    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert restarted.list_pending_outbox(RUN_ID, 10) == ()
    assert restarted.load_current_appeal(RUN_ID, source.case_id) == terminal
    assert restarted.load_appeal_by_id(RUN_ID, terminal.appeal.appeal_id) == terminal
    assert restarted.load_resolution(RUN_ID, terminal.appeal.appeal_id) == intent
    assert restarted.load_closed_case_authority(RUN_ID, source.case_id) == source
    with sqlite3.connect(database) as connection:
        source_count = connection.execute("SELECT COUNT(*) FROM precedents").fetchone()[0]
        source_count += connection.execute("SELECT COUNT(*) FROM precedent_citations").fetchone()[0]
        source_count += connection.execute(
            "SELECT COUNT(*) FROM precedent_conflict_batch_receipts"
        ).fetchone()[0]
        source_count += connection.execute(
            "SELECT COUNT(*) FROM precedent_lifecycle_receipts WHERE receipt_kind = 'REVOCATION'"
        ).fetchone()[0]
        source_count += connection.execute(
            "SELECT COUNT(*) FROM appeal_resolution_commit_receipts"
        ).fetchone()[0]
        event_count = connection.execute(
            "SELECT COUNT(*) FROM m5_precedent_causal_events"
        ).fetchone()[0]
        assert event_count == source_count
        event_rows = connection.execute(
            """
            SELECT sequence, event_kind, source_id, precedent_authority_id
            FROM m5_precedent_causal_events ORDER BY sequence
            """
        ).fetchall()
        revocation_markers = [
            row for row in event_rows if row[1] == "PRECEDENT_REVOCATION_COMMITTED"
        ]
        assert len(revocation_markers) == len(intent.precedent_revocations)
        for sequence, _kind, _source_id, authority_id in revocation_markers:
            assert event_rows[sequence - 2][1:] == (
                "PRECEDENT_AUTHORITY_APPENDED",
                authority_id,
                authority_id,
            )
        assert event_rows[-1][1] == "APPEAL_RESOLUTION_COMMITTED"
        assert event_rows[-2][2] == replacement.authority_id
    assert ConfiguredAlertPolicyVerifier(config)


def test_resolution_replay_uses_historical_replacement_after_later_revocation(
    tmp_path: Path,
) -> None:
    database, repository, _, _, config, _, _, _, _, intent = _prepare_overturn(tmp_path)
    repository.commit_resolution(intent)
    replacement = intent.appeal_precedent_authority
    assert replacement is not None
    snapshot = repository.citation_snapshot(
        RUN_ID,
        replacement.precedent.precedent_id,
    )
    later = revoke_m5_precedent(
        authority=replacement,
        citation_snapshot=snapshot,
        revoked_by_ref="later-policy-revocation",
        revoked_at=snapshot.captured_at,
    )
    assert repository.commit_revocation(later) == later
    assert (
        repository.get_precedent(
            RUN_ID,
            replacement.precedent.precedent_id,
        )
        == later.authority
    )
    assert (
        repository.load_resolution(
            RUN_ID,
            intent.appeal_authority.appeal.appeal_id,
        )
        == intent
    )
    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert (
        restarted.load_resolution(
            RUN_ID,
            intent.appeal_authority.appeal.appeal_id,
        )
        == intent
    )
    assert ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID).failures == ()


def test_resolution_replay_requires_durable_revocation_receipt(tmp_path: Path) -> None:
    database, repository, _, _, _, _, source, _, _, intent = _prepare_overturn(tmp_path)
    repository.commit_resolution(intent)
    with sqlite3.connect(database) as connection:
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'precedent_lifecycle_receipts_no_delete'
            """
        ).fetchone()
        assert trigger_sql is not None and isinstance(trigger_sql[0], str)
        connection.execute("DROP TRIGGER precedent_lifecycle_receipts_no_delete")
        connection.execute(
            """
            DELETE FROM precedent_lifecycle_receipts
            WHERE run_id = ? AND receipt_kind = 'REVOCATION'
            """,
            (RUN_ID,),
        )
        connection.execute(str(trigger_sql[0]))
        connection.commit()

    with pytest.raises(RepositoryIntegrityError, match="causal source/event bijection"):
        SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock).commit_resolution(intent)
    assert repository.load_case(RUN_ID, source.case_id).revision == source.case_revision + 3


def test_resolution_replay_requires_final_commit_receipt(tmp_path: Path) -> None:
    database, repository, _, _, _, _, _, _, _, intent = _prepare_overturn(tmp_path)
    repository.commit_resolution(intent)
    with sqlite3.connect(database) as connection:
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'appeal_resolution_commit_receipts_no_delete'
            """
        ).fetchone()
        assert trigger_sql is not None and isinstance(trigger_sql[0], str)
        connection.execute("DROP TRIGGER appeal_resolution_commit_receipts_no_delete")
        connection.execute(
            "DELETE FROM appeal_resolution_commit_receipts WHERE run_id = ?",
            (RUN_ID,),
        )
        connection.execute(str(trigger_sql[0]))
        connection.commit()

    with pytest.raises(RepositoryIntegrityError, match="final causal commit receipt"):
        SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock).load_resolution(
            RUN_ID,
            intent.appeal_authority.appeal.appeal_id,
        )


def test_resolution_read_rejects_self_consistent_verdict_rescission_rebinding(
    tmp_path: Path,
) -> None:
    database, repository, _, _, _, _, _, _, _, intent = _prepare_overturn(
        tmp_path,
        with_citation=False,
    )
    repository.commit_resolution(intent)
    original = intent.verdict_rescission
    assert original is not None
    forged = original.model_copy(update={"verdict_sha256": "f" * 64})
    payload = {
        "run_id": intent.run_id,
        "resolution_intent_id": intent.intent_id,
        "case_id": intent.case_id,
        "rescission": forged.model_dump(mode="json"),
    }
    raw = canonical_json(payload)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    forged_id = sha256_hex(["m5-verdict-rescission", 1, payload])

    with sqlite3.connect(database) as connection:
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger' AND name = 'verdict_rescissions_no_update'
            """
        ).fetchone()
        assert trigger_sql is not None and isinstance(trigger_sql[0], str)
        connection.execute("DROP TRIGGER verdict_rescissions_no_update")
        connection.execute(
            """
            UPDATE verdict_rescissions
            SET rescission_id = ?, verdict_sha256 = ?,
                rescission_json = ?, document_sha256 = ?
            WHERE run_id = ? AND resolution_intent_id = ?
            """,
            (
                forged_id,
                forged.verdict_sha256,
                raw,
                digest,
                intent.run_id,
                intent.intent_id,
            ),
        )
        connection.execute(str(trigger_sql[0]))
        connection.commit()

    with pytest.raises(RepositoryIntegrityError, match="row differs from intent"):
        SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock).load_resolution(
            intent.run_id,
            intent.appeal_authority.appeal.appeal_id,
        )


def test_training_label_inventory_is_complete_stable_bounded_and_restart_safe(
    tmp_path: Path,
) -> None:
    database, repository, _, _, _, _, _, _, reviewed, intent = _prepare_overturn(tmp_path)
    first = intent.training_labels[0]
    labels = build_m5_appeal_training_labels(
        appeal_authority=reviewed,
        terminal_status=AppealStatus.OVERTURNED,
        authored_inputs=(
            M5AppealTrainingLabelInput(
                crop_id=first.crop_id,
                bbox=first.bbox,
                label_name=first.label_name,
                label_value=first.label_value,
            ),
            M5AppealTrainingLabelInput(
                crop_id=first.crop_id,
                bbox=first.bbox,
                label_name="secondary_review_fact",
                label_value=False,
            ),
        ),
    )
    payload = intent.model_dump(
        mode="json",
        exclude={"intent_id", "final_decision_changed"},
    )
    payload["training_labels"] = [label.model_dump(mode="json") for label in labels]
    expanded = AppealResolutionSideEffectIntent.model_validate(payload)
    repository.commit_resolution(expanded)

    expected = labels
    assert repository.list_training_labels(RUN_ID, 2) == expected
    authorities = repository.list_training_label_authorities(RUN_ID, 2)
    assert tuple(item.label for item in authorities) == expected
    assert all(item.strong_provenance is not None for item in authorities)
    with pytest.raises(ContractViolation, match="exceeds the requested"):
        repository.list_training_labels(RUN_ID, 1)
    with pytest.raises(ContractViolation, match="complete-scan limit"):
        repository.list_training_labels(RUN_ID, MAX_M5_TRAINING_LABELS + 1)

    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    assert restarted.list_training_labels(RUN_ID, MAX_M5_TRAINING_LABELS) == expected


def test_missing_strong_label_provenance_fails_inventory_and_resolution_replay(
    tmp_path: Path,
) -> None:
    database, repository, _, _, _, _, _, _, _, intent = _prepare_overturn(tmp_path)
    repository.commit_resolution(intent)
    label_id = intent.training_labels[0].label_id

    with sqlite3.connect(database) as connection:
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'strong_training_label_provenance_receipts_no_delete'
            """
        ).fetchone()
        assert trigger_sql is not None and isinstance(trigger_sql[0], str)
        connection.execute("DROP TRIGGER strong_training_label_provenance_receipts_no_delete")
        connection.execute(
            """
            DELETE FROM strong_training_label_provenance_receipts
            WHERE run_id = ? AND label_id = ?
            """,
            (RUN_ID, label_id),
        )
        connection.execute(trigger_sql[0])
        connection.commit()

    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    with pytest.raises(RepositoryIntegrityError, match="lacks exact provenance"):
        restarted.list_training_labels(RUN_ID, MAX_M5_TRAINING_LABELS)
    with pytest.raises(RepositoryIntegrityError, match="provenance inventory"):
        restarted.load_resolution(
            RUN_ID,
            intent.appeal_authority.appeal.appeal_id,
        )


def test_missing_training_label_causal_event_fails_inventory_and_resolution_replay(
    tmp_path: Path,
) -> None:
    database, repository, _, _, _, _, _, _, _, intent = _prepare_overturn(tmp_path)
    repository.commit_resolution(intent)
    label_id = intent.training_labels[0].label_id

    with sqlite3.connect(database) as connection:
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm5_training_causal_events_no_delete'
            """
        ).fetchone()
        assert trigger_sql is not None and isinstance(trigger_sql[0], str)
        connection.execute("DROP TRIGGER m5_training_causal_events_no_delete")
        connection.execute(
            """
            DELETE FROM m5_training_causal_events
            WHERE run_id = ? AND label_id = ?
            """,
            (RUN_ID, label_id),
        )
        connection.execute(trigger_sql[0])
        connection.commit()

    restarted = SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock)
    with pytest.raises(RepositoryIntegrityError, match="causal event is missing"):
        restarted.list_training_labels(RUN_ID, MAX_M5_TRAINING_LABELS)
    with pytest.raises(RepositoryIntegrityError, match="causal event is missing"):
        restarted.load_resolution(
            RUN_ID,
            intent.appeal_authority.appeal.appeal_id,
        )


@pytest.mark.parametrize(
    "phase",
    [
        "appeal.resolve.after_authority",
        "appeal.resolve.after_receipt",
        "appeal.resolve.after_verdict_rescission",
        "appeal.resolve.after_alert_rescissions",
        "precedent.appeal_revocation.after_authority",
        "precedent.appeal_revocation.resulting_authority.before_causal_event",
        "precedent.appeal_revocation.resulting_authority.after_causal_event",
        "precedent.appeal_revocation.receipt.after_source",
        "precedent.appeal_revocation.receipt.before_causal_event",
        "precedent.appeal_revocation.receipt.after_causal_event",
        "precedent.appeal_revocation.after_receipt",
        "appeal.resolve.after_precedent_revocations",
        "appeal.resolve.replacement_precedent.before_causal_event",
        "appeal.resolve.replacement_precedent.after_causal_event",
        "appeal.resolve.after_replacement_precedent",
        "appeal.resolve.after_training_label_provenance",
        "appeal.resolve.after_training_label_causal_events",
        "appeal.resolve.after_training_labels",
        "appeal.resolve.after_case",
        "appeal.resolve.commit_receipt.after_source",
        "appeal.resolve.commit_receipt.before_causal_event",
        "appeal.resolve.commit_receipt.after_causal_event",
        "appeal.resolve.after_commit_marker",
    ],
)
def test_resolution_fault_rolls_back_every_root(tmp_path: Path, phase: str) -> None:
    def fail_at(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"injected appeal fault at {phase}")

    (
        database,
        repository,
        _,
        _,
        _,
        automatic,
        source,
        _,
        reviewed,
        intent,
    ) = _prepare_overturn(tmp_path, fault_injector=fail_at)
    tables = (
        "appeals",
        "appeal_resolution_receipts",
        "appeal_resolution_commit_receipts",
        "verdict_rescissions",
        "alert_rescissions",
        "precedents",
        "precedent_lifecycle_receipts",
        "strong_training_label_provenance_receipts",
        "m5_training_causal_events",
        "training_labels",
        "case_versions",
        "audit_entries",
        "m5_precedent_causal_events",
    )
    before = _table_counts(database, *tables)
    case_before = repository.load_case(RUN_ID, source.case_id)
    precedent_before = repository.get_precedent(
        RUN_ID,
        automatic.precedent.precedent_id,
    )

    with pytest.raises(RuntimeError, match="injected appeal fault"):
        repository.commit_resolution(intent)

    assert _table_counts(database, *tables) == before
    assert repository.load_case(RUN_ID, source.case_id) == case_before
    assert repository.load_current_appeal(RUN_ID, source.case_id) == reviewed
    assert repository.get_precedent(RUN_ID, automatic.precedent.precedent_id) == precedent_before
    assert repository.get_precedent(RUN_ID, "appeal-overturn-precedent-1") is None


@pytest.mark.parametrize("phase", ["appeal.append.after_authority", "appeal.append.after_case"])
def test_appeal_append_fault_does_not_consume_version_or_case_revision(
    tmp_path: Path,
    phase: str,
) -> None:
    def fail_at(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"injected append fault at {phase}")

    database, repository, closed, _, _, _ = _prepare_closed_case(
        tmp_path,
        fault_injector=fail_at,
    )
    source = repository.load_closed_case_authority(RUN_ID, closed.case.case_id)
    submitted = submit_appeal(
        source,
        AppealSubmissionCommand(
            run_id=RUN_ID,
            case_id=source.case_id,
            appeal_id="appeal-fault",
            expected_case_revision=source.case_revision,
            expected_case_authority_sha256=source.authority_sha256,
            reason="This decision needs human review.",
            submitted_by="subject-1",
        ),
        None,
    )
    before = _table_counts(database, "appeals", "case_versions", "audit_entries")

    with pytest.raises(RuntimeError, match="injected append fault"):
        repository.append_appeal_version(submitted, None)

    assert _table_counts(database, "appeals", "case_versions", "audit_entries") == before
    assert repository.load_current_appeal(RUN_ID, source.case_id) is None
    assert repository.load_case(RUN_ID, source.case_id).revision == source.case_revision


def test_resolution_rejects_a_citation_added_after_snapshot_without_partial_effects(
    tmp_path: Path,
) -> None:
    database, repository, closed, manifest, config, automatic = _prepare_closed_case(tmp_path)
    _activate_automatic_precedent(repository, automatic)
    source, _, reviewed = _append_review(repository, closed.case.case_id)
    stale_intent = _overturn_intent(
        repository,
        closed,
        source,
        reviewed,
        manifest,
        config,
    )
    _record_current_citation(repository, source, manifest, config)
    before = _table_counts(
        database,
        "appeals",
        "appeal_resolution_receipts",
        "precedents",
        "precedent_lifecycle_receipts",
        "training_labels",
        "case_versions",
    )

    with pytest.raises(ConcurrentModification, match="snapshot changed"):
        repository.commit_resolution(stale_intent)

    assert (
        _table_counts(
            database,
            "appeals",
            "appeal_resolution_receipts",
            "precedents",
            "precedent_lifecycle_receipts",
            "training_labels",
            "case_versions",
        )
        == before
    )
    assert repository.load_current_appeal(RUN_ID, source.case_id) == reviewed
    assert repository.load_case(RUN_ID, source.case_id).revision == source.case_revision + 2


def test_resolution_rejects_forged_side_effect_composition_before_any_write(
    tmp_path: Path,
) -> None:
    database, repository, _, _, _, _, source, _, reviewed, intent = _prepare_overturn(tmp_path)
    payload = intent.model_dump(
        mode="json",
        exclude={"intent_id", "final_decision_changed"},
    )
    payload["alert_rescissions"] = []
    forged = AppealResolutionSideEffectIntent.model_validate(payload)
    before = _table_counts(
        database,
        "appeals",
        "appeal_resolution_receipts",
        "verdict_rescissions",
        "alert_rescissions",
        "precedents",
        "training_labels",
        "case_versions",
    )

    with pytest.raises(ContractViolation, match="trusted reconstruction"):
        repository.commit_resolution(forged)

    assert (
        _table_counts(
            database,
            "appeals",
            "appeal_resolution_receipts",
            "verdict_rescissions",
            "alert_rescissions",
            "precedents",
            "training_labels",
            "case_versions",
        )
        == before
    )
    assert repository.load_current_appeal(RUN_ID, source.case_id) == reviewed


def test_resolution_rejects_caller_forged_ground_truth_label_before_any_write(
    tmp_path: Path,
) -> None:
    database, repository, _, _, _, _, source, _, reviewed, intent = _prepare_overturn(tmp_path)
    payload = intent.model_dump(
        mode="json",
        exclude={"intent_id", "final_decision_changed"},
    )
    forged_label = dict(payload["training_labels"][0])
    forged_label["source"] = "caller-asserted-ground-truth"
    payload["training_labels"] = [forged_label]
    forged = AppealResolutionSideEffectIntent.model_validate(payload)
    before = _table_counts(
        database,
        "appeals",
        "appeal_resolution_receipts",
        "precedents",
        "training_labels",
        "case_versions",
    )

    with pytest.raises(
        ContractViolation,
        match="trusted appeal resolution reconstruction",
    ):
        repository.commit_resolution(forged)

    assert (
        _table_counts(
            database,
            "appeals",
            "appeal_resolution_receipts",
            "precedents",
            "training_labels",
            "case_versions",
        )
        == before
    )
    assert repository.load_current_appeal(RUN_ID, source.case_id) == reviewed


def test_resolution_rejects_forged_replacement_vector_before_any_write(
    tmp_path: Path,
) -> None:
    database, repository, _, _, _, _, source, _, reviewed, intent = _prepare_overturn(tmp_path)
    replacement = intent.appeal_precedent_authority
    assert replacement is not None and replacement.text_embedding is not None
    original_embedding = replacement.text_embedding
    embedding_payload = original_embedding.model_dump(
        mode="json",
        exclude={"embedding_id"},
    )
    embedding_payload["values"] = [-value for value in original_embedding.values]
    forged_embedding = M5EmbeddingVector.model_validate(embedding_payload)
    authority_payload = replacement.model_dump(mode="json", exclude={"authority_id"})
    authority_payload["text_embedding"] = forged_embedding.model_dump(mode="json")
    authority_payload["precedent"]["text_embedding_ref"] = forged_embedding.embedding_id
    forged_replacement = M5PrecedentAuthority.model_validate(authority_payload)
    intent_payload = intent.model_dump(
        mode="json",
        exclude={"intent_id", "final_decision_changed"},
    )
    intent_payload["appeal_precedent_authority"] = forged_replacement.model_dump(mode="json")
    forged = AppealResolutionSideEffectIntent.model_validate(intent_payload)
    before = _table_counts(
        database,
        "appeals",
        "appeal_resolution_receipts",
        "precedents",
        "precedent_lifecycle_receipts",
        "training_labels",
        "case_versions",
    )

    with pytest.raises(ContractViolation, match="vector differs"):
        repository.commit_resolution(forged)

    assert (
        _table_counts(
            database,
            "appeals",
            "appeal_resolution_receipts",
            "precedents",
            "precedent_lifecycle_receipts",
            "training_labels",
            "case_versions",
        )
        == before
    )
    assert repository.load_current_appeal(RUN_ID, source.case_id) == reviewed


def test_reloaded_appeal_reconstructs_source_and_rejects_canonical_hash_tamper(
    tmp_path: Path,
) -> None:
    database, repository, closed, _, _, _ = _prepare_closed_case(tmp_path)
    source = repository.load_closed_case_authority(RUN_ID, closed.case.case_id)
    submitted = submit_appeal(
        source,
        AppealSubmissionCommand(
            run_id=RUN_ID,
            case_id=source.case_id,
            appeal_id="appeal-tamper",
            expected_case_revision=source.case_revision,
            expected_case_authority_sha256=source.authority_sha256,
            reason="This decision needs reconstruction testing.",
            submitted_by="subject-1",
        ),
        None,
    )
    repository.append_appeal_version(submitted, None)
    assert (
        SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock).load_current_appeal(
            RUN_ID,
            source.case_id,
        )
        == submitted
    )

    source_payload = source.model_dump(mode="json", exclude={"authority_sha256"})
    source_payload["rule_version"] = "tampered-rules-v1"
    tampered_source = ClosedCaseAppealAuthority.model_validate(source_payload)
    authority_payload = submitted.model_dump(mode="json", exclude={"authority_sha256"})
    authority_payload.update(
        {
            "source_case_authority": tampered_source.model_dump(mode="json"),
            "source_case_authority_sha256": tampered_source.authority_sha256,
            "rule_version": tampered_source.rule_version,
        }
    )
    tampered = AppealVersionAuthority.model_validate(authority_payload)
    raw = canonical_json(tampered.model_dump(mode="json"))
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    with sqlite3.connect(database) as connection:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'appeals_no_update'"
        ).fetchone()
        assert trigger_sql is not None and isinstance(trigger_sql[0], str)
        connection.execute("DROP TRIGGER appeals_no_update")
        connection.execute(
            """
            UPDATE appeals
            SET authority_sha256 = ?, source_case_authority_sha256 = ?,
                rule_version = ?, authority_json = ?, document_sha256 = ?
            WHERE run_id = ? AND appeal_id = ? AND version = 1
            """,
            (
                tampered.authority_sha256,
                tampered.source_case_authority_sha256,
                tampered.rule_version,
                raw,
                digest,
                RUN_ID,
                submitted.appeal.appeal_id,
            ),
        )
        connection.execute(str(trigger_sql[0]))
        connection.commit()

    with pytest.raises(RepositoryIntegrityError, match="immutable source roots"):
        SQLiteM5Repository(database, BUSY_TIMEOUT_MS, _clock).load_current_appeal(
            RUN_ID,
            source.case_id,
        )


def test_secure_dataset_publish_registers_atomically_and_recovers_after_registry_fault(
    tmp_path: Path,
) -> None:
    database_root = tmp_path / "db"
    database_root.mkdir()
    database, _, _, _, manifest, config = _prepare_ready_case(database_root)
    built = build_coco_dataset(
        command=CocoDatasetExportCommand(
            run_id=RUN_ID,
            relative_path="datasets/reviewed.coco.json",
            detector_manifest_id=manifest.models["detector"].model_manifest_id,
            manifest_id=manifest.manifest_id,
            rule_version=manifest.rule_version,
            purpose="DETECTOR_TRAINING_FROM_REVIEWED_LABELS",
            retention_hold_kind=RetentionHoldKind.GOLD_SET,
            retention_policy_version="m5-gold-set-retention-v1",
            retention_period="UNTIL_EXPLICIT_RELEASE",
        ),
        labels=(),
        crop_authorities=(),
    )

    def fail_at(phase: str) -> None:
        if phase == "dataset.register.after_artifact":
            raise RuntimeError("injected dataset registry fault")

    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    with SecureWorkspace(workspace_root, max_file_bytes=1024 * 1024) as workspace:
        verifier = StoredPngVerifier(
            run_id=RUN_ID,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        faulty = SQLiteM5Repository(
            database,
            BUSY_TIMEOUT_MS,
            _clock,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
            fault_injector=fail_at,
        )
        publisher = SecureDatasetArtifactPublisher(workspace=workspace, repository=faulty)
        with pytest.raises(RuntimeError, match="dataset registry fault"):
            publisher.publish(built.report, built.content)

    target = workspace_root / "datasets" / "reviewed.coco.json"
    assert target.read_bytes() == built.content
    assert _table_counts(database, "dataset_artifacts") == (0,)

    with SecureWorkspace(workspace_root, max_file_bytes=1024 * 1024) as workspace:
        verifier = StoredPngVerifier(
            run_id=RUN_ID,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        clean = SQLiteM5Repository(
            database,
            BUSY_TIMEOUT_MS,
            _clock,
            training_crop_verifier=verifier,
            dataset_artifact_verifier=SecureDatasetArtifactVerifier(workspace),
        )
        publisher = SecureDatasetArtifactPublisher(workspace=workspace, repository=clean)
        assert publisher.publish(built.report, built.content) == built.report.dataset
        assert publisher.publish(built.report, built.content) == built.report.dataset
    assert target.read_bytes() == built.content
    assert _table_counts(database, "dataset_artifacts") == (1,)
