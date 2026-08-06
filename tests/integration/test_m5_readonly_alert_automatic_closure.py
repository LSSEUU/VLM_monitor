from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.readonly_m5_artifacts import ReadonlyM5ArtifactRepository
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_repository import _audit_entry_from_row, _document
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.contracts.alert_policy import (
    AlertCooldownAuthority,
    AlertPolicyAuthority,
    AlertPolicyDisposition,
)
from labcourt.contracts.audit import AuditEntryDraft
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditActorRole,
)
from labcourt.contracts.events import derive_case_id
from labcourt.contracts.evidence import EvidencePackDraft
from labcourt.contracts.m5_artifact_validation import (
    M5AlertAuthorityReasonCode,
    M5ArtifactValidationIssueCode,
)
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.contracts.storage import ArtifactRef
from labcourt.services.m5_artifact_validation import validate_m5_artifacts
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    RUN_ID,
    _complete_call,
    _parsed,
    _parsed_receipt,
    _persist_direct_parse,
    _RawVerifier,
    _request,
    _response,
    _screening_for,
    _trusted_review,
    _verdict_for,
)
from tests.integration.test_m5_sqlite_alert_repository import (
    _automatic_precedent,
    _draft_for_manifest,
    _MutableClock,
    _prepare_ready_case,
)
from tests.integration.test_m5_sqlite_appeals import _prepare_closed_case


def _mutate_without_triggers(
    database: Path,
    trigger_names: tuple[str, ...],
    operation: Callable[[sqlite3.Connection], object],
) -> None:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        trigger_sql: list[str] = []
        for trigger_name in trigger_names:
            row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (trigger_name,),
            ).fetchone()
            assert row is not None and isinstance(row["sql"], str)
            trigger_sql.append(row["sql"])
            connection.execute(f'DROP TRIGGER "{trigger_name}"')
        operation(connection)
        for statement in trigger_sql:
            connection.execute(statement)


def _load_alert(connection: sqlite3.Connection) -> AlertPolicyAuthority:
    row = connection.execute(
        "SELECT authority_json FROM alerts WHERE run_id = ?",
        (RUN_ID,),
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    return AlertPolicyAuthority.model_validate_json(row[0])


def _load_automatic(connection: sqlite3.Connection) -> M5PrecedentAuthority:
    row = connection.execute(
        """
        SELECT authority_json FROM precedents
        WHERE run_id = ? AND source = 'AUTOMATIC' AND revision = 1
        """,
        (RUN_ID,),
    ).fetchone()
    assert row is not None and isinstance(row[0], str)
    return M5PrecedentAuthority.model_validate_json(row[0])


def _delete_precedent_causal_event(
    connection: sqlite3.Connection,
    authority: M5PrecedentAuthority,
) -> None:
    cursor = connection.execute(
        """
        DELETE FROM m5_precedent_causal_events
        WHERE run_id = ? AND event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
          AND source_id = ?
        """,
        (authority.run_id, authority.authority_id),
    )
    assert cursor.rowcount == 1


def _store_precedent(
    connection: sqlite3.Connection,
    authority: M5PrecedentAuthority,
    *,
    old_precedent_id: str,
    old_revision: int,
) -> None:
    raw, document_sha256 = _document(authority)
    precedent = authority.precedent
    dump = authority.model_dump(mode="json")
    connection.execute(
        """
        UPDATE precedents SET
            precedent_id = ?, revision = ?, authority_id = ?, status = ?, source = ?,
            evidence_class = ?, violation_type = ?, decision_direction = ?,
            rule_version = ?, source_case_id = ?, citation_count = ?,
            text_embedding_id = ?, visual_embedding_ids_json = ?, created_at = ?,
            activation_not_before = ?, activated_at = ?, authority_json = ?,
            document_sha256 = ?
        WHERE run_id = ? AND precedent_id = ? AND revision = ?
        """,
        (
            precedent.precedent_id,
            authority.revision,
            authority.authority_id,
            precedent.status.value,
            precedent.source.value,
            precedent.evidence_class.value,
            precedent.violation_type.value,
            precedent.decision_direction.value,
            precedent.rule_version,
            precedent.source_case_id,
            precedent.citation_count,
            authority.text_embedding.embedding_id if authority.text_embedding else None,
            canonical_json([item.embedding_id for item in authority.visual_embeddings]),
            dump["created_at"],
            dump["activation_not_before"],
            dump["activated_at"],
            raw,
            document_sha256,
            authority.run_id,
            old_precedent_id,
            old_revision,
        ),
    )


def _insert_precedent(
    connection: sqlite3.Connection,
    authority: M5PrecedentAuthority,
) -> None:
    raw, document_sha256 = _document(authority)
    precedent = authority.precedent
    dump = authority.model_dump(mode="json")
    connection.execute(
        """
        INSERT INTO precedents(
            run_id, precedent_id, revision, authority_id, status, source,
            evidence_class, violation_type, decision_direction, rule_version,
            source_case_id, citation_count, text_embedding_id,
            visual_embedding_ids_json, created_at, activation_not_before,
            activated_at, manifest_id, authority_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            authority.run_id,
            precedent.precedent_id,
            authority.revision,
            authority.authority_id,
            precedent.status.value,
            precedent.source.value,
            precedent.evidence_class.value,
            precedent.violation_type.value,
            precedent.decision_direction.value,
            precedent.rule_version,
            precedent.source_case_id,
            precedent.citation_count,
            authority.text_embedding.embedding_id if authority.text_embedding else None,
            canonical_json([item.embedding_id for item in authority.visual_embeddings]),
            dump["created_at"],
            dump["activation_not_before"],
            dump["activated_at"],
            next(
                row[0]
                for row in connection.execute(
                    "SELECT manifest_id FROM runs WHERE run_id = ?",
                    (authority.run_id,),
                )
            ),
            raw,
            document_sha256,
        ),
    )


def _rewrite_last_audit(
    connection: sqlite3.Connection,
    *,
    sequence: int,
    after_sha256: str | None = None,
    actor: AuditActorRole | None = None,
) -> None:
    row = connection.execute(
        "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
        (RUN_ID, sequence),
    ).fetchone()
    assert row is not None
    maximum = connection.execute(
        "SELECT MAX(sequence) FROM audit_entries WHERE run_id = ?",
        (RUN_ID,),
    ).fetchone()
    assert maximum is not None and maximum[0] == sequence
    current = _audit_entry_from_row(row)
    payload = current.model_dump(mode="json", exclude={"entry_hash"})
    if after_sha256 is not None:
        payload["after_sha256"] = after_sha256
    if actor is not None:
        payload["actor"] = actor.value
    rewritten = AuditEntryDraft.model_validate(payload).seal()
    raw, document_sha256 = _document(rewritten)
    connection.execute(
        """
        UPDATE audit_entries SET actor = ?, after_sha256 = ?, entry_hash = ?,
                                 entry_json = ?, document_sha256 = ?
        WHERE run_id = ? AND sequence = ?
        """,
        (
            rewritten.actor,
            rewritten.after_sha256,
            rewritten.entry_hash,
            raw,
            document_sha256,
            RUN_ID,
            sequence,
        ),
    )
    connection.execute(
        "UPDATE runs SET audit_head_hash = ? WHERE run_id = ?",
        (rewritten.entry_hash, RUN_ID),
    )


def _rewrite_closing_case(
    connection: sqlite3.Connection,
    transform: Callable[[Case], Case],
) -> None:
    alert_row = connection.execute(
        "SELECT case_id, closing_case_revision FROM alerts WHERE run_id = ?",
        (RUN_ID,),
    ).fetchone()
    assert alert_row is not None
    row = connection.execute(
        """
        SELECT case_json, audit_sequence FROM case_versions
        WHERE run_id = ? AND case_id = ? AND revision = ?
        """,
        (RUN_ID, alert_row["case_id"], alert_row["closing_case_revision"]),
    ).fetchone()
    assert row is not None and isinstance(row["case_json"], str)
    rewritten = Case.model_validate(transform(Case.model_validate_json(row["case_json"])))
    raw, document_sha256 = _document(rewritten)
    connection.execute(
        """
        UPDATE case_versions SET case_json = ?, document_sha256 = ?
        WHERE run_id = ? AND case_id = ? AND revision = ?
        """,
        (
            raw,
            document_sha256,
            RUN_ID,
            alert_row["case_id"],
            alert_row["closing_case_revision"],
        ),
    )
    _rewrite_last_audit(
        connection,
        sequence=int(row["audit_sequence"]),
        after_sha256=document_sha256,
    )


def _reasons(database: Path, config: object) -> set[str]:
    snapshot = ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID)  # type: ignore[arg-type]
    return {failure.reason_code for failure in snapshot.failures}


def _append_second_ready_case(
    *,
    database: Path,
    evidence: object,
    manifest: object,
    config: object,
    clock: _MutableClock,
    not_established: bool = False,
) -> object:
    base = _draft_for_manifest(manifest)  # type: ignore[arg-type]
    event = base.event.model_copy(
        update={
            "start_frame": 1,
            "l1_score": 0.05 if not_established else base.event.l1_score,
        }
    )
    draft = EvidencePackDraft.model_validate(
        base.model_copy(
            update={
                "case_id": derive_case_id(event.event_id),
                "event": event,
                "track_summary": base.track_summary.model_copy(
                    update={
                        "start_frame": 1,
                        "observed_frame_count": event.end_frame_exclusive - 1,
                    }
                ),
            }
        ).model_dump(mode="json")
    )
    evidence.create_or_get_case(RUN_ID, event)  # type: ignore[attr-defined]
    published = evidence.publish_pack(RUN_ID, 1, draft)  # type: ignore[attr-defined]
    pack = published.pack
    closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)  # type: ignore[attr-defined]
    review_verifier = DeterministicProceduralReviewVerifier(config, evidence)  # type: ignore[arg-type]
    m3 = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=clock,
        current_pack_verifier=evidence.verify_current_pack,  # type: ignore[attr-defined]
        raw_response_verifier=_RawVerifier(),
        procedural_review_verifier=review_verifier,
    )
    if not_established:
        request = _request(pack)
        response = _response(
            request,
            content_sha256="b" * 64,
            input_tokens=11,
            output_tokens=7,
            latency_ms=19,
        )
        output = _parsed(request, response, violation_probability=0.05)
        receipt = _parsed_receipt(request, response, output)
        _complete_call(m3, request, response)
        m3.append_parse_receipt(receipt, output)
    else:
        _, response, output, _ = _persist_direct_parse(m3, pack)
    screening = _screening_for(pack, output)
    screened = m3.commit_screening(
        RUN_ID,
        published.case.revision,
        evidence.get_audit_head(RUN_ID),  # type: ignore[attr-defined]
        closure,
        screening,
    ).case
    response_refs = (
        ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=response.response_id),
    )
    verdict = _verdict_for(screening, pack, response_refs)
    current_closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)  # type: ignore[attr-defined]
    history = m3.load_parse_history_for_output(
        RUN_ID,
        screening.parsed_output.parsed_output_id,
    )
    review = _trusted_review(evidence, verdict, pack, current_closure, history)  # type: ignore[arg-type]
    return m3.commit_verdict_review(
        RUN_ID,
        screened.revision,
        evidence.get_audit_head(RUN_ID),  # type: ignore[attr-defined]
        current_closure,
        verdict,
        review,
    ).case


def _insert_cooldown_row(
    connection: sqlite3.Connection,
    row: dict[str, object],
    *,
    revision: int,
) -> None:
    connection.execute(
        """
        INSERT INTO alert_cooldowns(
            run_id, key_id, revision, authority_id, zone_id, violation_type,
            track_ref, tracker_epoch, stream_id, stream_authority_sha256,
            source_alert_id, source_trigger_frame, cooldown_until_frame_exclusive,
            manifest_id, authority_json, document_sha256
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            row["run_id"],
            row["key_id"],
            revision,
            row["authority_id"],
            row["zone_id"],
            row["violation_type"],
            row["track_ref"],
            row["tracker_epoch"],
            row["stream_id"],
            row["stream_authority_sha256"],
            row["source_alert_id"],
            row["source_trigger_frame"],
            row["cooldown_until_frame_exclusive"],
            row["manifest_id"],
            row["authority_json"],
            row["document_sha256"],
        ),
    )


def _prepare_reordered_same_key_cooldowns(
    tmp_path: Path,
) -> tuple[Path, object, object, object, AlertPolicyAuthority, AlertPolicyAuthority]:
    clock = _MutableClock()
    database, evidence, repository, first_ready, manifest, config = _prepare_ready_case(
        tmp_path,
        clock=clock,
    )
    verifier = ConfiguredAlertPolicyVerifier(config)
    first = verifier.rebuild(first_ready.case, manifest, None, None)
    assert first.cooldown_write is not None
    first_automatic = _automatic_precedent(
        first_ready,
        manifest,
        config,
        first,
        created_at=clock.value,
    )
    repository.commit_alert_policy(
        RUN_ID,
        first_ready.revision,
        first,
        first_automatic,
    )

    saved_cooldown: dict[str, object] = {}

    def remove_first_cooldown(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT * FROM alert_cooldowns WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
        assert row is not None
        saved_cooldown.update(dict(row))
        connection.execute("DELETE FROM alert_cooldowns WHERE run_id = ?", (RUN_ID,))

    _mutate_without_triggers(
        database,
        ("alert_cooldowns_no_delete",),
        remove_first_cooldown,
    )

    clock.advance(seconds=1)
    second_ready = _append_second_ready_case(
        database=database,
        evidence=evidence,
        manifest=manifest,
        config=config,
        clock=clock,
    )
    second = verifier.rebuild(second_ready.case, manifest, None, None)  # type: ignore[attr-defined]
    assert second.cooldown_write is not None
    second_automatic = _automatic_precedent(
        second_ready,  # type: ignore[arg-type]
        manifest,
        config,
        second,
        created_at=clock.value,
    )
    repository.commit_alert_policy(
        RUN_ID,
        second_ready.revision,  # type: ignore[attr-defined]
        second,
        second_automatic,
    )

    with sqlite3.connect(database) as connection:
        _insert_cooldown_row(connection, saved_cooldown, revision=2)
    return database, manifest, config, first_ready, first, second


def _prepare_close_no_alert_then_alert(
    tmp_path: Path,
) -> tuple[Path, object, object, object, AlertPolicyAuthority, AlertPolicyAuthority]:
    clock = _MutableClock()
    database, evidence, repository, later_ready, manifest, config = _prepare_ready_case(
        tmp_path,
        clock=clock,
    )
    clock.advance(seconds=1)
    earlier_ready = _append_second_ready_case(
        database=database,
        evidence=evidence,
        manifest=manifest,
        config=config,
        clock=clock,
        not_established=True,
    )
    verifier = ConfiguredAlertPolicyVerifier(config)
    earlier = verifier.rebuild(earlier_ready.case, manifest, None, None)  # type: ignore[attr-defined]
    assert earlier.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT
    assert earlier.cooldown_write is None
    earlier_automatic = _automatic_precedent(
        earlier_ready,  # type: ignore[arg-type]
        manifest,
        config,
        earlier,
        created_at=clock.value,
    )
    repository.commit_alert_policy(
        RUN_ID,
        earlier_ready.revision,  # type: ignore[attr-defined]
        earlier,
        earlier_automatic,
    )

    clock.advance(seconds=1)
    later = verifier.rebuild(later_ready.case, manifest, None, None)
    assert later.cooldown_write is not None
    later_automatic = _automatic_precedent(
        later_ready,
        manifest,
        config,
        later,
        created_at=clock.value,
    )
    repository.commit_alert_policy(
        RUN_ID,
        later_ready.revision,
        later,
        later_automatic,
    )
    return database, manifest, config, earlier_ready, earlier, later


def test_clean_close_has_exact_bidirectional_alert_automatic_closure(tmp_path: Path) -> None:
    database, _repository, _closed, _manifest, config, _automatic = _prepare_closed_case(tmp_path)

    assert ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID).failures == ()


def test_cooldown_write_revision_must_follow_writer_close_sequence(tmp_path: Path) -> None:
    database, _manifest, config, _first_ready, _first, _second = (
        _prepare_reordered_same_key_cooldowns(tmp_path)
    )

    reasons = _reasons(database, config)
    assert M5AlertAuthorityReasonCode.ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH.value in reasons
    assert M5AlertAuthorityReasonCode.ALERT_COOLDOWN_WRITE_CAUSAL_CLOSURE_INVALID.value in reasons


def test_earlier_alert_cannot_claim_later_same_key_cooldown_head(tmp_path: Path) -> None:
    database, manifest, config, first_ready, first, second = _prepare_close_no_alert_then_alert(
        tmp_path
    )
    assert ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID).failures == ()
    assert first.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT
    assert first.cooldown_write is None and second.cooldown_write is not None
    forged = ConfiguredAlertPolicyVerifier(config).rebuild(  # type: ignore[arg-type]
        first_ready.case,  # type: ignore[attr-defined]
        manifest,  # type: ignore[arg-type]
        second.cooldown_write,
        None,
    )
    assert forged.request.prior_cooldown == second.cooldown_write

    def attack(connection: sqlite3.Connection) -> None:
        raw, document_sha256 = _document(forged)
        connection.execute(
            """
            UPDATE alerts SET authority_id = ?, policy_request_id = ?, disposition = ?,
                              alert_id = ?, final_decision = ?, authority_json = ?,
                              document_sha256 = ?
            WHERE run_id = ? AND case_id = ?
            """,
            (
                forged.authority_id,
                forged.request.request_id,
                forged.disposition.value,
                forged.decision.alert_id if forged.decision is not None else None,
                forged.final_decision.value,
                raw,
                document_sha256,
                RUN_ID,
                first.request.case_id,
            ),
        )

    _mutate_without_triggers(
        database,
        ("alerts_no_update",),
        attack,
    )

    reason = M5AlertAuthorityReasonCode.ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH
    snapshot = ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID)
    assert {failure.reason_code for failure in snapshot.failures} == {reason.value}
    workspace = tmp_path / "future-head-projection"
    workspace.mkdir()
    report = validate_m5_artifacts(
        config=config,  # type: ignore[arg-type]
        run_id=RUN_ID,
        database_path=database,
        workspace_root=workspace,
    )
    assert any(
        issue.code == M5ArtifactValidationIssueCode.ALERT_POLICY_REPLAY_INVALID
        and issue.reason_code == reason.value
        for issue in report.issues
    )


def test_close_no_alert_cannot_hide_wrong_key_prior_cooldown(tmp_path: Path) -> None:
    database, manifest, config, earlier_ready, earlier, later = _prepare_close_no_alert_then_alert(
        tmp_path
    )
    assert ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID).failures == ()
    assert earlier.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT
    assert later.cooldown_write is not None
    wrong_key = later.cooldown_write.key.model_copy(
        update={"track_ref": "cam-01:epoch-02:bottle-01"}
    )
    wrong_cooldown = AlertCooldownAuthority.model_validate(
        later.cooldown_write.model_copy(update={"key": wrong_key}).model_dump(mode="json")
    )
    forged = ConfiguredAlertPolicyVerifier(config).rebuild(  # type: ignore[arg-type]
        earlier_ready.case,  # type: ignore[attr-defined]
        manifest,  # type: ignore[arg-type]
        wrong_cooldown,
        None,
    )
    assert forged.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT
    assert forged.request.prior_cooldown == wrong_cooldown

    def attack(connection: sqlite3.Connection) -> None:
        cooldown_raw, cooldown_sha256 = _document(wrong_cooldown)
        _insert_cooldown_row(
            connection,
            {
                "run_id": RUN_ID,
                "key_id": wrong_cooldown.key.key_id,
                "authority_id": wrong_cooldown.authority_id,
                "zone_id": wrong_cooldown.key.zone_id,
                "violation_type": wrong_cooldown.key.violation_type.value,
                "track_ref": wrong_cooldown.key.track_ref,
                "tracker_epoch": wrong_cooldown.key.tracker_epoch,
                "stream_id": wrong_cooldown.stream_id,
                "stream_authority_sha256": later.request.stream_authority_sha256,
                "source_alert_id": wrong_cooldown.source_alert_id,
                "source_trigger_frame": wrong_cooldown.source_trigger_frame,
                "cooldown_until_frame_exclusive": (wrong_cooldown.cooldown_until_frame_exclusive),
                "manifest_id": later.request.manifest_id,
                "authority_json": cooldown_raw,
                "document_sha256": cooldown_sha256,
            },
            revision=1,
        )
        raw, document_sha256 = _document(forged)
        connection.execute(
            """
            UPDATE alerts SET authority_id = ?, policy_request_id = ?,
                              authority_json = ?, document_sha256 = ?
            WHERE run_id = ? AND case_id = ?
            """,
            (
                forged.authority_id,
                forged.request.request_id,
                raw,
                document_sha256,
                RUN_ID,
                earlier.request.case_id,
            ),
        )

    _mutate_without_triggers(
        database,
        ("alerts_no_update",),
        attack,
    )

    reasons = _reasons(database, config)
    assert M5AlertAuthorityReasonCode.ALERT_PRIOR_COOLDOWN_CAUSAL_HEAD_MISMATCH.value in reasons
    assert M5AlertAuthorityReasonCode.ALERT_POLICY_INPUT_ROOT_INVALID.value not in reasons


@pytest.mark.parametrize(
    ("target", "expected_reason"),
    (
        ("automatic", M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_MISSING),
        (
            "embedding",
            M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_EMBEDDING_CLOSURE_INVALID,
        ),
    ),
)
def test_automatic_delete_or_embedding_document_attack_breaks_exact_inventory(
    tmp_path: Path,
    target: str,
    expected_reason: M5AlertAuthorityReasonCode,
) -> None:
    database, _repository, _closed, _manifest, config, automatic = _prepare_closed_case(tmp_path)
    if target == "automatic":

        def delete_automatic_with_event(connection: sqlite3.Connection) -> None:
            _delete_precedent_causal_event(connection, automatic)
            connection.execute(
                "DELETE FROM precedents WHERE run_id = ? AND precedent_id = ? AND revision = 1",
                (RUN_ID, automatic.precedent.precedent_id),
            )

        _mutate_without_triggers(
            database,
            (
                "m5_precedent_causal_events_no_delete",
                "precedents_no_delete",
            ),
            delete_automatic_with_event,
        )
    else:
        assert automatic.text_embedding is not None
        embedding_id = automatic.text_embedding.embedding_id
        invalid_json = "{}"
        _mutate_without_triggers(
            database,
            ("precedent_embeddings_no_update",),
            lambda connection: connection.execute(
                """
                UPDATE precedent_embeddings
                SET embedding_json = ?, document_sha256 = ?
                WHERE run_id = ? AND embedding_id = ?
                """,
                (
                    invalid_json,
                    hashlib.sha256(invalid_json.encode()).hexdigest(),
                    RUN_ID,
                    embedding_id,
                ),
            ),
        )

    assert expected_reason.value in _reasons(database, config)


def test_invalid_policy_input_does_not_mask_missing_automatic_root(tmp_path: Path) -> None:
    database, _repository, _closed, _manifest, config, automatic = _prepare_closed_case(tmp_path)

    def attack(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            UPDATE alerts SET source_case_revision = 1, closing_case_revision = 2
            WHERE run_id = ?
            """,
            (RUN_ID,),
        )
        _delete_precedent_causal_event(connection, automatic)
        connection.execute(
            "DELETE FROM precedents WHERE run_id = ? AND precedent_id = ? AND revision = 1",
            (RUN_ID, automatic.precedent.precedent_id),
        )

    _mutate_without_triggers(
        database,
        (
            "alerts_no_update",
            "m5_precedent_causal_events_no_delete",
            "precedents_no_delete",
        ),
        attack,
    )

    reasons = _reasons(database, config)
    assert M5AlertAuthorityReasonCode.ALERT_POLICY_INPUT_ROOT_INVALID.value in reasons
    assert M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_MISSING.value in reasons


def test_second_automatic_lineage_for_one_close_is_rejected(tmp_path: Path) -> None:
    database, _repository, _closed, _manifest, config, automatic = _prepare_closed_case(tmp_path)
    second = M5PrecedentAuthority.model_validate(
        automatic.model_copy(
            update={
                "revision": 2,
                "precedent": automatic.precedent.model_copy(
                    update={"precedent_id": sha256_hex(["attack-second-automatic", 1])}
                ),
            }
        ).model_dump(mode="json")
    )
    _mutate_without_triggers(
        database,
        ("precedents_validate_contiguous_revision",),
        lambda connection: _insert_precedent(connection, second),
    )

    assert M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_DUPLICATE.value in _reasons(
        database, config
    )


@pytest.mark.parametrize("attack", ("content", "created_at"))
def test_rehashed_automatic_content_or_time_attack_fails_exact_replay(
    tmp_path: Path,
    attack: str,
) -> None:
    database, _repository, _closed, _manifest, config, automatic = _prepare_closed_case(tmp_path)
    if attack == "content":
        forged = automatic.model_copy(
            update={
                "precedent": automatic.precedent.model_copy(
                    update={"situation_text": f"{automatic.precedent.situation_text} tampered"}
                )
            }
        )
        expected = M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_REPLAY_MISMATCH
    else:
        delta = timedelta(days=1)
        assert automatic.activation_not_before is not None
        forged = automatic.model_copy(
            update={
                "created_at": automatic.created_at + delta,
                "activation_not_before": automatic.activation_not_before + delta,
            }
        )
        expected = M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_TIME_INVALID
    forged = M5PrecedentAuthority.model_validate(forged.model_dump(mode="json"))

    def replace_automatic_without_event(connection: sqlite3.Connection) -> None:
        _delete_precedent_causal_event(connection, automatic)
        _store_precedent(
            connection,
            forged,
            old_precedent_id=automatic.precedent.precedent_id,
            old_revision=automatic.revision,
        )

    _mutate_without_triggers(
        database,
        (
            "m5_precedent_causal_events_no_delete",
            "precedents_no_update",
        ),
        replace_automatic_without_event,
    )

    assert expected.value in _reasons(database, config)


def test_rehashed_policy_tamper_is_rejected_by_configured_replay(tmp_path: Path) -> None:
    database, _repository, _closed, _manifest, config, _automatic = _prepare_closed_case(tmp_path)

    def attack(connection: sqlite3.Connection) -> None:
        authority = _load_alert(connection)
        assert authority.decision is not None and authority.outbox_item is not None
        forged_rules = tuple(sorted((*authority.policy_rule_ids, "tampered-policy-rule")))
        decision = authority.decision.model_copy(update={"policy_rule_ids": forged_rules})
        outbox = authority.outbox_item.model_copy(update={"alert": decision})
        forged = AlertPolicyAuthority.model_validate(
            authority.model_copy(
                update={
                    "policy_rule_ids": forged_rules,
                    "decision": decision,
                    "outbox_item": outbox,
                }
            ).model_dump(mode="json")
        )
        alert_raw, alert_sha256 = _document(forged)
        outbox_raw, outbox_sha256 = _document(outbox)
        connection.execute(
            """
            UPDATE alerts SET authority_id = ?, authority_json = ?, document_sha256 = ?
            WHERE run_id = ?
            """,
            (forged.authority_id, alert_raw, alert_sha256, RUN_ID),
        )
        connection.execute(
            """
            UPDATE alert_outbox SET outbox_id = ?, alert_authority_id = ?,
                                    outbox_json = ?, document_sha256 = ?
            WHERE run_id = ?
            """,
            (outbox.outbox_id, forged.authority_id, outbox_raw, outbox_sha256, RUN_ID),
        )

        def replace_decision(closing: Case) -> Case:
            return closing.model_copy(update={"alerts": (*closing.alerts[:-1], decision)})

        _rewrite_closing_case(connection, replace_decision)

    _mutate_without_triggers(
        database,
        (
            "alerts_no_update",
            "alert_outbox_no_update",
            "case_versions_no_update",
            "audit_entries_no_update",
            "runs_monotonic_head_update",
            "runs_m6_audit_head_matches_entry",
        ),
        attack,
    )

    reasons = _reasons(database, config)
    assert M5AlertAuthorityReasonCode.ALERT_POLICY_REPLAY_MISMATCH.value in reasons
    workspace = tmp_path / "empty-projection"
    workspace.mkdir()
    report = validate_m5_artifacts(
        config=config,
        run_id=RUN_ID,
        database_path=database,
        workspace_root=workspace,
    )
    assert any(
        issue.code == M5ArtifactValidationIssueCode.ALERT_POLICY_REPLAY_INVALID
        and issue.reason_code == M5AlertAuthorityReasonCode.ALERT_POLICY_REPLAY_MISMATCH.value
        for issue in report.issues
    )


def test_rehashed_closing_timeline_tamper_breaks_exact_successor(tmp_path: Path) -> None:
    database, _repository, _closed, _manifest, config, _automatic = _prepare_closed_case(tmp_path)

    def attack(connection: sqlite3.Connection) -> None:
        def rewrite(closing: Case) -> Case:
            entry = closing.timeline[-1]
            details = dict(entry.details)
            details["disposition"] = "SUPPRESSED_MERGED"
            return closing.model_copy(
                update={
                    "timeline": (
                        *closing.timeline[:-1],
                        entry.model_copy(update={"details": details}),
                    )
                }
            )

        _rewrite_closing_case(connection, rewrite)

    _mutate_without_triggers(
        database,
        (
            "case_versions_no_update",
            "audit_entries_no_update",
            "runs_monotonic_head_update",
            "runs_m6_audit_head_matches_entry",
        ),
        attack,
    )

    assert M5AlertAuthorityReasonCode.ALERT_POLICY_INPUT_ROOT_INVALID.value in _reasons(
        database, config
    )


def test_rehashed_non_system_close_audit_breaks_causal_authority(tmp_path: Path) -> None:
    database, _repository, _closed, _manifest, config, _automatic = _prepare_closed_case(tmp_path)

    def attack(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            """
            SELECT v.audit_sequence FROM case_versions AS v
            JOIN alerts AS a ON a.run_id = v.run_id AND a.case_id = v.case_id
                             AND a.closing_case_revision = v.revision
            WHERE a.run_id = ?
            """,
            (RUN_ID,),
        ).fetchone()
        assert row is not None
        _rewrite_last_audit(
            connection,
            sequence=int(row["audit_sequence"]),
            actor=AuditActorRole.PROJECTOR,
        )

    _mutate_without_triggers(
        database,
        (
            "audit_entries_no_update",
            "runs_monotonic_head_update",
            "runs_m6_audit_head_matches_entry",
        ),
        attack,
    )

    reasons = _reasons(database, config)
    assert M5AlertAuthorityReasonCode.ALERT_POLICY_INPUT_ROOT_INVALID.value in reasons
    assert M5AlertAuthorityReasonCode.ALERT_AUTOMATIC_PRECEDENT_TIME_INVALID.value in reasons
