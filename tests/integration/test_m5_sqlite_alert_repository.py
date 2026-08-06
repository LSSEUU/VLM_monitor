from __future__ import annotations

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
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_m5_repository_alerts import (
    MAX_PENDING_ALERT_OUTBOX,
    MAX_READY_ALERT_CASES,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
    _document,
)
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.automatic_precedent_verifier import (
    ConfiguredAutomaticPrecedentVerifier,
)
from labcourt.application.m5_automatic_precedent import (
    build_automatic_precedent_authority,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.config_loader import load_config
from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertChannelIdempotencyGuarantee,
    AlertDispatchAttempt,
    AlertDispatchContinuation,
    AlertDispatchDisposition,
    AlertDispatchFailureCode,
    AlertDispatchReceipt,
    AlertOutboxItem,
    AlertPolicyAuthority,
)
from labcourt.contracts.alerts import DeliveryReceipt
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    PrecedentSource,
    PrecedentStatus,
)
from labcourt.contracts.evidence import EvidencePackDraft
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.manifests import (
    RunManifest,
    SoftwareComponentManifest,
    StreamManifest,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ConcurrentModification, ContractViolation, ManifestMismatch
from labcourt.ports.alert_policy import (
    ImmediateSafetyDeliveryDisabledError,
    ImmediateSafetyDeliveryFailureCode,
)
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.services.m5_artifact_validation import validate_m5_artifacts
from tests.contract.test_m5_alert_contracts import _emergency_delivery
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    RECORDED_AT,
    ROOT,
    RUN_ID,
    _detection,
    _draft,
    _frame,
    _manifest,
    _persist_direct_parse,
    _RawVerifier,
    _screening_for,
    _trusted_review,
    _verdict_for,
    _Verifier,
)


def _clock() -> datetime:
    return RECORDED_AT


class _MutableClock:
    def __init__(self, value: datetime = RECORDED_AT) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **kwargs: int) -> None:
        self.value += timedelta(**kwargs)


def _channel_capability(
    *,
    exact: bool = True,
    manifest: RunManifest | None = None,
    config: AppConfig | None = None,
) -> AlertChannelCapabilityAuthority:
    selected_manifest = manifest or _manifest_with_stream()
    selected_config = config or load_config(ROOT / "configs" / "demo.yaml")
    if exact:
        return DeterministicFakeAlertChannel().capability_authority(
            run_id=RUN_ID,
            manifest_id=selected_manifest.manifest_id,
            config_sha256=selected_config.config_sha256,
        )
    return AlertChannelCapabilityAuthority(
        run_id=RUN_ID,
        manifest_id=selected_manifest.manifest_id,
        config_sha256=selected_config.config_sha256,
        channel="non-idempotent-fake-alert-v1",
        capability_revision="non-idempotent-fake-capability-v1",
        idempotency_guarantee=AlertChannelIdempotencyGuarantee.NONE,
        provider_idempotency_key=None,
    )


def _owner(worker_id: str) -> str:
    return sha256_hex(["test-alert-dispatch-worker", 1, worker_id])


class _DispatchSelectionRepository(SQLiteM5Repository):
    """Selection-only fixture that isolates durable outbox ordering."""

    def _require_outbox_close_authority(
        self,
        connection: sqlite3.Connection,
        outbox_row: sqlite3.Row,
        item: AlertOutboxItem,
    ) -> None:
        del connection, outbox_row, item


def _insert_outbox_clone(
    database: Path,
    source: AlertOutboxItem,
    suffix: str,
) -> AlertOutboxItem:
    alert = source.alert.model_copy(update={"alert_id": sha256_hex(["fairness-alert", 1, suffix])})
    clone = AlertOutboxItem(
        run_id=source.run_id,
        case_id=source.case_id,
        case_authority_sha256=source.case_authority_sha256,
        policy_request_id=source.policy_request_id,
        manifest_id=source.manifest_id,
        alert=alert,
        priority=source.priority,
        idempotency_key=alert.alert_id,
    )
    raw, digest = _document(clone)
    with sqlite3.connect(database) as connection:
        authority = connection.execute(
            "SELECT alert_authority_id FROM alert_outbox WHERE outbox_id = ?",
            (source.outbox_id,),
        ).fetchone()
        assert authority is not None
        connection.execute(
            """
            INSERT INTO alert_outbox(
                run_id, outbox_id, alert_authority_id, alert_id, case_id,
                case_authority_sha256, policy_request_id, priority,
                idempotency_key, manifest_id, outbox_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                clone.run_id,
                clone.outbox_id,
                str(authority[0]),
                clone.alert.alert_id,
                clone.case_id,
                clone.case_authority_sha256,
                clone.policy_request_id,
                clone.priority.value,
                clone.idempotency_key,
                clone.manifest_id,
                raw,
                digest,
            ),
        )
    return clone


def _dispatch_receipt(
    attempt: AlertDispatchAttempt,
    *,
    disposition: AlertDispatchDisposition,
    failure_code: AlertDispatchFailureCode | None = None,
) -> AlertDispatchReceipt:
    exhausted = attempt.attempt_number >= 3
    if disposition == AlertDispatchDisposition.SUCCEEDED:
        continuation = AlertDispatchContinuation.CLOSED
        delivery = DeliveryReceipt(
            alert_id=attempt.alert_id,
            channel=attempt.channel_capability.channel,
            idempotency_key=attempt.idempotency_key,
            accepted=True,
            provider_receipt_ref=f"provider-{attempt.attempt_id}",
        )
    elif disposition == AlertDispatchDisposition.RETRYABLE_FAILURE:
        continuation = (
            AlertDispatchContinuation.ATTENTION_REQUIRED
            if exhausted
            else AlertDispatchContinuation.RETRY_ALLOWED
        )
        delivery = None
    else:
        retry_safe = (
            attempt.channel_capability.idempotency_guarantee
            == AlertChannelIdempotencyGuarantee.EXACT_ALERT_ID
            and not exhausted
        )
        continuation = (
            AlertDispatchContinuation.RETRY_ALLOWED
            if retry_safe
            else AlertDispatchContinuation.ATTENTION_REQUIRED
        )
        delivery = None
    return AlertDispatchReceipt(
        attempt_id=attempt.attempt_id,
        outbox_id=attempt.outbox_id,
        alert_id=attempt.alert_id,
        case_id=attempt.case_id,
        attempt_number=attempt.attempt_number,
        fence=attempt.fence,
        lease_owner_sha256=attempt.lease_owner_sha256,
        started_at=attempt.started_at,
        lease_expires_at=attempt.lease_expires_at,
        channel_capability=attempt.channel_capability,
        idempotency_key=attempt.idempotency_key,
        disposition=disposition,
        continuation=continuation,
        failure_code=failure_code,
        delivery_receipt=delivery,
    )


def _manifest_with_stream() -> RunManifest:
    base = _manifest()
    component = SoftwareComponentManifest(
        component="fixture-decoder",
        package="fixture-decoder",
        version="1.0.0",
        license_id="synthetic-fixture",
    )
    stream = StreamManifest(
        camera_id="cam-01",
        stream_id="demo-ntsc",
        input_file_sha256="1" * 64,
        fps_num=30,
        fps_den=1,
        timing_mode="CFR",
        timing_authority="TRUSTED_SIDECAR",
        timing_evidence_type="TRUSTED_SIDECAR_JSON",
        timing_evidence_sha256="2" * 64,
        width=640,
        height=480,
        frame_count=1_000,
        decoder="fixture",
        decoder_version="1.0.0",
        backend="fixture",
        software_component=component.component,
        library=component.package,
        library_version=component.version,
        codec="fake",
        color_conversion="IDENTITY",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )
    return base.model_copy(
        update={
            "streams": (stream,),
            "software_components": {component.component: component},
        }
    )


def _draft_for_manifest(manifest: RunManifest) -> EvidencePackDraft:
    base = _draft(version=1, complete=True)
    event = base.event.model_copy(update={"manifest_id": manifest.manifest_id})
    payload = base.model_dump(mode="json", exclude_computed_fields=True)
    payload["event"] = event.model_dump(mode="json")
    payload["manifest_id"] = manifest.manifest_id
    return EvidencePackDraft.model_validate(payload)


def _prepare_ready_case(
    tmp_path: Path,
    *,
    fault_injector: Callable[[str], None] | None = None,
    clock: Callable[[], datetime] = _clock,
    channel_capability_exact: bool = True,
    draft: EvidencePackDraft | None = None,
) -> tuple[
    Path,
    SQLiteEvidenceRepository,
    SQLiteM5Repository,
    CaseSnapshot,
    RunManifest,
    AppConfig,
]:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=clock).apply_all()
    manifest = _manifest_with_stream()
    evidence = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=clock,
    )
    evidence.register_run(RUN_ID, manifest)
    evidence.register_frame(RUN_ID, _frame())
    evidence.register_detection(RUN_ID, _detection())
    selected_draft = draft or _draft_for_manifest(manifest)
    evidence.create_or_get_case(RUN_ID, selected_draft.event)
    published = evidence.publish_pack(RUN_ID, 1, selected_draft)
    pack = published.pack
    closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)
    config = load_config(ROOT / "configs" / "demo.yaml")
    review_verifier = DeterministicProceduralReviewVerifier(config, evidence)
    m3 = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
        procedural_review_verifier=review_verifier,
    )
    _, response, output, _ = _persist_direct_parse(m3, pack)
    screening = _screening_for(pack, output)
    screened = m3.commit_screening(
        RUN_ID,
        published.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        screening,
    ).case
    response_refs = (
        ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        ),
    )
    verdict = _verdict_for(screening, pack, response_refs)
    current_closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)
    history = m3.load_parse_history_for_output(
        RUN_ID,
        screening.parsed_output.parsed_output_id,
    )
    review = _trusted_review(evidence, verdict, pack, current_closure, history)
    ready = m3.commit_verdict_review(
        RUN_ID,
        screened.revision,
        evidence.get_audit_head(RUN_ID),
        current_closure,
        verdict,
        review,
    ).case
    assert ready.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    repository = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=clock,
        alert_policy_verifier=ConfiguredAlertPolicyVerifier(config),
        automatic_precedent_verifier=ConfiguredAutomaticPrecedentVerifier(
            config,
            DeterministicFakePrecedentEmbeddingProvider(),
        ),
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(config),
        alert_channel_capability=_channel_capability(
            exact=channel_capability_exact,
            manifest=manifest,
            config=config,
        ),
        fault_injector=fault_injector,
    )
    return database, evidence, repository, ready, manifest, config


def _automatic_precedent(
    case: CaseSnapshot,
    manifest: RunManifest,
    config: AppConfig,
    alert_authority: AlertPolicyAuthority,
    *,
    created_at: datetime = RECORDED_AT,
) -> M5PrecedentAuthority:
    return build_automatic_precedent_authority(
        case=case.case,
        manifest=manifest,
        alert_authority=alert_authority,
        config=config,
        embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        created_at=created_at,
    )


def _table_counts(database: Path, *tables: str) -> tuple[int, ...]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in tables
        )


def test_close_commits_case_alert_cooldown_outbox_and_automatic_precedent(
    tmp_path: Path,
) -> None:
    database, evidence, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    automatic = _automatic_precedent(ready, manifest, config, authority)

    assert repository.list_ready_cases(RUN_ID, 10) == (ready,)
    committed = repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        automatic,
    )

    assert committed.revision == ready.revision + 1
    assert committed.case.status == CaseStatus.CLOSED
    assert committed.case.alerts[-1] == authority.decision
    assert committed.case.timeline[-1].action == "CASE_CLOSED"
    assert evidence.load_case(RUN_ID, ready.case.case_id) == committed
    assert repository.list_ready_cases(RUN_ID, 10) == ()
    assert (
        repository.load_current_cooldown(
            RUN_ID,
            authority.cooldown_write.key,  # type: ignore[union-attr]
            authority.request.stream_id,
            authority.request.stream_authority_sha256,
        )
        == authority.cooldown_write
    )
    assert repository.list_pending_outbox(RUN_ID, 10) == (authority.outbox_item,)
    assert _table_counts(
        database,
        "alerts",
        "alert_cooldowns",
        "alert_outbox",
        "precedents",
    ) == (1, 1, 1, 1)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT source, status, revision, source_case_id FROM precedents"
        ).fetchone()
    assert row == (
        PrecedentSource.AUTOMATIC.value,
        PrecedentStatus.PROVISIONAL.value,
        1,
        ready.case.case_id,
    )

    replay = repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        automatic,
    )
    assert replay == committed
    assert _table_counts(
        database,
        "alerts",
        "alert_cooldowns",
        "alert_outbox",
        "precedents",
    ) == (1, 1, 1, 1)


def test_close_rejects_forged_automatic_precedent_content_and_clock_drift(
    tmp_path: Path,
) -> None:
    database, evidence, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    automatic = _automatic_precedent(ready, manifest, config, authority)
    forged_text = automatic.model_copy(
        update={
            "precedent": automatic.precedent.model_copy(
                update={"situation_text": "forged situation text"}
            )
        }
    )
    forged_id = automatic.model_copy(
        update={
            "precedent": automatic.precedent.model_copy(
                update={"precedent_id": "forged-automatic-precedent"}
            )
        }
    )
    assert automatic.text_embedding is not None
    forged_embedding = automatic.text_embedding.model_copy(
        update={
            "values": (
                automatic.text_embedding.values[0] + 0.125,
                *automatic.text_embedding.values[1:],
            )
        }
    )
    forged_vector = automatic.model_copy(
        update={
            "precedent": automatic.precedent.model_copy(
                update={"text_embedding_ref": forged_embedding.embedding_id}
            ),
            "text_embedding": forged_embedding,
        }
    )
    drifted_time = _automatic_precedent(
        ready,
        manifest,
        config,
        authority,
        created_at=RECORDED_AT - timedelta(minutes=1),
    )

    for proposed in (forged_text, forged_id, forged_vector, drifted_time):
        with pytest.raises(ContractViolation):
            repository.commit_alert_policy(
                RUN_ID,
                ready.revision,
                authority,
                proposed,
            )

    assert evidence.load_case(RUN_ID, ready.case.case_id) == ready
    assert _table_counts(
        database,
        "alerts",
        "alert_cooldowns",
        "alert_outbox",
        "precedents",
    ) == (0, 0, 0, 0)


def test_close_without_automatic_precedent_verifier_fails_closed(tmp_path: Path) -> None:
    database, evidence, _, ready, manifest, config = _prepare_ready_case(tmp_path)
    repository = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        alert_policy_verifier=ConfiguredAlertPolicyVerifier(config),
    )
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    with pytest.raises(ContractViolation, match="AutomaticPrecedentVerifier"):
        repository.commit_alert_policy(
            RUN_ID,
            ready.revision,
            authority,
            _automatic_precedent(ready, manifest, config, authority),
        )
    assert evidence.load_case(RUN_ID, ready.case.case_id) == ready
    assert _table_counts(database, "alerts", "alert_outbox", "precedents") == (0, 0, 0)


@pytest.mark.parametrize(
    "phase",
    [
        "m5.alert.case_closed",
        "m5.alert.authority_inserted",
        "m5.alert.cooldown_inserted",
        "m5.alert.outbox_inserted",
        "m5.alert.automatic_precedent.before_causal_event",
        "m5.alert.automatic_precedent.after_causal_event",
        "m5.alert.automatic_precedent_inserted",
    ],
)
def test_close_fault_rolls_back_every_root(tmp_path: Path, phase: str) -> None:
    def fail_at(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"injected fault at {phase}")

    database, evidence, repository, ready, manifest, config = _prepare_ready_case(
        tmp_path,
        fault_injector=fail_at,
    )
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    before_counts = _table_counts(database, "case_versions", "audit_entries")

    with pytest.raises(RuntimeError, match="injected fault"):
        repository.commit_alert_policy(
            RUN_ID,
            ready.revision,
            authority,
            _automatic_precedent(ready, manifest, config, authority),
        )

    assert evidence.load_case(RUN_ID, ready.case.case_id) == ready
    assert _table_counts(database, "case_versions", "audit_entries") == before_counts
    assert _table_counts(
        database,
        "alerts",
        "alert_cooldowns",
        "alert_outbox",
        "precedents",
        "m5_precedent_causal_events",
    ) == (0, 0, 0, 0, 0)


def test_dispatch_requires_the_close_authority_causal_event(tmp_path: Path) -> None:
    database, _, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    automatic = _automatic_precedent(ready, manifest, config, authority)
    repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        automatic,
    )
    item = authority.outbox_item
    assert item is not None

    with sqlite3.connect(database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm5_precedent_causal_events_no_delete'
            """
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        connection.execute("DROP TRIGGER m5_precedent_causal_events_no_delete")
        cursor = connection.execute(
            """
            DELETE FROM m5_precedent_causal_events
            WHERE run_id = ? AND source_id = ?
            """,
            (RUN_ID, automatic.authority_id),
        )
        assert cursor.rowcount == 1
        connection.execute(trigger_row[0])

    with pytest.raises(RepositoryIntegrityError, match="exactly one event"):
        repository.begin_dispatch(
            item,
            _owner("missing-close-causal-event"),
            _channel_capability(),
        )
    assert _table_counts(database, "alert_dispatch_attempts") == (0,)


def test_dispatch_crash_restart_retries_same_key_and_records_one_success(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    database, _, repository, ready, manifest, config = _prepare_ready_case(
        tmp_path,
        clock=clock,
    )
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        _automatic_precedent(ready, manifest, config, authority),
    )
    item = authority.outbox_item
    assert item is not None

    capability = _channel_capability()
    abandoned = repository.begin_dispatch(
        item,
        _owner("worker-before-crash"),
        capability,
    )
    assert isinstance(abandoned, AlertDispatchAttempt)
    assert abandoned.attempt_number == 1
    restarted = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=clock,
        alert_policy_verifier=ConfiguredAlertPolicyVerifier(config),
        automatic_precedent_verifier=ConfiguredAutomaticPrecedentVerifier(
            config,
            DeterministicFakePrecedentEmbeddingProvider(),
        ),
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(config),
        alert_channel_capability=capability,
    )
    assert restarted.list_pending_outbox(RUN_ID, 10) == ()
    with pytest.raises(ConcurrentModification, match="active lease"):
        restarted.begin_dispatch(
            item,
            _owner("concurrent-worker"),
            capability,
        )

    clock.advance(seconds=61)
    assert restarted.list_pending_outbox(RUN_ID, 10) == (item,)
    retry = restarted.begin_dispatch(
        item,
        _owner("worker-after-crash"),
        capability,
    )
    assert isinstance(retry, AlertDispatchAttempt)
    assert retry.attempt_number == 2
    assert retry.idempotency_key == abandoned.idempotency_key == item.alert.alert_id
    assert retry.fence == 2
    assert retry.lease_owner_sha256 == _owner("worker-after-crash")
    recovery = _dispatch_receipt(
        abandoned,
        disposition=AlertDispatchDisposition.UNKNOWN_DELIVERY,
        failure_code=AlertDispatchFailureCode.LEASE_EXPIRED,
    )
    assert restarted.complete_dispatch(abandoned, recovery) == recovery
    with pytest.raises(RepositoryIntegrityError, match="another receipt"):
        restarted.complete_dispatch(
            abandoned,
            _dispatch_receipt(
                abandoned,
                disposition=AlertDispatchDisposition.SUCCEEDED,
            ),
        )
    success = _dispatch_receipt(
        retry,
        disposition=AlertDispatchDisposition.SUCCEEDED,
    )
    assert restarted.complete_dispatch(retry, success) == success
    assert restarted.list_pending_outbox(RUN_ID, 10) == ()
    assert restarted.begin_dispatch(item, _owner("worker-third"), capability) == success
    assert _table_counts(
        database,
        "alert_dispatch_attempts",
        "alert_dispatch_receipts",
    ) == (2, 2)


def test_expired_non_idempotent_delivery_is_quarantined_without_successor(
    tmp_path: Path,
) -> None:
    clock = _MutableClock()
    database, _, repository, ready, manifest, config = _prepare_ready_case(
        tmp_path,
        clock=clock,
        channel_capability_exact=False,
    )
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        _automatic_precedent(ready, manifest, config, authority),
    )
    item = authority.outbox_item
    assert item is not None
    capability = _channel_capability(exact=False)
    abandoned = repository.begin_dispatch(item, _owner("non-idempotent-1"), capability)
    assert isinstance(abandoned, AlertDispatchAttempt)

    # Whether the provider accepted before the crash is unknowable locally. Expiry is
    # therefore persisted as UNKNOWN and a non-idempotent channel cannot be retried.
    clock.advance(seconds=61)
    terminal = repository.begin_dispatch(item, _owner("non-idempotent-2"), capability)
    assert isinstance(terminal, AlertDispatchReceipt)
    assert terminal.attempt_id == abandoned.attempt_id
    assert terminal.disposition == AlertDispatchDisposition.UNKNOWN_DELIVERY
    assert terminal.failure_code == AlertDispatchFailureCode.LEASE_EXPIRED
    assert terminal.continuation == AlertDispatchContinuation.ATTENTION_REQUIRED
    assert repository.list_pending_outbox(RUN_ID, 10) == ()
    assert _table_counts(
        database,
        "alert_dispatch_attempts",
        "alert_dispatch_receipts",
    ) == (1, 1)
    assert ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID).failures == ()


def test_three_definitely_not_sent_attempts_end_in_durable_attention(
    tmp_path: Path,
) -> None:
    database, _, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        _automatic_precedent(ready, manifest, config, authority),
    )
    item = authority.outbox_item
    assert item is not None
    capability = _channel_capability()
    receipts: list[AlertDispatchReceipt] = []
    for number in range(1, 4):
        attempt = repository.begin_dispatch(
            item,
            _owner(f"bounded-worker-{number}"),
            capability,
        )
        assert isinstance(attempt, AlertDispatchAttempt)
        assert attempt.attempt_number == number
        receipt = _dispatch_receipt(
            attempt,
            disposition=AlertDispatchDisposition.RETRYABLE_FAILURE,
            failure_code=AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT,
        )
        receipts.append(repository.complete_dispatch(attempt, receipt))

    assert [item.continuation for item in receipts] == [
        AlertDispatchContinuation.RETRY_ALLOWED,
        AlertDispatchContinuation.RETRY_ALLOWED,
        AlertDispatchContinuation.ATTENTION_REQUIRED,
    ]
    assert repository.list_pending_outbox(RUN_ID, 10) == ()
    assert repository.begin_dispatch(item, _owner("bounded-worker-4"), capability) == receipts[-1]
    assert _table_counts(
        database,
        "alert_dispatch_attempts",
        "alert_dispatch_receipts",
    ) == (3, 3)
    assert ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID).failures == ()


def test_fifo_and_bounded_attempts_prevent_poison_prefix_and_new_item_starvation(
    tmp_path: Path,
) -> None:
    database, _, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        _automatic_precedent(ready, manifest, config, authority),
    )
    poison = authority.outbox_item
    assert poison is not None
    capability = _channel_capability()
    selector = _DispatchSelectionRepository(database, BUSY_TIMEOUT_MS, clock=_clock)

    attempt = repository.begin_dispatch(poison, _owner("poison-1"), capability)
    assert isinstance(attempt, AlertDispatchAttempt)
    repository.complete_dispatch(
        attempt,
        _dispatch_receipt(
            attempt,
            disposition=AlertDispatchDisposition.RETRYABLE_FAILURE,
            failure_code=AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT,
        ),
    )
    first_existing = _insert_outbox_clone(database, poison, "existing-before-new")
    assert selector.list_pending_outbox(RUN_ID, 1) == (poison,)

    attempt = repository.begin_dispatch(poison, _owner("poison-2"), capability)
    assert isinstance(attempt, AlertDispatchAttempt)
    repository.complete_dispatch(
        attempt,
        _dispatch_receipt(
            attempt,
            disposition=AlertDispatchDisposition.RETRYABLE_FAILURE,
            failure_code=AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT,
        ),
    )
    later_new = _insert_outbox_clone(database, poison, "continuously-new")
    assert selector.list_pending_outbox(RUN_ID, 1) == (poison,)

    attempt = repository.begin_dispatch(poison, _owner("poison-3"), capability)
    assert isinstance(attempt, AlertDispatchAttempt)
    terminal = repository.complete_dispatch(
        attempt,
        _dispatch_receipt(
            attempt,
            disposition=AlertDispatchDisposition.RETRYABLE_FAILURE,
            failure_code=AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT,
        ),
    )
    assert terminal.continuation == AlertDispatchContinuation.ATTENTION_REQUIRED
    assert selector.list_pending_outbox(RUN_ID, 2) == (first_existing, later_new)


def test_failed_dispatch_remains_pending_and_immediate_delivery_is_typed_disabled(
    tmp_path: Path,
) -> None:
    database, _, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        _automatic_precedent(ready, manifest, config, authority),
    )
    item = authority.outbox_item
    assert item is not None
    attempt = repository.begin_dispatch(
        item,
        _owner("worker-failure"),
        _channel_capability(),
    )
    assert isinstance(attempt, AlertDispatchAttempt)
    failed = _dispatch_receipt(
        attempt,
        disposition=AlertDispatchDisposition.RETRYABLE_FAILURE,
        failure_code=AlertDispatchFailureCode.CHANNEL_DEFINITELY_NOT_SENT,
    )
    assert repository.complete_dispatch(attempt, failed) == failed
    assert repository.list_pending_outbox(RUN_ID, 10) == (item,)

    emergency = _emergency_delivery()
    for operation in (
        lambda: repository.record_immediate_safety_delivery(RUN_ID, emergency),
        lambda: repository.load_immediate_safety_delivery(
            RUN_ID,
            emergency.incident.incident_id,
        ),
    ):
        with pytest.raises(ImmediateSafetyDeliveryDisabledError) as error:
            operation()
        assert (
            error.value.reason_code
            == ImmediateSafetyDeliveryFailureCode.DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY
        )
    assert _table_counts(database, "m5_immediate_safety_deliveries") == (0,)

    with pytest.raises(ValueError, match="limit"):
        repository.list_ready_cases(RUN_ID, MAX_READY_ALERT_CASES + 1)
    with pytest.raises(ValueError, match="limit"):
        repository.list_pending_outbox(RUN_ID, MAX_PENDING_ALERT_OUTBOX + 1)


def test_dispatch_rejects_caller_forged_idempotency_capability(tmp_path: Path) -> None:
    database, _, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        _automatic_precedent(ready, manifest, config, authority),
    )
    item = authority.outbox_item
    assert item is not None
    trusted = _channel_capability(manifest=manifest, config=config)
    forged = AlertChannelCapabilityAuthority(
        run_id=trusted.run_id,
        manifest_id=trusted.manifest_id,
        config_sha256=trusted.config_sha256,
        channel=trusted.channel,
        capability_revision="caller-forged-non-idempotent-v1",
        idempotency_guarantee=AlertChannelIdempotencyGuarantee.NONE,
        provider_idempotency_key=None,
    )

    with pytest.raises(ContractViolation, match="caller channel capability"):
        repository.begin_dispatch(item, _owner("forged-idempotency"), forged)

    assert _table_counts(database, "alert_channel_capabilities", "alert_dispatch_attempts") == (
        0,
        0,
    )


@pytest.mark.parametrize("scope", ["manifest", "config"])
def test_dispatch_rejects_capability_outside_run_manifest_config(
    tmp_path: Path,
    scope: str,
) -> None:
    database, _, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        authority,
        _automatic_precedent(ready, manifest, config, authority),
    )
    item = authority.outbox_item
    assert item is not None
    trusted = _channel_capability(manifest=manifest, config=config)
    mismatched = AlertChannelCapabilityAuthority(
        run_id=trusted.run_id,
        manifest_id=("f" * 64 if scope == "manifest" else trusted.manifest_id),
        config_sha256=("e" * 64 if scope == "config" else trusted.config_sha256),
        channel=trusted.channel,
        capability_revision=trusted.capability_revision,
        idempotency_guarantee=trusted.idempotency_guarantee,
        provider_idempotency_key=trusted.provider_idempotency_key,
    )
    mismatched_repository = SQLiteM5Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        alert_channel_capability=mismatched,
    )

    with pytest.raises(ManifestMismatch, match="run manifest/config"):
        mismatched_repository.begin_dispatch(
            item,
            _owner(f"wrong-{scope}"),
            mismatched,
        )

    assert _table_counts(database, "alert_channel_capabilities", "alert_dispatch_attempts") == (
        0,
        0,
    )


def test_historical_immediate_only_row_is_counted_and_reported_untrusted(
    tmp_path: Path,
) -> None:
    database, _, _, _, manifest, config = _prepare_ready_case(tmp_path)
    emergency = _emergency_delivery()
    authority_json, document_sha256 = _document(emergency)
    incident = emergency.incident
    receipt = emergency.delivery_receipt
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER m5_immediate_safety_deliveries_reject_uncertified_insert")
        connection.execute(
            """
            INSERT INTO m5_immediate_safety_deliveries(
                run_id, authority_id, incident_id, signal_id, zone_id,
                delivery_idempotency_key, delivery_alert_id, delivery_channel,
                provider_receipt_ref, manifest_id, authority_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                RUN_ID,
                emergency.authority_id,
                incident.incident_id,
                incident.signal_id,
                incident.zone_id,
                incident.delivery_idempotency_key,
                receipt.alert_id,
                receipt.channel,
                receipt.provider_receipt_ref,
                manifest.manifest_id,
                authority_json,
                document_sha256,
            ),
        )
        connection.execute(
            """
            CREATE TRIGGER m5_immediate_safety_deliveries_reject_uncertified_insert
            BEFORE INSERT ON m5_immediate_safety_deliveries
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'immediate safety delivery disabled without certified signal authority'
                );
            END
            """
        )

    snapshot = ReadonlyM5ArtifactRepository(database, config=config).scan(RUN_ID)
    inventory = {item.authority_kind: item.count for item in snapshot.traversed}
    assert inventory[M5AuthorityKind.IMMEDIATE_SAFETY_DELIVERY] == 1
    assert snapshot.case_roots == ()
    assert {failure.reason_code for failure in snapshot.failures} == {
        "IMMEDIATE_SAFETY_DELIVERY_UNTRUSTED_NO_CERTIFIED_SIGNAL"
    }

    report = validate_m5_artifacts(
        config=config,
        run_id=RUN_ID,
        database_path=database,
        workspace_root=tmp_path,
    )
    assert report.counts.authority_rows == 1
    assert any(
        item.authority_kind == M5AuthorityKind.IMMEDIATE_SAFETY_DELIVERY
        and item.authoritative_count == 1
        for item in report.counts.inventories
    )
    assert any(
        issue.reason_code == "IMMEDIATE_SAFETY_DELIVERY_UNTRUSTED_NO_CERTIFIED_SIGNAL"
        for issue in report.issues
    )


def test_close_cas_rejects_stale_revision_without_side_effects(tmp_path: Path) -> None:
    database, _, repository, ready, manifest, config = _prepare_ready_case(tmp_path)
    authority = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    with pytest.raises(ConcurrentModification, match="revision"):
        repository.commit_alert_policy(
            RUN_ID,
            ready.revision - 1,
            authority,
            _automatic_precedent(ready, manifest, config, authority),
        )
    assert _table_counts(
        database,
        "alerts",
        "alert_cooldowns",
        "alert_outbox",
        "precedents",
    ) == (0, 0, 0, 0)
