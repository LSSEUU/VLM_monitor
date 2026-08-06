from __future__ import annotations

import hashlib
import inspect
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.hearing_model_response_store import (
    SecureHearingModelResponseStore,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_hearing_recovery import (
    SQLiteHearingModelCallRecoveryRepository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.hearing_model_response_recovery import (
    HearingModelCallRecoveryService,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind, EvidenceClass, ViolationType, VlmRole
from labcourt.contracts.hearing import (
    HearingModelRequest,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingUsageReceipt,
)
from labcourt.contracts.hearing_recovery import (
    HearingModelResponseRecoveryReason,
)
from labcourt.contracts.m3_models import PromptManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import begin_hearing
from labcourt.exceptions import ContractViolation
from labcourt.services.m4_maintenance_recovery import (
    build_m4_hearing_model_response_recovery,
)
from tests.integration.test_m4_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    CASE_ID,
    MANIFEST_ID,
    RUN_ID,
    _digest,
    _model_request,
    _seed_entry_authority,
    _session_and_cycle,
)

OLD_NOW = datetime(2020, 1, 1, tzinfo=UTC)
RECOVERY_NOW = datetime(2026, 7, 28, 8, 0, tzinfo=UTC)
RAW = b'{"result":"durable-hearing-response"}'


def _old_clock() -> datetime:
    return OLD_NOW


def _recovery_clock() -> datetime:
    return RECOVERY_NOW


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _setup(
    tmp_path: Path,
    *,
    claim_clock: datetime = OLD_NOW,
    workspace_name: str = "workspace",
) -> tuple[Path, Path, SQLiteEvidenceRepository, HearingModelRequest]:
    root = tmp_path / workspace_name
    root.mkdir()
    database = root / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=lambda: claim_clock).apply_all()
    pack_id, screening_id = _seed_entry_authority(database)
    session, cycle = _session_and_cycle(pack_id, screening_id)
    storage = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        clock=lambda: claim_clock,
    )
    storage.start_hearing(RUN_ID, session, cycle, begin_hearing(session))
    retrieval = HearingPrecedentRetrievalReceipt(
        run_id=RUN_ID,
        case_id=CASE_ID,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack_id,
        current_evidence_pack_version=1,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.REAGENT_CONTAINER_OPEN,
        rule_version="laboratory-v1",
        top_k=0,
        query_sha256=_digest("hearing-recovery-query"),
        candidate_snapshot_sha256=_digest("hearing-recovery-candidates"),
        visible_snapshot_sha256=_digest("hearing-recovery-visible"),
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_digest("hearing-recovery-retriever"),
        embedding_model_manifest_id=_digest("hearing-recovery-embedding"),
        manifest_id=MANIFEST_ID,
    )
    storage.append_precedent_retrieval(RUN_ID, retrieval)
    return root, database, storage, _model_request(session, retrieval)


def _usage(
    request: HearingModelRequest, response: object, retry_count: int = 0
) -> HearingUsageReceipt:
    from labcourt.contracts.hearing import HearingModelResponse

    assert isinstance(response, HearingModelResponse)
    return HearingUsageReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        request_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        ),
        response_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        ),
        input_images=len(request.media),
        input_pixels=sum(item.width * item.height for item in request.media),
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        latency_ms=response.latency_ms,
        retry_count=retry_count,
        estimated_cost=request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        ),
        manifest_id=request.manifest_id,
    )


def _defender_request(request: HearingModelRequest) -> HearingModelRequest:
    updated = request.model_copy(
        update={
            "role": VlmRole.DEFENDER,
            "provider_profile": "fake-defender",
            "model": "fixture-defender",
            "model_manifest_id": _digest("m4-defender-model"),
            "prompt_manifest": PromptManifest(
                prompt_id="hearing_defender_v1",
                role=VlmRole.DEFENDER,
                template_sha256=_digest("DEFENDER-template"),
                output_schema_sha256=_digest("DEFENDER-schema"),
                prompt_bundle_sha256=request.hearing_prompt_bundle_sha256,
                renderer_version="fixture-renderer-v1",
            ),
            "rendered_prompt_sha256": _digest("DEFENDER-rendered"),
            "prosecutor_output_ref": ArtifactRef(
                kind=ArtifactKind.PARSED_MODEL_OUTPUT,
                artifact_id=_digest("recovery-prosecutor-output"),
            ),
        }
    )
    return HearingModelRequest.model_validate(updated.model_dump(mode="json"))


def _insert_claim(
    database: Path,
    request: HearingModelRequest,
    *,
    request_json: str | None = None,
) -> None:
    document = request_json or canonical_json(request.model_dump(mode="json"))
    context = request.backlog_retry_context
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO m4_model_call_claims(
                run_id, request_id, request_sha256, cache_key,
                hearing_id, cycle_scope_id, cycle_scope_sha256, case_id,
                role, purpose, attempt_index, call_generation,
                backlog_item_id, retry_generation,
                reserved_images, reserved_pixels,
                evidence_pack_id, evidence_pack_version,
                model_manifest_id, prompt_manifest_id, manifest_id,
                request_json, request_document_sha256,
                status, owner_token_sha256, lease_expires_at,
                takeover_count, created_at, response_id, completed_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                'ACTIVE', ?, ?, 0, ?, NULL, NULL
            )
            """,
            (
                request.run_id,
                request.request_id,
                request.request_sha256,
                request.cache_key,
                request.hearing_session_id,
                request.cycle_scope_id,
                request.cycle_scope_sha256,
                request.case_id,
                request.role.value,
                "ROLE_CALL" if request.attempt_index == 0 else "STRUCTURE_REPAIR",
                request.attempt_index,
                "BACKLOG" if context is not None else "INITIAL",
                context.backlog_item_id if context is not None else None,
                context.retry_generation if context is not None else 0,
                len(request.media),
                sum(item.width * item.height for item in request.media),
                request.current_evidence_pack_id,
                request.current_evidence_pack_version,
                request.model_manifest_id,
                request.prompt_manifest.prompt_manifest_id,
                request.manifest_id,
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
                hashlib.sha256(b"manual-recovery-owner").hexdigest(),
                _timestamp(OLD_NOW + timedelta(seconds=5)),
                _timestamp(OLD_NOW),
            ),
        )


def _database_counts(database: Path) -> tuple[int, int, int, int]:
    with sqlite3.connect(database) as connection:
        return tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "m4_model_responses",
                "m4_model_cache",
                "m4_hearing_usage_receipts",
                "m4_model_call_claims",
            )
        )


def test_unexpired_active_claim_is_observed_without_journal_or_mutation(
    tmp_path: Path,
) -> None:
    root, database, storage, request = _setup(tmp_path, claim_clock=RECOVERY_NOW)
    storage.claim_hearing_model_call(RUN_ID, request, "active-owner-" + "a" * 51)

    with SecureWorkspace(root, 256 * 1024) as workspace:
        report = build_m4_hearing_model_response_recovery(
            database_path=database,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            workspace=workspace,
            limit=10,
            clock=_recovery_clock,
        ).recover(RUN_ID, RECOVERY_NOW)

    assert report.passed
    assert report.items[0].reason_code == (
        HearingModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED
    )
    assert _database_counts(database) == (0, 0, 0, 1)


def test_expired_journaled_claim_completes_usage_once_and_replays_idempotently(
    tmp_path: Path,
) -> None:
    root, database, storage, request = _setup(tmp_path)
    storage.claim_hearing_model_call(RUN_ID, request, "expired-owner-" + "e" * 50)

    with SecureWorkspace(root, 256 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        response = store.publish(
            request,
            RAW,
            input_tokens=11,
            output_tokens=7,
            latency_ms=13,
        )
        service = build_m4_hearing_model_response_recovery(
            database_path=database,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            workspace=workspace,
            limit=10,
            clock=_recovery_clock,
        )
        first = service.recover(RUN_ID, RECOVERY_NOW)
        second = service.recover(RUN_ID, RECOVERY_NOW)

    assert first.items[0].reason_code == (HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED)
    assert second.items[0].reason_code == (
        HearingModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT
    )
    assert _database_counts(database) == (1, 1, 1, 1)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT SUM(output_tokens) FROM m4_hearing_usage_receipts WHERE hearing_id = ?",
            (request.hearing_session_id,),
        ).fetchone() == (response.output_tokens,)
        assert connection.execute(
            "SELECT takeover_count, status FROM m4_model_call_claims WHERE request_id = ?",
            (request.request_id,),
        ).fetchone() == (0, "COMPLETED")


def test_general_sqlite_facade_without_raw_verifier_refuses_recovery_write(
    tmp_path: Path,
) -> None:
    root, database, storage, request = _setup(tmp_path)
    storage.claim_hearing_model_call(RUN_ID, request, "unverified-owner-" + "u" * 48)

    with SecureWorkspace(root, 256 * 1024) as workspace:
        response = SecureHearingModelResponseStore(workspace).publish(request, RAW)
        facade = SQLiteEvidenceRepository(
            database,
            BUSY_TIMEOUT_MS,
            clock=_recovery_clock,
        )
        scan = facade.scan_hearing_model_call_recovery_candidates(RUN_ID, 10)
        candidate = scan.candidates[0]
        assert candidate.lease_expires_at is not None
        with pytest.raises(ContractViolation, match="raw response verifier"):
            facade.complete_expired_hearing_model_call_from_recovery(
                RUN_ID,
                request,
                response,
                candidate.lease_expires_at,
                candidate.takeover_count,
            )

    assert _database_counts(database) == (0, 0, 0, 1)


def test_general_sqlite_facade_with_raw_verifier_implements_full_recovery_port(
    tmp_path: Path,
) -> None:
    root, database, storage, request = _setup(tmp_path)
    storage.claim_hearing_model_call(RUN_ID, request, "verified-owner-" + "w" * 50)

    with SecureWorkspace(root, 256 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        store.publish(request, RAW, output_tokens=3)
        facade = SQLiteEvidenceRepository(
            database,
            BUSY_TIMEOUT_MS,
            clock=_recovery_clock,
            hearing_raw_response_verifier=store,
        )
        report = HearingModelCallRecoveryService(
            repository=facade,
            responses=store,
            limit=10,
        ).recover(RUN_ID, RECOVERY_NOW)

    assert report.items[0].reason_code == (HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED)
    assert _database_counts(database) == (1, 1, 1, 1)


def test_completed_claim_with_journal_is_verified_and_acknowledged_without_new_usage(
    tmp_path: Path,
) -> None:
    root, database, storage, request = _setup(tmp_path, claim_clock=RECOVERY_NOW)
    owner = "completed-owner-" + "c" * 48
    storage.claim_hearing_model_call(RUN_ID, request, owner)

    with SecureWorkspace(root, 256 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        response = store.publish(request, RAW, input_tokens=3, output_tokens=5, latency_ms=7)
        storage.complete_hearing_model_call(
            RUN_ID,
            request,
            response,
            _usage(request, response),
            owner,
        )
        report = build_m4_hearing_model_response_recovery(
            database_path=database,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            workspace=workspace,
            limit=10,
            clock=_recovery_clock,
        ).recover(RUN_ID, RECOVERY_NOW)

    assert report.items[0].reason_code == (HearingModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED)
    assert _database_counts(database) == (1, 1, 1, 1)


def test_incomplete_scan_never_touches_any_journal_or_claim(
    tmp_path: Path,
) -> None:
    root, database, storage, first_request = _setup(tmp_path)
    storage.claim_hearing_model_call(RUN_ID, first_request, "first-owner-" + "f" * 52)
    second_request = _defender_request(first_request)
    _insert_claim(database, second_request)

    with SecureWorkspace(root, 256 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        first_response = store.publish(first_request, RAW + b"-first")
        second_response = store.publish(second_request, RAW + b"-second")
        report = build_m4_hearing_model_response_recovery(
            database_path=database,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            workspace=workspace,
            limit=1,
            clock=_recovery_clock,
        ).recover(RUN_ID, RECOVERY_NOW)

    assert not report.scan_complete
    assert report.items[0].reason_code == HearingModelResponseRecoveryReason.CLAIM_SCAN_INCOMPLETE
    assert _database_counts(database) == (0, 0, 0, 2)
    assert (root / first_response.raw_response_ref).is_file()
    assert (root / second_response.raw_response_ref).is_file()


def test_malformed_claim_authority_suppresses_a_valid_expired_journal(
    tmp_path: Path,
) -> None:
    root, database, storage, valid_request = _setup(tmp_path)
    storage.claim_hearing_model_call(RUN_ID, valid_request, "valid-owner-" + "v" * 52)
    malformed_request = _defender_request(valid_request)
    _insert_claim(database, malformed_request, request_json="{}")

    with SecureWorkspace(root, 256 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        valid_response = store.publish(valid_request, RAW)
        report = build_m4_hearing_model_response_recovery(
            database_path=database,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            workspace=workspace,
            limit=10,
            clock=_recovery_clock,
        ).recover(RUN_ID, RECOVERY_NOW)

    assert report.requires_attention
    assert {item.reason_code for item in report.items} == {
        HearingModelResponseRecoveryReason.CLAIM_AUTHORITY_INVALID,
        HearingModelResponseRecoveryReason.CLAIM_RECOVERY_SUPPRESSED,
    }
    assert _database_counts(database) == (0, 0, 0, 2)
    assert (root / valid_response.raw_response_ref).is_file()


def test_tampered_raw_response_is_typed_and_never_committed(tmp_path: Path) -> None:
    root, database, storage, request = _setup(tmp_path)
    storage.claim_hearing_model_call(RUN_ID, request, "tamper-owner-" + "t" * 51)

    with SecureWorkspace(root, 256 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        response = store.publish(request, RAW)
        tampered = bytearray(RAW)
        tampered[-2] = ord("X")
        (root / response.raw_response_ref).write_bytes(bytes(tampered))
        report = HearingModelCallRecoveryService(
            repository=SQLiteHearingModelCallRecoveryRepository(
                SQLiteEvidenceRepository(
                    database,
                    BUSY_TIMEOUT_MS,
                    clock=_recovery_clock,
                ),
                store,
            ),
            responses=store,
            limit=10,
        ).recover(RUN_ID, RECOVERY_NOW)

    assert report.items[0].reason_code == (
        HearingModelResponseRecoveryReason.RESPONSE_INTEGRITY_FAILURE
    )
    assert _database_counts(database) == (0, 0, 0, 1)


class _RacingRecoveryStore:
    def __init__(
        self,
        database: Path,
        delegate: SecureHearingModelResponseStore,
    ) -> None:
        self._database = database
        self._delegate = delegate
        self._raced = False

    def probe_recovery(self, request: HearingModelRequest):  # type: ignore[no-untyped-def]
        if not self._raced:
            with sqlite3.connect(self._database) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute(
                    """
                    UPDATE m4_model_call_claims
                    SET owner_token_sha256 = ?, lease_expires_at = ?,
                        takeover_count = takeover_count + 1
                    WHERE run_id = ? AND request_id = ?
                    """,
                    (
                        hashlib.sha256(b"racing-owner").hexdigest(),
                        _timestamp(RECOVERY_NOW + timedelta(hours=1)),
                        request.run_id,
                        request.request_id,
                    ),
                )
            self._raced = True
        return self._delegate.probe_recovery(request)

    def recover(self, request: HearingModelRequest):  # type: ignore[no-untyped-def]
        return self._delegate.recover(request)

    def verify_raw_response(self, run_id, request, response):  # type: ignore[no-untyped-def]
        return self._delegate.verify_raw_response(run_id, request, response)

    def acknowledge(self, request, response):  # type: ignore[no-untyped-def]
        return self._delegate.acknowledge(request, response)


def test_claim_epoch_cas_race_keeps_journal_and_creates_no_usage(tmp_path: Path) -> None:
    root, database, storage, request = _setup(tmp_path)
    storage.claim_hearing_model_call(RUN_ID, request, "race-owner-" + "r" * 53)

    with SecureWorkspace(root, 256 * 1024) as workspace:
        store = SecureHearingModelResponseStore(workspace)
        response = store.publish(request, RAW)
        racing = _RacingRecoveryStore(database, store)
        report = HearingModelCallRecoveryService(
            repository=SQLiteHearingModelCallRecoveryRepository(
                SQLiteEvidenceRepository(
                    database,
                    BUSY_TIMEOUT_MS,
                    clock=_recovery_clock,
                ),
                store,
            ),
            responses=racing,
            limit=10,
        ).recover(RUN_ID, RECOVERY_NOW)

    assert report.items[0].reason_code == HearingModelResponseRecoveryReason.CLAIM_RACE_LOST
    assert _database_counts(database) == (0, 0, 0, 1)
    journal = (
        root / ".staging" / RUN_ID / f"hearing-model-request-{request.request_id}" / "receipt.json"
    )
    assert journal.is_file()
    assert (root / response.raw_response_ref).is_file()


def test_m4_recovery_composition_accepts_no_provider_parser_or_case_writer() -> None:
    parameters = set(inspect.signature(build_m4_hearing_model_response_recovery).parameters)
    assert (
        not {
            "provider",
            "vlm_client",
            "parser",
            "acquisition_executor",
            "case_repository",
        }
        & parameters
    )
