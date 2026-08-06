from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import (
    RepositoryIntegrityError,
    SecureHearingModelResponseStore,
    SecureWorkspace,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.vlm import (
    OUTAGE_FIXTURE,
    DeterministicFakeHearingVLMClient,
)
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_request import (
    HearingBudgetUsage,
    HearingRequestGeneration,
    PreparedHearingRequest,
    prepare_primary_hearing_request,
)
from labcourt.application.hearing_role_call import HearingRoleCallContext, HearingRoleCallService
from labcourt.config_loader import load_config
from labcourt.contracts.backlog import BacklogItem, BacklogLeaseIdentity
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArgumentStance,
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.hearing import (
    HearingBacklogRetryFailure,
    HearingBacklogRetrySuccess,
    HearingCheckpointPhase,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
    ProsecutorModelPayload,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.model_call_failures import (
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Argument
from labcourt.domain.evidence_authority import derive_evidence_authority
from labcourt.domain.hearing_fsm import complete_prosecutor
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.hearing_backlog import (
    HearingBacklogRetryAuthority,
    HearingBacklogRetryCommit,
    HearingModelCallFailureIntent,
)
from tests.integration.test_m3_sqlite_repository import (
    BUSY_TIMEOUT_MS,
    RECORDED_AT,
    ROOT,
    RUN_ID,
    _clock,
)
from tests.integration.test_m4_hearing_coordinator import (
    _escalated_case,
    _fixtures_for_terminal_hearing,
    _NeverAcquisitionExecutor,
    _PromptRegistrar,
    _simulated_call,
)
from tests.unit.test_m4_hearing_backlog_retry import _strict_error
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents


@dataclass(frozen=True, slots=True)
class _OutageSeed:
    database: Path
    repository: SQLiteEvidenceRepository
    config: AppConfig
    manifest: RunManifest
    catalog: HearingJinjaPromptCatalog
    item_id: str
    hearing_id: str


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _provider_outage_seed(tmp_path: Path) -> _OutageSeed:
    database, repository, pack, escalated = _escalated_case(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = repository.load_run_manifest(RUN_ID)
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=_digest("fake-hearing-precedents"),
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
    )
    fixtures[next(iter(fixtures))] = OUTAGE_FIXTURE
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    with SecureWorkspace(workspace_root, 256 * 1024) as workspace:
        response_store = SecureHearingModelResponseStore(workspace)
        role_calls = HearingRoleCallService(
            repository=repository,
            response_store=response_store,
            vlm_client=DeterministicFakeHearingVLMClient(fixtures, response_store),
            prompt_registrar=_PromptRegistrar(),
            owner_token_factory=lambda: "o" * 43,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=repository,
            hearing_repository=repository,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=repository,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                repository,
            ),
        )
        outcome = coordinator.process_case(RUN_ID, pack.case_id)
    assert outcome.backlog_item_id is not None
    assert outcome.session is not None
    return _OutageSeed(
        database=database,
        repository=repository,
        config=config,
        manifest=manifest,
        catalog=catalog,
        item_id=outcome.backlog_item_id,
        hearing_id=outcome.session.session_id,
    )


def _lease(
    seed: _OutageSeed,
    *,
    attempt_expiry: datetime = RECORDED_AT + timedelta(minutes=5),
) -> BacklogItem | None:
    return seed.repository.lease_next_hearing_backlog(
        RUN_ID,
        sha256_hex("hearing-retry-worker"),
        attempt_expiry,
    )


def _prepared_prosecutor(
    seed: _OutageSeed,
    authority: HearingBacklogRetryAuthority,
) -> PreparedHearingRequest:
    retrieval = seed.repository.load_precedent_retrieval(
        RUN_ID,
        authority.stage_request.precedent_retrieval_receipt_id,
    )
    evidence = derive_evidence_authority(authority.case.case.evidence_packs[-1])
    prepared = prepare_primary_hearing_request(
        role=VlmRole.PROSECUTOR,
        session=authority.session,
        cycle_scope=authority.cycle_scope,
        retrieval=retrieval,
        evidence_pack=evidence.pack,
        evidence_authority=evidence,
        hearing_grant=None,
        budget_usage=HearingBudgetUsage(
            reserved_images=authority.reserved_images,
            accounted_output_tokens=authority.accounted_output_tokens,
        ),
        config=seed.config,
        run_manifest=seed.manifest,
        catalog=seed.catalog,
    )
    assert prepared.request == authority.stage_request
    return prepared


def test_known_unsent_initial_claim_takeover_is_fenced_and_single_winner(
    tmp_path: Path,
) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None and leased.lease_id is not None
    lease = BacklogLeaseIdentity(
        run_id=leased.run_id,
        item_id=leased.item_id,
        lease_id=leased.lease_id,
        attempt_count=leased.attempt_count,
        retry_generation=leased.retry_generation,
    )
    authority = seed.repository.load_hearing_backlog_retry_authority(RUN_ID, lease)

    with pytest.raises(ConcurrentModification, match="lease identity is stale"):
        seed.repository.claim_hearing_model_call(
            RUN_ID,
            authority.stage_request,
            "wrong-lease-owner-" + "w" * 32,
            lease.model_copy(update={"lease_id": "f" * 64}),
        )
    with pytest.raises(ConcurrentModification, match="lease identity is stale"):
        seed.repository.claim_hearing_model_call(
            RUN_ID,
            authority.stage_request,
            "wrong-generation-owner-" + "g" * 32,
            lease.model_copy(update={"retry_generation": lease.retry_generation + 1}),
        )

    def fail_after_takeover(phase: str) -> None:
        if phase == "hearing.model.claim.after_known_failure_takeover":
            raise RuntimeError("injected known-failure takeover crash")

    faulty = SQLiteEvidenceRepository(
        seed.database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        fault_injector=fail_after_takeover,
    )
    with pytest.raises(RuntimeError, match="known-failure takeover crash"):
        faulty.claim_hearing_model_call(
            RUN_ID,
            authority.stage_request,
            "rolled-back-owner-" + "r" * 32,
            lease,
        )
    with sqlite3.connect(seed.database) as connection:
        assert connection.execute(
            """
            SELECT owner_token_sha256, takeover_count
            FROM m4_model_call_claims
            WHERE run_id = ? AND request_id = ?
            """,
            (RUN_ID, authority.stage_request.request_id),
        ).fetchone() == (_digest("o" * 43), 0)

    owner = "takeover-owner-" + "t" * 32
    acquired = seed.repository.claim_hearing_model_call(
        RUN_ID,
        authority.stage_request,
        owner,
        lease,
    )
    assert acquired.status.value == "ACQUIRED"
    assert acquired.takeover_count == 1
    assert acquired.lease_expires_at is not None

    contender = seed.repository.claim_hearing_model_call(
        RUN_ID,
        authority.stage_request,
        "contender-owner-" + "c" * 32,
        lease,
    )
    assert contender.status.value == "WAITING"
    assert contender.takeover_count == 1
    with sqlite3.connect(seed.database) as connection:
        assert connection.execute(
            """
            SELECT owner_token_sha256, takeover_count
            FROM m4_model_call_claims
            WHERE run_id = ? AND request_id = ?
            """,
            (RUN_ID, authority.stage_request.request_id),
        ).fetchone() == (_digest(owner), 1)


def test_known_unsent_claim_takeover_fails_closed_on_authority_tamper(
    tmp_path: Path,
) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None and leased.lease_id is not None
    lease = BacklogLeaseIdentity(
        run_id=leased.run_id,
        item_id=leased.item_id,
        lease_id=leased.lease_id,
        attempt_count=leased.attempt_count,
        retry_generation=leased.retry_generation,
    )
    authority = seed.repository.load_hearing_backlog_retry_authority(RUN_ID, lease)
    with sqlite3.connect(seed.database) as connection:
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm4_model_call_failure_authorities_no_update'
            """
        ).fetchone()
        assert trigger is not None
        connection.execute("DROP TRIGGER m4_model_call_failure_authorities_no_update")
        connection.execute(
            """
            UPDATE m4_model_call_failure_authorities
            SET claim_owner_sha256 = ?
            WHERE run_id = ? AND request_id = ?
            """,
            ("f" * 64, RUN_ID, authority.stage_request.request_id),
        )
        connection.execute(str(trigger[0]))

    with pytest.raises(RepositoryIntegrityError, match="indexes conflict"):
        seed.repository.claim_hearing_model_call(
            RUN_ID,
            authority.stage_request,
            "tamper-contender-" + "x" * 32,
            lease,
        )


def _persist_prosecutor_success(
    seed: _OutageSeed,
    authority: HearingBacklogRetryAuthority,
) -> HearingBacklogRetrySuccess:
    prepared = _prepared_prosecutor(seed, authority)
    crop_ref = next(
        ref for ref in prepared.request.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
    )
    _raw, output, trace = _simulated_call(
        prepared,
        ProsecutorModelPayload(
            arguments=(
                Argument(
                    stance=ArgumentStance.PROSECUTION,
                    claim="The disclosed crop supports the allegation.",
                    evidence_refs=(crop_ref,),
                    uncertainty=0.1,
                ),
            ),
            case_summary="The prosecution uses only disclosed evidence.",
        ),
    )
    call = trace.successful_call
    seed.repository.complete_hearing_model_call(
        RUN_ID,
        call.request,
        call.response,
        call.usage,
        "o" * 43,
    )
    seed.repository.append_hearing_parse_receipt(call.parse_receipt, output)
    next_checkpoint = complete_prosecutor(
        authority.session,
        authority.checkpoint,
        output,
        trace,
    )
    return HearingBacklogRetrySuccess(
        lease=authority.lease,
        session=authority.session,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        request=call.request,
        response=call.response,
        parse_receipt=call.parse_receipt,
        parsed_role_output=output,
        next_checkpoint=next_checkpoint,
        manifest_id=authority.item.manifest_id,
    )


def test_real_outage_seed_leases_loads_commits_success_and_replays(tmp_path: Path) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None
    authority = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id,
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        ),
    )
    assert authority.item == leased
    assert authority.unfinished_request == authority.stage_request
    assert authority.checkpoint.phase == HearingCheckpointPhase.PROSECUTOR_PENDING
    assert authority.reserved_images > 0
    assert authority.reserved_images_before_primary == 0
    assert authority.accounted_output_tokens_before_primary == 0
    outcome = _persist_prosecutor_success(seed, authority)
    after_provider = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        authority.lease,
    )
    assert after_provider.reserved_images_before_primary == 0
    assert after_provider.accounted_output_tokens > 0
    assert after_provider.accounted_output_tokens_before_primary == 0

    commit = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        outcome,
    )
    replay = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        outcome,
    )

    assert commit.created is True and replay.created is False
    assert replay == commit.__class__(
        item=commit.item,
        receipt=commit.receipt,
        case=commit.case,
        checkpoint=commit.checkpoint,
        audit_head=commit.audit_head,
        created=False,
    )
    assert commit.item.status == BacklogStatus.COMPLETED
    assert commit.case.case.status == CaseStatus.DELIBERATING
    assert commit.checkpoint.phase == HearingCheckpointPhase.DEFENDER_PENDING
    with pytest.raises(ConcurrentModification):
        seed.repository.load_hearing_backlog_retry_authority(RUN_ID, authority.lease)


def test_response_integrity_failure_remains_pending_and_stale_lease_fails(
    tmp_path: Path,
) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None
    authority = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id,
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        ),
    )
    failure = HearingBacklogRetryFailure(
        lease=authority.lease,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        request=authority.stage_request,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
        next_status=BacklogStatus.PENDING,
        manifest_id=authority.item.manifest_id,
    )
    commit = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        failure,
    )
    assert commit.item.status == BacklogStatus.PENDING
    assert commit.case.case.status == CaseStatus.BACKLOGGED
    assert commit.checkpoint == authority.checkpoint

    leased_again = _lease(seed)
    assert leased_again is not None
    with pytest.raises(ConcurrentModification):
        seed.repository.load_hearing_backlog_retry_authority(RUN_ID, authority.lease)
    current = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased_again.run_id,
            item_id=leased_again.item_id,
            lease_id=leased_again.lease_id,
            attempt_count=leased_again.attempt_count,
            retry_generation=leased_again.retry_generation,
        ),
    )
    assert current.latest_completion == commit.receipt
    assert current.unfinished_request == authority.stage_request


def test_retry_commit_fault_rolls_back_every_authority_and_then_replays(
    tmp_path: Path,
) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None
    authority = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id,
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        ),
    )
    failure = HearingBacklogRetryFailure(
        lease=authority.lease,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        request=authority.stage_request,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
        next_status=BacklogStatus.PENDING,
        manifest_id=authority.item.manifest_id,
    )

    def fail_after_outcome(phase: str) -> None:
        if phase == "hearing.backlog_retry.after_outcome":
            raise RuntimeError("injected hearing backlog retry failure")

    faulty = SQLiteEvidenceRepository(
        seed.database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        fault_injector=fail_after_outcome,
    )
    with pytest.raises(RuntimeError, match="injected hearing backlog retry failure"):
        faulty.commit_hearing_backlog_retry(
            RUN_ID,
            authority.case.revision,
            authority.audit_head,
            failure,
        )

    with sqlite3.connect(seed.database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_hearing_backlog_retry_outcomes"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_backlog_completion_receipts"
        ).fetchone() == (0,)
        assert connection.execute(
            """
            SELECT status FROM backlog_item_versions
            WHERE run_id = ? AND item_id = ?
            ORDER BY version DESC LIMIT 1
            """,
            (RUN_ID, seed.item_id),
        ).fetchone() == (BacklogStatus.LEASED.value,)

    committed = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        failure,
    )
    replayed = faulty.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        failure,
    )
    assert committed.created is True
    assert replayed.created is False
    assert replayed.receipt == committed.receipt


def test_completion_receipt_semantic_hash_tamper_fails_closed(tmp_path: Path) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None
    authority = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id,
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        ),
    )
    outcome = _persist_prosecutor_success(seed, authority)
    committed = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        outcome,
    )

    with sqlite3.connect(seed.database) as connection:
        hashes = connection.execute(
            """
            SELECT receipt_sha256, document_sha256
            FROM m4_backlog_completion_receipts
            WHERE run_id = ? AND receipt_id = ?
            """,
            (RUN_ID, committed.receipt.receipt_id),
        ).fetchone()
        assert hashes is not None and hashes[0] != hashes[1]
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm4_backlog_completion_receipts_no_update'
            """
        ).fetchone()
        assert trigger_sql is not None
        connection.execute("DROP TRIGGER m4_backlog_completion_receipts_no_update")
        connection.execute(
            """
            UPDATE m4_backlog_completion_receipts
            SET receipt_sha256 = document_sha256
            WHERE run_id = ? AND receipt_id = ?
            """,
            (RUN_ID, committed.receipt.receipt_id),
        )
        connection.execute(str(trigger_sql[0]))

    with pytest.raises(RepositoryIntegrityError, match="indexes conflict"):
        seed.repository.commit_hearing_backlog_retry(
            RUN_ID,
            authority.case.revision,
            authority.audit_head,
            outcome,
        )


def test_retry_provider_failure_authority_fault_rolls_back_and_replays(
    tmp_path: Path,
) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None
    authority = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id,
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        ),
    )
    prepared = _prepared_prosecutor(seed, authority)
    context = HearingRoleCallContext(
        session=authority.session,
        cycle_scope=authority.cycle_scope,
        budget_usage_before_primary=HearingBudgetUsage(
            reserved_images=authority.reserved_images,
            accounted_output_tokens=authority.accounted_output_tokens,
        ),
        config=seed.config,
        run_manifest=seed.manifest,
        catalog=seed.catalog,
    )
    primary, repair = _strict_error(prepared, context).failed_calls
    seed.repository.complete_hearing_model_call(
        RUN_ID,
        primary.request,
        primary.response,
        primary.usage,
        "o" * 43,
    )
    claim = seed.repository.claim_hearing_model_call(
        RUN_ID,
        repair.request,
        "r" * 43,
        authority.lease,
    )
    assert claim.lease_expires_at is not None
    seed.repository.append_hearing_parse_receipt(primary.parse_receipt)
    outcome = HearingBacklogRetryFailure(
        lease=authority.lease,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        request=repair.request,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=BacklogStatus.PENDING,
        manifest_id=authority.item.manifest_id,
    )
    provider_failure = HearingModelCallFailureIntent(
        request=repair.request,
        owner_token="r" * 43,
        claim_lease_expires_at=claim.lease_expires_at,
        claim_takeover_count=claim.takeover_count,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )

    with pytest.raises(ContractViolation, match="fenced failure authority"):
        seed.repository.commit_hearing_backlog_retry(
            RUN_ID,
            authority.case.revision,
            authority.audit_head,
            outcome,
        )
    wrong_owner = HearingModelCallFailureIntent(
        request=repair.request,
        owner_token="x" * 43,
        claim_lease_expires_at=claim.lease_expires_at,
        claim_takeover_count=claim.takeover_count,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    with pytest.raises(ConcurrentModification, match="claim fence"):
        seed.repository.commit_hearing_backlog_retry(
            RUN_ID,
            authority.case.revision,
            authority.audit_head,
            outcome,
            wrong_owner,
        )

    def fail_after_authority(phase: str) -> None:
        if phase == "hearing.backlog_retry.after_failure_authority":
            raise RuntimeError("injected retry provider authority failure")

    faulty = SQLiteEvidenceRepository(
        seed.database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        fault_injector=fail_after_authority,
    )
    with pytest.raises(RuntimeError, match="injected retry provider authority failure"):
        faulty.commit_hearing_backlog_retry(
            RUN_ID,
            authority.case.revision,
            authority.audit_head,
            outcome,
            provider_failure,
        )

    with sqlite3.connect(seed.database) as connection:
        assert connection.execute(
            """
            SELECT COUNT(*) FROM m4_model_call_failure_authorities
            WHERE closure_kind = 'RETRY_FAILURE'
            """
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_hearing_backlog_retry_outcomes"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_backlog_completion_receipts"
        ).fetchone() == (0,)

    committed = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        outcome,
        provider_failure,
    )
    replayed = faulty.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        outcome,
        provider_failure,
    )
    assert committed.failure_authority is not None
    assert replayed.created is False
    assert replayed.failure_authority == committed.failure_authority

    with sqlite3.connect(seed.database) as connection:
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm4_model_call_failure_authorities_no_update'
            """
        ).fetchone()
        assert trigger is not None
        connection.execute("DROP TRIGGER m4_model_call_failure_authorities_no_update")
        connection.execute(
            """
            UPDATE m4_model_call_failure_authorities
            SET claim_owner_sha256 = ?
            WHERE run_id = ? AND closure_kind = 'RETRY_FAILURE'
            """,
            ("f" * 64, RUN_ID),
        )
        connection.execute(str(trigger[0]))

    reopened = SQLiteEvidenceRepository(
        seed.database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
    )
    with pytest.raises(RepositoryIntegrityError, match="indexes conflict"):
        reopened.commit_hearing_backlog_retry(
            RUN_ID,
            authority.case.revision,
            authority.audit_head,
            outcome,
            provider_failure,
        )


def test_real_outage_seed_strict_pair_advances_one_generation(tmp_path: Path) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None
    lease = BacklogLeaseIdentity(
        run_id=leased.run_id,
        item_id=leased.item_id,
        lease_id=leased.lease_id,
        attempt_count=leased.attempt_count,
        retry_generation=leased.retry_generation,
    )
    authority = seed.repository.load_hearing_backlog_retry_authority(RUN_ID, lease)
    prepared = _prepared_prosecutor(seed, authority)
    context = HearingRoleCallContext(
        session=authority.session,
        cycle_scope=authority.cycle_scope,
        budget_usage_before_primary=HearingBudgetUsage(
            reserved_images=authority.reserved_images,
            accounted_output_tokens=authority.accounted_output_tokens,
        ),
        config=seed.config,
        run_manifest=seed.manifest,
        catalog=seed.catalog,
    )
    calls = _strict_error(prepared, context).failed_calls
    for index, call in enumerate(calls):
        owner = "o" * 43 if index == 0 else "r" * 43
        seed.repository.complete_hearing_model_call(
            RUN_ID,
            call.request,
            call.response,
            call.usage,
            owner,
        )
        if index == 0:
            claimed = seed.repository.claim_hearing_model_call(
                RUN_ID,
                calls[1].request,
                "r" * 43,
                lease,
            )
            assert claimed.request_id == calls[1].request.request_id
        seed.repository.append_hearing_parse_receipt(call.parse_receipt)

    authority = seed.repository.load_hearing_backlog_retry_authority(RUN_ID, lease)
    proof = HearingStrictParseFailureProof(
        lease=lease,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        role=VlmRole.PROSECUTOR,
        attempts=tuple(
            HearingStrictParseFailureAttempt(
                request=call.request,
                response=call.response,
                parse_receipt=call.parse_receipt,
            )
            for call in calls
        ),
    )
    response_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=call.response.response_id,
                )
                for call in calls
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    failure = HearingBacklogRetryFailure(
        lease=lease,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        request=calls[0].request,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        next_status=BacklogStatus.PENDING,
        response_refs=response_refs,
        strict_parse_failure=proof,
        manifest_id=authority.item.manifest_id,
    )
    committed = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        failure,
    )
    assert committed.item.retry_generation == 1

    leased_again = _lease(seed)
    assert leased_again is not None
    next_authority = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased_again.run_id,
            item_id=leased_again.item_id,
            lease_id=leased_again.lease_id,
            attempt_count=leased_again.attempt_count,
            retry_generation=leased_again.retry_generation,
        ),
    )
    assert next_authority.item.retry_generation == 1
    assert next_authority.unfinished_request is None
    assert next_authority.latest_completion == committed.receipt
    assert next_authority.reserved_images_before_primary == next_authority.reserved_images
    assert (
        next_authority.accounted_output_tokens_before_primary
        == next_authority.accounted_output_tokens
    )

    retrieval = seed.repository.load_precedent_retrieval(
        RUN_ID,
        next_authority.stage_request.precedent_retrieval_receipt_id,
    )
    evidence = derive_evidence_authority(next_authority.case.case.evidence_packs[-1])
    fresh = prepare_primary_hearing_request(
        role=VlmRole.PROSECUTOR,
        session=next_authority.session,
        cycle_scope=next_authority.cycle_scope,
        retrieval=retrieval,
        evidence_pack=evidence.pack,
        evidence_authority=evidence,
        hearing_grant=None,
        budget_usage=HearingBudgetUsage(
            reserved_images=next_authority.reserved_images_before_primary,
            accounted_output_tokens=(next_authority.accounted_output_tokens_before_primary),
        ),
        config=seed.config,
        run_manifest=seed.manifest,
        catalog=seed.catalog,
        generation=HearingRequestGeneration(
            retry_generation=next_authority.item.retry_generation,
            backlog_item_id=next_authority.item.item_id,
        ),
    )
    fresh_claim = seed.repository.claim_hearing_model_call(
        RUN_ID,
        fresh.request,
        "fresh-generation-owner-" + "n" * 32,
        next_authority.lease,
    )
    assert fresh_claim.status.value == "ACQUIRED"
    after_fresh_claim = seed.repository.load_hearing_backlog_retry_authority(
        RUN_ID,
        next_authority.lease,
    )
    assert after_fresh_claim.reserved_images_before_primary == next_authority.reserved_images
    assert after_fresh_claim.reserved_images > next_authority.reserved_images


def test_primary_parse_then_provider_failure_reloads_exact_repair_resume(
    tmp_path: Path,
) -> None:
    seed = _provider_outage_seed(tmp_path)
    leased = _lease(seed)
    assert leased is not None
    lease = BacklogLeaseIdentity(
        run_id=leased.run_id,
        item_id=leased.item_id,
        lease_id=leased.lease_id,
        attempt_count=leased.attempt_count,
        retry_generation=leased.retry_generation,
    )
    authority = seed.repository.load_hearing_backlog_retry_authority(RUN_ID, lease)
    prepared = _prepared_prosecutor(seed, authority)
    context = HearingRoleCallContext(
        session=authority.session,
        cycle_scope=authority.cycle_scope,
        budget_usage_before_primary=HearingBudgetUsage(
            reserved_images=authority.reserved_images,
            accounted_output_tokens=authority.accounted_output_tokens,
        ),
        config=seed.config,
        run_manifest=seed.manifest,
        catalog=seed.catalog,
    )
    primary, repair = _strict_error(prepared, context).failed_calls
    seed.repository.complete_hearing_model_call(
        RUN_ID,
        primary.request,
        primary.response,
        primary.usage,
        "o" * 43,
    )
    claimed = seed.repository.claim_hearing_model_call(
        RUN_ID,
        repair.request,
        "r" * 43,
        lease,
    )
    assert claimed.request_id == repair.request.request_id and claimed.lease_expires_at is not None
    seed.repository.append_hearing_parse_receipt(primary.parse_receipt)
    failure = HearingBacklogRetryFailure(
        lease=lease,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        request=repair.request,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=BacklogStatus.PENDING,
        manifest_id=authority.item.manifest_id,
    )
    provider_failure = HearingModelCallFailureIntent(
        request=repair.request,
        owner_token="r" * 43,
        claim_lease_expires_at=claimed.lease_expires_at,
        claim_takeover_count=claimed.takeover_count,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    committed = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        failure,
        provider_failure,
    )
    failure_authority = committed.failure_authority
    assert failure_authority is not None
    assert failure_authority.closure_kind.value == "RETRY_FAILURE"
    assert (
        failure_authority.claim_owner_sha256
        == hashlib.sha256(("r" * 43).encode("utf-8")).hexdigest()
    )
    assert failure_authority.claim_takeover_count == claimed.takeover_count
    assert failure_authority.completion_receipt_id == committed.receipt.receipt_id
    replayed = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        failure,
        provider_failure,
    )
    assert replayed.created is False
    assert replayed.failure_authority == failure_authority

    leased_again = _lease(seed)
    assert leased_again is not None
    reopened = SQLiteEvidenceRepository(
        seed.database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
    )
    resumed = reopened.load_hearing_backlog_retry_authority(
        RUN_ID,
        BacklogLeaseIdentity(
            run_id=leased_again.run_id,
            item_id=leased_again.item_id,
            lease_id=leased_again.lease_id,
            attempt_count=leased_again.attempt_count,
            retry_generation=leased_again.retry_generation,
        ),
    )
    assert resumed.unfinished_request == repair.request
    assert resumed.prior_primary_failure == primary
    assert resumed.latest_completion == committed.receipt
    assert resumed.latest_failure_authority == failure_authority
    assert resumed.reserved_images_before_primary == 0
    assert resumed.accounted_output_tokens_before_primary == 0

    repair_owner = "repair-takeover-owner-" + "s" * 32
    repair_takeover = reopened.claim_hearing_model_call(
        RUN_ID,
        repair.request,
        repair_owner,
        resumed.lease,
    )
    assert repair_takeover.status.value == "ACQUIRED"
    assert repair_takeover.takeover_count == claimed.takeover_count + 1

    seed.repository.complete_hearing_model_call(
        RUN_ID,
        repair.request,
        repair.response,
        repair.usage,
        repair_owner,
    )
    seed.repository.append_hearing_parse_receipt(repair.parse_receipt)
    repair_lease = resumed.lease
    proof = HearingStrictParseFailureProof(
        lease=repair_lease,
        source_checkpoint_id=resumed.checkpoint.checkpoint_id,
        source_checkpoint_sha256=resumed.checkpoint.checkpoint_sha256,
        source_checkpoint_version=resumed.checkpoint.version,
        role=VlmRole.PROSECUTOR,
        attempts=tuple(
            HearingStrictParseFailureAttempt(
                request=call.request,
                response=call.response,
                parse_receipt=call.parse_receipt,
            )
            for call in (primary, repair)
        ),
    )
    response_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=call.response.response_id,
                )
                for call in (primary, repair)
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    strict_failure = HearingBacklogRetryFailure(
        lease=repair_lease,
        source_checkpoint_id=resumed.checkpoint.checkpoint_id,
        source_checkpoint_sha256=resumed.checkpoint.checkpoint_sha256,
        source_checkpoint_version=resumed.checkpoint.version,
        request=primary.request,
        role=VlmRole.PROSECUTOR,
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        next_status=BacklogStatus.PENDING,
        response_refs=response_refs,
        strict_parse_failure=proof,
        manifest_id=resumed.item.manifest_id,
    )
    strict_commit = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        resumed.case.revision,
        resumed.audit_head,
        strict_failure,
    )
    assert strict_commit.item.retry_generation == 1


def test_real_outage_seed_reclaims_pending_then_exhausted_without_fake_claim(
    tmp_path: Path,
) -> None:
    seed = _provider_outage_seed(tmp_path)
    commits: list[HearingBacklogRetryCommit] = []
    for attempt in range(1, 4):
        leased = _lease(seed, attempt_expiry=RECORDED_AT + timedelta(seconds=1))
        assert leased is not None and leased.attempt_count == attempt
        reopened = SQLiteEvidenceRepository(
            seed.database,
            BUSY_TIMEOUT_MS,
            clock=_clock,
        )
        loaded = reopened.load_hearing_backlog_retry_authority(
            RUN_ID,
            BacklogLeaseIdentity(
                run_id=leased.run_id,
                item_id=leased.item_id,
                lease_id=leased.lease_id,
                attempt_count=leased.attempt_count,
                retry_generation=leased.retry_generation,
            ),
        )
        if attempt > 1:
            assert loaded.latest_completion is not None
            assert isinstance(
                loaded.latest_completion.outcome,
                HearingBacklogRetryFailure,
            )
            assert (
                loaded.latest_completion.outcome.reason_code
                == BacklogReasonCode.WORKER_LEASE_EXPIRED
            )
            assert loaded.latest_failure_authority is None
        reclaimed = seed.repository.reclaim_expired_hearing_backlog(
            RUN_ID,
            RECORDED_AT + timedelta(seconds=2),
            1,
        )
        assert len(reclaimed) == 1
        commits.append(reclaimed[0])

    assert all(isinstance(commit.receipt.outcome, HearingBacklogRetryFailure) for commit in commits)
    assert all(commit.failure_authority is None for commit in commits)
    assert [
        commit.receipt.outcome.reason_code
        for commit in commits
        if isinstance(commit.receipt.outcome, HearingBacklogRetryFailure)
    ] == [
        BacklogReasonCode.WORKER_LEASE_EXPIRED,
    ] * 3
    assert [commit.item.status for commit in commits] == [
        BacklogStatus.PENDING,
        BacklogStatus.PENDING,
        BacklogStatus.EXHAUSTED,
    ]
    assert commits[-1].case.case.status == CaseStatus.HUMAN_REVIEW
    human = commits[-1].receipt.outcome.human_review_receipt
    assert human is not None
    assert human.backlog_item_ref == ArtifactRef(
        kind=ArtifactKind.BACKLOG_ITEM,
        artifact_id=seed.item_id,
    )
    with sqlite3.connect(seed.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM m4_model_call_claims").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m4_backlog_completion_receipts"
        ).fetchone() == (3,)


def test_exhaustion_human_receipt_semantic_hash_tamper_fails_closed(
    tmp_path: Path,
) -> None:
    seed = _provider_outage_seed(tmp_path)
    final_authority: HearingBacklogRetryAuthority | None = None
    final_commit: HearingBacklogRetryCommit | None = None
    for _attempt in range(1, 4):
        leased = _lease(seed, attempt_expiry=RECORDED_AT + timedelta(seconds=1))
        assert leased is not None
        authority = seed.repository.load_hearing_backlog_retry_authority(
            RUN_ID,
            BacklogLeaseIdentity(
                run_id=leased.run_id,
                item_id=leased.item_id,
                lease_id=leased.lease_id,
                attempt_count=leased.attempt_count,
                retry_generation=leased.retry_generation,
            ),
        )
        reclaimed = seed.repository.reclaim_expired_hearing_backlog(
            RUN_ID,
            RECORDED_AT + timedelta(seconds=2),
            1,
        )
        assert len(reclaimed) == 1
        final_authority = authority
        final_commit = reclaimed[0]

    assert final_authority is not None and final_commit is not None
    outcome = final_commit.receipt.outcome
    assert isinstance(outcome, HearingBacklogRetryFailure)
    human = outcome.human_review_receipt
    assert human is not None
    with sqlite3.connect(seed.database) as connection:
        hashes = connection.execute(
            """
            SELECT receipt_sha256, document_sha256
            FROM m4_hearing_human_review_receipts
            WHERE run_id = ? AND receipt_id = ?
            """,
            (RUN_ID, human.receipt_id),
        ).fetchone()
        assert hashes is not None and hashes[0] != hashes[1]
        trigger_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm4_hearing_human_review_receipts_no_update'
            """
        ).fetchone()
        assert trigger_sql is not None
        connection.execute("DROP TRIGGER m4_hearing_human_review_receipts_no_update")
        connection.execute(
            """
            UPDATE m4_hearing_human_review_receipts
            SET receipt_sha256 = document_sha256
            WHERE run_id = ? AND receipt_id = ?
            """,
            (RUN_ID, human.receipt_id),
        )
        connection.execute(str(trigger_sql[0]))

    with pytest.raises(RepositoryIntegrityError, match="human-review"):
        seed.repository.commit_hearing_backlog_retry(
            RUN_ID,
            final_authority.case.revision,
            final_authority.audit_head,
            outcome,
        )
