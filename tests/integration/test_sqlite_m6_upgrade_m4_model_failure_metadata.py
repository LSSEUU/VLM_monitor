from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import SecureHearingModelResponseStore, SecureWorkspace
from labcourt.adapters.storage._sqlite_m6_live_read_cut import m6_live_committed_read_cut
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    read_m6_sqlite_case_authority,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_documents import (
    M6SQLiteM4ModelDocumentError,
    M6SQLiteM4RoleModelManifestBinding,
    plan_m6_sqlite_m4_model_documents,
    resolve_m6_sqlite_m4_model_documents,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4ClaimStatus,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4SupportRoute,
)
from labcourt.adapters.vlm import DeterministicFakeHearingVLMClient
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_request import HearingBudgetUsage
from labcourt.application.hearing_role_call import HearingRoleCallContext, HearingRoleCallService
from labcourt.application.m6_upgrade_m4_model_physical import (
    plan_m6_m4_observed_model_call_closures,
)
from labcourt.config_loader import load_config
from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArgumentStance,
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
)
from labcourt.contracts.hearing import (
    HearingBacklogRetryFailure,
    HearingBacklogRetrySuccess,
    ProsecutorModelPayload,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall
from labcourt.contracts.model_call_failures import (
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.verdicts import Argument
from labcourt.domain.hearing_fsm import complete_prosecutor
from labcourt.ports.hearing_backlog import HearingModelCallFailureIntent
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS, ROOT, RUN_ID
from tests.integration.test_m4_hearing_coordinator import (
    OUTAGE_FIXTURE,
    _digest,
    _escalated_case,
    _fixtures_for_terminal_hearing,
    _NeverAcquisitionExecutor,
    _PromptRegistrar,
    _simulated_call,
)
from tests.integration.test_m4_sqlite_hearing_retry import (
    _lease,
    _prepared_prosecutor,
    _provider_outage_seed,
)
from tests.unit.test_m4_hearing_backlog_retry import _strict_error
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents


def test_current_provider_failure_closes_to_backlog_checkpoint_case_and_audit(
    tmp_path: Path,
) -> None:
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
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=repository,
            hearing_repository=repository,
            precedent_retrieval=precedents,
            role_calls=HearingRoleCallService(
                repository=repository,
                response_store=response_store,
                vlm_client=DeterministicFakeHearingVLMClient(fixtures, response_store),
                prompt_registrar=_PromptRegistrar(),
                owner_token_factory=lambda: "o" * 43,
            ),
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

    assert outcome.session is not None
    requests = repository.list_hearing_model_requests(RUN_ID, outcome.session.session_id)
    assert len(requests) == 1
    request = requests[0]
    case_document = canonical_json(outcome.case.case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(case_document.encode("utf-8")).hexdigest()
    selected_audits = tuple(
        audit
        for audit in repository.list_audit_entries(RUN_ID)
        if audit.after_sha256 == case_sha256
    )
    assert len(selected_audits) == 1
    selected_audit = selected_audits[0]
    binding = M6UpgradeCandidateCaseBinding(
        case_id=outcome.case.case.case_id,
        case_revision=outcome.case.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=selected_audit.sequence,
        case_audit_entry_hash=selected_audit.entry_hash,
    )
    role_bindings = tuple(
        M6SQLiteM4RoleModelManifestBinding(
            role=role,
            model_manifest_id=manifest.models[role.value.lower()].model_manifest_id,
        )
        for role in (
            M6LockedModelRole.PROSECUTOR,
            M6LockedModelRole.DEFENDER,
            M6LockedModelRole.JUDGE,
        )
    )
    observation = M6UpgradeObservedModelCall(
        request_id=request.request_id,
        layer=M6LockedModelCallLayer.HEARING,
        role=M6LockedModelRole.PROSECUTOR,
        attempt_index=request.attempt_index,
        result_kind=M6LockedModelCallResultKind.FAILURE,
        provider_invoked=True,
    )

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            assert selector.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
        with cut.reader() as reader:
            authority = read_m6_sqlite_case_authority(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_manifest_rule_version=manifest.rule_version,
                candidate_case_binding=binding,
            )
            plan = plan_m6_sqlite_m4_model_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=manifest.manifest_id,
                expected_role_model_manifests=role_bindings,
                selected_case_authority=authority,
                observed_model_calls=(observation,),
            )
            snapshot = resolve_m6_sqlite_m4_model_documents(
                connection=reader,
                metadata_plan=plan,
            )
            physical_plan = plan_m6_m4_observed_model_call_closures(
                source_case=authority.case,
                snapshot=snapshot,
            )
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone()["ready"] == 1

    assert len(plan.call_graphs) == 1
    graph = plan.call_graphs[0]
    assert graph.claim_status == M6SQLiteM4ClaimStatus.ACTIVE
    assert graph.failure is not None
    assert len(graph.artifact_refs) == 2
    assert plan.historical_failures == ()
    assert len(snapshot.failures) == 1
    assert physical_plan.planned_refs == plan.planned_artifact_refs
    support_routes = {slot.route for slot in plan.support_slots}
    assert {
        M6SQLiteM4SupportRoute.BACKLOG_ITEM,
        M6SQLiteM4SupportRoute.BACKLOG_ITEM_VERSION,
        M6SQLiteM4SupportRoute.BACKLOG_HEAD,
        M6SQLiteM4SupportRoute.HEARING_CHECKPOINT,
        M6SQLiteM4SupportRoute.CASE_VERSION,
        M6SQLiteM4SupportRoute.AUDIT_ENTRY,
    } <= support_routes


def test_completed_takeover_keeps_older_failure_only_in_history_and_support(
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
    takeover_owner = "takeover-owner-" + "t" * 32
    claimed = seed.repository.claim_hearing_model_call(
        RUN_ID,
        authority.stage_request,
        takeover_owner,
        lease,
    )
    assert claimed.takeover_count == 1
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
    call = replace(
        call,
        usage=call.usage.model_copy(update={"retry_count": claimed.takeover_count}),
    )
    trace = replace(trace, calls=(call,))
    seed.repository.complete_hearing_model_call(
        RUN_ID,
        call.request,
        call.response,
        call.usage,
        takeover_owner,
    )
    seed.repository.append_hearing_parse_receipt(call.parse_receipt, output)
    next_checkpoint = complete_prosecutor(
        authority.session,
        authority.checkpoint,
        output,
        trace,
    )
    outcome = HearingBacklogRetrySuccess(
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
    commit = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        outcome,
    )

    selected_case = commit.case.case
    case_document = canonical_json(selected_case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(case_document.encode("utf-8")).hexdigest()
    selected_audits = tuple(
        audit
        for audit in seed.repository.list_audit_entries(RUN_ID)
        if audit.after_sha256 == case_sha256
    )
    assert len(selected_audits) == 1
    selected_audit = selected_audits[0]
    binding = M6UpgradeCandidateCaseBinding(
        case_id=selected_case.case_id,
        case_revision=commit.case.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=selected_audit.sequence,
        case_audit_entry_hash=selected_audit.entry_hash,
    )
    role_bindings = tuple(
        M6SQLiteM4RoleModelManifestBinding(
            role=role,
            model_manifest_id=seed.manifest.models[role.value.lower()].model_manifest_id,
        )
        for role in (
            M6LockedModelRole.PROSECUTOR,
            M6LockedModelRole.DEFENDER,
            M6LockedModelRole.JUDGE,
        )
    )
    observation = M6UpgradeObservedModelCall(
        request_id=outcome.request.request_id,
        layer=M6LockedModelCallLayer.HEARING,
        role=M6LockedModelRole.PROSECUTOR,
        attempt_index=0,
        result_kind=M6LockedModelCallResultKind.RESPONSE,
        provider_invoked=True,
    )
    with m6_live_committed_read_cut(seed.database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            assert selector.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
        with cut.reader() as reader:
            case_authority = read_m6_sqlite_case_authority(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=seed.manifest.manifest_id,
                expected_manifest_rule_version=seed.manifest.rule_version,
                candidate_case_binding=binding,
            )
            plan = plan_m6_sqlite_m4_model_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=seed.manifest.manifest_id,
                expected_role_model_manifests=role_bindings,
                selected_case_authority=case_authority,
                observed_model_calls=(observation,),
            )
            snapshot = resolve_m6_sqlite_m4_model_documents(
                connection=reader,
                metadata_plan=plan,
            )
            physical_plan = plan_m6_m4_observed_model_call_closures(
                source_case=case_authority.case,
                snapshot=snapshot,
            )
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone()["ready"] == 1

    assert len(plan.call_graphs) == 1
    assert plan.call_graphs[0].failure is None
    assert tuple(value.claim_takeover_count for value in plan.historical_failures) == (0,)
    assert snapshot.failures == ()
    assert physical_plan.planned_refs == plan.planned_artifact_refs
    assert plan.historical_failures[0].authority_id not in {
        ref.artifact_id for ref in plan.planned_artifact_refs
    }
    assert M6SQLiteM4SupportRoute.BACKLOG_COMPLETION_RECEIPT in {
        slot.route for slot in plan.support_slots
    }

    historical = plan.historical_failures[0]
    with sqlite3.connect(seed.database) as connection:
        trigger = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm4_model_call_failure_authorities_no_update'
            """
        ).fetchone()
        row = connection.execute(
            """
            SELECT authority_json FROM m4_model_call_failure_authorities
            WHERE authority_id = ?
            """,
            (historical.authority_id,),
        ).fetchone()
        assert trigger is not None and row is not None
        raw = str(row[0])
        forged = raw[:-1] + " "
        assert len(forged.encode("utf-8")) == historical.document_bytes
        connection.execute("DROP TRIGGER m4_model_call_failure_authorities_no_update")
        connection.execute(
            """
            UPDATE m4_model_call_failure_authorities
            SET authority_json = ? WHERE authority_id = ?
            """,
            (forged, historical.authority_id),
        )
        connection.execute(str(trigger[0]))

    with m6_live_committed_read_cut(seed.database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            assert selector.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
        with cut.reader() as reader, pytest.raises(M6SQLiteM4ModelDocumentError) as raised:
            resolve_m6_sqlite_m4_model_documents(
                connection=reader,
                metadata_plan=plan,
            )
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
    assert raised.value.reason_code == M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID


def test_retry_provider_failure_binds_one_completion_and_keeps_initial_epoch_historical(
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
    primary_owner = "primary-takeover-" + "p" * 32
    claimed_primary = seed.repository.claim_hearing_model_call(
        RUN_ID,
        authority.stage_request,
        primary_owner,
        lease,
    )
    assert claimed_primary.takeover_count == 1
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
    primary = replace(
        primary,
        usage=primary.usage.model_copy(update={"retry_count": claimed_primary.takeover_count}),
    )
    seed.repository.complete_hearing_model_call(
        RUN_ID,
        primary.request,
        primary.response,
        primary.usage,
        primary_owner,
    )
    repair_owner = "repair-owner-" + "r" * 32
    claimed_repair = seed.repository.claim_hearing_model_call(
        RUN_ID,
        repair.request,
        repair_owner,
        lease,
    )
    assert claimed_repair.takeover_count == 0
    assert claimed_repair.lease_expires_at is not None
    seed.repository.append_hearing_parse_receipt(primary.parse_receipt)
    outcome = HearingBacklogRetryFailure(
        lease=lease,
        source_checkpoint_id=authority.checkpoint.checkpoint_id,
        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
        source_checkpoint_version=authority.checkpoint.version,
        request=repair.request,
        role=repair.request.role,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=BacklogStatus.PENDING,
        manifest_id=authority.item.manifest_id,
    )
    intent = HearingModelCallFailureIntent(
        request=repair.request,
        owner_token=repair_owner,
        claim_lease_expires_at=claimed_repair.lease_expires_at,
        claim_takeover_count=claimed_repair.takeover_count,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    commit = seed.repository.commit_hearing_backlog_retry(
        RUN_ID,
        authority.case.revision,
        authority.audit_head,
        outcome,
        intent,
    )
    assert commit.failure_authority is not None

    selected_case = commit.case.case
    case_document = canonical_json(selected_case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(case_document.encode("utf-8")).hexdigest()
    selected_audit = next(
        audit
        for audit in seed.repository.list_audit_entries(RUN_ID)
        if audit.after_sha256 == case_sha256
    )
    binding = M6UpgradeCandidateCaseBinding(
        case_id=selected_case.case_id,
        case_revision=commit.case.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=selected_audit.sequence,
        case_audit_entry_hash=selected_audit.entry_hash,
    )
    role_bindings = tuple(
        M6SQLiteM4RoleModelManifestBinding(
            role=role,
            model_manifest_id=seed.manifest.models[role.value.lower()].model_manifest_id,
        )
        for role in (
            M6LockedModelRole.PROSECUTOR,
            M6LockedModelRole.DEFENDER,
            M6LockedModelRole.JUDGE,
        )
    )
    observations = (
        M6UpgradeObservedModelCall(
            request_id=primary.request.request_id,
            layer=M6LockedModelCallLayer.HEARING,
            role=M6LockedModelRole.PROSECUTOR,
            attempt_index=0,
            result_kind=M6LockedModelCallResultKind.RESPONSE,
            provider_invoked=True,
        ),
        M6UpgradeObservedModelCall(
            request_id=repair.request.request_id,
            layer=M6LockedModelCallLayer.HEARING,
            role=M6LockedModelRole.PROSECUTOR,
            attempt_index=1,
            result_kind=M6LockedModelCallResultKind.FAILURE,
            provider_invoked=True,
        ),
    )
    with m6_live_committed_read_cut(seed.database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector() as selector:
            assert selector.execute("SELECT 1 AS ready").fetchone()["ready"] == 1
        with cut.reader() as reader:
            case_authority = read_m6_sqlite_case_authority(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=seed.manifest.manifest_id,
                expected_manifest_rule_version=seed.manifest.rule_version,
                candidate_case_binding=binding,
            )
            plan = plan_m6_sqlite_m4_model_documents(
                connection=reader,
                expected_run_id=RUN_ID,
                expected_manifest_id=seed.manifest.manifest_id,
                expected_role_model_manifests=role_bindings,
                selected_case_authority=case_authority,
                observed_model_calls=observations,
            )
            snapshot = resolve_m6_sqlite_m4_model_documents(
                connection=reader,
                metadata_plan=plan,
            )
            physical_plan = plan_m6_m4_observed_model_call_closures(
                source_case=case_authority.case,
                snapshot=snapshot,
            )
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone()["ready"] == 1

    assert len(plan.call_graphs) == 2
    assert len(snapshot.failures) == 1
    assert physical_plan.planned_refs == plan.planned_artifact_refs
    assert tuple(value.claim_takeover_count for value in plan.historical_failures) == (0,)
    terminal = next(graph for graph in plan.call_graphs if graph.failure is not None)
    assert terminal.observation.request_id == repair.request.request_id
    assert commit.failure_authority.completion_receipt_id in {
        slot.artifact_id
        for slot in plan.support_document_slots
        if slot.route.value == "m4_backlog_completion_receipts.receipt_json"
    }
    assert {
        M6SQLiteM4SupportRoute.BACKLOG_RETRY_OUTCOME,
        M6SQLiteM4SupportRoute.BACKLOG_COMPLETION_RECEIPT,
    } <= {slot.route for slot in plan.support_slots}
