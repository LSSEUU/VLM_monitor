from __future__ import annotations

import hashlib
from pathlib import Path

from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import SecureHearingModelResponseStore, SecureWorkspace
from labcourt.adapters.storage._sqlite_m6_live_read_cut import m6_live_committed_read_cut
from labcourt.adapters.storage._sqlite_m6_upgrade_case_document import (
    read_m6_sqlite_case_authority,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m4_model_documents import (
    M6SQLiteM4RoleModelManifestBinding,
    plan_m6_sqlite_m4_model_documents,
    resolve_m6_sqlite_m4_model_documents,
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
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.m6_upgrade_m4_model_physical import (
    plan_m6_m4_observed_model_call_closures,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import VlmRole
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactSource
from tests.integration.test_m3_sqlite_repository import BUSY_TIMEOUT_MS, ROOT, RUN_ID
from tests.integration.test_m4_hearing_coordinator import (
    _digest,
    _escalated_case,
    _fixtures_for_terminal_hearing,
    _NeverAcquisitionExecutor,
    _PromptRegistrar,
)
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents


def test_real_three_role_hearing_builds_same_reader_metadata_body_and_physical_plans(
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
                vlm_client=DeterministicFakeHearingVLMClient(
                    fixtures,
                    response_store,
                ),
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

    case_document = canonical_json(outcome.case.case.model_dump(mode="json"))
    case_sha256 = hashlib.sha256(case_document.encode("utf-8")).hexdigest()
    matching_audits = tuple(
        item for item in repository.list_audit_entries(RUN_ID) if item.after_sha256 == case_sha256
    )
    assert len(matching_audits) == 1
    selected_audit = matching_audits[0]
    binding = M6UpgradeCandidateCaseBinding(
        case_id=outcome.case.case.case_id,
        case_revision=outcome.case.revision,
        case_document_sha256=case_sha256,
        case_audit_sequence=selected_audit.sequence,
        case_audit_entry_hash=selected_audit.entry_hash,
    )
    assert outcome.record is not None
    requests = repository.list_hearing_model_requests(
        RUN_ID,
        outcome.record.hearing_session_id,
    )
    role_map = {
        VlmRole.PROSECUTOR: M6LockedModelRole.PROSECUTOR,
        VlmRole.DEFENDER: M6LockedModelRole.DEFENDER,
        VlmRole.JUDGE: M6LockedModelRole.JUDGE,
    }
    observations = tuple(
        sorted(
            (
                M6UpgradeObservedModelCall(
                    request_id=request.request_id,
                    layer=M6LockedModelCallLayer.HEARING,
                    role=role_map[request.role],
                    attempt_index=request.attempt_index,
                    result_kind=M6LockedModelCallResultKind.RESPONSE,
                    provider_invoked=True,
                )
                for request in requests
            ),
            key=lambda value: value.sort_key,
        )
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
                observed_model_calls=observations,
            )
            snapshot = resolve_m6_sqlite_m4_model_documents(
                connection=reader,
                metadata_plan=plan,
            )
            physical_plan = plan_m6_m4_observed_model_call_closures(
                source_case=plan.selected_case,
                snapshot=snapshot,
            )
        with cut.writer() as writer:
            assert writer.execute("SELECT 1 AS ready").fetchone()["ready"] == 1

    assert len(plan.call_graphs) == 3
    assert len(plan.hearing_model_bindings) == 1
    assert len(plan.selected_packs) == 1
    assert len(plan.planned_artifact_refs) == 18
    assert all(
        ref.source == M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL
        for ref in plan.planned_artifact_refs
    )
    assert plan.planned_document_bytes > plan.planned_physical_bytes > 0
    assert snapshot.source_identity_sha256 == plan.plan_identity_sha256
    assert physical_plan.planned_refs == plan.planned_artifact_refs
