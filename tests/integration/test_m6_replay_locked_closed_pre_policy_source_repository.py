from __future__ import annotations

import hashlib
from unittest.mock import patch

import pytest

import tests.integration.test_m3_sqlite_repository as m3_fixture
from labcourt.adapters.fake_hearing_precedents import FakeHearingPrecedentRetriever
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.hearing_prompt_renderer import HearingJinjaPromptCatalog
from labcourt.adapters.storage import SecureHearingModelResponseStore, SecureWorkspace
from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.readonly_m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPrePolicySourceReadError,
    M6ReplayLockedClosedPrePolicySourceReadErrorCode,
    ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository,
)
from labcourt.adapters.storage.readonly_m6_replay_locked_policy_source import (
    ReadonlyM6ReplayLockedAlertPolicySourceRepository,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.vlm import (
    DeterministicFakeHearingVLMClient,
    DeterministicFakeVLMClient,
    FakeVLMFixture,
)
from labcourt.application.alert_policy_verifier import ConfiguredAlertPolicyVerifier
from labcourt.application.automatic_precedent_verifier import (
    ConfiguredAutomaticPrecedentVerifier,
)
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.application.m6_replay_locked_policy_source import (
    build_m6_replay_locked_alert_policy_causal_cut,
)
from labcourt.config_loader import load_config
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_replay_locked_execution import M6ReplayLockedExecutionRoute
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyFastPrePolicySource,
    M6ReplayLockedClosedPolicyM4PrePolicySource,
)
from labcourt.ports.m6_source_authority_builder import M6ReplayInputSelection
from tests.integration.test_m3_screening_pipeline import (
    _draft as _m3_draft,
)
from tests.integration.test_m3_screening_pipeline import (
    _pipeline_coordinator,
    _setup_pipeline_runtime,
)
from tests.integration.test_m3_sqlite_repository import ROOT, RUN_ID
from tests.integration.test_m4_hearing_coordinator import (
    _escalated_case,
    _fixtures_for_terminal_hearing,
    _NeverAcquisitionExecutor,
    _PromptRegistrar,
)
from tests.integration.test_m5_sqlite_alert_repository import (
    _automatic_precedent,
    _channel_capability,
    _clock,
    _manifest_with_stream,
)
from tests.integration.test_m6_readonly_projection_context import (
    _base_closure,
    _exact_closure,
)
from tests.integration.test_m6_replay_locked_policy_source_repository import (
    _publish_source,
)
from tests.unit.test_m4_hearing_prompt_renderer import _hearing_schema_documents
from tests.unit.test_m6_replay_locked_alert_policy import _source_binding


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _draft_for_m3_manifest(manifest):  # type: ignore[no-untyped-def]
    base = _m3_draft()
    event = base.event.model_copy(update={"manifest_id": manifest.manifest_id})
    return type(base).model_validate(
        {
            **base.model_dump(mode="json", exclude_computed_fields=True),
            "event": event.model_dump(mode="json"),
            "manifest_id": manifest.manifest_id,
        }
    )


def _published_projection_source(tmp_path):  # type: ignore[no-untyped-def]
    manifest = _manifest_with_stream()
    runtime = _setup_pipeline_runtime(
        tmp_path,
        manifest_override=manifest,
        draft_override=_draft_for_m3_manifest(manifest),
    )
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        response_store = SecureModelResponseStore(workspace)
        ready = (
            _pipeline_coordinator(
                runtime,
                response_store=response_store,
                client=DeterministicFakeVLMClient(
                    {
                        runtime.prepared.request.cache_key: FakeVLMFixture.response(
                            runtime.raw_response,
                            input_tokens=23,
                            output_tokens=11,
                            latency_ms=17,
                        )
                    },
                    response_store,
                ),
            )
            .process_case(RUN_ID, runtime.case_id)
            .case
        )
    repository = SQLiteM5Repository(
        runtime.database,
        runtime.config.storage.busy_timeout_ms,
        clock=_clock,
        alert_policy_verifier=ConfiguredAlertPolicyVerifier(runtime.config),
        automatic_precedent_verifier=ConfiguredAutomaticPrecedentVerifier(
            runtime.config,
            DeterministicFakePrecedentEmbeddingProvider(),
        ),
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(runtime.config),
        alert_channel_capability=_channel_capability(
            manifest=manifest,
            config=runtime.config,
        ),
    )
    policy = ConfiguredAlertPolicyVerifier(runtime.config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    closed = repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        policy,
        _automatic_precedent(ready, manifest, runtime.config, policy),
    )
    source_case, base = _base_closure(runtime.database, RUN_ID)
    exact = _exact_closure(
        runtime.database,
        source_case=source_case,
        base=base,
        config=runtime.config,
    )
    selection = M6ReplayInputSelection(
        sample_id=_sha("m6-closed-pre-policy-projection-sample"),
        source_run_id=source_case.run_id,
        source_case_id=source_case.case_id,
        source_case_revision=closed.revision,
        frames=exact.frames,
        detections=exact.detections,
        model_calls=exact.model_calls,
        embeddings=exact.embeddings,
        tool_results=exact.tool_results,
        historical_cut=exact.historical_cut,
    )
    return _publish_source(
        tmp_path,
        database=runtime.database,
        closed=closed,
        manifest=manifest,
        config=runtime.config,
        selection_override=selection,
    )


def _published_m4_projection_source(tmp_path):  # type: ignore[no-untyped-def]
    manifest = _manifest_with_stream()
    base_event = m3_fixture._event()
    event = type(base_event).model_validate(
        {
            **base_event.model_dump(mode="json", exclude_computed_fields=True),
            "manifest_id": manifest.manifest_id,
        }
    )
    with (
        patch.object(m3_fixture, "_manifest", return_value=manifest),
        patch.object(m3_fixture, "_event", return_value=event),
    ):
        database, evidence, pack, escalated = _escalated_case(tmp_path)
    config = load_config(ROOT / "configs" / "demo.yaml")
    assert evidence.load_run_manifest(RUN_ID) == manifest
    catalog = HearingJinjaPromptCatalog(output_schema_json_by_prompt=_hearing_schema_documents())
    precedents = HearingPrecedentRetrievalService(
        FakeHearingPrecedentRetriever(()),
        retriever_version="fake-hearing-precedents-v1",
        retriever_manifest_id=_sha("fake-hearing-precedents"),
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=escalated,
        config=config,
        manifest=manifest,
        catalog=catalog,
        precedents=precedents,
    )
    workspace_root = tmp_path / "m4-workspace"
    workspace_root.mkdir()
    with SecureWorkspace(
        workspace_root,
        config.storage.max_media_bytes,
    ) as workspace:
        response_store = SecureHearingModelResponseStore(workspace)
        role_calls = HearingRoleCallService(
            repository=evidence,
            response_store=response_store,
            vlm_client=DeterministicFakeHearingVLMClient(fixtures, response_store),
            prompt_registrar=_PromptRegistrar(),
            owner_token_factory=lambda: "o" * 43,
        )
        outcome = HearingCoordinator(
            config=config,
            evidence_repository=evidence,
            hearing_repository=evidence,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=evidence,
                executor=_NeverAcquisitionExecutor(),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                evidence,
            ),
        ).process_case(RUN_ID, pack.case_id)
    ready = outcome.case
    assert ready.case.status is CaseStatus.READY_FOR_ALERT_POLICY
    assert outcome.review is not None and outcome.review.passed

    repository = SQLiteM5Repository(
        database,
        config.storage.busy_timeout_ms,
        clock=_clock,
        alert_policy_verifier=ConfiguredAlertPolicyVerifier(config),
        automatic_precedent_verifier=ConfiguredAutomaticPrecedentVerifier(
            config,
            DeterministicFakePrecedentEmbeddingProvider(),
        ),
        m5_precedent_policy_verifier=ConfiguredM5PrecedentPolicyVerifier(config),
        alert_channel_capability=_channel_capability(
            manifest=manifest,
            config=config,
        ),
    )
    policy = ConfiguredAlertPolicyVerifier(config).rebuild(
        ready.case,
        manifest,
        None,
        None,
    )
    closed = repository.commit_alert_policy(
        RUN_ID,
        ready.revision,
        policy,
        _automatic_precedent(ready, manifest, config, policy),
    )
    assert closed.case.status is CaseStatus.CLOSED

    source_case, base = _base_closure(database, RUN_ID)
    exact = _exact_closure(
        database,
        source_case=source_case,
        base=base,
        config=config,
    )
    selection = M6ReplayInputSelection(
        sample_id=_sha("m6-closed-pre-policy-m4-projection-sample"),
        source_run_id=source_case.run_id,
        source_case_id=source_case.case_id,
        source_case_revision=closed.revision,
        frames=exact.frames,
        detections=exact.detections,
        model_calls=exact.model_calls,
        embeddings=exact.embeddings,
        tool_results=exact.tool_results,
        historical_cut=exact.historical_cut,
    )
    return _publish_source(
        tmp_path,
        database=database,
        closed=closed,
        manifest=manifest,
        config=config,
        selection_override=selection,
    )


def test_repository_rebases_one_real_closed_sqlite_cut_to_its_fast_ready_predecessor(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    database, source_root, bundle, config = _published_projection_source(tmp_path)
    closure = bundle.replay_input_closure
    observation = ReadonlyM6ReplayLockedAlertPolicySourceRepository(
        database,
        store_root=source_root,
        config=config,
    ).load_alert_policy_source(closure)
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
    binding = _source_binding(cut)

    source = ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository(
        database,
        store_root=source_root,
        config=config,
    ).load_closed_policy_pre_policy_source(closure, binding)

    assert type(source) is M6ReplayLockedClosedPolicyFastPrePolicySource
    assert source.catalog_closure == closure
    assert source.projection_context.case == cut.source_ready_case
    assert source.source_ready_case_revision == cut.source_ready_case_revision
    assert closure.source_case_revision == cut.source_closed_case_revision
    assert source.source_snapshot.source_case_revision + 1 == closure.source_case_revision
    assert not hasattr(source, "source_alert_policy")
    assert not hasattr(source, "source_closed_case")


def test_repository_rebases_one_real_closed_sqlite_cut_to_its_m4_ready_predecessor(
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    database, source_root, bundle, config = _published_m4_projection_source(tmp_path)
    closure = bundle.replay_input_closure
    observation = ReadonlyM6ReplayLockedAlertPolicySourceRepository(
        database,
        store_root=source_root,
        config=config,
    ).load_alert_policy_source(closure)
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
    binding = _source_binding(cut).model_copy(
        update={
            "pre_policy_route": (M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE)
        }
    )

    source = ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository(
        database,
        store_root=source_root,
        config=config,
    ).load_closed_policy_pre_policy_source(closure, binding)

    assert type(source) is M6ReplayLockedClosedPolicyM4PrePolicySource
    assert source.catalog_closure == closure
    assert source.projection_context.case == cut.source_ready_case
    assert source.projection_context.case.status is CaseStatus.READY_FOR_ALERT_POLICY
    assert source.projection_context.case.procedural_reviews[-1].passed is True
    assert source.source_ready_case_revision == cut.source_ready_case_revision
    assert closure.source_case_revision == cut.source_closed_case_revision
    assert cut.source_closed_case.status is CaseStatus.CLOSED
    assert closure.source_case_document_sha256 == cut.source_closed_case_content_sha256
    assert closure.source_case_document_sha256 != source.source_snapshot.source_case_document_sha256
    assert len(closure.model_calls) == 4
    assert source.hearing_verdict_binding.verdict_id == (
        source.projection_context.case.verdicts[-1].verdict_id
    )
    assert source.gate_current_closure_receipt.source_review_id == (
        source.projection_context.case.procedural_reviews[-1].review_id
    )
    assert not hasattr(source, "private_ready_selector")
    assert not hasattr(source, "source_alert_policy")
    assert not hasattr(source, "source_closed_case")


def test_repository_rejects_a_binding_outside_the_loaded_cut(tmp_path) -> None:  # type: ignore[no-untyped-def]
    database, source_root, bundle, config = _published_projection_source(tmp_path)
    closure = bundle.replay_input_closure
    observation = ReadonlyM6ReplayLockedAlertPolicySourceRepository(
        database,
        store_root=source_root,
        config=config,
    ).load_alert_policy_source(closure)
    cut = build_m6_replay_locked_alert_policy_causal_cut(observation=observation)
    binding = _source_binding(cut).model_copy(update={"source_config_sha256": "f" * 64})
    repository = ReadonlyM6ReplayLockedClosedPolicyPrePolicySourceRepository(
        database,
        store_root=source_root,
        config=config,
    )

    with pytest.raises(M6ReplayLockedClosedPrePolicySourceReadError) as raised:
        repository.load_closed_policy_pre_policy_source(closure, binding)

    assert raised.value.code is (
        M6ReplayLockedClosedPrePolicySourceReadErrorCode.SOURCE_CUT_REJECTED
    )
