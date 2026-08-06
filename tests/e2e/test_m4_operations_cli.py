"""Offline M4 CLI flow over real SQLite, private media, and three role fakes."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from labcourt.adapters.acquisition_fake import (
    CONTROLLED_FAKE_ACQUISITION_COMPONENT,
    CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY,
    acquisition_parameters_schema_sha256,
    controlled_fake_acquisition_component_manifest_id,
)
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage.hearing_model_response_store import (
    SecureHearingModelResponseStore,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_hearing_repository import SQLiteHearingRepository
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.adapters.vlm.openai_compatible import AppendOnlyRenderedPromptRegistry
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_role_call import HearingRoleCallService
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    M5HearingPrecedentRetriever,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.cli import app
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionMode,
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    CaseStatus,
    JudgeDisposition,
    ObjectiveFactKind,
    VerdictDecision,
    VlmRole,
)
from labcourt.contracts.events import ObjectiveFact
from labcourt.contracts.evidence import TrackConfidenceCurveParameters
from labcourt.contracts.hearing import (
    AcquisitionRequest,
    AcquisitionRequestPayload,
    DefenderModelPayload,
    HearingModelRequest,
    HearingModelResponse,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
    ToolExecutionManifest,
    derive_m4_tool_result_id,
)
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.m3_operations import (
    FakeVLMFixtureDisposition,
    FakeVLMResponseFixtureInput,
)
from labcourt.contracts.m4_operations import (
    M4FakeAcquisitionFixtureInput,
    M4FakeVLMFixtureBundle,
    M4ProcessCommandReport,
    M4ProcessDisposition,
    M4ProjectionDisposition,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Argument, JudgeResponse
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionRecovery,
    HearingAcquisitionRecoveryStatus,
)
from labcourt.services.m4_operations import (
    _fake_acquisition_executor,
    build_hearing_prompt_catalog,
)
from tests.integration.test_m3_operations_service import (
    ROOT,
    RUN_ID,
    _manifest,
    _response_bundle,
    _setup_ready_runtime,
)
from tests.integration.test_m4_hearing_coordinator import (
    _fixtures_for_terminal_hearing,
)
from tests.unit.test_m4_acquisition_fake import _fixture_execution

RUNNER = CliRunner()


def _manifest_with_controlled_acquisition() -> RunManifest:
    payload = _manifest().model_dump(mode="json", exclude={"manifest_id"})
    payload["software_components"] = {
        **payload["software_components"],
        CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY: (
            CONTROLLED_FAKE_ACQUISITION_COMPONENT.model_dump(mode="json")
        ),
    }
    return RunManifest.model_validate(payload)


def _allowed_crop(request: HearingModelRequest) -> ArtifactRef:
    return next(ref for ref in request.allowed_evidence_refs if ref.kind == ArtifactKind.CROP)


class _ExactAcquisitionHearingPlanner:
    """Author exact raw fixtures while exercising the production fake publisher."""

    def __init__(self, store: SecureHearingModelResponseStore, source_case) -> None:
        self._store = store
        self._source_case = source_case
        self._defense_argument_ids: dict[int, str] = {}
        self.fixtures: dict[str, FakeVLMResponseFixtureInput] = {}
        self.requests: list[HearingModelRequest] = []

    def complete(self, request: HearingModelRequest) -> HearingModelResponse:
        self.requests.append(request)
        crop_ref = _allowed_crop(request)
        if request.role == VlmRole.PROSECUTOR:
            argument = Argument(
                stance=ArgumentStance.PROSECUTION,
                claim=f"The disclosed crop supports acquisition round {request.round_index}.",
                evidence_refs=(crop_ref,),
                uncertainty=0.1,
            )
            payload = ProsecutorModelPayload(
                arguments=(argument,),
                case_summary="The prosecution uses only disclosed evidence.",
            )
        elif request.role == VlmRole.DEFENDER:
            argument = Argument(
                stance=ArgumentStance.DEFENSE,
                claim=f"The defense preserves objection {request.round_index}.",
                evidence_refs=(crop_ref,),
                uncertainty=0.2,
            )
            self._defense_argument_ids[request.round_index] = argument.argument_id
            payload = DefenderModelPayload(
                arguments=(argument,),
                case_summary="The defense uses only disclosed evidence.",
            )
        elif request.role == VlmRole.JUDGE:
            defense_argument_id = self._defense_argument_ids[request.round_index]
            if request.prior_acquisition_rounds == 0:
                event = self._source_case.case.event
                outcome = JudgeAcquisitionDecisionPayload(
                    request=AcquisitionRequestPayload(
                        action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
                        validated_parameters=TrackConfidenceCurveParameters(
                            action=AcquisitionAction.TRACK_CONFIDENCE_CURVE,
                            track_ref=event.primary_track_ref,
                            start_frame=event.start_frame,
                            end_frame_exclusive=event.end_frame_exclusive,
                        ),
                        reason_summary="Inspect the bounded confidence curve.",
                        supporting_evidence_refs=(crop_ref,),
                    )
                )
            else:
                outcome = JudgeFinalDecisionPayload(
                    decision=VerdictDecision.ESTABLISHED,
                    confidence=0.9,
                    recommended_alert_level=AlertLevel.CONFIRMED,
                    rationale_summary="The acquired structured record supports the proposal.",
                    evidence_citations=(EvidenceCitation(evidence_ref=crop_ref),),
                )
            payload = JudgeModelPayload(
                judge_responses=(
                    JudgeResponse(
                        defense_argument_id=defense_argument_id,
                        disposition=JudgeDisposition.REJECTED,
                        response_summary="The exact defense point is addressed.",
                    ),
                ),
                outcome=outcome,
            )
        else:  # pragma: no cover - the coordinator only has three frozen roles
            raise AssertionError(f"unexpected hearing role: {request.role}")

        raw = canonical_bytes(payload.model_dump(mode="json", exclude_computed_fields=True))
        fixture = FakeVLMResponseFixtureInput(
            disposition=FakeVLMFixtureDisposition.RESPONSE,
            cache_key=request.cache_key,
            raw_response_utf8=raw.decode("utf-8"),
            input_tokens=2,
            output_tokens=3,
            latency_ms=4,
        )
        if request.cache_key in self.fixtures:
            raise AssertionError("planner observed a duplicate role request")
        self.fixtures[request.cache_key] = fixture
        return self._store.publish(
            request,
            raw,
            input_tokens=fixture.input_tokens,
            output_tokens=fixture.output_tokens,
            latency_ms=fixture.latency_ms,
        )


class _ExactControlledAcquisitionPlanner:
    """Capture one request, then delegate execution to the production fake tool."""

    def __init__(self, manifest: RunManifest) -> None:
        self._manifest = manifest
        self.fixture: M4FakeAcquisitionFixtureInput | None = None

    @property
    def execution_mode(self) -> AcquisitionExecutionMode:
        return AcquisitionExecutionMode.PURE

    def execute(self, request: AcquisitionRequest, authority, *, idempotency_key: str):
        if self.fixture is not None:
            raise AssertionError("planner must execute exactly one acquisition")
        if (
            request.action != AcquisitionAction.TRACK_CONFIDENCE_CURVE
            or idempotency_key != request.request_id
        ):
            raise AssertionError("planner received an unexpected acquisition request")
        execution_manifest = ToolExecutionManifest(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            acquisition_request_id=request.request_id,
            action=request.action,
            tool_id="controlled-fake-track-confidence-curve",
            tool_revision="1.0.0",
            parameters_schema_sha256=acquisition_parameters_schema_sha256(request.action),
            component_manifest_id=controlled_fake_acquisition_component_manifest_id(),
            manifest_id=request.manifest_id,
        )
        input_refs = (
            ArtifactRef(
                kind=ArtifactKind.EVIDENCE_PACK,
                artifact_id=request.current_evidence_pack_id,
            ),
        )
        output_ref = ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id="acquired-confidence-fact",
        )
        result_id = derive_m4_tool_result_id(
            request.action,
            input_refs,
            (output_ref,),
            request.validated_parameters,
            execution_manifest.execution_manifest_id,
        )
        authored = M4FakeAcquisitionFixtureInput(
            request=request,
            objective_facts=(
                ObjectiveFact(
                    fact_id=output_ref.artifact_id,
                    kind=ObjectiveFactKind.DETECTION_SCORE,
                    value=0.75,
                    source_ref=ArtifactRef(
                        kind=ArtifactKind.TOOL_RESULT,
                        artifact_id=result_id,
                    ),
                    source_manifest_id=execution_manifest.execution_manifest_id,
                ),
            ),
        )
        bundle = M4FakeVLMFixtureBundle(
            schema_version="m4-fake-vlm-fixture-bundle-v1",
            fixtures=(),
            acquisition_fixtures=(authored,),
        )
        execution = _fake_acquisition_executor(self._manifest, bundle).execute(
            request,
            authority,
            idempotency_key=idempotency_key,
        )
        self.fixture = authored
        return execution

    def recover(self, request, authority, *, idempotency_key):
        del request, authority, idempotency_key
        return HearingAcquisitionRecovery(status=HearingAcquisitionRecoveryStatus.UNKNOWN)


def _plan_exact_acquisition_bundle(runtime, planner_workspace: Path) -> M4FakeVLMFixtureBundle:
    planner_workspace.mkdir()
    planner_database = planner_workspace / runtime.config.storage.database_filename
    with SecureWorkspace(
        planner_workspace,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        with SecureWorkspace(
            runtime.workspace_root,
            runtime.config.storage.max_media_bytes,
        ) as source_workspace:
            workspace.ensure_private_directory(RUN_ID)
            workspace.ensure_private_directory(f"{RUN_ID}/frames")
            for crop in runtime.pack.focus_crops:
                source = source_workspace.read_verified(
                    crop.local_path,
                    crop.media_sha256,
                    max_bytes=crop.size_bytes,
                )
                workspace.create_new(crop.local_path, source.bytes, crop.media_sha256)
        with (
            sqlite3.connect(runtime.database) as source_database,
            sqlite3.connect(planner_database) as destination_database,
        ):
            source_database.backup(destination_database)
        verifier = StoredPngVerifier(
            run_id=RUN_ID,
            workspace=workspace,
            max_media_bytes=runtime.config.storage.max_media_bytes,
            max_image_pixels=runtime.config.storage.max_image_pixels,
        )
        evidence = SQLiteEvidenceRepository(
            planner_database,
            runtime.config.storage.busy_timeout_ms,
            verifier=verifier,
        )
        hearings = SQLiteHearingRepository(evidence)
        manifest = evidence.load_run_manifest(RUN_ID)
        source_case = evidence.load_case(RUN_ID, runtime.case_id)
        response_store = SecureHearingModelResponseStore(workspace)
        planner_client = _ExactAcquisitionHearingPlanner(response_store, source_case)
        role_calls = HearingRoleCallService(
            repository=hearings,
            response_store=response_store,
            vlm_client=planner_client,
            prompt_registrar=AppendOnlyRenderedPromptRegistry(),
        )
        catalog = build_hearing_prompt_catalog()
        precedent_policy_verifier = ConfiguredM5PrecedentPolicyVerifier(runtime.config)
        m5_repository = SQLiteM5Repository(
            planner_database,
            runtime.config.storage.busy_timeout_ms,
            m5_precedent_policy_verifier=precedent_policy_verifier,
        )
        precedents = HearingPrecedentRetrievalService(
            M5HearingPrecedentRetriever(
                repository=m5_repository,
                manifest=manifest,
                policy=precedent_policy_verifier.expected_policy(manifest),
                run_mode=precedent_policy_verifier.run_mode,
                embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
            ),
            retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
            retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        )
        acquisition = _ExactControlledAcquisitionPlanner(manifest)
        coordinator = HearingCoordinator(
            config=runtime.config,
            evidence_repository=evidence,
            hearing_repository=hearings,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=hearings,
                executor=acquisition,
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                runtime.config,
                evidence,
            ),
        )
        outcome = coordinator.process_case(RUN_ID, runtime.case_id)

    assert outcome.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert [request.role for request in planner_client.requests] == [
        VlmRole.PROSECUTOR,
        VlmRole.DEFENDER,
        VlmRole.JUDGE,
        VlmRole.PROSECUTOR,
        VlmRole.DEFENDER,
        VlmRole.JUDGE,
    ]
    assert acquisition.fixture is not None
    return M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=tuple(sorted(planner_client.fixtures.values(), key=lambda item: item.cache_key)),
        acquisition_fixtures=(acquisition.fixture,),
    )


def _escalate(runtime, tmp_path: Path) -> None:
    authored = json.loads(runtime.raw_response)
    authored["violation_probability"] = 0.5
    fixture_bundle = _response_bundle(
        runtime.initial_cache_key,
        canonical_bytes(authored),
    )
    fixture = tmp_path / "m3-escalation.json"
    fixture.write_text(fixture_bundle.model_dump_json(), encoding="utf-8")
    result = RUNNER.invoke(
        app,
        [
            "process",
            "--run-id",
            RUN_ID,
            "--case-id",
            runtime.case_id,
            "--fixture-bundle",
            str(fixture),
            "--config",
            str(ROOT / "configs" / "demo.yaml"),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert (
        json.loads(result.stdout)["authority_report"]["outcomes"][0]["status"]
        == CaseStatus.ESCALATED.value
    )


def _m4_bundle(runtime, tmp_path: Path) -> Path:
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        verifier = StoredPngVerifier(
            run_id=RUN_ID,
            workspace=workspace,
            max_media_bytes=runtime.config.storage.max_media_bytes,
            max_image_pixels=runtime.config.storage.max_image_pixels,
        )
        evidence = SQLiteEvidenceRepository(
            runtime.database,
            runtime.config.storage.busy_timeout_ms,
            verifier=verifier,
        )
        source_case = evidence.load_case(RUN_ID, runtime.case_id)
    catalog = build_hearing_prompt_catalog()
    precedent_policy_verifier = ConfiguredM5PrecedentPolicyVerifier(runtime.config)
    m5_repository = SQLiteM5Repository(
        runtime.database,
        runtime.config.storage.busy_timeout_ms,
        m5_precedent_policy_verifier=precedent_policy_verifier,
    )
    precedents = HearingPrecedentRetrievalService(
        M5HearingPrecedentRetriever(
            repository=m5_repository,
            manifest=runtime.manifest,
            policy=precedent_policy_verifier.expected_policy(runtime.manifest),
            run_mode=precedent_policy_verifier.run_mode,
            embedding_provider=DeterministicFakePrecedentEmbeddingProvider(),
        ),
        retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    )
    fixtures = _fixtures_for_terminal_hearing(
        source_case=source_case,
        config=runtime.config,
        manifest=runtime.manifest,
        catalog=catalog,
        precedents=precedents,
    )
    bundle = M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=tuple(
            sorted(
                (
                    FakeVLMResponseFixtureInput(
                        disposition=FakeVLMFixtureDisposition.RESPONSE,
                        cache_key=cache_key,
                        raw_response_utf8=fixture.raw_response.decode("utf-8"),
                        input_tokens=fixture.input_tokens,
                        output_tokens=fixture.output_tokens,
                        latency_ms=fixture.latency_ms,
                    )
                    for cache_key, fixture in fixtures.items()
                ),
                key=lambda item: item.cache_key,
            )
        ),
    )
    path = tmp_path / "m4-terminal-hearing.json"
    path.write_text(bundle.model_dump_json(), encoding="utf-8")
    return path


def _args(
    runtime,
    fixture: Path,
    *,
    case_id: str | None = None,
    run_id: str = RUN_ID,
) -> list[str]:
    return [
        "hearing",
        "process",
        "--run-id",
        run_id,
        "--case-id",
        case_id or runtime.case_id,
        "--fixture-bundle",
        str(fixture),
        "--config",
        str(ROOT / "configs" / "demo.yaml"),
        "--json",
    ]


def _precedent_usage_counts(database: Path) -> tuple[int, int, int, int]:
    with sqlite3.connect(database) as connection:
        receipt_count = int(
            connection.execute("SELECT COUNT(*) FROM m4_precedent_retrieval_receipts").fetchone()[0]
        )
        exposure_count = int(
            connection.execute("SELECT COUNT(*) FROM m5_precedent_exposures").fetchone()[0]
        )
        citation_count = int(
            connection.execute("SELECT COUNT(*) FROM precedent_citations").fetchone()[0]
        )
        joined_count = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM m5_precedent_exposures AS exposure
                JOIN m4_precedent_retrieval_receipts AS receipt
                  ON receipt.run_id = exposure.run_id
                 AND receipt.retrieval_receipt_id = exposure.retrieval_receipt_id
                """
            ).fetchone()[0]
        )
        return receipt_count, exposure_count, citation_count, joined_count


def test_hearing_process_is_offline_complete_idempotent_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _setup_ready_runtime(tmp_path)
    workspace = tmp_path / "runs"
    seeded.workspace_root.rename(workspace)
    runtime = replace(
        seeded,
        workspace_root=workspace,
        database=workspace / seeded.config.storage.database_filename,
    )
    monkeypatch.chdir(tmp_path)
    _escalate(runtime, tmp_path)
    fixture = _m4_bundle(runtime, tmp_path)

    first = RUNNER.invoke(app, _args(runtime, fixture))

    assert first.exit_code == 0, first.output
    first_report = M4ProcessCommandReport.model_validate_json(first.stdout)
    first_outcome = first_report.authority_report.outcomes[0]
    assert first_report.perception_mode == "SIMULATED PERCEPTION"
    assert first_report.model_mode == "FAKE VLM"
    assert first_report.precedent_mode == "CONTROLLED FAKE"
    assert first_report.projection.disposition == M4ProjectionDisposition.REBUILT
    assert first_outcome.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert first_outcome.disposition == M4ProcessDisposition.PROCESSED
    assert first_outcome.hearing_session_id is not None
    assert first_outcome.verdict_id is not None
    assert first_outcome.procedural_review_id is not None
    assert first.stdout.strip() == canonical_bytes(json.loads(first.stdout)).decode("utf-8")
    assert _precedent_usage_counts(runtime.database) == (1, 1, 0, 1)

    repeated = RUNNER.invoke(app, _args(runtime, fixture))
    assert repeated.exit_code == 0, repeated.output
    repeated_report = M4ProcessCommandReport.model_validate_json(repeated.stdout)
    repeated_outcome = repeated_report.authority_report.outcomes[0]
    assert repeated_outcome.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert repeated_outcome.disposition == M4ProcessDisposition.OBSERVED_EXISTING
    assert repeated_outcome.pipeline_invoked is False
    assert repeated_outcome.verdict_id == first_outcome.verdict_id
    assert repeated_outcome.procedural_review_id == first_outcome.procedural_review_id
    assert _precedent_usage_counts(runtime.database) == (1, 1, 0, 1)

    before_unknown = _authority_counts(runtime.database)
    unknown = RUNNER.invoke(app, _args(runtime, fixture, case_id="unknown-case"))
    assert unknown.exit_code == 2
    assert json.loads(unknown.stdout)["authority_complete"] is False
    assert json.loads(unknown.stdout)["reason_code"] == "AUTHORITY_BOUNDARY_ERROR"
    assert _authority_counts(runtime.database) == before_unknown

    unknown_run = RUNNER.invoke(
        app,
        _args(runtime, fixture, run_id="run-missing-from-manifest"),
    )
    assert unknown_run.exit_code == 2
    assert json.loads(unknown_run.stdout)["authority_complete"] is False
    assert json.loads(unknown_run.stdout)["reason_code"] == "AUTHORITY_BOUNDARY_ERROR"
    assert _authority_counts(runtime.database) == before_unknown


def test_hearing_process_executes_one_exact_acquisition_then_completes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _setup_ready_runtime(
        tmp_path,
        run_manifest=_manifest_with_controlled_acquisition(),
    )
    workspace = tmp_path / "runs"
    seeded.workspace_root.rename(workspace)
    runtime = replace(
        seeded,
        workspace_root=workspace,
        database=workspace / seeded.config.storage.database_filename,
    )
    monkeypatch.chdir(tmp_path)
    _escalate(runtime, tmp_path)

    bundle = _plan_exact_acquisition_bundle(runtime, tmp_path / "planner-runs")
    assert bundle.fixture_count == 6
    assert bundle.acquisition_fixture_count == 1
    fixture = tmp_path / "m4-acquisition-hearing.json"
    fixture.write_text(bundle.model_dump_json(), encoding="utf-8")

    first = RUNNER.invoke(app, _args(runtime, fixture))

    assert first.exit_code == 0, first.output
    report = M4ProcessCommandReport.model_validate_json(first.stdout)
    outcome = report.authority_report.outcomes[0]
    assert report.authority_report.fixture_entry_count == 6
    assert report.authority_report.acquisition_fixture_count == 1
    assert outcome.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert outcome.disposition == M4ProcessDisposition.PROCESSED
    assert outcome.pipeline_invoked is True
    assert outcome.hearing_session_id is not None
    assert _acquisition_authority_snapshot(runtime.database) == (
        6,
        6,
        6,
        1,
        1,
        1,
        "COMPLETED",
        2,
    )

    before_repeat = _acquisition_authority_snapshot(runtime.database)
    repeated = RUNNER.invoke(app, _args(runtime, fixture))

    assert repeated.exit_code == 0, repeated.output
    repeated_report = M4ProcessCommandReport.model_validate_json(repeated.stdout)
    repeated_outcome = repeated_report.authority_report.outcomes[0]
    assert repeated_report.authority_report.acquisition_fixture_count == 1
    assert repeated_outcome.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert repeated_outcome.disposition == M4ProcessDisposition.OBSERVED_EXISTING
    assert repeated_outcome.pipeline_invoked is False
    assert repeated_outcome.verdict_id == outcome.verdict_id
    assert repeated_outcome.procedural_review_id == outcome.procedural_review_id
    assert _acquisition_authority_snapshot(runtime.database) == before_repeat


def test_hearing_process_rejects_unpinned_acquisition_before_m4_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeded = _setup_ready_runtime(tmp_path)
    workspace = tmp_path / "runs"
    seeded.workspace_root.rename(workspace)
    runtime = replace(
        seeded,
        workspace_root=workspace,
        database=workspace / seeded.config.storage.database_filename,
    )
    monkeypatch.chdir(tmp_path)
    _escalate(runtime, tmp_path)

    _pack, execution, _loaded, _specs = _fixture_execution(AcquisitionAction.TRACK_CONFIDENCE_CURVE)
    bundle = M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=(),
        acquisition_fixtures=(
            M4FakeAcquisitionFixtureInput(
                request=execution.request,
                objective_facts=execution.output_objects.objective_facts,
            ),
        ),
    )
    fixture = tmp_path / "m4-unpinned-acquisition.json"
    fixture.write_text(bundle.model_dump_json(), encoding="utf-8")
    before = _m4_boundary_snapshot(runtime.database, runtime.case_id)

    rejected = RUNNER.invoke(app, _args(runtime, fixture))

    assert rejected.exit_code == 2
    payload = json.loads(rejected.stdout)
    assert payload["authority_complete"] is False
    assert payload["reason_code"] == "ACQUISITION_COMPONENT_UNPINNED"
    assert _m4_boundary_snapshot(runtime.database, runtime.case_id) == before


def _acquisition_authority_snapshot(database: Path) -> tuple[int | str, ...]:
    with sqlite3.connect(database) as connection:
        claim = connection.execute("SELECT status FROM m4_acquisition_execution_claims").fetchone()
        case = connection.execute(
            "SELECT latest_pack_version FROM cases WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
        assert claim is not None
        assert case is not None
        return (
            connection.execute("SELECT COUNT(*) FROM m4_model_call_claims").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM m4_model_responses").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM m4_parsed_hearing_outputs").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM m4_acquisition_requests").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM m4_tool_execution_receipts").fetchone()[0],
            connection.execute(
                "SELECT COUNT(*) FROM m4_acquisition_execution_publications"
            ).fetchone()[0],
            claim[0],
            case[0],
        )


def _m4_boundary_snapshot(database: Path, case_id: str) -> tuple[object, ...]:
    with sqlite3.connect(database) as connection:
        table_names = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT name
                  FROM sqlite_master
                 WHERE type = 'table'
                   AND name LIKE 'm4_%'
                   AND name <> 'm4_authority_preflight'
                 ORDER BY name
                """
            )
        )
        row_counts = tuple(
            (name, connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0])
            for name in table_names
        )
        case = connection.execute(
            """
            SELECT status, current_revision, latest_pack_id, latest_pack_version
              FROM cases
             WHERE run_id = ? AND case_id = ?
            """,
            (RUN_ID, case_id),
        ).fetchone()
        audit_head = connection.execute(
            """
            SELECT sequence, entry_hash
              FROM audit_entries
             WHERE run_id = ?
             ORDER BY sequence DESC
             LIMIT 1
            """,
            (RUN_ID,),
        ).fetchone()
    return row_counts, case, audit_head


def _authority_counts(database: Path) -> tuple[int, ...]:
    with sqlite3.connect(database) as connection:
        return tuple(
            connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in (
                "cases",
                "m4_hearings",
                "m4_model_call_claims",
                "m4_model_responses",
                "m4_hearing_verdict_bindings",
                "procedural_reviews",
            )
        )
