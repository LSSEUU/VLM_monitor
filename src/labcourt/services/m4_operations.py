"""Run-scoped, offline composition root for bounded M4 hearing operations."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from labcourt.adapters.acquisition_fake import (
    CONTROLLED_FAKE_ACQUISITION_COMPONENT,
    CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY,
    DeterministicFakeHearingAcquisitionExecutor,
    FakeAcquisitionFixture,
    FakeAcquisitionToolSpec,
    acquisition_parameters_schema_sha256,
    controlled_fake_acquisition_component_manifest_id,
)
from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.hearing_prompt_renderer import (
    HEARING_PROMPT_DEFINITIONS,
    LEGACY_HEARING_PROMPT_DEFINITIONS,
    M8_HEARING_PROMPT_V2_DEFINITIONS,
    HearingJinjaPromptCatalog,
)
from labcourt.adapters.storage.hearing_model_response_store import (
    SecureHearingModelResponseStore,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_hearing_repository import SQLiteHearingRepository
from labcourt.adapters.storage.sqlite_m5_precedent_usage import (
    SQLiteM5PrecedentExposureCommitter,
)
from labcourt.adapters.storage.sqlite_m5_repository import SQLiteM5Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.adapters.vlm.fake import FakeFixtureDisposition, FakeVLMFixture
from labcourt.adapters.vlm.hearing_fake import DeterministicFakeHearingVLMClient
from labcourt.adapters.vlm.openai_compatible import AppendOnlyRenderedPromptRegistry
from labcourt.application._hearing_workflow_types import HearingPipelineOutcome
from labcourt.application.hearing_acquisition import HearingAcquisitionService
from labcourt.application.hearing_coordinator import HearingCoordinator
from labcourt.application.hearing_precedent_retrieval import (
    HearingPrecedentRetrievalService,
)
from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
)
from labcourt.application.hearing_request import (
    FROZEN_M4_PROMPT_BUNDLE_SHA256,
    LEGACY_M4_PROMPT_BUNDLE_SHA256,
    M8_HEARING_PROMPT_V2_BUNDLE_SHA256,
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
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    AcquisitionAction,
    CaseStatus,
    ProviderTransport,
)
from labcourt.contracts.hearing import HearingHumanReviewReason
from labcourt.contracts.m3_operations import (
    FakeVLMFixtureDisposition,
    FakeVLMResponseFixtureInput,
)
from labcourt.contracts.m4_operations import (
    M4BacklogRetryReport,
    M4FakeVLMFixtureBundle,
    M4ProcessCaseOutcome,
    M4ProcessCounts,
    M4ProcessDisposition,
    M4ProcessReport,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.references import require_reference_token
from labcourt.domain.evidence_authority import LoadedEvidenceObjects
from labcourt.exceptions import LabCourtError
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.ports.hearing_repository import HearingRepository
from labcourt.schema_export import expected_schema_files
from labcourt.services.m4_backlog_worker import (
    M4BacklogAuthorityRepository,
    M4HearingBacklogWorker,
)


class M4OperationsBoundaryCode(StrEnum):
    """Controlled composition failures safe for the CLI boundary."""

    DEPLOYMENT_UNSUPPORTED = "DEPLOYMENT_UNSUPPORTED"
    ACQUISITION_COMPONENT_UNPINNED = "ACQUISITION_COMPONENT_UNPINNED"
    BACKLOG_ADAPTER_UNAVAILABLE = "BACKLOG_ADAPTER_UNAVAILABLE"
    BACKLOG_WORKER_CONTRACT_VIOLATION = "BACKLOG_WORKER_CONTRACT_VIOLATION"


class M4OperationsBoundaryError(LabCourtError):
    """The requested runtime cannot preserve the advertised M4 authority."""

    def __init__(self, code: M4OperationsBoundaryCode) -> None:
        if not isinstance(code, M4OperationsBoundaryCode):
            raise TypeError("code must be an M4OperationsBoundaryCode")
        self.code = code
        super().__init__(code.value)


class M4BacklogWorker(Protocol):
    """Injectable boundary for the default SQLite HEARING worker."""

    def run_once(
        self,
        *,
        run_id: str,
        worker_id: str,
        lease_duration_seconds: int | None,
        reclaim_limit: int,
    ) -> M4BacklogRetryReport: ...


class M4CaseReader(Protocol):
    """Minimum read capability needed by the operations report boundary."""

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot: ...


class M4CaseCoordinator(Protocol):
    """Minimum bounded driver capability needed by one process command."""

    def process_case(self, run_id: str, case_id: str) -> HearingPipelineOutcome: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _fixture_mapping(bundle: M4FakeVLMFixtureBundle) -> Mapping[str, FakeVLMFixture]:
    mapped: dict[str, FakeVLMFixture] = {}
    for fixture in bundle.fixtures:
        if isinstance(fixture, FakeVLMResponseFixtureInput):
            mapped[fixture.cache_key] = FakeVLMFixture.response(
                fixture.raw_response_utf8.encode("utf-8"),
                input_tokens=fixture.input_tokens,
                output_tokens=fixture.output_tokens,
                latency_ms=fixture.latency_ms,
            )
            continue
        disposition = {
            FakeVLMFixtureDisposition.OUTAGE: FakeFixtureDisposition.OUTAGE,
            FakeVLMFixtureDisposition.TIMEOUT: FakeFixtureDisposition.TIMEOUT,
        }[fixture.disposition]
        mapped[fixture.cache_key] = FakeVLMFixture(disposition=disposition)
    return MappingProxyType(mapped)


def build_hearing_prompt_catalog(
    bundle_sha256: str = FROZEN_M4_PROMPT_BUNDLE_SHA256,
) -> HearingJinjaPromptCatalog:
    """Build the checked-in, independent M4 prompt/schema authority."""

    schemas = expected_schema_files()
    documents = {
        "hearing_prosecutor_v1": canonical_json(
            json.loads(schemas["prosecutor-model-payload.schema.json"])
        ),
        "hearing_defender_v1": canonical_json(
            json.loads(schemas["defender-model-payload.schema.json"])
        ),
        "hearing_judge_v1": canonical_json(json.loads(schemas["judge-model-payload.schema.json"])),
    }
    definitions = {
        FROZEN_M4_PROMPT_BUNDLE_SHA256: HEARING_PROMPT_DEFINITIONS,
        LEGACY_M4_PROMPT_BUNDLE_SHA256: LEGACY_HEARING_PROMPT_DEFINITIONS,
        M8_HEARING_PROMPT_V2_BUNDLE_SHA256: M8_HEARING_PROMPT_V2_DEFINITIONS,
    }.get(bundle_sha256)
    if definitions is None:
        raise ValueError("unsupported M4 hearing prompt bundle")
    return HearingJinjaPromptCatalog(
        output_schema_json_by_prompt=documents,
        expected_bundle_sha256=bundle_sha256,
        definitions=definitions,
    )


def _fake_acquisition_executor(
    manifest: RunManifest,
    bundle: M4FakeVLMFixtureBundle,
) -> DeterministicFakeHearingAcquisitionExecutor:
    """Install all five pure fake tools and exact authored success fixtures."""

    if (
        bundle.acquisition_fixtures
        and manifest.software_components.get(CONTROLLED_FAKE_ACQUISITION_COMPONENT_KEY)
        != CONTROLLED_FAKE_ACQUISITION_COMPONENT
    ):
        raise M4OperationsBoundaryError(M4OperationsBoundaryCode.ACQUISITION_COMPONENT_UNPINNED)
    detector_manifest_id = manifest.models["detector"].model_manifest_id
    specs = tuple(
        sorted(
            (
                FakeAcquisitionToolSpec(
                    action=action,
                    tool_id=f"controlled-fake-{action.value.lower().replace('_', '-')}",
                    tool_revision="1.0.0",
                    parameters_schema_sha256=acquisition_parameters_schema_sha256(action),
                    component_manifest_id=(controlled_fake_acquisition_component_manifest_id()),
                    model_manifest_id=(
                        detector_manifest_id
                        if action == AcquisitionAction.REDETECT_HIGH_RES
                        else None
                    ),
                )
                for action in AcquisitionAction
            ),
            key=lambda item: item.sort_key,
        )
    )
    fixtures = tuple(
        FakeAcquisitionFixture(
            request=fixture.request,
            output_objects=LoadedEvidenceObjects(
                frames=fixture.frames,
                crops=fixture.crops,
                objective_facts=fixture.objective_facts,
                detections=fixture.detections,
            ),
            crop_request=fixture.crop_request,
        )
        for fixture in bundle.acquisition_fixtures
    )
    return DeterministicFakeHearingAcquisitionExecutor(
        tool_specs=specs,
        fixtures=fixtures,
    )


def _m4_human_reason(snapshot: CaseSnapshot) -> HearingHumanReviewReason | None:
    for entry in reversed(snapshot.case.timeline):
        if entry.stage != "HEARING":
            continue
        value = entry.details.get("reason")
        if not isinstance(value, str):
            continue
        try:
            return HearingHumanReviewReason(value)
        except ValueError:
            return None
    return None


class M4OperationsService:
    """Single-case M4 process and injectable one-item retry operations."""

    __slots__ = (
        "_backlog_worker",
        "_coordinator",
        "_evidence",
        "_fixture_bundle",
        "_manifest_id",
        "_run_id",
    )

    def __init__(
        self,
        *,
        run_id: str,
        manifest_id: str,
        fixture_bundle: M4FakeVLMFixtureBundle,
        evidence_repository: M4CaseReader,
        hearing_coordinator: M4CaseCoordinator,
        backlog_worker: M4BacklogWorker | None = None,
    ) -> None:
        self._run_id = require_reference_token(run_id, "M4 operations run reference")
        if (
            not isinstance(manifest_id, str)
            or len(manifest_id) != 64
            or any(character not in "0123456789abcdef" for character in manifest_id)
        ):
            raise ValueError("manifest_id must be a lowercase SHA-256 digest")
        if not isinstance(fixture_bundle, M4FakeVLMFixtureBundle):
            raise TypeError("fixture_bundle must be an M4FakeVLMFixtureBundle")
        if not callable(getattr(evidence_repository, "load_case", None)):
            raise TypeError("evidence_repository does not implement load_case")
        if not callable(getattr(hearing_coordinator, "process_case", None)):
            raise TypeError("hearing_coordinator does not implement process_case")
        if backlog_worker is not None and not callable(getattr(backlog_worker, "run_once", None)):
            raise TypeError("backlog_worker does not implement run_once")
        self._manifest_id = manifest_id
        self._fixture_bundle = fixture_bundle
        self._evidence = evidence_repository
        self._coordinator = hearing_coordinator
        self._backlog_worker = backlog_worker

    def __repr__(self) -> str:
        return (
            "M4OperationsService("
            f"run_id={self._run_id!r}, perception_mode='SIMULATED PERCEPTION', "
            "model_mode='FAKE VLM', precedent_mode='CONTROLLED FAKE')"
        )

    def process_case(self, case_id: str) -> M4ProcessReport:
        """Advance or safely observe exactly one explicitly selected Case."""

        controlled_case_id = require_reference_token(case_id, "M4 process case reference")
        initial = self._evidence.load_case(self._run_id, controlled_case_id)
        active = initial.case.status in {
            CaseStatus.ESCALATED,
            CaseStatus.REWORK_REQUIRED,
            CaseStatus.DELIBERATING,
            CaseStatus.BACKLOGGED,
        }
        pipeline = (
            self._coordinator.process_case(self._run_id, controlled_case_id) if active else None
        )
        current = pipeline.case if pipeline is not None else initial
        status = current.case.status
        if pipeline is None:
            disposition = (
                M4ProcessDisposition.OBSERVED_EXISTING
                if status in {CaseStatus.READY_FOR_ALERT_POLICY, CaseStatus.HUMAN_REVIEW}
                else M4ProcessDisposition.SKIPPED_NOT_HEARING_READY
            )
        elif status == CaseStatus.BACKLOGGED:
            disposition = M4ProcessDisposition.DEFERRED_TO_BACKLOG
        elif status == CaseStatus.HUMAN_REVIEW:
            disposition = M4ProcessDisposition.TRANSFERRED_TO_HUMAN
        else:
            disposition = M4ProcessDisposition.PROCESSED

        case = current.case
        latest_verdict = case.verdicts[-1] if case.verdicts else None
        latest_review = case.procedural_reviews[-1] if case.procedural_reviews else None
        outcome = M4ProcessCaseOutcome(
            event_id=case.event.event_id,
            case_id=case.case_id,
            initial_status=initial.case.status,
            status=status,
            revision=current.revision,
            disposition=disposition,
            pipeline_invoked=pipeline is not None,
            hearing_session_id=(
                pipeline.session.session_id
                if pipeline is not None and pipeline.session is not None
                else None
            ),
            checkpoint_id=(
                pipeline.checkpoint.checkpoint_id
                if pipeline is not None and pipeline.checkpoint is not None
                else None
            ),
            verdict_id=latest_verdict.verdict_id if latest_verdict is not None else None,
            procedural_review_id=(latest_review.review_id if latest_review is not None else None),
            backlog_item_id=case.current_backlog_item_id,
            human_review_reason=_m4_human_reason(current),
            cache_hit_count=pipeline.cache_hit_count if pipeline is not None else 0,
            recovered_response_count=(
                pipeline.recovered_response_count if pipeline is not None else 0
            ),
        )
        counts = M4ProcessCounts(
            selected_cases=1,
            pipeline_invocations=int(outcome.pipeline_invoked),
            processed_cases=int(disposition == M4ProcessDisposition.PROCESSED),
            deferred_to_backlog_cases=int(disposition == M4ProcessDisposition.DEFERRED_TO_BACKLOG),
            transferred_to_human_cases=int(
                disposition == M4ProcessDisposition.TRANSFERRED_TO_HUMAN
            ),
            observed_existing_cases=int(disposition == M4ProcessDisposition.OBSERVED_EXISTING),
            skipped_not_hearing_ready_cases=int(
                disposition == M4ProcessDisposition.SKIPPED_NOT_HEARING_READY
            ),
            cache_hits=outcome.cache_hit_count,
            recovered_responses=outcome.recovered_response_count,
        )
        return M4ProcessReport(
            run_id=self._run_id,
            manifest_id=self._manifest_id,
            perception_mode="SIMULATED PERCEPTION",
            model_mode="FAKE VLM",
            precedent_mode="CONTROLLED FAKE",
            fixture_bundle_id=self._fixture_bundle.fixture_bundle_id,
            fixture_entry_count=self._fixture_bundle.fixture_count,
            acquisition_fixture_count=self._fixture_bundle.acquisition_fixture_count,
            requested_case_id=controlled_case_id,
            selection_limit=1,
            available_case_count=1,
            selection_truncated=False,
            outcomes=(outcome,),
            counts=counts,
        )

    def backlog_retry_run_once(
        self,
        *,
        worker_id: str,
        lease_duration_seconds: int | None = None,
        reclaim_limit: int = 100,
    ) -> M4BacklogRetryReport:
        """Delegate one bounded retry only through an explicit typed worker."""

        controlled_worker_id = require_reference_token(
            worker_id,
            "M4 backlog worker reference",
        )
        if lease_duration_seconds is not None and (
            not isinstance(lease_duration_seconds, int)
            or isinstance(lease_duration_seconds, bool)
            or not 1 <= lease_duration_seconds <= 14_400
        ):
            raise ValueError("lease_duration_seconds must be from 1 through 14400")
        if (
            not isinstance(reclaim_limit, int)
            or isinstance(reclaim_limit, bool)
            or not 1 <= reclaim_limit <= 10_000
        ):
            raise ValueError("reclaim_limit must be from 1 through 10000")
        if self._backlog_worker is None:
            raise M4OperationsBoundaryError(M4OperationsBoundaryCode.BACKLOG_ADAPTER_UNAVAILABLE)
        report = self._backlog_worker.run_once(
            run_id=self._run_id,
            worker_id=controlled_worker_id,
            lease_duration_seconds=lease_duration_seconds,
            reclaim_limit=reclaim_limit,
        )
        if (
            not isinstance(report, M4BacklogRetryReport)
            or report.run_id != self._run_id
            or report.manifest_id != self._manifest_id
            or report.fixture_bundle_id != self._fixture_bundle.fixture_bundle_id
            or report.fixture_entry_count != self._fixture_bundle.fixture_count
            or report.acquisition_fixture_count != self._fixture_bundle.acquisition_fixture_count
        ):
            raise M4OperationsBoundaryError(
                M4OperationsBoundaryCode.BACKLOG_WORKER_CONTRACT_VIOLATION
            )
        return report


@contextmanager
def open_m4_operations_service(
    *,
    config: AppConfig,
    run_id: str,
    workspace_root: str | Path,
    database_path: str | Path,
    fixture_bundle: M4FakeVLMFixtureBundle,
    clock: Callable[[], datetime] | None = None,
    backlog_worker: M4BacklogWorker | None = None,
) -> Iterator[M4OperationsService]:
    """Open the supported offline M4 runtime with three independent fake roles."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    controlled_run_id = require_reference_token(run_id, "M4 operations run reference")
    if not isinstance(fixture_bundle, M4FakeVLMFixtureBundle):
        raise TypeError("fixture_bundle must be an M4FakeVLMFixtureBundle")
    supplied_workspace_root = Path(workspace_root)
    supplied_database_path = Path(database_path)
    if ".." in supplied_workspace_root.parts or ".." in supplied_database_path.parts:
        raise ValueError("workspace_root and database_path cannot contain parent traversal")
    controlled_workspace_root = supplied_workspace_root.absolute()
    controlled_database_path = supplied_database_path.absolute()
    expected_database_path = controlled_workspace_root / config.storage.database_filename
    if controlled_database_path != expected_database_path:
        raise ValueError(
            "database_path must exactly match the configured file inside workspace_root"
        )
    profile_names = (
        config.hearing.prosecutor_profile,
        config.hearing.defender_profile,
        config.hearing.judge_profile,
    )
    profiles = tuple(config.providers[name] for name in profile_names)
    if (
        config.perception.provider != "precomputed"
        or len(set(profile_names)) != 3
        or any(
            profile.provider != "fake" or profile.transport != ProviderTransport.IN_PROCESS
            for profile in profiles
        )
    ):
        raise M4OperationsBoundaryError(M4OperationsBoundaryCode.DEPLOYMENT_UNSUPPORTED)
    effective_clock = clock or _utc_now
    if not callable(effective_clock):
        raise TypeError("clock must be callable")

    with SecureWorkspace(
        controlled_workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        verifier = StoredPngVerifier(
            run_id=controlled_run_id,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        evidence = SQLiteEvidenceRepository(
            controlled_database_path,
            config.storage.busy_timeout_ms,
            verifier=verifier,
            clock=effective_clock,
        )
        hearings = SQLiteHearingRepository(evidence)
        hearing_authority = cast(HearingRepository, hearings)
        manifest = evidence.load_run_manifest(controlled_run_id)
        precedent_policy_verifier = ConfiguredM5PrecedentPolicyVerifier(config)
        m5_repository = SQLiteM5Repository(
            controlled_database_path,
            config.storage.busy_timeout_ms,
            clock=effective_clock,
            m5_precedent_policy_verifier=precedent_policy_verifier,
        )
        embedding_provider = DeterministicFakePrecedentEmbeddingProvider()
        response_store = SecureHearingModelResponseStore(workspace)
        catalog = build_hearing_prompt_catalog()
        role_calls = HearingRoleCallService(
            repository=hearing_authority,
            response_store=response_store,
            vlm_client=DeterministicFakeHearingVLMClient(
                _fixture_mapping(fixture_bundle),
                response_store,
            ),
            prompt_registrar=AppendOnlyRenderedPromptRegistry(),
        )
        precedents = HearingPrecedentRetrievalService(
            M5HearingPrecedentRetriever(
                repository=m5_repository,
                manifest=manifest,
                policy=precedent_policy_verifier.expected_policy(manifest),
                run_mode=precedent_policy_verifier.run_mode,
                embedding_provider=embedding_provider,
            ),
            retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
            retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        )
        coordinator = HearingCoordinator(
            config=config,
            evidence_repository=evidence,
            hearing_repository=hearing_authority,
            precedent_retrieval=precedents,
            role_calls=role_calls,
            acquisition=HearingAcquisitionService(
                repository=hearing_authority,
                executor=_fake_acquisition_executor(manifest, fixture_bundle),
            ),
            prompt_catalog=catalog,
            review_verifier=DeterministicHearingProceduralReviewVerifier(
                config,
                evidence,
            ),
            precedent_outcome_committer=SQLiteM5PrecedentExposureCommitter(
                repository=m5_repository,
                hearing_repository=hearings,
                embedding_provider=embedding_provider,
            ),
        )
        effective_backlog_worker = backlog_worker
        if effective_backlog_worker is None:
            effective_backlog_worker = M4HearingBacklogWorker(
                run_id=controlled_run_id,
                config=config,
                manifest=manifest,
                fixture_bundle=fixture_bundle,
                catalog=catalog,
                repository=cast(M4BacklogAuthorityRepository, evidence),
                response_store=response_store,
                role_calls=role_calls,
                clock=effective_clock,
            )
        yield M4OperationsService(
            run_id=controlled_run_id,
            manifest_id=manifest.manifest_id,
            fixture_bundle=fixture_bundle,
            evidence_repository=evidence,
            hearing_coordinator=coordinator,
            backlog_worker=effective_backlog_worker,
        )


__all__ = [
    "M4BacklogWorker",
    "M4CaseCoordinator",
    "M4CaseReader",
    "M4OperationsBoundaryCode",
    "M4OperationsBoundaryError",
    "M4OperationsService",
    "build_hearing_prompt_catalog",
    "open_m4_operations_service",
]
