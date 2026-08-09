"""Run-scoped, offline composition root for bounded M3 operations."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.adapters.vlm.fake import (
    DeterministicFakeVLMClient,
    FakeFixtureDisposition,
    FakeVLMFixture,
)
from labcourt.adapters.vlm.http_transport import build_openai_compatible_transport
from labcourt.adapters.vlm.openai_compatible import (
    AppendOnlyRenderedPromptRegistry,
    OpenAICompatibleClientIdentity,
    OpenAICompatibleTransport,
    OpenAICompatibleVLMClient,
)
from labcourt.application.backlog_retry import BacklogRetryCoordinator
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.application.screening_coordinator import (
    ScreeningCoordinator,
    ScreeningPipelineOutcome,
)
from labcourt.contracts.backlog import BacklogRetryReport
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    ExecutionLocation,
    ProviderTransport,
)
from labcourt.contracts.m3_operations import (
    MAX_M3_PROCESS_CASES,
    FakeVLMFixtureBundle,
    FakeVLMFixtureDisposition,
    FakeVLMResponseFixtureInput,
    M3ProcessCaseOutcome,
    M3ProcessCounts,
    M3ProcessDisposition,
    M3ProcessReport,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.pilot import PilotA3Report
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import LabCourtError
from labcourt.ports.evidence_repository import CaseSnapshot
from labcourt.ports.vlm import VLMClient
from labcourt.services.m3 import build_screening_prompt_catalog


class M3OperationsBoundaryCode(StrEnum):
    """Controlled composition failures safe for a later CLI boundary."""

    DEPLOYMENT_UNSUPPORTED = "DEPLOYMENT_UNSUPPORTED"


class M3OperationsBoundaryError(LabCourtError):
    """A requested runtime cannot preserve the advertised M3 authority."""

    def __init__(self, code: M3OperationsBoundaryCode) -> None:
        self.code = code
        super().__init__(code.value)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _fixture_mapping(bundle: FakeVLMFixtureBundle) -> Mapping[str, FakeVLMFixture]:
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


def _artifact_ref(kind: ArtifactKind, artifact_id: str | None) -> ArtifactRef | None:
    if artifact_id is None:
        return None
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


@dataclass(frozen=True, slots=True)
class _ProcessedSelection:
    requested_case_id: str | None
    available_case_count: int
    selection_truncated: bool
    outcomes: tuple[M3ProcessCaseOutcome, ...]
    counts: M3ProcessCounts


class _ScreeningOperationsCore:
    """Provider-neutral bounded processing over one run-scoped composition."""

    __slots__ = ("clock", "config", "evidence", "manifest_id", "repository", "run_id", "screening")

    def __init__(
        self,
        *,
        config: AppConfig,
        run_id: str,
        manifest_id: str,
        evidence_repository: SQLiteEvidenceRepository,
        screening_repository: SQLiteM3Repository,
        screening_coordinator: ScreeningCoordinator,
        clock: Callable[[], datetime],
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        self.run_id = require_reference_token(run_id, "screening operations run reference")
        if (
            not isinstance(manifest_id, str)
            or len(manifest_id) != 64
            or any(character not in "0123456789abcdef" for character in manifest_id)
        ):
            raise ValueError("manifest_id must be a lowercase SHA-256 digest")
        for dependency, method, name in (
            (evidence_repository, "load_case", "evidence_repository"),
            (screening_repository, "lease_next", "screening_repository"),
            (screening_repository, "select_case_ids_bounded", "screening_repository"),
            (screening_coordinator, "process_case", "screening_coordinator"),
        ):
            if not callable(getattr(dependency, method, None)):
                raise TypeError(f"{name} does not implement {method}")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self.config = config
        self.manifest_id = manifest_id
        self.evidence = evidence_repository
        self.repository = screening_repository
        self.screening = screening_coordinator
        self.clock = clock

    @property
    def minimum_backlog_lease_seconds(self) -> int:
        return self.screening.minimum_backlog_lease_seconds

    def process_selection(
        self,
        *,
        case_id: str | None,
        max_cases: int,
    ) -> _ProcessedSelection:
        if (
            not isinstance(max_cases, int)
            or isinstance(max_cases, bool)
            or not 1 <= max_cases <= MAX_M3_PROCESS_CASES
        ):
            raise ValueError(f"max_cases must be an integer from 1 through {MAX_M3_PROCESS_CASES}")
        requested_case_id: str | None = None
        case_ids: tuple[str, ...]
        if case_id is not None:
            requested_case_id = require_reference_token(case_id, "screening process case reference")
            case_ids = (requested_case_id,)
            available_case_count = 1
            selection_truncated = False
        else:
            case_ids, available_case_count = self.repository.select_case_ids_bounded(
                self.run_id,
                max_cases,
            )
            case_ids = tuple(sorted(case_ids))
            selection_truncated = available_case_count > len(case_ids)
        outcomes = tuple(self._process_or_observe(selected) for selected in case_ids)
        dispositions = tuple(outcome.disposition for outcome in outcomes)
        counts = M3ProcessCounts(
            selected_cases=len(outcomes),
            pipeline_invocations=sum(outcome.pipeline_invoked for outcome in outcomes),
            processed_cases=dispositions.count(M3ProcessDisposition.PROCESSED),
            deferred_to_backlog_cases=dispositions.count(M3ProcessDisposition.DEFERRED_TO_BACKLOG),
            observed_existing_cases=dispositions.count(M3ProcessDisposition.OBSERVED_EXISTING),
            skipped_not_ready_cases=dispositions.count(M3ProcessDisposition.SKIPPED_NOT_READY),
            cache_hits=sum(outcome.cache_hit_count for outcome in outcomes),
            recovered_responses=sum(outcome.recovered_response_count for outcome in outcomes),
            repair_attempts=sum(outcome.repair_attempt_count for outcome in outcomes),
        )
        return _ProcessedSelection(
            requested_case_id=requested_case_id,
            available_case_count=available_case_count,
            selection_truncated=selection_truncated,
            outcomes=outcomes,
            counts=counts,
        )

    def build_backlog_retry_coordinator(
        self,
        *,
        lease_duration_seconds: int | None = None,
        reclaim_limit: int = 100,
    ) -> BacklogRetryCoordinator:
        effective_lease = (
            self.minimum_backlog_lease_seconds
            if lease_duration_seconds is None
            else lease_duration_seconds
        )
        return BacklogRetryCoordinator(
            backlog_store=self.repository,
            processor=self.screening,
            lease_duration_seconds=effective_lease,
            reclaim_limit=reclaim_limit,
            clock=self.clock,
        )

    def _process_or_observe(self, case_id: str) -> M3ProcessCaseOutcome:
        initial = self.evidence.load_case(self.run_id, case_id)
        if initial.case.status in {CaseStatus.EVIDENCE_READY, CaseStatus.SCREENED}:
            pipeline = self.screening.process_case(self.run_id, case_id)
            disposition = (
                M3ProcessDisposition.DEFERRED_TO_BACKLOG
                if pipeline.case.case.status == CaseStatus.BACKLOGGED
                else M3ProcessDisposition.PROCESSED
            )
            return self._case_outcome(
                initial,
                pipeline.case,
                disposition=disposition,
                pipeline_invoked=True,
                pipeline=pipeline,
            )
        disposition = (
            M3ProcessDisposition.SKIPPED_NOT_READY
            if initial.case.status == CaseStatus.CANDIDATE
            else M3ProcessDisposition.OBSERVED_EXISTING
        )
        return self._case_outcome(
            initial,
            initial,
            disposition=disposition,
            pipeline_invoked=False,
            pipeline=None,
        )

    @staticmethod
    def _case_outcome(
        initial: CaseSnapshot,
        current: CaseSnapshot,
        *,
        disposition: M3ProcessDisposition,
        pipeline_invoked: bool,
        pipeline: ScreeningPipelineOutcome | None,
    ) -> M3ProcessCaseOutcome:
        case = current.case
        latest_screening = case.screening_results[-1] if case.screening_results else None
        latest_verdict = case.verdicts[-1] if case.verdicts else None
        latest_review = case.procedural_reviews[-1] if case.procedural_reviews else None
        return M3ProcessCaseOutcome(
            event_id=case.event.event_id,
            case_id=case.case_id,
            initial_status=initial.case.status,
            status=case.status,
            revision=current.revision,
            disposition=disposition,
            pipeline_invoked=pipeline_invoked,
            screening_result_ref=_artifact_ref(
                ArtifactKind.SCREENING_RESULT,
                latest_screening.screening_id if latest_screening is not None else None,
            ),
            verdict_ref=_artifact_ref(
                ArtifactKind.VERDICT,
                latest_verdict.verdict_id if latest_verdict is not None else None,
            ),
            procedural_review_ref=_artifact_ref(
                ArtifactKind.PROCEDURAL_REVIEW,
                latest_review.review_id if latest_review is not None else None,
            ),
            backlog_item_ref=_artifact_ref(ArtifactKind.BACKLOG_ITEM, case.current_backlog_item_id),
            cache_hit_count=pipeline.cache_hit_count if pipeline is not None else 0,
            recovered_response_count=(
                pipeline.recovered_response_count if pipeline is not None else 0
            ),
            repair_attempt_count=int(pipeline.repair_attempted) if pipeline is not None else 0,
        )


class M3OperationsService:
    """Offline fake-provider facade over the provider-neutral screening core."""

    __slots__ = ("_core", "_fixture_bundle")

    def __init__(
        self,
        *,
        core: _ScreeningOperationsCore,
        fixture_bundle: FakeVLMFixtureBundle,
    ) -> None:
        if not isinstance(core, _ScreeningOperationsCore):
            raise TypeError("core must be a _ScreeningOperationsCore")
        if not isinstance(fixture_bundle, FakeVLMFixtureBundle):
            raise TypeError("fixture_bundle must be a FakeVLMFixtureBundle")
        self._core = core
        self._fixture_bundle = fixture_bundle

    def __repr__(self) -> str:
        return (
            "M3OperationsService("
            f"run_id={self._core.run_id!r}, perception_mode='SIMULATED PERCEPTION', "
            "model_mode='FAKE VLM')"
        )

    @property
    def minimum_backlog_lease_seconds(self) -> int:
        return self._core.minimum_backlog_lease_seconds

    def process_run(
        self,
        *,
        case_id: str | None = None,
        max_cases: int = 100,
    ) -> M3ProcessReport:
        selected = self._core.process_selection(case_id=case_id, max_cases=max_cases)
        return M3ProcessReport(
            run_id=self._core.run_id,
            manifest_id=self._core.manifest_id,
            provider_profile=self._core.config.screening.provider_profile,
            perception_mode="SIMULATED PERCEPTION",
            model_mode="FAKE VLM",
            fixture_bundle_id=self._fixture_bundle.fixture_bundle_id,
            fixture_entry_count=self._fixture_bundle.fixture_count,
            requested_case_id=selected.requested_case_id,
            selection_limit=max_cases,
            available_case_count=selected.available_case_count,
            selection_truncated=selected.selection_truncated,
            outcomes=selected.outcomes,
            counts=selected.counts,
        )

    def build_backlog_retry_coordinator(
        self,
        *,
        lease_duration_seconds: int | None = None,
        reclaim_limit: int = 100,
    ) -> BacklogRetryCoordinator:
        return self._core.build_backlog_retry_coordinator(
            lease_duration_seconds=lease_duration_seconds,
            reclaim_limit=reclaim_limit,
        )

    def backlog_retry_run_once(
        self,
        *,
        worker_id: str,
        lease_duration_seconds: int | None = None,
        reclaim_limit: int = 100,
    ) -> BacklogRetryReport:
        return self.build_backlog_retry_coordinator(
            lease_duration_seconds=lease_duration_seconds,
            reclaim_limit=reclaim_limit,
        ).run_once(self._core.run_id, worker_id)


class PilotA3OperationsService:
    """Real-provider pilot facade with a secret-free report boundary."""

    __slots__ = ("_core", "_manifest")

    def __init__(self, *, core: _ScreeningOperationsCore, manifest: RunManifest) -> None:
        if not isinstance(core, _ScreeningOperationsCore):
            raise TypeError("core must be a _ScreeningOperationsCore")
        if not isinstance(manifest, RunManifest):
            raise TypeError("manifest must be a RunManifest")
        self._core = core
        self._manifest = manifest

    def __repr__(self) -> str:
        return (
            "PilotA3OperationsService("
            f"run_id={self._core.run_id!r}, perception_mode='REAL PERCEPTION', "
            "model_mode='OPENAI-COMPATIBLE VLM')"
        )

    @property
    def minimum_backlog_lease_seconds(self) -> int:
        return self._core.minimum_backlog_lease_seconds

    def process_run(
        self,
        *,
        case_id: str | None = None,
        max_cases: int = 10,
    ) -> PilotA3Report:
        selected = self._core.process_selection(case_id=case_id, max_cases=max_cases)
        profile_name = self._core.config.screening.provider_profile
        profile = self._core.config.providers[profile_name]
        model_manifest = self._manifest.models["screening"]
        return PilotA3Report(
            run_id=self._core.run_id,
            manifest_id=self._core.manifest_id,
            provider_profile=profile_name,
            provider=profile.provider,
            model=profile.model,
            revision=profile.revision,
            model_manifest_id=model_manifest.model_manifest_id,
            execution_location=profile.execution_location,
            transport=profile.transport,
            requested_case_id=selected.requested_case_id,
            selection_limit=max_cases,
            available_case_count=selected.available_case_count,
            selection_truncated=selected.selection_truncated,
            outcomes=selected.outcomes,
            counts=selected.counts,
        )

    def build_backlog_retry_coordinator(
        self,
        *,
        lease_duration_seconds: int | None = None,
        reclaim_limit: int = 100,
    ) -> BacklogRetryCoordinator:
        return self._core.build_backlog_retry_coordinator(
            lease_duration_seconds=lease_duration_seconds,
            reclaim_limit=reclaim_limit,
        )

    def backlog_retry_run_once(
        self,
        *,
        worker_id: str,
        lease_duration_seconds: int | None = None,
        reclaim_limit: int = 100,
    ) -> BacklogRetryReport:
        return self.build_backlog_retry_coordinator(
            lease_duration_seconds=lease_duration_seconds,
            reclaim_limit=reclaim_limit,
        ).run_once(self._core.run_id, worker_id)


_VLMClientBuilder = Callable[
    [
        SecureWorkspace,
        SecureModelResponseStore,
        AppendOnlyRenderedPromptRegistry,
        RunManifest,
    ],
    VLMClient,
]


def _controlled_runtime_paths(
    config: AppConfig,
    workspace_root: str | Path,
    database_path: str | Path,
) -> tuple[Path, Path]:
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
    return controlled_workspace_root, controlled_database_path


def _controlled_pilot_runtime_paths(
    config: AppConfig,
    run_id: str,
    workspace_root: str | Path,
    database_path: str | Path,
) -> tuple[Path, Path]:
    supplied_workspace_root = Path(workspace_root)
    supplied_database_path = Path(database_path)
    if ".." in supplied_workspace_root.parts or ".." in supplied_database_path.parts:
        raise ValueError("workspace_root and database_path cannot contain parent traversal")
    controlled_workspace_root = supplied_workspace_root.absolute()
    controlled_database_path = supplied_database_path.absolute()
    expected_database_path = controlled_workspace_root / run_id / config.storage.database_filename
    if controlled_database_path != expected_database_path:
        raise ValueError(
            "database_path must exactly match the configured pilot run file inside workspace_root"
        )
    return controlled_workspace_root, controlled_database_path


@contextmanager
def _open_screening_core(
    *,
    config: AppConfig,
    run_id: str,
    workspace_root: Path,
    database_path: Path,
    client_builder: _VLMClientBuilder,
    clock: Callable[[], datetime],
) -> Iterator[tuple[_ScreeningOperationsCore, RunManifest]]:
    with SecureWorkspace(
        workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        verifier = StoredPngVerifier(
            run_id=run_id,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        evidence = SQLiteEvidenceRepository(
            database_path,
            config.storage.busy_timeout_ms,
            verifier=verifier,
            clock=clock,
        )
        manifest = evidence.load_run_manifest(run_id)
        review_verifier = DeterministicProceduralReviewVerifier(config, evidence)
        response_store = SecureModelResponseStore(workspace)
        repository = SQLiteM3Repository(
            database_path,
            config.storage.busy_timeout_ms,
            clock=clock,
            current_pack_verifier=evidence.verify_current_pack,
            raw_response_verifier=response_store,
            procedural_review_verifier=review_verifier,
            semantic_verifier=review_verifier,
        )
        prompt_catalog = build_screening_prompt_catalog(manifest)
        prompt_registry = AppendOnlyRenderedPromptRegistry()
        client = client_builder(workspace, response_store, prompt_registry, manifest)
        screening = ScreeningCoordinator(
            config=config,
            evidence_repository=evidence,
            screening_repository=repository,
            response_store=response_store,
            vlm_client=client,
            prompt_catalog=prompt_catalog,
            prompt_registrar=prompt_registry,
            procedural_review_verifier=review_verifier,
            semantic_verifier=review_verifier,
        )
        yield (
            _ScreeningOperationsCore(
                config=config,
                run_id=run_id,
                manifest_id=manifest.manifest_id,
                evidence_repository=evidence,
                screening_repository=repository,
                screening_coordinator=screening,
                clock=clock,
            ),
            manifest,
        )


@contextmanager
def open_m3_operations_service(
    *,
    config: AppConfig,
    run_id: str,
    workspace_root: str | Path,
    database_path: str | Path,
    fixture_bundle: FakeVLMFixtureBundle,
    clock: Callable[[], datetime] | None = None,
) -> Iterator[M3OperationsService]:
    """Open the sole supported M3 runtime: precomputed perception plus fake VLM."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    controlled_run_id = require_reference_token(run_id, "M3 operations run reference")
    if not isinstance(fixture_bundle, FakeVLMFixtureBundle):
        raise TypeError("fixture_bundle must be a FakeVLMFixtureBundle")
    controlled_workspace_root, controlled_database_path = _controlled_runtime_paths(
        config,
        workspace_root,
        database_path,
    )
    profile = config.providers[config.screening.provider_profile]
    if (
        config.perception.provider != "precomputed"
        or profile.provider != "fake"
        or profile.transport != ProviderTransport.IN_PROCESS
    ):
        raise M3OperationsBoundaryError(M3OperationsBoundaryCode.DEPLOYMENT_UNSUPPORTED)
    effective_clock = clock or _utc_now
    if not callable(effective_clock):
        raise TypeError("clock must be callable")

    def build_fake_client(
        _workspace: SecureWorkspace,
        response_store: SecureModelResponseStore,
        _prompt_registry: AppendOnlyRenderedPromptRegistry,
        _manifest: RunManifest,
    ) -> VLMClient:
        return DeterministicFakeVLMClient(
            _fixture_mapping(fixture_bundle),
            response_store,
        )

    with _open_screening_core(
        config=config,
        run_id=controlled_run_id,
        workspace_root=controlled_workspace_root,
        database_path=controlled_database_path,
        client_builder=build_fake_client,
        clock=effective_clock,
    ) as (core, _manifest):
        yield M3OperationsService(
            core=core,
            fixture_bundle=fixture_bundle,
        )


@contextmanager
def open_pilot_a3_operations_service(
    *,
    config: AppConfig,
    run_id: str,
    workspace_root: str | Path,
    database_path: str | Path,
    transport: OpenAICompatibleTransport | None = None,
    environment: Mapping[str, str] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> Iterator[PilotA3OperationsService]:
    """Open real pilot screening while resolving secrets only inside the adapter."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    controlled_run_id = require_reference_token(run_id, "pilot A3 operations run reference")
    controlled_workspace_root, controlled_database_path = _controlled_pilot_runtime_paths(
        config,
        controlled_run_id,
        workspace_root,
        database_path,
    )
    profile_name = config.screening.provider_profile
    profile = config.providers[profile_name]
    if (
        config.perception.provider != "local-worker"
        or profile.provider == "fake"
        or profile.execution_location != ExecutionLocation.EXTERNAL
        or profile.transport != ProviderTransport.HTTP
    ):
        raise M3OperationsBoundaryError(M3OperationsBoundaryCode.DEPLOYMENT_UNSUPPORTED)
    if transport is not None and not callable(getattr(transport, "send", None)):
        raise TypeError("transport must implement send")
    active_transport = transport or build_openai_compatible_transport(
        profile,
        environment=environment,
    )
    effective_clock = clock or _utc_now
    if not callable(effective_clock):
        raise TypeError("clock must be callable")

    def build_real_client(
        workspace: SecureWorkspace,
        response_store: SecureModelResponseStore,
        prompt_registry: AppendOnlyRenderedPromptRegistry,
        manifest: RunManifest,
    ) -> VLMClient:
        model_manifest = manifest.models["screening"]
        if (
            model_manifest.provider != profile.provider
            or model_manifest.model != profile.model
            or model_manifest.revision != profile.revision
            or manifest.config_sha256 != config.config_sha256
        ):
            raise M3OperationsBoundaryError(M3OperationsBoundaryCode.DEPLOYMENT_UNSUPPORTED)
        return OpenAICompatibleVLMClient(
            identity=OpenAICompatibleClientIdentity(
                provider_profile=profile_name,
                provider=profile.provider,
                model=profile.model,
                revision=profile.revision,
                model_manifest_id=model_manifest.model_manifest_id,
                execution_location=profile.execution_location,
            ),
            transport=active_transport,
            prompt_resolver=prompt_registry,
            media_reader=workspace,
            response_store=response_store,
        )

    with _open_screening_core(
        config=config,
        run_id=controlled_run_id,
        workspace_root=controlled_workspace_root,
        database_path=controlled_database_path,
        client_builder=build_real_client,
        clock=effective_clock,
    ) as (core, manifest):
        yield PilotA3OperationsService(core=core, manifest=manifest)


__all__ = [
    "M3OperationsBoundaryCode",
    "M3OperationsBoundaryError",
    "M3OperationsService",
    "PilotA3OperationsService",
    "open_m3_operations_service",
    "open_pilot_a3_operations_service",
]
