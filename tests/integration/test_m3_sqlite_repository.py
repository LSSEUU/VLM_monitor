import hashlib
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Never

import pytest

from labcourt.adapters.storage.json_projector import JsonProjector
from labcourt.adapters.storage.readonly_m3_artifacts import (
    M3AuthorityFailureType,
    ReadonlyM3ArtifactRepository,
)
from labcourt.adapters.storage.readonly_sqlite import (
    ReadOnlySnapshotError,
    SnapshotRunCounts,
    readonly_sqlite_snapshot,
    snapshot_run_counts,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m3_repository import (
    SQLiteM3Repository,
    m3_root_document_sha256,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationIntegrityError,
    MigrationRunner,
    RepositoryIntegrityError,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.storage.sqlite_schema import (
    M3_AUTHORITY_HARDENING_OBJECTS,
    M5_AUTHORITY_OBJECTS,
    M6_UPGRADE_LEDGER_OBJECTS,
)
from labcourt.application.artifact_validation import (
    M3ArtifactValidator,
    artifact_budget_preflight_report,
    m3_artifact_budget_preflight_report,
)
from labcourt.application.backlog_retry import BacklogRetryCoordinator
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.config_loader import load_config
from labcourt.contracts.artifact_validation import (
    ArtifactValidationBudget,
    ArtifactValidationCounts,
    ArtifactValidationReport,
    M3ArtifactValidationBudget,
    M3ArtifactValidationCounts,
    M3ArtifactValidationIssueCode,
)
from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogParseFailureEvidence,
    BacklogRetryContext,
    BacklogRetryDisposition,
    BacklogRetryFailure,
    BacklogRetrySuccess,
    BacklogStrictParseFailureProof,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    ClosureDefectCode,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ModelParseStatus,
    PrivacyPolicy,
    PrivacyReasonCode,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    ScreeningDecision,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
    VerdictDecision,
    VerificationStatus,
    ViolationType,
    VlmRole,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m3_models import (
    EvidenceCitation,
    PromptManifest,
    UnknownReferenceAttempt,
    VlmCallBudget,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningModelPayload,
    ScreeningResult,
    StructureRepairRequest,
    VLMCallRequest,
    VLMMediaRef,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import (
    ArtifactRef,
    ArtifactVerification,
    ClosureDefect,
    ClosureReport,
)
from labcourt.contracts.verdicts import ProceduralDefect, ProceduralReview, Verdict
from labcourt.domain.screening_router import (
    FastVerdictBuilder,
    ScreeningRoutePolicy,
    ScreeningRouter,
)
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, ContractViolation
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.model_response_recovery import (
    ModelCallRecoveryScanFailureCode,
    PersistedModelCallStatus,
)
from labcourt.ports.screening_repository import (
    ModelCallClaimStatus,
    ModelCallFailureIntent,
)
from labcourt.ports.vlm import VLMDeliveryCertainty, VLMProviderFailureCode

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
ROOT = Path(__file__).parents[2]
RUN_ID = "run-01"
BUSY_TIMEOUT_MS = 5_000
RECORDED_AT = datetime(2026, 7, 27, 12, 34, 56, 123456, tzinfo=UTC)
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
VALIDATION_RAW_BYTES = b"x" * 128
VALIDATION_RAW_SHA256 = hashlib.sha256(VALIDATION_RAW_BYTES).hexdigest()


class _Verifier:
    def __init__(self, status: VerificationStatus = VerificationStatus.VERIFIED) -> None:
        self._status = status

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        actual_media_sha256 = crop.media_sha256
        if self._status == VerificationStatus.MEDIA_HASH_MISMATCH:
            actual_media_sha256 = "d" * 64
        return ArtifactVerification(
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            status=self._status,
            availability=crop.availability,
            media_type=crop.media_type,
            expected_source_pixel_sha256=crop.source_media_sha256,
            actual_source_pixel_sha256=crop.source_media_sha256,
            expected_output_pixel_sha256=crop.pixel_sha256,
            actual_output_pixel_sha256=crop.pixel_sha256,
            expected_media_sha256=crop.media_sha256,
            actual_media_sha256=actual_media_sha256,
            expected_width=crop.output_width,
            actual_width=crop.output_width,
            expected_height=crop.output_height,
            actual_height=crop.output_height,
            expected_size_bytes=crop.size_bytes,
            actual_size_bytes=crop.size_bytes,
        )

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id, ref
        return False


class _RawVerifier:
    """Explicit contract fake for repository-only tests without workspace bytes."""

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse:
        if (
            request.run_id != run_id
            or response.run_id != run_id
            or request.request_id != response.request_id
            or request.request_sha256 != response.request_sha256
            or request.cache_key != response.cache_key
            or request.case_id != response.case_id
            or request.evidence_pack_id != response.evidence_pack_id
            or request.evidence_pack_version != response.evidence_pack_version
            or request.purpose != response.purpose
            or request.model_manifest_id != response.model_manifest_id
            or request.manifest_id != response.manifest_id
        ):
            raise ContractViolation("raw response fake observed a binding mismatch")
        return response


def _clock() -> datetime:
    return RECORDED_AT


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _event() -> CandidateEvent:
    return CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )


def _frame() -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id="demo-ntsc",
        frame_index=90,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256="a" * 64,
    )


def _detection() -> Detection:
    frame = _frame()
    return Detection(
        detection_id="det-bottle-090",
        frame_id=frame.frame_id,
        label="reagent_bottle",
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        score=0.92,
        track_ref=_event().primary_track_ref,
        model_manifest_id=_manifest().models["detector"].model_manifest_id,
    )


def _draft(*, version: int, complete: bool) -> EvidencePackDraft:
    event = _event()
    frame = _frame()
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id="det-bottle-090",
    )
    source_refs = tuple(sorted((detection_ref, frame_ref), key=lambda ref: ref.sort_key))
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path="frames/focus.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256="a" * 64,
        pixel_sha256="b" * 64,
        media_sha256="c" * 64,
        output_width=100,
        output_height=200,
        size_bytes=512,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
    )
    return EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=version,
        complete=complete,
        event=event,
        key_frame_ids=(frame.frame_id,),
        focus_crops=(crop,),
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            end_frame_exclusive=event.end_frame_exclusive,
            observed_frame_count=event.end_frame_exclusive - event.start_frame,
        ),
        confirmation_record=event.confirmation,
        manifest_id=event.manifest_id,
    )


def _repository(tmp_path: Path) -> tuple[Path, SQLiteEvidenceRepository]:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    repository = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=_clock,
    )
    repository.register_run(RUN_ID, _manifest())
    return database, repository


def _remove_v7_authority_schema(connection: sqlite3.Connection) -> None:
    """Reconstruct a real v6 database without rewriting any application row."""

    # The locked-replay candidate tables are empty additive v16/v17/v18
    # authorities in this fixture and must be removed before reconstructing
    # the v6 schema.  Drop M4 first because its triggers reference M3.
    connection.execute('DROP TABLE "m6_replay_locked_closed_policy_candidate_cases"')
    connection.execute('DROP TABLE "m6_replay_locked_m4_candidate_cases"')
    connection.execute('DROP TABLE "m6_replay_locked_candidate_cases"')

    # The candidate run-cut table depends on the sealed M6 ledger and is empty
    # in this v6 reconstruction fixture, so remove it before the older M6 set.
    connection.execute('DROP TABLE "m6_upgrade_candidate_run_cuts"')

    # M6 depends on M5/base authority, so remove its empty additive objects next.
    for object_type in ("trigger", "index"):
        names = sorted(name for kind, name in M6_UPGRADE_LEDGER_OBJECTS if kind == object_type)
        for name in names:
            connection.execute(f'DROP {object_type.upper()} "{name}"')
    m6_table_drop_order = (
        "m6_upgrade_sample_artifact_links",
        "m6_upgrade_pending_sample_commitments",
        "m6_upgrade_observed_non_model_artifacts",
        "m6_upgrade_observed_model_calls",
        "m6_upgrade_execution_ledger_seals",
        "m6_upgrade_sample_execution_observations",
        "m6_upgrade_sample_executions",
        "m6_upgrade_physical_artifact_refs",
        "m6_upgrade_execution_ledger_protocols",
        "m6_upgrade_execution_scopes",
    )
    assert set(m6_table_drop_order) == {
        name for kind, name in M6_UPGRADE_LEDGER_OBJECTS if kind == "table"
    }
    for name in m6_table_drop_order:
        connection.execute(f'DROP TABLE "{name}"')

    # M5 depends on M4/base authority, so remove its empty additive objects next.
    for object_type in ("trigger", "index", "table"):
        names = sorted(name for kind, name in M5_AUTHORITY_OBJECTS if kind == object_type)
        for name in names:
            connection.execute(f'DROP {object_type.upper()} "{name}"')

    m4_objects = connection.execute(
        """
        SELECT type, name
        FROM sqlite_master
        WHERE name GLOB 'm4_*'
           OR name GLOB 'idx_m4_*'
           OR name GLOB 'uq_m4_*'
        ORDER BY CASE type WHEN 'trigger' THEN 0 WHEN 'index' THEN 1 ELSE 2 END,
                 name
        """
    ).fetchall()
    for object_type, name in m4_objects:
        if object_type in {"trigger", "index", "table"}:
            connection.execute(f'DROP {str(object_type).upper()} "{name!s}"')
    connection.execute("DROP TRIGGER IF EXISTS backlog_item_versions_validate_transition")
    connection.execute("DROP TRIGGER IF EXISTS runs_portable_filesystem_identity_insert")
    connection.execute("DROP INDEX IF EXISTS uq_runs_filesystem_identity_nocase")
    connection.execute("DROP TRIGGER schema_migrations_no_delete")
    connection.execute("DELETE FROM schema_migrations WHERE version BETWEEN 7 AND 18")
    connection.executescript(
        """
        CREATE TRIGGER schema_migrations_no_delete
        BEFORE DELETE ON schema_migrations
        BEGIN
            SELECT RAISE(ABORT, 'schema_migrations is append-only');
        END;
        """
    )


def _v7_authority_objects(connection: sqlite3.Connection) -> set[tuple[str, str]]:
    rows = connection.execute(
        """
        SELECT type, name
        FROM sqlite_master
        WHERE name IN (
            'uq_runs_filesystem_identity_nocase',
            'runs_portable_filesystem_identity_insert',
            'backlog_item_versions_validate_transition'
        )
        """
    ).fetchall()
    return {(str(row[0]), str(row[1])) for row in rows}


def _register_case(repository: SQLiteEvidenceRepository) -> None:
    repository.register_frame(RUN_ID, _frame())
    repository.register_detection(RUN_ID, _detection())
    repository.create_or_get_case(RUN_ID, _event())


def _prompt(role: VlmRole) -> PromptManifest:
    return PromptManifest(
        prompt_id=f"{role.value.lower()}-v1",
        role=role,
        template_sha256=SHA_1,
        output_schema_sha256=SHA_2,
        prompt_bundle_sha256=_manifest().prompt_bundle_sha256,
        renderer_version="jinja-3-1",
    )


def _budget(*, repair: bool = False) -> VlmCallBudget:
    return VlmCallBudget(
        max_images=0 if repair else 4,
        max_input_pixels=0 if repair else 100_000,
        max_output_tokens=1_024,
        pricing_currency="USD",
        input_cost_per_million_tokens=2.0,
        output_cost_per_million_tokens=4.0,
        max_estimated_cost=10.0,
        max_response_bytes=65_536,
        max_json_depth=8,
        max_json_fields=128,
        max_string_chars=8_192,
        timeout_seconds=15.0,
        claim_completion_grace_seconds=5.0,
    )


def _request(
    pack: EvidencePack,
    *,
    backlog_retry_context: BacklogRetryContext | None = None,
) -> VLMRequest:
    crop = pack.focus_crops[0]
    model = _manifest().models["screening"]
    media = VLMMediaRef(
        crop_id=crop.crop_id,
        media_sha256=crop.media_sha256,
        local_path=f"{RUN_ID}/frames/{crop.media_sha256}.png",
        source=crop.source,
        media_access=crop.privacy_receipt.media_access,
        privacy_policy=crop.privacy_receipt.policy,
        privacy_transform_version=crop.privacy_receipt.transform_version,
        width=crop.output_width,
        height=crop.output_height,
    )
    return VLMRequest(
        run_id=RUN_ID,
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        provider_profile="fake-screening",
        provider=model.provider,
        model=model.model,
        revision=model.revision,
        model_manifest_id=model.model_manifest_id,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=_prompt(VlmRole.SCREENING),
        rendered_prompt_sha256=SHA_3,
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        rule_summary="Apply the configured laboratory rule.",
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),),
        objective_summary={"duration_frames": 91},
        temperature=0.0,
        seed=7,
        budget=_budget(),
        backlog_retry_context=backlog_retry_context,
        manifest_id=pack.manifest_id,
    )


def _request_variant(pack: EvidencePack, hex_digit: str) -> VLMRequest:
    payload = _request(pack).model_dump(mode="json")
    for computed_name in (
        "allowed_crop_ids",
        "request_sha256",
        "request_id",
        "cache_key",
    ):
        payload.pop(computed_name)
    payload["rendered_prompt_sha256"] = hex_digit * 64
    return VLMRequest.model_validate(payload)


def _repair_request(
    request: VLMRequest,
    response: VLMResponse,
) -> StructureRepairRequest:
    return StructureRepairRequest(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        provider_profile=request.provider_profile,
        provider=request.provider,
        model=request.model,
        revision=request.revision,
        model_manifest_id=request.model_manifest_id,
        execution_location=request.execution_location,
        prompt_manifest=_prompt(VlmRole.STRUCTURE_REPAIR),
        rendered_prompt_sha256=SHA_4,
        original_request_id=request.request_id,
        original_request_sha256=request.request_sha256,
        original_response_id=response.response_id,
        original_response_sha256=response.content_sha256,
        original_backlog_retry_context_id=(
            request.backlog_retry_context.context_id
            if request.backlog_retry_context is not None
            else None
        ),
        parse_defect_codes=(ProceduralDefectCode.MALFORMED_STRUCTURE,),
        temperature=0.0,
        seed=7,
        budget=_budget(repair=True),
        backlog_retry_context=request.backlog_retry_context,
        manifest_id=request.manifest_id,
    )


def _response(
    request: VLMCallRequest,
    *,
    content_sha256: str,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
) -> VLMResponse:
    response_id = derive_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
    )
    return VLMResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        purpose=request.purpose,
        attempt_index=0 if isinstance(request, VLMRequest) else 1,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=128,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency_ms,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _parsed(
    request: VLMCallRequest,
    response: VLMResponse,
    *,
    violation_type: ViolationType = ViolationType.REAGENT_CONTAINER_OPEN,
    evidence_ref: ArtifactRef | None = None,
    violation_probability: float = 0.95,
) -> ParsedScreeningOutput:
    if evidence_ref is None and isinstance(request, VLMRequest):
        evidence_ref = request.allowed_evidence_refs[0]
    return ParsedScreeningOutput(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        payload=ScreeningModelPayload(
            violation_type=violation_type,
            evidence_class=EvidenceClass.PRESENCE,
            violation_probability=violation_probability,
            prosecution_summary="The structured observations support routing.",
            rationale_summary="Only typed fields are used by deterministic code.",
            evidence_citations=(
                (EvidenceCitation(evidence_ref=evidence_ref),) if evidence_ref is not None else ()
            ),
        ),
        manifest_id=request.manifest_id,
    )


def _parsed_receipt(
    request: VLMCallRequest,
    response: VLMResponse,
    output: ParsedScreeningOutput,
) -> ModelParseReceipt:
    return ModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        attempt_index=response.attempt_index,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_output_id=output.parsed_output_id,
        parsed_output_sha256=output.parsed_output_sha256,
        manifest_id=request.manifest_id,
    )


def _parser_defect(response_id: str) -> ProceduralDefect:
    return ProceduralDefect(
        code=ProceduralDefectCode.MALFORMED_STRUCTURE,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.MALFORMED_JSON,
        artifact_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response_id,
        ),
        field=ProceduralField.JSON_ROOT,
    )


def _screening_for(pack: EvidencePack, output: ParsedScreeningOutput) -> ScreeningResult:
    return ScreeningRouter(
        ScreeningRoutePolicy(
            low_probability=0.15,
            high_probability=0.88,
            strong_signal_threshold=0.5,
            conflict_policy_version="strong-signal-v1",
            router_version="screening-router-v1",
        )
    ).route(
        output,
        pack,
        version=1,
    )


def _verdict_for(
    screening: ScreeningResult,
    pack: EvidencePack,
    response_refs: tuple[ArtifactRef, ...],
) -> Verdict:
    return FastVerdictBuilder().build(
        screening,
        pack,
        version=1,
        model_response_refs=response_refs,
    )


def _review_for(
    verdict: Verdict,
    defects: tuple[ProceduralDefect, ...],
) -> ProceduralReview:
    return ProceduralReview(
        run_id=verdict.run_id,
        case_id=verdict.case_id,
        version=1,
        evidence_pack_id=verdict.evidence_pack_id,
        evidence_pack_version=verdict.evidence_pack_version,
        reviewed_verdict_id=verdict.verdict_id,
        reviewed_verdict_version=verdict.version,
        reviewed_verdict_sha256=verdict.verdict_sha256,
        gate_version="procedural-gate-v1",
        defects=defects,
        manifest_id=verdict.manifest_id,
    )


def _trusted_review(
    evidence: SQLiteEvidenceRepository,
    verdict: Verdict,
    pack: EvidencePack,
    closure: ClosureReport,
    history: tuple[ModelParseReceipt, ...],
) -> ProceduralReview:
    return DeterministicProceduralReviewVerifier(
        load_config(ROOT / "configs" / "demo.yaml"),
        evidence,
    ).rebuild_review(
        verdict=verdict,
        evidence_pack=pack,
        current_closure=closure,
        parse_history=history,
        review_version=1,
    )


def _m3_setup(
    tmp_path: Path,
    *,
    current_pack_verifier: Callable[[str, str], ClosureReport] | None = None,
) -> tuple[
    Path,
    SQLiteEvidenceRepository,
    SQLiteM3Repository,
    EvidencePack,
    ClosureReport,
    CaseSnapshot,
    AuditHead,
]:
    database, evidence = _repository(tmp_path)
    _register_case(evidence)
    published = evidence.publish_pack(
        RUN_ID,
        1,
        _draft(version=1, complete=True),
    )
    closure = evidence.verify_current_pack(RUN_ID, published.pack.pack_id)
    review_verifier = DeterministicProceduralReviewVerifier(
        load_config(ROOT / "configs" / "demo.yaml"),
        evidence,
    )
    m3 = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=(current_pack_verifier or evidence.verify_current_pack),
        raw_response_verifier=_RawVerifier(),
        procedural_review_verifier=review_verifier,
    )
    return (
        database,
        evidence,
        m3,
        published.pack,
        closure,
        published.case,
        evidence.get_audit_head(RUN_ID),
    )


def _persist_direct_parse(
    repository: SQLiteM3Repository,
    pack: EvidencePack,
    *,
    violation_type: ViolationType = ViolationType.REAGENT_CONTAINER_OPEN,
) -> tuple[VLMRequest, VLMResponse, ParsedScreeningOutput, ModelParseReceipt]:
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    output = _parsed(request, response, violation_type=violation_type)
    receipt = _parsed_receipt(request, response, output)
    _complete_call(repository, request, response)
    repository.append_parse_receipt(receipt, output)
    return request, response, output, receipt


def _complete_call(
    repository: SQLiteM3Repository,
    request: VLMCallRequest,
    response: VLMResponse,
    backlog_lease: BacklogLeaseIdentity | None = None,
) -> CachedModelResponse:
    owner_token = f"integration-owner-{request.request_id}"
    claim = repository.claim_model_call(RUN_ID, request, owner_token, backlog_lease)
    assert claim.status.value == "ACQUIRED"
    return repository.complete_model_call(
        RUN_ID,
        request,
        response,
        owner_token,
    )


def _table_counts(database: Path, *tables: str) -> tuple[int, ...]:
    connection = sqlite3.connect(database)
    try:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        )
    finally:
        connection.close()


def _insert_recovery_claim_row(
    database: Path,
    request: VLMCallRequest,
    *,
    request_id: str,
    request_sha256: str,
    cache_key: str,
    request_json: str,
    request_document_sha256: str,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO model_call_claims(
                run_id, request_id, request_sha256, cache_key, case_id,
                evidence_pack_id, evidence_pack_version, purpose,
                model_manifest_id, manifest_id,
                request_json, request_document_sha256,
                status, owner_token_sha256, lease_expires_at,
                takeover_count, created_at, response_id, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      'ACTIVE', ?, ?, 0, ?, NULL, NULL)
            """,
            (
                request.run_id,
                request_id,
                request_sha256,
                cache_key,
                request.case_id,
                request.evidence_pack_id,
                request.evidence_pack_version,
                request.purpose.value,
                request.model_manifest_id,
                request.manifest_id,
                request_json,
                request_document_sha256,
                hashlib.sha256(
                    b"recovery-corrupt-row-owner-with-at-least-thirty-two-bytes"
                ).hexdigest(),
                "2026-07-27T12:35:16.123456Z",
                "2026-07-27T12:34:56.123456Z",
            ),
        )


def _backlog_item(
    pack: EvidencePack,
    *,
    reason: BacklogReasonCode = BacklogReasonCode.PROVIDER_UNAVAILABLE,
    max_attempts: int = 2,
    stage: BacklogStage = BacklogStage.SCREENING,
) -> BacklogItem:
    return BacklogItem(
        run_id=RUN_ID,
        case_id=pack.case_id,
        stage=stage,
        role=(VlmRole.SCREENING if stage == BacklogStage.SCREENING else VlmRole.PROSECUTOR),
        reason_code=reason,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=pack.pack_id,
        ),
        stage_input_sha256=m3_root_document_sha256(pack),
        max_attempts=max_attempts,
        retry_generation=(1 if reason == BacklogReasonCode.MODEL_OUTPUT_INVALID else 0),
        manifest_id=pack.manifest_id,
    )


def _lease_identity(item: BacklogItem) -> BacklogLeaseIdentity:
    assert item.lease_id is not None
    return BacklogLeaseIdentity(
        run_id=item.run_id,
        item_id=item.item_id,
        lease_id=item.lease_id,
        attempt_count=item.attempt_count,
        retry_generation=item.retry_generation,
    )


def test_model_response_reference_query_requires_exact_run_id_and_content_binding(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    counts_before = _table_counts(database, "model_responses", "model_call_claims")

    assert (
        repository.model_response_is_referenced(
            RUN_ID,
            response.response_id,
            response.content_sha256,
        )
        is False
    )
    assert _table_counts(database, "model_responses", "model_call_claims") == counts_before

    _complete_call(repository, request, response)

    assert (
        repository.model_response_is_referenced(
            RUN_ID,
            response.response_id,
            response.content_sha256,
        )
        is True
    )
    assert (
        repository.model_response_is_referenced(
            "run-02",
            response.response_id,
            response.content_sha256,
        )
        is False
    )
    assert repository.model_response_is_referenced(RUN_ID, "b" * 64, "c" * 64) is False
    with pytest.raises(RepositoryIntegrityError, match="durable receipt binding"):
        repository.model_response_is_referenced(
            RUN_ID,
            response.response_id,
            "b" * 64,
        )
    assert _table_counts(database, "model_responses", "model_call_claims") == (1, 1)


def test_model_response_reference_query_rejects_a_corrupt_durable_receipt(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    _complete_call(repository, request, response)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_responses_no_update")
        connection.execute(
            """
            UPDATE model_responses SET content_sha256 = ?
            WHERE run_id = ? AND response_id = ?
            """,
            ("b" * 64, RUN_ID, response.response_id),
        )

    with pytest.raises(
        RepositoryIntegrityError,
        match="index columns differ from its canonical document",
    ):
        repository.model_response_is_referenced(
            RUN_ID,
            response.response_id,
            response.content_sha256,
        )


def test_model_response_reference_query_rejects_dangling_normalized_references(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    _complete_call(repository, request, response)
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TRIGGER model_responses_no_delete")
        connection.execute(
            "DELETE FROM model_responses WHERE run_id = ? AND response_id = ?",
            (RUN_ID, response.response_id),
        )
    assert _table_counts(database, "model_responses", "model_call_claims", "model_cache") == (
        0,
        1,
        1,
    )

    with pytest.raises(RepositoryIntegrityError, match="dangling durable database reference"):
        repository.model_response_is_referenced(
            RUN_ID,
            response.response_id,
            response.content_sha256,
        )


def test_model_response_reference_query_rejects_a_dangling_generic_artifact_ref(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    item = BacklogItem(
        run_id=RUN_ID,
        case_id=pack.case_id,
        stage=BacklogStage.HUMAN_REVIEW,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        ),
        stage_input_sha256=m3_root_document_sha256(response),
        max_attempts=1,
        manifest_id=pack.manifest_id,
    )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO backlog_items(
                run_id, item_id, case_id, stage, role, reason_code,
                stage_input_kind, stage_input_id, stage_input_sha256,
                max_attempts, manifest_id, initial_json, initial_document_sha256
            ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.run_id,
                item.item_id,
                item.case_id,
                item.stage.value,
                item.reason_code.value,
                item.stage_input_ref.kind.value,
                item.stage_input_ref.artifact_id,
                item.stage_input_sha256,
                item.max_attempts,
                item.manifest_id,
                canonical_json(item.model_dump(mode="json")),
                m3_root_document_sha256(item),
            ),
        )

    with pytest.raises(RepositoryIntegrityError, match="dangling durable database reference"):
        repository.model_response_is_referenced(
            RUN_ID,
            response.response_id,
            response.content_sha256,
        )


def test_artifact_recovery_fence_is_read_only_and_excludes_other_m3_writers(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    owner = "fenced-writer-owner-token-with-at-least-thirty-two-bytes"
    contender = SQLiteM3Repository(
        database,
        10,
        clock=_clock,
    )

    with repository.model_response_artifact_recovery_fence(RUN_ID):
        scan = repository.scan_model_call_recovery_candidates(RUN_ID, 10)
        assert scan.complete is True
        assert scan.claims_scanned == 0
        assert (
            repository.model_response_is_referenced(
                RUN_ID,
                "e" * 64,
                "f" * 64,
            )
            is False
        )

        with pytest.raises(ConcurrentModification, match="prohibited"):
            repository.claim_model_call(RUN_ID, request, owner)
        with pytest.raises(ConcurrentModification, match="writer lock"):
            contender.claim_model_call(RUN_ID, request, owner)
        with (
            pytest.raises(ContractViolation, match="cannot nest"),
            repository.model_response_artifact_recovery_fence(RUN_ID),
        ):
            raise AssertionError("nested fence unexpectedly entered")

    with (
        pytest.raises(RuntimeError, match="simulated recovery failure"),
        repository.model_response_artifact_recovery_fence(RUN_ID),
    ):
        raise RuntimeError("simulated recovery failure")
    acquired = contender.claim_model_call(RUN_ID, request, owner)
    assert acquired.request_id == request.request_id


def test_model_call_recovery_scan_reconstructs_empty_active_and_completed_claims(
    tmp_path: Path,
) -> None:
    _, _, repository, pack, _, _, _ = _m3_setup(tmp_path)

    empty = repository.scan_model_call_recovery_candidates(RUN_ID, 10)

    assert empty.complete is True
    assert empty.claims_scanned == 0
    assert empty.candidates == ()
    assert empty.anomalies == ()

    request = _request(pack)
    owner_token = "recovery-active-owner-token-with-at-least-thirty-two-bytes"
    acquired = repository.claim_model_call(RUN_ID, request, owner_token)
    active = repository.scan_model_call_recovery_candidates(RUN_ID, 10)

    assert active.complete is True
    assert active.anomalies == ()
    assert len(active.candidates) == 1
    assert active.candidates[0].request == request
    assert active.candidates[0].status == PersistedModelCallStatus.ACTIVE
    assert active.candidates[0].lease_expires_at == acquired.lease_expires_at
    assert active.candidates[0].takeover_count == 0
    assert active.candidates[0].response_id is None

    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    repository.complete_model_call(RUN_ID, request, response, owner_token)
    completed = repository.scan_model_call_recovery_candidates(RUN_ID, 10)

    assert completed.complete is True
    assert completed.anomalies == ()
    assert len(completed.candidates) == 1
    assert completed.candidates[0].request == request
    assert completed.candidates[0].status == PersistedModelCallStatus.COMPLETED
    assert completed.candidates[0].takeover_count == 0
    assert completed.candidates[0].response_id == response.response_id


def test_model_call_recovery_scan_is_stable_and_honors_its_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "labcourt.adapters.storage.sqlite_m3_repository._MODEL_CALL_RECOVERY_SCAN_PAGE_SIZE",
        1,
    )
    _, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    requests = tuple(_request_variant(pack, digit) for digit in ("5", "6", "7"))
    for index, request in enumerate(requests):
        repository.claim_model_call(
            RUN_ID,
            request,
            f"recovery-scan-owner-{index}-with-at-least-thirty-two-bytes",
        )
    expected_ids = tuple(sorted(request.request_id for request in requests))

    bounded = repository.scan_model_call_recovery_candidates(RUN_ID, 2)
    repeated = repository.scan_model_call_recovery_candidates(RUN_ID, 2)
    complete = repository.scan_model_call_recovery_candidates(RUN_ID, 3)

    assert bounded == repeated
    assert bounded.complete is False
    assert bounded.claims_scanned == 2
    assert tuple(item.request.request_id for item in bounded.candidates) == expected_ids[:2]
    assert bounded.anomalies == ()
    assert complete.complete is True
    assert complete.claims_scanned == 3
    assert tuple(item.request.request_id for item in complete.candidates) == expected_ids


def test_new_model_call_cannot_exceed_the_run_recovery_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "labcourt.adapters.storage.sqlite_m3_repository.MAX_MODEL_CALL_RECOVERY_ITEMS",
        2,
    )
    _, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    requests = tuple(_request_variant(pack, digit) for digit in ("5", "6", "7"))
    for index, request in enumerate(requests[:2]):
        repository.claim_model_call(
            RUN_ID,
            request,
            f"recovery-capacity-owner-{index}-with-at-least-thirty-two-bytes",
        )

    with pytest.raises(BudgetExceeded, match="recovery capacity"):
        repository.claim_model_call(
            RUN_ID,
            requests[2],
            "recovery-capacity-owner-2-with-at-least-thirty-two-bytes",
        )

    assert repository.scan_model_call_recovery_candidates(RUN_ID, 2).complete is True


def test_model_call_recovery_scan_turns_tampered_or_oversized_rows_into_opaque_anomalies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "labcourt.adapters.storage.sqlite_m3_repository._MODEL_CALL_RECOVERY_SCAN_PAGE_SIZE",
        1,
    )
    database, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    indexed_request = _request_variant(pack, "5")
    sensitive_fragment = "C:/private/real-person/frame.png"
    _insert_recovery_claim_row(
        database,
        request,
        request_id="0" * 64,
        request_sha256="1" * 64,
        cache_key="2" * 64,
        request_json=f'{{"local_path":"{sensitive_fragment}"',
        request_document_sha256="3" * 64,
    )
    _insert_recovery_claim_row(
        database,
        request,
        request_id="4" * 64,
        request_sha256="5" * 64,
        cache_key="6" * 64,
        request_json=sensitive_fragment + ("x" * 1_048_576),
        request_document_sha256="7" * 64,
    )
    indexed_json = canonical_json(indexed_request.model_dump(mode="json"))
    _insert_recovery_claim_row(
        database,
        indexed_request,
        request_id="8" * 64,
        request_sha256="9" * 64,
        cache_key="a" * 64,
        request_json=indexed_json,
        request_document_sha256=m3_root_document_sha256(indexed_request),
    )

    scan = repository.scan_model_call_recovery_candidates(RUN_ID, 10)
    repeated = repository.scan_model_call_recovery_candidates(RUN_ID, 10)

    assert scan == repeated
    assert scan.complete is True
    assert scan.claims_scanned == 3
    assert scan.candidates == ()
    assert tuple(anomaly.source_token for anomaly in scan.anomalies) == tuple(
        sorted(anomaly.source_token for anomaly in scan.anomalies)
    )
    assert [anomaly.failure_code for anomaly in scan.anomalies].count(
        ModelCallRecoveryScanFailureCode.CLAIM_AUTHORITY_INVALID
    ) == 2
    assert [anomaly.failure_code for anomaly in scan.anomalies].count(
        ModelCallRecoveryScanFailureCode.DATABASE_OBSERVATION_CONFLICT
    ) == 1
    assert all(len(anomaly.source_token) == 64 for anomaly in scan.anomalies)
    assert sensitive_fragment not in repr(scan)
    assert indexed_json not in repr(scan)


def test_model_call_claim_rejects_requests_too_large_for_bounded_recovery(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    payload = request.model_dump(mode="json")
    for computed_name in (
        "allowed_crop_ids",
        "request_sha256",
        "request_id",
        "cache_key",
    ):
        payload.pop(computed_name)
    tool_result_ids = sorted(
        hashlib.sha256(f"oversized-recovery-ref-{index}".encode()).hexdigest()
        for index in range(12_000)
    )
    payload["allowed_evidence_refs"] = [
        request.allowed_evidence_refs[0].model_dump(mode="json"),
        *(
            {"kind": ArtifactKind.TOOL_RESULT.value, "artifact_id": artifact_id}
            for artifact_id in tool_result_ids
        ),
    ]
    oversized_request = VLMRequest.model_validate(payload)
    request_json = canonical_json(oversized_request.model_dump(mode="json"))
    assert len(request_json.encode("utf-8")) > 1_048_576

    with pytest.raises(ContractViolation, match="recovery byte limit"):
        repository.claim_model_call(
            RUN_ID,
            oversized_request,
            "oversized-recovery-owner-with-at-least-thirty-two-bytes",
        )

    assert _table_counts(database, "model_call_claims") == (0,)


def test_model_call_recovery_completion_never_creates_a_missing_claim(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )

    with pytest.raises(ContractViolation, match="existing durable claim"):
        repository.complete_expired_model_call_from_recovery(
            RUN_ID,
            request,
            response,
            RECORDED_AT,
            0,
        )

    assert _table_counts(database, "model_call_claims") == (0,)
    assert _table_counts(database, "model_responses", "model_cache") == (0, 0)


def test_model_call_recovery_completion_requires_exact_expired_observation(
    tmp_path: Path,
) -> None:
    database, evidence, _, pack, _, _, _ = _m3_setup(tmp_path)
    now = [RECORDED_AT]
    repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=lambda: now[0],
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    request = _request(pack)
    first_owner = "first-recovery-owner-token-with-at-least-thirty-two-bytes"
    acquired = repository.claim_model_call(RUN_ID, request, first_owner)
    assert acquired.lease_expires_at is not None
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )

    with pytest.raises(ConcurrentModification, match="observation changed"):
        repository.complete_expired_model_call_from_recovery(
            RUN_ID,
            request,
            response,
            acquired.lease_expires_at,
            0,
        )
    now[0] = acquired.lease_expires_at + timedelta(microseconds=1)
    for stale_expiry, stale_count in (
        (acquired.lease_expires_at + timedelta(microseconds=1), 0),
        (acquired.lease_expires_at, 1),
    ):
        with pytest.raises(ConcurrentModification, match="observation changed"):
            repository.complete_expired_model_call_from_recovery(
                RUN_ID,
                request,
                response,
                stale_expiry,
                stale_count,
            )

    completed = repository.complete_expired_model_call_from_recovery(
        RUN_ID,
        request,
        response,
        acquired.lease_expires_at,
        0,
    )
    assert completed.response == response

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT owner_token_sha256, lease_expires_at, takeover_count,
                   status, response_id
            FROM model_call_claims
            WHERE run_id = ? AND request_id = ?
            """,
            (RUN_ID, request.request_id),
        ).fetchone()
    assert row == (
        hashlib.sha256(first_owner.encode()).hexdigest(),
        "2026-07-27T12:35:16.123456Z",
        0,
        "COMPLETED",
        response.response_id,
    )
    assert _table_counts(database, "model_responses", "model_cache") == (1, 1)


def test_model_call_recovery_completion_observes_same_completed_race(
    tmp_path: Path,
) -> None:
    _, _, repository, pack, _, _, _ = _m3_setup(tmp_path)
    request = _request(pack)
    owner_token = "completed-recovery-owner-token-with-at-least-thirty-two-bytes"
    acquired = repository.claim_model_call(RUN_ID, request, owner_token)
    assert acquired.lease_expires_at is not None
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    repository.complete_model_call(RUN_ID, request, response, owner_token)

    observed = repository.complete_expired_model_call_from_recovery(
        RUN_ID,
        request,
        response,
        acquired.lease_expires_at,
        0,
    )

    assert observed.response == response
    different = _response(
        request,
        content_sha256="b" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    with pytest.raises(RepositoryIntegrityError, match="another recovery response"):
        repository.complete_expired_model_call_from_recovery(
            RUN_ID,
            request,
            different,
            acquired.lease_expires_at,
            0,
        )


def test_concurrent_model_call_recovery_completions_converge_same_response(
    tmp_path: Path,
) -> None:
    database, evidence, _, pack, _, _, _ = _m3_setup(tmp_path)
    now = [RECORDED_AT]

    def new_repository() -> SQLiteM3Repository:
        return SQLiteM3Repository(
            database,
            BUSY_TIMEOUT_MS,
            clock=lambda: now[0],
            current_pack_verifier=evidence.verify_current_pack,
            raw_response_verifier=_RawVerifier(),
        )

    first_repository = new_repository()
    second_repository = new_repository()
    request = _request(pack)
    initial = first_repository.claim_model_call(
        RUN_ID,
        request,
        "initial-recovery-owner-token-with-at-least-thirty-two-bytes",
    )
    observed_expiry = initial.lease_expires_at
    assert observed_expiry is not None
    now[0] = observed_expiry + timedelta(microseconds=1)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    barrier = Barrier(2)

    def attempt(repository: SQLiteM3Repository) -> CachedModelResponse:
        barrier.wait()
        return repository.complete_expired_model_call_from_recovery(
            RUN_ID,
            request,
            response,
            observed_expiry,
            0,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(attempt, first_repository),
            executor.submit(attempt, second_repository),
        )
        completed = tuple(future.result(timeout=10) for future in futures)

    assert all(item.response == response for item in completed)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT owner_token_sha256, takeover_count, status, response_id
            FROM model_call_claims
            WHERE run_id = ? AND request_id = ?
            """,
            (RUN_ID, request.request_id),
        ).fetchone()
    assert row is not None
    assert row == (
        hashlib.sha256(b"initial-recovery-owner-token-with-at-least-thirty-two-bytes").hexdigest(),
        0,
        "COMPLETED",
        response.response_id,
    )
    assert _table_counts(database, "model_responses", "model_cache") == (1, 1)


def test_model_call_claim_expiry_requires_verified_maintenance_completion(
    tmp_path: Path,
) -> None:
    database, evidence, _, pack, _, _, _ = _m3_setup(tmp_path)
    now = [RECORDED_AT]
    repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=lambda: now[0],
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    request = _request(pack)
    first_owner = "first-owner-token-with-at-least-thirty-two-bytes"
    second_owner = "second-owner-token-with-at-least-thirty-two-bytes"

    acquired = repository.claim_model_call(RUN_ID, request, first_owner)

    assert acquired.status.value == "ACQUIRED"
    assert acquired.lease_expires_at == RECORDED_AT + timedelta(
        seconds=request.budget.claim_lease_seconds
    )
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM model_call_claims WHERE run_id = ? AND request_id = ?",
            (RUN_ID, request.request_id),
        ).fetchone()
        assert row is not None
        assert row["request_json"] == canonical_json(request.model_dump(mode="json"))
        assert row["request_document_sha256"] == m3_root_document_sha256(request)
        assert row["owner_token_sha256"] == hashlib.sha256(first_owner.encode()).hexdigest()
        assert row["owner_token_sha256"] != first_owner
        assert row["lease_expires_at"] == "2026-07-27T12:35:16.123456Z"
        with pytest.raises(sqlite3.IntegrityError, match="controlled transition"):
            connection.execute(
                """
                UPDATE model_call_claims SET request_json = '{}'
                WHERE run_id = ? AND request_id = ?
                """,
                (RUN_ID, request.request_id),
            )

    waiting = repository.claim_model_call(RUN_ID, request, second_owner)
    assert waiting.status.value == "WAITING"
    assert waiting.lease_expires_at == acquired.lease_expires_at

    now[0] += timedelta(seconds=request.budget.timeout_seconds)
    still_waiting = repository.claim_model_call(RUN_ID, request, second_owner)
    assert still_waiting.status.value == "WAITING"
    now[0] += timedelta(seconds=request.budget.claim_completion_grace_seconds)
    expired = repository.claim_model_call(RUN_ID, request, second_owner)
    assert expired.status.value == "EXPIRED_REQUIRES_RECOVERY"
    assert expired.lease_expires_at == acquired.lease_expires_at
    assert expired.takeover_count == 0
    with sqlite3.connect(database) as connection:
        unchanged = connection.execute(
            """
            SELECT owner_token_sha256, lease_expires_at, takeover_count
            FROM model_call_claims WHERE run_id = ? AND request_id = ?
            """,
            (RUN_ID, request.request_id),
        ).fetchone()
    assert unchanged == (
        hashlib.sha256(first_owner.encode()).hexdigest(),
        "2026-07-27T12:35:16.123456Z",
        0,
    )

    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    completed = repository.complete_expired_model_call_from_recovery(
        RUN_ID,
        request,
        response,
        acquired.lease_expires_at,
        0,
    )
    assert completed.response == response
    observed = repository.claim_model_call(
        RUN_ID, request, "third-owner-token-with-at-least-thirty-two-bytes"
    )
    assert observed.status.value == "COMPLETED"
    assert observed.response_id == response.response_id

    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT owner_token_sha256, takeover_count, status, response_id
            FROM model_call_claims WHERE run_id = ? AND request_id = ?
            """,
            (RUN_ID, request.request_id),
        ).fetchone()
    assert row == (
        hashlib.sha256(first_owner.encode()).hexdigest(),
        0,
        "COMPLETED",
        response.response_id,
    )


def test_known_failure_retry_requires_the_new_exact_backlog_lease(
    tmp_path: Path,
) -> None:
    database, evidence, _, pack, closure, snapshot, head = _m3_setup(tmp_path)
    now = [RECORDED_AT]
    repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=lambda: now[0],
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    request = _request(pack)
    first_owner = "known-failure-owner-token-with-at-least-thirty-two-bytes"
    claim = repository.claim_model_call(RUN_ID, request, first_owner)
    assert claim.lease_expires_at is not None
    item = _backlog_item(pack)
    intent = ModelCallFailureIntent(
        request=request,
        owner_token=first_owner,
        claim_lease_expires_at=claim.lease_expires_at,
        claim_takeover_count=claim.takeover_count,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    committed = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
        model_call_failure=intent,
    )
    lease_a = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "6" * 64,
        now[0] + timedelta(minutes=1),
    )
    assert lease_a is not None
    lease_a_identity = _lease_identity(lease_a)
    now[0] += timedelta(minutes=2)
    reclaimed = repository.reclaim_expired(RUN_ID, now[0], 1)
    assert len(reclaimed) == 1 and reclaimed[0].status == BacklogStatus.PENDING
    lease_b = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "7" * 64,
        now[0] + timedelta(minutes=5),
    )
    assert lease_b is not None
    lease_b_identity = _lease_identity(lease_b)
    retry_request = _request(
        pack,
        backlog_retry_context=BacklogRetryContext(
            backlog_item_id=item.item_id,
            retry_generation=0,
        ),
    )
    assert retry_request.request_id == request.request_id
    assert retry_request.cache_key == request.cache_key

    with pytest.raises(ConcurrentModification, match="four-part lease identity"):
        repository.claim_model_call(
            RUN_ID,
            retry_request,
            "stale-worker-owner-token-with-at-least-thirty-two-bytes",
            lease_a_identity,
        )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT owner_token_sha256, takeover_count FROM model_call_claims"
        ).fetchone() == (hashlib.sha256(first_owner.encode()).hexdigest(), 0)

    second_owner = "fresh-worker-owner-token-with-at-least-thirty-two-bytes"
    acquired = repository.claim_model_call(
        RUN_ID,
        retry_request,
        second_owner,
        lease_b_identity,
    )
    assert acquired.status == ModelCallClaimStatus.ACQUIRED
    assert acquired.takeover_count == 1
    response = _response(
        retry_request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    with pytest.raises(ConcurrentModification, match="owner no longer holds claim"):
        repository.complete_model_call(RUN_ID, retry_request, response, first_owner)
    repository.complete_model_call(RUN_ID, retry_request, response, second_owner)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM model_call_failure_authorities"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT status, takeover_count FROM model_call_claims"
        ).fetchone() == ("COMPLETED", 1)
    assert committed.case.case.status == CaseStatus.BACKLOGGED


def test_failure_intent_without_atomic_backlog_closure_grants_no_retry(
    tmp_path: Path,
) -> None:
    database, evidence, _, pack, closure, snapshot, head = _m3_setup(tmp_path)
    now = [RECORDED_AT]
    repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=lambda: now[0],
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    request = _request(pack)
    owner = "pre-aggregate-crash-owner-token-with-at-least-thirty-two-bytes"
    claim = repository.claim_model_call(RUN_ID, request, owner)
    assert claim.lease_expires_at is not None
    intent = ModelCallFailureIntent(
        request=request,
        owner_token=owner,
        claim_lease_expires_at=claim.lease_expires_at,
        claim_takeover_count=claim.takeover_count,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    with pytest.raises(ConcurrentModification):
        repository.commit_backlog(
            RUN_ID,
            snapshot.revision + 1,
            head,
            closure,
            _backlog_item(pack),
            model_call_failure=intent,
        )
    assert _table_counts(
        database,
        "model_call_failure_authorities",
        "backlog_items",
    ) == (0, 0)
    now[0] = claim.lease_expires_at + timedelta(microseconds=1)
    expired = repository.claim_model_call(
        RUN_ID,
        request,
        "post-crash-owner-token-with-at-least-thirty-two-bytes",
    )
    assert expired.status == ModelCallClaimStatus.EXPIRED_REQUIRES_RECOVERY
    assert expired.takeover_count == 0


def test_stale_authorized_worker_may_converge_response_but_not_case_or_usage(
    tmp_path: Path,
) -> None:
    database, evidence, _, pack, closure, snapshot, head = _m3_setup(tmp_path)
    now = [RECORDED_AT]
    repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=lambda: now[0],
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    request = _request(pack)
    failed_owner = "failed-call-owner-token-with-at-least-thirty-two-bytes"
    failed_claim = repository.claim_model_call(RUN_ID, request, failed_owner)
    assert failed_claim.lease_expires_at is not None
    item = _backlog_item(pack)
    repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
        model_call_failure=ModelCallFailureIntent(
            request=request,
            owner_token=failed_owner,
            claim_lease_expires_at=failed_claim.lease_expires_at,
            claim_takeover_count=0,
            failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
            delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
            backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        ),
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "6" * 64,
        now[0] + timedelta(minutes=1),
    )
    assert leased is not None
    now[0] += timedelta(seconds=1)
    retry_request = _request(
        pack,
        backlog_retry_context=BacklogRetryContext(
            backlog_item_id=item.item_id,
            retry_generation=0,
        ),
    )
    stale_owner = "stale-authorized-owner-token-with-at-least-thirty-two-bytes"
    acquired = repository.claim_model_call(
        RUN_ID,
        retry_request,
        stale_owner,
        _lease_identity(leased),
    )
    assert acquired.status == ModelCallClaimStatus.ACQUIRED
    response = _response(
        retry_request,
        content_sha256="b" * 64,
        input_tokens=13,
        output_tokens=5,
        latency_ms=17,
    )

    now[0] += timedelta(minutes=2)
    assert repository.reclaim_expired(RUN_ID, now[0], 1)[0].status == BacklogStatus.PENDING
    case_after_reclaim = evidence.load_case(RUN_ID, pack.case_id)
    assert case_after_reclaim.case.usage.input_tokens == 0
    repository.complete_model_call(RUN_ID, retry_request, response, stale_owner)

    assert evidence.load_case(RUN_ID, pack.case_id) == case_after_reclaim
    assert _table_counts(
        database,
        "model_responses",
        "model_cache",
        "model_call_usage_accounting",
    ) == (1, 1, 0)
    fresh_lease = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "7" * 64,
        now[0] + timedelta(minutes=5),
    )
    assert fresh_lease is not None
    observed = repository.claim_model_call(
        RUN_ID,
        retry_request,
        "fresh-cache-reader-owner-token-with-at-least-thirty-two-bytes",
        _lease_identity(fresh_lease),
    )
    assert observed.status == ModelCallClaimStatus.COMPLETED
    assert observed.response_id == response.response_id
    assert repository.get(RUN_ID, retry_request) is not None


def test_model_call_completion_without_raw_verifier_fails_closed(
    tmp_path: Path,
) -> None:
    database, evidence, _, pack, _, _, _ = _m3_setup(tmp_path)
    repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=evidence.verify_current_pack,
    )
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
    )
    owner_token = "unverified-raw-owner-token-with-thirty-two-bytes"
    repository.claim_model_call(RUN_ID, request, owner_token)

    with pytest.raises(ContractViolation, match="raw_response_verifier"):
        repository.complete_model_call(RUN_ID, request, response, owner_token)

    assert _table_counts(database, "model_responses", "model_cache") == (0, 0)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT status, response_id, completed_at
            FROM model_call_claims WHERE run_id = ? AND request_id = ?
            """,
            (RUN_ID, request.request_id),
        ).fetchone() == ("ACTIVE", None, None)


def test_raw_cache_parse_and_screening_commit_are_recoverable_and_idempotent(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    request = _request(pack)
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )

    with pytest.raises(ContractViolation, match="complete_model_call"):
        repository.append_raw_response(response)
    with pytest.raises(ContractViolation, match="completed atomic model call"):
        repository.put(RUN_ID, request, response)
    assert _table_counts(database, "model_responses", "model_cache") == (0, 0)
    cached = _complete_call(repository, request, response)
    assert repository.load_raw_response_for_request(RUN_ID, request.request_id) == response
    assert repository.load_case(RUN_ID, pack.case_id) == snapshot
    assert evidence.get_audit_head(RUN_ID) == head

    assert repository.put(RUN_ID, request, response) == cached
    assert repository.get(RUN_ID, request) == cached
    assert (
        repository.complete_model_call(
            RUN_ID,
            request,
            response,
            f"integration-owner-{request.request_id}",
        )
        == cached
    )

    output = _parsed(request, response)
    receipt = _parsed_receipt(request, response, output)
    assert repository.append_parse_receipt(receipt, output) == receipt
    assert repository.load_parse_receipt_for_output(RUN_ID, output.parsed_output_id) == receipt
    assert repository.load_parse_history_for_output(RUN_ID, output.parsed_output_id) == (receipt,)
    screening = _screening_for(pack, output)
    committed = repository.commit_screening(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    )

    assert committed.created
    assert committed.case.case.status == CaseStatus.SCREENED
    assert committed.case.case.usage.input_images == 1
    assert committed.case.case.usage.input_pixels == 20_000
    assert committed.case.case.usage.input_tokens == 11
    assert committed.case.case.usage.output_tokens == 7
    assert committed.case.case.usage.provider_latency_ms == 19
    assert committed.case.case.usage.retries == 0
    assert committed.case.case.usage.estimated_cost == pytest.approx(0.00005)
    assert repository.load_screening(RUN_ID, screening.screening_id) == screening
    assert evidence.load_case(RUN_ID, pack.case_id) == committed.case

    replay = repository.commit_screening(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    )
    assert replay.created is False
    assert replay.case == committed.case
    assert _table_counts(
        database,
        "model_responses",
        "model_cache",
        "parsed_screening_outputs",
        "model_parse_receipts",
        "screening_results",
    ) == (1, 1, 1, 1, 1)

    connection = sqlite3.connect(database)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM model_responses WHERE run_id = ?",
                (RUN_ID,),
            )
    finally:
        connection.close()


@pytest.mark.parametrize(
    "forged_fields",
    [
        {"authoritative_l1_score": 0.0},
        {"strong_signal_threshold": 0.8},
        {"low_probability": 0.1},
        {"router_version": "forged-router-v1"},
        {"conflict_policy_version": "forged-conflict-v1"},
    ],
)
def test_commit_screening_rejects_forged_derived_authority_without_writes(
    tmp_path: Path,
    forged_fields: dict[str, object],
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    _, _, output, _ = _persist_direct_parse(repository, pack)
    authoritative = _screening_for(pack, output)
    forged = authoritative.model_copy(update=forged_fields)
    before = _table_counts(
        database,
        "screening_results",
        "case_versions",
        "audit_entries",
    )

    with pytest.raises(ContractViolation, match="trusted reconstruction"):
        repository.commit_screening(
            RUN_ID,
            snapshot.revision,
            head,
            closure,
            forged,
        )

    assert (
        _table_counts(
            database,
            "screening_results",
            "case_versions",
            "audit_entries",
        )
        == before
    )
    assert evidence.load_case(RUN_ID, pack.case_id) == snapshot


def test_new_screening_commit_fails_closed_without_semantic_verifier(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    _, _, output, _ = _persist_direct_parse(repository, pack)
    screening = _screening_for(pack, output)
    unverified = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    before = _table_counts(database, "screening_results", "case_versions", "audit_entries")

    with pytest.raises(ContractViolation, match="semantic_verifier"):
        unverified.commit_screening(
            RUN_ID,
            snapshot.revision,
            head,
            closure,
            screening,
        )

    assert (
        _table_counts(
            database,
            "screening_results",
            "case_versions",
            "audit_entries",
        )
        == before
    )


def test_repair_history_round_trips_and_usage_counts_two_provider_calls(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    request = _request(pack)
    first_response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=13,
        output_tokens=3,
        latency_ms=17,
    )
    repair = _repair_request(request, first_response)
    unknown_first = UnknownReferenceAttempt(
        namespace=UnknownReferenceNamespace.EVIDENCE,
        source=UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID,
        value_sha256="5" * 64,
    )
    first_receipt = ModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=first_response.response_id,
        response_content_sha256=first_response.content_sha256,
        attempt_index=0,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.REPAIR_REQUIRED,
        defects=(_parser_defect(first_response.response_id),),
        unknown_reference_attempts=(unknown_first,),
        repair_request_id=repair.request_id,
        manifest_id=request.manifest_id,
    )
    _complete_call(repository, request, first_response)
    repository.append_parse_receipt(first_receipt)

    final_response = _response(
        repair,
        content_sha256="b" * 64,
        input_tokens=5,
        output_tokens=9,
        latency_ms=23,
    )
    output = _parsed(
        repair,
        final_response,
        evidence_ref=request.allowed_evidence_refs[0],
    )
    final_receipt = _parsed_receipt(repair, final_response, output)
    _complete_call(repository, repair, final_response)
    repository.append_parse_receipt(final_receipt, output)

    assert repository.load_parse_history_for_output(RUN_ID, output.parsed_output_id) == (
        first_receipt,
        final_receipt,
    )
    screening = _screening_for(pack, output)
    committed = repository.commit_screening(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    )
    usage = committed.case.case.usage
    assert (
        usage.input_images,
        usage.input_pixels,
        usage.input_tokens,
        usage.output_tokens,
        usage.provider_latency_ms,
        usage.retries,
    ) == (1, 20_000, 18, 12, 40, 1)
    assert usage.estimated_cost == pytest.approx(0.000084)

    incomplete_trace = _verdict_for(
        screening,
        pack,
        (
            ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=final_response.response_id,
            ),
        ),
    )
    before = _table_counts(database, "verdicts", "procedural_reviews", "case_versions")
    with pytest.raises(ContractViolation, match="exactly match the parse history"):
        repository.commit_verdict_review(
            RUN_ID,
            committed.case.revision,
            evidence.get_audit_head(RUN_ID),
            evidence.verify_current_pack(RUN_ID, pack.pack_id),
            incomplete_trace,
            _review_for(incomplete_trace, ()),
        )
    assert (
        _table_counts(
            database,
            "verdicts",
            "procedural_reviews",
            "case_versions",
        )
        == before
    )


def test_commit_rejects_incomplete_or_changed_physical_closure_and_rolls_back(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    _, _, output, _ = _persist_direct_parse(repository, pack)
    screening = _screening_for(pack, output)
    root_only = ClosureReport(
        run_id=closure.run_id,
        root_ref=closure.root_ref,
        manifest_id=closure.manifest_id,
        input_sha256=closure.input_sha256,
        checked_refs=(closure.root_ref,),
    )
    before = _table_counts(database, "screening_results", "case_versions", "audit_entries")
    with pytest.raises(ContractViolation, match="not bound"):
        repository.commit_screening(
            RUN_ID,
            snapshot.revision,
            head,
            root_only,
            screening,
        )
    assert (
        _table_counts(
            database,
            "screening_results",
            "case_versions",
            "audit_entries",
        )
        == before
    )

    incomplete_verifier_repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=lambda _run_id, _pack_id: root_only,
        raw_response_verifier=_RawVerifier(),
    )
    with pytest.raises(ConcurrentModification, match="closure binding changed"):
        incomplete_verifier_repository.commit_screening(
            RUN_ID,
            snapshot.revision,
            head,
            closure,
            screening,
        )
    assert (
        _table_counts(
            database,
            "screening_results",
            "case_versions",
            "audit_entries",
        )
        == before
    )

    failed = closure.model_copy(
        update={
            "defects": (
                ClosureDefect(
                    code=ClosureDefectCode.MEDIA_MISSING,
                    artifact_ref=ArtifactRef(
                        kind=ArtifactKind.CROP,
                        artifact_id=pack.focus_crops[0].crop_id,
                    ),
                    reason_code="TEST_PHYSICAL_CHANGE",
                ),
            )
        }
    )
    changed_verifier_repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=lambda _run_id, _pack_id: failed,
        raw_response_verifier=_RawVerifier(),
    )
    with pytest.raises(ConcurrentModification, match="failed physical closure"):
        changed_verifier_repository.commit_screening(
            RUN_ID,
            snapshot.revision,
            head,
            closure,
            screening,
        )
    assert (
        _table_counts(
            database,
            "screening_results",
            "case_versions",
            "audit_entries",
        )
        == before
    )


def test_backlog_lease_filters_stage_atomically_without_leasing_future_work(
    tmp_path: Path,
) -> None:
    _, _, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    hearing = _backlog_item(pack, stage=BacklogStage.HEARING)
    repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        hearing,
    )

    assert (
        repository.lease_next(
            RUN_ID,
            BacklogStage.SCREENING,
            "9" * 64,
            RECORDED_AT + timedelta(minutes=5),
        )
        is None
    )
    assert repository.load_backlog_item(RUN_ID, hearing.item_id) == hearing

    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.HEARING,
        "8" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert leased is not None
    assert leased.stage == BacklogStage.HEARING
    assert leased.item_id == hearing.item_id
    assert (
        repository.reclaim_expired(
            RUN_ID,
            RECORDED_AT + timedelta(minutes=6),
            1,
        )
        == ()
    )
    assert repository.load_backlog_item(RUN_ID, hearing.item_id) == leased

    with pytest.raises(TypeError, match="BacklogStage"):
        repository.lease_next(
            RUN_ID,
            "SCREENING",  # type: ignore[arg-type]
            "7" * 64,
            RECORDED_AT + timedelta(minutes=5),
        )


def test_atomic_backlog_failure_is_idempotent_and_keeps_retry_identity(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack)
    enqueued = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "9" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert leased is not None
    failure = BacklogRetryFailure(
        lease=_lease_identity(leased),
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=BacklogStatus.PENDING,
        manifest_id=pack.manifest_id,
    )
    retry_head = evidence.get_audit_head(RUN_ID)
    committed = repository.commit_backlog_retry_failure(
        RUN_ID,
        enqueued.case.revision,
        retry_head,
        closure,
        failure,
    )

    assert committed.created is True
    assert committed.item.status == BacklogStatus.PENDING
    assert committed.item.attempt_count == 1
    assert committed.item.retry_generation == 0
    assert committed.case.case.status == CaseStatus.BACKLOGGED
    assert committed.case.case.current_backlog_item_id == item.item_id
    assert committed.receipt.completion_case_revision == enqueued.case.revision + 1
    assert _table_counts(database, "backlog_completion_receipts") == (1,)

    replay = repository.commit_backlog_retry_failure(
        RUN_ID,
        enqueued.case.revision,
        retry_head,
        closure,
        failure,
    )
    assert replay.created is False
    assert replay.receipt == committed.receipt
    assert replay.item == committed.item
    assert replay.case == committed.case
    conflicting = BacklogRetryFailure(
        lease=failure.lease,
        reason_code=BacklogReasonCode.BUDGET_EXCEEDED,
        next_status=BacklogStatus.PENDING,
        manifest_id=pack.manifest_id,
    )
    with pytest.raises(ConcurrentModification, match="different outcome"):
        repository.commit_backlog_retry_failure(
            RUN_ID,
            enqueued.case.revision,
            retry_head,
            closure,
            conflicting,
        )
    next_lease = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "a" * 64,
        RECORDED_AT + timedelta(minutes=6),
    )
    assert next_lease is not None and next_lease.attempt_count == 2
    historical_replay = repository.commit_backlog_retry_failure(
        RUN_ID,
        enqueued.case.revision,
        retry_head,
        closure,
        failure,
    )
    assert historical_replay.created is False
    assert historical_replay.item == committed.item
    assert repository.load_backlog_item(RUN_ID, item.item_id) == next_lease
    assert _table_counts(
        database,
        "backlog_completion_receipts",
        "case_versions",
        "audit_entries",
    ) == (1, committed.case.revision, evidence.get_audit_head(RUN_ID).sequence + 1)
    with pytest.raises(ContractViolation, match="atomic retry outcome"):
        repository.complete(RUN_ID, item.item_id, leased.lease_id or "")
    with pytest.raises(ContractViolation, match="commit_backlog_retry_failure"):
        repository.release(RUN_ID, item.item_id, leased.lease_id or "")


def test_expired_final_lease_atomically_exhausts_with_recovery_receipt(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack, max_attempts=1)
    enqueued = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    first_lease = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "5" * 64,
        RECORDED_AT + timedelta(minutes=1),
    )
    assert first_lease is not None and first_lease.attempt_count == 1
    before_head = evidence.get_audit_head(RUN_ID)
    reclaimed = repository.reclaim_expired(
        RUN_ID,
        RECORDED_AT + timedelta(minutes=2),
        1,
    )
    assert len(reclaimed) == 1
    assert reclaimed[0].status == BacklogStatus.EXHAUSTED
    assert reclaimed[0].attempt_count == 1
    assert reclaimed[0].retry_generation == first_lease.retry_generation
    assert repository.load_backlog_item(RUN_ID, item.item_id) == reclaimed[0]
    exhausted_case = evidence.load_case(RUN_ID, pack.case_id)
    assert exhausted_case.revision == enqueued.case.revision + 1
    assert exhausted_case.case.status == CaseStatus.HUMAN_REVIEW
    assert exhausted_case.case.current_backlog_item_id is None
    assert evidence.get_audit_head(RUN_ID).sequence == before_head.sequence + 1
    assert (
        repository.lease_next(
            RUN_ID,
            BacklogStage.SCREENING,
            "4" * 64,
            RECORDED_AT + timedelta(minutes=5),
        )
        is None
    )
    assert _table_counts(database, "backlog_completion_receipts") == (1,)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT receipt_json FROM backlog_completion_receipts WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
    assert row is not None
    receipt = BacklogCompletionReceipt.model_validate_json(row[0])
    assert isinstance(receipt.outcome, BacklogRetryFailure)
    assert receipt.outcome.reason_code == BacklogReasonCode.WORKER_LEASE_EXPIRED
    assert receipt.outcome.response_refs == ()
    assert receipt.outcome.strict_parse_failure is None
    assert receipt.backlog_status == BacklogStatus.EXHAUSTED
    assert receipt.completion_case_status == CaseStatus.HUMAN_REVIEW

    validation_root = tmp_path / "lease-expiry-validation"
    validation_root.mkdir()
    with readonly_sqlite_snapshot(database) as snapshot_path:
        counts = snapshot_run_counts(snapshot_path, RUN_ID)
        authority = ReadonlyM3ArtifactRepository(snapshot_path)
        with SecureWorkspace(validation_root, max_file_bytes=4096) as workspace:
            report = M3ArtifactValidator(
                authority=authority,
                artifact_reader=workspace,
                authority_counts=_m3_validation_counts(counts),
            ).validate(RUN_ID, ArtifactValidationReport(run_id=RUN_ID))
    assert report.passed is True
    assert report.issues == ()

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER backlog_completion_receipts_no_delete")
        connection.execute("DELETE FROM backlog_completion_receipts")
    with readonly_sqlite_snapshot(database) as snapshot_path:
        corrupt_authority = ReadonlyM3ArtifactRepository(snapshot_path).scan(RUN_ID)
    assert any(
        failure.reason_code == "BACKLOG_LEASE_EXIT_RECEIPT_MISSING"
        for failure in corrupt_authority.failures
    )


def test_expired_lease_preserves_attempt_and_stale_worker_cannot_commit(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack, max_attempts=2)
    enqueued = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "2" * 64,
        RECORDED_AT,
    )
    assert leased is not None and leased.attempt_count == 1
    failure = BacklogRetryFailure(
        lease=_lease_identity(leased),
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=BacklogStatus.PENDING,
        manifest_id=pack.manifest_id,
    )
    reserved_recovery = BacklogRetryFailure(
        lease=_lease_identity(leased),
        reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED,
        next_status=BacklogStatus.PENDING,
        manifest_id=pack.manifest_id,
    )
    retry_head = evidence.get_audit_head(RUN_ID)
    before = _table_counts(
        database,
        "backlog_item_versions",
        "backlog_completion_receipts",
        "case_versions",
        "audit_entries",
    )
    with pytest.raises(ContractViolation, match="reserved for atomic reclaim"):
        repository.commit_backlog_retry_failure(
            RUN_ID,
            enqueued.case.revision,
            retry_head,
            closure,
            reserved_recovery,
        )
    assert (
        _table_counts(
            database,
            "backlog_item_versions",
            "backlog_completion_receipts",
            "case_versions",
            "audit_entries",
        )
        == before
    )
    reclaimed = repository.reclaim_expired(
        RUN_ID,
        RECORDED_AT + timedelta(minutes=1),
        1,
    )
    assert len(reclaimed) == 1
    assert reclaimed[0].status == BacklogStatus.PENDING
    assert reclaimed[0].attempt_count == 1
    assert reclaimed[0].retry_generation == leased.retry_generation
    after_reclaim = _table_counts(
        database,
        "backlog_item_versions",
        "backlog_completion_receipts",
        "case_versions",
        "audit_entries",
    )
    assert after_reclaim == tuple(value + 1 for value in before)

    with pytest.raises(ConcurrentModification, match="different outcome"):
        repository.commit_backlog_retry_failure(
            RUN_ID,
            enqueued.case.revision,
            retry_head,
            closure,
            failure,
        )
    assert (
        _table_counts(
            database,
            "backlog_item_versions",
            "backlog_completion_receipts",
            "case_versions",
            "audit_entries",
        )
        == after_reclaim
    )
    second_lease = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "3" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert second_lease is not None and second_lease.attempt_count == 2


@pytest.mark.parametrize("max_attempts", [1, 2, 3])
def test_repeated_crash_after_provider_call_has_hard_attempt_bound(
    tmp_path: Path,
    max_attempts: int,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack, max_attempts=max_attempts)
    repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )

    class CrashAfterProviderCall:
        minimum_backlog_lease_seconds = 1

        def __init__(self) -> None:
            self.provider_calls = 0

        def retry_leased_item(self, leased_item: BacklogItem) -> Never:
            assert leased_item.status == BacklogStatus.LEASED
            self.provider_calls += 1
            raise RuntimeError("simulated crash after provider call")

    processor = CrashAfterProviderCall()
    clock_value = [RECORDED_AT]
    coordinator = BacklogRetryCoordinator(
        backlog_store=repository,
        processor=processor,
        lease_duration_seconds=1,
        clock=lambda: clock_value[0],
    )

    for _ in range(max_attempts):
        with pytest.raises(RuntimeError, match="after provider call"):
            coordinator.run_once(RUN_ID, "crashing-worker")
        clock_value[0] += timedelta(seconds=2)

    terminal = coordinator.run_once(RUN_ID, "replacement-worker")
    assert terminal.disposition == BacklogRetryDisposition.NO_WORK
    assert terminal.reclaimed_expired_count == 1
    assert terminal.reclaimed_exhausted_count == 1
    assert processor.provider_calls == max_attempts
    exhausted = repository.load_backlog_item(RUN_ID, item.item_id)
    assert exhausted.status == BacklogStatus.EXHAUSTED
    assert exhausted.attempt_count == max_attempts
    assert evidence.load_case(RUN_ID, pack.case_id).case.status == CaseStatus.HUMAN_REVIEW
    assert _table_counts(database, "backlog_completion_receipts") == (max_attempts,)

    for _ in range(3):
        clock_value[0] += timedelta(hours=1)
        idle = coordinator.run_once(RUN_ID, "replacement-worker")
        assert idle.disposition == BacklogRetryDisposition.NO_WORK
        assert idle.reclaimed_expired_count == 0
        assert idle.reclaimed_exhausted_count == 0
    assert processor.provider_calls == max_attempts


def test_strict_two_call_failure_advances_generation_and_accounts_once(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack)
    enqueued = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "3" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert leased is not None
    context = BacklogRetryContext(
        backlog_item_id=leased.item_id,
        retry_generation=leased.retry_generation,
    )
    request = _request(pack, backlog_retry_context=context)
    first_response = _response(
        request,
        content_sha256="7" * 64,
        input_tokens=19,
        output_tokens=3,
        latency_ms=29,
    )
    repair = _repair_request(request, first_response)
    first_receipt = ModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=first_response.response_id,
        response_content_sha256=first_response.content_sha256,
        attempt_index=0,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.REPAIR_REQUIRED,
        defects=(_parser_defect(first_response.response_id),),
        repair_request_id=repair.request_id,
        manifest_id=request.manifest_id,
    )
    _complete_call(repository, request, first_response, _lease_identity(leased))
    repository.append_parse_receipt(first_receipt)
    final_response = _response(
        repair,
        content_sha256="8" * 64,
        input_tokens=7,
        output_tokens=5,
        latency_ms=31,
    )
    final_receipt = ModelParseReceipt(
        run_id=repair.run_id,
        case_id=repair.case_id,
        evidence_pack_id=repair.evidence_pack_id,
        evidence_pack_version=repair.evidence_pack_version,
        request_id=repair.request_id,
        request_sha256=repair.request_sha256,
        response_id=final_response.response_id,
        response_content_sha256=final_response.content_sha256,
        attempt_index=1,
        parser_version="strict-json-v1",
        output_schema_sha256=repair.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.INVALID_FINAL,
        defects=(_parser_defect(final_response.response_id),),
        manifest_id=repair.manifest_id,
    )
    _complete_call(repository, repair, final_response, _lease_identity(leased))
    repository.append_parse_receipt(final_receipt)
    proof = BacklogStrictParseFailureProof(
        retry_context=context,
        attempts=(
            BacklogParseFailureEvidence(
                attempt_index=0,
                role=VlmRole.SCREENING,
                request_ref=ArtifactRef(
                    kind=ArtifactKind.MODEL_REQUEST,
                    artifact_id=request.request_id,
                ),
                response_ref=ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=first_response.response_id,
                ),
                parse_receipt_ref=ArtifactRef(
                    kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                    artifact_id=first_receipt.parse_receipt_id,
                ),
            ),
            BacklogParseFailureEvidence(
                attempt_index=1,
                role=VlmRole.STRUCTURE_REPAIR,
                request_ref=ArtifactRef(
                    kind=ArtifactKind.MODEL_REQUEST,
                    artifact_id=repair.request_id,
                ),
                response_ref=ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=final_response.response_id,
                ),
                parse_receipt_ref=ArtifactRef(
                    kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                    artifact_id=final_receipt.parse_receipt_id,
                ),
            ),
        ),
    )
    response_refs = tuple(
        sorted(
            (attempt.response_ref for attempt in proof.attempts),
            key=lambda ref: ref.sort_key,
        )
    )
    failure = BacklogRetryFailure(
        lease=_lease_identity(leased),
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        next_status=BacklogStatus.PENDING,
        response_refs=response_refs,
        strict_parse_failure=proof,
        manifest_id=pack.manifest_id,
    )
    committed = repository.commit_backlog_retry_failure(
        RUN_ID,
        enqueued.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        failure,
    )

    assert committed.item.retry_generation == leased.retry_generation + 1
    assert committed.case.case.usage.input_tokens == 26
    assert committed.case.case.usage.output_tokens == 8
    assert committed.case.case.usage.retries == 1
    assert _table_counts(
        database,
        "model_call_usage_accounting",
        "backlog_completion_receipts",
    ) == (2, 1)


def test_atomic_backlog_screening_success_completes_case_and_replays(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack)
    enqueued = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "8" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert leased is not None
    context = BacklogRetryContext(
        backlog_item_id=leased.item_id,
        retry_generation=leased.retry_generation,
    )
    request = _request(pack, backlog_retry_context=context)
    response = _response(
        request,
        content_sha256="e" * 64,
        input_tokens=13,
        output_tokens=5,
        latency_ms=17,
    )
    output = _parsed(request, response, violation_probability=0.5)
    receipt = _parsed_receipt(request, response, output)
    _complete_call(repository, request, response, _lease_identity(leased))
    repository.append_parse_receipt(receipt, output)
    screening = _screening_for(pack, output)
    assert screening.decision == ScreeningDecision.ESCALATE
    response_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_RESPONSE,
        artifact_id=response.response_id,
    )
    success = BacklogRetrySuccess(
        lease=_lease_identity(leased),
        completion_case_status=CaseStatus.ESCALATED,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.SCREENING_RESULT,
            artifact_id=screening.screening_id,
        ),
        response_refs=(response_ref,),
        manifest_id=pack.manifest_id,
    )
    retry_head = evidence.get_audit_head(RUN_ID)
    committed = repository.commit_backlog_screening_success(
        RUN_ID,
        enqueued.case.revision,
        retry_head,
        closure,
        success,
        screening,
    )

    assert committed.created is True
    assert committed.item.status == BacklogStatus.COMPLETED
    assert committed.case.case.status == CaseStatus.ESCALATED
    assert committed.case.case.current_backlog_item_id is None
    assert committed.case.case.usage.input_tokens == 13
    assert evidence.load_case(RUN_ID, pack.case_id) == committed.case
    assert repository.complete(RUN_ID, item.item_id, leased.lease_id or "") == committed.item
    replay = repository.commit_backlog_screening_success(
        RUN_ID,
        enqueued.case.revision,
        retry_head,
        closure,
        success,
        screening,
    )
    assert replay.created is False
    assert replay.receipt == committed.receipt
    assert _table_counts(
        database,
        "screening_results",
        "backlog_completion_receipts",
        "model_call_usage_accounting",
    ) == (1, 1, 1)
    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE backlog_completion_receipts SET outcome_kind = 'FAILURE'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM backlog_completion_receipts")


def test_atomic_backlog_verdict_success_can_create_all_three_roots(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack)
    enqueued = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "7" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert leased is not None
    request = _request(
        pack,
        backlog_retry_context=BacklogRetryContext(
            backlog_item_id=leased.item_id,
            retry_generation=leased.retry_generation,
        ),
    )
    response = _response(
        request,
        content_sha256="f" * 64,
        input_tokens=17,
        output_tokens=11,
        latency_ms=23,
    )
    output = _parsed(request, response)
    parse_receipt = _parsed_receipt(request, response, output)
    _complete_call(repository, request, response, _lease_identity(leased))
    repository.append_parse_receipt(parse_receipt, output)
    screening = _screening_for(pack, output)
    assert screening.decision != ScreeningDecision.ESCALATE
    response_refs = (
        ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        ),
    )
    verdict = _verdict_for(screening, pack, response_refs)
    review = _trusted_review(evidence, verdict, pack, closure, (parse_receipt,))
    target = CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
    success = BacklogRetrySuccess(
        lease=_lease_identity(leased),
        completion_case_status=target,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.PROCEDURAL_REVIEW,
            artifact_id=review.review_id,
        ),
        response_refs=response_refs,
        manifest_id=pack.manifest_id,
    )
    committed = repository.commit_backlog_verdict_review_success(
        RUN_ID,
        enqueued.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        success,
        verdict,
        review,
        screening,
    )

    assert committed.case.case.status == target
    assert committed.item.status == BacklogStatus.COMPLETED
    assert committed.case.case.screening_results == (screening,)
    assert committed.case.case.verdicts == (verdict,)
    assert committed.case.case.procedural_reviews == (review,)
    assert evidence.load_case(RUN_ID, pack.case_id) == committed.case
    projection = JsonProjector(evidence, tmp_path / "retry-success-projection").project_run(RUN_ID)
    assert len(projection.case_paths) == 1
    assert (
        Case.model_validate_json(projection.case_paths[0].read_text(encoding="utf-8"))
        == committed.case.case
    )
    assert _table_counts(
        database,
        "screening_results",
        "verdicts",
        "procedural_reviews",
        "backlog_completion_receipts",
        "model_call_usage_accounting",
    ) == (1, 1, 1, 1, 1)


def test_atomic_backlog_verdict_success_reuses_existing_screening_usage(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    _, response, output, parse_receipt = _persist_direct_parse(repository, pack)
    screening = _screening_for(pack, output)
    screened = repository.commit_screening(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    )
    response_refs = (
        ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        ),
    )
    item = _backlog_item(
        pack,
        reason=BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
    )
    enqueued = repository.commit_backlog(
        RUN_ID,
        screened.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        item,
        (response.response_id,),
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "6" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert leased is not None
    verdict = _verdict_for(screening, pack, response_refs)
    review = _trusted_review(evidence, verdict, pack, closure, (parse_receipt,))
    target = CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
    success = BacklogRetrySuccess(
        lease=_lease_identity(leased),
        completion_case_status=target,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.PROCEDURAL_REVIEW,
            artifact_id=review.review_id,
        ),
        response_refs=response_refs,
        manifest_id=pack.manifest_id,
    )
    before_usage = screened.case.case.usage
    committed = repository.commit_backlog_verdict_review_success(
        RUN_ID,
        enqueued.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        success,
        verdict,
        review,
    )

    assert committed.case.case.usage == before_usage
    assert committed.case.case.screening_results == (screening,)
    assert evidence.load_case(RUN_ID, pack.case_id) == committed.case
    assert _table_counts(
        database,
        "screening_results",
        "verdicts",
        "procedural_reviews",
        "backlog_completion_receipts",
        "model_call_usage_accounting",
    ) == (1, 1, 1, 1, 1)


def test_failed_current_closure_can_only_atomically_backlog_current_pack_change(
    tmp_path: Path,
) -> None:
    database, evidence, _, pack, _, snapshot, head = _m3_setup(tmp_path)
    failing_evidence = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(status=VerificationStatus.MEDIA_HASH_MISMATCH),
        clock=_clock,
    )
    failed = failing_evidence.verify_current_pack(RUN_ID, pack.pack_id)
    assert failed.passed is False
    repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=failing_evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    item = BacklogItem(
        run_id=RUN_ID,
        case_id=pack.case_id,
        stage=BacklogStage.SCREENING,
        role=VlmRole.SCREENING,
        reason_code=BacklogReasonCode.CURRENT_PACK_CHANGED,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=pack.pack_id,
        ),
        stage_input_sha256=m3_root_document_sha256(pack),
        max_attempts=2,
        manifest_id=pack.manifest_id,
    )
    ordinary_failure = item.model_copy(
        update={"reason_code": BacklogReasonCode.PROVIDER_UNAVAILABLE}
    )
    with pytest.raises(ContractViolation, match="requires commit_backlog"):
        repository.enqueue(RUN_ID, item)
    before = _table_counts(database, "backlog_items", "case_versions", "audit_entries")
    with pytest.raises(ContractViolation, match="closure did not pass"):
        repository.commit_backlog(
            RUN_ID,
            snapshot.revision,
            head,
            failed,
            ordinary_failure,
        )
    assert (
        _table_counts(
            database,
            "backlog_items",
            "case_versions",
            "audit_entries",
        )
        == before
    )

    committed = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        failed,
        item,
    )
    assert committed.created
    assert committed.case.case.status == CaseStatus.BACKLOGGED
    assert committed.case.case.current_backlog_item_id == item.item_id
    assert repository.load_backlog_item(RUN_ID, item.item_id) == item
    assert evidence.load_case(RUN_ID, pack.case_id) == committed.case
    assert evidence.get_audit_head(RUN_ID).sequence == head.sequence + 1

    lease = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "6" * 64,
        RECORDED_AT + timedelta(minutes=1),
    )
    assert lease is not None and lease.status == BacklogStatus.LEASED
    reclaimed = repository.reclaim_expired(
        RUN_ID,
        RECORDED_AT + timedelta(minutes=2),
        10,
    )
    assert len(reclaimed) == 1 and reclaimed[0].status == BacklogStatus.PENDING
    assert reclaimed[0].attempt_count == 1
    recovered_case = evidence.load_case(RUN_ID, pack.case_id)
    assert recovered_case.revision == committed.case.revision + 1
    assert recovered_case.case.status == CaseStatus.BACKLOGGED
    assert recovered_case.case.current_backlog_item_id == item.item_id
    assert _table_counts(database, "backlog_completion_receipts") == (1,)
    lease2 = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "7" * 64,
        RECORDED_AT + timedelta(minutes=3),
    )
    assert lease2 is not None and lease2.attempt_count == 2
    with pytest.raises(ContractViolation, match="commit_backlog_retry_failure"):
        repository.release(RUN_ID, item.item_id, lease2.lease_id or "")
    assert repository.load_backlog_item(RUN_ID, item.item_id) == lease2
    assert evidence.load_case(RUN_ID, pack.case_id) == recovered_case
    assert evidence.get_audit_head(RUN_ID).sequence == head.sequence + 2


def test_verdict_and_failed_review_round_trip_as_one_case_transition(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    _, response, output, _ = _persist_direct_parse(
        repository,
        pack,
        violation_type=ViolationType.FOOD_OR_DRINK_IN_LAB,
    )
    screening = _screening_for(pack, output)
    screening_commit = repository.commit_screening(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    )
    verdict = _verdict_for(
        screening,
        pack,
        (
            ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=response.response_id,
            ),
        ),
    )
    next_head = evidence.get_audit_head(RUN_ID)
    current_closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)
    history = repository.load_parse_history_for_output(
        RUN_ID,
        screening.parsed_output.parsed_output_id,
    )
    authoritative_review = _trusted_review(
        evidence,
        verdict,
        pack,
        current_closure,
        history,
    )
    unverified_repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    with pytest.raises(ContractViolation, match="procedural_review_verifier"):
        unverified_repository.commit_verdict_review(
            RUN_ID,
            screening_commit.case.revision,
            next_head,
            current_closure,
            verdict,
            authoritative_review,
        )
    forged_review = _review_for(verdict, ())
    before = _table_counts(
        database,
        "verdicts",
        "procedural_reviews",
        "procedural_defects",
        "case_versions",
        "audit_entries",
    )
    with pytest.raises(ContractViolation, match="differs from trusted reconstruction"):
        repository.commit_verdict_review(
            RUN_ID,
            screening_commit.case.revision,
            next_head,
            current_closure,
            verdict,
            forged_review,
        )
    assert (
        _table_counts(
            database,
            "verdicts",
            "procedural_reviews",
            "procedural_defects",
            "case_versions",
            "audit_entries",
        )
        == before
    )

    review = authoritative_review
    assert tuple(defect.code for defect in review.defects) == (
        ProceduralDefectCode.VIOLATION_TYPE_MISMATCH,
    )
    committed = repository.commit_verdict_review(
        RUN_ID,
        screening_commit.case.revision,
        next_head,
        current_closure,
        verdict,
        review,
    )
    assert committed.created
    assert committed.case.case.status == CaseStatus.REWORK_REQUIRED
    assert repository.load_verdict(RUN_ID, verdict.verdict_id) == verdict
    assert repository.load_procedural_review(RUN_ID, review.review_id) == review
    assert evidence.load_case(RUN_ID, pack.case_id) == committed.case

    replay_repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        raw_response_verifier=_RawVerifier(),
    )
    replay = replay_repository.commit_verdict_review(
        RUN_ID,
        screening_commit.case.revision,
        next_head,
        current_closure,
        verdict,
        review,
    )
    assert replay.created is False
    assert _table_counts(
        database,
        "verdicts",
        "procedural_reviews",
        "procedural_defects",
    ) == (1, 1, len(review.defects))


def test_commit_verdict_rejects_forged_fast_decision_without_writes(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    _, response, output, _ = _persist_direct_parse(repository, pack)
    screening = _screening_for(pack, output)
    screened = repository.commit_screening(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    ).case
    response_refs = (
        ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        ),
    )
    authoritative = _verdict_for(screening, pack, response_refs)
    forged = authoritative.model_copy(
        update={
            "decision": VerdictDecision.NOT_ESTABLISHED,
            "confidence": 0.05,
            "recommended_alert_level": "ADVISORY",
        }
    )
    forged_review = _review_for(forged, ())
    current_closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)
    before = _table_counts(
        database,
        "verdicts",
        "procedural_reviews",
        "procedural_defects",
        "case_versions",
        "audit_entries",
    )

    with pytest.raises(ContractViolation, match="trusted reconstruction"):
        repository.commit_verdict_review(
            RUN_ID,
            screened.revision,
            evidence.get_audit_head(RUN_ID),
            current_closure,
            forged,
            forged_review,
        )

    assert (
        _table_counts(
            database,
            "verdicts",
            "procedural_reviews",
            "procedural_defects",
            "case_versions",
            "audit_entries",
        )
        == before
    )


def test_m3_case_writes_reject_state_regression_after_successful_progress(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    _, response, output, _ = _persist_direct_parse(repository, pack)
    screening = _screening_for(pack, output)
    screened = repository.commit_screening(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    ).case

    with pytest.raises(ConcurrentModification, match="EVIDENCE_READY"):
        repository.commit_screening(
            RUN_ID,
            screened.revision,
            evidence.get_audit_head(RUN_ID),
            evidence.verify_current_pack(RUN_ID, pack.pack_id),
            screening.model_copy(update={"version": 2}),
        )

    verdict = _verdict_for(
        screening,
        pack,
        (
            ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=response.response_id,
            ),
        ),
    )
    current_closure = evidence.verify_current_pack(RUN_ID, pack.pack_id)
    history = repository.load_parse_history_for_output(
        RUN_ID,
        screening.parsed_output.parsed_output_id,
    )
    review = _trusted_review(evidence, verdict, pack, current_closure, history)
    terminal = repository.commit_verdict_review(
        RUN_ID,
        screened.revision,
        evidence.get_audit_head(RUN_ID),
        current_closure,
        verdict,
        review,
    ).case
    assert terminal.case.status == CaseStatus.READY_FOR_ALERT_POLICY

    second_verdict = verdict.model_copy(update={"version": 2})
    second_review = ProceduralReview(
        run_id=second_verdict.run_id,
        case_id=second_verdict.case_id,
        version=2,
        evidence_pack_id=second_verdict.evidence_pack_id,
        evidence_pack_version=second_verdict.evidence_pack_version,
        reviewed_verdict_id=second_verdict.verdict_id,
        reviewed_verdict_version=second_verdict.version,
        reviewed_verdict_sha256=second_verdict.verdict_sha256,
        gate_version=review.gate_version,
        defects=(),
        manifest_id=second_verdict.manifest_id,
    )
    with pytest.raises(ConcurrentModification, match="SCREENED"):
        repository.commit_verdict_review(
            RUN_ID,
            terminal.revision,
            evidence.get_audit_head(RUN_ID),
            evidence.verify_current_pack(RUN_ID, pack.pack_id),
            second_verdict,
            second_review,
        )

    backlog = BacklogItem(
        run_id=RUN_ID,
        case_id=pack.case_id,
        stage=BacklogStage.SCREENING,
        role=VlmRole.SCREENING,
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.EVIDENCE_PACK,
            artifact_id=pack.pack_id,
        ),
        stage_input_sha256=m3_root_document_sha256(pack),
        max_attempts=2,
        manifest_id=pack.manifest_id,
    )
    counts_before = _table_counts(database, "backlog_items", "case_versions", "audit_entries")
    with pytest.raises(ConcurrentModification, match="backlog requires"):
        repository.commit_backlog(
            RUN_ID,
            terminal.revision,
            evidence.get_audit_head(RUN_ID),
            evidence.verify_current_pack(RUN_ID, pack.pack_id),
            backlog,
        )
    assert (
        _table_counts(
            database,
            "backlog_items",
            "case_versions",
            "audit_entries",
        )
        == counts_before
    )


def test_repository_without_physical_verifier_cannot_commit_case_state(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    _, _, output, _ = _persist_direct_parse(repository, pack)
    unguarded = SQLiteM3Repository(database, BUSY_TIMEOUT_MS, clock=_clock)
    with pytest.raises(ContractViolation, match="current_pack_verifier"):
        unguarded.commit_screening(
            RUN_ID,
            snapshot.revision,
            head,
            closure,
            _screening_for(pack, output),
        )


def test_m3_schema_version_and_foreign_keys_are_enabled(tmp_path: Path) -> None:
    database, _, _, _, _, _, _ = _m3_setup(tmp_path)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, 19)]
        assert _v7_authority_objects(connection) == M3_AUTHORITY_HARDENING_OBJECTS
        connection.execute("PRAGMA foreign_keys = ON")
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)
    finally:
        connection.close()


def test_backlog_history_rejects_leased_owner_takeover_and_detects_v6_forgery(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack)
    repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "5" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert leased is not None
    forged_payload = leased.model_dump(mode="json")
    forged_payload.pop("item_id")
    forged_payload.pop("completed")
    forged_payload.update(
        {
            "attempt_count": leased.attempt_count + 1,
            "lease_id": "f" * 64,
            "lease_owner_sha256": "e" * 64,
        }
    )
    forged = BacklogItem.model_validate(forged_payload)
    forged_document = forged.model_dump(mode="json")
    forged_json = canonical_json(forged_document)
    forged_sha256 = hashlib.sha256(forged_json.encode("utf-8")).hexdigest()
    insert_forged = """
        INSERT INTO backlog_item_versions(
            run_id, item_id, version, status, attempt_count,
            retry_generation, lease_id, lease_owner_sha256,
            lease_expires_at, item_json, document_sha256
        ) VALUES (?, ?, 3, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    forged_row = (
        RUN_ID,
        forged.item_id,
        forged.status.value,
        forged.attempt_count,
        forged.retry_generation,
        forged.lease_id,
        forged.lease_owner_sha256,
        forged_document["lease_expires_at"],
        forged_json,
        forged_sha256,
    )

    with sqlite3.connect(database) as connection:
        transition_sql = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'backlog_item_versions_validate_transition'
            """
        ).fetchone()
        assert transition_sql is not None and isinstance(transition_sql[0], str)
        with pytest.raises(sqlite3.IntegrityError, match="backlog history transition"):
            connection.execute(insert_forged, forged_row)
        assert connection.execute(
            "SELECT COUNT(*) FROM backlog_item_versions WHERE run_id = ? AND item_id = ?",
            (RUN_ID, item.item_id),
        ).fetchone() == (2,)

        # Simulate a v6-era direct SQL injection, then restore the v7 trigger so
        # the read-only authority scanner can independently diagnose history.
        connection.execute("DROP TRIGGER backlog_item_versions_validate_transition")
        connection.execute(insert_forged, forged_row)
        connection.execute(
            """
            UPDATE backlog_heads SET current_version = 3
            WHERE run_id = ? AND item_id = ? AND current_version = 2
            """,
            (RUN_ID, item.item_id),
        )
        connection.execute(str(transition_sql[0]))
        connection.commit()

    with readonly_sqlite_snapshot(database) as readonly:
        authority = ReadonlyM3ArtifactRepository(readonly).scan(RUN_ID)
    assert any(
        failure.failure_type == M3AuthorityFailureType.REFERENCE_INVALID
        and failure.reason_code == "BACKLOG_HISTORY_TRANSITION_INVALID"
        for failure in authority.failures
    )

    with sqlite3.connect(database) as connection:
        _remove_v7_authority_schema(connection)
        before_versions = connection.execute(
            """
            SELECT * FROM backlog_item_versions
            WHERE run_id = ? AND item_id = ? ORDER BY version
            """,
            (RUN_ID, item.item_id),
        ).fetchall()
        connection.commit()

    with pytest.raises(MigrationIntegrityError, match=r"0007_m3_authority_hardening\.sql failed"):
        MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,), (3,), (4,), (5,), (6,)]
        assert _v7_authority_objects(connection) == set()
        assert (
            connection.execute(
                """
            SELECT * FROM backlog_item_versions
            WHERE run_id = ? AND item_id = ? ORDER BY version
            """,
                (RUN_ID, item.item_id),
            ).fetchall()
            == before_versions
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_populated_v6_migrates_to_v7_without_rewriting_history_and_accepts_failure_authority(
    tmp_path: Path,
) -> None:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    completed_request = _request(pack)
    completed_response = _response(
        completed_request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    _complete_call(repository, completed_request, completed_response)

    item = _backlog_item(pack, max_attempts=3)
    enqueued = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    first_lease = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "5" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert first_lease is not None
    first_failure = BacklogRetryFailure(
        lease=_lease_identity(first_lease),
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=BacklogStatus.PENDING,
        manifest_id=pack.manifest_id,
    )
    failed_once = repository.commit_backlog_retry_failure(
        RUN_ID,
        enqueued.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        first_failure,
    )
    second_lease = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "6" * 64,
        RECORDED_AT + timedelta(minutes=10),
    )
    assert second_lease is not None

    active_payload = _request(
        pack,
        backlog_retry_context=BacklogRetryContext(
            backlog_item_id=item.item_id,
            retry_generation=second_lease.retry_generation,
        ),
    ).model_dump(mode="json")
    for computed_name in (
        "allowed_crop_ids",
        "request_sha256",
        "request_id",
        "cache_key",
    ):
        active_payload.pop(computed_name)
    active_payload["rendered_prompt_sha256"] = "e" * 64
    active_request = VLMRequest.model_validate(active_payload)
    active_owner = "migration-active-owner-token-with-at-least-thirty-two-bytes"
    active_claim = repository.claim_model_call(
        RUN_ID,
        active_request,
        active_owner,
        _lease_identity(second_lease),
    )
    assert active_claim.status == ModelCallClaimStatus.ACQUIRED
    assert active_claim.lease_expires_at is not None

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        assert connection.execute(
            "SELECT COUNT(*) FROM model_call_failure_authorities"
        ).fetchone() == (0,)
        # Remove only migration 0007's schema objects and immutable history
        # record. Every populated row remains exactly as authored through the
        # public v1-v7 APIs, yielding a real populated v6 database.
        _remove_v7_authority_schema(connection)
        connection.commit()
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(1,), (2,), (3,), (4,), (5,), (6,)]
        assert _v7_authority_objects(connection) == set()
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

        preserved_tables = (
            "run_manifests",
            "runs",
            "audit_entries",
            "cases",
            "case_versions",
            "evidence_packs",
            "model_call_claims",
            "model_responses",
            "model_cache",
            "backlog_items",
            "backlog_item_versions",
            "backlog_heads",
            "backlog_completion_receipts",
            "model_call_failure_authorities",
        )
        before = {
            table: tuple(
                sorted(
                    connection.execute(f"SELECT * FROM {table}").fetchall(),
                    key=repr,
                )
            )
            for table in preserved_tables
        }
        assert connection.execute(
            "SELECT status, COUNT(*) FROM model_call_claims GROUP BY status ORDER BY status"
        ).fetchall() == [("ACTIVE", 1), ("COMPLETED", 1)]
        assert connection.execute(
            "SELECT COUNT(*) FROM backlog_completion_receipts"
        ).fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM backlog_item_versions").fetchone() == (4,)
        assert connection.execute("SELECT COUNT(*) FROM backlog_heads").fetchone() == (1,)
        assert int(connection.execute("SELECT COUNT(*) FROM case_versions").fetchone()[0]) >= 3
        assert int(connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0]) >= 3

    assert MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all() == (
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
    )
    assert MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all() == ()

    with sqlite3.connect(database) as connection:
        after = {
            table: tuple(
                sorted(
                    connection.execute(f"SELECT * FROM {table}").fetchall(),
                    key=repr,
                )
            )
            for table in preserved_tables
        }
        assert after == before
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall() == [(version,) for version in range(1, 19)]
        assert _v7_authority_objects(connection) == M3_AUTHORITY_HARDENING_OBJECTS
        assert connection.execute(
            "SELECT COUNT(*) FROM model_call_failure_authorities"
        ).fetchone() == (0,)

    reopened_evidence = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_Verifier(),
        clock=_clock,
    )
    reopened_repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=reopened_evidence.verify_current_pack,
        raw_response_verifier=_RawVerifier(),
    )
    assert reopened_evidence.load_case(RUN_ID, pack.case_id) == failed_once.case
    assert reopened_repository.load_backlog_item(RUN_ID, item.item_id) == second_lease

    second_failure = BacklogRetryFailure(
        lease=_lease_identity(second_lease),
        reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        next_status=BacklogStatus.PENDING,
        manifest_id=pack.manifest_id,
    )
    failure_intent = ModelCallFailureIntent(
        request=active_request,
        owner_token=active_owner,
        claim_lease_expires_at=active_claim.lease_expires_at,
        claim_takeover_count=active_claim.takeover_count,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    expected_head = reopened_evidence.get_audit_head(RUN_ID)
    committed = reopened_repository.commit_backlog_retry_failure(
        RUN_ID,
        failed_once.case.revision,
        expected_head,
        reopened_evidence.verify_current_pack(RUN_ID, pack.pack_id),
        second_failure,
        failure_intent,
    )
    replayed = reopened_repository.commit_backlog_retry_failure(
        RUN_ID,
        failed_once.case.revision,
        expected_head,
        reopened_evidence.verify_current_pack(RUN_ID, pack.pack_id),
        second_failure,
        failure_intent,
    )
    assert committed.created is True
    assert replayed.created is False
    assert replayed.receipt == committed.receipt
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM model_call_failure_authorities"
        ).fetchone() == (1,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def _all_m3_artifacts_for_validation(tmp_path: Path) -> Path:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = _backlog_item(pack)
    enqueued = repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )
    leased = repository.lease_next(
        RUN_ID,
        BacklogStage.SCREENING,
        "7" * 64,
        RECORDED_AT + timedelta(minutes=5),
    )
    assert leased is not None
    request = _request(
        pack,
        backlog_retry_context=BacklogRetryContext(
            backlog_item_id=leased.item_id,
            retry_generation=leased.retry_generation,
        ),
    )
    response = _response(
        request,
        content_sha256=VALIDATION_RAW_SHA256,
        input_tokens=17,
        output_tokens=11,
        latency_ms=23,
    )
    output = _parsed(
        request,
        response,
        violation_type=ViolationType.FOOD_OR_DRINK_IN_LAB,
    )
    parse_receipt = _parsed_receipt(request, response, output)
    _complete_call(repository, request, response, _lease_identity(leased))
    repository.append_parse_receipt(parse_receipt, output)
    screening = _screening_for(pack, output)
    response_refs = (
        ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=response.response_id,
        ),
    )
    verdict = _verdict_for(screening, pack, response_refs)
    review = _trusted_review(evidence, verdict, pack, closure, (parse_receipt,))
    assert review.defects
    target = CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
    success = BacklogRetrySuccess(
        lease=_lease_identity(leased),
        completion_case_status=target,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.PROCEDURAL_REVIEW,
            artifact_id=review.review_id,
        ),
        response_refs=response_refs,
        manifest_id=pack.manifest_id,
    )
    committed = repository.commit_backlog_verdict_review_success(
        RUN_ID,
        enqueued.case.revision,
        evidence.get_audit_head(RUN_ID),
        closure,
        success,
        verdict,
        review,
        screening,
    )
    assert committed.item.status == BacklogStatus.COMPLETED
    return database


def _failed_model_call_for_validation(tmp_path: Path) -> tuple[Path, str]:
    database, _, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    request = _request(pack)
    owner = "validation-failure-owner-token-with-at-least-thirty-two-bytes"
    claim = repository.claim_model_call(RUN_ID, request, owner)
    assert claim.status == ModelCallClaimStatus.ACQUIRED
    assert claim.lease_expires_at is not None
    failure_intent = ModelCallFailureIntent(
        request=request,
        owner_token=owner,
        claim_lease_expires_at=claim.lease_expires_at,
        claim_takeover_count=claim.takeover_count,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
    )
    repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        _backlog_item(pack),
        model_call_failure=failure_intent,
    )
    return database, request.request_id


def _repair_artifacts_for_validation(tmp_path: Path) -> tuple[Path, str]:
    database, evidence, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    request = _request(pack)
    first_response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=13,
        output_tokens=3,
        latency_ms=17,
    )
    repair = _repair_request(request, first_response)
    first_receipt = ModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=first_response.response_id,
        response_content_sha256=first_response.content_sha256,
        attempt_index=0,
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.REPAIR_REQUIRED,
        defects=(_parser_defect(first_response.response_id),),
        repair_request_id=repair.request_id,
        manifest_id=request.manifest_id,
    )
    _complete_call(repository, request, first_response)
    repository.append_parse_receipt(first_receipt)
    final_response = _response(
        repair,
        content_sha256="b" * 64,
        input_tokens=5,
        output_tokens=9,
        latency_ms=23,
    )
    output = _parsed(
        repair,
        final_response,
        evidence_ref=request.allowed_evidence_refs[0],
    )
    final_receipt = _parsed_receipt(repair, final_response, output)
    _complete_call(repository, repair, final_response)
    repository.append_parse_receipt(final_receipt, output)
    screening = _screening_for(pack, output)
    committed = repository.commit_screening(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        screening,
    )
    response_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=response.response_id,
                )
                for response in (first_response, final_response)
            ),
            key=lambda reference: reference.sort_key,
        )
    )
    verdict = _verdict_for(screening, pack, response_refs)
    review = _trusted_review(
        evidence,
        verdict,
        pack,
        evidence.verify_current_pack(RUN_ID, pack.pack_id),
        (first_receipt, final_receipt),
    )
    repository.commit_verdict_review(
        RUN_ID,
        committed.case.revision,
        evidence.get_audit_head(RUN_ID),
        evidence.verify_current_pack(RUN_ID, pack.pack_id),
        verdict,
        review,
    )
    return database, first_receipt.parse_receipt_id


def _m3_validation_counts(
    snapshot_counts: SnapshotRunCounts,
) -> M3ArtifactValidationCounts:
    return M3ArtifactValidationCounts(
        max_document_bytes=snapshot_counts.m3_max_document_bytes,
        raw_response_bytes=snapshot_counts.raw_response_bytes,
        max_raw_response_bytes=snapshot_counts.max_raw_response_bytes,
        model_call_claims=snapshot_counts.model_call_claims,
        model_call_failure_authorities=snapshot_counts.model_call_failure_authorities,
        model_responses=snapshot_counts.model_responses,
        parsed_screening_outputs=snapshot_counts.parsed_screening_outputs,
        model_parse_receipts=snapshot_counts.model_parse_receipts,
        model_cache_entries=snapshot_counts.model_cache_entries,
        model_call_usage=snapshot_counts.model_call_usage,
        screening_results=snapshot_counts.screening_results,
        verdicts=snapshot_counts.verdicts,
        procedural_reviews=snapshot_counts.procedural_reviews,
        procedural_defects=snapshot_counts.procedural_defects,
        backlog_items=snapshot_counts.backlog_items,
        backlog_item_versions=snapshot_counts.backlog_item_versions,
        backlog_heads=snapshot_counts.backlog_heads,
        backlog_completion_receipts=snapshot_counts.backlog_completion_receipts,
    )


def test_readonly_m3_validator_reconstructs_all_fifteen_durable_tables(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot:
        counts = snapshot_run_counts(snapshot, RUN_ID)
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    assert (
        counts.model_call_claims,
        counts.model_responses,
        counts.parsed_screening_outputs,
        counts.model_parse_receipts,
        counts.model_cache_entries,
        counts.model_call_usage,
        counts.screening_results,
        counts.verdicts,
        counts.procedural_reviews,
        counts.backlog_items,
        counts.backlog_heads,
        counts.backlog_completion_receipts,
    ) == (1,) * 12
    assert counts.procedural_defects >= 1
    assert counts.backlog_item_versions == 3
    assert counts.raw_response_bytes == 128
    assert counts.max_raw_response_bytes == 128
    assert counts.m3_max_document_bytes > 0
    assert authority.failures == ()
    assert len(authority.raw_responses) == 1
    traversed = {item.inventory_kind.value: item.count for item in authority.traversed}
    assert traversed == {
        "MODEL_CALL_CLAIM": counts.model_call_claims,
        "MODEL_CALL_FAILURE_AUTHORITY": counts.model_call_failure_authorities,
        "MODEL_RESPONSE": counts.model_responses,
        "PARSED_SCREENING_OUTPUT": counts.parsed_screening_outputs,
        "MODEL_PARSE_RECEIPT": counts.model_parse_receipts,
        "MODEL_CACHE_ENTRY": counts.model_cache_entries,
        "MODEL_CALL_USAGE": counts.model_call_usage,
        "SCREENING_RESULT": counts.screening_results,
        "VERDICT": counts.verdicts,
        "PROCEDURAL_REVIEW": counts.procedural_reviews,
        "PROCEDURAL_DEFECT": counts.procedural_defects,
        "BACKLOG_ITEM": counts.backlog_items,
        "BACKLOG_ITEM_VERSION": counts.backlog_item_versions,
        "BACKLOG_HEAD": counts.backlog_heads,
        "BACKLOG_COMPLETION_RECEIPT": counts.backlog_completion_receipts,
    }


def test_readonly_m3_snapshot_exposes_exact_validated_model_call_documents(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)
        with closing(sqlite3.connect(f"{Path(snapshot).as_uri()}?mode=ro", uri=True)) as connection:
            persisted_hashes = {
                "request": str(
                    connection.execute(
                        "SELECT request_document_sha256 FROM model_call_claims"
                    ).fetchone()[0]
                ),
                "response": str(
                    connection.execute("SELECT document_sha256 FROM model_responses").fetchone()[0]
                ),
                "cache_request": str(
                    connection.execute(
                        "SELECT request_document_sha256 FROM model_cache"
                    ).fetchone()[0]
                ),
                "cache_entry": str(
                    connection.execute("SELECT document_sha256 FROM model_cache").fetchone()[0]
                ),
                "receipt": str(
                    connection.execute(
                        "SELECT document_sha256 FROM model_parse_receipts"
                    ).fetchone()[0]
                ),
                "output": str(
                    connection.execute(
                        "SELECT document_sha256 FROM parsed_screening_outputs"
                    ).fetchone()[0]
                ),
                "usage": tuple(
                    connection.execute(
                        """
                        SELECT document_sha256, request_id, response_id, case_id,
                               case_revision, consumer_kind, consumer_id, accounted_at
                        FROM model_call_usage_accounting
                        """
                    ).fetchone()
                ),
            }

    assert authority.failures == ()
    request = authority.model_call_requests[0]
    response = authority.raw_responses[0]
    cache = authority.model_cache_entries[0]
    receipt = authority.parse_receipts[0]
    output = authority.parsed_outputs[0]
    usage = authority.model_call_usages[0]
    assert request.request.request_id == response.response.request_id
    assert cache.request == request.request
    assert cache.entry.request_id == request.request.request_id
    assert cache.entry.response_id == response.response.response_id
    assert receipt.receipt.request_id == request.request.request_id
    assert receipt.receipt.response_id == response.response.response_id
    assert receipt.receipt.parsed_output_id == output.output.parsed_output_id
    assert output.output.request_id == request.request.request_id
    assert output.output.response_id == response.response.response_id
    assert usage.request_id == request.request.request_id
    assert usage.response_id == response.response.response_id
    assert (
        usage.document_sha256,
        usage.request_id,
        usage.response_id,
        usage.case_id,
        usage.case_revision,
        usage.consumer_kind,
        usage.consumer_id,
        usage.accounted_at,
    ) == persisted_hashes["usage"]
    assert request.document_sha256 == persisted_hashes["request"]
    assert response.document_sha256 == persisted_hashes["response"]
    assert cache.request_document_sha256 == persisted_hashes["cache_request"]
    assert cache.document_sha256 == persisted_hashes["cache_entry"]
    assert receipt.document_sha256 == persisted_hashes["receipt"]
    assert output.document_sha256 == persisted_hashes["output"]


def test_readonly_m3_snapshot_exposes_exact_failure_authority_from_same_scan(
    tmp_path: Path,
) -> None:
    database, request_id = _failed_model_call_for_validation(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)
        with closing(sqlite3.connect(f"{Path(snapshot).as_uri()}?mode=ro", uri=True)) as connection:
            persisted_hash = str(
                connection.execute(
                    "SELECT document_sha256 FROM model_call_failure_authorities"
                ).fetchone()[0]
            )

    assert authority.failures == ()
    request = authority.model_call_requests[0]
    failure = authority.model_call_failure_authorities[0]
    assert request.request.request_id == request_id
    assert failure.authority.request == request.request
    assert failure.document_sha256 == persisted_hash
    assert authority.raw_responses == ()
    assert authority.model_cache_entries == ()
    assert authority.parse_receipts == ()
    assert authority.parsed_outputs == ()


def test_readonly_m3_snapshot_model_call_views_are_stable_and_reject_duplicates(
    tmp_path: Path,
) -> None:
    database, _ = _repair_artifacts_for_validation(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    request_ids = tuple(item.request.request_id for item in authority.model_call_requests)
    response_ids = tuple(item.response.response_id for item in authority.raw_responses)
    cache_ids = tuple(item.entry.cache_entry_id for item in authority.model_cache_entries)
    receipt_ids = tuple(item.receipt.parse_receipt_id for item in authority.parse_receipts)
    output_ids = tuple(item.output.parsed_output_id for item in authority.parsed_outputs)
    usage_request_ids = tuple(item.request_id for item in authority.model_call_usages)
    assert request_ids == tuple(sorted(request_ids))
    assert response_ids == tuple(sorted(response_ids))
    assert cache_ids == tuple(sorted(cache_ids))
    assert receipt_ids == tuple(sorted(receipt_ids))
    assert output_ids == tuple(sorted(output_ids))
    assert usage_request_ids == tuple(sorted(usage_request_ids))

    with pytest.raises(ReadOnlySnapshotError, match="DUPLICATE_VALIDATED_DOCUMENT"):
        replace(
            authority,
            model_call_requests=(
                authority.model_call_requests[0],
                authority.model_call_requests[0],
            ),
        )
    with pytest.raises(ReadOnlySnapshotError, match="DUPLICATE_VALIDATED_DOCUMENT"):
        replace(
            authority,
            model_call_requests=(
                authority.model_call_requests[0],
                replace(
                    authority.model_call_requests[1],
                    record_identity_sha256=(
                        authority.model_call_requests[0].record_identity_sha256
                    ),
                ),
            ),
        )
    with pytest.raises(ReadOnlySnapshotError, match="VALIDATED_DOCUMENT_ORDER_INVALID"):
        replace(
            authority,
            model_call_requests=tuple(reversed(authority.model_call_requests)),
        )
    with pytest.raises(ReadOnlySnapshotError, match="VALIDATED_DOCUMENT_TYPE_INVALID"):
        replace(
            authority,
            model_call_requests=(object(),),  # type: ignore[arg-type]
        )
    with pytest.raises(ReadOnlySnapshotError, match="DUPLICATE_VALIDATED_DOCUMENT"):
        replace(
            authority,
            model_call_usages=(
                authority.model_call_usages[0],
                authority.model_call_usages[0],
            ),
        )
    with pytest.raises(ReadOnlySnapshotError, match="VALIDATED_DOCUMENT_ORDER_INVALID"):
        replace(
            authority,
            model_call_usages=tuple(reversed(authority.model_call_usages)),
        )


def test_readonly_m3_snapshot_does_not_expose_forged_request_document(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_call_claims_controlled_update")
        connection.execute("UPDATE model_call_claims SET request_json = ' ' || request_json")

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    assert authority.model_call_requests == ()
    assert any(
        failure.failure_type == M3AuthorityFailureType.DOCUMENT_INVALID
        and failure.inventory_kind.value == "MODEL_CALL_CLAIM"
        and failure.reason_code == "DOCUMENT_NOT_CANONICAL"
        for failure in authority.failures
    )


def test_readonly_m3_validator_reconstructs_two_attempt_parse_history(
    tmp_path: Path,
) -> None:
    database, _ = _repair_artifacts_for_validation(tmp_path)

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    assert authority.failures == ()
    assert len(authority.raw_responses) == 2


def test_readonly_m3_validator_rejects_missing_first_repair_receipt(
    tmp_path: Path,
) -> None:
    database, first_receipt_id = _repair_artifacts_for_validation(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER procedural_defects_no_delete")
        connection.execute("DROP TRIGGER model_parse_receipts_no_delete")
        connection.execute(
            "DELETE FROM procedural_defects WHERE owner_id = ?",
            (first_receipt_id,),
        )
        connection.execute(
            "DELETE FROM model_parse_receipts WHERE parse_receipt_id = ?",
            (first_receipt_id,),
        )

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    reasons = {failure.reason_code for failure in authority.failures}
    assert "REPAIR_REQUEST_HISTORY_MISMATCH" in reasons
    assert "PARSE_REPAIR_HISTORY_MISMATCH" in reasons


def test_readonly_m3_validator_preserves_historical_case_stage_input(
    tmp_path: Path,
) -> None:
    database, _, repository, pack, closure, snapshot, head = _m3_setup(tmp_path)
    item = BacklogItem(
        run_id=RUN_ID,
        case_id=pack.case_id,
        stage=BacklogStage.EVIDENCE,
        role=None,
        reason_code=BacklogReasonCode.BUDGET_EXCEEDED,
        stage_input_ref=ArtifactRef(
            kind=ArtifactKind.CASE,
            artifact_id=snapshot.case.case_id,
        ),
        stage_input_sha256=m3_root_document_sha256(snapshot.case),
        max_attempts=2,
        manifest_id=pack.manifest_id,
    )
    repository.commit_backlog(
        RUN_ID,
        snapshot.revision,
        head,
        closure,
        item,
    )

    with readonly_sqlite_snapshot(database) as readonly:
        authority = ReadonlyM3ArtifactRepository(readonly).scan(RUN_ID)

    assert authority.failures == ()


def test_m3_artifact_validator_reads_physical_raw_bytes_through_secure_workspace(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    workspace_root = tmp_path / "artifact-workspace"
    workspace_root.mkdir()

    with readonly_sqlite_snapshot(database) as snapshot:
        counts = snapshot_run_counts(snapshot, RUN_ID)
        authority = ReadonlyM3ArtifactRepository(snapshot)
        response = authority.scan(RUN_ID).raw_responses[0].response
        with SecureWorkspace(workspace_root, max_file_bytes=4096) as workspace:
            workspace.ensure_private_directory(RUN_ID)
            workspace.ensure_private_directory(f"{RUN_ID}/model_responses")
            workspace.create_new(
                response.raw_response_ref,
                VALIDATION_RAW_BYTES,
                VALIDATION_RAW_SHA256,
            )
            report = M3ArtifactValidator(
                authority=authority,
                artifact_reader=workspace,
                authority_counts=_m3_validation_counts(counts),
            ).validate(RUN_ID, ArtifactValidationReport(run_id=RUN_ID))

    assert report.issues == ()
    assert report.passed is True


def test_m3_artifact_validator_reports_physical_raw_tampering(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    workspace_root = tmp_path / "artifact-workspace"
    workspace_root.mkdir()

    with readonly_sqlite_snapshot(database) as snapshot:
        counts = snapshot_run_counts(snapshot, RUN_ID)
        authority = ReadonlyM3ArtifactRepository(snapshot)
        response = authority.scan(RUN_ID).raw_responses[0].response
        with SecureWorkspace(workspace_root, max_file_bytes=4096) as workspace:
            workspace.ensure_private_directory(RUN_ID)
            workspace.ensure_private_directory(f"{RUN_ID}/model_responses")
            workspace.create_new(
                response.raw_response_ref,
                VALIDATION_RAW_BYTES,
                VALIDATION_RAW_SHA256,
            )
        (workspace_root / Path(response.raw_response_ref)).write_bytes(b"y" * 128)
        with SecureWorkspace(workspace_root, max_file_bytes=4096) as workspace:
            report = M3ArtifactValidator(
                authority=authority,
                artifact_reader=workspace,
                authority_counts=_m3_validation_counts(counts),
            ).validate(RUN_ID, ArtifactValidationReport(run_id=RUN_ID))

    assert {issue.code for issue in report.issues} == {
        M3ArtifactValidationIssueCode.RAW_RESPONSE_UNSAFE
    }
    assert report.issues[0].reason_code == "ARTIFACT_INTEGRITY_FAILURE"


def test_m3_document_bytes_do_not_change_frozen_m2_budget_report(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    with readonly_sqlite_snapshot(database) as snapshot:
        before = snapshot_run_counts(snapshot, RUN_ID)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_responses_no_update")
        connection.execute(
            "UPDATE model_responses SET response_json = ? || response_json",
            (" " * 1_000_000,),
        )
    with readonly_sqlite_snapshot(database) as snapshot:
        after = snapshot_run_counts(snapshot, RUN_ID)

    assert after.max_document_bytes == before.max_document_bytes
    assert after.m3_max_document_bytes > before.m3_max_document_bytes
    m2_budget = ArtifactValidationBudget(
        max_document_bytes=before.max_document_bytes,
    )
    m2_counts = ArtifactValidationCounts(
        max_document_bytes=after.max_document_bytes,
        audit_entries=after.audit_entries,
        events=after.events,
        cases=after.cases,
        packs=after.packs,
        media=after.media,
    )
    assert (
        artifact_budget_preflight_report(
            run_id=RUN_ID,
            budget=m2_budget,
            counts=m2_counts,
        )
        is None
    )
    m2_report = ArtifactValidationReport(
        run_id=RUN_ID,
        budget=m2_budget,
        counts=m2_counts,
    )
    m3_report = m3_artifact_budget_preflight_report(
        run_id=RUN_ID,
        m2_report=m2_report,
        budget=M3ArtifactValidationBudget(
            max_document_bytes=before.m3_max_document_bytes,
        ),
        counts=_m3_validation_counts(after),
    )
    assert m3_report is not None
    assert m3_report.m2_report == m2_report
    assert m3_report.m2_report.passed is True
    assert {issue.code for issue in m3_report.issues} == {
        M3ArtifactValidationIssueCode.DOCUMENT_BYTES_BUDGET_EXCEEDED
    }


def test_readonly_m3_counts_reject_partial_schema(tmp_path: Path) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE backlog_completion_receipts")

    with (
        readonly_sqlite_snapshot(database) as snapshot,
        pytest.raises(ReadOnlySnapshotError, match="DATABASE_SCHEMA_INVALID"),
    ):
        snapshot_run_counts(snapshot, RUN_ID)


def test_readonly_m3_validator_rejects_noncanonical_document(tmp_path: Path) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_responses_no_update")
        raw = str(connection.execute("SELECT response_json FROM model_responses").fetchone()[0])
        connection.execute(
            "UPDATE model_responses SET response_json = ?",
            (f" {raw}",),
        )

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    response_failures = [
        failure
        for failure in authority.failures
        if failure.inventory_kind.value == "MODEL_RESPONSE"
    ]
    assert {(failure.failure_type, failure.reason_code) for failure in response_failures} == {
        (M3AuthorityFailureType.DOCUMENT_INVALID, "DOCUMENT_NOT_CANONICAL")
    }


def test_readonly_m3_validator_rejects_missing_atomic_cache_reference(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_cache_no_delete")
        connection.execute("DELETE FROM model_cache")

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    assert any(
        failure.failure_type == M3AuthorityFailureType.REFERENCE_INVALID
        and failure.reason_code
        in {
            "COMPLETED_CLAIM_BINDING_MISSING",
            "ATOMIC_CALL_BINDING_MISSING",
        }
        for failure in authority.failures
    )


def test_readonly_m3_validator_rejects_usage_rebound_to_backlog_consumer(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_call_usage_accounting_no_update")
        connection.execute(
            """
            UPDATE model_call_usage_accounting
            SET consumer_kind = 'BACKLOG_ITEM',
                consumer_id = (SELECT item_id FROM backlog_items LIMIT 1)
            """
        )

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    assert any(
        failure.inventory_kind.value == "MODEL_CALL_USAGE"
        and failure.failure_type == M3AuthorityFailureType.REFERENCE_INVALID
        and failure.reason_code == "USAGE_AUTHORITY_BINDING_MISMATCH"
        for failure in authority.failures
    )


@pytest.mark.parametrize(
    ("table", "trigger", "json_column", "inventory_kind"),
    (
        (
            "model_call_claims",
            "model_call_claims_controlled_update",
            "request_json",
            "MODEL_CALL_CLAIM",
        ),
        ("model_responses", "model_responses_no_update", "response_json", "MODEL_RESPONSE"),
        (
            "parsed_screening_outputs",
            "parsed_screening_outputs_no_update",
            "output_json",
            "PARSED_SCREENING_OUTPUT",
        ),
        (
            "model_parse_receipts",
            "model_parse_receipts_no_update",
            "receipt_json",
            "MODEL_PARSE_RECEIPT",
        ),
        ("model_cache", "model_cache_no_update", "request_json", "MODEL_CACHE_ENTRY"),
        ("model_cache", "model_cache_no_update", "entry_json", "MODEL_CACHE_ENTRY"),
        (
            "model_call_usage_accounting",
            "model_call_usage_accounting_no_update",
            "usage_json",
            "MODEL_CALL_USAGE",
        ),
        (
            "screening_results",
            "screening_results_no_update",
            "result_json",
            "SCREENING_RESULT",
        ),
        ("verdicts", "verdicts_no_update", "verdict_json", "VERDICT"),
        (
            "procedural_reviews",
            "procedural_reviews_no_update",
            "review_json",
            "PROCEDURAL_REVIEW",
        ),
        (
            "procedural_defects",
            "procedural_defects_no_update",
            "defect_json",
            "PROCEDURAL_DEFECT",
        ),
        ("backlog_items", "backlog_items_no_update", "initial_json", "BACKLOG_ITEM"),
        (
            "backlog_item_versions",
            "backlog_item_versions_no_update",
            "item_json",
            "BACKLOG_ITEM_VERSION",
        ),
        (
            "backlog_completion_receipts",
            "backlog_completion_receipts_no_update",
            "receipt_json",
            "BACKLOG_COMPLETION_RECEIPT",
        ),
    ),
)
def test_readonly_m3_validator_rejects_noncanonical_json_in_every_document_column(
    tmp_path: Path,
    table: str,
    trigger: str,
    json_column: str,
    inventory_kind: str,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute(f"UPDATE {table} SET {json_column} = ' ' || {json_column}")

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    assert any(
        failure.failure_type == M3AuthorityFailureType.DOCUMENT_INVALID
        and failure.inventory_kind.value == inventory_kind
        and failure.reason_code == "DOCUMENT_NOT_CANONICAL"
        for failure in authority.failures
    )


def test_readonly_m3_validator_rejects_index_and_backlog_head_tampering(
    tmp_path: Path,
) -> None:
    database = _all_m3_artifacts_for_validation(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER model_responses_no_update")
        connection.execute(
            "UPDATE model_responses SET raw_response_ref = 'wrong/run/response.json'"
        )
        connection.execute("DROP TRIGGER backlog_heads_monotonic_update")
        connection.execute("UPDATE backlog_heads SET current_version = 2")

    with readonly_sqlite_snapshot(database) as snapshot:
        authority = ReadonlyM3ArtifactRepository(snapshot).scan(RUN_ID)

    assert any(
        failure.failure_type == M3AuthorityFailureType.INDEX_MISMATCH
        and failure.inventory_kind.value == "MODEL_RESPONSE"
        for failure in authority.failures
    )
    assert any(
        failure.failure_type == M3AuthorityFailureType.REFERENCE_INVALID
        and failure.inventory_kind.value == "BACKLOG_HEAD"
        and failure.reason_code == "BACKLOG_HEAD_BINDING_MISMATCH"
        for failure in authority.failures
    )
