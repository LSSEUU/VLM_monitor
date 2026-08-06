from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import replace
from pathlib import Path

from pydantic import BaseModel

from labcourt.adapters.storage.m6_regression_execution_source_catalog_store import (
    M6RegressionExecutionSourceCatalogPublisher,
    ReadonlyM6RegressionExecutionSourceCatalogStore,
)
from labcourt.adapters.storage.m6_source_authority_store import M6SourceAuthorityPublisher
from labcourt.adapters.storage.m6_upgrade_candidate_source_seal import (
    ReadonlyM6UpgradeCandidateSourceSealProvider,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_candidate_run_cut import (
    SQLiteM6UpgradeCandidateRunCutRepository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_observation_v3 import (
    SQLiteM6UpgradeExecutionObservationV3Repository,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_pending_sample_commitment_v3 import (
    SQLiteM6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.application.m6_regression_source_catalog import (
    M6RegressionSourceCatalogBundle,
    build_m6_regression_source_catalog,
)
from labcourt.application.m6_source_authority_builder import (
    M6SealedSourceBundle,
    build_m6_sealed_source_bundle,
)
from labcourt.application.m6_source_authority_sealing import M6SealedGateSource
from labcourt.application.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorServiceV3,
)
from labcourt.application.m6_upgrade_candidate_observation_producer import (
    M6PrecomputedNoCaseObservationProducerV3,
)
from labcourt.application.m6_upgrade_candidate_perception_materializer import (
    M6PrecomputedCandidatePerceptionMaterializerV3,
)
from labcourt.application.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderServiceV3,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import BBoxXYXY, Detection
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression import (
    M6BaselineAuthorityKind,
    M6CaseReplaySnapshot,
    M6ChallengeKind,
    M6RegressionDatasetEntry,
    M6RegressionDatasetKind,
    M6RegressionDatasetSnapshot,
    M6RegressionDisposition,
    M6ReplayExecutionOutcome,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedDetectionInput,
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeExecutionScopeAuthority
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactKind
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.m6_regression_dataset import (
    M6RegressionRequiredSource,
    M6RegressionRunScopeObservation,
)
from labcourt.ports.pixels import RGB8Frame, rgb8_pixel_sha256
from labcourt.services.m6_upgrade_regression import run_m6_upgrade_regression_v3
from tests.contract.test_m6_regression_contracts import _appeal_truth, _baseline_snapshot
from tests.integration.test_m6_upgrade_candidate_coordinator_v3 import (
    _PostSealValidationReportProvider,
)
from tests.integration.test_m6_upgrade_candidate_output_builder_v3 import (
    _terminal_builder,
)
from tests.integration.test_m6_upgrade_whole_sample_record_builder_v3 import (
    BUSY_TIMEOUT_MS,
    _builder,
    _ExactArtifactVerifier,
    _PixelProvider,
)
from tests.unit.test_m6_regression_execution_source_catalog import _execution_scope
from tests.unit.test_m6_regression_source_catalog import _observation
from tests.unit.test_m6_source_authority import _bundle
from tests.unit.test_m6_source_authority_builder import _inputs


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _model_sha(value: BaseModel) -> str:
    return _sha(canonical_json(value.model_dump(mode="json")))


class _SourcePerception:
    def __init__(self, values: dict[str, M6ResolvedPerception]) -> None:
        self.values = values
        self.calls: list[str] = []

    def assemble(self, closure: M6ReplayInputClosureAuthority) -> M6ResolvedPerception:
        authority_id = closure.replay_input_closure_authority_id
        self.calls.append(authority_id)
        return self.values[authority_id]


def _rebind_source_run(
    gate_source: M6SealedGateSource,
    report: M5ArtifactValidationReport,
    run_id: str,
) -> tuple[M6SealedGateSource, M5ArtifactValidationReport]:
    source_case = gate_source.source_case
    source_pack = source_case.evidence_packs[0]
    pack = source_pack.model_copy(
        update={
            "run_id": run_id,
            "closure_report": source_pack.closure_report.model_copy(update={"run_id": run_id}),
        }
    )
    source_screening = source_case.screening_results[0]
    screening = source_screening.model_copy(
        update={
            "run_id": run_id,
            "parsed_output": source_screening.parsed_output.model_copy(update={"run_id": run_id}),
        }
    )
    verdict = source_case.verdicts[0].model_copy(
        update={"run_id": run_id, "screening_id": screening.screening_id}
    )
    review = source_case.procedural_reviews[0].model_copy(
        update={
            "run_id": run_id,
            "reviewed_verdict_id": verdict.verdict_id,
            "reviewed_verdict_sha256": verdict.verdict_sha256,
        }
    )
    rebound_case = source_case.model_copy(
        update={
            "run_id": run_id,
            "status": CaseStatus.CLOSED,
            "evidence_packs": (pack,),
            "screening_results": (screening,),
            "verdicts": (verdict,),
            "procedural_reviews": (review,),
            "final_decision": verdict.decision,
        }
    )
    rebound_case = type(source_case).model_validate(rebound_case.model_dump(mode="json"))
    closures = tuple(
        item.model_copy(
            update={
                "run_id": run_id,
                "source_review_id": review.review_id,
                "source_review_document_sha256": _model_sha(review),
                "evidence_pack_id": pack.pack_id,
                "evidence_pack_document_sha256": _model_sha(pack),
                "current_closure": item.current_closure.model_copy(update={"run_id": run_id}),
            }
        )
        for item in gate_source.gate_current_closures
    )
    rebound_gate = replace(
        gate_source,
        source_case=rebound_case,
        source_case_document_sha256=_model_sha(rebound_case),
        gate_current_closures=closures,
    )
    m4_report = report.predecessor_report
    assert m4_report is not None
    m3_report = m4_report.m3_report
    m2_report = m3_report.m2_report.model_copy(update={"run_id": run_id})
    m3_report = m3_report.model_copy(update={"run_id": run_id, "m2_report": m2_report})
    m4_report = m4_report.model_copy(update={"run_id": run_id, "m3_report": m3_report})
    rebound_report = report.model_copy(update={"run_id": run_id, "predecessor_report": m4_report})
    return rebound_gate, rebound_report


def _source_cut() -> tuple[
    object,
    tuple[M6SealedSourceBundle, ...],
    tuple[M6RegressionRunScopeObservation, ...],
    tuple[RGB8Frame, ...],
    tuple[Detection, ...],
]:
    template = _bundle()
    selection, gate_source, manifest, report = _inputs(template)
    sealed_sources: list[M6SealedSourceBundle] = []
    scopes: list[M6RegressionRunScopeObservation] = []
    rgb_frames: list[RGB8Frame] = []
    detections: list[Detection] = []
    for index, run_id in enumerate(("m6-full-source-a", "m6-full-source-b")):
        rebound_gate, rebound_report = _rebind_source_run(gate_source, report, run_id)
        pixels = bytes((index + 1, index + 2, index + 3) * 100)
        frame = FrameRef(
            camera_id="cam-01",
            stream_id=f"m6-full-{index}",
            frame_index=90 + index,
            fps_num=30,
            fps_den=1,
            width=10,
            height=10,
            content_sha256=rgb8_pixel_sha256(10, 10, pixels),
        )
        detection = Detection(
            detection_id=f"m6-full-precomputed-detection-{index}",
            frame_id=frame.frame_id,
            label="person",
            bbox=BBoxXYXY(x1=1, y1=1, x2=5, y2=8),
            score=0.9,
            model_manifest_id=manifest.models["detector"].model_manifest_id,
        )
        frame_document = canonical_json(frame.model_dump(mode="json"))
        detection_document = canonical_json(detection.model_dump(mode="json"))
        rebound_selection = replace(
            selection,
            sample_id=_sha(f"m6-full-precomputed-sample-{index}"),
            source_run_id=run_id,
            frames=(
                M6LockedFrameInput(
                    frame_id=frame.frame_id,
                    document_sha256=_sha(frame_document),
                    content_sha256=frame.content_sha256 or "",
                ),
            ),
            detections=(
                M6LockedDetectionInput(
                    detection_id=detection.detection_id,
                    frame_id=detection.frame_id,
                    document_sha256=_sha(detection_document),
                    model_manifest_id=detection.model_manifest_id,
                ),
            ),
        )
        sealed = build_m6_sealed_source_bundle(
            selection=rebound_selection,
            gate_source=rebound_gate,
            source_manifest=manifest,
            source_validation_report=rebound_report,
            config=template.config,
        )
        required = M6RegressionRequiredSource(
            source_run_id=sealed.seal.source_run_id,
            source_case_id=sealed.seal.source_case_id,
            source_case_revision=sealed.seal.source_case_revision,
            source_case_document_sha256=sealed.seal.source_case_document_sha256,
            source_manifest_id=sealed.seal.source_manifest_id,
        )
        scopes.append(
            M6RegressionRunScopeObservation(
                source_identity_sha256=_sha("m6-full-source-snapshot"),
                source_run_id=sealed.seal.source_run_id,
                audit_head_sequence=sealed.seal.audit_head_sequence,
                audit_head_hash=sealed.seal.audit_head_hash,
                m5_validation_report=sealed.source_validation_report,
                m5_validation_report_document=sealed.source_validation_report_document,
                required_sources=(required,),
            )
        )
        sealed_sources.append(sealed)
        rgb_frames.append(RGB8Frame(frame=frame, pixels=pixels))
        detections.append(detection)
    return (
        template.config,
        tuple(sealed_sources),
        tuple(scopes),
        tuple(rgb_frames),
        tuple(detections),
    )


def _evaluator_dataset(
    scope: M6UpgradeExecutionScopeAuthority,
    catalog: M6RegressionSourceCatalogBundle,
    sealed_sources: tuple[M6SealedSourceBundle, ...],
) -> M6RegressionDatasetSnapshot:
    source_by_sample = {item.seal.sample_id: item for item in sealed_sources}
    entries: list[M6RegressionDatasetEntry] = []
    for index, execution_entry in enumerate(scope.execution_dataset.entries):
        source = source_by_sample[execution_entry.sample_id]
        baseline = _baseline_snapshot(f"m6-full-{index}").model_copy(
            update={
                "sample_id": execution_entry.sample_id,
                "source_run_id": source.seal.source_run_id,
                "source_case_id": source.seal.source_case_id,
                "source_case_revision": source.seal.source_case_revision,
                "source_case_document_sha256": source.seal.source_case_document_sha256,
                "manifest_id": scope.execution_dataset.baseline_manifest_id,
            }
        )
        baseline = M6CaseReplaySnapshot.model_validate(baseline.model_dump(mode="json"))
        if index == 0:
            authority_kind = M6BaselineAuthorityKind.MACHINE_TERMINAL_CASE
            memberships = (
                M6RegressionDatasetKind.STABILITY,
                M6RegressionDatasetKind.CHALLENGE,
            )
            challenge_kinds = (M6ChallengeKind.DIFFICULT_NEGATIVE,)
            gold_truth = None
        else:
            authority_kind = M6BaselineAuthorityKind.PRE_APPEAL_CLOSED_CASE
            memberships = (M6RegressionDatasetKind.GOLD,)
            challenge_kinds = ()
            gold_truth = _appeal_truth(baseline)
        entries.append(
            M6RegressionDatasetEntry(
                sample_id=execution_entry.sample_id,
                input_authority_id=execution_entry.input_authority_id,
                input_authority_document_sha256=(execution_entry.input_authority_document_sha256),
                replay_input_closure_authority_id=(
                    execution_entry.replay_input_closure_authority_id
                ),
                replay_input_closure_document_sha256=(
                    execution_entry.replay_input_closure_document_sha256
                ),
                baseline_authority_kind=authority_kind,
                baseline_authority_id=baseline.snapshot_id,
                baseline_authority_document_sha256=_model_sha(baseline),
                baseline_snapshot=baseline,
                memberships=memberships,
                gold_truth=gold_truth,
                challenge_kinds=challenge_kinds,
            )
        )
    cut = catalog.source_inventory_cut
    return M6RegressionDatasetSnapshot(
        baseline_manifest_id=scope.execution_dataset.baseline_manifest_id,
        execution_dataset=scope.execution_dataset,
        source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
        source_inventory_cut_document_sha256=(catalog.source_inventory_cut_content_sha256),
        source_inventory_item_count=cut.source_item_count,
        source_inventory_root_sha256=cut.source_inventory_root_sha256,
        eligibility_policy_authority_id=_sha("m6-full-eligibility-policy"),
        eligibility_policy_document_sha256=_sha("m6-full-eligibility-policy-document"),
        selection_inventory_authority_id=_sha("m6-full-selection-inventory"),
        selection_inventory_document_sha256=_sha("m6-full-selection-document"),
        selection_receipt_count=len(entries),
        selection_inventory_root_sha256=_sha("m6-full-selection-root"),
        entries=tuple(entries),
    )


def test_real_sqlite_coordinator_publishes_terminal_v3_regression_report(
    tmp_path: Path,
) -> None:
    source_config, sealed_sources, source_scopes, rgb_frames, source_detections = _source_cut()
    source_root = tmp_path / "source-authority"
    source_publisher = M6SourceAuthorityPublisher(source_root)
    for sealed_source in sealed_sources:
        source_publisher.publish(sealed_source, config=source_config)
    catalog_bundle = build_m6_regression_source_catalog(
        run_scopes=source_scopes,
        sealed_sources=tuple(_observation(item) for item in sealed_sources),
    )
    catalog_root = tmp_path / "candidate-catalog"
    stored_catalog = M6RegressionExecutionSourceCatalogPublisher(catalog_root).publish(
        catalog_bundle.execution_source_catalog,
        catalog_bundle.execution_source_catalog_document,
    )
    scope = _execution_scope(stored_catalog.source_catalog, stored_catalog.content_sha256)

    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    evidence = SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS)
    evidence.register_run(scope.candidate_run_id, scope.candidate_manifest)
    pixels = _PixelProvider(rgb_frames[0], additional_frames=rgb_frames[1:])
    verifier = _ExactArtifactVerifier()
    ledger = SQLiteM6UpgradeExecutionLedgerV3Repository(
        database,
        BUSY_TIMEOUT_MS,
        sample_artifact_verifier=verifier,
    )
    observations = SQLiteM6UpgradeExecutionObservationV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    commitments = SQLiteM6UpgradePendingSampleCommitmentV3Repository(
        database,
        BUSY_TIMEOUT_MS,
    )
    source_perception = _SourcePerception(
        {
            sealed_source.replay_input_closure.replay_input_closure_authority_id: (
                M6ResolvedPerception(
                    frames=(rgb_frame.frame,),
                    detections=(source_detection,),
                )
            )
            for sealed_source, rgb_frame, source_detection in zip(
                sealed_sources,
                rgb_frames,
                source_detections,
                strict=True,
            )
        }
    )
    materializer = M6PrecomputedCandidatePerceptionMaterializerV3(
        ledger_repository=ledger,
        source_catalog_provider=ReadonlyM6RegressionExecutionSourceCatalogStore(catalog_root),
        source_seal_provider=ReadonlyM6UpgradeCandidateSourceSealProvider(source_root),
        source_perception_reader=source_perception,
        candidate_perception_writer=evidence,
    )
    producer = M6PrecomputedNoCaseObservationProducerV3(
        ledger_repository=ledger,
        source_catalog_provider=ReadonlyM6RegressionExecutionSourceCatalogStore(catalog_root),
        perception_materializer=materializer,
    )
    appender = M6UpgradeDurableSampleAppenderServiceV3(
        ledger_repository=ledger,
        commitment_repository=commitments,
        record_builder=_builder(database, pixels),
    )
    events: list[str] = []
    run_cuts = SQLiteM6UpgradeCandidateRunCutRepository(
        database,
        BUSY_TIMEOUT_MS,
        validation_report_provider=_PostSealValidationReportProvider(ledger, scope, events),
    )
    coordinator = M6UpgradeCandidateCoordinatorServiceV3(
        ledger_repository=ledger,
        observation_repository=observations,
        observation_producer=producer,
        sample_appender=appender,
        run_cut_repository=run_cuts,
        candidate_output_builder=_terminal_builder(database, pixels),
    )

    evaluator_dataset = _evaluator_dataset(scope, catalog_bundle, sealed_sources)
    run_result = run_m6_upgrade_regression_v3(
        execution_scope=scope,
        evaluator_dataset=evaluator_dataset,
        evaluator_dataset_document=canonical_json(evaluator_dataset.model_dump(mode="json")),
        coordinator=coordinator,
        output_root=tmp_path / "regression-output",
    )
    inventory = run_result.stored_bundle.candidate_output_inventory
    assert isinstance(inventory, M6UpgradeCandidateOutputInventoryAuthorityV3)

    assert inventory.schema_version == "m6-upgrade-candidate-output-inventory-authority-v3"
    assert inventory.output_count == 2
    assert inventory.candidate_case_count == 0
    assert inventory.model_call_count == 0
    assert all(item.outcome == M6ReplayExecutionOutcome.NO_CASE for item in inventory.outputs)
    assert inventory.execution_observations[0].artifacts[0].kind in {
        M6UpgradePhysicalArtifactKind.FRAME,
        M6UpgradePhysicalArtifactKind.DETECTION,
    }
    assert all(item.detection_count == 1 for item in inventory.outputs)
    assert source_perception.calls == [
        item.replay_input_closure.replay_input_closure_authority_id
        for item in stored_catalog.source_catalog.entries
    ]
    assert verifier.calls == list(inventory.execution_ledger.sample_executions)
    assert Counter(pixels.requested_ids) == Counter({item.frame.frame_id: 3 for item in rgb_frames})
    for rgb_frame in rgb_frames:
        assert (
            evidence.load_frame(scope.candidate_run_id, rgb_frame.frame.frame_id) == rgb_frame.frame
        )
    assert events == ["validation-report"]

    assert run_result.publication_result.report_path.name == "regression.json"
    assert run_result.stored_bundle.report == run_result.report_bundle.report
    assert run_result.stored_bundle.report.disposition == M6RegressionDisposition.FAILED
    assert run_result.stored_bundle.report.release_allowed is False
