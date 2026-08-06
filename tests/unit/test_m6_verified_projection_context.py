from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, fields, replace
from unittest.mock import patch

import pytest

from labcourt.application.m6_hearing_model_call_authority import (
    derive_m6_hearing_model_call_authority_root,
)
from labcourt.application.m6_model_call_authority import (
    assemble_m6_locked_screening_model_calls,
)
from labcourt.application.m6_verified_projection_context import (
    M6SqliteProjectionAssembly,
    M6SqliteProjectionAssemblyError,
    M6SqliteProjectionAssemblyErrorCode,
    assemble_m6_sqlite_projection_authority,
)
from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import AlertLevel
from labcourt.contracts.m6_replay_locked import (
    M6HistoricalCausalCut,
    M6LockedDetectionInput,
    M6LockedFrameInput,
    M6LockedModelCallInput,
    M6LockedRetrievalCycleInput,
    M6LockedRetrievalOutcomeKind,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
    M6ReplayInputClosureAuthority,
)
from labcourt.ports.m6_acquisition_authority import (
    M6ValidatedM4ReplayAuthoritySnapshot,
)
from labcourt.ports.m6_embeddings import M6EmbeddingAuthoritySnapshot
from labcourt.ports.m6_historical_retrieval import (
    M6ValidatedHistoricalRetrievalSnapshots,
)
from labcourt.ports.m6_model_calls import (
    M6M3ModelCallAuthoritySnapshot,
    M6M4ModelCallAuthoritySnapshot,
)
from labcourt.ports.m6_perception import M6PerceptionAuthoritySnapshot
from tests.unit.test_m6_model_call_authority import (
    _response_snapshot,
    _source_case,
)
from tests.unit.test_m6_perception_authority import (
    _detection_document,
    _frame,
    _frame_document,
    _manifest,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _AuthorityBundle:
    case: Case
    closure: M6ReplayInputClosureAuthority
    perception: M6PerceptionAuthoritySnapshot
    m3: M6M3ModelCallAuthoritySnapshot
    m4: M6M4ModelCallAuthoritySnapshot
    historical: M6ValidatedHistoricalRetrievalSnapshots
    acquisition: M6ValidatedM4ReplayAuthoritySnapshot
    embedding: M6EmbeddingAuthoritySnapshot


def _bundle(
    *,
    source_case: Case | None = None,
    m3_snapshot: M6M3ModelCallAuthoritySnapshot | None = None,
    closure_model_calls: tuple[M6LockedModelCallInput, ...] | None = None,
    historical_cut: M6HistoricalCausalCut | None = None,
) -> _AuthorityBundle:
    default_case, _pack = _source_case()
    case = source_case or default_case
    identity = _sha("one-private-sqlite-snapshot")
    manifest, manifest_document = _manifest()
    case_document = canonical_json(case.model_dump(mode="json"))
    frame = _frame(90).model_copy(update={"width": 1280, "height": 720})
    frame_document = _frame_document(frame, run_id=case.run_id)
    source_crop = next(
        crop
        for pack in case.evidence_packs
        for crop in pack.crops
        if any(ref.artifact_id == "det-bottle-090" for ref in crop.source_refs)
    )
    detection = Detection(
        detection_id="det-bottle-090",
        frame_id=source_crop.frame_id,
        label="reagent_bottle",
        bbox=source_crop.bbox,
        score=0.91,
        track_ref=source_crop.primary_track_ref,
        attributes={"cap_detected": False},
        model_manifest_id=manifest.models["detector"].model_manifest_id,
    )
    detection_document = _detection_document(detection, run_id=case.run_id)
    m3 = m3_snapshot or M6M3ModelCallAuthoritySnapshot(
        source_identity_sha256=identity,
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        requests=(),
        responses=(),
        caches=(),
        usages=(),
        parse_receipts=(),
        parsed_outputs=(),
        failures=(),
    )
    if m3.source_identity_sha256 != identity:
        m3 = replace(m3, source_identity_sha256=identity)
    actual_screening_calls = assemble_m6_locked_screening_model_calls(
        source_case=case,
        snapshot=m3,
    )
    model_calls = actual_screening_calls if closure_model_calls is None else closure_model_calls
    closure = M6ReplayInputClosureAuthority(
        sample_id="sample-sqlite-projection",
        source_run_id=case.run_id,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_document_sha256=_sha(case_document),
        source_manifest_id=case.manifest_id,
        source_manifest_document_sha256=_sha(manifest_document),
        input_authority_id=_sha("unresolved-input-authority"),
        input_authority_document_sha256=_sha("unresolved-input-authority-document"),
        source_validation_report_id=_sha("unresolved-source-validation-report"),
        source_validation_report_document_sha256=_sha(
            "unresolved-source-validation-report-document"
        ),
        frames=(
            M6LockedFrameInput(
                frame_id=frame.frame_id,
                document_sha256=frame_document.document_sha256,
                content_sha256=frame.content_sha256,
            ),
        ),
        detections=(
            M6LockedDetectionInput(
                detection_id=detection.detection_id,
                frame_id=detection.frame_id,
                document_sha256=detection_document.document_sha256,
                model_manifest_id=detection.model_manifest_id,
            ),
        ),
        model_calls=model_calls,
        historical_cut=historical_cut or M6HistoricalCausalCut(),
    )
    perception = M6PerceptionAuthoritySnapshot(
        source_identity_sha256=identity,
        run_id=case.run_id,
        manifest_id=manifest.manifest_id,
        manifest_canonical_document=manifest_document,
        manifest_document_sha256=_sha(manifest_document),
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_canonical_document=case_document,
        source_case_document_sha256=_sha(case_document),
        frames=(frame_document,),
        detections=(detection_document,),
    )
    m4_replay_root = _sha("validated-m4-replay-root")
    m4_call_root = derive_m6_hearing_model_call_authority_root(
        source_identity_sha256=identity,
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        m4_replay_authority_root_sha256=m4_replay_root,
        requests=(),
        responses=(),
        caches=(),
        usages=(),
        parse_receipts=(),
        role_outputs=(),
        failures=(),
    )
    m4 = M6M4ModelCallAuthoritySnapshot(
        source_identity_sha256=identity,
        m4_replay_authority_root_sha256=m4_replay_root,
        model_call_authority_root_sha256=m4_call_root,
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        requests=(),
        responses=(),
        caches=(),
        parse_receipts=(),
        role_outputs=(),
        failures=(),
    )
    historical = M6ValidatedHistoricalRetrievalSnapshots(
        source_identity_sha256=identity,
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        m4_documents=(),
        m5_documents=(),
    )
    acquisition = M6ValidatedM4ReplayAuthoritySnapshot(
        source_identity_sha256=identity,
        run_id=case.run_id,
        documents=(),
    )
    embedding = M6EmbeddingAuthoritySnapshot(
        source_identity_sha256=identity,
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        source_authority_root_sha256=_sha("validated-m5-authority-root"),
        documents=(),
    )
    return _AuthorityBundle(
        case=case,
        closure=closure,
        perception=perception,
        m3=m3,
        m4=m4,
        historical=historical,
        acquisition=acquisition,
        embedding=embedding,
    )


def _assemble(bundle: _AuthorityBundle) -> M6SqliteProjectionAssembly:
    return assemble_m6_sqlite_projection_authority(
        closure=bundle.closure,
        perception_snapshot=bundle.perception,
        m3_snapshot=bundle.m3,
        m4_snapshot=bundle.m4,
        historical_snapshots=bundle.historical,
        acquisition_snapshot=bundle.acquisition,
        embedding_snapshot=bundle.embedding,
    )


def _assert_error(
    code: M6SqliteProjectionAssemblyErrorCode,
    bundle: _AuthorityBundle,
) -> None:
    with pytest.raises(M6SqliteProjectionAssemblyError) as raised:
        _assemble(bundle)
    assert raised.value.code == code


def test_assembles_exact_partial_sqlite_projection_without_claiming_full_verification() -> None:
    bundle = _bundle()

    result = _assemble(bundle)

    assert result.source_identity_sha256 == bundle.perception.source_identity_sha256
    assert result.closure == bundle.closure
    assert result.model_calls == bundle.closure.model_calls == ()
    assert result.embeddings == ()
    assert result.projection_context.case == bundle.case
    assert result.case_replay_snapshot.sample_id == bundle.closure.sample_id
    assert (
        result.case_replay_snapshot.source_case_document_sha256
        == bundle.closure.source_case_document_sha256
    )
    assert {field.name for field in fields(M6SqliteProjectionAssembly)} == {
        "source_identity_sha256",
        "closure",
        "model_calls",
        "embeddings",
        "projection_context",
        "case_replay_snapshot",
    }
    assert not hasattr(result, "verified")
    assert not hasattr(result, "replay_execution_receipt")
    assert not hasattr(result, "candidate_policy_recomputation_authority")


def test_source_alert_is_projected_without_becoming_candidate_policy_proof() -> None:
    source_case, _pack = _source_case()
    alert = AlertDecision(
        alert_id="source-alert-01",
        case_id=source_case.case_id,
        level=AlertLevel.ADVISORY,
        recipients=("lab-supervisor",),
        policy_rule_ids=("source-policy-rule",),
    )
    source_with_alert = Case.model_validate(
        {
            **source_case.model_dump(mode="json", exclude_computed_fields=True),
            "alerts": [alert.model_dump(mode="json")],
        }
    )

    result = _assemble(_bundle(source_case=source_with_alert))

    assert result.projection_context.case.alerts == (alert,)
    assert result.case_replay_snapshot.highest_alert_level == AlertLevel.ADVISORY
    assert not hasattr(result, "candidate_policy_recomputation_authority")
    assert not hasattr(result, "replay_execution_receipt")


def test_requires_one_exact_identity_across_all_six_authority_snapshots() -> None:
    bundle = _bundle()

    _assert_error(
        M6SqliteProjectionAssemblyErrorCode.SNAPSHOT_IDENTITY_MISMATCH,
        replace(
            bundle,
            acquisition=replace(
                bundle.acquisition,
                source_identity_sha256=_sha("another-private-snapshot"),
            ),
        ),
    )


def test_requires_case_binding_and_exact_canonical_case_document() -> None:
    bundle = _bundle()
    no_case = bundle.closure.model_copy(
        update={
            "source_case_id": None,
            "source_case_revision": None,
            "source_case_document_sha256": None,
        }
    )
    _assert_error(
        M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_REQUIRED,
        replace(bundle, closure=no_case),
    )
    _assert_error(
        M6SqliteProjectionAssemblyErrorCode.SOURCE_CASE_DOCUMENT_INVALID,
        replace(
            bundle,
            perception=replace(
                bundle.perception,
                source_case_canonical_document=(
                    f"{bundle.perception.source_case_canonical_document} "
                ),
            ),
        ),
    )


def test_rejects_cross_reader_source_scope_before_semantic_projection() -> None:
    bundle = _bundle()

    _assert_error(
        M6SqliteProjectionAssemblyErrorCode.SOURCE_SCOPE_MISMATCH,
        replace(
            bundle,
            acquisition=replace(bundle.acquisition, run_id="foreign-run"),
        ),
    )


def test_recomputes_exact_combined_model_call_closure() -> None:
    case, m3 = _response_snapshot()
    assert case == _source_case()[0]
    bundle = _bundle(m3_snapshot=m3, closure_model_calls=())

    _assert_error(
        M6SqliteProjectionAssemblyErrorCode.MODEL_CALL_CLOSURE_MISMATCH,
        bundle,
    )


def test_recomputes_exact_historical_cut_before_cycle_resolution() -> None:
    bundle = _bundle()
    forged_cut = M6HistoricalCausalCut(
        retrieval_cycles=(
            M6LockedRetrievalCycleInput(
                source_run_id=bundle.case.run_id,
                source_case_id=bundle.case.case_id,
                hearing_session_id=_sha("hearing-session-01"),
                cycle_index=1,
                cycle_scope_id=_sha("hearing-cycle-01"),
                outcome=M6LockedRetrievalOutcomeKind.DEGRADED,
                authority_ref=M6ReplayAuthorityRef(
                    kind=M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT,
                    artifact_id="retrieval-receipt-01",
                    document_sha256=_sha("retrieval-receipt-document"),
                ),
            ),
        )
    )
    mismatch = _bundle(historical_cut=forged_cut)

    _assert_error(
        M6SqliteProjectionAssemblyErrorCode.HISTORICAL_CUT_MISMATCH,
        mismatch,
    )


def test_converts_projection_context_and_snapshot_construction_failures_to_typed_errors() -> None:
    bundle = _bundle()
    with patch(
        "labcourt.application.m6_verified_projection_context.M6VerifiedProjectionContext",
        side_effect=ValueError("injected context defect"),
    ):
        _assert_error(
            M6SqliteProjectionAssemblyErrorCode.PROJECTION_CONTEXT_INVALID,
            bundle,
        )
    with patch(
        "labcourt.application.m6_verified_projection_context.build_m6_case_replay_snapshot",
        side_effect=ValueError("injected snapshot defect"),
    ):
        _assert_error(
            M6SqliteProjectionAssemblyErrorCode.CASE_REPLAY_SNAPSHOT_INVALID,
            bundle,
        )


def test_revalidates_forged_closure_instances() -> None:
    bundle = _bundle()
    forged = copy.deepcopy(bundle.closure)
    object.__setattr__(forged, "source_run_id", "invalid run id")

    _assert_error(
        M6SqliteProjectionAssemblyErrorCode.INVALID_ARGUMENT,
        replace(bundle, closure=forged),
    )
