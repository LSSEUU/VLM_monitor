from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_model_call_authority import (
    assemble_m6_locked_screening_model_calls,
)
from labcourt.application.m6_model_reference_authority import (
    assemble_m6_case_model_reference_authority,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AlertConfig, ProceduralGateConfig
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.m6_replay_locked import (
    M6LockedDetectionInput,
    M6LockedFrameInput,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
)
from labcourt.domain.m6_semantic_projection import (
    M6ResolvedPerception,
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)
from labcourt.ports.m6_acquisition_authority import M6ValidatedM4ReplayAuthoritySnapshot
from labcourt.ports.m6_model_calls import M6M3ModelCallAuthoritySnapshot
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
)
from tests.unit.test_m6_model_reference_authority import _fast_case, _repair_snapshot
from tests.unit.test_m6_semantic_projection import (
    _alert_config,
    _current_closure,
    _gate_config,
    _resolved_perception,
)
from tests.unit.test_m6_source_authority import _bundle


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _terminal_source(
    *,
    gate_config: ProceduralGateConfig | None = None,
    alert_config: AlertConfig | None = None,
    m3_snapshot: M6M3ModelCallAuthoritySnapshot | None = None,
) -> M6ReplayLockedFastTerminalSource:
    m3 = m3_snapshot or _repair_snapshot()
    fast_case = _fast_case(m3)
    pack = fast_case.evidence_packs[0]
    verdict = fast_case.verdicts[0]
    provisional_gate = M6ProceduralGateExecutionInput(
        source_review_id="provisional-fast-review",
        source_review_document_sha256="0" * 64,
        verdict=verdict,
        evidence_pack=pack,
        current_closure=_current_closure(pack),
        gate_config=gate_config or _gate_config(),
        alert_config=alert_config or _alert_config(),
        review_version=1,
    )
    review = provisional_gate.rebuild_review()
    case = Case.model_validate(
        {
            **fast_case.model_dump(mode="json", exclude_computed_fields=True),
            "status": (
                CaseStatus.READY_FOR_ALERT_POLICY.value
                if review.passed
                else CaseStatus.REWORK_REQUIRED.value
            ),
            "procedural_reviews": (review.model_dump(mode="json"),),
        }
    )
    references = assemble_m6_case_model_reference_authority(
        source_case=case,
        m3_snapshot=m3,
        m4_snapshot=M6ValidatedM4ReplayAuthoritySnapshot(
            source_identity_sha256=m3.source_identity_sha256,
            run_id=case.run_id,
            documents=(),
        ),
    )
    gate_input = M6ProceduralGateExecutionInput(
        source_review_id=review.review_id,
        source_review_document_sha256=_sha(canonical_json(review.model_dump(mode="json"))),
        verdict=verdict,
        evidence_pack=pack,
        current_closure=provisional_gate.current_closure,
        gate_config=provisional_gate.gate_config,
        alert_config=provisional_gate.alert_config,
        review_version=review.version,
    )
    gates = M6CaseProceduralGateAuthority(
        source_identity_sha256=m3.source_identity_sha256,
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        inputs=(gate_input,),
    )
    calls = assemble_m6_locked_screening_model_calls(
        source_case=case,
        snapshot=m3,
    )
    raw_perception = _resolved_perception(case)
    source_manifest = RunManifest.model_validate_json(
        _bundle().snapshot.source_manifest_canonical_document
    )
    perception = M6ResolvedPerception(
        frames=raw_perception.frames,
        detections=tuple(
            item.model_copy(
                update={"model_manifest_id": (source_manifest.models["detector"].model_manifest_id)}
            )
            for item in raw_perception.detections
        ),
    )
    context = M6VerifiedProjectionContext(
        case=case,
        perception=perception,
        historical_source_run_id=case.run_id,
        historical_source_case_id=case.case_id,
        historical_source_manifest_id=case.manifest_id,
        model_reference_authority=references,
        procedural_gate_authority=gates,
        model_responses=resolve_m6_locked_model_responses(calls),
    )
    document = canonical_json(case.model_dump(mode="json"))
    closure = M6ReplayInputClosureAuthority(
        sample_id="fast-terminal-source-sample",
        source_run_id=case.run_id,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_document_sha256=_sha(document),
        source_manifest_id=case.manifest_id,
        source_manifest_document_sha256=(_bundle().snapshot.source_manifest_document_sha256),
        input_authority_id=_sha("fast-source-input-authority"),
        input_authority_document_sha256=_sha("fast-source-input-document"),
        source_validation_report_id=_sha("fast-source-validation-report"),
        source_validation_report_document_sha256=_sha("fast-source-validation-document"),
        frames=tuple(
            M6LockedFrameInput(
                frame_id=item.frame_id,
                document_sha256=_sha(canonical_json(item.model_dump(mode="json"))),
                content_sha256=item.content_sha256,
            )
            for item in perception.frames
        ),
        detections=tuple(
            M6LockedDetectionInput(
                detection_id=item.detection_id,
                frame_id=item.frame_id,
                document_sha256=_sha(canonical_json(item.model_dump(mode="json"))),
                model_manifest_id=item.model_manifest_id,
            )
            for item in perception.detections
        ),
        model_calls=calls,
    )
    snapshot = build_m6_case_replay_snapshot(
        context=context,
        sample_id=closure.sample_id,
        source_case_revision=1,
    )
    return M6ReplayLockedFastTerminalSource(
        source_identity_sha256=m3.source_identity_sha256,
        closure=closure,
        projection_context=context,
        source_snapshot=snapshot,
    )


def test_fast_terminal_source_closes_one_m3_verdict_and_gate_without_raw_bodies() -> None:
    source = _terminal_source()

    assert source.source_snapshot.semantic_case_hash
    assert len(source.projection_context.model_responses) == 2
    assert source.projection_context.retrieval_cycles == ()
    assert source.projection_context.model_reference_authority.verdict_bindings == ()
    assert len(source.projection_context.model_reference_authority.fast_verdict_bindings) == 1


def test_fast_terminal_source_rejects_a_forged_semantic_snapshot() -> None:
    source = _terminal_source()
    roots = list(source.source_snapshot.stage_roots)
    roots[-1] = roots[-1].model_copy(update={"projection_sha256": "f" * 64})

    with pytest.raises(ValueError):
        M6ReplayLockedFastTerminalSource(
            source_identity_sha256=source.source_identity_sha256,
            closure=source.closure,
            projection_context=source.projection_context,
            source_snapshot=source.source_snapshot.model_copy(update={"stage_roots": tuple(roots)}),
        )
