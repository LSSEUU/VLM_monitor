from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_replay_locked_m4_source import (
    M6ReplayLockedM4PrePolicyProjection,
    M6ReplayLockedM4SourceError,
    M6ReplayLockedM4SourceErrorCode,
    assemble_m6_replay_locked_closed_policy_m4_predecessor_projection,
)
from labcourt.application.m6_verified_projection_context import M6SqliteProjectionAssembly
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, TimelineEntry, UsageSummary
from labcourt.contracts.enums import AuditAction, CaseStatus
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.verdicts import ProceduralReview
from labcourt.domain.m6_procedural_gate_authority import (
    M6ProceduralGateExecutionInput,
)
from labcourt.domain.m6_semantic_projection import (
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)
from tests.unit.test_m6_replay_locked_m4_source import _terminal_source


def _document_sha256(case: Case) -> str:
    document = canonical_json(case.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _ready_terminal_source(
    monkeypatch: pytest.MonkeyPatch,
) -> M6ReplayLockedM4GateTerminalSource:
    def passed_review(execution: M6ProceduralGateExecutionInput) -> ProceduralReview:
        verdict = execution.verdict
        return ProceduralReview(
            run_id=verdict.run_id,
            case_id=verdict.case_id,
            version=execution.review_version,
            evidence_pack_id=verdict.evidence_pack_id,
            evidence_pack_version=verdict.evidence_pack_version,
            reviewed_verdict_id=verdict.verdict_id,
            reviewed_verdict_version=verdict.version,
            reviewed_verdict_sha256=verdict.verdict_sha256,
            gate_version=execution.gate_config.gate_version,
            manifest_id=verdict.manifest_id,
        )

    monkeypatch.setattr(
        M6ProceduralGateExecutionInput,
        "rebuild_review",
        passed_review,
    )
    source = _terminal_source(monkeypatch)
    assert source.projection_context.case.status is CaseStatus.READY_FOR_ALERT_POLICY
    return source


def _closed_successor(ready: Case) -> Case:
    return ready.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "final_decision": ready.verdicts[-1].decision,
            "timeline": (
                *ready.timeline,
                TimelineEntry(
                    sequence=len(ready.timeline),
                    action=AuditAction.CASE_CLOSED.value,
                    stage="ALERT_POLICY",
                    object_ref=ready.case_id,
                    details={
                        "alert_id": "NONE",
                        "disposition": "CLOSE_NO_ALERT",
                        "status": CaseStatus.CLOSED.value,
                    },
                ),
            ),
        }
    )


def _closed_cut(
    source: M6ReplayLockedM4GateTerminalSource,
    *,
    closed_case: Case | None = None,
    revision_delta: int = 1,
    source_identity_sha256: str | None = None,
) -> tuple[M6ReplayInputClosureAuthority, M6SqliteProjectionAssembly]:
    ready = source.projection_context.case
    closed = closed_case or _closed_successor(ready)
    closed_revision = source.source_snapshot.source_case_revision + revision_delta
    context = M6VerifiedProjectionContext(
        case=closed,
        perception=source.projection_context.perception,
        historical_source_run_id=source.projection_context.historical_source_run_id,
        historical_source_case_id=source.projection_context.historical_source_case_id,
        historical_source_manifest_id=(source.projection_context.historical_source_manifest_id),
        model_reference_authority=(source.projection_context.model_reference_authority),
        procedural_gate_authority=(source.projection_context.procedural_gate_authority),
        model_responses=source.projection_context.model_responses,
        retrieval_cycles=source.projection_context.retrieval_cycles,
        acquisitions=source.projection_context.acquisitions,
    )
    closure = M6ReplayInputClosureAuthority.model_validate(
        {
            **source.closure.model_dump(mode="json", exclude_computed_fields=True),
            "source_case_revision": closed_revision,
            "source_case_document_sha256": _document_sha256(closed),
        }
    )
    snapshot = build_m6_case_replay_snapshot(
        context=context,
        sample_id=closure.sample_id,
        source_case_revision=closed_revision,
    )
    return closure, M6SqliteProjectionAssembly(
        source_identity_sha256=(source_identity_sha256 or source.source_identity_sha256),
        closure=closure,
        model_calls=closure.model_calls,
        embeddings=(),
        projection_context=context,
        case_replay_snapshot=snapshot,
    )


def _project(
    source: M6ReplayLockedM4GateTerminalSource,
    closure: M6ReplayInputClosureAuthority,
    assembly: M6SqliteProjectionAssembly,
    *,
    hearing_verdict_binding: object | None = None,
) -> M6ReplayLockedM4PrePolicyProjection:
    return assemble_m6_replay_locked_closed_policy_m4_predecessor_projection(
        catalog_closure=closure,
        closed_projection_assembly=assembly,
        ready_case=source.projection_context.case,
        ready_case_revision=source.source_snapshot.source_case_revision,
        hearing_record=source.hearing_record,
        hearing_verdict_binding=(
            source.hearing_verdict_binding
            if hearing_verdict_binding is None
            else hearing_verdict_binding
        ),
        gate_current_closure_receipt=source.gate_current_closure_receipt,
    )


def test_closed_m4_predecessor_retains_real_catalog_cut_but_only_ready_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _ready_terminal_source(monkeypatch)
    closure, assembly = _closed_cut(source)

    projection = _project(source, closure, assembly)

    assert projection.catalog_closure == closure
    assert projection.projection_context == source.projection_context
    assert projection.source_snapshot == source.source_snapshot
    assert projection.hearing_record == source.hearing_record
    assert projection.hearing_verdict_binding == source.hearing_verdict_binding
    assert projection.gate_current_closure_receipt == (source.gate_current_closure_receipt)
    assert projection.projection_context.case.status is CaseStatus.READY_FOR_ALERT_POLICY
    assert not hasattr(projection, "private_ready_selector")
    assert not hasattr(projection, "closed_projection_assembly")
    assert not hasattr(projection, "closed_case")
    assert not hasattr(projection, "source_alert_policy")


def test_closed_m4_predecessor_rejects_cross_snapshot_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _ready_terminal_source(monkeypatch)
    closure, assembly = _closed_cut(
        source,
        source_identity_sha256="f" * 64,
    )

    with pytest.raises(M6ReplayLockedM4SourceError) as raised:
        _project(source, closure, assembly)

    assert raised.value.code == (M6ReplayLockedM4SourceErrorCode.SNAPSHOT_IDENTITY_MISMATCH)


def test_closed_m4_predecessor_rejects_non_adjacent_case_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _ready_terminal_source(monkeypatch)
    closure, assembly = _closed_cut(source, revision_delta=2)

    with pytest.raises(M6ReplayLockedM4SourceError) as raised:
        _project(source, closure, assembly)

    assert raised.value.code == M6ReplayLockedM4SourceErrorCode.SOURCE_SCOPE_MISMATCH


def test_closed_m4_predecessor_rejects_non_policy_case_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _ready_terminal_source(monkeypatch)
    closed = _closed_successor(source.projection_context.case)
    drifted = closed.model_copy(
        update={
            "usage": UsageSummary(
                input_tokens=closed.usage.input_tokens + 1,
            )
        }
    )
    closure, assembly = _closed_cut(source, closed_case=drifted)

    with pytest.raises(M6ReplayLockedM4SourceError) as raised:
        _project(source, closure, assembly)

    assert raised.value.code == M6ReplayLockedM4SourceErrorCode.SOURCE_SCOPE_MISMATCH


def test_closed_m4_predecessor_rejects_hearing_binding_graft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _ready_terminal_source(monkeypatch)
    closure, assembly = _closed_cut(source)
    foreign_binding = source.hearing_verdict_binding.model_copy(
        update={"hearing_record_id": "f" * 64}
    )

    with pytest.raises(M6ReplayLockedM4SourceError) as raised:
        _project(
            source,
            closure,
            assembly,
            hearing_verdict_binding=foreign_binding,
        )

    assert raised.value.code == M6ReplayLockedM4SourceErrorCode.ROUTE_REJECTED
