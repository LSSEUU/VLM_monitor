from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

import pytest
from pydantic import BaseModel

import tests.unit.test_m4_hearing_procedural_review as m4_fixture
from labcourt.application.m6_procedural_gate_authority import (
    M6ProceduralGateAuthorityError,
    M6ProceduralGateAuthorityErrorCode,
    assemble_m6_candidate_case_procedural_gate_authority,
)
from labcourt.application.m6_source_authority_sealing import M6SealedGateSource
from labcourt.contracts.cases import Case
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m6_regression_execution import M6UpgradeCandidateRunCutAuthority
from labcourt.domain.m6_procedural_gate_authority import M6CaseProceduralGateAuthority
from labcourt.ports.m6_procedural_gate_authority import M6ProceduralGateHistorySnapshot
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v2_inventory,
)
from tests.unit.test_m6_procedural_gate_history import (
    _bundle,
    _document_sha256,
    _sha,
)


@dataclass(frozen=True, slots=True)
class _CandidateBundle:
    run_cut: M6UpgradeCandidateRunCutAuthority
    selected_case: Case
    selected_case_revision: int
    selected_case_document_sha256: str
    source_identity_sha256: str
    gate_source: M6SealedGateSource
    snapshot: M6ProceduralGateHistorySnapshot


def _candidate_bundle(monkeypatch: pytest.MonkeyPatch) -> _CandidateBundle:
    run_cut = _v2_inventory().candidate_run_cut
    original_event = m4_fixture._event
    monkeypatch.setattr(m4_fixture, "RUN_ID", run_cut.candidate_run_id)

    def candidate_event() -> CandidateEvent:
        payload = original_event().model_dump(
            mode="json",
            exclude_computed_fields=True,
        )
        payload["manifest_id"] = run_cut.candidate_manifest.manifest_id
        return CandidateEvent.model_validate(payload)

    monkeypatch.setattr(m4_fixture, "_event", candidate_event)
    monkeypatch.setattr(m4_fixture, "_manifest", lambda: run_cut.candidate_manifest)
    monkeypatch.setattr(m4_fixture, "load_config", lambda _path: run_cut.candidate_config)

    historical = _bundle(monkeypatch)
    selected_case = historical.source.source_case
    selected_case_document_sha256 = _document_sha256(selected_case)
    source_identity_sha256 = _sha("candidate-gate-source")
    m4_report = run_cut.validation_report.predecessor_report
    assert isinstance(m4_report, M4ArtifactValidationReport)
    assert m4_report.authority_root_sha256 is not None
    snapshot = replace(
        historical.snapshot,
        source_identity_sha256=source_identity_sha256,
        source_m4_authority_root_sha256=m4_report.authority_root_sha256,
    )
    gate_source = M6SealedGateSource(
        source_case=selected_case,
        source_case_revision=1,
        source_case_document_sha256=selected_case_document_sha256,
        audit_head_sequence=run_cut.audit_head_sequence,
        audit_head_hash=run_cut.audit_head_hash,
        gate_current_closures=(historical.source.input_authority.gate_current_closures),
    )
    return _CandidateBundle(
        run_cut=run_cut,
        selected_case=selected_case,
        selected_case_revision=1,
        selected_case_document_sha256=selected_case_document_sha256,
        source_identity_sha256=source_identity_sha256,
        gate_source=gate_source,
        snapshot=snapshot,
    )


def _assemble(bundle: _CandidateBundle) -> M6CaseProceduralGateAuthority:
    return assemble_m6_candidate_case_procedural_gate_authority(
        run_cut=bundle.run_cut,
        selected_case=bundle.selected_case,
        selected_case_revision=bundle.selected_case_revision,
        selected_case_document_sha256=bundle.selected_case_document_sha256,
        source_identity_sha256=bundle.source_identity_sha256,
        gate_source=bundle.gate_source,
        snapshot=bundle.snapshot,
    )


def _assert_error(
    code: M6ProceduralGateAuthorityErrorCode,
    bundle: _CandidateBundle,
) -> None:
    with pytest.raises(M6ProceduralGateAuthorityError) as raised:
        _assemble(bundle)
    assert raised.value.code == code


def test_candidate_cut_rebuilds_exact_gate_input_from_real_m4_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _candidate_bundle(monkeypatch)

    authority = _assemble(bundle)

    review = bundle.selected_case.procedural_reviews[0]
    execution = authority.input_for_review(review)
    assert authority.source_identity_sha256 == bundle.source_identity_sha256
    assert (authority.run_id, authority.case_id, authority.manifest_id) == (
        bundle.run_cut.candidate_run_id,
        bundle.selected_case.case_id,
        bundle.run_cut.candidate_manifest.manifest_id,
    )
    assert len(authority.inputs) == 1
    assert execution.rebuild_review() == review
    assert execution.source_review_document_sha256 == _document_sha256(review)
    assert execution.current_closure == bundle.gate_source.gate_current_closures[0].current_closure


def test_candidate_run_cut_graft_is_rejected_before_gate_reconstruction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _candidate_bundle(monkeypatch)
    grafted_cut = BaseModel.model_copy(
        bundle.run_cut, update={"audit_head_hash": _sha("foreign-candidate-audit-head")}
    )

    _assert_error(
        M6ProceduralGateAuthorityErrorCode.INVALID_ARGUMENT,
        replace(bundle, run_cut=grafted_cut),
    )


def _graft_case_revision(source: M6SealedGateSource) -> M6SealedGateSource:
    return replace(source, source_case_revision=2)


def _graft_case_document(source: M6SealedGateSource) -> M6SealedGateSource:
    return replace(source, source_case_document_sha256=_sha("foreign-case-document"))


def _graft_audit_sequence(source: M6SealedGateSource) -> M6SealedGateSource:
    return replace(source, audit_head_sequence=99)


def _graft_audit_hash(source: M6SealedGateSource) -> M6SealedGateSource:
    return replace(source, audit_head_hash=_sha("foreign-audit-head"))


@pytest.mark.parametrize(
    "graft",
    (
        _graft_case_revision,
        _graft_case_document,
        _graft_audit_sequence,
        _graft_audit_hash,
    ),
)
def test_candidate_case_and_audit_cut_grafts_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    graft: Callable[[M6SealedGateSource], M6SealedGateSource],
) -> None:
    bundle = _candidate_bundle(monkeypatch)

    _assert_error(
        M6ProceduralGateAuthorityErrorCode.SOURCE_SCOPE_MISMATCH,
        replace(
            bundle,
            gate_source=graft(bundle.gate_source),
        ),
    )


def test_candidate_current_crop_receipt_graft_fails_resealing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _candidate_bundle(monkeypatch)
    receipt = bundle.gate_source.gate_current_closures[0]
    grafted_receipt = BaseModel.model_copy(receipt, update={"crop_verifications": ()})
    grafted_source = replace(
        bundle.gate_source,
        gate_current_closures=(grafted_receipt,),
    )

    _assert_error(
        M6ProceduralGateAuthorityErrorCode.CURRENT_CLOSURE_AUTHORITY_INVALID,
        replace(bundle, gate_source=grafted_source),
    )


def test_candidate_snapshot_identity_and_m4_root_remain_independent_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _candidate_bundle(monkeypatch)
    _assert_error(
        M6ProceduralGateAuthorityErrorCode.SNAPSHOT_IDENTITY_MISMATCH,
        replace(
            bundle,
            snapshot=replace(
                bundle.snapshot,
                source_identity_sha256=_sha("foreign-source-identity"),
            ),
        ),
    )
    _assert_error(
        M6ProceduralGateAuthorityErrorCode.SOURCE_AUTHORITY_ROOT_MISMATCH,
        replace(
            bundle,
            snapshot=replace(
                bundle.snapshot,
                source_m4_authority_root_sha256=_sha("foreign-m4-root"),
            ),
        ),
    )
