from __future__ import annotations

import pytest

from labcourt.application.m6_historical_retrieval_cut import (
    M6HistoricalRetrievalCutError,
    M6HistoricalRetrievalCutErrorCode,
    assemble_m6_historical_retrieval_cut,
    resolve_m6_historical_retrieval_cycles,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.hearing_common import HearingCycleScope
from labcourt.contracts.hearing_state import (
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_replay_locked import (
    M6HistoricalCausalCut,
    M6LockedRetrievalOutcomeKind,
    M6ReplayAuthorityKind,
)
from labcourt.ports.m6_historical_retrieval import (
    M6HistoricalAuthorityDocument,
    M6ValidatedHistoricalRetrievalSnapshots,
)
from tests.contract.test_m5_precedent_usage_contracts import _exposure, _ready_case


def _cycle(receipt: HearingPrecedentRetrievalReceipt) -> HearingCycleScope:
    return HearingCycleScope(
        run_id=receipt.run_id,
        case_id=receipt.case_id,
        hearing_session_id=receipt.hearing_session_id,
        cycle_index=receipt.round_index,
        prior_acquisition_rounds=receipt.prior_acquisition_rounds,
        prior_rework_rounds=receipt.prior_rework_rounds,
        cycle_evidence_pack_id=receipt.current_evidence_pack_id,
        cycle_evidence_pack_version=receipt.current_evidence_pack_version,
        initial_trigger_review_ref=receipt.initial_trigger_review_ref,
        initial_defect_codes=receipt.initial_defect_codes,
        rework_review_ref=receipt.rework_review_ref,
        rework_defect_codes=receipt.rework_defect_codes,
        manifest_id=receipt.manifest_id,
    )


def _m4_document(
    kind: M4ProjectionArtifactKind,
    value: HearingCycleScope | HearingPrecedentRetrievalReceipt,
) -> M6HistoricalAuthorityDocument:
    artifact_id = value.cycle_id if isinstance(value, HearingCycleScope) else value.receipt_id
    return M6HistoricalAuthorityDocument(
        kind=kind,
        artifact_id=artifact_id,
        canonical_document=canonical_json(value.model_dump(mode="json")),
    )


def _m5_document(
    exposure: M5PrecedentExposureBatchAuthority,
) -> M6HistoricalAuthorityDocument:
    return M6HistoricalAuthorityDocument(
        kind=M5AuthorityKind.PRECEDENT_EXPOSURE,
        artifact_id=exposure.exposure_id,
        canonical_document=canonical_json(exposure.model_dump(mode="json")),
    )


def _snapshots(
    case: Case,
    *,
    cycles: tuple[HearingCycleScope, ...],
    receipts: tuple[HearingPrecedentRetrievalReceipt, ...],
    exposures: tuple[M5PrecedentExposureBatchAuthority, ...],
) -> M6ValidatedHistoricalRetrievalSnapshots:
    m4_documents = tuple(
        sorted(
            (
                *(_m4_document(M4ProjectionArtifactKind.HEARING_CYCLE, item) for item in cycles),
                *(
                    _m4_document(M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL, item)
                    for item in receipts
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    m5_documents = tuple(
        sorted((_m5_document(item) for item in exposures), key=lambda x: x.sort_key)
    )
    return M6ValidatedHistoricalRetrievalSnapshots(
        source_identity_sha256="f" * 64,
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        m4_documents=m4_documents,
        m5_documents=m5_documents,
    )


def _degraded_receipt(
    source: HearingPrecedentRetrievalReceipt,
    *,
    cycle_index: int = 1,
) -> HearingPrecedentRetrievalReceipt:
    return source.model_copy(
        update={
            "round_index": cycle_index,
            "prior_acquisition_rounds": cycle_index - 1,
            "candidate_precedent_refs": (),
            "visible_precedent_refs": (),
            "scored_precedents": (),
            "status": HearingPrecedentRetrievalStatus.DEGRADED,
            "degraded_reason": HearingPrecedentDegradedReason.PRECEDENT_INDEX_UNAVAILABLE,
            "embedding_model_manifest_id": None,
        }
    )


def _relocate_exposure(
    source: M5PrecedentExposureBatchAuthority,
    *,
    hearing_session_id: str | None = None,
    hearing_session_sha256: str | None = None,
    cycle_index: int = 1,
    current_evidence_pack_id: str | None = None,
) -> M5PrecedentExposureBatchAuthority:
    outcome = source.m4_retrieval_outcome
    original_receipt = outcome.receipt
    session_id = hearing_session_id or source.hearing_session_id
    session_sha256 = hearing_session_sha256 or source.hearing_session_sha256
    pack_id = current_evidence_pack_id or original_receipt.current_evidence_pack_id
    provisional_receipt = original_receipt.model_copy(
        update={
            "hearing_session_id": session_id,
            "round_index": cycle_index,
            "prior_acquisition_rounds": cycle_index - 1,
            "current_evidence_pack_id": pack_id,
        }
    )
    query = outcome.query.model_copy(
        update={
            "hearing_session_id": session_id,
            "hearing_session_sha256": session_sha256,
            "cycle_scope_id": provisional_receipt.cycle_scope_id,
            "cycle_scope_sha256": provisional_receipt.cycle_scope_sha256,
            "current_evidence_pack_id": pack_id,
            "current_evidence_pack_sha256": (
                outcome.query.current_evidence_pack_sha256
                if current_evidence_pack_id is None
                else "7" * 64
            ),
        }
    )
    assert outcome.result is not None
    result = outcome.result.model_copy(update={"query": query})
    receipt = provisional_receipt.model_copy(
        update={
            "query_sha256": query.query_sha256,
            "candidate_snapshot_sha256": result.candidate_snapshot_sha256,
            "visible_snapshot_sha256": result.visible_snapshot_sha256,
        }
    )
    relocated_outcome = outcome.model_copy(
        update={"query": query, "result": result, "receipt": receipt}
    )
    return source.model_copy(
        update={
            "hearing_session_id": session_id,
            "hearing_session_sha256": session_sha256,
            "cycle_index": cycle_index,
            "cycle_scope_id": receipt.cycle_scope_id,
            "cycle_scope_sha256": receipt.cycle_scope_sha256,
            "m4_retrieval_outcome": relocated_outcome,
        }
    )


def _assemble(
    case: Case,
    *,
    cycles: tuple[HearingCycleScope, ...],
    receipts: tuple[HearingPrecedentRetrievalReceipt, ...],
    exposures: tuple[M5PrecedentExposureBatchAuthority, ...],
):
    snapshots = _snapshots(
        case,
        cycles=cycles,
        receipts=receipts,
        exposures=exposures,
    )
    return assemble_m6_historical_retrieval_cut(
        source_case=case,
        snapshots=snapshots,
    )


def test_success_cycle_requires_and_binds_the_exact_m5_exposure() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = exposure.m4_retrieval_outcome.receipt
    cut = _assemble(
        case,
        cycles=(_cycle(receipt),),
        receipts=(receipt,),
        exposures=(exposure,),
    )

    assert cut.retrieval_cycle_count == 1
    item = cut.retrieval_cycles[0]
    assert item.outcome == M6LockedRetrievalOutcomeKind.SUCCESS
    assert item.authority_ref.kind == M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE
    assert item.authority_ref.artifact_id == exposure.exposure_id


def test_exact_success_cut_resolves_to_its_typed_exposure() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = exposure.m4_retrieval_outcome.receipt
    snapshots = _snapshots(
        case,
        cycles=(_cycle(receipt),),
        receipts=(receipt,),
        exposures=(exposure,),
    )
    cut = assemble_m6_historical_retrieval_cut(
        source_case=case,
        snapshots=snapshots,
    )

    resolved = resolve_m6_historical_retrieval_cycles(
        source_case=case,
        snapshots=snapshots,
        historical_cut=cut,
    )

    assert len(resolved) == 1
    assert resolved[0].success_exposure == exposure
    assert resolved[0].degraded_receipt is None


def test_resolver_rejects_a_cut_that_is_not_the_exact_snapshot_projection() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = exposure.m4_retrieval_outcome.receipt
    snapshots = _snapshots(
        case,
        cycles=(_cycle(receipt),),
        receipts=(receipt,),
        exposures=(exposure,),
    )

    with pytest.raises(M6HistoricalRetrievalCutError) as raised:
        resolve_m6_historical_retrieval_cycles(
            source_case=case,
            snapshots=snapshots,
            historical_cut=M6HistoricalCausalCut(),
        )

    assert raised.value.code == M6HistoricalRetrievalCutErrorCode.HISTORICAL_CUT_MISMATCH


def test_foreign_cycle_scope_cannot_replace_the_exact_success_exposure() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = exposure.m4_retrieval_outcome.receipt
    foreign_cycle = _relocate_exposure(
        exposure,
        current_evidence_pack_id="e" * 64,
    )

    with pytest.raises(M6HistoricalRetrievalCutError) as raised:
        _assemble(
            case,
            cycles=(_cycle(receipt),),
            receipts=(receipt,),
            exposures=(foreign_cycle,),
        )

    assert raised.value.code == M6HistoricalRetrievalCutErrorCode.SUCCESS_EXPOSURE_SCOPE_MISMATCH


def test_self_consistent_extra_exposure_is_not_silently_accepted() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = exposure.m4_retrieval_outcome.receipt
    extra = _relocate_exposure(
        exposure,
        hearing_session_id="9" * 64,
        hearing_session_sha256="8" * 64,
    )

    with pytest.raises(M6HistoricalRetrievalCutError) as raised:
        _assemble(
            case,
            cycles=(_cycle(receipt),),
            receipts=(receipt,),
            exposures=(exposure, extra),
        )

    assert raised.value.code == M6HistoricalRetrievalCutErrorCode.EXTRA_EXPOSURE


def test_degraded_cycle_has_no_exposure_and_binds_the_exact_m4_receipt() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = _degraded_receipt(exposure.m4_retrieval_outcome.receipt)
    cut = _assemble(
        case,
        cycles=(_cycle(receipt),),
        receipts=(receipt,),
        exposures=(),
    )

    item = cut.retrieval_cycles[0]
    assert item.outcome == M6LockedRetrievalOutcomeKind.DEGRADED
    assert item.authority_ref.kind == (M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT)
    assert item.authority_ref.artifact_id == receipt.receipt_id

    snapshots = _snapshots(
        case,
        cycles=(_cycle(receipt),),
        receipts=(receipt,),
        exposures=(),
    )
    resolved = resolve_m6_historical_retrieval_cycles(
        source_case=case,
        snapshots=snapshots,
        historical_cut=cut,
    )
    assert resolved[0].success_exposure is None
    assert resolved[0].degraded_receipt == receipt


def test_degraded_cycle_rejects_an_exposure_for_the_same_logical_cycle() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = _degraded_receipt(exposure.m4_retrieval_outcome.receipt)

    with pytest.raises(M6HistoricalRetrievalCutError) as raised:
        _assemble(
            case,
            cycles=(_cycle(receipt),),
            receipts=(receipt,),
            exposures=(exposure,),
        )

    assert raised.value.code == M6HistoricalRetrievalCutErrorCode.DEGRADED_EXPOSURE_PRESENT


def test_success_then_degraded_cycles_form_one_contiguous_cut() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    first = exposure.m4_retrieval_outcome.receipt
    second = _degraded_receipt(first, cycle_index=2)
    cut = _assemble(
        case,
        cycles=(_cycle(first), _cycle(second)),
        receipts=(first, second),
        exposures=(exposure,),
    )

    assert tuple(item.cycle_index for item in cut.retrieval_cycles) == (1, 2)
    assert tuple(item.outcome for item in cut.retrieval_cycles) == (
        M6LockedRetrievalOutcomeKind.SUCCESS,
        M6LockedRetrievalOutcomeKind.DEGRADED,
    )


def test_missing_retrieval_receipt_is_a_typed_hard_failure() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = exposure.m4_retrieval_outcome.receipt

    with pytest.raises(M6HistoricalRetrievalCutError) as raised:
        _assemble(
            case,
            cycles=(_cycle(receipt),),
            receipts=(),
            exposures=(exposure,),
        )

    assert raised.value.code == M6HistoricalRetrievalCutErrorCode.MISSING_RETRIEVAL_RECEIPT


def test_foreign_run_cycle_cannot_be_joined_to_a_same_case_id() -> None:
    exposure = _exposure()
    case, _verdict = _ready_case(())
    receipt = _degraded_receipt(exposure.m4_retrieval_outcome.receipt).model_copy(
        update={"run_id": "foreign-run"}
    )

    with pytest.raises(M6HistoricalRetrievalCutError) as raised:
        _assemble(
            case,
            cycles=(_cycle(receipt),),
            receipts=(receipt,),
            exposures=(),
        )

    assert raised.value.code == (M6HistoricalRetrievalCutErrorCode.SOURCE_AUTHORITY_SCOPE_MISMATCH)
