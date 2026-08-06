"""Assemble the exact historical precedent cut for one locked M6 replay.

Only canonical documents from already validated M4 and M5 authority snapshots
are accepted here.  The assembler never asks a live precedent repository for a
head and never inspects training-label authority.  Successful M4 retrievals
must have exactly one matching M5 exposure; degraded retrievals must have none.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.hearing_common import HearingCycleScope
from labcourt.contracts.hearing_state import (
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_replay_locked import (
    M6HistoricalCausalCut,
    M6LockedRetrievalCycleInput,
    M6LockedRetrievalOutcomeKind,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
)
from labcourt.domain.m6_semantic_projection import M6ResolvedRetrievalCycle
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_historical_retrieval import (
    M6HistoricalAuthorityDocument,
    M6ValidatedHistoricalRetrievalSnapshots,
)


class M6HistoricalRetrievalCutErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_RUN_MISMATCH = "SNAPSHOT_RUN_MISMATCH"
    SNAPSHOT_AUTHORITY_INVALID = "SNAPSHOT_AUTHORITY_INVALID"
    SOURCE_MANIFEST_MISMATCH = "SOURCE_MANIFEST_MISMATCH"
    SOURCE_AUTHORITY_SCOPE_MISMATCH = "SOURCE_AUTHORITY_SCOPE_MISMATCH"
    VALIDATED_DOCUMENT_INVALID = "VALIDATED_DOCUMENT_INVALID"
    MULTIPLE_HEARING_SESSIONS = "MULTIPLE_HEARING_SESSIONS"
    DUPLICATE_HEARING_CYCLE = "DUPLICATE_HEARING_CYCLE"
    NONCONTIGUOUS_HEARING_CYCLES = "NONCONTIGUOUS_HEARING_CYCLES"
    MISSING_RETRIEVAL_RECEIPT = "MISSING_RETRIEVAL_RECEIPT"
    EXTRA_RETRIEVAL_RECEIPT = "EXTRA_RETRIEVAL_RECEIPT"
    RETRIEVAL_CYCLE_SCOPE_MISMATCH = "RETRIEVAL_CYCLE_SCOPE_MISMATCH"
    SUCCESS_EXPOSURE_MISSING = "SUCCESS_EXPOSURE_MISSING"
    SUCCESS_EXPOSURE_DUPLICATE = "SUCCESS_EXPOSURE_DUPLICATE"
    SUCCESS_EXPOSURE_SCOPE_MISMATCH = "SUCCESS_EXPOSURE_SCOPE_MISMATCH"
    SUCCESS_EXPOSURE_RECEIPT_MISMATCH = "SUCCESS_EXPOSURE_RECEIPT_MISMATCH"
    DEGRADED_EXPOSURE_PRESENT = "DEGRADED_EXPOSURE_PRESENT"
    EXTRA_EXPOSURE = "EXTRA_EXPOSURE"
    HISTORICAL_CUT_MISMATCH = "HISTORICAL_CUT_MISMATCH"


class M6HistoricalRetrievalCutError(LabCourtError):
    """A validated historical graph cannot produce one exact locked cut."""

    def __init__(self, code: M6HistoricalRetrievalCutErrorCode) -> None:
        if not isinstance(code, M6HistoricalRetrievalCutErrorCode):
            raise TypeError("code must be an M6HistoricalRetrievalCutErrorCode")
        self.code = code
        super().__init__(f"M6 historical retrieval cut failed: {code.value}")


def _fail(code: M6HistoricalRetrievalCutErrorCode) -> NoReturn:
    raise M6HistoricalRetrievalCutError(code)


def _canonical_m4_document(
    document: M6HistoricalAuthorityDocument,
    model: type[HearingCycleScope] | type[HearingPrecedentRetrievalReceipt],
) -> HearingCycleScope | HearingPrecedentRetrievalReceipt:
    try:
        parsed = model.model_validate_json(document.canonical_document)
    except (TypeError, ValueError, ValidationError):
        _fail(M6HistoricalRetrievalCutErrorCode.VALIDATED_DOCUMENT_INVALID)
    if canonical_json(parsed.model_dump(mode="json")) != document.canonical_document:
        _fail(M6HistoricalRetrievalCutErrorCode.VALIDATED_DOCUMENT_INVALID)
    expected_id = parsed.cycle_id if isinstance(parsed, HearingCycleScope) else parsed.receipt_id
    if document.artifact_id != expected_id:
        _fail(M6HistoricalRetrievalCutErrorCode.VALIDATED_DOCUMENT_INVALID)
    return parsed


def _canonical_exposure(
    document: M6HistoricalAuthorityDocument,
) -> M5PrecedentExposureBatchAuthority:
    try:
        exposure = M5PrecedentExposureBatchAuthority.model_validate_json(
            document.canonical_document
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6HistoricalRetrievalCutErrorCode.VALIDATED_DOCUMENT_INVALID)
    if (
        canonical_json(exposure.model_dump(mode="json")) != document.canonical_document
        or document.artifact_id != exposure.exposure_id
    ):
        _fail(M6HistoricalRetrievalCutErrorCode.VALIDATED_DOCUMENT_INVALID)
    return exposure


def _validate_arguments(
    source_case: object,
    snapshots: object,
) -> tuple[Case, M6ValidatedHistoricalRetrievalSnapshots]:
    if not isinstance(source_case, Case):
        _fail(M6HistoricalRetrievalCutErrorCode.INVALID_ARGUMENT)
    if not isinstance(snapshots, M6ValidatedHistoricalRetrievalSnapshots):
        _fail(M6HistoricalRetrievalCutErrorCode.INVALID_ARGUMENT)
    try:
        case = Case.model_validate(source_case.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError):
        _fail(M6HistoricalRetrievalCutErrorCode.INVALID_ARGUMENT)
    return case, snapshots


def _source_cycles(
    snapshot: M6ValidatedHistoricalRetrievalSnapshots,
    case: Case,
) -> tuple[tuple[HearingCycleScope, M6HistoricalAuthorityDocument], ...]:
    values: list[tuple[HearingCycleScope, M6HistoricalAuthorityDocument]] = []
    for document in snapshot.m4_documents:
        if document.kind != M4ProjectionArtifactKind.HEARING_CYCLE:
            continue
        parsed = _canonical_m4_document(document, HearingCycleScope)
        if not isinstance(parsed, HearingCycleScope):
            _fail(M6HistoricalRetrievalCutErrorCode.VALIDATED_DOCUMENT_INVALID)
        if parsed.case_id == case.case_id:
            if parsed.run_id != case.run_id or parsed.manifest_id != case.manifest_id:
                _fail(M6HistoricalRetrievalCutErrorCode.SOURCE_AUTHORITY_SCOPE_MISMATCH)
            values.append((parsed, document))
    values.sort(key=lambda item: (item[0].hearing_session_id, item[0].cycle_index))
    return tuple(values)


def _source_receipts(
    snapshot: M6ValidatedHistoricalRetrievalSnapshots,
    case: Case,
) -> tuple[tuple[HearingPrecedentRetrievalReceipt, M6HistoricalAuthorityDocument], ...]:
    values: list[tuple[HearingPrecedentRetrievalReceipt, M6HistoricalAuthorityDocument]] = []
    for document in snapshot.m4_documents:
        if document.kind != M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL:
            continue
        parsed = _canonical_m4_document(document, HearingPrecedentRetrievalReceipt)
        if not isinstance(parsed, HearingPrecedentRetrievalReceipt):
            _fail(M6HistoricalRetrievalCutErrorCode.VALIDATED_DOCUMENT_INVALID)
        if parsed.case_id == case.case_id:
            if parsed.run_id != case.run_id or parsed.manifest_id != case.manifest_id:
                _fail(M6HistoricalRetrievalCutErrorCode.SOURCE_AUTHORITY_SCOPE_MISMATCH)
            values.append((parsed, document))
    values.sort(
        key=lambda item: (
            item[0].hearing_session_id,
            item[0].round_index,
            item[0].receipt_id,
        )
    )
    return tuple(values)


def _source_exposures(
    snapshot: M6ValidatedHistoricalRetrievalSnapshots,
    case: Case,
) -> tuple[tuple[M5PrecedentExposureBatchAuthority, M6HistoricalAuthorityDocument], ...]:
    values: list[tuple[M5PrecedentExposureBatchAuthority, M6HistoricalAuthorityDocument]] = []
    for document in snapshot.m5_documents:
        if document.kind != M5AuthorityKind.PRECEDENT_EXPOSURE:
            continue
        exposure = _canonical_exposure(document)
        if exposure.case_id == case.case_id:
            if exposure.run_id != case.run_id or exposure.manifest_id != case.manifest_id:
                _fail(M6HistoricalRetrievalCutErrorCode.SOURCE_AUTHORITY_SCOPE_MISMATCH)
            values.append((exposure, document))
    values.sort(
        key=lambda item: (
            item[0].hearing_session_id,
            item[0].cycle_index,
            item[0].exposure_id,
        )
    )
    return tuple(values)


def _require_cycle_inventory(
    cycles: tuple[tuple[HearingCycleScope, M6HistoricalAuthorityDocument], ...],
) -> None:
    sessions = {cycle.hearing_session_id for cycle, _document in cycles}
    if len(sessions) > 1:
        _fail(M6HistoricalRetrievalCutErrorCode.MULTIPLE_HEARING_SESSIONS)
    keys = tuple((cycle.hearing_session_id, cycle.cycle_index) for cycle, _ in cycles)
    if len(keys) != len(set(keys)):
        _fail(M6HistoricalRetrievalCutErrorCode.DUPLICATE_HEARING_CYCLE)
    indices = tuple(cycle.cycle_index for cycle, _ in cycles)
    if indices != tuple(range(1, len(indices) + 1)):
        _fail(M6HistoricalRetrievalCutErrorCode.NONCONTIGUOUS_HEARING_CYCLES)


def _receipt_by_cycle(
    cycles: tuple[tuple[HearingCycleScope, M6HistoricalAuthorityDocument], ...],
    receipts: tuple[tuple[HearingPrecedentRetrievalReceipt, M6HistoricalAuthorityDocument], ...],
) -> dict[str, tuple[HearingPrecedentRetrievalReceipt, M6HistoricalAuthorityDocument]]:
    receipt_by_scope: dict[
        str, tuple[HearingPrecedentRetrievalReceipt, M6HistoricalAuthorityDocument]
    ] = {}
    for receipt, document in receipts:
        if receipt.cycle_scope_id in receipt_by_scope:
            _fail(M6HistoricalRetrievalCutErrorCode.EXTRA_RETRIEVAL_RECEIPT)
        receipt_by_scope[receipt.cycle_scope_id] = (receipt, document)

    cycle_scope_ids = {cycle.cycle_id for cycle, _document in cycles}
    if set(receipt_by_scope) - cycle_scope_ids:
        _fail(M6HistoricalRetrievalCutErrorCode.EXTRA_RETRIEVAL_RECEIPT)
    if cycle_scope_ids - set(receipt_by_scope):
        _fail(M6HistoricalRetrievalCutErrorCode.MISSING_RETRIEVAL_RECEIPT)
    return receipt_by_scope


def _require_exact_cycle_receipt(
    cycle: HearingCycleScope,
    receipt: HearingPrecedentRetrievalReceipt,
) -> None:
    if (
        receipt.run_id != cycle.run_id
        or receipt.case_id != cycle.case_id
        or receipt.hearing_session_id != cycle.hearing_session_id
        or receipt.round_index != cycle.cycle_index
        or receipt.cycle_scope_id != cycle.cycle_id
        or receipt.cycle_scope_sha256 != cycle.cycle_sha256
    ):
        _fail(M6HistoricalRetrievalCutErrorCode.RETRIEVAL_CYCLE_SCOPE_MISMATCH)


def _successful_cycle_input(
    *,
    cycle: HearingCycleScope,
    receipt: HearingPrecedentRetrievalReceipt,
    logical_exposures: tuple[
        tuple[M5PrecedentExposureBatchAuthority, M6HistoricalAuthorityDocument], ...
    ],
) -> tuple[M6LockedRetrievalCycleInput, str]:
    if not logical_exposures:
        _fail(M6HistoricalRetrievalCutErrorCode.SUCCESS_EXPOSURE_MISSING)
    if len(logical_exposures) != 1:
        _fail(M6HistoricalRetrievalCutErrorCode.SUCCESS_EXPOSURE_DUPLICATE)
    exposure, document = logical_exposures[0]
    if (
        exposure.run_id != cycle.run_id
        or exposure.case_id != cycle.case_id
        or exposure.hearing_session_id != cycle.hearing_session_id
        or exposure.cycle_index != cycle.cycle_index
        or exposure.cycle_scope_id != cycle.cycle_id
        or exposure.cycle_scope_sha256 != cycle.cycle_sha256
        or exposure.manifest_id != cycle.manifest_id
    ):
        _fail(M6HistoricalRetrievalCutErrorCode.SUCCESS_EXPOSURE_SCOPE_MISMATCH)
    exposure_receipt = exposure.m4_retrieval_outcome.receipt
    if (
        exposure_receipt != receipt
        or exposure_receipt.receipt_id != receipt.receipt_id
        or exposure_receipt.receipt_sha256 != receipt.receipt_sha256
    ):
        _fail(M6HistoricalRetrievalCutErrorCode.SUCCESS_EXPOSURE_RECEIPT_MISMATCH)
    return (
        M6LockedRetrievalCycleInput(
            source_run_id=cycle.run_id,
            source_case_id=cycle.case_id,
            hearing_session_id=cycle.hearing_session_id,
            cycle_index=cycle.cycle_index,
            cycle_scope_id=cycle.cycle_id,
            outcome=M6LockedRetrievalOutcomeKind.SUCCESS,
            authority_ref=M6ReplayAuthorityRef(
                kind=M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE,
                artifact_id=exposure.exposure_id,
                document_sha256=document.document_sha256,
            ),
        ),
        exposure.exposure_id,
    )


def _degraded_cycle_input(
    *,
    cycle: HearingCycleScope,
    receipt: HearingPrecedentRetrievalReceipt,
    receipt_document: M6HistoricalAuthorityDocument,
    logical_exposures: tuple[
        tuple[M5PrecedentExposureBatchAuthority, M6HistoricalAuthorityDocument], ...
    ],
) -> M6LockedRetrievalCycleInput:
    if logical_exposures:
        _fail(M6HistoricalRetrievalCutErrorCode.DEGRADED_EXPOSURE_PRESENT)
    return M6LockedRetrievalCycleInput(
        source_run_id=cycle.run_id,
        source_case_id=cycle.case_id,
        hearing_session_id=cycle.hearing_session_id,
        cycle_index=cycle.cycle_index,
        cycle_scope_id=cycle.cycle_id,
        outcome=M6LockedRetrievalOutcomeKind.DEGRADED,
        authority_ref=M6ReplayAuthorityRef(
            kind=M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT,
            artifact_id=receipt.receipt_id,
            document_sha256=receipt_document.document_sha256,
        ),
    )


def assemble_m6_historical_retrieval_cut(
    *,
    source_case: Case,
    snapshots: M6ValidatedHistoricalRetrievalSnapshots,
) -> M6HistoricalCausalCut:
    """Build one complete per-cycle historical cut from validated snapshots."""

    case, authority = _validate_arguments(source_case, snapshots)
    if authority.run_id != case.run_id:
        _fail(M6HistoricalRetrievalCutErrorCode.SNAPSHOT_RUN_MISMATCH)
    if not authority.authority_valid:
        _fail(M6HistoricalRetrievalCutErrorCode.SNAPSHOT_AUTHORITY_INVALID)
    if authority.manifest_id != case.manifest_id:
        _fail(M6HistoricalRetrievalCutErrorCode.SOURCE_MANIFEST_MISMATCH)

    cycles = _source_cycles(authority, case)
    receipts = _source_receipts(authority, case)
    exposures = _source_exposures(authority, case)
    _require_cycle_inventory(cycles)
    receipt_by_scope = _receipt_by_cycle(cycles, receipts)

    exposures_by_logical_cycle: dict[
        tuple[str, int],
        list[tuple[M5PrecedentExposureBatchAuthority, M6HistoricalAuthorityDocument]],
    ] = {}
    for exposure, document in exposures:
        exposures_by_logical_cycle.setdefault(
            (exposure.hearing_session_id, exposure.cycle_index), []
        ).append((exposure, document))

    used_exposure_ids: set[str] = set()
    items: list[M6LockedRetrievalCycleInput] = []
    for cycle, _cycle_document in cycles:
        receipt, receipt_document = receipt_by_scope[cycle.cycle_id]
        _require_exact_cycle_receipt(cycle, receipt)
        logical_exposures = tuple(
            exposures_by_logical_cycle.get(
                (cycle.hearing_session_id, cycle.cycle_index),
                (),
            )
        )
        if receipt.status == HearingPrecedentRetrievalStatus.SUCCESS:
            item, exposure_id = _successful_cycle_input(
                cycle=cycle,
                receipt=receipt,
                logical_exposures=logical_exposures,
            )
            used_exposure_ids.add(exposure_id)
            items.append(item)
        else:
            items.append(
                _degraded_cycle_input(
                    cycle=cycle,
                    receipt=receipt,
                    receipt_document=receipt_document,
                    logical_exposures=logical_exposures,
                )
            )

    all_exposure_ids = {exposure.exposure_id for exposure, _document in exposures}
    if used_exposure_ids != all_exposure_ids:
        _fail(M6HistoricalRetrievalCutErrorCode.EXTRA_EXPOSURE)
    try:
        return M6HistoricalCausalCut(retrieval_cycles=tuple(items))
    except (TypeError, ValueError, ValidationError):
        _fail(M6HistoricalRetrievalCutErrorCode.NONCONTIGUOUS_HEARING_CYCLES)


def resolve_m6_historical_retrieval_cycles(
    *,
    source_case: Case,
    snapshots: M6ValidatedHistoricalRetrievalSnapshots,
    historical_cut: M6HistoricalCausalCut,
) -> tuple[M6ResolvedRetrievalCycle, ...]:
    """Resolve a proven cut to the exact typed authorities used by projection."""

    case, authority = _validate_arguments(source_case, snapshots)
    if not isinstance(historical_cut, M6HistoricalCausalCut):
        _fail(M6HistoricalRetrievalCutErrorCode.INVALID_ARGUMENT)
    try:
        controlled_cut = M6HistoricalCausalCut.model_validate(
            historical_cut.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6HistoricalRetrievalCutErrorCode.INVALID_ARGUMENT)
    expected_cut = assemble_m6_historical_retrieval_cut(
        source_case=case,
        snapshots=authority,
    )
    if controlled_cut != historical_cut or controlled_cut != expected_cut:
        _fail(M6HistoricalRetrievalCutErrorCode.HISTORICAL_CUT_MISMATCH)

    receipts = {
        receipt.receipt_id: receipt for receipt, _document in _source_receipts(authority, case)
    }
    exposures = {
        exposure.exposure_id: exposure for exposure, _document in _source_exposures(authority, case)
    }
    resolved: list[M6ResolvedRetrievalCycle] = []
    try:
        for item in controlled_cut.retrieval_cycles:
            if item.outcome == M6LockedRetrievalOutcomeKind.SUCCESS:
                exposure = exposures.get(item.authority_ref.artifact_id)
                if exposure is None:
                    _fail(M6HistoricalRetrievalCutErrorCode.SUCCESS_EXPOSURE_MISSING)
                resolved.append(
                    M6ResolvedRetrievalCycle(
                        cycle_index=item.cycle_index,
                        success_exposure=exposure,
                    )
                )
            else:
                receipt = receipts.get(item.authority_ref.artifact_id)
                if receipt is None:
                    _fail(M6HistoricalRetrievalCutErrorCode.MISSING_RETRIEVAL_RECEIPT)
                resolved.append(
                    M6ResolvedRetrievalCycle(
                        cycle_index=item.cycle_index,
                        degraded_receipt=receipt,
                    )
                )
    except M6HistoricalRetrievalCutError:
        raise
    except (TypeError, ValueError, ValidationError):
        _fail(M6HistoricalRetrievalCutErrorCode.HISTORICAL_CUT_MISMATCH)
    return tuple(resolved)


__all__ = [
    "M6HistoricalRetrievalCutError",
    "M6HistoricalRetrievalCutErrorCode",
    "assemble_m6_historical_retrieval_cut",
    "resolve_m6_historical_retrieval_cycles",
]
