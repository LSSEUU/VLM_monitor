from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

import pytest
from pydantic import BaseModel, ValidationError

from labcourt.application.appeal_resolution import build_appeal_resolution_intent
from labcourt.application.m5_training_provenance import (
    M5TrainingLabelProvenanceError,
    M5TrainingLabelProvenanceErrorCode,
    build_m5_strong_training_label_provenance_receipts,
    require_m5_strong_training_label_provenance,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import AppealStatus, TrainingLabelQuality, VerdictDecision
from labcourt.contracts.m5_appeals import (
    AppealResolutionCommand,
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    M5AppealResolutionCommitReceipt,
)
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
)
from labcourt.contracts.m5_training_provenance import (
    M5StrongTrainingLabelProvenanceReceipt,
    M5TrainingLabelAuthority,
)
from tests.unit.test_m5_appeal_resolution import (
    _case,
    _labels,
    _overturn_command,
    _reviewed,
    _snapshot,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class _ProvenanceChain:
    review_authority: AppealVersionAuthority
    terminal_authority: AppealVersionAuthority
    intent: AppealResolutionSideEffectIntent
    commit_receipt: M5AppealResolutionCommitReceipt
    commit_event: M5PrecedentCausalEvent
    label_authorities: tuple[M5TrainingLabelAuthority, ...]


def _constructed_copy(model: ModelT, **updates: object) -> ModelT:
    values = {name: getattr(model, name) for name in type(model).model_fields}
    values.update(updates)
    return type(model).model_construct(**values)


def _intent(
    status: AppealStatus,
) -> tuple[AppealVersionAuthority, AppealResolutionSideEffectIntent]:
    case = _case()
    if status == AppealStatus.OVERTURNED:
        reviewed, command = _overturn_command(case)
    else:
        reviewed = _reviewed(case)
        command = AppealResolutionCommand(
            run_id=case.run_id,
            case_id=case.case_id,
            appeal_id=reviewed.appeal.appeal_id,
            expected_appeal_authority_sha256=reviewed.authority_sha256,
            status=AppealStatus.UPHELD,
            reviewer_id="reviewer-1",
            resolution_summary="The human reviewer upheld the original decision.",
            resolved_decision=VerdictDecision.ESTABLISHED,
            training_labels=_labels(reviewed, AppealStatus.UPHELD),
        )
    return reviewed, build_appeal_resolution_intent(
        case_authority=case,
        appeal_authority=reviewed,
        precedent_snapshot=_snapshot(case),
        command=command,
    )


def _commit_receipt(
    intent: AppealResolutionSideEffectIntent,
) -> M5AppealResolutionCommitReceipt:
    overturned = intent.appeal_authority.appeal.status == AppealStatus.OVERTURNED
    replacement = intent.appeal_precedent_authority
    return M5AppealResolutionCommitReceipt(
        run_id=intent.run_id,
        resolution_intent_id=intent.intent_id,
        resolution_document_sha256=sha256_hex(intent.model_dump(mode="json")),
        appeal_id=intent.appeal_authority.appeal.appeal_id,
        appeal_authority_sha256=intent.appeal_authority.authority_sha256,
        case_id=intent.case_id,
        source_case_revision=intent.appeal_authority.source_case_revision,
        resulting_case_revision=intent.appeal_authority.source_case_revision + 3,
        resulting_case_document_sha256="1" * 64,
        verdict_rescission_ids=(("2" * 64,) if overturned else ()),
        alert_rescission_ids=(("3" * 64,) if overturned else ()),
        precedent_revocation_receipt_ids=(("4" * 64,) if overturned else ()),
        replacement_precedent_authority_id=(
            replacement.authority_id if replacement is not None else None
        ),
        training_label_ids=tuple(label.label_id for label in intent.training_labels),
        affected_citation_report_sha256=intent.affected_citations.report_sha256,
        manifest_id=intent.manifest_id,
    )


def _commit_event(
    receipt: M5AppealResolutionCommitReceipt,
) -> M5PrecedentCausalEvent:
    return M5PrecedentCausalEvent(
        run_id=receipt.run_id,
        sequence=1,
        event_kind=M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED,
        source_id=receipt.receipt_id,
        precedent_id=None,
        precedent_authority_id=None,
        precedent_revision=None,
        citation_kind=None,
        manifest_id=receipt.manifest_id,
        source_document_sha256=sha256_hex(receipt.model_dump(mode="json")),
        previous_event_sha256=M5_PRECEDENT_CAUSAL_GENESIS_SHA256,
    )


def _chain(status: AppealStatus = AppealStatus.UPHELD) -> _ProvenanceChain:
    review, intent = _intent(status)
    commit = _commit_receipt(intent)
    provenance = build_m5_strong_training_label_provenance_receipts(
        intent=intent,
        resolution_commit_receipt=commit,
    )
    authorities = tuple(
        M5TrainingLabelAuthority(label=label, strong_provenance=receipt)
        for label, receipt in zip(intent.training_labels, provenance, strict=True)
    )
    return _ProvenanceChain(
        review_authority=review,
        terminal_authority=intent.appeal_authority,
        intent=intent,
        commit_receipt=commit,
        commit_event=_commit_event(commit),
        label_authorities=authorities,
    )


def _resolve(
    chain: _ProvenanceChain,
    **updates: object,
) -> M5TrainingLabelAuthority:
    arguments: dict[str, object] = {
        "authority": chain.label_authorities[0],
        "review_authority": chain.review_authority,
        "terminal_authority": chain.terminal_authority,
        "resolution_intent": chain.intent,
        "resolution_commit_receipt": chain.commit_receipt,
        "resolution_commit_event": chain.commit_event,
    }
    arguments.update(updates)
    return require_m5_strong_training_label_provenance(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("status", "quality"),
    [
        (AppealStatus.UPHELD, TrainingLabelQuality.HUMAN_CONFIRMED),
        (AppealStatus.OVERTURNED, TrainingLabelQuality.APPEAL_CONFIRMED),
    ],
)
def test_builder_emits_constant_size_receipts_for_both_terminal_outcomes(
    status: AppealStatus,
    quality: TrainingLabelQuality,
) -> None:
    chain = _chain(status)
    authority = chain.label_authorities[0]
    receipt = authority.strong_provenance
    assert receipt is not None

    assert authority.label.quality == receipt.quality == quality
    assert receipt.terminal_status == status
    assert tuple(type(receipt).model_fields) == (
        "schema_version",
        "run_id",
        "case_id",
        "appeal_id",
        "label_id",
        "label_document_sha256",
        "crop_id",
        "reviewer_id",
        "quality",
        "authored_input",
        "review_authority_sha256",
        "terminal_authority_sha256",
        "terminal_status",
        "resolution_intent_id",
        "resolution_document_sha256",
        "resolution_commit_receipt_id",
        "resolution_commit_effect_root_sha256",
        "manifest_id",
        "rule_version",
        "detector_manifest_id",
    )
    assert not any(
        isinstance(
            value,
            (
                AppealVersionAuthority,
                AppealResolutionSideEffectIntent,
                M5AppealResolutionCommitReceipt,
            ),
        )
        for value in receipt.__dict__.values()
    )
    assert _resolve(chain) == authority


@pytest.mark.parametrize(
    ("mismatch", "expected_code"),
    [
        ("label", M5TrainingLabelProvenanceErrorCode.LABEL_AUTHORITY_INVALID),
        ("review", M5TrainingLabelProvenanceErrorCode.REVIEW_AUTHORITY_INVALID),
        ("terminal_predecessor", M5TrainingLabelProvenanceErrorCode.TERMINAL_AUTHORITY_INVALID),
        ("intent", M5TrainingLabelProvenanceErrorCode.RESOLUTION_INTENT_INVALID),
        ("commit_receipt", M5TrainingLabelProvenanceErrorCode.RESOLUTION_COMMIT_INVALID),
        ("commit_effect", M5TrainingLabelProvenanceErrorCode.RESOLUTION_COMMIT_INVALID),
        ("marker", M5TrainingLabelProvenanceErrorCode.RESOLUTION_MARKER_INVALID),
    ],
)
def test_resolver_returns_exact_typed_code_for_each_broken_root(
    mismatch: str,
    expected_code: M5TrainingLabelProvenanceErrorCode,
) -> None:
    chain = _chain()
    authority = chain.label_authorities[0]
    provenance = authority.strong_provenance
    assert provenance is not None
    updates: dict[str, object] = {}

    if mismatch == "label":
        forged_label = authority.label.model_copy(update={"case_id": "another-case"})
        updates["authority"] = M5TrainingLabelAuthority.model_construct(
            label=forged_label,
            strong_provenance=provenance,
        )
    elif mismatch == "review":
        updates["review_authority"] = chain.review_authority.model_copy(
            update={"assigned_reviewer_id": "reviewer-2"}
        )
    elif mismatch == "terminal_predecessor":
        forged_terminal = chain.terminal_authority.model_copy(
            update={"previous_authority_sha256": "f" * 64}
        )
        forged_provenance = _constructed_copy(
            provenance,
            terminal_authority_sha256=forged_terminal.authority_sha256,
        )
        updates["authority"] = M5TrainingLabelAuthority.model_construct(
            label=authority.label,
            strong_provenance=forged_provenance,
        )
        updates["terminal_authority"] = forged_terminal
    elif mismatch == "intent":
        updates["resolution_intent"] = _constructed_copy(
            chain.intent,
            training_labels=(),
        )
    elif mismatch == "commit_receipt":
        forged_provenance = _constructed_copy(
            provenance,
            resolution_commit_receipt_id="f" * 64,
        )
        updates["authority"] = M5TrainingLabelAuthority.model_construct(
            label=authority.label,
            strong_provenance=forged_provenance,
        )
    elif mismatch == "commit_effect":
        forged_provenance = _constructed_copy(
            provenance,
            resolution_commit_effect_root_sha256="f" * 64,
        )
        updates["authority"] = M5TrainingLabelAuthority.model_construct(
            label=authority.label,
            strong_provenance=forged_provenance,
        )
    else:
        updates["resolution_commit_event"] = chain.commit_event.model_copy(
            update={"source_document_sha256": "f" * 64}
        )

    with pytest.raises(M5TrainingLabelProvenanceError) as failure:
        _resolve(chain, **updates)
    assert failure.value.code is expected_code


def test_builder_rejects_a_final_commit_that_does_not_close_the_intent() -> None:
    _, intent = _intent(AppealStatus.UPHELD)
    receipt = _commit_receipt(intent).model_copy(update={"resolution_document_sha256": "f" * 64})

    with pytest.raises(M5TrainingLabelProvenanceError) as failure:
        build_m5_strong_training_label_provenance_receipts(
            intent=intent,
            resolution_commit_receipt=receipt,
        )
    assert failure.value.code is M5TrainingLabelProvenanceErrorCode.RESOLUTION_COMMIT_INVALID


def test_forged_serialized_computed_root_and_model_construct_bypass_fail_closed() -> None:
    chain = _chain()
    authority = chain.label_authorities[0]
    provenance = authority.strong_provenance
    assert provenance is not None

    serialized = provenance.model_dump(mode="json")
    serialized["provenance_id"] = "f" * 64
    with pytest.raises(ValidationError, match="provenance_id"):
        M5StrongTrainingLabelProvenanceReceipt.model_validate(serialized)

    forged_provenance = _constructed_copy(
        provenance,
        resolution_intent_id="f" * 64,
    )
    forged_authority = M5TrainingLabelAuthority.model_construct(
        label=authority.label,
        strong_provenance=forged_provenance,
    )
    with pytest.raises(M5TrainingLabelProvenanceError) as failure:
        _resolve(chain, authority=forged_authority)
    assert failure.value.code is M5TrainingLabelProvenanceErrorCode.RESOLUTION_INTENT_INVALID
