"""Build and resolve fail-closed provenance for strong M5 training labels."""

from __future__ import annotations

from enum import StrEnum

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import AppealStatus
from labcourt.contracts.m5_appeals import (
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    M5AppealResolutionCommitReceipt,
)
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_precedent_causal_ledger import (
    M5PrecedentCausalEvent,
    M5PrecedentCausalEventKind,
)
from labcourt.contracts.m5_training_provenance import (
    M5StrongTrainingLabelProvenanceReceipt,
    M5TrainingLabelAuthority,
)
from labcourt.exceptions import LabCourtError


class M5TrainingLabelProvenanceErrorCode(StrEnum):
    LABEL_AUTHORITY_INVALID = "LABEL_AUTHORITY_INVALID"
    REVIEW_AUTHORITY_INVALID = "REVIEW_AUTHORITY_INVALID"
    TERMINAL_AUTHORITY_INVALID = "TERMINAL_AUTHORITY_INVALID"
    RESOLUTION_INTENT_INVALID = "RESOLUTION_INTENT_INVALID"
    RESOLUTION_COMMIT_INVALID = "RESOLUTION_COMMIT_INVALID"
    RESOLUTION_MARKER_INVALID = "RESOLUTION_MARKER_INVALID"


class M5TrainingLabelProvenanceError(LabCourtError):
    def __init__(self, code: M5TrainingLabelProvenanceErrorCode) -> None:
        if not isinstance(code, M5TrainingLabelProvenanceErrorCode):
            raise TypeError("code must be an M5TrainingLabelProvenanceErrorCode")
        self.code = code
        super().__init__(f"M5 strong training label provenance failed: {code.value}")


def _document_sha256(document: object) -> str:
    model_dump = getattr(document, "model_dump", None)
    if not callable(model_dump):
        raise TypeError("provenance document must be a contract model")
    return sha256_hex(model_dump(mode="json"))


def _require_commit_closes_intent(
    intent: AppealResolutionSideEffectIntent,
    receipt: M5AppealResolutionCommitReceipt,
) -> None:
    terminal = intent.appeal_authority
    replacement = intent.appeal_precedent_authority
    expected = (
        intent.run_id,
        intent.intent_id,
        _document_sha256(intent),
        terminal.appeal.appeal_id,
        terminal.authority_sha256,
        intent.case_id,
        terminal.source_case_revision,
        tuple(label.label_id for label in intent.training_labels),
        replacement.authority_id if replacement is not None else None,
        intent.affected_citations.report_sha256,
        intent.manifest_id,
    )
    observed = (
        receipt.run_id,
        receipt.resolution_intent_id,
        receipt.resolution_document_sha256,
        receipt.appeal_id,
        receipt.appeal_authority_sha256,
        receipt.case_id,
        receipt.source_case_revision,
        receipt.training_label_ids,
        receipt.replacement_precedent_authority_id,
        receipt.affected_citation_report_sha256,
        receipt.manifest_id,
    )
    if observed != expected:
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.RESOLUTION_COMMIT_INVALID
        )


def build_m5_strong_training_label_provenance_receipts(
    *,
    intent: AppealResolutionSideEffectIntent,
    resolution_commit_receipt: M5AppealResolutionCommitReceipt,
) -> tuple[M5StrongTrainingLabelProvenanceReceipt, ...]:
    """Bind every strong label to the exact terminal appeal transaction roots."""

    if not isinstance(intent, AppealResolutionSideEffectIntent):
        raise TypeError("intent must be an AppealResolutionSideEffectIntent")
    if not isinstance(resolution_commit_receipt, M5AppealResolutionCommitReceipt):
        raise TypeError("resolution_commit_receipt must be an M5AppealResolutionCommitReceipt")
    terminal = intent.appeal_authority
    review_authority_sha256 = terminal.previous_authority_sha256
    reviewer_id = terminal.assigned_reviewer_id
    terminal_status = terminal.appeal.status
    if (
        terminal.version != 3
        or review_authority_sha256 is None
        or reviewer_id is None
        or terminal_status not in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
    ):
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.TERMINAL_AUTHORITY_INVALID
        )
    _require_commit_closes_intent(intent, resolution_commit_receipt)

    receipts: list[M5StrongTrainingLabelProvenanceReceipt] = []
    for label in intent.training_labels:
        authored_input = M5AppealTrainingLabelInput(
            crop_id=label.crop_id,
            bbox=label.bbox,
            label_name=label.label_name,
            label_value=label.label_value,
        )
        receipt = M5StrongTrainingLabelProvenanceReceipt(
            run_id=intent.run_id,
            case_id=intent.case_id,
            appeal_id=terminal.appeal.appeal_id,
            label_id=label.label_id,
            label_document_sha256=_document_sha256(label),
            crop_id=label.crop_id,
            reviewer_id=reviewer_id,
            quality=label.quality,
            authored_input=authored_input,
            review_authority_sha256=review_authority_sha256,
            terminal_authority_sha256=terminal.authority_sha256,
            terminal_status=terminal_status,
            resolution_intent_id=intent.intent_id,
            resolution_document_sha256=_document_sha256(intent),
            resolution_commit_receipt_id=resolution_commit_receipt.receipt_id,
            resolution_commit_effect_root_sha256=(resolution_commit_receipt.effect_root_sha256),
            manifest_id=intent.manifest_id,
            rule_version=intent.rule_version,
            detector_manifest_id=(terminal.source_case_authority.detector_manifest_id),
        )
        # Reuse the formal wrapper here so a future contract change cannot make
        # the write path weaker than the export path.
        M5TrainingLabelAuthority(label=label, strong_provenance=receipt)
        receipts.append(receipt)
    result = tuple(sorted(receipts, key=lambda item: item.label_id))
    if tuple(item.label_id for item in result) != resolution_commit_receipt.training_label_ids:
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.RESOLUTION_COMMIT_INVALID
        )
    return result


def require_m5_strong_training_label_provenance(
    *,
    authority: M5TrainingLabelAuthority,
    review_authority: AppealVersionAuthority,
    terminal_authority: AppealVersionAuthority,
    resolution_intent: AppealResolutionSideEffectIntent,
    resolution_commit_receipt: M5AppealResolutionCommitReceipt,
    resolution_commit_event: M5PrecedentCausalEvent,
) -> M5TrainingLabelAuthority:
    """Resolve one compact receipt through every durable human-decision root."""

    if not isinstance(authority, M5TrainingLabelAuthority):
        raise TypeError("authority must be an M5TrainingLabelAuthority")
    provenance = authority.strong_provenance
    if provenance is None:
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.LABEL_AUTHORITY_INVALID
        )
    label = authority.label
    if (
        provenance.label_id != label.label_id
        or provenance.label_document_sha256 != authority.label_document_sha256
    ):
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.LABEL_AUTHORITY_INVALID
        )

    if (
        review_authority.version != 2
        or review_authority.appeal.status != AppealStatus.UNDER_REVIEW
        or review_authority.authority_sha256 != provenance.review_authority_sha256
        or review_authority.run_id != provenance.run_id
        or review_authority.appeal.case_id != provenance.case_id
        or review_authority.appeal.appeal_id != provenance.appeal_id
        or review_authority.assigned_reviewer_id != provenance.reviewer_id
    ):
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.REVIEW_AUTHORITY_INVALID
        )

    if (
        terminal_authority.version != 3
        or terminal_authority.authority_sha256 != provenance.terminal_authority_sha256
        or terminal_authority.previous_authority_sha256 != review_authority.authority_sha256
        or terminal_authority.run_id != provenance.run_id
        or terminal_authority.appeal.case_id != provenance.case_id
        or terminal_authority.appeal.appeal_id != provenance.appeal_id
        or terminal_authority.appeal.status != provenance.terminal_status
        or terminal_authority.assigned_reviewer_id != provenance.reviewer_id
        or terminal_authority.manifest_id != provenance.manifest_id
        or terminal_authority.rule_version != provenance.rule_version
        or terminal_authority.source_case_authority.detector_manifest_id
        != provenance.detector_manifest_id
    ):
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.TERMINAL_AUTHORITY_INVALID
        )

    matching_labels = tuple(
        item for item in resolution_intent.training_labels if item.label_id == provenance.label_id
    )
    if (
        resolution_intent.appeal_authority != terminal_authority
        or resolution_intent.run_id != provenance.run_id
        or resolution_intent.case_id != provenance.case_id
        or resolution_intent.intent_id != provenance.resolution_intent_id
        or _document_sha256(resolution_intent) != provenance.resolution_document_sha256
        or resolution_intent.manifest_id != provenance.manifest_id
        or len(matching_labels) != 1
        or matching_labels[0] != label
    ):
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.RESOLUTION_INTENT_INVALID
        )

    try:
        _require_commit_closes_intent(resolution_intent, resolution_commit_receipt)
    except M5TrainingLabelProvenanceError as exc:
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.RESOLUTION_COMMIT_INVALID
        ) from exc
    if (
        resolution_commit_receipt.receipt_id != provenance.resolution_commit_receipt_id
        or resolution_commit_receipt.effect_root_sha256
        != provenance.resolution_commit_effect_root_sha256
    ):
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.RESOLUTION_COMMIT_INVALID
        )

    commit_document_sha256 = _document_sha256(resolution_commit_receipt)
    if (
        resolution_commit_event.event_kind != M5PrecedentCausalEventKind.APPEAL_RESOLUTION_COMMITTED
        or resolution_commit_event.run_id != provenance.run_id
        or resolution_commit_event.source_id != provenance.resolution_commit_receipt_id
        or resolution_commit_event.manifest_id != provenance.manifest_id
        or resolution_commit_event.source_document_sha256 != commit_document_sha256
        or resolution_commit_event.precedent_id is not None
        or resolution_commit_event.precedent_authority_id is not None
        or resolution_commit_event.precedent_revision is not None
        or resolution_commit_event.citation_kind is not None
    ):
        raise M5TrainingLabelProvenanceError(
            M5TrainingLabelProvenanceErrorCode.RESOLUTION_MARKER_INVALID
        )
    return authority


__all__ = [
    "M5TrainingLabelProvenanceError",
    "M5TrainingLabelProvenanceErrorCode",
    "build_m5_strong_training_label_provenance_receipts",
    "require_m5_strong_training_label_provenance",
]
