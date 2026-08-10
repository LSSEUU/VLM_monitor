"""Pure construction of M8.7 adapter commissioning persistence receipts."""

from __future__ import annotations

import hashlib
from datetime import datetime

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import (
    M8AdapterReadinessAssessmentV1,
    M8CommissioningEvidenceAuthorityV1,
    M8CommissioningEvidenceCommitReceiptV1,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterCandidateCommitReceiptV1,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1


def build_adapter_candidate_commit(
    candidate: M8ProductionAdapterCandidateAuthorityV1,
    registrar_actor_receipt: M8ActorAuthorityCommitReceiptV1,
    repository_manifest_id: Sha256Hex,
) -> M8ProductionAdapterCandidateCommitReceiptV1:
    return M8ProductionAdapterCandidateCommitReceiptV1(
        candidate=candidate,
        registered_by_actor_receipt=registrar_actor_receipt,
        repository_manifest_id=repository_manifest_id,
    )


def build_commissioning_evidence_commit(
    evidence: M8CommissioningEvidenceAuthorityV1,
    artifact_bytes: bytes,
    candidate_receipt: M8ProductionAdapterCandidateCommitReceiptV1,
    current_reviewer_receipt: M8ActorAuthorityCommitReceiptV1,
    artifact_storage_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
) -> M8CommissioningEvidenceCommitReceiptV1:
    if not isinstance(artifact_bytes, bytes):
        raise TypeError("M8 commissioning artifact must be exact bytes")
    if candidate_receipt.candidate != evidence.candidate:
        raise ValueError("M8 commissioning evidence candidate is not registered")
    if (
        current_reviewer_receipt.commit_receipt_id
        != evidence.reviewer_actor_receipt.commit_receipt_id
    ):
        raise ValueError("M8 commissioning evidence reviewer is not current")
    if (
        len(artifact_bytes) != evidence.artifact_size_bytes
        or hashlib.sha256(artifact_bytes).hexdigest() != evidence.artifact_sha256
    ):
        raise ValueError("M8 commissioning artifact hash or size does not match evidence")
    return M8CommissioningEvidenceCommitReceiptV1(
        evidence=evidence,
        artifact_storage_manifest_id=artifact_storage_manifest_id,
        repository_manifest_id=repository_manifest_id,
    )


def build_adapter_readiness_assessment(
    candidate_receipt: M8ProductionAdapterCandidateCommitReceiptV1,
    evidence_receipts: tuple[M8CommissioningEvidenceCommitReceiptV1, ...],
    assessor_actor_receipt: M8ActorAuthorityCommitReceiptV1,
    assessed_at: datetime,
    assessment_manifest_id: Sha256Hex,
) -> M8AdapterReadinessAssessmentV1:
    receipt_ids = tuple(item.commit_receipt_id for item in evidence_receipts)
    if len(receipt_ids) != len(set(receipt_ids)):
        raise ValueError("M8 readiness input cannot duplicate evidence receipts")
    if any(
        item.evidence.candidate != candidate_receipt.candidate
        or item.repository_manifest_id != candidate_receipt.repository_manifest_id
        for item in evidence_receipts
    ):
        raise ValueError("M8 readiness evidence is outside the persisted candidate scope")
    if assessor_actor_receipt.repository_manifest_id != candidate_receipt.repository_manifest_id:
        raise ValueError("M8 readiness assessor uses another repository manifest")
    latest_by_kind: dict[str, M8CommissioningEvidenceCommitReceiptV1] = {}
    for receipt in evidence_receipts:
        kind = receipt.evidence.evidence_kind.value
        prior = latest_by_kind.get(kind)
        if prior is None or (
            receipt.evidence.reviewed_at,
            receipt.evidence.evidence_authority_id,
        ) > (
            prior.evidence.reviewed_at,
            prior.evidence.evidence_authority_id,
        ):
            latest_by_kind[kind] = receipt
    selected = tuple(latest_by_kind[kind] for kind in sorted(latest_by_kind))
    return M8AdapterReadinessAssessmentV1(
        candidate=candidate_receipt.candidate,
        evidence=selected,
        assessor_actor_receipt=assessor_actor_receipt,
        assessed_at=assessed_at,
        assessment_manifest_id=assessment_manifest_id,
    )


__all__ = [
    "build_adapter_candidate_commit",
    "build_adapter_readiness_assessment",
    "build_commissioning_evidence_commit",
]
