"""Pure construction of M8.7 adapter commissioning persistence receipts."""

from __future__ import annotations

import hashlib

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import (
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


__all__ = ["build_adapter_candidate_commit", "build_commissioning_evidence_commit"]
