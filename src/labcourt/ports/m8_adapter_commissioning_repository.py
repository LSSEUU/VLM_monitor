"""Persistence port for append-only M8 production-adapter commissioning evidence."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_adapter_commissioning import (
    M8CommissioningEvidenceAuthorityV1,
    M8CommissioningEvidenceCommitReceiptV1,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterCandidateCommitReceiptV1,
)


class M8AdapterCommissioningRepository(Protocol):
    def register_candidate(
        self,
        candidate: M8ProductionAdapterCandidateAuthorityV1,
        registrar_actor_id: str,
    ) -> M8ProductionAdapterCandidateCommitReceiptV1: ...

    def get_candidate(
        self,
        candidate_authority_id: str,
    ) -> M8ProductionAdapterCandidateCommitReceiptV1: ...

    def commit_evidence(
        self,
        evidence: M8CommissioningEvidenceAuthorityV1,
        artifact_bytes: bytes,
        artifact_storage_manifest_id: str,
    ) -> M8CommissioningEvidenceCommitReceiptV1: ...

    def get_evidence(
        self,
        evidence_authority_id: str,
    ) -> M8CommissioningEvidenceCommitReceiptV1: ...

    def list_candidate_evidence(
        self,
        candidate_authority_id: str,
        limit: int,
    ) -> tuple[M8CommissioningEvidenceCommitReceiptV1, ...]: ...

    def read_artifact(self, artifact_ref: str) -> bytes: ...


__all__ = ["M8AdapterCommissioningRepository"]
