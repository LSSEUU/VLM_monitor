"""Append-only Pending/Record/Seal boundary for CLOSED-policy replay."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ValidationError

from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    M6ReplayLockedClosedPolicySampleExecutionRecordV2,
)
from labcourt.exceptions import ContractViolation

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedClosedPolicyLedgerFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_CONFLICT = "SCOPE_CONFLICT"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    PENDING_CONFLICT = "PENDING_CONFLICT"
    RECORD_CONFLICT = "RECORD_CONFLICT"
    SEAL_CONFLICT = "SEAL_CONFLICT"
    CHAIN_MISMATCH = "CHAIN_MISMATCH"
    EXECUTION_SEALED = "EXECUTION_SEALED"
    COMMIT_OUTCOME_UNKNOWN = "COMMIT_OUTCOME_UNKNOWN"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6ReplayLockedClosedPolicyLedgerError(ContractViolation):
    """Payload-free CLOSED-policy ledger failure."""

    def __init__(
        self,
        reason_code: M6ReplayLockedClosedPolicyLedgerFailureCode,
    ) -> None:
        if not isinstance(
            reason_code,
            M6ReplayLockedClosedPolicyLedgerFailureCode,
        ):
            raise TypeError("reason_code must be an M6 CLOSED-policy ledger failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 CLOSED-policy ledger failed: {reason_code.value}")


class M6ReplayLockedClosedPolicyLedgerStatus(StrEnum):
    READY_FOR_PENDING = "READY_FOR_PENDING"
    PENDING = "PENDING"
    READY_TO_SEAL = "READY_TO_SEAL"
    SEALED = "SEALED"


def _canonical(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        raise TypeError("M6 CLOSED-policy ledger contains another contract type")
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("M6 CLOSED-policy ledger contains a non-canonical contract") from None
    if controlled != value:
        raise ValueError("M6 CLOSED-policy ledger contains a non-canonical contract")
    return controlled


@dataclass(frozen=True, slots=True)
class M6ReplayLockedClosedPolicyExecutionResumeV2:
    execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2
    pending_commitments: tuple[
        M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        ...,
    ]
    sample_records: tuple[
        M6ReplayLockedClosedPolicySampleExecutionRecordV2,
        ...,
    ]
    execution_seal: M6ReplayLockedClosedPolicyExecutionSealAuthorityV2 | None = None

    def __post_init__(self) -> None:
        scope = _canonical(
            self.execution_scope,
            M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        )
        pending = tuple(
            _canonical(
                item,
                M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
            )
            for item in self.pending_commitments
        )
        records = tuple(
            _canonical(
                item,
                M6ReplayLockedClosedPolicySampleExecutionRecordV2,
            )
            for item in self.sample_records
        )
        seal = (
            _canonical(
                self.execution_seal,
                M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
            )
            if self.execution_seal is not None
            else None
        )
        pre_scope = scope.pre_policy_execution_scope
        entries = pre_scope.execution_dataset.entries
        entry_count = len(entries)
        if (
            len(records) > entry_count
            or len(pending) not in {len(records), len(records) + 1}
            or len(pending) > entry_count
        ):
            raise ValueError("M6 CLOSED-policy ledger Pending/Record cardinality is invalid")
        previous = AUDIT_GENESIS_HASH
        seen_candidate_case_ids: set[str] = set()
        supported_routes = set(pre_scope.execution_component.supported_routes)
        for index, commitment in enumerate(pending):
            if (
                commitment.ledger_sequence != index
                or commitment.previous_ledger_entry_hash != previous
                or commitment.execution_scope_authority_id != scope.execution_scope_authority_id
                or commitment.execution_component_authority_id
                != scope.execution_component.component_authority_id
                or commitment.pre_policy_execution_scope_authority_id
                != pre_scope.execution_scope_authority_id
                or commitment.pre_policy_execution_component_authority_id
                != pre_scope.execution_component.component_authority_id
                or commitment.candidate_run_id != scope.candidate_run_id
                or commitment.command_id != scope.command_id
                or commitment.execution_dataset_snapshot_id != scope.execution_dataset_snapshot_id
                or commitment.locked_config_sha256 != scope.locked_config_sha256
                or commitment.source_catalog_entry_id != pre_scope.source_catalog_entry_ids[index]
                or commitment.pre_policy_pending_commitment.execution_entry != entries[index]
                or commitment.pre_policy_route not in supported_routes
            ):
                raise ValueError("M6 CLOSED-policy Pending chain differs from its scope")
            if index < len(records):
                record = records[index]
                binding = record.closed_candidate_binding
                if (
                    record.pending_commitment != commitment
                    or record.ledger_sequence != index
                    or record.previous_ledger_entry_hash != previous
                    or record.execution_scope_authority_id != scope.execution_scope_authority_id
                    or record.candidate_run_id != scope.candidate_run_id
                    or record.command_id != scope.command_id
                    or record.execution_dataset_snapshot_id != scope.execution_dataset_snapshot_id
                    or record.candidate_manifest_id != scope.candidate_manifest_id
                    or record.execution_entry != entries[index]
                    or record.source_determinism.execution_component_manifest_id
                    != pre_scope.execution_component.component_authority_id
                    or binding.persisted_candidate_case.case_audit_sequence != index
                    or binding.case_id in seen_candidate_case_ids
                ):
                    raise ValueError("M6 CLOSED-policy Record differs from its Pending")
                seen_candidate_case_ids.add(binding.case_id)
                previous = record.sample_execution_record_id
        if seal is not None and (
            len(records) != entry_count
            or len(pending) != entry_count
            or seal.execution_scope != scope
            or seal.sample_executions != records
        ):
            raise ValueError("M6 CLOSED-policy Seal differs from its terminal chain")
        object.__setattr__(self, "execution_scope", scope)
        object.__setattr__(self, "pending_commitments", pending)
        object.__setattr__(self, "sample_records", records)
        object.__setattr__(self, "execution_seal", seal)

    @property
    def committed_sample_count(self) -> int:
        return len(self.sample_records)

    @property
    def ledger_head_hash(self) -> str:
        if not self.sample_records:
            return AUDIT_GENESIS_HASH
        return self.sample_records[-1].sample_execution_record_id

    @property
    def next_ledger_sequence(self) -> int:
        return len(self.sample_records)

    @property
    def status(self) -> M6ReplayLockedClosedPolicyLedgerStatus:
        if self.execution_seal is not None:
            return M6ReplayLockedClosedPolicyLedgerStatus.SEALED
        if len(self.sample_records) == len(
            self.execution_scope.pre_policy_execution_scope.execution_dataset.entries
        ):
            return M6ReplayLockedClosedPolicyLedgerStatus.READY_TO_SEAL
        if len(self.pending_commitments) == len(self.sample_records) + 1:
            return M6ReplayLockedClosedPolicyLedgerStatus.PENDING
        return M6ReplayLockedClosedPolicyLedgerStatus.READY_FOR_PENDING


@runtime_checkable
class M6ReplayLockedClosedPolicyLedgerRepository(Protocol):
    def resume(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    ) -> M6ReplayLockedClosedPolicyExecutionResumeV2: ...

    def persist_pending(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        pending_commitment: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
        canonical_document: str,
    ) -> M6ReplayLockedClosedPolicyExecutionResumeV2: ...

    def append_record(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        sample_record: M6ReplayLockedClosedPolicySampleExecutionRecordV2,
        canonical_document: str,
    ) -> M6ReplayLockedClosedPolicyExecutionResumeV2: ...

    def seal(
        self,
        execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        execution_seal: M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
        canonical_document: str,
    ) -> M6ReplayLockedClosedPolicyExecutionResumeV2: ...


__all__ = [
    "M6ReplayLockedClosedPolicyExecutionResumeV2",
    "M6ReplayLockedClosedPolicyLedgerError",
    "M6ReplayLockedClosedPolicyLedgerFailureCode",
    "M6ReplayLockedClosedPolicyLedgerRepository",
    "M6ReplayLockedClosedPolicyLedgerStatus",
]
