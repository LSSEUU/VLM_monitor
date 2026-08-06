"""Append-only Pending/Record/Seal persistence boundary for M6 locked execution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ValidationError

from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedExecutionSealAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
    M6ReplayLockedSampleExecutionRecord,
)
from labcourt.exceptions import ContractViolation

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6ReplayLockedLedgerFailureCode(StrEnum):
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


class M6ReplayLockedLedgerError(ContractViolation):
    """Payload-free locked execution ledger failure."""

    def __init__(self, reason_code: M6ReplayLockedLedgerFailureCode) -> None:
        if not isinstance(reason_code, M6ReplayLockedLedgerFailureCode):
            raise TypeError("reason_code must be an M6 locked ledger failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 locked execution ledger failed: {reason_code.value}")


class M6ReplayLockedLedgerStatus(StrEnum):
    READY_FOR_PENDING = "READY_FOR_PENDING"
    PENDING = "PENDING"
    READY_TO_SEAL = "READY_TO_SEAL"
    SEALED = "SEALED"


def _canonical(value: object, expected: type[_ModelT]) -> _ModelT:
    if type(value) is not expected:
        raise TypeError("M6 locked ledger contains another contract type")
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise ValueError("M6 locked ledger contains a non-canonical contract") from None
    if controlled != value:
        raise ValueError("M6 locked ledger contains a non-canonical contract")
    return controlled


@dataclass(frozen=True, slots=True)
class M6ReplayLockedExecutionResume:
    execution_scope: M6ReplayLockedExecutionScopeAuthority
    pending_commitments: tuple[M6ReplayLockedPendingSampleCommitmentAuthority, ...]
    sample_records: tuple[M6ReplayLockedSampleExecutionRecord, ...]
    execution_seal: M6ReplayLockedExecutionSealAuthority | None = None

    def __post_init__(self) -> None:
        scope = _canonical(
            self.execution_scope,
            M6ReplayLockedExecutionScopeAuthority,
        )
        pending = tuple(
            _canonical(item, M6ReplayLockedPendingSampleCommitmentAuthority)
            for item in self.pending_commitments
        )
        records = tuple(
            _canonical(item, M6ReplayLockedSampleExecutionRecord) for item in self.sample_records
        )
        seal = (
            _canonical(self.execution_seal, M6ReplayLockedExecutionSealAuthority)
            if self.execution_seal is not None
            else None
        )
        entry_count = len(scope.execution_dataset.entries)
        if (
            len(records) > entry_count
            or len(pending) not in {len(records), len(records) + 1}
            or len(pending) > entry_count
        ):
            raise ValueError("M6 locked ledger Pending/Record cardinality is invalid")
        previous = AUDIT_GENESIS_HASH
        seen_candidate_case_ids: set[str] = set()
        supported_routes = set(scope.execution_component.supported_routes)
        for index, commitment in enumerate(pending):
            if (
                commitment.ledger_sequence != index
                or commitment.previous_ledger_entry_hash != previous
                or commitment.execution_scope_authority_id != scope.execution_scope_authority_id
                or commitment.candidate_run_id != scope.candidate_run_id
                or commitment.command_id != scope.command.command_id
                or commitment.execution_dataset_snapshot_id
                != scope.execution_dataset.execution_dataset_snapshot_id
                or commitment.execution_component_authority_id
                != scope.execution_component.component_authority_id
                or commitment.source_catalog_entry_id != scope.source_catalog_entry_ids[index]
                or commitment.execution_entry != scope.execution_dataset.entries[index]
            ):
                raise ValueError("M6 locked ledger Pending chain differs from its scope")
            if index < len(records):
                record = records[index]
                if (
                    record.pending_commitment != commitment
                    or record.ledger_sequence != index
                    or record.previous_ledger_entry_hash != previous
                    or record.execution_scope_authority_id != scope.execution_scope_authority_id
                    or record.candidate_run_id != scope.candidate_run_id
                    or record.command_id != scope.command.command_id
                    or record.execution_dataset_snapshot_id
                    != scope.execution_dataset.execution_dataset_snapshot_id
                    or record.candidate_manifest_id != scope.locked_manifest.manifest_id
                    or record.execution_entry != scope.execution_dataset.entries[index]
                    or record.route not in supported_routes
                    or record.pending_commitment.execution_component_authority_id
                    != scope.execution_component.component_authority_id
                    or record.source_determinism.execution_component_manifest_id
                    != scope.execution_component.component_authority_id
                    or record.candidate_case.case_audit_sequence != index
                    or record.candidate_case.case_id in seen_candidate_case_ids
                ):
                    raise ValueError("M6 locked ledger Record differs from its Pending")
                seen_candidate_case_ids.add(record.candidate_case.case_id)
                previous = record.sample_execution_record_id
        if seal is not None and (
            len(records) != entry_count
            or len(pending) != entry_count
            or seal.execution_scope != scope
            or seal.sample_executions != records
        ):
            raise ValueError("M6 locked ledger Seal differs from its terminal chain")
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
    def status(self) -> M6ReplayLockedLedgerStatus:
        if self.execution_seal is not None:
            return M6ReplayLockedLedgerStatus.SEALED
        if len(self.sample_records) == len(self.execution_scope.execution_dataset.entries):
            return M6ReplayLockedLedgerStatus.READY_TO_SEAL
        if len(self.pending_commitments) == len(self.sample_records) + 1:
            return M6ReplayLockedLedgerStatus.PENDING
        return M6ReplayLockedLedgerStatus.READY_FOR_PENDING


@runtime_checkable
class M6ReplayLockedLedgerRepository(Protocol):
    def resume(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
    ) -> M6ReplayLockedExecutionResume: ...

    def persist_pending(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority,
        canonical_document: str,
    ) -> M6ReplayLockedExecutionResume: ...

    def append_record(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        sample_record: M6ReplayLockedSampleExecutionRecord,
        canonical_document: str,
    ) -> M6ReplayLockedExecutionResume: ...

    def seal(
        self,
        execution_scope: M6ReplayLockedExecutionScopeAuthority,
        execution_seal: M6ReplayLockedExecutionSealAuthority,
        canonical_document: str,
    ) -> M6ReplayLockedExecutionResume: ...


__all__ = [
    "M6ReplayLockedExecutionResume",
    "M6ReplayLockedLedgerError",
    "M6ReplayLockedLedgerFailureCode",
    "M6ReplayLockedLedgerRepository",
    "M6ReplayLockedLedgerStatus",
]
