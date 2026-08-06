"""Persistence boundary for the observation-backed M6 upgrade ledger V2."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m6_regression import M6RegressionExecutionEntry
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.exceptions import ContractViolation


class M6UpgradeExecutionLedgerV2FailureCode(StrEnum):
    """Controlled V2 failures without database text, paths, or authority payloads."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_CONFLICT = "SCOPE_CONFLICT"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    LEDGER_VERSION_UNSUPPORTED = "LEDGER_VERSION_UNSUPPORTED"
    LEGACY_LEDGER_UNSUPPORTED = "LEGACY_LEDGER_UNSUPPORTED"
    OBSERVATION_NOT_FOUND = "OBSERVATION_NOT_FOUND"
    COMMITMENT_NOT_FOUND = "COMMITMENT_NOT_FOUND"
    COMMITMENT_CONFLICT = "COMMITMENT_CONFLICT"
    SAMPLE_CONFLICT = "SAMPLE_CONFLICT"
    SAMPLE_OUT_OF_ORDER = "SAMPLE_OUT_OF_ORDER"
    PHYSICAL_ARTIFACT_REJECTED = "PHYSICAL_ARTIFACT_REJECTED"
    LEDGER_SEALED = "LEDGER_SEALED"
    LEDGER_INCOMPLETE = "LEDGER_INCOMPLETE"
    LEDGER_NOT_SEALED = "LEDGER_NOT_SEALED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    STORED_AUTHORITY_INVALID = "STORED_AUTHORITY_INVALID"
    STORAGE_REJECTED = "STORAGE_REJECTED"


class M6UpgradeExecutionLedgerV2Error(ContractViolation):
    """Typed, payload-free failure at the V2 ledger persistence boundary."""

    def __init__(self, reason_code: M6UpgradeExecutionLedgerV2FailureCode) -> None:
        if not isinstance(reason_code, M6UpgradeExecutionLedgerV2FailureCode):
            raise TypeError("reason_code must be an M6UpgradeExecutionLedgerV2FailureCode")
        self.reason_code = reason_code
        super().__init__(f"M6 upgrade execution ledger V2 failed: {reason_code.value}")


class M6UpgradeExecutionLedgerV2Status(StrEnum):
    """Durable restart phase for one observation-backed sample pipeline."""

    READY_FOR_OBSERVATION = "READY_FOR_OBSERVATION"
    READY_FOR_COMMITMENT = "READY_FOR_COMMITMENT"
    READY_FOR_LEDGER_APPEND = "READY_FOR_LEDGER_APPEND"
    READY_TO_SEAL = "READY_TO_SEAL"
    SEALED = "SEALED"


def _is_lower_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and not any(character not in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True)
class M6UpgradeExecutionResumeV2:
    """Validated V2 restart point derived only from persisted authorities."""

    status: M6UpgradeExecutionLedgerV2Status
    execution_scope: M6UpgradeExecutionScopeAuthority
    committed_sample_count: int
    ledger_head_hash: str
    next_execution_entry: M6RegressionExecutionEntry | None
    pending_observation: M6UpgradeSampleExecutionObservationAuthority | None = None
    pending_commitment: M6UpgradePendingSampleCommitmentAuthority | None = None
    seal: M6UpgradeExecutionLedgerSealV2 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, M6UpgradeExecutionLedgerV2Status):
            raise TypeError("status must be an M6UpgradeExecutionLedgerV2Status")
        if type(self.execution_scope) is not M6UpgradeExecutionScopeAuthority:
            raise TypeError("execution_scope must be an exact typed M6 execution scope")
        if (
            not isinstance(self.committed_sample_count, int)
            or isinstance(self.committed_sample_count, bool)
            or self.committed_sample_count < 0
        ):
            raise ValueError("committed_sample_count must be a non-negative integer")
        if not _is_lower_sha256(self.ledger_head_hash):
            raise ValueError("ledger_head_hash must be a lowercase SHA-256")
        if (
            self.next_execution_entry is not None
            and type(self.next_execution_entry) is not M6RegressionExecutionEntry
        ):
            raise TypeError("next_execution_entry must be an exact typed execution entry")
        if (
            self.pending_observation is not None
            and type(self.pending_observation) is not M6UpgradeSampleExecutionObservationAuthority
        ):
            raise TypeError("pending_observation must be an exact typed M6 observation")
        if (
            self.pending_commitment is not None
            and type(self.pending_commitment) is not M6UpgradePendingSampleCommitmentAuthority
        ):
            raise TypeError("pending_commitment must be an exact typed M6 commitment")
        if self.seal is not None and type(self.seal) is not M6UpgradeExecutionLedgerSealV2:
            raise TypeError("seal must be an exact typed M6 V2 ledger seal")

        entries = self.execution_scope.execution_dataset.entries
        expected_count = len(entries)
        if self.committed_sample_count > expected_count:
            raise ValueError("committed samples exceed the execution dataset")
        if (
            self.committed_sample_count == 0
            and self.ledger_head_hash != M6_UPGRADE_LEDGER_GENESIS_HASH
        ):
            raise ValueError("empty M6 V2 ledger must use the ledger genesis hash")

        if self.status == M6UpgradeExecutionLedgerV2Status.READY_FOR_OBSERVATION:
            self._validate_ready_for_observation(entries)
        elif self.status == M6UpgradeExecutionLedgerV2Status.READY_FOR_COMMITMENT:
            self._validate_pending_observation(entries)
            if self.pending_commitment is not None or self.seal is not None:
                raise ValueError("ready-for-commitment M6 V2 state is inconsistent")
        elif self.status == M6UpgradeExecutionLedgerV2Status.READY_FOR_LEDGER_APPEND:
            observation = self._validate_pending_observation(entries)
            self._validate_pending_commitment(observation)
            if self.seal is not None:
                raise ValueError("ready-for-ledger-append M6 V2 state is inconsistent")
        elif self.status == M6UpgradeExecutionLedgerV2Status.READY_TO_SEAL:
            if (
                self.committed_sample_count != expected_count
                or self.next_execution_entry is not None
                or self.pending_observation is not None
                or self.pending_commitment is not None
                or self.seal is not None
            ):
                raise ValueError("ready-to-seal M6 V2 state is inconsistent")
        else:
            self._validate_sealed(expected_count)

    def _expected_pending_entry(
        self,
        entries: tuple[M6RegressionExecutionEntry, ...],
    ) -> M6RegressionExecutionEntry:
        if self.committed_sample_count >= len(entries):
            raise ValueError("pending M6 V2 state exceeds the execution dataset")
        expected_entry = entries[self.committed_sample_count]
        if self.next_execution_entry != expected_entry:
            raise ValueError("pending M6 V2 entry differs from the execution dataset")
        return expected_entry

    def _validate_ready_for_observation(
        self,
        entries: tuple[M6RegressionExecutionEntry, ...],
    ) -> None:
        self._expected_pending_entry(entries)
        if (
            self.pending_observation is not None
            or self.pending_commitment is not None
            or self.seal is not None
        ):
            raise ValueError("ready-for-observation M6 V2 state is inconsistent")

    def _validate_pending_observation(
        self,
        entries: tuple[M6RegressionExecutionEntry, ...],
    ) -> M6UpgradeSampleExecutionObservationAuthority:
        expected_entry = self._expected_pending_entry(entries)
        observation = self.pending_observation
        if observation is None:
            raise ValueError("pending M6 V2 state requires one observation")
        scope = self.execution_scope
        if (
            observation.execution_scope_authority_id != scope.execution_scope_authority_id
            or observation.candidate_run_id != scope.candidate_run_id
            or observation.command_id != scope.command.command_id
            or observation.execution_dataset_snapshot_id
            != scope.execution_dataset.execution_dataset_snapshot_id
            or observation.ledger_sequence != self.committed_sample_count
            or observation.execution_entry != expected_entry
        ):
            raise ValueError("pending M6 V2 observation differs from its exact scope and entry")
        return observation

    def _validate_pending_commitment(
        self,
        observation: M6UpgradeSampleExecutionObservationAuthority,
    ) -> None:
        commitment = self.pending_commitment
        if commitment is None:
            raise ValueError("ready-for-ledger-append M6 V2 state requires one commitment")
        scope = self.execution_scope
        record = commitment.sample_execution_record
        if (
            commitment.execution_scope_authority_id != scope.execution_scope_authority_id
            or commitment.candidate_run_id != scope.candidate_run_id
            or commitment.command_id != scope.command.command_id
            or commitment.execution_dataset_snapshot_id
            != scope.execution_dataset.execution_dataset_snapshot_id
            or commitment.ledger_sequence != self.committed_sample_count
            or commitment.execution_entry != observation.execution_entry
            or commitment.observation_authority_id != observation.observation_authority_id
            or record.previous_ledger_entry_hash != self.ledger_head_hash
            or record.outcome != observation.outcome
            or record.candidate_case != observation.candidate_case
        ):
            raise ValueError(
                "pending M6 V2 commitment differs from its observation, chain, or scope"
            )

    def _validate_sealed(self, expected_count: int) -> None:
        seal = self.seal
        if (
            self.committed_sample_count != expected_count
            or self.next_execution_entry is not None
            or self.pending_observation is not None
            or self.pending_commitment is not None
            or seal is None
            or type(seal) is not M6UpgradeExecutionLedgerSealV2
            or seal.execution_scope != self.execution_scope
            or seal.sample_execution_count != self.committed_sample_count
            or seal.ledger_preseal_hash != self.ledger_head_hash
        ):
            raise ValueError("sealed M6 V2 resume state is inconsistent")


class M6UpgradeExecutionLedgerV2Repository(Protocol):
    """Persist V2 records only by consuming their prior durable commitments."""

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority: ...

    def resume(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResumeV2: ...

    def append_committed_sample(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradeSampleExecutionRecordV2: ...

    def seal(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSealV2: ...

    def load_sealed(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSealV2: ...


__all__ = [
    "M6UpgradeExecutionLedgerV2Error",
    "M6UpgradeExecutionLedgerV2FailureCode",
    "M6UpgradeExecutionLedgerV2Repository",
    "M6UpgradeExecutionLedgerV2Status",
    "M6UpgradeExecutionResumeV2",
]
