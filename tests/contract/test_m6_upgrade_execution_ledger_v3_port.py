from __future__ import annotations

import hashlib
import inspect
from dataclasses import FrozenInstanceError

import pytest

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.ports import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Repository,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
    M6UpgradePendingSampleCommitmentV3Repository,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v2_inventory,
    _v3_inventory,
)


def _commitment(index: int) -> M6UpgradePendingSampleCommitmentAuthority:
    inventory = _v3_inventory()
    record = inventory.execution_ledger.sample_executions[index]
    document = canonical_json(record.model_dump(mode="json")).encode("utf-8")
    return M6UpgradePendingSampleCommitmentAuthority(
        execution_scope_authority_id=record.execution_scope_authority_id,
        candidate_run_id=record.candidate_run_id,
        command_id=record.command_id,
        execution_dataset_snapshot_id=record.execution_dataset_snapshot_id,
        execution_entry=record.execution_entry,
        ledger_sequence=record.ledger_sequence,
        observation_authority_id=record.observation_authority_id,
        sample_execution_record=record,
        sample_execution_record_document_sha256=hashlib.sha256(document).hexdigest(),
        sample_execution_record_size_bytes=len(document),
    )


def _resume(
    status: M6UpgradeExecutionLedgerV3Status,
    *,
    committed_sample_count: int,
    ledger_head_hash: str,
    with_observation: bool = False,
    with_commitment: bool = False,
    with_seal: bool = False,
) -> M6UpgradeExecutionResumeV3:
    inventory = _v3_inventory()
    entries = inventory.execution_dataset.entries
    has_next = committed_sample_count < len(entries)
    return M6UpgradeExecutionResumeV3(
        status=status,
        execution_scope=inventory.execution_ledger.execution_scope,
        committed_sample_count=committed_sample_count,
        ledger_head_hash=ledger_head_hash,
        next_execution_entry=(entries[committed_sample_count] if has_next else None),
        pending_observation=(
            inventory.execution_observations[committed_sample_count]
            if with_observation and has_next
            else None
        ),
        pending_commitment=(
            _commitment(committed_sample_count) if with_commitment and has_next else None
        ),
        seal=inventory.execution_ledger if with_seal else None,
    )


def test_v3_resume_accepts_all_five_exact_durable_states() -> None:
    inventory = _v3_inventory()
    records = inventory.execution_ledger.sample_executions
    expected_count = len(records)

    ready_for_observation = _resume(
        M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION,
        committed_sample_count=0,
        ledger_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
    )
    ready_for_commitment = _resume(
        M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT,
        committed_sample_count=1,
        ledger_head_hash=records[0].sample_execution_record_id,
        with_observation=True,
    )
    ready_for_append = _resume(
        M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND,
        committed_sample_count=1,
        ledger_head_hash=records[0].sample_execution_record_id,
        with_observation=True,
        with_commitment=True,
    )
    ready_to_seal = _resume(
        M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL,
        committed_sample_count=expected_count,
        ledger_head_hash=records[-1].sample_execution_record_id,
    )
    sealed = _resume(
        M6UpgradeExecutionLedgerV3Status.SEALED,
        committed_sample_count=expected_count,
        ledger_head_hash=records[-1].sample_execution_record_id,
        with_seal=True,
    )

    assert ready_for_observation.next_execution_entry == inventory.execution_dataset.entries[0]
    assert ready_for_commitment.pending_observation == inventory.execution_observations[1]
    assert ready_for_append.pending_commitment == _commitment(1)
    assert ready_to_seal.seal is None
    assert sealed.seal == inventory.execution_ledger
    with pytest.raises(FrozenInstanceError):
        sealed.committed_sample_count = 0  # type: ignore[misc]


@pytest.mark.parametrize(
    ("status", "with_observation", "with_commitment"),
    (
        (M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION, True, False),
        (M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT, False, False),
        (M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT, True, True),
        (M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND, True, False),
        (M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND, False, True),
    ),
)
def test_v3_resume_rejects_crossed_pending_states(
    status: M6UpgradeExecutionLedgerV3Status,
    with_observation: bool,
    with_commitment: bool,
) -> None:
    with pytest.raises(ValueError):
        _resume(
            status,
            committed_sample_count=0,
            ledger_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
            with_observation=with_observation,
            with_commitment=with_commitment,
        )


def test_v3_resume_rejects_v1_observation_and_v1_seal_subclasses() -> None:
    inventory = _v3_inventory()
    legacy_observation = _v2_inventory().execution_observations[0]
    legacy_seal = _inventory().execution_ledger
    assert type(legacy_seal) is M6UpgradeExecutionLedgerSeal

    with pytest.raises(TypeError, match="exact typed M6 observation V2"):
        M6UpgradeExecutionResumeV3(
            status=M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=0,
            ledger_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
            next_execution_entry=inventory.execution_dataset.entries[0],
            pending_observation=legacy_observation,  # type: ignore[arg-type]
        )

    with pytest.raises(TypeError, match="exact typed M6 V2 ledger seal"):
        M6UpgradeExecutionResumeV3(
            status=M6UpgradeExecutionLedgerV3Status.SEALED,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=len(inventory.execution_dataset.entries),
            ledger_head_hash=inventory.execution_ledger.ledger_preseal_hash,
            next_execution_entry=None,
            seal=legacy_seal,  # type: ignore[arg-type]
        )


def test_v3_resume_rejects_scope_entry_chain_and_commitment_drift() -> None:
    inventory = _v3_inventory()
    records = inventory.execution_ledger.sample_executions
    observation = inventory.execution_observations[1]

    with pytest.raises(ValueError, match="observation differs"):
        M6UpgradeExecutionResumeV3(
            status=M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=1,
            ledger_head_hash=records[0].sample_execution_record_id,
            next_execution_entry=inventory.execution_dataset.entries[1],
            pending_observation=observation.model_copy(update={"ledger_sequence": 0}),
        )

    with pytest.raises(ValueError, match="commitment differs"):
        M6UpgradeExecutionResumeV3(
            status=M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=1,
            ledger_head_hash="e" * 64,
            next_execution_entry=inventory.execution_dataset.entries[1],
            pending_observation=observation,
            pending_commitment=_commitment(1),
        )


def test_v3_repository_ports_keep_the_unchanged_pending_record_and_seal_wires() -> None:
    assert tuple(inspect.signature(M6UpgradeExecutionLedgerV3Repository.resume).parameters) == (
        "self",
        "run_id",
        "execution_scope_authority_id",
    )
    append_annotations = inspect.get_annotations(
        M6UpgradeExecutionLedgerV3Repository.append_committed_sample,
        eval_str=True,
    )
    assert append_annotations == {
        "commitment": M6UpgradePendingSampleCommitmentAuthority,
        "return": M6UpgradeSampleExecutionRecordV2,
    }
    for method in (
        M6UpgradeExecutionLedgerV3Repository.seal,
        M6UpgradeExecutionLedgerV3Repository.load_sealed,
    ):
        assert inspect.get_annotations(method, eval_str=True)["return"] is (
            M6UpgradeExecutionLedgerSealV2
        )
    assert (
        inspect.get_annotations(M6UpgradeExecutionLedgerV3Repository.resume, eval_str=True)[
            "return"
        ]
        is M6UpgradeExecutionResumeV3
    )

    assert tuple(
        inspect.signature(M6UpgradePendingSampleCommitmentV3Repository.append).parameters
    ) == ("self", "commitment")
    pending_annotations = inspect.get_annotations(
        M6UpgradePendingSampleCommitmentV3Repository.append,
        eval_str=True,
    )
    assert pending_annotations == {
        "commitment": M6UpgradePendingSampleCommitmentAuthority,
        "return": M6UpgradePendingSampleCommitmentAuthority,
    }


def test_v3_error_is_typed_and_payload_free() -> None:
    error = M6UpgradeExecutionLedgerV3Error(
        M6UpgradeExecutionLedgerV3FailureCode.COMMITMENT_CONFLICT
    )
    assert error.args == ("M6 upgrade execution ledger V3 failed: COMMITMENT_CONFLICT",)
    assert vars(error) == {"reason_code": error.reason_code}

    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeExecutionLedgerV3Error("COMMITMENT_CONFLICT")  # type: ignore[arg-type]
