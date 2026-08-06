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
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.ports import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
    M6UpgradeExecutionLedgerV2Repository,
    M6UpgradeExecutionLedgerV2Status,
    M6UpgradeExecutionResumeV2,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v2_inventory,
)


def _commitment(index: int) -> M6UpgradePendingSampleCommitmentAuthority:
    inventory = _v2_inventory()
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
    status: M6UpgradeExecutionLedgerV2Status,
    *,
    committed_sample_count: int,
    ledger_head_hash: str,
    with_observation: bool = False,
    with_commitment: bool = False,
    with_seal: bool = False,
) -> M6UpgradeExecutionResumeV2:
    inventory = _v2_inventory()
    entries = inventory.execution_dataset.entries
    has_next = committed_sample_count < len(entries)
    return M6UpgradeExecutionResumeV2(
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


def test_v2_resume_accepts_each_exact_durable_pipeline_state() -> None:
    inventory = _v2_inventory()
    records = inventory.execution_ledger.sample_executions
    expected_count = len(records)

    ready_for_observation = _resume(
        M6UpgradeExecutionLedgerV2Status.READY_FOR_OBSERVATION,
        committed_sample_count=0,
        ledger_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
    )
    ready_for_commitment = _resume(
        M6UpgradeExecutionLedgerV2Status.READY_FOR_COMMITMENT,
        committed_sample_count=1,
        ledger_head_hash=records[0].sample_execution_record_id,
        with_observation=True,
    )
    ready_for_append = _resume(
        M6UpgradeExecutionLedgerV2Status.READY_FOR_LEDGER_APPEND,
        committed_sample_count=1,
        ledger_head_hash=records[0].sample_execution_record_id,
        with_observation=True,
        with_commitment=True,
    )
    ready_to_seal = _resume(
        M6UpgradeExecutionLedgerV2Status.READY_TO_SEAL,
        committed_sample_count=expected_count,
        ledger_head_hash=records[-1].sample_execution_record_id,
    )
    sealed = _resume(
        M6UpgradeExecutionLedgerV2Status.SEALED,
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
        (M6UpgradeExecutionLedgerV2Status.READY_FOR_OBSERVATION, True, False),
        (M6UpgradeExecutionLedgerV2Status.READY_FOR_COMMITMENT, False, False),
        (M6UpgradeExecutionLedgerV2Status.READY_FOR_COMMITMENT, True, True),
        (M6UpgradeExecutionLedgerV2Status.READY_FOR_LEDGER_APPEND, True, False),
        (M6UpgradeExecutionLedgerV2Status.READY_FOR_LEDGER_APPEND, False, True),
    ),
)
def test_v2_resume_rejects_crossed_pending_states(
    status: M6UpgradeExecutionLedgerV2Status,
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


def test_v2_resume_rejects_pending_scope_sequence_entry_and_chain_drift() -> None:
    inventory = _v2_inventory()
    scope = inventory.execution_ledger.execution_scope
    observation = inventory.execution_observations[1]
    record = inventory.execution_ledger.sample_executions[0]

    for changed_observation in (
        observation.model_copy(update={"execution_scope_authority_id": "f" * 64}),
        observation.model_copy(update={"ledger_sequence": 0}),
        observation.model_copy(update={"execution_entry": inventory.execution_dataset.entries[2]}),
    ):
        with pytest.raises(ValueError, match="observation differs"):
            M6UpgradeExecutionResumeV2(
                status=M6UpgradeExecutionLedgerV2Status.READY_FOR_COMMITMENT,
                execution_scope=scope,
                committed_sample_count=1,
                ledger_head_hash=record.sample_execution_record_id,
                next_execution_entry=inventory.execution_dataset.entries[1],
                pending_observation=changed_observation,
            )

    with pytest.raises(ValueError, match="commitment differs"):
        M6UpgradeExecutionResumeV2(
            status=M6UpgradeExecutionLedgerV2Status.READY_FOR_LEDGER_APPEND,
            execution_scope=scope,
            committed_sample_count=1,
            ledger_head_hash="e" * 64,
            next_execution_entry=inventory.execution_dataset.entries[1],
            pending_observation=observation,
            pending_commitment=_commitment(1),
        )


def test_v2_resume_rejects_terminal_pending_values_counts_and_wrong_entry() -> None:
    inventory = _v2_inventory()
    records = inventory.execution_ledger.sample_executions
    count = len(records)

    with pytest.raises(ValueError, match="ready-to-seal"):
        M6UpgradeExecutionResumeV2(
            status=M6UpgradeExecutionLedgerV2Status.READY_TO_SEAL,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=count - 1,
            ledger_head_hash=records[-2].sample_execution_record_id,
            next_execution_entry=inventory.execution_dataset.entries[-1],
        )

    with pytest.raises(ValueError, match="entry differs"):
        M6UpgradeExecutionResumeV2(
            status=M6UpgradeExecutionLedgerV2Status.READY_FOR_OBSERVATION,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=0,
            ledger_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
            next_execution_entry=inventory.execution_dataset.entries[1],
        )

    with pytest.raises(ValueError, match="committed samples exceed"):
        M6UpgradeExecutionResumeV2(
            status=M6UpgradeExecutionLedgerV2Status.READY_TO_SEAL,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=count + 1,
            ledger_head_hash=records[-1].sample_execution_record_id,
            next_execution_entry=None,
        )

    with pytest.raises(ValueError, match="non-negative integer"):
        M6UpgradeExecutionResumeV2(
            status=M6UpgradeExecutionLedgerV2Status.READY_FOR_OBSERVATION,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=True,
            ledger_head_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
            next_execution_entry=inventory.execution_dataset.entries[0],
        )


def test_v2_resume_requires_an_exact_v2_seal_and_exact_head() -> None:
    inventory = _v2_inventory()
    records = inventory.execution_ledger.sample_executions
    legacy_seal = _inventory().execution_ledger

    assert type(legacy_seal) is M6UpgradeExecutionLedgerSeal
    with pytest.raises(TypeError, match="exact typed M6 V2 ledger seal"):
        M6UpgradeExecutionResumeV2(
            status=M6UpgradeExecutionLedgerV2Status.SEALED,
            execution_scope=inventory.execution_ledger.execution_scope,
            committed_sample_count=len(records),
            ledger_head_hash=records[-1].sample_execution_record_id,
            next_execution_entry=None,
            seal=legacy_seal,  # type: ignore[arg-type]
        )

    with pytest.raises(ValueError, match="sealed M6 V2 resume state"):
        _resume(
            M6UpgradeExecutionLedgerV2Status.SEALED,
            committed_sample_count=len(records),
            ledger_head_hash="f" * 64,
            with_seal=True,
        )


def test_v2_repository_port_consumes_only_a_commitment_and_returns_v2_types() -> None:
    assert tuple(
        inspect.signature(M6UpgradeExecutionLedgerV2Repository.begin_execution).parameters
    ) == ("self", "scope")
    assert tuple(inspect.signature(M6UpgradeExecutionLedgerV2Repository.resume).parameters) == (
        "self",
        "run_id",
        "execution_scope_authority_id",
    )
    assert tuple(
        inspect.signature(M6UpgradeExecutionLedgerV2Repository.append_committed_sample).parameters
    ) == ("self", "commitment")
    assert tuple(inspect.signature(M6UpgradeExecutionLedgerV2Repository.seal).parameters) == (
        "self",
        "run_id",
        "execution_scope_authority_id",
    )
    assert tuple(
        inspect.signature(M6UpgradeExecutionLedgerV2Repository.load_sealed).parameters
    ) == (
        "self",
        "run_id",
        "execution_scope_authority_id",
    )

    annotations = inspect.get_annotations(
        M6UpgradeExecutionLedgerV2Repository.append_committed_sample,
        eval_str=True,
    )
    assert annotations["commitment"] is M6UpgradePendingSampleCommitmentAuthority
    assert annotations["return"] is M6UpgradeSampleExecutionRecordV2
    assert (
        inspect.get_annotations(
            M6UpgradeExecutionLedgerV2Repository.begin_execution,
            eval_str=True,
        )["return"]
        is M6UpgradeExecutionScopeAuthority
    )
    assert (
        inspect.get_annotations(
            M6UpgradeExecutionLedgerV2Repository.resume,
            eval_str=True,
        )["return"]
        is M6UpgradeExecutionResumeV2
    )
    for method in (
        M6UpgradeExecutionLedgerV2Repository.seal,
        M6UpgradeExecutionLedgerV2Repository.load_sealed,
    ):
        assert inspect.get_annotations(method, eval_str=True)["return"] is (
            M6UpgradeExecutionLedgerSealV2
        )


def test_v2_error_is_typed_and_payload_free() -> None:
    error = M6UpgradeExecutionLedgerV2Error(
        M6UpgradeExecutionLedgerV2FailureCode.COMMITMENT_CONFLICT
    )
    assert error.args == ("M6 upgrade execution ledger V2 failed: COMMITMENT_CONFLICT",)
    assert vars(error) == {"reason_code": error.reason_code}

    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeExecutionLedgerV2Error("COMMITMENT_CONFLICT")  # type: ignore[arg-type]
