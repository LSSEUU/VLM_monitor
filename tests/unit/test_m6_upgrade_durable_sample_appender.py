from __future__ import annotations

import hashlib
from functools import cache

import pytest

from labcourt.application.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderServiceV3,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.ports.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderError,
    M6UpgradeDurableSampleAppenderFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v3_inventory,
)

_FailureCode = M6UpgradeDurableSampleAppenderFailureCode


@cache
def _inventory():
    return _v3_inventory()


def _commitment_for(
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradePendingSampleCommitmentAuthority:
    payload = canonical_json(record.model_dump(mode="json")).encode("utf-8")
    return M6UpgradePendingSampleCommitmentAuthority(
        execution_scope_authority_id=record.execution_scope_authority_id,
        candidate_run_id=record.candidate_run_id,
        command_id=record.command_id,
        execution_dataset_snapshot_id=record.execution_dataset_snapshot_id,
        execution_entry=record.execution_entry,
        ledger_sequence=record.ledger_sequence,
        observation_authority_id=record.observation_authority_id,
        sample_execution_record=record,
        sample_execution_record_document_sha256=hashlib.sha256(payload).hexdigest(),
        sample_execution_record_size_bytes=len(payload),
    )


def _pending_resume(
    index: int,
    status: M6UpgradeExecutionLedgerV3Status,
) -> M6UpgradeExecutionResumeV3:
    inventory = _inventory()
    records = inventory.execution_ledger.sample_executions
    observation = inventory.execution_observations[index]
    return M6UpgradeExecutionResumeV3(
        status=status,
        execution_scope=inventory.execution_ledger.execution_scope,
        committed_sample_count=index,
        ledger_head_hash=(
            M6_UPGRADE_LEDGER_GENESIS_HASH
            if index == 0
            else records[index - 1].sample_execution_record_id
        ),
        next_execution_entry=inventory.execution_dataset.entries[index],
        pending_observation=observation,
        pending_commitment=(
            _commitment_for(records[index])
            if status == M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND
            else None
        ),
    )


def _ready_for_observation(index: int) -> M6UpgradeExecutionResumeV3:
    inventory = _inventory()
    records = inventory.execution_ledger.sample_executions
    return M6UpgradeExecutionResumeV3(
        status=M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION,
        execution_scope=inventory.execution_ledger.execution_scope,
        committed_sample_count=index,
        ledger_head_hash=(
            M6_UPGRADE_LEDGER_GENESIS_HASH
            if index == 0
            else records[index - 1].sample_execution_record_id
        ),
        next_execution_entry=inventory.execution_dataset.entries[index],
    )


def _ready_to_seal() -> M6UpgradeExecutionResumeV3:
    inventory = _inventory()
    records = inventory.execution_ledger.sample_executions
    return M6UpgradeExecutionResumeV3(
        status=M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL,
        execution_scope=inventory.execution_ledger.execution_scope,
        committed_sample_count=len(records),
        ledger_head_hash=records[-1].sample_execution_record_id,
        next_execution_entry=None,
    )


def _sealed() -> M6UpgradeExecutionResumeV3:
    inventory = _inventory()
    records = inventory.execution_ledger.sample_executions
    return M6UpgradeExecutionResumeV3(
        status=M6UpgradeExecutionLedgerV3Status.SEALED,
        execution_scope=inventory.execution_ledger.execution_scope,
        committed_sample_count=len(records),
        ledger_head_hash=records[-1].sample_execution_record_id,
        next_execution_entry=None,
        seal=inventory.execution_ledger,
    )


class _Ledger:
    def __init__(
        self,
        log: list[str],
        resume_steps: list[M6UpgradeExecutionResumeV3 | Exception],
        append_result: M6UpgradeSampleExecutionRecordV2 | Exception,
    ) -> None:
        self._log = log
        self._resume_steps = list(resume_steps)
        self._append_result = append_result
        self.appended: list[M6UpgradePendingSampleCommitmentAuthority] = []

    def resume(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResumeV3:
        self._log.append("resume")
        step = self._resume_steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return step

    def append_committed_sample(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradeSampleExecutionRecordV2:
        self._log.append("ledger.append")
        self.appended.append(commitment)
        if isinstance(self._append_result, Exception):
            raise self._append_result
        return self._append_result


class _Commitments:
    def __init__(
        self,
        log: list[str],
        result: M6UpgradePendingSampleCommitmentAuthority | Exception,
    ) -> None:
        self._log = log
        self._result = result
        self.appended: list[M6UpgradePendingSampleCommitmentAuthority] = []

    def append(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        self._log.append("commitment.append")
        self.appended.append(commitment)
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class _Builder:
    def __init__(
        self,
        log: list[str],
        result: (
            M6UpgradeSampleExecutionRecordV2
            | Exception
            | list[M6UpgradeSampleExecutionRecordV2 | Exception]
        ),
    ) -> None:
        self._log = log
        self._result = result
        self.calls: list[tuple[str, str]] = []

    def build_m6_upgrade_sample_record(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionRecordV2:
        self._log.append("build")
        self.calls.append((candidate_run_id, execution_scope_authority_id))
        result = self._result.pop(0) if isinstance(self._result, list) else self._result
        if isinstance(result, Exception):
            raise result
        return result


def _service(
    *,
    resume_steps: list[M6UpgradeExecutionResumeV3 | Exception],
    record: (
        M6UpgradeSampleExecutionRecordV2
        | Exception
        | list[M6UpgradeSampleExecutionRecordV2 | Exception]
    ),
    commitment: M6UpgradePendingSampleCommitmentAuthority | Exception,
    append_result: M6UpgradeSampleExecutionRecordV2 | Exception,
) -> tuple[
    M6UpgradeDurableSampleAppenderServiceV3,
    _Ledger,
    _Commitments,
    _Builder,
    list[str],
]:
    log: list[str] = []
    ledger = _Ledger(log, resume_steps, append_result)
    commitments = _Commitments(log, commitment)
    builder = _Builder(log, record)
    return (
        M6UpgradeDurableSampleAppenderServiceV3(
            ledger_repository=ledger,
            commitment_repository=commitments,
            record_builder=builder,
        ),
        ledger,
        commitments,
        builder,
        log,
    )


def _call(service: M6UpgradeDurableSampleAppenderServiceV3) -> M6UpgradeSampleExecutionRecordV2:
    scope = _inventory().execution_ledger.execution_scope
    return service.append_pending_sample(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )


def _assert_failure(
    service: M6UpgradeDurableSampleAppenderServiceV3,
    expected: _FailureCode,
) -> M6UpgradeDurableSampleAppenderError:
    with pytest.raises(M6UpgradeDurableSampleAppenderError) as raised:
        _call(service)
    error = raised.value
    assert error.reason_code == expected
    assert error.args == (f"M6 durable sample append failed: {expected.value}",)
    assert vars(error) == {"reason_code": expected}
    assert error.__cause__ is None
    return error


def test_ready_for_commitment_runs_exact_durable_order() -> None:
    inventory = _inventory()
    record = inventory.execution_ledger.sample_executions[0]
    commitment = _commitment_for(record)
    service, ledger, commitments, builder, log = _service(
        resume_steps=[_pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT)],
        record=record,
        commitment=commitment,
        append_result=record,
    )

    assert _call(service) == record
    assert log == [
        "resume",
        "build",
        "commitment.append",
        "build",
        "ledger.append",
    ]
    assert builder.calls == [
        (
            inventory.execution_ledger.execution_scope.candidate_run_id,
            inventory.execution_ledger.execution_scope.execution_scope_authority_id,
        ),
        (
            inventory.execution_ledger.execution_scope.candidate_run_id,
            inventory.execution_ledger.execution_scope.execution_scope_authority_id,
        ),
    ]
    assert commitments.appended == [commitment]
    assert ledger.appended == [commitment]


def test_ready_for_ledger_append_rebuilds_and_idempotently_revalidates_exact_commitment() -> None:
    inventory = _inventory()
    record = inventory.execution_ledger.sample_executions[0]
    commitment = _commitment_for(record)
    service, ledger, commitments, builder, log = _service(
        resume_steps=[_pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND)],
        record=record,
        commitment=commitment,
        append_result=record,
    )

    assert _call(service) == record
    assert log == [
        "resume",
        "build",
        "commitment.append",
        "ledger.append",
    ]
    assert len(builder.calls) == 1
    assert commitments.appended == [commitment]
    assert ledger.appended == [commitment]


def test_first_append_rejects_post_commitment_record_drift_before_ledger_write() -> None:
    inventory = _inventory()
    record = inventory.execution_ledger.sample_executions[0]
    drifted = inventory.execution_ledger.sample_executions[1]
    commitment = _commitment_for(record)
    service, ledger, commitments, builder, log = _service(
        resume_steps=[_pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT)],
        record=[record, drifted],
        commitment=commitment,
        append_result=record,
    )

    _assert_failure(service, _FailureCode.RECORD_CONFLICT)
    assert log == ["resume", "build", "commitment.append", "build"]
    assert len(builder.calls) == 2
    assert commitments.appended == [commitment]
    assert ledger.appended == []


@pytest.mark.parametrize(
    ("resume", "expected"),
    (
        (_ready_for_observation(0), _FailureCode.OBSERVATION_NOT_FOUND),
        (_ready_to_seal(), _FailureCode.LEDGER_COMPLETE),
        (_sealed(), _FailureCode.LEDGER_SEALED),
    ),
)
def test_non_appendable_resume_states_short_circuit_before_record_build(
    resume: M6UpgradeExecutionResumeV3,
    expected: _FailureCode,
) -> None:
    record = _inventory().execution_ledger.sample_executions[0]
    commitment = _commitment_for(record)
    service, ledger, commitments, builder, log = _service(
        resume_steps=[resume],
        record=record,
        commitment=commitment,
        append_result=record,
    )

    _assert_failure(service, expected)
    assert log == ["resume"]
    assert builder.calls == []
    assert commitments.appended == []
    assert ledger.appended == []


def test_recovery_rejects_rebuilt_record_graft_before_commitment_or_ledger_write() -> None:
    inventory = _inventory()
    expected = inventory.execution_ledger.sample_executions[0]
    graft = inventory.execution_ledger.sample_executions[1]
    commitment = _commitment_for(expected)
    service, ledger, commitments, _builder, log = _service(
        resume_steps=[_pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND)],
        record=graft,
        commitment=commitment,
        append_result=expected,
    )

    _assert_failure(service, _FailureCode.RECORD_CONFLICT)
    assert log == ["resume", "build"]
    assert commitments.appended == []
    assert ledger.appended == []


def test_recovery_rejects_durable_commitment_graft_before_any_write() -> None:
    inventory = _inventory()
    record = inventory.execution_ledger.sample_executions[0]
    graft = _pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND)
    object.__setattr__(
        graft,
        "pending_commitment",
        _commitment_for(inventory.execution_ledger.sample_executions[1]),
    )
    commitment = _commitment_for(record)
    service, ledger, commitments, _builder, log = _service(
        resume_steps=[graft],
        record=record,
        commitment=commitment,
        append_result=record,
    )

    _assert_failure(service, _FailureCode.COMMITMENT_CONFLICT)
    assert log == ["resume", "build"]
    assert commitments.appended == []
    assert ledger.appended == []


def test_commitment_repository_and_ledger_return_values_cannot_graft_authority() -> None:
    inventory = _inventory()
    record = inventory.execution_ledger.sample_executions[0]
    graft_record = inventory.execution_ledger.sample_executions[1]
    commitment = _commitment_for(record)
    graft_commitment = _commitment_for(graft_record)

    commitment_service, commitment_ledger, _commitments, _builder, log = _service(
        resume_steps=[_pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT)],
        record=record,
        commitment=graft_commitment,
        append_result=record,
    )
    _assert_failure(commitment_service, _FailureCode.COMMITMENT_CONFLICT)
    assert log == ["resume", "build", "commitment.append"]
    assert commitment_ledger.appended == []

    ledger_service, _ledger, _commitments, _builder, log = _service(
        resume_steps=[_pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT)],
        record=record,
        commitment=commitment,
        append_result=graft_record,
    )
    _assert_failure(ledger_service, _FailureCode.RECORD_CONFLICT)
    assert log == [
        "resume",
        "build",
        "commitment.append",
        "build",
        "ledger.append",
    ]


@pytest.mark.parametrize(
    ("phase", "lower_error", "expected"),
    (
        (
            "resume",
            M6UpgradeExecutionLedgerV3Error(M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND),
            _FailureCode.SCOPE_NOT_FOUND,
        ),
        (
            "resume",
            M6UpgradeExecutionLedgerV3Error(
                M6UpgradeExecutionLedgerV3FailureCode.OBSERVATION_NOT_FOUND
            ),
            _FailureCode.OBSERVATION_NOT_FOUND,
        ),
        (
            "builder",
            M6UpgradeWholeSampleRecordBuilderError(
                M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH
            ),
            _FailureCode.APPEND_STATE_MISMATCH,
        ),
        (
            "builder",
            M6UpgradeWholeSampleRecordBuilderError(
                M6UpgradeWholeSampleRecordBuilderFailureCode.LEDGER_VERSION_UNSUPPORTED
            ),
            _FailureCode.APPEND_STATE_MISMATCH,
        ),
        (
            "builder",
            M6UpgradeWholeSampleRecordBuilderError(
                M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH
            ),
            _FailureCode.RECORD_CONFLICT,
        ),
        (
            "builder",
            M6UpgradeWholeSampleRecordBuilderError(
                M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED
            ),
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED,
        ),
        (
            "builder",
            M6UpgradeWholeSampleRecordBuilderError(
                M6UpgradeWholeSampleRecordBuilderFailureCode.RAW_RESPONSE_REJECTED
            ),
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED,
        ),
        (
            "builder",
            M6UpgradeWholeSampleRecordBuilderError(
                M6UpgradeWholeSampleRecordBuilderFailureCode.RECORD_TOO_LARGE
            ),
            _FailureCode.DOCUMENT_TOO_LARGE,
        ),
        (
            "builder",
            M6UpgradeWholeSampleRecordBuilderError(
                M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED
            ),
            _FailureCode.SNAPSHOT_REJECTED,
        ),
        (
            "commitment",
            M6UpgradePendingSampleCommitmentError(
                M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT
            ),
            _FailureCode.COMMITMENT_CONFLICT,
        ),
        (
            "commitment",
            M6UpgradePendingSampleCommitmentError(
                M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
            ),
            _FailureCode.STORAGE_REJECTED,
        ),
        (
            "ledger",
            M6UpgradeExecutionLedgerV3Error(M6UpgradeExecutionLedgerV3FailureCode.SAMPLE_CONFLICT),
            _FailureCode.RECORD_CONFLICT,
        ),
        (
            "ledger",
            M6UpgradeExecutionLedgerV3Error(
                M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED
            ),
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED,
        ),
        (
            "ledger",
            M6UpgradeExecutionLedgerV3Error(
                M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID
            ),
            _FailureCode.STORED_AUTHORITY_INVALID,
        ),
    ),
)
def test_lower_typed_failures_map_without_message_or_cause_leakage(
    phase: str,
    lower_error: Exception,
    expected: _FailureCode,
) -> None:
    inventory = _inventory()
    record = inventory.execution_ledger.sample_executions[0]
    commitment = _commitment_for(record)
    secret = "sensitive-database-path-and-authority-body"
    lower_error.__cause__ = RuntimeError(secret)
    service, _ledger, _commitments, _builder, _log = _service(
        resume_steps=[
            lower_error
            if phase == "resume"
            else _pending_resume(0, M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT)
        ],
        record=lower_error if phase == "builder" else record,
        commitment=lower_error if phase == "commitment" else commitment,
        append_result=lower_error if phase == "ledger" else record,
    )

    error = _assert_failure(service, expected)
    assert secret not in str(error)
    assert secret not in repr(vars(error))


def test_invalid_public_id_and_unknown_dependency_failure_are_payload_free() -> None:
    inventory = _inventory()
    record = inventory.execution_ledger.sample_executions[0]
    commitment = _commitment_for(record)
    service, _ledger, _commitments, builder, log = _service(
        resume_steps=[RuntimeError("private storage path")],
        record=record,
        commitment=commitment,
        append_result=record,
    )

    with pytest.raises(M6UpgradeDurableSampleAppenderError) as invalid:
        service.append_pending_sample("", "not-a-scope-id")
    assert invalid.value.reason_code == _FailureCode.INVALID_ARGUMENT
    assert log == []
    assert builder.calls == []

    error = _assert_failure(service, _FailureCode.STORAGE_REJECTED)
    assert "private storage path" not in str(error)
    assert error.__cause__ is None
