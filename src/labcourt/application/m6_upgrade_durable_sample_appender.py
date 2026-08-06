"""Recoverably close one durable M6 Observation V2 into protocol V3."""

from __future__ import annotations

import hashlib
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.ports.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderError,
    M6UpgradeDurableSampleAppenderFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Repository,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
    M6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilder,
    M6UpgradeWholeSampleRecordBuilderError,
    M6UpgradeWholeSampleRecordBuilderFailureCode,
)

_FailureCode = M6UpgradeDurableSampleAppenderFailureCode


def _error(code: _FailureCode) -> M6UpgradeDurableSampleAppenderError:
    return M6UpgradeDurableSampleAppenderError(code)


def _fail(code: _FailureCode) -> NoReturn:
    raise _error(code) from None


def _public_identity(candidate_run_id: object, scope_id: object) -> tuple[str, str]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 durable append run_id")
    except (TypeError, ValueError):
        _fail(_FailureCode.INVALID_ARGUMENT)
    if (
        not isinstance(scope_id, str)
        or len(scope_id) != 64
        or any(character not in "0123456789abcdef" for character in scope_id)
    ):
        _fail(_FailureCode.INVALID_ARGUMENT)
    return run_id, scope_id


def _ledger_failure(code: M6UpgradeExecutionLedgerV3FailureCode) -> _FailureCode:
    direct = {
        M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT: _FailureCode.INVALID_ARGUMENT,
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND: _FailureCode.SCOPE_NOT_FOUND,
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_CONFLICT: (_FailureCode.APPEND_STATE_MISMATCH),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_MISMATCH: (_FailureCode.APPEND_STATE_MISMATCH),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_VERSION_UNSUPPORTED: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.OBSERVATION_NOT_FOUND: (
            _FailureCode.OBSERVATION_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerV3FailureCode.COMMITMENT_NOT_FOUND: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.COMMITMENT_CONFLICT: (
            _FailureCode.COMMITMENT_CONFLICT
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SAMPLE_CONFLICT: _FailureCode.RECORD_CONFLICT,
        M6UpgradeExecutionLedgerV3FailureCode.SAMPLE_OUT_OF_ORDER: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED: (
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED: _FailureCode.LEDGER_SEALED,
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_INCOMPLETE: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_NOT_SEALED: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE: (_FailureCode.DOCUMENT_TOO_LARGE),
        M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED: (_FailureCode.STORAGE_REJECTED),
    }
    return direct.get(code, _FailureCode.APPEND_STATE_MISMATCH)


def _commitment_failure(
    code: M6UpgradePendingSampleCommitmentFailureCode,
) -> _FailureCode:
    direct = {
        M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT: (
            _FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND: (_FailureCode.SCOPE_NOT_FOUND),
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_NOT_FOUND: (
            _FailureCode.OBSERVATION_NOT_FOUND
        ),
        M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_MISMATCH: (
            _FailureCode.RECORD_CONFLICT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_NOT_FOUND: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT: (
            _FailureCode.COMMITMENT_CONFLICT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_OUT_OF_ORDER: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradePendingSampleCommitmentFailureCode.PENDING_COMMITMENT_EXISTS: (
            _FailureCode.COMMITMENT_CONFLICT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED: (_FailureCode.LEDGER_SEALED),
        M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED: (
            _FailureCode.STORAGE_REJECTED
        ),
    }
    return direct.get(code, _FailureCode.APPEND_STATE_MISMATCH)


def _record_builder_failure(
    code: M6UpgradeWholeSampleRecordBuilderFailureCode,
) -> _FailureCode:
    direct = {
        M6UpgradeWholeSampleRecordBuilderFailureCode.INVALID_ARGUMENT: (
            _FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_NOT_FOUND: (
            _FailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_NOT_FOUND: (
            _FailureCode.OBSERVATION_NOT_FOUND
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.SCOPE_MISMATCH: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.LEDGER_VERSION_UNSUPPORTED: (
            _FailureCode.APPEND_STATE_MISMATCH
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.OBSERVATION_CLOSURE_MISMATCH: (
            _FailureCode.RECORD_CONFLICT
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_PREFIX_MISMATCH: (
            _FailureCode.RECORD_CONFLICT
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.CASE_BINDING_MISMATCH: (
            _FailureCode.RECORD_CONFLICT
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.MODEL_CALL_CLOSURE_MISMATCH: (
            _FailureCode.RECORD_CONFLICT
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.ROUTE_REJECTED: (_FailureCode.RECORD_CONFLICT),
        M6UpgradeWholeSampleRecordBuilderFailureCode.IDENTITY_CONFLICT: (
            _FailureCode.RECORD_CONFLICT
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.LINK_LIMIT_EXCEEDED: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.PHYSICAL_BYTE_LIMIT_EXCEEDED: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.CANONICAL_DOCUMENT_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.RECORD_TOO_LARGE: (
            _FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.PIXEL_AUTHORITY_REJECTED: (
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.RAW_RESPONSE_REJECTED: (
            _FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.STORED_AUTHORITY_INVALID: (
            _FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeWholeSampleRecordBuilderFailureCode.SNAPSHOT_REJECTED: (
            _FailureCode.SNAPSHOT_REJECTED
        ),
    }
    return direct.get(code, _FailureCode.RECORD_CONFLICT)


def _canonical_record(value: object) -> M6UpgradeSampleExecutionRecordV2:
    if type(value) is not M6UpgradeSampleExecutionRecordV2:
        _fail(_FailureCode.RECORD_CONFLICT)
    try:
        controlled = M6UpgradeSampleExecutionRecordV2.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(_FailureCode.RECORD_CONFLICT)
    if controlled != value:
        _fail(_FailureCode.RECORD_CONFLICT)
    return controlled


def _require_record_binding(
    resume: M6UpgradeExecutionResumeV3,
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradeSampleExecutionObservationAuthorityV2:
    observation = resume.pending_observation
    if type(observation) is not M6UpgradeSampleExecutionObservationAuthorityV2:
        _fail(_FailureCode.OBSERVATION_NOT_FOUND)
    scope = resume.execution_scope
    if (
        record.execution_scope_authority_id != scope.execution_scope_authority_id
        or record.candidate_run_id != scope.candidate_run_id
        or record.command_id != scope.command.command_id
        or record.execution_dataset_snapshot_id
        != scope.execution_dataset.execution_dataset_snapshot_id
        or record.execution_entry != resume.next_execution_entry
        or record.ledger_sequence != resume.committed_sample_count
        or record.previous_ledger_entry_hash != resume.ledger_head_hash
        or record.observation_authority_id != observation.observation_authority_id
        or record.outcome != observation.outcome
        or record.candidate_case != observation.candidate_case
    ):
        _fail(_FailureCode.RECORD_CONFLICT)
    return observation


def _commitment(
    record: M6UpgradeSampleExecutionRecordV2,
) -> M6UpgradePendingSampleCommitmentAuthority:
    raw = canonical_json(record.model_dump(mode="json"))
    payload = raw.encode("utf-8")
    if len(payload) > MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES:
        _fail(_FailureCode.DOCUMENT_TOO_LARGE)
    try:
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
    except (TypeError, ValueError, ValidationError):
        _fail(_FailureCode.RECORD_CONFLICT)


class M6UpgradeDurableSampleAppenderServiceV3:
    """Advance READY_FOR_COMMITMENT/LEDGER_APPEND by exact durable steps."""

    __slots__ = ("_commitments", "_ledger", "_record_builder")

    def __init__(
        self,
        *,
        ledger_repository: M6UpgradeExecutionLedgerV3Repository,
        commitment_repository: M6UpgradePendingSampleCommitmentV3Repository,
        record_builder: M6UpgradeWholeSampleRecordBuilder,
    ) -> None:
        if (
            not callable(getattr(ledger_repository, "resume", None))
            or not callable(getattr(ledger_repository, "append_committed_sample", None))
            or not callable(getattr(commitment_repository, "append", None))
            or not callable(getattr(record_builder, "build_m6_upgrade_sample_record", None))
        ):
            raise TypeError("invalid M6 durable sample-appender dependency")
        self._ledger = ledger_repository
        self._commitments = commitment_repository
        self._record_builder = record_builder

    def _attempt_append_pending_sample(
        self,
        candidate_run_id: object,
        execution_scope_authority_id: object,
    ) -> M6UpgradeSampleExecutionRecordV2:
        run_id, scope_id = _public_identity(candidate_run_id, execution_scope_authority_id)
        try:
            resume = self._ledger.resume(run_id, scope_id)
            if resume.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION:
                _fail(_FailureCode.OBSERVATION_NOT_FOUND)
            if resume.status == M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL:
                _fail(_FailureCode.LEDGER_COMPLETE)
            if resume.status == M6UpgradeExecutionLedgerV3Status.SEALED:
                _fail(_FailureCode.LEDGER_SEALED)
            if resume.status not in {
                M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT,
                M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND,
            }:
                _fail(_FailureCode.APPEND_STATE_MISMATCH)

            record = _canonical_record(
                self._record_builder.build_m6_upgrade_sample_record(run_id, scope_id)
            )
            _require_record_binding(resume, record)
            commitment = _commitment(record)
            if (
                resume.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND
                and resume.pending_commitment != commitment
            ):
                _fail(_FailureCode.COMMITMENT_CONFLICT)
            persisted = self._commitments.append(commitment)
            if (
                type(persisted) is not M6UpgradePendingSampleCommitmentAuthority
                or persisted != commitment
            ):
                _fail(_FailureCode.COMMITMENT_CONFLICT)
            if resume.status == M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT:
                # The first build proves the bytes used to author Pending.  Once
                # Pending is durable, rebuild from a fresh read cut so the ledger
                # commit cannot rely on physical bytes observed only before the
                # recoverable commitment point.
                post_commitment_record = _canonical_record(
                    self._record_builder.build_m6_upgrade_sample_record(run_id, scope_id)
                )
                _require_record_binding(resume, post_commitment_record)
                if (
                    post_commitment_record != record
                    or _commitment(post_commitment_record) != persisted
                ):
                    _fail(_FailureCode.COMMITMENT_CONFLICT)
            appended = _canonical_record(self._ledger.append_committed_sample(persisted))
            if appended != record:
                _fail(_FailureCode.RECORD_CONFLICT)
            return appended
        except M6UpgradeDurableSampleAppenderError:
            raise
        except M6UpgradeExecutionLedgerV3Error as error:
            _fail(_ledger_failure(error.reason_code))
        except M6UpgradePendingSampleCommitmentError as error:
            _fail(_commitment_failure(error.reason_code))
        except M6UpgradeWholeSampleRecordBuilderError as error:
            _fail(_record_builder_failure(error.reason_code))

    def append_pending_sample(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeSampleExecutionRecordV2:
        """Advance one pending sample through a fresh payload-free boundary."""

        failure = _FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_append_pending_sample(
                candidate_run_id,
                execution_scope_authority_id,
            )
        except M6UpgradeDurableSampleAppenderError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, candidate_run_id, execution_scope_authority_id
        raise _error(failure) from None


__all__ = ["M6UpgradeDurableSampleAppenderServiceV3"]
