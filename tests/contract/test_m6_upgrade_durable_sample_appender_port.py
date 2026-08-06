from __future__ import annotations

import inspect

import pytest

from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.ports.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderError,
    M6UpgradeDurableSampleAppenderFailureCode,
    M6UpgradeDurableSampleAppenderV3,
)
from labcourt.schema_export import expected_schema_files


def test_durable_sample_appender_exposes_only_two_scope_identities() -> None:
    method = M6UpgradeDurableSampleAppenderV3.append_pending_sample
    assert tuple(inspect.signature(method).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
    )
    assert inspect.get_annotations(method, eval_str=True) == {
        "candidate_run_id": str,
        "execution_scope_authority_id": str,
        "return": M6UpgradeSampleExecutionRecordV2,
    }

    forbidden_inputs = {
        "observation",
        "commitment",
        "record",
        "ref",
        "digest",
        "size",
        "container",
        "previous_hash",
        "ledger_sequence",
        "sequence",
        "ordinal",
        "verifier",
    }
    public_inputs = set(inspect.signature(method).parameters) - {"self"}
    assert public_inputs.isdisjoint(forbidden_inputs)


def test_durable_sample_appender_failure_is_closed_typed_and_payload_free() -> None:
    assert {item.value for item in M6UpgradeDurableSampleAppenderFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_NOT_FOUND",
        "OBSERVATION_NOT_FOUND",
        "APPEND_STATE_MISMATCH",
        "LEDGER_COMPLETE",
        "LEDGER_SEALED",
        "COMMITMENT_CONFLICT",
        "RECORD_CONFLICT",
        "PHYSICAL_ARTIFACT_REJECTED",
        "DOCUMENT_TOO_LARGE",
        "STORED_AUTHORITY_INVALID",
        "SNAPSHOT_REJECTED",
        "STORAGE_REJECTED",
    }

    error = M6UpgradeDurableSampleAppenderError(
        M6UpgradeDurableSampleAppenderFailureCode.COMMITMENT_CONFLICT
    )
    assert error.args == ("M6 durable sample append failed: COMMITMENT_CONFLICT",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert error.__cause__ is None

    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeDurableSampleAppenderError(  # type: ignore[arg-type]
            "COMMITMENT_CONFLICT"
        )


def test_durable_sample_appender_port_adds_no_serialization_schema() -> None:
    assert not any("durable-sample-appender" in name for name in expected_schema_files())
