from __future__ import annotations

import inspect

import pytest

from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.ports.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorError,
    M6UpgradeCandidateCoordinatorFailureCode,
    M6UpgradeCandidateCoordinatorV3,
)
from labcourt.schema_export import expected_schema_files


def test_candidate_coordinator_start_and_resume_have_narrow_surfaces() -> None:
    start = M6UpgradeCandidateCoordinatorV3.run_to_terminal
    resume = M6UpgradeCandidateCoordinatorV3.resume_to_terminal
    assert tuple(inspect.signature(start).parameters) == ("self", "execution_scope")
    assert inspect.get_annotations(start, eval_str=True) == {
        "execution_scope": M6UpgradeExecutionScopeAuthority,
        "return": M6UpgradeCandidateOutputInventoryAuthorityV3,
    }
    assert tuple(inspect.signature(resume).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
    )
    assert inspect.get_annotations(resume, eval_str=True) == {
        "candidate_run_id": str,
        "execution_scope_authority_id": str,
        "return": M6UpgradeCandidateOutputInventoryAuthorityV3,
    }
    forbidden_resume_inputs = {
        "scope",
        "catalog",
        "entry",
        "observation",
        "record",
        "commitment",
        "seal",
        "run_cut",
        "inventory",
        "verifier",
    }
    assert (set(inspect.signature(resume).parameters) - {"self"}).isdisjoint(
        forbidden_resume_inputs
    )


def test_candidate_coordinator_failure_is_closed_and_payload_free() -> None:
    assert {item.value for item in M6UpgradeCandidateCoordinatorFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_NOT_FOUND",
        "SCOPE_CONFLICT",
        "EXECUTION_STATE_INVALID",
        "OBSERVATION_REJECTED",
        "SAMPLE_REJECTED",
        "SEAL_REJECTED",
        "RUN_CUT_REJECTED",
        "TERMINAL_OUTPUT_REJECTED",
        "DOCUMENT_TOO_LARGE",
        "STORED_AUTHORITY_INVALID",
        "COORDINATION_STALLED",
        "STORAGE_REJECTED",
    }
    error = M6UpgradeCandidateCoordinatorError(
        M6UpgradeCandidateCoordinatorFailureCode.RUN_CUT_REJECTED
    )
    assert error.args == ("M6 candidate coordination failed: RUN_CUT_REJECTED",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert error.__context__ is None
    assert error.__cause__ is None
    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeCandidateCoordinatorError("RUN_CUT_REJECTED")  # type: ignore[arg-type]


def test_candidate_coordinator_adds_no_wire_schema() -> None:
    assert not any("candidate-coordinator" in name for name in expected_schema_files())
