from __future__ import annotations

import inspect

import pytest

from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.ports import (
    M6UpgradeCandidateRunCutError,
    M6UpgradeCandidateRunCutFailureCode,
    M6UpgradeCandidateRunCutRepository,
    M6UpgradeCandidateValidationReportProvider,
)


class _StructuralCandidateRunCutRepository:
    def build_or_load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateRunCutAuthority:
        del candidate_run_id, execution_scope_authority_id
        raise AssertionError("structural port check must not invoke the repository")


class _MissingCandidateRunCutRepository:
    pass


class _StructuralCandidateValidationReportProvider:
    def load_m6_upgrade_candidate_validation_report(
        self,
        candidate_run_id: str,
        audit_head_sequence: int,
        audit_head_hash: str,
    ) -> M5ArtifactValidationReport:
        del candidate_run_id, audit_head_sequence, audit_head_hash
        raise AssertionError("structural port check must not invoke the provider")


def test_candidate_run_cut_port_accepts_only_durable_scope_identities() -> None:
    method = M6UpgradeCandidateRunCutRepository.build_or_load
    assert tuple(inspect.signature(method).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
    )
    assert inspect.get_annotations(method, eval_str=True) == {
        "candidate_run_id": str,
        "execution_scope_authority_id": str,
        "return": M6UpgradeCandidateRunCutAuthority,
    }

    forbidden_inputs = {
        "scope",
        "ledger",
        "seal",
        "manifest",
        "config",
        "audit_head",
        "validation_report",
        "run_cut",
        "authority",
        "payload",
        "document",
        "digest",
        "size",
    }
    public_inputs = set(inspect.signature(method).parameters) - {"self"}
    assert public_inputs == {"candidate_run_id", "execution_scope_authority_id"}
    assert public_inputs.isdisjoint(forbidden_inputs)
    assert M6UpgradeCandidateRunCutAuthority.model_config["frozen"] is True


def test_candidate_run_cut_failure_is_exact_typed_and_payload_free() -> None:
    assert {item.value for item in M6UpgradeCandidateRunCutFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_NOT_FOUND",
        "LEDGER_VERSION_UNSUPPORTED",
        "LEDGER_NOT_SEALED",
        "SCOPE_MISMATCH",
        "AUDIT_HEAD_MISMATCH",
        "VALIDATION_REPORT_REJECTED",
        "RUN_CUT_NOT_FOUND",
        "RUN_CUT_CONFLICT",
        "DOCUMENT_TOO_LARGE",
        "STORED_AUTHORITY_INVALID",
        "SNAPSHOT_REJECTED",
        "STORAGE_REJECTED",
    }

    error = M6UpgradeCandidateRunCutError(M6UpgradeCandidateRunCutFailureCode.RUN_CUT_CONFLICT)
    assert error.args == ("M6 upgrade candidate run cut failed: RUN_CUT_CONFLICT",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert not hasattr(error, "payload")

    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeCandidateRunCutError("RUN_CUT_CONFLICT")  # type: ignore[arg-type]


def test_candidate_run_cut_repository_is_runtime_checkable_by_structure() -> None:
    assert isinstance(
        _StructuralCandidateRunCutRepository(),
        M6UpgradeCandidateRunCutRepository,
    )
    assert not isinstance(
        _MissingCandidateRunCutRepository(),
        M6UpgradeCandidateRunCutRepository,
    )


def test_candidate_validation_report_provider_requires_the_exact_historical_head() -> None:
    method = M6UpgradeCandidateValidationReportProvider.load_m6_upgrade_candidate_validation_report
    assert tuple(inspect.signature(method).parameters) == (
        "self",
        "candidate_run_id",
        "audit_head_sequence",
        "audit_head_hash",
    )
    assert inspect.get_annotations(method, eval_str=True) == {
        "candidate_run_id": str,
        "audit_head_sequence": int,
        "audit_head_hash": str,
        "return": M5ArtifactValidationReport,
    }
    assert isinstance(
        _StructuralCandidateValidationReportProvider(),
        M6UpgradeCandidateValidationReportProvider,
    )
