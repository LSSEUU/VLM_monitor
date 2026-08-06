from __future__ import annotations

import hashlib

import pytest

from labcourt.application.m6_upgrade_candidate_run_cut import (
    build_m6_upgrade_candidate_run_cut,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m5_artifact_validation import (
    M5ArtifactValidationArea,
    M5ArtifactValidationCounts,
    M5ArtifactValidationIssue,
    M5ArtifactValidationIssueCode,
    M5ArtifactValidationReport,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.ports.m6_upgrade_candidate_run_cut import (
    M6UpgradeCandidateRunCutError,
    M6UpgradeCandidateRunCutFailureCode,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import (
    _v3_inventory,
)


def _inputs() -> tuple[
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeExecutionLedgerSealV2,
    M5ArtifactValidationReport,
]:
    inventory = _v3_inventory()
    return (
        inventory.execution_ledger.execution_scope,
        inventory.execution_ledger,
        inventory.candidate_run_cut.validation_report,
    )


def _canonical_report_copy(
    report: M5ArtifactValidationReport,
    *,
    run_id: str | None = None,
    manifest_id: str | None = None,
    config_sha256: str | None = None,
    audit_head_sequence: int | None = None,
    audit_head_hash: str | None = None,
    counts: M5ArtifactValidationCounts | None = None,
    issues: tuple[M5ArtifactValidationIssue, ...] | None = None,
) -> M5ArtifactValidationReport:
    predecessor = report.predecessor_report
    assert type(predecessor) is M4ArtifactValidationReport
    m4_report = predecessor
    m3_report = m4_report.m3_report
    m2_report = m3_report.m2_report
    changed_m2 = m2_report.model_copy(
        update={
            **({"run_id": run_id} if run_id is not None else {}),
            **({"manifest_id": manifest_id} if manifest_id is not None else {}),
            **(
                {"audit_head_sequence": audit_head_sequence}
                if audit_head_sequence is not None
                else {}
            ),
            **({"audit_head_hash": audit_head_hash} if audit_head_hash is not None else {}),
        }
    )
    changed_m3 = m3_report.model_copy(
        update={
            "m2_report": changed_m2,
            **({"run_id": run_id} if run_id is not None else {}),
        }
    )
    changed_m4 = m4_report.model_copy(
        update={
            "m3_report": changed_m3,
            **({"run_id": run_id} if run_id is not None else {}),
        }
    )
    changed = report.model_copy(
        update={
            "predecessor_report": changed_m4,
            **({"run_id": run_id} if run_id is not None else {}),
            **({"manifest_id": manifest_id} if manifest_id is not None else {}),
            **({"config_sha256": config_sha256} if config_sha256 is not None else {}),
            **({"counts": counts} if counts is not None else {}),
            **({"issues": issues} if issues is not None else {}),
        }
    )
    return M5ArtifactValidationReport.model_validate(
        changed.model_dump(mode="json", exclude_computed_fields=True)
    )


def _assert_failure(
    expected: M6UpgradeCandidateRunCutFailureCode,
    *,
    execution_scope: M6UpgradeExecutionScopeAuthority,
    execution_ledger: object,
    validation_report: M5ArtifactValidationReport,
) -> M6UpgradeCandidateRunCutError:
    with pytest.raises(M6UpgradeCandidateRunCutError) as raised:
        build_m6_upgrade_candidate_run_cut(
            execution_scope=execution_scope,
            execution_ledger=execution_ledger,  # type: ignore[arg-type]
            validation_report=validation_report,
        )
    assert raised.value.reason_code == expected
    return raised.value


def test_build_candidate_run_cut_is_exact_deterministic_and_canonically_revalidates() -> None:
    scope, ledger, report = _inputs()

    first = build_m6_upgrade_candidate_run_cut(
        execution_scope=scope,
        execution_ledger=ledger,
        validation_report=report,
    )
    second = build_m6_upgrade_candidate_run_cut(
        execution_scope=scope,
        execution_ledger=ledger,
        validation_report=report,
    )

    report_document = canonical_json(report.model_dump(mode="json"))
    expected = _v3_inventory().candidate_run_cut
    assert first == second == expected
    assert first.candidate_run_id == scope.candidate_run_id
    assert first.candidate_manifest == scope.candidate_manifest
    assert first.candidate_manifest_content_sha256 == scope.candidate_manifest_content_sha256
    assert first.candidate_config == scope.candidate_config
    assert first.candidate_config_content_sha256 == scope.candidate_config_content_sha256
    assert first.execution_component_manifest_id == (
        scope.execution_component.component_authority_id
    )
    assert first.audit_head_sequence == ledger.source_audit_head_sequence
    assert first.audit_head_hash == ledger.source_audit_head_hash
    assert first.validation_report == report
    assert (
        first.validation_report_content_sha256
        == hashlib.sha256(report_document.encode("utf-8")).hexdigest()
    )
    assert M6UpgradeCandidateRunCutAuthority.model_validate(first.model_dump(mode="json")) == first


@pytest.mark.parametrize(
    "target",
    ("execution_scope", "execution_ledger", "validation_report"),
)
def test_build_candidate_run_cut_rejects_every_noncanonical_exact_input(target: str) -> None:
    scope, ledger, report = _inputs()
    if target == "execution_scope":
        scope = scope.model_copy(deep=True)
        object.__setattr__(scope, "candidate_run_id", "")
    elif target == "execution_ledger":
        ledger = ledger.model_copy(deep=True)
        object.__setattr__(ledger, "source_audit_head_sequence", True)
    else:
        report = report.model_copy(deep=True)
        object.__setattr__(report, "run_id", "")

    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT,
        execution_scope=scope,
        execution_ledger=ledger,
        validation_report=report,
    )


def test_build_candidate_run_cut_rejects_non_v2_seal_and_cross_scope() -> None:
    scope, ledger, report = _inputs()
    legacy_ledger = _inventory().execution_ledger
    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.LEDGER_VERSION_UNSUPPORTED,
        execution_scope=scope,
        execution_ledger=legacy_ledger,
        validation_report=report,
    )

    foreign_payload = scope.model_dump(mode="python", exclude_computed_fields=True)
    foreign_payload["candidate_run_id"] = "run-foreign-candidate"
    foreign_scope = M6UpgradeExecutionScopeAuthority.model_validate(foreign_payload)
    assert foreign_scope != ledger.execution_scope
    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.SCOPE_MISMATCH,
        execution_scope=foreign_scope,
        execution_ledger=ledger,
        validation_report=report,
    )


def test_build_candidate_run_cut_rejects_non_passing_validation_report() -> None:
    scope, ledger, report = _inputs()
    issue = M5ArtifactValidationIssue(
        code=M5ArtifactValidationIssueCode.AUTHORITY_RECORD_COUNT_BUDGET_EXCEEDED,
        area=M5ArtifactValidationArea.BUDGET,
        reason_code="unit-budget-exceeded",
        limit=1,
        observed=2,
    )
    rejected = _canonical_report_copy(report, issues=(issue,))
    assert not rejected.passed

    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED,
        execution_scope=scope,
        execution_ledger=ledger,
        validation_report=rejected,
    )


@pytest.mark.parametrize(
    "report_update",
    (
        {"run_id": "run-foreign-candidate"},
        {"manifest_id": "e" * 64},
        {"config_sha256": "d" * 64},
    ),
)
def test_build_candidate_run_cut_rejects_report_scope_mismatch(
    report_update: dict[str, str],
) -> None:
    scope, ledger, report = _inputs()
    rejected = _canonical_report_copy(report, **report_update)  # type: ignore[arg-type]

    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED,
        execution_scope=scope,
        execution_ledger=ledger,
        validation_report=rejected,
    )


def test_build_candidate_run_cut_rejects_m2_audit_head_drift() -> None:
    scope, ledger, report = _inputs()
    rejected = _canonical_report_copy(
        report,
        audit_head_sequence=ledger.source_audit_head_sequence - 1,
        audit_head_hash="c" * 64,
    )

    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.AUDIT_HEAD_MISMATCH,
        execution_scope=scope,
        execution_ledger=ledger,
        validation_report=rejected,
    )


def test_build_candidate_run_cut_rejects_case_root_count_drift() -> None:
    scope, ledger, report = _inputs()
    counts = report.counts.model_copy(update={"case_roots": ledger.candidate_case_count + 1})
    rejected = _canonical_report_copy(report, counts=counts)

    _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED,
        execution_scope=scope,
        execution_ledger=ledger,
        validation_report=rejected,
    )


def test_build_candidate_run_cut_error_is_payload_free() -> None:
    scope, ledger, report = _inputs()
    error = _assert_failure(
        M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED,
        execution_scope=scope,
        execution_ledger=ledger,
        validation_report=_canonical_report_copy(
            report,
            counts=report.counts.model_copy(update={"case_roots": ledger.candidate_case_count + 1}),
        ),
    )

    assert error.args == ("M6 upgrade candidate run cut failed: VALIDATION_REPORT_REJECTED",)
    assert vars(error) == {"reason_code": error.reason_code}
    assert error.__cause__ is None
