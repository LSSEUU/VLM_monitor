from __future__ import annotations

from pathlib import Path

import pytest

from labcourt.adapters.storage.m6_regression_store import (
    M6RegressionPublisher,
    M6RegressionStoreError,
    M6RegressionStoreErrorCode,
    ReadonlyM6RegressionStore,
)
from labcourt.application.m6_regression_publication import (
    build_m6_regression_publication_bundle,
)
from labcourt.application.m6_upgrade_regression import (
    assemble_m6_upgrade_regression_report,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import VerdictDecision
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthority,
)
from tests.contract.test_m6_regression_contracts import _gold_entry, _minimal_dataset
from tests.unit.test_m6_upgrade_regression import _inputs, _v3_inputs


def _publication():  # type: ignore[no-untyped-def]
    return build_m6_regression_publication_bundle(
        assemble_m6_upgrade_regression_report(**_inputs())
    )


def _different_publication():  # type: ignore[no-untyped-def]
    inputs = _inputs()
    outputs = inputs["candidate_output_inventory"]
    assert isinstance(outputs, M6UpgradeCandidateOutputInventoryAuthority)
    dataset = _minimal_dataset(
        gold_entry=_gold_entry(expected_decision=VerdictDecision.NOT_ESTABLISHED)
    )
    assert dataset.execution_dataset == outputs.execution_dataset
    inputs.update(
        {
            "dataset": dataset,
            "dataset_document": canonical_json(dataset.model_dump(mode="json")),
        }
    )
    return build_m6_regression_publication_bundle(assemble_m6_upgrade_regression_report(**inputs))


def test_publishes_idempotently_and_reads_from_regression_commit_point(
    tmp_path: Path,
) -> None:
    publication = _publication()
    publisher = M6RegressionPublisher(tmp_path)

    first = publisher.publish(publication)
    second = publisher.publish(publication)
    stored = ReadonlyM6RegressionStore(tmp_path).load(publication.seal.candidate_run_id)

    assert first == second
    assert first.report_path == tmp_path / publication.seal.candidate_run_id / "regression.json"
    assert first.report_path.is_file()
    assert first.seal_path.is_file()
    assert all(path.is_file() for path in first.dependency_paths)
    assert stored.report == publication.report_bundle.report
    assert stored.seal == publication.seal
    assert stored.to_report_bundle() == publication.report_bundle
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_publishes_and_reads_terminal_v3_inventory_without_reinterpretation(
    tmp_path: Path,
) -> None:
    publication = build_m6_regression_publication_bundle(
        assemble_m6_upgrade_regression_report(**_v3_inputs())
    )

    result = M6RegressionPublisher(tmp_path).publish(publication)
    stored = ReadonlyM6RegressionStore(tmp_path).load(publication.seal.candidate_run_id)

    assert result.report_path.is_file()
    assert stored.candidate_output_inventory.schema_version == (
        "m6-upgrade-candidate-output-inventory-authority-v3"
    )
    assert stored.candidate_output_inventory == (
        publication.report_bundle.candidate_output_inventory
    )
    assert stored.to_report_bundle() == publication.report_bundle


@pytest.mark.parametrize(
    "phase",
    (
        "after_staging",
        "after_dependency:COMMAND",
        "after_seal",
        "before_commit",
    ),
)
def test_faults_before_report_commit_cannot_be_mistaken_for_success(
    tmp_path: Path,
    phase: str,
) -> None:
    publication = _publication()

    def fault(observed: str) -> None:
        if observed == phase:
            raise RuntimeError(f"fault:{phase}")

    with pytest.raises(M6RegressionStoreError):
        M6RegressionPublisher(tmp_path, fault_injector=fault).publish(publication)
    with pytest.raises(M6RegressionStoreError) as missing:
        ReadonlyM6RegressionStore(tmp_path).load(publication.seal.candidate_run_id)
    assert missing.value.code == M6RegressionStoreErrorCode.COMMIT_MISSING

    recovered = M6RegressionPublisher(tmp_path).publish(publication)
    assert recovered.report_path.is_file()
    assert not tuple(path for path in (tmp_path / ".staging").rglob("*") if path.is_file())


def test_lost_report_commit_receipt_recovers_only_after_full_readback(
    tmp_path: Path,
) -> None:
    publication = _publication()

    def fault(phase: str) -> None:
        if phase == "after_commit":
            raise RuntimeError("simulated lost report rename receipt")

    result = M6RegressionPublisher(tmp_path, fault_injector=fault).publish(publication)

    assert result.report_path.is_file()
    assert (
        ReadonlyM6RegressionStore(tmp_path).load(publication.seal.candidate_run_id).seal
        == publication.seal
    )


def test_fixed_run_rejects_a_different_report_without_overwrite(tmp_path: Path) -> None:
    first = _publication()
    conflicting = _different_publication()
    assert first.seal.candidate_run_id == conflicting.seal.candidate_run_id
    assert first.seal.report_id != conflicting.seal.report_id
    published = M6RegressionPublisher(tmp_path).publish(first)
    original = published.report_path.read_bytes()

    with pytest.raises(M6RegressionStoreError) as conflict:
        M6RegressionPublisher(tmp_path).publish(conflicting)
    assert conflict.value.code == M6RegressionStoreErrorCode.COMMIT_CONFLICT
    assert published.report_path.read_bytes() == original
    assert ReadonlyM6RegressionStore(tmp_path).load(first.seal.candidate_run_id).seal == (
        first.seal
    )


def test_reader_rejects_extra_seal_inventory_tamper_and_noncanonical_report(
    tmp_path: Path,
) -> None:
    publication = _publication()
    result = M6RegressionPublisher(tmp_path).publish(publication)
    extra = result.seal_path.parent / "extra.json"
    extra.write_text("{}", encoding="utf-8")

    with pytest.raises(M6RegressionStoreError) as inventory:
        ReadonlyM6RegressionStore(tmp_path).load(publication.seal.candidate_run_id)
    assert inventory.value.code == M6RegressionStoreErrorCode.INVENTORY_INVALID

    extra.unlink()
    dependency = result.dependency_paths[0]
    original_dependency = dependency.read_bytes()
    dependency.write_bytes(b"{}")
    with pytest.raises(M6RegressionStoreError) as tampered:
        ReadonlyM6RegressionStore(tmp_path).load(publication.seal.candidate_run_id)
    assert tampered.value.code == M6RegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE

    dependency.write_bytes(original_dependency)
    result.report_path.write_bytes(result.report_path.read_bytes() + b" ")
    with pytest.raises(M6RegressionStoreError) as noncanonical:
        ReadonlyM6RegressionStore(tmp_path).load(publication.seal.candidate_run_id)
    assert noncanonical.value.code == M6RegressionStoreErrorCode.REPORT_INVALID


def test_reader_enforces_document_budget_before_json_parsing(tmp_path: Path) -> None:
    publication = _publication()
    M6RegressionPublisher(tmp_path).publish(publication)

    with pytest.raises(M6RegressionStoreError) as oversized:
        ReadonlyM6RegressionStore(tmp_path, max_document_bytes=1).load(
            publication.seal.candidate_run_id
        )
    assert oversized.value.code == M6RegressionStoreErrorCode.STORAGE_BOUNDARY_FAILURE
