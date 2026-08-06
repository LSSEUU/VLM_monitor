from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from labcourt.application.m6_regression_source_catalog import (
    M6RegressionSourceCatalogError,
    M6RegressionSourceCatalogErrorCode,
    build_m6_regression_source_catalog,
)
from labcourt.application.m6_source_authority_builder import (
    M6SealedSourceBundle,
    build_m6_sealed_source_bundle,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import CaseStatus
from labcourt.ports.m6_regression_dataset import (
    M6RegressionRequiredSource,
    M6RegressionRunScopeObservation,
    M6RegressionSealedSourceObservation,
)
from tests.unit.test_m6_source_authority import _bundle
from tests.unit.test_m6_source_authority_builder import _inputs


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sealed_source(
    sample_seed: str = "opaque-sample",
) -> tuple[M6RegressionRunScopeObservation, M6RegressionSealedSourceObservation]:
    source = _bundle()
    selection, gate_source, manifest, report = _inputs(source)
    selection = replace(selection, sample_id=_sha(sample_seed))
    decision = gate_source.source_case.verdicts[-1].decision
    closed_case = gate_source.source_case.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "final_decision": decision,
        }
    )
    closed_document = canonical_json(closed_case.model_dump(mode="json"))
    gate_source = replace(
        gate_source,
        source_case=closed_case,
        source_case_document_sha256=_sha(closed_document),
    )
    built = build_m6_sealed_source_bundle(
        selection=selection,
        gate_source=gate_source,
        source_manifest=manifest,
        source_validation_report=report,
        config=source.config,
    )
    observation = _observation(built)
    required = M6RegressionRequiredSource(
        source_run_id=built.seal.source_run_id,
        source_case_id=built.seal.source_case_id,
        source_case_revision=built.seal.source_case_revision,
        source_case_document_sha256=built.seal.source_case_document_sha256,
        source_manifest_id=built.seal.source_manifest_id,
    )
    scope = M6RegressionRunScopeObservation(
        source_identity_sha256=_sha("private-snapshot"),
        source_run_id=built.seal.source_run_id,
        audit_head_sequence=built.seal.audit_head_sequence,
        audit_head_hash=built.seal.audit_head_hash,
        m5_validation_report=built.source_validation_report,
        m5_validation_report_document=built.source_validation_report_document,
        required_sources=(required,),
    )
    return scope, observation


def _observation(built: M6SealedSourceBundle) -> M6RegressionSealedSourceObservation:
    return M6RegressionSealedSourceObservation(
        replay_input_closure=built.replay_input_closure,
        replay_input_authority=built.replay_input_authority,
        source_validation_report=built.source_validation_report,
        source_case=built.source_case,
        source_manifest=built.source_manifest,
        source_seal=built.seal,
        replay_input_closure_document=built.replay_input_closure_document,
        replay_input_authority_document=built.replay_input_authority_document,
        source_validation_report_document=built.source_validation_report_document,
        source_case_document=built.source_case_document,
        source_manifest_document=built.source_manifest_document,
        source_seal_document=built.seal_document,
    )


def test_builds_complete_source_cut_and_blind_candidate_catalog() -> None:
    scope, source = _sealed_source()

    result = build_m6_regression_source_catalog(
        run_scopes=(scope,),
        sealed_sources=(source,),
    )

    cut = result.source_inventory_cut
    catalog = result.execution_source_catalog
    assert cut.source_item_count == catalog.entry_count == 1
    assert cut.source_inventory_root_sha256 == catalog.source_inventory_root_sha256
    assert catalog.source_inventory_cut_content_sha256 == (
        result.source_inventory_cut_content_sha256
    )
    assert _sha(result.source_inventory_cut_document) == (
        result.source_inventory_cut_content_sha256
    )
    assert _sha(result.execution_source_catalog_document) == (
        result.execution_source_catalog_content_sha256
    )
    entry = catalog.entries[0]
    assert entry.replay_input_closure == source.replay_input_closure
    serialized = result.execution_source_catalog_document
    for forbidden in (
        "baseline_snapshot",
        "memberships",
        "gold_truth",
        "expected_decision",
        "challenge_kinds",
        "selection_receipt",
        "eligibility_policy",
    ):
        assert forbidden not in serialized


def test_missing_extra_or_cross_grafted_source_is_fail_closed() -> None:
    scope, source = _sealed_source()
    with pytest.raises(M6RegressionSourceCatalogError) as missing:
        build_m6_regression_source_catalog(run_scopes=(scope,), sealed_sources=())
    assert missing.value.code == M6RegressionSourceCatalogErrorCode.INVALID_ARGUMENT

    _, other = _sealed_source("second-source")
    with pytest.raises(M6RegressionSourceCatalogError) as extra:
        build_m6_regression_source_catalog(
            run_scopes=(scope,),
            sealed_sources=(source, other),
        )
    assert extra.value.code == M6RegressionSourceCatalogErrorCode.SOURCE_SCOPE_INCOMPLETE

    wrong_required = replace(
        scope.required_sources[0],
        source_case_document_sha256=_sha("other-case-document"),
    )
    grafted_scope = replace(scope, required_sources=(wrong_required,))
    with pytest.raises(M6RegressionSourceCatalogError) as grafted:
        build_m6_regression_source_catalog(
            run_scopes=(grafted_scope,),
            sealed_sources=(source,),
        )
    assert grafted.value.code == M6RegressionSourceCatalogErrorCode.SOURCE_SCOPE_INCOMPLETE


def test_physical_document_tamper_and_label_leaking_sample_id_are_rejected() -> None:
    scope, source = _sealed_source()
    tampered = replace(
        source,
        replay_input_closure_document=source.replay_input_closure_document + " ",
    )
    with pytest.raises(M6RegressionSourceCatalogError) as document:
        build_m6_regression_source_catalog(
            run_scopes=(scope,),
            sealed_sources=(tampered,),
        )
    assert document.value.code == M6RegressionSourceCatalogErrorCode.SOURCE_DOCUMENT_INVALID

    leaking_scope, leaking = _sealed_source()
    leaking_closure = leaking.replay_input_closure.model_copy(update={"sample_id": "gold-001"})
    leaking_authority = leaking.replay_input_authority.model_copy(update={"sample_id": "gold-001"})
    leaking_seal = leaking.source_seal.model_copy(update={"sample_id": "gold-001"})
    leaking = replace(
        leaking,
        replay_input_closure=leaking_closure,
        replay_input_authority=leaking_authority,
        source_seal=leaking_seal,
    )
    with pytest.raises(M6RegressionSourceCatalogError) as sample:
        build_m6_regression_source_catalog(
            run_scopes=(leaking_scope,),
            sealed_sources=(leaking,),
        )
    assert sample.value.code in {
        M6RegressionSourceCatalogErrorCode.SOURCE_BUNDLE_INVALID,
        M6RegressionSourceCatalogErrorCode.SOURCE_DOCUMENT_INVALID,
    }


def test_mixed_private_snapshot_identities_are_rejected_before_catalog_build() -> None:
    scope, source = _sealed_source()
    required = replace(scope.required_sources[0], source_run_id="run-z")
    foreign = replace(
        scope,
        source_identity_sha256=_sha("foreign-private-snapshot"),
        source_run_id="run-z",
        required_sources=(required,),
    )

    with pytest.raises(M6RegressionSourceCatalogError) as raised:
        build_m6_regression_source_catalog(
            run_scopes=(scope, foreign),
            sealed_sources=(source,),
        )
    assert raised.value.code == M6RegressionSourceCatalogErrorCode.SNAPSHOT_IDENTITY_MISMATCH


def test_source_seal_and_run_scope_must_share_the_exact_authority_snapshot() -> None:
    scope, source = _sealed_source()
    foreign_scope = replace(
        scope,
        audit_head_hash=_sha("newer-audit-head"),
    )

    with pytest.raises(M6RegressionSourceCatalogError) as raised:
        build_m6_regression_source_catalog(
            run_scopes=(foreign_scope,),
            sealed_sources=(source,),
        )
    assert raised.value.code == M6RegressionSourceCatalogErrorCode.SNAPSHOT_IDENTITY_MISMATCH
