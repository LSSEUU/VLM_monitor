from __future__ import annotations

import hashlib
import importlib.util
import sys
from dataclasses import dataclass, fields, replace
from pathlib import Path
from types import ModuleType

import pytest

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_m5_precedent_query import (
    M6SQLiteM5CycleQueryMetadata,
    M6SQLiteM5ExposureQueryMetadata,
    M6SQLiteM5HearingQueryMetadata,
    M6SQLiteM5PrecedentQueryError,
    M6SQLiteM5PrecedentQueryFailureCode,
    M6SQLiteM5ReconstructedPrecedentQuery,
    M6SQLiteM5RetrievalQueryMetadata,
    reconstruct_m6_sqlite_m5_precedent_query,
)
from labcourt.application.hearing_situation import build_hearing_situation_text
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
    derive_m5_query_for_hearing,
)
from labcourt.application.m5_precedent_policy_verifier import (
    ConfiguredM5PrecedentPolicyVerifier,
)
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import CaseStatus
from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalQuery,
    derive_hearing_evidence_pack_document_sha256,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingScope,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)

ROOT = Path(__file__).parents[2]


def _load_hearing_helpers() -> ModuleType:
    module_name = "_labcourt_test_m6_m5_query_hearing_helpers"
    specification = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "tests" / "unit" / "test_m4_hearing_request.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = module
    specification.loader.exec_module(module)
    return module


hearing_helpers = _load_hearing_helpers()


def _sha(label: str) -> str:
    return sha256_hex(["m6-sqlite-m5-query-test", label])


def _codes_sha256(codes: tuple[object, ...]) -> str:
    document = canonical_json([code.value for code in codes])  # type: ignore[attr-defined]
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class _Fixture:
    manifest: object
    config: object
    selected_case: Case
    hearing: M6SQLiteM5HearingQueryMetadata
    cycle: M6SQLiteM5CycleQueryMetadata
    retrieval: M6SQLiteM5RetrievalQueryMetadata
    exposure: M6SQLiteM5ExposureQueryMetadata
    expected_m4_query: HearingPrecedentRetrievalQuery

    def reconstruct(self) -> M6SQLiteM5ReconstructedPrecedentQuery:
        return reconstruct_m6_sqlite_m5_precedent_query(
            manifest=self.manifest,  # type: ignore[arg-type]
            config=self.config,  # type: ignore[arg-type]
            selected_case=self.selected_case,
            hearing_metadata=self.hearing,
            cycle_metadata=self.cycle,
            retrieval_metadata=self.retrieval,
            exposure_metadata=self.exposure,
        )


def _fixture() -> _Fixture:
    scenario = hearing_helpers._scenario()
    selected_case = Case(
        run_id=scenario.pack.run_id,
        status=CaseStatus.EVIDENCE_READY,
        event=scenario.pack.event,
        evidence_packs=(scenario.pack,),
        manifest_id=scenario.manifest.manifest_id,
    )
    m4_query = HearingPrecedentRetrievalQuery(
        run_id=scenario.pack.run_id,
        case_id=scenario.pack.case_id,
        hearing_session_id=scenario.session.session_id,
        hearing_session_sha256=scenario.session.session_sha256,
        cycle_scope_id=scenario.scope.cycle_id,
        cycle_scope_sha256=scenario.scope.cycle_sha256,
        current_evidence_pack_id=scenario.pack.pack_id,
        current_evidence_pack_version=scenario.pack.version,
        current_evidence_pack_sha256=derive_hearing_evidence_pack_document_sha256(scenario.pack),
        evidence_class=scenario.pack.event.evidence_class,
        violation_type=scenario.pack.event.violation_type,
        rule_version=scenario.manifest.rule_version,
        situation_text=build_hearing_situation_text(scenario.pack),
        top_k=scenario.config.hearing.precedent_top_k,
        config_sha256=scenario.config.config_sha256,
        retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        embedding_model_manifest=scenario.manifest.models["text_embedding"],
        manifest_id=scenario.manifest.manifest_id,
    )
    verifier = ConfiguredM5PrecedentPolicyVerifier(scenario.config)
    policy = verifier.expected_policy(scenario.manifest)
    m5_query = derive_m5_query_for_hearing(
        query=m4_query,
        manifest=scenario.manifest,
        policy=policy,
        run_mode=verifier.run_mode,
    )
    hearing = M6SQLiteM5HearingQueryMetadata(
        run_id=scenario.session.run_id,
        case_id=scenario.session.case_id,
        hearing_id=scenario.session.session_id,
        screening_id=scenario.session.screening_id,
        entry_status=scenario.session.entry_status,
        trigger_review_id=None,
        initial_defect_codes_sha256=_codes_sha256(()),
        initial_pack_id=scenario.session.initial_evidence_pack_id,
        initial_pack_version=scenario.session.initial_evidence_pack_version,
        max_acquisition_rounds=scenario.session.acquisition_round_limit,
        max_rework_rounds=scenario.session.rework_round_limit,
        max_total_images=scenario.session.max_total_images,
        max_total_output_tokens=scenario.session.max_total_output_tokens,
        max_judge_cycles=scenario.session.max_total_judge_cycles,
        hearing_prompt_bundle_sha256=scenario.session.hearing_prompt_bundle_sha256,
        prosecutor_model_manifest_id=scenario.session.prosecutor_model_manifest_id,
        defender_model_manifest_id=scenario.session.defender_model_manifest_id,
        judge_model_manifest_id=scenario.session.judge_model_manifest_id,
        manifest_id=scenario.session.manifest_id,
        document_sha256=scenario.session.session_sha256,
    )
    cycle = M6SQLiteM5CycleQueryMetadata(
        run_id=scenario.scope.run_id,
        case_id=scenario.scope.case_id,
        hearing_id=scenario.scope.hearing_session_id,
        cycle_id=scenario.scope.cycle_id,
        cycle_sha256=scenario.scope.cycle_sha256,
        cycle_index=scenario.scope.cycle_index,
        prior_acquisition_rounds=scenario.scope.prior_acquisition_rounds,
        prior_rework_rounds=scenario.scope.prior_rework_rounds,
        cycle_pack_id=scenario.scope.cycle_evidence_pack_id,
        cycle_pack_version=scenario.scope.cycle_evidence_pack_version,
        initial_trigger_review_id=None,
        initial_defect_codes_sha256=_codes_sha256(()),
        rework_review_id=None,
        rework_defect_codes_sha256=_codes_sha256(()),
        manifest_id=scenario.scope.manifest_id,
    )
    receipt_id = _sha("retrieval-receipt")
    retrieval = M6SQLiteM5RetrievalQueryMetadata(
        run_id=scenario.pack.run_id,
        retrieval_receipt_id=receipt_id,
        hearing_id=scenario.session.session_id,
        cycle_scope_id=scenario.scope.cycle_id,
        cycle_scope_sha256=scenario.scope.cycle_sha256,
        case_id=scenario.pack.case_id,
        prior_acquisition_rounds=scenario.scope.prior_acquisition_rounds,
        prior_rework_rounds=scenario.scope.prior_rework_rounds,
        current_pack_id=scenario.pack.pack_id,
        current_pack_version=scenario.pack.version,
        evidence_class=scenario.pack.event.evidence_class,
        violation_type=scenario.pack.event.violation_type,
        rule_version=scenario.manifest.rule_version,
        top_k=scenario.config.hearing.precedent_top_k,
        initial_trigger_review_id=None,
        initial_defect_codes_sha256=_codes_sha256(()),
        rework_review_id=None,
        rework_defect_codes_sha256=_codes_sha256(()),
        retrieval_status=scenario.retrieval.status,
        degraded_reason=None,
        precedent_retrieval_degraded=False,
        retriever_version=M5_HEARING_PRECEDENT_BRIDGE_VERSION,
        retriever_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        query_sha256=m4_query.query_sha256,
        embedding_model_manifest_id=scenario.manifest.models["text_embedding"].model_manifest_id,
        manifest_id=scenario.manifest.manifest_id,
    )
    exposure = M6SQLiteM5ExposureQueryMetadata(
        run_id=scenario.pack.run_id,
        exposure_id=_sha("exposure"),
        case_id=scenario.pack.case_id,
        hearing_id=scenario.session.session_id,
        cycle_index=scenario.scope.cycle_index,
        cycle_scope_id=scenario.scope.cycle_id,
        cycle_scope_sha256=scenario.scope.cycle_sha256,
        retrieval_receipt_id=receipt_id,
        m4_query_id=m4_query.query_id,
        m5_query_id=m5_query.query_id,
        policy_id=policy.policy_id,
        bridge_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        manifest_id=scenario.manifest.manifest_id,
    )
    return _Fixture(
        manifest=scenario.manifest,
        config=scenario.config,
        selected_case=selected_case,
        hearing=hearing,
        cycle=cycle,
        retrieval=retrieval,
        exposure=exposure,
        expected_m4_query=m4_query,
    )


def _assert_code(
    fixture: _Fixture,
    expected: M6SQLiteM5PrecedentQueryFailureCode,
) -> None:
    with pytest.raises(M6SQLiteM5PrecedentQueryError) as captured:
        fixture.reconstruct()
    assert captured.value.reason_code == expected


def test_reconstructs_exact_text_query_embedding_without_provider_or_m5_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture()

    def _forbidden_embed(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("query reconstruction must not call an embedding provider")

    monkeypatch.setattr(
        DeterministicFakePrecedentEmbeddingProvider,
        "embed",
        _forbidden_embed,
    )
    first = fixture.reconstruct()
    second = fixture.reconstruct()

    assert first == second
    assert first.m4_query == fixture.expected_m4_query
    assert first.m5_query.situation_text == build_hearing_situation_text(
        fixture.selected_case.evidence_packs[0]
    )
    assert first.m5_query.text_embedding is not None
    assert first.m5_query.visual_embeddings == ()
    assert first.query_embedding_authority.scope == M6LockedEmbeddingScope.QUERY
    assert first.query_embedding_authority.channel == M6LockedEmbeddingChannel.TEXT
    assert first.query_embedding_ref.source == M6UpgradePhysicalArtifactSource.M5_PRECEDENT
    assert first.query_embedding_ref.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
    assert (
        first.query_embedding_ref.artifact_id == first.query_embedding_authority.vector.embedding_id
    )
    assert len(first.reconstruction_identity_sha256) == 64


def test_metadata_contracts_cannot_carry_the_forbidden_bodies_or_free_text() -> None:
    forbidden = {
        "hearing_json",
        "cycle_json",
        "receipt_json",
        "exposure_json",
        "situation_text",
        "query_embedding",
    }
    metadata_types = (
        M6SQLiteM5HearingQueryMetadata,
        M6SQLiteM5CycleQueryMetadata,
        M6SQLiteM5RetrievalQueryMetadata,
        M6SQLiteM5ExposureQueryMetadata,
    )

    for metadata_type in metadata_types:
        names = {field.name for field in fields(metadata_type)}
        assert names.isdisjoint(forbidden)
        assert metadata_type.__dataclass_params__.frozen
        assert "__slots__" in metadata_type.__dict__


@pytest.mark.parametrize(
    ("field_name", "replacement", "expected"),
    (
        (
            "document_sha256",
            _sha("wrong-hearing-document"),
            M6SQLiteM5PrecedentQueryFailureCode.HEARING_BINDING_MISMATCH,
        ),
        (
            "hearing_prompt_bundle_sha256",
            _sha("wrong-prompt-bundle"),
            M6SQLiteM5PrecedentQueryFailureCode.HEARING_BINDING_MISMATCH,
        ),
        (
            "prosecutor_model_manifest_id",
            _sha("wrong-prosecutor-model"),
            M6SQLiteM5PrecedentQueryFailureCode.HEARING_BINDING_MISMATCH,
        ),
    ),
)
def test_hearing_metadata_tampering_fails_closed(
    field_name: str,
    replacement: object,
    expected: M6SQLiteM5PrecedentQueryFailureCode,
) -> None:
    fixture = _fixture()
    fixture = replace(
        fixture,
        hearing=replace(fixture.hearing, **{field_name: replacement}),
    )
    _assert_code(fixture, expected)


@pytest.mark.parametrize(
    ("field_name", "replacement"),
    (
        ("cycle_sha256", _sha("wrong-cycle-sha")),
        ("cycle_id", _sha("wrong-cycle-id")),
        ("cycle_pack_id", _sha("missing-cycle-pack")),
        ("initial_defect_codes_sha256", _sha("wrong-cycle-defects")),
    ),
)
def test_cycle_metadata_tampering_fails_closed(field_name: str, replacement: object) -> None:
    fixture = _fixture()
    fixture = replace(
        fixture,
        cycle=replace(fixture.cycle, **{field_name: replacement}),
    )
    expected = (
        M6SQLiteM5PrecedentQueryFailureCode.PACK_BINDING_MISMATCH
        if field_name == "cycle_pack_id"
        else M6SQLiteM5PrecedentQueryFailureCode.CYCLE_BINDING_MISMATCH
    )
    _assert_code(fixture, expected)


@pytest.mark.parametrize(
    ("field_name", "replacement", "expected"),
    (
        (
            "query_sha256",
            _sha("wrong-m4-query"),
            M6SQLiteM5PrecedentQueryFailureCode.QUERY_BINDING_MISMATCH,
        ),
        (
            "retriever_version",
            "wrong-bridge-version",
            M6SQLiteM5PrecedentQueryFailureCode.BRIDGE_BINDING_MISMATCH,
        ),
        (
            "retriever_manifest_id",
            _sha("wrong-bridge-manifest"),
            M6SQLiteM5PrecedentQueryFailureCode.BRIDGE_BINDING_MISMATCH,
        ),
        (
            "embedding_model_manifest_id",
            _sha("wrong-embedding-model"),
            M6SQLiteM5PrecedentQueryFailureCode.RETRIEVAL_BINDING_MISMATCH,
        ),
    ),
)
def test_retrieval_metadata_tampering_fails_closed(
    field_name: str,
    replacement: object,
    expected: M6SQLiteM5PrecedentQueryFailureCode,
) -> None:
    fixture = _fixture()
    fixture = replace(
        fixture,
        retrieval=replace(fixture.retrieval, **{field_name: replacement}),
    )
    _assert_code(fixture, expected)


@pytest.mark.parametrize(
    ("field_name", "replacement", "expected"),
    (
        (
            "m4_query_id",
            _sha("wrong-m4-query-id"),
            M6SQLiteM5PrecedentQueryFailureCode.BRIDGE_BINDING_MISMATCH,
        ),
        (
            "m5_query_id",
            _sha("wrong-m5-query-id"),
            M6SQLiteM5PrecedentQueryFailureCode.QUERY_BINDING_MISMATCH,
        ),
        (
            "policy_id",
            _sha("wrong-policy"),
            M6SQLiteM5PrecedentQueryFailureCode.POLICY_BINDING_MISMATCH,
        ),
        (
            "bridge_manifest_id",
            _sha("wrong-exposure-bridge"),
            M6SQLiteM5PrecedentQueryFailureCode.BRIDGE_BINDING_MISMATCH,
        ),
    ),
)
def test_exposure_identity_tampering_fails_closed(
    field_name: str,
    replacement: object,
    expected: M6SQLiteM5PrecedentQueryFailureCode,
) -> None:
    fixture = _fixture()
    fixture = replace(
        fixture,
        exposure=replace(fixture.exposure, **{field_name: replacement}),
    )
    _assert_code(fixture, expected)


def test_missing_selected_case_pack_fails_before_any_query_derivation() -> None:
    fixture = _fixture()
    selected_case = Case(
        run_id=fixture.selected_case.run_id,
        status=CaseStatus.CANDIDATE,
        event=fixture.selected_case.event,
        manifest_id=fixture.selected_case.manifest_id,
    )

    _assert_code(
        replace(fixture, selected_case=selected_case),
        M6SQLiteM5PrecedentQueryFailureCode.PACK_BINDING_MISMATCH,
    )


def test_failure_code_vocabulary_is_closed() -> None:
    assert {code.value for code in M6SQLiteM5PrecedentQueryFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_MISMATCH",
        "CASE_BINDING_MISMATCH",
        "HEARING_BINDING_MISMATCH",
        "CYCLE_BINDING_MISMATCH",
        "PACK_BINDING_MISMATCH",
        "RETRIEVAL_BINDING_MISMATCH",
        "BRIDGE_BINDING_MISMATCH",
        "QUERY_BINDING_MISMATCH",
        "POLICY_BINDING_MISMATCH",
        "EMBEDDING_BINDING_MISMATCH",
        "PHYSICAL_PLAN_INVALID",
    }
