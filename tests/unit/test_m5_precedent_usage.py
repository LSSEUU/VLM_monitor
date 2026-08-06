from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

import pytest
from pydantic import BaseModel

from labcourt.application.m5_precedent_usage import (
    M5PrecedentUsageError,
    M5PrecedentUsageErrorCode,
    build_m5_precedent_application_batch,
    build_m5_precedent_application_citation_commits,
)
from labcourt.application.m5_precedents import m5_precedent_policy_from_config
from labcourt.config_loader import load_config
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    PrecedentApplicationMode,
    ViolationType,
)
from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalOutcome,
    HearingPrecedentRetrievalResult,
)
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationBinding,
    M5PrecedentExposureBatchAuthority,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import PrecedentApplication
from labcourt.ports.evidence_repository import CaseSnapshot
from tests.contract.test_m3_contracts import _review
from tests.contract.test_m5_precedent_usage_contracts import (
    DISTINGUISH_ID,
    FOLLOW_ID,
    OTHER_VIOLATION_ID,
    _default_applications,
    _exposure,
    _ready_case,
)

ROOT = Path(__file__).parents[2]
CITED_AT = datetime(2026, 8, 3, 9, tzinfo=UTC)

ModelT = TypeVar("ModelT", bound=BaseModel)


def _config(*, precedent_similarity_min: float | None = None) -> AppConfig:
    config = load_config(ROOT / "configs" / "demo.yaml")
    if precedent_similarity_min is None:
        return config
    gate = config.procedural_gate.model_copy(
        update={"precedent_similarity_min": precedent_similarity_min}
    )
    return config.model_copy(update={"procedural_gate": gate})


def _fixture(
    *,
    config: AppConfig | None = None,
    applications: tuple[PrecedentApplication, ...] | None = None,
) -> tuple[AppConfig, M5PrecedentExposureBatchAuthority, CaseSnapshot]:
    config = config or _config()
    exposure = _exposure(
        config.config_sha256,
        policy=m5_precedent_policy_from_config(config),
        m4_top_k=config.hearing.precedent_top_k,
    )
    applications = applications or _default_applications(exposure)
    ready, _ = _ready_case(applications)
    return config, exposure, CaseSnapshot(case=ready, revision=11)


def _constructed_copy(model: ModelT, **updates: object) -> ModelT:
    values = {name: getattr(model, name) for name in type(model).model_fields}
    values.update(updates)
    return type(model).model_construct(**values)


def _expect_code(code: M5PrecedentUsageErrorCode, action: object) -> None:
    assert callable(action)
    with pytest.raises(M5PrecedentUsageError) as captured:
        action()
    assert captured.value.code == code


def _build(
    config: AppConfig,
    exposure: M5PrecedentExposureBatchAuthority,
    snapshot: CaseSnapshot,
) -> M5PrecedentApplicationBatchAuthority:
    return build_m5_precedent_application_batch(
        case_snapshot=snapshot,
        exposure=exposure,
        config=config,
    )


def test_build_application_batch_uses_exact_ready_revision_config_and_verdict_order() -> None:
    config, exposure, snapshot = _fixture()
    batch = _build(config, exposure, snapshot)

    assert batch.ready_case_revision == 11
    assert batch.ready_case == snapshot.case
    assert batch.verdict == snapshot.case.verdicts[-1]
    assert batch.config_sha256 == config.config_sha256
    assert batch.precedent_similarity_min == config.procedural_gate.precedent_similarity_min
    assert tuple(
        binding.application.precedent_ref.artifact_id for binding in batch.application_bindings
    ) == (DISTINGUISH_ID, FOLLOW_ID)
    assert tuple(binding.exposure_item.rank for binding in batch.application_bindings) == (2, 1)


def test_build_application_batch_returns_typed_case_config_and_scope_failures() -> None:
    config, exposure, snapshot = _fixture()
    _expect_code(
        M5PrecedentUsageErrorCode.INVALID_CASE_SNAPSHOT,
        lambda: _build(config, exposure, CaseSnapshot(case=snapshot.case, revision=0)),
    )

    non_ready = snapshot.case.model_copy(update={"status": CaseStatus.SCREENED})
    _expect_code(
        M5PrecedentUsageErrorCode.CASE_NOT_READY,
        lambda: _build(config, exposure, CaseSnapshot(case=non_ready, revision=12)),
    )

    foreign_config = _config(precedent_similarity_min=0.8)
    _expect_code(
        M5PrecedentUsageErrorCode.CONFIG_AUTHORITY_MISMATCH,
        lambda: _build(foreign_config, exposure, snapshot),
    )

    wrong_policy = _exposure(
        config.config_sha256,
        m4_top_k=config.hearing.precedent_top_k,
    )
    wrong_top_k = _exposure(
        config.config_sha256,
        policy=m5_precedent_policy_from_config(config),
    )
    for inconsistent_exposure in (wrong_policy, wrong_top_k):
        inconsistent_case, _ = _ready_case(_default_applications(inconsistent_exposure))
        _expect_code(
            M5PrecedentUsageErrorCode.CONFIG_AUTHORITY_MISMATCH,
            lambda exposure=inconsistent_exposure, case=inconsistent_case: _build(
                config,
                exposure,
                CaseSnapshot(case=case, revision=12),
            ),
        )

    forged_exposure = _constructed_copy(exposure, manifest_id="0" * 64)
    _expect_code(
        M5PrecedentUsageErrorCode.INVALID_EXPOSURE,
        lambda: _build(config, forged_exposure, snapshot),
    )
    empty_construct = M5PrecedentExposureBatchAuthority.model_construct()
    _expect_code(
        M5PrecedentUsageErrorCode.INVALID_EXPOSURE,
        lambda: _build(config, empty_construct, snapshot),
    )


def test_build_application_batch_rejects_missing_extra_and_low_score_applications() -> None:
    config = _config()
    exposure = _exposure(
        config.config_sha256,
        policy=m5_precedent_policy_from_config(config),
        m4_top_k=config.hearing.precedent_top_k,
    )
    defaults = _default_applications(exposure)

    missing_case, _ = _ready_case(defaults[1:])
    _expect_code(
        M5PrecedentUsageErrorCode.VERDICT_APPLICATION_INVALID,
        lambda: _build(config, exposure, CaseSnapshot(case=missing_case, revision=11)),
    )

    nonvisible = PrecedentApplication(
        precedent_ref=ArtifactRef(
            kind=ArtifactKind.PRECEDENT,
            artifact_id=OTHER_VIOLATION_ID,
        ),
        mode=PrecedentApplicationMode.FOLLOWED,
        similarity_score=0.95,
    )
    extra_case, _ = _ready_case(
        tuple(sorted((*defaults, nonvisible), key=lambda item: item.sort_key))
    )
    _expect_code(
        M5PrecedentUsageErrorCode.VERDICT_APPLICATION_INVALID,
        lambda: _build(config, exposure, CaseSnapshot(case=extra_case, revision=11)),
    )

    high_config = _config(precedent_similarity_min=0.8)
    high_exposure = _exposure(
        high_config.config_sha256,
        policy=m5_precedent_policy_from_config(high_config),
        m4_top_k=high_config.hearing.precedent_top_k,
    )
    low_case, _ = _ready_case(_default_applications(high_exposure))
    _expect_code(
        M5PrecedentUsageErrorCode.VERDICT_APPLICATION_INVALID,
        lambda: _build(
            high_config,
            high_exposure,
            CaseSnapshot(case=low_case, revision=11),
        ),
    )


def test_build_application_batch_rejects_mode_semantic_attacks() -> None:
    config, exposure, _ = _fixture()
    defaults = {item.precedent_ref.artifact_id: item for item in _default_applications(exposure)}
    wrong_direction = defaults[DISTINGUISH_ID].model_copy(
        update={
            "mode": PrecedentApplicationMode.FOLLOWED,
            "distinguishing_reason": None,
            "fact_difference_refs": (),
        }
    )
    direction_case, _ = _ready_case(
        tuple(sorted((wrong_direction, defaults[FOLLOW_ID]), key=lambda item: item.sort_key))
    )
    _expect_code(
        M5PrecedentUsageErrorCode.VERDICT_APPLICATION_INVALID,
        lambda: _build(config, exposure, CaseSnapshot(case=direction_case, revision=11)),
    )

    mixed_mode = defaults[FOLLOW_ID].model_copy(
        update={
            "distinguishing_reason": "This must not accompany FOLLOWED.",
            "fact_difference_refs": defaults[DISTINGUISH_ID].fact_difference_refs,
        }
    )
    mixed_case, _ = _ready_case(
        tuple(sorted((defaults[DISTINGUISH_ID], mixed_mode), key=lambda item: item.sort_key))
    )
    _expect_code(
        M5PrecedentUsageErrorCode.VERDICT_APPLICATION_INVALID,
        lambda: _build(config, exposure, CaseSnapshot(case=mixed_case, revision=11)),
    )


def test_citation_builder_emits_one_stable_raw_score_commit_per_binding() -> None:
    config, exposure, snapshot = _fixture()
    batch = _build(config, exposure, snapshot)
    commits = build_m5_precedent_application_citation_commits(
        application_batch=batch,
        cited_at=CITED_AT,
    )

    assert len(commits) == len(batch.application_bindings) == 2
    assert tuple(commit.application_binding for commit in commits) == batch.application_bindings
    assert tuple(commit.citation.precedent_id for commit in commits) == (
        DISTINGUISH_ID,
        FOLLOW_ID,
    )
    for commit in commits:
        evaluation_score = commit.application_binding.exposure_item.candidate_evaluation.score
        assert commit.citation.score == evaluation_score
        assert commit.citation.cited_at == CITED_AT
    followed = commits[1]
    assert followed.application_binding.application.similarity_score == 1.0
    assert followed.citation.score == pytest.approx(1.1)


@pytest.mark.parametrize(
    "cited_at",
    [
        datetime(2026, 8, 3, 9),
        datetime(2026, 8, 3, 17, tzinfo=timezone(timedelta(hours=8))),
        datetime(2026, 8, 3, 8, 59, tzinfo=UTC),
    ],
)
def test_citation_builder_rejects_non_utc_or_early_time(cited_at: datetime) -> None:
    config, exposure, snapshot = _fixture()
    batch = _build(config, exposure, snapshot)
    _expect_code(
        M5PrecedentUsageErrorCode.INVALID_CITATION_TIME,
        lambda: build_m5_precedent_application_citation_commits(
            application_batch=batch,
            cited_at=cited_at,
        ),
    )


def test_citation_builder_revalidates_model_construct_batch_and_authority() -> None:
    config, exposure, snapshot = _fixture()
    batch = _build(config, exposure, snapshot)
    omitted = _constructed_copy(
        batch,
        application_bindings=batch.application_bindings[1:],
    )
    _expect_code(
        M5PrecedentUsageErrorCode.INVALID_APPLICATION_BATCH,
        lambda: build_m5_precedent_application_citation_commits(
            application_batch=omitted,
            cited_at=CITED_AT,
        ),
    )

    empty_construct = M5PrecedentApplicationBatchAuthority.model_construct()
    _expect_code(
        M5PrecedentUsageErrorCode.INVALID_APPLICATION_BATCH,
        lambda: build_m5_precedent_application_citation_commits(
            application_batch=empty_construct,
            cited_at=CITED_AT,
        ),
    )

    first = batch.application_bindings[0]
    forged_item = _constructed_copy(first.exposure_item, precedent_revision=999)
    forged_binding = M5PrecedentApplicationBinding.model_construct(
        application=first.application,
        exposure_item=forged_item,
    )
    forged_batch = _constructed_copy(
        batch,
        application_bindings=(forged_binding, *batch.application_bindings[1:]),
    )
    _expect_code(
        M5PrecedentUsageErrorCode.INVALID_APPLICATION_BATCH,
        lambda: build_m5_precedent_application_citation_commits(
            application_batch=forged_batch,
            cited_at=CITED_AT,
        ),
    )


def _empty_application_batch(config: AppConfig) -> M5PrecedentApplicationBatchAuthority:
    exposure = _exposure(
        config.config_sha256,
        policy=m5_precedent_policy_from_config(config),
        m4_top_k=config.hearing.precedent_top_k,
    )
    outcome = exposure.m4_retrieval_outcome
    assert outcome.result is not None
    empty_violation = ViolationType.FOOD_OR_DRINK_IN_LAB
    query = outcome.query.model_copy(update={"violation_type": empty_violation})
    result = HearingPrecedentRetrievalResult(
        query=query,
        candidate_precedents=outcome.result.candidate_precedents,
    )
    receipt = outcome.receipt.model_copy(
        update={
            "violation_type": empty_violation,
            "query_sha256": query.query_sha256,
            "visible_precedent_refs": (),
            "visible_snapshot_sha256": result.visible_snapshot_sha256,
            "scored_precedents": (),
        }
    )
    empty_outcome = HearingPrecedentRetrievalOutcome(
        query=query,
        result=result,
        receipt=receipt,
    )
    empty_exposure = exposure.model_copy(
        update={
            "m4_retrieval_outcome": empty_outcome,
            "exposed_precedents": (),
        }
    )

    ready, verdict = _ready_case(())
    empty_verdict = verdict.model_copy(update={"violation_type": empty_violation})
    empty_ready = Case(
        run_id=ready.run_id,
        status=CaseStatus.READY_FOR_ALERT_POLICY,
        event=ready.event,
        evidence_packs=ready.evidence_packs,
        screening_results=ready.screening_results,
        verdicts=(empty_verdict,),
        procedural_reviews=(_review(empty_verdict),),
        manifest_id=ready.manifest_id,
    )
    return _build(
        config,
        empty_exposure,
        CaseSnapshot(case=empty_ready, revision=12),
    )


def test_citation_builder_returns_empty_for_a_valid_empty_application_batch() -> None:
    config = _config()
    batch = _empty_application_batch(config)
    assert batch.application_bindings == ()
    assert (
        build_m5_precedent_application_citation_commits(
            application_batch=batch,
            cited_at=CITED_AT,
        )
        == ()
    )


def test_usage_error_requires_the_typed_code_enum() -> None:
    with pytest.raises(TypeError, match="M5PrecedentUsageErrorCode"):
        M5PrecedentUsageError("INVALID_ARGUMENT")  # type: ignore[arg-type]
