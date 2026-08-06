from __future__ import annotations

from dataclasses import replace

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_m5_precedent_plan as subject
from labcourt.application.m5_hearing_precedent_bridge import (
    M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
    M5_HEARING_PRECEDENT_BRIDGE_VERSION,
)
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.hearing_state import (
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalStatus,
    HearingSessionEntryStatus,
)
from labcourt.contracts.m5_precedents import M5EmbeddingChannel
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)


def _sha(value: int) -> str:
    return f"{value:064x}"


def _hearing() -> subject.M6SQLiteM5PrecedentHearingSlot:
    return subject.M6SQLiteM5PrecedentHearingSlot(
        run_id="run-1",
        case_id="case-1",
        rowid=1,
        hearing_id=_sha(1),
        screening_id=_sha(2),
        entry_status=HearingSessionEntryStatus.ESCALATED,
        trigger_review_id=None,
        initial_defect_codes=(),
        initial_defect_codes_sha256=_sha(3),
        initial_pack_id=_sha(4),
        initial_pack_version=1,
        max_acquisition_rounds=2,
        max_rework_rounds=2,
        max_total_images=320,
        max_total_output_tokens=1000,
        max_judge_cycles=5,
        hearing_prompt_bundle_sha256=_sha(5),
        prosecutor_model_manifest_id=_sha(6),
        defender_model_manifest_id=_sha(7),
        judge_model_manifest_id=_sha(8),
        manifest_id=_sha(9),
        created_audit_sequence=10,
        document_sha256=_sha(11),
        document_bytes=101,
    )


def _cycle() -> subject.M6SQLiteM5PrecedentCycleSlot:
    return subject.M6SQLiteM5PrecedentCycleSlot(
        run_id="run-1",
        case_id="case-1",
        rowid=2,
        cycle_id=_sha(12),
        cycle_sha256=_sha(13),
        hearing_id=_sha(1),
        cycle_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        cycle_pack_id=_sha(4),
        cycle_pack_version=1,
        initial_trigger_review_id=None,
        initial_defect_codes=(),
        initial_defect_codes_sha256=_sha(14),
        rework_review_id=None,
        rework_defect_codes=(),
        rework_defect_codes_sha256=_sha(15),
        manifest_id=_sha(9),
        created_audit_sequence=11,
        document_sha256=_sha(16),
        document_bytes=102,
    )


def _retrieval(
    *,
    bridge: bool = True,
    status: HearingPrecedentRetrievalStatus = HearingPrecedentRetrievalStatus.SUCCESS,
    candidate_ids: tuple[str, ...] = (),
) -> subject.M6SQLiteM5PrecedentRetrievalSlot:
    return subject.M6SQLiteM5PrecedentRetrievalSlot(
        run_id="run-1",
        case_id="case-1",
        rowid=3,
        retrieval_receipt_id=_sha(17),
        hearing_id=_sha(1),
        cycle_scope_id=_sha(12),
        cycle_scope_sha256=_sha(13),
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_pack_id=_sha(4),
        current_pack_version=1,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        rule_version="rule-v1",
        top_k=1,
        initial_trigger_review_id=None,
        initial_defect_codes=(),
        initial_defect_codes_sha256=_sha(18),
        rework_review_id=None,
        rework_defect_codes=(),
        rework_defect_codes_sha256=_sha(19),
        candidate_precedent_ids=candidate_ids,
        candidate_refs_sha256=_sha(20),
        candidate_snapshot_sha256=_sha(21),
        visible_precedent_ids=(),
        visible_refs_sha256=_sha(22),
        visible_snapshot_sha256=_sha(23),
        scored_precedents_sha256=_sha(24),
        retrieval_status=status,
        degraded_reason=(
            HearingPrecedentDegradedReason.EMBEDDING_PROVIDER_UNAVAILABLE
            if status == HearingPrecedentRetrievalStatus.DEGRADED
            else None
        ),
        precedent_retrieval_degraded=(status == HearingPrecedentRetrievalStatus.DEGRADED),
        retriever_version=(M5_HEARING_PRECEDENT_BRIDGE_VERSION if bridge else "fake-retriever-v1"),
        retriever_manifest_id=(M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID if bridge else _sha(25)),
        query_sha256=_sha(26),
        embedding_model_manifest_id=_sha(27),
        manifest_id=_sha(9),
        document_sha256=_sha(28),
        document_bytes=103,
    )


def _exposure(*, candidate_count: int = 0) -> subject.M6SQLiteM5PrecedentExposureSlot:
    return subject.M6SQLiteM5PrecedentExposureSlot(
        run_id="run-1",
        case_id="case-1",
        rowid=4,
        exposure_id=_sha(29),
        exposure_sha256=_sha(30),
        hearing_id=_sha(1),
        cycle_index=1,
        cycle_scope_id=_sha(12),
        cycle_scope_sha256=_sha(13),
        retrieval_receipt_id=_sha(17),
        m4_query_id=_sha(31),
        m5_query_id=_sha(32),
        m5_result_id=_sha(33),
        candidate_count=candidate_count,
        exposed_count=0,
        policy_id=_sha(34),
        bridge_manifest_id=M5_HEARING_PRECEDENT_BRIDGE_MANIFEST_ID,
        manifest_id=_sha(9),
        document_sha256=_sha(35),
        document_bytes=104,
    )


def _derived() -> subject.M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot:
    ref = M6UpgradePhysicalArtifactRef(
        source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        kind=M6UpgradePhysicalArtifactKind.EMBEDDING,
        artifact_id=_sha(36),
        document_sha256=_sha(37),
        content_sha256=_sha(37),
        size_bytes=105,
    )
    return subject.M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot(
        run_id="run-1",
        case_id="case-1",
        hearing_id=_sha(1),
        cycle_scope_id=_sha(12),
        retrieval_receipt_id=_sha(17),
        m4_query_id=_sha(31),
        m5_query_id=_sha(32),
        channel=M5EmbeddingChannel.TEXT,
        channel_index=0,
        request_id=_sha(38),
        input_ref="hearing-situation-1",
        input_sha256=_sha(39),
        model_manifest_id=_sha(27),
        dimensions=8,
        algorithm="FAKE_SHA256_SIGNED_PROJECTION_V1",
        physical_ref=ref,
    )


def _observation(
    kind: M6UpgradePhysicalArtifactKind,
    artifact_id: str,
    *,
    usage: M6UpgradeArtifactUsage = M6UpgradeArtifactUsage.PRODUCED,
) -> M6UpgradeObservedArtifactIdentity:
    return M6UpgradeObservedArtifactIdentity(
        source=M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        kind=kind,
        artifact_id=artifact_id,
        usage=usage,
    )


def _durable() -> subject.M6SQLiteM5PrecedentDurableEmbeddingSlot:
    return subject.M6SQLiteM5PrecedentDurableEmbeddingSlot(
        run_id="run-1",
        rowid=5,
        embedding_id=_sha(40),
        request_id=_sha(41),
        channel=M5EmbeddingChannel.TEXT,
        input_ref="precedent-1",
        input_sha256=_sha(42),
        model_manifest_id=_sha(43),
        dimensions=8,
        algorithm="FAKE_SHA256_SIGNED_PROJECTION_V1",
        manifest_id=_sha(9),
        document_sha256=_sha(44),
        document_bytes=106,
    )


def _revision() -> subject.M6SQLiteM5PrecedentRevisionSlot:
    return subject.M6SQLiteM5PrecedentRevisionSlot(
        run_id="run-1",
        rowid=6,
        precedent_id="precedent-1",
        revision=1,
        authority_id=_sha(45),
        status=PrecedentStatus.ACTIVE,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        decision_direction=VerdictDecision.ESTABLISHED,
        rule_version="rule-v1",
        source_case_id=None,
        citation_count=0,
        text_embedding_id=_sha(40),
        visual_embedding_ids=(),
        visual_embedding_ids_sha256=_sha(46),
        created_at="2026-01-01T00:00:00.000000Z",
        activation_not_before=None,
        activated_at="2026-01-01T00:00:00.000000Z",
        manifest_id=_sha(9),
        document_sha256=_sha(47),
        document_bytes=107,
    )


def _plan(
    *,
    retrieval: subject.M6SQLiteM5PrecedentRetrievalSlot | None = None,
    exposure: subject.M6SQLiteM5PrecedentExposureSlot | None = None,
    derived: subject.M6SQLiteM5PrecedentDerivedQueryEmbeddingSlot | None = None,
    durable: tuple[subject.M6SQLiteM5PrecedentDurableEmbeddingSlot, ...] = (),
    revisions: tuple[subject.M6SQLiteM5PrecedentRevisionSlot, ...] = (),
) -> subject.M6SQLiteM5PrecedentDocumentsPlan:
    selected = retrieval or _retrieval()
    selected_exposure = _exposure() if exposure is None else exposure
    selected_derived = _derived() if derived is None else derived
    bridge_success = (
        selected.is_m5_bridge
        and selected.retrieval_status == HearingPrecedentRetrievalStatus.SUCCESS
    )
    exposures = (selected_exposure,) if bridge_success else ()
    derived_items = (selected_derived,) if bridge_success else ()
    observed_items: tuple[M6UpgradeObservedArtifactIdentity, ...] = ()
    if bridge_success:
        observed_items = (
            _observation(
                M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                selected_exposure.exposure_id,
            ),
            _observation(
                M6UpgradePhysicalArtifactKind.EMBEDDING,
                selected_derived.physical_ref.artifact_id,
            ),
        )
    observations = tuple(
        sorted(
            observed_items,
            key=lambda value: value.sort_key,
        )
    )
    return subject.M6SQLiteM5PrecedentDocumentsPlan(
        run_id="run-1",
        case_id="case-1",
        manifest_id=_sha(9),
        upstream_m4_plan_identity_sha256=_sha(48),
        upstream_retrieval_keys=(selected.retrieval_key,),
        observed_artifacts=observations,
        hearings=(_hearing(),),
        cycles=(_cycle(),),
        retrievals=(selected,),
        exposures=exposures,
        derived_query_embeddings=derived_items,
        durable_embeddings=durable,
        precedent_revisions=revisions,
    )


def test_physical_route_matrix_is_exactly_exposure_and_embedding() -> None:
    assert set(subject.M6SQLiteM5PrecedentPhysicalRoute) == {
        subject.M6SQLiteM5PrecedentPhysicalRoute.PRECEDENT_EXPOSURE,
        subject.M6SQLiteM5PrecedentPhysicalRoute.EMBEDDING,
    }


def test_semantic_exposure_digest_is_distinct_from_raw_document_digest() -> None:
    exposure = _exposure()
    assert exposure.exposure_sha256 != exposure.document_sha256
    assert exposure.physical_ref.document_sha256 == exposure.document_sha256
    assert exposure.physical_ref.content_sha256 == exposure.document_sha256
    plan = _plan(exposure=exposure)
    assert subject._plan_is_consistent(plan)
    assert plan.plan_identity_sha256


def test_support_embedding_is_not_physical_without_observation() -> None:
    retrieval = _retrieval(candidate_ids=("precedent-1",))
    plan = _plan(
        retrieval=retrieval,
        exposure=_exposure(candidate_count=1),
        durable=(_durable(),),
        revisions=(_revision(),),
    )
    assert _sha(40) not in {value.artifact_id for value in plan.planned_artifact_refs}
    assert {value.kind for value in plan.planned_artifact_refs} == {
        M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
        M6UpgradePhysicalArtifactKind.EMBEDDING,
    }


def test_unreferenced_unobserved_durable_embedding_is_rejected() -> None:
    with pytest.raises(ValueError, match="exact observed/support inventory"):
        _plan(durable=(_durable(),))


def test_exposure_count_must_equal_normalized_m4_visible_set() -> None:
    retrieval = replace(
        _retrieval(candidate_ids=("precedent-1",)),
        visible_precedent_ids=("precedent-1",),
    )
    with pytest.raises(ValueError, match="crosses its M4 retrieval"):
        _plan(
            retrieval=retrieval,
            exposure=_exposure(candidate_count=1),
            durable=(_durable(),),
            revisions=(_revision(),),
        )

    accepted = _plan(
        retrieval=retrieval,
        exposure=replace(_exposure(candidate_count=1), exposed_count=1),
        durable=(_durable(),),
        revisions=(_revision(),),
    )
    assert accepted.exposures[0].exposed_count == 1


def test_non_bridge_success_requires_no_m5_artifacts() -> None:
    plan = _plan(retrieval=_retrieval(bridge=False))
    assert not plan.observed_artifacts
    assert not plan.exposures
    assert not plan.derived_query_embeddings
    assert not plan.planned_artifact_refs


def test_degraded_bridge_requires_no_exposure_or_query() -> None:
    plan = _plan(retrieval=_retrieval(status=HearingPrecedentRetrievalStatus.DEGRADED))
    assert not plan.planned_artifact_refs


def test_bridge_pin_half_match_is_rejected() -> None:
    retrieval = _retrieval(bridge=True)
    with pytest.raises(ValueError, match="pinned together"):
        replace(retrieval, retriever_manifest_id=_sha(25))


def test_retrieval_top_k_zero_is_rejected_before_body_recovery() -> None:
    with pytest.raises(ValueError, match=r"\[1, 64\]"):
        replace(_retrieval(), top_k=0)


def test_upstream_membership_is_exact() -> None:
    plan = _plan()
    with pytest.raises(ValueError, match="upstream M4"):
        replace(
            plan,
            upstream_retrieval_keys=(
                replace(plan.upstream_retrieval_keys[0], retrieval_receipt_id=_sha(49)),
            ),
        )


def test_successful_bridge_requires_query_and_exposure() -> None:
    plan = _plan()
    with pytest.raises(ValueError, match="lacks exposure/query"):
        replace(plan, exposures=(), observed_artifacts=plan.observed_artifacts[1:])


def test_successful_bridge_rejects_multiple_derived_query_embeddings() -> None:
    plan = _plan()
    second_ref = plan.derived_query_embeddings[0].physical_ref.model_copy(
        update={
            "artifact_id": _sha(50),
            "document_sha256": _sha(51),
            "content_sha256": _sha(51),
        }
    )
    second = replace(plan.derived_query_embeddings[0], physical_ref=second_ref)
    observations = tuple(
        sorted(
            (
                *plan.observed_artifacts,
                _observation(M6UpgradePhysicalArtifactKind.EMBEDDING, _sha(50)),
            ),
            key=lambda value: value.sort_key,
        )
    )
    with pytest.raises(ValueError, match="lacks exposure/query"):
        replace(
            plan,
            observed_artifacts=observations,
            derived_query_embeddings=tuple(
                sorted(
                    (*plan.derived_query_embeddings, second),
                    key=lambda value: value.sort_key,
                )
            ),
        )


def test_two_retrievals_may_reuse_one_derived_query_embedding_identity() -> None:
    hearing = _hearing()
    cycle_one = _cycle()
    retrieval_one = _retrieval()
    exposure_one = _exposure()
    derived_one = _derived()
    cycle_two = replace(
        cycle_one,
        rowid=7,
        cycle_id=_sha(52),
        cycle_sha256=_sha(53),
        cycle_index=2,
        prior_acquisition_rounds=1,
        created_audit_sequence=12,
        document_sha256=_sha(54),
    )
    retrieval_two = replace(
        retrieval_one,
        rowid=8,
        retrieval_receipt_id=_sha(55),
        cycle_scope_id=cycle_two.cycle_id,
        cycle_scope_sha256=cycle_two.cycle_sha256,
        prior_acquisition_rounds=1,
        document_sha256=_sha(56),
    )
    exposure_two = replace(
        exposure_one,
        rowid=9,
        exposure_id=_sha(57),
        exposure_sha256=_sha(58),
        cycle_index=2,
        cycle_scope_id=cycle_two.cycle_id,
        cycle_scope_sha256=cycle_two.cycle_sha256,
        retrieval_receipt_id=retrieval_two.retrieval_receipt_id,
        m4_query_id=_sha(59),
        document_sha256=_sha(60),
    )
    derived_two = replace(
        derived_one,
        cycle_scope_id=cycle_two.cycle_id,
        retrieval_receipt_id=retrieval_two.retrieval_receipt_id,
        m4_query_id=exposure_two.m4_query_id,
    )
    observations = tuple(
        sorted(
            (
                _observation(
                    M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                    exposure_one.exposure_id,
                ),
                _observation(
                    M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
                    exposure_two.exposure_id,
                ),
                _observation(
                    M6UpgradePhysicalArtifactKind.EMBEDDING,
                    derived_one.physical_ref.artifact_id,
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )
    plan = subject.M6SQLiteM5PrecedentDocumentsPlan(
        run_id="run-1",
        case_id="case-1",
        manifest_id=_sha(9),
        upstream_m4_plan_identity_sha256=_sha(48),
        upstream_retrieval_keys=(
            retrieval_one.retrieval_key,
            retrieval_two.retrieval_key,
        ),
        observed_artifacts=observations,
        hearings=(hearing,),
        cycles=(cycle_one, cycle_two),
        retrievals=(retrieval_one, retrieval_two),
        exposures=(exposure_one, exposure_two),
        derived_query_embeddings=(derived_one, derived_two),
        durable_embeddings=(),
        precedent_revisions=(),
    )
    embedding_refs = tuple(
        value
        for value in plan.planned_artifact_refs
        if value.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
    )
    assert embedding_refs == (derived_one.physical_ref,)


def test_derived_query_embedding_must_be_observed_as_produced() -> None:
    plan = _plan()
    observations = tuple(
        sorted(
            (
                next(
                    value
                    for value in plan.observed_artifacts
                    if value.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
                ),
                _observation(
                    M6UpgradePhysicalArtifactKind.EMBEDDING,
                    plan.derived_query_embeddings[0].physical_ref.artifact_id,
                    usage=M6UpgradeArtifactUsage.CONSUMED,
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )
    with pytest.raises(ValueError, match="must be produced"):
        replace(plan, observed_artifacts=observations)


def test_observed_durable_embedding_must_be_consumed() -> None:
    retrieval = _retrieval(candidate_ids=("precedent-1",))
    plan = _plan(
        retrieval=retrieval,
        exposure=_exposure(candidate_count=1),
        durable=(_durable(),),
        revisions=(_revision(),),
    )
    produced = tuple(
        sorted(
            (
                *plan.observed_artifacts,
                _observation(M6UpgradePhysicalArtifactKind.EMBEDDING, _sha(40)),
            ),
            key=lambda value: value.sort_key,
        )
    )
    with pytest.raises(ValueError, match="historical embeddings must be consumed"):
        replace(plan, observed_artifacts=produced)

    consumed = tuple(
        sorted(
            (
                *plan.observed_artifacts,
                _observation(
                    M6UpgradePhysicalArtifactKind.EMBEDDING,
                    _sha(40),
                    usage=M6UpgradeArtifactUsage.CONSUMED,
                ),
            ),
            key=lambda value: value.sort_key,
        )
    )
    accepted = replace(plan, observed_artifacts=consumed)
    assert _sha(40) in {value.artifact_id for value in accepted.planned_artifact_refs}


def test_precedent_revision_embedding_support_is_mandatory() -> None:
    retrieval = _retrieval(candidate_ids=("precedent-1",))
    with pytest.raises(ValueError, match="embedding support"):
        _plan(
            retrieval=retrieval,
            exposure=_exposure(candidate_count=1),
            revisions=(_revision(),),
        )


def test_total_document_budget_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subject, "MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_TOTAL_BYTES", 1)
    with pytest.raises(ValueError, match="total budget"):
        _plan()
