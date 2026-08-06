from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.adapters.fake_precedent_embeddings import (
    DeterministicFakePrecedentEmbeddingProvider,
)
from labcourt.application.m5_precedents import (
    ExactM5PrecedentRetrievalService,
    M5PrecedentServiceError,
    M5PrecedentServiceErrorCode,
    create_m5_precedent_authority,
    evaluate_m5_automatic_activation,
    record_m5_precedent_citation,
    resolve_m5_precedent_conflict,
    resolve_m5_precedent_conflict_batch,
    revoke_m5_precedent,
)
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    RunMode,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.m5_precedents import (
    M5AppealWindowSnapshot,
    M5EmbeddingChannel,
    M5EmbeddingRequest,
    M5EmbeddingVector,
    M5PrecedentActivationOutcome,
    M5PrecedentAuthority,
    M5PrecedentCandidateDisposition,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictBatchAuthority,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictCausalCut,
    M5PrecedentConflictOutcome,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5PrecedentRevocationOutcome,
    m5_precedent_active_head_root_sha256,
)

NOW = datetime(2026, 8, 2, 10, tzinfo=UTC)
RUN_ID = "run-m5"
RULE_VERSION = "rules-v1"
TEXT_MANIFEST = "a" * 64
VISUAL_MANIFEST = "b" * 64
CONFIG_SHA256 = "c" * 64


def _policy(*, equal_priorities: bool = False) -> M5PrecedentPolicy:
    priorities = {
        PrecedentSource.AUTOMATIC: 100,
        PrecedentSource.PRESET: 200,
        PrecedentSource.HUMAN_REVIEW: 300,
        PrecedentSource.APPEAL_OVERTURN: 400,
    }
    if equal_priorities:
        priorities = dict.fromkeys(PrecedentSource, 100)
    return M5PrecedentPolicy(
        config_sha256=CONFIG_SHA256,
        text_weight=0.7,
        visual_weight=0.3,
        source_weights={
            PrecedentSource.PRESET: 1.0,
            PrecedentSource.AUTOMATIC: 0.75,
            PrecedentSource.HUMAN_REVIEW: 1.1,
            PrecedentSource.APPEAL_OVERTURN: 1.25,
        },
        source_priorities=priorities,
        conflict_similarity=0.8,
        automatic_activation_delay_seconds=3_600,
    )


def _embedding(
    channel: M5EmbeddingChannel,
    input_ref: str,
    values: tuple[float, ...],
    *,
    manifest_id: str | None = None,
) -> M5EmbeddingVector:
    return M5EmbeddingVector(
        request=M5EmbeddingRequest(
            channel=channel,
            input_ref=input_ref,
            input_sha256=hashlib.sha256(input_ref.encode()).hexdigest(),
            model_manifest_id=(
                manifest_id
                or (TEXT_MANIFEST if channel == M5EmbeddingChannel.TEXT else VISUAL_MANIFEST)
            ),
            dimensions=len(values),
        ),
        values=values,
    )


def _authority(
    precedent_id: str,
    *,
    source: PrecedentSource = PrecedentSource.PRESET,
    direction: VerdictDecision = VerdictDecision.ESTABLISHED,
    evidence_class: EvidenceClass = EvidenceClass.PRESENCE,
    violation_type: ViolationType = ViolationType.OPEN_FLAME,
    rule_version: str = RULE_VERSION,
    text: tuple[float, ...] | None = (1.0, 0.0),
    visual: tuple[float, ...] | None = None,
) -> M5PrecedentAuthority:
    return create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id=precedent_id,
        situation_text=f"Situation for {precedent_id}.",
        decision_direction=direction,
        source=source,
        evidence_class=evidence_class,
        violation_type=violation_type,
        rule_version=rule_version,
        source_case_id=(f"case-{precedent_id}" if source == PrecedentSource.AUTOMATIC else None),
        created_at=NOW,
        policy=_policy(),
        text_embedding=(
            _embedding(M5EmbeddingChannel.TEXT, f"text-{precedent_id}", text)
            if text is not None
            else None
        ),
        visual_embeddings=(
            (_embedding(M5EmbeddingChannel.VISUAL, f"visual-{precedent_id}", visual),)
            if visual is not None
            else ()
        ),
    )


def _query(
    *,
    case_id: str = "case-query",
    policy: M5PrecedentPolicy | None = None,
    text: M5EmbeddingVector | None = None,
    visual: M5EmbeddingVector | None = None,
    experimental: bool = False,
    top_k: int = 20,
) -> M5PrecedentRetrievalQuery:
    selected_text = text or _embedding(
        M5EmbeddingChannel.TEXT,
        f"query-{case_id}",
        (1.0, 0.0),
    )
    return M5PrecedentRetrievalQuery(
        run_id=RUN_ID,
        case_id=case_id,
        evidence_class=EvidenceClass.PRESENCE,
        rule_version=RULE_VERSION,
        situation_text="Query situation.",
        text_embedding_model_manifest_id=selected_text.request.model_manifest_id,
        visual_embedding_model_manifest_id=(
            visual.request.model_manifest_id if visual is not None else VISUAL_MANIFEST
        ),
        text_embedding=selected_text,
        visual_embeddings=((visual,) if visual is not None else ()),
        policy=policy or _policy(),
        top_k=top_k,
        run_mode=(RunMode.OFFLINE_EXPERIMENT if experimental else RunMode.STANDARD),
        include_provisional_experiment=experimental,
    )


def _terminal(
    authority: M5PrecedentAuthority,
    status: PrecedentStatus,
) -> M5PrecedentAuthority:
    precedent = authority.precedent.model_copy(
        update={"status": status, "invalidated_by": "governance-ref"}
    )
    return authority.model_copy(update={"revision": 2, "precedent": precedent})


def _conflict_snapshot(
    authorities: tuple[M5PrecedentAuthority, ...],
    *,
    policy: M5PrecedentPolicy | None = None,
) -> M5PrecedentConflictSnapshot:
    ordered = tuple(sorted(authorities, key=lambda item: item.precedent.precedent_id))
    selected_policy = policy or _policy()
    return M5PrecedentConflictSnapshot(
        causal_cut=M5PrecedentConflictCausalCut(
            run_id=RUN_ID,
            manifest_id="f" * 64,
            config_sha256=CONFIG_SHA256,
            policy_id=selected_policy.policy_id,
            authority_event_sequence=1,
            authority_event_sha256="e" * 64,
            active_head_count=len(ordered),
            active_head_root_sha256=m5_precedent_active_head_root_sha256(
                run_id=RUN_ID,
                heads=tuple(
                    (
                        item.precedent.precedent_id,
                        item.authority_id,
                        item.revision,
                    )
                    for item in ordered
                ),
            ),
        ),
        authorities=ordered,
    )


def test_exact_retrieval_filters_status_class_and_rule_but_not_other_violation_type() -> None:
    eligible = _authority("precedent-eligible")
    other_violation_same_class = _authority(
        "precedent-other-violation",
        violation_type=ViolationType.FOOD_OR_DRINK_IN_LAB,
    )
    wrong_class = _authority(
        "precedent-wrong-class",
        evidence_class=EvidenceClass.ABSENCE,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
    )
    wrong_rule = _authority("precedent-wrong-rule", rule_version="rules-v0")
    provisional = _authority("precedent-provisional", source=PrecedentSource.AUTOMATIC)
    invalidated = _terminal(_authority("precedent-invalidated"), PrecedentStatus.INVALIDATED)
    revoked = _terminal(_authority("precedent-revoked"), PrecedentStatus.REVOKED)
    conflict = _terminal(_authority("precedent-conflict"), PrecedentStatus.CONFLICT)

    result = ExactM5PrecedentRetrievalService().retrieve(
        _query(),
        (
            conflict,
            wrong_rule,
            provisional,
            eligible,
            wrong_class,
            revoked,
            other_violation_same_class,
            invalidated,
        ),
    )

    assert result.candidate_count == 8
    assert result.eligible_count == 2
    assert result.unscorable_count == 0
    dispositions = {
        item.authority.precedent.precedent_id: item.disposition
        for item in result.candidate_evaluations
    }
    assert dispositions == {
        "precedent-conflict": M5PrecedentCandidateDisposition.STATUS_EXCLUDED,
        "precedent-eligible": M5PrecedentCandidateDisposition.SCORED,
        "precedent-invalidated": M5PrecedentCandidateDisposition.STATUS_EXCLUDED,
        "precedent-other-violation": M5PrecedentCandidateDisposition.SCORED,
        "precedent-provisional": M5PrecedentCandidateDisposition.STATUS_EXCLUDED,
        "precedent-revoked": M5PrecedentCandidateDisposition.STATUS_EXCLUDED,
        "precedent-wrong-class": M5PrecedentCandidateDisposition.SCOPE_EXCLUDED,
        "precedent-wrong-rule": M5PrecedentCandidateDisposition.SCOPE_EXCLUDED,
    }
    assert tuple(item.authority.precedent.precedent_id for item in result.scored_precedents) == (
        "precedent-eligible",
        "precedent-other-violation",
    )


def test_retrieval_inventory_records_unscorable_and_rejects_inventory_tamper() -> None:
    scorable = _authority("precedent-scorable")
    unscorable = _authority("precedent-unscorable", text=None)
    result = ExactM5PrecedentRetrievalService().retrieve(
        _query(),
        (unscorable, scorable),
    )

    assert result.candidate_count == 2
    assert result.eligible_count == 2
    assert result.unscorable_count == 1
    assert tuple(
        (item.authority.precedent.precedent_id, item.disposition)
        for item in result.candidate_evaluations
    ) == (
        ("precedent-scorable", M5PrecedentCandidateDisposition.SCORED),
        ("precedent-unscorable", M5PrecedentCandidateDisposition.UNSCORABLE),
    )

    serialized = result.model_dump(mode="json")
    serialized["candidate_evaluations"] = serialized["candidate_evaluations"][:-1]
    with pytest.raises(ValueError, match="candidate_count"):
        type(result).model_validate(serialized)

    duplicate = result.model_dump(mode="json")
    duplicate.pop("result_id")
    duplicate.pop("candidate_count")
    duplicate.pop("eligible_count")
    duplicate.pop("unscorable_count")
    duplicate["candidate_evaluations"].append(duplicate["candidate_evaluations"][0])
    with pytest.raises(ValueError, match="unique and stably ordered"):
        type(result).model_validate(duplicate)


def test_citation_rejects_time_before_historical_authority_visibility() -> None:
    authority = _authority("precedent-citation-time")
    result = ExactM5PrecedentRetrievalService().retrieve(_query(), (authority,))

    with pytest.raises(M5PrecedentServiceError) as raised:
        record_m5_precedent_citation(
            result=result,
            precedent_id=authority.precedent.precedent_id,
            cited_at=authority.created_at - timedelta(microseconds=1),
        )
    assert raised.value.code == M5PrecedentServiceErrorCode.INVALID_CITATION_TIME


def test_missing_channels_are_renormalized_and_source_weight_is_applied() -> None:
    text_only = _authority("precedent-text", text=(1.0, 0.0))
    visual_only = _authority("precedent-visual", text=None, visual=(0.0, 1.0))
    human = _authority(
        "precedent-human",
        source=PrecedentSource.HUMAN_REVIEW,
        text=(1.0, 0.0),
    )
    query = _query(visual=_embedding(M5EmbeddingChannel.VISUAL, "query-visual", (0.0, 1.0)))

    result = ExactM5PrecedentRetrievalService().retrieve(
        query,
        (visual_only, text_only, human),
    )
    by_id = {item.authority.precedent.precedent_id: item for item in result.scored_precedents}

    assert by_id["precedent-text"].normalized_text_weight == 1.0
    assert by_id["precedent-text"].normalized_visual_weight == 0.0
    assert by_id["precedent-visual"].normalized_text_weight == 0.0
    assert by_id["precedent-visual"].normalized_visual_weight == 1.0
    assert by_id["precedent-human"].base_similarity == pytest.approx(1.0)
    assert by_id["precedent-human"].score == pytest.approx(1.1)
    assert result.scored_precedents[0].authority.precedent.precedent_id == "precedent-human"


def test_stable_ties_use_precedent_id_and_provisional_needs_experiment_mode() -> None:
    second = _authority("precedent-b")
    first = _authority("precedent-a")
    provisional = _authority("precedent-auto", source=PrecedentSource.AUTOMATIC)
    service = ExactM5PrecedentRetrievalService()

    standard = service.retrieve(_query(), (second, provisional, first))
    assert tuple(item.authority.precedent.precedent_id for item in standard.scored_precedents) == (
        "precedent-a",
        "precedent-b",
    )

    experimental = service.retrieve(_query(experimental=True), (second, provisional, first))
    assert {item.authority.precedent.precedent_id for item in experimental.scored_precedents} == {
        "precedent-a",
        "precedent-auto",
        "precedent-b",
    }


def test_incompatible_embedding_manifest_fails_closed() -> None:
    candidate = _authority("precedent-manifest")
    query = _query(
        text=_embedding(
            M5EmbeddingChannel.TEXT,
            "query-other-manifest",
            (1.0, 0.0),
            manifest_id="f" * 64,
        )
    )
    with pytest.raises(M5PrecedentServiceError) as raised:
        ExactM5PrecedentRetrievalService().retrieve(query, (candidate,))
    assert raised.value.code == M5PrecedentServiceErrorCode.EMBEDDING_INCOMPATIBLE


def test_retrieval_and_conflict_reject_foreign_config_policy() -> None:
    established = _authority("precedent-config-established")
    opposed = _authority(
        "precedent-config-opposed",
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    foreign_policy = _policy().model_copy(update={"config_sha256": "d" * 64})

    with pytest.raises(M5PrecedentServiceError) as retrieval_failure:
        ExactM5PrecedentRetrievalService().retrieve(
            _query(policy=foreign_policy),
            (established,),
        )
    assert retrieval_failure.value.code == M5PrecedentServiceErrorCode.CONFIG_AUTHORITY_MISMATCH

    with pytest.raises(M5PrecedentServiceError) as conflict_failure:
        resolve_m5_precedent_conflict(
            existing=established,
            new=opposed,
            policy=foreign_policy,
        )
    assert conflict_failure.value.code == M5PrecedentServiceErrorCode.CONFIG_AUTHORITY_MISMATCH


def test_deterministic_fake_embedding_is_offline_manifest_bound_and_input_checked() -> None:
    payload = "受控离线判例".encode()
    request = M5EmbeddingRequest(
        channel=M5EmbeddingChannel.TEXT,
        input_ref="fixture-text",
        input_sha256=hashlib.sha256(payload).hexdigest(),
        model_manifest_id=TEXT_MANIFEST,
        dimensions=16,
    )
    provider = DeterministicFakePrecedentEmbeddingProvider()

    first = provider.embed(request, payload)
    second = provider.embed(request, payload)

    assert first == second
    assert sum(value * value for value in first.values) == pytest.approx(1.0)
    with pytest.raises(ValueError, match="input_sha256"):
        provider.embed(request, b"different")


def test_automatic_activation_waits_for_cooling_and_complete_no_appeal_snapshot() -> None:
    authority = _authority("precedent-auto", source=PrecedentSource.AUTOMATIC)
    early_at = NOW + timedelta(minutes=30)
    early_snapshot = M5AppealWindowSnapshot(
        run_id=RUN_ID,
        source_case_id="case-precedent-auto",
        source_case_revision=1,
        source_case_document_sha256="d" * 64,
        observed_through=early_at,
    )
    early = evaluate_m5_automatic_activation(
        authority=authority,
        appeal_snapshot=early_snapshot,
        evaluated_at=early_at,
    )
    assert early.receipt.outcome == M5PrecedentActivationOutcome.TOO_EARLY
    assert early.authority == authority

    eligible_at = NOW + timedelta(hours=1)
    appealed_snapshot = M5AppealWindowSnapshot(
        run_id=RUN_ID,
        source_case_id="case-precedent-auto",
        source_case_revision=2,
        source_case_document_sha256="e" * 64,
        observed_through=eligible_at,
        appeal_ids=("appeal-1",),
    )
    appealed = evaluate_m5_automatic_activation(
        authority=authority,
        appeal_snapshot=appealed_snapshot,
        evaluated_at=eligible_at,
    )
    assert appealed.receipt.outcome == M5PrecedentActivationOutcome.APPEAL_PRESENT

    clear_snapshot = appealed_snapshot.model_copy(update={"appeal_ids": ()})
    activated = evaluate_m5_automatic_activation(
        authority=authority,
        appeal_snapshot=clear_snapshot,
        evaluated_at=eligible_at,
    )
    assert activated.receipt.outcome == M5PrecedentActivationOutcome.ACTIVATED
    assert activated.authority.precedent.status == PrecedentStatus.ACTIVE
    assert activated.authority.revision == authority.revision + 1


def test_conflict_governance_invalidates_lower_priority_and_marks_equal_peers() -> None:
    automatic = _authority("precedent-auto", source=PrecedentSource.AUTOMATIC)
    activation_at = NOW + timedelta(hours=1)
    snapshot = M5AppealWindowSnapshot(
        run_id=RUN_ID,
        source_case_id="case-precedent-auto",
        source_case_revision=1,
        source_case_document_sha256="d" * 64,
        observed_through=activation_at,
    )
    automatic_active = evaluate_m5_automatic_activation(
        authority=automatic,
        appeal_snapshot=snapshot,
        evaluated_at=activation_at,
    ).authority
    human = _authority(
        "precedent-human",
        source=PrecedentSource.HUMAN_REVIEW,
        direction=VerdictDecision.NOT_ESTABLISHED,
    )

    higher = resolve_m5_precedent_conflict(
        existing=automatic_active,
        new=human,
        policy=_policy(),
    )
    assert higher.receipt.outcome == M5PrecedentConflictOutcome.EXISTING_INVALIDATED
    assert higher.existing_authority.precedent.status == PrecedentStatus.INVALIDATED
    assert higher.new_authority.precedent.status == PrecedentStatus.ACTIVE

    first = _authority("precedent-peer-a")
    second = _authority(
        "precedent-peer-b",
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    peer = resolve_m5_precedent_conflict(
        existing=first,
        new=second,
        policy=_policy(equal_priorities=True),
    )
    assert peer.receipt.outcome == M5PrecedentConflictOutcome.PEER_CONFLICT
    assert peer.existing_authority.precedent.status == PrecedentStatus.CONFLICT
    assert peer.new_authority.precedent.status == PrecedentStatus.CONFLICT


def test_conflict_excludes_different_type_neutral_direction_and_below_threshold() -> None:
    established = _authority("precedent-base")
    different_type = _authority(
        "precedent-other-type",
        direction=VerdictDecision.NOT_ESTABLISHED,
        violation_type=ViolationType.FOOD_OR_DRINK_IN_LAB,
    )
    neutral = _authority(
        "precedent-neutral",
        direction=VerdictDecision.INSUFFICIENT_EVIDENCE,
    )
    dissimilar = _authority(
        "precedent-dissimilar",
        direction=VerdictDecision.NOT_ESTABLISHED,
        text=(0.0, 1.0),
    )
    for candidate in (different_type, neutral, dissimilar):
        resolution = resolve_m5_precedent_conflict(
            existing=established,
            new=candidate,
            policy=_policy(),
        )
        assert resolution.receipt.outcome == M5PrecedentConflictOutcome.NO_CONFLICT
        assert resolution.existing_authority == established
        assert resolution.new_authority == candidate


def test_complete_conflict_graph_is_stable_for_one_complete_causal_snapshot() -> None:
    authorities = (
        _authority("precedent-a", direction=VerdictDecision.ESTABLISHED),
        _authority("precedent-b", direction=VerdictDecision.NOT_ESTABLISHED),
        _authority("precedent-c", direction=VerdictDecision.ESTABLISHED),
    )
    snapshot = _conflict_snapshot(authorities)
    first = resolve_m5_precedent_conflict_batch(
        snapshot=snapshot,
        policy=_policy(),
        scan_limit=3,
    )
    replay = resolve_m5_precedent_conflict_batch(
        snapshot=snapshot,
        policy=_policy(),
        scan_limit=3,
    )

    assert replay == first
    assert first.batch_authority.evaluated_pair_count == 2
    assert tuple(edge.sort_key for edge in first.batch_authority.edges) == (
        ("precedent-a", "precedent-b"),
        ("precedent-b", "precedent-c"),
    )
    assert tuple(item.precedent.status for item in first.resulting_authorities) == (
        PrecedentStatus.CONFLICT,
        PrecedentStatus.CONFLICT,
        PrecedentStatus.CONFLICT,
    )


def test_complete_conflict_graph_uses_higher_then_equal_precedence_deterministically() -> None:
    higher = _authority(
        "precedent-higher",
        source=PrecedentSource.APPEAL_OVERTURN,
        direction=VerdictDecision.ESTABLISHED,
    )
    middle_opposite = _authority(
        "precedent-middle-opposite",
        source=PrecedentSource.PRESET,
        direction=VerdictDecision.NOT_ESTABLISHED,
    )
    middle_peer = _authority(
        "precedent-middle-peer",
        source=PrecedentSource.PRESET,
        direction=VerdictDecision.ESTABLISHED,
    )

    result = resolve_m5_precedent_conflict_batch(
        snapshot=_conflict_snapshot((middle_peer, higher, middle_opposite)),
        policy=_policy(),
        scan_limit=3,
    )
    by_id = {
        authority.precedent.precedent_id: authority for authority in result.resulting_authorities
    }

    assert by_id["precedent-higher"].precedent.status == PrecedentStatus.ACTIVE
    assert by_id["precedent-middle-opposite"].precedent.status == PrecedentStatus.INVALIDATED
    assert by_id["precedent-middle-opposite"].precedent.invalidated_by == "precedent-higher"
    assert by_id["precedent-middle-peer"].precedent.status == PrecedentStatus.CONFLICT
    assert by_id["precedent-middle-peer"].precedent.invalidated_by == "precedent-middle-opposite"


def test_conflict_batch_resolution_closes_priority_and_threshold_to_policy() -> None:
    policy = _policy()
    snapshot = _conflict_snapshot(
        (
            _authority("precedent-a", direction=VerdictDecision.ESTABLISHED),
            _authority("precedent-b", direction=VerdictDecision.NOT_ESTABLISHED),
        ),
        policy=policy,
    )
    resolution = resolve_m5_precedent_conflict_batch(
        snapshot=snapshot,
        policy=policy,
        scan_limit=2,
    )

    def attacked_resolution(
        *,
        priority_delta: int = 0,
        threshold: float | None = None,
    ) -> M5PrecedentConflictBatchResolution:
        candidates = list(resolution.batch_authority.candidates)
        edges = list(resolution.batch_authority.edges)
        if priority_delta:
            candidates[0] = candidates[0].model_copy(
                update={"source_priority": candidates[0].source_priority + priority_delta}
            )
            edges[0] = edges[0].model_copy(
                update={"left_priority": edges[0].left_priority + priority_delta}
            )
        if threshold is not None:
            edges[0] = edges[0].model_copy(update={"threshold": threshold})
        batch = M5PrecedentConflictBatchAuthority(
            run_id=resolution.batch_authority.run_id,
            config_sha256=resolution.batch_authority.config_sha256,
            policy_id=resolution.batch_authority.policy_id,
            causal_cut=resolution.batch_authority.causal_cut,
            scan_limit=resolution.batch_authority.scan_limit,
            candidates=tuple(candidates),
            evaluated_pair_count=resolution.batch_authority.evaluated_pair_count,
            edges=tuple(edges),
        )
        receipt = M5PrecedentConflictBatchReceipt(
            run_id=resolution.receipt.run_id,
            config_sha256=resolution.receipt.config_sha256,
            policy_id=resolution.receipt.policy_id,
            batch_authority_id=batch.batch_authority_id,
            causal_cut_id=batch.causal_cut.cut_id,
            results=resolution.receipt.results,
        )
        return M5PrecedentConflictBatchResolution(
            policy=policy,
            batch_authority=batch,
            receipt=receipt,
            prior_authorities=resolution.prior_authorities,
            resulting_authorities=resolution.resulting_authorities,
        )

    with pytest.raises(ValidationError, match="priority differs"):
        attacked_resolution(priority_delta=1)
    with pytest.raises(ValidationError, match="threshold differs"):
        attacked_resolution(threshold=0.7)


def test_revocation_returns_all_historical_cases_without_rewriting_old_citations() -> None:
    service = ExactM5PrecedentRetrievalService()
    authority = _authority("precedent-cited")
    first_result = service.retrieve(_query(case_id="case-a"), (authority,))
    first_commit = record_m5_precedent_citation(
        result=first_result,
        precedent_id="precedent-cited",
        cited_at=NOW + timedelta(minutes=1),
    )
    second_result = service.retrieve(_query(case_id="case-b"), (authority,))
    second_commit = record_m5_precedent_citation(
        result=second_result,
        precedent_id="precedent-cited",
        cited_at=NOW + timedelta(minutes=2),
    )
    old_citations = (first_commit.citation, second_commit.citation)
    revoked_at = NOW + timedelta(minutes=3)
    snapshot = M5PrecedentCitationSnapshot(
        run_id=RUN_ID,
        precedent_id="precedent-cited",
        captured_at=revoked_at,
        citations=tuple(sorted(old_citations, key=lambda item: (item.case_id, item.citation_id))),
    )

    result = revoke_m5_precedent(
        authority=authority,
        citation_snapshot=snapshot,
        revoked_by_ref="appeal-overturn-1",
        revoked_at=revoked_at,
    )

    assert result.receipt.outcome == M5PrecedentRevocationOutcome.REVOKED
    assert result.authority.precedent.status == PrecedentStatus.REVOKED
    assert result.receipt.historical_case_ids == ("case-a", "case-b")
    assert result.receipt.old_cases_rewritten is False
    assert snapshot.citations == old_citations
    assert all(
        citation.precedent_authority_id != result.authority.authority_id
        for citation in old_citations
    )

    replay = revoke_m5_precedent(
        authority=result.authority,
        citation_snapshot=snapshot,
        revoked_by_ref="appeal-overturn-1",
        revoked_at=revoked_at,
    )
    assert replay.receipt.outcome == M5PrecedentRevocationOutcome.ALREADY_REVOKED
    assert replay.authority == result.authority
