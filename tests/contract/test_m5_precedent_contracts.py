from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.application.m5_precedents import create_m5_precedent_authority
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
    M5PrecedentConflictBatchAuthority,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentConflictCandidateAuthority,
    M5PrecedentConflictCausalCut,
    M5PrecedentConflictEdge,
    M5PrecedentConflictNodeResult,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    m5_precedent_active_head_root_sha256,
)

NOW = datetime(2026, 8, 2, 9, tzinfo=UTC)
MANIFEST_ID = "a" * 64
CONFIG_SHA256 = "c" * 64


def test_appeal_window_snapshot_binds_exact_immutable_case_cut() -> None:
    snapshot = M5AppealWindowSnapshot(
        run_id="run-m5",
        source_case_id="case-source",
        source_case_revision=7,
        source_case_document_sha256="d" * 64,
        observed_through=NOW,
        appeal_ids=("appeal-1",),
    )
    serialized = snapshot.model_dump(mode="json")

    assert M5AppealWindowSnapshot.model_validate(serialized) == snapshot
    assert (
        snapshot.model_copy(update={"source_case_revision": 8}).snapshot_id != snapshot.snapshot_id
    )
    assert (
        snapshot.model_copy(update={"source_case_document_sha256": "e" * 64}).snapshot_id
        != snapshot.snapshot_id
    )
    serialized["source_case_document_sha256"] = "e" * 64
    with pytest.raises(ValidationError, match="snapshot_id"):
        M5AppealWindowSnapshot.model_validate(serialized)

    missing_cut = snapshot.model_dump(
        mode="json",
        exclude={"snapshot_id", "source_case_revision"},
    )
    with pytest.raises(ValidationError, match="source_case_revision"):
        M5AppealWindowSnapshot.model_validate(missing_cut)


def _policy() -> M5PrecedentPolicy:
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
        source_priorities={
            PrecedentSource.AUTOMATIC: 100,
            PrecedentSource.PRESET: 200,
            PrecedentSource.HUMAN_REVIEW: 300,
            PrecedentSource.APPEAL_OVERTURN: 400,
        },
        conflict_similarity=0.55,
        automatic_activation_delay_seconds=86_400,
    )


def _embedding(
    channel: M5EmbeddingChannel,
    input_ref: str,
    values: tuple[float, ...] = (1.0, 0.0),
) -> M5EmbeddingVector:
    return M5EmbeddingVector(
        request=M5EmbeddingRequest(
            channel=channel,
            input_ref=input_ref,
            input_sha256="b" * 64,
            model_manifest_id=MANIFEST_ID,
            dimensions=len(values),
        ),
        values=values,
    )


def test_embedding_and_policy_are_content_addressed_and_reject_tamper() -> None:
    embedding = _embedding(M5EmbeddingChannel.TEXT, "case-text")
    serialized = embedding.model_dump(mode="json")
    assert M5EmbeddingVector.model_validate(serialized) == embedding

    serialized["embedding_id"] = "0" * 64
    with pytest.raises(ValidationError, match="embedding_id"):
        M5EmbeddingVector.model_validate(serialized)

    with pytest.raises(ValidationError, match="non-zero norm"):
        _embedding(M5EmbeddingChannel.TEXT, "zero", (0.0, 0.0))
    with pytest.raises(ValidationError, match="must sum to one"):
        _policy().model_copy(update={"text_weight": 0.8})
    with pytest.raises(ValidationError, match="every precedent source"):
        _policy().model_copy(
            update={
                "source_weights": {
                    PrecedentSource.PRESET: 1.0,
                }
            }
        )

    policy = _policy()
    foreign_config = policy.model_copy(update={"config_sha256": "d" * 64})
    assert foreign_config.policy_id != policy.policy_id
    serialized_policy = policy.model_dump(mode="json")
    serialized_policy["config_sha256"] = "d" * 64
    with pytest.raises(ValidationError, match="policy_id"):
        M5PrecedentPolicy.model_validate(serialized_policy)


def test_m5_authority_wraps_frozen_precedent_without_changing_legacy_wire() -> None:
    text = _embedding(M5EmbeddingChannel.TEXT, "automatic-text")
    authority = create_m5_precedent_authority(
        run_id="run-m5",
        precedent_id="precedent-auto",
        situation_text="Controlled automatic precedent.",
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.AUTOMATIC,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.OPEN_FLAME,
        rule_version="rules-v1",
        source_case_id="case-source",
        created_at=NOW,
        policy=_policy(),
        text_embedding=text,
    )

    assert authority.precedent.status.value == "PROVISIONAL"
    assert authority.config_sha256 == CONFIG_SHA256
    assert authority.activation_not_before == NOW + timedelta(days=1)
    assert authority.precedent.text_embedding_ref == text.embedding_id
    serialized = authority.model_dump(mode="json")
    assert type(authority).model_validate(serialized) == authority
    serialized["authority_id"] = "f" * 64
    with pytest.raises(ValidationError, match="authority_id"):
        type(authority).model_validate(serialized)

    broken = authority.precedent.model_copy(update={"text_embedding_ref": "missing"})
    with pytest.raises(ValidationError, match="text embedding reference"):
        authority.model_copy(update={"precedent": broken})
    counted = authority.precedent.model_copy(update={"citation_count": 1})
    with pytest.raises(ValidationError, match="frozen compatibility field"):
        authority.model_copy(update={"precedent": counted})


def test_provisional_visibility_requires_two_explicit_experiment_controls() -> None:
    text = _embedding(M5EmbeddingChannel.TEXT, "query-text")
    arguments = {
        "run_id": "run-m5",
        "case_id": "case-query",
        "evidence_class": EvidenceClass.PRESENCE,
        "rule_version": "rules-v1",
        "situation_text": "A query situation.",
        "text_embedding_model_manifest_id": MANIFEST_ID,
        "visual_embedding_model_manifest_id": MANIFEST_ID,
        "text_embedding": text,
        "policy": _policy(),
        "top_k": 4,
    }
    standard = M5PrecedentRetrievalQuery(**arguments)
    assert standard.include_provisional_experiment is False

    with pytest.raises(ValidationError, match="OFFLINE_EXPERIMENT"):
        M5PrecedentRetrievalQuery(
            **arguments,
            include_provisional_experiment=True,
        )
    experimental = M5PrecedentRetrievalQuery(
        **arguments,
        run_mode=RunMode.OFFLINE_EXPERIMENT,
        include_provisional_experiment=True,
    )
    assert experimental.include_provisional_experiment is True


def test_query_rejects_channel_confusion_and_absent_embeddings() -> None:
    text = _embedding(M5EmbeddingChannel.TEXT, "query-text")
    base = {
        "run_id": "run-m5",
        "case_id": "case-query",
        "evidence_class": EvidenceClass.PRESENCE,
        "rule_version": "rules-v1",
        "situation_text": "A query situation.",
        "text_embedding_model_manifest_id": MANIFEST_ID,
        "visual_embedding_model_manifest_id": MANIFEST_ID,
        "policy": _policy(),
        "top_k": 4,
    }
    with pytest.raises(ValidationError, match="at least one embedding channel"):
        M5PrecedentRetrievalQuery(**base)
    with pytest.raises(ValidationError, match="VISUAL channel"):
        M5PrecedentRetrievalQuery(**base, visual_embeddings=(text,))
    wrong_request = text.request.model_copy(update={"model_manifest_id": "d" * 64})
    wrong_text = text.model_copy(update={"request": wrong_request})
    with pytest.raises(ValidationError, match="bound model manifest"):
        M5PrecedentRetrievalQuery(**base, text_embedding=wrong_text)


def _conflict_candidate(
    precedent_id: str,
    authority_id: str,
    direction: VerdictDecision,
) -> M5PrecedentConflictCandidateAuthority:
    return M5PrecedentConflictCandidateAuthority(
        precedent_id=precedent_id,
        authority_id=authority_id,
        revision=1,
        source=PrecedentSource.PRESET,
        source_priority=200,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.OPEN_FLAME,
        rule_version="rules-v1",
        decision_direction=direction,
    )


def _conflict_cut(
    candidates: tuple[M5PrecedentConflictCandidateAuthority, ...],
    *,
    sequence: int = 7,
    event_sha256: str = "7" * 64,
) -> M5PrecedentConflictCausalCut:
    return M5PrecedentConflictCausalCut(
        run_id="run-m5",
        manifest_id=MANIFEST_ID,
        config_sha256=CONFIG_SHA256,
        policy_id=_policy().policy_id,
        authority_event_sequence=sequence,
        authority_event_sha256=event_sha256,
        active_head_count=len(candidates),
        active_head_root_sha256=m5_precedent_active_head_root_sha256(
            run_id="run-m5",
            heads=tuple(
                (item.precedent_id, item.authority_id, item.revision) for item in candidates
            ),
        ),
    )


def test_conflict_causal_cut_and_snapshot_bind_stable_complete_active_root() -> None:
    left = create_m5_precedent_authority(
        run_id="run-m5",
        precedent_id="precedent-left",
        situation_text="left",
        decision_direction=VerdictDecision.ESTABLISHED,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.OPEN_FLAME,
        rule_version="rules-v1",
        source_case_id=None,
        created_at=NOW,
        policy=_policy(),
        text_embedding=_embedding(M5EmbeddingChannel.TEXT, "left"),
    )
    right = create_m5_precedent_authority(
        run_id="run-m5",
        precedent_id="precedent-right",
        situation_text="right",
        decision_direction=VerdictDecision.NOT_ESTABLISHED,
        source=PrecedentSource.PRESET,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.OPEN_FLAME,
        rule_version="rules-v1",
        source_case_id=None,
        created_at=NOW,
        policy=_policy(),
        text_embedding=_embedding(M5EmbeddingChannel.TEXT, "right"),
    )
    heads = tuple(
        (item.precedent.precedent_id, item.authority_id, item.revision) for item in (left, right)
    )
    root = m5_precedent_active_head_root_sha256(run_id="run-m5", heads=heads)
    assert root == m5_precedent_active_head_root_sha256(
        run_id="run-m5",
        heads=tuple(reversed(heads)),
    )
    cut = M5PrecedentConflictCausalCut(
        run_id="run-m5",
        manifest_id=MANIFEST_ID,
        config_sha256=CONFIG_SHA256,
        policy_id=_policy().policy_id,
        authority_event_sequence=2,
        authority_event_sha256="7" * 64,
        active_head_count=2,
        active_head_root_sha256=root,
    )
    snapshot = M5PrecedentConflictSnapshot(
        causal_cut=cut,
        authorities=(left, right),
    )
    assert M5PrecedentConflictSnapshot.model_validate(snapshot.model_dump(mode="json")) == snapshot

    with pytest.raises(ValidationError, match="zero authority watermark"):
        M5PrecedentConflictCausalCut.model_validate(
            {
                **cut.model_dump(mode="json", exclude={"cut_id"}),
                "authority_event_sequence": 0,
                "authority_event_sha256": "7" * 64,
            }
        )
    with pytest.raises(ValidationError, match="cannot contain ACTIVE heads"):
        M5PrecedentConflictCausalCut.model_validate(
            {
                **cut.model_dump(mode="json", exclude={"cut_id"}),
                "authority_event_sequence": 0,
                "authority_event_sha256": "0" * 64,
            }
        )
    with pytest.raises(ValidationError, match="ACTIVE head root"):
        M5PrecedentConflictSnapshot(
            causal_cut=M5PrecedentConflictCausalCut.model_validate(
                {
                    **cut.model_dump(mode="json", exclude={"cut_id"}),
                    "active_head_root_sha256": "8" * 64,
                }
            ),
            authorities=(left, right),
        )
    with pytest.raises(ValidationError, match="stably ordered"):
        M5PrecedentConflictSnapshot(
            causal_cut=cut,
            authorities=(right, left),
        )
    with pytest.raises(ValidationError, match="stably ordered"):
        M5PrecedentConflictSnapshot(
            causal_cut=cut,
            authorities=(left, left),
        )
    attacked = cut.model_dump(mode="json")
    attacked["cut_id"] = "9" * 64
    with pytest.raises(ValidationError, match="cut_id"):
        M5PrecedentConflictCausalCut.model_validate(attacked)


def test_conflict_batch_contract_binds_complete_ordered_graph_and_all_results() -> None:
    left = _conflict_candidate(
        "precedent-left",
        "d" * 64,
        VerdictDecision.ESTABLISHED,
    )
    right = _conflict_candidate(
        "precedent-right",
        "e" * 64,
        VerdictDecision.NOT_ESTABLISHED,
    )
    edge = M5PrecedentConflictEdge(
        left_precedent_id=left.precedent_id,
        right_precedent_id=right.precedent_id,
        left_authority_id=left.authority_id,
        right_authority_id=right.authority_id,
        left_priority=left.source_priority,
        right_priority=right.source_priority,
        text_similarity=1.0,
        normalized_text_weight=1.0,
        normalized_visual_weight=0.0,
        similarity=1.0,
        threshold=0.55,
    )
    batch = M5PrecedentConflictBatchAuthority(
        run_id="run-m5",
        config_sha256=CONFIG_SHA256,
        policy_id=_policy().policy_id,
        causal_cut=_conflict_cut((left, right)),
        scan_limit=2,
        candidates=(left, right),
        evaluated_pair_count=1,
        edges=(edge,),
    )
    receipt = M5PrecedentConflictBatchReceipt(
        run_id=batch.run_id,
        config_sha256=batch.config_sha256,
        policy_id=batch.policy_id,
        batch_authority_id=batch.batch_authority_id,
        causal_cut_id=batch.causal_cut.cut_id,
        results=(
            M5PrecedentConflictNodeResult(
                precedent_id=left.precedent_id,
                prior_authority_id=left.authority_id,
                prior_revision=left.revision,
                resulting_authority_id="1" * 64,
                resulting_revision=2,
                status_after=PrecedentStatus.CONFLICT,
                invalidated_by_precedent_id=right.precedent_id,
            ),
            M5PrecedentConflictNodeResult(
                precedent_id=right.precedent_id,
                prior_authority_id=right.authority_id,
                prior_revision=right.revision,
                resulting_authority_id="2" * 64,
                resulting_revision=2,
                status_after=PrecedentStatus.CONFLICT,
                invalidated_by_precedent_id=left.precedent_id,
            ),
        ),
    )

    assert M5PrecedentConflictBatchAuthority.model_validate(batch.model_dump(mode="json")) == batch
    assert (
        M5PrecedentConflictBatchReceipt.model_validate(receipt.model_dump(mode="json")) == receipt
    )

    reversed_batch = batch.model_dump(mode="json")
    reversed_batch.pop("batch_authority_id")
    reversed_batch["candidates"] = list(reversed(reversed_batch["candidates"]))
    with pytest.raises(ValidationError, match="stably ordered"):
        M5PrecedentConflictBatchAuthority.model_validate(reversed_batch)

    forged = batch.model_dump(mode="json")
    forged["batch_authority_id"] = "0" * 64
    with pytest.raises(ValidationError, match="batch_authority_id"):
        M5PrecedentConflictBatchAuthority.model_validate(forged)


def test_conflict_batch_contract_rejects_edge_or_successor_outside_snapshot() -> None:
    left = _conflict_candidate("precedent-left", "d" * 64, VerdictDecision.ESTABLISHED)
    right = _conflict_candidate(
        "precedent-right",
        "e" * 64,
        VerdictDecision.NOT_ESTABLISHED,
    )
    with pytest.raises(ValidationError, match="below the policy threshold"):
        M5PrecedentConflictEdge(
            left_precedent_id=left.precedent_id,
            right_precedent_id=right.precedent_id,
            left_authority_id=left.authority_id,
            right_authority_id=right.authority_id,
            left_priority=200,
            right_priority=200,
            text_similarity=0.5,
            normalized_text_weight=1.0,
            normalized_visual_weight=0.0,
            similarity=0.5,
            threshold=0.55,
        )
    with pytest.raises(ValidationError, match="one successor"):
        M5PrecedentConflictNodeResult(
            precedent_id=left.precedent_id,
            prior_authority_id=left.authority_id,
            prior_revision=1,
            resulting_authority_id=left.authority_id,
            resulting_revision=1,
            status_after=PrecedentStatus.INVALIDATED,
            invalidated_by_precedent_id=right.precedent_id,
        )
