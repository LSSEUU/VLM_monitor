"""M5 precedent creation, exact retrieval, citation, and lifecycle orchestration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.m5_precedents import (
    MAX_M5_PRECEDENTS,
    M5AppealWindowSnapshot,
    M5EmbeddingVector,
    M5PrecedentActivationOutcome,
    M5PrecedentActivationReceipt,
    M5PrecedentActivationResult,
    M5PrecedentAuthority,
    M5PrecedentCandidateDisposition,
    M5PrecedentCandidateEvaluation,
    M5PrecedentCitationAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictBatchAuthority,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictCandidateAuthority,
    M5PrecedentConflictEdge,
    M5PrecedentConflictNodeResult,
    M5PrecedentConflictOutcome,
    M5PrecedentConflictReceipt,
    M5PrecedentConflictResolution,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5PrecedentRetrievalResult,
    M5PrecedentRevocationOutcome,
    M5PrecedentRevocationReceipt,
    M5PrecedentRevocationResult,
)
from labcourt.contracts.precedents import Precedent
from labcourt.contracts.references import require_reference_token
from labcourt.domain.precedent_conflict_policy import (
    classify_precedent_conflict,
    precedent_directions_are_opposed,
)
from labcourt.domain.precedent_similarity import compare_precedent_embeddings


class M5PrecedentServiceErrorCode(StrEnum):
    AUTHORITY_SCOPE_MISMATCH = "AUTHORITY_SCOPE_MISMATCH"
    CONFIG_AUTHORITY_MISMATCH = "CONFIG_AUTHORITY_MISMATCH"
    DUPLICATE_PRECEDENT = "DUPLICATE_PRECEDENT"
    EMBEDDING_INCOMPATIBLE = "EMBEDDING_INCOMPATIBLE"
    INVALID_CITATION_TIME = "INVALID_CITATION_TIME"
    INVALID_LIFECYCLE_TRANSITION = "INVALID_LIFECYCLE_TRANSITION"
    SNAPSHOT_MISMATCH = "SNAPSHOT_MISMATCH"
    TOO_MANY_PRECEDENTS = "TOO_MANY_PRECEDENTS"
    UNKNOWN_RETRIEVAL_RESULT = "UNKNOWN_RETRIEVAL_RESULT"


class M5PrecedentServiceError(RuntimeError):
    def __init__(self, code: M5PrecedentServiceErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


_SOURCE_PRIORITIES = {
    PrecedentSource.AUTOMATIC: 100,
    PrecedentSource.PRESET: 200,
    PrecedentSource.HUMAN_REVIEW: 300,
    PrecedentSource.APPEAL_OVERTURN: 400,
}


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None or value.utcoffset() != timedelta(0):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.INVALID_LIFECYCLE_TRANSITION)
    return value


def _wire_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def m5_precedent_policy_from_config(config: AppConfig) -> M5PrecedentPolicy:
    """Freeze existing authored M0 config into an additive M5 policy authority."""

    return M5PrecedentPolicy(
        config_sha256=config.config_sha256,
        text_weight=float(config.precedents.text_weight),
        visual_weight=float(config.precedents.visual_weight),
        source_weights={
            source: float(config.precedents.source_weights[source]) for source in PrecedentSource
        },
        source_priorities=_SOURCE_PRIORITIES,
        conflict_similarity=float(config.precedents.conflict_similarity),
        automatic_activation_delay_seconds=(
            config.precedents.automatic_activation_delay_days * 86_400
        ),
    )


def create_m5_precedent_authority(
    *,
    run_id: str,
    precedent_id: str,
    situation_text: str,
    decision_direction: VerdictDecision,
    source: PrecedentSource,
    evidence_class: EvidenceClass,
    violation_type: ViolationType,
    rule_version: str,
    source_case_id: str | None,
    created_at: datetime,
    policy: M5PrecedentPolicy,
    text_embedding: M5EmbeddingVector | None = None,
    visual_embeddings: tuple[M5EmbeddingVector, ...] = (),
) -> M5PrecedentAuthority:
    """Create an active authored precedent or a cooling automatic precedent."""

    _require_utc(created_at)
    require_reference_token(run_id, "M5 run_id")
    require_reference_token(precedent_id, "M5 precedent_id")
    if source_case_id is not None:
        require_reference_token(source_case_id, "M5 source_case_id")
    if source == PrecedentSource.AUTOMATIC and source_case_id is None:
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.INVALID_LIFECYCLE_TRANSITION)

    visuals = tuple(sorted(visual_embeddings, key=lambda item: item.embedding_id))
    automatic = source == PrecedentSource.AUTOMATIC
    status = PrecedentStatus.PROVISIONAL if automatic else PrecedentStatus.ACTIVE
    activated_at = None if automatic else created_at
    activation_not_before = (
        created_at + timedelta(seconds=policy.automatic_activation_delay_seconds)
        if automatic
        else None
    )
    precedent = Precedent(
        precedent_id=precedent_id,
        situation_text=situation_text,
        text_embedding_ref=(text_embedding.embedding_id if text_embedding is not None else None),
        visual_embedding_refs=tuple(item.embedding_id for item in visuals),
        decision_direction=decision_direction,
        source=source,
        status=status,
        evidence_class=evidence_class,
        violation_type=violation_type,
        rule_version=rule_version,
        source_case_id=source_case_id,
        activation_at=_wire_time(activated_at) if activated_at is not None else None,
        invalidated_by=None,
        citation_count=0,
    )
    return M5PrecedentAuthority(
        run_id=run_id,
        config_sha256=policy.config_sha256,
        revision=1,
        precedent=precedent,
        created_at=created_at,
        activation_not_before=activation_not_before,
        activated_at=activated_at,
        text_embedding=text_embedding,
        visual_embeddings=visuals,
    )


class ExactM5PrecedentRetrievalService:
    """Exact, bounded, stable retrieval for the first-stage SQLite-sized corpus."""

    def retrieve(
        self,
        query: M5PrecedentRetrievalQuery,
        candidates: tuple[M5PrecedentAuthority, ...],
    ) -> M5PrecedentRetrievalResult:
        if len(candidates) > MAX_M5_PRECEDENTS:
            raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.TOO_MANY_PRECEDENTS)
        identifiers = tuple(item.precedent.precedent_id for item in candidates)
        if len(identifiers) != len(set(identifiers)):
            raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.DUPLICATE_PRECEDENT)
        if any(item.run_id != query.run_id for item in candidates):
            raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.AUTHORITY_SCOPE_MISMATCH)
        if any(item.config_sha256 != query.policy.config_sha256 for item in candidates):
            raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.CONFIG_AUTHORITY_MISMATCH)

        visible_statuses = {PrecedentStatus.ACTIVE}
        if query.include_provisional_experiment:
            visible_statuses.add(PrecedentStatus.PROVISIONAL)
        evaluations: list[M5PrecedentCandidateEvaluation] = []
        for authority in sorted(
            candidates,
            key=lambda item: item.precedent.precedent_id,
        ):
            precedent = authority.precedent
            if (
                precedent.evidence_class != query.evidence_class
                or precedent.rule_version != query.rule_version
            ):
                evaluations.append(
                    M5PrecedentCandidateEvaluation(
                        authority=authority,
                        disposition=M5PrecedentCandidateDisposition.SCOPE_EXCLUDED,
                    )
                )
                continue
            if precedent.status not in visible_statuses:
                evaluations.append(
                    M5PrecedentCandidateEvaluation(
                        authority=authority,
                        disposition=M5PrecedentCandidateDisposition.STATUS_EXCLUDED,
                    )
                )
                continue
            try:
                fused = compare_precedent_embeddings(
                    left_text=query.text_embedding,
                    left_visual=query.visual_embeddings,
                    right_text=authority.text_embedding,
                    right_visual=authority.visual_embeddings,
                    text_weight=float(query.policy.text_weight),
                    visual_weight=float(query.policy.visual_weight),
                )
            except ValueError as error:
                raise M5PrecedentServiceError(
                    M5PrecedentServiceErrorCode.EMBEDDING_INCOMPATIBLE
                ) from error
            if fused is None:
                evaluations.append(
                    M5PrecedentCandidateEvaluation(
                        authority=authority,
                        disposition=M5PrecedentCandidateDisposition.UNSCORABLE,
                    )
                )
                continue
            source_weight = float(query.policy.source_weights[precedent.source])
            evaluations.append(
                M5PrecedentCandidateEvaluation(
                    authority=authority,
                    disposition=M5PrecedentCandidateDisposition.SCORED,
                    text_similarity=fused.text_similarity,
                    visual_similarity=fused.visual_similarity,
                    normalized_text_weight=fused.normalized_text_weight,
                    normalized_visual_weight=fused.normalized_visual_weight,
                    base_similarity=fused.base_similarity,
                    source_weight=source_weight,
                    score=fused.base_similarity * source_weight,
                )
            )
        scored = tuple(
            item.as_scored_precedent()
            for item in evaluations
            if item.disposition == M5PrecedentCandidateDisposition.SCORED
        )
        ranked = tuple(
            sorted(
                scored,
                key=lambda item: (-item.score, item.authority.precedent.precedent_id),
            )[: query.top_k]
        )
        return M5PrecedentRetrievalResult(
            query=query,
            candidate_evaluations=tuple(evaluations),
            scored_precedents=ranked,
        )


def record_m5_precedent_citation(
    *,
    result: M5PrecedentRetrievalResult,
    precedent_id: str,
    cited_at: datetime,
) -> M5PrecedentCitationCommit:
    _require_utc(cited_at)
    selected = next(
        (
            item
            for item in result.scored_precedents
            if item.authority.precedent.precedent_id == precedent_id
        ),
        None,
    )
    if selected is None:
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.UNKNOWN_RETRIEVAL_RESULT)
    historical = selected.authority
    if cited_at < historical.created_at or (
        historical.precedent.status == PrecedentStatus.ACTIVE
        and (historical.activated_at is None or cited_at < historical.activated_at)
    ):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.INVALID_CITATION_TIME)
    citation = M5PrecedentCitationAuthority(
        run_id=result.query.run_id,
        case_id=result.query.case_id,
        precedent_id=precedent_id,
        precedent_authority_id=historical.authority_id,
        precedent_revision=historical.revision,
        query_id=result.query.query_id,
        score=selected.score,
        cited_at=cited_at,
    )
    return M5PrecedentCitationCommit(
        retrieval_result=result,
        citation=citation,
    )


def evaluate_m5_automatic_activation(
    *,
    authority: M5PrecedentAuthority,
    appeal_snapshot: M5AppealWindowSnapshot,
    evaluated_at: datetime,
) -> M5PrecedentActivationResult:
    _require_utc(evaluated_at)
    precedent = authority.precedent
    if authority.run_id != appeal_snapshot.run_id:
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.SNAPSHOT_MISMATCH)

    if precedent.source != PrecedentSource.AUTOMATIC:
        outcome = M5PrecedentActivationOutcome.NOT_AUTOMATIC
        resulting = authority
    elif precedent.status != PrecedentStatus.PROVISIONAL:
        outcome = M5PrecedentActivationOutcome.NOT_PROVISIONAL
        resulting = authority
    else:
        if (
            precedent.source_case_id != appeal_snapshot.source_case_id
            or appeal_snapshot.observed_through < evaluated_at
        ):
            raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.SNAPSHOT_MISMATCH)
        assert authority.activation_not_before is not None
        if appeal_snapshot.appeal_ids:
            outcome = M5PrecedentActivationOutcome.APPEAL_PRESENT
            resulting = authority
        elif evaluated_at < authority.activation_not_before:
            outcome = M5PrecedentActivationOutcome.TOO_EARLY
            resulting = authority
        else:
            outcome = M5PrecedentActivationOutcome.ACTIVATED
            activated = precedent.model_copy(
                update={
                    "status": PrecedentStatus.ACTIVE,
                    "activation_at": _wire_time(evaluated_at),
                }
            )
            resulting = authority.model_copy(
                update={
                    "revision": authority.revision + 1,
                    "precedent": activated,
                    "activated_at": evaluated_at,
                }
            )

    receipt = M5PrecedentActivationReceipt(
        run_id=authority.run_id,
        precedent_id=precedent.precedent_id,
        prior_authority_id=authority.authority_id,
        prior_revision=authority.revision,
        appeal_snapshot_id=appeal_snapshot.snapshot_id,
        evaluated_at=evaluated_at,
        outcome=outcome,
        resulting_authority_id=resulting.authority_id,
        resulting_revision=resulting.revision,
        status_before=precedent.status,
        status_after=resulting.precedent.status,
    )
    return M5PrecedentActivationResult(
        appeal_snapshot=appeal_snapshot,
        receipt=receipt,
        authority=resulting,
    )


def _with_terminal_status(
    authority: M5PrecedentAuthority,
    *,
    status: PrecedentStatus,
    invalidated_by: str,
) -> M5PrecedentAuthority:
    updated = authority.precedent.model_copy(
        update={
            "status": status,
            "invalidated_by": invalidated_by,
        }
    )
    return authority.model_copy(
        update={
            "revision": authority.revision + 1,
            "precedent": updated,
        }
    )


def resolve_m5_precedent_conflict(
    *,
    existing: M5PrecedentAuthority,
    new: M5PrecedentAuthority,
    policy: M5PrecedentPolicy,
) -> M5PrecedentConflictResolution:
    if existing.run_id != new.run_id:
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.AUTHORITY_SCOPE_MISMATCH)
    if existing.config_sha256 != policy.config_sha256 or new.config_sha256 != policy.config_sha256:
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.CONFIG_AUTHORITY_MISMATCH)
    if existing.precedent.precedent_id == new.precedent.precedent_id:
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.DUPLICATE_PRECEDENT)
    if (
        existing.precedent.status != PrecedentStatus.ACTIVE
        or new.precedent.status != PrecedentStatus.ACTIVE
    ):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.INVALID_LIFECYCLE_TRANSITION)

    first = existing.precedent
    second = new.precedent
    same_type = (
        first.evidence_class == second.evidence_class
        and first.violation_type == second.violation_type
        and first.rule_version == second.rule_version
    )
    fused = None
    if same_type and precedent_directions_are_opposed(
        first.decision_direction, second.decision_direction
    ):
        try:
            fused = compare_precedent_embeddings(
                left_text=existing.text_embedding,
                left_visual=existing.visual_embeddings,
                right_text=new.text_embedding,
                right_visual=new.visual_embeddings,
                text_weight=float(policy.text_weight),
                visual_weight=float(policy.visual_weight),
            )
        except ValueError as error:
            raise M5PrecedentServiceError(
                M5PrecedentServiceErrorCode.EMBEDDING_INCOMPATIBLE
            ) from error

    existing_priority = policy.source_priorities[first.source]
    new_priority = policy.source_priorities[second.source]
    outcome = classify_precedent_conflict(
        same_authority_scope=same_type,
        existing_direction=first.decision_direction,
        new_direction=second.decision_direction,
        similarity=fused.base_similarity if fused is not None else None,
        threshold=policy.conflict_similarity,
        existing_priority=existing_priority,
        new_priority=new_priority,
    )
    if outcome == M5PrecedentConflictOutcome.NO_CONFLICT:
        existing_result = existing
        new_result = new
    elif outcome == M5PrecedentConflictOutcome.NEW_INVALIDATED:
        existing_result = existing
        new_result = _with_terminal_status(
            new,
            status=PrecedentStatus.INVALIDATED,
            invalidated_by=first.precedent_id,
        )
    elif outcome == M5PrecedentConflictOutcome.EXISTING_INVALIDATED:
        existing_result = _with_terminal_status(
            existing,
            status=PrecedentStatus.INVALIDATED,
            invalidated_by=second.precedent_id,
        )
        new_result = new
    else:
        existing_result = _with_terminal_status(
            existing,
            status=PrecedentStatus.CONFLICT,
            invalidated_by=second.precedent_id,
        )
        new_result = _with_terminal_status(
            new,
            status=PrecedentStatus.CONFLICT,
            invalidated_by=first.precedent_id,
        )

    receipt = M5PrecedentConflictReceipt(
        run_id=existing.run_id,
        policy_id=policy.policy_id,
        existing_precedent_id=first.precedent_id,
        new_precedent_id=second.precedent_id,
        existing_prior_authority_id=existing.authority_id,
        new_prior_authority_id=new.authority_id,
        existing_prior_revision=existing.revision,
        new_prior_revision=new.revision,
        text_similarity=fused.text_similarity if fused is not None else None,
        visual_similarity=fused.visual_similarity if fused is not None else None,
        normalized_text_weight=(fused.normalized_text_weight if fused is not None else 0.0),
        normalized_visual_weight=(fused.normalized_visual_weight if fused is not None else 0.0),
        similarity=fused.base_similarity if fused is not None else None,
        threshold=policy.conflict_similarity,
        existing_priority=existing_priority,
        new_priority=new_priority,
        outcome=outcome,
        existing_resulting_authority_id=existing_result.authority_id,
        new_resulting_authority_id=new_result.authority_id,
        existing_resulting_revision=existing_result.revision,
        new_resulting_revision=new_result.revision,
        existing_status_after=existing_result.precedent.status,
        new_status_after=new_result.precedent.status,
    )
    return M5PrecedentConflictResolution(
        policy=policy,
        receipt=receipt,
        existing_authority=existing_result,
        new_authority=new_result,
    )


def resolve_m5_precedent_conflict_batch(
    *,
    snapshot: M5PrecedentConflictSnapshot,
    policy: M5PrecedentPolicy,
    scan_limit: int,
) -> M5PrecedentConflictBatchResolution:
    """Compute a complete conflict graph before selecting any node successor.

    A node is invalidated when any higher-priority opposite neighbour exists.  If
    no such neighbour exists but an equal-priority edge does, the node enters
    ``CONFLICT``.  Lower-priority neighbours never suppress those outcomes.  The
    chosen ``invalidated_by`` is the highest-priority neighbour, then the lowest
    precedent ID, so input order and ID placement cannot change the graph result.
    """

    if not isinstance(snapshot, M5PrecedentConflictSnapshot):
        raise TypeError("snapshot must be an M5PrecedentConflictSnapshot")
    cut = snapshot.causal_cut
    run_id = cut.run_id
    if cut.config_sha256 != policy.config_sha256 or cut.policy_id != policy.policy_id:
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.CONFIG_AUTHORITY_MISMATCH)
    if (
        isinstance(scan_limit, bool)
        or not isinstance(scan_limit, int)
        or not 1 <= scan_limit <= MAX_M5_PRECEDENTS
    ):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.TOO_MANY_PRECEDENTS)
    ordered = snapshot.authorities
    if len(ordered) > scan_limit:
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.TOO_MANY_PRECEDENTS)
    precedent_ids = tuple(item.precedent.precedent_id for item in ordered)
    if len(precedent_ids) != len(set(precedent_ids)):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.DUPLICATE_PRECEDENT)
    if any(item.run_id != run_id for item in ordered):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.AUTHORITY_SCOPE_MISMATCH)
    if any(item.config_sha256 != policy.config_sha256 for item in ordered):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.CONFIG_AUTHORITY_MISMATCH)
    if any(item.precedent.status != PrecedentStatus.ACTIVE for item in ordered):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.INVALID_LIFECYCLE_TRANSITION)

    candidates = tuple(
        M5PrecedentConflictCandidateAuthority(
            precedent_id=item.precedent.precedent_id,
            authority_id=item.authority_id,
            revision=item.revision,
            source=item.precedent.source,
            source_priority=policy.source_priorities[item.precedent.source],
            evidence_class=item.precedent.evidence_class,
            violation_type=item.precedent.violation_type,
            rule_version=item.precedent.rule_version,
            decision_direction=item.precedent.decision_direction,
        )
        for item in ordered
    )
    adjacency: dict[str, list[tuple[int, str]]] = {
        precedent_id: [] for precedent_id in precedent_ids
    }
    edges: list[M5PrecedentConflictEdge] = []
    evaluated_pair_count = 0
    for index, left in enumerate(ordered):
        first = left.precedent
        for right in ordered[index + 1 :]:
            second = right.precedent
            if (
                first.evidence_class != second.evidence_class
                or first.violation_type != second.violation_type
                or first.rule_version != second.rule_version
                or not precedent_directions_are_opposed(
                    first.decision_direction,
                    second.decision_direction,
                )
            ):
                continue
            evaluated_pair_count += 1
            try:
                fused = compare_precedent_embeddings(
                    left_text=left.text_embedding,
                    left_visual=left.visual_embeddings,
                    right_text=right.text_embedding,
                    right_visual=right.visual_embeddings,
                    text_weight=float(policy.text_weight),
                    visual_weight=float(policy.visual_weight),
                )
            except ValueError as error:
                raise M5PrecedentServiceError(
                    M5PrecedentServiceErrorCode.EMBEDDING_INCOMPATIBLE
                ) from error
            if fused is None or fused.base_similarity < policy.conflict_similarity:
                continue
            left_priority = policy.source_priorities[first.source]
            right_priority = policy.source_priorities[second.source]
            edge = M5PrecedentConflictEdge(
                left_precedent_id=first.precedent_id,
                right_precedent_id=second.precedent_id,
                left_authority_id=left.authority_id,
                right_authority_id=right.authority_id,
                left_priority=left_priority,
                right_priority=right_priority,
                text_similarity=fused.text_similarity,
                visual_similarity=fused.visual_similarity,
                normalized_text_weight=fused.normalized_text_weight,
                normalized_visual_weight=fused.normalized_visual_weight,
                similarity=fused.base_similarity,
                threshold=policy.conflict_similarity,
            )
            edges.append(edge)
            adjacency[first.precedent_id].append((right_priority, second.precedent_id))
            adjacency[second.precedent_id].append((left_priority, first.precedent_id))

    batch_authority = M5PrecedentConflictBatchAuthority(
        run_id=run_id,
        config_sha256=policy.config_sha256,
        policy_id=policy.policy_id,
        causal_cut=cut,
        scan_limit=scan_limit,
        candidates=candidates,
        evaluated_pair_count=evaluated_pair_count,
        edges=tuple(edges),
    )
    resulting: list[M5PrecedentAuthority] = []
    node_results: list[M5PrecedentConflictNodeResult] = []
    for prior, candidate in zip(ordered, candidates, strict=True):
        neighbours = adjacency[candidate.precedent_id]
        higher = tuple(
            sorted(
                (
                    (priority, precedent_id)
                    for priority, precedent_id in neighbours
                    if priority > candidate.source_priority
                ),
                key=lambda item: (-item[0], item[1]),
            )
        )
        peers = tuple(
            sorted(
                precedent_id
                for priority, precedent_id in neighbours
                if priority == candidate.source_priority
            )
        )
        if higher:
            invalidated_by = higher[0][1]
            result = _with_terminal_status(
                prior,
                status=PrecedentStatus.INVALIDATED,
                invalidated_by=invalidated_by,
            )
        elif peers:
            invalidated_by = peers[0]
            result = _with_terminal_status(
                prior,
                status=PrecedentStatus.CONFLICT,
                invalidated_by=invalidated_by,
            )
        else:
            invalidated_by = None
            result = prior
        resulting.append(result)
        node_results.append(
            M5PrecedentConflictNodeResult(
                precedent_id=candidate.precedent_id,
                prior_authority_id=candidate.authority_id,
                prior_revision=candidate.revision,
                resulting_authority_id=result.authority_id,
                resulting_revision=result.revision,
                status_after=result.precedent.status,
                invalidated_by_precedent_id=invalidated_by,
            )
        )
    receipt = M5PrecedentConflictBatchReceipt(
        run_id=run_id,
        config_sha256=policy.config_sha256,
        policy_id=policy.policy_id,
        batch_authority_id=batch_authority.batch_authority_id,
        causal_cut_id=cut.cut_id,
        results=tuple(node_results),
    )
    return M5PrecedentConflictBatchResolution(
        policy=policy,
        batch_authority=batch_authority,
        receipt=receipt,
        prior_authorities=ordered,
        resulting_authorities=tuple(resulting),
    )


def revoke_m5_precedent(
    *,
    authority: M5PrecedentAuthority,
    citation_snapshot: M5PrecedentCitationSnapshot,
    revoked_by_ref: str,
    revoked_at: datetime,
) -> M5PrecedentRevocationResult:
    _require_utc(revoked_at)
    require_reference_token(revoked_by_ref, "M5 revocation authority")
    if (
        citation_snapshot.run_id != authority.run_id
        or citation_snapshot.precedent_id != authority.precedent.precedent_id
        or citation_snapshot.captured_at < revoked_at
    ):
        raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.SNAPSHOT_MISMATCH)

    if authority.precedent.status == PrecedentStatus.REVOKED:
        if authority.precedent.invalidated_by != revoked_by_ref:
            raise M5PrecedentServiceError(M5PrecedentServiceErrorCode.INVALID_LIFECYCLE_TRANSITION)
        outcome = M5PrecedentRevocationOutcome.ALREADY_REVOKED
        resulting = authority
    else:
        outcome = M5PrecedentRevocationOutcome.REVOKED
        resulting = _with_terminal_status(
            authority,
            status=PrecedentStatus.REVOKED,
            invalidated_by=revoked_by_ref,
        )

    historical_case_ids = tuple(sorted({item.case_id for item in citation_snapshot.citations}))
    historical_citation_ids = tuple(
        sorted(item.citation_id for item in citation_snapshot.citations)
    )
    receipt = M5PrecedentRevocationReceipt(
        run_id=authority.run_id,
        precedent_id=authority.precedent.precedent_id,
        prior_authority_id=authority.authority_id,
        prior_revision=authority.revision,
        citation_snapshot_id=citation_snapshot.snapshot_id,
        revoked_by_ref=revoked_by_ref,
        revoked_at=revoked_at,
        outcome=outcome,
        resulting_authority_id=resulting.authority_id,
        resulting_revision=resulting.revision,
        historical_case_ids=historical_case_ids,
        historical_citation_ids=historical_citation_ids,
        old_cases_rewritten=False,
    )
    return M5PrecedentRevocationResult(
        citation_snapshot=citation_snapshot,
        receipt=receipt,
        authority=resulting,
    )


__all__ = [
    "ExactM5PrecedentRetrievalService",
    "M5PrecedentServiceError",
    "M5PrecedentServiceErrorCode",
    "create_m5_precedent_authority",
    "evaluate_m5_automatic_activation",
    "m5_precedent_policy_from_config",
    "record_m5_precedent_citation",
    "resolve_m5_precedent_conflict",
    "resolve_m5_precedent_conflict_batch",
    "revoke_m5_precedent",
]
