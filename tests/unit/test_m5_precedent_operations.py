from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from labcourt.application.m5_precedent_operations import (
    activate_m5_precedents,
    import_m5_precedent_authorities,
    reconcile_m5_precedent_conflicts,
)
from labcourt.application.m5_precedents import create_m5_precedent_authority
from labcourt.contracts.enums import (
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.m5_precedents import (
    M5AppealWindowSnapshot,
    M5EmbeddingChannel,
    M5EmbeddingRequest,
    M5EmbeddingVector,
    M5PrecedentActivationResult,
    M5PrecedentAuthority,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictCausalCut,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
    m5_precedent_active_head_root_sha256,
)
from labcourt.exceptions import ContractViolation

NOW = datetime(2026, 8, 2, 10, tzinfo=UTC)
RUN_ID = "run-m5-operations"
CONFIG_SHA256 = "c" * 64


def _policy(*, equal: bool = False) -> M5PrecedentPolicy:
    priorities = {
        PrecedentSource.AUTOMATIC: 100,
        PrecedentSource.PRESET: 200,
        PrecedentSource.HUMAN_REVIEW: 300,
        PrecedentSource.APPEAL_OVERTURN: 400,
    }
    if equal:
        priorities = dict.fromkeys(PrecedentSource, 100)
    return M5PrecedentPolicy(
        config_sha256=CONFIG_SHA256,
        text_weight=0.7,
        visual_weight=0.3,
        source_weights=dict.fromkeys(PrecedentSource, 1.0),
        source_priorities=priorities,
        conflict_similarity=0.8,
        automatic_activation_delay_seconds=60,
    )


def _text_embedding(identity: str) -> M5EmbeddingVector:
    payload = identity.encode()
    return M5EmbeddingVector(
        request=M5EmbeddingRequest(
            channel=M5EmbeddingChannel.TEXT,
            input_ref=identity,
            input_sha256=hashlib.sha256(payload).hexdigest(),
            model_manifest_id="a" * 64,
            dimensions=2,
        ),
        values=(1.0, 0.0),
    )


def _authority(
    precedent_id: str,
    *,
    source: PrecedentSource = PrecedentSource.PRESET,
    direction: VerdictDecision = VerdictDecision.ESTABLISHED,
) -> M5PrecedentAuthority:
    return create_m5_precedent_authority(
        run_id=RUN_ID,
        precedent_id=precedent_id,
        situation_text=f"controlled situation {precedent_id}",
        decision_direction=direction,
        source=source,
        evidence_class=EvidenceClass.PRESENCE,
        violation_type=ViolationType.OPEN_FLAME,
        rule_version="rules-v1",
        source_case_id=(f"case-{precedent_id}" if source == PrecedentSource.AUTOMATIC else None),
        created_at=NOW,
        policy=_policy(),
        text_embedding=_text_embedding(precedent_id),
    )


class _Repository:
    def __init__(
        self,
        authorities: tuple[M5PrecedentAuthority, ...] = (),
        *,
        conflict_policy: M5PrecedentPolicy | None = None,
    ) -> None:
        self.authorities = {item.precedent.precedent_id: item for item in authorities}
        self.conflict_policy = conflict_policy or _policy()

    def append_authority(
        self,
        authority: M5PrecedentAuthority,
        expected_revision: int | None,
    ) -> M5PrecedentAuthority:
        del authority, expected_revision
        raise AssertionError("production import must use the atomic batch append")

    def append_authorities(
        self,
        run_id: str,
        authorities: tuple[M5PrecedentAuthority, ...],
    ) -> tuple[M5PrecedentAuthority, ...]:
        assert all(item.run_id == run_id for item in authorities)
        for authority in authorities:
            existing = self.authorities.get(authority.precedent.precedent_id)
            if existing is not None and existing != authority:
                raise AssertionError("identity collision")
        self.authorities.update(
            (authority.precedent.precedent_id, authority) for authority in authorities
        )
        return authorities

    def list_activation_candidates(
        self,
        run_id: str,
        evaluated_at: datetime,
        limit: int,
    ) -> tuple[M5PrecedentAuthority, ...]:
        return tuple(
            item
            for item in self.authorities.values()
            if item.run_id == run_id
            and item.precedent.status == PrecedentStatus.PROVISIONAL
            and item.activation_not_before is not None
            and item.activation_not_before <= evaluated_at
        )[:limit]

    def load_appeal_window_snapshot(
        self,
        run_id: str,
        source_case_id: str,
        observed_through: datetime,
    ) -> M5AppealWindowSnapshot:
        return M5AppealWindowSnapshot(
            run_id=run_id,
            source_case_id=source_case_id,
            source_case_revision=1,
            source_case_document_sha256="d" * 64,
            observed_through=observed_through,
        )

    def commit_activation(
        self,
        result: M5PrecedentActivationResult,
    ) -> M5PrecedentActivationResult:
        self.authorities[result.receipt.precedent_id] = result.authority
        return result

    def load_conflict_snapshot(
        self,
        run_id: str,
        limit: int,
    ) -> M5PrecedentConflictSnapshot:
        candidates = tuple(
            sorted(
                (
                    item
                    for item in self.authorities.values()
                    if item.run_id == run_id and item.precedent.status == PrecedentStatus.ACTIVE
                ),
                key=lambda item: item.precedent.precedent_id,
            )
        )
        if len(candidates) > limit:
            raise ContractViolation("M5 conflict complete snapshot exceeds its scan budget")
        return M5PrecedentConflictSnapshot(
            causal_cut=M5PrecedentConflictCausalCut(
                run_id=run_id,
                manifest_id="f" * 64,
                config_sha256=CONFIG_SHA256,
                policy_id=self.conflict_policy.policy_id,
                authority_event_sequence=1,
                authority_event_sha256="e" * 64,
                active_head_count=len(candidates),
                active_head_root_sha256=m5_precedent_active_head_root_sha256(
                    run_id=run_id,
                    heads=tuple(
                        (
                            item.precedent.precedent_id,
                            item.authority_id,
                            item.revision,
                        )
                        for item in candidates
                    ),
                ),
            ),
            authorities=candidates,
        )

    def get(self, run_id: str, precedent_id: str) -> M5PrecedentAuthority | None:
        authority = self.authorities.get(precedent_id)
        return authority if authority is not None and authority.run_id == run_id else None

    def commit_conflict_batch(
        self,
        resolution: M5PrecedentConflictBatchResolution,
    ) -> M5PrecedentConflictBatchResolution:
        for authority in resolution.resulting_authorities:
            self.authorities[authority.precedent.precedent_id] = authority
        return resolution

    def list_conflicts(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[M5PrecedentAuthority, ...]:
        return tuple(
            sorted(
                (
                    item
                    for item in self.authorities.values()
                    if item.run_id == run_id and item.precedent.status == PrecedentStatus.CONFLICT
                ),
                key=lambda item: item.precedent.precedent_id,
            )
        )[:limit]


def test_import_is_stable_and_rejects_cross_run_or_duplicate_input() -> None:
    repository = _Repository()
    first = _authority("precedent-a")
    second = _authority("precedent-b")

    report = import_m5_precedent_authorities(
        repository=repository,
        run_id=RUN_ID,
        authorities=(second, first),
    )

    assert report.precedent_ids == ("precedent-a", "precedent-b")
    assert report.accepted_count == 2
    with pytest.raises(ContractViolation, match="duplicate"):
        import_m5_precedent_authorities(
            repository=repository,
            run_id=RUN_ID,
            authorities=(first, first),
        )
    with pytest.raises(ContractViolation, match="another run"):
        import_m5_precedent_authorities(
            repository=repository,
            run_id="run-other",
            authorities=(first,),
        )


def test_due_automatic_precedent_activates_against_fresh_appeal_snapshot() -> None:
    automatic = _authority("precedent-auto", source=PrecedentSource.AUTOMATIC)
    repository = _Repository((automatic,))
    evaluated_at = NOW + timedelta(seconds=60)

    report = activate_m5_precedents(
        repository=repository,
        run_id=RUN_ID,
        evaluated_at=evaluated_at,
    )

    assert report.selected_count == 1
    assert report.receipts[0].status_after == PrecedentStatus.ACTIVE
    assert repository.authorities["precedent-auto"].revision == 2


def test_conflict_reconciliation_exactly_applies_peer_conflict_and_lists_heads() -> None:
    left = _authority("precedent-a", direction=VerdictDecision.ESTABLISHED)
    right = _authority("precedent-b", direction=VerdictDecision.NOT_ESTABLISHED)
    unrelated = _authority("precedent-c", direction=VerdictDecision.ESTABLISHED)
    policy = _policy(equal=True)
    repository = _Repository((unrelated, right, left), conflict_policy=policy)

    report = reconcile_m5_precedent_conflicts(
        repository=repository,
        run_id=RUN_ID,
        policy=policy,
    )

    assert report.candidate_count == 3
    assert report.evaluated_pair_count == 2
    assert report.conflict_edge_count == 2
    assert len(report.applied_receipts) == 1
    assert report.current_conflict_precedent_ids == (
        "precedent-a",
        "precedent-b",
        "precedent-c",
    )
    assert repository.authorities["precedent-c"].precedent.status == PrecedentStatus.CONFLICT


def test_conflict_reconciliation_limit_is_a_complete_snapshot_budget() -> None:
    authorities = (
        _authority("precedent-a", direction=VerdictDecision.ESTABLISHED),
        _authority("precedent-b", direction=VerdictDecision.NOT_ESTABLISHED),
        _authority("precedent-c", direction=VerdictDecision.ESTABLISHED),
    )
    policy = _policy(equal=True)
    repository = _Repository(authorities, conflict_policy=policy)

    with pytest.raises(ContractViolation, match="complete snapshot"):
        reconcile_m5_precedent_conflicts(
            repository=repository,
            run_id=RUN_ID,
            policy=policy,
            limit=2,
        )

    assert all(
        authority.precedent.status == PrecedentStatus.ACTIVE
        for authority in repository.authorities.values()
    )
