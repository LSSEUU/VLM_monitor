from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from labcourt.application.retention import MAX_RETENTION_ITEMS, RetentionCoordinator
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    PurgeDisposition,
    PurgeReasonCode,
    PurgeRecoveryKind,
    RetentionHoldKind,
)
from labcourt.contracts.storage import ArtifactRef, PurgeItemResult, RetentionHold
from labcourt.exceptions import (
    ArtifactConflict,
    ArtifactIntegrityViolation,
    BudgetExceeded,
    ConcurrentModification,
    ContractViolation,
    PathBoundaryViolation,
    ProviderUnavailable,
)
from labcourt.ports.retention import PurgeLease, PurgeRecoveryCandidate

RUN_ID = "run-01"
POLICY_VERSION = "retention-v1"
CUTOFF = datetime(2026, 7, 27, 12, 0, 0, tzinfo=UTC)
MEDIA_A = "a" * 64
MEDIA_B = "b" * 64
MEDIA_C = "c" * 64


def _crop_ref(value: str) -> ArtifactRef:
    return ArtifactRef(kind=ArtifactKind.CROP, artifact_id=value)


def _lease(
    media_sha256: str = MEDIA_A,
    *,
    intent_audit_sequence: int = 10,
) -> PurgeLease:
    return PurgeLease(
        run_id=RUN_ID,
        media_sha256=media_sha256,
        source_relative_path=f"{RUN_ID}/frames/{media_sha256}.png",
        trash_relative_path=f".trash/{RUN_ID}/{media_sha256}.png",
        crop_refs=(_crop_ref(media_sha256),),
        intent_audit_sequence=intent_audit_sequence,
    )


def _retained(
    media_sha256: str,
    reason_code: PurgeReasonCode,
) -> PurgeItemResult:
    return PurgeItemResult(
        run_id=RUN_ID,
        media_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=media_sha256),
        crop_refs=(_crop_ref(media_sha256),),
        disposition=PurgeDisposition.RETAINED,
        reason_code=reason_code,
        previous_availability=MediaAvailability.AVAILABLE,
        current_availability=MediaAvailability.AVAILABLE,
        hold_kinds=(
            (RetentionHoldKind.APPEAL,)
            if reason_code == PurgeReasonCode.ACTIVE_RETENTION_HOLD
            else ()
        ),
    )


def _completed(lease: PurgeLease, *, recovered: bool) -> PurgeItemResult:
    return PurgeItemResult(
        run_id=lease.run_id,
        media_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=lease.media_sha256),
        crop_refs=lease.crop_refs,
        disposition=PurgeDisposition.PURGED,
        reason_code=(
            PurgeReasonCode.RECOVERED_PURGE_COMPLETED
            if recovered
            else PurgeReasonCode.EXPIRED_AND_PURGED
        ),
        previous_availability=(
            MediaAvailability.PURGING if recovered else MediaAvailability.AVAILABLE
        ),
        current_availability=MediaAvailability.PURGED_BY_RETENTION,
        audit_sequences=(lease.intent_audit_sequence, lease.intent_audit_sequence + 1),
    )


def _recovery_candidate(
    lease: PurgeLease,
    kind: PurgeRecoveryKind,
) -> PurgeRecoveryCandidate:
    return PurgeRecoveryCandidate(
        kind=kind,
        lease=lease,
        completion_audit_sequence=(
            lease.intent_audit_sequence + 1 if kind == PurgeRecoveryKind.TRASH_CLEANUP else None
        ),
    )


def _already_purged(lease: PurgeLease) -> PurgeItemResult:
    return PurgeItemResult(
        run_id=lease.run_id,
        media_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=lease.media_sha256),
        crop_refs=lease.crop_refs,
        disposition=PurgeDisposition.RETAINED,
        reason_code=PurgeReasonCode.ALREADY_PURGED,
        previous_availability=MediaAvailability.PURGED_BY_RETENTION,
        current_availability=MediaAvailability.PURGED_BY_RETENTION,
        audit_sequences=(lease.intent_audit_sequence, lease.intent_audit_sequence + 1),
    )


def _cleanup_failed(lease: PurgeLease) -> PurgeItemResult:
    return PurgeItemResult(
        run_id=lease.run_id,
        media_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=lease.media_sha256),
        crop_refs=lease.crop_refs,
        disposition=PurgeDisposition.RECOVERY_REQUIRED,
        reason_code=PurgeReasonCode.TRASH_CLEANUP_FAILED,
        previous_availability=MediaAvailability.PURGED_BY_RETENTION,
        current_availability=MediaAvailability.PURGED_BY_RETENTION,
        audit_sequences=(lease.intent_audit_sequence, lease.intent_audit_sequence + 1),
    )


class _FakeRepository:
    def __init__(self, timeline: list[tuple[object, ...]]) -> None:
        self.timeline = timeline
        self.expirable: tuple[str, ...] = ()
        self.recovery_claims: list[PurgeRecoveryCandidate | None] = []
        self.decisions: dict[str, PurgeLease | PurgeItemResult] = {}
        self.leases: dict[str, PurgeLease] = {}
        self.complete_error: Exception | None = None
        self.mark_error: Exception | None = None

    def list_expirable_media(
        self,
        run_id: str,
        expires_before: datetime,
        limit: int,
    ) -> tuple[str, ...]:
        self.timeline.append(("list-expirable", run_id, expires_before, limit))
        return self.expirable

    def begin_media_purge(
        self,
        run_id: str,
        media_sha256: str,
        expires_before: datetime,
        policy_version: str,
    ) -> PurgeLease | PurgeItemResult:
        self.timeline.append(("begin", run_id, media_sha256, expires_before, policy_version))
        decision = self.decisions[media_sha256]
        if isinstance(decision, PurgeLease):
            self.leases[media_sha256] = decision
        return decision

    def complete_media_purge(
        self,
        run_id: str,
        media_sha256: str,
        intent_audit_sequence: int,
        recovered: bool,
    ) -> PurgeItemResult:
        self.timeline.append(("complete", run_id, media_sha256, intent_audit_sequence, recovered))
        if self.complete_error is not None:
            raise self.complete_error
        lease = self.leases[media_sha256]
        return _completed(lease, recovered=recovered)

    def claim_next_recovery(self, run_id: str) -> PurgeRecoveryCandidate | None:
        self.timeline.append(("claim-recovery", run_id))
        if not self.recovery_claims:
            return None
        candidate = self.recovery_claims.pop(0)
        if candidate is not None:
            self.leases[candidate.lease.media_sha256] = candidate.lease
        return candidate

    def mark_trash_cleaned(
        self,
        run_id: str,
        media_sha256: str,
        intent_audit_sequence: int,
    ) -> None:
        self.timeline.append(("mark-clean", run_id, media_sha256, intent_audit_sequence))
        if self.mark_error is not None:
            raise self.mark_error

    def create_retention_hold(self, hold: RetentionHold) -> int:
        self.timeline.append(("create-hold", hold.hold_id))
        return 1

    def release_retention_hold(self, run_id: str, hold_id: str) -> int:
        self.timeline.append(("release-hold", run_id, hold_id))
        return 1


class _FakeFileOps:
    def __init__(self, timeline: list[tuple[object, ...]]) -> None:
        self.timeline = timeline
        self.stage_errors: dict[str, Exception] = {}
        self.destroy_errors: dict[str, Exception] = {}
        self.destroyed: set[str] = set()

    def stage_for_purge(self, lease: PurgeLease) -> None:
        self.timeline.append(("stage", lease.media_sha256))
        error = self.stage_errors.get(lease.media_sha256)
        if error is not None:
            raise error

    def destroy_purged(self, lease: PurgeLease) -> None:
        self.timeline.append(("destroy", lease.media_sha256))
        error = self.destroy_errors.get(lease.media_sha256)
        if error is not None:
            raise error
        self.destroyed.add(lease.media_sha256)


def _coordinator(
    repository: _FakeRepository,
    file_ops: _FakeFileOps,
    *,
    max_items: int = 100,
) -> RetentionCoordinator:
    return RetentionCoordinator(
        repository=repository,
        file_ops=file_ops,
        max_items=max_items,
    )


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        (
            "source_relative_path",
            f".trash/{RUN_ID}/{MEDIA_A}.png",
            "canonical run media locator",
        ),
        (
            "source_relative_path",
            f"other-run/frames/{MEDIA_A}.png",
            "canonical run media locator",
        ),
        (
            "trash_relative_path",
            f".trash/other-run/{MEDIA_A}.png",
            "canonical run trash locator",
        ),
        (
            "trash_relative_path",
            f".trash/{RUN_ID}/{MEDIA_B}.png",
            "canonical run trash locator",
        ),
        ("source_relative_path", "../private.png", "safe workspace-relative"),
    ],
)
def test_purge_lease_rejects_noncanonical_or_unsafe_paths(
    field_name: str,
    value: str,
    message: str,
) -> None:
    payload = _lease().model_dump(mode="python")
    payload[field_name] = value

    with pytest.raises(ValidationError, match=message):
        PurgeLease.model_validate(payload)


def test_purge_lease_requires_nonempty_unique_stably_ordered_crop_refs() -> None:
    payload = _lease().model_dump(mode="python")
    with pytest.raises(ValidationError, match="at least 1"):
        PurgeLease.model_validate({**payload, "crop_refs": ()})
    with pytest.raises(ValidationError, match="unique"):
        PurgeLease.model_validate(
            {**payload, "crop_refs": (_crop_ref(MEDIA_A), _crop_ref(MEDIA_A))}
        )
    with pytest.raises(ValidationError, match="stable order"):
        PurgeLease.model_validate(
            {**payload, "crop_refs": (_crop_ref(MEDIA_B), _crop_ref(MEDIA_A))}
        )


def test_recovery_candidate_enforces_phase_specific_completion_audit() -> None:
    lease = _lease()
    assert (
        _recovery_candidate(
            lease,
            PurgeRecoveryKind.INCOMPLETE_PURGE,
        ).completion_audit_sequence
        is None
    )
    assert (
        _recovery_candidate(
            lease,
            PurgeRecoveryKind.TRASH_CLEANUP,
        ).completion_audit_sequence
        == lease.intent_audit_sequence + 1
    )

    with pytest.raises(ValidationError, match="cannot carry"):
        PurgeRecoveryCandidate(
            kind=PurgeRecoveryKind.INCOMPLETE_PURGE,
            lease=lease,
            completion_audit_sequence=lease.intent_audit_sequence + 1,
        )
    with pytest.raises(ValidationError, match="later completion audit"):
        PurgeRecoveryCandidate(
            kind=PurgeRecoveryKind.TRASH_CLEANUP,
            lease=lease,
            completion_audit_sequence=lease.intent_audit_sequence,
        )


def test_hold_and_unexpired_results_pass_through_without_file_operations() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    held = _retained(MEDIA_A, PurgeReasonCode.ACTIVE_RETENTION_HOLD)
    unexpired = _retained(MEDIA_B, PurgeReasonCode.RETENTION_NOT_EXPIRED)
    repository.expirable = (MEDIA_A, MEDIA_B)
    repository.decisions = {MEDIA_A: held, MEDIA_B: unexpired}

    results = _coordinator(repository, file_ops, max_items=2).purge_expired(
        RUN_ID,
        expires_before=CUTOFF,
        policy_version=POLICY_VERSION,
    )

    assert results == (held, unexpired)
    assert [entry[0] for entry in timeline] == ["list-expirable", "begin", "begin"]
    assert timeline[0] == ("list-expirable", RUN_ID, CUTOFF, 2)


def test_repository_cannot_claim_purge_completion_before_file_operations() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    repository.expirable = (MEDIA_A,)
    repository.decisions = {MEDIA_A: _completed(lease, recovered=False)}

    with pytest.raises(ContractViolation, match="pre-file purge decision"):
        _coordinator(repository, file_ops).purge_expired(
            RUN_ID,
            expires_before=CUTOFF,
            policy_version=POLICY_VERSION,
        )

    assert [entry[0] for entry in timeline] == ["list-expirable", "begin"]


def test_purge_happy_path_orders_intent_move_completion_delete_and_ack() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    repository.expirable = (MEDIA_A,)
    repository.decisions = {MEDIA_A: lease}

    results = _coordinator(repository, file_ops).purge_expired(
        RUN_ID,
        expires_before=CUTOFF,
        policy_version=POLICY_VERSION,
    )

    assert results == (_completed(lease, recovered=False),)
    assert [entry[0] for entry in timeline] == [
        "list-expirable",
        "begin",
        "stage",
        "complete",
        "destroy",
        "mark-clean",
    ]


@pytest.mark.parametrize(
    ("error", "reason_code"),
    [
        (
            PathBoundaryViolation("SOURCE_OR_PARENT_MISSING", "private/source.png"),
            PurgeReasonCode.MEDIA_FILE_MISSING,
        ),
        (
            ArtifactIntegrityViolation("EXPECTED_HASH_MISMATCH", "private/source.png"),
            PurgeReasonCode.MEDIA_INTEGRITY_FAILURE,
        ),
        (
            ArtifactConflict("DESTINATION_ALREADY_EXISTS", "private/trash.png"),
            PurgeReasonCode.MEDIA_INTEGRITY_FAILURE,
        ),
        (
            PathBoundaryViolation("UNSAFE_LINK", "private/source.png"),
            PurgeReasonCode.WORKSPACE_OPERATION_FAILED,
        ),
        (
            ProviderUnavailable("private provider failure"),
            PurgeReasonCode.WORKSPACE_OPERATION_FAILED,
        ),
    ],
)
def test_stage_failures_become_typed_recovery_without_diagnostic_leakage(
    error: Exception,
    reason_code: PurgeReasonCode,
) -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    repository.expirable = (MEDIA_A,)
    repository.decisions = {MEDIA_A: lease}
    file_ops.stage_errors[MEDIA_A] = error

    result = _coordinator(repository, file_ops).purge_expired(
        RUN_ID,
        expires_before=CUTOFF,
        policy_version=POLICY_VERSION,
    )[0]

    assert result.disposition == PurgeDisposition.RECOVERY_REQUIRED
    assert result.reason_code == reason_code
    assert result.previous_availability == MediaAvailability.PURGING
    assert result.current_availability == MediaAvailability.PURGING
    assert result.audit_sequences == (lease.intent_audit_sequence,)
    assert "private" not in result.model_dump_json()
    assert [entry[0] for entry in timeline] == ["list-expirable", "begin", "stage"]


def test_database_completion_crash_leaves_staged_lease_recoverable() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    repository.expirable = (MEDIA_A,)
    repository.decisions = {MEDIA_A: lease}
    repository.complete_error = RuntimeError("simulated database crash")
    coordinator = _coordinator(repository, file_ops)

    with pytest.raises(RuntimeError, match="simulated database crash"):
        coordinator.purge_expired(
            RUN_ID,
            expires_before=CUTOFF,
            policy_version=POLICY_VERSION,
        )
    assert [entry[0] for entry in timeline][-2:] == ["stage", "complete"]
    assert MEDIA_A not in file_ops.destroyed

    repository.complete_error = None
    repository.expirable = ()
    repository.recovery_claims = [
        _recovery_candidate(lease, PurgeRecoveryKind.INCOMPLETE_PURGE),
        None,
    ]
    recovered = coordinator.recover(RUN_ID)

    assert recovered == (_completed(lease, recovered=True),)
    assert MEDIA_A in file_ops.destroyed


def test_concurrent_modification_from_completion_is_not_swallowed() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    repository.expirable = (MEDIA_A,)
    repository.decisions = {MEDIA_A: lease}
    repository.complete_error = ConcurrentModification("stale purge intent")

    with pytest.raises(ConcurrentModification, match="stale purge intent"):
        _coordinator(repository, file_ops).purge_expired(
            RUN_ID,
            expires_before=CUTOFF,
            policy_version=POLICY_VERSION,
        )


def test_recovery_claims_both_phases_with_one_shared_hard_budget() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    cleanup = _lease(MEDIA_A, intent_audit_sequence=10)
    incomplete = _lease(MEDIA_B, intent_audit_sequence=20)
    repository.recovery_claims = [
        _recovery_candidate(cleanup, PurgeRecoveryKind.TRASH_CLEANUP),
        _recovery_candidate(incomplete, PurgeRecoveryKind.INCOMPLETE_PURGE),
    ]

    results = _coordinator(repository, file_ops, max_items=2).recover(RUN_ID)

    assert results == (_already_purged(cleanup), _completed(incomplete, recovered=True))
    assert timeline.count(("claim-recovery", RUN_ID)) == 2
    assert [entry[:2] for entry in timeline if entry[0] in {"destroy", "stage"}] == [
        ("destroy", MEDIA_A),
        ("stage", MEDIA_B),
        ("destroy", MEDIA_B),
    ]


def test_max_one_persistent_claims_do_not_starve_incomplete_behind_poisoned_cleanup() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    poisoned = _lease(MEDIA_A, intent_audit_sequence=10)
    incomplete = _lease(MEDIA_B, intent_audit_sequence=20)
    repository.recovery_claims = [
        _recovery_candidate(poisoned, PurgeRecoveryKind.TRASH_CLEANUP),
        _recovery_candidate(incomplete, PurgeRecoveryKind.INCOMPLETE_PURGE),
    ]
    file_ops.destroy_errors[MEDIA_A] = PathBoundaryViolation(
        "UNSAFE_LINK",
        "private/trash.png",
    )

    first = _coordinator(repository, file_ops, max_items=1).recover(RUN_ID)
    second = _coordinator(repository, file_ops, max_items=1).recover(RUN_ID)

    assert first == (_cleanup_failed(poisoned),)
    assert second == (_completed(incomplete, recovered=True),)
    assert [entry[:2] for entry in timeline if entry[0] in {"destroy", "stage"}] == [
        ("destroy", MEDIA_A),
        ("stage", MEDIA_B),
        ("destroy", MEDIA_B),
    ]


def test_poisoned_cleanup_is_isolated_from_later_cleanup_in_same_batch() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    poisoned = _lease(MEDIA_A, intent_audit_sequence=10)
    healthy = _lease(MEDIA_B, intent_audit_sequence=20)
    repository.recovery_claims = [
        _recovery_candidate(poisoned, PurgeRecoveryKind.TRASH_CLEANUP),
        _recovery_candidate(healthy, PurgeRecoveryKind.TRASH_CLEANUP),
    ]
    file_ops.destroy_errors[MEDIA_A] = ProviderUnavailable("private provider detail")

    results = _coordinator(repository, file_ops, max_items=2).recover(RUN_ID)

    assert results == (_cleanup_failed(poisoned), _already_purged(healthy))
    assert "private" not in results[0].model_dump_json()
    assert ("mark-clean", RUN_ID, MEDIA_B, healthy.intent_audit_sequence) in timeline


def test_single_candidate_wrap_is_attempted_once_per_recovery_batch() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    candidate = _recovery_candidate(lease, PurgeRecoveryKind.TRASH_CLEANUP)
    repository.recovery_claims = [candidate, candidate, candidate]
    file_ops.destroy_errors[MEDIA_A] = ProviderUnavailable("still unavailable")

    assert _coordinator(repository, file_ops, max_items=100).recover(RUN_ID) == (
        _cleanup_failed(lease),
    )
    assert sum(entry == ("destroy", MEDIA_A) for entry in timeline) == 1
    assert repository.recovery_claims == [candidate]


def test_unexpected_poison_is_visible_but_durable_claim_advances_for_next_start() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    poisoned = _lease(MEDIA_A, intent_audit_sequence=10)
    healthy = _lease(MEDIA_B, intent_audit_sequence=20)
    repository.recovery_claims = [
        _recovery_candidate(poisoned, PurgeRecoveryKind.TRASH_CLEANUP),
        _recovery_candidate(healthy, PurgeRecoveryKind.TRASH_CLEANUP),
    ]
    file_ops.destroy_errors[MEDIA_A] = RuntimeError("unexpected adapter defect")

    with pytest.raises(RuntimeError, match="unexpected adapter defect"):
        _coordinator(repository, file_ops, max_items=2).recover(RUN_ID)

    assert _coordinator(repository, file_ops, max_items=1).recover(RUN_ID) == (
        _already_purged(healthy),
    )


def test_post_commit_cleanup_failure_is_controlled_and_cleanup_retry_skips_completion() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    repository.expirable = (MEDIA_A,)
    repository.decisions = {MEDIA_A: lease}
    file_ops.destroy_errors[MEDIA_A] = PathBoundaryViolation(
        "WORKSPACE_CLOSED",
        "private/path.png",
    )
    coordinator = _coordinator(repository, file_ops)

    result = coordinator.purge_expired(
        RUN_ID,
        expires_before=CUTOFF,
        policy_version=POLICY_VERSION,
    )
    assert result == (_cleanup_failed(lease),)
    assert "private" not in result[0].model_dump_json()
    assert sum(entry[0] == "complete" for entry in timeline) == 1
    assert not any(entry[0] == "mark-clean" for entry in timeline)

    file_ops.destroy_errors.clear()
    repository.expirable = ()
    repository.recovery_claims = [
        _recovery_candidate(lease, PurgeRecoveryKind.TRASH_CLEANUP),
        None,
    ]
    assert coordinator.recover(RUN_ID) == (_already_purged(lease),)
    assert sum(entry[0] == "complete" for entry in timeline) == 1
    assert ("mark-clean", RUN_ID, MEDIA_A, lease.intent_audit_sequence) in timeline


def test_unexpected_cleanup_programming_error_is_not_hidden() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    repository.expirable = (MEDIA_A,)
    repository.decisions = {MEDIA_A: lease}
    file_ops.destroy_errors[MEDIA_A] = RuntimeError("unexpected adapter defect")

    with pytest.raises(RuntimeError, match="unexpected adapter defect"):
        _coordinator(repository, file_ops).purge_expired(
            RUN_ID,
            expires_before=CUTOFF,
            policy_version=POLICY_VERSION,
        )

    assert sum(entry[0] == "complete" for entry in timeline) == 1
    assert not any(entry[0] == "mark-clean" for entry in timeline)


def test_crash_after_delete_before_ack_retries_idempotent_delete_then_marks_clean() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    lease = _lease()
    repository.recovery_claims = [_recovery_candidate(lease, PurgeRecoveryKind.TRASH_CLEANUP)]
    repository.mark_error = RuntimeError("simulated ack crash")
    coordinator = _coordinator(repository, file_ops)

    with pytest.raises(RuntimeError, match="simulated ack crash"):
        coordinator.recover(RUN_ID)
    assert MEDIA_A in file_ops.destroyed

    repository.mark_error = None
    repository.recovery_claims = [
        _recovery_candidate(lease, PurgeRecoveryKind.TRASH_CLEANUP),
        None,
    ]
    assert coordinator.recover(RUN_ID) == (_already_purged(lease),)
    assert sum(entry == ("destroy", MEDIA_A) for entry in timeline) == 2
    assert sum(entry[0] == "complete" for entry in timeline) == 0
    assert ("mark-clean", RUN_ID, MEDIA_A, lease.intent_audit_sequence) in timeline


def test_repository_order_and_limits_fail_closed_before_processing() -> None:
    timeline: list[tuple[object, ...]] = []
    repository = _FakeRepository(timeline)
    file_ops = _FakeFileOps(timeline)
    repository.expirable = (MEDIA_B, MEDIA_A)

    with pytest.raises(ContractViolation, match="stable SHA-256 order"):
        _coordinator(repository, file_ops, max_items=2).purge_expired(
            RUN_ID,
            expires_before=CUTOFF,
            policy_version=POLICY_VERSION,
        )
    assert not any(entry[0] == "begin" for entry in timeline)

    timeline.clear()
    repository.expirable = (MEDIA_A, MEDIA_B, MEDIA_C)
    with pytest.raises(BudgetExceeded, match="requested media limit"):
        _coordinator(repository, file_ops, max_items=2).purge_expired(
            RUN_ID,
            expires_before=CUTOFF,
            policy_version=POLICY_VERSION,
        )
    assert not any(entry[0] == "begin" for entry in timeline)

    timeline.clear()
    repository.expirable = ()
    cleanup_a = _lease(MEDIA_A, intent_audit_sequence=10)
    cleanup_b = _lease(MEDIA_B, intent_audit_sequence=20)
    cleanup_c = _lease(MEDIA_C, intent_audit_sequence=30)
    repository.recovery_claims = [
        _recovery_candidate(cleanup_a, PurgeRecoveryKind.TRASH_CLEANUP),
        _recovery_candidate(cleanup_b, PurgeRecoveryKind.TRASH_CLEANUP),
        _recovery_candidate(cleanup_c, PurgeRecoveryKind.TRASH_CLEANUP),
    ]
    assert len(_coordinator(repository, file_ops, max_items=2).recover(RUN_ID)) == 2
    assert repository.recovery_claims == [
        _recovery_candidate(cleanup_c, PurgeRecoveryKind.TRASH_CLEANUP)
    ]


@pytest.mark.parametrize("max_items", [False, 0, MAX_RETENTION_ITEMS + 1])
def test_coordinator_requires_a_hard_bounded_item_budget(max_items: int) -> None:
    timeline: list[tuple[object, ...]] = []

    with pytest.raises(ValueError, match="max_items"):
        _coordinator(
            _FakeRepository(timeline),
            _FakeFileOps(timeline),
            max_items=max_items,
        )
