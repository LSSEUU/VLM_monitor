from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.contracts.m8_notification_dispatch_claims import (
    M8NotificationDispatchClaimState,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelFailureCode,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
)
from labcourt.contracts.m8_notifications import M8NotificationStatus
from labcourt.exceptions import ConcurrentModification
from tests.integration.test_m8_sqlite_notification_repository import (
    BUSY_TIMEOUT_MS,
    SHA_A,
    SHA_C,
    SHA_D,
    SHA_E,
    _dispatch,
    _planned_fixture,
    _queue,
)

WORKER_TOKEN = b"fake-worker-owner-token-0000000001"
OTHER_WORKER_TOKEN = b"fake-worker-owner-token-0000000002"
CARD_BYTES = b'{"badge":"SIMULATED","case":"dispatch-claim"}'
RESPONSE_BYTES = b'{"accepted":true,"provider":"local-fake"}'


def _queued_fixture(tmp_path: Path):
    _, notifications, database, _, _, planned = _planned_fixture(tmp_path)
    queued = notifications.transition_notification(_queue(planned), (), SHA_D, SHA_E)
    command = _dispatch(queued, CARD_BYTES, RESPONSE_BYTES)
    assert command.dispatch_result is not None
    return notifications, database, queued, command


def _claim(
    notifications: SQLiteM8NotificationRepository,
    request: M8NotificationDispatchRequestV1,
    *,
    token: bytes = WORKER_TOKEN,
):
    return notifications.claim_dispatch(
        request,
        token,
        request.dispatched_at + timedelta(seconds=60),
        SHA_A,
    )


def _fence(notifications: SQLiteM8NotificationRepository, claim, *, token=WORKER_TOKEN):
    return notifications.fence_dispatch_call(
        claim.claim_id,
        token,
        SHA_D,
        claim.claimed_at + timedelta(seconds=1),
        SHA_E,
    )


def _complete(
    notifications: SQLiteM8NotificationRepository,
    claim,
    fence,
    command,
    *,
    result: M8NotificationDispatchResultV1 | None = None,
    response: bytes = RESPONSE_BYTES,
):
    selected = result or command.dispatch_result
    assert selected is not None
    return notifications.complete_dispatch(
        claim.claim_id,
        fence.call_fence_id,
        WORKER_TOKEN,
        selected,
        (CARD_BYTES, response),
        SHA_D,
        command.supporting_authorities,
        command.command_manifest_id,
        SHA_E,
        selected.completed_at + timedelta(seconds=1),
        SHA_A,
    )


def test_dispatch_claim_completion_is_atomic_idempotent_and_restart_safe(
    tmp_path: Path,
) -> None:
    notifications, database, queued, command = _queued_fixture(tmp_path)
    request = command.dispatch_result.request
    claim = _claim(notifications, request)

    assert _claim(notifications, request) == claim
    assert (
        notifications.get_dispatch_claim_status_for_source(
            queued.notification_id,
            queued.notification_version,
            claim.claimed_at + timedelta(seconds=1),
        ).state
        == M8NotificationDispatchClaimState.CLAIMED
    )
    with pytest.raises(ConcurrentModification, match="already has a dispatch claim"):
        _claim(notifications, request, token=OTHER_WORKER_TOKEN)

    fence = _fence(notifications, claim)
    with pytest.raises(ConcurrentModification, match="one-shot call boundary"):
        _fence(notifications, claim)
    completion = _complete(notifications, claim, fence, command)
    assert _complete(notifications, claim, fence, command) == completion
    assert completion.notification_commit.status == M8NotificationStatus.SENT
    assert notifications.get_current_notification(queued.notification_id) == (
        completion.notification_commit
    )

    reopened = SQLiteM8NotificationRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    status = reopened.get_dispatch_claim_status(
        claim.claim_id,
        completion.committed_at,
    )
    assert status.state == M8NotificationDispatchClaimState.COMPLETED
    assert status.completion == completion
    assert reopened.read_raw_artifact(request.rendered_card_ref) == CARD_BYTES
    assert reopened.read_raw_artifact(command.dispatch_result.raw_response_ref) == RESPONSE_BYTES


def test_one_source_version_cannot_be_claimed_with_a_retimed_request(tmp_path: Path) -> None:
    notifications, _, _, command = _queued_fixture(tmp_path)
    request = command.dispatch_result.request
    _claim(notifications, request)
    payload = request.model_dump(mode="json", exclude={"dispatch_request_id"})
    payload["dispatched_at"] = (request.dispatched_at + timedelta(seconds=1)).isoformat()
    retimed = M8NotificationDispatchRequestV1.model_validate(payload)

    with pytest.raises(ConcurrentModification, match="already has a dispatch claim"):
        _claim(notifications, retimed, token=OTHER_WORKER_TOKEN)


def test_expired_pre_call_claim_cannot_cross_the_call_boundary(tmp_path: Path) -> None:
    notifications, _, queued, command = _queued_fixture(tmp_path)
    claim = _claim(notifications, command.dispatch_result.request)
    status = notifications.get_dispatch_claim_status(
        claim.claim_id,
        claim.lease_expires_at,
    )
    assert status.state == M8NotificationDispatchClaimState.EXPIRED_PRE_CALL

    with pytest.raises(ConcurrentModification, match="outside its live claim"):
        notifications.fence_dispatch_call(
            claim.claim_id,
            WORKER_TOKEN,
            SHA_D,
            claim.lease_expires_at,
            SHA_E,
        )
    assert notifications.get_current_notification(queued.notification_id) == queued


def test_uncompleted_call_fence_becomes_reconciliation_required(tmp_path: Path) -> None:
    notifications, database, queued, command = _queued_fixture(tmp_path)
    claim = _claim(notifications, command.dispatch_result.request)
    _fence(notifications, claim)

    reopened = SQLiteM8NotificationRepository(database, BUSY_TIMEOUT_MS, SHA_C)
    status = reopened.get_dispatch_claim_status(claim.claim_id, claim.lease_expires_at)
    assert status.state == M8NotificationDispatchClaimState.RECONCILIATION_REQUIRED
    assert status.reconciliation_required is True
    assert status.automatic_retry_permitted is False
    assert reopened.get_current_notification(queued.notification_id) == queued


def test_bad_raw_completion_rolls_back_then_exact_completion_can_commit(tmp_path: Path) -> None:
    notifications, database, queued, command = _queued_fixture(tmp_path)
    claim = _claim(notifications, command.dispatch_result.request)
    fence = _fence(notifications, claim)

    with pytest.raises(ConcurrentModification, match="raw artifact"):
        _complete(
            notifications,
            claim,
            fence,
            command,
            response=b'{"different":true}',
        )
    assert notifications.get_current_notification(queued.notification_id) == queued
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM m8_notification_dispatch_completions"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM m8_notification_raw_artifacts"
        ).fetchone() == (0,)

    completion = _complete(notifications, claim, fence, command)
    assert completion.notification_commit.status == M8NotificationStatus.SENT


def test_unknown_delivery_is_persisted_as_failed_without_retry_authority(tmp_path: Path) -> None:
    notifications, _, _, command = _queued_fixture(tmp_path)
    accepted = command.dispatch_result
    assert accepted is not None
    unknown = M8NotificationDispatchResultV1(
        request=accepted.request,
        disposition=M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
        raw_response_ref=accepted.raw_response_ref,
        raw_response_sha256=accepted.raw_response_sha256,
        failure_code=M8NotificationChannelFailureCode.UNKNOWN_DELIVERY,
        completed_at=accepted.completed_at,
        result_manifest_id=accepted.result_manifest_id,
    )
    claim = _claim(notifications, unknown.request)
    fence = _fence(notifications, claim)

    completion = _complete(
        notifications,
        claim,
        fence,
        command,
        result=unknown,
    )

    assert completion.unknown_delivery is True
    assert completion.notification_commit.status == M8NotificationStatus.FAILED
    assert completion.additional_dispatch_call_permitted is False


def test_dispatch_claim_tables_are_append_only(tmp_path: Path) -> None:
    notifications, database, _, command = _queued_fixture(tmp_path)
    claim = _claim(notifications, command.dispatch_result.request)
    fence = _fence(notifications, claim)
    completion = _complete(notifications, claim, fence, command)

    with sqlite3.connect(database) as connection:
        for statement in (
            "UPDATE m8_notification_dispatch_claims SET attempt_number = 2",
            "DELETE FROM m8_notification_dispatch_call_fences",
            "UPDATE m8_notification_dispatch_completions SET committed_at = committed_at",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(statement)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                INSERT OR REPLACE INTO m8_notification_dispatch_completions
                SELECT * FROM m8_notification_dispatch_completions WHERE completion_id = ?
                """,
                (completion.completion_id,),
            )
