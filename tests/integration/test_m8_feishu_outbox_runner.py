from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxActivationStatusV1
from labcourt.contracts.m8_notification_dispatch_claims import (
    M8NotificationDispatchClaimState,
)
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.contracts.m8_notifications import M8NotificationStatus
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_feishu_http import (
    M8FeishuHttpCallStage,
    M8FeishuHttpDeliveryCertainty,
    M8FeishuHttpError,
    M8FeishuHttpFailureCode,
)
from labcourt.services.m8_feishu_outbox_runner import M8FeishuSandboxOutboxRunner
from labcourt.services.m8_feishu_sandbox_transport import M8FeishuSandboxSendService
from tests.contract.test_m8_feishu_notification_contracts import _binding, _profile
from tests.contract.test_m8_feishu_transport_contracts import _activation_status
from tests.integration.test_m8_sqlite_notification_repository import (
    SHA_A,
    SHA_B,
    SHA_C,
    SHA_D,
    SHA_E,
    _create_command,
    _plan,
    _queue,
    _repositories,
    _student,
    _workflow,
)
from tests.unit.test_m8_feishu_sandbox_transport import (
    _ActivationRepository,
    _HttpTransport,
    _SecretResolver,
)

RUN_TIME = datetime(2026, 8, 11, 14, 0, tzinfo=UTC)
WORKER_TOKEN = b"offline-feishu-runner-worker-token-01"


class _RunnerClock:
    def __init__(self) -> None:
        self._values = iter(
            (
                RUN_TIME,
                RUN_TIME + timedelta(seconds=1),
                RUN_TIME + timedelta(seconds=3),
            )
        )

    def __call__(self) -> datetime:
        return next(self._values)


class _ActivationSequence:
    def __init__(
        self,
        active: M8FeishuSandboxActivationStatusV1,
        inactive: M8FeishuSandboxActivationStatusV1,
    ) -> None:
        self._active = _ActivationRepository(active)
        self._inactive = inactive
        self.calls = 0

    def get_current_status(
        self,
        candidate_authority_id: str,
        assessed_at: datetime,
    ) -> M8FeishuSandboxActivationStatusV1:
        self.calls += 1
        if self.calls <= 2:
            return self._active.get_current_status(candidate_authority_id, assessed_at)
        return self._inactive


def _queued_fixture(tmp_path: Path):
    operations, notifications, _database = _repositories(tmp_path)
    student = _student()
    operations.publish_actor_authority(student, None)
    case = operations.create_operational_case(
        _create_command(),
        student.actor_id,
        SHA_D,
        SHA_E,
    )
    binding = _binding()
    notifications.publish_target_authority(binding.target, None)
    planned = notifications.create_notification(_plan(case, binding.target), SHA_E)
    queued = notifications.transition_notification(_queue(planned), (), SHA_D, SHA_E)
    return operations, notifications, case, binding, queued


def _runner(notifications, activations, http: _HttpTransport) -> M8FeishuSandboxOutboxRunner:
    sender = M8FeishuSandboxSendService(
        activations,
        _SecretResolver(),
        http,
        lambda: RUN_TIME + timedelta(seconds=2),
        SHA_A,
        SHA_B,
        SHA_C,
    )
    return M8FeishuSandboxOutboxRunner(
        notifications,
        notifications,
        activations,
        sender,
        _profile(),
        _workflow(),
        _RunnerClock(),
        SHA_A,
        SHA_B,
        SHA_C,
        SHA_D,
        SHA_E,
    )


@pytest.mark.parametrize(
    ("message_error", "expected_disposition", "expected_status"),
    (
        (None, M8NotificationDispatchDisposition.ACCEPTED, M8NotificationStatus.SENT),
        (
            M8FeishuHttpError(
                M8FeishuHttpCallStage.MESSAGE,
                M8FeishuHttpFailureCode.TIMEOUT,
                M8FeishuHttpDeliveryCertainty.UNKNOWN,
            ),
            M8NotificationDispatchDisposition.UNKNOWN_DELIVERY,
            M8NotificationStatus.FAILED,
        ),
    ),
)
def test_runner_claims_sends_and_atomically_completes_sqlite_notification(
    tmp_path: Path,
    message_error: M8FeishuHttpError | None,
    expected_disposition: M8NotificationDispatchDisposition,
    expected_status: M8NotificationStatus,
) -> None:
    operations, notifications, case, binding, queued = _queued_fixture(tmp_path)
    activations = _ActivationRepository(_activation_status())
    http = _HttpTransport(message_error=message_error)

    receipt = _runner(notifications, activations, http).run_one(
        queued.notification_id,
        binding,
        WORKER_TOKEN,
    )

    assert receipt.send_receipt.dispatch_result.disposition == expected_disposition
    assert receipt.notification_status == expected_status
    assert notifications.get_current_notification(queued.notification_id).status == expected_status
    assert len(receipt.completion.notification_commit.raw_artifact_receipts) == 2
    assert (
        notifications.get_dispatch_claim_status(
            receipt.claim.claim_id,
            RUN_TIME + timedelta(minutes=2),
        ).state
        == M8NotificationDispatchClaimState.COMPLETED
    )
    assert operations.get_current_operational_case(case.case_id) == case
    assert http.token_calls == 1
    assert http.message_calls == 1
    assert receipt.real_delivery_confirmed is False
    assert receipt.automatic_retry_permitted is False
    assert receipt.case_transition_permitted is False


def test_inactive_activation_fails_before_claim_and_http(tmp_path: Path) -> None:
    _operations, notifications, _case, binding, queued = _queued_fixture(tmp_path)
    inactive = _activation_status().model_copy(update={"current_readiness_assessment": None})
    activations = _ActivationRepository(inactive)
    http = _HttpTransport()

    with pytest.raises(ConcurrentModification, match="does not authorize"):
        _runner(notifications, activations, http).run_one(
            queued.notification_id,
            binding,
            WORKER_TOKEN,
        )
    with pytest.raises(EvidenceMissing):
        notifications.get_dispatch_claim_status_for_source(
            queued.notification_id,
            queued.notification_version,
            RUN_TIME,
        )
    assert http.token_calls == 0
    assert http.message_calls == 0


def test_activation_loss_after_fence_requires_reconciliation_without_http(
    tmp_path: Path,
) -> None:
    _operations, notifications, _case, binding, queued = _queued_fixture(tmp_path)
    active = _activation_status()
    inactive = active.model_copy(update={"current_readiness_assessment": None})
    activations = _ActivationSequence(active, inactive)
    http = _HttpTransport()

    with pytest.raises(ConcurrentModification, match="activation is not current"):
        _runner(notifications, activations, http).run_one(
            queued.notification_id,
            binding,
            WORKER_TOKEN,
        )

    status = notifications.get_dispatch_claim_status_for_source(
        queued.notification_id,
        queued.notification_version,
        RUN_TIME + timedelta(minutes=2),
    )
    assert status.state == M8NotificationDispatchClaimState.RECONCILIATION_REQUIRED
    assert status.automatic_retry_permitted is False
    assert notifications.get_current_notification(queued.notification_id) == queued
    assert http.token_calls == 0
    assert http.message_calls == 0
