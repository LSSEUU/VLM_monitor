from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from labcourt.contracts.m8_notifications import M8NotificationChannelKind
from labcourt.exceptions import EvidenceMissing
from labcourt.m8_feishu_live_cli import _run_resilient_worker
from labcourt.services.m8_feishu_platform import M8FeishuPlatformService
from labcourt.services.m8_feishu_process_supervisor import (
    M8FeishuLiveProcessSupervisor,
    M8FeishuSupervisorAlreadyRunning,
    M8FeishuSupervisorLock,
)


class _ResetRaceNotifications:
    def __init__(self, *, always_missing: bool = False) -> None:
        self.scans = 0
        self.always_missing = always_missing

    def list_current_notifications(self, _limit: int) -> list[object]:
        self.scans += 1
        target = SimpleNamespace(channel=M8NotificationChannelKind.FEISHU)
        plan = SimpleNamespace(target=target)
        authority = SimpleNamespace(plan=plan)
        audit_event = SimpleNamespace(notification_authority=authority)
        return [SimpleNamespace(notification_id="old-reset-id", audit_event=audit_event)]

    def list_notification_audit(self, _notification_id: str) -> list[object]:
        if self.always_missing or self.scans == 1:
            raise EvidenceMissing("notification disappeared during reset")
        return []


def test_last_feishu_attempt_rereads_one_coherent_snapshot_after_online_reset() -> None:
    service = object.__new__(M8FeishuPlatformService)
    notifications = _ResetRaceNotifications()
    service._notifications = notifications  # type: ignore[attr-defined]

    assert service._last_audited_attempt() is None
    assert notifications.scans == 2


def test_last_feishu_attempt_keeps_stable_missing_authority_typed() -> None:
    service = object.__new__(M8FeishuPlatformService)
    notifications = _ResetRaceNotifications(always_missing=True)
    service._notifications = notifications  # type: ignore[attr-defined]

    with pytest.raises(EvidenceMissing):
        service._last_audited_attempt()
    assert notifications.scans == 2


def test_resilient_worker_recovers_after_one_cycle_failure() -> None:
    calls = 0
    failures = 0
    delays: list[float] = []

    def cycle() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("reset race")

    def failed() -> None:
        nonlocal failures
        failures += 1

    _run_resilient_worker(
        cycle,
        on_failure=failed,
        once=False,
        interval_seconds=0.5,
        sleep=delays.append,
        stop_requested=lambda: calls >= 2,
    )

    assert calls == 2
    assert failures == 1
    assert delays == [0.5]


def test_resilient_worker_once_is_fail_fast() -> None:
    with pytest.raises(RuntimeError, match="typed failure"):
        _run_resilient_worker(
            lambda: (_ for _ in ()).throw(RuntimeError("typed failure")),
            on_failure=lambda: None,
            once=True,
            interval_seconds=0.5,
            sleep=lambda _delay: None,
        )


class _FakeProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.returncode: int | None = None
        self.terminated = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        assert self.returncode is not None
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


def test_supervisor_starts_all_components_and_restarts_failed_child(tmp_path: Path) -> None:
    now = [0.0]
    started: list[tuple[str, _FakeProcess]] = []

    def start(component: str) -> _FakeProcess:
        process = _FakeProcess(len(started) + 100)
        started.append((component, process))
        return process

    supervisor = M8FeishuLiveProcessSupervisor(
        start_process=start,
        monotonic=lambda: now[0],
        restart_initial_seconds=0.5,
        restart_max_seconds=10.0,
    )
    supervisor.start_all()
    assert [component for component, _process in started] == [
        "LONG_CONNECTION",
        "AUTHORITY_WORKER",
        "DELIVERY_WORKER",
    ]

    first_delivery = started[-1][1]
    first_delivery.returncode = 7
    supervisor.poll_once()
    assert len(started) == 3
    now[0] = 0.5
    supervisor.poll_once()
    assert len(started) == 4
    assert started[-1][0] == "DELIVERY_WORKER"

    supervisor.shutdown()
    assert all(process.terminated for _component, process in started if process.poll() == 0)


def test_supervisor_lock_rejects_duplicate_owner(tmp_path: Path) -> None:
    first = M8FeishuSupervisorLock(tmp_path / "supervisor.lock")
    second = M8FeishuSupervisorLock(tmp_path / "supervisor.lock")
    first.acquire()
    try:
        with pytest.raises(M8FeishuSupervisorAlreadyRunning):
            second.acquire()
    finally:
        first.release()
