from __future__ import annotations

import pytest

from labcourt.contracts.m4_operations import (
    M4BacklogRetryDisposition,
    M4BacklogRetryReport,
    M4FakeVLMFixtureBundle,
)
from labcourt.services.m4_operations import (
    M4OperationsBoundaryCode,
    M4OperationsBoundaryError,
    M4OperationsService,
)

RUN_ID = "run-m4-service"
MANIFEST_ID = "a" * 64


class _Reader:
    def load_case(self, run_id: str, case_id: str):
        raise AssertionError((run_id, case_id))


class _Coordinator:
    def process_case(self, run_id: str, case_id: str):
        raise AssertionError((run_id, case_id))


class _Worker:
    def __init__(self, report: M4BacklogRetryReport) -> None:
        self.report = report
        self.calls: list[tuple[str, str, int | None, int]] = []

    def run_once(
        self,
        *,
        run_id: str,
        worker_id: str,
        lease_duration_seconds: int | None,
        reclaim_limit: int,
    ) -> M4BacklogRetryReport:
        self.calls.append((run_id, worker_id, lease_duration_seconds, reclaim_limit))
        return self.report


def _bundle() -> M4FakeVLMFixtureBundle:
    return M4FakeVLMFixtureBundle(
        schema_version="m4-fake-vlm-fixture-bundle-v1",
        fixtures=(),
    )


def _service(worker: object | None) -> M4OperationsService:
    return M4OperationsService(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        fixture_bundle=_bundle(),
        evidence_repository=_Reader(),  # type: ignore[arg-type]
        hearing_coordinator=_Coordinator(),  # type: ignore[arg-type]
        backlog_worker=worker,  # type: ignore[arg-type]
    )


def test_injected_backlog_worker_is_bounded_and_report_binding_is_rechecked() -> None:
    report = M4BacklogRetryReport(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        fixture_bundle_id=_bundle().fixture_bundle_id,
        fixture_entry_count=0,
        disposition=M4BacklogRetryDisposition.NO_WORK,
    )
    worker = _Worker(report)

    actual = _service(worker).backlog_retry_run_once(
        worker_id="worker-m4",
        lease_duration_seconds=60,
        reclaim_limit=9,
    )

    assert actual == report
    assert worker.calls == [(RUN_ID, "worker-m4", 60, 9)]


def test_missing_real_backlog_adapter_fails_closed_without_claiming_authority() -> None:
    with pytest.raises(M4OperationsBoundaryError) as raised:
        _service(None).backlog_retry_run_once(worker_id="worker-m4")

    assert raised.value.code == M4OperationsBoundaryCode.BACKLOG_ADAPTER_UNAVAILABLE


def test_worker_cannot_return_another_run_or_fixture_authority() -> None:
    forged = M4BacklogRetryReport(
        run_id="another-run",
        manifest_id=MANIFEST_ID,
        fixture_bundle_id=_bundle().fixture_bundle_id,
        fixture_entry_count=0,
        disposition=M4BacklogRetryDisposition.NO_WORK,
    )

    with pytest.raises(M4OperationsBoundaryError) as raised:
        _service(_Worker(forged)).backlog_retry_run_once(worker_id="worker-m4")

    assert raised.value.code == M4OperationsBoundaryCode.BACKLOG_WORKER_CONTRACT_VIOLATION


@pytest.mark.parametrize(
    ("lease", "reclaim"),
    ((0, 1), (14_401, 1), (1, 0), (1, 10_001)),
)
def test_backlog_worker_limits_are_checked_before_injection(
    lease: int,
    reclaim: int,
) -> None:
    report = M4BacklogRetryReport(
        run_id=RUN_ID,
        manifest_id=MANIFEST_ID,
        fixture_bundle_id=_bundle().fixture_bundle_id,
        fixture_entry_count=0,
        disposition=M4BacklogRetryDisposition.NO_WORK,
    )
    worker = _Worker(report)

    with pytest.raises(ValueError):
        _service(worker).backlog_retry_run_once(
            worker_id="worker-m4",
            lease_duration_seconds=lease,
            reclaim_limit=reclaim,
        )
    assert worker.calls == []
