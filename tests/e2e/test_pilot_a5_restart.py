from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from labcourt.adapters.perception.local_worker import PerceptionWorkerExchange
from labcourt.adapters.vlm import (
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
    VLMDeliveryCertainty,
    VLMProviderError,
    VLMProviderFailureCode,
)
from labcourt.contracts.backlog import BacklogRetryDisposition
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.pilot import PilotPerceptionWorkerRequest
from labcourt.services.pilot_a5 import run_pilot_a5
from labcourt.services.pilot_operations import (
    build_expected_perception_manifest,
    build_pilot_run_request,
)
from tests.integration.test_a2_pilot_evidence import (
    PROJECT_ROOT,
    _Backend,
    _ClearMissingGogglesWorker,
    _external_pilot_config,
    _screening_envelope,
)


class _NeverPerceptionTransport:
    """Provider trap: a sealed A1 restart must never reach this transport."""

    def exchange_with_raw(
        self,
        _request: PilotPerceptionWorkerRequest,
    ) -> PerceptionWorkerExchange:
        raise AssertionError("sealed pilot restart called the detector provider")

    def close(self) -> None:
        return None


@dataclass(slots=True)
class _InjectedVLMTransport:
    response: OpenAICompatibleTransportResponse | None = None
    failure: VLMProviderError | None = None
    trap: bool = False
    calls: list[OpenAICompatibleTransportRequest] = field(default_factory=list)

    def send(
        self,
        request: OpenAICompatibleTransportRequest,
    ) -> OpenAICompatibleTransportResponse:
        self.calls.append(request)
        if self.trap:
            raise AssertionError("REPLAY_LOCKED restart called the VLM provider")
        if self.failure is not None:
            raise self.failure
        if self.response is None:
            raise AssertionError("injected VLM transport has no response")
        return self.response


def _database_counts(database: Path) -> dict[str, int]:
    with sqlite3.connect(database) as connection:
        return {
            table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "cases",
                "backlog_items",
                "alerts",
                "alert_outbox",
                "alert_dispatch_attempts",
                "alert_dispatch_receipts",
            )
        }


def test_a5_timeout_restart_and_terminal_replay_are_provider_trapped_and_idempotent(
    tmp_path: Path,
) -> None:
    (tmp_path / "inputs").mkdir()
    (tmp_path / "runs").mkdir()
    (tmp_path / "inputs" / "missing.mp4").write_bytes(b"bounded-a5-video")
    run_id = "pilot-a5-restart"
    config = _external_pilot_config()
    request = build_pilot_run_request(
        config=config,
        run_id=run_id,
        video_path=Path("inputs/missing.mp4"),
        project_root=tmp_path,
        resume=True,
    )
    detector = _ClearMissingGogglesWorker(build_expected_perception_manifest(config))
    timeout_transport = _InjectedVLMTransport(
        failure=VLMProviderError(
            VLMProviderFailureCode.PROVIDER_TIMEOUT,
            VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        )
    )

    first = run_pilot_a5(
        config=config,
        request=request,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
        project_root=tmp_path,
        decoder_backend=_Backend(),
        perception_transport=detector,
        screening_transport=timeout_transport,
        code_commit="test-a5-commit",
    )

    assert first.state == "ATTENTION_REQUIRED"
    assert first.screening.counts.deferred_to_backlog_cases == 1
    assert first.publication.metrics.unresolved_count == 1
    assert len(timeout_transport.calls) == 1
    assert detector.calls
    database = tmp_path / "runs" / run_id / config.storage.database_filename
    assert _database_counts(database) == {
        "cases": 1,
        "backlog_items": 1,
        "alerts": 0,
        "alert_outbox": 0,
        "alert_dispatch_attempts": 0,
        "alert_dispatch_receipts": 0,
    }

    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT pack_json FROM evidence_packs").fetchone()
    assert row is not None
    pack = EvidencePack.model_validate_json(row[0])
    _raw_content, envelope = _screening_envelope(pack)
    recovery_transport = _InjectedVLMTransport(
        response=OpenAICompatibleTransportResponse(body=envelope, latency_ms=9)
    )
    recovered = run_pilot_a5(
        config=config,
        request=request,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
        project_root=tmp_path,
        decoder_backend=_Backend(),
        perception_transport=_NeverPerceptionTransport(),
        screening_transport=recovery_transport,
    )

    assert recovered.state == "COMPLETE"
    assert recovered.backlog_retry.disposition is BacklogRetryDisposition.COMPLETED
    assert recovered.publication.metrics.established_count == 1
    assert recovered.publication.metrics.verified_local_alert_count == 1
    assert recovered.production_delivery_count == 0
    assert len(recovery_transport.calls) == 1
    assert _database_counts(database) == {
        "cases": 1,
        "backlog_items": 1,
        "alerts": 1,
        "alert_outbox": 1,
        "alert_dispatch_attempts": 1,
        "alert_dispatch_receipts": 1,
    }

    replay_transport = _InjectedVLMTransport(trap=True)
    replayed = run_pilot_a5(
        config=config,
        request=request,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
        project_root=tmp_path,
        decoder_backend=_Backend(),
        perception_transport=_NeverPerceptionTransport(),
        screening_transport=replay_transport,
    )
    exact_retry = run_pilot_a5(
        config=config,
        request=request,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
        project_root=tmp_path,
        decoder_backend=_Backend(),
        perception_transport=_NeverPerceptionTransport(),
        screening_transport=replay_transport,
    )

    assert replayed == exact_retry
    assert replayed.state == "COMPLETE"
    assert replayed.backlog_retry.disposition is BacklogRetryDisposition.NO_WORK
    assert replayed.screening.counts.pipeline_invocations == 0
    assert replayed.publication.closure.selected_count == 0
    assert replayed.publication.dispatch.selected_count == 0
    assert replayed.publication.metrics.cases[0].case_view_id == (
        recovered.publication.metrics.cases[0].case_view_id
    )
    assert replayed.publication.metrics.cases[0].final_decision == (
        recovered.publication.metrics.cases[0].final_decision
    )
    assert replay_transport.calls == []
    assert _database_counts(database) == {
        "cases": 1,
        "backlog_items": 1,
        "alerts": 1,
        "alert_outbox": 1,
        "alert_dispatch_attempts": 1,
        "alert_dispatch_receipts": 1,
    }
