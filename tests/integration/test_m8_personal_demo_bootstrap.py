from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.application.m8_personal_demo_camera import register_m8_personal_demo_camera
from labcourt.application.m8_personal_demo_media import bind_m8_personal_demo_recorded_media
from labcourt.application.m8_personal_demo_notification import (
    acknowledge_m8_personal_demo_notification,
    deliver_m8_personal_demo_notification,
    route_m8_personal_demo_notification,
)
from labcourt.application.m8_personal_demo_ppe_case import create_m8_personal_demo_ppe_case
from labcourt.cli import app
from labcourt.contracts.m8_access_cases import (
    M8AuthorityReferenceKind,
    M8OperationalCaseStatus,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_notifications import M8NotificationStatus

RUNNER = CliRunner()
BUSY_TIMEOUT_MS = 5_000


def test_bootstrap_is_idempotent_and_persists_pending_case_projection(tmp_path: Path) -> None:
    database = tmp_path / "demo" / "labcourt.sqlite3"

    first = bootstrap_m8_personal_demo(database)
    replay = bootstrap_m8_personal_demo(database)

    assert replay == first
    assert first.receipt.case_status == M8OperationalCaseStatus.PENDING_VERIFICATION
    assert first.projection.overview.location_count == 4
    assert first.projection.overview.observed_sensor_count == 1
    assert first.projection.overview.pending_verification_case_count == 1
    repository = SQLiteM8OperationsRepository(
        database,
        BUSY_TIMEOUT_MS,
        first.projection.topology_receipt.repository_manifest_id,
    )
    case = repository.get_current_operational_case(first.receipt.case_id)
    assert case.status == M8OperationalCaseStatus.PENDING_VERIFICATION
    assert len(repository.list_operational_case_audit(first.receipt.case_id)) == 1


def test_bootstrap_cli_writes_replayable_local_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "local-demo"

    result = RUNNER.invoke(app, ["demo", "bootstrap", "--output", str(output), "--json"])
    replay = RUNNER.invoke(app, ["demo", "bootstrap", "--output", str(output), "--json"])

    assert result.exit_code == 0
    assert replay.exit_code == 0
    assert json.loads(result.stdout) == json.loads(replay.stdout)
    summary = json.loads(result.stdout)
    assert summary["case_status"] == "PENDING_VERIFICATION"
    assert summary["risk_level"] == "EMERGENCY"
    assert summary["simulated"] is True
    assert (output / "labcourt.sqlite3").is_file()
    assert (output / "bootstrap-receipt.json").is_file()
    assert (output / "operations-projection.json").is_file()


def test_notification_route_is_idempotent_and_writes_offline_card(tmp_path: Path) -> None:
    output = tmp_path / "notification-demo"
    database = output / "labcourt.sqlite3"

    first = route_m8_personal_demo_notification(database)
    replay = route_m8_personal_demo_notification(database)

    assert replay == first
    assert first.receipt.notification_status == M8NotificationStatus.QUEUED
    assert first.receipt.target_actor_id == "safety-officer-demo"
    assert first.card.display_badge == "SIMULATED · LOCAL MESSAGE CARD"
    assert first.card.real_delivery_confirmed is False

    result = RUNNER.invoke(
        app,
        ["demo", "notification-route", "--output", str(output), "--json"],
    )
    replay_result = RUNNER.invoke(
        app,
        ["demo", "notification-route", "--output", str(output), "--json"],
    )
    assert result.exit_code == 0
    assert replay_result.exit_code == 0
    assert json.loads(result.stdout) == json.loads(replay_result.stdout)
    assert json.loads(result.stdout)["real_delivery_confirmed"] is False
    assert (output / "notification-route-receipt.json").is_file()
    assert (output / "notification-card.json").is_file()

    delivered = deliver_m8_personal_demo_notification(database, first.receipt)
    delivered_replay = deliver_m8_personal_demo_notification(database, first.receipt)
    assert delivered_replay == delivered
    assert delivered.status == M8NotificationStatus.DELIVERED
    assert delivered.notification_version == 4
    transition = delivered.audit_event.transition_command
    assert transition is not None
    assert transition.delivery_receipt is not None
    assert transition.delivery_receipt.simulated is True

    delivery_result = RUNNER.invoke(
        app,
        ["demo", "notification-deliver", "--output", str(output), "--json"],
    )
    delivery_replay = RUNNER.invoke(
        app,
        ["demo", "notification-deliver", "--output", str(output), "--json"],
    )
    assert delivery_result.exit_code == 0
    assert delivery_replay.exit_code == 0
    assert json.loads(delivery_result.stdout) == json.loads(delivery_replay.stdout)
    assert json.loads(delivery_result.stdout)["notification_status"] == "DELIVERED"
    assert json.loads(delivery_result.stdout)["real_delivery_confirmed"] is False
    assert (output / "notification-delivery-receipt.json").is_file()

    with pytest.raises(ValueError, match="explicit confirmation"):
        acknowledge_m8_personal_demo_notification(database, first.receipt, confirmed=False)
    acknowledged = acknowledge_m8_personal_demo_notification(
        database,
        first.receipt,
        confirmed=True,
    )
    acknowledged_replay = acknowledge_m8_personal_demo_notification(
        database,
        first.receipt,
        confirmed=True,
    )
    assert acknowledged_replay == acknowledged
    assert acknowledged.status == M8NotificationStatus.ACKNOWLEDGED
    assert acknowledged.notification_version == 5
    acknowledgement = acknowledged.audit_event.transition_command
    assert acknowledgement is not None
    assert acknowledgement.explicit_human_confirmation is True
    assert acknowledgement.actor_authority is not None
    assert acknowledgement.actor_authority.actor_id == "safety-officer-demo"

    acknowledgement_result = RUNNER.invoke(
        app,
        [
            "demo",
            "notification-acknowledge",
            "--output",
            str(output),
            "--confirmed",
            "--json",
        ],
    )
    acknowledgement_replay = RUNNER.invoke(
        app,
        [
            "demo",
            "notification-acknowledge",
            "--output",
            str(output),
            "--confirmed",
            "--json",
        ],
    )
    assert acknowledgement_result.exit_code == 0
    assert acknowledgement_replay.exit_code == 0
    assert json.loads(acknowledgement_result.stdout) == json.loads(acknowledgement_replay.stdout)
    assert json.loads(acknowledgement_result.stdout)["notification_status"] == "ACKNOWLEDGED"
    assert json.loads(acknowledgement_result.stdout)["case_transition_permitted"] is False
    assert (output / "notification-acknowledgement-receipt.json").is_file()


def test_recorded_camera_registration_is_additive_idempotent_and_replayable(
    tmp_path: Path,
) -> None:
    output = tmp_path / "camera-demo"
    database = output / "labcourt.sqlite3"

    first = register_m8_personal_demo_camera(database)
    replay = register_m8_personal_demo_camera(database)

    assert replay == first
    assert first.source_count == 2
    assert first.camera_count == 1
    assert first.simulated_source_count == 2
    assert first.media_attached is False
    assert first.live_camera_claim_permitted is False
    post_registration = bootstrap_m8_personal_demo(database)
    assert post_registration.projection.overview.source_count == 1
    assert post_registration.projection.overview.camera_count == 0
    assert post_registration.projection.overview.observed_sensor_count == 1

    result = RUNNER.invoke(
        app,
        ["demo", "camera-register", "--output", str(output), "--json"],
    )
    replay_result = RUNNER.invoke(
        app,
        ["demo", "camera-register", "--output", str(output), "--json"],
    )
    assert result.exit_code == 0
    assert replay_result.exit_code == 0
    assert json.loads(result.stdout) == json.loads(replay_result.stdout)
    summary = json.loads(result.stdout)
    assert summary["mode"] == "RECORDED_VIDEO_SIMULATION"
    assert summary["display_badge"] == "SIMULATED · RECORDED VIDEO"
    assert summary["media_attached"] is False
    assert (output / "camera-registration-receipt.json").is_file()


def test_recorded_media_binding_preserves_input_and_is_replayable(tmp_path: Path) -> None:
    output = tmp_path / "camera-demo"
    input_media = tmp_path / "authorized-demo.mp4"
    media_bytes = (
        b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"
        b"\x00\x00\x00\x08mdat"
    )
    input_media.write_bytes(media_bytes)

    first = bind_m8_personal_demo_recorded_media(
        output / "labcourt.sqlite3", input_media, output
    )
    replay = bind_m8_personal_demo_recorded_media(
        output / "labcourt.sqlite3", input_media, output
    )

    assert replay == first
    assert input_media.read_bytes() == media_bytes
    assert (output / first.playback_media_ref).read_bytes() == media_bytes
    assert first.media_attached is True
    assert first.exact_byte_copy is True
    assert first.original_media_modified is False
    assert first.decoder_preflight_performed is False

    result = RUNNER.invoke(
        app,
        [
            "demo",
            "media-bind",
            "--input",
            str(input_media),
            "--output",
            str(output),
            "--json",
        ],
    )
    assert result.exit_code == 0
    summary = json.loads(result.stdout)
    assert summary["media_attached"] is True
    assert summary["exact_byte_copy"] is True
    assert summary["original_media_modified"] is False
    assert (output / "camera-media-receipt.json").is_file()


def test_ppe_weak_label_creates_only_a_replayable_pending_student_case(
    tmp_path: Path,
) -> None:
    output = tmp_path / "ppe-demo"
    input_media = tmp_path / "authorized-ppe.mp4"
    input_media.write_bytes(
        b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"
        b"\x00\x00\x00\x08mdat"
    )
    binding = bind_m8_personal_demo_recorded_media(
        output / "labcourt.sqlite3", input_media, output
    )
    (output / "camera-media-receipt.json").write_text(
        binding.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )

    first = create_m8_personal_demo_ppe_case(
        output / "labcourt.sqlite3", output, binding
    )
    replay = create_m8_personal_demo_ppe_case(
        output / "labcourt.sqlite3", output, binding
    )

    assert replay == first
    assert first.case_status == M8OperationalCaseStatus.PENDING_VERIFICATION
    assert first.risk_level == M8OperationalRiskLevel.GENERAL
    assert first.subject_actor_id == "student-demo"
    assert first.machine_weak_label_is_ground_truth is False
    assert first.direct_disciplinary_action_permitted is False
    repository_manifest_id = bootstrap_m8_personal_demo(
        output / "labcourt.sqlite3"
    ).projection.topology_receipt.repository_manifest_id
    repository = SQLiteM8OperationsRepository(
        output / "labcourt.sqlite3",
        BUSY_TIMEOUT_MS,
        repository_manifest_id,
    )
    case = repository.get_current_operational_case(first.case_id)
    authority = case.audit_event.case_authority
    assert authority.subject_actor_id == "student-demo"
    assert authority.risk_level == M8OperationalRiskLevel.GENERAL
    assert authority.create_command.human_verification_required is True
    assert authority.create_command.direct_disciplinary_action_permitted is False
    assert authority.create_command.trigger_authorities[0].kind == (
        M8AuthorityReferenceKind.VIDEO_EVENT
    )
    assert len(repository.list_current_operational_cases(10)) == 2

    result = RUNNER.invoke(
        app,
        ["demo", "ppe-case-create", "--output", str(output), "--json"],
    )
    assert result.exit_code == 0
    summary = json.loads(result.stdout)
    assert summary["case_status"] == "PENDING_VERIFICATION"
    assert summary["risk_level"] == "GENERAL"
    assert summary["machine_weak_label_is_ground_truth"] is False
    assert (output / "ppe-case-receipt.json").is_file()
