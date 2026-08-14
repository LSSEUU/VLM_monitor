from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME, platform_manifest
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_feishu_live import M8FeishuDutyRouteV1
from labcourt.contracts.m8_feishu_notification import M8FeishuRecipientBindingAuthorityV1
from labcourt.contracts.m8_notification_lifecycle import M8NotificationDispatchDisposition
from labcourt.contracts.m8_notifications import M8NotificationPurpose, M8NotificationStatus
from labcourt.contracts.m8_platform_demo import M8PlatformScenarioKind
from labcourt.ports.m8_feishu_http import M8FeishuHttpResponse
from labcourt.ports.m8_feishu_secrets import M8FeishuResolvedSecrets
from labcourt.services.m8_feishu_action_cards import M8FeishuActionCardService
from labcourt.services.m8_feishu_alert_bridge import M8FeishuAlertBridgeService
from labcourt.services.m8_feishu_interactive_outbox import M8FeishuInteractiveOutboxRunner
from labcourt.services.m8_notifications import M8NotificationService
from labcourt.services.m8_platform_demo import _notification_channel, _workflow
from tests.contract.test_m8_feishu_transport_contracts import _activation_status
from tests.integration.test_m8_platform_knowledge_agent_feishu import _feishu_service

BUSY_TIMEOUT_MS = 5_000


class _ActivationRepository:
    def __init__(self, status) -> None:
        self.status = status

    def get_current_status(self, _candidate_id: str, assessed_at: datetime):
        assert assessed_at.tzinfo is not None
        return self.status


class _Secrets:
    def resolve(self, profile, binding) -> M8FeishuResolvedSecrets:
        return M8FeishuResolvedSecrets(
            profile_id=profile.profile_id,
            binding_authority_id=binding.binding_authority_id,
            credential_bundle_reference_id=profile.credential_bundle_reference_id,
            app_id=b"demo-app-id",
            app_secret=b"demo-app-secret",
            open_id=b"demo-safety-open-id",
        )


class _AcceptedHttp:
    def __init__(self) -> None:
        self.message_calls = 0

    def acquire_tenant_access_token(self, _profile, _secrets) -> M8FeishuHttpResponse:
        return M8FeishuHttpResponse(
            200,
            canonical_json(
                {"code": 0, "tenant_access_token": "demo-tenant-token", "expire": 7200}
            ).encode(),
            "feishu-token-demo-log",
        )

    def send_personal_demo_card(
        self,
        _open_id: bytes,
        _tenant_access_token: bytes,
        _provider_uuid: str,
        rendered_card: bytes,
        _timeout_ms: int,
    ) -> M8FeishuHttpResponse:
        self.message_calls += 1
        assert json.loads(rendered_card)["schema"] == "2.0"
        return M8FeishuHttpResponse(
            200,
            canonical_json(
                {
                    "code": 0,
                    "data": {"message_id": f"om-demo-alert-card-{self.message_calls}"},
                }
            ).encode(),
            f"feishu-message-demo-log-{self.message_calls}",
        )


def _token(card: dict[str, object], index: int = 0) -> str:
    body = card["body"]
    assert isinstance(body, dict)
    elements = body["elements"]
    assert isinstance(elements, list)
    buttons = [item for item in elements if isinstance(item, dict) and item.get("tag") == "button"]
    button = buttons[index]
    assert isinstance(button, dict)
    behaviors = button["behaviors"]
    assert isinstance(behaviors, list)
    behavior = behaviors[0]
    assert isinstance(behavior, dict)
    value = behavior["value"]
    assert isinstance(value, dict)
    token = value["confirmation_token"]
    assert isinstance(token, str)
    return token


def _safety_binding(actor_id: str) -> tuple[object, M8FeishuRecipientBindingAuthorityV1]:
    activation = _activation_status()
    original = activation.activation_receipt.runtime_config.recipient_allowlist[0]
    target = original.target.model_copy(update={"actor_id": actor_id})
    binding = M8FeishuRecipientBindingAuthorityV1(
        target=target,
        profile_id=original.profile_id,
        receive_id_reference="feishu-safety-open-id-demo",
        receive_id_sha256=original.receive_id_sha256,
        mapping_revision=1,
        active=True,
        mapping_manifest_id=platform_manifest("platform-feishu-test-binding-v1"),
    )
    runtime = SimpleNamespace(
        profile=activation.activation_receipt.runtime_config.profile,
        recipient_allowlist=(binding,),
    )
    receipt = SimpleNamespace(
        runtime_config=runtime,
        activation_commit_id=activation.activation_receipt.activation_commit_id,
    )
    return SimpleNamespace(
        activation_receipt=receipt,
        sandbox_external_call_permitted=True,
    ), binding


def test_emergency_alert_is_sent_once_then_requires_ack_and_final_confirmation(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    media = tmp_path / "fixture.mp4"
    media.write_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2" + b"\x00" * 40)
    assembly = assemble_m8_platform_demo_api(
        project_root=Path(__file__).parents[2],
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=media,
        port=0,
    )
    server = assembly.server
    operations_token = server.platform_role_tokens[M8ActorRole.OPERATIONS]
    operations_principal = server.api_authenticator.authenticate(
        f"Bearer {operations_token}"
    )
    run = server.platform_service.start_scenario(
        operations_principal, M8PlatformScenarioKind.SMOKE_TEMPERATURE_EMERGENCY
    )
    assert run.case_id is not None

    repository_manifest = platform_manifest("labcourt-platform-sqlite-repository-v1")
    operations = SQLiteM8OperationsRepository(
        assembly.database_path, BUSY_TIMEOUT_MS, repository_manifest
    )
    notifications = SQLiteM8NotificationRepository(
        assembly.database_path, BUSY_TIMEOUT_MS, repository_manifest
    )
    notification_service = M8NotificationService(
        notifications, operations, _notification_channel(), _workflow()
    )
    safety = operations.get_current_actor_authority("safety-officer-demo")
    activation, binding = _safety_binding(safety.authority.actor_id)
    notification_service.publish_target(binding.target, None)
    platform_status = _feishu_service(active=True).status()
    now = [datetime.now(UTC)]

    assembly.feishu_live.repository.commit_duty_route(
        M8FeishuDutyRouteV1(
            actor_id=safety.authority.actor_id,
            actor_authority_commit_receipt_id=safety.commit_receipt_id,
            recipient_binding_authority_id=binding.binding_authority_id,
            activation_revision=platform_status.activation_revision or 1,
            activation_status_id=platform_status.activation_status_id or ("a" * 64),
            route_revision=1,
            committed_at=now[0],
            repository_manifest_id=platform_manifest(
                "platform-feishu-live-repository-v1"
            ),
        )
    )
    action_cards = M8FeishuActionCardService(
        assembly.feishu_live.repository,
        notifications,
        notification_service,
        server.api_service,
        operations.get_current_operational_case,
        lambda: platform_status,
        lambda sender: binding
        if sender == binding.receive_id_sha256
        else (_ for _ in ()).throw(ValueError("unknown sender")),
        operations.get_current_actor_authority,
        lambda: now[0],
        hashlib.sha256(b"demo-feishu-card-token-key").digest(),
        platform_manifest("platform-feishu-card-intent-test-v1"),
        platform_manifest("platform-feishu-case-command-test-v1"),
    )
    bridge = M8FeishuAlertBridgeService(
        assembly.feishu_live.repository,
        operations,
        notifications,
        notification_service,
        lambda: platform_status,
        lambda binding_id: binding
        if binding_id == binding.binding_authority_id
        else (_ for _ in ()).throw(ValueError("unknown binding")),
        lambda: now[0],
        platform_manifest,
    )

    projected = bridge.bridge_current_emergencies()
    queued = next(item for item in projected if item.source_case_id == run.case_id)
    assert queued.queued_notification_id is not None
    queued_notification = notifications.get_current_notification(queued.queued_notification_id)
    assert queued_notification.status == M8NotificationStatus.QUEUED
    local_notification = notifications.get_current_notification(queued.source_notification_id)
    assert local_notification.audit_event.notification_authority.plan.simulated is True

    transport = _AcceptedHttp()
    delivery = M8FeishuInteractiveOutboxRunner(
        notifications,
        notifications,
        _ActivationRepository(activation),
        _Secrets(),
        transport,
        activation.activation_receipt.runtime_config.profile,
        _workflow(),
        action_cards,
        lambda: now[0],
        platform_manifest("platform-feishu-claim-test-v1"),
        platform_manifest("platform-feishu-fence-test-v1"),
        platform_manifest("platform-feishu-completion-test-v1"),
        platform_manifest("platform-feishu-result-test-v1"),
    )
    completion = delivery.run_one(
        queued_notification.notification_id,
        binding,
        b"demo-worker-token-32-byte-minimum-value",
    )
    assert completion.dispatch_result.disposition == M8NotificationDispatchDisposition.ACCEPTED
    assert transport.message_calls == 1
    sent = notifications.get_current_notification(queued_notification.notification_id)
    assert sent.status == M8NotificationStatus.SENT

    now[0] += timedelta(microseconds=1)
    initial_card_bytes, _ = action_cards.render_initial_alert(sent.notification_id)
    initial_card = json.loads(initial_card_bytes)
    elements = initial_card["body"]["elements"]
    assert all(item.get("tag") != "action" for item in elements)
    assert len({item["element_id"] for item in elements if item.get("tag") == "button"}) == 2
    ack_result = action_cards.execute(
        _token(initial_card, 1), binding.receive_id_sha256
    )
    assert ack_result["toast"]["type"] == "success"  # type: ignore[index]
    action_update = ack_result["card"]
    assert isinstance(action_update, dict)
    assert action_update["type"] == "raw"
    action_card = action_update["data"]
    assert isinstance(action_card, dict)

    confirm_result = action_cards.execute(
        _token(action_card), binding.receive_id_sha256
    )
    final_update = confirm_result["card"]
    assert isinstance(final_update, dict)
    assert final_update["type"] == "raw"
    final_card = final_update["data"]
    assert isinstance(final_card, dict)
    final_token = _token(final_card)
    completed = action_cards.execute(final_token, binding.receive_id_sha256)
    assert completed["toast"]["type"] == "success"  # type: ignore[index]
    assert operations.get_current_operational_case(run.case_id).status.value == "CONFIRMED"
    assert bridge.bridge_current_emergencies() == ()

    duplicate = action_cards.execute(final_token, binding.receive_id_sha256)
    assert duplicate["toast"]["type"] == "info"  # type: ignore[index]
    assert transport.message_calls == 1

    now[0] += timedelta(minutes=2, seconds=1)
    reminder = bridge.assess_reminder(sent.notification_id)
    assert reminder is not None
    assert reminder.outcome.value == "CANCELLED_ACKNOWLEDGED"

    resolved_alert = bridge._create_notification(
        run.case_id, M8NotificationPurpose.CASE_ACTION_REQUIRED
    )
    delivery.run_one(
        resolved_alert.notification_id,
        binding,
        b"demo-worker-token-32-byte-minimum-value",
    )
    now[0] += timedelta(minutes=2, seconds=1)
    resolved_reminder = bridge.assess_reminder(resolved_alert.notification_id)
    assert resolved_reminder is not None
    assert resolved_reminder.outcome.value == "CANCELLED_CASE_RESOLVED"

    escalation = bridge._create_notification(
        run.case_id, M8NotificationPurpose.ESCALATION
    )
    assert escalation.status == M8NotificationStatus.QUEUED
    assert bridge.assess_reminder(escalation.notification_id) is None
