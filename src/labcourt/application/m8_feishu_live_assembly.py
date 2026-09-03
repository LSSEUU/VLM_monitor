"""Compose Feishu live services around existing M8 authorities."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from labcourt.adapters.m8_feishu_environment_secrets import (
    EnvironmentM8FeishuSecretResolver,
    M8FeishuEnvironmentSecretBinding,
)
from labcourt.adapters.m8_feishu_stdlib_http import StdlibM8FeishuHttpTransport
from labcourt.adapters.storage.sqlite_m8_feishu_activation_repository import (
    SQLiteM8FeishuActivationRepository,
)
from labcourt.adapters.storage.sqlite_m8_feishu_live_repository import (
    SQLiteM8FeishuLiveRepository,
)
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_platform_bootstrap import platform_manifest
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_feishu_activation import M8FeishuSandboxActivationStatusV1
from labcourt.contracts.m8_feishu_live import M8FeishuDutyRouteV1
from labcourt.contracts.m8_feishu_notification import M8FeishuRecipientBindingAuthorityV1
from labcourt.contracts.m8_feishu_personal_demo import (
    M8FeishuPersonalDemoProbeReceiptV1,
    M8FeishuPersonalDemoProbeV1,
)
from labcourt.exceptions import EvidenceMissing
from labcourt.services.m8_agent_chat import M8AgentChatService
from labcourt.services.m8_feishu_action_cards import M8FeishuActionCardService
from labcourt.services.m8_feishu_agent_reply_delivery import (
    M8FeishuAgentReplyDeliveryWorker,
)
from labcourt.services.m8_feishu_agent_worker import (
    M8FeishuAgentAuthorityWorker,
    M8FeishuTrustedActorContext,
)
from labcourt.services.m8_feishu_alert_bridge import M8FeishuAlertBridgeService
from labcourt.services.m8_feishu_delivery_worker import M8FeishuDeliveryWorker
from labcourt.services.m8_feishu_interactive_outbox import M8FeishuInteractiveOutboxRunner
from labcourt.services.m8_feishu_live_api import M8FeishuLiveApiService
from labcourt.services.m8_feishu_personal_demo import M8FeishuPersonalDemoService
from labcourt.services.m8_feishu_platform import M8FeishuPlatformService
from labcourt.services.m8_notification_api import M8NotificationApiService
from labcourt.services.m8_notifications import M8NotificationService
from labcourt.services.m8_operations_api import M8OperationsApiService
from labcourt.services.m8_platform_demo import _notification_channel, _workflow


@dataclass(frozen=True, slots=True)
class M8FeishuLiveAssembly:
    api: M8FeishuLiveApiService
    repository: SQLiteM8FeishuLiveRepository
    action_cards: M8FeishuActionCardService
    alert_bridge: M8FeishuAlertBridgeService
    agent_worker: M8FeishuAgentAuthorityWorker
    delivery_worker: M8FeishuDeliveryWorker | None
    secret_resolver: EnvironmentM8FeishuSecretResolver | None
    clock: Callable[[], datetime]


def assemble_m8_feishu_live_services(
    *,
    database_path: Path,
    busy_timeout_ms: int,
    operations_repository: SQLiteM8OperationsRepository,
    operations_api: M8OperationsApiService,
    notification_repository: SQLiteM8NotificationRepository,
    notification_api: M8NotificationApiService,
    activation_repository: SQLiteM8FeishuActivationRepository,
    platform: M8FeishuPlatformService,
    agent_chat: M8AgentChatService,
    principal_for_actor: Callable[[str], M8ApiPrincipalV1],
    clock: Callable[[], datetime],
) -> M8FeishuLiveAssembly:
    repository_manifest = platform_manifest("platform-feishu-live-repository-v1")
    live = SQLiteM8FeishuLiveRepository.initialize(
        database_path,
        busy_timeout_ms,
        repository_manifest,
        clock,
    )
    notification_service = M8NotificationService(
        notification_repository,
        operations_repository,
        _notification_channel(),
        _workflow(),
    )

    def current_activation() -> M8FeishuSandboxActivationStatusV1:
        status = platform.status()
        if status.candidate_authority_id is None:
            raise EvidenceMissing("Feishu candidate is not configured")
        return activation_repository.get_current_status(status.candidate_authority_id, clock())

    def binding_by_id(binding_id: str) -> M8FeishuRecipientBindingAuthorityV1:
        activation = current_activation()
        matching = tuple(
            item
            for item in activation.activation_receipt.runtime_config.recipient_allowlist
            if item.binding_authority_id == binding_id
        )
        if len(matching) != 1:
            raise EvidenceMissing("Feishu recipient binding is absent")
        return matching[0]

    def binding_by_sender(sender_sha256: str) -> M8FeishuRecipientBindingAuthorityV1:
        activation = current_activation()
        matching = tuple(
            item
            for item in activation.activation_receipt.runtime_config.recipient_allowlist
            if item.receive_id_sha256 == sender_sha256 and item.active
        )
        if len(matching) != 1:
            raise EvidenceMissing("Feishu sender binding is absent")
        return matching[0]

    worker_value = os.environ.get("LABCOURT_FEISHU_WORKER_TOKEN", "")
    worker_key = (
        worker_value.encode("utf-8")
        if len(worker_value.encode("utf-8")) >= 32
        else hashlib.sha256(b"labcourt-feishu-offline-no-send-token-key").digest()
    )
    action_cards = M8FeishuActionCardService(
        live,
        notification_repository,
        notification_service,
        operations_api,
        operations_repository.get_current_operational_case,
        platform.status,
        binding_by_sender,
        operations_repository.get_current_actor_authority,
        clock,
        worker_key,
        platform_manifest("platform-feishu-card-intent-v1"),
        platform_manifest("platform-feishu-case-command-v1"),
    )
    alert_bridge = M8FeishuAlertBridgeService(
        live,
        operations_repository,
        notification_repository,
        notification_service,
        platform.status,
        binding_by_id,
        clock,
        platform_manifest,
    )

    def trusted_actor_context(sender_sha256: str) -> M8FeishuTrustedActorContext:
        binding = binding_by_sender(sender_sha256)
        actor = operations_repository.get_current_actor_authority(binding.target.actor_id)
        principal = principal_for_actor(actor.authority.actor_id)
        if agent_chat.actor_authority(principal) != actor:
            raise ValueError("Feishu actor principal no longer resolves to current authority")
        return M8FeishuTrustedActorContext(
            principal=principal,
            actor_authority=actor,
            recipient_binding=binding,
        )

    agent_worker = M8FeishuAgentAuthorityWorker(
        live,
        agent_chat,
        trusted_actor_context,
        clock,
        repository_manifest,
        platform_manifest("platform-feishu-agent-reply-envelope-v1"),
        platform_manifest("platform-feishu-authority-worker-v1"),
    )

    def build_secret_resolver() -> EnvironmentM8FeishuSecretResolver:
        activation = current_activation()
        profile = activation.activation_receipt.runtime_config.profile
        route = live.current_duty_route()
        allowlist = activation.activation_receipt.runtime_config.recipient_allowlist
        binding = (
            binding_by_id(route.recipient_binding_authority_id)
            if route is not None
            else allowlist[0]
        )
        bindings = ((binding.receive_id_reference, "LABCOURT_FEISHU_TEST_OPEN_ID"),)
        return EnvironmentM8FeishuSecretResolver(
            (
                M8FeishuEnvironmentSecretBinding(
                    credential_bundle_reference_id=profile.credential_bundle_reference_id,
                    app_id_env="LABCOURT_FEISHU_APP_ID",
                    app_secret_env="LABCOURT_FEISHU_APP_SECRET",
                    receive_id_env_by_reference=bindings,
                ),
            )
        )

    def test_dispatcher(
        route: M8FeishuDutyRouteV1,
    ) -> M8FeishuPersonalDemoProbeReceiptV1:
        activation = current_activation()
        runtime = activation.activation_receipt.runtime_config
        binding = binding_by_id(route.recipient_binding_authority_id)
        resolver = build_secret_resolver()
        probe = M8FeishuPersonalDemoProbeV1(
            app_id_sha256=runtime.profile.app_id_sha256,
            recipient_open_id_sha256=binding.receive_id_sha256,
            requested_at=clock(),
            timeout_ms=min(runtime.profile.candidate.request_timeout_ms, 10_000),
            probe_manifest_id=platform_manifest("platform-feishu-live-test-card-v1"),
        )
        with resolver.resolve(runtime.profile, binding) as secrets:
            run = M8FeishuPersonalDemoService(StdlibM8FeishuHttpTransport(), clock).send(
                probe,
                secrets.app_id_bytes(),
                secrets.app_secret_bytes(),
                secrets.open_id_bytes(),
            )
        if not isinstance(run.receipt, M8FeishuPersonalDemoProbeReceiptV1):
            raise TypeError("Feishu test card returned an emergency probe receipt")
        return run.receipt

    api = M8FeishuLiveApiService(
        live,
        operations_api,
        notification_api,
        platform.status,
        operations_repository.get_current_actor_authority,
        binding_by_id,
        alert_bridge,
        test_dispatcher,
        clock,
        repository_manifest,
    )
    secret_resolver = None
    delivery_worker = None
    with suppress(EvidenceMissing):
        secret_resolver = build_secret_resolver()
        activation = current_activation()
        runtime = activation.activation_receipt.runtime_config
        http = StdlibM8FeishuHttpTransport()
        interactive = M8FeishuInteractiveOutboxRunner(
            notification_repository,
            notification_repository,
            activation_repository,
            secret_resolver,
            http,
            runtime.profile,
            _workflow(),
            action_cards,
            clock,
            platform_manifest("platform-feishu-notification-claim-v1"),
            platform_manifest("platform-feishu-notification-call-fence-v1"),
            platform_manifest("platform-feishu-notification-completion-v1"),
            platform_manifest("platform-feishu-notification-result-v1"),
        )
        reply_delivery = M8FeishuAgentReplyDeliveryWorker(
            live,
            activation_repository,
            secret_resolver,
            http,
            runtime.profile,
            binding_by_id,
            clock,
            platform_manifest("platform-feishu-agent-reply-completion-v1"),
        )
        delivery_worker = M8FeishuDeliveryWorker(
            live,
            notification_repository,
            alert_bridge,
            interactive,
            reply_delivery,
            binding_by_id,
            worker_key,
            clock,
            platform_manifest("platform-feishu-delivery-worker-v1"),
        )
        if len(worker_value.encode("utf-8")) < 32:
            delivery_worker = None
    return M8FeishuLiveAssembly(
        api=api,
        repository=live,
        action_cards=action_cards,
        alert_bridge=alert_bridge,
        agent_worker=agent_worker,
        delivery_worker=delivery_worker,
        secret_resolver=secret_resolver,
        clock=clock,
    )


__all__ = ["M8FeishuLiveAssembly", "assemble_m8_feishu_live_services"]
