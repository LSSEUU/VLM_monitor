"""Explicit one-shot runtime for an activated Feishu sandbox outbox item."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from labcourt.adapters.m8_feishu_environment_secrets import (
    EnvironmentM8FeishuSecretResolver,
    M8FeishuEnvironmentSecretBinding,
)
from labcourt.adapters.m8_feishu_stdlib_http import StdlibM8FeishuHttpTransport
from labcourt.adapters.storage.sqlite_m8_feishu_activation_repository import (
    SQLiteM8FeishuActivationRepository,
)
from labcourt.adapters.storage.sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import MAX_M8_RUNTIME_CONFIG_BYTES
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_feishu_outbox import M8FeishuSandboxOutboxRunReceiptV1
from labcourt.contracts.m8_notification_cards import (
    M8NotificationWorkflowManifestAuthorityV1,
)
from labcourt.contracts.m8_notifications import M8NotificationStatus
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_feishu_http import M8FeishuHttpTransport
from labcourt.services.m8_feishu_outbox_runner import M8FeishuSandboxOutboxRunner
from labcourt.services.m8_feishu_sandbox_transport import M8FeishuSandboxSendService

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu outbox runtime {name} must be lowercase SHA-256 hex")
    return value


def _require_database(database_path: str | Path) -> Path:
    database = Path(database_path)
    if not database.is_file():
        raise ValueError("M8 Feishu outbox runtime database must already exist")
    return database


def _workflow(document: bytes) -> M8NotificationWorkflowManifestAuthorityV1:
    if not isinstance(document, bytes) or not 0 < len(document) <= MAX_M8_RUNTIME_CONFIG_BYTES:
        raise ValueError("M8 Feishu outbox workflow document exceeds the allowed bound")
    workflow = M8NotificationWorkflowManifestAuthorityV1.model_validate_json(document)
    canonical = canonical_json(workflow.model_dump(mode="json")).encode("utf-8")
    if document != canonical:
        raise ContractViolation("M8 Feishu outbox workflow document must be exact canonical bytes")
    return workflow


def _worker_token(
    environment: Mapping[str, str],
    worker_token_env: str,
) -> bytes:
    if _ENV_NAME.fullmatch(worker_token_env) is None:
        raise ValueError("M8 Feishu outbox worker token environment name is invalid")
    value = environment.get(worker_token_env)
    if (
        not isinstance(value, str)
        or not 32 <= len(value) <= 256
        or any(character.isspace() or ord(character) < 0x20 for character in value)
    ):
        raise ValueError("M8 Feishu outbox worker token environment value is invalid")
    return value.encode("utf-8")


@dataclass(frozen=True, slots=True)
class M8FeishuOutboxRuntimeCheck:
    """Secret-free proof that one exact attempt can reach the claim boundary."""

    activation_commit_id: str
    notification_id: str
    notification_version: int
    recipient_binding_authority_id: str
    workflow_authority_id: str
    secrets_validated: bool = True
    dispatch_claim_created: bool = False
    external_call_attempted: bool = False


@dataclass(frozen=True, slots=True)
class _PreparedRuntime:
    activation_repository: SQLiteM8FeishuActivationRepository
    notifications: SQLiteM8NotificationRepository
    resolver: EnvironmentM8FeishuSecretResolver
    profile: M8FeishuAdapterProfileV1
    binding: M8FeishuRecipientBindingAuthorityV1
    workflow: M8NotificationWorkflowManifestAuthorityV1
    owner_token: bytes = field(repr=False)
    runtime_manifest: str
    activation_commit_id: str
    notification_version: int


def _prepare_runtime(
    *,
    database_path: str | Path,
    notification_id: str,
    candidate_authority_id: str,
    recipient_binding_authority_id: str,
    workflow_document: bytes,
    app_id_env: str,
    app_secret_env: str,
    receive_id_env: str,
    worker_token_env: str,
    repository_manifest_id: Sha256Hex,
    assessment_manifest_id: Sha256Hex,
    runtime_manifest_id: Sha256Hex,
    busy_timeout_ms: int,
    clock: Callable[[], datetime],
    environment: Mapping[str, str] | None,
) -> _PreparedRuntime:
    if not callable(clock):
        raise TypeError("M8 Feishu outbox runtime requires a clock")
    database = _require_database(database_path)
    repository_manifest = _validate_sha256(
        repository_manifest_id,
        "repository manifest",
    )
    assessment_manifest = _validate_sha256(
        assessment_manifest_id,
        "assessment manifest",
    )
    runtime_manifest = _validate_sha256(runtime_manifest_id, "runtime manifest")
    activation_repository = SQLiteM8FeishuActivationRepository(
        database,
        busy_timeout_ms,
        repository_manifest,
        assessment_manifest,
    )
    status = activation_repository.get_current_status(
        candidate_authority_id,
        clock(),
    )
    if not status.sandbox_external_call_permitted:
        raise ValueError("M8 Feishu outbox runtime activation is not currently active")
    config = status.activation_receipt.runtime_config
    if config.profile.candidate.candidate_authority_id != candidate_authority_id:
        raise ContractViolation("M8 Feishu outbox runtime candidate authority drifted")
    matches = tuple(
        item
        for item in config.recipient_allowlist
        if item.binding_authority_id == recipient_binding_authority_id
    )
    if len(matches) != 1:
        raise ValueError("M8 Feishu outbox runtime recipient binding is not allowlisted")
    binding = matches[0]
    runtime_environment = os.environ if environment is None else environment
    resolver = EnvironmentM8FeishuSecretResolver(
        (
            M8FeishuEnvironmentSecretBinding(
                credential_bundle_reference_id=(config.profile.credential_bundle_reference_id),
                app_id_env=app_id_env,
                app_secret_env=app_secret_env,
                receive_id_env_by_reference=((binding.receive_id_reference, receive_id_env),),
            ),
        ),
        environment=runtime_environment,
    )
    with resolver.resolve(config.profile, binding):
        pass
    owner_token = _worker_token(runtime_environment, worker_token_env)
    notifications = SQLiteM8NotificationRepository(
        database,
        busy_timeout_ms,
        repository_manifest,
    )
    current = notifications.get_current_notification(notification_id)
    if current.status != M8NotificationStatus.QUEUED:
        raise ValueError("M8 Feishu outbox runtime requires current QUEUED notification")
    if current.audit_event.notification_authority.plan.target != binding.target:
        raise ContractViolation(
            "M8 Feishu outbox runtime notification target is not the exact binding target"
        )
    return _PreparedRuntime(
        activation_repository=activation_repository,
        notifications=notifications,
        resolver=resolver,
        profile=config.profile,
        binding=binding,
        workflow=_workflow(workflow_document),
        owner_token=owner_token,
        runtime_manifest=runtime_manifest,
        activation_commit_id=status.activation_receipt.activation_commit_id,
        notification_version=current.notification_version,
    )


def check_m8_feishu_outbox_once(
    *,
    database_path: str | Path,
    notification_id: str,
    candidate_authority_id: str,
    recipient_binding_authority_id: str,
    workflow_document: bytes,
    app_id_env: str,
    app_secret_env: str,
    receive_id_env: str,
    worker_token_env: str,
    repository_manifest_id: Sha256Hex,
    assessment_manifest_id: Sha256Hex,
    runtime_manifest_id: Sha256Hex,
    busy_timeout_ms: int = 5_000,
    clock: Callable[[], datetime] = _default_clock,
    environment: Mapping[str, str] | None = None,
) -> M8FeishuOutboxRuntimeCheck:
    """Validate one exact attempt without claiming, networking, or mutation."""

    prepared = _prepare_runtime(
        database_path=database_path,
        notification_id=notification_id,
        candidate_authority_id=candidate_authority_id,
        recipient_binding_authority_id=recipient_binding_authority_id,
        workflow_document=workflow_document,
        app_id_env=app_id_env,
        app_secret_env=app_secret_env,
        receive_id_env=receive_id_env,
        worker_token_env=worker_token_env,
        repository_manifest_id=repository_manifest_id,
        assessment_manifest_id=assessment_manifest_id,
        runtime_manifest_id=runtime_manifest_id,
        busy_timeout_ms=busy_timeout_ms,
        clock=clock,
        environment=environment,
    )
    return M8FeishuOutboxRuntimeCheck(
        activation_commit_id=prepared.activation_commit_id,
        notification_id=notification_id,
        notification_version=prepared.notification_version,
        recipient_binding_authority_id=prepared.binding.binding_authority_id,
        workflow_authority_id=prepared.workflow.workflow_authority_id,
    )


def run_m8_feishu_outbox_once(
    *,
    database_path: str | Path,
    notification_id: str,
    candidate_authority_id: str,
    recipient_binding_authority_id: str,
    workflow_document: bytes,
    app_id_env: str,
    app_secret_env: str,
    receive_id_env: str,
    worker_token_env: str,
    repository_manifest_id: Sha256Hex,
    assessment_manifest_id: Sha256Hex,
    runtime_manifest_id: Sha256Hex,
    busy_timeout_ms: int = 5_000,
    claim_lease_seconds: int = 60,
    clock: Callable[[], datetime] = _default_clock,
    environment: Mapping[str, str] | None = None,
    http_transport: M8FeishuHttpTransport | None = None,
) -> M8FeishuSandboxOutboxRunReceiptV1:
    """Claim, fence, call, and complete one exact current QUEUED notification."""

    prepared = _prepare_runtime(
        database_path=database_path,
        notification_id=notification_id,
        candidate_authority_id=candidate_authority_id,
        recipient_binding_authority_id=recipient_binding_authority_id,
        workflow_document=workflow_document,
        app_id_env=app_id_env,
        app_secret_env=app_secret_env,
        receive_id_env=receive_id_env,
        worker_token_env=worker_token_env,
        repository_manifest_id=repository_manifest_id,
        assessment_manifest_id=assessment_manifest_id,
        runtime_manifest_id=runtime_manifest_id,
        busy_timeout_ms=busy_timeout_ms,
        clock=clock,
        environment=environment,
    )
    sender = M8FeishuSandboxSendService(
        prepared.activation_repository,
        prepared.resolver,
        http_transport or StdlibM8FeishuHttpTransport(),
        clock,
        prepared.runtime_manifest,
        prepared.runtime_manifest,
        prepared.runtime_manifest,
    )
    runner = M8FeishuSandboxOutboxRunner(
        prepared.notifications,
        prepared.notifications,
        prepared.activation_repository,
        sender,
        prepared.profile,
        prepared.workflow,
        clock,
        prepared.runtime_manifest,
        prepared.runtime_manifest,
        prepared.runtime_manifest,
        prepared.runtime_manifest,
        prepared.runtime_manifest,
        claim_lease_seconds,
    )
    return runner.run_one(notification_id, prepared.binding, prepared.owner_token)


__all__ = [
    "M8FeishuOutboxRuntimeCheck",
    "check_m8_feishu_outbox_once",
    "run_m8_feishu_outbox_once",
]
