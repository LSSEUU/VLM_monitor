"""Explicit persistence boundary for Feishu sandbox send authority."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_feishu_activation_repository import (
    SQLiteM8FeishuActivationRepository,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_adapter_commissioning import (
    MAX_M8_RUNTIME_CONFIG_BYTES,
    M8AdapterActivationIntentV1,
)
from labcourt.contracts.m8_feishu_activation import (
    M8FeishuSandboxActivationCommitReceiptV1,
    M8FeishuSandboxActivationRevocationCommitReceiptV1,
    M8FeishuSandboxActivationStatusV1,
    M8FeishuSandboxRevocationReason,
    M8FeishuSandboxRuntimeConfigV1,
    m8_feishu_runtime_config_bytes,
)
from labcourt.exceptions import ContractViolation


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu outbox authority {name} must be lowercase SHA-256 hex")
    return value


def _require_database(database_path: str | Path) -> Path:
    database = Path(database_path)
    if not database.is_file():
        raise ValueError("M8 Feishu outbox authority database must already exist")
    return database


def _require_document(document: bytes, name: str) -> bytes:
    if not isinstance(document, bytes):
        raise TypeError(f"M8 Feishu outbox {name} must be exact bytes")
    if not 0 < len(document) <= MAX_M8_RUNTIME_CONFIG_BYTES:
        raise ValueError(f"M8 Feishu outbox {name} exceeds the allowed bound")
    return document


def _require_utc_time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 Feishu outbox authority {name} must be aware UTC")
    return value


def _server_time(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise TypeError("M8 Feishu outbox authority requires a clock")
    return _require_utc_time(clock(), "clock")


def _repository(
    database_path: str | Path,
    busy_timeout_ms: int,
    repository_manifest_id: Sha256Hex,
    assessment_manifest_id: Sha256Hex,
) -> SQLiteM8FeishuActivationRepository:
    return SQLiteM8FeishuActivationRepository(
        _require_database(database_path),
        busy_timeout_ms,
        _validate_sha256(repository_manifest_id, "repository manifest"),
        _validate_sha256(assessment_manifest_id, "assessment manifest"),
    )


def commit_m8_feishu_outbox_activation(
    *,
    database_path: str | Path,
    activation_intent_document: bytes,
    runtime_config_document: bytes,
    runtime_config_storage_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
    assessment_manifest_id: Sha256Hex,
    busy_timeout_ms: int = 5_000,
    clock: Callable[[], datetime] = _default_clock,
) -> M8FeishuSandboxActivationCommitReceiptV1:
    """Commit exact dual-confirmed sandbox send authority; never call Feishu."""

    intent = M8AdapterActivationIntentV1.model_validate_json(
        _require_document(activation_intent_document, "activation intent document")
    )
    config_document = _require_document(
        runtime_config_document,
        "runtime config document",
    )
    config = M8FeishuSandboxRuntimeConfigV1.model_validate_json(config_document)
    if config_document != m8_feishu_runtime_config_bytes(config):
        raise ContractViolation(
            "M8 Feishu outbox runtime config document must be exact canonical bytes"
        )
    repository = _repository(
        database_path,
        busy_timeout_ms,
        repository_manifest_id,
        assessment_manifest_id,
    )
    committed_at = _server_time(clock)
    return repository.commit_activation(
        intent,
        config,
        config_document,
        _validate_sha256(
            runtime_config_storage_manifest_id,
            "runtime config storage manifest",
        ),
        committed_at,
        committed_at,
    )


def revoke_m8_feishu_outbox_activation(
    *,
    database_path: str | Path,
    activation_commit_id: str,
    revoker_actor_id: str,
    reason: M8FeishuSandboxRevocationReason,
    reason_ref: str,
    revoked_at: datetime,
    revocation_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
    assessment_manifest_id: Sha256Hex,
    busy_timeout_ms: int = 5_000,
) -> M8FeishuSandboxActivationRevocationCommitReceiptV1:
    """Commit the existing send kill switch with stable retry time."""

    repository = _repository(
        database_path,
        busy_timeout_ms,
        repository_manifest_id,
        assessment_manifest_id,
    )
    return repository.revoke_activation(
        activation_commit_id,
        revoker_actor_id,
        reason,
        reason_ref,
        _require_utc_time(revoked_at, "revoked_at"),
        _validate_sha256(revocation_manifest_id, "revocation manifest"),
    )


def get_m8_feishu_outbox_activation_status(
    *,
    database_path: str | Path,
    candidate_authority_id: str,
    repository_manifest_id: Sha256Hex,
    assessment_manifest_id: Sha256Hex,
    busy_timeout_ms: int = 5_000,
    clock: Callable[[], datetime] = _default_clock,
) -> M8FeishuSandboxActivationStatusV1:
    """Recompute current send authority including recipient drift."""

    repository = _repository(
        database_path,
        busy_timeout_ms,
        repository_manifest_id,
        assessment_manifest_id,
    )
    return repository.get_current_status(
        candidate_authority_id,
        _server_time(clock),
    )


__all__ = [
    "commit_m8_feishu_outbox_activation",
    "get_m8_feishu_outbox_activation_status",
    "revoke_m8_feishu_outbox_activation",
]
