# mypy: disable-error-code="import-not-found, unused-ignore"

"""Explicit production assembly for the activation-gated Feishu webhook backend."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from labcourt.adapters.m8_feishu_inbound_cryptography import (
    CryptographyM8FeishuInboundCrypto,
)
from labcourt.adapters.m8_feishu_inbound_environment_secrets import (
    EnvironmentM8FeishuInboundSecretResolver,
    M8FeishuInboundEnvironmentSecretBinding,
)
from labcourt.adapters.storage.sqlite_m8_feishu_challenge_receipt_sink import (
    SQLiteM8FeishuUrlChallengeReceiptSink,
)
from labcourt.adapters.storage.sqlite_m8_feishu_inbound_activation_repository import (
    SQLiteM8FeishuInboundActivationRepository,
)
from labcourt.adapters.storage.sqlite_m8_feishu_inbound_repository import (
    SQLiteM8FeishuInboundRepository,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_inbound_activation import (
    M8FeishuInboundSandboxActivationStatusV1,
)
from labcourt.exceptions import ContractViolation
from labcourt.m8_feishu_activated_webhook_server import (
    M8FeishuActivatedWebhookHttpServer,
    build_m8_feishu_activated_webhook_server,
)
from labcourt.services.m8_feishu_challenge import M8FeishuUrlChallengeService
from labcourt.services.m8_feishu_inbound import M8FeishuInboundVerificationService


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu webhook runtime {name} must be lowercase SHA-256 hex")
    return value


@dataclass(frozen=True, slots=True)
class M8FeishuWebhookRuntimeAssembly:
    """Secret-free handle for one explicitly constructed backend listener."""

    server: M8FeishuActivatedWebhookHttpServer
    activation_status: M8FeishuInboundSandboxActivationStatusV1
    encrypt_key_env: str
    verification_token_env: str

    def __repr__(self) -> str:
        return (
            "M8FeishuWebhookRuntimeAssembly("
            "activation_commit_id="
            f"{self.activation_status.activation_receipt.activation_commit_id!r}, "
            f"bind={self.server.server_address!r}, environment_values=<redacted>)"
        )


def build_m8_feishu_webhook_runtime(
    *,
    database_path: str | Path,
    candidate_authority_id: str,
    encrypt_key_env: str,
    verification_token_env: str,
    runtime_manifest_id: Sha256Hex,
    busy_timeout_ms: int = 5_000,
    clock: Callable[[], datetime] = _default_clock,
) -> M8FeishuWebhookRuntimeAssembly:
    """Build and bind, but never start, one current-authority webhook backend."""

    if not callable(clock):
        raise TypeError("M8 Feishu webhook runtime requires a clock")
    manifest_id = _validate_sha256(runtime_manifest_id, "manifest")
    database = Path(database_path)
    if not database.is_file():
        raise ValueError("M8 Feishu webhook runtime database must already exist")
    activation_repository = SQLiteM8FeishuInboundActivationRepository(
        database,
        busy_timeout_ms,
        manifest_id,
        manifest_id,
    )
    status = activation_repository.get_current_inbound_status(
        candidate_authority_id,
        clock(),
    )
    if not status.sandbox_external_ingress_permitted:
        raise ValueError("M8 Feishu webhook runtime ingress is not currently active")
    profile = status.activation_receipt.runtime_config.profile
    resolver = EnvironmentM8FeishuInboundSecretResolver(
        (
            M8FeishuInboundEnvironmentSecretBinding(
                inbound_profile_id=profile.inbound_profile_id,
                encrypt_key_reference_id=profile.encrypt_key_reference_id,
                verification_token_reference_id=profile.verification_token_reference_id,
                encrypt_key_env=encrypt_key_env,
                verification_token_env=verification_token_env,
            ),
        )
    )
    with resolver.resolve(profile):
        pass

    try:
        from cryptography.hazmat.primitives import padding as _padding
    except ImportError as error:
        raise ContractViolation(
            "M8 Feishu webhook runtime requires the feishu-inbound optional dependency"
        ) from error
    del _padding

    crypto = CryptographyM8FeishuInboundCrypto()
    inbound_repository = SQLiteM8FeishuInboundRepository(
        database,
        busy_timeout_ms,
        manifest_id,
    )
    challenge_sink = SQLiteM8FeishuUrlChallengeReceiptSink(
        database,
        busy_timeout_ms,
        manifest_id,
        manifest_id,
        clock,
    )
    challenge_service = M8FeishuUrlChallengeService(
        resolver,
        crypto,
        clock,
        manifest_id,
    )
    inbound_service = M8FeishuInboundVerificationService(
        inbound_repository,
        resolver,
        crypto,
        clock,
        manifest_id,
        manifest_id,
        manifest_id,
    )
    server = build_m8_feishu_activated_webhook_server(
        candidate_authority_id=candidate_authority_id,
        activation_repository=activation_repository,
        challenge_service=challenge_service,
        inbound_service=inbound_service,
        challenge_receipt_sink=challenge_sink,
        clock=clock,
    )
    return M8FeishuWebhookRuntimeAssembly(
        server=server,
        activation_status=server.startup_status,
        encrypt_key_env=encrypt_key_env,
        verification_token_env=verification_token_env,
    )


__all__ = ["M8FeishuWebhookRuntimeAssembly", "build_m8_feishu_webhook_runtime"]
