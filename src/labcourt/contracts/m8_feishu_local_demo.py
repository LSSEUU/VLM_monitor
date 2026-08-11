"""Local-only Windows personal-demo configuration for Feishu integration."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import SecretStr, ValidationInfo, field_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.frames import Sha256Hex

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_MAX_LOCAL_PATH_CHARS = 4_096
_MAX_SECRET_CHARS = 8_192


def _require_local_path(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_LOCAL_PATH_CHARS
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"M8 Feishu local demo {name} is invalid")
    return value


class M8FeishuLocalDemoCredentialsV1(FrozenContractModel):
    """Plaintext values allowed only in the ignored local personal-demo file."""

    app_id: SecretStr
    app_secret: SecretStr
    test_open_id: SecretStr
    encrypt_key: SecretStr
    verification_token: SecretStr
    worker_token: SecretStr

    @field_validator("*")
    @classmethod
    def validate_secret_shape(
        cls,
        value: SecretStr,
        info: ValidationInfo,
    ) -> SecretStr:
        plaintext = value.get_secret_value()
        minimum = 32 if info.field_name == "worker_token" else 1
        maximum = 256 if info.field_name == "worker_token" else _MAX_SECRET_CHARS
        if (
            not minimum <= len(plaintext) <= maximum
            or any(
                character.isspace() or ord(character) < 0x20
                for character in plaintext
            )
        ):
            raise ValueError("M8 Feishu local demo credentials reject whitespace/control")
        return value


class M8FeishuLocalDemoEnvironmentNamesV1(FrozenContractModel):
    app_id: str
    app_secret: str
    test_open_id: str
    encrypt_key: str
    verification_token: str
    worker_token: str

    @field_validator("*")
    @classmethod
    def validate_environment_name(cls, value: str) -> str:
        if _ENV_NAME.fullmatch(value) is None:
            raise ValueError("M8 Feishu local demo environment name is invalid")
        return value


class M8FeishuLocalDemoActivationFilesV1(FrozenContractModel):
    activation_intent_path: str
    runtime_config_path: str
    runtime_config_storage_manifest_id: Sha256Hex

    @field_validator("activation_intent_path", "runtime_config_path")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _require_local_path(value, "activation artifact path")


class M8FeishuLocalDemoRuntimeV1(FrozenContractModel):
    database_path: str
    candidate_authority_id: Sha256Hex
    recipient_binding_authority_id: Sha256Hex
    notification_id: Sha256Hex
    workflow_path: str
    repository_manifest_id: Sha256Hex
    assessment_manifest_id: Sha256Hex
    runtime_manifest_id: Sha256Hex

    @field_validator("database_path", "workflow_path")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _require_local_path(value, "runtime artifact path")


class M8FeishuLocalDemoConfigV1(FrozenContractModel):
    """Strict local file contract; its repr/JSON serialization redacts secret values."""

    schema_version: Literal["m8-feishu-local-demo-config-v1"] = (
        "m8-feishu-local-demo-config-v1"
    )
    display_badge: Literal["PERSONAL DEMO · LOCAL PLAINTEXT CREDENTIALS"] = (
        "PERSONAL DEMO · LOCAL PLAINTEXT CREDENTIALS"
    )
    credentials: M8FeishuLocalDemoCredentialsV1
    environment_names: M8FeishuLocalDemoEnvironmentNamesV1
    runtime: M8FeishuLocalDemoRuntimeV1
    outbox_activation: M8FeishuLocalDemoActivationFilesV1
    webhook_activation: M8FeishuLocalDemoActivationFilesV1
    personal_demo_only: Literal[True] = True
    plaintext_credentials_persisted_locally: Literal[True] = True
    default_preflight_required: Literal[True] = True
    public_https_managed_by_scripts: Literal[False] = False
    automatic_send_permitted: Literal[False] = False
    production_ready: Literal[False] = False
    case_transition_permitted: Literal[False] = False
    direct_disciplinary_action_permitted: Literal[False] = False


__all__ = [
    "M8FeishuLocalDemoActivationFilesV1",
    "M8FeishuLocalDemoConfigV1",
    "M8FeishuLocalDemoCredentialsV1",
    "M8FeishuLocalDemoEnvironmentNamesV1",
    "M8FeishuLocalDemoRuntimeV1",
]
