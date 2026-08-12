"""Explicit environment-reference resolver for encrypted Feishu inbound events."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundWebhookProfileV1
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_feishu_inbound_secrets import M8FeishuInboundResolvedSecrets

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_MAX_SECRET_CHARS = 8_192


class M8FeishuInboundSecretResolutionFailureCode(StrEnum):
    ENCRYPT_KEY_HASH_MISMATCH = "ENCRYPT_KEY_HASH_MISMATCH"
    ENVIRONMENT_VALUE_INVALID = "ENVIRONMENT_VALUE_INVALID"
    ENVIRONMENT_VALUE_MISSING = "ENVIRONMENT_VALUE_MISSING"
    PROFILE_NOT_CONFIGURED = "PROFILE_NOT_CONFIGURED"
    PROFILE_REFERENCE_MISMATCH = "PROFILE_REFERENCE_MISMATCH"
    VERIFICATION_TOKEN_HASH_MISMATCH = "VERIFICATION_TOKEN_HASH_MISMATCH"


class M8FeishuInboundSecretResolutionError(ContractViolation):
    def __init__(self, code: M8FeishuInboundSecretResolutionFailureCode) -> None:
        if not isinstance(code, M8FeishuInboundSecretResolutionFailureCode):
            raise TypeError("code must be M8FeishuInboundSecretResolutionFailureCode")
        self.code = code
        super().__init__(f"M8 Feishu inbound secret resolution failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M8FeishuInboundEnvironmentSecretBinding:
    inbound_profile_id: str
    encrypt_key_reference_id: str
    verification_token_reference_id: str
    encrypt_key_env: str
    verification_token_env: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (
                self.inbound_profile_id,
                self.encrypt_key_reference_id,
                self.verification_token_reference_id,
            )
        ):
            raise ValueError("M8 Feishu inbound secret references cannot be empty")
        if (
            _ENV_NAME.fullmatch(self.encrypt_key_env) is None
            or _ENV_NAME.fullmatch(self.verification_token_env) is None
            or self.encrypt_key_env == self.verification_token_env
        ):
            raise ValueError("M8 Feishu inbound environment names are invalid or reused")


class EnvironmentM8FeishuInboundSecretResolver:
    """Resolve only allowlisted environment names into a zeroizable short-lived lease."""

    def __init__(
        self,
        bindings: tuple[M8FeishuInboundEnvironmentSecretBinding, ...],
        *,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        profile_ids = tuple(item.inbound_profile_id for item in bindings)
        if not profile_ids or profile_ids != tuple(sorted(profile_ids)):
            raise ValueError("M8 Feishu inbound secret bindings must use stable profile order")
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("M8 Feishu inbound secret bindings cannot duplicate profiles")
        env_names = tuple(
            name
            for item in bindings
            for name in (item.encrypt_key_env, item.verification_token_env)
        )
        if len(env_names) != len(set(env_names)):
            raise ValueError("M8 Feishu inbound environment names cannot be reused")
        self._bindings = {item.inbound_profile_id: item for item in bindings}
        self._environment = os.environ if environment is None else environment

    def __repr__(self) -> str:
        return (
            "EnvironmentM8FeishuInboundSecretResolver("
            f"configured_profiles={len(self._bindings)}, values_redacted=True)"
        )

    def resolve(
        self,
        profile: M8FeishuInboundWebhookProfileV1,
    ) -> M8FeishuInboundResolvedSecrets:
        if not isinstance(profile, M8FeishuInboundWebhookProfileV1):
            raise TypeError("M8 Feishu inbound secret resolution requires a typed profile")
        configured = self._bindings.get(profile.inbound_profile_id)
        if configured is None:
            raise M8FeishuInboundSecretResolutionError(
                M8FeishuInboundSecretResolutionFailureCode.PROFILE_NOT_CONFIGURED
            )
        if (
            configured.encrypt_key_reference_id != profile.encrypt_key_reference_id
            or configured.verification_token_reference_id
            != profile.verification_token_reference_id
        ):
            raise M8FeishuInboundSecretResolutionError(
                M8FeishuInboundSecretResolutionFailureCode.PROFILE_REFERENCE_MISMATCH
            )
        encrypt_key = self._read(configured.encrypt_key_env)
        if not hmac.compare_digest(
            hashlib.sha256(encrypt_key).hexdigest(),
            profile.encrypt_key_sha256,
        ):
            raise M8FeishuInboundSecretResolutionError(
                M8FeishuInboundSecretResolutionFailureCode.ENCRYPT_KEY_HASH_MISMATCH
            )
        verification_token = self._read(configured.verification_token_env)
        if not hmac.compare_digest(
            hashlib.sha256(verification_token).hexdigest(),
            profile.verification_token_sha256,
        ):
            raise M8FeishuInboundSecretResolutionError(
                M8FeishuInboundSecretResolutionFailureCode.VERIFICATION_TOKEN_HASH_MISMATCH
            )
        return M8FeishuInboundResolvedSecrets(
            inbound_profile_id=profile.inbound_profile_id,
            encrypt_key_reference_id=profile.encrypt_key_reference_id,
            verification_token_reference_id=profile.verification_token_reference_id,
            encrypt_key=encrypt_key,
            verification_token=verification_token,
        )

    def _read(self, env_name: str) -> bytes:
        value = self._environment.get(env_name)
        if value is None or value == "":
            raise M8FeishuInboundSecretResolutionError(
                M8FeishuInboundSecretResolutionFailureCode.ENVIRONMENT_VALUE_MISSING
            )
        if (
            not isinstance(value, str)
            or len(value) > _MAX_SECRET_CHARS
            or any(character.isspace() or ord(character) < 0x20 for character in value)
        ):
            raise M8FeishuInboundSecretResolutionError(
                M8FeishuInboundSecretResolutionFailureCode.ENVIRONMENT_VALUE_INVALID
            )
        return value.encode("utf-8")


__all__ = [
    "EnvironmentM8FeishuInboundSecretResolver",
    "M8FeishuInboundEnvironmentSecretBinding",
    "M8FeishuInboundSecretResolutionError",
    "M8FeishuInboundSecretResolutionFailureCode",
]
