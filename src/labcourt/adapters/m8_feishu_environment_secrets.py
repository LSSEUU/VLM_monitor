"""Explicit environment-reference resolver for ephemeral Feishu sandbox secrets."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_feishu_secrets import M8FeishuResolvedSecrets

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_MAX_SECRET_CHARS = 8_192


class M8FeishuSecretResolutionFailureCode(StrEnum):
    APP_ID_HASH_MISMATCH = "APP_ID_HASH_MISMATCH"
    BINDING_NOT_CONFIGURED = "BINDING_NOT_CONFIGURED"
    ENVIRONMENT_VALUE_INVALID = "ENVIRONMENT_VALUE_INVALID"
    ENVIRONMENT_VALUE_MISSING = "ENVIRONMENT_VALUE_MISSING"
    PROFILE_NOT_CONFIGURED = "PROFILE_NOT_CONFIGURED"
    RECEIVE_ID_HASH_MISMATCH = "RECEIVE_ID_HASH_MISMATCH"


class M8FeishuSecretResolutionError(ContractViolation):
    def __init__(self, code: M8FeishuSecretResolutionFailureCode) -> None:
        if not isinstance(code, M8FeishuSecretResolutionFailureCode):
            raise TypeError("code must be M8FeishuSecretResolutionFailureCode")
        self.code = code
        super().__init__(f"M8 Feishu secret resolution failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M8FeishuEnvironmentSecretBinding:
    credential_bundle_reference_id: str
    app_id_env: str
    app_secret_env: str
    receive_id_env_by_reference: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not self.credential_bundle_reference_id:
            raise ValueError("M8 Feishu credential reference cannot be empty")
        env_names = (
            self.app_id_env,
            self.app_secret_env,
            *(item[1] for item in self.receive_id_env_by_reference),
        )
        if any(_ENV_NAME.fullmatch(name) is None for name in env_names):
            raise ValueError("M8 Feishu environment variable name is invalid")
        references = tuple(item[0] for item in self.receive_id_env_by_reference)
        if (
            not references
            or any(not reference for reference in references)
            or references != tuple(sorted(references))
            or len(references) != len(set(references))
            or len(env_names) != len(set(env_names))
        ):
            raise ValueError("M8 Feishu environment secret mapping is not closed and stable")


class EnvironmentM8FeishuSecretResolver:
    """Resolve only explicitly mapped environment names and never retain copied values."""

    def __init__(
        self,
        bindings: tuple[M8FeishuEnvironmentSecretBinding, ...],
        *,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        references = tuple(item.credential_bundle_reference_id for item in bindings)
        if not references or references != tuple(sorted(references)):
            raise ValueError("M8 Feishu secret bindings must use stable reference order")
        if len(references) != len(set(references)):
            raise ValueError("M8 Feishu secret bindings cannot duplicate references")
        self._bindings = {item.credential_bundle_reference_id: item for item in bindings}
        self._environment = os.environ if environment is None else environment

    def __repr__(self) -> str:
        return (
            "EnvironmentM8FeishuSecretResolver("
            f"configured_profiles={len(self._bindings)}, values_redacted=True)"
        )

    def resolve(
        self,
        profile: M8FeishuAdapterProfileV1,
        recipient_binding: M8FeishuRecipientBindingAuthorityV1,
    ) -> M8FeishuResolvedSecrets:
        if not isinstance(profile, M8FeishuAdapterProfileV1):
            raise TypeError("M8 Feishu secret resolution requires a typed profile")
        if not isinstance(recipient_binding, M8FeishuRecipientBindingAuthorityV1):
            raise TypeError("M8 Feishu secret resolution requires a typed recipient binding")
        configured = self._bindings.get(profile.credential_bundle_reference_id)
        if configured is None:
            raise M8FeishuSecretResolutionError(
                M8FeishuSecretResolutionFailureCode.PROFILE_NOT_CONFIGURED
            )
        receive_env = dict(configured.receive_id_env_by_reference).get(
            recipient_binding.receive_id_reference
        )
        if receive_env is None:
            raise M8FeishuSecretResolutionError(
                M8FeishuSecretResolutionFailureCode.BINDING_NOT_CONFIGURED
            )
        app_id = self._read(configured.app_id_env)
        if not hmac.compare_digest(
            hashlib.sha256(app_id).hexdigest(),
            profile.app_id_sha256,
        ):
            raise M8FeishuSecretResolutionError(
                M8FeishuSecretResolutionFailureCode.APP_ID_HASH_MISMATCH
            )
        receive_id = self._read(receive_env)
        if not hmac.compare_digest(
            hashlib.sha256(receive_id).hexdigest(),
            recipient_binding.receive_id_sha256,
        ):
            raise M8FeishuSecretResolutionError(
                M8FeishuSecretResolutionFailureCode.RECEIVE_ID_HASH_MISMATCH
            )
        app_secret = self._read(configured.app_secret_env)
        return M8FeishuResolvedSecrets(
            profile_id=profile.profile_id,
            binding_authority_id=recipient_binding.binding_authority_id,
            credential_bundle_reference_id=profile.credential_bundle_reference_id,
            app_id=app_id,
            app_secret=app_secret,
            open_id=receive_id,
        )

    def _read(self, env_name: str) -> bytes:
        value = self._environment.get(env_name)
        if value is None or value == "":
            raise M8FeishuSecretResolutionError(
                M8FeishuSecretResolutionFailureCode.ENVIRONMENT_VALUE_MISSING
            )
        if (
            not isinstance(value, str)
            or len(value) > _MAX_SECRET_CHARS
            or any(character.isspace() or ord(character) < 0x20 for character in value)
        ):
            raise M8FeishuSecretResolutionError(
                M8FeishuSecretResolutionFailureCode.ENVIRONMENT_VALUE_INVALID
            )
        return value.encode("utf-8")


__all__ = [
    "EnvironmentM8FeishuSecretResolver",
    "M8FeishuEnvironmentSecretBinding",
    "M8FeishuSecretResolutionError",
    "M8FeishuSecretResolutionFailureCode",
]
