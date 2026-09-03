from __future__ import annotations

import hashlib

import pytest

from labcourt.adapters.m8_feishu_inbound_environment_secrets import (
    EnvironmentM8FeishuInboundSecretResolver,
    M8FeishuInboundEnvironmentSecretBinding,
    M8FeishuInboundSecretResolutionError,
    M8FeishuInboundSecretResolutionFailureCode,
)
from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundWebhookProfileV1
from tests.contract.test_m8_feishu_inbound_contracts import _webhook_profile

ENCRYPT_KEY = "fake-encrypt-key-for-environment"
VERIFICATION_TOKEN = "fake-verification-token-for-environment"


def _profile() -> M8FeishuInboundWebhookProfileV1:
    return _webhook_profile().model_copy(
        update={
            "encrypt_key_sha256": hashlib.sha256(ENCRYPT_KEY.encode()).hexdigest(),
            "verification_token_sha256": hashlib.sha256(VERIFICATION_TOKEN.encode()).hexdigest(),
        }
    )


def _binding(
    profile: M8FeishuInboundWebhookProfileV1 | None = None,
) -> M8FeishuInboundEnvironmentSecretBinding:
    resolved = profile or _profile()
    return M8FeishuInboundEnvironmentSecretBinding(
        inbound_profile_id=resolved.inbound_profile_id,
        encrypt_key_reference_id=resolved.encrypt_key_reference_id,
        verification_token_reference_id=resolved.verification_token_reference_id,
        encrypt_key_env="LABCOURT_FEISHU_INBOUND_ENCRYPT_KEY",
        verification_token_env="LABCOURT_FEISHU_INBOUND_VERIFICATION_TOKEN",
    )


def _resolver(
    environment: dict[str, str] | None = None,
) -> EnvironmentM8FeishuInboundSecretResolver:
    return EnvironmentM8FeishuInboundSecretResolver(
        (_binding(),),
        environment=(
            environment
            or {
                "LABCOURT_FEISHU_INBOUND_ENCRYPT_KEY": ENCRYPT_KEY,
                "LABCOURT_FEISHU_INBOUND_VERIFICATION_TOKEN": VERIFICATION_TOKEN,
            }
        ),
    )


def test_resolver_returns_exact_zeroizable_lease_without_repr_disclosure() -> None:
    resolver = _resolver()
    lease = resolver.resolve(_profile())

    assert lease.encrypt_key_bytes() == ENCRYPT_KEY.encode()
    assert lease.verification_token_bytes() == VERIFICATION_TOKEN.encode()
    assert ENCRYPT_KEY not in repr(resolver)
    assert VERIFICATION_TOKEN not in repr(resolver)
    assert ENCRYPT_KEY not in repr(lease)
    assert VERIFICATION_TOKEN not in repr(lease)

    lease.close()
    with pytest.raises(RuntimeError, match="closed"):
        lease.encrypt_key_bytes()


@pytest.mark.parametrize(
    ("environment", "code"),
    (
        (
            {"LABCOURT_FEISHU_INBOUND_VERIFICATION_TOKEN": VERIFICATION_TOKEN},
            M8FeishuInboundSecretResolutionFailureCode.ENVIRONMENT_VALUE_MISSING,
        ),
        (
            {
                "LABCOURT_FEISHU_INBOUND_ENCRYPT_KEY": "bad key with spaces",
                "LABCOURT_FEISHU_INBOUND_VERIFICATION_TOKEN": VERIFICATION_TOKEN,
            },
            M8FeishuInboundSecretResolutionFailureCode.ENVIRONMENT_VALUE_INVALID,
        ),
        (
            {
                "LABCOURT_FEISHU_INBOUND_ENCRYPT_KEY": "wrong-encrypt-key",
                "LABCOURT_FEISHU_INBOUND_VERIFICATION_TOKEN": VERIFICATION_TOKEN,
            },
            M8FeishuInboundSecretResolutionFailureCode.ENCRYPT_KEY_HASH_MISMATCH,
        ),
        (
            {
                "LABCOURT_FEISHU_INBOUND_ENCRYPT_KEY": ENCRYPT_KEY,
                "LABCOURT_FEISHU_INBOUND_VERIFICATION_TOKEN": "wrong-token",
            },
            M8FeishuInboundSecretResolutionFailureCode.VERIFICATION_TOKEN_HASH_MISMATCH,
        ),
    ),
)
def test_resolver_fails_closed_with_typed_sanitized_errors(
    environment: dict[str, str],
    code: M8FeishuInboundSecretResolutionFailureCode,
) -> None:
    with pytest.raises(M8FeishuInboundSecretResolutionError) as captured:
        _resolver(environment).resolve(_profile())

    assert captured.value.code == code
    assert ENCRYPT_KEY not in str(captured.value)
    assert VERIFICATION_TOKEN not in str(captured.value)


def test_resolver_rejects_unknown_profile_or_reference_graft() -> None:
    profile = _profile()
    unknown = profile.model_copy(update={"profile_manifest_id": "f" * 64})
    with pytest.raises(M8FeishuInboundSecretResolutionError) as captured:
        _resolver().resolve(unknown)
    assert captured.value.code == M8FeishuInboundSecretResolutionFailureCode.PROFILE_NOT_CONFIGURED

    grafted = _binding(profile)
    grafted = M8FeishuInboundEnvironmentSecretBinding(
        inbound_profile_id=grafted.inbound_profile_id,
        encrypt_key_reference_id="foreign-encrypt-key-reference",
        verification_token_reference_id=grafted.verification_token_reference_id,
        encrypt_key_env=grafted.encrypt_key_env,
        verification_token_env=grafted.verification_token_env,
    )
    resolver = EnvironmentM8FeishuInboundSecretResolver(
        (grafted,),
        environment={
            grafted.encrypt_key_env: ENCRYPT_KEY,
            grafted.verification_token_env: VERIFICATION_TOKEN,
        },
    )
    with pytest.raises(M8FeishuInboundSecretResolutionError) as captured:
        resolver.resolve(profile)
    assert (
        captured.value.code == M8FeishuInboundSecretResolutionFailureCode.PROFILE_REFERENCE_MISMATCH
    )


def test_secret_binding_requires_stable_unique_profiles_and_environment_names() -> None:
    binding = _binding()
    with pytest.raises(ValueError, match="duplicate profiles"):
        EnvironmentM8FeishuInboundSecretResolver((binding, binding))
    with pytest.raises(ValueError, match="invalid or reused"):
        M8FeishuInboundEnvironmentSecretBinding(
            inbound_profile_id=binding.inbound_profile_id,
            encrypt_key_reference_id=binding.encrypt_key_reference_id,
            verification_token_reference_id=binding.verification_token_reference_id,
            encrypt_key_env="SHARED_ENV",
            verification_token_env="SHARED_ENV",
        )
