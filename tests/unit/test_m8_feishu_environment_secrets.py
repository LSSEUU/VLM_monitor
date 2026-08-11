from __future__ import annotations

import pytest

from labcourt.adapters.m8_feishu_environment_secrets import (
    EnvironmentM8FeishuSecretResolver,
    M8FeishuEnvironmentSecretBinding,
    M8FeishuSecretResolutionError,
    M8FeishuSecretResolutionFailureCode,
)
from tests.contract.test_m8_feishu_notification_contracts import (
    FAKE_FEISHU_APP_ID,
    FAKE_FEISHU_OPEN_ID,
    _binding,
    _profile,
)

APP_ID_ENV = "LABCOURT_TEST_FEISHU_APP_ID"
APP_SECRET_ENV = "LABCOURT_TEST_FEISHU_APP_SECRET"
OPEN_ID_ENV = "LABCOURT_TEST_FEISHU_OPEN_ID_STUDENT_01"
FAKE_APP_SECRET = "fake_labcourt_feishu_app_secret"


def _configured_binding() -> M8FeishuEnvironmentSecretBinding:
    return M8FeishuEnvironmentSecretBinding(
        credential_bundle_reference_id=_profile().credential_bundle_reference_id,
        app_id_env=APP_ID_ENV,
        app_secret_env=APP_SECRET_ENV,
        receive_id_env_by_reference=((_binding().receive_id_reference, OPEN_ID_ENV),),
    )


def _environment() -> dict[str, str]:
    return {
        APP_ID_ENV: FAKE_FEISHU_APP_ID.decode(),
        APP_SECRET_ENV: FAKE_APP_SECRET,
        OPEN_ID_ENV: FAKE_FEISHU_OPEN_ID.decode(),
    }


def test_environment_resolver_uses_only_explicit_references_and_redacts_repr() -> None:
    resolver = EnvironmentM8FeishuSecretResolver(
        (_configured_binding(),),
        environment=_environment(),
    )

    assert "fake_" not in repr(resolver)
    with resolver.resolve(_profile(), _binding()) as secrets:
        assert secrets.app_id_bytes() == FAKE_FEISHU_APP_ID
        assert secrets.app_secret_bytes() == FAKE_APP_SECRET.encode()
        assert secrets.open_id_bytes() == FAKE_FEISHU_OPEN_ID
        assert "fake_" not in repr(secrets)

    with pytest.raises(RuntimeError, match="lease is closed"):
        secrets.app_secret_bytes()


@pytest.mark.parametrize("missing_name", [APP_ID_ENV, APP_SECRET_ENV, OPEN_ID_ENV])
def test_environment_resolver_fails_closed_when_a_value_is_missing(missing_name: str) -> None:
    environment = _environment()
    del environment[missing_name]
    resolver = EnvironmentM8FeishuSecretResolver(
        (_configured_binding(),),
        environment=environment,
    )

    with pytest.raises(M8FeishuSecretResolutionError) as raised:
        resolver.resolve(_profile(), _binding())

    assert raised.value.code == M8FeishuSecretResolutionFailureCode.ENVIRONMENT_VALUE_MISSING
    assert "fake_" not in str(raised.value)


def test_environment_resolver_rejects_hash_drift_without_returning_values() -> None:
    environment = _environment()
    environment[APP_ID_ENV] = "cli_fake_wrong_app"
    resolver = EnvironmentM8FeishuSecretResolver(
        (_configured_binding(),),
        environment=environment,
    )

    with pytest.raises(M8FeishuSecretResolutionError) as raised:
        resolver.resolve(_profile(), _binding())
    assert raised.value.code == M8FeishuSecretResolutionFailureCode.APP_ID_HASH_MISMATCH

    environment = _environment()
    environment[OPEN_ID_ENV] = "ou_fake_wrong_student"
    resolver = EnvironmentM8FeishuSecretResolver(
        (_configured_binding(),),
        environment=environment,
    )
    with pytest.raises(M8FeishuSecretResolutionError) as raised:
        resolver.resolve(_profile(), _binding())
    assert raised.value.code == M8FeishuSecretResolutionFailureCode.RECEIVE_ID_HASH_MISMATCH


def test_environment_resolver_rejects_unconfigured_profile_and_binding() -> None:
    resolver = EnvironmentM8FeishuSecretResolver(
        (_configured_binding(),),
        environment=_environment(),
    )
    another_profile = _profile().model_copy(
        update={"credential_bundle_reference_id": "secret-feishu-unconfigured"}
    )
    with pytest.raises(M8FeishuSecretResolutionError) as raised:
        resolver.resolve(another_profile, _binding())
    assert raised.value.code == M8FeishuSecretResolutionFailureCode.PROFILE_NOT_CONFIGURED

    another_binding = _binding().model_copy(
        update={"receive_id_reference": "feishu-open-id-unconfigured"}
    )
    with pytest.raises(M8FeishuSecretResolutionError) as raised:
        resolver.resolve(_profile(), another_binding)
    assert raised.value.code == M8FeishuSecretResolutionFailureCode.BINDING_NOT_CONFIGURED


@pytest.mark.parametrize(
    "binding",
    [
        M8FeishuEnvironmentSecretBinding(
            credential_bundle_reference_id="a",
            app_id_env="APP_ID",
            app_secret_env="APP_SECRET",
            receive_id_env_by_reference=(("actor-b", "OPEN_ID_B"),),
        ),
        M8FeishuEnvironmentSecretBinding(
            credential_bundle_reference_id="b",
            app_id_env="APP_ID_2",
            app_secret_env="APP_SECRET_2",
            receive_id_env_by_reference=(("actor-a", "OPEN_ID_A"),),
        ),
    ],
)
def test_environment_resolver_requires_stable_unique_profile_order(
    binding: M8FeishuEnvironmentSecretBinding,
) -> None:
    first, second = (
        M8FeishuEnvironmentSecretBinding(
            credential_bundle_reference_id="a",
            app_id_env="APP_ID",
            app_secret_env="APP_SECRET",
            receive_id_env_by_reference=(("actor-b", "OPEN_ID_B"),),
        ),
        M8FeishuEnvironmentSecretBinding(
            credential_bundle_reference_id="b",
            app_id_env="APP_ID_2",
            app_secret_env="APP_SECRET_2",
            receive_id_env_by_reference=(("actor-a", "OPEN_ID_A"),),
        ),
    )
    if binding.credential_bundle_reference_id == "a":
        with pytest.raises(ValueError, match="stable reference order"):
            EnvironmentM8FeishuSecretResolver((second, first), environment={})
    else:
        with pytest.raises(ValueError, match="duplicate"):
            EnvironmentM8FeishuSecretResolver((second, second), environment={})


def test_environment_binding_rejects_implicit_or_ambiguous_mapping() -> None:
    with pytest.raises(ValueError, match="variable name"):
        M8FeishuEnvironmentSecretBinding(
            credential_bundle_reference_id="secret-ref",
            app_id_env="lowercase_name",
            app_secret_env="APP_SECRET",
            receive_id_env_by_reference=(("actor-a", "OPEN_ID_A"),),
        )
    with pytest.raises(ValueError, match="closed and stable"):
        M8FeishuEnvironmentSecretBinding(
            credential_bundle_reference_id="secret-ref",
            app_id_env="APP_ID",
            app_secret_env="APP_SECRET",
            receive_id_env_by_reference=(),
        )
    with pytest.raises(ValueError, match="closed and stable"):
        M8FeishuEnvironmentSecretBinding(
            credential_bundle_reference_id="secret-ref",
            app_id_env="APP_ID",
            app_secret_env="APP_ID",
            receive_id_env_by_reference=(("actor-a", "OPEN_ID_A"),),
        )
