from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m8_feishu_local_demo import M8FeishuLocalDemoConfigV1
from labcourt.schema_registry import SCHEMA_MODELS

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def _payload() -> dict[str, object]:
    return {
        "schema_version": "m8-feishu-local-demo-config-v1",
        "display_badge": "PERSONAL DEMO · LOCAL PLAINTEXT CREDENTIALS",
        "credentials": {
            "app_id": "cli_demo_app_id",
            "app_secret": "demo_app_secret",
            "test_open_id": "ou_demo_test_student",
            "encrypt_key": "demo_encrypt_key",
            "verification_token": "demo_verification_token",
            "worker_token": "demo-worker-token-at-least-32-bytes",
        },
        "environment_names": {
            "app_id": "LABCOURT_FEISHU_APP_ID",
            "app_secret": "LABCOURT_FEISHU_APP_SECRET",
            "test_open_id": "LABCOURT_FEISHU_TEST_OPEN_ID",
            "encrypt_key": "LABCOURT_FEISHU_ENCRYPT_KEY",
            "verification_token": "LABCOURT_FEISHU_VERIFICATION_TOKEN",
            "worker_token": "LABCOURT_FEISHU_WORKER_TOKEN",
        },
        "runtime": {
            "database_path": ".labcourt-local/labcourt.sqlite3",
            "candidate_authority_id": SHA_A,
            "recipient_binding_authority_id": SHA_B,
            "notification_id": SHA_C,
            "workflow_path": ".labcourt-local/notification-workflow.json",
            "repository_manifest_id": SHA_A,
            "assessment_manifest_id": SHA_B,
            "runtime_manifest_id": SHA_C,
        },
        "outbox_activation": {
            "activation_intent_path": ".labcourt-local/outbox-activation-intent.json",
            "runtime_config_path": ".labcourt-local/outbox-runtime-config.json",
            "runtime_config_storage_manifest_id": SHA_A,
        },
        "webhook_activation": {
            "activation_intent_path": ".labcourt-local/webhook-activation-intent.json",
            "runtime_config_path": ".labcourt-local/webhook-runtime-config.json",
            "runtime_config_storage_manifest_id": SHA_B,
        },
        "personal_demo_only": True,
        "plaintext_credentials_persisted_locally": True,
        "default_preflight_required": True,
        "public_https_managed_by_scripts": False,
        "automatic_send_permitted": False,
        "production_ready": False,
        "case_transition_permitted": False,
        "direct_disciplinary_action_permitted": False,
    }


def test_local_demo_config_is_strict_and_redacts_every_plaintext_secret() -> None:
    config = M8FeishuLocalDemoConfigV1.model_validate(_payload())

    rendered = repr(config) + config.model_dump_json()
    credentials = _payload()["credentials"]
    assert isinstance(credentials, dict)
    for value in credentials.values():
        assert str(value) not in rendered
    assert config.personal_demo_only is True
    assert config.production_ready is False
    assert config.automatic_send_permitted is False


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("credentials", "app_secret"), "contains whitespace"),
        (("credentials", "worker_token"), "too-short"),
        (("environment_names", "app_id"), "lowercase-name"),
        (("runtime", "database_path"), "bad\npath"),
    ),
)
def test_local_demo_config_rejects_unsafe_values(
    path: tuple[str, str],
    value: str,
) -> None:
    payload = _payload()
    nested = payload[path[0]]
    assert isinstance(nested, dict)
    nested[path[1]] = value

    with pytest.raises(ValidationError):
        M8FeishuLocalDemoConfigV1.model_validate(payload)


def test_local_demo_config_rejects_claims_that_widen_demo_authority() -> None:
    payload = _payload()
    payload["production_ready"] = True

    with pytest.raises(ValidationError):
        M8FeishuLocalDemoConfigV1.model_validate(payload)


def test_local_demo_schema_is_registered_and_validates_serialized_shape() -> None:
    assert SCHEMA_MODELS["m8-feishu-local-demo-config-v1"] is M8FeishuLocalDemoConfigV1
    schema = M8FeishuLocalDemoConfigV1.model_json_schema(mode="serialization")
    Draft202012Validator.check_schema(schema)
    serialized = json.loads(M8FeishuLocalDemoConfigV1.model_validate(_payload()).model_dump_json())
    Draft202012Validator(schema).validate(serialized)
