from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from labcourt.application.m8_feishu_outbox_authority import (
    commit_m8_feishu_outbox_activation,
)
from labcourt.application.m8_feishu_outbox_runtime import (
    check_m8_feishu_outbox_once,
    run_m8_feishu_outbox_once,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_activation import (
    M8FeishuSandboxRuntimeConfigV1,
    m8_feishu_runtime_config_bytes,
)
from labcourt.contracts.m8_feishu_notification import (
    M8FeishuRecipientBindingAuthorityV1,
)
from labcourt.contracts.m8_notifications import M8NotificationStatus
from labcourt.exceptions import ContractViolation, EvidenceMissing
from tests.contract.test_m8_feishu_notification_contracts import (
    FAKE_FEISHU_APP_ID,
    FAKE_FEISHU_APP_ID_SHA256,
    FAKE_FEISHU_OPEN_ID,
    FAKE_FEISHU_OPEN_ID_SHA256,
)
from tests.integration.test_m8_sqlite_feishu_activation_repository import (
    BASE_TIME,
    BUSY_TIMEOUT_MS,
    SHA_A,
    SHA_B,
    SHA_E,
    _Harness,
    _profile,
    _target,
)
from tests.integration.test_m8_sqlite_feishu_activation_repository import (
    harness as outbox_runtime_harness,  # noqa: F401
)
from tests.integration.test_m8_sqlite_notification_repository import (
    _create_command,
    _plan,
    _queue,
    _workflow,
)
from tests.unit.test_m8_feishu_environment_secrets import FAKE_APP_SECRET
from tests.unit.test_m8_feishu_sandbox_transport import _HttpTransport

APP_ID_ENV = "LABCOURT_TEST_RUNTIME_FEISHU_APP_ID"
APP_SECRET_ENV = "LABCOURT_TEST_RUNTIME_FEISHU_APP_SECRET"
OPEN_ID_ENV = "LABCOURT_TEST_RUNTIME_FEISHU_OPEN_ID"
WORKER_TOKEN_ENV = "LABCOURT_TEST_RUNTIME_FEISHU_WORKER_TOKEN"
WORKER_TOKEN = "offline-feishu-runtime-worker-token-01"


class _Clock:
    def __init__(self, start: datetime) -> None:
        self._current = start

    def __call__(self) -> datetime:
        value = self._current
        self._current += timedelta(seconds=1)
        return value


def _activate_and_queue(authority: _Harness):
    prior = authority.notifications.get_current_target_authority(
        _target().actor_id,
        _target().channel,
    )
    target = _target(revision=2).model_copy(
        update={"external_subject_binding_sha256": FAKE_FEISHU_OPEN_ID_SHA256}
    )
    authority.notifications.publish_target_authority(
        target,
        prior.target.authority_revision,
    )
    profile = _profile().model_copy(update={"app_id_sha256": FAKE_FEISHU_APP_ID_SHA256})
    binding = M8FeishuRecipientBindingAuthorityV1(
        target=target,
        profile_id=profile.profile_id,
        receive_id_reference="feishu-open-id-runtime-student-01",
        receive_id_sha256=FAKE_FEISHU_OPEN_ID_SHA256,
        mapping_revision=1,
        active=True,
        mapping_manifest_id=SHA_B,
    )
    config = M8FeishuSandboxRuntimeConfigV1(
        profile=profile,
        recipient_allowlist=(binding,),
        runtime_config_ref="m8-feishu-outbox-runtime-live-test-01",
        runtime_config_manifest_id=SHA_E,
    )
    raw = m8_feishu_runtime_config_bytes(config)
    intent = authority.intent(
        config,
        assessed_at=BASE_TIME + timedelta(hours=1),
        requested_at=BASE_TIME + timedelta(hours=2),
    )
    intent_document = canonical_json(intent.model_dump(mode="json")).encode("utf-8")
    commit_m8_feishu_outbox_activation(
        database_path=authority.database,
        activation_intent_document=intent_document,
        runtime_config_document=raw,
        runtime_config_storage_manifest_id=SHA_B,
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=lambda: BASE_TIME + timedelta(hours=3),
    )
    student_id = authority.operations.get_current_actor_authority(
        _target().actor_id
    ).authority.actor_id
    case = authority.operations.create_operational_case(
        _create_command(),
        student_id,
        SHA_B,
        SHA_E,
    )
    planned = authority.notifications.create_notification(_plan(case, target), SHA_E)
    queued = authority.notifications.transition_notification(
        _queue(planned),
        (),
        SHA_B,
        SHA_E,
    )
    workflow = _workflow()
    workflow_document = canonical_json(workflow.model_dump(mode="json")).encode("utf-8")
    return config, binding, queued, workflow_document


def _environment() -> dict[str, str]:
    return {
        APP_ID_ENV: FAKE_FEISHU_APP_ID.decode(),
        APP_SECRET_ENV: FAKE_APP_SECRET,
        OPEN_ID_ENV: FAKE_FEISHU_OPEN_ID.decode(),
        WORKER_TOKEN_ENV: WORKER_TOKEN,
    }


def test_outbox_runtime_resolves_exact_environment_and_commits_one_attempt(
    outbox_runtime_harness: _Harness,  # noqa: F811
) -> None:
    config, binding, queued, workflow_document = _activate_and_queue(
        outbox_runtime_harness
    )
    http = _HttpTransport()

    checked = check_m8_feishu_outbox_once(
        database_path=outbox_runtime_harness.database,
        notification_id=queued.notification_id,
        candidate_authority_id=config.profile.candidate.candidate_authority_id,
        recipient_binding_authority_id=binding.binding_authority_id,
        workflow_document=workflow_document,
        app_id_env=APP_ID_ENV,
        app_secret_env=APP_SECRET_ENV,
        receive_id_env=OPEN_ID_ENV,
        worker_token_env=WORKER_TOKEN_ENV,
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        runtime_manifest_id=SHA_B,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=_Clock(BASE_TIME + timedelta(hours=4)),
        environment=_environment(),
    )
    assert checked.secrets_validated is True
    assert checked.dispatch_claim_created is False
    assert checked.external_call_attempted is False
    assert WORKER_TOKEN not in repr(checked)
    with pytest.raises(EvidenceMissing):
        outbox_runtime_harness.notifications.get_dispatch_claim_status_for_source(
            queued.notification_id,
            queued.notification_version,
            BASE_TIME + timedelta(hours=4),
        )
    assert outbox_runtime_harness.notifications.get_current_notification(
        queued.notification_id
    ) == queued

    receipt = run_m8_feishu_outbox_once(
        database_path=outbox_runtime_harness.database,
        notification_id=queued.notification_id,
        candidate_authority_id=config.profile.candidate.candidate_authority_id,
        recipient_binding_authority_id=binding.binding_authority_id,
        workflow_document=workflow_document,
        app_id_env=APP_ID_ENV,
        app_secret_env=APP_SECRET_ENV,
        receive_id_env=OPEN_ID_ENV,
        worker_token_env=WORKER_TOKEN_ENV,
        repository_manifest_id=SHA_A,
        assessment_manifest_id=SHA_E,
        runtime_manifest_id=SHA_B,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=_Clock(BASE_TIME + timedelta(hours=4)),
        environment=_environment(),
        http_transport=http,
    )

    assert receipt.notification_status == M8NotificationStatus.SENT
    assert receipt.provider_acceptance_confirmed is True
    assert receipt.real_delivery_confirmed is False
    assert receipt.automatic_retry_permitted is False
    assert http.token_calls == 1
    assert http.message_calls == 1


def test_outbox_runtime_missing_secret_fails_before_claim_or_http(
    outbox_runtime_harness: _Harness,  # noqa: F811
) -> None:
    config, binding, queued, workflow_document = _activate_and_queue(
        outbox_runtime_harness
    )
    environment = _environment()
    del environment[APP_SECRET_ENV]
    http = _HttpTransport()

    with pytest.raises(ContractViolation, match="ENVIRONMENT_VALUE_MISSING"):
        run_m8_feishu_outbox_once(
            database_path=outbox_runtime_harness.database,
            notification_id=queued.notification_id,
            candidate_authority_id=config.profile.candidate.candidate_authority_id,
            recipient_binding_authority_id=binding.binding_authority_id,
            workflow_document=workflow_document,
            app_id_env=APP_ID_ENV,
            app_secret_env=APP_SECRET_ENV,
            receive_id_env=OPEN_ID_ENV,
            worker_token_env=WORKER_TOKEN_ENV,
            repository_manifest_id=SHA_A,
            assessment_manifest_id=SHA_E,
            runtime_manifest_id=SHA_B,
            busy_timeout_ms=BUSY_TIMEOUT_MS,
            clock=_Clock(BASE_TIME + timedelta(hours=4)),
            environment=environment,
            http_transport=http,
        )

    assert outbox_runtime_harness.notifications.get_current_notification(
        queued.notification_id
    ) == queued
    assert http.token_calls == 0
    assert http.message_calls == 0
