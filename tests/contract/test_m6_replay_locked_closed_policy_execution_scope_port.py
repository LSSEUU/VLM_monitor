from __future__ import annotations

import hashlib
import inspect
from dataclasses import FrozenInstanceError

import pytest

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
)
from labcourt.ports.m6_replay_locked_closed_policy_execution_scope import (
    M6ReplayLockedClosedPolicyExecutionScopeFailureCode,
    M6ReplayLockedClosedPolicyExecutionScopeProvider,
    M6ReplayLockedClosedPolicyExecutionScopePublisher,
    M6ReplayLockedClosedPolicyExecutionScopeStoreError,
    M6StoredReplayLockedClosedPolicyExecutionScope,
)
from tests.contract.test_m6_replay_locked_closed_policy_execution_contracts import (
    _authorities,
)


def _stored() -> M6StoredReplayLockedClosedPolicyExecutionScope:
    scope, _pending = _authorities()
    document = canonical_json(scope.model_dump(mode="json"))
    payload = document.encode("utf-8")
    return M6StoredReplayLockedClosedPolicyExecutionScope(
        scope=scope,
        canonical_document=document,
        content_sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
    )


def test_stored_closed_policy_scope_is_exact_canonical_and_frozen() -> None:
    stored = _stored()

    assert type(stored.scope) is M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2
    assert stored.scope.route.value == "ALERT_POLICY_CLOSED"
    with pytest.raises(FrozenInstanceError):
        stored.size_bytes = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("canonical_document", "{}"),
        ("content_sha256", "f" * 64),
        ("size_bytes", 1),
    ),
)
def test_stored_closed_policy_scope_rejects_physical_identity_drift(
    field: str,
    value: object,
) -> None:
    stored = _stored()
    payload = {
        "scope": stored.scope,
        "canonical_document": stored.canonical_document,
        "content_sha256": stored.content_sha256,
        "size_bytes": stored.size_bytes,
    }
    payload[field] = value

    with pytest.raises((TypeError, ValueError)):
        M6StoredReplayLockedClosedPolicyExecutionScope(**payload)  # type: ignore[arg-type]


def test_closed_policy_scope_ports_have_narrow_exact_signatures() -> None:
    publish = M6ReplayLockedClosedPolicyExecutionScopePublisher.publish
    load = M6ReplayLockedClosedPolicyExecutionScopeProvider.load

    assert tuple(inspect.signature(publish).parameters) == (
        "self",
        "scope",
        "canonical_document",
    )
    assert inspect.get_annotations(publish, eval_str=True) == {
        "scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
        "canonical_document": str,
        "return": M6StoredReplayLockedClosedPolicyExecutionScope,
    }
    assert tuple(inspect.signature(load).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
    )
    assert inspect.get_annotations(load, eval_str=True) == {
        "candidate_run_id": str,
        "execution_scope_authority_id": str,
        "return": M6StoredReplayLockedClosedPolicyExecutionScope,
    }


def test_closed_policy_scope_error_is_typed_and_payload_free() -> None:
    error = M6ReplayLockedClosedPolicyExecutionScopeStoreError(
        M6ReplayLockedClosedPolicyExecutionScopeFailureCode.SCOPE_CONFLICT
    )

    assert error.args == ("M6 CLOSED-policy execution scope store failed: SCOPE_CONFLICT",)
    assert vars(error) == {"reason_code": error.reason_code}
    with pytest.raises(TypeError, match="reason_code"):
        M6ReplayLockedClosedPolicyExecutionScopeStoreError(
            "SCOPE_CONFLICT"  # type: ignore[arg-type]
        )
