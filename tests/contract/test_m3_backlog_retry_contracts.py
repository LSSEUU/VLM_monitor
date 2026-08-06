import json
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogParseFailureEvidence,
    BacklogRetryContext,
    BacklogRetryDisposition,
    BacklogRetryFailure,
    BacklogRetryReport,
    BacklogRetrySuccess,
    BacklogStrictParseFailureProof,
)
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.schema_export import expected_schema_files

RUN_ID = "run-01"


def _sha(value: int) -> str:
    return f"{value:064x}"


def _ref(kind: ArtifactKind, value: int) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=_sha(value))


def _item(
    *,
    attempt_count: int = 0,
    retry_generation: int = 0,
    status: BacklogStatus = BacklogStatus.PENDING,
    max_attempts: int = 3,
    reason_code: BacklogReasonCode = BacklogReasonCode.PROVIDER_UNAVAILABLE,
) -> BacklogItem:
    lease_fields: dict[str, object] = {}
    if status == BacklogStatus.LEASED:
        lease_fields = {
            "lease_id": _sha(4),
            "lease_owner_sha256": _sha(5),
            "lease_expires_at": datetime(2026, 7, 28, 12, tzinfo=UTC),
        }
    return BacklogItem(
        run_id=RUN_ID,
        case_id="case-01",
        stage=BacklogStage.SCREENING,
        role=VlmRole.SCREENING,
        reason_code=reason_code,
        stage_input_ref=_ref(ArtifactKind.EVIDENCE_PACK, 1),
        stage_input_sha256=_sha(2),
        attempt_count=attempt_count,
        max_attempts=max_attempts,
        retry_generation=retry_generation,
        status=status,
        manifest_id=_sha(3),
        **lease_fields,
    )


def _lease(*, attempt_count: int = 1, retry_generation: int = 0) -> BacklogLeaseIdentity:
    item = _item()
    return BacklogLeaseIdentity(
        run_id=item.run_id,
        item_id=item.item_id,
        lease_id=_sha(4),
        attempt_count=attempt_count,
        retry_generation=retry_generation,
    )


def _strict_failure_proof(
    *,
    lease: BacklogLeaseIdentity | None = None,
) -> BacklogStrictParseFailureProof:
    bound = lease or _lease()
    return BacklogStrictParseFailureProof(
        retry_context=BacklogRetryContext(
            backlog_item_id=bound.item_id,
            retry_generation=bound.retry_generation,
        ),
        attempts=(
            BacklogParseFailureEvidence(
                attempt_index=0,
                role=VlmRole.SCREENING,
                request_ref=_ref(ArtifactKind.MODEL_REQUEST, 10),
                response_ref=_ref(ArtifactKind.MODEL_RESPONSE, 20),
                parse_receipt_ref=_ref(ArtifactKind.MODEL_PARSE_RECEIPT, 30),
            ),
            BacklogParseFailureEvidence(
                attempt_index=1,
                role=VlmRole.STRUCTURE_REPAIR,
                request_ref=_ref(ArtifactKind.MODEL_REQUEST, 11),
                response_ref=_ref(ArtifactKind.MODEL_RESPONSE, 21),
                parse_receipt_ref=_ref(ArtifactKind.MODEL_PARSE_RECEIPT, 31),
            ),
        ),
    )


def _failure(
    *,
    reason_code: BacklogReasonCode = BacklogReasonCode.PROVIDER_UNAVAILABLE,
    next_status: BacklogStatus = BacklogStatus.PENDING,
    lease: BacklogLeaseIdentity | None = None,
) -> BacklogRetryFailure:
    bound = lease or _lease()
    proof = (
        _strict_failure_proof(lease=bound)
        if reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID
        else None
    )
    response_refs = (
        tuple(attempt.response_ref for attempt in proof.attempts) if proof is not None else ()
    )
    return BacklogRetryFailure(
        lease=bound,
        reason_code=reason_code,
        next_status=next_status,
        response_refs=response_refs,
        strict_parse_failure=proof,
        manifest_id=_sha(3),
    )


def test_lease_identity_binds_item_lease_attempt_and_generation_without_owner_token() -> None:
    lease = _lease()
    payload = lease.model_dump(mode="json")
    assert set(payload) == {
        "run_id",
        "item_id",
        "lease_id",
        "attempt_count",
        "retry_generation",
        "lease_identity_sha256",
    }
    assert "owner" not in json.dumps(payload).lower()

    with pytest.raises(ValidationError, match="identity hash"):
        BacklogLeaseIdentity.model_validate({**payload, "attempt_count": 2})


@given(
    attempt_count=st.integers(min_value=1, max_value=20),
    retry_generation=st.integers(min_value=0, max_value=20),
)
def test_lease_identity_changes_with_attempt_or_generation(
    attempt_count: int,
    retry_generation: int,
) -> None:
    lease = _lease(
        attempt_count=attempt_count,
        retry_generation=retry_generation,
    )
    changed_attempt = lease.model_copy(update={"attempt_count": attempt_count + 1})
    changed_generation = lease.model_copy(update={"retry_generation": retry_generation + 1})
    assert changed_attempt.lease_identity_sha256 != lease.lease_identity_sha256
    assert changed_generation.lease_identity_sha256 != lease.lease_identity_sha256


@given(
    attempt_count=st.integers(min_value=0, max_value=2),
    retry_generation=st.integers(min_value=0, max_value=3),
)
def test_retry_generation_is_version_state_and_never_changes_item_id(
    attempt_count: int,
    retry_generation: int,
) -> None:
    invalid_initial = attempt_count == 0 and retry_generation != 0
    if retry_generation > attempt_count + 1 or invalid_initial:
        with pytest.raises(ValidationError, match="retry generation"):
            _item(attempt_count=attempt_count, retry_generation=retry_generation)
        return
    candidate = _item(
        attempt_count=attempt_count,
        retry_generation=retry_generation,
    )
    assert candidate.item_id == _item().item_id


def test_initial_generation_matrix_skips_a_cached_final_invalid_response_only() -> None:
    invalid_output = _item(
        retry_generation=1,
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
    )
    assert invalid_output.retry_generation == 1

    with pytest.raises(ValidationError, match="failure reason"):
        _item(reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID)
    with pytest.raises(ValidationError, match="failure reason"):
        _item(retry_generation=1)


@pytest.mark.parametrize(
    "reason_code",
    [
        BacklogReasonCode.PROVIDER_UNAVAILABLE,
        BacklogReasonCode.BUDGET_EXCEEDED,
        BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
        BacklogReasonCode.CURRENT_PACK_CHANGED,
    ],
)
def test_outage_integrity_budget_and_unknown_progress_never_advance_generation(
    reason_code: BacklogReasonCode,
) -> None:
    failure = _failure(reason_code=reason_code)
    assert failure.next_retry_generation == failure.lease.retry_generation

    with pytest.raises(ValidationError, match="requires MODEL_OUTPUT_INVALID"):
        BacklogRetryFailure(
            lease=failure.lease,
            reason_code=reason_code,
            next_status=BacklogStatus.PENDING,
            response_refs=tuple(
                attempt.response_ref for attempt in _strict_failure_proof().attempts
            ),
            strict_parse_failure=_strict_failure_proof(),
            manifest_id=_sha(3),
        )


def test_worker_lease_expiry_is_retry_only_and_cannot_claim_model_evidence() -> None:
    with pytest.raises(ValidationError):
        _item(reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED)

    lease_expiry = _failure(reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED)
    assert lease_expiry.response_refs == ()
    assert lease_expiry.strict_parse_failure is None
    assert lease_expiry.next_retry_generation == lease_expiry.lease.retry_generation

    with pytest.raises(ValidationError, match="cannot claim model responses"):
        BacklogRetryFailure(
            lease=lease_expiry.lease,
            reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED,
            next_status=BacklogStatus.PENDING,
            response_refs=(
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=_sha(92),
                ),
            ),
            manifest_id=_sha(3),
        )


def test_only_two_strict_persisted_parse_failures_authorize_next_generation() -> None:
    failure = _failure(reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID)
    assert failure.next_retry_generation == failure.lease.retry_generation + 1
    assert tuple(attempt.attempt_index for attempt in failure.strict_parse_failure.attempts) == (
        0,
        1,
    )

    with pytest.raises(ValidationError, match="requires strict parse-failure proof"):
        BacklogRetryFailure(
            lease=failure.lease,
            reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
            next_status=BacklogStatus.PENDING,
            response_refs=failure.response_refs,
            manifest_id=_sha(3),
        )
    with pytest.raises(ValidationError, match="another lease generation"):
        BacklogRetryFailure(
            lease=failure.lease.model_copy(update={"retry_generation": 1}),
            reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
            next_status=BacklogStatus.PENDING,
            response_refs=failure.response_refs,
            strict_parse_failure=failure.strict_parse_failure,
            manifest_id=_sha(3),
        )


def test_parse_attempt_order_does_not_impose_hash_order_on_response_refs() -> None:
    lease = _lease()
    proof = _strict_failure_proof(lease=lease)
    reverse_hash_proof = proof.model_copy(
        update={
            "attempts": (
                proof.attempts[0].model_copy(
                    update={"response_ref": _ref(ArtifactKind.MODEL_RESPONSE, 21)}
                ),
                proof.attempts[1].model_copy(
                    update={"response_ref": _ref(ArtifactKind.MODEL_RESPONSE, 20)}
                ),
            )
        }
    )
    failure = BacklogRetryFailure(
        lease=lease,
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        next_status=BacklogStatus.PENDING,
        response_refs=(
            _ref(ArtifactKind.MODEL_RESPONSE, 20),
            _ref(ArtifactKind.MODEL_RESPONSE, 21),
        ),
        strict_parse_failure=reverse_hash_proof,
        manifest_id=_sha(3),
    )
    assert failure.next_retry_generation == 1


def test_terminal_model_output_failure_does_not_create_an_unused_generation() -> None:
    failure = _failure(
        reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID,
        next_status=BacklogStatus.EXHAUSTED,
    )
    assert failure.next_retry_generation == failure.lease.retry_generation


@pytest.mark.parametrize(
    ("case_status", "completion_kind"),
    [
        (CaseStatus.ESCALATED, ArtifactKind.SCREENING_RESULT),
        (CaseStatus.READY_FOR_ALERT_POLICY, ArtifactKind.PROCEDURAL_REVIEW),
        (CaseStatus.REWORK_REQUIRED, ArtifactKind.PROCEDURAL_REVIEW),
    ],
)
def test_m3_success_matrix_is_explicit_and_receipt_is_idempotent(
    case_status: CaseStatus,
    completion_kind: ArtifactKind,
) -> None:
    success = BacklogRetrySuccess(
        lease=_lease(),
        completion_case_status=case_status,
        completion_ref=_ref(completion_kind, 40),
        response_refs=(_ref(ArtifactKind.MODEL_RESPONSE, 20),),
        manifest_id=_sha(3),
    )
    receipt = BacklogCompletionReceipt(
        outcome=success,
        backlog_status=BacklogStatus.COMPLETED,
        completion_ref=success.completion_ref,
        completion_case_status=case_status,
        completion_case_revision=3,
        completion_audit_sequence=7,
        completion_audit_entry_hash=_sha(50),
        manifest_id=_sha(3),
    )
    replayed = BacklogCompletionReceipt.model_validate_json(receipt.model_dump_json())
    assert replayed == receipt
    assert replayed.receipt_id == receipt.receipt_id

    with pytest.raises(ValidationError, match="receipt_id"):
        BacklogCompletionReceipt.model_validate(
            {
                **receipt.model_dump(mode="json"),
                "completion_case_revision": 4,
            }
        )


def test_success_and_failure_receipts_reject_crossed_state_combinations() -> None:
    with pytest.raises(ValidationError, match="completion ref conflicts"):
        BacklogRetrySuccess(
            lease=_lease(),
            completion_case_status=CaseStatus.ESCALATED,
            completion_ref=_ref(ArtifactKind.PROCEDURAL_REVIEW, 40),
            response_refs=(_ref(ArtifactKind.MODEL_RESPONSE, 20),),
            manifest_id=_sha(3),
        )

    failure = _failure()
    with pytest.raises(ValidationError, match="queue status"):
        BacklogCompletionReceipt(
            outcome=failure,
            backlog_status=BacklogStatus.EXHAUSTED,
            completion_ref=_ref(ArtifactKind.BACKLOG_ITEM, int(failure.lease.item_id, 16)),
            completion_case_status=CaseStatus.HUMAN_REVIEW,
            completion_case_revision=3,
            completion_audit_sequence=7,
            completion_audit_entry_hash=_sha(50),
            manifest_id=_sha(3),
        )


@pytest.mark.parametrize(
    ("next_status", "case_status"),
    [
        (BacklogStatus.PENDING, CaseStatus.BACKLOGGED),
        (BacklogStatus.EXHAUSTED, CaseStatus.HUMAN_REVIEW),
    ],
)
def test_failure_receipt_binds_backlog_ref_case_revision_and_audit(
    next_status: BacklogStatus,
    case_status: CaseStatus,
) -> None:
    failure = _failure(next_status=next_status)
    receipt = BacklogCompletionReceipt(
        outcome=failure,
        backlog_status=next_status,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=failure.lease.item_id,
        ),
        completion_case_status=case_status,
        completion_case_revision=5,
        completion_audit_sequence=9,
        completion_audit_entry_hash=_sha(51),
        manifest_id=_sha(3),
    )
    assert receipt.completion_case_revision == 5
    assert receipt.completion_audit_sequence == 9


@pytest.mark.parametrize(
    ("next_status", "disposition"),
    [
        (BacklogStatus.PENDING, BacklogRetryDisposition.RETRY_PENDING),
        (BacklogStatus.EXHAUSTED, BacklogRetryDisposition.HUMAN_REVIEW),
    ],
)
def test_retry_report_binds_failure_receipt_and_terminal_item(
    next_status: BacklogStatus,
    disposition: BacklogRetryDisposition,
) -> None:
    source = _item(max_attempts=(1 if next_status == BacklogStatus.EXHAUSTED else 3))
    lease = BacklogLeaseIdentity(
        run_id=source.run_id,
        item_id=source.item_id,
        lease_id=_sha(4),
        attempt_count=1,
        retry_generation=source.retry_generation,
    )
    failure = _failure(next_status=next_status, lease=lease)
    receipt = BacklogCompletionReceipt(
        outcome=failure,
        backlog_status=next_status,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=failure.lease.item_id,
        ),
        completion_case_status=failure.completion_case_status,
        completion_case_revision=5,
        completion_audit_sequence=9,
        completion_audit_entry_hash=_sha(51),
        manifest_id=_sha(3),
    )
    item = BacklogItem.model_validate(
        {
            **source.model_dump(mode="json", exclude_computed_fields=True),
            "attempt_count": failure.lease.attempt_count,
            "retry_generation": failure.next_retry_generation,
            "status": next_status.value,
        }
    )
    report = BacklogRetryReport(
        run_id=RUN_ID,
        reclaimed_expired_count=2,
        reclaimed_exhausted_count=1,
        disposition=disposition,
        item=item,
        receipt=receipt,
    )
    assert report.schema_version == "m3-backlog-retry-report-v1"

    with pytest.raises(ValidationError, match="disposition conflicts"):
        BacklogRetryReport.model_validate(
            {
                **report.model_dump(mode="json"),
                "disposition": BacklogRetryDisposition.COMPLETED.value,
            }
        )


def test_retry_report_no_work_is_explicit_and_rejects_partial_outcomes() -> None:
    report = BacklogRetryReport(
        run_id=RUN_ID,
        reclaimed_expired_count=0,
        reclaimed_exhausted_count=0,
        disposition=BacklogRetryDisposition.NO_WORK,
    )
    assert report.item is None
    assert report.receipt is None

    with pytest.raises(ValidationError, match="cannot contain an outcome"):
        BacklogRetryReport.model_validate(
            {**report.model_dump(mode="json"), "item": _item().model_dump(mode="json")}
        )

    with pytest.raises(ValidationError, match="cannot exceed"):
        BacklogRetryReport.model_validate(
            {
                **report.model_dump(mode="json"),
                "reclaimed_exhausted_count": 1,
            }
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("reclaimed_expired_count", True),
        ("reclaimed_exhausted_count", True),
        ("reclaimed_expired_count", -1),
        ("reclaimed_exhausted_count", -1),
    ],
)
def test_retry_report_reclaim_counts_are_strict_non_negative_integers(
    field: str,
    value: object,
) -> None:
    payload = {
        "run_id": RUN_ID,
        "reclaimed_expired_count": 0,
        "reclaimed_exhausted_count": 0,
        "disposition": BacklogRetryDisposition.NO_WORK.value,
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        BacklogRetryReport.model_validate(payload)


def test_retry_report_requires_both_reclaim_counts() -> None:
    payload = {
        "run_id": RUN_ID,
        "reclaimed_expired_count": 0,
        "disposition": BacklogRetryDisposition.NO_WORK.value,
    }

    with pytest.raises(ValidationError, match="reclaimed_exhausted_count"):
        BacklogRetryReport.model_validate(payload)


def test_retry_contract_schemas_round_trip_without_sensitive_fields() -> None:
    failure = _failure(reason_code=BacklogReasonCode.MODEL_OUTPUT_INVALID)
    receipt = BacklogCompletionReceipt(
        outcome=failure,
        backlog_status=BacklogStatus.PENDING,
        completion_ref=ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=failure.lease.item_id,
        ),
        completion_case_status=CaseStatus.BACKLOGGED,
        completion_case_revision=5,
        completion_audit_sequence=9,
        completion_audit_entry_hash=_sha(51),
        manifest_id=_sha(3),
    )
    schemas = expected_schema_files()
    instances = {
        "backlog-completion-receipt": receipt,
        "backlog-lease-identity": failure.lease,
        "backlog-retry-context": failure.strict_parse_failure.retry_context,
        "backlog-retry-failure": failure,
        "backlog-retry-report": BacklogRetryReport(
            run_id=RUN_ID,
            reclaimed_expired_count=0,
            reclaimed_exhausted_count=0,
            disposition=BacklogRetryDisposition.NO_WORK,
        ),
        "backlog-strict-parse-failure-proof": failure.strict_parse_failure,
    }
    for name, instance in instances.items():
        schema = json.loads(schemas[f"{name}.schema.json"])
        Draft202012Validator(schema).validate(instance.model_dump(mode="json"))

    all_property_names: set[str] = set()
    stack: list[object] = [json.loads(schemas["backlog-completion-receipt.schema.json"])]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, dict):
                all_property_names.update(properties)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    assert {
        "owner_token",
        "local_path",
        "raw_response",
        "raw_bytes",
    }.isdisjoint(all_property_names)
