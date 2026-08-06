"""Run-scoped persistent retry work contracts."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Literal, Self, TypeAlias

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    VlmRole,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token
from labcourt.contracts.storage import ArtifactRef

_STAGE_ROLES: dict[BacklogStage, frozenset[VlmRole] | None] = {
    BacklogStage.SCREENING: frozenset({VlmRole.SCREENING, VlmRole.STRUCTURE_REPAIR}),
    BacklogStage.HEARING: frozenset({VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE}),
    BacklogStage.EVIDENCE: None,
    BacklogStage.HUMAN_REVIEW: None,
}
_STAGE_INPUT_KINDS: dict[BacklogStage, frozenset[ArtifactKind]] = {
    BacklogStage.SCREENING: frozenset({ArtifactKind.EVIDENCE_PACK}),
    BacklogStage.HEARING: frozenset(
        {
            ArtifactKind.EVIDENCE_PACK,
            ArtifactKind.MODEL_REQUEST,
            ArtifactKind.SCREENING_RESULT,
            ArtifactKind.VERDICT,
        }
    ),
    BacklogStage.EVIDENCE: frozenset(
        {ArtifactKind.EVENT, ArtifactKind.CASE, ArtifactKind.EVIDENCE_PACK}
    ),
    BacklogStage.HUMAN_REVIEW: frozenset(
        {
            ArtifactKind.CASE,
            ArtifactKind.MODEL_RESPONSE,
            ArtifactKind.SCREENING_RESULT,
            ArtifactKind.VERDICT,
            ArtifactKind.PROCEDURAL_REVIEW,
        }
    ),
}

_MODEL_RESPONSE_KINDS = frozenset({ArtifactKind.MODEL_RESPONSE})
BacklogItemReasonCode: TypeAlias = Literal[
    BacklogReasonCode.PROVIDER_UNAVAILABLE,
    BacklogReasonCode.MODEL_OUTPUT_INVALID,
    BacklogReasonCode.BUDGET_EXCEEDED,
    BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE,
    BacklogReasonCode.CURRENT_PACK_CHANGED,
]
_M3_SUCCESS_MATRIX: dict[CaseStatus, ArtifactKind] = {
    CaseStatus.ESCALATED: ArtifactKind.SCREENING_RESULT,
    CaseStatus.READY_FOR_ALERT_POLICY: ArtifactKind.PROCEDURAL_REVIEW,
    CaseStatus.REWORK_REQUIRED: ArtifactKind.PROCEDURAL_REVIEW,
}


def _require_stable_refs(
    refs: tuple[ArtifactRef, ...],
    name: str,
    *,
    allowed_kinds: frozenset[ArtifactKind],
) -> None:
    keys = tuple(ref.sort_key for ref in refs)
    if len(keys) != len(set(keys)):
        raise ValueError(f"{name} must be unique")
    if keys != tuple(sorted(keys)):
        raise ValueError(f"{name} must use stable artifact order")
    if any(ref.kind not in allowed_kinds for ref in refs):
        raise ValueError(f"{name} contains an unsupported artifact kind")


class BacklogRetryContext(FrozenContractModel):
    """Request identity input that changes only after a proven parse failure.

    The lease is deliberately absent.  A provider outage, timeout, or unknown
    worker crash may result in another lease, but must keep the same model
    request identity so durable claim/journal recovery can prevent a duplicate
    external call.
    """

    backlog_item_id: Sha256Hex
    retry_generation: int = Field(ge=0, strict=True)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_context_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "context_id" in payload
        claimed = payload.pop("context_id", None)
        context = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != context.context_id):
            raise ValueError("serialized backlog retry context_id does not match its content")
        return context

    @computed_field  # type: ignore[prop-decorator]
    @property
    def context_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "backlog-retry-context",
                1,
                self.backlog_item_id,
                self.retry_generation,
            ]
        )


class BacklogLeaseIdentity(FrozenContractModel):
    """Non-secret CAS identity for one exact leased backlog generation."""

    run_id: ReferenceToken
    item_id: Sha256Hex
    lease_id: Sha256Hex
    attempt_count: int = Field(gt=0, strict=True)
    retry_generation: int = Field(ge=0, strict=True)

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        return require_reference_token(value, "backlog lease run reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_identity(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "lease_identity_sha256" in payload
        claimed = payload.pop("lease_identity_sha256", None)
        identity = handler(payload)
        if claimed_present and (
            not isinstance(claimed, str) or claimed != identity.lease_identity_sha256
        ):
            raise ValueError("serialized backlog lease identity hash does not match its content")
        return identity

    @computed_field  # type: ignore[prop-decorator]
    @property
    def lease_identity_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "backlog-lease-identity",
                1,
                self.run_id,
                self.item_id,
                self.lease_id,
                self.attempt_count,
                self.retry_generation,
            ]
        )


class BacklogParseFailureEvidence(FrozenContractModel):
    """Typed references for one persisted strict-parser failure."""

    attempt_index: Literal[0, 1]
    role: Literal[VlmRole.SCREENING, VlmRole.STRUCTURE_REPAIR]
    request_ref: ArtifactRef
    response_ref: ArtifactRef
    parse_receipt_ref: ArtifactRef

    @model_validator(mode="after")
    def validate_attempt_matrix(self) -> BacklogParseFailureEvidence:
        expected_role = VlmRole.SCREENING if self.attempt_index == 0 else VlmRole.STRUCTURE_REPAIR
        if self.role != expected_role:
            raise ValueError("backlog parse-failure role conflicts with its attempt index")
        if self.request_ref.kind != ArtifactKind.MODEL_REQUEST:
            raise ValueError("backlog parse failure must reference a model request")
        if self.response_ref.kind != ArtifactKind.MODEL_RESPONSE:
            raise ValueError("backlog parse failure must reference a model response")
        if self.parse_receipt_ref.kind != ArtifactKind.MODEL_PARSE_RECEIPT:
            raise ValueError("backlog parse failure must reference a parse receipt")
        return self


class BacklogStrictParseFailureProof(FrozenContractModel):
    """Two persisted, billable strict failures authorizing one new generation.

    IDs are public references only.  The repository remains responsible for
    loading both receipts, proving their request/response/generation bindings,
    revalidating raw responses, and atomically accounting their usage.
    """

    retry_context: BacklogRetryContext
    attempts: tuple[BacklogParseFailureEvidence, ...] = Field(min_length=2, max_length=2)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_proof_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "proof_id" in payload
        claimed = payload.pop("proof_id", None)
        proof = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != proof.proof_id):
            raise ValueError("serialized strict parse-failure proof_id does not match its content")
        return proof

    @computed_field  # type: ignore[prop-decorator]
    @property
    def proof_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "backlog-strict-parse-failure-proof",
                1,
                self.retry_context.context_id,
                [attempt.model_dump(mode="json") for attempt in self.attempts],
            ]
        )

    @model_validator(mode="after")
    def validate_complete_strict_failure(self) -> BacklogStrictParseFailureProof:
        if tuple(attempt.attempt_index for attempt in self.attempts) != (0, 1):
            raise ValueError("strict parse-failure proof requires ordered attempts zero and one")
        for attribute, name in (
            ("request_ref", "request refs"),
            ("response_ref", "response refs"),
            ("parse_receipt_ref", "parse receipt refs"),
        ):
            refs = tuple(getattr(attempt, attribute) for attempt in self.attempts)
            if len(refs) != len(set(refs)):
                raise ValueError(f"strict parse-failure {name} must be unique")
        return self


class BacklogRetrySuccess(FrozenContractModel):
    """Intent for one M3 business success under an exact lease identity."""

    outcome_kind: Literal["SUCCESS"] = "SUCCESS"
    lease: BacklogLeaseIdentity
    completion_case_status: Literal[
        CaseStatus.ESCALATED,
        CaseStatus.READY_FOR_ALERT_POLICY,
        CaseStatus.REWORK_REQUIRED,
    ]
    completion_ref: ArtifactRef
    response_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_outcome_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "outcome_id" in payload
        claimed = payload.pop("outcome_id", None)
        outcome = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != outcome.outcome_id):
            raise ValueError("serialized backlog success outcome_id does not match its content")
        return outcome

    @computed_field  # type: ignore[prop-decorator]
    @property
    def outcome_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "backlog-retry-success",
                1,
                self.lease.lease_identity_sha256,
                self.completion_case_status.value,
                self.completion_ref.model_dump(mode="json"),
                [ref.model_dump(mode="json") for ref in self.response_refs],
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_success_matrix(self) -> BacklogRetrySuccess:
        expected_kind = _M3_SUCCESS_MATRIX[self.completion_case_status]
        if self.completion_ref.kind != expected_kind:
            raise ValueError("backlog success completion ref conflicts with target Case status")
        _require_stable_refs(
            self.response_refs,
            "backlog success response refs",
            allowed_kinds=_MODEL_RESPONSE_KINDS,
        )
        return self


class BacklogRetryFailure(FrozenContractModel):
    """One atomic retry failure, including any controlled generation advance."""

    outcome_kind: Literal["FAILURE"] = "FAILURE"
    lease: BacklogLeaseIdentity
    reason_code: BacklogReasonCode
    next_status: Literal[BacklogStatus.PENDING, BacklogStatus.EXHAUSTED]
    response_refs: tuple[ArtifactRef, ...] = ()
    strict_parse_failure: BacklogStrictParseFailureProof | None = None
    manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        computed_names = ("next_retry_generation", "completion_case_status", "outcome_id")
        claims = {name: payload.pop(name, None) for name in computed_names}
        present = {name: name in value for name in computed_names}
        outcome = handler(payload)
        for name in computed_names:
            actual = getattr(outcome, name)
            claimed = claims[name]
            if name == "completion_case_status" and isinstance(claimed, str):
                claimed = CaseStatus(claimed)
            if present[name] and claimed != actual:
                raise ValueError(f"serialized backlog failure {name} conflicts with its content")
        return outcome

    @computed_field  # type: ignore[prop-decorator]
    @property
    def next_retry_generation(self) -> int:
        if self.next_status == BacklogStatus.PENDING and self.strict_parse_failure is not None:
            return self.lease.retry_generation + 1
        return self.lease.retry_generation

    @computed_field  # type: ignore[prop-decorator]
    @property
    def completion_case_status(self) -> CaseStatus:
        return (
            CaseStatus.BACKLOGGED
            if self.next_status == BacklogStatus.PENDING
            else CaseStatus.HUMAN_REVIEW
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def outcome_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "backlog-retry-failure",
                1,
                self.lease.lease_identity_sha256,
                self.reason_code.value,
                self.next_status.value,
                [ref.model_dump(mode="json") for ref in self.response_refs],
                (
                    self.strict_parse_failure.proof_id
                    if self.strict_parse_failure is not None
                    else None
                ),
                self.next_retry_generation,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_failure_matrix(self) -> BacklogRetryFailure:
        _require_stable_refs(
            self.response_refs,
            "backlog failure response refs",
            allowed_kinds=_MODEL_RESPONSE_KINDS,
        )
        if self.reason_code == BacklogReasonCode.WORKER_LEASE_EXPIRED:
            if self.response_refs:
                raise ValueError("WORKER_LEASE_EXPIRED cannot claim model responses")
            if self.strict_parse_failure is not None:
                raise ValueError("WORKER_LEASE_EXPIRED cannot claim parse-failure proof")
        elif self.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID:
            if self.strict_parse_failure is None:
                raise ValueError("MODEL_OUTPUT_INVALID requires strict parse-failure proof")
            context = self.strict_parse_failure.retry_context
            if (
                context.backlog_item_id != self.lease.item_id
                or context.retry_generation != self.lease.retry_generation
            ):
                raise ValueError("strict parse-failure proof belongs to another lease generation")
            proof_response_refs = tuple(
                sorted(
                    (attempt.response_ref for attempt in self.strict_parse_failure.attempts),
                    key=lambda ref: ref.sort_key,
                )
            )
            if proof_response_refs != self.response_refs:
                raise ValueError(
                    "MODEL_OUTPUT_INVALID response refs must exactly match its strict proof"
                )
        elif self.strict_parse_failure is not None:
            raise ValueError("strict parse-failure proof requires MODEL_OUTPUT_INVALID")
        return self


BacklogRetryOutcome: TypeAlias = Annotated[
    BacklogRetrySuccess | BacklogRetryFailure,
    Field(discriminator="outcome_kind"),
]


class BacklogCompletionReceipt(FrozenContractModel):
    """Immutable receipt for an atomic retry attempt and Case/audit transition.

    Replaying the exact outcome under the exact lease must return this same
    ``receipt_id``.  A caller-visible ``created`` flag belongs to the repository
    return wrapper and is intentionally excluded from the durable identity.
    """

    outcome: BacklogRetryOutcome
    backlog_status: Literal[
        BacklogStatus.PENDING,
        BacklogStatus.COMPLETED,
        BacklogStatus.EXHAUSTED,
    ]
    completion_ref: ArtifactRef
    completion_case_status: Literal[
        CaseStatus.BACKLOGGED,
        CaseStatus.ESCALATED,
        CaseStatus.READY_FOR_ALERT_POLICY,
        CaseStatus.REWORK_REQUIRED,
        CaseStatus.HUMAN_REVIEW,
    ]
    completion_case_revision: int = Field(gt=0, strict=True)
    completion_audit_sequence: int = Field(ge=0, strict=True)
    completion_audit_entry_hash: Sha256Hex
    manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claimed_present = "receipt_id" in payload
        claimed = payload.pop("receipt_id", None)
        receipt = handler(payload)
        if claimed_present and (not isinstance(claimed, str) or claimed != receipt.receipt_id):
            raise ValueError("serialized backlog completion receipt_id does not match content")
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "backlog-completion-receipt",
                1,
                self.outcome.outcome_id,
                self.backlog_status.value,
                self.completion_ref.model_dump(mode="json"),
                self.completion_case_status.value,
                self.completion_case_revision,
                self.completion_audit_sequence,
                self.completion_audit_entry_hash,
                self.manifest_id,
            ]
        )

    @model_validator(mode="after")
    def validate_completion_matrix(self) -> BacklogCompletionReceipt:
        if self.manifest_id != self.outcome.manifest_id:
            raise ValueError("backlog completion receipt uses another manifest")
        if isinstance(self.outcome, BacklogRetrySuccess):
            if self.backlog_status != BacklogStatus.COMPLETED:
                raise ValueError("successful backlog retry must complete its queue item")
            if (
                self.completion_ref != self.outcome.completion_ref
                or self.completion_case_status != self.outcome.completion_case_status
            ):
                raise ValueError("backlog success receipt conflicts with its outcome")
            return self

        if self.backlog_status != self.outcome.next_status:
            raise ValueError("backlog failure receipt conflicts with its queue status")
        expected_ref = ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=self.outcome.lease.item_id,
        )
        if self.completion_ref != expected_ref:
            raise ValueError("backlog failure receipt must reference its backlog item")
        if self.completion_case_status != self.outcome.completion_case_status:
            raise ValueError("backlog failure receipt conflicts with its Case status")
        return self


class BacklogItem(FrozenContractModel):
    """One immutable retry identity with explicit mutable lease progress."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    stage: BacklogStage
    role: VlmRole | None = None
    reason_code: BacklogItemReasonCode
    stage_input_ref: ArtifactRef
    stage_input_sha256: Sha256Hex
    attempt_count: int = Field(default=0, ge=0, strict=True)
    max_attempts: int = Field(gt=0, strict=True)
    retry_generation: int = Field(default=0, ge=0, strict=True)
    status: BacklogStatus = BacklogStatus.PENDING
    lease_id: Sha256Hex | None = None
    lease_owner_sha256: Sha256Hex | None = None
    lease_expires_at: datetime | None = None
    manifest_id: Sha256Hex

    @field_validator("run_id", "case_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "backlog run or case reference")

    @field_validator("lease_expires_at")
    @classmethod
    def validate_lease_expiry(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("backlog lease expiry must be timezone-aware UTC")
        if value.utcoffset() != timedelta(0):
            raise ValueError("backlog lease expiry must use UTC")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        item_id_present = "item_id" in payload
        completed_present = "completed" in payload
        claimed_item_id = payload.pop("item_id", None)
        claimed_completed = payload.pop("completed", None)
        item = handler(payload)
        if item_id_present and (
            not isinstance(claimed_item_id, str) or claimed_item_id != item.item_id
        ):
            raise ValueError("serialized backlog item_id does not match immutable input")
        if completed_present and (
            type(claimed_completed) is not bool or claimed_completed != item.completed
        ):
            raise ValueError("serialized backlog completed state conflicts with status")
        return item

    @computed_field  # type: ignore[prop-decorator]
    @property
    def item_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "backlog-item",
                1,
                self.run_id,
                self.case_id,
                self.stage.value,
                self.role.value if self.role is not None else None,
                self.reason_code.value,
                self.stage_input_ref.model_dump(mode="json"),
                self.stage_input_sha256,
                self.max_attempts,
                self.manifest_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def completed(self) -> bool:
        return self.status == BacklogStatus.COMPLETED

    @model_validator(mode="after")
    def validate_stage_and_progress(self) -> BacklogItem:
        allowed_roles = _STAGE_ROLES[self.stage]
        if allowed_roles is None:
            if self.role is not None:
                raise ValueError("backlog stage does not accept a model role")
        elif self.role not in allowed_roles:
            raise ValueError("backlog model role conflicts with its stage")
        if self.stage_input_ref.kind not in _STAGE_INPUT_KINDS[self.stage]:
            raise ValueError("backlog stage input kind conflicts with its stage")
        if self.attempt_count > self.max_attempts:
            raise ValueError("backlog attempt count exceeds its retry budget")
        # A generation can advance at most once per completed backlog attempt,
        # plus once for the strict two-call failure that originally enqueued it.
        if self.retry_generation > self.attempt_count + 1:
            raise ValueError("backlog retry generation exceeds proven attempt progress")
        if self.attempt_count == 0:
            expected_initial_generation = (
                1 if self.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID else 0
            )
            if self.retry_generation != expected_initial_generation:
                raise ValueError(
                    "initial backlog retry generation conflicts with its failure reason"
                )
        lease_values = (self.lease_id, self.lease_owner_sha256, self.lease_expires_at)
        if self.status == BacklogStatus.LEASED:
            if self.attempt_count == 0:
                raise ValueError("leased backlog work must record its attempt")
            if any(value is None for value in lease_values):
                raise ValueError("leased backlog work requires complete lease ownership")
        elif any(value is not None for value in lease_values):
            raise ValueError("only leased backlog work may carry lease ownership")
        if self.status == BacklogStatus.PENDING and (self.attempt_count >= self.max_attempts):
            raise ValueError("retry budget exhaustion requires EXHAUSTED status")
        if self.status == BacklogStatus.COMPLETED and self.attempt_count == 0:
            raise ValueError("completed backlog work must record an attempt")
        if self.status == BacklogStatus.EXHAUSTED and (self.attempt_count != self.max_attempts):
            raise ValueError("EXHAUSTED backlog work must consume its retry budget")
        return self


class BacklogRetryDisposition(StrEnum):
    """Stable public result of one bounded backlog-worker invocation."""

    NO_WORK = "NO_WORK"
    COMPLETED = "COMPLETED"
    RETRY_PENDING = "RETRY_PENDING"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class BacklogRetryReport(FrozenContractModel):
    """Public, secret-free report for reclaiming and processing at most one item."""

    schema_version: Literal["m3-backlog-retry-report-v1"] = "m3-backlog-retry-report-v1"
    run_id: ReferenceToken
    reclaimed_expired_count: int = Field(ge=0, strict=True)
    reclaimed_exhausted_count: int = Field(ge=0, strict=True)
    disposition: BacklogRetryDisposition
    item: BacklogItem | None = None
    receipt: BacklogCompletionReceipt | None = None

    @field_validator("run_id")
    @classmethod
    def validate_report_run_id(cls, value: str) -> str:
        return require_reference_token(value, "backlog retry report run reference")

    @model_validator(mode="after")
    def validate_report_matrix(self) -> BacklogRetryReport:
        if self.reclaimed_exhausted_count > self.reclaimed_expired_count:
            raise ValueError("reclaimed exhausted count cannot exceed reclaimed expired count")
        if self.disposition == BacklogRetryDisposition.NO_WORK:
            if self.item is not None or self.receipt is not None:
                raise ValueError("NO_WORK backlog retry report cannot contain an outcome")
            return self

        if self.item is None or self.receipt is None:
            raise ValueError("processed backlog retry report requires item and receipt")
        lease = self.receipt.outcome.lease
        if (
            self.item.run_id != self.run_id
            or lease.run_id != self.run_id
            or self.item.item_id != lease.item_id
            or self.item.attempt_count != lease.attempt_count
            or self.item.manifest_id != self.receipt.manifest_id
            or self.item.status != self.receipt.backlog_status
        ):
            raise ValueError("backlog retry report outcome bindings conflict")
        expected_generation = (
            self.receipt.outcome.next_retry_generation
            if isinstance(self.receipt.outcome, BacklogRetryFailure)
            else lease.retry_generation
        )
        if self.item.retry_generation != expected_generation:
            raise ValueError("backlog retry report has the wrong retry generation")

        expected_disposition = {
            BacklogStatus.COMPLETED: BacklogRetryDisposition.COMPLETED,
            BacklogStatus.PENDING: BacklogRetryDisposition.RETRY_PENDING,
            BacklogStatus.EXHAUSTED: BacklogRetryDisposition.HUMAN_REVIEW,
        }[self.receipt.backlog_status]
        if self.disposition != expected_disposition:
            raise ValueError("backlog retry report disposition conflicts with its receipt")
        if (
            expected_disposition == BacklogRetryDisposition.COMPLETED
            and not isinstance(self.receipt.outcome, BacklogRetrySuccess)
        ) or (
            expected_disposition != BacklogRetryDisposition.COMPLETED
            and not isinstance(self.receipt.outcome, BacklogRetryFailure)
        ):
            raise ValueError("backlog retry report outcome kind conflicts with disposition")
        return self


__all__ = [
    "BacklogCompletionReceipt",
    "BacklogItem",
    "BacklogLeaseIdentity",
    "BacklogParseFailureEvidence",
    "BacklogRetryContext",
    "BacklogRetryDisposition",
    "BacklogRetryFailure",
    "BacklogRetryOutcome",
    "BacklogRetryReport",
    "BacklogRetrySuccess",
    "BacklogStrictParseFailureProof",
]
