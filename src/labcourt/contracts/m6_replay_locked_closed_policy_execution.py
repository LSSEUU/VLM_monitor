"""Execution-start contracts for M6 replay of the final alert-policy close.

The original replay-locked execution wire remains frozen.  These additive V2
authorities bind that pre-policy execution scope to the independent M5
alert-policy causal cut before a candidate sample can be materialized.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal, Self, TypeVar

from pydantic import (
    BaseModel,
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.alert_policy import (
    AlertPolicyAuthority,
    AlertPolicyDisposition,
)
from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    CaseStatus,
    ReproducibilityMode,
    ScreeningDecision,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m6_regression import (
    MAX_M6_REGRESSION_CASES,
    M6CaseReplaySnapshot,
    M6RegressionExecutionEntry,
    M6ReplayExecutionOutcome,
    M6ReplayExecutionReceipt,
)
from labcourt.contracts.m6_replay_locked import (
    M6ProviderCapabilityCounters,
    M6ProviderTrapAuthority,
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    MAX_M6_REPLAY_LOCKED_COMPONENT_VERSION_LENGTH,
    MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
    M6ReplayLockedCandidateCaseBinding,
    M6ReplayLockedExecutionRoute,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_replay_locked_policy import (
    M6_REPLAY_LOCKED_EMERGENCY_CAUSAL_BASIS,
    MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES,
    M6ReplayLockedAlertPolicyCausalCutAuthority,
    M6ReplayLockedCooldownCausalHead,
)
from labcourt.contracts.references import (
    ReferenceToken,
    require_portable_run_id,
    require_reference_token,
)
from labcourt.contracts.storage import ArtifactRef

_CanonicalT = TypeVar("_CanonicalT", bound=BaseModel)


def _pop_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M6 closed-policy execution")


def _canonical_nested(expected: type[_CanonicalT], value: object, label: str) -> _CanonicalT:
    if type(value) is not expected:
        raise ValueError(f"{label} must be an exact canonical authority")
    controlled = expected.model_validate(
        value.model_dump(mode="json", exclude_computed_fields=True)
    )
    if controlled != value:
        raise ValueError(f"{label} must be an exact canonical authority")
    return controlled


def _physical_content_sha256(value: BaseModel) -> Sha256Hex:
    document = canonical_json(value.model_dump(mode="json"))
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _physical_size_bytes(value: BaseModel) -> int:
    return len(canonical_json(value.model_dump(mode="json")).encode("utf-8"))


def _is_fast_ready_case(case: Case) -> bool:
    if (
        len(case.evidence_packs) != 1
        or len(case.screening_results) != 1
        or len(case.verdicts) != 1
        or len(case.procedural_reviews) != 1
        or case.status != CaseStatus.READY_FOR_ALERT_POLICY
        or case.alerts
        or case.appeals
        or case.final_decision is not None
        or case.current_backlog_item_id is not None
    ):
        return False
    pack = case.evidence_packs[0]
    screening = case.screening_results[0]
    verdict = case.verdicts[0]
    review = case.procedural_reviews[0]
    return (
        pack.version == 1
        and not pack.tool_results
        and screening.decision != ScreeningDecision.ESCALATE
        and screening.evidence_pack_id == pack.pack_id
        and verdict.screening_id == screening.screening_id
        and verdict.evidence_pack_id == pack.pack_id
        and review.passed
        and review.reviewed_verdict_id == verdict.verdict_id
        and review.evidence_pack_id == pack.pack_id
    )


def _is_m4_ready_case(case: Case) -> bool:
    if (
        len(case.evidence_packs) != 1
        or len(case.screening_results) != 1
        or len(case.verdicts) != 1
        or len(case.procedural_reviews) != 1
        or case.status != CaseStatus.READY_FOR_ALERT_POLICY
        or case.alerts
        or case.appeals
        or case.final_decision is not None
        or case.current_backlog_item_id is not None
    ):
        return False
    pack = case.evidence_packs[0]
    screening = case.screening_results[0]
    verdict = case.verdicts[0]
    review = case.procedural_reviews[0]
    return (
        pack.version == 1
        and not pack.tool_results
        and screening.decision == ScreeningDecision.ESCALATE
        and screening.evidence_pack_id == pack.pack_id
        and screening.evidence_pack_version == pack.version
        and verdict.screening_id == screening.screening_id
        and verdict.evidence_pack_id == pack.pack_id
        and verdict.evidence_pack_version == pack.version
        and review.passed
        and review.reviewed_verdict_id == verdict.verdict_id
        and review.reviewed_verdict_version == verdict.version
        and review.reviewed_verdict_sha256 == verdict.verdict_sha256
        and review.evidence_pack_id == pack.pack_id
        and review.evidence_pack_version == pack.version
    )


def _matches_ready_route(
    route: M6ReplayLockedExecutionRoute,
    case: Case,
) -> bool:
    if route == M6ReplayLockedExecutionRoute.M3_FAST_TERMINAL_POST_PARSE:
        return _is_fast_ready_case(case)
    if route == M6ReplayLockedExecutionRoute.M4_HEARING_GATE_TERMINAL_POST_PARSE:
        return _is_m4_ready_case(case)
    return False


def _expected_closed_case(ready: Case, policy: AlertPolicyAuthority) -> Case:
    decision = policy.decision
    if decision is None:
        object_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=ready.case_id)
        alerts = ready.alerts
        alert_id = "NONE"
    else:
        object_ref = ArtifactRef(kind=ArtifactKind.ALERT, artifact_id=decision.alert_id)
        alerts = (*ready.alerts, decision)
        alert_id = decision.alert_id
    timeline = (
        *ready.timeline,
        TimelineEntry(
            sequence=len(ready.timeline),
            action=AuditAction.CASE_CLOSED.value,
            stage="ALERT_POLICY",
            object_ref=object_ref.artifact_id,
            details={
                "alert_id": alert_id,
                "disposition": policy.disposition.value,
                "status": CaseStatus.CLOSED.value,
            },
        ),
    )
    return ready.model_copy(
        update={
            "status": CaseStatus.CLOSED,
            "alerts": alerts,
            "final_decision": policy.final_decision,
            "timeline": timeline,
        }
    )


def _alert_semantic_projection(policy: AlertPolicyAuthority) -> dict[str, object]:
    decision = policy.decision
    cooldown = policy.cooldown_write
    outbox = policy.outbox_item
    return {
        "disposition": policy.disposition.value,
        "policy_rule_ids": tuple(policy.policy_rule_ids),
        "decision": (
            None
            if decision is None
            else {
                "level": decision.level.value,
                "recipients": tuple(decision.recipients),
                "policy_rule_ids": tuple(decision.policy_rule_ids),
                "suppressed_by_cooldown": decision.suppressed_by_cooldown,
                "merged": decision.merged_into_alert_id is not None,
                "human_review_required": decision.human_review_required,
                "rescinded": decision.rescinded,
            }
        ),
        "cooldown_write": (
            None
            if cooldown is None
            else {
                "key": cooldown.key.model_dump(mode="json"),
                "stream_id": cooldown.stream_id,
                "source_trigger_frame": cooldown.source_trigger_frame,
                "cooldown_frames": cooldown.cooldown_frames,
                "cooldown_until_frame_exclusive": (cooldown.cooldown_until_frame_exclusive),
            }
        ),
        "outbox_priority": None if outbox is None else outbox.priority.value,
        "target_case_status": policy.target_case_status.value,
        "final_decision": policy.final_decision.value,
    }


def _policy_input_semantic_projection(policy: AlertPolicyAuthority) -> dict[str, object]:
    request = policy.request
    return {
        "policy_version": request.policy_version,
        "source_case_status": request.source_case_status.value,
        "config_sha256": request.config_sha256,
        "manifest_id": request.manifest_id,
        "camera_id": request.camera_id,
        "stream_id": request.stream_id,
        "stream_authority_sha256": request.stream_authority_sha256,
        "fps_num": request.fps_num,
        "fps_den": request.fps_den,
        "zone_id": request.zone_id,
        "zone_risk": request.zone_risk.value,
        "violation_type": request.violation_type.value,
        "primary_track_ref": request.primary_track_ref,
        "trigger_frame": request.trigger_frame,
        "hard_rule": request.hard_rule,
        "verdict_decision": request.verdict_decision.value,
        "verdict_confidence": request.verdict_confidence,
        "recommended_alert_level": request.recommended_alert_level.value,
        "procedural_review_passed": request.procedural_review_passed,
        "observation_sufficiency_sha256": request.observation_sufficiency_sha256,
        "cooldown_seconds": request.cooldown_seconds,
        "cooldown_frames": request.cooldown_frames,
        "confirmed_min_confidence": request.confirmed_min_confidence,
        "insufficient_evidence_max_level": (request.insufficient_evidence_max_level.value),
        "repeat_history_mode": request.repeat_history_mode,
        "cross_day_repeat_count": request.cross_day_repeat_count,
        "prior_cooldown": (
            None
            if request.prior_cooldown is None
            else request.prior_cooldown.model_dump(mode="json")
        ),
        "prior_emergency_delivery": request.prior_emergency_delivery,
    }


class M6ReplayLockedClosedPolicyExecutionRoute(StrEnum):
    """The additive route that persists only the final CLOSED candidate Case."""

    ALERT_POLICY_CLOSED = "ALERT_POLICY_CLOSED"


class M6ReplayLockedClosedPolicySourceBindingAuthority(FrozenContractModel):
    """Candidate-safe projection that pre-binds one independently held policy cut.

    The complete causal cut includes evaluator-only source policy outputs and is
    intentionally absent.  A trusted record builder later joins it by the
    authority and physical identities fixed here.
    """

    schema_version: Literal["m6-replay-locked-closed-policy-source-binding-authority-v1"] = (
        "m6-replay-locked-closed-policy-source-binding-authority-v1"
    )
    source_catalog_entry_id: Sha256Hex
    sample_id: ReferenceToken
    execution_entry_id: Sha256Hex
    replay_input_closure_authority_id: Sha256Hex
    replay_input_closure_document_sha256: Sha256Hex
    pre_policy_route: M6ReplayLockedExecutionRoute
    source_config_sha256: Sha256Hex
    policy_causal_cut_authority_id: Sha256Hex
    policy_causal_cut_content_sha256: Sha256Hex
    policy_causal_cut_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_POLICY_CAUSAL_CUT_BYTES,
        strict=True,
    )
    cooldown_causal_head: M6ReplayLockedCooldownCausalHead
    emergency_causal_basis: Literal["DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY"] = (
        M6_REPLAY_LOCKED_EMERGENCY_CAUSAL_BASIS
    )

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 closed-policy source sample_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "cooldown_causal_head_id",
                "source_binding_authority_id",
            ),
        )
        binding = handler(payload)
        _verify_claims(binding, claims)
        return binding

    @model_validator(mode="after")
    def validate_candidate_safe_source_cut(self) -> Self:
        cooldown = _canonical_nested(
            M6ReplayLockedCooldownCausalHead,
            self.cooldown_causal_head,
            "M6 closed-policy cooldown causal head",
        )
        object.__setattr__(self, "cooldown_causal_head", cooldown)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def cooldown_causal_head_id(self) -> Sha256Hex:
        return self.cooldown_causal_head.causal_head_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_binding_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-source-binding-authority",
                1,
                self.source_catalog_entry_id,
                self.sample_id,
                self.execution_entry_id,
                self.replay_input_closure_authority_id,
                self.replay_input_closure_document_sha256,
                self.pre_policy_route,
                self.source_config_sha256,
                self.policy_causal_cut_authority_id,
                self.policy_causal_cut_content_sha256,
                self.policy_causal_cut_size_bytes,
                self.cooldown_causal_head_id,
                self.emergency_causal_basis,
            ]
        )


class M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2(FrozenContractModel):
    """Offline component that adds deterministic alert-policy closure to V1."""

    schema_version: Literal["m6-replay-locked-closed-policy-execution-component-authority-v2"] = (
        "m6-replay-locked-closed-policy-execution-component-authority-v2"
    )
    component: Literal["labcourt-m6-replay-locked-closed-policy-executor"] = (
        "labcourt-m6-replay-locked-closed-policy-executor"
    )
    package: Literal["labcourt"] = "labcourt"
    version: str = Field(
        min_length=1,
        max_length=MAX_M6_REPLAY_LOCKED_COMPONENT_VERSION_LENGTH,
    )
    code_commit: str = Field(min_length=1, max_length=128)
    execution_mode: Literal["OFFLINE_LOCKED"] = "OFFLINE_LOCKED"
    input_contract: Literal["SEALED_SAVED_AUTHORITIES_WITH_POLICY_CAUSAL_HEAD_BINDING"] = (
        "SEALED_SAVED_AUTHORITIES_WITH_POLICY_CAUSAL_HEAD_BINDING"
    )
    output_contract: Literal["APPEND_ONLY_CLOSED_LOCKED_INVENTORY"] = (
        "APPEND_ONLY_CLOSED_LOCKED_INVENTORY"
    )
    route: Literal[M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED] = (
        M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED
    )
    pre_policy_component_authority_id: Sha256Hex
    supported_pre_policy_routes: tuple[M6ReplayLockedExecutionRoute, ...]
    network_allowed: Literal[False] = False
    gpu_required: Literal[False] = False
    evaluator_fields_accessible: Literal[False] = False
    provider_ports_exposed: Literal[False] = False
    recovery_ports_exposed: Literal[False] = False
    cache_write_ports_exposed: Literal[False] = False
    live_tail_ports_exposed: Literal[False] = False
    raw_model_response_accessible: Literal[False] = False
    safety_signal_accessible: Literal[False] = False
    alert_channel_ports_exposed: Literal[False] = False
    cooldown_write_ports_exposed: Literal[False] = False
    outbox_write_ports_exposed: Literal[False] = False

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("component_authority_id",))
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_supported_routes(self) -> Self:
        if not self.supported_pre_policy_routes:
            raise ValueError("M6 closed-policy component requires a pre-policy route")
        if self.supported_pre_policy_routes != tuple(
            sorted(set(self.supported_pre_policy_routes), key=str)
        ):
            raise ValueError("M6 closed-policy pre-policy routes must be unique and ordered")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def component_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-execution-component-authority",
                2,
                self.component,
                self.package,
                self.version,
                self.code_commit,
                self.execution_mode,
                self.input_contract,
                self.output_contract,
                self.route,
                self.pre_policy_component_authority_id,
                self.supported_pre_policy_routes,
                self.network_allowed,
                self.gpu_required,
                self.evaluator_fields_accessible,
                self.provider_ports_exposed,
                self.recovery_ports_exposed,
                self.cache_write_ports_exposed,
                self.live_tail_ports_exposed,
                self.raw_model_response_accessible,
                self.safety_signal_accessible,
                self.alert_channel_ports_exposed,
                self.cooldown_write_ports_exposed,
                self.outbox_write_ports_exposed,
            ]
        )


class M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2(FrozenContractModel):
    """Candidate-blind V2 start cut that wraps the exact frozen V1 scope."""

    schema_version: Literal["m6-replay-locked-closed-policy-execution-scope-authority-v2"] = (
        "m6-replay-locked-closed-policy-execution-scope-authority-v2"
    )
    route: Literal[M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED] = (
        M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED
    )
    pre_policy_execution_scope: M6ReplayLockedExecutionScopeAuthority
    pre_policy_execution_scope_content_sha256: Sha256Hex
    pre_policy_execution_scope_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    execution_component: M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2
    execution_component_content_sha256: Sha256Hex
    execution_component_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "pre_policy_execution_scope_authority_id",
                "candidate_run_id",
                "command_id",
                "execution_dataset_snapshot_id",
                "candidate_manifest_id",
                "locked_config_sha256",
                "execution_scope_authority_id",
            ),
        )
        scope = handler(payload)
        _verify_claims(scope, claims)
        return scope

    @model_validator(mode="after")
    def validate_exact_start_cut(self) -> Self:
        pre_policy_scope = _canonical_nested(
            M6ReplayLockedExecutionScopeAuthority,
            self.pre_policy_execution_scope,
            "M6 closed-policy pre-policy execution scope",
        )
        component = _canonical_nested(
            M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
            self.execution_component,
            "M6 closed-policy execution component",
        )
        if (
            _physical_content_sha256(pre_policy_scope)
            != self.pre_policy_execution_scope_content_sha256
            or _physical_size_bytes(pre_policy_scope) != self.pre_policy_execution_scope_size_bytes
            or _physical_content_sha256(component) != self.execution_component_content_sha256
            or _physical_size_bytes(component) != self.execution_component_size_bytes
            or component.code_commit != pre_policy_scope.locked_manifest.code_commit
            or component.pre_policy_component_authority_id
            != pre_policy_scope.execution_component.component_authority_id
            or component.supported_pre_policy_routes
            != pre_policy_scope.execution_component.supported_routes
        ):
            raise ValueError("M6 closed-policy scope is not one exact offline start cut")
        object.__setattr__(self, "pre_policy_execution_scope", pre_policy_scope)
        object.__setattr__(self, "execution_component", component)
        if _physical_size_bytes(self) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            raise ValueError("M6 closed-policy execution scope exceeds its byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pre_policy_execution_scope_authority_id(self) -> Sha256Hex:
        return self.pre_policy_execution_scope.execution_scope_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_run_id(self) -> ReferenceToken:
        return self.pre_policy_execution_scope.candidate_run_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def command_id(self) -> Sha256Hex:
        return self.pre_policy_execution_scope.command.command_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_dataset_snapshot_id(self) -> Sha256Hex:
        return self.pre_policy_execution_scope.execution_dataset.execution_dataset_snapshot_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_manifest_id(self) -> Sha256Hex:
        return self.pre_policy_execution_scope.locked_manifest.manifest_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def locked_config_sha256(self) -> Sha256Hex:
        return self.pre_policy_execution_scope.locked_config.config_sha256

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_scope_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-execution-scope-authority",
                2,
                self.route,
                self.pre_policy_execution_scope_authority_id,
                self.pre_policy_execution_scope_content_sha256,
                self.pre_policy_execution_scope_size_bytes,
                self.execution_component.component_authority_id,
                self.execution_component_content_sha256,
                self.execution_component_size_bytes,
            ]
        )


class M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2(FrozenContractModel):
    """Durable intent that freezes the exact policy cut before materialization."""

    schema_version: Literal["m6-replay-locked-closed-policy-pending-sample-commitment-v2"] = (
        "m6-replay-locked-closed-policy-pending-sample-commitment-v2"
    )
    execution_scope_authority_id: Sha256Hex
    execution_component_authority_id: Sha256Hex
    locked_config_sha256: Sha256Hex
    route: Literal[M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED] = (
        M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED
    )
    pre_policy_pending_commitment: M6ReplayLockedPendingSampleCommitmentAuthority
    source_binding: M6ReplayLockedClosedPolicySourceBindingAuthority

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "pre_policy_execution_scope_authority_id",
                "pre_policy_execution_component_authority_id",
                "candidate_run_id",
                "command_id",
                "execution_dataset_snapshot_id",
                "source_catalog_entry_id",
                "pre_policy_route",
                "sample_id",
                "execution_entry_id",
                "ledger_sequence",
                "previous_ledger_entry_hash",
                "source_binding_authority_id",
                "policy_causal_cut_authority_id",
                "pending_commitment_authority_id",
            ),
        )
        pending = handler(payload)
        _verify_claims(pending, claims)
        return pending

    @model_validator(mode="after")
    def validate_prebound_policy_cut(self) -> Self:
        pre_policy_pending = _canonical_nested(
            M6ReplayLockedPendingSampleCommitmentAuthority,
            self.pre_policy_pending_commitment,
            "M6 closed-policy pre-policy pending commitment",
        )
        source_binding = _canonical_nested(
            M6ReplayLockedClosedPolicySourceBindingAuthority,
            self.source_binding,
            "M6 closed-policy source binding",
        )
        execution_entry = pre_policy_pending.execution_entry
        if (
            source_binding.source_catalog_entry_id != pre_policy_pending.source_catalog_entry_id
            or source_binding.sample_id != execution_entry.sample_id
            or source_binding.execution_entry_id != execution_entry.execution_entry_id
            or source_binding.replay_input_closure_authority_id
            != execution_entry.replay_input_closure_authority_id
            or source_binding.replay_input_closure_document_sha256
            != execution_entry.replay_input_closure_document_sha256
            or source_binding.pre_policy_route != pre_policy_pending.route
            or source_binding.source_config_sha256 != self.locked_config_sha256
        ):
            raise ValueError(
                "M6 closed-policy pending commitment differs from its frozen source cut"
            )
        object.__setattr__(
            self,
            "pre_policy_pending_commitment",
            pre_policy_pending,
        )
        object.__setattr__(self, "source_binding", source_binding)
        if _physical_size_bytes(self) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            raise ValueError("M6 closed-policy pending commitment exceeds its byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pre_policy_execution_scope_authority_id(self) -> Sha256Hex:
        return self.pre_policy_pending_commitment.execution_scope_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pre_policy_execution_component_authority_id(self) -> Sha256Hex:
        return self.pre_policy_pending_commitment.execution_component_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_run_id(self) -> ReferenceToken:
        return self.pre_policy_pending_commitment.candidate_run_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def command_id(self) -> Sha256Hex:
        return self.pre_policy_pending_commitment.command_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_dataset_snapshot_id(self) -> Sha256Hex:
        return self.pre_policy_pending_commitment.execution_dataset_snapshot_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_catalog_entry_id(self) -> Sha256Hex:
        return self.pre_policy_pending_commitment.source_catalog_entry_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pre_policy_route(self) -> M6ReplayLockedExecutionRoute:
        return self.pre_policy_pending_commitment.route

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_id(self) -> ReferenceToken:
        return self.pre_policy_pending_commitment.sample_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_entry_id(self) -> Sha256Hex:
        return self.pre_policy_pending_commitment.execution_entry_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ledger_sequence(self) -> int:
        return self.pre_policy_pending_commitment.ledger_sequence

    @computed_field  # type: ignore[prop-decorator]
    @property
    def previous_ledger_entry_hash(self) -> Sha256Hex:
        return self.pre_policy_pending_commitment.previous_ledger_entry_hash

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_binding_authority_id(self) -> Sha256Hex:
        return self.source_binding.source_binding_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def policy_causal_cut_authority_id(self) -> Sha256Hex:
        return self.source_binding.policy_causal_cut_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pending_commitment_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-pending-sample-commitment",
                2,
                self.previous_ledger_entry_hash,
                self.ledger_sequence,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.execution_component_authority_id,
                self.locked_config_sha256,
                self.route,
                self.pre_policy_pending_commitment.pending_commitment_authority_id,
                self.source_binding_authority_id,
            ]
        )


class M6ReplayLockedClosedCandidateBindingAuthority(FrozenContractModel):
    """Transient READY witness, pure policy intent, and sole persisted CLOSED Case."""

    schema_version: Literal["m6-replay-locked-closed-candidate-binding-authority-v1"] = (
        "m6-replay-locked-closed-candidate-binding-authority-v1"
    )
    execution_scope_authority_id: Sha256Hex
    pending_commitment_authority_id: Sha256Hex
    source_binding_authority_id: Sha256Hex
    policy_causal_cut_authority_id: Sha256Hex
    pre_policy_route: M6ReplayLockedExecutionRoute
    locked_config_sha256: Sha256Hex
    transient_ready_case: Case
    candidate_alert_policy: AlertPolicyAuthority
    closed_candidate_case: Case
    persisted_candidate_case: M6ReplayLockedCandidateCaseBinding

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "candidate_run_id",
                "sample_id",
                "case_id",
                "transient_ready_case_content_sha256",
                "transient_ready_case_size_bytes",
                "candidate_alert_policy_authority_id",
                "candidate_alert_policy_content_sha256",
                "candidate_alert_policy_size_bytes",
                "closed_candidate_case_content_sha256",
                "closed_candidate_case_size_bytes",
                "closed_candidate_binding_authority_id",
            ),
        )
        binding = handler(payload)
        _verify_claims(binding, claims)
        return binding

    @model_validator(mode="after")
    def validate_exact_ready_to_closed_candidate(self) -> Self:
        ready = _canonical_nested(
            Case,
            self.transient_ready_case,
            "M6 closed-policy transient READY Case",
        )
        policy = _canonical_nested(
            AlertPolicyAuthority,
            self.candidate_alert_policy,
            "M6 closed-policy candidate alert policy",
        )
        closed = _canonical_nested(
            Case,
            self.closed_candidate_case,
            "M6 closed-policy candidate CLOSED Case",
        )
        persisted = _canonical_nested(
            M6ReplayLockedCandidateCaseBinding,
            self.persisted_candidate_case,
            "M6 closed-policy persisted candidate Case binding",
        )
        if not _matches_ready_route(self.pre_policy_route, ready):
            raise ValueError(
                "M6 closed-policy replay requires a READY candidate; REWORK cannot consume a cut"
            )
        verdict = ready.verdicts[-1]
        review = ready.procedural_reviews[-1]
        request = policy.request
        expected_case_authority = sha256_hex(
            ["alert-case-authority", 1, ready.model_dump(mode="json")]
        )
        if (
            request.run_id != ready.run_id
            or request.case_id != ready.case_id
            or request.case_authority_sha256 != expected_case_authority
            or request.source_case_status != ready.status
            or request.config_sha256 != self.locked_config_sha256
            or request.manifest_id != ready.manifest_id
            or request.camera_id != ready.event.camera_id
            or request.stream_id != ready.event.stream_id
            or request.zone_id != ready.event.zone_id
            or request.violation_type != ready.event.violation_type
            or request.primary_track_ref != ready.event.primary_track_ref
            or request.trigger_frame != ready.event.trigger_frame
            or request.hard_rule != ready.event.hard_rule
            or request.verdict_id != verdict.verdict_id
            or request.verdict_version != verdict.version
            or request.verdict_sha256 != verdict.verdict_sha256
            or request.verdict_decision != verdict.decision
            or request.verdict_confidence != verdict.confidence
            or request.recommended_alert_level != verdict.recommended_alert_level
            or request.procedural_review_id != review.review_id
            or request.procedural_review_version != review.version
            or not request.procedural_review_passed
            or request.prior_emergency_delivery is not None
        ):
            raise ValueError(
                "M6 closed-policy candidate policy differs from its transient READY Case"
            )
        if _expected_closed_case(ready, policy) != closed:
            raise ValueError(
                "M6 closed-policy candidate CLOSED Case is not the exact policy successor"
            )
        if (
            policy.target_case_status != CaseStatus.CLOSED
            or policy.final_decision != closed.final_decision
            or (
                policy.disposition == AlertPolicyDisposition.CLOSE_NO_ALERT
                and policy.decision is not None
            )
        ):
            raise ValueError("M6 candidate policy does not close its exact Case")
        if (
            ready.run_id != persisted.candidate_run_id
            or ready.case_id != persisted.case_id
            or closed.run_id != persisted.candidate_run_id
            or closed.case_id != persisted.case_id
            or ready.manifest_id != closed.manifest_id
            or persisted.case_revision != 1
            or persisted.case_document_sha256 != _physical_content_sha256(closed)
            or persisted.case_document_size_bytes != _physical_size_bytes(closed)
        ):
            raise ValueError(
                "M6 closed-policy persistence must contain only one atomic CLOSED Case revision"
            )
        object.__setattr__(self, "transient_ready_case", ready)
        object.__setattr__(self, "candidate_alert_policy", policy)
        object.__setattr__(self, "closed_candidate_case", closed)
        object.__setattr__(self, "persisted_candidate_case", persisted)
        if _physical_size_bytes(self) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            raise ValueError("M6 closed-policy candidate binding exceeds its byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_run_id(self) -> ReferenceToken:
        return self.persisted_candidate_case.candidate_run_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_id(self) -> ReferenceToken:
        return self.persisted_candidate_case.sample_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_id(self) -> ReferenceToken:
        return self.persisted_candidate_case.case_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def transient_ready_case_content_sha256(self) -> Sha256Hex:
        return _physical_content_sha256(self.transient_ready_case)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def transient_ready_case_size_bytes(self) -> int:
        return _physical_size_bytes(self.transient_ready_case)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_alert_policy_authority_id(self) -> Sha256Hex:
        return self.candidate_alert_policy.authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_alert_policy_content_sha256(self) -> Sha256Hex:
        return _physical_content_sha256(self.candidate_alert_policy)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_alert_policy_size_bytes(self) -> int:
        return _physical_size_bytes(self.candidate_alert_policy)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def closed_candidate_case_content_sha256(self) -> Sha256Hex:
        return _physical_content_sha256(self.closed_candidate_case)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def closed_candidate_case_size_bytes(self) -> int:
        return _physical_size_bytes(self.closed_candidate_case)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def closed_candidate_binding_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-candidate-binding-authority",
                1,
                self.execution_scope_authority_id,
                self.pending_commitment_authority_id,
                self.source_binding_authority_id,
                self.policy_causal_cut_authority_id,
                self.pre_policy_route,
                self.locked_config_sha256,
                self.transient_ready_case_content_sha256,
                self.transient_ready_case_size_bytes,
                self.candidate_alert_policy_authority_id,
                self.candidate_alert_policy_content_sha256,
                self.candidate_alert_policy_size_bytes,
                self.closed_candidate_case_content_sha256,
                self.closed_candidate_case_size_bytes,
                self.persisted_candidate_case.case_binding_id,
            ]
        )


class M6ReplayLockedClosedPolicySampleExecutionRecordV2(FrozenContractModel):
    """Trusted join of source policy truth and one independently persisted close."""

    schema_version: Literal["m6-replay-locked-closed-policy-sample-execution-record-v2"] = (
        "m6-replay-locked-closed-policy-sample-execution-record-v2"
    )
    execution_scope_authority_id: Sha256Hex
    candidate_run_id: ReferenceToken
    command_id: Sha256Hex
    execution_dataset_snapshot_id: Sha256Hex
    candidate_manifest_id: Sha256Hex
    route: Literal[M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED] = (
        M6ReplayLockedClosedPolicyExecutionRoute.ALERT_POLICY_CLOSED
    )
    outcome: Literal[M6ReplayExecutionOutcome.CASE_REPLAYED] = (
        M6ReplayExecutionOutcome.CASE_REPLAYED
    )
    execution_entry: M6RegressionExecutionEntry
    pending_commitment: M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2
    replay_input_closure: M6ReplayInputClosureAuthority
    source_determinism: M6ReplayLockedSourceDeterminismAuthority
    policy_causal_cut: M6ReplayLockedAlertPolicyCausalCutAuthority
    closed_candidate_binding: M6ReplayLockedClosedCandidateBindingAuthority
    candidate_snapshot: M6CaseReplaySnapshot
    ledger_sequence: int = Field(ge=0, strict=True)
    previous_ledger_entry_hash: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M6 closed-policy candidate run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "sample_id",
                "execution_entry_id",
                "pending_commitment_authority_id",
                "source_snapshot_id",
                "source_semantic_case_hash",
                "candidate_snapshot_id",
                "candidate_semantic_case_hash",
                "candidate_snapshot_content_sha256",
                "candidate_snapshot_size_bytes",
                "sample_execution_record_id",
            ),
        )
        record = handler(payload)
        _verify_claims(record, claims)
        return record

    @model_validator(mode="after")
    def validate_complete_closed_record(self) -> Self:
        entry = _canonical_nested(
            M6RegressionExecutionEntry,
            self.execution_entry,
            "M6 closed-policy execution entry",
        )
        pending = _canonical_nested(
            M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
            self.pending_commitment,
            "M6 closed-policy pending commitment",
        )
        closure = _canonical_nested(
            M6ReplayInputClosureAuthority,
            self.replay_input_closure,
            "M6 closed-policy replay input closure",
        )
        proof = _canonical_nested(
            M6ReplayLockedSourceDeterminismAuthority,
            self.source_determinism,
            "M6 closed-policy source determinism",
        )
        cut = _canonical_nested(
            M6ReplayLockedAlertPolicyCausalCutAuthority,
            self.policy_causal_cut,
            "M6 closed-policy full causal cut",
        )
        candidate = _canonical_nested(
            M6ReplayLockedClosedCandidateBindingAuthority,
            self.closed_candidate_binding,
            "M6 closed-policy candidate binding",
        )
        snapshot = _canonical_nested(
            M6CaseReplaySnapshot,
            self.candidate_snapshot,
            "M6 closed-policy candidate snapshot",
        )
        source_binding = pending.source_binding
        entry_identity = (
            entry.sample_id,
            entry.input_authority_id,
            entry.input_authority_document_sha256,
            entry.replay_input_closure_authority_id,
            entry.replay_input_closure_document_sha256,
        )
        closure_identity = (
            closure.sample_id,
            closure.input_authority_id,
            closure.input_authority_document_sha256,
            closure.replay_input_closure_authority_id,
            closure.replay_input_closure_document_sha256,
        )
        if entry_identity != closure_identity:
            raise ValueError("M6 closed-policy input closure differs from its execution entry")
        if (
            pending.execution_scope_authority_id != self.execution_scope_authority_id
            or pending.candidate_run_id != self.candidate_run_id
            or pending.command_id != self.command_id
            or pending.execution_dataset_snapshot_id != self.execution_dataset_snapshot_id
            or pending.route != self.route
            or pending.pre_policy_pending_commitment.execution_entry != entry
            or pending.ledger_sequence != self.ledger_sequence
            or pending.previous_ledger_entry_hash != self.previous_ledger_entry_hash
        ):
            raise ValueError("M6 closed-policy pending commitment differs from its sample record")
        if (
            source_binding.policy_causal_cut_authority_id != cut.policy_causal_cut_authority_id
            or source_binding.policy_causal_cut_content_sha256 != _physical_content_sha256(cut)
            or source_binding.policy_causal_cut_size_bytes != _physical_size_bytes(cut)
            or source_binding.sample_id != cut.sample_id
            or source_binding.replay_input_closure_authority_id
            != cut.replay_input_closure_authority_id
            or source_binding.replay_input_closure_document_sha256
            != cut.replay_input_closure_document_sha256
            or source_binding.source_config_sha256 != cut.source_config_sha256
            or source_binding.cooldown_causal_head != cut.cooldown_causal_head
            or source_binding.emergency_causal_basis != cut.emergency_causal_basis
        ):
            raise ValueError(
                "M6 closed-policy full causal cut differs from its prebound safe identity"
            )
        if (
            closure.source_case_id is None
            or closure.source_case_revision is None
            or closure.source_case_document_sha256 is None
            or cut.source_identity_sha256 != proof.source_identity_sha256
            or cut.source_closed_case.run_id != closure.source_run_id
            or cut.source_closed_case.case_id != closure.source_case_id
            or cut.source_closed_case_revision != closure.source_case_revision
            or cut.source_closed_case_content_sha256 != closure.source_case_document_sha256
            or cut.source_closed_case.manifest_id != closure.source_manifest_id
            or cut.source_validation_report_id != closure.source_validation_report_id
            or cut.source_validation_report_document_sha256
            != closure.source_validation_report_document_sha256
        ):
            raise ValueError("M6 closed-policy causal cut does not close the selected source Case")
        if (
            proof.command_id != self.command_id
            or proof.execution_entry_id != entry.execution_entry_id
            or proof.sample_id != entry.sample_id
            or proof.source_run_id != closure.source_run_id
            or proof.candidate_run_id != self.candidate_run_id
            or proof.source_manifest_id != closure.source_manifest_id
            or proof.replay_input_closure_authority_id != closure.replay_input_closure_authority_id
            or proof.replay_input_closure_document_sha256
            != closure.replay_input_closure_document_sha256
        ):
            raise ValueError(
                "M6 closed-policy source proof differs from its sample execution scope"
            )
        if (
            candidate.execution_scope_authority_id != self.execution_scope_authority_id
            or candidate.pending_commitment_authority_id != pending.pending_commitment_authority_id
            or candidate.source_binding_authority_id != source_binding.source_binding_authority_id
            or candidate.policy_causal_cut_authority_id != cut.policy_causal_cut_authority_id
            or candidate.pre_policy_route != pending.pre_policy_route
            or candidate.locked_config_sha256 != pending.locked_config_sha256
            or candidate.candidate_run_id != self.candidate_run_id
            or candidate.sample_id != entry.sample_id
            or candidate.persisted_candidate_case.case_audit_sequence != self.ledger_sequence
            or candidate.candidate_alert_policy.request.prior_cooldown
            != source_binding.cooldown_causal_head.prior_authority
            or candidate.candidate_alert_policy.request.prior_emergency_delivery is not None
        ):
            raise ValueError(
                "M6 closed-policy candidate differs from its frozen pending commitment"
            )
        if (
            not _matches_ready_route(
                pending.pre_policy_route,
                cut.source_ready_case,
            )
            or _policy_input_semantic_projection(candidate.candidate_alert_policy)
            != _policy_input_semantic_projection(cut.source_alert_policy)
            or _alert_semantic_projection(candidate.candidate_alert_policy)
            != _alert_semantic_projection(cut.source_alert_policy)
        ):
            raise ValueError(
                "M6 closed-policy candidate policy is not source-semantically identical"
            )
        closed = candidate.closed_candidate_case
        decision = candidate.candidate_alert_policy.decision
        expected_highest = None if decision is None or decision.rescinded else decision.level
        if (
            candidate.persisted_candidate_case.case_document_sha256
            == closure.source_case_document_sha256
            or snapshot.sample_id != entry.sample_id
            or snapshot.source_run_id != self.candidate_run_id
            or snapshot.source_case_id != candidate.case_id
            or snapshot.source_case_revision != candidate.persisted_candidate_case.case_revision
            or snapshot.source_case_document_sha256
            != candidate.closed_candidate_case_content_sha256
            or snapshot.manifest_id != self.candidate_manifest_id
            or snapshot.case_status != CaseStatus.CLOSED
            or snapshot.final_decision != closed.final_decision
            or snapshot.highest_alert_level != expected_highest
            or snapshot.snapshot_id == proof.first_source_snapshot_id
            or snapshot.semantic_case_hash != proof.first_semantic_case_hash
        ):
            raise ValueError(
                "M6 closed-policy candidate snapshot is not the independent final CLOSED output"
            )
        if (self.ledger_sequence == 0) != (self.previous_ledger_entry_hash == AUDIT_GENESIS_HASH):
            raise ValueError("M6 closed-policy sample ledger genesis binding is invalid")
        object.__setattr__(self, "execution_entry", entry)
        object.__setattr__(self, "pending_commitment", pending)
        object.__setattr__(self, "replay_input_closure", closure)
        object.__setattr__(self, "source_determinism", proof)
        object.__setattr__(self, "policy_causal_cut", cut)
        object.__setattr__(self, "closed_candidate_binding", candidate)
        object.__setattr__(self, "candidate_snapshot", snapshot)
        if _physical_size_bytes(self) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            raise ValueError("M6 closed-policy sample record exceeds its byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_id(self) -> ReferenceToken:
        return self.execution_entry.sample_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_entry_id(self) -> Sha256Hex:
        return self.execution_entry.execution_entry_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pending_commitment_authority_id(self) -> Sha256Hex:
        return self.pending_commitment.pending_commitment_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_snapshot_id(self) -> Sha256Hex:
        return self.source_determinism.first_source_snapshot_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def source_semantic_case_hash(self) -> Sha256Hex:
        return self.source_determinism.first_semantic_case_hash

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_snapshot_id(self) -> Sha256Hex:
        return self.candidate_snapshot.snapshot_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_semantic_case_hash(self) -> Sha256Hex:
        return self.candidate_snapshot.semantic_case_hash

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_snapshot_content_sha256(self) -> Sha256Hex:
        return _physical_content_sha256(self.candidate_snapshot)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_snapshot_size_bytes(self) -> int:
        return _physical_size_bytes(self.candidate_snapshot)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_record_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-sample-execution-record",
                2,
                self.previous_ledger_entry_hash,
                self.ledger_sequence,
                self.execution_scope_authority_id,
                self.candidate_run_id,
                self.command_id,
                self.execution_dataset_snapshot_id,
                self.candidate_manifest_id,
                self.route,
                self.execution_entry_id,
                self.pending_commitment_authority_id,
                self.replay_input_closure.replay_input_closure_authority_id,
                self.source_determinism.source_determinism_authority_id,
                self.policy_causal_cut.policy_causal_cut_authority_id,
                self.closed_candidate_binding.closed_candidate_binding_authority_id,
                self.candidate_snapshot_id,
                self.candidate_snapshot_content_sha256,
                self.candidate_snapshot_size_bytes,
            ]
        )


class M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2(FrozenContractModel):
    """Terminal proof that replay caused no provider or policy side effect."""

    schema_version: Literal["m6-replay-locked-closed-policy-run-trap-seal-authority-v2"] = (
        "m6-replay-locked-closed-policy-run-trap-seal-authority-v2"
    )
    execution_scope_authority_id: Sha256Hex
    command_id: Sha256Hex
    candidate_run_id: ReferenceToken
    execution_component_authority_id: Sha256Hex
    counters: M6ProviderCapabilityCounters
    persisted_transient_ready_case_count: Literal[0] = 0
    candidate_alert_outbox_write_count: Literal[0] = 0
    candidate_cooldown_write_count: Literal[0] = 0
    sealed_sample_execution_count: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_CASES,
        strict=True,
    )
    sealed_sample_execution_inventory_root_sha256: Sha256Hex
    terminal_ledger_sequence: int = Field(ge=0, strict=True)
    terminal_sample_execution_record_id: Sha256Hex

    @field_validator("candidate_run_id")
    @classmethod
    def validate_candidate_run_id(cls, value: str) -> str:
        return require_portable_run_id(value, "M6 closed-policy trap candidate run_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "external_capability_call_count",
                "forbidden_policy_side_effect_count",
                "clean",
                "provider_trap",
                "run_trap_seal_authority_id",
            ),
        )
        seal = handler(payload)
        _verify_claims(seal, claims)
        return seal

    @model_validator(mode="after")
    def validate_terminal_clean_trap(self) -> Self:
        counters = _canonical_nested(
            M6ProviderCapabilityCounters,
            self.counters,
            "M6 closed-policy run trap counters",
        )
        if self.terminal_ledger_sequence != self.sealed_sample_execution_count - 1:
            raise ValueError("M6 closed-policy trap was not sealed after its terminal record")
        if counters.total != 0 or self.forbidden_policy_side_effect_count != 0:
            raise ValueError(
                "M6 closed-policy run trap observed a forbidden capability or side effect"
            )
        object.__setattr__(self, "counters", counters)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def external_capability_call_count(self) -> int:
        return self.counters.total

    @computed_field  # type: ignore[prop-decorator]
    @property
    def forbidden_policy_side_effect_count(self) -> int:
        return (
            self.persisted_transient_ready_case_count
            + self.candidate_alert_outbox_write_count
            + self.candidate_cooldown_write_count
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def clean(self) -> bool:
        return (
            self.external_capability_call_count == 0
            and self.forbidden_policy_side_effect_count == 0
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_trap(self) -> M6ProviderTrapAuthority:
        return M6ProviderTrapAuthority(
            command_id=self.command_id,
            candidate_run_id=self.candidate_run_id,
            execution_component_manifest_id=self.execution_component_authority_id,
            counters=self.counters,
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def run_trap_seal_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-run-trap-seal-authority",
                2,
                self.execution_scope_authority_id,
                self.command_id,
                self.candidate_run_id,
                self.execution_component_authority_id,
                self.provider_trap.provider_trap_authority_id,
                self.provider_trap.provider_trap_document_sha256,
                self.persisted_transient_ready_case_count,
                self.candidate_alert_outbox_write_count,
                self.candidate_cooldown_write_count,
                self.sealed_sample_execution_count,
                self.sealed_sample_execution_inventory_root_sha256,
                self.terminal_ledger_sequence,
                self.terminal_sample_execution_record_id,
            ]
        )


class M6ReplayLockedClosedPolicyExecutionSealAuthorityV2(FrozenContractModel):
    """Complete CLOSED inventory and run-wide zero-side-effect seal."""

    schema_version: Literal["m6-replay-locked-closed-policy-execution-seal-authority-v2"] = (
        "m6-replay-locked-closed-policy-execution-seal-authority-v2"
    )
    execution_scope: M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2
    execution_scope_content_sha256: Sha256Hex
    execution_scope_size_bytes: int = Field(
        gt=0,
        le=MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES,
        strict=True,
    )
    candidate_audit_head_sequence: int = Field(ge=0, strict=True)
    candidate_audit_head_hash: Sha256Hex
    sample_executions: tuple[
        M6ReplayLockedClosedPolicySampleExecutionRecordV2,
        ...,
    ] = Field(min_length=1, max_length=MAX_M6_REGRESSION_CASES)
    run_trap_seal: M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(
            value,
            (
                "sample_execution_count",
                "sample_execution_inventory_root_sha256",
                "candidate_case_count",
                "candidate_case_inventory_root_sha256",
                "execution_receipts",
                "execution_receipt_count",
                "execution_receipt_inventory_root_sha256",
                "execution_seal_authority_id",
            ),
        )
        seal = handler(payload)
        _verify_claims(seal, claims)
        return seal

    @model_validator(mode="after")
    def validate_complete_terminal_inventory(self) -> Self:
        scope = _canonical_nested(
            M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
            self.execution_scope,
            "M6 closed-policy execution scope",
        )
        records = tuple(
            _canonical_nested(
                M6ReplayLockedClosedPolicySampleExecutionRecordV2,
                item,
                "M6 closed-policy sample execution record",
            )
            for item in self.sample_executions
        )
        trap = _canonical_nested(
            M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2,
            self.run_trap_seal,
            "M6 closed-policy run trap seal",
        )
        if (
            _physical_content_sha256(scope) != self.execution_scope_content_sha256
            or _physical_size_bytes(scope) != self.execution_scope_size_bytes
        ):
            raise ValueError("M6 closed-policy terminal scope physical content differs")
        pre_policy_scope = scope.pre_policy_execution_scope
        if len(records) != len(pre_policy_scope.execution_dataset.entries):
            raise ValueError("M6 closed-policy terminal inventory must cover every execution entry")
        previous = AUDIT_GENESIS_HASH
        supported_routes = set(pre_policy_scope.execution_component.supported_routes)
        for index, (entry, source_catalog_entry_id, record) in enumerate(
            zip(
                pre_policy_scope.execution_dataset.entries,
                pre_policy_scope.source_catalog_entry_ids,
                records,
                strict=True,
            )
        ):
            pending = record.pending_commitment
            if (
                record.ledger_sequence != index
                or record.previous_ledger_entry_hash != previous
                or record.execution_scope_authority_id != scope.execution_scope_authority_id
                or record.candidate_run_id != scope.candidate_run_id
                or record.command_id != scope.command_id
                or record.execution_dataset_snapshot_id != scope.execution_dataset_snapshot_id
                or record.candidate_manifest_id != scope.candidate_manifest_id
                or record.execution_entry != entry
                or pending.execution_component_authority_id
                != scope.execution_component.component_authority_id
                or pending.pre_policy_execution_scope_authority_id
                != pre_policy_scope.execution_scope_authority_id
                or pending.pre_policy_execution_component_authority_id
                != pre_policy_scope.execution_component.component_authority_id
                or pending.source_catalog_entry_id != source_catalog_entry_id
                or pending.pre_policy_route not in supported_routes
                or pending.locked_config_sha256 != scope.locked_config_sha256
                or record.source_determinism.execution_component_manifest_id
                != pre_policy_scope.execution_component.component_authority_id
                or record.closed_candidate_binding.persisted_candidate_case.case_audit_sequence
                != index
                or record.closed_candidate_binding.closed_candidate_case.status != CaseStatus.CLOSED
            ):
                raise ValueError("M6 closed-policy sample chain or execution scope differs")
            previous = record.sample_execution_record_id
        case_ids = tuple(item.closed_candidate_binding.case_id for item in records)
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("M6 closed-policy candidate Case bindings must be unique")
        source_catalog_entry_ids = tuple(
            item.pending_commitment.source_catalog_entry_id for item in records
        )
        if len(source_catalog_entry_ids) != len(set(source_catalog_entry_ids)):
            raise ValueError("M6 closed-policy source catalog bindings must be unique")
        if (
            self.candidate_audit_head_sequence != len(records) - 1
            or self.candidate_audit_head_hash
            != records[-1].closed_candidate_binding.persisted_candidate_case.case_audit_entry_hash
        ):
            raise ValueError("M6 closed-policy audit head is not the terminal CLOSED Case anchor")
        if (
            trap.execution_scope_authority_id != scope.execution_scope_authority_id
            or trap.command_id != scope.command_id
            or trap.candidate_run_id != scope.candidate_run_id
            or trap.execution_component_authority_id
            != scope.execution_component.component_authority_id
            or trap.sealed_sample_execution_count != len(records)
            or trap.sealed_sample_execution_inventory_root_sha256
            != self.sample_execution_inventory_root_sha256
            or trap.terminal_ledger_sequence != len(records) - 1
            or trap.terminal_sample_execution_record_id != records[-1].sample_execution_record_id
            or not trap.clean
        ):
            raise ValueError("M6 closed-policy run trap seal differs from terminal inventory")
        object.__setattr__(self, "execution_scope", scope)
        object.__setattr__(self, "sample_executions", records)
        object.__setattr__(self, "run_trap_seal", trap)
        if _physical_size_bytes(self) > MAX_M6_REPLAY_LOCKED_EXECUTION_DOCUMENT_BYTES:
            raise ValueError("M6 closed-policy execution seal exceeds its byte budget")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_count(self) -> int:
        return len(self.sample_executions)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def sample_execution_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-sample-execution-inventory",
                2,
                [item.sample_execution_record_id for item in self.sample_executions],
            ]
        )

    def _candidate_case_binding_ids(self) -> tuple[Sha256Hex, ...]:
        return tuple(
            item.closed_candidate_binding.persisted_candidate_case.case_binding_id
            for item in self.sample_executions
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_case_count(self) -> int:
        return len(self.sample_executions)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_case_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-candidate-case-inventory",
                2,
                self._candidate_case_binding_ids(),
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_receipts(self) -> tuple[M6ReplayExecutionReceipt, ...]:
        provider_trap = self.run_trap_seal.provider_trap
        scope = self.execution_scope
        return tuple(
            M6ReplayExecutionReceipt(
                command_id=scope.command_id,
                mode=ReproducibilityMode.REPLAY_LOCKED,
                sample_id=record.sample_id,
                execution_entry_id=record.execution_entry_id,
                candidate_run_id=scope.candidate_run_id,
                candidate_manifest_id=scope.candidate_manifest_id,
                execution_component_manifest_id=(scope.execution_component.component_authority_id),
                outcome=record.outcome,
                candidate_snapshot_id=record.candidate_snapshot_id,
                detection_count=record.replay_input_closure.detection_count,
                detection_inventory_root_sha256=(
                    record.replay_input_closure.detection_inventory_root_sha256
                ),
                model_response_count=record.replay_input_closure.model_response_count,
                model_response_inventory_root_sha256=(
                    record.replay_input_closure.model_response_inventory_root_sha256
                ),
                embedding_count=record.replay_input_closure.embedding_count,
                embedding_inventory_root_sha256=(
                    record.replay_input_closure.embedding_inventory_root_sha256
                ),
                tool_result_count=record.replay_input_closure.tool_result_count,
                tool_result_inventory_root_sha256=(
                    record.replay_input_closure.tool_result_inventory_root_sha256
                ),
                provider_call_count=provider_trap.external_capability_call_count,
                provider_trap_authority_id=provider_trap.provider_trap_authority_id,
                provider_trap_document_sha256=(provider_trap.provider_trap_document_sha256),
            )
            for record in self.sample_executions
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_receipt_count(self) -> int:
        return len(self.execution_receipts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_receipt_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-execution-receipt-inventory",
                2,
                [item.execution_receipt_id for item in self.execution_receipts],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_seal_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-locked-closed-policy-execution-seal-authority",
                2,
                self.execution_scope.execution_scope_authority_id,
                self.execution_scope_content_sha256,
                self.execution_scope_size_bytes,
                self.candidate_audit_head_sequence,
                self.candidate_audit_head_hash,
                self.sample_execution_count,
                self.sample_execution_inventory_root_sha256,
                self.candidate_case_count,
                self.candidate_case_inventory_root_sha256,
                self.run_trap_seal.run_trap_seal_authority_id,
                self.execution_receipt_count,
                self.execution_receipt_inventory_root_sha256,
            ]
        )


__all__ = [
    "M6ReplayLockedClosedCandidateBindingAuthority",
    "M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2",
    "M6ReplayLockedClosedPolicyExecutionRoute",
    "M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2",
    "M6ReplayLockedClosedPolicyExecutionSealAuthorityV2",
    "M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2",
    "M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2",
    "M6ReplayLockedClosedPolicySampleExecutionRecordV2",
    "M6ReplayLockedClosedPolicySourceBindingAuthority",
]
