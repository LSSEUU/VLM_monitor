"""M8 role authority and human-controlled operational-case contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M8_ACTOR_SCOPE_LOCATIONS = 10_000
MAX_M8_CASE_SOURCES = 64
MAX_M8_CASE_AUTHORITIES = 64


class M8ActorRole(StrEnum):
    LEADER = "LEADER"
    SAFETY_OFFICER = "SAFETY_OFFICER"
    STUDENT = "STUDENT"
    OPERATIONS = "OPERATIONS"


class M8ActorScopeKind(StrEnum):
    CAMPUS_WIDE = "CAMPUS_WIDE"
    LOCATIONS = "LOCATIONS"
    SELF_ONLY = "SELF_ONLY"


class M8Capability(StrEnum):
    VIEW_GLOBAL_OVERVIEW = "VIEW_GLOBAL_OVERVIEW"
    VIEW_MAJOR_EVENTS = "VIEW_MAJOR_EVENTS"
    VIEW_AUDIT = "VIEW_AUDIT"
    CONFIRM_CASE = "CONFIRM_CASE"
    REJECT_CASE = "REJECT_CASE"
    REQUEST_CASE_EVIDENCE = "REQUEST_CASE_EVIDENCE"
    RETURN_CASE_TO_VERIFICATION = "RETURN_CASE_TO_VERIFICATION"
    RESOLVE_CASE = "RESOLVE_CASE"
    RESOLVE_APPEAL = "RESOLVE_APPEAL"
    MANAGE_RULES = "MANAGE_RULES"
    VIEW_OWN_CASE = "VIEW_OWN_CASE"
    SUBMIT_EXPLANATION = "SUBMIT_EXPLANATION"
    SUBMIT_APPEAL = "SUBMIT_APPEAL"
    MANAGE_DEVICES = "MANAGE_DEVICES"
    VIEW_DEVICE_HEALTH = "VIEW_DEVICE_HEALTH"


class M8OperationalRiskLevel(StrEnum):
    REMINDER = "REMINDER"
    GENERAL = "GENERAL"
    SEVERE = "SEVERE"
    EMERGENCY = "EMERGENCY"


class M8OperationalCaseStatus(StrEnum):
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    EVIDENCE_REQUESTED = "EVIDENCE_REQUESTED"
    RESOLVED = "RESOLVED"
    APPEALED = "APPEALED"
    APPEAL_RESOLVED = "APPEAL_RESOLVED"


class M8OperationalCaseAction(StrEnum):
    CONFIRM = "CONFIRM"
    REJECT = "REJECT"
    REQUEST_EVIDENCE = "REQUEST_EVIDENCE"
    RETURN_TO_VERIFICATION = "RETURN_TO_VERIFICATION"
    RESOLVE = "RESOLVE"
    SUBMIT_APPEAL = "SUBMIT_APPEAL"
    RESOLVE_APPEAL = "RESOLVE_APPEAL"


class M8OperationalCaseReasonCode(StrEnum):
    VERIFIED_VIOLATION = "VERIFIED_VIOLATION"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_ACTIONABLE = "NOT_ACTIONABLE"
    MORE_EVIDENCE_REQUIRED = "MORE_EVIDENCE_REQUIRED"
    EVIDENCE_RECEIVED = "EVIDENCE_RECEIVED"
    HAZARD_CLEARED = "HAZARD_CLEARED"
    CORRECTIVE_ACTION_COMPLETED = "CORRECTIVE_ACTION_COMPLETED"
    SUBJECT_DISPUTE = "SUBJECT_DISPUTE"
    APPEAL_UPHELD = "APPEAL_UPHELD"
    APPEAL_OVERTURNED = "APPEAL_OVERTURNED"


class M8AppealResolution(StrEnum):
    UPHELD = "UPHELD"
    OVERTURNED = "OVERTURNED"


class M8AuthorityReferenceKind(StrEnum):
    SOURCE_CATALOG = "SOURCE_CATALOG"
    SENSOR_SIGNAL = "SENSOR_SIGNAL"
    VIDEO_EVENT = "VIDEO_EVENT"
    M0_CASE = "M0_CASE"
    USER_STATEMENT = "USER_STATEMENT"
    NOTIFICATION_REPLY = "NOTIFICATION_REPLY"
    EVIDENCE_PACK = "EVIDENCE_PACK"
    RESERVATION = "RESERVATION"


_ROLE_CAPABILITIES: dict[M8ActorRole, tuple[M8Capability, ...]] = {
    M8ActorRole.LEADER: (
        M8Capability.VIEW_GLOBAL_OVERVIEW,
        M8Capability.VIEW_MAJOR_EVENTS,
        M8Capability.VIEW_AUDIT,
    ),
    M8ActorRole.SAFETY_OFFICER: (
        M8Capability.VIEW_GLOBAL_OVERVIEW,
        M8Capability.VIEW_MAJOR_EVENTS,
        M8Capability.VIEW_AUDIT,
        M8Capability.CONFIRM_CASE,
        M8Capability.REJECT_CASE,
        M8Capability.REQUEST_CASE_EVIDENCE,
        M8Capability.RETURN_CASE_TO_VERIFICATION,
        M8Capability.RESOLVE_CASE,
        M8Capability.RESOLVE_APPEAL,
        M8Capability.MANAGE_RULES,
    ),
    M8ActorRole.STUDENT: (
        M8Capability.VIEW_OWN_CASE,
        M8Capability.SUBMIT_EXPLANATION,
        M8Capability.SUBMIT_APPEAL,
    ),
    M8ActorRole.OPERATIONS: (
        M8Capability.MANAGE_DEVICES,
        M8Capability.VIEW_DEVICE_HEALTH,
    ),
}


_ACTION_SOURCE_STATUSES: dict[M8OperationalCaseAction, tuple[M8OperationalCaseStatus, ...]] = {
    M8OperationalCaseAction.CONFIRM: (M8OperationalCaseStatus.PENDING_VERIFICATION,),
    M8OperationalCaseAction.REJECT: (M8OperationalCaseStatus.PENDING_VERIFICATION,),
    M8OperationalCaseAction.REQUEST_EVIDENCE: (M8OperationalCaseStatus.PENDING_VERIFICATION,),
    M8OperationalCaseAction.RETURN_TO_VERIFICATION: (M8OperationalCaseStatus.EVIDENCE_REQUESTED,),
    M8OperationalCaseAction.RESOLVE: (M8OperationalCaseStatus.CONFIRMED,),
    M8OperationalCaseAction.SUBMIT_APPEAL: (
        M8OperationalCaseStatus.CONFIRMED,
        M8OperationalCaseStatus.RESOLVED,
    ),
    M8OperationalCaseAction.RESOLVE_APPEAL: (M8OperationalCaseStatus.APPEALED,),
}
_ACTION_TARGET_STATUS = {
    M8OperationalCaseAction.CONFIRM: M8OperationalCaseStatus.CONFIRMED,
    M8OperationalCaseAction.REJECT: M8OperationalCaseStatus.REJECTED,
    M8OperationalCaseAction.REQUEST_EVIDENCE: M8OperationalCaseStatus.EVIDENCE_REQUESTED,
    M8OperationalCaseAction.RETURN_TO_VERIFICATION: (M8OperationalCaseStatus.PENDING_VERIFICATION),
    M8OperationalCaseAction.RESOLVE: M8OperationalCaseStatus.RESOLVED,
    M8OperationalCaseAction.SUBMIT_APPEAL: M8OperationalCaseStatus.APPEALED,
    M8OperationalCaseAction.RESOLVE_APPEAL: M8OperationalCaseStatus.APPEAL_RESOLVED,
}
_ACTION_CAPABILITY = {
    M8OperationalCaseAction.CONFIRM: M8Capability.CONFIRM_CASE,
    M8OperationalCaseAction.REJECT: M8Capability.REJECT_CASE,
    M8OperationalCaseAction.REQUEST_EVIDENCE: M8Capability.REQUEST_CASE_EVIDENCE,
    M8OperationalCaseAction.RETURN_TO_VERIFICATION: (M8Capability.RETURN_CASE_TO_VERIFICATION),
    M8OperationalCaseAction.RESOLVE: M8Capability.RESOLVE_CASE,
    M8OperationalCaseAction.SUBMIT_APPEAL: M8Capability.SUBMIT_APPEAL,
    M8OperationalCaseAction.RESOLVE_APPEAL: M8Capability.RESOLVE_APPEAL,
}
_ACTION_REASON_CODES: dict[M8OperationalCaseAction, tuple[M8OperationalCaseReasonCode, ...]] = {
    M8OperationalCaseAction.CONFIRM: (M8OperationalCaseReasonCode.VERIFIED_VIOLATION,),
    M8OperationalCaseAction.REJECT: (
        M8OperationalCaseReasonCode.FALSE_POSITIVE,
        M8OperationalCaseReasonCode.NOT_ACTIONABLE,
    ),
    M8OperationalCaseAction.REQUEST_EVIDENCE: (M8OperationalCaseReasonCode.MORE_EVIDENCE_REQUIRED,),
    M8OperationalCaseAction.RETURN_TO_VERIFICATION: (
        M8OperationalCaseReasonCode.EVIDENCE_RECEIVED,
    ),
    M8OperationalCaseAction.RESOLVE: (
        M8OperationalCaseReasonCode.HAZARD_CLEARED,
        M8OperationalCaseReasonCode.CORRECTIVE_ACTION_COMPLETED,
    ),
    M8OperationalCaseAction.SUBMIT_APPEAL: (M8OperationalCaseReasonCode.SUBJECT_DISPUTE,),
    M8OperationalCaseAction.RESOLVE_APPEAL: (
        M8OperationalCaseReasonCode.APPEAL_UPHELD,
        M8OperationalCaseReasonCode.APPEAL_OVERTURNED,
    ),
}


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    if not claims:
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 authority")


def _validate_visible_text(value: str, name: str) -> str:
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError(f"M8 {name} must be bounded visible text without edge whitespace")
    return value


def _actor_authority_json_schema(schema: dict[str, Any]) -> None:
    branches: list[dict[str, Any]] = []
    for role, capabilities in _ROLE_CAPABILITIES.items():
        then: dict[str, Any] = {
            "properties": {
                "capabilities": {"const": [capability.value for capability in capabilities]}
            }
        }
        if role == M8ActorRole.LEADER:
            then["properties"].update(
                {
                    "scope_kind": {"const": M8ActorScopeKind.CAMPUS_WIDE.value},
                    "scope_location_ids": {"maxItems": 0},
                }
            )
        elif role == M8ActorRole.STUDENT:
            then["properties"].update(
                {
                    "scope_kind": {"const": M8ActorScopeKind.SELF_ONLY.value},
                    "scope_location_ids": {"maxItems": 0},
                }
            )
        else:
            then["properties"].update(
                {
                    "scope_kind": {
                        "enum": [
                            M8ActorScopeKind.CAMPUS_WIDE.value,
                            M8ActorScopeKind.LOCATIONS.value,
                        ]
                    }
                }
            )
            then["allOf"] = [
                {
                    "if": {
                        "properties": {"scope_kind": {"const": M8ActorScopeKind.LOCATIONS.value}},
                        "required": ["scope_kind"],
                    },
                    "then": {"properties": {"scope_location_ids": {"minItems": 1}}},
                    "else": {"properties": {"scope_location_ids": {"maxItems": 0}}},
                }
            ]
        branches.append(
            {
                "if": {
                    "properties": {"role": {"const": role.value}},
                    "required": ["role"],
                },
                "then": then,
            }
        )
    schema["allOf"] = branches


def _create_command_json_schema(schema: dict[str, Any]) -> None:
    schema["allOf"] = [
        {
            "properties": {
                "initial_status": {"const": M8OperationalCaseStatus.PENDING_VERIFICATION.value},
                "human_verification_required": {"const": True},
                "direct_disciplinary_action_permitted": {"const": False},
            }
        },
        {
            "if": {
                "properties": {"simulated_source_ids": {"minItems": 1}},
                "required": ["simulated_source_ids"],
            },
            "then": {
                "properties": {
                    "simulation_disclosure_required": {"const": True},
                    "display_badge": {"const": "SIMULATED INPUT · PENDING VERIFICATION"},
                }
            },
            "else": {
                "properties": {
                    "simulation_disclosure_required": {"const": False},
                    "display_badge": {"const": "LIVE INPUT · PENDING VERIFICATION"},
                }
            },
        },
    ]


def _transition_command_json_schema(schema: dict[str, Any]) -> None:
    branches: list[dict[str, Any]] = [
        {
            "properties": {
                "explicit_human_confirmation": {"const": True},
                "direct_disciplinary_action_permitted": {"const": False},
            }
        }
    ]
    for action in M8OperationalCaseAction:
        resolution_schema: dict[str, Any]
        if action == M8OperationalCaseAction.RESOLVE_APPEAL:
            resolution_schema = {"enum": [item.value for item in M8AppealResolution]}
        else:
            resolution_schema = {"type": "null"}
        branches.append(
            {
                "if": {
                    "properties": {"action": {"const": action.value}},
                    "required": ["action"],
                },
                "then": {
                    "properties": {
                        "source_status": {
                            "enum": [item.value for item in _ACTION_SOURCE_STATUSES[action]]
                        },
                        "target_status": {"const": _ACTION_TARGET_STATUS[action].value},
                        "required_capability": {"const": _ACTION_CAPABILITY[action].value},
                        "reason_code": {
                            "enum": [item.value for item in _ACTION_REASON_CODES[action]]
                        },
                        "appeal_resolution": resolution_schema,
                    }
                },
            }
        )
    schema["allOf"] = branches


class M8AuthorityReference(FrozenContractModel):
    """Typed reference to source evidence or another persisted authority."""

    schema_version: Literal["m8-authority-reference-v1"] = "m8-authority-reference-v1"
    kind: M8AuthorityReferenceKind
    authority_id: ReferenceToken
    document_sha256: Sha256Hex

    @field_validator("authority_id")
    @classmethod
    def validate_authority_id(cls, value: str) -> str:
        return require_reference_token(value, "M8 authority_id")


class M8ActorAuthorityV1(FrozenContractModel):
    """Versioned actor role, scope, and derived capability authority."""

    model_config = ConfigDict(json_schema_extra=_actor_authority_json_schema)

    schema_version: Literal["m8-actor-authority-v1"] = "m8-actor-authority-v1"
    actor_id: ReferenceToken
    role: M8ActorRole
    scope_kind: M8ActorScopeKind
    scope_location_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M8_ACTOR_SCOPE_LOCATIONS,
    )
    identity_provider_id: ReferenceToken
    subject_binding_sha256: Sha256Hex
    authority_revision: int = Field(gt=0, strict=True)
    active: StrictBool
    manifest_id: Sha256Hex

    @field_validator("actor_id", "identity_provider_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 actor authority reference")

    @field_validator("scope_location_ids")
    @classmethod
    def validate_scope_location_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for location_id in value:
            require_reference_token(location_id, "M8 scope location_id")
        if value != tuple(sorted(value)):
            raise ValueError("M8 scope_location_ids must use stable order")
        if len(value) != len(set(value)):
            raise ValueError("M8 scope_location_ids must be unique")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("capabilities", "actor_authority_id"),
        )
        actor = handler(payload)
        _verify_computed_claims(actor, claims)
        return actor

    @model_validator(mode="after")
    def validate_role_scope_matrix(self) -> Self:
        if self.role == M8ActorRole.LEADER:
            if self.scope_kind != M8ActorScopeKind.CAMPUS_WIDE:
                raise ValueError("M8 LEADER scope must be CAMPUS_WIDE")
            if self.scope_location_ids:
                raise ValueError("M8 CAMPUS_WIDE scope cannot list locations")
        elif self.role == M8ActorRole.STUDENT:
            if self.scope_kind != M8ActorScopeKind.SELF_ONLY:
                raise ValueError("M8 STUDENT scope must be SELF_ONLY")
            if self.scope_location_ids:
                raise ValueError("M8 SELF_ONLY scope cannot list locations")
        else:
            if self.scope_kind not in {
                M8ActorScopeKind.CAMPUS_WIDE,
                M8ActorScopeKind.LOCATIONS,
            }:
                raise ValueError("M8 staff scope must be CAMPUS_WIDE or LOCATIONS")
            if self.scope_kind == M8ActorScopeKind.LOCATIONS and not self.scope_location_ids:
                raise ValueError("M8 LOCATIONS scope requires at least one location")
            if self.scope_kind == M8ActorScopeKind.CAMPUS_WIDE and self.scope_location_ids:
                raise ValueError("M8 CAMPUS_WIDE scope cannot list locations")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def capabilities(self) -> tuple[M8Capability, ...]:
        return _ROLE_CAPABILITIES[self.role]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def actor_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-actor-authority",
                1,
                self.actor_id,
                self.role,
                self.scope_kind,
                self.scope_location_ids,
                self.identity_provider_id,
                self.subject_binding_sha256,
                self.authority_revision,
                self.active,
                self.capabilities,
                self.manifest_id,
            ]
        )


class M8OperationalCaseCreateCommandV1(FrozenContractModel):
    """Automation request that can create only a pending-verification case."""

    model_config = ConfigDict(json_schema_extra=_create_command_json_schema)

    schema_version: Literal["m8-operational-case-create-command-v1"] = (
        "m8-operational-case-create-command-v1"
    )
    source_catalog_id: Sha256Hex
    location_id: ReferenceToken
    risk_level: M8OperationalRiskLevel
    policy_rule_id: ReferenceToken
    policy_manifest_id: Sha256Hex
    source_ids: tuple[ReferenceToken, ...] = Field(min_length=1, max_length=MAX_M8_CASE_SOURCES)
    simulated_source_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M8_CASE_SOURCES,
    )
    trigger_authorities: tuple[M8AuthorityReference, ...] = Field(
        min_length=1,
        max_length=MAX_M8_CASE_AUTHORITIES,
    )
    automation_component_id: ReferenceToken
    automation_manifest_id: Sha256Hex

    @field_validator("location_id", "policy_rule_id", "automation_component_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 case-create reference")

    @field_validator("source_ids", "simulated_source_ids")
    @classmethod
    def validate_source_inventory(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for source_id in value:
            require_reference_token(source_id, "M8 case source_id")
        if value != tuple(sorted(value)):
            raise ValueError("M8 source IDs must use stable order")
        if len(value) != len(set(value)):
            raise ValueError("M8 source IDs must be unique")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "initial_status",
                "human_verification_required",
                "direct_disciplinary_action_permitted",
                "simulation_disclosure_required",
                "display_badge",
                "case_id",
                "create_command_id",
            ),
        )
        command = handler(payload)
        _verify_computed_claims(command, claims)
        return command

    @model_validator(mode="after")
    def validate_authority_inventory(self) -> Self:
        if not set(self.simulated_source_ids).issubset(self.source_ids):
            raise ValueError("M8 simulated_source_ids must be a subset of source_ids")
        authority_keys = tuple(_authority_reference_key(item) for item in self.trigger_authorities)
        if len(authority_keys) != len(set(authority_keys)):
            raise ValueError("M8 trigger authorities must be unique")
        if authority_keys != tuple(sorted(authority_keys)):
            raise ValueError("M8 trigger authorities must use stable order")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def initial_status(self) -> M8OperationalCaseStatus:
        return M8OperationalCaseStatus.PENDING_VERIFICATION

    @computed_field  # type: ignore[prop-decorator]
    @property
    def human_verification_required(self) -> bool:
        return True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def simulation_disclosure_required(self) -> bool:
        return bool(self.simulated_source_ids)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_badge(self) -> str:
        if self.simulation_disclosure_required:
            return "SIMULATED INPUT · PENDING VERIFICATION"
        return "LIVE INPUT · PENDING VERIFICATION"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-case",
                1,
                self.source_catalog_id,
                self.location_id,
                self.risk_level,
                self.policy_rule_id,
                self.policy_manifest_id,
                self.source_ids,
                [item.model_dump(mode="json") for item in self.trigger_authorities],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def create_command_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-case-create-command",
                1,
                self.case_id,
                self.simulated_source_ids,
                self.automation_component_id,
                self.automation_manifest_id,
                self.initial_status,
                self.human_verification_required,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8OperationalCaseTransitionCommandV1(FrozenContractModel):
    """Explicit human intent for one authorized operational-case transition."""

    model_config = ConfigDict(json_schema_extra=_transition_command_json_schema)

    schema_version: Literal["m8-operational-case-transition-command-v1"] = (
        "m8-operational-case-transition-command-v1"
    )
    case_id: ReferenceToken
    source_case_version: int = Field(gt=0, strict=True)
    source_case_authority_sha256: Sha256Hex
    source_status: M8OperationalCaseStatus
    case_location_id: ReferenceToken
    subject_actor_id: ReferenceToken | None = None
    action: M8OperationalCaseAction
    reason_code: M8OperationalCaseReasonCode
    reason_summary: str = Field(min_length=1, max_length=2048)
    supporting_authorities: tuple[M8AuthorityReference, ...] = Field(
        min_length=1,
        max_length=MAX_M8_CASE_AUTHORITIES,
    )
    actor_authority: M8ActorAuthorityV1
    appeal_resolution: M8AppealResolution | None = None
    explicit_human_confirmation: StrictBool
    command_manifest_id: Sha256Hex

    @field_validator("case_id", "case_location_id")
    @classmethod
    def validate_reference_tokens(cls, value: str) -> str:
        return require_reference_token(value, "M8 case-transition reference")

    @field_validator("subject_actor_id")
    @classmethod
    def validate_subject_actor_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return require_reference_token(value, "M8 subject_actor_id")

    @field_validator("reason_summary")
    @classmethod
    def validate_reason_summary(cls, value: str) -> str:
        return _validate_visible_text(value, "reason_summary")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "target_status",
                "required_capability",
                "target_case_version",
                "direct_disciplinary_action_permitted",
                "command_id",
            ),
        )
        command = handler(payload)
        _verify_computed_claims(command, claims)
        return command

    @model_validator(mode="after")
    def validate_transition_authority(self) -> Self:
        if self.source_status not in _ACTION_SOURCE_STATUSES[self.action]:
            raise ValueError("M8 action is not allowed from the supplied source status")
        if self.reason_code not in _ACTION_REASON_CODES[self.action]:
            raise ValueError("M8 action does not allow the supplied reason code")
        if self.action == M8OperationalCaseAction.RESOLVE_APPEAL:
            if self.appeal_resolution is None:
                raise ValueError("M8 RESOLVE_APPEAL requires appeal_resolution")
            expected_reason = {
                M8AppealResolution.UPHELD: M8OperationalCaseReasonCode.APPEAL_UPHELD,
                M8AppealResolution.OVERTURNED: M8OperationalCaseReasonCode.APPEAL_OVERTURNED,
            }[self.appeal_resolution]
            if self.reason_code != expected_reason:
                raise ValueError("M8 appeal_resolution conflicts with reason code")
        elif self.appeal_resolution is not None:
            raise ValueError("M8 appeal_resolution is only valid for RESOLVE_APPEAL")
        if self.explicit_human_confirmation is not True:
            raise ValueError("M8 transition requires explicit human confirmation")

        actor = self.actor_authority
        if not actor.active:
            raise ValueError("M8 transition actor authority must be active")
        if self.required_capability not in actor.capabilities:
            raise ValueError("M8 transition actor lacks the required capability")
        if self.action == M8OperationalCaseAction.SUBMIT_APPEAL:
            if actor.role != M8ActorRole.STUDENT:
                raise ValueError("M8 appeal submission requires a STUDENT actor")
            if self.subject_actor_id is None or actor.actor_id != self.subject_actor_id:
                raise ValueError("M8 appeal actor must be the case subject")
        else:
            if actor.role != M8ActorRole.SAFETY_OFFICER:
                raise ValueError("M8 staff case transition requires a SAFETY_OFFICER actor")
            if actor.scope_kind == M8ActorScopeKind.LOCATIONS and (
                self.case_location_id not in actor.scope_location_ids
            ):
                raise ValueError("M8 transition case location is outside actor scope")

        authority_keys = tuple(
            _authority_reference_key(item) for item in self.supporting_authorities
        )
        if len(authority_keys) != len(set(authority_keys)):
            raise ValueError("M8 supporting authorities must be unique")
        if authority_keys != tuple(sorted(authority_keys)):
            raise ValueError("M8 supporting authorities must use stable order")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_status(self) -> M8OperationalCaseStatus:
        return _ACTION_TARGET_STATUS[self.action]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def required_capability(self) -> M8Capability:
        return _ACTION_CAPABILITY[self.action]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_case_version(self) -> int:
        return self.source_case_version + 1

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direct_disciplinary_action_permitted(self) -> bool:
        return False

    @computed_field  # type: ignore[prop-decorator]
    @property
    def command_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-case-transition-command",
                1,
                self.case_id,
                self.source_case_version,
                self.source_case_authority_sha256,
                self.source_status,
                self.target_status,
                self.case_location_id,
                self.subject_actor_id,
                self.action,
                self.reason_code,
                self.reason_summary,
                [item.model_dump(mode="json") for item in self.supporting_authorities],
                self.actor_authority.actor_authority_id,
                self.required_capability,
                self.appeal_resolution,
                self.explicit_human_confirmation,
                self.command_manifest_id,
                self.direct_disciplinary_action_permitted,
            ]
        )


class M8OperationalCaseAuditIntentV1(FrozenContractModel):
    """Audit-ready binding for a validated transition command; it performs no write."""

    schema_version: Literal["m8-operational-case-audit-intent-v1"] = (
        "m8-operational-case-audit-intent-v1"
    )
    command: M8OperationalCaseTransitionCommandV1
    audit_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "case_id",
                "before_case_version",
                "after_case_version",
                "before_status",
                "after_status",
                "actor_authority_id",
                "transition_command_id",
                "supporting_authority_inventory_sha256",
                "audit_intent_id",
            ),
        )
        intent = handler(payload)
        _verify_computed_claims(intent, claims)
        return intent

    @computed_field  # type: ignore[prop-decorator]
    @property
    def case_id(self) -> ReferenceToken:
        return self.command.case_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def before_case_version(self) -> int:
        return self.command.source_case_version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def after_case_version(self) -> int:
        return self.command.target_case_version

    @computed_field  # type: ignore[prop-decorator]
    @property
    def before_status(self) -> M8OperationalCaseStatus:
        return self.command.source_status

    @computed_field  # type: ignore[prop-decorator]
    @property
    def after_status(self) -> M8OperationalCaseStatus:
        return self.command.target_status

    @computed_field  # type: ignore[prop-decorator]
    @property
    def actor_authority_id(self) -> Sha256Hex:
        return self.command.actor_authority.actor_authority_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def transition_command_id(self) -> Sha256Hex:
        return self.command.command_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def supporting_authority_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-supporting-authority-inventory",
                1,
                [item.model_dump(mode="json") for item in self.command.supporting_authorities],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def audit_intent_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-case-audit-intent",
                1,
                self.transition_command_id,
                self.case_id,
                self.before_case_version,
                self.after_case_version,
                self.before_status,
                self.after_status,
                self.actor_authority_id,
                self.supporting_authority_inventory_sha256,
                self.audit_manifest_id,
            ]
        )


def _authority_reference_key(reference: M8AuthorityReference) -> tuple[str, str, str]:
    return (reference.kind.value, reference.authority_id, reference.document_sha256)


__all__ = [
    "MAX_M8_ACTOR_SCOPE_LOCATIONS",
    "MAX_M8_CASE_AUTHORITIES",
    "MAX_M8_CASE_SOURCES",
    "M8ActorAuthorityV1",
    "M8ActorRole",
    "M8ActorScopeKind",
    "M8AppealResolution",
    "M8AuthorityReference",
    "M8AuthorityReferenceKind",
    "M8Capability",
    "M8OperationalCaseAction",
    "M8OperationalCaseAuditIntentV1",
    "M8OperationalCaseCreateCommandV1",
    "M8OperationalCaseReasonCode",
    "M8OperationalCaseStatus",
    "M8OperationalCaseTransitionCommandV1",
    "M8OperationalRiskLevel",
]
