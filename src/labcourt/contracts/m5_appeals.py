"""Additive M5 appeal commands, authorities, and atomic side-effect intents.

The frozen M0 ``Appeal`` and ``Case`` wire contracts intentionally remain
unchanged.  M5 wraps one ``Appeal`` in a versioned authority chain and emits a
single, fully bound side-effect intent for the future persistence adapter.
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictBool,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.appeals import Appeal
from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    AppealStatus,
    CaseStatus,
    EvidenceClass,
    PrecedentSource,
    PrecedentStatus,
    TrainingLabelQuality,
    VerdictDecision,
    ViolationType,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m3_models import require_bounded_public_text
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.contracts.references import ReferenceToken
from labcourt.contracts.training import TrainingLabel

MAX_M5_APPEAL_TRAINING_LABELS = 10_000


def _require_stable_unique(values: tuple[str, ...], name: str) -> None:
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{name} must be unique and use stable order")


class AffectedPrecedentCitation(FrozenContractModel):
    """One immutable historical citation affected by a precedent revocation."""

    source_citation_id: Sha256Hex
    citing_case_id: ReferenceToken
    precedent_id: ReferenceToken
    similarity_score: StrictFloat = Field(ge=-10, le=10)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_citation_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "citation_id" in payload
        claimed = payload.pop("citation_id", None)
        citation = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != citation.citation_id):
            raise ValueError("serialized affected citation ID does not match")
        return citation

    @computed_field  # type: ignore[prop-decorator]
    @property
    def citation_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "affected-precedent-citation",
                1,
                self.source_citation_id,
                self.citing_case_id,
                self.precedent_id,
                self.similarity_score,
            ]
        )

    @property
    def sort_key(self) -> tuple[str, str, str]:
        return self.precedent_id, self.citing_case_id, self.citation_id


class AutomaticPrecedentAppealAuthority(FrozenContractModel):
    """The exact automatic precedent state visible before appeal resolution."""

    precedent_id: ReferenceToken
    precedent_authority_id: Sha256Hex
    precedent_revision: int = Field(gt=0, strict=True)
    source: Literal[PrecedentSource.AUTOMATIC] = PrecedentSource.AUTOMATIC
    status: Literal[
        PrecedentStatus.PROVISIONAL,
        PrecedentStatus.ACTIVE,
        PrecedentStatus.CONFLICT,
        PrecedentStatus.INVALIDATED,
    ]
    decision_direction: VerdictDecision
    source_case_id: ReferenceToken
    citations: tuple[AffectedPrecedentCitation, ...] = ()

    @model_validator(mode="after")
    def validate_scope_and_order(self) -> Self:
        keys = tuple(item.sort_key for item in self.citations)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("automatic precedent citations must be unique and stably ordered")
        if any(item.precedent_id != self.precedent_id for item in self.citations):
            raise ValueError("automatic precedent citation belongs to another precedent")
        return self

    @property
    def sort_key(self) -> str:
        return self.precedent_id


class AppealResolutionPrecedentSnapshot(FrozenContractModel):
    """Complete current automatic-precedent view captured for terminal CAS."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    automatic_precedents: tuple[AutomaticPrecedentAppealAuthority, ...] = ()
    complete: Literal[True] = True

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_snapshot_sha256(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "snapshot_sha256" in payload
        claimed = payload.pop("snapshot_sha256", None)
        snapshot = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != snapshot.snapshot_sha256):
            raise ValueError("serialized appeal precedent snapshot hash does not match")
        return snapshot

    @model_validator(mode="after")
    def validate_complete_stable_snapshot(self) -> Self:
        keys = tuple(item.sort_key for item in self.automatic_precedents)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError(
                "appeal precedent snapshot authorities must be unique and stably ordered"
            )
        if any(precedent.source_case_id != self.case_id for precedent in self.automatic_precedents):
            raise ValueError("appeal precedent snapshot contains another Case")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def snapshot_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "appeal-resolution-precedent-snapshot",
                1,
                self.model_dump(mode="json", exclude={"snapshot_sha256"}),
            ]
        )


class AppealableAlertAuthority(FrozenContractModel):
    """An original adjudicated alert that has not yet been rescinded."""

    alert_id: ReferenceToken
    rescinded: Literal[False] = False


class ClosedCaseAppealAuthority(FrozenContractModel):
    """Minimal immutable Case projection authorized to accept one appeal."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    case_revision: int = Field(gt=0, strict=True)
    case_status: Literal[CaseStatus.CLOSED] = CaseStatus.CLOSED
    verdict_id: Sha256Hex
    verdict_version: int = Field(gt=0, strict=True)
    verdict_sha256: Sha256Hex
    final_decision: VerdictDecision
    evidence_class: EvidenceClass
    violation_type: ViolationType
    alerts: tuple[AppealableAlertAuthority, ...] = ()
    automatic_precedents: tuple[AutomaticPrecedentAppealAuthority, ...] = ()
    effective_appeal_ids: tuple[ReferenceToken, ...] = ()
    detector_manifest_id: Sha256Hex
    text_embedding_manifest_id: Sha256Hex
    visual_embedding_manifest_id: Sha256Hex
    manifest_id: Sha256Hex
    config_sha256: Sha256Hex
    rule_version: str = Field(min_length=1, max_length=128)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_sha256(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "authority_sha256" in payload
        claimed = payload.pop("authority_sha256", None)
        authority = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != authority.authority_sha256):
            raise ValueError("serialized closed-case appeal authority hash does not match")
        return authority

    @model_validator(mode="after")
    def validate_stable_authority(self) -> Self:
        alert_ids = tuple(item.alert_id for item in self.alerts)
        _require_stable_unique(alert_ids, "appealable alert IDs")
        precedent_ids = tuple(item.precedent_id for item in self.automatic_precedents)
        _require_stable_unique(precedent_ids, "automatic precedent IDs")
        _require_stable_unique(self.effective_appeal_ids, "effective appeal IDs")
        for precedent in self.automatic_precedents:
            if (
                precedent.source_case_id != self.case_id
                or precedent.decision_direction != self.final_decision
            ):
                raise ValueError("automatic precedent conflicts with the closed Case authority")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "closed-case-appeal-authority",
                1,
                self.model_dump(mode="json", exclude={"authority_sha256"}),
            ]
        )


class AppealSubmissionCommand(FrozenContractModel):
    run_id: ReferenceToken
    case_id: ReferenceToken
    appeal_id: ReferenceToken
    expected_case_revision: int = Field(gt=0, strict=True)
    expected_case_authority_sha256: Sha256Hex
    reason: str = Field(min_length=1, max_length=2_048)
    submitted_by: ReferenceToken

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return require_bounded_public_text(value, "appeal reason", max_length=2_048)


class AppealReviewCommand(FrozenContractModel):
    run_id: ReferenceToken
    case_id: ReferenceToken
    appeal_id: ReferenceToken
    expected_appeal_version: Literal[1] = 1
    expected_appeal_authority_sha256: Sha256Hex
    reviewer_id: ReferenceToken


class AppealResolutionCommand(FrozenContractModel):
    run_id: ReferenceToken
    case_id: ReferenceToken
    appeal_id: ReferenceToken
    expected_appeal_version: Literal[2] = 2
    expected_appeal_authority_sha256: Sha256Hex
    status: Literal[AppealStatus.UPHELD, AppealStatus.OVERTURNED]
    reviewer_id: ReferenceToken
    resolution_summary: str = Field(min_length=1, max_length=2_048)
    resolved_decision: VerdictDecision
    appeal_precedent_authority: M5PrecedentAuthority | None = None
    training_labels: tuple[TrainingLabel, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_TRAINING_LABELS,
    )

    @field_validator("resolution_summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return require_bounded_public_text(value, "appeal resolution", max_length=2_048)

    @model_validator(mode="after")
    def validate_stable_labels(self) -> Self:
        label_ids = tuple(item.label_id for item in self.training_labels)
        _require_stable_unique(label_ids, "appeal resolution training label IDs")
        return self


class AppealVersionAuthority(FrozenContractModel):
    """One append-only version in the fixed three-step appeal state machine."""

    run_id: ReferenceToken
    appeal: Appeal
    version: int = Field(ge=1, le=3, strict=True)
    previous_authority_sha256: Sha256Hex | None = None
    assigned_reviewer_id: ReferenceToken | None = None
    source_case_authority: ClosedCaseAppealAuthority
    source_case_revision: int = Field(gt=0, strict=True)
    source_case_authority_sha256: Sha256Hex
    source_verdict_id: Sha256Hex
    source_verdict_version: int = Field(gt=0, strict=True)
    source_verdict_sha256: Sha256Hex
    source_decision: VerdictDecision
    text_embedding_manifest_id: Sha256Hex
    visual_embedding_manifest_id: Sha256Hex
    manifest_id: Sha256Hex
    rule_version: str = Field(min_length=1, max_length=128)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_authority_sha256(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "authority_sha256" in payload
        claimed = payload.pop("authority_sha256", None)
        authority = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != authority.authority_sha256):
            raise ValueError("serialized appeal version authority hash does not match")
        return authority

    @model_validator(mode="after")
    def validate_version_state_matrix(self) -> Self:
        expected_status = {
            1: AppealStatus.SUBMITTED,
            2: AppealStatus.UNDER_REVIEW,
        }.get(self.version)
        if expected_status is not None and self.appeal.status != expected_status:
            raise ValueError("appeal status does not match its authority version")
        if self.version == 3 and self.appeal.status not in {
            AppealStatus.UPHELD,
            AppealStatus.OVERTURNED,
        }:
            raise ValueError("appeal version three must be terminal")
        if (self.version == 1) != (self.previous_authority_sha256 is None):
            raise ValueError("only the first appeal version omits its predecessor hash")
        if self.version == 1:
            if self.assigned_reviewer_id is not None:
                raise ValueError("a submitted appeal cannot already assign its reviewer")
        elif self.assigned_reviewer_id is None:
            raise ValueError("review and terminal appeal versions require an assigned reviewer")
        if self.version < 3 and self.appeal.reviewer_id is not None:
            raise ValueError("non-terminal frozen Appeal cannot carry resolution fields")
        if self.version == 3 and self.appeal.reviewer_id != self.assigned_reviewer_id:
            raise ValueError("terminal Appeal reviewer conflicts with its review assignment")
        source = self.source_case_authority
        if (
            source.run_id != self.run_id
            or source.case_id != self.appeal.case_id
            or source.case_revision != self.source_case_revision
            or source.authority_sha256 != self.source_case_authority_sha256
            or source.verdict_id != self.source_verdict_id
            or source.verdict_version != self.source_verdict_version
            or source.verdict_sha256 != self.source_verdict_sha256
            or source.final_decision != self.source_decision
            or source.text_embedding_manifest_id != self.text_embedding_manifest_id
            or source.visual_embedding_manifest_id != self.visual_embedding_manifest_id
            or source.manifest_id != self.manifest_id
            or source.rule_version != self.rule_version
        ):
            raise ValueError("appeal source fields conflict with embedded closed Case authority")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def authority_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "appeal-version-authority",
                1,
                self.model_dump(mode="json", exclude={"authority_sha256"}),
            ]
        )


class VerdictRescissionIntent(FrozenContractModel):
    verdict_id: Sha256Hex
    verdict_version: int = Field(gt=0, strict=True)
    verdict_sha256: Sha256Hex
    rescinded: Literal[True] = True


class AlertRescissionIntent(FrozenContractModel):
    alert_id: ReferenceToken
    rescinded: Literal[True] = True

    @property
    def sort_key(self) -> str:
        return self.alert_id


class PrecedentRevocationIntent(FrozenContractModel):
    precedent_id: ReferenceToken
    prior_authority_id: Sha256Hex
    prior_revision: int = Field(gt=0, strict=True)
    source: Literal[PrecedentSource.AUTOMATIC] = PrecedentSource.AUTOMATIC
    previous_status: Literal[
        PrecedentStatus.PROVISIONAL,
        PrecedentStatus.ACTIVE,
        PrecedentStatus.CONFLICT,
        PrecedentStatus.INVALIDATED,
    ]
    status: Literal[PrecedentStatus.REVOKED] = PrecedentStatus.REVOKED

    @property
    def sort_key(self) -> str:
        return self.precedent_id


class AffectedCitationReport(FrozenContractModel):
    revoked_precedent_ids: tuple[ReferenceToken, ...] = ()
    citations: tuple[AffectedPrecedentCitation, ...] = ()

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_report_sha256(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        present = "report_sha256" in payload
        claimed = payload.pop("report_sha256", None)
        report = handler(payload)
        if present and (not isinstance(claimed, str) or claimed != report.report_sha256):
            raise ValueError("serialized affected-citation report hash does not match")
        return report

    @model_validator(mode="after")
    def validate_complete_stable_report(self) -> Self:
        _require_stable_unique(self.revoked_precedent_ids, "revoked precedent IDs")
        keys = tuple(item.sort_key for item in self.citations)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("affected citations must be unique and stably ordered")
        if any(item.precedent_id not in self.revoked_precedent_ids for item in self.citations):
            raise ValueError("affected citation references a precedent outside the revocation set")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def report_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "affected-citation-report",
                1,
                list(self.revoked_precedent_ids),
                [item.model_dump(mode="json") for item in self.citations],
            ]
        )


class AppealResolutionSideEffectIntent(FrozenContractModel):
    """Atomic effects required by one terminal human appeal decision."""

    run_id: ReferenceToken
    case_id: ReferenceToken
    expected_case_revision: int = Field(gt=0, strict=True)
    appeal_authority: AppealVersionAuthority
    source_verdict_id: Sha256Hex
    source_decision: VerdictDecision
    precedent_snapshot: AppealResolutionPrecedentSnapshot
    verdict_rescission: VerdictRescissionIntent | None = None
    alert_rescissions: tuple[AlertRescissionIntent, ...] = ()
    final_decision: VerdictDecision
    precedent_revocations: tuple[PrecedentRevocationIntent, ...] = ()
    appeal_precedent_authority: M5PrecedentAuthority | None = None
    training_labels: tuple[TrainingLabel, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_TRAINING_LABELS,
    )
    affected_citations: AffectedCitationReport
    text_embedding_manifest_id: Sha256Hex
    visual_embedding_manifest_id: Sha256Hex
    manifest_id: Sha256Hex
    rule_version: str = Field(min_length=1, max_length=128)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_intent_fields(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        intent_present = "intent_id" in payload
        changed_present = "final_decision_changed" in payload
        claimed_intent = payload.pop("intent_id", None)
        claimed_changed = payload.pop("final_decision_changed", None)
        intent = handler(payload)
        if intent_present and (
            not isinstance(claimed_intent, str) or claimed_intent != intent.intent_id
        ):
            raise ValueError("serialized appeal resolution intent ID does not match")
        if changed_present and (
            not isinstance(claimed_changed, bool)
            or claimed_changed != intent.final_decision_changed
        ):
            raise ValueError("serialized final-decision change flag does not match")
        return intent

    @computed_field  # type: ignore[prop-decorator]
    @property
    def final_decision_changed(self) -> StrictBool:
        return self.final_decision != self.source_decision

    @computed_field  # type: ignore[prop-decorator]
    @property
    def intent_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "appeal-resolution-side-effect-intent",
                1,
                self.model_dump(
                    mode="json",
                    exclude={"intent_id", "final_decision_changed"},
                ),
            ]
        )

    @model_validator(mode="after")
    def validate_atomic_effect_matrix(self) -> Self:
        authority = self.appeal_authority
        if (
            authority.version != 3
            or authority.run_id != self.run_id
            or authority.appeal.case_id != self.case_id
            or authority.source_case_revision != self.expected_case_revision
            or authority.source_verdict_id != self.source_verdict_id
            or authority.source_decision != self.source_decision
            or authority.text_embedding_manifest_id != self.text_embedding_manifest_id
            or authority.visual_embedding_manifest_id != self.visual_embedding_manifest_id
            or authority.manifest_id != self.manifest_id
            or authority.rule_version != self.rule_version
        ):
            raise ValueError("appeal resolution intent conflicts with terminal authority")
        if (
            self.precedent_snapshot.run_id != self.run_id
            or self.precedent_snapshot.case_id != self.case_id
        ):
            raise ValueError("appeal resolution precedent snapshot has another scope")

        alert_keys = tuple(item.sort_key for item in self.alert_rescissions)
        if alert_keys != tuple(sorted(alert_keys)) or len(alert_keys) != len(set(alert_keys)):
            raise ValueError("alert rescissions must be unique and stably ordered")
        precedent_keys = tuple(item.sort_key for item in self.precedent_revocations)
        if precedent_keys != tuple(sorted(precedent_keys)) or len(precedent_keys) != len(
            set(precedent_keys)
        ):
            raise ValueError("precedent revocations must be unique and stably ordered")
        label_ids = tuple(item.label_id for item in self.training_labels)
        _require_stable_unique(label_ids, "appeal side-effect training label IDs")

        if authority.appeal.status == AppealStatus.OVERTURNED:
            if not self.final_decision_changed or self.verdict_rescission is None:
                raise ValueError("overturned appeals require a changed decision and rescission")
            if (
                self.verdict_rescission.verdict_id != self.source_verdict_id
                or self.verdict_rescission.verdict_version != authority.source_verdict_version
                or self.verdict_rescission.verdict_sha256 != authority.source_verdict_sha256
            ):
                raise ValueError("verdict rescission conflicts with source verdict authority")
            if self.appeal_precedent_authority is None:
                raise ValueError("overturned appeals require a replacement appeal precedent")
            precedent_authority = self.appeal_precedent_authority
            precedent = precedent_authority.precedent
            if (
                precedent_authority.run_id != self.run_id
                or precedent_authority.config_sha256
                != authority.source_case_authority.config_sha256
                or precedent_authority.revision != 1
                or precedent_authority.text_embedding is None
                or precedent_authority.text_embedding.request.model_manifest_id
                != self.text_embedding_manifest_id
                or any(
                    embedding.request.model_manifest_id != self.visual_embedding_manifest_id
                    for embedding in precedent_authority.visual_embeddings
                )
                or precedent.source != PrecedentSource.APPEAL_OVERTURN
                or precedent.status != PrecedentStatus.ACTIVE
                or precedent.source_case_id != self.case_id
                or precedent.decision_direction != self.final_decision
                or precedent.rule_version != self.rule_version
            ):
                raise ValueError("replacement appeal precedent conflicts with resolution")
            expected_revocations = tuple(
                PrecedentRevocationIntent(
                    precedent_id=item.precedent_id,
                    prior_authority_id=item.precedent_authority_id,
                    prior_revision=item.precedent_revision,
                    previous_status=item.status,
                )
                for item in self.precedent_snapshot.automatic_precedents
            )
            if self.precedent_revocations != expected_revocations:
                raise ValueError("precedent revocations differ from the captured current snapshot")
            revoked_ids = tuple(item.precedent_id for item in expected_revocations)
            if revoked_ids != self.affected_citations.revoked_precedent_ids:
                raise ValueError("citation report does not cover every revoked precedent")
            expected_citations = tuple(
                sorted(
                    (
                        citation
                        for item in self.precedent_snapshot.automatic_precedents
                        for citation in item.citations
                    ),
                    key=lambda item: item.sort_key,
                )
            )
            if self.affected_citations.citations != expected_citations:
                raise ValueError("citation report differs from the captured current snapshot")
            if not self.training_labels or any(
                label.quality != TrainingLabelQuality.APPEAL_CONFIRMED
                for label in self.training_labels
            ):
                raise ValueError("overturned appeals require APPEAL_CONFIRMED labels")
        else:
            if self.final_decision_changed:
                raise ValueError("upheld appeals cannot change the final decision")
            if any(
                (
                    self.verdict_rescission,
                    self.alert_rescissions,
                    self.precedent_revocations,
                    self.appeal_precedent_authority,
                    self.affected_citations.revoked_precedent_ids,
                    self.affected_citations.citations,
                )
            ):
                raise ValueError("upheld appeals cannot emit overturn side effects")
            if any(
                label.quality != TrainingLabelQuality.HUMAN_CONFIRMED
                for label in self.training_labels
            ):
                raise ValueError("upheld appeal labels must be HUMAN_CONFIRMED")

        for label in self.training_labels:
            if (
                label.case_id != self.case_id
                or label.reviewer_id != authority.assigned_reviewer_id
                or label.rule_version != self.rule_version
            ):
                raise ValueError("appeal training label conflicts with resolution authority")
        return self


class M5AppealResolutionCommitReceipt(FrozenContractModel):
    """Final durable root proving that every appeal side effect committed atomically."""

    schema_version: Literal["m5-appeal-resolution-commit-receipt-v1"] = (
        "m5-appeal-resolution-commit-receipt-v1"
    )
    run_id: ReferenceToken
    resolution_intent_id: Sha256Hex
    resolution_document_sha256: Sha256Hex
    appeal_id: ReferenceToken
    appeal_authority_sha256: Sha256Hex
    case_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    resulting_case_revision: int = Field(gt=0, strict=True)
    resulting_case_document_sha256: Sha256Hex
    verdict_rescission_ids: tuple[Sha256Hex, ...] = Field(default=(), max_length=1)
    alert_rescission_ids: tuple[Sha256Hex, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_TRAINING_LABELS,
    )
    precedent_revocation_receipt_ids: tuple[Sha256Hex, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_TRAINING_LABELS,
    )
    replacement_precedent_authority_id: Sha256Hex | None = None
    training_label_ids: tuple[ReferenceToken, ...] = Field(
        default=(),
        max_length=MAX_M5_APPEAL_TRAINING_LABELS,
    )
    affected_citation_report_sha256: Sha256Hex
    manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_computed_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        if not isinstance(value, dict):
            return handler(value)
        payload = dict(value)
        claims = {
            name: (name in payload, payload.pop(name, None))
            for name in ("effect_root_sha256", "receipt_id")
        }
        receipt = handler(payload)
        for name, (present, claimed) in claims.items():
            if present and (not isinstance(claimed, str) or claimed != getattr(receipt, name)):
                raise ValueError(f"serialized {name} does not match appeal commit content")
        return receipt

    @model_validator(mode="after")
    def validate_effect_inventory(self) -> Self:
        if self.resulting_case_revision != self.source_case_revision + 3:
            raise ValueError("appeal commit Case revision must close the three-step appeal chain")
        inventories = (
            (self.verdict_rescission_ids, "verdict rescission IDs"),
            (self.alert_rescission_ids, "alert rescission IDs"),
            (self.precedent_revocation_receipt_ids, "precedent revocation receipt IDs"),
            (self.training_label_ids, "appeal training label IDs"),
        )
        for values, name in inventories:
            _require_stable_unique(values, name)
        overturned = self.replacement_precedent_authority_id is not None
        if overturned:
            if (
                len(self.verdict_rescission_ids) != 1
                or not self.precedent_revocation_receipt_ids
                or not self.training_label_ids
            ):
                raise ValueError(
                    "overturned appeal commit requires verdict, revocation, replacement, and "
                    "training roots"
                )
        elif (
            self.verdict_rescission_ids
            or self.alert_rescission_ids
            or self.precedent_revocation_receipt_ids
        ):
            raise ValueError("upheld appeal commit cannot contain overturn-only roots")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effect_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-appeal-resolution-effect-root",
                1,
                self.run_id,
                self.resolution_intent_id,
                self.resolution_document_sha256,
                self.appeal_id,
                self.appeal_authority_sha256,
                self.case_id,
                self.source_case_revision,
                self.resulting_case_revision,
                self.resulting_case_document_sha256,
                list(self.verdict_rescission_ids),
                list(self.alert_rescission_ids),
                list(self.precedent_revocation_receipt_ids),
                self.replacement_precedent_authority_id,
                list(self.training_label_ids),
                self.affected_citation_report_sha256,
                self.manifest_id,
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m5-appeal-resolution-commit-receipt",
                1,
                self.effect_root_sha256,
            ]
        )


__all__ = [
    "MAX_M5_APPEAL_TRAINING_LABELS",
    "AffectedCitationReport",
    "AffectedPrecedentCitation",
    "AlertRescissionIntent",
    "AppealResolutionCommand",
    "AppealResolutionPrecedentSnapshot",
    "AppealResolutionSideEffectIntent",
    "AppealReviewCommand",
    "AppealSubmissionCommand",
    "AppealVersionAuthority",
    "AppealableAlertAuthority",
    "AutomaticPrecedentAppealAuthority",
    "ClosedCaseAppealAuthority",
    "M5AppealResolutionCommitReceipt",
    "PrecedentRevocationIntent",
    "VerdictRescissionIntent",
]
