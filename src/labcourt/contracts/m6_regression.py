"""Additive M6 replay, dataset, and regression report contracts.

These contracts deliberately wrap frozen M0--M5 authorities.  A stable
``sample_id`` pairs baseline and candidate executions because an upgraded rule
version may legitimately change the event and Case identities.  All aggregate
gate claims are derived from the complete per-sample inventory.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    StrictFloat,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import (
    AlertLevel,
    AppealStatus,
    CaseStatus,
    ReproducibilityMode,
    VerdictDecision,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.references import ReferenceToken, require_reference_token

MAX_M6_REGRESSION_CASES = 100_000
MAX_M6_REVIEW_SUMMARY_LENGTH = 2_048


class M6RegressionDatasetKind(StrEnum):
    STABILITY = "STABILITY"
    GOLD = "GOLD"
    CHALLENGE = "CHALLENGE"


class M6RegressionStage(StrEnum):
    PERCEPTION = "PERCEPTION"
    SCREENING = "SCREENING"
    RETRIEVAL = "RETRIEVAL"
    HEARING = "HEARING"
    GATE = "GATE"
    POLICY = "POLICY"


class M6ChallengeKind(StrEnum):
    DIFFICULT_NEGATIVE = "DIFFICULT_NEGATIVE"
    INSUFFICIENT_OBSERVATION = "INSUFFICIENT_OBSERVATION"
    DON_AFTER_THRESHOLD = "DON_AFTER_THRESHOLD"
    OCCLUSION = "OCCLUSION"
    DETECTOR_MISS = "DETECTOR_MISS"
    FABRICATED_REFERENCE = "FABRICATED_REFERENCE"
    OBJECTIVE_CONFLICT = "OBJECTIVE_CONFLICT"
    PROVIDER_OUTAGE = "PROVIDER_OUTAGE"
    PRECEDENT_MISMATCH = "PRECEDENT_MISMATCH"
    HARD_SIGNAL_UNCERTIFIED = "HARD_SIGNAL_UNCERTIFIED"


class M6BaselineAuthorityKind(StrEnum):
    MACHINE_TERMINAL_CASE = "MACHINE_TERMINAL_CASE"
    PRE_APPEAL_CLOSED_CASE = "PRE_APPEAL_CLOSED_CASE"
    CHALLENGE_NO_CASE = "CHALLENGE_NO_CASE"


class M6GoldTruthAuthorityKind(StrEnum):
    APPEAL_RESOLUTION = "APPEAL_RESOLUTION"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    PRESET_GOLD = "PRESET_GOLD"


class M6RegressionCaseDisposition(StrEnum):
    IDENTICAL = "IDENTICAL"
    MANIFEST_ONLY_CHANGE = "MANIFEST_ONLY_CHANGE"
    SEMANTIC_DRIFT = "SEMANTIC_DRIFT"
    DECISION_FLIP = "DECISION_FLIP"
    CANDIDATE_MISSING = "CANDIDATE_MISSING"
    CANDIDATE_ADDED = "CANDIDATE_ADDED"


class M6EmergencyReviewDecision(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class M6RegressionGateReason(StrEnum):
    LOCKED_SEMANTIC_MISMATCH = "LOCKED_SEMANTIC_MISMATCH"
    REQUIRED_CANDIDATE_MISSING = "REQUIRED_CANDIDATE_MISSING"
    REQUIRED_CANDIDATE_NONTERMINAL = "REQUIRED_CANDIDATE_NONTERMINAL"
    MACHINE_FLIP_RATE_EXCEEDED = "MACHINE_FLIP_RATE_EXCEEDED"
    GOLD_ACCURACY_DROP_EXCEEDED = "GOLD_ACCURACY_DROP_EXCEEDED"
    EMERGENCY_DEGRADATION_UNREVIEWED = "EMERGENCY_DEGRADATION_UNREVIEWED"
    EMERGENCY_DEGRADATION_REJECTED = "EMERGENCY_DEGRADATION_REJECTED"


class M6RegressionDisposition(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"
    DIAGNOSTIC_COMPLETE = "DIAGNOSTIC_COMPLETE"


class M6ReplayExecutionOutcome(StrEnum):
    CASE_REPLAYED = "CASE_REPLAYED"
    NO_CASE = "NO_CASE"


_STAGE_ORDER = tuple(M6RegressionStage)
_DATASET_KIND_RANK = {
    M6RegressionDatasetKind.STABILITY: 0,
    M6RegressionDatasetKind.GOLD: 1,
    M6RegressionDatasetKind.CHALLENGE: 2,
}
_CHALLENGE_RANK = {value: index for index, value in enumerate(M6ChallengeKind)}
_ALERT_RANK = {
    None: -1,
    AlertLevel.ADVISORY: 0,
    AlertLevel.CONFIRMED: 1,
    AlertLevel.EMERGENCY: 2,
}
_GATE_REASON_RANK = {value: index for index, value in enumerate(M6RegressionGateReason)}


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
    if not claims:
        return
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} does not match derived M6 content")


def _ratio_exceeds(numerator: int, denominator: int, threshold: float) -> bool:
    if denominator <= 0:
        raise ValueError("M6 regression gate denominator must be positive")
    return Decimal(numerator) > Decimal(str(threshold)) * Decimal(denominator)


class M6SemanticStageRoot(FrozenContractModel):
    stage: M6RegressionStage
    projection_sha256: Sha256Hex


class M6CaseReplaySnapshot(FrozenContractModel):
    """One replayed Case semantic projection without operational identity noise."""

    schema_version: Literal["m6-case-replay-snapshot-v1"] = "m6-case-replay-snapshot-v1"
    projection_version: Literal["m6-semantic-case-v1"] = "m6-semantic-case-v1"
    sample_id: ReferenceToken
    source_run_id: ReferenceToken
    source_case_id: ReferenceToken
    source_case_revision: int = Field(gt=0, strict=True)
    source_case_document_sha256: Sha256Hex
    manifest_id: Sha256Hex
    stage_roots: tuple[M6SemanticStageRoot, ...] = Field(min_length=6, max_length=6)
    case_status: CaseStatus
    final_decision: VerdictDecision | None = None
    highest_alert_level: AlertLevel | None = None
    terminal_appeal_status: AppealStatus | None = None

    @field_validator("sample_id", "source_run_id", "source_case_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 Case replay reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("semantic_case_hash", "snapshot_id"))
        snapshot = handler(payload)
        _verify_claims(snapshot, claims)
        return snapshot

    @model_validator(mode="after")
    def validate_stage_and_appeal_matrix(self) -> Self:
        if tuple(root.stage for root in self.stage_roots) != _STAGE_ORDER:
            raise ValueError("M6 semantic stage roots must contain the exact stable stage order")
        if self.terminal_appeal_status not in {
            None,
            AppealStatus.UPHELD,
            AppealStatus.OVERTURNED,
        }:
            raise ValueError("M6 replay snapshot may only expose a terminal appeal status")
        if (
            self.case_status in {CaseStatus.CLOSED, CaseStatus.APPEAL_RESOLVED}
            and self.final_decision is None
        ):
            raise ValueError("terminal M6 Case replay snapshot requires a final decision")
        if (
            self.case_status not in {CaseStatus.CLOSED, CaseStatus.APPEAL_RESOLVED}
            and self.final_decision is not None
        ):
            raise ValueError("non-terminal M6 Case replay snapshot cannot carry a final decision")
        if (
            self.terminal_appeal_status is not None
            and self.case_status != CaseStatus.APPEAL_RESOLVED
        ):
            raise ValueError("terminal appeal status requires APPEAL_RESOLVED Case status")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def semantic_case_hash(self) -> Sha256Hex:
        payload: dict[str, object] = {
            "projection_version": self.projection_version,
            "manifest_id": self.manifest_id,
            "stage_roots": [root.model_dump(mode="json") for root in self.stage_roots],
            "case_status": self.case_status.value,
            "final_decision": (
                self.final_decision.value if self.final_decision is not None else None
            ),
            "highest_alert_level": (
                self.highest_alert_level.value if self.highest_alert_level is not None else None
            ),
            "terminal_appeal_status": (
                self.terminal_appeal_status.value
                if self.terminal_appeal_status is not None
                else None
            ),
        }
        return sha256_hex(["semantic-case", 1, payload])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def snapshot_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-case-replay-snapshot",
                1,
                self.sample_id,
                self.source_run_id,
                self.source_case_id,
                self.source_case_revision,
                self.source_case_document_sha256,
                self.semantic_case_hash,
            ]
        )


class M6GoldTruthAuthority(FrozenContractModel):
    sample_id: ReferenceToken
    baseline_snapshot_id: Sha256Hex
    baseline_source_run_id: ReferenceToken
    baseline_source_case_id: ReferenceToken
    baseline_source_case_revision: int = Field(gt=0, strict=True)
    authority_kind: M6GoldTruthAuthorityKind
    decision_authority_id: Sha256Hex
    decision_authority_document_sha256: Sha256Hex
    expected_decision: VerdictDecision
    resolution_commit_id: Sha256Hex | None = None
    resolution_commit_document_sha256: Sha256Hex | None = None

    @field_validator("sample_id", "baseline_source_run_id", "baseline_source_case_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 gold truth reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_truth_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("truth_id",))
        truth = handler(payload)
        _verify_claims(truth, claims)
        return truth

    @model_validator(mode="after")
    def validate_appeal_commit_matrix(self) -> Self:
        commit_values = (
            self.resolution_commit_id,
            self.resolution_commit_document_sha256,
        )
        if self.authority_kind == M6GoldTruthAuthorityKind.APPEAL_RESOLUTION:
            if any(value is None for value in commit_values):
                raise ValueError("appeal gold truth requires its resolution commit authority")
        elif any(value is not None for value in commit_values):
            raise ValueError("non-appeal gold truth cannot claim an appeal resolution commit")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def truth_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-gold-truth-authority",
                1,
                self.sample_id,
                self.baseline_snapshot_id,
                self.baseline_source_run_id,
                self.baseline_source_case_id,
                self.baseline_source_case_revision,
                self.authority_kind,
                self.decision_authority_id,
                self.decision_authority_document_sha256,
                self.expected_decision,
                self.resolution_commit_id,
                self.resolution_commit_document_sha256,
            ]
        )


class M6RegressionExecutionEntry(FrozenContractModel):
    """Blinded candidate input; it contains no membership or expected decision."""

    sample_id: ReferenceToken
    input_authority_id: Sha256Hex
    input_authority_document_sha256: Sha256Hex
    replay_input_closure_authority_id: Sha256Hex
    replay_input_closure_document_sha256: Sha256Hex

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 execution sample_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_execution_entry_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("execution_entry_id",))
        entry = handler(payload)
        _verify_claims(entry, claims)
        return entry

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_entry_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-execution-entry",
                1,
                self.sample_id,
                self.input_authority_id,
                self.input_authority_document_sha256,
                self.replay_input_closure_authority_id,
                self.replay_input_closure_document_sha256,
            ]
        )


class M6RegressionExecutionDatasetSnapshot(FrozenContractModel):
    """Candidate-facing dataset projection with evaluator truth intentionally absent."""

    schema_version: Literal["m6-regression-execution-dataset-v1"] = (
        "m6-regression-execution-dataset-v1"
    )
    baseline_manifest_id: Sha256Hex
    source_catalog_authority_id: Sha256Hex
    source_catalog_document_sha256: Sha256Hex
    entries: tuple[M6RegressionExecutionEntry, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
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
            ("entry_count", "execution_dataset_snapshot_id"),
        )
        snapshot = handler(payload)
        _verify_claims(snapshot, claims)
        return snapshot

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        sample_ids = tuple(entry.sample_id for entry in self.entries)
        if sample_ids != tuple(sorted(sample_ids)):
            raise ValueError("M6 execution entries must use stable sample_id order")
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("M6 execution sample_ids must be unique")
        for values, name in (
            (
                tuple(entry.input_authority_id for entry in self.entries),
                "input authorities",
            ),
            (
                tuple(entry.replay_input_closure_authority_id for entry in self.entries),
                "input closures",
            ),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"M6 execution {name} must be unique")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def entry_count(self) -> int:
        return len(self.entries)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_dataset_snapshot_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-execution-dataset",
                1,
                self.baseline_manifest_id,
                self.source_catalog_authority_id,
                self.source_catalog_document_sha256,
                [entry.execution_entry_id for entry in self.entries],
            ]
        )


class M6RegressionDatasetEntry(FrozenContractModel):
    sample_id: ReferenceToken
    input_authority_id: Sha256Hex
    input_authority_document_sha256: Sha256Hex
    replay_input_closure_authority_id: Sha256Hex
    replay_input_closure_document_sha256: Sha256Hex
    baseline_authority_kind: M6BaselineAuthorityKind
    baseline_authority_id: Sha256Hex
    baseline_authority_document_sha256: Sha256Hex
    baseline_snapshot: M6CaseReplaySnapshot | None = None
    memberships: tuple[M6RegressionDatasetKind, ...] = Field(min_length=1, max_length=3)
    gold_truth: M6GoldTruthAuthority | None = None
    challenge_kinds: tuple[M6ChallengeKind, ...] = Field(default=(), max_length=10)

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 regression sample_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_entry_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("entry_id",))
        entry = handler(payload)
        _verify_claims(entry, claims)
        return entry

    @model_validator(mode="after")
    def validate_membership_and_authority_matrix(self) -> Self:
        if len(self.memberships) != len(set(self.memberships)):
            raise ValueError("M6 regression dataset memberships must be unique")
        if self.memberships != tuple(sorted(self.memberships, key=_DATASET_KIND_RANK.__getitem__)):
            raise ValueError("M6 regression dataset memberships must use stable order")
        kinds = set(self.memberships)
        if {
            M6RegressionDatasetKind.STABILITY,
            M6RegressionDatasetKind.GOLD,
        }.issubset(kinds):
            raise ValueError("machine stability and human gold membership cannot overlap")

        if self.baseline_snapshot is not None:
            if self.baseline_snapshot.sample_id != self.sample_id:
                raise ValueError("M6 dataset entry and baseline snapshot sample_id differ")
            if self.baseline_authority_kind == M6BaselineAuthorityKind.CHALLENGE_NO_CASE:
                raise ValueError("CHALLENGE_NO_CASE cannot carry a baseline Case snapshot")
            baseline_document = canonical_json(self.baseline_snapshot.model_dump(mode="json"))
            baseline_content_sha256 = hashlib.sha256(baseline_document.encode("utf-8")).hexdigest()
            if (
                self.baseline_authority_id != self.baseline_snapshot.snapshot_id
                or self.baseline_authority_document_sha256 != baseline_content_sha256
            ):
                raise ValueError(
                    "M6 dataset baseline authority does not bind its embedded snapshot"
                )
        elif self.baseline_authority_kind != M6BaselineAuthorityKind.CHALLENGE_NO_CASE:
            raise ValueError("missing baseline snapshot requires CHALLENGE_NO_CASE authority")

        if M6RegressionDatasetKind.STABILITY in kinds and (
            self.baseline_snapshot is None
            or self.baseline_snapshot.case_status != CaseStatus.CLOSED
            or self.baseline_snapshot.terminal_appeal_status is not None
            or self.baseline_authority_kind != M6BaselineAuthorityKind.MACHINE_TERMINAL_CASE
        ):
            raise ValueError("stability set requires an unappealed machine terminal Case")

        has_gold = M6RegressionDatasetKind.GOLD in kinds
        if has_gold != (self.gold_truth is not None):
            raise ValueError("gold membership and explicit human truth authority must coincide")
        if has_gold and self.baseline_snapshot is None:
            raise ValueError("gold set requires a machine baseline snapshot")
        if self.gold_truth is not None:
            baseline = self.baseline_snapshot
            if (
                baseline is None
                or self.gold_truth.sample_id != self.sample_id
                or self.gold_truth.baseline_snapshot_id != baseline.snapshot_id
                or self.gold_truth.baseline_source_run_id != baseline.source_run_id
                or self.gold_truth.baseline_source_case_id != baseline.source_case_id
                or self.gold_truth.baseline_source_case_revision != baseline.source_case_revision
            ):
                raise ValueError("M6 gold truth does not bind its exact machine baseline")
        if (
            self.gold_truth is not None
            and self.gold_truth.authority_kind == M6GoldTruthAuthorityKind.APPEAL_RESOLUTION
            and (
                self.baseline_authority_kind != M6BaselineAuthorityKind.PRE_APPEAL_CLOSED_CASE
                or self.baseline_snapshot is None
                or self.baseline_snapshot.case_status != CaseStatus.CLOSED
                or self.baseline_snapshot.terminal_appeal_status is not None
            )
        ):
            raise ValueError("appeal gold truth requires its pre-appeal closed machine baseline")

        has_challenge = M6RegressionDatasetKind.CHALLENGE in kinds
        if has_challenge != bool(self.challenge_kinds):
            raise ValueError("challenge membership requires controlled challenge kinds")
        if len(self.challenge_kinds) != len(set(self.challenge_kinds)):
            raise ValueError("M6 challenge kinds must be unique")
        if self.challenge_kinds != tuple(
            sorted(self.challenge_kinds, key=_CHALLENGE_RANK.__getitem__)
        ):
            raise ValueError("M6 challenge kinds must use stable order")
        if self.baseline_snapshot is None and kinds != {M6RegressionDatasetKind.CHALLENGE}:
            raise ValueError("a no-Case baseline may only belong to the challenge set")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def entry_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-dataset-entry",
                1,
                self.sample_id,
                self.input_authority_id,
                self.input_authority_document_sha256,
                self.replay_input_closure_authority_id,
                self.replay_input_closure_document_sha256,
                self.baseline_authority_kind,
                self.baseline_authority_id,
                self.baseline_authority_document_sha256,
                (
                    self.baseline_snapshot.snapshot_id
                    if self.baseline_snapshot is not None
                    else None
                ),
                self.memberships,
                self.gold_truth.truth_id if self.gold_truth is not None else None,
                self.challenge_kinds,
            ]
        )


class M6RegressionDatasetSnapshot(FrozenContractModel):
    schema_version: Literal["m6-regression-dataset-snapshot-v1"] = (
        "m6-regression-dataset-snapshot-v1"
    )
    baseline_manifest_id: Sha256Hex
    execution_dataset: M6RegressionExecutionDatasetSnapshot
    source_inventory_cut_authority_id: Sha256Hex
    source_inventory_cut_document_sha256: Sha256Hex
    source_inventory_item_count: int = Field(gt=0, strict=True)
    source_inventory_root_sha256: Sha256Hex
    eligibility_policy_authority_id: Sha256Hex
    eligibility_policy_document_sha256: Sha256Hex
    selection_inventory_authority_id: Sha256Hex
    selection_inventory_document_sha256: Sha256Hex
    selection_receipt_count: int = Field(gt=0, strict=True)
    selection_inventory_root_sha256: Sha256Hex
    entries: tuple[M6RegressionDatasetEntry, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
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
                "stability_count",
                "gold_count",
                "challenge_count",
                "dataset_snapshot_id",
            ),
        )
        snapshot = handler(payload)
        _verify_claims(snapshot, claims)
        return snapshot

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        if (
            self.execution_dataset.baseline_manifest_id != self.baseline_manifest_id
            or self.source_inventory_item_count != self.selection_receipt_count
            or self.selection_receipt_count != len(self.entries)
        ):
            raise ValueError("M6 dataset inventory cut, selection, and execution scope differ")
        sample_ids = tuple(entry.sample_id for entry in self.entries)
        if sample_ids != tuple(sorted(sample_ids)):
            raise ValueError("M6 regression dataset entries must use stable sample_id order")
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("M6 regression dataset sample_ids must be unique")
        if len({entry.entry_id for entry in self.entries}) != len(self.entries):
            raise ValueError("M6 regression dataset entry identities must be unique")
        input_authority_ids = tuple(entry.input_authority_id for entry in self.entries)
        if len(input_authority_ids) != len(set(input_authority_ids)):
            raise ValueError("M6 regression dataset input authorities must be unique")
        baseline_authority_ids = tuple(entry.baseline_authority_id for entry in self.entries)
        if len(baseline_authority_ids) != len(set(baseline_authority_ids)):
            raise ValueError("M6 regression dataset baseline authorities must be unique")
        source_case_keys = tuple(
            (
                entry.baseline_snapshot.source_run_id,
                entry.baseline_snapshot.source_case_id,
                entry.baseline_snapshot.source_case_revision,
            )
            for entry in self.entries
            if entry.baseline_snapshot is not None
        )
        if len(source_case_keys) != len(set(source_case_keys)):
            raise ValueError("M6 regression dataset source Case revisions must be unique")
        if len(self.execution_dataset.entries) != len(self.entries):
            raise ValueError("M6 blinded execution and evaluator inventories differ")
        for entry, execution_entry in zip(
            self.entries,
            self.execution_dataset.entries,
            strict=True,
        ):
            if (
                entry.sample_id != execution_entry.sample_id
                or entry.input_authority_id != execution_entry.input_authority_id
                or entry.input_authority_document_sha256
                != execution_entry.input_authority_document_sha256
                or entry.replay_input_closure_authority_id
                != execution_entry.replay_input_closure_authority_id
                or entry.replay_input_closure_document_sha256
                != execution_entry.replay_input_closure_document_sha256
            ):
                raise ValueError("M6 evaluator entry differs from its blinded execution entry")
            baseline = entry.baseline_snapshot
            if baseline is not None and baseline.manifest_id != self.baseline_manifest_id:
                raise ValueError("M6 dataset baseline snapshot uses another manifest")
        gold_truths = tuple(
            entry.gold_truth for entry in self.entries if entry.gold_truth is not None
        )
        for values, name in (
            (tuple(truth.truth_id for truth in gold_truths), "truth identities"),
            (
                tuple(truth.decision_authority_id for truth in gold_truths),
                "decision authorities",
            ),
            (
                tuple(
                    truth.resolution_commit_id
                    for truth in gold_truths
                    if truth.resolution_commit_id is not None
                ),
                "appeal resolution commits",
            ),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"M6 gold {name} must be unique")
        if not self.stability_count or not self.gold_count or not self.challenge_count:
            raise ValueError(
                "M6 regression dataset requires non-empty stability, gold, and challenge sets"
            )
        return self

    def _membership_count(self, kind: M6RegressionDatasetKind) -> int:
        return sum(kind in entry.memberships for entry in self.entries)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def stability_count(self) -> int:
        return self._membership_count(M6RegressionDatasetKind.STABILITY)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def gold_count(self) -> int:
        return self._membership_count(M6RegressionDatasetKind.GOLD)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def challenge_count(self) -> int:
        return self._membership_count(M6RegressionDatasetKind.CHALLENGE)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dataset_snapshot_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-dataset-snapshot",
                1,
                self.baseline_manifest_id,
                self.execution_dataset.execution_dataset_snapshot_id,
                self.source_inventory_cut_authority_id,
                self.source_inventory_cut_document_sha256,
                self.source_inventory_item_count,
                self.source_inventory_root_sha256,
                self.eligibility_policy_authority_id,
                self.eligibility_policy_document_sha256,
                self.selection_inventory_authority_id,
                self.selection_inventory_document_sha256,
                self.selection_receipt_count,
                self.selection_inventory_root_sha256,
                [entry.entry_id for entry in self.entries],
            ]
        )


class M6RegressionPolicyAuthority(FrozenContractModel):
    schema_version: Literal["m6-regression-policy-authority-v1"] = (
        "m6-regression-policy-authority-v1"
    )
    config_sha256: Sha256Hex
    policy_version: ReferenceToken
    maximum_machine_flip_rate: StrictFloat = Field(ge=0, le=0.05)
    gold_set_max_accuracy_drop: StrictFloat = Field(ge=0, le=0)

    @field_validator("policy_version")
    @classmethod
    def validate_policy_version(cls, value: str) -> str:
        return require_reference_token(value, "M6 regression policy_version")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_policy_authority_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("policy_authority_id",))
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @computed_field  # type: ignore[prop-decorator]
    @property
    def policy_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-policy-authority",
                1,
                self.config_sha256,
                self.policy_version,
                self.maximum_machine_flip_rate,
                self.gold_set_max_accuracy_drop,
            ]
        )


class M6RegressionRunCommand(FrozenContractModel):
    schema_version: Literal["m6-regression-run-command-v1"] = "m6-regression-run-command-v1"
    mode: ReproducibilityMode
    execution_dataset_snapshot_id: Sha256Hex
    baseline_manifest_id: Sha256Hex
    candidate_manifest_id: Sha256Hex
    policy_authority: M6RegressionPolicyAuthority

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_command_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("command_id",))
        command = handler(payload)
        _verify_claims(command, claims)
        return command

    @model_validator(mode="after")
    def validate_manifest_mode(self) -> Self:
        same = self.baseline_manifest_id == self.candidate_manifest_id
        if self.mode == ReproducibilityMode.UPGRADE_REGRESSION and same:
            raise ValueError("UPGRADE_REGRESSION requires distinct manifests")
        if self.mode != ReproducibilityMode.UPGRADE_REGRESSION and not same:
            raise ValueError("locked and pinned replay require one fixed manifest")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def command_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-run-command",
                1,
                self.mode,
                self.execution_dataset_snapshot_id,
                self.baseline_manifest_id,
                self.candidate_manifest_id,
                self.policy_authority.policy_authority_id,
            ]
        )


class M6ReplayExecutionReceipt(FrozenContractModel):
    """Per-sample proof envelope reconstructed from replay input/output closure."""

    schema_version: Literal["m6-replay-execution-receipt-v1"] = "m6-replay-execution-receipt-v1"
    command_id: Sha256Hex
    mode: ReproducibilityMode
    sample_id: ReferenceToken
    execution_entry_id: Sha256Hex
    candidate_run_id: ReferenceToken
    candidate_manifest_id: Sha256Hex
    execution_component_manifest_id: Sha256Hex
    outcome: M6ReplayExecutionOutcome
    candidate_snapshot_id: Sha256Hex | None = None
    detection_count: int = Field(ge=0, strict=True)
    detection_inventory_root_sha256: Sha256Hex
    model_response_count: int = Field(ge=0, strict=True)
    model_response_inventory_root_sha256: Sha256Hex
    embedding_count: int = Field(ge=0, strict=True)
    embedding_inventory_root_sha256: Sha256Hex
    tool_result_count: int = Field(ge=0, strict=True)
    tool_result_inventory_root_sha256: Sha256Hex
    provider_call_count: int = Field(ge=0, strict=True)
    provider_trap_authority_id: Sha256Hex | None = None
    provider_trap_document_sha256: Sha256Hex | None = None

    @field_validator("sample_id", "candidate_run_id")
    @classmethod
    def validate_references(cls, value: str) -> str:
        return require_reference_token(value, "M6 replay execution reference")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_receipt_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("execution_receipt_id",))
        receipt = handler(payload)
        _verify_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_outcome_and_provider_proof(self) -> Self:
        has_snapshot = self.candidate_snapshot_id is not None
        if has_snapshot != (self.outcome == M6ReplayExecutionOutcome.CASE_REPLAYED):
            raise ValueError("M6 replay outcome and candidate snapshot binding differ")
        trap_values = (
            self.provider_trap_authority_id,
            self.provider_trap_document_sha256,
        )
        if self.mode == ReproducibilityMode.REPLAY_LOCKED:
            if self.provider_call_count != 0 or any(value is None for value in trap_values):
                raise ValueError("REPLAY_LOCKED requires zero provider calls and a trap authority")
        elif any(value is not None for value in trap_values):
            raise ValueError("only REPLAY_LOCKED may bind a provider trap authority")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def execution_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-replay-execution-receipt",
                1,
                self.command_id,
                self.mode,
                self.sample_id,
                self.execution_entry_id,
                self.candidate_run_id,
                self.candidate_manifest_id,
                self.execution_component_manifest_id,
                self.outcome,
                self.candidate_snapshot_id,
                self.detection_count,
                self.detection_inventory_root_sha256,
                self.model_response_count,
                self.model_response_inventory_root_sha256,
                self.embedding_count,
                self.embedding_inventory_root_sha256,
                self.tool_result_count,
                self.tool_result_inventory_root_sha256,
                self.provider_call_count,
                self.provider_trap_authority_id,
                self.provider_trap_document_sha256,
            ]
        )


class M6SemanticStageComparison(FrozenContractModel):
    stage: M6RegressionStage
    baseline_projection_sha256: Sha256Hex | None = None
    candidate_projection_sha256: Sha256Hex | None = None

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_changed(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("changed",))
        comparison = handler(payload)
        _verify_claims(comparison, claims)
        return comparison

    @computed_field  # type: ignore[prop-decorator]
    @property
    def changed(self) -> bool:
        return self.baseline_projection_sha256 != self.candidate_projection_sha256


class M6RegressionCaseResult(FrozenContractModel):
    entry_id: Sha256Hex
    sample_id: ReferenceToken
    baseline_snapshot: M6CaseReplaySnapshot | None = None
    candidate_snapshot: M6CaseReplaySnapshot | None = None

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 regression result sample_id")

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
                "stage_comparisons",
                "changed_stages",
                "first_divergence_stage",
                "semantic_identical",
                "behavior_identical",
                "direction_flipped",
                "emergency_degradation",
                "disposition",
                "result_id",
            ),
        )
        result = handler(payload)
        _verify_claims(result, claims)
        return result

    @model_validator(mode="after")
    def validate_snapshot_pair(self) -> Self:
        for snapshot in (self.baseline_snapshot, self.candidate_snapshot):
            if snapshot is not None and snapshot.sample_id != self.sample_id:
                raise ValueError("M6 regression result snapshot sample_id differs")
        if self.baseline_snapshot is not None and self.candidate_snapshot is not None:
            roots_equal = self.baseline_snapshot.stage_roots == self.candidate_snapshot.stage_roots
            summaries_equal = (
                self.baseline_snapshot.case_status == self.candidate_snapshot.case_status
                and self.baseline_snapshot.final_decision == self.candidate_snapshot.final_decision
                and self.baseline_snapshot.highest_alert_level
                == self.candidate_snapshot.highest_alert_level
                and self.baseline_snapshot.terminal_appeal_status
                == self.candidate_snapshot.terminal_appeal_status
            )
            if roots_equal and not summaries_equal:
                raise ValueError("equal M6 stage roots cannot carry different semantic summaries")
            if self.direction_flipped and self.first_divergence_stage is None:
                raise ValueError("a decision flip requires a first divergent semantic stage")
        return self

    def _roots(
        self,
        snapshot: M6CaseReplaySnapshot | None,
    ) -> dict[M6RegressionStage, str | None]:
        if snapshot is None:
            return {stage: None for stage in _STAGE_ORDER}
        return {root.stage: root.projection_sha256 for root in snapshot.stage_roots}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def stage_comparisons(self) -> tuple[M6SemanticStageComparison, ...]:
        baseline = self._roots(self.baseline_snapshot)
        candidate = self._roots(self.candidate_snapshot)
        return tuple(
            M6SemanticStageComparison(
                stage=stage,
                baseline_projection_sha256=baseline[stage],
                candidate_projection_sha256=candidate[stage],
            )
            for stage in _STAGE_ORDER
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def changed_stages(self) -> tuple[M6RegressionStage, ...]:
        return tuple(item.stage for item in self.stage_comparisons if item.changed)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def first_divergence_stage(self) -> M6RegressionStage | None:
        return self.changed_stages[0] if self.changed_stages else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def semantic_identical(self) -> bool:
        if self.baseline_snapshot is None or self.candidate_snapshot is None:
            return self.baseline_snapshot is self.candidate_snapshot
        return (
            self.baseline_snapshot.semantic_case_hash == self.candidate_snapshot.semantic_case_hash
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def behavior_identical(self) -> bool:
        if self.baseline_snapshot is None or self.candidate_snapshot is None:
            return self.baseline_snapshot is self.candidate_snapshot
        return (
            self.baseline_snapshot.stage_roots == self.candidate_snapshot.stage_roots
            and self.baseline_snapshot.case_status == self.candidate_snapshot.case_status
            and self.baseline_snapshot.final_decision == self.candidate_snapshot.final_decision
            and self.baseline_snapshot.highest_alert_level
            == self.candidate_snapshot.highest_alert_level
            and self.baseline_snapshot.terminal_appeal_status
            == self.candidate_snapshot.terminal_appeal_status
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def direction_flipped(self) -> bool:
        baseline = (
            self.baseline_snapshot.final_decision if self.baseline_snapshot is not None else None
        )
        candidate = (
            self.candidate_snapshot.final_decision if self.candidate_snapshot is not None else None
        )
        if self.baseline_snapshot is None or self.candidate_snapshot is None:
            return baseline is not None or candidate is not None
        return (baseline is not None or candidate is not None) and baseline != candidate

    @computed_field  # type: ignore[prop-decorator]
    @property
    def emergency_degradation(self) -> bool:
        if self.baseline_snapshot is None:
            return False
        baseline = self.baseline_snapshot.highest_alert_level
        candidate_snapshot = self.candidate_snapshot
        if baseline != AlertLevel.EMERGENCY:
            return False
        if candidate_snapshot is None or candidate_snapshot.case_status != CaseStatus.CLOSED:
            return True
        return (
            _ALERT_RANK[candidate_snapshot.highest_alert_level] < _ALERT_RANK[baseline]
            or self.direction_flipped
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def disposition(self) -> M6RegressionCaseDisposition:
        if self.baseline_snapshot is None and self.candidate_snapshot is not None:
            return M6RegressionCaseDisposition.CANDIDATE_ADDED
        if self.baseline_snapshot is not None and self.candidate_snapshot is None:
            return M6RegressionCaseDisposition.CANDIDATE_MISSING
        if self.semantic_identical:
            return M6RegressionCaseDisposition.IDENTICAL
        if self.behavior_identical:
            return M6RegressionCaseDisposition.MANIFEST_ONLY_CHANGE
        if self.direction_flipped:
            return M6RegressionCaseDisposition.DECISION_FLIP
        return M6RegressionCaseDisposition.SEMANTIC_DRIFT

    @computed_field  # type: ignore[prop-decorator]
    @property
    def result_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-case-result",
                1,
                self.entry_id,
                self.sample_id,
                (
                    self.baseline_snapshot.snapshot_id
                    if self.baseline_snapshot is not None
                    else None
                ),
                (
                    self.candidate_snapshot.snapshot_id
                    if self.candidate_snapshot is not None
                    else None
                ),
                self.disposition,
                self.changed_stages,
            ]
        )


class M6EmergencyRegressionReview(FrozenContractModel):
    result_id: Sha256Hex
    baseline_snapshot_id: Sha256Hex
    candidate_snapshot_id: Sha256Hex | None = None
    human_input_authority_id: Sha256Hex
    human_input_authority_document_sha256: Sha256Hex
    reviewer_capability_authority_id: Sha256Hex
    reviewer_capability_document_sha256: Sha256Hex
    reviewer_id: ReferenceToken
    decision: M6EmergencyReviewDecision
    summary: str = Field(min_length=1, max_length=MAX_M6_REVIEW_SUMMARY_LENGTH)

    @field_validator("reviewer_id")
    @classmethod
    def validate_reviewer_id(cls, value: str) -> str:
        return require_reference_token(value, "M6 emergency reviewer_id")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_review_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("review_id",))
        review = handler(payload)
        _verify_claims(review, claims)
        return review

    @computed_field  # type: ignore[prop-decorator]
    @property
    def review_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-emergency-regression-review",
                1,
                self.result_id,
                self.baseline_snapshot_id,
                self.candidate_snapshot_id,
                self.human_input_authority_id,
                self.human_input_authority_document_sha256,
                self.reviewer_capability_authority_id,
                self.reviewer_capability_document_sha256,
                self.reviewer_id,
                self.decision,
                self.summary,
            ]
        )


class M6RegressionReport(FrozenContractModel):
    schema_version: Literal["m6-regression-report-v1"] = "m6-regression-report-v1"
    command: M6RegressionRunCommand
    dataset: M6RegressionDatasetSnapshot
    results: tuple[M6RegressionCaseResult, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )
    execution_receipts: tuple[M6ReplayExecutionReceipt, ...] = Field(
        min_length=1,
        max_length=MAX_M6_REGRESSION_CASES,
    )
    emergency_reviews: tuple[M6EmergencyRegressionReview, ...] = ()

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
                "stability_case_count",
                "machine_flip_count",
                "machine_flip_rate",
                "gold_case_count",
                "baseline_gold_correct_count",
                "candidate_gold_correct_count",
                "baseline_gold_accuracy",
                "candidate_gold_accuracy",
                "gold_accuracy_drop",
                "challenge_case_count",
                "emergency_degradation_sample_ids",
                "gate_reason_codes",
                "disposition",
                "release_allowed",
                "report_id",
            ),
        )
        report = handler(payload)
        _verify_claims(report, claims)
        return report

    @model_validator(mode="after")
    def validate_complete_inventory_and_reviews(self) -> Self:
        if (
            self.command.execution_dataset_snapshot_id
            != self.dataset.execution_dataset.execution_dataset_snapshot_id
            or self.command.baseline_manifest_id != self.dataset.baseline_manifest_id
        ):
            raise ValueError("M6 regression command does not bind its exact execution dataset")
        if len(self.results) != len(self.dataset.entries) or len(self.execution_receipts) != len(
            self.dataset.entries
        ):
            raise ValueError(
                "M6 regression report requires one result and execution receipt per entry"
            )
        baseline_run_ids = {
            entry.baseline_snapshot.source_run_id
            for entry in self.dataset.entries
            if entry.baseline_snapshot is not None
        }
        candidate_run_ids: set[str] = set()
        for entry, execution_entry, result, receipt in zip(
            self.dataset.entries,
            self.dataset.execution_dataset.entries,
            self.results,
            self.execution_receipts,
            strict=True,
        ):
            if (
                result.entry_id != entry.entry_id
                or result.sample_id != entry.sample_id
                or result.baseline_snapshot != entry.baseline_snapshot
            ):
                raise ValueError("M6 regression result does not match its dataset entry")
            candidate = result.candidate_snapshot
            if candidate is not None:
                if candidate.manifest_id != self.command.candidate_manifest_id:
                    raise ValueError("M6 regression candidate snapshot uses another manifest")
                if candidate.source_run_id in baseline_run_ids:
                    raise ValueError("M6 candidate must come from a distinct replay run")
            candidate_snapshot_id = candidate.snapshot_id if candidate is not None else None
            if (
                receipt.command_id != self.command.command_id
                or receipt.mode != self.command.mode
                or receipt.sample_id != entry.sample_id
                or receipt.execution_entry_id != execution_entry.execution_entry_id
                or receipt.candidate_manifest_id != self.command.candidate_manifest_id
                or receipt.candidate_snapshot_id != candidate_snapshot_id
                or receipt.candidate_run_id in baseline_run_ids
                or (candidate is not None and receipt.candidate_run_id != candidate.source_run_id)
            ):
                raise ValueError("M6 execution receipt does not bind its exact replay result")
            candidate_run_ids.add(receipt.candidate_run_id)
        if len(candidate_run_ids) > 1:
            raise ValueError("M6 candidate executions must come from one replay run")
        receipt_ids = tuple(receipt.execution_receipt_id for receipt in self.execution_receipts)
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("M6 replay execution receipt identities must be unique")

        if self.command.mode != ReproducibilityMode.UPGRADE_REGRESSION and self.emergency_reviews:
            raise ValueError("emergency release reviews only apply to upgrade regression")
        result_by_id = {result.result_id: result for result in self.results}
        if len(result_by_id) != len(self.results):
            raise ValueError("M6 regression result identities must be unique")
        reviewed_ids = tuple(review.result_id for review in self.emergency_reviews)
        if reviewed_ids != tuple(sorted(reviewed_ids)):
            raise ValueError("M6 emergency reviews must use stable result_id order")
        if len(reviewed_ids) != len(set(reviewed_ids)):
            raise ValueError("M6 emergency reviews must be unique by result")
        human_input_ids = tuple(
            review.human_input_authority_id for review in self.emergency_reviews
        )
        if len(human_input_ids) != len(set(human_input_ids)):
            raise ValueError("M6 emergency human-input authorities must be unique")
        for review in self.emergency_reviews:
            reviewed_result = result_by_id.get(review.result_id)
            if (
                reviewed_result is None
                or not reviewed_result.emergency_degradation
                or reviewed_result.baseline_snapshot is None
                or review.baseline_snapshot_id != reviewed_result.baseline_snapshot.snapshot_id
                or review.candidate_snapshot_id
                != (
                    reviewed_result.candidate_snapshot.snapshot_id
                    if reviewed_result.candidate_snapshot is not None
                    else None
                )
            ):
                raise ValueError("M6 emergency review does not bind an exact degradation result")
        return self

    def _entry_result_pairs(
        self,
        kind: M6RegressionDatasetKind,
    ) -> tuple[tuple[M6RegressionDatasetEntry, M6RegressionCaseResult], ...]:
        return tuple(
            (entry, result)
            for entry, result in zip(self.dataset.entries, self.results, strict=True)
            if kind in entry.memberships
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def stability_case_count(self) -> int:
        return len(self._entry_result_pairs(M6RegressionDatasetKind.STABILITY))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def machine_flip_count(self) -> int:
        return sum(
            result.direction_flipped
            for _, result in self._entry_result_pairs(M6RegressionDatasetKind.STABILITY)
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def machine_flip_rate(self) -> float:
        return self.machine_flip_count / self.stability_case_count

    @computed_field  # type: ignore[prop-decorator]
    @property
    def gold_case_count(self) -> int:
        return len(self._entry_result_pairs(M6RegressionDatasetKind.GOLD))

    def _gold_correct_count(self, *, candidate: bool) -> int:
        correct = 0
        for entry, result in self._entry_result_pairs(M6RegressionDatasetKind.GOLD):
            if entry.gold_truth is None:
                raise ValueError("M6 gold entry lost its truth authority")
            snapshot = result.candidate_snapshot if candidate else result.baseline_snapshot
            if (
                snapshot is not None
                and snapshot.final_decision == entry.gold_truth.expected_decision
            ):
                correct += 1
        return correct

    @computed_field  # type: ignore[prop-decorator]
    @property
    def baseline_gold_correct_count(self) -> int:
        return self._gold_correct_count(candidate=False)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_gold_correct_count(self) -> int:
        return self._gold_correct_count(candidate=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def baseline_gold_accuracy(self) -> float:
        return self.baseline_gold_correct_count / self.gold_case_count

    @computed_field  # type: ignore[prop-decorator]
    @property
    def candidate_gold_accuracy(self) -> float:
        return self.candidate_gold_correct_count / self.gold_case_count

    @computed_field  # type: ignore[prop-decorator]
    @property
    def gold_accuracy_drop(self) -> float:
        return self.baseline_gold_accuracy - self.candidate_gold_accuracy

    @computed_field  # type: ignore[prop-decorator]
    @property
    def challenge_case_count(self) -> int:
        return len(self._entry_result_pairs(M6RegressionDatasetKind.CHALLENGE))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def emergency_degradation_sample_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(result.sample_id for result in self.results if result.emergency_degradation)
        )

    def _emergency_review_state(self) -> tuple[bool, bool]:
        review_by_result = {review.result_id: review for review in self.emergency_reviews}
        unreviewed = False
        rejected = False
        for result in self.results:
            if not result.emergency_degradation:
                continue
            review = review_by_result.get(result.result_id)
            if review is None:
                unreviewed = True
            elif review.decision == M6EmergencyReviewDecision.REJECTED:
                rejected = True
        return unreviewed, rejected

    @computed_field  # type: ignore[prop-decorator]
    @property
    def gate_reason_codes(self) -> tuple[M6RegressionGateReason, ...]:
        reasons: list[M6RegressionGateReason] = []
        if self.command.mode == ReproducibilityMode.REPLAY_LOCKED:
            if any(not result.semantic_identical for result in self.results):
                reasons.append(M6RegressionGateReason.LOCKED_SEMANTIC_MISMATCH)
        elif self.command.mode == ReproducibilityMode.UPGRADE_REGRESSION:
            required_pairs = tuple(
                (entry, result)
                for entry, result in zip(self.dataset.entries, self.results, strict=True)
                if M6RegressionDatasetKind.STABILITY in entry.memberships
                or M6RegressionDatasetKind.GOLD in entry.memberships
            )
            if any(result.candidate_snapshot is None for _, result in required_pairs):
                reasons.append(M6RegressionGateReason.REQUIRED_CANDIDATE_MISSING)
            if any(
                result.candidate_snapshot is not None
                and result.candidate_snapshot.case_status != CaseStatus.CLOSED
                for _, result in required_pairs
            ):
                reasons.append(M6RegressionGateReason.REQUIRED_CANDIDATE_NONTERMINAL)
            if _ratio_exceeds(
                self.machine_flip_count,
                self.stability_case_count,
                self.command.policy_authority.maximum_machine_flip_rate,
            ):
                reasons.append(M6RegressionGateReason.MACHINE_FLIP_RATE_EXCEEDED)
            gold_drop_count = self.baseline_gold_correct_count - self.candidate_gold_correct_count
            if _ratio_exceeds(
                gold_drop_count,
                self.gold_case_count,
                self.command.policy_authority.gold_set_max_accuracy_drop,
            ):
                reasons.append(M6RegressionGateReason.GOLD_ACCURACY_DROP_EXCEEDED)
            unreviewed, rejected = self._emergency_review_state()
            if unreviewed:
                reasons.append(M6RegressionGateReason.EMERGENCY_DEGRADATION_UNREVIEWED)
            if rejected:
                reasons.append(M6RegressionGateReason.EMERGENCY_DEGRADATION_REJECTED)
        return tuple(sorted(reasons, key=_GATE_REASON_RANK.__getitem__))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def disposition(self) -> M6RegressionDisposition:
        if self.command.mode == ReproducibilityMode.REINFER_PINNED:
            return M6RegressionDisposition.DIAGNOSTIC_COMPLETE
        hard_reasons = tuple(
            reason
            for reason in self.gate_reason_codes
            if reason != M6RegressionGateReason.EMERGENCY_DEGRADATION_UNREVIEWED
        )
        if hard_reasons:
            return M6RegressionDisposition.FAILED
        if M6RegressionGateReason.EMERGENCY_DEGRADATION_UNREVIEWED in self.gate_reason_codes:
            return M6RegressionDisposition.REQUIRES_HUMAN_REVIEW
        return M6RegressionDisposition.PASSED

    @computed_field  # type: ignore[prop-decorator]
    @property
    def release_allowed(self) -> bool:
        return self.disposition == M6RegressionDisposition.PASSED

    @computed_field  # type: ignore[prop-decorator]
    @property
    def report_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-report",
                1,
                self.command.command_id,
                self.dataset.dataset_snapshot_id,
                [result.result_id for result in self.results],
                [receipt.execution_receipt_id for receipt in self.execution_receipts],
                [review.review_id for review in self.emergency_reviews],
                self.gate_reason_codes,
                self.disposition,
            ]
        )


__all__ = [
    "MAX_M6_REGRESSION_CASES",
    "M6BaselineAuthorityKind",
    "M6CaseReplaySnapshot",
    "M6ChallengeKind",
    "M6EmergencyRegressionReview",
    "M6EmergencyReviewDecision",
    "M6GoldTruthAuthority",
    "M6GoldTruthAuthorityKind",
    "M6RegressionCaseDisposition",
    "M6RegressionCaseResult",
    "M6RegressionDatasetEntry",
    "M6RegressionDatasetKind",
    "M6RegressionDatasetSnapshot",
    "M6RegressionDisposition",
    "M6RegressionExecutionDatasetSnapshot",
    "M6RegressionExecutionEntry",
    "M6RegressionGateReason",
    "M6RegressionPolicyAuthority",
    "M6RegressionReport",
    "M6RegressionRunCommand",
    "M6RegressionStage",
    "M6ReplayExecutionOutcome",
    "M6ReplayExecutionReceipt",
    "M6SemanticStageComparison",
    "M6SemanticStageRoot",
]
