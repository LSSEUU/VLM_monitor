"""Evaluator-only M6 eligibility, challenge, and complete selection contracts."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    Field,
    ModelWrapValidatorHandler,
    computed_field,
    field_validator,
    model_validator,
)

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.enums import AppealStatus, CaseStatus
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m5_appeals import AppealVersionAuthority
from labcourt.contracts.m6_regression import (
    MAX_M6_REGRESSION_CASES,
    M6CaseReplaySnapshot,
    M6ChallengeKind,
    M6RegressionDatasetKind,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionSourceInventoryItem,
    require_m6_opaque_sample_id,
)
from labcourt.contracts.m6_regression_gold import M6AppealGoldTruthAuthority
from labcourt.contracts.references import ReferenceToken, require_reference_token

_CHALLENGE_RANK = {value: index for index, value in enumerate(M6ChallengeKind)}


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
            raise ValueError(f"serialized {name} conflicts with derived M6 selection content")


def _content_sha256(value: FrozenContractModel) -> str:
    payload = canonical_json(value.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class M6RegressionSelectionDisposition(StrEnum):
    SELECTED_STABILITY = "SELECTED_STABILITY"
    SELECTED_APPEAL_GOLD = "SELECTED_APPEAL_GOLD"
    BLOCKED_PENDING_APPEAL = "BLOCKED_PENDING_APPEAL"


class M6RegressionEligibilityPolicyAuthority(FrozenContractModel):
    """The fixed first M6 policy; unsupported truth sources cannot be enabled."""

    schema_version: Literal["m6-regression-eligibility-policy-v1"] = (
        "m6-regression-eligibility-policy-v1"
    )
    selection_scope: Literal["INCLUDE_ALL_SOURCE_ITEMS"] = "INCLUDE_ALL_SOURCE_ITEMS"
    closed_unappealed_policy: Literal["SELECT_STABILITY"] = "SELECT_STABILITY"
    pending_appeal_policy: Literal["BLOCK_DATASET"] = "BLOCK_DATASET"
    terminal_appeal_policy: Literal["SELECT_APPEAL_GOLD"] = "SELECT_APPEAL_GOLD"
    gold_authority_policy: Literal["APPEAL_RESOLUTION_ONLY"] = "APPEAL_RESOLUTION_ONLY"
    challenge_policy: Literal["EXPLICIT_AUTHORITY_ONLY"] = "EXPLICIT_AUTHORITY_ONLY"
    sample_identity_policy: Literal["REUSE_SOURCE_CUT_OPAQUE_ID"] = "REUSE_SOURCE_CUT_OPAQUE_ID"

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_policy_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("eligibility_policy_authority_id",))
        policy = handler(payload)
        _verify_claims(policy, claims)
        return policy

    @computed_field  # type: ignore[prop-decorator]
    @property
    def eligibility_policy_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-eligibility-policy",
                1,
                self.selection_scope,
                self.closed_unappealed_policy,
                self.pending_appeal_policy,
                self.terminal_appeal_policy,
                self.gold_authority_policy,
                self.challenge_policy,
                self.sample_identity_policy,
            ]
        )


class M6SyntheticChallengeScenarioAuthority(FrozenContractModel):
    """Physical evaluator annotation for one synthetic/precomputed challenge."""

    schema_version: Literal["m6-synthetic-challenge-scenario-authority-v1"] = (
        "m6-synthetic-challenge-scenario-authority-v1"
    )
    scenario_name: ReferenceToken
    scenario_revision: int = Field(gt=0, strict=True)
    source_mode: Literal["SYNTHETIC_PRECOMPUTED"] = "SYNTHETIC_PRECOMPUTED"
    source_item_id: Sha256Hex
    sample_id: ReferenceToken
    input_authority_id: Sha256Hex
    input_authority_document_sha256: Sha256Hex
    replay_input_closure_authority_id: Sha256Hex
    replay_input_closure_document_sha256: Sha256Hex
    challenge_kinds: tuple[M6ChallengeKind, ...] = Field(min_length=1, max_length=10)

    @field_validator("scenario_name")
    @classmethod
    def validate_scenario_name(cls, value: str) -> str:
        return require_reference_token(value, "M6 challenge scenario_name")

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_scenario_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("scenario_authority_id",))
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_scope_and_kinds(self) -> Self:
        require_m6_opaque_sample_id(self.sample_id)
        if len(self.challenge_kinds) != len(set(self.challenge_kinds)) or (
            self.challenge_kinds
            != tuple(sorted(self.challenge_kinds, key=_CHALLENGE_RANK.__getitem__))
        ):
            raise ValueError("M6 synthetic challenge kinds must be unique and ordered")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def scenario_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-synthetic-challenge-scenario-authority",
                1,
                self.scenario_name,
                self.scenario_revision,
                self.source_mode,
                self.source_item_id,
                self.sample_id,
                self.input_authority_id,
                self.input_authority_document_sha256,
                self.replay_input_closure_authority_id,
                self.replay_input_closure_document_sha256,
                self.challenge_kinds,
            ]
        )


class M6ChallengeDesignationAuthority(FrozenContractModel):
    """Explicit evaluator authority overlaying a selected source with challenge kinds."""

    schema_version: Literal["m6-challenge-designation-authority-v1"] = (
        "m6-challenge-designation-authority-v1"
    )
    source_item_id: Sha256Hex
    sample_id: ReferenceToken
    authority_kind: Literal["SYNTHETIC_SCENARIO"] = "SYNTHETIC_SCENARIO"
    source_authority_id: Sha256Hex
    source_authority_document_sha256: Sha256Hex
    challenge_kinds: tuple[M6ChallengeKind, ...] = Field(min_length=1, max_length=10)

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_designation_id(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_claims(value, ("challenge_designation_authority_id",))
        authority = handler(payload)
        _verify_claims(authority, claims)
        return authority

    @model_validator(mode="after")
    def validate_stable_kinds(self) -> Self:
        require_m6_opaque_sample_id(self.sample_id)
        if len(self.challenge_kinds) != len(set(self.challenge_kinds)) or self.challenge_kinds != (
            tuple(sorted(self.challenge_kinds, key=_CHALLENGE_RANK.__getitem__))
        ):
            raise ValueError("M6 challenge designation kinds must be unique and ordered")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def challenge_designation_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-challenge-designation-authority",
                1,
                self.source_item_id,
                self.sample_id,
                self.authority_kind,
                self.source_authority_id,
                self.source_authority_document_sha256,
                self.challenge_kinds,
            ]
        )


class M6RegressionSelectionReceipt(FrozenContractModel):
    """One derived receipt for every source item, including blocked pending appeals."""

    source_inventory_cut_authority_id: Sha256Hex
    eligibility_policy_authority_id: Sha256Hex
    source_item: M6RegressionSourceInventoryItem
    baseline_snapshot: M6CaseReplaySnapshot
    source_m5_authority_root_sha256: Sha256Hex
    current_case_authority_root_sha256: Sha256Hex
    current_case_revision: int = Field(gt=0, strict=True)
    current_case_document_sha256: Sha256Hex
    current_case_status: CaseStatus
    current_appeal_authority: AppealVersionAuthority | None = None
    appeal_gold_authority: M6AppealGoldTruthAuthority | None = None
    challenge_designation: M6ChallengeDesignationAuthority | None = None

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
                "baseline_snapshot_content_sha256",
                "current_appeal_content_sha256",
                "appeal_gold_content_sha256",
                "challenge_designation_content_sha256",
                "selection_disposition",
                "memberships",
                "challenge_kinds",
                "selection_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_exact_selection_matrix(self) -> Self:
        item = M6RegressionSourceInventoryItem.model_validate(
            self.source_item.model_dump(mode="json", exclude_computed_fields=True)
        )
        baseline = M6CaseReplaySnapshot.model_validate(
            self.baseline_snapshot.model_dump(mode="json", exclude_computed_fields=True)
        )
        if item != self.source_item or baseline != self.baseline_snapshot:
            raise ValueError("M6 selection receipt contains a non-canonical source or baseline")
        if (
            baseline.sample_id != item.sample_id
            or baseline.source_run_id != item.source_run_id
            or baseline.source_case_id != item.source_case_id
            or baseline.source_case_revision != item.source_case_revision
            or baseline.source_case_document_sha256 != item.source_case_document_sha256
            or baseline.manifest_id != item.source_manifest_id
            or baseline.case_status != CaseStatus.CLOSED
            or baseline.final_decision is None
            or baseline.terminal_appeal_status is not None
            or self.source_m5_authority_root_sha256 != item.sealed_source_m5_authority_root_sha256
        ):
            raise ValueError("M6 selection baseline differs from its sealed source item")
        appeal = self.current_appeal_authority
        if appeal is not None and not isinstance(appeal, AppealVersionAuthority):
            raise ValueError("M6 selection current appeal must be a typed authority")
        if isinstance(appeal, AppealVersionAuthority):
            canonical_appeal = AppealVersionAuthority.model_validate(
                appeal.model_dump(mode="json", exclude_computed_fields=True)
            )
            if canonical_appeal != appeal:
                raise ValueError("M6 selection current appeal is not canonical")
            appeal = canonical_appeal
            source = appeal.source_case_authority
            if (
                appeal.run_id != item.source_run_id
                or appeal.appeal.case_id != item.source_case_id
                or appeal.source_case_revision != item.source_case_revision
                or appeal.manifest_id != item.source_manifest_id
                or appeal.source_decision != baseline.final_decision
                or source.final_decision != baseline.final_decision
            ):
                raise ValueError("M6 selection appeal differs from its pre-appeal baseline")
        gold = self.appeal_gold_authority
        if gold is not None:
            canonical_gold = M6AppealGoldTruthAuthority.model_validate(
                gold.model_dump(mode="json", exclude_computed_fields=True)
            )
            if canonical_gold != gold:
                raise ValueError("M6 selection appeal gold authority is not canonical")
            gold = canonical_gold
        challenge = self.challenge_designation
        if challenge is not None:
            canonical_challenge = M6ChallengeDesignationAuthority.model_validate(
                challenge.model_dump(mode="json", exclude_computed_fields=True)
            )
            if canonical_challenge != challenge:
                raise ValueError("M6 selection challenge designation is not canonical")
            if (
                challenge.source_item_id != item.source_item_id
                or challenge.sample_id != item.sample_id
            ):
                raise ValueError("M6 challenge designation belongs to another source item")
            challenge = canonical_challenge

        if self.current_case_status == CaseStatus.CLOSED:
            valid = (
                self.current_case_revision == item.source_case_revision
                and self.current_case_document_sha256 == item.source_case_document_sha256
                and appeal is None
                and gold is None
            )
        elif self.current_case_status == CaseStatus.APPEALED:
            valid = (
                appeal is not None
                and appeal.version in {1, 2}
                and appeal.appeal.status in {AppealStatus.SUBMITTED, AppealStatus.UNDER_REVIEW}
                and self.current_case_revision == item.source_case_revision + appeal.version
                and gold is None
                and challenge is None
            )
        elif self.current_case_status == CaseStatus.APPEAL_RESOLVED:
            valid = (
                appeal is not None
                and appeal.version == 3
                and appeal.appeal.status in {AppealStatus.UPHELD, AppealStatus.OVERTURNED}
                and self.current_case_revision == item.source_case_revision + 3
                and gold is not None
                and gold.source_item == item
                and gold.baseline_snapshot == baseline
                and gold.terminal_appeal_authority == appeal
                and gold.resolution_commit.resulting_case_revision == self.current_case_revision
                and gold.resolution_commit.resulting_case_document_sha256
                == self.current_case_document_sha256
            )
        else:
            valid = False
        if not valid:
            raise ValueError("M6 selection receipt violates the exact Case/appeal state matrix")
        object.__setattr__(self, "source_item", item)
        object.__setattr__(self, "baseline_snapshot", baseline)
        object.__setattr__(self, "current_appeal_authority", appeal)
        object.__setattr__(self, "appeal_gold_authority", gold)
        object.__setattr__(self, "challenge_designation", challenge)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def baseline_snapshot_content_sha256(self) -> Sha256Hex:
        return _content_sha256(self.baseline_snapshot)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def current_appeal_content_sha256(self) -> Sha256Hex | None:
        appeal = self.current_appeal_authority
        return _content_sha256(appeal) if appeal is not None else None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def appeal_gold_content_sha256(self) -> Sha256Hex | None:
        return (
            _content_sha256(self.appeal_gold_authority)
            if self.appeal_gold_authority is not None
            else None
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def challenge_designation_content_sha256(self) -> Sha256Hex | None:
        return (
            _content_sha256(self.challenge_designation)
            if self.challenge_designation is not None
            else None
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def selection_disposition(self) -> M6RegressionSelectionDisposition:
        if self.current_case_status == CaseStatus.CLOSED:
            return M6RegressionSelectionDisposition.SELECTED_STABILITY
        if self.current_case_status == CaseStatus.APPEALED:
            return M6RegressionSelectionDisposition.BLOCKED_PENDING_APPEAL
        return M6RegressionSelectionDisposition.SELECTED_APPEAL_GOLD

    @computed_field  # type: ignore[prop-decorator]
    @property
    def memberships(self) -> tuple[M6RegressionDatasetKind, ...]:
        if self.selection_disposition == M6RegressionSelectionDisposition.BLOCKED_PENDING_APPEAL:
            return ()
        primary = (
            M6RegressionDatasetKind.STABILITY
            if self.selection_disposition == M6RegressionSelectionDisposition.SELECTED_STABILITY
            else M6RegressionDatasetKind.GOLD
        )
        if self.challenge_designation is None:
            return (primary,)
        return (primary, M6RegressionDatasetKind.CHALLENGE)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def challenge_kinds(self) -> tuple[M6ChallengeKind, ...]:
        return (
            self.challenge_designation.challenge_kinds
            if self.challenge_designation is not None
            else ()
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def selection_receipt_id(self) -> Sha256Hex:
        appeal = self.current_appeal_authority
        appeal_id = appeal.authority_sha256 if appeal is not None else None
        return sha256_hex(
            [
                "m6-regression-selection-receipt",
                1,
                self.source_inventory_cut_authority_id,
                self.eligibility_policy_authority_id,
                self.source_item.source_item_id,
                self.baseline_snapshot.snapshot_id,
                self.baseline_snapshot_content_sha256,
                self.source_m5_authority_root_sha256,
                self.current_case_authority_root_sha256,
                self.current_case_revision,
                self.current_case_document_sha256,
                self.current_case_status,
                appeal_id,
                self.current_appeal_content_sha256,
                (
                    self.appeal_gold_authority.appeal_gold_authority_id
                    if self.appeal_gold_authority is not None
                    else None
                ),
                self.appeal_gold_content_sha256,
                (
                    self.challenge_designation.challenge_designation_authority_id
                    if self.challenge_designation is not None
                    else None
                ),
                self.challenge_designation_content_sha256,
                self.selection_disposition,
                self.memberships,
                self.challenge_kinds,
            ]
        )


class M6RegressionSelectionInventoryAuthority(FrozenContractModel):
    """One complete selection receipt per source-cut item, including blockers."""

    schema_version: Literal["m6-regression-selection-inventory-v1"] = (
        "m6-regression-selection-inventory-v1"
    )
    baseline_manifest_id: Sha256Hex
    source_inventory_cut_authority_id: Sha256Hex
    source_inventory_cut_content_sha256: Sha256Hex
    source_inventory_item_count: int = Field(
        gt=0,
        le=MAX_M6_REGRESSION_CASES,
        strict=True,
    )
    source_inventory_root_sha256: Sha256Hex
    eligibility_policy: M6RegressionEligibilityPolicyAuthority
    receipts: tuple[M6RegressionSelectionReceipt, ...] = Field(
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
                "eligibility_policy_content_sha256",
                "receipt_count",
                "selected_count",
                "blocked_count",
                "stability_count",
                "gold_count",
                "challenge_count",
                "selection_inventory_root_sha256",
                "selection_inventory_authority_id",
            ),
        )
        inventory = handler(payload)
        _verify_claims(inventory, claims)
        return inventory

    @model_validator(mode="after")
    def validate_complete_source_coverage(self) -> Self:
        policy = M6RegressionEligibilityPolicyAuthority.model_validate(
            self.eligibility_policy.model_dump(mode="json", exclude_computed_fields=True)
        )
        receipts = tuple(
            M6RegressionSelectionReceipt.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in self.receipts
        )
        if policy != self.eligibility_policy or receipts != self.receipts:
            raise ValueError("M6 selection inventory contains non-canonical authorities")
        sample_ids = tuple(item.source_item.sample_id for item in receipts)
        if sample_ids != tuple(sorted(sample_ids)) or len(sample_ids) != len(set(sample_ids)):
            raise ValueError("M6 selection receipts must be unique and ordered by sample_id")
        if self.source_inventory_item_count != len(receipts):
            raise ValueError("M6 selection receipts do not cover every source item")
        expected_source_root = sha256_hex(
            [
                "m6-regression-source-inventory",
                1,
                [item.source_item.source_item_id for item in receipts],
            ]
        )
        if expected_source_root != self.source_inventory_root_sha256:
            raise ValueError("M6 selection source inventory root differs from its receipts")
        if any(
            item.source_inventory_cut_authority_id != self.source_inventory_cut_authority_id
            or item.eligibility_policy_authority_id != policy.eligibility_policy_authority_id
            or item.source_item.source_manifest_id != self.baseline_manifest_id
            for item in receipts
        ):
            raise ValueError("M6 selection receipt belongs to another cut, policy, or manifest")
        for values, label in (
            (tuple(item.source_item.source_item_id for item in receipts), "source items"),
            (
                tuple(
                    (item.source_item.source_run_id, item.source_item.source_case_id)
                    for item in receipts
                ),
                "source Cases",
            ),
            (tuple(item.selection_receipt_id for item in receipts), "selection receipts"),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"M6 selection inventory {label} must be unique")
        object.__setattr__(self, "eligibility_policy", policy)
        object.__setattr__(self, "receipts", receipts)
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def eligibility_policy_content_sha256(self) -> Sha256Hex:
        return _content_sha256(self.eligibility_policy)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def receipt_count(self) -> int:
        return len(self.receipts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def selected_count(self) -> int:
        return self.receipt_count - self.blocked_count

    @computed_field  # type: ignore[prop-decorator]
    @property
    def blocked_count(self) -> int:
        return sum(
            item.selection_disposition == M6RegressionSelectionDisposition.BLOCKED_PENDING_APPEAL
            for item in self.receipts
        )

    def _membership_count(self, kind: M6RegressionDatasetKind) -> int:
        return sum(kind in item.memberships for item in self.receipts)

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
    def selection_inventory_root_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-selection-inventory-root",
                1,
                [item.selection_receipt_id for item in self.receipts],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def selection_inventory_authority_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m6-regression-selection-inventory",
                1,
                self.baseline_manifest_id,
                self.source_inventory_cut_authority_id,
                self.source_inventory_cut_content_sha256,
                self.source_inventory_item_count,
                self.source_inventory_root_sha256,
                self.eligibility_policy.eligibility_policy_authority_id,
                self.eligibility_policy_content_sha256,
                self.selection_inventory_root_sha256,
            ]
        )


__all__ = [
    "M6ChallengeDesignationAuthority",
    "M6RegressionEligibilityPolicyAuthority",
    "M6RegressionSelectionDisposition",
    "M6RegressionSelectionInventoryAuthority",
    "M6RegressionSelectionReceipt",
    "M6SyntheticChallengeScenarioAuthority",
]
