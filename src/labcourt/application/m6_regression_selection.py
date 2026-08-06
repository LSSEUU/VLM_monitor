"""Build the complete M6 selection inventory from verified source observations."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_regression_gold import (
    M6AppealGoldTruthError,
    build_m6_appeal_gold_truth_authority,
)
from labcourt.application.m6_verified_projection_context import M6SqliteProjectionAssembly
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression import M6CaseReplaySnapshot
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionSourceInventoryCutAuthority,
    M6RegressionSourceInventoryItem,
)
from labcourt.contracts.m6_regression_selection import (
    M6ChallengeDesignationAuthority,
    M6RegressionEligibilityPolicyAuthority,
    M6RegressionSelectionInventoryAuthority,
    M6RegressionSelectionReceipt,
    M6SyntheticChallengeScenarioAuthority,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_challenge_scenarios import M6ChallengeScenarioObservation
from labcourt.ports.m6_regression_appeals import (
    M6RegressionAppealHistoryObservation,
    M6RegressionAppealState,
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6RegressionSelectionErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_CUT_INVALID = "SOURCE_CUT_INVALID"
    SOURCE_CUT_DOCUMENT_INVALID = "SOURCE_CUT_DOCUMENT_INVALID"
    SOURCE_SCOPE_INCOMPLETE = "SOURCE_SCOPE_INCOMPLETE"
    SNAPSHOT_IDENTITY_MISMATCH = "SNAPSHOT_IDENTITY_MISMATCH"
    BASELINE_PROJECTION_INVALID = "BASELINE_PROJECTION_INVALID"
    APPEAL_HISTORY_INVALID = "APPEAL_HISTORY_INVALID"
    CHALLENGE_AUTHORITY_INVALID = "CHALLENGE_AUTHORITY_INVALID"
    GOLD_AUTHORITY_INVALID = "GOLD_AUTHORITY_INVALID"
    SELECTION_INVARIANT_VIOLATION = "SELECTION_INVARIANT_VIOLATION"


class M6RegressionSelectionError(LabCourtError):
    """The complete source universe could not produce one selection inventory."""

    def __init__(self, code: M6RegressionSelectionErrorCode) -> None:
        if not isinstance(code, M6RegressionSelectionErrorCode):
            raise TypeError("code must be an M6RegressionSelectionErrorCode")
        self.code = code
        super().__init__(f"M6 regression selection failed: {code.value}")


@dataclass(frozen=True, slots=True)
class M6RegressionSelectionBundle:
    eligibility_policy: M6RegressionEligibilityPolicyAuthority
    selection_inventory: M6RegressionSelectionInventoryAuthority
    eligibility_policy_document: str
    eligibility_policy_content_sha256: str
    selection_inventory_document: str
    selection_inventory_content_sha256: str


def _fail(code: M6RegressionSelectionErrorCode) -> NoReturn:
    raise M6RegressionSelectionError(code)


def _canonical_model(
    value: object,
    expected: type[_ModelT],
    code: M6RegressionSelectionErrorCode,
) -> _ModelT:
    if not isinstance(value, expected):
        _fail(M6RegressionSelectionErrorCode.INVALID_ARGUMENT)
    try:
        controlled = expected.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(code)
    if controlled != value:
        _fail(code)
    return controlled


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json"))


def _content_sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _validate_projection(
    projection: M6SqliteProjectionAssembly,
    item: M6RegressionSourceInventoryItem,
    history: M6RegressionAppealHistoryObservation,
) -> M6CaseReplaySnapshot:
    closure = _canonical_model(
        projection.closure,
        M6ReplayInputClosureAuthority,
        M6RegressionSelectionErrorCode.BASELINE_PROJECTION_INVALID,
    )
    baseline = _canonical_model(
        projection.case_replay_snapshot,
        M6CaseReplaySnapshot,
        M6RegressionSelectionErrorCode.BASELINE_PROJECTION_INVALID,
    )
    if (
        projection.source_identity_sha256 != history.source_identity_sha256
        or projection.model_calls != closure.model_calls
        or closure.sample_id != item.sample_id
        or closure.source_run_id != item.source_run_id
        or closure.source_case_id != item.source_case_id
        or closure.source_case_revision != item.source_case_revision
        or closure.source_case_document_sha256 != item.source_case_document_sha256
        or closure.source_manifest_id != item.source_manifest_id
        or closure.input_authority_id != item.input_authority_id
        or closure.input_authority_document_sha256 != item.input_authority_document_sha256
        or closure.replay_input_closure_authority_id != item.replay_input_closure_authority_id
        or closure.replay_input_closure_document_sha256 != item.replay_input_closure_document_sha256
        or baseline.sample_id != item.sample_id
        or baseline.source_run_id != item.source_run_id
        or baseline.source_case_id != item.source_case_id
        or baseline.source_case_revision != item.source_case_revision
        or baseline.source_case_document_sha256 != item.source_case_document_sha256
        or baseline.manifest_id != item.source_manifest_id
    ):
        _fail(M6RegressionSelectionErrorCode.BASELINE_PROJECTION_INVALID)
    return baseline


def _resolve_challenge_scenario(
    observation: M6ChallengeScenarioObservation,
) -> M6ChallengeDesignationAuthority:
    scenario = _canonical_model(
        observation.scenario,
        M6SyntheticChallengeScenarioAuthority,
        M6RegressionSelectionErrorCode.CHALLENGE_AUTHORITY_INVALID,
    )
    document = observation.canonical_document
    payload = document.encode("utf-8")
    if (
        _document(scenario) != document
        or hashlib.sha256(payload).hexdigest() != observation.content_sha256
        or len(payload) != observation.size_bytes
    ):
        _fail(M6RegressionSelectionErrorCode.CHALLENGE_AUTHORITY_INVALID)
    try:
        return M6ChallengeDesignationAuthority(
            source_item_id=scenario.source_item_id,
            sample_id=scenario.sample_id,
            source_authority_id=scenario.scenario_authority_id,
            source_authority_document_sha256=observation.content_sha256,
            challenge_kinds=scenario.challenge_kinds,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6RegressionSelectionErrorCode.CHALLENGE_AUTHORITY_INVALID)


def build_m6_regression_selection_inventory(
    *,
    source_inventory_cut: object,
    source_inventory_cut_document: object,
    baseline_projections: object,
    appeal_histories: object,
    challenge_scenarios: object = (),
) -> M6RegressionSelectionBundle:
    """Emit one derived receipt for every item in the exact source cut."""

    cut = _canonical_model(
        source_inventory_cut,
        M6RegressionSourceInventoryCutAuthority,
        M6RegressionSelectionErrorCode.SOURCE_CUT_INVALID,
    )
    if (
        not isinstance(source_inventory_cut_document, str)
        or _document(cut) != source_inventory_cut_document
    ):
        _fail(M6RegressionSelectionErrorCode.SOURCE_CUT_DOCUMENT_INVALID)
    if (
        not isinstance(baseline_projections, tuple)
        or any(not isinstance(item, M6SqliteProjectionAssembly) for item in baseline_projections)
        or not isinstance(appeal_histories, tuple)
        or any(
            not isinstance(item, M6RegressionAppealHistoryObservation) for item in appeal_histories
        )
        or not isinstance(challenge_scenarios, tuple)
        or any(not isinstance(item, M6ChallengeScenarioObservation) for item in challenge_scenarios)
    ):
        _fail(M6RegressionSelectionErrorCode.INVALID_ARGUMENT)
    challenges = tuple(_resolve_challenge_scenario(item) for item in challenge_scenarios)
    projections_by_sample = {item.closure.sample_id: item for item in baseline_projections}
    histories_by_sample = {item.source_item.sample_id: item for item in appeal_histories}
    challenges_by_sample = {item.sample_id: item for item in challenges}
    cut_samples = tuple(item.sample_id for item in cut.items)
    if (
        len(projections_by_sample) != len(baseline_projections)
        or len(histories_by_sample) != len(appeal_histories)
        or len(challenges_by_sample) != len(challenges)
        or set(projections_by_sample) != set(cut_samples)
        or set(histories_by_sample) != set(cut_samples)
        or not set(challenges_by_sample).issubset(cut_samples)
    ):
        _fail(M6RegressionSelectionErrorCode.SOURCE_SCOPE_INCOMPLETE)
    identities = {
        *(item.source_identity_sha256 for item in baseline_projections),
        *(item.source_identity_sha256 for item in appeal_histories),
    }
    if len(identities) != 1:
        _fail(M6RegressionSelectionErrorCode.SNAPSHOT_IDENTITY_MISMATCH)
    run_cuts = {item.source_run_id: item for item in cut.run_cuts}
    policy = M6RegressionEligibilityPolicyAuthority()
    receipts: list[M6RegressionSelectionReceipt] = []
    for item in cut.items:
        history = histories_by_sample[item.sample_id]
        run_cut = run_cuts[item.source_run_id]
        if (
            history.source_inventory_cut_authority_id != cut.source_inventory_cut_authority_id
            or history.source_item != item
            or history.run_cut != run_cut
            or history.m5_authority_root_sha256 != run_cut.m5_authority_root_sha256
        ):
            _fail(M6RegressionSelectionErrorCode.APPEAL_HISTORY_INVALID)
        baseline = _validate_projection(
            projections_by_sample[item.sample_id],
            item,
            history,
        )
        challenge = challenges_by_sample.get(item.sample_id)
        if challenge is not None and (
            challenge.source_item_id != item.source_item_id or challenge.sample_id != item.sample_id
        ):
            _fail(M6RegressionSelectionErrorCode.CHALLENGE_AUTHORITY_INVALID)
        gold = None
        if history.state == M6RegressionAppealState.TERMINAL:
            try:
                gold = build_m6_appeal_gold_truth_authority(
                    appeal_history=history,
                    baseline_snapshot=baseline,
                ).authority
            except M6AppealGoldTruthError as exc:
                raise M6RegressionSelectionError(
                    M6RegressionSelectionErrorCode.GOLD_AUTHORITY_INVALID
                ) from exc
        try:
            receipt = M6RegressionSelectionReceipt(
                source_inventory_cut_authority_id=(cut.source_inventory_cut_authority_id),
                eligibility_policy_authority_id=(policy.eligibility_policy_authority_id),
                source_item=item,
                baseline_snapshot=baseline,
                source_m5_authority_root_sha256=history.m5_authority_root_sha256,
                current_case_authority_root_sha256=(history.current_case_root_sha256),
                current_case_revision=history.current_case_revision,
                current_case_document_sha256=history.current_case_document_sha256,
                current_case_status=history.current_case_status,
                current_appeal_authority=history.current_appeal_authority,
                appeal_gold_authority=gold,
                challenge_designation=challenge,
            )
        except (TypeError, ValueError, ValidationError):
            _fail(M6RegressionSelectionErrorCode.SELECTION_INVARIANT_VIOLATION)
        receipts.append(receipt)
    source_cut_document = str(source_inventory_cut_document)
    try:
        inventory = M6RegressionSelectionInventoryAuthority(
            baseline_manifest_id=cut.baseline_manifest_id,
            source_inventory_cut_authority_id=cut.source_inventory_cut_authority_id,
            source_inventory_cut_content_sha256=_content_sha256(source_cut_document),
            source_inventory_item_count=cut.source_item_count,
            source_inventory_root_sha256=cut.source_inventory_root_sha256,
            eligibility_policy=policy,
            receipts=tuple(receipts),
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6RegressionSelectionErrorCode.SELECTION_INVARIANT_VIOLATION)
    policy_document = _document(policy)
    inventory_document = _document(inventory)
    return M6RegressionSelectionBundle(
        eligibility_policy=policy,
        selection_inventory=inventory,
        eligibility_policy_document=policy_document,
        eligibility_policy_content_sha256=_content_sha256(policy_document),
        selection_inventory_document=inventory_document,
        selection_inventory_content_sha256=_content_sha256(inventory_document),
    )


__all__ = [
    "M6RegressionSelectionBundle",
    "M6RegressionSelectionError",
    "M6RegressionSelectionErrorCode",
    "build_m6_regression_selection_inventory",
]
