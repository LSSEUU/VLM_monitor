"""Deterministic objective-evidence gate before a frozen M4 hearing starts."""

from __future__ import annotations

from dataclasses import dataclass

from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    AuditAction,
    CaseStatus,
    EvidenceClass,
    EvidenceFailureCode,
    ScreeningDecision,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m8_prehearing import (
    M8PreHearingPreparationState,
    M8PreHearingPreparationV1,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.evidence_repository import CaseSnapshot, EvidenceRepository
from labcourt.ports.m8_hearing_api import M8HearingSessionLocator
from labcourt.ports.m8_prehearing import M8PreHearingRepository

PREHEARING_SELECTION_POLICY_VERSION = "prehearing-top-m-observability-v1"


def latest_evidence_pack_authority(
    case: Case,
    *,
    historical_pack_id: str | None = None,
) -> EvidencePack:
    """Resolve current P2+ authority while verifying an older P1 binding.

    M8 scenario metadata may retain the initially published pack ID.  That ID
    is an audit anchor, not permission to ignore a successor.  Callers should
    use this helper after loading the current M4 ``Case`` and then rerun L3 if
    the latest pack is newer than the latest screening authority.
    """

    if not isinstance(case, Case):
        raise TypeError("latest evidence authority requires a typed Case")
    if not case.evidence_packs:
        raise ContractViolation("Case has no published evidence authority")
    if historical_pack_id is not None and all(
        pack.pack_id != historical_pack_id for pack in case.evidence_packs
    ):
        raise ContractViolation("historical evidence pack is outside the current Case")
    latest = case.evidence_packs[-1]
    if latest.version != len(case.evidence_packs):
        raise ContractViolation("Case evidence authority versions are not contiguous")
    return latest


def _is_expected_human_review(snapshot: CaseSnapshot, source_revision: int) -> bool:
    case = snapshot.case
    if (
        snapshot.revision != source_revision + 1
        or case.status != CaseStatus.HUMAN_REVIEW
        or not case.timeline
    ):
        return False
    entry = case.timeline[-1]
    return (
        entry.action == AuditAction.CASE_STATE_CHANGED.value
        and entry.stage == "EVIDENCE"
        and entry.object_ref == case.case_id
        and dict(entry.details) == {"failure_code": EvidenceFailureCode.EVIDENCE_MISSING.value}
    )


@dataclass(frozen=True, slots=True)
class M8PreHearingCoordinator:
    """Route objective insufficiency without importing an M4 model client."""

    evidence_repository: EvidenceRepository
    preparation_repository: M8PreHearingRepository
    session_locator: M8HearingSessionLocator

    def get(
        self,
        run_id: str,
        case_id: str,
    ) -> M8PreHearingPreparationV1 | None:
        """Load the restart-safe preparation currently projected by M8."""

        require_reference_token(run_id, "pre-hearing run_id")
        require_reference_token(case_id, "pre-hearing case_id")
        return self.preparation_repository.load_for_case(run_id, case_id)

    def route(
        self,
        run_id: str,
        case_id: str,
    ) -> M8PreHearingPreparationV1 | None:
        """Apply the first-ESCALATED gate or resume its exact persisted CAS.

        ``None`` means this slice does not apply: presence evidence, an
        existing session, a non-first escalation, or objectively sufficient
        evidence continues through the existing frozen M4 path unchanged.
        """

        require_reference_token(run_id, "pre-hearing run_id")
        require_reference_token(case_id, "pre-hearing case_id")
        existing = self.preparation_repository.load_for_case(run_id, case_id)
        snapshot = self.evidence_repository.load_case(run_id, case_id)
        if existing is not None:
            return self._resume(existing, snapshot)

        pending = self._prepare_if_applicable(snapshot)
        if pending is None:
            return None
        if self.session_locator.load_hearing_for_case(run_id, case_id) is not None:
            return None

        persisted = self.preparation_repository.put(pending, None)
        # A platform start boundary should serialize this coordinator before
        # M4 preparation.  Rechecking closes the ordinary race and fails
        # explicitly if another writer violated that ordering.
        if self.session_locator.load_hearing_for_case(run_id, case_id) is not None:
            raise ConcurrentModification(
                "M4 hearing session appeared during pre-hearing preparation"
            )
        return self._resume(persisted, snapshot)

    def _prepare_if_applicable(
        self,
        snapshot: CaseSnapshot,
    ) -> M8PreHearingPreparationV1 | None:
        case = snapshot.case
        if (
            case.status != CaseStatus.ESCALATED
            or len(case.screening_results) != 1
            or not case.evidence_packs
        ):
            return None
        screening = case.screening_results[-1]
        if (
            screening.decision != ScreeningDecision.ESCALATE
            or screening.authoritative_evidence_class != EvidenceClass.ABSENCE
        ):
            return None
        latest = latest_evidence_pack_authority(case)
        if (
            screening.evidence_pack_id != latest.pack_id
            or screening.evidence_pack_version != latest.version
        ):
            raise ContractViolation("first escalation does not bind the latest evidence authority")
        sufficiency = latest.observation_sufficiency_input
        if sufficiency is None:
            raise ContractViolation("absence escalation lacks observation authority")
        if not sufficiency.selected_by_observability:
            raise ContractViolation("pre-hearing top-M gate requires observability-ranked evidence")
        if len(sufficiency.clear_crop_ids) >= sufficiency.required_clear_count:
            return None
        candidate_ids = tuple(sorted(crop.crop_id for crop in latest.temporal_crops))
        if candidate_ids != screening.alleged_interval_crop_ids:
            raise ContractViolation("screening candidate crops do not match current top-M")
        return M8PreHearingPreparationV1(
            revision=1,
            run_id=case.run_id,
            case_id=case.case_id,
            source_case_revision=snapshot.revision,
            source_screening_id=screening.screening_id,
            source_screening_version=screening.version,
            source_evidence_pack_id=latest.pack_id,
            source_evidence_pack_version=latest.version,
            manifest_id=case.manifest_id,
            candidate_crop_ids=candidate_ids,
            clear_crop_ids=tuple(sorted(sufficiency.clear_crop_ids)),
            clear_threshold=sufficiency.clear_threshold,
            required_clear_count=sufficiency.required_clear_count,
            selection_policy_version=PREHEARING_SELECTION_POLICY_VERSION,
            state=M8PreHearingPreparationState.PENDING,
        )

    def _resume(
        self,
        preparation: M8PreHearingPreparationV1,
        snapshot: CaseSnapshot,
    ) -> M8PreHearingPreparationV1:
        if (
            preparation.run_id != snapshot.case.run_id
            or preparation.case_id != snapshot.case.case_id
        ):
            raise ContractViolation("pre-hearing preparation and Case scope differ")
        if preparation.state == M8PreHearingPreparationState.COMPLETED:
            if not _is_expected_human_review(snapshot, preparation.source_case_revision):
                raise ConcurrentModification(
                    "completed pre-hearing outcome no longer matches Case authority"
                )
            return preparation

        if snapshot.revision == preparation.source_case_revision:
            case = snapshot.case
            if (
                case.status != CaseStatus.ESCALATED
                or not case.screening_results
                or case.screening_results[-1].screening_id != preparation.source_screening_id
                or not case.evidence_packs
                or case.evidence_packs[-1].pack_id != preparation.source_evidence_pack_id
            ):
                raise ConcurrentModification("Case authority changed after pre-hearing preparation")
            snapshot = self.evidence_repository.record_evidence_failure(
                preparation.run_id,
                preparation.source_case_revision,
                preparation.case_id,
                EvidenceFailureCode.EVIDENCE_MISSING,
            )
        if not _is_expected_human_review(snapshot, preparation.source_case_revision):
            raise ConcurrentModification(
                "pending pre-hearing preparation cannot resume from current Case state"
            )
        completed = preparation.complete_no_novel_clear_frame(snapshot.revision)
        return self.preparation_repository.put(completed, 1)


__all__ = [
    "PREHEARING_SELECTION_POLICY_VERSION",
    "M8PreHearingCoordinator",
    "latest_evidence_pack_authority",
]
