"""Persistence boundary for append-only M5 appeal authorities and effects."""

from typing import Protocol

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m5_appeals import (
    AppealResolutionPrecedentSnapshot,
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
)


class AppealRepository(Protocol):
    def load_closed_case_authority(
        self,
        run_id: str,
        case_id: str,
    ) -> ClosedCaseAppealAuthority: ...

    def load_current_appeal(
        self,
        run_id: str,
        case_id: str,
    ) -> AppealVersionAuthority | None: ...

    def load_appeal_by_id(
        self,
        run_id: str,
        appeal_id: str,
    ) -> AppealVersionAuthority | None: ...

    def load_resolution(
        self,
        run_id: str,
        appeal_id: str,
    ) -> AppealResolutionSideEffectIntent | None: ...

    def load_resolution_precedent_snapshot(
        self,
        run_id: str,
        case_id: str,
    ) -> AppealResolutionPrecedentSnapshot: ...

    def append_appeal_version(
        self,
        authority: AppealVersionAuthority,
        expected_previous_authority_sha256: Sha256Hex | None,
    ) -> AppealVersionAuthority: ...

    def commit_resolution(
        self,
        intent: AppealResolutionSideEffectIntent,
    ) -> AppealResolutionSideEffectIntent: ...


__all__ = ["AppealRepository"]
