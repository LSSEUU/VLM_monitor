"""Persistence port for the additive M8 pre-hearing evidence gate."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_prehearing import M8PreHearingPreparationV1


class M8PreHearingRepository(Protocol):
    def put(
        self,
        preparation: M8PreHearingPreparationV1,
        expected_prior_revision: int | None,
    ) -> M8PreHearingPreparationV1: ...

    def get(self, preparation_id: str) -> M8PreHearingPreparationV1: ...

    def load_for_case(
        self,
        run_id: str,
        case_id: str,
    ) -> M8PreHearingPreparationV1 | None: ...


__all__ = ["M8PreHearingRepository"]
