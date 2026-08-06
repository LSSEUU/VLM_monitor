"""Public facade for guarded transactional M5 SQLite persistence."""

from __future__ import annotations

from typing import overload

from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.contracts.screening import (
    CachedModelResponse,
    VLMCallRequest,
)

from .sqlite_m5_repository_alerts import SQLiteM5AlertRepository
from .sqlite_m5_repository_appeals import SQLiteM5AppealRepository
from .sqlite_m5_repository_foundation import SQLiteM5RepositoryFoundation
from .sqlite_m5_repository_precedents import SQLiteM5PrecedentRepository
from .sqlite_m5_repository_usage import SQLiteM5PrecedentUsageRepository


class SQLiteM5Repository(
    SQLiteM5RepositoryFoundation,
    SQLiteM5PrecedentRepository,
    SQLiteM5PrecedentUsageRepository,
    SQLiteM5AlertRepository,
    SQLiteM5AppealRepository,
):
    """One guarded database authority composed from focused M5 mixins.

    M3's request-cache port and M5's precedent port both froze a method named
    ``get``.  The facade preserves both contracts with strict argument dispatch;
    strings are precedent IDs and validated request models remain M3 cache keys.
    """

    @overload
    def get(
        self,
        run_id: str,
        request_or_precedent_id: str,
    ) -> M5PrecedentAuthority | None: ...

    @overload
    def get(
        self,
        run_id: str,
        request_or_precedent_id: VLMCallRequest,
    ) -> CachedModelResponse | None: ...

    def get(
        self,
        run_id: str,
        request_or_precedent_id: str | VLMCallRequest,
    ) -> M5PrecedentAuthority | CachedModelResponse | None:
        if isinstance(request_or_precedent_id, str):
            return SQLiteM5PrecedentRepository.get(
                self,
                run_id,
                request_or_precedent_id,
            )
        return super().get(run_id, request_or_precedent_id)

    def get_precedent(
        self,
        run_id: str,
        precedent_id: str,
    ) -> M5PrecedentAuthority | None:
        """Unambiguous convenience name for orchestration and CLI wiring."""

        return SQLiteM5PrecedentRepository.get(self, run_id, precedent_id)


__all__ = ["SQLiteM5Repository"]
