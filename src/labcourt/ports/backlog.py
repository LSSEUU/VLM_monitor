"""Durable retry queue port."""

from datetime import datetime
from typing import Protocol

from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.enums import BacklogStage


class BacklogStore(Protocol):
    def enqueue(self, run_id: str, item: BacklogItem) -> BacklogItem: ...

    def lease_next(
        self,
        run_id: str,
        stage: BacklogStage,
        lease_owner_sha256: str,
        lease_expires_at: datetime,
    ) -> BacklogItem | None: ...

    def complete(
        self,
        run_id: str,
        item_id: str,
        expected_lease_id: str,
    ) -> BacklogItem: ...

    def release(
        self,
        run_id: str,
        item_id: str,
        expected_lease_id: str,
    ) -> BacklogItem: ...

    def reclaim_expired(
        self,
        run_id: str,
        not_after: datetime,
        limit: int,
    ) -> tuple[BacklogItem, ...]: ...


__all__ = ["BacklogStore"]
