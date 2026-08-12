"""Persistence port for M8 campus topology and source snapshots."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_operations import (
    M8CampusTopologyAuthorityV1,
    M8OperationalSourceCatalogAuthorityV1,
)


class M8InventoryRepository(Protocol):
    def publish_topology(
        self,
        topology: M8CampusTopologyAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8CampusTopologyCommitReceiptV1: ...

    def get_current_topology(self, campus_id: str) -> M8CampusTopologyCommitReceiptV1: ...

    def publish_source_catalog(
        self,
        catalog: M8OperationalSourceCatalogAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8OperationalSourceCatalogCommitReceiptV1: ...

    def get_current_source_catalog(
        self,
        campus_id: str,
    ) -> M8OperationalSourceCatalogCommitReceiptV1: ...

    def get_source_catalog(
        self,
        catalog_id: str,
    ) -> M8OperationalSourceCatalogCommitReceiptV1: ...


__all__ = ["M8InventoryRepository"]
