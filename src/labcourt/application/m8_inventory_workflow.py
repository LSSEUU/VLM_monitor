"""Pure builders for M8 campus inventory snapshot commits."""

from __future__ import annotations

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_operations import (
    M8CampusTopologyAuthorityV1,
    M8OperationalSourceCatalogAuthorityV1,
)


def build_topology_commit(
    topology: M8CampusTopologyAuthorityV1,
    prior: M8CampusTopologyCommitReceiptV1 | None,
    repository_manifest_id: Sha256Hex,
) -> M8CampusTopologyCommitReceiptV1:
    if prior is None:
        if topology.revision != 1:
            raise ValueError("first persisted M8 topology must use revision 1")
        return M8CampusTopologyCommitReceiptV1(
            topology=topology,
            repository_manifest_id=repository_manifest_id,
        )
    if prior.topology.campus_id != topology.campus_id:
        raise ValueError("M8 topology successor belongs to another campus")
    if topology.revision != prior.topology.revision + 1:
        raise ValueError("M8 topology successor revision must be contiguous")
    return M8CampusTopologyCommitReceiptV1(
        topology=topology,
        prior_topology_id=prior.topology.topology_id,
        prior_document_sha256=prior.topology_document_sha256,
        repository_manifest_id=repository_manifest_id,
    )


def build_source_catalog_commit(
    catalog: M8OperationalSourceCatalogAuthorityV1,
    resolved_topology: M8CampusTopologyCommitReceiptV1,
    prior: M8OperationalSourceCatalogCommitReceiptV1 | None,
    repository_manifest_id: Sha256Hex,
) -> M8OperationalSourceCatalogCommitReceiptV1:
    if catalog.topology != resolved_topology.topology:
        raise ValueError("M8 source catalog does not use the current persisted topology")
    if prior is None:
        if catalog.revision != 1:
            raise ValueError("first persisted M8 source catalog must use revision 1")
        return M8OperationalSourceCatalogCommitReceiptV1(
            catalog=catalog,
            resolved_topology_commit_receipt_id=resolved_topology.commit_receipt_id,
            repository_manifest_id=repository_manifest_id,
        )
    if prior.catalog.topology.campus_id != catalog.topology.campus_id:
        raise ValueError("M8 source catalog successor belongs to another campus")
    if catalog.revision != prior.catalog.revision + 1:
        raise ValueError("M8 source catalog successor revision must be contiguous")
    return M8OperationalSourceCatalogCommitReceiptV1(
        catalog=catalog,
        resolved_topology_commit_receipt_id=resolved_topology.commit_receipt_id,
        prior_catalog_id=prior.catalog.catalog_id,
        prior_document_sha256=prior.catalog_document_sha256,
        repository_manifest_id=repository_manifest_id,
    )


__all__ = ["build_source_catalog_commit", "build_topology_commit"]
