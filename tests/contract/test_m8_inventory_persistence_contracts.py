from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_operations import (
    M8CampusLocation,
    M8CampusLocationKind,
    M8CampusTopologyAuthorityV1,
    M8OperationalSource,
    M8OperationalSourceCatalogAuthorityV1,
    M8OperationalSourceMode,
    M8SensorType,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _topology(revision: int = 1) -> M8CampusTopologyAuthorityV1:
    return M8CampusTopologyAuthorityV1(
        revision=revision,
        locations=(
            M8CampusLocation(
                location_id="campus-main",
                kind=M8CampusLocationKind.CAMPUS,
                parent_location_id=None,
                display_name="主校区",
            ),
            M8CampusLocation(
                location_id="building-chem",
                kind=M8CampusLocationKind.BUILDING,
                parent_location_id="campus-main",
                display_name="化学楼",
            ),
            M8CampusLocation(
                location_id="floor-chem-03",
                kind=M8CampusLocationKind.FLOOR,
                parent_location_id="building-chem",
                display_name="三层",
            ),
            M8CampusLocation(
                location_id="room-chem-301",
                kind=M8CampusLocationKind.ROOM,
                parent_location_id="floor-chem-03",
                display_name="实验室 301",
            ),
        ),
        manifest_id=SHA_A,
    )


def _topology_receipt(revision: int = 1) -> M8CampusTopologyCommitReceiptV1:
    topology = _topology(revision)
    if revision == 1:
        return M8CampusTopologyCommitReceiptV1(
            topology=topology,
            repository_manifest_id=SHA_B,
        )
    prior = _topology_receipt(revision - 1)
    return M8CampusTopologyCommitReceiptV1(
        topology=topology,
        prior_topology_id=prior.topology.topology_id,
        prior_document_sha256=prior.topology_document_sha256,
        repository_manifest_id=SHA_B,
    )


def _catalog(revision: int = 1) -> M8OperationalSourceCatalogAuthorityV1:
    topology = _topology()
    return M8OperationalSourceCatalogAuthorityV1(
        revision=revision,
        topology=topology,
        sources=(
            M8OperationalSource(
                source_id="sensor-simulated-smoke-01",
                device_id="sensor-smoke-01",
                location_id="room-chem-301",
                mode=M8OperationalSourceMode.SIMULATED_SENSOR,
                sensor_type=M8SensorType.SMOKE,
                adapter_id="m8-offline-sensor-simulator",
                manifest_id=SHA_C,
            ),
        ),
        catalog_manifest_id=SHA_D,
    )


def test_topology_receipt_requires_contiguous_prior_shape_and_hashes_document() -> None:
    first = _topology_receipt()
    second = _topology_receipt(2)

    assert second.prior_topology_id == first.topology.topology_id
    assert second.prior_document_sha256 == first.topology_document_sha256
    assert len(second.topology_document_sha256) == 64
    assert len(second.commit_receipt_id) == 64

    with pytest.raises(ValidationError, match="complete prior snapshot"):
        M8CampusTopologyCommitReceiptV1(
            topology=_topology(2),
            repository_manifest_id=SHA_B,
        )


def test_catalog_receipt_binds_resolved_topology_and_prior_catalog() -> None:
    topology_receipt = _topology_receipt()
    first = M8OperationalSourceCatalogCommitReceiptV1(
        catalog=_catalog(),
        resolved_topology_commit_receipt_id=topology_receipt.commit_receipt_id,
        repository_manifest_id=SHA_B,
    )
    second = M8OperationalSourceCatalogCommitReceiptV1(
        catalog=_catalog(2),
        resolved_topology_commit_receipt_id=topology_receipt.commit_receipt_id,
        prior_catalog_id=first.catalog.catalog_id,
        prior_document_sha256=first.catalog_document_sha256,
        repository_manifest_id=SHA_B,
    )

    assert first.resolved_topology_document_sha256 == topology_receipt.topology_document_sha256
    assert second.prior_catalog_id == first.catalog.catalog_id
    assert len(second.commit_receipt_id) == 64


@pytest.mark.parametrize(
    "field",
    (
        "resolved_topology_document_sha256",
        "catalog_document_sha256",
        "commit_receipt_id",
    ),
)
def test_inventory_receipt_rejects_serialized_computed_forgery(field: str) -> None:
    receipt = M8OperationalSourceCatalogCommitReceiptV1(
        catalog=_catalog(),
        resolved_topology_commit_receipt_id=_topology_receipt().commit_receipt_id,
        repository_manifest_id=SHA_B,
    )
    payload = receipt.model_dump(mode="json")
    payload[field] = "0" * 64
    with pytest.raises(ValidationError, match=field):
        M8OperationalSourceCatalogCommitReceiptV1.model_validate(payload)


def test_inventory_receipts_validate_as_serialization_schemas() -> None:
    topology = _topology_receipt()
    catalog = M8OperationalSourceCatalogCommitReceiptV1(
        catalog=_catalog(),
        resolved_topology_commit_receipt_id=topology.commit_receipt_id,
        repository_manifest_id=SHA_B,
    )
    Draft202012Validator(
        M8CampusTopologyCommitReceiptV1.model_json_schema(mode="serialization")
    ).validate(topology.model_dump(mode="json"))
    Draft202012Validator(
        M8OperationalSourceCatalogCommitReceiptV1.model_json_schema(mode="serialization")
    ).validate(catalog.model_dump(mode="json"))


def test_inventory_receipt_schemas_are_registered_serialization_roots() -> None:
    from labcourt.schema_registry import SCHEMA_MODELS, SCHEMA_VALIDATION_MODELS

    expected = {
        "m8-campus-topology-commit-receipt-v1": M8CampusTopologyCommitReceiptV1,
        "m8-operational-source-catalog-commit-receipt-v1": (
            M8OperationalSourceCatalogCommitReceiptV1
        ),
    }
    assert {name: SCHEMA_MODELS[name] for name in expected} == expected
    assert expected.keys().isdisjoint(SCHEMA_VALIDATION_MODELS)
