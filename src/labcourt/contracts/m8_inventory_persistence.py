"""M8 campus inventory snapshot persistence receipts."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_operations import (
    M8CampusTopologyAuthorityV1,
    M8OperationalSourceCatalogAuthorityV1,
)


def _pop_computed_claims(
    value: object,
    names: tuple[str, ...],
) -> tuple[object, dict[str, tuple[bool, object]]]:
    if not isinstance(value, dict):
        return value, {}
    payload = dict(value)
    claims = {name: (name in payload, payload.pop(name, None)) for name in names}
    return payload, claims


def _verify_computed_claims(
    instance: FrozenContractModel,
    claims: dict[str, tuple[bool, object]],
) -> None:
    serialized = instance.model_dump(mode="json")
    for name, (present, claimed) in claims.items():
        if present and canonical_json(claimed) != canonical_json(serialized[name]):
            raise ValueError(f"serialized {name} conflicts with derived M8 inventory receipt")


def _validate_prior_shape(
    revision: int,
    prior_authority_id: str | None,
    prior_document_sha256: str | None,
    authority_name: str,
) -> None:
    if revision == 1:
        if prior_authority_id is not None or prior_document_sha256 is not None:
            raise ValueError(f"M8 first {authority_name} revision cannot declare a prior snapshot")
    elif prior_authority_id is None or prior_document_sha256 is None:
        raise ValueError(f"M8 later {authority_name} revision requires a complete prior snapshot")
    if (prior_authority_id is None) != (prior_document_sha256 is None):
        raise ValueError(f"M8 {authority_name} prior fields must be present together")


class M8CampusTopologyCommitReceiptV1(FrozenContractModel):
    """Append receipt for one complete campus topology snapshot."""

    schema_version: Literal["m8-campus-topology-commit-receipt-v1"] = (
        "m8-campus-topology-commit-receipt-v1"
    )
    topology: M8CampusTopologyAuthorityV1
    prior_topology_id: Sha256Hex | None = None
    prior_document_sha256: Sha256Hex | None = None
    repository_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            ("topology_document_sha256", "commit_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_prior_snapshot(self) -> Self:
        _validate_prior_shape(
            self.topology.revision,
            self.prior_topology_id,
            self.prior_document_sha256,
            "topology",
        )
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def topology_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.topology.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-campus-topology-commit-receipt",
                1,
                self.topology.topology_id,
                self.topology_document_sha256,
                self.prior_topology_id,
                self.prior_document_sha256,
                self.repository_manifest_id,
            ]
        )


class M8OperationalSourceCatalogCommitReceiptV1(FrozenContractModel):
    """Append receipt for a source catalog resolved against persisted topology."""

    schema_version: Literal["m8-operational-source-catalog-commit-receipt-v1"] = (
        "m8-operational-source-catalog-commit-receipt-v1"
    )
    catalog: M8OperationalSourceCatalogAuthorityV1
    resolved_topology_commit_receipt_id: Sha256Hex
    prior_catalog_id: Sha256Hex | None = None
    prior_document_sha256: Sha256Hex | None = None
    repository_manifest_id: Sha256Hex

    @model_validator(mode="wrap")
    @classmethod
    def validate_serialized_claims(
        cls,
        value: object,
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        payload, claims = _pop_computed_claims(
            value,
            (
                "resolved_topology_document_sha256",
                "catalog_document_sha256",
                "commit_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_prior_snapshot(self) -> Self:
        _validate_prior_shape(
            self.catalog.revision,
            self.prior_catalog_id,
            self.prior_document_sha256,
            "source catalog",
        )
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resolved_topology_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.catalog.topology.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def catalog_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.catalog.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-operational-source-catalog-commit-receipt",
                1,
                self.catalog.catalog_id,
                self.catalog_document_sha256,
                self.catalog.topology.topology_id,
                self.resolved_topology_document_sha256,
                self.resolved_topology_commit_receipt_id,
                self.prior_catalog_id,
                self.prior_document_sha256,
                self.repository_manifest_id,
            ]
        )


__all__ = [
    "M8CampusTopologyCommitReceiptV1",
    "M8OperationalSourceCatalogCommitReceiptV1",
]
