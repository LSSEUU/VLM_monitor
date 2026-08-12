"""M8 append-only knowledge catalog, raw content, and answer commit receipts."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, ModelWrapValidatorHandler, computed_field, model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_knowledge import (
    MAX_M8_KNOWLEDGE_DOCUMENTS,
    M8KnowledgeAnswerV1,
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeDocumentAuthorityV1,
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
            raise ValueError(
                f"serialized {name} conflicts with derived M8 knowledge persistence authority"
            )


class M8KnowledgeDocumentCommitReceiptV1(FrozenContractModel):
    """Receipt for exact persisted raw bytes of one document authority."""

    schema_version: Literal["m8-knowledge-document-commit-receipt-v1"] = (
        "m8-knowledge-document-commit-receipt-v1"
    )
    document: M8KnowledgeDocumentAuthorityV1
    raw_storage_manifest_id: Sha256Hex
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
            ("document_metadata_sha256", "commit_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def document_metadata_sha256(self) -> Sha256Hex:
        return sha256_hex(self.document.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-document-commit-receipt",
                1,
                self.document.document_authority_id,
                self.document_metadata_sha256,
                self.document.content_ref,
                self.document.content_sha256,
                self.document.content_size_bytes,
                self.raw_storage_manifest_id,
                self.repository_manifest_id,
            ]
        )


class M8KnowledgeCatalogCommitReceiptV1(FrozenContractModel):
    """Atomic append receipt for one catalog revision and all exact document bytes."""

    schema_version: Literal["m8-knowledge-catalog-commit-receipt-v1"] = (
        "m8-knowledge-catalog-commit-receipt-v1"
    )
    catalog: M8KnowledgeCatalogAuthorityV1
    document_receipts: tuple[M8KnowledgeDocumentCommitReceiptV1, ...] = Field(
        min_length=1,
        max_length=MAX_M8_KNOWLEDGE_DOCUMENTS,
    )
    prior_catalog_authority_id: Sha256Hex | None = None
    prior_catalog_document_sha256: Sha256Hex | None = None
    raw_storage_manifest_id: Sha256Hex
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
                "catalog_document_sha256",
                "content_inventory_sha256",
                "total_content_size_bytes",
                "commit_receipt_id",
            ),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.catalog.catalog_revision == 1:
            if (
                self.prior_catalog_authority_id is not None
                or self.prior_catalog_document_sha256 is not None
            ):
                raise ValueError("M8 first knowledge catalog cannot declare a prior revision")
        elif self.prior_catalog_authority_id is None or self.prior_catalog_document_sha256 is None:
            raise ValueError("M8 later knowledge catalog requires a prior revision")
        expected = tuple(document.document_authority_id for document in self.catalog.documents)
        observed = tuple(
            receipt.document.document_authority_id for receipt in self.document_receipts
        )
        if observed != expected:
            raise ValueError("M8 knowledge document receipts do not bind the catalog inventory")
        if any(
            receipt.raw_storage_manifest_id != self.raw_storage_manifest_id
            or receipt.repository_manifest_id != self.repository_manifest_id
            for receipt in self.document_receipts
        ):
            raise ValueError("M8 knowledge document receipt manifests conflict with catalog")
        return self

    @computed_field  # type: ignore[prop-decorator]
    @property
    def catalog_document_sha256(self) -> Sha256Hex:
        return sha256_hex(self.catalog.model_dump(mode="json"))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def content_inventory_sha256(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-content-inventory",
                1,
                [receipt.commit_receipt_id for receipt in self.document_receipts],
            ]
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def total_content_size_bytes(self) -> int:
        return sum(receipt.document.content_size_bytes for receipt in self.document_receipts)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-catalog-commit-receipt",
                1,
                self.catalog.catalog_authority_id,
                self.catalog_document_sha256,
                self.content_inventory_sha256,
                self.total_content_size_bytes,
                self.prior_catalog_authority_id,
                self.prior_catalog_document_sha256,
                self.raw_storage_manifest_id,
                self.repository_manifest_id,
            ]
        )


class M8KnowledgeAnswerCommitReceiptV1(FrozenContractModel):
    """Receipt binding a deterministic answer to the repository-resolved requester."""

    schema_version: Literal["m8-knowledge-answer-commit-receipt-v1"] = (
        "m8-knowledge-answer-commit-receipt-v1"
    )
    answer: M8KnowledgeAnswerV1
    resolved_actor_document_sha256: Sha256Hex
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
            ("query_id", "answer_id", "commit_receipt_id"),
        )
        receipt = handler(payload)
        _verify_computed_claims(receipt, claims)
        return receipt

    @computed_field  # type: ignore[prop-decorator]
    @property
    def query_id(self) -> Sha256Hex:
        return self.answer.query.query_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def answer_id(self) -> Sha256Hex:
        return self.answer.answer_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def commit_receipt_id(self) -> Sha256Hex:
        return sha256_hex(
            [
                "m8-knowledge-answer-commit-receipt",
                1,
                self.query_id,
                self.answer_id,
                self.answer.query.requester_actor_id,
                self.answer.query.requester_actor_authority_id,
                self.resolved_actor_document_sha256,
                self.repository_manifest_id,
            ]
        )


__all__ = [
    "M8KnowledgeAnswerCommitReceiptV1",
    "M8KnowledgeCatalogCommitReceiptV1",
    "M8KnowledgeDocumentCommitReceiptV1",
]
