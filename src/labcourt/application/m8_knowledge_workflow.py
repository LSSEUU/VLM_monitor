"""Pure construction of M8 knowledge catalog and answer commit receipts."""

from __future__ import annotations

import hashlib

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.contracts.m8_knowledge import M8KnowledgeAnswerV1, M8KnowledgeCatalogAuthorityV1
from labcourt.contracts.m8_knowledge_persistence import (
    M8KnowledgeAnswerCommitReceiptV1,
    M8KnowledgeCatalogCommitReceiptV1,
    M8KnowledgeDocumentCommitReceiptV1,
)


def build_knowledge_catalog_commit(
    catalog: M8KnowledgeCatalogAuthorityV1,
    raw_contents: tuple[bytes, ...],
    prior: M8KnowledgeCatalogCommitReceiptV1 | None,
    raw_storage_manifest_id: Sha256Hex,
    repository_manifest_id: Sha256Hex,
) -> M8KnowledgeCatalogCommitReceiptV1:
    if len(raw_contents) != len(catalog.documents):
        raise ValueError("M8 knowledge raw content inventory does not match the catalog")
    if prior is None:
        if catalog.catalog_revision != 1:
            raise ValueError("first persisted M8 knowledge catalog must use revision 1")
        prior_authority_id = None
        prior_document_sha256 = None
    else:
        if prior.catalog.catalog_id != catalog.catalog_id:
            raise ValueError("M8 knowledge catalog successor belongs to another catalog")
        if catalog.catalog_revision != prior.catalog.catalog_revision + 1:
            raise ValueError("M8 knowledge catalog successor revision must be contiguous")
        prior_authority_id = prior.catalog.catalog_authority_id
        prior_document_sha256 = prior.catalog_document_sha256
    receipts: list[M8KnowledgeDocumentCommitReceiptV1] = []
    for document, raw in zip(catalog.documents, raw_contents, strict=True):
        if not isinstance(raw, bytes):
            raise TypeError("M8 knowledge raw content must be exact bytes")
        if (
            len(raw) != document.content_size_bytes
            or hashlib.sha256(raw).hexdigest() != document.content_sha256
        ):
            raise ValueError("M8 knowledge raw content hash or size does not match its document")
        receipts.append(
            M8KnowledgeDocumentCommitReceiptV1(
                document=document,
                raw_storage_manifest_id=raw_storage_manifest_id,
                repository_manifest_id=repository_manifest_id,
            )
        )
    return M8KnowledgeCatalogCommitReceiptV1(
        catalog=catalog,
        document_receipts=tuple(receipts),
        prior_catalog_authority_id=prior_authority_id,
        prior_catalog_document_sha256=prior_document_sha256,
        raw_storage_manifest_id=raw_storage_manifest_id,
        repository_manifest_id=repository_manifest_id,
    )


def build_knowledge_answer_commit(
    answer: M8KnowledgeAnswerV1,
    resolved_actor: M8ActorAuthorityCommitReceiptV1,
    repository_manifest_id: Sha256Hex,
) -> M8KnowledgeAnswerCommitReceiptV1:
    actor = resolved_actor.authority
    query = answer.query
    if (
        not actor.active
        or actor.actor_id != query.requester_actor_id
        or actor.actor_authority_id != query.requester_actor_authority_id
    ):
        raise ValueError("M8 knowledge answer requester is not the current active actor")
    return M8KnowledgeAnswerCommitReceiptV1(
        answer=answer,
        resolved_actor_document_sha256=resolved_actor.authority_document_sha256,
        repository_manifest_id=repository_manifest_id,
    )


__all__ = ["build_knowledge_answer_commit", "build_knowledge_catalog_commit"]
