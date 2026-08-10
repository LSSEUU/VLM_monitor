"""Persistence port for append-only M8 knowledge catalogs, bytes, and answers."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_knowledge import M8KnowledgeAnswerV1, M8KnowledgeCatalogAuthorityV1
from labcourt.contracts.m8_knowledge_persistence import (
    M8KnowledgeAnswerCommitReceiptV1,
    M8KnowledgeCatalogCommitReceiptV1,
)


class M8KnowledgeRepository(Protocol):
    def publish_catalog(
        self,
        catalog: M8KnowledgeCatalogAuthorityV1,
        raw_contents: tuple[bytes, ...],
        expected_prior_revision: int | None,
        raw_storage_manifest_id: str,
    ) -> M8KnowledgeCatalogCommitReceiptV1: ...

    def get_current_catalog(
        self,
        catalog_id: str,
    ) -> M8KnowledgeCatalogCommitReceiptV1: ...

    def read_content(self, content_ref: str) -> bytes: ...

    def commit_answer(
        self,
        answer: M8KnowledgeAnswerV1,
    ) -> M8KnowledgeAnswerCommitReceiptV1: ...

    def get_answer(
        self,
        query_id: str,
    ) -> M8KnowledgeAnswerCommitReceiptV1: ...


__all__ = ["M8KnowledgeRepository"]
