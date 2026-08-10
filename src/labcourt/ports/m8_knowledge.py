"""Port for deterministic knowledge query replay and exact raw content access."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m8_knowledge import (
    M8KnowledgeAnswerV1,
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeQueryV1,
)
from labcourt.exceptions import ContractViolation


class M8KnowledgeRetrieverFailureCode(StrEnum):
    CATALOG_MISMATCH = "CATALOG_MISMATCH"
    CONTENT_ENCODING_INVALID = "CONTENT_ENCODING_INVALID"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    CONTENT_INVENTORY_MISMATCH = "CONTENT_INVENTORY_MISMATCH"
    CONTENT_NOT_FOUND = "CONTENT_NOT_FOUND"
    QUERY_REPLAY_NOT_FOUND = "QUERY_REPLAY_NOT_FOUND"


class M8KnowledgeRetrieverError(ContractViolation):
    """Typed, sanitized failure from the offline knowledge boundary."""

    def __init__(self, reason_code: M8KnowledgeRetrieverFailureCode) -> None:
        if not isinstance(reason_code, M8KnowledgeRetrieverFailureCode):
            raise TypeError("reason_code must be an M8KnowledgeRetrieverFailureCode")
        self.reason_code = reason_code
        super().__init__(f"M8 knowledge retriever failed: {reason_code.value}")


class M8KnowledgeRetriever(Protocol):
    def catalog_authority(self) -> M8KnowledgeCatalogAuthorityV1: ...

    def query(self, request: M8KnowledgeQueryV1) -> M8KnowledgeAnswerV1: ...

    def replay(self, query_id: str) -> M8KnowledgeAnswerV1: ...

    def read_content(self, content_ref: str) -> bytes: ...


__all__ = [
    "M8KnowledgeRetriever",
    "M8KnowledgeRetrieverError",
    "M8KnowledgeRetrieverFailureCode",
]
