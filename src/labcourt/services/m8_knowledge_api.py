"""Authenticated, offline-only knowledge orchestration for the M8 loopback API."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from labcourt.adapters.m8_offline_knowledge import DeterministicOfflineKnowledgeRetriever
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8ActorAuthorityV1
from labcourt.contracts.m8_api import M8ApiKnowledgeQueryRequestV1, M8ApiPrincipalV1
from labcourt.contracts.m8_knowledge import M8KnowledgeQueryV1
from labcourt.contracts.m8_knowledge_persistence import (
    M8KnowledgeAnswerCommitReceiptV1,
    M8KnowledgeCatalogCommitReceiptV1,
)
from labcourt.exceptions import ConcurrentModification, EvidenceMissing
from labcourt.ports.m8_knowledge import M8KnowledgeRetrieverError
from labcourt.ports.m8_knowledge_repository import M8KnowledgeRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.services.m8_operations_api import M8ApiServiceError, M8ApiServiceFailureCode

_T = TypeVar("_T")


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 {name} must be lowercase SHA-256 hex")
    return value


class M8KnowledgeApiService:
    """Resolve all authorities server-side and persist deterministic extractive answers."""

    def __init__(
        self,
        knowledge_repository: M8KnowledgeRepository,
        operations_repository: M8OperationsRepository,
        query_manifest_id: Sha256Hex,
        adapter_manifest_id: Sha256Hex,
    ) -> None:
        self._knowledge = knowledge_repository
        self._operations = operations_repository
        self._query_manifest_id = _validate_sha256(query_manifest_id, "knowledge query manifest")
        self._adapter_manifest_id = _validate_sha256(
            adapter_manifest_id,
            "knowledge adapter manifest",
        )

    def current_catalog(
        self,
        principal: M8ApiPrincipalV1,
        catalog_id: str,
    ) -> M8KnowledgeCatalogCommitReceiptV1:
        self._actor(principal)
        return self._call(lambda: self._knowledge.get_current_catalog(catalog_id))

    def query(
        self,
        principal: M8ApiPrincipalV1,
        catalog_id: str,
        request: M8ApiKnowledgeQueryRequestV1,
    ) -> M8KnowledgeAnswerCommitReceiptV1:
        if not isinstance(request, M8ApiKnowledgeQueryRequestV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.INVALID_REQUEST)
        actor = self._actor(principal)
        catalog_receipt = self._call(lambda: self._knowledge.get_current_catalog(catalog_id))
        catalog = catalog_receipt.catalog
        contents: dict[str, bytes] = {}
        for document in catalog.documents:
            contents[document.content_ref] = self._content(document.content_ref)
        query = M8KnowledgeQueryV1(
            catalog_authority_id=catalog.catalog_authority_id,
            requester_actor_id=actor.actor_id,
            requester_actor_authority_id=actor.actor_authority_id,
            query_text=request.query_text,
            locale=request.locale,
            as_of=request.as_of,
            allowed_document_types=request.allowed_document_types,
            max_citations=request.max_citations,
            query_manifest_id=self._query_manifest_id,
        )
        try:
            answer = DeterministicOfflineKnowledgeRetriever(
                catalog,
                contents,
                self._adapter_manifest_id,
            ).query(query)
        except M8KnowledgeRetrieverError as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.INTERNAL_FAILURE) from error
        return self._call(lambda: self._knowledge.commit_answer(answer))

    def answer(
        self,
        principal: M8ApiPrincipalV1,
        query_id: str,
    ) -> M8KnowledgeAnswerCommitReceiptV1:
        actor = self._actor(principal)
        receipt = self._call(lambda: self._knowledge.get_answer(query_id))
        if receipt.answer.query.requester_actor_id != actor.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return receipt

    def _actor(self, principal: M8ApiPrincipalV1) -> M8ActorAuthorityV1:
        if not isinstance(principal, M8ApiPrincipalV1):
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        receipt = self._call(
            lambda: self._operations.get_current_actor_authority(principal.actor_id)
        )
        actor = receipt.authority
        if not actor.active or actor.actor_id != principal.actor_id:
            raise M8ApiServiceError(M8ApiServiceFailureCode.FORBIDDEN)
        return actor

    def _content(self, content_ref: str) -> bytes:
        return self._call(lambda: self._knowledge.read_content(content_ref))

    @staticmethod
    def _call(function: Callable[[], _T]) -> _T:
        try:
            return function()
        except EvidenceMissing as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.RESOURCE_NOT_FOUND) from error
        except ConcurrentModification as error:
            raise M8ApiServiceError(M8ApiServiceFailureCode.CONCURRENT_MODIFICATION) from error


__all__ = ["M8KnowledgeApiService"]
