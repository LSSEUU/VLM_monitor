"""Deterministic offline lexical knowledge retriever with exact citations."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_knowledge import (
    M8KnowledgeAnswerV1,
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeCitationV1,
    M8KnowledgeQueryV1,
)
from labcourt.ports.m8_knowledge import (
    M8KnowledgeRetrieverError,
    M8KnowledgeRetrieverFailureCode,
)

_LEXICAL_TOKEN = re.compile(r"[a-z0-9]+|[\u3400-\u9fff]")
_MAX_CHUNK_CHARACTERS = 2000


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 {name} must be lowercase SHA-256 hex")
    return value


def _tokens(value: str) -> frozenset[str]:
    return frozenset(_LEXICAL_TOKEN.findall(value.casefold()))


@dataclass(frozen=True, slots=True)
class _KnowledgeChunk:
    chunk_index: int
    start_char: int
    end_char: int
    text: str


class DeterministicOfflineKnowledgeRetriever:
    """Query exact fixture bytes without network, embeddings, models, or wall clock."""

    def __init__(
        self,
        catalog: M8KnowledgeCatalogAuthorityV1,
        contents: Mapping[str, bytes],
        adapter_manifest_id: Sha256Hex,
    ) -> None:
        if not isinstance(catalog, M8KnowledgeCatalogAuthorityV1):
            raise TypeError("offline knowledge retriever requires a typed catalog")
        if not isinstance(contents, Mapping):
            raise TypeError("offline knowledge retriever contents must be a mapping")
        self._adapter_manifest_id = _validate_sha256(
            adapter_manifest_id,
            "knowledge adapter manifest",
        )
        expected_refs = {document.content_ref for document in catalog.documents}
        if set(contents) != expected_refs:
            raise M8KnowledgeRetrieverError(
                M8KnowledgeRetrieverFailureCode.CONTENT_INVENTORY_MISMATCH
            )
        controlled: dict[str, bytes] = {}
        decoded: dict[str, str] = {}
        for document in catalog.documents:
            raw = contents.get(document.content_ref)
            if not isinstance(raw, bytes):
                raise M8KnowledgeRetrieverError(
                    M8KnowledgeRetrieverFailureCode.CONTENT_INVENTORY_MISMATCH
                )
            if (
                len(raw) != document.content_size_bytes
                or hashlib.sha256(raw).hexdigest() != document.content_sha256
            ):
                raise M8KnowledgeRetrieverError(
                    M8KnowledgeRetrieverFailureCode.CONTENT_HASH_MISMATCH
                )
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as error:
                raise M8KnowledgeRetrieverError(
                    M8KnowledgeRetrieverFailureCode.CONTENT_ENCODING_INVALID
                ) from error
            if any(ord(character) < 32 and character not in "\r\n\t" for character in text):
                raise M8KnowledgeRetrieverError(
                    M8KnowledgeRetrieverFailureCode.CONTENT_ENCODING_INVALID
                )
            controlled[document.content_ref] = raw
            decoded[document.content_ref] = text
        self._catalog = catalog
        self._contents = controlled
        self._decoded = decoded
        self._answers: dict[str, M8KnowledgeAnswerV1] = {}
        self._generation_count = 0

    def catalog_authority(self) -> M8KnowledgeCatalogAuthorityV1:
        return self._catalog

    def query(self, request: M8KnowledgeQueryV1) -> M8KnowledgeAnswerV1:
        if not isinstance(request, M8KnowledgeQueryV1):
            raise TypeError("offline knowledge query requires M8KnowledgeQueryV1")
        cached = self._answers.get(request.query_id)
        if cached is not None:
            return cached
        if request.catalog_authority_id != self._catalog.catalog_authority_id:
            raise M8KnowledgeRetrieverError(M8KnowledgeRetrieverFailureCode.CATALOG_MISMATCH)
        query_tokens = _tokens(request.query_text)
        citations: list[M8KnowledgeCitationV1] = []
        for document in self._catalog.documents:
            if (
                document.locale != request.locale
                or document.document_type not in request.allowed_document_types
                or document.effective_at > request.as_of
                or (document.expires_at is not None and request.as_of >= document.expires_at)
            ):
                continue
            for chunk in self._chunks(self._decoded[document.content_ref]):
                match_count = len(query_tokens.intersection(_tokens(chunk.text)))
                if match_count == 0:
                    continue
                citations.append(
                    M8KnowledgeCitationV1(
                        document=document,
                        chunk_index=chunk.chunk_index,
                        snippet_start_char=chunk.start_char,
                        snippet_end_char=chunk.end_char,
                        snippet=chunk.text,
                        lexical_match_count=match_count,
                    )
                )
        citations.sort(
            key=lambda citation: (
                -citation.lexical_match_count,
                citation.document.logical_document_id,
                citation.document.document_version,
                citation.chunk_index,
                citation.snippet_start_char,
            )
        )
        answer = M8KnowledgeAnswerV1(
            catalog=self._catalog,
            query=request,
            citations=tuple(citations[: request.max_citations]),
            adapter_manifest_id=self._adapter_manifest_id,
        )
        self._answers[request.query_id] = answer
        self._generation_count += 1
        return answer

    def replay(self, query_id: str) -> M8KnowledgeAnswerV1:
        if not isinstance(query_id, str):
            raise TypeError("M8 knowledge replay query_id must be str")
        answer = self._answers.get(query_id)
        if answer is None:
            raise M8KnowledgeRetrieverError(M8KnowledgeRetrieverFailureCode.QUERY_REPLAY_NOT_FOUND)
        return answer

    def read_content(self, content_ref: str) -> bytes:
        if not isinstance(content_ref, str):
            raise TypeError("M8 knowledge content_ref must be str")
        raw = self._contents.get(content_ref)
        if raw is None:
            raise M8KnowledgeRetrieverError(M8KnowledgeRetrieverFailureCode.CONTENT_NOT_FOUND)
        return raw

    @property
    def generation_count(self) -> int:
        return self._generation_count

    @staticmethod
    def _chunks(text: str) -> tuple[_KnowledgeChunk, ...]:
        chunks: list[_KnowledgeChunk] = []
        offset = 0
        for line in text.splitlines(keepends=True):
            logical_line = line.rstrip("\r\n")
            stripped = logical_line.strip()
            if stripped:
                leading = len(logical_line) - len(logical_line.lstrip())
                start = offset + leading
                for part_start in range(0, len(stripped), _MAX_CHUNK_CHARACTERS):
                    part = stripped[part_start : part_start + _MAX_CHUNK_CHARACTERS]
                    absolute_start = start + part_start
                    chunks.append(
                        _KnowledgeChunk(
                            chunk_index=len(chunks),
                            start_char=absolute_start,
                            end_char=absolute_start + len(part),
                            text=part,
                        )
                    )
            offset += len(line)
        if not text.endswith(("\n", "\r")) and not text.splitlines(keepends=True):
            return ()
        return tuple(chunks)


__all__ = ["DeterministicOfflineKnowledgeRetriever"]
