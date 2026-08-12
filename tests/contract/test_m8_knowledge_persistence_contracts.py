from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from labcourt.contracts.m8_knowledge import (
    M8KnowledgeAnswerV1,
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeContentType,
    M8KnowledgeDocumentAuthorityV1,
    M8KnowledgeDocumentType,
    M8KnowledgeQueryV1,
)
from labcourt.contracts.m8_knowledge_persistence import (
    M8KnowledgeAnswerCommitReceiptV1,
    M8KnowledgeCatalogCommitReceiptV1,
    M8KnowledgeDocumentCommitReceiptV1,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
BASE_TIME = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)
RAW = "护目镜操作规程\n进入实验区域前必须佩戴护目镜.\n".encode()


def _document(version: int = 1) -> M8KnowledgeDocumentAuthorityV1:
    return M8KnowledgeDocumentAuthorityV1(
        logical_document_id="sop-goggles",
        document_version=version,
        document_type=M8KnowledgeDocumentType.SOP,
        title="护目镜操作规程",
        locale="zh-CN",
        issuer_id="campus-safety-office",
        source_ref=f"source-sop-goggles-v{version}",
        content_ref=f"content-sop-goggles-v{version}",
        content_sha256=hashlib.sha256(RAW).hexdigest(),
        content_size_bytes=len(RAW),
        content_type=M8KnowledgeContentType.MARKDOWN,
        published_at=BASE_TIME - timedelta(days=1),
        effective_at=BASE_TIME,
        document_manifest_id=SHA_A,
    )


def _catalog(document: M8KnowledgeDocumentAuthorityV1 | None = None):
    selected = document or _document()
    return M8KnowledgeCatalogAuthorityV1(
        catalog_id="campus-safety-knowledge",
        catalog_revision=selected.document_version,
        documents=(selected,),
        generated_at=BASE_TIME + timedelta(minutes=selected.document_version),
        catalog_manifest_id=SHA_B,
    )


def _catalog_receipt() -> M8KnowledgeCatalogCommitReceiptV1:
    document = _document()
    document_receipt = M8KnowledgeDocumentCommitReceiptV1(
        document=document,
        raw_storage_manifest_id=SHA_C,
        repository_manifest_id=SHA_D,
    )
    return M8KnowledgeCatalogCommitReceiptV1(
        catalog=_catalog(document),
        document_receipts=(document_receipt,),
        raw_storage_manifest_id=SHA_C,
        repository_manifest_id=SHA_D,
    )


def test_catalog_receipt_binds_exact_raw_inventory_and_contiguous_prior_shape() -> None:
    first = _catalog_receipt()
    assert first.total_content_size_bytes == len(RAW)
    assert first.document_receipts[0].document.content_sha256 == hashlib.sha256(RAW).hexdigest()

    second_document = _document(version=2)
    second_document_receipt = M8KnowledgeDocumentCommitReceiptV1(
        document=second_document,
        raw_storage_manifest_id=SHA_C,
        repository_manifest_id=SHA_D,
    )
    second = M8KnowledgeCatalogCommitReceiptV1(
        catalog=_catalog(second_document),
        document_receipts=(second_document_receipt,),
        prior_catalog_authority_id=first.catalog.catalog_authority_id,
        prior_catalog_document_sha256=first.catalog_document_sha256,
        raw_storage_manifest_id=SHA_C,
        repository_manifest_id=SHA_D,
    )
    assert second.catalog.catalog_revision == 2

    with pytest.raises(ValidationError, match="requires a prior"):
        M8KnowledgeCatalogCommitReceiptV1(
            catalog=_catalog(second_document),
            document_receipts=(second_document_receipt,),
            raw_storage_manifest_id=SHA_C,
            repository_manifest_id=SHA_D,
        )


def test_answer_receipt_binds_resolved_actor_and_rejects_computed_graft() -> None:
    catalog = _catalog()
    query = M8KnowledgeQueryV1(
        catalog_authority_id=catalog.catalog_authority_id,
        requester_actor_id="student-01",
        requester_actor_authority_id=SHA_A,
        query_text="不存在的词",
        locale="zh-CN",
        as_of=BASE_TIME,
        allowed_document_types=(M8KnowledgeDocumentType.SOP,),
        max_citations=1,
        query_manifest_id=SHA_B,
    )
    answer = M8KnowledgeAnswerV1(
        catalog=catalog,
        query=query,
        citations=(),
        adapter_manifest_id=SHA_C,
    )
    receipt = M8KnowledgeAnswerCommitReceiptV1(
        answer=answer,
        resolved_actor_document_sha256=SHA_B,
        repository_manifest_id=SHA_D,
    )
    payload = receipt.model_dump(mode="json")
    payload["answer_id"] = SHA_A
    with pytest.raises(ValidationError, match="answer_id"):
        M8KnowledgeAnswerCommitReceiptV1.model_validate(payload)


@pytest.mark.parametrize(
    "model",
    (
        _catalog_receipt().document_receipts[0],
        _catalog_receipt(),
    ),
)
def test_knowledge_persistence_receipts_round_trip_computed_claims(
    model: M8KnowledgeDocumentCommitReceiptV1 | M8KnowledgeCatalogCommitReceiptV1,
) -> None:
    assert type(model).model_validate_json(model.model_dump_json()) == model
