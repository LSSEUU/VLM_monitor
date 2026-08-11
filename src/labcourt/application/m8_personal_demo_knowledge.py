"""Persist the fixed six-type offline knowledge catalog for the personal Demo."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_knowledge_repository import SQLiteM8KnowledgeRepository
from labcourt.application.m8_knowledge_demo import build_offline_knowledge_demo_bundle
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_knowledge import M8KnowledgeDocumentType
from labcourt.contracts.m8_personal_demo import M8PersonalDemoKnowledgeReceiptV1

_BUSY_TIMEOUT_MS = 5_000
_GENERATED_AT = datetime(2026, 8, 10, 9, 0, tzinfo=UTC)


def _manifest(name: str) -> Sha256Hex:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def bootstrap_m8_personal_demo_knowledge(
    database_path: Path,
) -> M8PersonalDemoKnowledgeReceiptV1:
    bundle = build_offline_knowledge_demo_bundle(
        generated_at=_GENERATED_AT,
        document_manifest_id=_manifest("labcourt-personal-demo-knowledge-documents-v1"),
        catalog_manifest_id=_manifest("labcourt-personal-demo-knowledge-catalog-v1"),
        adapter_manifest_id=_manifest("labcourt-personal-demo-knowledge-adapter-v1"),
    )
    repository = SQLiteM8KnowledgeRepository(
        database_path,
        _BUSY_TIMEOUT_MS,
        _manifest("labcourt-personal-demo-sqlite-repository-v1"),
    )
    contents = bundle.content_map()
    commit = repository.publish_catalog(
        bundle.catalog,
        tuple(contents[document.content_ref] for document in bundle.catalog.documents),
        None,
        _manifest("labcourt-personal-demo-knowledge-raw-store-v1"),
    )
    return M8PersonalDemoKnowledgeReceiptV1(
        catalog_authority_id=commit.catalog.catalog_authority_id,
        catalog_commit_receipt_id=commit.commit_receipt_id,
        generated_at=commit.catalog.generated_at,
        document_types=tuple(sorted(M8KnowledgeDocumentType, key=lambda item: item.value)),
        ordinary_documents_can_define_case_rules=(
            commit.catalog.ordinary_documents_can_define_case_rules
        ),
        knowledge_manifest_id=_manifest("labcourt-personal-demo-knowledge-bootstrap-v1"),
    )


__all__ = ["bootstrap_m8_personal_demo_knowledge"]
