"""Default synthetic, offline-only M8 campus safety knowledge fixture."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta

from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_knowledge import (
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeContentType,
    M8KnowledgeDocumentAuthorityV1,
    M8KnowledgeDocumentType,
)


@dataclass(frozen=True, slots=True)
class M8OfflineKnowledgeDemoBundle:
    catalog: M8KnowledgeCatalogAuthorityV1
    content_items: tuple[tuple[str, bytes], ...]
    adapter_manifest_id: Sha256Hex

    def content_map(self) -> dict[str, bytes]:
        return dict(self.content_items)


_FIXTURES: tuple[tuple[str, M8KnowledgeDocumentType, str, str], ...] = (
    (
        "device-gas-detector-manual",
        M8KnowledgeDocumentType.DEVICE_MANUAL,
        "气体检测器设备资料",
        "气体检测器设备资料\n报警后先撤离并通知安全负责人, 不得仅依据视觉模型判断气体浓度.\n",
    ),
    (
        "emergency-chemical-spill",
        M8KnowledgeDocumentType.EMERGENCY_PLAN,
        "化学品泄漏应急预案",
        "化学品泄漏应急预案\n发现泄漏时应远离污染区域, 按校园应急流程报告并等待有资质人员处置.\n",
    ),
    (
        "faq-goggles",
        M8KnowledgeDocumentType.FAQ,
        "护目镜常见问题",
        "护目镜常见问题\n问: 临时进入实验区域是否需要佩戴? 答: 进入指定化学实验区域前必须佩戴.\n",
    ),
    (
        "historical-synthetic-goggles",
        M8KnowledgeDocumentType.HISTORICAL_PRECEDENT,
        "合成历史案例",
        "合成历史案例\n本案例完全虚构. 历史处理只能作为参考, 不能自动成为当前案件裁决规则.\n",
    ),
    (
        "policy-laboratory-entry",
        M8KnowledgeDocumentType.POLICY,
        "实验室安全制度",
        "实验室安全制度\n进入化学实验区域前必须正确佩戴护目镜, 发现设备损坏应立即报告.\n",
    ),
    (
        "sop-goggles",
        M8KnowledgeDocumentType.SOP,
        "护目镜操作规程",
        "护目镜操作规程\n佩戴前检查镜片和绑带, 覆盖眼部后再开始实验操作.\n",
    ),
)


def build_offline_knowledge_demo_bundle(
    *,
    generated_at: datetime,
    document_manifest_id: Sha256Hex,
    catalog_manifest_id: Sha256Hex,
    adapter_manifest_id: Sha256Hex,
) -> M8OfflineKnowledgeDemoBundle:
    effective_at = generated_at - timedelta(days=180)
    published_at = effective_at - timedelta(days=1)
    documents: list[M8KnowledgeDocumentAuthorityV1] = []
    content_items: list[tuple[str, bytes]] = []
    for logical_id, document_type, title, text in _FIXTURES:
        raw = text.encode("utf-8")
        content_ref = f"knowledge-{logical_id}-v1"
        documents.append(
            M8KnowledgeDocumentAuthorityV1(
                logical_document_id=logical_id,
                document_version=1,
                document_type=document_type,
                title=title,
                locale="zh-CN",
                issuer_id="campus-safety-office",
                source_ref=f"source-{logical_id}-v1",
                content_ref=content_ref,
                content_sha256=hashlib.sha256(raw).hexdigest(),
                content_size_bytes=len(raw),
                content_type=M8KnowledgeContentType.MARKDOWN,
                published_at=published_at,
                effective_at=effective_at,
                document_manifest_id=document_manifest_id,
            )
        )
        content_items.append((content_ref, raw))
    catalog = M8KnowledgeCatalogAuthorityV1(
        catalog_id="campus-safety-knowledge",
        catalog_revision=1,
        documents=tuple(documents),
        generated_at=generated_at,
        catalog_manifest_id=catalog_manifest_id,
    )
    return M8OfflineKnowledgeDemoBundle(
        catalog=catalog,
        content_items=tuple(content_items),
        adapter_manifest_id=adapter_manifest_id,
    )


__all__ = ["M8OfflineKnowledgeDemoBundle", "build_offline_knowledge_demo_bundle"]
