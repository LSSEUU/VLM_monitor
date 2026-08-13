"""Bounded Feishu P2P ingress normalization with provider event-id deduplication."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_live import (
    M8FeishuInboundEventKind,
    M8FeishuInboundEventV1,
)
from labcourt.contracts.references import ReferenceToken
from labcourt.ports.m8_feishu_live import (
    M8FeishuInboundEnqueueResult,
    M8FeishuLiveRepository,
)


class M8FeishuP2PTextIngress(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    provider_event_id: ReferenceToken
    provider_message_id: ReferenceToken
    sender_open_id: str = Field(min_length=1, max_length=256)
    chat_id: str = Field(min_length=1, max_length=256)
    chat_type: str
    sender_type: str
    message_type: str
    text: str = Field(min_length=1, max_length=4_000)
    received_at: datetime


class M8FeishuCardActionIngress(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    provider_event_id: ReferenceToken
    provider_message_id: ReferenceToken
    sender_open_id: str = Field(min_length=1, max_length=256)
    chat_id: str = Field(min_length=1, max_length=256)
    action_token: str = Field(min_length=32, max_length=512)
    received_at: datetime


class M8FeishuLiveIngressService:
    """Accept only first-release P2P text and opaque card confirmation events."""

    def __init__(
        self,
        repository: M8FeishuLiveRepository,
        ingress_manifest_id: Sha256Hex,
    ) -> None:
        self._repository = repository
        self._manifest = ingress_manifest_id

    def accept_text(self, ingress: M8FeishuP2PTextIngress) -> M8FeishuInboundEnqueueResult:
        if (
            ingress.chat_type != "p2p"
            or ingress.sender_type != "user"
            or ingress.message_type != "text"
        ):
            raise ValueError("M8 Feishu live ingress accepts only user P2P text")
        content = ingress.text.encode("utf-8")
        sanitized = self._sanitized_event(
            ingress.provider_event_id,
            ingress.provider_message_id,
            "DIRECT_MESSAGE",
            ingress.sender_open_id,
            ingress.chat_id,
        )
        event = M8FeishuInboundEventV1(
            event_kind=M8FeishuInboundEventKind.DIRECT_MESSAGE,
            provider_event_id=ingress.provider_event_id,
            provider_message_id=ingress.provider_message_id,
            sender_open_id_sha256=self._digest_text(ingress.sender_open_id),
            chat_id_sha256=self._digest_text(ingress.chat_id),
            received_at=ingress.received_at,
            raw_event_ref=f"feishu-live-event-{sha256_hex([ingress.provider_event_id])[:24]}",
            raw_event_sha256=hashlib.sha256(sanitized).hexdigest(),
            content_ref=f"feishu-live-content-{sha256_hex([ingress.provider_event_id])[:24]}",
            content_sha256=hashlib.sha256(content).hexdigest(),
            ingress_manifest_id=self._manifest,
        )
        return self._repository.enqueue_inbound(event, sanitized, content)

    def accept_card_action(
        self, ingress: M8FeishuCardActionIngress
    ) -> M8FeishuInboundEnqueueResult:
        sanitized = self._sanitized_event(
            ingress.provider_event_id,
            ingress.provider_message_id,
            "CARD_ACTION",
            ingress.sender_open_id,
            ingress.chat_id,
        )
        event = M8FeishuInboundEventV1(
            event_kind=M8FeishuInboundEventKind.CARD_ACTION,
            provider_event_id=ingress.provider_event_id,
            provider_message_id=ingress.provider_message_id,
            sender_open_id_sha256=self._digest_text(ingress.sender_open_id),
            chat_id_sha256=self._digest_text(ingress.chat_id),
            received_at=ingress.received_at,
            raw_event_ref=f"feishu-live-event-{sha256_hex([ingress.provider_event_id])[:24]}",
            raw_event_sha256=hashlib.sha256(sanitized).hexdigest(),
            action_token_sha256=self._digest_text(ingress.action_token),
            ingress_manifest_id=self._manifest,
        )
        return self._repository.enqueue_inbound(event, sanitized, None)

    @staticmethod
    def card_callback(
        ingress: M8FeishuCardActionIngress,
        accept: Callable[[M8FeishuCardActionIngress], M8FeishuInboundEnqueueResult],
        execute: Callable[[str, str], dict[str, object]],
    ) -> dict[str, object]:
        result = accept(ingress)
        if result.duplicate:
            return {"toast": {"type": "info", "content": "该操作已处理"}}
        return execute(ingress.action_token, result.job.inbound_event.sender_open_id_sha256)

    @staticmethod
    def _digest_text(value: str) -> Sha256Hex:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _sanitized_event(
        cls,
        provider_event_id: str,
        provider_message_id: str,
        event_kind: str,
        sender_open_id: str,
        chat_id: str,
    ) -> bytes:
        return canonical_json(
            {
                "event_kind": event_kind,
                "provider_event_id": provider_event_id,
                "provider_message_id": provider_message_id,
                "sender_open_id_sha256": cls._digest_text(sender_open_id),
                "chat_id_sha256": cls._digest_text(chat_id),
                "clear_external_id_persisted": False,
            }
        ).encode("utf-8")


__all__ = [
    "M8FeishuCardActionIngress",
    "M8FeishuLiveIngressService",
    "M8FeishuP2PTextIngress",
]
