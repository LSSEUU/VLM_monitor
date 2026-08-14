from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from labcourt.adapters.m8_feishu_lark_ws import install_card_frame_compat

lark_oapi = pytest.importorskip("lark_oapi")

from lark_oapi.ws.const import (  # noqa: E402
    HEADER_MESSAGE_ID,
    HEADER_SEQ,
    HEADER_SUM,
    HEADER_TRACE_ID,
    HEADER_TYPE,
)
from lark_oapi.ws.enum import FrameType, MessageType  # noqa: E402
from lark_oapi.ws.pb.pbbp2_pb2 import Frame  # noqa: E402


def _frame(message_type: MessageType, payload: bytes, *, total: int = 1, index: int = 0) -> Frame:
    frame = Frame()
    frame.method = FrameType.DATA.value
    frame.SeqID = index
    frame.LogID = 1
    frame.service = 1
    frame.payload = payload
    for key, value in (
        (HEADER_MESSAGE_ID, "message-01"),
        (HEADER_TRACE_ID, "trace-01"),
        (HEADER_SUM, str(total)),
        (HEADER_SEQ, str(index)),
        (HEADER_TYPE, message_type.value),
    ):
        header = frame.headers.add()
        header.key = key
        header.value = value
    return frame


class _Dispatcher:
    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def _do_without_validation(self, payload: bytes) -> dict[str, object]:
        self.payloads.append(payload)
        return {"toast": {"type": "success", "content": "已接收"}}


class _FakeClient:
    def __init__(self) -> None:
        self._event_handler = _Dispatcher()
        self.writes: list[bytes] = []
        self.original_frames: list[Any] = []
        self._parts: dict[str, list[bytes]] = {}

    async def _handle_data_frame(self, frame: Any) -> None:
        self.original_frames.append(frame)

    async def _write_message(self, payload: bytes) -> None:
        self.writes.append(payload)

    def _combine(self, message_id: str, total: int, index: int, payload: bytes) -> bytes | None:
        parts = self._parts.setdefault(message_id, [b""] * total)
        parts[index] = payload
        if any(not part for part in parts):
            return None
        return b"".join(parts)


def _run(coroutine: Any) -> None:
    with pytest.raises(StopIteration):
        coroutine.send(None)


def test_card_frame_uses_official_dispatcher_and_preserves_card_response_type() -> None:
    client = _FakeClient()
    install_card_frame_compat(client)
    frame = _frame(MessageType.CARD, b'{"event":{"token":"opaque"}}')

    _run(client._handle_data_frame(frame))

    assert client._event_handler.payloads == [b'{"event":{"token":"opaque"}}']
    assert client.original_frames == []
    assert len(client.writes) == 1
    response = Frame()
    response.ParseFromString(client.writes[0])
    headers = {header.key: header.value for header in response.headers}
    assert headers[HEADER_TYPE] == MessageType.CARD.value
    body = json.loads(response.payload)
    assert body["code"] == 200
    result = json.loads(base64.b64decode(body["data"]))
    assert result["toast"]["content"] == "已接收"


def test_fragmented_card_dispatches_once_and_event_remains_on_sdk_path() -> None:
    client = _FakeClient()
    install_card_frame_compat(client)
    first = _frame(MessageType.CARD, b'{"event":', total=2, index=0)
    second = _frame(MessageType.CARD, b'{"token":"opaque"}}', total=2, index=1)
    event = _frame(MessageType.EVENT, b'{"event_id":"event-01"}')

    _run(client._handle_data_frame(first))
    _run(client._handle_data_frame(second))
    _run(client._handle_data_frame(event))

    assert client._event_handler.payloads == [b'{"event":{"token":"opaque"}}']
    assert len(client.writes) == 1
    assert client.original_frames == [event]
