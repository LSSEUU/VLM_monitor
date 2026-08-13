"""Narrow lark-oapi 1.7.1 compatibility hook for CARD data frames."""

from __future__ import annotations

import base64
import http
import time
from collections.abc import Awaitable
from types import MethodType
from typing import Any, Protocol, cast


class M8FeishuLarkSdkUnavailable(RuntimeError):
    pass


class _FrameHandler(Protocol):
    def __call__(self, frame: Any) -> Awaitable[None]: ...


def _header_value(headers: Any, key: str) -> str:
    for header in headers:
        if header.key == key:
            return cast(str, header.value)
    raise ValueError(f"Feishu CARD frame is missing required header {key}")


def install_card_frame_compat(client: object) -> object:
    """Route CARD payloads through the SDK dispatcher and preserve CARD response framing."""

    try:
        from lark_oapi.core.const import UTF_8  # type: ignore[import-not-found]
        from lark_oapi.core.json import JSON  # type: ignore[import-not-found]
        from lark_oapi.ws.const import (  # type: ignore[import-not-found]
            HEADER_BIZ_RT,
            HEADER_MESSAGE_ID,
            HEADER_SEQ,
            HEADER_SUM,
            HEADER_TRACE_ID,
            HEADER_TYPE,
        )
        from lark_oapi.ws.enum import MessageType  # type: ignore[import-not-found]
        from lark_oapi.ws.model import Response  # type: ignore[import-not-found]
    except ModuleNotFoundError as error:
        raise M8FeishuLarkSdkUnavailable(
            "install the pinned labcourt[feishu-live] optional dependency"
        ) from error

    if getattr(client, "_labcourt_card_compat_installed", False):
        return client
    original = getattr(client, "_handle_data_frame", None)
    dispatcher = getattr(client, "_event_handler", None)
    writer = getattr(client, "_write_message", None)
    if not callable(original) or dispatcher is None or not callable(writer):
        raise TypeError("Feishu CARD compatibility requires an initialized lark-oapi client")

    async def _handle_data_frame(instance: object, frame: Any) -> None:
        headers = frame.headers
        message_type = MessageType(_header_value(headers, HEADER_TYPE))
        if message_type != MessageType.CARD:
            await cast(_FrameHandler, original)(frame)
            return

        message_id = _header_value(headers, HEADER_MESSAGE_ID)
        _header_value(headers, HEADER_TRACE_ID)
        part_count = int(_header_value(headers, HEADER_SUM))
        part_index = int(_header_value(headers, HEADER_SEQ))
        payload = frame.payload
        if part_count > 1:
            combine = getattr(instance, "_combine", None)
            if not callable(combine):
                raise TypeError("Feishu CARD compatibility requires the SDK frame combiner")
            payload = combine(message_id, part_count, part_index, payload)
            if payload is None:
                return

        response = Response(code=http.HTTPStatus.OK)
        started = round(time.time() * 1_000)
        try:
            result = dispatcher._do_without_validation(payload)
            elapsed = round(time.time() * 1_000) - started
            header = headers.add()
            header.key = HEADER_BIZ_RT
            header.value = str(elapsed)
            if result is not None:
                response.data = base64.b64encode(JSON.marshal(result).encode(UTF_8))
        except Exception:
            response = Response(code=http.HTTPStatus.INTERNAL_SERVER_ERROR)
        frame.payload = JSON.marshal(response).encode(UTF_8)
        await writer(frame.SerializeToString())

    dynamic_client = cast(Any, client)
    dynamic_client._handle_data_frame = MethodType(_handle_data_frame, client)
    dynamic_client._labcourt_card_compat_installed = True
    return client


__all__ = ["M8FeishuLarkSdkUnavailable", "install_card_frame_compat"]
