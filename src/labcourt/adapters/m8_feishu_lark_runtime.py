"""Optional lark-oapi long-connection assembly for Feishu P2P and card ingress."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import datetime
from typing import Any, cast

from labcourt.adapters.m8_feishu_lark_ws import (
    M8FeishuLarkSdkUnavailable,
    install_card_frame_compat,
)
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_live import (
    M8FeishuLiveConnectionState,
    M8FeishuRuntimeHeartbeatV1,
)
from labcourt.ports.m8_feishu_live import M8FeishuLiveRepository
from labcourt.services.m8_feishu_live_ingress import (
    M8FeishuCardActionIngress,
    M8FeishuLiveIngressService,
    M8FeishuP2PTextIngress,
)

CardExecutor = Callable[[str, str], dict[str, object]]


def build_lark_long_connection(
    *,
    app_id: str,
    app_secret: str,
    ingress: M8FeishuLiveIngressService,
    card_executor: CardExecutor,
    clock: Callable[[], datetime],
) -> object:
    """Build the official client without starting a network connection."""

    if not app_id or not app_secret:
        raise ValueError("Feishu long connection requires App ID and App Secret")
    try:
        import lark_oapi as lark  # type: ignore[import-not-found]
        from lark_oapi.event.callback.model.p2_card_action_trigger import (  # type: ignore[import-not-found]
            P2CardActionTriggerResponse,
        )
    except ModuleNotFoundError as error:
        raise M8FeishuLarkSdkUnavailable(
            "install the pinned labcourt[feishu-live] optional dependency"
        ) from error

    def on_message(event: Any) -> None:
        header = _required(event, "header")
        body = _required(event, "event")
        sender = _required(body, "sender")
        sender_id = _required(sender, "sender_id")
        message = _required(body, "message")
        content = json.loads(cast(str, _required(message, "content")))
        if not isinstance(content, dict) or set(content) != {"text"}:
            raise ValueError("Feishu P2P text content envelope is invalid")
        ingress.accept_text(
            M8FeishuP2PTextIngress(
                provider_event_id=_required_str(header, "event_id"),
                provider_message_id=_required_str(message, "message_id"),
                sender_open_id=_required_str(sender_id, "open_id"),
                chat_id=_required_str(message, "chat_id"),
                chat_type=_required_str(message, "chat_type"),
                sender_type=_required_str(sender, "sender_type"),
                message_type=_required_str(message, "message_type"),
                text=_required_text(content, "text"),
                received_at=clock(),
            )
        )

    def on_card(event: Any) -> Any:
        header = _required(event, "header")
        body = _required(event, "event")
        operator = _required(body, "operator")
        context = _required(body, "context")
        action = _required(body, "action")
        value = _required(action, "value")
        if not isinstance(value, dict):
            raise ValueError("Feishu card action value must be an object")
        request = M8FeishuCardActionIngress(
            provider_event_id=_required_str(header, "event_id"),
            provider_message_id=_required_str(context, "open_message_id"),
            sender_open_id=_required_str(operator, "open_id"),
            chat_id=_required_str(context, "open_chat_id"),
            action_token=_required_text(value, "confirmation_token"),
            received_at=clock(),
        )
        result = ingress.card_callback(request, ingress.accept_card_action, card_executor)
        return P2CardActionTriggerResponse(result)

    dispatcher = (
        lark.EventDispatcherHandler.builder("", "")
        .register_p2_im_message_receive_v1(on_message)
        .register_p2_card_action_trigger(on_card)
        .build()
    )
    client = lark.ws.Client(app_id, app_secret, event_handler=dispatcher)
    return install_card_frame_compat(client)


class M8FeishuLongConnectionRunner:
    """Record connection lifecycle while the official client owns reconnect behavior."""

    def __init__(
        self,
        client: object,
        repository: M8FeishuLiveRepository,
        clock: Callable[[], datetime],
        runtime_manifest_id: Sha256Hex,
    ) -> None:
        self._client = client
        self._repository = repository
        self._clock = clock
        self._manifest = runtime_manifest_id
        self._state = M8FeishuLiveConnectionState.DISCONNECTED
        self._stop = threading.Event()

    def start(self) -> None:
        self._record(M8FeishuLiveConnectionState.CONNECTING)
        heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat.start()
        dynamic_client = cast(Any, self._client)
        dynamic_client.on_reconnecting = lambda: self._record(
            M8FeishuLiveConnectionState.RECONNECTING
        )
        dynamic_client.on_reconnected = lambda: self._record(
            M8FeishuLiveConnectionState.READY
        )
        original_connect = dynamic_client._connect

        async def connect_with_ready() -> None:
            await original_connect()
            self._record(M8FeishuLiveConnectionState.READY)

        dynamic_client._connect = connect_with_ready
        try:
            dynamic_client.start()
        except Exception:
            self._record(M8FeishuLiveConnectionState.FAILED)
            raise
        finally:
            self._stop.set()
            heartbeat.join(timeout=1)

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(10):
            self._record(self._state)

    def _record(self, state: M8FeishuLiveConnectionState) -> None:
        from labcourt.contracts.m8_feishu_live import M8FeishuLiveFailureCode

        self._state = state
        self._repository.record_heartbeat(
            M8FeishuRuntimeHeartbeatV1(
                component="LONG_CONNECTION",
                connection_state=state,
                observed_at=self._clock(),
                failure_code=(
                    M8FeishuLiveFailureCode.WORKER_UNAVAILABLE
                    if state == M8FeishuLiveConnectionState.FAILED
                    else None
                ),
                runtime_manifest_id=self._manifest,
            )
        )


def _required(value: object, name: str) -> Any:
    result = getattr(value, name, None)
    if result is None:
        raise ValueError(f"Feishu event is missing {name}")
    return result


def _required_str(value: object, name: str) -> str:
    result = _required(value, name)
    if not isinstance(result, str) or not result:
        raise ValueError(f"Feishu event {name} must be non-empty text")
    return result


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, dict):
        raise ValueError("Feishu event content must be an object")
    result = value.get(name)
    if not isinstance(result, str) or not result.strip():
        raise ValueError(f"Feishu event {name} must be non-empty text")
    return result.strip()


__all__ = ["M8FeishuLongConnectionRunner", "build_lark_long_connection"]
