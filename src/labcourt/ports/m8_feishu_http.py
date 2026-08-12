"""Provider-specific HTTP boundary for Feishu token and message calls."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuCardDispatchPreflightV1,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_feishu_secrets import M8FeishuResolvedSecrets


class M8FeishuHttpCallStage(StrEnum):
    MESSAGE = "MESSAGE"
    TOKEN = "TOKEN"


class M8FeishuHttpFailureCode(StrEnum):
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    TIMEOUT = "TIMEOUT"
    TLS_FAILED = "TLS_FAILED"
    TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"


class M8FeishuHttpDeliveryCertainty(StrEnum):
    DEFINITELY_NOT_SENT = "DEFINITELY_NOT_SENT"
    UNKNOWN = "UNKNOWN"


class M8FeishuHttpError(ContractViolation):
    def __init__(
        self,
        stage: M8FeishuHttpCallStage,
        failure_code: M8FeishuHttpFailureCode,
        delivery_certainty: M8FeishuHttpDeliveryCertainty,
    ) -> None:
        if not isinstance(stage, M8FeishuHttpCallStage):
            raise TypeError("stage must be M8FeishuHttpCallStage")
        if not isinstance(failure_code, M8FeishuHttpFailureCode):
            raise TypeError("failure_code must be M8FeishuHttpFailureCode")
        if not isinstance(delivery_certainty, M8FeishuHttpDeliveryCertainty):
            raise TypeError("delivery_certainty must be M8FeishuHttpDeliveryCertainty")
        self.stage = stage
        self.failure_code = failure_code
        self.delivery_certainty = delivery_certainty
        super().__init__(f"M8 Feishu HTTP failed: {stage.value}/{failure_code.value}")


@dataclass(frozen=True, slots=True)
class M8FeishuHttpResponse:
    status_code: int
    body: bytes
    provider_log_id: str | None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status_code, int)
            or isinstance(self.status_code, bool)
            or not 100 <= self.status_code <= 599
        ):
            raise ValueError("M8 Feishu HTTP status is invalid")
        if not isinstance(self.body, bytes):
            raise TypeError("M8 Feishu HTTP response body must be bytes")
        if self.provider_log_id is not None and not isinstance(self.provider_log_id, str):
            raise TypeError("M8 Feishu provider log ID must be str")


class M8FeishuHttpTransport(Protocol):
    def acquire_tenant_access_token(
        self,
        profile: M8FeishuAdapterProfileV1,
        secrets: M8FeishuResolvedSecrets,
    ) -> M8FeishuHttpResponse: ...

    def send_interactive_message(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        secrets: M8FeishuResolvedSecrets,
        tenant_access_token: bytes,
        rendered_card: bytes,
    ) -> M8FeishuHttpResponse: ...


__all__ = [
    "M8FeishuHttpCallStage",
    "M8FeishuHttpDeliveryCertainty",
    "M8FeishuHttpError",
    "M8FeishuHttpFailureCode",
    "M8FeishuHttpResponse",
    "M8FeishuHttpTransport",
]
