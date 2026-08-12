"""Authentication port for the M8 loopback API."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.exceptions import ContractViolation


class M8AuthenticationFailureCode(StrEnum):
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    INVALID_CREDENTIAL = "INVALID_CREDENTIAL"


class M8AuthenticationError(ContractViolation):
    def __init__(self, reason_code: M8AuthenticationFailureCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"M8 authentication failed: {reason_code.value}")


class M8RequestAuthenticator(Protocol):
    def authenticate(self, authorization_header: str | None) -> M8ApiPrincipalV1: ...


__all__ = [
    "M8AuthenticationError",
    "M8AuthenticationFailureCode",
    "M8RequestAuthenticator",
]
