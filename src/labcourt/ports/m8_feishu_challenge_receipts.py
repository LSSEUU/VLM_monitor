"""Persistence boundary for verified Feishu URL challenge receipts."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_feishu_challenge import (
    M8FeishuUrlChallengeVerificationReceiptV1,
)


class M8FeishuUrlChallengeReceiptSink(Protocol):
    """Record one secret-free URL challenge verification receipt."""

    def record_verification(
        self,
        receipt: M8FeishuUrlChallengeVerificationReceiptV1,
    ) -> None: ...


__all__ = ["M8FeishuUrlChallengeReceiptSink"]
