"""Identity-free, non-persistent preventive reminder contract."""

from __future__ import annotations

from typing import Literal, TypeAlias

from pydantic import model_validator

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.enums import PpeType
from labcourt.contracts.references import ReferenceToken

SoftReminderMessage: TypeAlias = Literal[
    "请佩戴护目镜。",
    "请佩戴防护手套。",
    "请穿着实验服。",
]

_MESSAGE_BY_PPE: dict[PpeType, SoftReminderMessage] = {
    PpeType.GOGGLES: "请佩戴护目镜。",
    PpeType.GLOVES: "请佩戴防护手套。",
    PpeType.LAB_COAT: "请穿着实验服。",
}


def reminder_message_for(ppe_type: PpeType) -> SoftReminderMessage:
    """Return the controlled template for a PPE reminder."""

    return _MESSAGE_BY_PPE[ppe_type]


class SoftReminder(FrozenContractModel):
    """An anonymous L0 notification that is never an audit or case artifact."""

    zone_id: ReferenceToken
    ppe_type: PpeType
    message: SoftReminderMessage
    channel: ReferenceToken

    @model_validator(mode="after")
    def validate_controlled_message(self) -> SoftReminder:
        if self.message != reminder_message_for(self.ppe_type):
            raise ValueError("soft reminder message must match its PPE type")
        return self


__all__ = ["SoftReminder", "SoftReminderMessage", "reminder_message_for"]
