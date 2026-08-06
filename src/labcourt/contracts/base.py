"""Shared Pydantic configuration for all public contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Self, TypeAlias

from pydantic import BaseModel, ConfigDict, model_validator

from labcourt.contracts.immutable import deep_freeze

Scalar: TypeAlias = str | int | float | bool | None


class ContractModel(BaseModel):
    """Strict-by-shape base model for persisted and exchanged data."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        frozen=True,
        hide_input_in_errors=True,
        populate_by_name=True,
        str_strip_whitespace=False,
        validate_default=True,
    )

    @model_validator(mode="after")
    def freeze_nested_containers(self) -> Self:
        for field_name in type(self).model_fields:
            value = getattr(self, field_name)
            frozen = deep_freeze(value)
            if frozen is not value:
                object.__setattr__(self, field_name, frozen)
        return self

    def model_copy(
        self,
        *,
        update: Mapping[str, object] | None = None,
        deep: bool = False,
    ) -> Self:
        """Return a fully revalidated copy; Pydantic's unchecked update is unsafe for IDs."""

        payload = self.model_dump(
            mode="python",
            exclude_computed_fields=True,
            round_trip=True,
        )
        if update:
            payload.update(update)
        return type(self).model_validate(payload)


class FrozenContractModel(ContractModel):
    """Immutable contract for value objects and source references."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        frozen=True,
        hide_input_in_errors=True,
        populate_by_name=True,
        str_strip_whitespace=False,
        validate_default=True,
    )
