from __future__ import annotations

import inspect
from typing import get_type_hints

import pytest

from labcourt.adapters.storage.sqlite_hearing_recovery import (
    SQLiteHearingModelCallRecoveryRepository,
)
from labcourt.adapters.storage.sqlite_repository import SQLiteEvidenceRepository
from labcourt.ports.hearing_model_response_recovery import (
    HearingModelCallRecoveryRepository,
)

_METHODS = {
    name
    for name, member in HearingModelCallRecoveryRepository.__dict__.items()
    if inspect.isfunction(member) and not name.startswith("_")
}


def _require_recovery_repository(
    repository: HearingModelCallRecoveryRepository,
) -> HearingModelCallRecoveryRepository:
    """Make structural compatibility part of the static type gate."""

    return repository


@pytest.mark.parametrize(
    "concrete",
    [SQLiteHearingModelCallRecoveryRepository, SQLiteEvidenceRepository],
)
def test_sqlite_recovery_implementations_cover_the_complete_protocol(
    concrete: type[object],
) -> None:
    for name in _METHODS:
        protocol_method = HearingModelCallRecoveryRepository.__dict__[name]
        concrete_method = getattr(concrete, name)
        assert tuple(inspect.signature(concrete_method).parameters) == tuple(
            inspect.signature(protocol_method).parameters
        )
        assert get_type_hints(concrete_method) == get_type_hints(protocol_method)


def test_standalone_recovery_adapter_has_no_extra_public_capabilities() -> None:
    public = {
        name
        for name, member in SQLiteHearingModelCallRecoveryRepository.__dict__.items()
        if callable(member) and not name.startswith("_")
    }
    assert public == _METHODS


def _static_protocol_regression(
    facade: SQLiteEvidenceRepository,
    adapter: SQLiteHearingModelCallRecoveryRepository,
) -> None:
    _require_recovery_repository(facade)
    _require_recovery_repository(adapter)
