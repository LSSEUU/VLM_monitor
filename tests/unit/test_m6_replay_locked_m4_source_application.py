from __future__ import annotations

import pytest

from labcourt.application.m6_replay_locked_m4_source import (
    M6ReplayLockedM4SourceError,
    M6ReplayLockedM4SourceErrorCode,
    narrow_m6_replay_locked_m4_gate_terminal_source,
)
from labcourt.application.m6_verified_projection_context import M6SqliteProjectionAssembly
from tests.unit.test_m6_replay_locked_m4_source import _terminal_source


def _assembly(source: object) -> M6SqliteProjectionAssembly:
    return M6SqliteProjectionAssembly(
        source_identity_sha256=source.source_identity_sha256,  # type: ignore[attr-defined]
        closure=source.closure,  # type: ignore[attr-defined]
        model_calls=source.closure.model_calls,  # type: ignore[attr-defined]
        embeddings=(),
        projection_context=source.projection_context,  # type: ignore[attr-defined]
        case_replay_snapshot=source.source_snapshot,  # type: ignore[attr-defined]
    )


def test_narrower_selects_one_atomic_m4_gate_terminal_join(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _terminal_source(monkeypatch)

    narrowed = narrow_m6_replay_locked_m4_gate_terminal_source(
        projection_assembly=_assembly(source),
        hearing_record=source.hearing_record,
        hearing_verdict_binding=source.hearing_verdict_binding,
        gate_current_closure_receipt=source.gate_current_closure_receipt,
    )

    assert narrowed == source


def test_narrower_converts_a_terminal_binding_graft_to_a_typed_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _terminal_source(monkeypatch)
    foreign_binding = source.hearing_verdict_binding.model_copy(
        update={"hearing_record_id": "f" * 64}
    )

    with pytest.raises(M6ReplayLockedM4SourceError) as raised:
        narrow_m6_replay_locked_m4_gate_terminal_source(
            projection_assembly=_assembly(source),
            hearing_record=source.hearing_record,
            hearing_verdict_binding=foreign_binding,
            gate_current_closure_receipt=source.gate_current_closure_receipt,
        )

    assert raised.value.code == M6ReplayLockedM4SourceErrorCode.ROUTE_REJECTED
