from __future__ import annotations

import pytest

from labcourt.application.m6_replay_locked_source_determinism import (
    M6ReplayLockedSourceDeterminismError,
    M6ReplayLockedSourceDeterminismErrorCode,
    prove_m6_replay_locked_source_determinism,
)
from labcourt.contracts.enums import ReproducibilityMode
from labcourt.ports.m6_replay_locked_source import M6ReplayLockedSourceProjection
from tests.unit.test_m6_replay_locked_receipt import (
    _closure,
    _command,
    _entry,
    _snapshot,
)


def _source_projection() -> M6ReplayLockedSourceProjection:
    closure = _closure()
    snapshot = _snapshot(
        run_id=closure.source_run_id,
        manifest_id=closure.source_manifest_id,
    ).model_copy(
        update={
            "source_case_id": closure.source_case_id,
            "source_case_revision": closure.source_case_revision,
            "source_case_document_sha256": closure.source_case_document_sha256,
        }
    )
    return M6ReplayLockedSourceProjection(
        source_identity_sha256="1" * 64,
        closure=closure,
        source_snapshot=snapshot,
    )


class _ProjectionProvider:
    def __init__(self, *results: object) -> None:
        self.results = results
        self.calls = 0

    def load_source_projection(self, _closure: object) -> object:
        result = self.results[min(self.calls, len(self.results) - 1)]
        self.calls += 1
        if isinstance(result, Exception):
            raise result
        return result


def _prove(provider: object, **updates: object):
    closure = _closure()
    arguments = {
        "command": _command(),
        "execution_entry": _entry(closure),
        "closure": closure,
        "candidate_run_id": "run-candidate",
        "execution_component_manifest_id": "e" * 64,
        "projection_provider": provider,
    }
    arguments.update(updates)
    return prove_m6_replay_locked_source_determinism(**arguments)


def test_prover_owns_two_fresh_reads_and_emits_no_candidate_or_trap_claim() -> None:
    projection = _source_projection()
    provider = _ProjectionProvider(projection, projection)

    proof = _prove(provider)

    assert provider.calls == 2
    assert proof.source_run_id == projection.closure.source_run_id
    assert proof.candidate_run_id == "run-candidate"
    assert proof.first_source_snapshot_id == proof.second_source_snapshot_id
    assert proof.first_semantic_case_hash == proof.second_semantic_case_hash
    serialized = proof.model_dump(mode="json")
    assert "candidate_snapshot" not in serialized
    assert "provider_trap" not in serialized
    assert "execution_receipt" not in serialized


def test_prover_rejects_non_locked_mode_and_source_run_reuse_before_reading() -> None:
    projection = _source_projection()
    provider = _ProjectionProvider(projection)

    with pytest.raises(M6ReplayLockedSourceDeterminismError) as mode:
        _prove(provider, command=_command(mode=ReproducibilityMode.REINFER_PINNED))
    assert mode.value.code == M6ReplayLockedSourceDeterminismErrorCode.MODE_NOT_REPLAY_LOCKED
    assert provider.calls == 0

    with pytest.raises(M6ReplayLockedSourceDeterminismError) as reused:
        _prove(provider, candidate_run_id=projection.closure.source_run_id)
    assert reused.value.code == M6ReplayLockedSourceDeterminismErrorCode.CANDIDATE_RUN_NOT_DISTINCT
    assert provider.calls == 0


def test_prover_rejects_drift_between_fresh_source_reads() -> None:
    first = _source_projection()
    second = M6ReplayLockedSourceProjection(
        source_identity_sha256="2" * 64,
        closure=first.closure,
        source_snapshot=first.source_snapshot,
    )
    provider = _ProjectionProvider(first, second)

    with pytest.raises(M6ReplayLockedSourceDeterminismError) as raised:
        _prove(provider)

    assert raised.value.code == M6ReplayLockedSourceDeterminismErrorCode.SOURCE_PROJECTION_MISMATCH
    assert provider.calls == 2


@pytest.mark.parametrize("result", [object(), RuntimeError("secret C:/alice")])
def test_prover_closes_untrusted_source_failures(result: object) -> None:
    provider = _ProjectionProvider(result)

    with pytest.raises(M6ReplayLockedSourceDeterminismError) as raised:
        _prove(provider)

    assert raised.value.code == M6ReplayLockedSourceDeterminismErrorCode.SOURCE_READ_REJECTED
    assert raised.value.__cause__ is None
    assert provider.calls == 1
