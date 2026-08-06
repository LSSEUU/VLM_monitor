from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from labcourt.adapters.storage.readonly_m6_challenge_scenarios import (
    M6ChallengeScenarioReadError,
    M6ChallengeScenarioReadErrorCode,
    ReadonlyM6ChallengeScenarioRepository,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.contracts.canonical import canonical_json
from tests.unit.test_m6_regression_selection import _inputs


def _scenario_path(root: Path) -> tuple[Path, object, object]:
    cut, _, _, observation = _inputs()
    path = root / f"{observation.scenario.sample_id}.json"
    return path, cut, observation


def test_repository_resolves_exact_canonical_scenario_and_missing_is_absent(
    tmp_path: Path,
) -> None:
    path, cut, expected = _scenario_path(tmp_path)
    assert ReadonlyM6ChallengeScenarioRepository(tmp_path).observe(cut) == ()

    path.write_text(expected.canonical_document, encoding="utf-8", newline="\n")
    observed = ReadonlyM6ChallengeScenarioRepository(tmp_path).observe(cut)
    assert observed == (expected,)


def test_repository_rejects_noncanonical_cross_scope_and_oversize_scenarios(
    tmp_path: Path,
) -> None:
    path, cut, expected = _scenario_path(tmp_path)
    path.write_text(expected.canonical_document + " ", encoding="utf-8", newline="\n")
    with pytest.raises(M6ChallengeScenarioReadError) as noncanonical:
        ReadonlyM6ChallengeScenarioRepository(tmp_path).observe(cut)
    assert noncanonical.value.code == M6ChallengeScenarioReadErrorCode.DOCUMENT_INVALID

    foreign = expected.scenario.model_copy(update={"source_item_id": "f" * 64})
    path.write_text(
        canonical_json(foreign.model_dump(mode="json")),
        encoding="utf-8",
        newline="\n",
    )
    with pytest.raises(M6ChallengeScenarioReadError) as scope:
        ReadonlyM6ChallengeScenarioRepository(tmp_path).observe(cut)
    assert scope.value.code == M6ChallengeScenarioReadErrorCode.SCOPE_MISMATCH

    path.write_text(expected.canonical_document, encoding="utf-8", newline="\n")
    with pytest.raises(M6ChallengeScenarioReadError) as oversized:
        ReadonlyM6ChallengeScenarioRepository(tmp_path, max_document_bytes=16).observe(cut)
    assert oversized.value.code == M6ChallengeScenarioReadErrorCode.DOCUMENT_TOO_LARGE


def test_repository_detects_scenario_change_during_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, cut, expected = _scenario_path(tmp_path)
    path.write_text(expected.canonical_document, encoding="utf-8", newline="\n")
    replacement = expected.scenario.model_copy(update={"scenario_revision": 2})
    replacement_document = canonical_json(replacement.model_dump(mode="json"))
    original = SecureWorkspace.read_verified
    calls = 0

    def swapping_read(self: SecureWorkspace, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        nonlocal calls
        observed = original(self, *args, **kwargs)
        calls += 1
        if calls == 1:
            path.write_text(replacement_document, encoding="utf-8", newline="\n")
        return observed

    monkeypatch.setattr(SecureWorkspace, "read_verified", swapping_read)
    with pytest.raises(M6ChallengeScenarioReadError) as changed:
        ReadonlyM6ChallengeScenarioRepository(tmp_path).observe(cut)
    assert changed.value.code == M6ChallengeScenarioReadErrorCode.SNAPSHOT_CHANGED
