"""Bounded, handle-anchored reads of explicit M6 challenge scenarios."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionSourceInventoryCutAuthority,
    M6RegressionSourceInventoryItem,
)
from labcourt.contracts.m6_regression_selection import (
    M6SyntheticChallengeScenarioAuthority,
)
from labcourt.exceptions import (
    ArtifactIntegrityViolation,
    LabCourtError,
    PathBoundaryViolation,
)
from labcourt.ports.m6_challenge_scenarios import M6ChallengeScenarioObservation

from .secure_workspace import SecureWorkspace

MAX_M6_CHALLENGE_SCENARIO_DOCUMENT_BYTES = 1024 * 1024


class M6ChallengeScenarioReadErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    SNAPSHOT_CHANGED = "SNAPSHOT_CHANGED"
    STORAGE_BOUNDARY_FAILURE = "STORAGE_BOUNDARY_FAILURE"


class M6ChallengeScenarioReadError(LabCourtError):
    """The explicit synthetic challenge inventory could not be read exactly."""

    def __init__(self, code: M6ChallengeScenarioReadErrorCode) -> None:
        if not isinstance(code, M6ChallengeScenarioReadErrorCode):
            raise TypeError("code must be an M6ChallengeScenarioReadErrorCode")
        self.code = code
        super().__init__(f"M6 challenge scenario read failed: {code.value}")


def _fail(code: M6ChallengeScenarioReadErrorCode) -> NoReturn:
    raise M6ChallengeScenarioReadError(code)


def _canonical_cut(value: object) -> M6RegressionSourceInventoryCutAuthority:
    if not isinstance(value, M6RegressionSourceInventoryCutAuthority):
        _fail(M6ChallengeScenarioReadErrorCode.INVALID_ARGUMENT)
    try:
        controlled = M6RegressionSourceInventoryCutAuthority.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6ChallengeScenarioReadErrorCode.INVALID_ARGUMENT)
    if controlled != value:
        _fail(M6ChallengeScenarioReadErrorCode.INVALID_ARGUMENT)
    return controlled


def _require_scope(
    scenario: M6SyntheticChallengeScenarioAuthority,
    item: M6RegressionSourceInventoryItem,
) -> None:
    if (
        scenario.source_item_id != item.source_item_id
        or scenario.sample_id != item.sample_id
        or scenario.input_authority_id != item.input_authority_id
        or scenario.input_authority_document_sha256 != item.input_authority_document_sha256
        or scenario.replay_input_closure_authority_id != item.replay_input_closure_authority_id
        or scenario.replay_input_closure_document_sha256
        != item.replay_input_closure_document_sha256
    ):
        _fail(M6ChallengeScenarioReadErrorCode.SCOPE_MISMATCH)


class ReadonlyM6ChallengeScenarioRepository:
    """Resolve optional ``<sample_id>.json`` scenario files for one source cut."""

    def __init__(
        self,
        scenario_root: str | Path,
        *,
        max_document_bytes: int = MAX_M6_CHALLENGE_SCENARIO_DOCUMENT_BYTES,
    ) -> None:
        if (
            not isinstance(max_document_bytes, int)
            or isinstance(max_document_bytes, bool)
            or max_document_bytes <= 0
        ):
            raise ValueError("max_document_bytes must be a positive integer")
        self._scenario_root = Path(scenario_root).absolute()
        self._max_document_bytes = max_document_bytes

    def observe(self, source_inventory_cut: object) -> tuple[M6ChallengeScenarioObservation, ...]:
        cut = _canonical_cut(source_inventory_cut)
        first_reads: dict[str, tuple[str, bytes]] = {}
        missing: set[str] = set()
        observations: list[M6ChallengeScenarioObservation] = []
        try:
            with SecureWorkspace(
                self._scenario_root,
                self._max_document_bytes,
            ) as workspace:
                for item in cut.items:
                    relative_path = f"{item.sample_id}.json"
                    try:
                        observed = workspace.read_verified(
                            relative_path,
                            max_bytes=self._max_document_bytes,
                        )
                    except PathBoundaryViolation as exc:
                        if exc.reason_code == "FILE_MISSING":
                            missing.add(relative_path)
                            continue
                        if exc.reason_code == "FILE_TOO_LARGE":
                            _fail(M6ChallengeScenarioReadErrorCode.DOCUMENT_TOO_LARGE)
                        raise
                    try:
                        document = observed.bytes.decode("utf-8")
                        scenario = M6SyntheticChallengeScenarioAuthority.model_validate_json(
                            document
                        )
                    except (UnicodeDecodeError, TypeError, ValueError, ValidationError):
                        _fail(M6ChallengeScenarioReadErrorCode.DOCUMENT_INVALID)
                    if canonical_json(scenario.model_dump(mode="json")) != document:
                        _fail(M6ChallengeScenarioReadErrorCode.DOCUMENT_INVALID)
                    _require_scope(scenario, item)
                    first_reads[relative_path] = (observed.sha256, observed.bytes)
                    observations.append(
                        M6ChallengeScenarioObservation(
                            scenario=scenario,
                            canonical_document=document,
                            content_sha256=observed.sha256,
                            size_bytes=observed.size_bytes,
                        )
                    )

                for relative_path, (expected_sha256, expected_bytes) in first_reads.items():
                    try:
                        second = workspace.read_verified(
                            relative_path,
                            expected_sha256,
                            max_bytes=len(expected_bytes),
                        )
                    except (ArtifactIntegrityViolation, PathBoundaryViolation):
                        _fail(M6ChallengeScenarioReadErrorCode.SNAPSHOT_CHANGED)
                    if second.bytes != expected_bytes:
                        _fail(M6ChallengeScenarioReadErrorCode.SNAPSHOT_CHANGED)
                for relative_path in missing:
                    try:
                        workspace.read_verified(
                            relative_path,
                            max_bytes=self._max_document_bytes,
                        )
                    except PathBoundaryViolation as exc:
                        if exc.reason_code == "FILE_MISSING":
                            continue
                        raise
                    _fail(M6ChallengeScenarioReadErrorCode.SNAPSHOT_CHANGED)
        except M6ChallengeScenarioReadError:
            raise
        except (ArtifactIntegrityViolation, PathBoundaryViolation) as exc:
            raise M6ChallengeScenarioReadError(
                M6ChallengeScenarioReadErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from exc
        except OSError as exc:
            raise M6ChallengeScenarioReadError(
                M6ChallengeScenarioReadErrorCode.STORAGE_BOUNDARY_FAILURE
            ) from exc
        return tuple(observations)


__all__ = [
    "MAX_M6_CHALLENGE_SCENARIO_DOCUMENT_BYTES",
    "M6ChallengeScenarioReadError",
    "M6ChallengeScenarioReadErrorCode",
    "ReadonlyM6ChallengeScenarioRepository",
]
