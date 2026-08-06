from __future__ import annotations

import inspect

import pytest

from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.m6_upgrade_candidate_perception_materializer import (
    M6UpgradeCandidatePerceptionMaterializerError,
    M6UpgradeCandidatePerceptionMaterializerFailureCode,
    M6UpgradeCandidatePerceptionMaterializerV3,
)
from labcourt.schema_export import expected_schema_files


def test_candidate_perception_materializer_exposes_only_two_durable_identities() -> None:
    method = M6UpgradeCandidatePerceptionMaterializerV3.materialize_next_perception
    assert tuple(inspect.signature(method).parameters) == (
        "self",
        "candidate_run_id",
        "execution_scope_authority_id",
    )
    assert inspect.get_annotations(method, eval_str=True) == {
        "candidate_run_id": str,
        "execution_scope_authority_id": str,
        "return": M6ResolvedPerception,
    }
    forbidden = {
        "closure",
        "frame",
        "detection",
        "manifest",
        "ordinal",
        "path",
        "digest",
        "sequence",
        "source_run_id",
    }
    assert (set(inspect.signature(method).parameters) - {"self"}).isdisjoint(forbidden)


def test_candidate_perception_materializer_failure_is_closed_and_payload_free() -> None:
    assert {item.value for item in M6UpgradeCandidatePerceptionMaterializerFailureCode} == {
        "INVALID_ARGUMENT",
        "SCOPE_NOT_FOUND",
        "EXECUTION_STATE_MISMATCH",
        "CATALOG_NOT_FOUND",
        "CATALOG_REJECTED",
        "SOURCE_SEAL_REJECTED",
        "SOURCE_PERCEPTION_REJECTED",
        "CANDIDATE_MANIFEST_MISMATCH",
        "IDENTITY_CONFLICT",
        "DOCUMENT_TOO_LARGE",
        "STORED_AUTHORITY_INVALID",
        "STORAGE_REJECTED",
    }
    error = M6UpgradeCandidatePerceptionMaterializerError(
        M6UpgradeCandidatePerceptionMaterializerFailureCode.SOURCE_PERCEPTION_REJECTED
    )
    assert error.args == (
        "M6 candidate perception materialization failed: SOURCE_PERCEPTION_REJECTED",
    )
    assert vars(error) == {"reason_code": error.reason_code}
    assert error.__cause__ is None
    with pytest.raises(TypeError, match="reason_code"):
        M6UpgradeCandidatePerceptionMaterializerError(  # type: ignore[arg-type]
            "SOURCE_PERCEPTION_REJECTED"
        )


def test_candidate_perception_materializer_adds_no_wire_schema() -> None:
    assert not any("candidate-perception-materializer" in item for item in expected_schema_files())
