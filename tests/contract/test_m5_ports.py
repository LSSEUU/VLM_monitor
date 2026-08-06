from __future__ import annotations

import inspect
from typing import get_type_hints

from labcourt.contracts.evidence import Crop
from labcourt.contracts.m5_appeals import (
    AppealResolutionPrecedentSnapshot,
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
)
from labcourt.contracts.m5_training import DatasetExportReport
from labcourt.contracts.m5_training_provenance import M5TrainingLabelAuthority
from labcourt.contracts.storage import ArtifactVerification
from labcourt.contracts.training import DatasetArtifact
from labcourt.ports.appeals import AppealRepository
from labcourt.ports.dataset_export import (
    DatasetArtifactPublisher,
    DatasetArtifactRegistrationRepository,
    M5DatasetArtifactVerifier,
    M5TrainingCropVerifier,
    TrainingDatasetRepository,
)


def test_appeal_repository_preserves_append_and_atomic_resolution_semantics() -> None:
    assert get_type_hints(AppealRepository.load_closed_case_authority) == {
        "run_id": str,
        "case_id": str,
        "return": ClosedCaseAppealAuthority,
    }
    assert tuple(inspect.signature(AppealRepository.load_current_appeal).parameters) == (
        "self",
        "run_id",
        "case_id",
    )
    assert get_type_hints(AppealRepository.load_appeal_by_id) == {
        "run_id": str,
        "appeal_id": str,
        "return": AppealVersionAuthority | None,
    }
    assert get_type_hints(AppealRepository.load_resolution) == {
        "run_id": str,
        "appeal_id": str,
        "return": AppealResolutionSideEffectIntent | None,
    }
    assert get_type_hints(AppealRepository.load_resolution_precedent_snapshot) == {
        "run_id": str,
        "case_id": str,
        "return": AppealResolutionPrecedentSnapshot,
    }
    append_hints = get_type_hints(AppealRepository.append_appeal_version)
    assert append_hints == {
        "authority": AppealVersionAuthority,
        "expected_previous_authority_sha256": str | None,
        "return": AppealVersionAuthority,
    }
    resolution_hints = get_type_hints(AppealRepository.commit_resolution)
    assert resolution_hints == {
        "intent": AppealResolutionSideEffectIntent,
        "return": AppealResolutionSideEffectIntent,
    }


def test_dataset_publisher_accepts_only_built_bytes_and_bound_report() -> None:
    assert get_type_hints(M5TrainingCropVerifier.verify_crop) == {
        "crop": Crop,
        "return": ArtifactVerification,
    }
    assert get_type_hints(M5DatasetArtifactVerifier.verify_published_dataset) == {
        "report": DatasetExportReport,
        "content": bytes,
        "return": DatasetArtifact,
    }
    assert get_type_hints(DatasetArtifactPublisher.publish) == {
        "report": DatasetExportReport,
        "content": bytes,
        "return": DatasetArtifact,
    }
    assert get_type_hints(DatasetArtifactRegistrationRepository.register_dataset_artifact) == {
        "report": DatasetExportReport,
        "content": bytes,
        "return": DatasetArtifact,
    }
    assert get_type_hints(TrainingDatasetRepository.list_training_label_authorities) == {
        "run_id": str,
        "limit": int,
        "return": tuple[M5TrainingLabelAuthority, ...],
    }
    assert get_type_hints(TrainingDatasetRepository.load_registered_dataset_report) == {
        "run_id": str,
        "command_id": str,
        "return": DatasetExportReport | None,
    }
    assert get_type_hints(TrainingDatasetRepository.register_dataset_artifact) == {
        "report": DatasetExportReport,
        "content": bytes,
        "return": DatasetArtifact,
    }


def test_training_export_exposes_a_typed_historical_replay_failure() -> None:
    from labcourt.application.m5_training_operations import M5TrainingExportFailureCode

    assert (
        M5TrainingExportFailureCode.REGISTERED_DATASET_REPLAY_FAILED.value
        == "REGISTERED_DATASET_REPLAY_FAILED"
    )
