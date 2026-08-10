import importlib
import inspect
import pkgutil
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from datetime import datetime
from typing import get_type_hints

import pytest

import labcourt.ports as ports_package
from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertDispatchAttempt,
    AlertDispatchReceipt,
    AlertOutboxItem,
    AlertPolicyAuthority,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.alerts import AlertDecision, DeliveryReceipt
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.backlog import (
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryFailure,
    BacklogRetrySuccess,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.detections import Detection, FrameBundle
from labcourt.contracts.enums import (
    AcquisitionExecutionMode,
    BacklogStage,
    DatasetFormat,
    EvidenceClass,
    EvidenceFailureCode,
    RunMode,
    ViolationType,
)
from labcourt.contracts.events import CandidateEvent, SafetySignal
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    EvidencePack,
    EvidencePackDraft,
)
from labcourt.contracts.frames import FrameData, FrameRef
from labcourt.contracts.hearing import (
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    HearingBacklogRetryFailure,
    HearingBacklogRetrySuccess,
    HearingCheckpoint,
    HearingCycleScope,
    HearingHumanReviewReceipt,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingRecord,
    HearingReworkReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingUsageReceipt,
    HearingVerdictBinding,
)
from labcourt.contracts.hearing_retrieval import (
    HearingPrecedentRetrievalOutcome,
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalResult,
)
from labcourt.contracts.m3_models import (
    PrecedentLookupQuery,
    PrecedentResolution,
    PromptManifest,
)
from labcourt.contracts.m5_appeals import (
    AppealResolutionPrecedentSnapshot,
    AppealResolutionSideEffectIntent,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
)
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
    M5PrecedentExposureBatchAuthority,
)
from labcourt.contracts.m5_precedents import (
    M5AppealWindowSnapshot,
    M5EmbeddingRequest,
    M5EmbeddingVector,
    M5PrecedentActivationResult,
    M5PrecedentAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5PrecedentRevocationResult,
)
from labcourt.contracts.m5_training import DatasetExportReport
from labcourt.contracts.m5_training_provenance import M5TrainingLabelAuthority
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthorityV3,
    M6UpgradeCandidateRunCutAuthority,
)
from labcourt.contracts.m6_replay_locked import M6ReplayInputClosureAuthority
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    M6ReplayLockedClosedPolicySampleExecutionRecordV2,
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedExecutionSealAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
    M6ReplayLockedSampleExecutionRecord,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecord,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseTransitionCommandV1,
)
from labcourt.contracts.m8_adapter_commissioning import (
    M8CommissioningEvidenceAuthorityV1,
    M8CommissioningEvidenceCommitReceiptV1,
    M8ProductionAdapterCandidateAuthorityV1,
    M8ProductionAdapterCandidateCommitReceiptV1,
)
from labcourt.contracts.m8_api import M8ApiPrincipalV1
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_knowledge import (
    M8KnowledgeAnswerV1,
    M8KnowledgeCatalogAuthorityV1,
    M8KnowledgeQueryV1,
)
from labcourt.contracts.m8_knowledge_persistence import (
    M8KnowledgeAnswerCommitReceiptV1,
    M8KnowledgeCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationChannelCapabilityAuthorityV1,
    M8NotificationDeliveryReceiptV1,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notification_persistence import (
    M8NotificationAuditEventV1,
    M8NotificationCommitReceiptV1,
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationChannelKind,
    M8NotificationPlanAuthorityV1,
    M8NotificationStatus,
    M8NotificationTargetAuthorityV1,
)
from labcourt.contracts.m8_operations import (
    M8CampusTopologyAuthorityV1,
    M8OperationalSourceCatalogAuthorityV1,
)
from labcourt.contracts.m8_projections import M8OperationsProjectionV1
from labcourt.contracts.m8_sensor_persistence import (
    M8SensorPollCacheCommitReceiptV1,
    M8SensorSampleCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorPollResultV1,
)
from labcourt.contracts.manifests import (
    ModelManifest,
    RunManifest,
    SoftwareComponentManifest,
)
from labcourt.contracts.model_response_recovery import ModelResponseRecoveryItem
from labcourt.contracts.precedents import Precedent, ScoredPrecedent
from labcourt.contracts.recovery import RecoveryItemResult
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
    StructureRepairRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.storage import (
    ArtifactRef,
    ArtifactVerification,
    ClosureReport,
    PurgeItemResult,
    RetentionHold,
)
from labcourt.contracts.training import DatasetArtifact, TrainingLabel
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.domain.evidence_authority import AcquisitionExecution, EvidenceAuthority
from labcourt.domain.m6_semantic_projection import M6ResolvedPerception
from labcourt.ports.alert_outbox import AlertOutboxRepository
from labcourt.ports.alert_policy import (
    AlertPolicyRepository,
    AlertPolicyVerifier,
    AutomaticPrecedentVerifier,
)
from labcourt.ports.alerts import AlertChannel
from labcourt.ports.appeals import AppealRepository
from labcourt.ports.backlog import BacklogStore
from labcourt.ports.dataset_export import (
    DatasetArtifactPublisher,
    DatasetArtifactRegistrationRepository,
    M5DatasetArtifactVerifier,
    M5TrainingCropVerifier,
    TrainingDatasetRepository,
)
from labcourt.ports.embeddings import EmbeddingClient, EmbeddingVector
from labcourt.ports.evidence_repository import (
    AuditHead,
    CaseSnapshot,
    EvidenceRepository,
    EvidenceVerifier,
    PublishResult,
)
from labcourt.ports.frame_source import FrameSource
from labcourt.ports.frame_store import FrameStore
from labcourt.ports.hearing_acquisition import (
    HearingAcquisitionExecutor,
    HearingAcquisitionRecovery,
)
from labcourt.ports.hearing_backlog import (
    HearingBacklogEnqueueCommit,
    HearingBacklogEnqueueIntent,
    HearingBacklogRepository,
    HearingBacklogRetryAuthority,
    HearingBacklogRetryCommit,
    HearingModelCallFailureIntent,
)
from labcourt.ports.hearing_model_response_recovery import (
    HearingModelCallRecoveryRepository,
    HearingModelCallRecoveryScan,
    HearingRecoveryResponseStore,
)
from labcourt.ports.hearing_precedents import (
    HearingPrecedentRetrievalOutcomeCommitter,
    HearingPrecedentRetriever,
)
from labcourt.ports.hearing_repository import (
    AcquisitionExecutionClaim,
    AcquisitionExecutionCommit,
    AcquisitionPublishResult,
    HearingBudgetUsage,
    HearingHumanReviewResult,
    HearingModelCallClaim,
    HearingRepository,
    HearingReworkResult,
    HearingStartResult,
    HearingVerdictReviewResult,
)
from labcourt.ports.hearing_vlm import (
    HearingModelResponsePublisher,
    HearingModelResponseStore,
    HearingRawModelResponseVerifier,
    HearingVLMClient,
    HearingVLMResponseCache,
)
from labcourt.ports.m3_semantics import M3SemanticVerifier
from labcourt.ports.m5_precedent_policy import M5PrecedentPolicyVerifier
from labcourt.ports.m5_precedent_usage import (
    M5PrecedentApplicationRepository,
    M5PrecedentApplicationVerifier,
    M5PrecedentExposureStore,
    M5ReadyPrecedentUsage,
)
from labcourt.ports.m5_precedents import (
    M5PrecedentEmbeddingProvider,
    M5PrecedentRepository,
)
from labcourt.ports.m6_regression_execution_source_catalog import (
    M6RegressionExecutionSourceCatalogProvider,
    M6RegressionExecutionSourceCatalogPublisher,
    M6StoredRegressionExecutionSourceCatalog,
)
from labcourt.ports.m6_replay_locked_candidate import (
    M6ReplayLockedCandidateAuditHeadProvider,
    M6ReplayLockedCandidateObservation,
    M6ReplayLockedCandidateObservationProvider,
    M6ReplayLockedCandidatePublisher,
    M6ReplayLockedCandidateWrite,
    M6ReplayLockedM4CandidatePublisher,
    M6ReplayLockedM4CandidateWrite,
    M6ReplayLockedStoredCandidateCase,
    M6ReplayLockedStoredCandidateProvider,
)
from labcourt.ports.m6_replay_locked_closed_policy_candidate import (
    M6ReplayLockedClosedCandidateAuditHeadProvider,
    M6ReplayLockedClosedCandidateObservation,
    M6ReplayLockedClosedCandidateObservationProvider,
    M6ReplayLockedClosedCandidatePublisher,
    M6ReplayLockedClosedCandidateWrite,
    M6ReplayLockedStoredClosedCandidate,
    M6ReplayLockedStoredClosedCandidateProvider,
)
from labcourt.ports.m6_replay_locked_closed_policy_coordinator import (
    M6ReplayLockedClosedPolicyCoordinator,
)
from labcourt.ports.m6_replay_locked_closed_policy_execution_scope import (
    M6ReplayLockedClosedPolicyExecutionScopeProvider,
    M6ReplayLockedClosedPolicyExecutionScopePublisher,
    M6StoredReplayLockedClosedPolicyExecutionScope,
)
from labcourt.ports.m6_replay_locked_closed_policy_ledger import (
    M6ReplayLockedClosedPolicyExecutionResumeV2,
    M6ReplayLockedClosedPolicyLedgerRepository,
)
from labcourt.ports.m6_replay_locked_closed_policy_sample_executor import (
    M6ReplayLockedClosedPolicySampleExecutor,
)
from labcourt.ports.m6_replay_locked_closed_pre_policy_source import (
    M6ReplayLockedClosedPolicyPrePolicySource,
    M6ReplayLockedClosedPolicyPrePolicySourceProvider,
)
from labcourt.ports.m6_replay_locked_coordinator import M6ReplayLockedCoordinator
from labcourt.ports.m6_replay_locked_execution_scope import (
    M6ReplayLockedExecutionScopeProvider,
    M6ReplayLockedExecutionScopePublisher,
    M6StoredReplayLockedExecutionScope,
)
from labcourt.ports.m6_replay_locked_fast_source import (
    M6ReplayLockedFastTerminalSource,
    M6ReplayLockedFastTerminalSourceProvider,
)
from labcourt.ports.m6_replay_locked_ledger import (
    M6ReplayLockedExecutionResume,
    M6ReplayLockedLedgerRepository,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
    M6ReplayLockedM4GateTerminalSourceProvider,
)
from labcourt.ports.m6_replay_locked_policy_source import (
    M6ReplayLockedAlertPolicySourceObservation,
    M6ReplayLockedAlertPolicySourceProvider,
)
from labcourt.ports.m6_replay_locked_sample_executor import (
    M6ReplayLockedSampleExecutor,
)
from labcourt.ports.m6_replay_locked_source import (
    M6ReplayLockedSourceProjection,
    M6ReplayLockedSourceProjectionProvider,
)
from labcourt.ports.m6_source_authority_sealing import (
    M6GateSourceObservation,
    M6GateSourceObserver,
)
from labcourt.ports.m6_upgrade_candidate_coordinator import (
    M6UpgradeCandidateCoordinatorV3,
)
from labcourt.ports.m6_upgrade_candidate_observation_producer import (
    M6UpgradeCandidateObservationProducerV3,
)
from labcourt.ports.m6_upgrade_candidate_output import M6UpgradeCandidateOutputBuilder
from labcourt.ports.m6_upgrade_candidate_perception_materializer import (
    M6UpgradeCandidatePerceptionMaterializerV3,
)
from labcourt.ports.m6_upgrade_candidate_run_cut import (
    M6UpgradeCandidateRunCutRepository,
    M6UpgradeCandidateValidationReportProvider,
)
from labcourt.ports.m6_upgrade_durable_sample_appender import (
    M6UpgradeDurableSampleAppenderV3,
)
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerRepository,
    M6UpgradeExecutionResume,
    M6UpgradeSampleArtifactVerifier,
)
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Repository,
    M6UpgradeExecutionResumeV2,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Repository,
    M6UpgradeExecutionResumeV3,
)
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationRepository,
    M6UpgradeExecutionObservationV3Repository,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentRepository,
    M6UpgradePendingSampleCommitmentV3Repository,
)
from labcourt.ports.m6_upgrade_whole_sample_record_builder import (
    M6UpgradeWholeSampleRecordBuilder,
)
from labcourt.ports.m8_adapter_commissioning_repository import (
    M8AdapterCommissioningRepository,
)
from labcourt.ports.m8_api_authentication import M8RequestAuthenticator
from labcourt.ports.m8_inventory_repository import M8InventoryRepository
from labcourt.ports.m8_knowledge import M8KnowledgeRetriever
from labcourt.ports.m8_knowledge_repository import M8KnowledgeRepository
from labcourt.ports.m8_notification_channel import M8NotificationChannelAdapter
from labcourt.ports.m8_notification_repository import M8NotificationRepository
from labcourt.ports.m8_operations_repository import M8OperationsRepository
from labcourt.ports.m8_projection_reader import M8OperationsProjectionReader
from labcourt.ports.m8_sensor_persistence_repository import M8SensorPersistenceRepository
from labcourt.ports.m8_sensors import M8SensorAdapter
from labcourt.ports.model_response_artifacts import (
    ModelResponseArtifactCandidate,
    ModelResponseArtifactFileOps,
    ModelResponseArtifactRecoveryFence,
    ModelResponseArtifactReferenceRepository,
    ModelResponseArtifactScan,
    ModelResponseEmptyOperationCandidate,
)
from labcourt.ports.model_response_recovery import (
    ModelCallRecoveryRepository,
    ModelCallRecoveryScan,
)
from labcourt.ports.perception import PerceptionProvider
from labcourt.ports.pixels import PixelFrameProvider, RGB8Frame
from labcourt.ports.precedents import PrecedentLookup, PrecedentQuery, PrecedentStore
from labcourt.ports.procedural_review import ProceduralReviewVerifier
from labcourt.ports.prompts import (
    PromptCatalog,
    RenderedPrompt,
    RenderedPromptRegistrar,
    RenderedPromptResolver,
)
from labcourt.ports.raw_frame_cache import RawFrameCache, RawFrameLease
from labcourt.ports.recovery import (
    OrphanRecoveryFileOps,
    OrphanReferenceRepository,
    RecoveryCandidate,
    RecoveryScan,
    StagingCleanupCandidate,
)
from labcourt.ports.retention import (
    PurgeLease,
    PurgeRecoveryCandidate,
    RetentionFileOps,
    RetentionRepository,
)
from labcourt.ports.safety import SafetySignalProvider
from labcourt.ports.screening_repository import (
    M3BacklogRetryCommit,
    M3CaseCommit,
    ModelCallClaim,
    ModelCallFailureIntent,
    ScreeningRepository,
)
from labcourt.ports.trainer import DetectorTrainer, DetectorTrainingConfig
from labcourt.ports.vlm import (
    ModelResponseStore,
    RawModelResponseVerifier,
    VLMClient,
    VLMResponseCache,
)

NONE_TYPE = type(None)

EXPECTED_METHODS: dict[type[object], dict[str, tuple[tuple[str, ...], dict[str, object]]]] = {
    M8AdapterCommissioningRepository: {
        "register_candidate": (
            ("self", "candidate", "registrar_actor_id"),
            {
                "candidate": M8ProductionAdapterCandidateAuthorityV1,
                "registrar_actor_id": str,
                "return": M8ProductionAdapterCandidateCommitReceiptV1,
            },
        ),
        "get_candidate": (
            ("self", "candidate_authority_id"),
            {
                "candidate_authority_id": str,
                "return": M8ProductionAdapterCandidateCommitReceiptV1,
            },
        ),
        "commit_evidence": (
            ("self", "evidence", "artifact_bytes", "artifact_storage_manifest_id"),
            {
                "evidence": M8CommissioningEvidenceAuthorityV1,
                "artifact_bytes": bytes,
                "artifact_storage_manifest_id": str,
                "return": M8CommissioningEvidenceCommitReceiptV1,
            },
        ),
        "get_evidence": (
            ("self", "evidence_authority_id"),
            {
                "evidence_authority_id": str,
                "return": M8CommissioningEvidenceCommitReceiptV1,
            },
        ),
        "list_candidate_evidence": (
            ("self", "candidate_authority_id", "limit"),
            {
                "candidate_authority_id": str,
                "limit": int,
                "return": tuple[M8CommissioningEvidenceCommitReceiptV1, ...],
            },
        ),
        "read_artifact": (
            ("self", "artifact_ref"),
            {"artifact_ref": str, "return": bytes},
        ),
    },
    M8KnowledgeRepository: {
        "publish_catalog": (
            (
                "self",
                "catalog",
                "raw_contents",
                "expected_prior_revision",
                "raw_storage_manifest_id",
            ),
            {
                "catalog": M8KnowledgeCatalogAuthorityV1,
                "raw_contents": tuple[bytes, ...],
                "expected_prior_revision": int | None,
                "raw_storage_manifest_id": str,
                "return": M8KnowledgeCatalogCommitReceiptV1,
            },
        ),
        "get_current_catalog": (
            ("self", "catalog_id"),
            {"catalog_id": str, "return": M8KnowledgeCatalogCommitReceiptV1},
        ),
        "read_content": (
            ("self", "content_ref"),
            {"content_ref": str, "return": bytes},
        ),
        "commit_answer": (
            ("self", "answer"),
            {"answer": M8KnowledgeAnswerV1, "return": M8KnowledgeAnswerCommitReceiptV1},
        ),
        "get_answer": (
            ("self", "query_id"),
            {"query_id": str, "return": M8KnowledgeAnswerCommitReceiptV1},
        ),
    },
    M8KnowledgeRetriever: {
        "catalog_authority": (
            ("self",),
            {"return": M8KnowledgeCatalogAuthorityV1},
        ),
        "query": (
            ("self", "request"),
            {"request": M8KnowledgeQueryV1, "return": M8KnowledgeAnswerV1},
        ),
        "replay": (
            ("self", "query_id"),
            {"query_id": str, "return": M8KnowledgeAnswerV1},
        ),
        "read_content": (
            ("self", "content_ref"),
            {"content_ref": str, "return": bytes},
        ),
    },
    M8NotificationChannelAdapter: {
        "capability_authority": (
            ("self",),
            {"return": M8NotificationChannelCapabilityAuthorityV1},
        ),
        "dispatch": (
            ("self", "request", "rendered_card"),
            {
                "request": M8NotificationDispatchRequestV1,
                "rendered_card": bytes,
                "return": M8NotificationDispatchResultV1,
            },
        ),
        "confirm_simulated_delivery": (
            ("self", "dispatch_result", "occurred_at"),
            {
                "dispatch_result": M8NotificationDispatchResultV1,
                "occurred_at": datetime,
                "return": M8NotificationDeliveryReceiptV1,
            },
        ),
        "replay_dispatch": (
            ("self", "dispatch_request_id"),
            {
                "dispatch_request_id": str,
                "return": M8NotificationDispatchResultV1,
            },
        ),
        "replay_delivery": (
            ("self", "dispatch_result_id"),
            {
                "dispatch_result_id": str,
                "return": M8NotificationDeliveryReceiptV1,
            },
        ),
        "read_raw_response": (
            ("self", "raw_response_ref"),
            {"raw_response_ref": str, "return": bytes},
        ),
    },
    M8NotificationRepository: {
        "publish_target_authority": (
            ("self", "target", "expected_prior_revision"),
            {
                "target": M8NotificationTargetAuthorityV1,
                "expected_prior_revision": int | None,
                "return": M8NotificationTargetCommitReceiptV1,
            },
        ),
        "get_current_target_authority": (
            ("self", "actor_id", "channel"),
            {
                "actor_id": str,
                "channel": M8NotificationChannelKind,
                "return": M8NotificationTargetCommitReceiptV1,
            },
        ),
        "create_notification": (
            ("self", "plan", "audit_manifest_id"),
            {
                "plan": M8NotificationPlanAuthorityV1,
                "audit_manifest_id": str,
                "return": M8NotificationCommitReceiptV1,
            },
        ),
        "get_current_notification": (
            ("self", "notification_id"),
            {"notification_id": str, "return": M8NotificationCommitReceiptV1},
        ),
        "transition_notification": (
            (
                "self",
                "command",
                "raw_artifacts",
                "raw_storage_manifest_id",
                "audit_manifest_id",
            ),
            {
                "command": M8NotificationTransitionCommandV1,
                "raw_artifacts": tuple[bytes, ...],
                "raw_storage_manifest_id": str,
                "audit_manifest_id": str,
                "return": M8NotificationCommitReceiptV1,
            },
        ),
        "list_notifications_by_status": (
            ("self", "status", "limit"),
            {
                "status": M8NotificationStatus,
                "limit": int,
                "return": tuple[M8NotificationCommitReceiptV1, ...],
            },
        ),
        "list_current_notifications": (
            ("self", "limit"),
            {"limit": int, "return": tuple[M8NotificationCommitReceiptV1, ...]},
        ),
        "list_notification_audit": (
            ("self", "notification_id"),
            {
                "notification_id": str,
                "return": tuple[M8NotificationAuditEventV1, ...],
            },
        ),
        "read_raw_artifact": (
            ("self", "raw_artifact_ref"),
            {"raw_artifact_ref": str, "return": bytes},
        ),
    },
    M8RequestAuthenticator: {
        "authenticate": (
            ("self", "authorization_header"),
            {
                "authorization_header": str | None,
                "return": M8ApiPrincipalV1,
            },
        ),
    },
    M8OperationsProjectionReader: {
        "current_projection": (
            ("self", "campus_id"),
            {"campus_id": str, "return": M8OperationsProjectionV1},
        ),
    },
    M8InventoryRepository: {
        "publish_topology": (
            ("self", "topology", "expected_prior_revision"),
            {
                "topology": M8CampusTopologyAuthorityV1,
                "expected_prior_revision": int | None,
                "return": M8CampusTopologyCommitReceiptV1,
            },
        ),
        "get_current_topology": (
            ("self", "campus_id"),
            {"campus_id": str, "return": M8CampusTopologyCommitReceiptV1},
        ),
        "publish_source_catalog": (
            ("self", "catalog", "expected_prior_revision"),
            {
                "catalog": M8OperationalSourceCatalogAuthorityV1,
                "expected_prior_revision": int | None,
                "return": M8OperationalSourceCatalogCommitReceiptV1,
            },
        ),
        "get_current_source_catalog": (
            ("self", "campus_id"),
            {"campus_id": str, "return": M8OperationalSourceCatalogCommitReceiptV1},
        ),
        "get_source_catalog": (
            ("self", "catalog_id"),
            {"catalog_id": str, "return": M8OperationalSourceCatalogCommitReceiptV1},
        ),
    },
    M8OperationsRepository: {
        "publish_actor_authority": (
            ("self", "authority", "expected_prior_revision"),
            {
                "authority": M8ActorAuthorityV1,
                "expected_prior_revision": int | None,
                "return": M8ActorAuthorityCommitReceiptV1,
            },
        ),
        "get_current_actor_authority": (
            ("self", "actor_id"),
            {"actor_id": str, "return": M8ActorAuthorityCommitReceiptV1},
        ),
        "create_operational_case": (
            (
                "self",
                "command",
                "subject_actor_id",
                "case_manifest_id",
                "audit_manifest_id",
            ),
            {
                "command": M8OperationalCaseCreateCommandV1,
                "subject_actor_id": str | None,
                "case_manifest_id": str,
                "audit_manifest_id": str,
                "return": M8OperationalCaseCommitReceiptV1,
            },
        ),
        "get_current_operational_case": (
            ("self", "case_id"),
            {"case_id": str, "return": M8OperationalCaseCommitReceiptV1},
        ),
        "list_current_operational_cases": (
            ("self", "limit"),
            {"limit": int, "return": tuple[M8OperationalCaseCommitReceiptV1, ...]},
        ),
        "transition_operational_case": (
            ("self", "command", "case_manifest_id", "audit_manifest_id"),
            {
                "command": M8OperationalCaseTransitionCommandV1,
                "case_manifest_id": str,
                "audit_manifest_id": str,
                "return": M8OperationalCaseCommitReceiptV1,
            },
        ),
        "list_operational_case_audit": (
            ("self", "case_id"),
            {
                "case_id": str,
                "return": tuple[M8OperationalCaseAuditEventV1, ...],
            },
        ),
    },
    M8SensorPersistenceRepository: {
        "commit_poll_result": (
            (
                "self",
                "result",
                "raw_signals",
                "raw_storage_manifest_id",
                "cache_manifest_id",
            ),
            {
                "result": M8SensorPollResultV1,
                "raw_signals": tuple[bytes, ...],
                "raw_storage_manifest_id": str,
                "cache_manifest_id": str,
                "return": M8SensorPollCacheCommitReceiptV1,
            },
        ),
        "get_poll_cache": (
            ("self", "request_id"),
            {"request_id": str, "return": M8SensorPollCacheCommitReceiptV1},
        ),
        "get_sample": (
            ("self", "sample_id"),
            {"sample_id": str, "return": M8SensorSampleCommitReceiptV1},
        ),
        "list_latest_sensor_samples": (
            ("self", "limit"),
            {"limit": int, "return": tuple[M8SensorSampleCommitReceiptV1, ...]},
        ),
        "read_raw_signal": (
            ("self", "raw_signal_ref"),
            {"raw_signal_ref": str, "return": bytes},
        ),
    },
    M8SensorAdapter: {
        "capability_authority": (
            ("self",),
            {"return": M8SensorAdapterCapabilityAuthorityV1},
        ),
        "poll": (
            ("self", "request"),
            {
                "request": M8SensorPollRequestV1,
                "return": M8SensorPollResultV1,
            },
        ),
        "replay": (
            ("self", "request_id"),
            {"request_id": str, "return": M8SensorPollResultV1},
        ),
        "read_raw_signal": (
            ("self", "raw_signal_ref"),
            {"raw_signal_ref": str, "return": bytes},
        ),
    },
    AutomaticPrecedentVerifier: {
        "rebuild": (
            ("self", "case", "manifest", "alert_authority", "created_at"),
            {
                "case": Case,
                "manifest": RunManifest,
                "alert_authority": AlertPolicyAuthority,
                "created_at": datetime,
                "return": M5PrecedentAuthority,
            },
        ),
    },
    AlertPolicyVerifier: {
        "rebuild": (
            (
                "self",
                "case",
                "manifest",
                "prior_cooldown",
                "prior_emergency_delivery",
            ),
            {
                "case": Case,
                "manifest": RunManifest,
                "prior_cooldown": AlertCooldownAuthority | None,
                "prior_emergency_delivery": ImmediateSafetyDeliveryAuthority | None,
                "return": AlertPolicyAuthority,
            },
        ),
    },
    AlertPolicyRepository: {
        "list_ready_cases": (
            ("self", "run_id", "limit"),
            {
                "run_id": str,
                "limit": int,
                "return": tuple[CaseSnapshot, ...],
            },
        ),
        "load_current_cooldown": (
            ("self", "run_id", "key", "stream_id", "stream_authority_sha256"),
            {
                "run_id": str,
                "key": AlertCooldownKey,
                "stream_id": str,
                "stream_authority_sha256": str,
                "return": AlertCooldownAuthority | None,
            },
        ),
        "record_immediate_safety_delivery": (
            ("self", "run_id", "authority"),
            {
                "run_id": str,
                "authority": ImmediateSafetyDeliveryAuthority,
                "return": ImmediateSafetyDeliveryAuthority,
            },
        ),
        "load_immediate_safety_delivery": (
            ("self", "run_id", "incident_id"),
            {
                "run_id": str,
                "incident_id": str,
                "return": ImmediateSafetyDeliveryAuthority | None,
            },
        ),
        "commit_alert_policy": (
            (
                "self",
                "run_id",
                "expected_revision",
                "authority",
                "automatic_precedent",
                "application_batch",
                "application_citations",
            ),
            {
                "run_id": str,
                "expected_revision": int,
                "authority": AlertPolicyAuthority,
                "automatic_precedent": M5PrecedentAuthority,
                "application_batch": M5PrecedentApplicationBatchAuthority | None,
                "application_citations": tuple[M5PrecedentApplicationCitationCommit, ...],
                "return": CaseSnapshot,
            },
        ),
    },
    AlertOutboxRepository: {
        "list_pending_outbox": (
            ("self", "run_id", "limit"),
            {
                "run_id": str,
                "limit": int,
                "return": tuple[AlertOutboxItem, ...],
            },
        ),
        "begin_dispatch": (
            ("self", "item", "lease_owner_sha256", "channel_capability"),
            {
                "item": AlertOutboxItem,
                "lease_owner_sha256": str,
                "channel_capability": AlertChannelCapabilityAuthority,
                "return": AlertDispatchAttempt | AlertDispatchReceipt,
            },
        ),
        "complete_dispatch": (
            ("self", "attempt", "receipt"),
            {
                "attempt": AlertDispatchAttempt,
                "receipt": AlertDispatchReceipt,
                "return": AlertDispatchReceipt,
            },
        ),
    },
    AlertChannel: {
        "capability_authority": (
            ("self", "run_id", "manifest_id", "config_sha256"),
            {
                "run_id": str,
                "manifest_id": str,
                "config_sha256": str,
                "return": AlertChannelCapabilityAuthority,
            },
        ),
        "send": (
            ("self", "alert", "case", "idempotency_key"),
            {
                "alert": AlertDecision,
                "case": Case,
                "idempotency_key": str,
                "return": DeliveryReceipt,
            },
        ),
    },
    AppealRepository: {
        "load_closed_case_authority": (
            ("self", "run_id", "case_id"),
            {
                "run_id": str,
                "case_id": str,
                "return": ClosedCaseAppealAuthority,
            },
        ),
        "load_current_appeal": (
            ("self", "run_id", "case_id"),
            {
                "run_id": str,
                "case_id": str,
                "return": AppealVersionAuthority | None,
            },
        ),
        "load_appeal_by_id": (
            ("self", "run_id", "appeal_id"),
            {
                "run_id": str,
                "appeal_id": str,
                "return": AppealVersionAuthority | None,
            },
        ),
        "load_resolution": (
            ("self", "run_id", "appeal_id"),
            {
                "run_id": str,
                "appeal_id": str,
                "return": AppealResolutionSideEffectIntent | None,
            },
        ),
        "load_resolution_precedent_snapshot": (
            ("self", "run_id", "case_id"),
            {
                "run_id": str,
                "case_id": str,
                "return": AppealResolutionPrecedentSnapshot,
            },
        ),
        "append_appeal_version": (
            ("self", "authority", "expected_previous_authority_sha256"),
            {
                "authority": AppealVersionAuthority,
                "expected_previous_authority_sha256": str | None,
                "return": AppealVersionAuthority,
            },
        ),
        "commit_resolution": (
            ("self", "intent"),
            {
                "intent": AppealResolutionSideEffectIntent,
                "return": AppealResolutionSideEffectIntent,
            },
        ),
    },
    BacklogStore: {
        "enqueue": (
            ("self", "run_id", "item"),
            {"run_id": str, "item": BacklogItem, "return": BacklogItem},
        ),
        "lease_next": (
            ("self", "run_id", "stage", "lease_owner_sha256", "lease_expires_at"),
            {
                "run_id": str,
                "stage": BacklogStage,
                "lease_owner_sha256": str,
                "lease_expires_at": datetime,
                "return": BacklogItem | None,
            },
        ),
        "complete": (
            ("self", "run_id", "item_id", "expected_lease_id"),
            {
                "run_id": str,
                "item_id": str,
                "expected_lease_id": str,
                "return": BacklogItem,
            },
        ),
        "release": (
            ("self", "run_id", "item_id", "expected_lease_id"),
            {
                "run_id": str,
                "item_id": str,
                "expected_lease_id": str,
                "return": BacklogItem,
            },
        ),
        "reclaim_expired": (
            ("self", "run_id", "not_after", "limit"),
            {
                "run_id": str,
                "not_after": datetime,
                "limit": int,
                "return": tuple[BacklogItem, ...],
            },
        ),
    },
    HearingAcquisitionExecutor: {
        "execution_mode": (
            ("self",),
            {"return": AcquisitionExecutionMode},
        ),
        "execute": (
            ("self", "request", "authority", "idempotency_key"),
            {
                "request": AcquisitionRequest,
                "authority": EvidenceAuthority,
                "idempotency_key": str,
                "return": AcquisitionExecution,
            },
        ),
        "recover": (
            ("self", "request", "authority", "idempotency_key"),
            {
                "request": AcquisitionRequest,
                "authority": EvidenceAuthority,
                "idempotency_key": str,
                "return": HearingAcquisitionRecovery,
            },
        ),
    },
    HearingBacklogRepository: {
        "commit_hearing_backlog": (
            (
                "self",
                "run_id",
                "expected_case_revision",
                "expected_audit_head",
                "intent",
            ),
            {
                "run_id": str,
                "expected_case_revision": int,
                "expected_audit_head": AuditHead,
                "intent": HearingBacklogEnqueueIntent,
                "return": HearingBacklogEnqueueCommit,
            },
        ),
        "lease_next_hearing_backlog": (
            ("self", "run_id", "lease_owner_sha256", "lease_expires_at"),
            {
                "run_id": str,
                "lease_owner_sha256": str,
                "lease_expires_at": datetime,
                "return": BacklogItem | None,
            },
        ),
        "load_hearing_backlog_retry_authority": (
            ("self", "run_id", "lease"),
            {
                "run_id": str,
                "lease": BacklogLeaseIdentity,
                "return": HearingBacklogRetryAuthority,
            },
        ),
        "commit_hearing_backlog_retry": (
            (
                "self",
                "run_id",
                "expected_case_revision",
                "expected_audit_head",
                "outcome",
                "model_call_failure",
            ),
            {
                "run_id": str,
                "expected_case_revision": int,
                "expected_audit_head": AuditHead,
                "outcome": HearingBacklogRetrySuccess | HearingBacklogRetryFailure,
                "model_call_failure": HearingModelCallFailureIntent | None,
                "return": HearingBacklogRetryCommit,
            },
        ),
        "reclaim_expired_hearing_backlog": (
            ("self", "run_id", "not_after", "limit"),
            {
                "run_id": str,
                "not_after": datetime,
                "limit": int,
                "return": tuple[HearingBacklogRetryCommit, ...],
            },
        ),
    },
    HearingRepository: {
        "begin_hearing_case": (
            (
                "self",
                "run_id",
                "expected_case_revision",
                "expected_audit_head",
                "session",
                "cycle_scope",
                "checkpoint",
            ),
            {
                "run_id": str,
                "expected_case_revision": int,
                "expected_audit_head": AuditHead,
                "session": HearingSession,
                "cycle_scope": HearingCycleScope,
                "checkpoint": HearingCheckpoint,
                "return": HearingStartResult,
            },
        ),
        "append_hearing_cycle": (
            ("self", "run_id", "cycle_scope"),
            {
                "run_id": str,
                "cycle_scope": HearingCycleScope,
                "return": NONE_TYPE,
            },
        ),
        "append_hearing_checkpoint": (
            ("self", "run_id", "checkpoint"),
            {
                "run_id": str,
                "checkpoint": HearingCheckpoint,
                "return": NONE_TYPE,
            },
        ),
        "append_precedent_retrieval": (
            ("self", "run_id", "receipt"),
            {
                "run_id": str,
                "receipt": HearingPrecedentRetrievalReceipt,
                "return": NONE_TYPE,
            },
        ),
        "claim_hearing_model_call": (
            ("self", "run_id", "request", "owner_token", "backlog_lease"),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "owner_token": str,
                "backlog_lease": BacklogLeaseIdentity | None,
                "return": HearingModelCallClaim,
            },
        ),
        "complete_hearing_model_call": (
            ("self", "run_id", "request", "response", "usage", "owner_token"),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "response": HearingModelResponse,
                "usage": HearingUsageReceipt,
                "owner_token": str,
                "return": HearingModelCacheEntry,
            },
        ),
        "append_hearing_parse_receipt": (
            ("self", "receipt", "output"),
            {
                "receipt": HearingModelParseReceipt,
                "output": HearingRoleOutput | None,
                "return": HearingModelParseReceipt,
            },
        ),
        "complete_hearing_round": (
            ("self", "run_id", "hearing_round"),
            {
                "run_id": str,
                "hearing_round": HearingRound,
                "return": NONE_TYPE,
            },
        ),
        "commit_hearing_verdict_review": (
            (
                "self",
                "run_id",
                "expected_case_revision",
                "expected_audit_head",
                "verdict",
                "binding",
                "review",
                "checkpoint",
            ),
            {
                "run_id": str,
                "expected_case_revision": int,
                "expected_audit_head": AuditHead,
                "verdict": Verdict,
                "binding": HearingVerdictBinding,
                "review": ProceduralReview,
                "checkpoint": HearingCheckpoint,
                "return": HearingVerdictReviewResult,
            },
        ),
        "begin_hearing_rework": (
            (
                "self",
                "run_id",
                "expected_case_revision",
                "expected_audit_head",
                "receipt",
                "cycle_scope",
                "checkpoint",
            ),
            {
                "run_id": str,
                "expected_case_revision": int,
                "expected_audit_head": AuditHead,
                "receipt": HearingReworkReceipt,
                "cycle_scope": HearingCycleScope,
                "checkpoint": HearingCheckpoint,
                "return": HearingReworkResult,
            },
        ),
        "commit_hearing_human_review": (
            (
                "self",
                "run_id",
                "expected_case_revision",
                "expected_audit_head",
                "receipt",
                "checkpoint",
            ),
            {
                "run_id": str,
                "expected_case_revision": int,
                "expected_audit_head": AuditHead,
                "receipt": HearingHumanReviewReceipt,
                "checkpoint": HearingCheckpoint,
                "return": HearingHumanReviewResult,
            },
        ),
        "claim_acquisition_execution": (
            ("self", "run_id", "request", "execution_mode", "owner_token"),
            {
                "run_id": str,
                "request": AcquisitionRequest,
                "execution_mode": AcquisitionExecutionMode,
                "owner_token": str,
                "return": AcquisitionExecutionClaim,
            },
        ),
        "claim_acquisition_recovery": (
            (
                "self",
                "run_id",
                "request",
                "observed_owner_fence",
                "owner_token",
            ),
            {
                "run_id": str,
                "request": AcquisitionRequest,
                "observed_owner_fence": int,
                "owner_token": str,
                "return": AcquisitionExecutionClaim,
            },
        ),
        "complete_acquisition_execution": (
            ("self", "run_id", "publication", "owner_token"),
            {
                "run_id": str,
                "publication": AcquisitionExecutionPublication,
                "owner_token": str,
                "return": AcquisitionExecutionCommit,
            },
        ),
        "abandon_acquisition_execution": (
            ("self", "run_id", "request", "observed_owner_fence", "owner_token"),
            {
                "run_id": str,
                "request": AcquisitionRequest,
                "observed_owner_fence": int,
                "owner_token": str,
                "return": AcquisitionExecutionClaim,
            },
        ),
        "load_acquisition_execution": (
            ("self", "run_id", "request_id"),
            {
                "run_id": str,
                "request_id": str,
                "return": AcquisitionExecutionPublication | None,
            },
        ),
        "persist_acquisition_successor": (
            (
                "self",
                "run_id",
                "expected_case_revision",
                "expected_audit_head",
                "request",
                "publication",
            ),
            {
                "run_id": str,
                "expected_case_revision": int,
                "expected_audit_head": AuditHead,
                "request": AcquisitionRequest,
                "publication": AcquisitionExecutionPublication,
                "return": AcquisitionPublishResult,
            },
        ),
        "load_hearing_session": (
            ("self", "run_id", "hearing_id"),
            {"run_id": str, "hearing_id": str, "return": HearingSession},
        ),
        "load_active_hearing": (
            ("self", "run_id", "case_id"),
            {"run_id": str, "case_id": str, "return": HearingSession | None},
        ),
        "load_latest_hearing_checkpoint": (
            ("self", "run_id", "hearing_id"),
            {"run_id": str, "hearing_id": str, "return": HearingCheckpoint},
        ),
        "list_hearing_cycles": (
            ("self", "run_id", "hearing_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "return": tuple[HearingCycleScope, ...],
            },
        ),
        "list_hearing_rounds": (
            ("self", "run_id", "hearing_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "return": tuple[HearingRound, ...],
            },
        ),
        "load_hearing_record": (
            ("self", "run_id", "hearing_id"),
            {"run_id": str, "hearing_id": str, "return": HearingRecord | None},
        ),
        "load_hearing_budget_usage": (
            ("self", "run_id", "hearing_id"),
            {"run_id": str, "hearing_id": str, "return": HearingBudgetUsage},
        ),
        "list_hearing_model_requests": (
            ("self", "run_id", "hearing_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "return": tuple[HearingModelRequest, ...],
            },
        ),
        "list_hearing_model_responses": (
            ("self", "run_id", "hearing_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "return": tuple[HearingModelResponse, ...],
            },
        ),
        "list_hearing_parse_receipts": (
            ("self", "run_id", "hearing_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "return": tuple[HearingModelParseReceipt, ...],
            },
        ),
        "list_hearing_role_outputs": (
            ("self", "run_id", "hearing_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "return": tuple[HearingRoleOutput, ...],
            },
        ),
        "list_hearing_usage_receipts": (
            ("self", "run_id", "hearing_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "return": tuple[HearingUsageReceipt, ...],
            },
        ),
        "list_hearing_failure_authorities": (
            ("self", "run_id", "hearing_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "return": tuple[HearingModelCallFailureAuthority, ...],
            },
        ),
        "load_hearing_evidence_authority": (
            ("self", "run_id", "hearing_id", "current_pack_id"),
            {
                "run_id": str,
                "hearing_id": str,
                "current_pack_id": str,
                "return": EvidenceAuthority,
            },
        ),
        "load_hearing_cycle": (
            ("self", "run_id", "cycle_id"),
            {"run_id": str, "cycle_id": str, "return": HearingCycleScope},
        ),
        "load_precedent_retrieval": (
            ("self", "run_id", "receipt_id"),
            {
                "run_id": str,
                "receipt_id": str,
                "return": HearingPrecedentRetrievalReceipt,
            },
        ),
        "load_hearing_checkpoint": (
            ("self", "run_id", "checkpoint_id"),
            {
                "run_id": str,
                "checkpoint_id": str,
                "return": HearingCheckpoint,
            },
        ),
        "load_hearing_round": (
            ("self", "run_id", "round_id"),
            {"run_id": str, "round_id": str, "return": HearingRound},
        ),
        "load_hearing_model_request": (
            ("self", "run_id", "request_id"),
            {"run_id": str, "request_id": str, "return": HearingModelRequest},
        ),
        "load_hearing_model_response": (
            ("self", "run_id", "response_id"),
            {"run_id": str, "response_id": str, "return": HearingModelResponse},
        ),
        "load_hearing_model_cache_entry": (
            ("self", "run_id", "cache_key"),
            {
                "run_id": str,
                "cache_key": str,
                "return": HearingModelCacheEntry | None,
            },
        ),
        "load_hearing_parse_receipt": (
            ("self", "run_id", "parse_receipt_id"),
            {
                "run_id": str,
                "parse_receipt_id": str,
                "return": HearingModelParseReceipt,
            },
        ),
        "load_hearing_role_output": (
            ("self", "run_id", "output_id"),
            {"run_id": str, "output_id": str, "return": HearingRoleOutput},
        ),
        "load_hearing_usage_receipt": (
            ("self", "run_id", "usage_receipt_id"),
            {
                "run_id": str,
                "usage_receipt_id": str,
                "return": HearingUsageReceipt,
            },
        ),
    },
    HearingVLMClient: {
        "complete": (
            ("self", "request"),
            {
                "request": HearingModelRequest,
                "return": HearingModelResponse,
            },
        ),
    },
    HearingModelResponsePublisher: {
        "publish": (
            (
                "self",
                "request",
                "raw_response",
                "input_tokens",
                "output_tokens",
                "latency_ms",
            ),
            {
                "request": HearingModelRequest,
                "raw_response": bytes,
                "input_tokens": int,
                "output_tokens": int,
                "latency_ms": int,
                "return": HearingModelResponse,
            },
        ),
    },
    HearingRawModelResponseVerifier: {
        "verify_raw_response": (
            ("self", "run_id", "request", "response"),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "response": HearingModelResponse,
                "return": HearingModelResponse,
            },
        ),
    },
    HearingModelResponseStore: {
        "probe_recovery": (
            ("self", "request"),
            {
                "request": HearingModelRequest,
                "return": HearingModelResponse | None,
            },
        ),
        "recover": (
            ("self", "request"),
            {
                "request": HearingModelRequest,
                "return": HearingModelResponse | None,
            },
        ),
        "acknowledge": (
            ("self", "request", "response"),
            {
                "request": HearingModelRequest,
                "response": HearingModelResponse,
                "return": NONE_TYPE,
            },
        ),
        "read_bytes": (
            ("self", "run_id", "response", "max_bytes"),
            {
                "run_id": str,
                "response": HearingModelResponse,
                "max_bytes": int,
                "return": bytes,
            },
        ),
        "read_json": (
            ("self", "run_id", "response", "max_bytes"),
            {
                "run_id": str,
                "response": HearingModelResponse,
                "max_bytes": int,
                "return": str,
            },
        ),
        "verify": (
            ("self", "run_id", "response"),
            {
                "run_id": str,
                "response": HearingModelResponse,
                "return": HearingModelResponse,
            },
        ),
        "verify_raw_response": (
            ("self", "run_id", "request", "response"),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "response": HearingModelResponse,
                "return": HearingModelResponse,
            },
        ),
    },
    HearingVLMResponseCache: {
        "get": (
            ("self", "run_id", "request"),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "return": HearingModelCacheEntry | None,
            },
        ),
        "put": (
            ("self", "run_id", "request", "response"),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "response": HearingModelResponse,
                "return": HearingModelCacheEntry,
            },
        ),
    },
    HearingModelCallRecoveryRepository: {
        "scan_hearing_model_call_recovery_candidates": (
            ("self", "run_id", "max_items"),
            {
                "run_id": str,
                "max_items": int,
                "return": HearingModelCallRecoveryScan,
            },
        ),
        "complete_expired_hearing_model_call_from_recovery": (
            (
                "self",
                "run_id",
                "request",
                "response",
                "observed_lease_expires_at",
                "observed_takeover_count",
            ),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "response": HearingModelResponse,
                "observed_lease_expires_at": datetime,
                "observed_takeover_count": int,
                "return": HearingModelCacheEntry,
            },
        ),
        "load_hearing_model_cache_entry_for_recovery": (
            ("self", "run_id", "request"),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "return": HearingModelCacheEntry | None,
            },
        ),
        "load_hearing_model_response_for_request": (
            ("self", "run_id", "request_id"),
            {
                "run_id": str,
                "request_id": str,
                "return": HearingModelResponse | None,
            },
        ),
    },
    HearingRecoveryResponseStore: {
        "probe_recovery": (
            ("self", "request"),
            {
                "request": HearingModelRequest,
                "return": HearingModelResponse | None,
            },
        ),
        "recover": (
            ("self", "request"),
            {
                "request": HearingModelRequest,
                "return": HearingModelResponse | None,
            },
        ),
        "verify_raw_response": (
            ("self", "run_id", "request", "response"),
            {
                "run_id": str,
                "request": HearingModelRequest,
                "response": HearingModelResponse,
                "return": HearingModelResponse,
            },
        ),
        "acknowledge": (
            ("self", "request", "response"),
            {
                "request": HearingModelRequest,
                "response": HearingModelResponse,
                "return": NONE_TYPE,
            },
        ),
    },
    HearingPrecedentRetrievalOutcomeCommitter: {
        "commit": (
            ("self", "outcome"),
            {
                "outcome": HearingPrecedentRetrievalOutcome,
                "return": HearingPrecedentRetrievalReceipt,
            },
        ),
    },
    HearingPrecedentRetriever: {
        "retrieve": (
            ("self", "query"),
            {
                "query": HearingPrecedentRetrievalQuery,
                "return": HearingPrecedentRetrievalResult,
            },
        ),
    },
    ModelCallRecoveryRepository: {
        "scan_model_call_recovery_candidates": (
            ("self", "run_id", "max_items"),
            {
                "run_id": str,
                "max_items": int,
                "return": ModelCallRecoveryScan,
            },
        ),
        "complete_expired_model_call_from_recovery": (
            (
                "self",
                "run_id",
                "request",
                "response",
                "observed_lease_expires_at",
                "observed_takeover_count",
            ),
            {
                "run_id": str,
                "request": VLMRequest | StructureRepairRequest,
                "response": VLMResponse,
                "observed_lease_expires_at": datetime,
                "observed_takeover_count": int,
                "return": CachedModelResponse,
            },
        ),
        "get": (
            ("self", "run_id", "request"),
            {
                "run_id": str,
                "request": VLMRequest | StructureRepairRequest,
                "return": CachedModelResponse | None,
            },
        ),
        "load_raw_response_for_request": (
            ("self", "run_id", "request_id"),
            {
                "run_id": str,
                "request_id": str,
                "return": VLMResponse | None,
            },
        ),
    },
    ModelResponseArtifactReferenceRepository: {
        "model_response_is_referenced": (
            ("self", "run_id", "response_id", "content_sha256"),
            {
                "run_id": str,
                "response_id": str,
                "content_sha256": str,
                "return": bool,
            },
        ),
    },
    ModelResponseArtifactRecoveryFence: {
        "model_response_artifact_recovery_fence": (
            ("self", "run_id"),
            {
                "run_id": str,
                "return": AbstractContextManager[None],
            },
        ),
    },
    ModelResponseArtifactFileOps: {
        "discover_model_response_artifacts": (
            (
                "self",
                "run_id",
                "max_items",
                "max_name_bytes",
                "max_file_bytes",
                "max_total_bytes",
            ),
            {
                "run_id": str,
                "max_items": int,
                "max_name_bytes": int,
                "max_file_bytes": int,
                "max_total_bytes": int,
                "return": ModelResponseArtifactScan,
            },
        ),
        "quarantine_model_response_artifact": (
            ("self", "candidate", "not_modified_after", "max_file_bytes"),
            {
                "candidate": ModelResponseArtifactCandidate,
                "not_modified_after": datetime,
                "max_file_bytes": int,
                "return": ModelResponseRecoveryItem,
            },
        ),
        "cleanup_empty_model_response_operation": (
            ("self", "candidate", "not_modified_after"),
            {
                "candidate": ModelResponseEmptyOperationCandidate,
                "not_modified_after": datetime,
                "return": ModelResponseRecoveryItem,
            },
        ),
    },
    ProceduralReviewVerifier: {
        "rebuild_review": (
            (
                "self",
                "verdict",
                "evidence_pack",
                "current_closure",
                "parse_history",
                "review_version",
            ),
            {
                "verdict": Verdict,
                "evidence_pack": EvidencePack,
                "current_closure": ClosureReport,
                "parse_history": tuple[ModelParseReceipt, ...],
                "review_version": int,
                "return": ProceduralReview,
            },
        ),
    },
    M3SemanticVerifier: {
        "rebuild_screening": (
            ("self", "parsed_output", "evidence_pack", "screening_version"),
            {
                "parsed_output": ParsedScreeningOutput,
                "evidence_pack": EvidencePack,
                "screening_version": int,
                "return": ScreeningResult,
            },
        ),
        "rebuild_fast_verdict": (
            (
                "self",
                "screening_result",
                "evidence_pack",
                "model_response_refs",
                "verdict_version",
            ),
            {
                "screening_result": ScreeningResult,
                "evidence_pack": EvidencePack,
                "model_response_refs": tuple[ArtifactRef, ...],
                "verdict_version": int,
                "return": Verdict,
            },
        ),
    },
    ScreeningRepository: {
        "load_raw_response": (
            ("self", "run_id", "response_id"),
            {"run_id": str, "response_id": str, "return": VLMResponse},
        ),
        "load_raw_response_for_request": (
            ("self", "run_id", "request_id"),
            {"run_id": str, "request_id": str, "return": VLMResponse | None},
        ),
        "claim_model_call": (
            ("self", "run_id", "request", "owner_token", "backlog_lease"),
            {
                "run_id": str,
                "request": VLMRequest | StructureRepairRequest,
                "owner_token": str,
                "backlog_lease": BacklogLeaseIdentity | None,
                "return": ModelCallClaim,
            },
        ),
        "complete_model_call": (
            ("self", "run_id", "request", "response", "owner_token"),
            {
                "run_id": str,
                "request": VLMRequest | StructureRepairRequest,
                "response": VLMResponse,
                "owner_token": str,
                "return": CachedModelResponse,
            },
        ),
        "append_parse_receipt": (
            ("self", "receipt", "parsed_output"),
            {
                "receipt": ModelParseReceipt,
                "parsed_output": ParsedScreeningOutput | None,
                "return": ModelParseReceipt,
            },
        ),
        "load_parse_receipt": (
            ("self", "run_id", "parse_receipt_id"),
            {
                "run_id": str,
                "parse_receipt_id": str,
                "return": ModelParseReceipt,
            },
        ),
        "load_parse_receipt_for_output": (
            ("self", "run_id", "parsed_output_id"),
            {
                "run_id": str,
                "parsed_output_id": str,
                "return": ModelParseReceipt,
            },
        ),
        "load_parse_history_for_output": (
            ("self", "run_id", "parsed_output_id"),
            {
                "run_id": str,
                "parsed_output_id": str,
                "return": tuple[ModelParseReceipt, ...],
            },
        ),
        "load_parsed_output": (
            ("self", "run_id", "parsed_output_id"),
            {
                "run_id": str,
                "parsed_output_id": str,
                "return": ParsedScreeningOutput,
            },
        ),
        "commit_screening": (
            (
                "self",
                "run_id",
                "expected_revision",
                "expected_audit_head",
                "current_pack_closure",
                "screening",
            ),
            {
                "run_id": str,
                "expected_revision": int,
                "expected_audit_head": AuditHead,
                "current_pack_closure": ClosureReport,
                "screening": ScreeningResult,
                "return": M3CaseCommit,
            },
        ),
        "commit_verdict_review": (
            (
                "self",
                "run_id",
                "expected_revision",
                "expected_audit_head",
                "current_pack_closure",
                "verdict",
                "review",
            ),
            {
                "run_id": str,
                "expected_revision": int,
                "expected_audit_head": AuditHead,
                "current_pack_closure": ClosureReport,
                "verdict": Verdict,
                "review": ProceduralReview,
                "return": M3CaseCommit,
            },
        ),
        "commit_backlog": (
            (
                "self",
                "run_id",
                "expected_revision",
                "expected_audit_head",
                "current_pack_closure",
                "item",
                "response_ids",
                "model_call_failure",
            ),
            {
                "run_id": str,
                "expected_revision": int,
                "expected_audit_head": AuditHead,
                "current_pack_closure": ClosureReport,
                "item": BacklogItem,
                "response_ids": tuple[str, ...],
                "model_call_failure": ModelCallFailureIntent | None,
                "return": M3CaseCommit,
            },
        ),
        "commit_backlog_screening_success": (
            (
                "self",
                "run_id",
                "expected_revision",
                "expected_audit_head",
                "current_pack_closure",
                "success",
                "screening",
            ),
            {
                "run_id": str,
                "expected_revision": int,
                "expected_audit_head": AuditHead,
                "current_pack_closure": ClosureReport,
                "success": BacklogRetrySuccess,
                "screening": ScreeningResult,
                "return": M3BacklogRetryCommit,
            },
        ),
        "commit_backlog_verdict_review_success": (
            (
                "self",
                "run_id",
                "expected_revision",
                "expected_audit_head",
                "current_pack_closure",
                "success",
                "verdict",
                "review",
                "screening",
            ),
            {
                "run_id": str,
                "expected_revision": int,
                "expected_audit_head": AuditHead,
                "current_pack_closure": ClosureReport,
                "success": BacklogRetrySuccess,
                "verdict": Verdict,
                "review": ProceduralReview,
                "screening": ScreeningResult | None,
                "return": M3BacklogRetryCommit,
            },
        ),
        "commit_backlog_retry_failure": (
            (
                "self",
                "run_id",
                "expected_revision",
                "expected_audit_head",
                "current_pack_closure",
                "failure",
                "model_call_failure",
            ),
            {
                "run_id": str,
                "expected_revision": int,
                "expected_audit_head": AuditHead,
                "current_pack_closure": ClosureReport,
                "failure": BacklogRetryFailure,
                "model_call_failure": ModelCallFailureIntent | None,
                "return": M3BacklogRetryCommit,
            },
        ),
        "load_case": (
            ("self", "run_id", "case_id"),
            {"run_id": str, "case_id": str, "return": CaseSnapshot},
        ),
        "load_screening": (
            ("self", "run_id", "screening_id"),
            {"run_id": str, "screening_id": str, "return": ScreeningResult},
        ),
        "load_verdict": (
            ("self", "run_id", "verdict_id"),
            {"run_id": str, "verdict_id": str, "return": Verdict},
        ),
        "load_procedural_review": (
            ("self", "run_id", "review_id"),
            {"run_id": str, "review_id": str, "return": ProceduralReview},
        ),
        "load_backlog_item": (
            ("self", "run_id", "item_id"),
            {"run_id": str, "item_id": str, "return": BacklogItem},
        ),
    },
    EmbeddingClient: {
        "embed_text": (
            ("self", "texts"),
            {"texts": Sequence[str], "return": Sequence[EmbeddingVector]},
        ),
        "embed_images": (
            ("self", "crops"),
            {"crops": Sequence[Crop], "return": Sequence[EmbeddingVector]},
        ),
    },
    EvidenceRepository: {
        "register_run": (
            ("self", "run_id", "manifest"),
            {"run_id": str, "manifest": RunManifest, "return": NONE_TYPE},
        ),
        "register_frame": (
            ("self", "run_id", "frame"),
            {"run_id": str, "frame": FrameRef, "return": NONE_TYPE},
        ),
        "register_detection": (
            ("self", "run_id", "detection"),
            {"run_id": str, "detection": Detection, "return": NONE_TYPE},
        ),
        "load_run_manifest": (
            ("self", "run_id"),
            {"run_id": str, "return": RunManifest},
        ),
        "create_or_get_case": (
            ("self", "run_id", "event"),
            {"run_id": str, "event": CandidateEvent, "return": CaseSnapshot},
        ),
        "publish_pack": (
            ("self", "run_id", "expected_revision", "pack"),
            {
                "run_id": str,
                "expected_revision": int,
                "pack": EvidencePackDraft,
                "return": PublishResult,
            },
        ),
        "record_evidence_failure": (
            ("self", "run_id", "expected_revision", "case_id", "failure_code"),
            {
                "run_id": str,
                "expected_revision": int,
                "case_id": str,
                "failure_code": EvidenceFailureCode,
                "return": CaseSnapshot,
            },
        ),
        "load_case": (
            ("self", "run_id", "case_id"),
            {"run_id": str, "case_id": str, "return": CaseSnapshot},
        ),
        "load_pack": (
            ("self", "run_id", "pack_id"),
            {"run_id": str, "pack_id": str, "return": EvidencePack},
        ),
        "load_frame": (
            ("self", "run_id", "frame_id"),
            {"run_id": str, "frame_id": str, "return": FrameRef},
        ),
        "verify_current_pack": (
            ("self", "run_id", "pack_id"),
            {"run_id": str, "pack_id": str, "return": ClosureReport},
        ),
        "list_events": (
            ("self", "run_id"),
            {"run_id": str, "return": tuple[CandidateEvent, ...]},
        ),
        "list_audit_entries": (
            ("self", "run_id"),
            {"run_id": str, "return": tuple[AuditEntry, ...]},
        ),
        "get_audit_head": (
            ("self", "run_id"),
            {"run_id": str, "return": AuditHead},
        ),
    },
    EvidenceVerifier: {
        "verify_crop": (
            ("self", "crop"),
            {"crop": Crop, "return": ArtifactVerification},
        ),
        "reference_exists": (
            ("self", "run_id", "ref"),
            {"run_id": str, "ref": ArtifactRef, "return": bool},
        ),
    },
    FrameSource: {
        "iter_frames": (("self",), {"return": Iterator[FrameBundle]}),
        "get_frame": (("self", "frame_id"), {"frame_id": str, "return": FrameData}),
        "get_range": (
            ("self", "camera_id", "stream_id", "start", "end", "step"),
            {
                "camera_id": str,
                "stream_id": str,
                "start": int,
                "end": int,
                "step": int,
                "return": Sequence[FrameData],
            },
        ),
    },
    PixelFrameProvider: {
        "read_rgb8": (
            ("self", "frame_id"),
            {"frame_id": str, "return": RGB8Frame},
        ),
    },
    RawFrameCache: {
        "put": (
            ("self", "frame"),
            {"frame": RGB8Frame, "return": RawFrameLease},
        ),
        "get": (
            ("self", "frame_id"),
            {"frame_id": str, "return": RGB8Frame},
        ),
        "purge_expired": (("self",), {"return": tuple[str, ...]}),
        "close": (("self",), {"return": NONE_TYPE}),
    },
    OrphanReferenceRepository: {
        "media_is_referenced": (
            ("self", "run_id", "media_sha256"),
            {"run_id": str, "media_sha256": str, "return": bool},
        ),
    },
    OrphanRecoveryFileOps: {
        "discover": (
            ("self", "run_id", "max_items", "max_depth", "max_name_bytes"),
            {
                "run_id": str,
                "max_items": int,
                "max_depth": int,
                "max_name_bytes": int,
                "return": RecoveryScan,
            },
        ),
        "quarantine": (
            ("self", "candidate", "not_modified_after"),
            {
                "candidate": RecoveryCandidate,
                "not_modified_after": datetime,
                "return": RecoveryItemResult,
            },
        ),
        "cleanup_empty_staging": (
            ("self", "candidate", "not_modified_after"),
            {
                "candidate": StagingCleanupCandidate,
                "not_modified_after": datetime,
                "return": RecoveryItemResult,
            },
        ),
    },
    RetentionFileOps: {
        "stage_for_purge": (
            ("self", "lease"),
            {"lease": PurgeLease, "return": NONE_TYPE},
        ),
        "destroy_purged": (
            ("self", "lease"),
            {"lease": PurgeLease, "return": NONE_TYPE},
        ),
    },
    RetentionRepository: {
        "list_expirable_media": (
            ("self", "run_id", "expires_before", "limit"),
            {
                "run_id": str,
                "expires_before": datetime,
                "limit": int,
                "return": tuple[str, ...],
            },
        ),
        "begin_media_purge": (
            (
                "self",
                "run_id",
                "media_sha256",
                "expires_before",
                "policy_version",
            ),
            {
                "run_id": str,
                "media_sha256": str,
                "expires_before": datetime,
                "policy_version": str,
                "return": PurgeLease | PurgeItemResult,
            },
        ),
        "complete_media_purge": (
            (
                "self",
                "run_id",
                "media_sha256",
                "intent_audit_sequence",
                "recovered",
            ),
            {
                "run_id": str,
                "media_sha256": str,
                "intent_audit_sequence": int,
                "recovered": bool,
                "return": PurgeItemResult,
            },
        ),
        "claim_next_recovery": (
            ("self", "run_id"),
            {
                "run_id": str,
                "return": PurgeRecoveryCandidate | None,
            },
        ),
        "mark_trash_cleaned": (
            ("self", "run_id", "media_sha256", "intent_audit_sequence"),
            {
                "run_id": str,
                "media_sha256": str,
                "intent_audit_sequence": int,
                "return": NONE_TYPE,
            },
        ),
        "create_retention_hold": (
            ("self", "hold"),
            {"hold": RetentionHold, "return": int},
        ),
        "release_retention_hold": (
            ("self", "run_id", "hold_id"),
            {"run_id": str, "hold_id": str, "return": int},
        ),
    },
    FrameStore: {
        "run_id": (("self",), {"return": str}),
        "software_component": (
            ("self",),
            {"return": SoftwareComponentManifest},
        ),
        "create_crop": (
            ("self", "request"),
            {
                "request": CropRequest,
                "return": Crop,
            },
        ),
        "verify_crop": (
            ("self", "crop"),
            {"crop": Crop, "return": ArtifactVerification},
        ),
    },
    PerceptionProvider: {
        "detect": (
            ("self", "frame"),
            {"frame": FrameData, "return": Sequence[Detection]},
        ),
        "redetect": (
            ("self", "crop", "prompts"),
            {
                "crop": Crop,
                "prompts": Sequence[str],
                "return": Sequence[Detection],
            },
        ),
    },
    PrecedentLookup: {
        "lookup": (
            ("self", "query"),
            {
                "query": PrecedentLookupQuery,
                "return": PrecedentResolution,
            },
        ),
    },
    PrecedentStore: {
        "add": (
            ("self", "run_id", "precedent"),
            {"run_id": str, "precedent": Precedent, "return": NONE_TYPE},
        ),
        "retrieve": (
            ("self", "run_id", "query", "limit"),
            {
                "run_id": str,
                "query": PrecedentQuery,
                "limit": int,
                "return": tuple[ScoredPrecedent, ...],
            },
        ),
        "record_citation": (
            ("self", "run_id", "case_id", "precedent_id", "score"),
            {
                "run_id": str,
                "case_id": str,
                "precedent_id": str,
                "score": float,
                "return": NONE_TYPE,
            },
        ),
        "find_conflicts": (
            ("self", "run_id", "precedent", "limit"),
            {
                "run_id": str,
                "precedent": Precedent,
                "limit": int,
                "return": tuple[ScoredPrecedent, ...],
            },
        ),
    },
    PromptCatalog: {
        "bundle_sha256": (
            ("self",),
            {"return": str},
        ),
        "manifest": (
            ("self", "prompt_id"),
            {"prompt_id": str, "return": PromptManifest},
        ),
        "render": (
            ("self", "prompt_id", "variables"),
            {
                "prompt_id": str,
                "variables": Mapping[str, str],
                "return": RenderedPrompt,
            },
        ),
    },
    RenderedPromptRegistrar: {
        "register": (
            ("self", "prompt"),
            {"prompt": RenderedPrompt, "return": NONE_TYPE},
        ),
    },
    RenderedPromptResolver: {
        "resolve": (
            ("self", "request"),
            {
                "request": VLMRequest | StructureRepairRequest,
                "return": bytes,
            },
        ),
    },
    SafetySignalProvider: {
        "signals_for_frame": (
            ("self", "frame"),
            {"frame": FrameRef, "return": Sequence[SafetySignal]},
        ),
    },
    DatasetArtifactPublisher: {
        "publish": (
            ("self", "report", "content"),
            {
                "report": DatasetExportReport,
                "content": bytes,
                "return": DatasetArtifact,
            },
        ),
    },
    DatasetArtifactRegistrationRepository: {
        "register_dataset_artifact": (
            ("self", "report", "content"),
            {
                "report": DatasetExportReport,
                "content": bytes,
                "return": DatasetArtifact,
            },
        ),
    },
    M5TrainingCropVerifier: {
        "verify_crop": (
            ("self", "crop"),
            {
                "crop": Crop,
                "return": ArtifactVerification,
            },
        ),
    },
    M5DatasetArtifactVerifier: {
        "verify_published_dataset": (
            ("self", "report", "content"),
            {
                "report": DatasetExportReport,
                "content": bytes,
                "return": DatasetArtifact,
            },
        ),
    },
    TrainingDatasetRepository: {
        "load_registered_dataset_report": (
            ("self", "run_id", "command_id"),
            {
                "run_id": str,
                "command_id": str,
                "return": DatasetExportReport | None,
            },
        ),
        "list_training_label_authorities": (
            ("self", "run_id", "limit"),
            {
                "run_id": str,
                "limit": int,
                "return": tuple[M5TrainingLabelAuthority, ...],
            },
        ),
        "register_dataset_artifact": (
            ("self", "report", "content"),
            {
                "report": DatasetExportReport,
                "content": bytes,
                "return": DatasetArtifact,
            },
        ),
    },
    DetectorTrainer: {
        "export_dataset": (
            ("self", "labels", "target"),
            {
                "labels": Sequence[TrainingLabel],
                "target": DatasetFormat,
                "return": DatasetArtifact,
            },
        ),
        "train": (
            ("self", "dataset", "base_manifest", "config"),
            {
                "dataset": DatasetArtifact,
                "base_manifest": ModelManifest,
                "config": DetectorTrainingConfig,
                "return": ModelManifest,
            },
        ),
    },
    VLMClient: {
        "complete": (
            ("self", "request"),
            {"request": VLMRequest | StructureRepairRequest, "return": VLMResponse},
        ),
    },
    ModelResponseStore: {
        "probe_recovery": (
            ("self", "request"),
            {
                "request": VLMRequest | StructureRepairRequest,
                "return": VLMResponse | None,
            },
        ),
        "recover": (
            ("self", "request"),
            {
                "request": VLMRequest | StructureRepairRequest,
                "return": VLMResponse | None,
            },
        ),
        "acknowledge": (
            ("self", "request", "response"),
            {
                "request": VLMRequest | StructureRepairRequest,
                "response": VLMResponse,
                "return": NONE_TYPE,
            },
        ),
        "read_bytes": (
            ("self", "run_id", "response", "max_bytes"),
            {
                "run_id": str,
                "response": VLMResponse,
                "max_bytes": int,
                "return": bytes,
            },
        ),
        "read_json": (
            ("self", "run_id", "response", "max_bytes"),
            {
                "run_id": str,
                "response": VLMResponse,
                "max_bytes": int,
                "return": str,
            },
        ),
        "verify": (
            ("self", "run_id", "response"),
            {"run_id": str, "response": VLMResponse, "return": VLMResponse},
        ),
    },
    RawModelResponseVerifier: {
        "verify_raw_response": (
            ("self", "run_id", "request", "response"),
            {
                "run_id": str,
                "request": VLMRequest | StructureRepairRequest,
                "response": VLMResponse,
                "return": VLMResponse,
            },
        ),
    },
    VLMResponseCache: {
        "get": (
            ("self", "run_id", "request"),
            {
                "run_id": str,
                "request": VLMRequest | StructureRepairRequest,
                "return": CachedModelResponse | None,
            },
        ),
        "put": (
            ("self", "run_id", "request", "response"),
            {
                "run_id": str,
                "request": VLMRequest | StructureRepairRequest,
                "response": VLMResponse,
                "return": CachedModelResponse,
            },
        ),
    },
    M5PrecedentEmbeddingProvider: {
        "embed": (
            ("self", "request", "payload"),
            {
                "request": M5EmbeddingRequest,
                "payload": bytes,
                "return": M5EmbeddingVector,
            },
        ),
    },
    M5PrecedentPolicyVerifier: {
        "run_mode": (
            ("self",),
            {"return": RunMode},
        ),
        "expected_policy": (
            ("self", "manifest"),
            {
                "manifest": RunManifest,
                "return": M5PrecedentPolicy,
            },
        ),
    },
    M5PrecedentExposureStore: {
        "commit": (
            ("self", "outcome"),
            {
                "outcome": HearingPrecedentRetrievalOutcome,
                "return": HearingPrecedentRetrievalReceipt,
            },
        ),
        "load_exposure": (
            ("self", "run_id", "cycle_scope_id"),
            {
                "run_id": str,
                "cycle_scope_id": str,
                "return": M5PrecedentExposureBatchAuthority | None,
            },
        ),
    },
    M5PrecedentApplicationVerifier: {
        "rebuild_application": (
            ("self", "case_snapshot", "exposure"),
            {
                "case_snapshot": CaseSnapshot,
                "exposure": M5PrecedentExposureBatchAuthority,
                "return": M5PrecedentApplicationBatchAuthority,
            },
        ),
        "rebuild_citations": (
            ("self", "application_batch", "cited_at"),
            {
                "application_batch": M5PrecedentApplicationBatchAuthority,
                "cited_at": datetime,
                "return": tuple[M5PrecedentApplicationCitationCommit, ...],
            },
        ),
    },
    M5PrecedentApplicationRepository: {
        "resolve_ready_precedent_usage": (
            ("self", "run_id", "case_id", "expected_revision"),
            {
                "run_id": str,
                "case_id": str,
                "expected_revision": int,
                "return": M5ReadyPrecedentUsage,
            },
        ),
    },
    M5PrecedentRepository: {
        "get": (
            ("self", "run_id", "precedent_id"),
            {
                "run_id": str,
                "precedent_id": str,
                "return": M5PrecedentAuthority | None,
            },
        ),
        "list_for_retrieval": (
            ("self", "query"),
            {
                "query": M5PrecedentRetrievalQuery,
                "return": tuple[M5PrecedentAuthority, ...],
            },
        ),
        "list_conflicts": (
            ("self", "run_id", "limit"),
            {
                "run_id": str,
                "limit": int,
                "return": tuple[M5PrecedentAuthority, ...],
            },
        ),
        "load_conflict_snapshot": (
            ("self", "run_id", "limit"),
            {
                "run_id": str,
                "limit": int,
                "return": M5PrecedentConflictSnapshot,
            },
        ),
        "list_activation_candidates": (
            ("self", "run_id", "evaluated_at", "limit"),
            {
                "run_id": str,
                "evaluated_at": datetime,
                "limit": int,
                "return": tuple[M5PrecedentAuthority, ...],
            },
        ),
        "load_appeal_window_snapshot": (
            ("self", "run_id", "source_case_id", "observed_through"),
            {
                "run_id": str,
                "source_case_id": str,
                "observed_through": datetime,
                "return": M5AppealWindowSnapshot,
            },
        ),
        "append_authority": (
            ("self", "authority", "expected_revision"),
            {
                "authority": M5PrecedentAuthority,
                "expected_revision": int | None,
                "return": M5PrecedentAuthority,
            },
        ),
        "append_authorities": (
            ("self", "run_id", "authorities"),
            {
                "run_id": str,
                "authorities": tuple[M5PrecedentAuthority, ...],
                "return": tuple[M5PrecedentAuthority, ...],
            },
        ),
        "commit_citation": (
            ("self", "commit"),
            {
                "commit": M5PrecedentCitationCommit,
                "return": M5PrecedentCitationCommit,
            },
        ),
        "commit_activation": (
            ("self", "result"),
            {
                "result": M5PrecedentActivationResult,
                "return": M5PrecedentActivationResult,
            },
        ),
        "citation_snapshot": (
            ("self", "run_id", "precedent_id"),
            {
                "run_id": str,
                "precedent_id": str,
                "return": M5PrecedentCitationSnapshot,
            },
        ),
        "commit_conflict_batch": (
            ("self", "resolution"),
            {
                "resolution": M5PrecedentConflictBatchResolution,
                "return": M5PrecedentConflictBatchResolution,
            },
        ),
        "commit_revocation": (
            ("self", "result"),
            {
                "result": M5PrecedentRevocationResult,
                "return": M5PrecedentRevocationResult,
            },
        ),
    },
    M6UpgradeSampleArtifactVerifier: {
        "verify_m6_upgrade_sample_artifacts": (
            ("self", "record"),
            {
                "record": M6UpgradeSampleExecutionRecord,
                "return": tuple[M6UpgradePhysicalArtifactRef, ...],
            },
        ),
    },
    M6UpgradeExecutionLedgerRepository: {
        "begin_execution": (
            ("self", "scope"),
            {
                "scope": M6UpgradeExecutionScopeAuthority,
                "return": M6UpgradeExecutionScopeAuthority,
            },
        ),
        "resume": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionResume,
            },
        ),
        "append_sample": (
            ("self", "record", "verifier"),
            {
                "record": M6UpgradeSampleExecutionRecord,
                "verifier": M6UpgradeSampleArtifactVerifier | None,
                "return": M6UpgradeSampleExecutionRecord,
            },
        ),
        "seal": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionLedgerSeal,
            },
        ),
        "load_sealed": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionLedgerSeal,
            },
        ),
    },
    M6UpgradeExecutionLedgerV2Repository: {
        "begin_execution": (
            ("self", "scope"),
            {
                "scope": M6UpgradeExecutionScopeAuthority,
                "return": M6UpgradeExecutionScopeAuthority,
            },
        ),
        "resume": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionResumeV2,
            },
        ),
        "append_committed_sample": (
            ("self", "commitment"),
            {
                "commitment": M6UpgradePendingSampleCommitmentAuthority,
                "return": M6UpgradeSampleExecutionRecordV2,
            },
        ),
        "seal": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionLedgerSealV2,
            },
        ),
        "load_sealed": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionLedgerSealV2,
            },
        ),
    },
    M6UpgradeExecutionLedgerV3Repository: {
        "begin_execution": (
            ("self", "scope"),
            {
                "scope": M6UpgradeExecutionScopeAuthority,
                "return": M6UpgradeExecutionScopeAuthority,
            },
        ),
        "resume": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionResumeV3,
            },
        ),
        "append_committed_sample": (
            ("self", "commitment"),
            {
                "commitment": M6UpgradePendingSampleCommitmentAuthority,
                "return": M6UpgradeSampleExecutionRecordV2,
            },
        ),
        "seal": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionLedgerSealV2,
            },
        ),
        "load_sealed": (
            ("self", "run_id", "execution_scope_authority_id"),
            {
                "run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeExecutionLedgerSealV2,
            },
        ),
    },
    M6UpgradeExecutionObservationRepository: {
        "append": (
            ("self", "observation"),
            {
                "observation": M6UpgradeSampleExecutionObservationAuthority,
                "return": M6UpgradeSampleExecutionObservationAuthority,
            },
        ),
        "load": (
            (
                "self",
                "candidate_run_id",
                "execution_scope_authority_id",
                "ledger_sequence",
            ),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "ledger_sequence": int,
                "return": M6UpgradeSampleExecutionObservationAuthority,
            },
        ),
    },
    M6UpgradeExecutionObservationV3Repository: {
        "append": (
            ("self", "observation"),
            {
                "observation": M6UpgradeSampleExecutionObservationAuthorityV2,
                "return": M6UpgradeSampleExecutionObservationAuthorityV2,
            },
        ),
        "load": (
            (
                "self",
                "candidate_run_id",
                "execution_scope_authority_id",
                "ledger_sequence",
            ),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "ledger_sequence": int,
                "return": M6UpgradeSampleExecutionObservationAuthorityV2,
            },
        ),
    },
    M6UpgradePendingSampleCommitmentRepository: {
        "append": (
            ("self", "commitment"),
            {
                "commitment": M6UpgradePendingSampleCommitmentAuthority,
                "return": M6UpgradePendingSampleCommitmentAuthority,
            },
        ),
        "load": (
            (
                "self",
                "candidate_run_id",
                "execution_scope_authority_id",
                "ledger_sequence",
            ),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "ledger_sequence": int,
                "return": M6UpgradePendingSampleCommitmentAuthority,
            },
        ),
    },
    M6UpgradePendingSampleCommitmentV3Repository: {
        "append": (
            ("self", "commitment"),
            {
                "commitment": M6UpgradePendingSampleCommitmentAuthority,
                "return": M6UpgradePendingSampleCommitmentAuthority,
            },
        ),
        "load": (
            (
                "self",
                "candidate_run_id",
                "execution_scope_authority_id",
                "ledger_sequence",
            ),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "ledger_sequence": int,
                "return": M6UpgradePendingSampleCommitmentAuthority,
            },
        ),
    },
    M6UpgradeWholeSampleRecordBuilder: {
        "build_m6_upgrade_sample_record": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeSampleExecutionRecordV2,
            },
        ),
    },
    M6UpgradeDurableSampleAppenderV3: {
        "append_pending_sample": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeSampleExecutionRecordV2,
            },
        ),
    },
    M6UpgradeCandidateObservationProducerV3: {
        "produce_next_observation": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeSampleExecutionObservationAuthorityV2,
            },
        ),
    },
    M6UpgradeCandidatePerceptionMaterializerV3: {
        "materialize_next_perception": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6ResolvedPerception,
            },
        ),
    },
    M6UpgradeCandidateCoordinatorV3: {
        "run_to_terminal": (
            ("self", "execution_scope"),
            {
                "execution_scope": M6UpgradeExecutionScopeAuthority,
                "return": M6UpgradeCandidateOutputInventoryAuthorityV3,
            },
        ),
        "resume_to_terminal": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeCandidateOutputInventoryAuthorityV3,
            },
        ),
    },
    M6UpgradeCandidateRunCutRepository: {
        "build_or_load": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeCandidateRunCutAuthority,
            },
        ),
    },
    M6UpgradeCandidateValidationReportProvider: {
        "load_m6_upgrade_candidate_validation_report": (
            (
                "self",
                "candidate_run_id",
                "audit_head_sequence",
                "audit_head_hash",
            ),
            {
                "candidate_run_id": str,
                "audit_head_sequence": int,
                "audit_head_hash": str,
                "return": M5ArtifactValidationReport,
            },
        ),
    },
    M6RegressionExecutionSourceCatalogPublisher: {
        "publish": (
            ("self", "catalog", "canonical_document"),
            {
                "catalog": M6RegressionExecutionSourceCatalogAuthority,
                "canonical_document": str,
                "return": M6StoredRegressionExecutionSourceCatalog,
            },
        ),
    },
    M6RegressionExecutionSourceCatalogProvider: {
        "load": (
            (
                "self",
                "source_catalog_authority_id",
                "source_catalog_document_sha256",
            ),
            {
                "source_catalog_authority_id": str,
                "source_catalog_document_sha256": str,
                "return": M6StoredRegressionExecutionSourceCatalog,
            },
        ),
    },
    M6ReplayLockedCandidateObservationProvider: {
        "load_candidate_observation": (
            ("self", "candidate_run_id", "sample_id"),
            {
                "candidate_run_id": str,
                "sample_id": str,
                "return": M6ReplayLockedCandidateObservation,
            },
        ),
    },
    M6ReplayLockedCandidatePublisher: {
        "publish_candidate": (
            (
                "self",
                "execution_scope",
                "pending_commitment",
                "candidate",
            ),
            {
                "execution_scope": M6ReplayLockedExecutionScopeAuthority,
                "pending_commitment": M6ReplayLockedPendingSampleCommitmentAuthority,
                "candidate": M6ReplayLockedCandidateWrite,
                "return": type(None),
            },
        ),
    },
    M6ReplayLockedM4CandidatePublisher: {
        "publish_m4_candidate": (
            (
                "self",
                "execution_scope",
                "pending_commitment",
                "candidate",
            ),
            {
                "execution_scope": M6ReplayLockedExecutionScopeAuthority,
                "pending_commitment": M6ReplayLockedPendingSampleCommitmentAuthority,
                "candidate": M6ReplayLockedM4CandidateWrite,
                "return": type(None),
            },
        ),
    },
    M6ReplayLockedStoredCandidateProvider: {
        "load_stored_candidate_case": (
            ("self", "candidate_run_id", "sample_id"),
            {
                "candidate_run_id": str,
                "sample_id": str,
                "return": M6ReplayLockedStoredCandidateCase,
            },
        ),
    },
    M6ReplayLockedCandidateAuditHeadProvider: {
        "load_candidate_audit_head": (
            ("self", "candidate_run_id"),
            {
                "candidate_run_id": str,
                "return": AuditHead,
            },
        ),
    },
    M6ReplayLockedClosedCandidatePublisher: {
        "publish_closed_candidate": (
            ("self", "execution_scope", "pending_commitment", "candidate"),
            {
                "execution_scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
                "pending_commitment": (
                    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2
                ),
                "candidate": M6ReplayLockedClosedCandidateWrite,
                "return": type(None),
            },
        ),
    },
    M6ReplayLockedStoredClosedCandidateProvider: {
        "load_stored_closed_candidate": (
            ("self", "candidate_run_id", "sample_id"),
            {
                "candidate_run_id": str,
                "sample_id": str,
                "return": M6ReplayLockedStoredClosedCandidate,
            },
        ),
    },
    M6ReplayLockedClosedCandidateObservationProvider: {
        "load_closed_candidate_observation": (
            ("self", "candidate_run_id", "sample_id"),
            {
                "candidate_run_id": str,
                "sample_id": str,
                "return": M6ReplayLockedClosedCandidateObservation,
            },
        ),
    },
    M6ReplayLockedClosedCandidateAuditHeadProvider: {
        "load_closed_candidate_audit_head": (
            ("self", "candidate_run_id"),
            {
                "candidate_run_id": str,
                "return": AuditHead,
            },
        ),
    },
    M6ReplayLockedClosedPolicyPrePolicySourceProvider: {
        "load_closed_policy_pre_policy_source": (
            ("self", "closure", "source_binding"),
            {
                "closure": M6ReplayInputClosureAuthority,
                "source_binding": M6ReplayLockedClosedPolicySourceBindingAuthority,
                "return": M6ReplayLockedClosedPolicyPrePolicySource,
            },
        ),
    },
    M6ReplayLockedCoordinator: {
        "run_to_terminal": (
            ("self", "execution_scope", "stored_source_catalog"),
            {
                "execution_scope": M6ReplayLockedExecutionScopeAuthority,
                "stored_source_catalog": M6StoredRegressionExecutionSourceCatalog,
                "return": M6ReplayLockedExecutionSealAuthority,
            },
        ),
    },
    M6ReplayLockedClosedPolicyCoordinator: {
        "run_to_terminal": (
            ("self", "execution_scope", "stored_source_catalog"),
            {
                "execution_scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
                "stored_source_catalog": M6StoredRegressionExecutionSourceCatalog,
                "return": M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
            },
        ),
    },
    M6ReplayLockedSampleExecutor: {
        "execute_sample": (
            (
                "self",
                "execution_scope",
                "pending_commitment",
                "replay_input_closure",
            ),
            {
                "execution_scope": M6ReplayLockedExecutionScopeAuthority,
                "pending_commitment": M6ReplayLockedPendingSampleCommitmentAuthority,
                "replay_input_closure": M6ReplayInputClosureAuthority,
                "return": type(None),
            },
        ),
    },
    M6ReplayLockedFastTerminalSourceProvider: {
        "load_fast_terminal_source": (
            ("self", "closure"),
            {
                "closure": M6ReplayInputClosureAuthority,
                "return": M6ReplayLockedFastTerminalSource,
            },
        ),
    },
    M6ReplayLockedM4GateTerminalSourceProvider: {
        "load_m4_gate_terminal_source": (
            ("self", "closure"),
            {
                "closure": M6ReplayInputClosureAuthority,
                "return": M6ReplayLockedM4GateTerminalSource,
            },
        ),
    },
    M6ReplayLockedSourceProjectionProvider: {
        "load_source_projection": (
            ("self", "closure"),
            {
                "closure": M6ReplayInputClosureAuthority,
                "return": M6ReplayLockedSourceProjection,
            },
        ),
    },
    M6ReplayLockedAlertPolicySourceProvider: {
        "load_alert_policy_source": (
            ("self", "closure"),
            {
                "closure": M6ReplayInputClosureAuthority,
                "return": M6ReplayLockedAlertPolicySourceObservation,
            },
        ),
    },
    M6ReplayLockedExecutionScopePublisher: {
        "publish": (
            ("self", "scope", "canonical_document"),
            {
                "scope": M6ReplayLockedExecutionScopeAuthority,
                "canonical_document": str,
                "return": M6StoredReplayLockedExecutionScope,
            },
        ),
    },
    M6ReplayLockedExecutionScopeProvider: {
        "load": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6StoredReplayLockedExecutionScope,
            },
        ),
    },
    M6ReplayLockedClosedPolicyExecutionScopePublisher: {
        "publish": (
            ("self", "scope", "canonical_document"),
            {
                "scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
                "canonical_document": str,
                "return": M6StoredReplayLockedClosedPolicyExecutionScope,
            },
        ),
    },
    M6ReplayLockedClosedPolicyExecutionScopeProvider: {
        "load": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6StoredReplayLockedClosedPolicyExecutionScope,
            },
        ),
    },
    M6ReplayLockedClosedPolicyLedgerRepository: {
        "resume": (
            ("self", "execution_scope"),
            {
                "execution_scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
                "return": M6ReplayLockedClosedPolicyExecutionResumeV2,
            },
        ),
        "persist_pending": (
            ("self", "execution_scope", "pending_commitment", "canonical_document"),
            {
                "execution_scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
                "pending_commitment": (
                    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2
                ),
                "canonical_document": str,
                "return": M6ReplayLockedClosedPolicyExecutionResumeV2,
            },
        ),
        "append_record": (
            ("self", "execution_scope", "sample_record", "canonical_document"),
            {
                "execution_scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
                "sample_record": M6ReplayLockedClosedPolicySampleExecutionRecordV2,
                "canonical_document": str,
                "return": M6ReplayLockedClosedPolicyExecutionResumeV2,
            },
        ),
        "seal": (
            ("self", "execution_scope", "execution_seal", "canonical_document"),
            {
                "execution_scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
                "execution_seal": M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
                "canonical_document": str,
                "return": M6ReplayLockedClosedPolicyExecutionResumeV2,
            },
        ),
    },
    M6ReplayLockedClosedPolicySampleExecutor: {
        "execute_sample": (
            (
                "self",
                "execution_scope",
                "pending_commitment",
                "replay_input_closure",
            ),
            {
                "execution_scope": M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
                "pending_commitment": (
                    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2
                ),
                "replay_input_closure": M6ReplayInputClosureAuthority,
                "return": type(None),
            },
        ),
    },
    M6ReplayLockedLedgerRepository: {
        "resume": (
            ("self", "execution_scope"),
            {
                "execution_scope": M6ReplayLockedExecutionScopeAuthority,
                "return": M6ReplayLockedExecutionResume,
            },
        ),
        "persist_pending": (
            ("self", "execution_scope", "pending_commitment", "canonical_document"),
            {
                "execution_scope": M6ReplayLockedExecutionScopeAuthority,
                "pending_commitment": M6ReplayLockedPendingSampleCommitmentAuthority,
                "canonical_document": str,
                "return": M6ReplayLockedExecutionResume,
            },
        ),
        "append_record": (
            ("self", "execution_scope", "sample_record", "canonical_document"),
            {
                "execution_scope": M6ReplayLockedExecutionScopeAuthority,
                "sample_record": M6ReplayLockedSampleExecutionRecord,
                "canonical_document": str,
                "return": M6ReplayLockedExecutionResume,
            },
        ),
        "seal": (
            ("self", "execution_scope", "execution_seal", "canonical_document"),
            {
                "execution_scope": M6ReplayLockedExecutionScopeAuthority,
                "execution_seal": M6ReplayLockedExecutionSealAuthority,
                "canonical_document": str,
                "return": M6ReplayLockedExecutionResume,
            },
        ),
    },
    M6UpgradeCandidateOutputBuilder: {
        "build_terminal_inventory": (
            ("self", "candidate_run_id", "execution_scope_authority_id"),
            {
                "candidate_run_id": str,
                "execution_scope_authority_id": str,
                "return": M6UpgradeCandidateOutputInventoryAuthorityV3,
            },
        ),
    },
    M6GateSourceObserver: {
        "observe_m6_gate_source": (
            ("self", "run_id", "case_id", "source_case_revision"),
            {
                "run_id": str,
                "case_id": str,
                "source_case_revision": int | None,
                "return": M6GateSourceObservation,
            },
        ),
    },
}

EXPECTED_ATTRIBUTE_PROTOCOLS = {
    PrecedentQuery: {
        "case_id": str,
        "evidence_class": EvidenceClass,
        "violation_type": ViolationType,
        "rule_version": str,
        "situation_text": str,
    },
    DetectorTrainingConfig: {"strategy": str},
}


def test_port_protocol_inventory_is_explicit() -> None:
    discovered: set[type[object]] = set()
    for module_info in pkgutil.iter_modules(ports_package.__path__):
        module = importlib.import_module(f"{ports_package.__name__}.{module_info.name}")
        discovered.update(
            member
            for _, member in inspect.getmembers(module, inspect.isclass)
            if member.__module__ == module.__name__ and getattr(member, "_is_protocol", False)
        )
    assert discovered == {*EXPECTED_METHODS, *EXPECTED_ATTRIBUTE_PROTOCOLS}


@pytest.mark.parametrize("protocol", [*EXPECTED_METHODS, *EXPECTED_ATTRIBUTE_PROTOCOLS])
def test_capability_boundaries_remain_protocols(protocol: type[object]) -> None:
    assert getattr(protocol, "_is_protocol", False), protocol


@pytest.mark.parametrize("protocol", EXPECTED_METHODS)
def test_port_method_names_and_signatures_are_stable(protocol: type[object]) -> None:
    expected = EXPECTED_METHODS[protocol]
    actual_method_names = {
        name
        for name, member in protocol.__dict__.items()
        if (inspect.isfunction(member) or isinstance(member, property)) and not name.startswith("_")
    }
    assert actual_method_names == set(expected), protocol

    for method_name, (parameter_names, annotations) in expected.items():
        member = protocol.__dict__[method_name]
        method = member.fget if isinstance(member, property) else member
        assert method is not None
        signature = inspect.signature(method)
        assert tuple(signature.parameters) == parameter_names
        if (protocol, method_name) == (PromptCatalog, "render"):
            keyword_only = {"prompt_id", "variables"}
        elif protocol is HearingAcquisitionExecutor and method_name in {
            "execute",
            "recover",
        }:
            keyword_only = {"idempotency_key"}
        elif (protocol, method_name) == (HearingModelResponsePublisher, "publish"):
            keyword_only = {"input_tokens", "output_tokens", "latency_ms"}
        elif (protocol, method_name) == (AlertChannel, "capability_authority"):
            keyword_only = {"run_id", "manifest_id", "config_sha256"}
        else:
            keyword_only = set()
        for name, parameter in signature.parameters.items():
            expected_kind = (
                inspect.Parameter.KEYWORD_ONLY
                if name in keyword_only
                else inspect.Parameter.POSITIONAL_OR_KEYWORD
            )
            assert parameter.kind is expected_kind
        expected_defaults: dict[str, object]
        if (protocol, method_name) == (FrameSource, "get_range"):
            expected_defaults = {"step": 1}
        elif (protocol, method_name) == (
            ScreeningRepository,
            "append_parse_receipt",
        ):
            expected_defaults = {"parsed_output": None}
        elif (protocol, method_name) == (
            ScreeningRepository,
            "commit_backlog",
        ):
            expected_defaults = {"response_ids": (), "model_call_failure": None}
        elif (protocol, method_name) == (
            ScreeningRepository,
            "claim_model_call",
        ):
            expected_defaults = {"backlog_lease": None}
        elif (protocol, method_name) == (
            ScreeningRepository,
            "commit_backlog_retry_failure",
        ):
            expected_defaults = {"model_call_failure": None}
        elif (protocol, method_name) == (
            ScreeningRepository,
            "commit_backlog_verdict_review_success",
        ):
            expected_defaults = {"screening": None}
        elif (protocol, method_name) == (
            HearingRepository,
            "append_hearing_parse_receipt",
        ):
            expected_defaults = {"output": None}
        elif (protocol, method_name) == (
            HearingRepository,
            "claim_hearing_model_call",
        ):
            expected_defaults = {"backlog_lease": None}
        elif (protocol, method_name) == (
            HearingBacklogRepository,
            "commit_hearing_backlog_retry",
        ):
            expected_defaults = {"model_call_failure": None}
        elif (protocol, method_name) == (
            HearingModelResponsePublisher,
            "publish",
        ):
            expected_defaults = {
                "input_tokens": 0,
                "output_tokens": 0,
                "latency_ms": 0,
            }
        elif (protocol, method_name) == (
            AlertPolicyRepository,
            "commit_alert_policy",
        ):
            expected_defaults = {
                "application_batch": None,
                "application_citations": (),
            }
        elif (protocol, method_name) == (
            M6UpgradeExecutionLedgerRepository,
            "append_sample",
        ):
            expected_defaults = {"verifier": None}
        elif (protocol, method_name) == (
            M6GateSourceObserver,
            "observe_m6_gate_source",
        ):
            expected_defaults = {"source_case_revision": None}
        else:
            expected_defaults = {}
        for name, parameter in signature.parameters.items():
            expected_default = expected_defaults.get(name, inspect.Signature.empty)
            assert parameter.default == expected_default
        assert get_type_hints(method) == annotations


@pytest.mark.parametrize("protocol", EXPECTED_ATTRIBUTE_PROTOCOLS)
def test_attribute_only_protocol_contracts_are_stable(protocol: type[object]) -> None:
    assert get_type_hints(protocol) == EXPECTED_ATTRIBUTE_PROTOCOLS[protocol]
