"""Root contracts exported as stable JSON Schema artifacts."""

from __future__ import annotations

from pydantic import BaseModel

from labcourt.contracts.alert_policy import (
    AlertChannelCapabilityAuthority,
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertDispatchAttempt,
    AlertDispatchReceipt,
    AlertOutboxItem,
    AlertPolicyAuthority,
    AlertPolicyRequest,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.alerts import AlertDecision, EmergencySafetyIncident
from labcourt.contracts.appeals import Appeal
from labcourt.contracts.artifact_validation import (
    ArtifactValidationReport,
    M3ArtifactValidationReport,
)
from labcourt.contracts.audit import AuditChainReport, AuditEntry
from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryContext,
    BacklogRetryFailure,
    BacklogRetryReport,
    BacklogRetrySuccess,
    BacklogStrictParseFailureProof,
)
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import AssociationResult, FrameBundle
from labcourt.contracts.events import CandidateEvent, SafetySignal
from labcourt.contracts.evidence import (
    Crop,
    CropRequest,
    EvidencePack,
    ObservabilityScore,
    PrivacyReceipt,
    ToolResult,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing import (
    AcquisitionExecutionClaimAuthority,
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    AcquisitionRequestPayload,
    DefenderModelPayload,
    EvidencePackDerivation,
    HearingBacklogCompletionReceipt,
    HearingBacklogRetryFailure,
    HearingBacklogRetrySuccess,
    HearingCheckpoint,
    HearingCycleScope,
    HearingHumanReviewReceipt,
    HearingInitialStrictParseFailureProof,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingModelResponseRecoveryReport,
    HearingPrecedentRetrievalOutcome,
    HearingPrecedentRetrievalQuery,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalResult,
    HearingRecord,
    HearingReworkReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
    HearingUnknownReferenceAttempt,
    HearingUsageReceipt,
    HearingVerdictBinding,
    JudgeModelPayload,
    ProsecutorModelPayload,
    ToolExecutionManifest,
    ToolExecutionReceipt,
)
from labcourt.contracts.m3_command_reports import (
    M3BacklogRetryCommandReport,
    M3ProcessCommandReport,
)
from labcourt.contracts.m3_models import (
    EvidenceCitation,
    PrecedentLookupQuery,
    PrecedentResolution,
    PromptManifest,
)
from labcourt.contracts.m3_operations import FakeVLMFixtureBundle, M3ProcessReport
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m4_operations import (
    M4BacklogRetryCommandReport,
    M4BacklogRetryReport,
    M4FakeVLMFixtureBundle,
    M4ProcessCommandReport,
    M4ProcessReport,
)
from labcourt.contracts.m4_projection import (
    M4ProjectionCurrentPointer,
    M4ProjectionGenerationManifest,
)
from labcourt.contracts.m5_appeal_operations import (
    M5AppealResolutionCommandReport,
    M5AppealReviewCommandReport,
    M5AppealSubmissionCommandReport,
)
from labcourt.contracts.m5_appeals import (
    AffectedCitationReport,
    AppealResolutionCommand,
    AppealResolutionPrecedentSnapshot,
    AppealResolutionSideEffectIntent,
    AppealReviewCommand,
    AppealSubmissionCommand,
    AppealVersionAuthority,
    ClosedCaseAppealAuthority,
    M5AppealResolutionCommitReceipt,
)
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m5_human_inputs import M5AppealTrainingLabelInput
from labcourt.contracts.m5_operations import (
    M5CloseCaseOutcome,
    M5DispatchCommandReport,
    M5FinalizeCommandReport,
    M5PrecedentActivationCommandReport,
    M5PrecedentConflictCommandReport,
    M5PrecedentImportReport,
)
from labcourt.contracts.m5_precedent_causal_ledger import M5PrecedentCausalEvent
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
    M5PrecedentExposureBatchAuthority,
)
from labcourt.contracts.m5_precedents import (
    M5AppealWindowSnapshot,
    M5EmbeddingRequest,
    M5EmbeddingVector,
    M5PrecedentActivationReceipt,
    M5PrecedentActivationResult,
    M5PrecedentAuthority,
    M5PrecedentCandidateEvaluation,
    M5PrecedentCitationAuthority,
    M5PrecedentCitationCommit,
    M5PrecedentCitationSnapshot,
    M5PrecedentConflictBatchAuthority,
    M5PrecedentConflictBatchReceipt,
    M5PrecedentConflictBatchResolution,
    M5PrecedentConflictCausalCut,
    M5PrecedentConflictReceipt,
    M5PrecedentConflictResolution,
    M5PrecedentConflictSnapshot,
    M5PrecedentPolicy,
    M5PrecedentRetrievalQuery,
    M5PrecedentRetrievalResult,
    M5PrecedentRevocationReceipt,
    M5PrecedentRevocationResult,
)
from labcourt.contracts.m5_projection import (
    M5ProjectionCurrentPointer,
    M5ProjectionGenerationManifest,
)
from labcourt.contracts.m5_training import (
    CocoDatasetExportCommand,
    DatasetExportReport,
    TrainingCropAuthority,
)
from labcourt.contracts.m5_training_history import (
    M5DatasetCropSnapshotAuthority,
    M5DatasetLabelSnapshotReceipt,
    M5DatasetRegistrationSnapshotAuthority,
    M5TrainingCausalEvent,
    M5TrainingCausalWatermark,
)
from labcourt.contracts.m5_training_provenance import (
    M5StrongTrainingLabelProvenanceReceipt,
    M5TrainingLabelAuthority,
)
from labcourt.contracts.m6_demo import (
    M6OfflineDemoManifestAuthorityV1,
    M6OfflineDemoScenarioArtifactReceiptV1,
    M6OfflineDemoScenarioResultAuthorityV1,
)
from labcourt.contracts.m6_demo_publication import M6OfflineDemoPublicationSealAuthorityV1
from labcourt.contracts.m6_regression import (
    M6CaseReplaySnapshot,
    M6RegressionDatasetSnapshot,
    M6RegressionExecutionDatasetSnapshot,
    M6RegressionReport,
    M6RegressionRunCommand,
)
from labcourt.contracts.m6_regression_dataset import (
    M6RegressionExecutionSourceCatalogAuthority,
    M6RegressionSourceInventoryCutAuthority,
)
from labcourt.contracts.m6_regression_execution import (
    M6UpgradeCandidateOutputInventoryAuthority,
    M6UpgradeCandidateOutputInventoryAuthorityV2,
    M6UpgradeCandidateOutputInventoryAuthorityV3,
    M6UpgradeCandidateRunCutAuthority,
    M6UpgradeCandidateSampleOutputAuthority,
)
from labcourt.contracts.m6_regression_gold import M6AppealGoldTruthAuthority
from labcourt.contracts.m6_regression_publication import M6RegressionPublicationSeal
from labcourt.contracts.m6_regression_selection import (
    M6ChallengeDesignationAuthority,
    M6RegressionEligibilityPolicyAuthority,
    M6RegressionSelectionInventoryAuthority,
    M6RegressionSelectionReceipt,
    M6SyntheticChallengeScenarioAuthority,
)
from labcourt.contracts.m6_replay_locked import (
    M6ProviderTrapAuthority,
    M6ReplayInputClosureAuthority,
    M6ReplayLockedSourceDeterminismAuthority,
)
from labcourt.contracts.m6_replay_locked_closed_policy_execution import (
    M6ReplayLockedClosedCandidateBindingAuthority,
    M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2,
    M6ReplayLockedClosedPolicyExecutionSealAuthorityV2,
    M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2,
    M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2,
    M6ReplayLockedClosedPolicySampleExecutionRecordV2,
    M6ReplayLockedClosedPolicySourceBindingAuthority,
)
from labcourt.contracts.m6_replay_locked_closed_policy_publication import (
    M6ReplayLockedClosedPolicyPublicationSealAuthorityV2,
)
from labcourt.contracts.m6_replay_locked_execution import (
    M6ReplayLockedCandidateCaseBinding,
    M6ReplayLockedExecutionComponentAuthority,
    M6ReplayLockedExecutionScopeAuthority,
    M6ReplayLockedExecutionSealAuthority,
    M6ReplayLockedPendingSampleCommitmentAuthority,
    M6ReplayLockedRunTrapSealAuthority,
    M6ReplayLockedSampleExecutionRecord,
)
from labcourt.contracts.m6_replay_locked_policy import (
    M6ReplayLockedAlertPolicyCausalCutAuthority,
)
from labcourt.contracts.m6_source_authority import M6ReplayInputAuthority
from labcourt.contracts.m6_source_authority_store import M6SourceAuthoritySeal
from labcourt.contracts.m6_static_report import (
    M6PrivacySafeStaticReportManifestAuthorityV1,
)
from labcourt.contracts.m6_static_report_publication import (
    M6PrivacySafeStaticReportPublicationSealAuthorityV1,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionComponentAuthority,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecord,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.contracts.m8_access_cases import (
    M8ActorAuthorityV1,
    M8AuthorityReference,
    M8OperationalCaseAuditIntentV1,
    M8OperationalCaseCreateCommandV1,
    M8OperationalCaseTransitionCommandV1,
)
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseAuditEventV1,
    M8OperationalCaseAuthorityV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_inventory_persistence import (
    M8CampusTopologyCommitReceiptV1,
    M8OperationalSourceCatalogCommitReceiptV1,
)
from labcourt.contracts.m8_operations import (
    M8CampusLocation,
    M8CampusTopologyAuthorityV1,
    M8OperationalSource,
    M8OperationalSourceCatalogAuthorityV1,
)
from labcourt.contracts.m8_sensor_persistence import (
    M8SensorPollCacheCommitReceiptV1,
    M8SensorSampleCommitReceiptV1,
)
from labcourt.contracts.m8_sensor_signals import (
    M8SensorAdapterCapabilityAuthorityV1,
    M8SensorPollRequestV1,
    M8SensorPollResultV1,
    M8SensorRiskAssessmentV1,
    M8SensorRiskPolicyAuthorityV1,
    M8SensorSample,
    M8SimulatedSensorScenarioAuthorityV1,
)
from labcourt.contracts.manifests import RunManifest, StreamManifest
from labcourt.contracts.model_call_failures import ModelCallFailureAuthority
from labcourt.contracts.model_response_recovery import (
    MaintenanceRecoveryReport,
    ModelResponseRecoveryReport,
)
from labcourt.contracts.pilot import (
    PilotA2Report,
    PilotA3Report,
    PilotA4CloseReport,
    PilotEvidencePackSummary,
    PilotPerceptionArtifactReceipt,
    PilotPerceptionCompletionManifest,
    PilotPerceptionExecutionManifest,
    PilotPerceptionFrameReceipt,
    PilotPerceptionReport,
    PilotPerceptionWorkerFailure,
    PilotPerceptionWorkerReady,
    PilotPerceptionWorkerRequest,
    PilotPerceptionWorkerResponse,
    PilotPerceptionWorkerStartupFailure,
    PilotRunRequest,
)
from labcourt.contracts.pilot_a5 import PilotA5RunReport
from labcourt.contracts.pilot_report import (
    PilotA4CaseView,
    PilotA4MediaView,
    PilotA4Metrics,
    PilotA4ModelVersion,
    PilotA4PublicationReport,
    PilotA4ReviewReport,
    PilotLocalAlertDocument,
)
from labcourt.contracts.pilot_ui import (
    PilotUiDashboard,
    PilotUiErrorResponse,
    PilotUiJobStartRequest,
    PilotUiJobStatus,
)
from labcourt.contracts.precedents import Precedent
from labcourt.contracts.projection_generation import (
    ProjectionCurrentPointer,
    ProjectionGenerationManifest,
)
from labcourt.contracts.recovery import RecoveryReport, StartupRecoveryReport
from labcourt.contracts.reminders import SoftReminder
from labcourt.contracts.screening import (
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningModelPayload,
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
from labcourt.contracts.training import TrainingLabel
from labcourt.contracts.verdicts import ProceduralDefect, ProceduralReview, Verdict

SCHEMA_VERSION = "2.0.0"

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "acquisition-execution-claim-authority": AcquisitionExecutionClaimAuthority,
    "acquisition-execution-publication": AcquisitionExecutionPublication,
    "acquisition-request": AcquisitionRequest,
    "acquisition-request-payload": AcquisitionRequestPayload,
    "alert-channel-capability-authority": AlertChannelCapabilityAuthority,
    "alert-cooldown-authority": AlertCooldownAuthority,
    "alert-cooldown-key": AlertCooldownKey,
    "alert-decision": AlertDecision,
    "alert-dispatch-attempt": AlertDispatchAttempt,
    "alert-dispatch-receipt": AlertDispatchReceipt,
    "alert-outbox-item": AlertOutboxItem,
    "alert-policy-authority": AlertPolicyAuthority,
    "alert-policy-request": AlertPolicyRequest,
    "affected-citation-report": AffectedCitationReport,
    "appeal": Appeal,
    "appeal-resolution-command": AppealResolutionCommand,
    "appeal-resolution-precedent-snapshot": AppealResolutionPrecedentSnapshot,
    "appeal-resolution-side-effect-intent": AppealResolutionSideEffectIntent,
    "appeal-review-command": AppealReviewCommand,
    "appeal-submission-command": AppealSubmissionCommand,
    "appeal-version-authority": AppealVersionAuthority,
    "app-config": AppConfig,
    "association-result": AssociationResult,
    "artifact-ref": ArtifactRef,
    "artifact-validation-report": ArtifactValidationReport,
    "m3-artifact-validation-report": M3ArtifactValidationReport,
    "m4-artifact-validation-report": M4ArtifactValidationReport,
    "artifact-verification": ArtifactVerification,
    "audit-chain-report": AuditChainReport,
    "audit-entry": AuditEntry,
    "backlog-item": BacklogItem,
    "backlog-completion-receipt": BacklogCompletionReceipt,
    "backlog-lease-identity": BacklogLeaseIdentity,
    "backlog-retry-context": BacklogRetryContext,
    "backlog-retry-failure": BacklogRetryFailure,
    "backlog-retry-report": BacklogRetryReport,
    "backlog-retry-success": BacklogRetrySuccess,
    "backlog-strict-parse-failure-proof": BacklogStrictParseFailureProof,
    "candidate-event": CandidateEvent,
    "case": Case,
    "closure-report": ClosureReport,
    "closed-case-appeal-authority": ClosedCaseAppealAuthority,
    "coco-dataset-export-command": CocoDatasetExportCommand,
    "crop": Crop,
    "crop-request": CropRequest,
    "defender-model-payload": DefenderModelPayload,
    "dataset-export-report": DatasetExportReport,
    "evidence-citation": EvidenceCitation,
    "evidence-pack": EvidencePack,
    "evidence-pack-derivation": EvidencePackDerivation,
    "emergency-safety-incident": EmergencySafetyIncident,
    "frame-bundle": FrameBundle,
    "frame-ref": FrameRef,
    "hearing-backlog-completion-receipt": HearingBacklogCompletionReceipt,
    "hearing-backlog-retry-failure": HearingBacklogRetryFailure,
    "hearing-backlog-retry-success": HearingBacklogRetrySuccess,
    "hearing-checkpoint": HearingCheckpoint,
    "hearing-cycle-scope": HearingCycleScope,
    "hearing-human-review-receipt": HearingHumanReviewReceipt,
    "hearing-initial-strict-parse-failure-proof": HearingInitialStrictParseFailureProof,
    "hearing-model-cache-entry": HearingModelCacheEntry,
    "hearing-model-call-failure-authority": HearingModelCallFailureAuthority,
    "hearing-model-parse-receipt": HearingModelParseReceipt,
    "hearing-model-request": HearingModelRequest,
    "hearing-model-response": HearingModelResponse,
    "hearing-model-response-recovery-report": HearingModelResponseRecoveryReport,
    "hearing-precedent-retrieval-outcome": HearingPrecedentRetrievalOutcome,
    "hearing-precedent-retrieval-query": HearingPrecedentRetrievalQuery,
    "hearing-precedent-retrieval-receipt": HearingPrecedentRetrievalReceipt,
    "hearing-precedent-retrieval-result": HearingPrecedentRetrievalResult,
    "hearing-record": HearingRecord,
    "hearing-rework-receipt": HearingReworkReceipt,
    "hearing-role-output": HearingRoleOutput,
    "hearing-round": HearingRound,
    "hearing-session": HearingSession,
    "hearing-strict-parse-failure-attempt": HearingStrictParseFailureAttempt,
    "hearing-strict-parse-failure-proof": HearingStrictParseFailureProof,
    "hearing-usage-receipt": HearingUsageReceipt,
    "hearing-unknown-reference-attempt": HearingUnknownReferenceAttempt,
    "hearing-verdict-binding": HearingVerdictBinding,
    "immediate-safety-delivery-authority": ImmediateSafetyDeliveryAuthority,
    "judge-model-payload": JudgeModelPayload,
    "fake-vlm-fixture-bundle": FakeVLMFixtureBundle,
    "maintenance-recovery-report": MaintenanceRecoveryReport,
    "m3-backlog-retry-command-report": M3BacklogRetryCommandReport,
    "m3-process-command-report": M3ProcessCommandReport,
    "m3-process-report": M3ProcessReport,
    "m4-projection-current-pointer": M4ProjectionCurrentPointer,
    "m4-projection-generation-manifest": M4ProjectionGenerationManifest,
    "m4-backlog-retry-command-report": M4BacklogRetryCommandReport,
    "m4-backlog-retry-report": M4BacklogRetryReport,
    "m4-fake-vlm-fixture-bundle": M4FakeVLMFixtureBundle,
    "m4-process-command-report": M4ProcessCommandReport,
    "m4-process-report": M4ProcessReport,
    "m5-close-case-outcome": M5CloseCaseOutcome,
    "m5-dispatch-command-report": M5DispatchCommandReport,
    "m5-dataset-crop-snapshot-authority": M5DatasetCropSnapshotAuthority,
    "m5-dataset-label-snapshot-receipt": M5DatasetLabelSnapshotReceipt,
    "m5-dataset-registration-snapshot-authority": M5DatasetRegistrationSnapshotAuthority,
    "m5-finalize-command-report": M5FinalizeCommandReport,
    "m5-appeal-training-label-input": M5AppealTrainingLabelInput,
    "m5-precedent-activation-command-report": M5PrecedentActivationCommandReport,
    "m5-precedent-conflict-command-report": M5PrecedentConflictCommandReport,
    "m5-precedent-import-report": M5PrecedentImportReport,
    "m5-appeal-window-snapshot": M5AppealWindowSnapshot,
    "m5-appeal-resolution-commit-receipt": M5AppealResolutionCommitReceipt,
    "m5-artifact-validation-report": M5ArtifactValidationReport,
    "m5-appeal-resolution-command-report": M5AppealResolutionCommandReport,
    "m5-appeal-review-command-report": M5AppealReviewCommandReport,
    "m5-appeal-submission-command-report": M5AppealSubmissionCommandReport,
    "m5-embedding-request": M5EmbeddingRequest,
    "m5-embedding-vector": M5EmbeddingVector,
    "m5-precedent-activation-receipt": M5PrecedentActivationReceipt,
    "m5-precedent-activation-result": M5PrecedentActivationResult,
    "m5-precedent-application-batch-authority": M5PrecedentApplicationBatchAuthority,
    "m5-precedent-application-citation-commit": M5PrecedentApplicationCitationCommit,
    "m5-precedent-authority": M5PrecedentAuthority,
    "m5-precedent-causal-event": M5PrecedentCausalEvent,
    "m5-precedent-candidate-evaluation": M5PrecedentCandidateEvaluation,
    "m5-precedent-citation-authority": M5PrecedentCitationAuthority,
    "m5-precedent-citation-commit": M5PrecedentCitationCommit,
    "m5-precedent-citation-snapshot": M5PrecedentCitationSnapshot,
    "m5-precedent-conflict-batch-authority": M5PrecedentConflictBatchAuthority,
    "m5-precedent-conflict-batch-receipt": M5PrecedentConflictBatchReceipt,
    "m5-precedent-conflict-batch-resolution": M5PrecedentConflictBatchResolution,
    "m5-precedent-conflict-causal-cut": M5PrecedentConflictCausalCut,
    "m5-precedent-conflict-receipt": M5PrecedentConflictReceipt,
    "m5-precedent-conflict-resolution": M5PrecedentConflictResolution,
    "m5-precedent-conflict-snapshot": M5PrecedentConflictSnapshot,
    "m5-precedent-exposure-batch-authority": M5PrecedentExposureBatchAuthority,
    "m5-precedent-policy": M5PrecedentPolicy,
    "m5-precedent-retrieval-query": M5PrecedentRetrievalQuery,
    "m5-precedent-retrieval-result": M5PrecedentRetrievalResult,
    "m5-precedent-revocation-receipt": M5PrecedentRevocationReceipt,
    "m5-precedent-revocation-result": M5PrecedentRevocationResult,
    "m5-projection-current-pointer": M5ProjectionCurrentPointer,
    "m5-projection-generation-manifest": M5ProjectionGenerationManifest,
    "m5-strong-training-label-provenance-receipt": M5StrongTrainingLabelProvenanceReceipt,
    "m5-training-label-authority": M5TrainingLabelAuthority,
    "m5-training-causal-event": M5TrainingCausalEvent,
    "m5-training-causal-watermark": M5TrainingCausalWatermark,
    "m6-case-replay-snapshot": M6CaseReplaySnapshot,
    "m6-appeal-gold-truth-authority": M6AppealGoldTruthAuthority,
    "m6-challenge-designation-authority": M6ChallengeDesignationAuthority,
    "m6-provider-trap-authority": M6ProviderTrapAuthority,
    "m6-replay-input-authority": M6ReplayInputAuthority,
    "m6-replay-input-closure-authority": M6ReplayInputClosureAuthority,
    "m6-replay-locked-source-determinism-authority": (M6ReplayLockedSourceDeterminismAuthority),
    "m6-replay-locked-execution-component-authority": (M6ReplayLockedExecutionComponentAuthority),
    "m6-replay-locked-candidate-case-binding": M6ReplayLockedCandidateCaseBinding,
    "m6-replay-locked-execution-seal-authority": M6ReplayLockedExecutionSealAuthority,
    "m6-replay-locked-execution-scope-authority": M6ReplayLockedExecutionScopeAuthority,
    "m6-replay-locked-pending-sample-commitment": (M6ReplayLockedPendingSampleCommitmentAuthority),
    "m6-replay-locked-run-trap-seal-authority": M6ReplayLockedRunTrapSealAuthority,
    "m6-replay-locked-sample-execution-record": M6ReplayLockedSampleExecutionRecord,
    "m6-replay-locked-alert-policy-causal-cut": (M6ReplayLockedAlertPolicyCausalCutAuthority),
    "m6-replay-locked-closed-policy-execution-component-authority-v2": (
        M6ReplayLockedClosedPolicyExecutionComponentAuthorityV2
    ),
    "m6-replay-locked-closed-candidate-binding-authority": (
        M6ReplayLockedClosedCandidateBindingAuthority
    ),
    "m6-replay-locked-closed-policy-execution-seal-authority-v2": (
        M6ReplayLockedClosedPolicyExecutionSealAuthorityV2
    ),
    "m6-replay-locked-closed-policy-execution-scope-authority-v2": (
        M6ReplayLockedClosedPolicyExecutionScopeAuthorityV2
    ),
    "m6-replay-locked-closed-policy-publication-seal-authority-v2": (
        M6ReplayLockedClosedPolicyPublicationSealAuthorityV2
    ),
    "m6-replay-locked-closed-policy-pending-sample-commitment-v2": (
        M6ReplayLockedClosedPolicyPendingSampleCommitmentAuthorityV2
    ),
    "m6-replay-locked-closed-policy-source-binding-authority": (
        M6ReplayLockedClosedPolicySourceBindingAuthority
    ),
    "m6-replay-locked-closed-policy-run-trap-seal-authority-v2": (
        M6ReplayLockedClosedPolicyRunTrapSealAuthorityV2
    ),
    "m6-replay-locked-closed-policy-sample-execution-record-v2": (
        M6ReplayLockedClosedPolicySampleExecutionRecordV2
    ),
    "m6-source-authority-seal": M6SourceAuthoritySeal,
    "m6-offline-demo-manifest-authority-v1": M6OfflineDemoManifestAuthorityV1,
    "m6-offline-demo-publication-seal-authority-v1": (M6OfflineDemoPublicationSealAuthorityV1),
    "m6-offline-demo-scenario-artifact-receipt-v1": (M6OfflineDemoScenarioArtifactReceiptV1),
    "m6-offline-demo-scenario-result-authority-v1": (M6OfflineDemoScenarioResultAuthorityV1),
    "m6-regression-dataset-snapshot": M6RegressionDatasetSnapshot,
    "m6-regression-eligibility-policy": M6RegressionEligibilityPolicyAuthority,
    "m6-regression-execution-source-catalog": M6RegressionExecutionSourceCatalogAuthority,
    "m6-regression-execution-dataset-snapshot": M6RegressionExecutionDatasetSnapshot,
    "m6-regression-report": M6RegressionReport,
    "m6-regression-publication-seal": M6RegressionPublicationSeal,
    "m6-regression-run-command": M6RegressionRunCommand,
    "m6-regression-source-inventory-cut": M6RegressionSourceInventoryCutAuthority,
    "m6-regression-selection-inventory": M6RegressionSelectionInventoryAuthority,
    "m6-regression-selection-receipt": M6RegressionSelectionReceipt,
    "m6-privacy-safe-static-report-manifest-authority-v1": (
        M6PrivacySafeStaticReportManifestAuthorityV1
    ),
    "m6-privacy-safe-static-report-publication-seal-authority-v1": (
        M6PrivacySafeStaticReportPublicationSealAuthorityV1
    ),
    "m6-synthetic-challenge-scenario-authority": (M6SyntheticChallengeScenarioAuthority),
    "m6-upgrade-candidate-output-inventory-authority": (M6UpgradeCandidateOutputInventoryAuthority),
    "m6-upgrade-candidate-output-inventory-authority-v2": (
        M6UpgradeCandidateOutputInventoryAuthorityV2
    ),
    "m6-upgrade-candidate-output-inventory-authority-v3": (
        M6UpgradeCandidateOutputInventoryAuthorityV3
    ),
    "m6-upgrade-candidate-run-cut-authority": M6UpgradeCandidateRunCutAuthority,
    "m6-upgrade-candidate-sample-output-authority": (M6UpgradeCandidateSampleOutputAuthority),
    "m6-upgrade-execution-component-authority": M6UpgradeExecutionComponentAuthority,
    "m6-upgrade-execution-ledger-seal": M6UpgradeExecutionLedgerSeal,
    "m6-upgrade-execution-ledger-seal-v2": M6UpgradeExecutionLedgerSealV2,
    "m6-upgrade-sample-execution-observation-authority": (
        M6UpgradeSampleExecutionObservationAuthority
    ),
    "m6-upgrade-sample-execution-observation-authority-v2": (
        M6UpgradeSampleExecutionObservationAuthorityV2
    ),
    "m6-upgrade-selected-case-audit-anchor": M6UpgradeSelectedCaseAuditAnchor,
    "m6-upgrade-execution-scope-authority": M6UpgradeExecutionScopeAuthority,
    "m6-upgrade-physical-artifact-ref": M6UpgradePhysicalArtifactRef,
    "m6-upgrade-pending-sample-commitment-authority": (M6UpgradePendingSampleCommitmentAuthority),
    "m6-upgrade-sample-execution-record": M6UpgradeSampleExecutionRecord,
    "m6-upgrade-sample-execution-record-v2": M6UpgradeSampleExecutionRecordV2,
    "model-cache-entry": ModelCacheEntry,
    "m8-campus-location": M8CampusLocation,
    "m8-campus-topology-authority-v1": M8CampusTopologyAuthorityV1,
    "m8-campus-topology-commit-receipt-v1": M8CampusTopologyCommitReceiptV1,
    "m8-actor-authority-v1": M8ActorAuthorityV1,
    "m8-actor-authority-commit-receipt-v1": M8ActorAuthorityCommitReceiptV1,
    "m8-authority-reference": M8AuthorityReference,
    "m8-operational-case-audit-intent-v1": M8OperationalCaseAuditIntentV1,
    "m8-operational-case-audit-event-v1": M8OperationalCaseAuditEventV1,
    "m8-operational-case-authority-v1": M8OperationalCaseAuthorityV1,
    "m8-operational-case-commit-receipt-v1": M8OperationalCaseCommitReceiptV1,
    "m8-operational-case-create-command-v1": M8OperationalCaseCreateCommandV1,
    "m8-operational-case-transition-command-v1": M8OperationalCaseTransitionCommandV1,
    "m8-operational-source": M8OperationalSource,
    "m8-operational-source-catalog-authority-v1": M8OperationalSourceCatalogAuthorityV1,
    "m8-operational-source-catalog-commit-receipt-v1": (M8OperationalSourceCatalogCommitReceiptV1),
    "m8-sensor-adapter-capability-authority-v1": M8SensorAdapterCapabilityAuthorityV1,
    "m8-sensor-poll-request-v1": M8SensorPollRequestV1,
    "m8-sensor-poll-result-v1": M8SensorPollResultV1,
    "m8-sensor-poll-cache-commit-receipt-v1": M8SensorPollCacheCommitReceiptV1,
    "m8-sensor-risk-assessment-v1": M8SensorRiskAssessmentV1,
    "m8-sensor-risk-policy-authority-v1": M8SensorRiskPolicyAuthorityV1,
    "m8-sensor-sample": M8SensorSample,
    "m8-sensor-sample-commit-receipt-v1": M8SensorSampleCommitReceiptV1,
    "m8-simulated-sensor-scenario-authority-v1": M8SimulatedSensorScenarioAuthorityV1,
    "model-call-failure-authority": ModelCallFailureAuthority,
    "model-parse-receipt": ModelParseReceipt,
    "model-response-recovery-report": ModelResponseRecoveryReport,
    "observability-score": ObservabilityScore,
    "parsed-screening-output": ParsedScreeningOutput,
    "pilot-a2-report": PilotA2Report,
    "pilot-a3-report": PilotA3Report,
    "pilot-a4-close-report": PilotA4CloseReport,
    "pilot-a4-case-view": PilotA4CaseView,
    "pilot-a4-media-view": PilotA4MediaView,
    "pilot-a4-metrics": PilotA4Metrics,
    "pilot-a4-model-version": PilotA4ModelVersion,
    "pilot-a4-publication-report": PilotA4PublicationReport,
    "pilot-a4-review-report": PilotA4ReviewReport,
    "pilot-a5-run-report": PilotA5RunReport,
    "pilot-local-alert-document": PilotLocalAlertDocument,
    "pilot-evidence-pack-summary": PilotEvidencePackSummary,
    "pilot-perception-artifact-receipt": PilotPerceptionArtifactReceipt,
    "pilot-perception-completion-manifest": PilotPerceptionCompletionManifest,
    "pilot-perception-execution-manifest": PilotPerceptionExecutionManifest,
    "pilot-perception-frame-receipt": PilotPerceptionFrameReceipt,
    "pilot-perception-report": PilotPerceptionReport,
    "pilot-perception-worker-failure": PilotPerceptionWorkerFailure,
    "pilot-perception-worker-ready": PilotPerceptionWorkerReady,
    "pilot-perception-worker-request": PilotPerceptionWorkerRequest,
    "pilot-perception-worker-response": PilotPerceptionWorkerResponse,
    "pilot-perception-worker-startup-failure": PilotPerceptionWorkerStartupFailure,
    "pilot-run-request": PilotRunRequest,
    "pilot-ui-dashboard": PilotUiDashboard,
    "pilot-ui-error-response": PilotUiErrorResponse,
    "pilot-ui-job-start-request": PilotUiJobStartRequest,
    "pilot-ui-job-status": PilotUiJobStatus,
    "precedent": Precedent,
    "precedent-lookup-query": PrecedentLookupQuery,
    "precedent-resolution": PrecedentResolution,
    "projection-current-pointer": ProjectionCurrentPointer,
    "projection-generation-manifest": ProjectionGenerationManifest,
    "privacy-receipt": PrivacyReceipt,
    "prosecutor-model-payload": ProsecutorModelPayload,
    "procedural-defect": ProceduralDefect,
    "procedural-review": ProceduralReview,
    "prompt-manifest": PromptManifest,
    "purge-item-result": PurgeItemResult,
    "recovery-report": RecoveryReport,
    "retention-hold": RetentionHold,
    "resolved-app-config": AppConfig,
    "run-manifest": RunManifest,
    "safety-signal": SafetySignal,
    "screening-result": ScreeningResult,
    "screening-model-payload": ScreeningModelPayload,
    "soft-reminder": SoftReminder,
    "stream-manifest": StreamManifest,
    "startup-recovery-report": StartupRecoveryReport,
    "structure-repair-request": StructureRepairRequest,
    "training-label": TrainingLabel,
    "training-crop-authority": TrainingCropAuthority,
    "tool-execution-manifest": ToolExecutionManifest,
    "tool-execution-receipt": ToolExecutionReceipt,
    "tool-result": ToolResult,
    "verdict": Verdict,
    "vlm-request": VLMRequest,
    "vlm-response": VLMResponse,
}

# AppConfig and ScreeningModelPayload validate authored/provider JSON input. Other
# schemas describe persisted wire artifacts, including read-only computed identities.
SCHEMA_VALIDATION_MODELS = {
    "acquisition-request-payload",
    "app-config",
    "appeal-resolution-command",
    "appeal-review-command",
    "appeal-submission-command",
    "coco-dataset-export-command",
    "defender-model-payload",
    "fake-vlm-fixture-bundle",
    "judge-model-payload",
    "m4-fake-vlm-fixture-bundle",
    "m5-appeal-training-label-input",
    "pilot-perception-worker-failure",
    "pilot-perception-worker-ready",
    "pilot-perception-worker-request",
    "pilot-perception-worker-response",
    "pilot-perception-worker-startup-failure",
    "pilot-run-request",
    "pilot-ui-job-start-request",
    "prosecutor-model-payload",
    "screening-model-payload",
}
