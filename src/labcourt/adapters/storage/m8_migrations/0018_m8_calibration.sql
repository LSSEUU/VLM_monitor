-- M8 shadow-calibration authority (migration 0018).
CREATE TABLE m8_calibration_dataset_manifests (
    dataset_manifest_id TEXT PRIMARY KEY
        CHECK (length(dataset_manifest_id) = 64 AND dataset_manifest_id NOT GLOB '*[^0-9a-f]*'),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    dataset_json TEXT NOT NULL CHECK (length(dataset_json) > 1)
) STRICT;

CREATE TABLE m8_calibration_artifacts (
    artifact_id TEXT PRIMARY KEY
        CHECK (length(artifact_id) = 64 AND artifact_id NOT GLOB '*[^0-9a-f]*'),
    dataset_manifest_id TEXT NOT NULL,
    detector_model_manifest_id TEXT NOT NULL
        CHECK (length(detector_model_manifest_id) = 64
            AND detector_model_manifest_id NOT GLOB '*[^0-9a-f]*'),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    artifact_json TEXT NOT NULL CHECK (length(artifact_json) > 1),
    FOREIGN KEY (dataset_manifest_id)
        REFERENCES m8_calibration_dataset_manifests(dataset_manifest_id)
) STRICT;

CREATE TABLE m8_calibration_reports (
    report_id TEXT PRIMARY KEY
        CHECK (length(report_id) = 64 AND report_id NOT GLOB '*[^0-9a-f]*'),
    artifact_id TEXT NOT NULL,
    dataset_manifest_id TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    report_json TEXT NOT NULL CHECK (length(report_json) > 1),
    FOREIGN KEY (artifact_id) REFERENCES m8_calibration_artifacts(artifact_id),
    FOREIGN KEY (dataset_manifest_id)
        REFERENCES m8_calibration_dataset_manifests(dataset_manifest_id)
) STRICT;

CREATE TABLE m8_detector_score_observations (
    observation_id TEXT PRIMARY KEY
        CHECK (length(observation_id) = 64 AND observation_id NOT GLOB '*[^0-9a-f]*'),
    run_id TEXT NOT NULL,
    asset_id TEXT NOT NULL
        CHECK (length(asset_id) = 64 AND asset_id NOT GLOB '*[^0-9a-f]*'),
    detector_model_manifest_id TEXT NOT NULL
        CHECK (length(detector_model_manifest_id) = 64
            AND detector_model_manifest_id NOT GLOB '*[^0-9a-f]*'),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    observation_json TEXT NOT NULL CHECK (length(observation_json) > 1)
) STRICT;

CREATE TABLE m8_evidence_quality_assessments (
    assessment_id TEXT PRIMARY KEY
        CHECK (length(assessment_id) = 64 AND assessment_id NOT GLOB '*[^0-9a-f]*'),
    run_id TEXT NOT NULL,
    asset_id TEXT NOT NULL
        CHECK (length(asset_id) = 64 AND asset_id NOT GLOB '*[^0-9a-f]*'),
    mode TEXT NOT NULL CHECK (mode IN ('SHADOW', 'NOT_APPLICABLE')),
    artifact_id TEXT,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    assessment_json TEXT NOT NULL CHECK (length(assessment_json) > 1),
    FOREIGN KEY (artifact_id) REFERENCES m8_calibration_artifacts(artifact_id)
) STRICT;

CREATE TABLE m8_event_risk_assessments (
    assessment_id TEXT PRIMARY KEY
        CHECK (length(assessment_id) = 64 AND assessment_id NOT GLOB '*[^0-9a-f]*'),
    run_id TEXT NOT NULL,
    asset_id TEXT NOT NULL
        CHECK (length(asset_id) = 64 AND asset_id NOT GLOB '*[^0-9a-f]*'),
    evidence_quality_assessment_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('SHADOW', 'NOT_APPLICABLE')),
    artifact_id TEXT,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    assessment_json TEXT NOT NULL CHECK (length(assessment_json) > 1),
    FOREIGN KEY (evidence_quality_assessment_id)
        REFERENCES m8_evidence_quality_assessments(assessment_id),
    FOREIGN KEY (artifact_id) REFERENCES m8_calibration_artifacts(artifact_id)
) STRICT;

CREATE INDEX idx_m8_calibration_artifacts_dataset
    ON m8_calibration_artifacts(dataset_manifest_id, artifact_id);
CREATE INDEX idx_m8_calibration_reports_artifact
    ON m8_calibration_reports(artifact_id, report_id);
CREATE INDEX idx_m8_detector_scores_run
    ON m8_detector_score_observations(run_id, observation_id);
CREATE INDEX idx_m8_evidence_quality_run
    ON m8_evidence_quality_assessments(run_id, assessment_id);
CREATE INDEX idx_m8_event_risk_run
    ON m8_event_risk_assessments(run_id, assessment_id);

CREATE TRIGGER m8_calibration_datasets_no_update
BEFORE UPDATE ON m8_calibration_dataset_manifests BEGIN
    SELECT RAISE(ABORT, 'M8 calibration datasets are append-only');
END;
CREATE TRIGGER m8_calibration_datasets_no_delete
BEFORE DELETE ON m8_calibration_dataset_manifests BEGIN
    SELECT RAISE(ABORT, 'M8 calibration datasets are append-only');
END;
CREATE TRIGGER m8_calibration_artifacts_no_update
BEFORE UPDATE ON m8_calibration_artifacts BEGIN
    SELECT RAISE(ABORT, 'M8 calibration artifacts are append-only');
END;
CREATE TRIGGER m8_calibration_artifacts_no_delete
BEFORE DELETE ON m8_calibration_artifacts BEGIN
    SELECT RAISE(ABORT, 'M8 calibration artifacts are append-only');
END;
CREATE TRIGGER m8_calibration_reports_no_update
BEFORE UPDATE ON m8_calibration_reports BEGIN
    SELECT RAISE(ABORT, 'M8 calibration reports are append-only');
END;
CREATE TRIGGER m8_calibration_reports_no_delete
BEFORE DELETE ON m8_calibration_reports BEGIN
    SELECT RAISE(ABORT, 'M8 calibration reports are append-only');
END;
CREATE TRIGGER m8_detector_scores_no_update
BEFORE UPDATE ON m8_detector_score_observations BEGIN
    SELECT RAISE(ABORT, 'M8 detector score observations are append-only');
END;
CREATE TRIGGER m8_detector_scores_no_delete
BEFORE DELETE ON m8_detector_score_observations BEGIN
    SELECT RAISE(ABORT, 'M8 detector score observations are append-only');
END;
CREATE TRIGGER m8_evidence_quality_no_update
BEFORE UPDATE ON m8_evidence_quality_assessments BEGIN
    SELECT RAISE(ABORT, 'M8 evidence quality assessments are append-only');
END;
CREATE TRIGGER m8_evidence_quality_no_delete
BEFORE DELETE ON m8_evidence_quality_assessments BEGIN
    SELECT RAISE(ABORT, 'M8 evidence quality assessments are append-only');
END;
CREATE TRIGGER m8_event_risk_no_update
BEFORE UPDATE ON m8_event_risk_assessments BEGIN
    SELECT RAISE(ABORT, 'M8 event risk assessments are append-only');
END;
CREATE TRIGGER m8_event_risk_no_delete
BEFORE DELETE ON m8_event_risk_assessments BEGIN
    SELECT RAISE(ABORT, 'M8 event risk assessments are append-only');
END;
