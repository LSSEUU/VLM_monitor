CREATE TABLE m8_evaluation_media_assets (
    asset_id TEXT PRIMARY KEY CHECK (
        length(asset_id) = 64 AND asset_id NOT GLOB '*[^0-9a-f]*'
    ),
    media_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(media_sha256) = 64 AND media_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    relative_path TEXT NOT NULL UNIQUE,
    document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    asset_json TEXT NOT NULL CHECK (json_valid(asset_json))
) STRICT;

CREATE TABLE m8_evaluation_ground_truth_versions (
    ground_truth_id TEXT PRIMARY KEY CHECK (
        length(ground_truth_id) = 64 AND ground_truth_id NOT GLOB '*[^0-9a-f]*'
    ),
    asset_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    review_state TEXT NOT NULL CHECK (review_state IN ('DRAFT', 'HUMAN_CONFIRMED')),
    document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    ground_truth_json TEXT NOT NULL CHECK (json_valid(ground_truth_json)),
    UNIQUE(asset_id, revision),
    FOREIGN KEY(asset_id) REFERENCES m8_evaluation_media_assets(asset_id)
) STRICT;

CREATE TABLE m8_evaluation_campaign_versions (
    campaign_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    state TEXT NOT NULL CHECK (state IN (
        'DRAFT', 'QUEUED', 'RUNNING', 'AWAITING_HUMAN', 'COMPLETED', 'PARTIAL_FAILED'
    )),
    document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    campaign_json TEXT NOT NULL CHECK (json_valid(campaign_json)),
    PRIMARY KEY(campaign_id, revision)
) STRICT;

CREATE TABLE m8_evaluation_run_versions (
    run_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    campaign_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'QUEUED', 'RUNNING', 'AWAITING_HEARING', 'SUCCEEDED', 'FAILED'
    )),
    document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    run_json TEXT NOT NULL CHECK (json_valid(run_json)),
    PRIMARY KEY(run_id, revision),
    FOREIGN KEY(asset_id) REFERENCES m8_evaluation_media_assets(asset_id)
) STRICT;

CREATE INDEX idx_m8_evaluation_runs_campaign_state
ON m8_evaluation_run_versions(campaign_id, state, run_id, revision);

CREATE TABLE m8_live_ingest_session_versions (
    session_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    state TEXT NOT NULL CHECK (state IN (
        'STARTING', 'RUNNING', 'DEGRADED', 'STOPPED', 'FAILED'
    )),
    document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    session_json TEXT NOT NULL CHECK (json_valid(session_json)),
    PRIMARY KEY(session_id, revision)
) STRICT;

CREATE TABLE m8_capture_segments (
    segment_id TEXT PRIMARY KEY CHECK (
        length(segment_id) = 64 AND segment_id NOT GLOB '*[^0-9a-f]*'
    ),
    session_id TEXT NOT NULL,
    asset_id TEXT NOT NULL UNIQUE,
    document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    segment_json TEXT NOT NULL CHECK (json_valid(segment_json)),
    FOREIGN KEY(asset_id) REFERENCES m8_evaluation_media_assets(asset_id)
) STRICT;

CREATE TRIGGER m8_evaluation_ground_truth_validate_contiguous
BEFORE INSERT ON m8_evaluation_ground_truth_versions
WHEN NEW.revision != COALESCE((
    SELECT MAX(revision) FROM m8_evaluation_ground_truth_versions
    WHERE asset_id = NEW.asset_id
), 0) + 1
BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation ground truth revision must be contiguous');
END;

CREATE TRIGGER m8_evaluation_campaign_validate_contiguous
BEFORE INSERT ON m8_evaluation_campaign_versions
WHEN NEW.revision != COALESCE((
    SELECT MAX(revision) FROM m8_evaluation_campaign_versions
    WHERE campaign_id = NEW.campaign_id
), 0) + 1
BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation campaign revision must be contiguous');
END;

CREATE TRIGGER m8_evaluation_run_validate_contiguous
BEFORE INSERT ON m8_evaluation_run_versions
WHEN NEW.revision != COALESCE((
    SELECT MAX(revision) FROM m8_evaluation_run_versions
    WHERE run_id = NEW.run_id
), 0) + 1
BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation run revision must be contiguous');
END;

CREATE TRIGGER m8_live_ingest_session_validate_contiguous
BEFORE INSERT ON m8_live_ingest_session_versions
WHEN NEW.revision != COALESCE((
    SELECT MAX(revision) FROM m8_live_ingest_session_versions
    WHERE session_id = NEW.session_id
), 0) + 1
BEGIN
    SELECT RAISE(ABORT, 'M8 live ingest session revision must be contiguous');
END;

CREATE TRIGGER m8_evaluation_media_assets_no_update
BEFORE UPDATE ON m8_evaluation_media_assets BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation media assets are append-only');
END;
CREATE TRIGGER m8_evaluation_media_assets_no_delete
BEFORE DELETE ON m8_evaluation_media_assets BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation media assets are append-only');
END;
CREATE TRIGGER m8_evaluation_ground_truth_no_update
BEFORE UPDATE ON m8_evaluation_ground_truth_versions BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation ground truth is append-only');
END;
CREATE TRIGGER m8_evaluation_ground_truth_no_delete
BEFORE DELETE ON m8_evaluation_ground_truth_versions BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation ground truth is append-only');
END;
CREATE TRIGGER m8_evaluation_campaigns_no_update
BEFORE UPDATE ON m8_evaluation_campaign_versions BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation campaigns are append-only');
END;
CREATE TRIGGER m8_evaluation_campaigns_no_delete
BEFORE DELETE ON m8_evaluation_campaign_versions BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation campaigns are append-only');
END;
CREATE TRIGGER m8_evaluation_runs_no_update
BEFORE UPDATE ON m8_evaluation_run_versions BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation runs are append-only');
END;
CREATE TRIGGER m8_evaluation_runs_no_delete
BEFORE DELETE ON m8_evaluation_run_versions BEGIN
    SELECT RAISE(ABORT, 'M8 evaluation runs are append-only');
END;
CREATE TRIGGER m8_live_ingest_sessions_no_update
BEFORE UPDATE ON m8_live_ingest_session_versions BEGIN
    SELECT RAISE(ABORT, 'M8 live ingest sessions are append-only');
END;
CREATE TRIGGER m8_live_ingest_sessions_no_delete
BEFORE DELETE ON m8_live_ingest_session_versions BEGIN
    SELECT RAISE(ABORT, 'M8 live ingest sessions are append-only');
END;
CREATE TRIGGER m8_capture_segments_no_update
BEFORE UPDATE ON m8_capture_segments BEGIN
    SELECT RAISE(ABORT, 'M8 capture segments are append-only');
END;
CREATE TRIGGER m8_capture_segments_no_delete
BEFORE DELETE ON m8_capture_segments BEGIN
    SELECT RAISE(ABORT, 'M8 capture segments are append-only');
END;
