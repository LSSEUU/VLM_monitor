CREATE TABLE detections (
    run_id TEXT NOT NULL,
    detection_id TEXT NOT NULL
        CHECK (length(detection_id) BETWEEN 1 AND 64)
        CHECK (substr(detection_id, 1, 1) GLOB '[A-Za-z0-9]')
        CHECK (detection_id NOT GLOB '*[^A-Za-z0-9_.-]*'),
    frame_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    detector_manifest_id TEXT NOT NULL
        CHECK (
            length(detector_manifest_id) = 64
            AND detector_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    label TEXT NOT NULL CHECK (length(label) > 0),
    document_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    registered_at TEXT NOT NULL,
    PRIMARY KEY (run_id, detection_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, frame_id, manifest_id)
        REFERENCES frames(run_id, frame_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_detections_frame
    ON detections(run_id, frame_id, detection_id);
CREATE INDEX idx_detections_detector_manifest
    ON detections(run_id, detector_manifest_id, detection_id);

CREATE TRIGGER detections_no_replace
BEFORE INSERT ON detections
WHEN EXISTS (
    SELECT 1 FROM detections
    WHERE run_id = NEW.run_id AND detection_id = NEW.detection_id
)
BEGIN
    SELECT RAISE(ABORT, 'detections is append-only');
END;

CREATE TRIGGER detections_no_update
BEFORE UPDATE ON detections
BEGIN
    SELECT RAISE(ABORT, 'detections is append-only');
END;

CREATE TRIGGER detections_no_delete
BEFORE DELETE ON detections
BEGIN
    SELECT RAISE(ABORT, 'detections is append-only');
END;
