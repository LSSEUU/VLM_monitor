CREATE TABLE run_manifests (
    manifest_id TEXT PRIMARY KEY
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    schema_version TEXT NOT NULL,
    document_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL UNIQUE
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    registered_at TEXT NOT NULL
) STRICT;

CREATE TABLE runs (
    run_id TEXT PRIMARY KEY
        CHECK (length(run_id) BETWEEN 1 AND 64),
    manifest_id TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    audit_head_sequence INTEGER NOT NULL DEFAULT -1 CHECK (audit_head_sequence >= -1),
    audit_head_hash TEXT NOT NULL
        CHECK (length(audit_head_hash) = 64 AND audit_head_hash NOT GLOB '*[^0-9a-f]*'),
    registered_at TEXT NOT NULL,
    UNIQUE (run_id, manifest_id),
    FOREIGN KEY (manifest_id) REFERENCES run_manifests(manifest_id) ON DELETE RESTRICT,
    CHECK (revision = audit_head_sequence + 1),
    CHECK (
        audit_head_sequence <> -1
        OR audit_head_hash = '0000000000000000000000000000000000000000000000000000000000000000'
    )
) STRICT;

CREATE TABLE frames (
    run_id TEXT NOT NULL,
    frame_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    camera_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    frame_index INTEGER NOT NULL CHECK (frame_index >= 0),
    fps_num INTEGER NOT NULL CHECK (fps_num > 0),
    fps_den INTEGER NOT NULL CHECK (fps_den > 0),
    width INTEGER NOT NULL CHECK (width > 0),
    height INTEGER NOT NULL CHECK (height > 0),
    content_sha256 TEXT NOT NULL
        CHECK (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
    document_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, frame_id),
    UNIQUE (run_id, frame_id, manifest_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE audit_entries (
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    manifest_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    before_sha256 TEXT,
    after_sha256 TEXT,
    recorded_at TEXT NOT NULL,
    prev_entry_hash TEXT NOT NULL
        CHECK (length(prev_entry_hash) = 64 AND prev_entry_hash NOT GLOB '*[^0-9a-f]*'),
    entry_hash TEXT NOT NULL
        CHECK (length(entry_hash) = 64 AND entry_hash NOT GLOB '*[^0-9a-f]*'),
    entry_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, sequence),
    UNIQUE (run_id, entry_hash),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (before_sha256 IS NOT NULL OR after_sha256 IS NOT NULL)
) STRICT;

CREATE TABLE cases (
    run_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    status TEXT NOT NULL,
    current_revision INTEGER NOT NULL CHECK (current_revision >= 1),
    latest_pack_id TEXT,
    latest_pack_version INTEGER CHECK (latest_pack_version > 0),
    event_json TEXT NOT NULL,
    event_sha256 TEXT NOT NULL
        CHECK (length(event_sha256) = 64 AND event_sha256 NOT GLOB '*[^0-9a-f]*'),
    created_audit_sequence INTEGER NOT NULL CHECK (created_audit_sequence >= 0),
    PRIMARY KEY (run_id, case_id),
    UNIQUE (run_id, event_id),
    UNIQUE (run_id, case_id, manifest_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, created_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, case_id, current_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, case_id, latest_pack_id, latest_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (latest_pack_id IS NULL AND latest_pack_version IS NULL)
        OR (latest_pack_id IS NOT NULL AND latest_pack_version IS NOT NULL)
    )
) STRICT;

CREATE TABLE case_versions (
    run_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    status TEXT NOT NULL,
    case_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    audit_sequence INTEGER NOT NULL CHECK (audit_sequence >= 0),
    PRIMARY KEY (run_id, case_id, revision),
    UNIQUE (run_id, audit_sequence),
    FOREIGN KEY (run_id, case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE evidence_packs (
    run_id TEXT NOT NULL,
    pack_id TEXT NOT NULL
        CHECK (length(pack_id) = 64 AND pack_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    pack_input_sha256 TEXT NOT NULL
        CHECK (length(pack_input_sha256) = 64 AND pack_input_sha256 NOT GLOB '*[^0-9a-f]*'),
    closure_input_sha256 TEXT NOT NULL
        CHECK (length(closure_input_sha256) = 64 AND closure_input_sha256 NOT GLOB '*[^0-9a-f]*'),
    pack_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    created_audit_sequence INTEGER NOT NULL CHECK (created_audit_sequence >= 0),
    PRIMARY KEY (run_id, pack_id),
    UNIQUE (run_id, case_id, version),
    UNIQUE (run_id, case_id, pack_input_sha256),
    UNIQUE (run_id, pack_id, manifest_id),
    UNIQUE (run_id, case_id, pack_id, version),
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, created_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE media_assets (
    run_id TEXT NOT NULL,
    media_sha256 TEXT NOT NULL
        CHECK (length(media_sha256) = 64 AND media_sha256 NOT GLOB '*[^0-9a-f]*'),
    manifest_id TEXT NOT NULL,
    local_path TEXT,
    availability TEXT NOT NULL,
    pixel_sha256 TEXT NOT NULL
        CHECK (length(pixel_sha256) = 64 AND pixel_sha256 NOT GLOB '*[^0-9a-f]*'),
    width INTEGER NOT NULL CHECK (width > 0),
    height INTEGER NOT NULL CHECK (height > 0),
    size_bytes INTEGER NOT NULL CHECK (size_bytes > 0),
    media_type TEXT NOT NULL,
    encoding_version TEXT NOT NULL,
    ttl_expires_at TEXT,
    purged_at TEXT,
    PRIMARY KEY (run_id, media_sha256),
    UNIQUE (run_id, local_path),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (availability = 'PURGED_BY_RETENTION' AND local_path IS NULL AND purged_at IS NOT NULL)
        OR (availability <> 'PURGED_BY_RETENTION' AND local_path IS NOT NULL AND purged_at IS NULL)
    )
) STRICT;

CREATE TABLE evidence_pack_crops (
    run_id TEXT NOT NULL,
    pack_id TEXT NOT NULL,
    crop_id TEXT NOT NULL
        CHECK (length(crop_id) = 64 AND crop_id NOT GLOB '*[^0-9a-f]*'),
    media_sha256 TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('panorama', 'subject', 'focus', 'temporal')),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    crop_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, pack_id, crop_id),
    UNIQUE (run_id, pack_id, role, ordinal),
    FOREIGN KEY (run_id, pack_id)
        REFERENCES evidence_packs(run_id, pack_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, media_sha256)
        REFERENCES media_assets(run_id, media_sha256) ON DELETE RESTRICT
) STRICT;

CREATE TABLE retention_holds (
    run_id TEXT NOT NULL,
    hold_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    hold_kind TEXT NOT NULL,
    owner_kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    manifest_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    reason_code TEXT,
    hold_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, hold_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_cases_created_audit
    ON cases(run_id, created_audit_sequence);
CREATE INDEX idx_case_versions_status
    ON case_versions(run_id, status, revision);
CREATE INDEX idx_evidence_packs_case_version
    ON evidence_packs(run_id, case_id, version);
CREATE INDEX idx_evidence_packs_input
    ON evidence_packs(run_id, case_id, pack_input_sha256);
CREATE INDEX idx_media_assets_availability
    ON media_assets(run_id, availability);
CREATE INDEX idx_evidence_pack_crops_media
    ON evidence_pack_crops(run_id, media_sha256);
CREATE INDEX idx_retention_holds_target
    ON retention_holds(run_id, target_kind, target_id, active);

CREATE TRIGGER runs_no_replace
BEFORE INSERT ON runs
WHEN EXISTS (SELECT 1 FROM runs WHERE run_id = NEW.run_id)
BEGIN
    SELECT RAISE(ABORT, 'runs cannot be replaced');
END;

CREATE TRIGGER runs_no_delete
BEFORE DELETE ON runs
BEGIN
    SELECT RAISE(ABORT, 'runs cannot be deleted');
END;

CREATE TRIGGER runs_monotonic_head_update
BEFORE UPDATE ON runs
WHEN NEW.run_id IS NOT OLD.run_id
  OR NEW.manifest_id IS NOT OLD.manifest_id
  OR NEW.registered_at IS NOT OLD.registered_at
  OR NEW.revision != OLD.revision + 1
  OR NEW.audit_head_sequence != OLD.audit_head_sequence + 1
  OR NEW.audit_head_hash IS OLD.audit_head_hash
BEGIN
    SELECT RAISE(ABORT, 'run identity is immutable and audit head updates must be monotonic');
END;

CREATE TRIGGER schema_migrations_no_update
BEFORE UPDATE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'schema_migrations is append-only');
END;

CREATE TRIGGER schema_migrations_no_replace
BEFORE INSERT ON schema_migrations
WHEN EXISTS (
    SELECT 1 FROM schema_migrations
    WHERE version = NEW.version OR name = NEW.name
)
BEGIN
    SELECT RAISE(ABORT, 'schema_migrations is append-only');
END;

CREATE TRIGGER schema_migrations_no_delete
BEFORE DELETE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'schema_migrations is append-only');
END;

CREATE TRIGGER run_manifests_no_update
BEFORE UPDATE ON run_manifests
BEGIN
    SELECT RAISE(ABORT, 'run_manifests is append-only');
END;

CREATE TRIGGER run_manifests_no_replace
BEFORE INSERT ON run_manifests
WHEN EXISTS (
    SELECT 1 FROM run_manifests
    WHERE manifest_id = NEW.manifest_id OR document_sha256 = NEW.document_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'run_manifests is append-only');
END;

CREATE TRIGGER run_manifests_no_delete
BEFORE DELETE ON run_manifests
BEGIN
    SELECT RAISE(ABORT, 'run_manifests is append-only');
END;

CREATE TRIGGER frames_no_update
BEFORE UPDATE ON frames
BEGIN
    SELECT RAISE(ABORT, 'frames is append-only');
END;

CREATE TRIGGER frames_no_replace
BEFORE INSERT ON frames
WHEN EXISTS (
    SELECT 1 FROM frames
    WHERE run_id = NEW.run_id AND frame_id = NEW.frame_id
)
BEGIN
    SELECT RAISE(ABORT, 'frames is append-only');
END;

CREATE TRIGGER frames_no_delete
BEFORE DELETE ON frames
BEGIN
    SELECT RAISE(ABORT, 'frames is append-only');
END;

CREATE TRIGGER case_versions_no_update
BEFORE UPDATE ON case_versions
BEGIN
    SELECT RAISE(ABORT, 'case_versions is append-only');
END;

CREATE TRIGGER case_versions_no_replace
BEFORE INSERT ON case_versions
WHEN EXISTS (
    SELECT 1 FROM case_versions
    WHERE (run_id = NEW.run_id AND case_id = NEW.case_id AND revision = NEW.revision)
       OR (run_id = NEW.run_id AND audit_sequence = NEW.audit_sequence)
)
BEGIN
    SELECT RAISE(ABORT, 'case_versions is append-only');
END;

CREATE TRIGGER case_versions_no_delete
BEFORE DELETE ON case_versions
BEGIN
    SELECT RAISE(ABORT, 'case_versions is append-only');
END;

CREATE TRIGGER evidence_packs_no_update
BEFORE UPDATE ON evidence_packs
BEGIN
    SELECT RAISE(ABORT, 'evidence_packs is append-only');
END;

CREATE TRIGGER evidence_packs_no_replace
BEFORE INSERT ON evidence_packs
WHEN EXISTS (
    SELECT 1 FROM evidence_packs
    WHERE (run_id = NEW.run_id AND pack_id = NEW.pack_id)
       OR (run_id = NEW.run_id AND case_id = NEW.case_id AND version = NEW.version)
       OR (
           run_id = NEW.run_id
           AND case_id = NEW.case_id
           AND pack_input_sha256 = NEW.pack_input_sha256
       )
)
BEGIN
    SELECT RAISE(ABORT, 'evidence_packs is append-only');
END;

CREATE TRIGGER evidence_packs_no_delete
BEFORE DELETE ON evidence_packs
BEGIN
    SELECT RAISE(ABORT, 'evidence_packs is append-only');
END;

CREATE TRIGGER evidence_pack_crops_no_update
BEFORE UPDATE ON evidence_pack_crops
BEGIN
    SELECT RAISE(ABORT, 'evidence_pack_crops is append-only');
END;

CREATE TRIGGER evidence_pack_crops_no_replace
BEFORE INSERT ON evidence_pack_crops
WHEN EXISTS (
    SELECT 1 FROM evidence_pack_crops
    WHERE (run_id = NEW.run_id AND pack_id = NEW.pack_id AND crop_id = NEW.crop_id)
       OR (
           run_id = NEW.run_id
           AND pack_id = NEW.pack_id
           AND role = NEW.role
           AND ordinal = NEW.ordinal
       )
)
BEGIN
    SELECT RAISE(ABORT, 'evidence_pack_crops is append-only');
END;

CREATE TRIGGER evidence_pack_crops_no_delete
BEFORE DELETE ON evidence_pack_crops
BEGIN
    SELECT RAISE(ABORT, 'evidence_pack_crops is append-only');
END;

CREATE TRIGGER audit_entries_no_update
BEFORE UPDATE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_entries is append-only');
END;

CREATE TRIGGER audit_entries_no_replace
BEFORE INSERT ON audit_entries
WHEN EXISTS (
    SELECT 1 FROM audit_entries
    WHERE (run_id = NEW.run_id AND sequence = NEW.sequence)
       OR (run_id = NEW.run_id AND entry_hash = NEW.entry_hash)
)
BEGIN
    SELECT RAISE(ABORT, 'audit_entries is append-only');
END;

CREATE TRIGGER audit_entries_no_delete
BEFORE DELETE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_entries is append-only');
END;

CREATE TRIGGER cases_monotonic_update
BEFORE UPDATE ON cases
WHEN NEW.run_id IS NOT OLD.run_id
  OR NEW.case_id IS NOT OLD.case_id
  OR NEW.event_id IS NOT OLD.event_id
  OR NEW.manifest_id IS NOT OLD.manifest_id
  OR NEW.event_json IS NOT OLD.event_json
  OR NEW.event_sha256 IS NOT OLD.event_sha256
  OR NEW.created_audit_sequence IS NOT OLD.created_audit_sequence
  OR NEW.current_revision != OLD.current_revision + 1
  OR NOT (
      (
          NEW.latest_pack_id IS OLD.latest_pack_id
          AND NEW.latest_pack_version IS OLD.latest_pack_version
      )
      OR (
          NEW.latest_pack_id IS NOT NULL
          AND NEW.latest_pack_version = COALESCE(OLD.latest_pack_version, 0) + 1
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'case head update is not monotonic');
END;
