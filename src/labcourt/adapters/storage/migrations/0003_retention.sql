-- M2 retention eligibility deliberately does not use media_assets.ttl_expires_at.
-- The repository compares the caller-supplied policy cutoff with the latest
-- EVIDENCE_PACK_PUBLISHED audit timestamp across every pack that references the
-- media.  This keeps shared media alive until its latest audited use and avoids
-- guessing a duration that is present only in configuration, not RunManifest.

CREATE TABLE media_purge_attempts (
    run_id TEXT NOT NULL,
    media_sha256 TEXT NOT NULL
        CHECK (length(media_sha256) = 64 AND media_sha256 NOT GLOB '*[^0-9a-f]*'),
    intent_audit_sequence INTEGER NOT NULL CHECK (intent_audit_sequence >= 0),
    manifest_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    expires_before TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    source_relative_path TEXT NOT NULL,
    trash_relative_path TEXT NOT NULL,
    crop_refs_json TEXT NOT NULL,
    crop_refs_sha256 TEXT NOT NULL
        CHECK (length(crop_refs_sha256) = 64 AND crop_refs_sha256 NOT GLOB '*[^0-9a-f]*'),
    available_state_json TEXT NOT NULL,
    available_state_sha256 TEXT NOT NULL
        CHECK (
            length(available_state_sha256) = 64
            AND available_state_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    purging_state_json TEXT NOT NULL,
    purging_state_sha256 TEXT NOT NULL
        CHECK (
            length(purging_state_sha256) = 64
            AND purging_state_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    purged_state_json TEXT,
    purged_state_sha256 TEXT
        CHECK (
            purged_state_sha256 IS NULL
            OR (
                length(purged_state_sha256) = 64
                AND purged_state_sha256 NOT GLOB '*[^0-9a-f]*'
            )
        ),
    completion_audit_sequence INTEGER CHECK (completion_audit_sequence >= 0),
    completion_recovered INTEGER CHECK (completion_recovered IN (0, 1)),
    cleanup_acked_at TEXT,
    status TEXT NOT NULL
        CHECK (status IN ('PURGING', 'PURGED_CLEANUP_PENDING', 'TRASH_CLEANED')),
    PRIMARY KEY (run_id, media_sha256, intent_audit_sequence),
    UNIQUE (run_id, media_sha256),
    UNIQUE (run_id, intent_audit_sequence),
    UNIQUE (run_id, completion_audit_sequence),
    FOREIGN KEY (run_id, media_sha256)
        REFERENCES media_assets(run_id, media_sha256) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, intent_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, completion_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (
            status = 'PURGING'
            AND purged_state_json IS NULL
            AND purged_state_sha256 IS NULL
            AND completion_audit_sequence IS NULL
            AND completion_recovered IS NULL
            AND cleanup_acked_at IS NULL
        )
        OR (
            status = 'PURGED_CLEANUP_PENDING'
            AND purged_state_json IS NOT NULL
            AND purged_state_sha256 IS NOT NULL
            AND completion_audit_sequence IS NOT NULL
            AND completion_recovered IS NOT NULL
            AND cleanup_acked_at IS NULL
        )
        OR (
            status = 'TRASH_CLEANED'
            AND purged_state_json IS NOT NULL
            AND purged_state_sha256 IS NOT NULL
            AND completion_audit_sequence IS NOT NULL
            AND completion_recovered IS NOT NULL
            AND cleanup_acked_at IS NOT NULL
        )
    ),
    CHECK (source_relative_path = run_id || '/frames/' || media_sha256 || '.png'),
    CHECK (trash_relative_path = '.trash/' || run_id || '/' || media_sha256 || '.png'),
    CHECK (
        completion_audit_sequence IS NULL
        OR completion_audit_sequence > intent_audit_sequence
    )
) STRICT;

CREATE TABLE retention_hold_audit_links (
    run_id TEXT NOT NULL,
    hold_id TEXT NOT NULL,
    created_audit_sequence INTEGER NOT NULL CHECK (created_audit_sequence >= 0),
    released_audit_sequence INTEGER CHECK (released_audit_sequence >= 0),
    PRIMARY KEY (run_id, hold_id),
    UNIQUE (run_id, created_audit_sequence),
    UNIQUE (run_id, released_audit_sequence),
    FOREIGN KEY (run_id, hold_id)
        REFERENCES retention_holds(run_id, hold_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, created_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, released_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        released_audit_sequence IS NULL
        OR released_audit_sequence > created_audit_sequence
    )
) STRICT;

-- Operational pagination state prevents a permanently-held SHA prefix from
-- starving later media while each returned page remains strict SHA order.
-- It is not a business state transition and therefore adds no audit entry.
CREATE TABLE retention_scan_cursors (
    run_id TEXT PRIMARY KEY,
    last_media_sha256 TEXT NOT NULL
        CHECK (
            length(last_media_sha256) = 64
            AND last_media_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE RESTRICT
) STRICT;

-- Recovery claims advance before filesystem work.  Keeping this cursor in
-- SQLite means a crashed or permanently failing item cannot become a prefix
-- barrier after the process restarts.  The referenced purge attempt is
-- append-only, so the cursor always names durable recovery history.
CREATE TABLE retention_recovery_cursors (
    run_id TEXT PRIMARY KEY,
    last_intent_audit_sequence INTEGER NOT NULL
        CHECK (last_intent_audit_sequence >= 0),
    FOREIGN KEY (run_id, last_intent_audit_sequence)
        REFERENCES media_purge_attempts(run_id, intent_audit_sequence)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_media_purge_attempts_recovery
    ON media_purge_attempts(run_id, status, media_sha256, intent_audit_sequence);
CREATE INDEX idx_media_purge_attempts_recovery_scheduler
    ON media_purge_attempts(run_id, intent_audit_sequence, status);
CREATE INDEX idx_pack_crops_crop_media
    ON evidence_pack_crops(run_id, crop_id, media_sha256);

CREATE TRIGGER media_assets_no_replace
BEFORE INSERT ON media_assets
WHEN EXISTS (
    SELECT 1 FROM media_assets
    WHERE run_id = NEW.run_id AND media_sha256 = NEW.media_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'media_assets cannot be replaced');
END;

CREATE TRIGGER media_assets_no_delete
BEFORE DELETE ON media_assets
BEGIN
    SELECT RAISE(ABORT, 'media_assets cannot be deleted');
END;

CREATE TRIGGER media_assets_controlled_retention_update
BEFORE UPDATE ON media_assets
WHEN NEW.run_id IS NOT OLD.run_id
  OR NEW.media_sha256 IS NOT OLD.media_sha256
  OR NEW.manifest_id IS NOT OLD.manifest_id
  OR NEW.pixel_sha256 IS NOT OLD.pixel_sha256
  OR NEW.width IS NOT OLD.width
  OR NEW.height IS NOT OLD.height
  OR NEW.size_bytes IS NOT OLD.size_bytes
  OR NEW.media_type IS NOT OLD.media_type
  OR NEW.encoding_version IS NOT OLD.encoding_version
  OR NEW.ttl_expires_at IS NOT OLD.ttl_expires_at
  OR NOT (
      (
          OLD.availability = 'AVAILABLE'
          AND NEW.availability = 'PURGING'
          AND NEW.local_path IS OLD.local_path
          AND OLD.purged_at IS NULL
          AND NEW.purged_at IS NULL
          AND EXISTS (
              SELECT 1 FROM media_purge_attempts AS attempt
              WHERE attempt.run_id = OLD.run_id
                AND attempt.media_sha256 = OLD.media_sha256
                AND attempt.status = 'PURGING'
          )
      )
      OR (
          OLD.availability = 'PURGING'
          AND NEW.availability = 'PURGED_BY_RETENTION'
          AND OLD.local_path IS NOT NULL
          AND NEW.local_path IS NULL
          AND OLD.purged_at IS NULL
          AND NEW.purged_at IS NOT NULL
          AND EXISTS (
              SELECT 1 FROM media_purge_attempts AS attempt
              WHERE attempt.run_id = OLD.run_id
                AND attempt.media_sha256 = OLD.media_sha256
                AND attempt.status = 'PURGING'
          )
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'media_assets update is not a controlled retention transition');
END;

CREATE TRIGGER media_purge_attempts_no_replace
BEFORE INSERT ON media_purge_attempts
WHEN EXISTS (
    SELECT 1 FROM media_purge_attempts
    WHERE run_id = NEW.run_id AND media_sha256 = NEW.media_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'media_purge_attempts cannot be replaced');
END;

CREATE TRIGGER media_purge_attempts_no_delete
BEFORE DELETE ON media_purge_attempts
BEGIN
    SELECT RAISE(ABORT, 'media_purge_attempts cannot be deleted');
END;

CREATE TRIGGER media_purge_attempts_controlled_update
BEFORE UPDATE ON media_purge_attempts
WHEN NEW.run_id IS NOT OLD.run_id
  OR NEW.media_sha256 IS NOT OLD.media_sha256
  OR NEW.intent_audit_sequence IS NOT OLD.intent_audit_sequence
  OR NEW.manifest_id IS NOT OLD.manifest_id
  OR NEW.policy_version IS NOT OLD.policy_version
  OR NEW.expires_before IS NOT OLD.expires_before
  OR NEW.requested_at IS NOT OLD.requested_at
  OR NEW.source_relative_path IS NOT OLD.source_relative_path
  OR NEW.trash_relative_path IS NOT OLD.trash_relative_path
  OR NEW.crop_refs_json IS NOT OLD.crop_refs_json
  OR NEW.crop_refs_sha256 IS NOT OLD.crop_refs_sha256
  OR NEW.available_state_json IS NOT OLD.available_state_json
  OR NEW.available_state_sha256 IS NOT OLD.available_state_sha256
  OR NEW.purging_state_json IS NOT OLD.purging_state_json
  OR NEW.purging_state_sha256 IS NOT OLD.purging_state_sha256
  OR NOT (
      (
          OLD.status = 'PURGING'
          AND NEW.status = 'PURGED_CLEANUP_PENDING'
          AND OLD.purged_state_json IS NULL
          AND NEW.purged_state_json IS NOT NULL
          AND OLD.purged_state_sha256 IS NULL
          AND NEW.purged_state_sha256 IS NOT NULL
          AND OLD.completion_audit_sequence IS NULL
          AND NEW.completion_audit_sequence IS NOT NULL
          AND OLD.completion_recovered IS NULL
          AND NEW.completion_recovered IS NOT NULL
          AND OLD.cleanup_acked_at IS NULL
          AND NEW.cleanup_acked_at IS NULL
      )
      OR (
          OLD.status = 'PURGED_CLEANUP_PENDING'
          AND NEW.status = 'TRASH_CLEANED'
          AND NEW.purged_state_json IS OLD.purged_state_json
          AND NEW.purged_state_sha256 IS OLD.purged_state_sha256
          AND NEW.completion_audit_sequence IS OLD.completion_audit_sequence
          AND NEW.completion_recovered IS OLD.completion_recovered
          AND OLD.cleanup_acked_at IS NULL
          AND NEW.cleanup_acked_at IS NOT NULL
      )
  )
BEGIN
    SELECT RAISE(ABORT, 'media_purge_attempts update is not a controlled recovery transition');
END;

CREATE TRIGGER retention_holds_no_replace
BEFORE INSERT ON retention_holds
WHEN EXISTS (
    SELECT 1 FROM retention_holds
    WHERE run_id = NEW.run_id AND hold_id = NEW.hold_id
)
BEGIN
    SELECT RAISE(ABORT, 'retention_holds cannot be replaced');
END;

CREATE TRIGGER retention_holds_validate_insert
BEFORE INSERT ON retention_holds
WHEN NEW.active <> 1
  OR NEW.target_kind NOT IN ('CROP', 'MEDIA')
  OR NEW.hold_kind NOT IN ('APPEAL', 'GOLD_SET', 'CHALLENGE_SET', 'MANUAL_LEGAL_HOLD')
  OR NOT (
      (NEW.hold_kind = 'APPEAL' AND NEW.owner_kind = 'APPEAL')
      OR (NEW.hold_kind IN ('GOLD_SET', 'CHALLENGE_SET') AND NEW.owner_kind = 'DATASET')
      OR (NEW.hold_kind = 'MANUAL_LEGAL_HOLD' AND NEW.owner_kind = 'CASE')
  )
BEGIN
    SELECT RAISE(ABORT, 'retention_holds insert violates its typed matrix');
END;

CREATE TRIGGER retention_holds_controlled_release
BEFORE UPDATE ON retention_holds
WHEN NEW.run_id IS NOT OLD.run_id
  OR NEW.hold_id IS NOT OLD.hold_id
  OR NEW.target_kind IS NOT OLD.target_kind
  OR NEW.target_id IS NOT OLD.target_id
  OR NEW.hold_kind IS NOT OLD.hold_kind
  OR NEW.owner_kind IS NOT OLD.owner_kind
  OR NEW.owner_id IS NOT OLD.owner_id
  OR NEW.manifest_id IS NOT OLD.manifest_id
  OR NEW.policy_version IS NOT OLD.policy_version
  OR NEW.reason_code IS NOT OLD.reason_code
  OR NEW.hold_json IS NOT OLD.hold_json
  OR NEW.document_sha256 IS NOT OLD.document_sha256
  OR OLD.active <> 1
  OR NEW.active <> 0
  OR NOT EXISTS (
      SELECT 1 FROM retention_hold_audit_links AS links
      WHERE links.run_id = OLD.run_id
        AND links.hold_id = OLD.hold_id
        AND links.released_audit_sequence IS NOT NULL
  )
BEGIN
    SELECT RAISE(ABORT, 'retention_holds update is not an active-to-released transition');
END;

CREATE TRIGGER retention_holds_no_delete
BEFORE DELETE ON retention_holds
BEGIN
    SELECT RAISE(ABORT, 'retention_holds cannot be deleted');
END;

CREATE TRIGGER retention_hold_audit_links_no_replace
BEFORE INSERT ON retention_hold_audit_links
WHEN EXISTS (
    SELECT 1 FROM retention_hold_audit_links
    WHERE run_id = NEW.run_id AND hold_id = NEW.hold_id
)
BEGIN
    SELECT RAISE(ABORT, 'retention_hold_audit_links cannot be replaced');
END;

CREATE TRIGGER retention_hold_audit_links_controlled_release
BEFORE UPDATE ON retention_hold_audit_links
WHEN NEW.run_id IS NOT OLD.run_id
  OR NEW.hold_id IS NOT OLD.hold_id
  OR NEW.created_audit_sequence IS NOT OLD.created_audit_sequence
  OR OLD.released_audit_sequence IS NOT NULL
  OR NEW.released_audit_sequence IS NULL
BEGIN
    SELECT RAISE(ABORT, 'retention_hold_audit_links update is not a release link');
END;

CREATE TRIGGER retention_hold_audit_links_no_delete
BEFORE DELETE ON retention_hold_audit_links
BEGIN
    SELECT RAISE(ABORT, 'retention_hold_audit_links cannot be deleted');
END;

CREATE TRIGGER retention_scan_cursors_no_replace
BEFORE INSERT ON retention_scan_cursors
WHEN EXISTS (
    SELECT 1 FROM retention_scan_cursors WHERE run_id = NEW.run_id
)
BEGIN
    SELECT RAISE(ABORT, 'retention_scan_cursors cannot be replaced');
END;

CREATE TRIGGER retention_scan_cursors_controlled_update
BEFORE UPDATE ON retention_scan_cursors
WHEN NEW.run_id IS NOT OLD.run_id
BEGIN
    SELECT RAISE(ABORT, 'retention_scan_cursors run scope is immutable');
END;

CREATE TRIGGER retention_scan_cursors_no_delete
BEFORE DELETE ON retention_scan_cursors
BEGIN
    SELECT RAISE(ABORT, 'retention_scan_cursors cannot be deleted');
END;

CREATE TRIGGER retention_recovery_cursors_no_replace
BEFORE INSERT ON retention_recovery_cursors
WHEN EXISTS (
    SELECT 1 FROM retention_recovery_cursors WHERE run_id = NEW.run_id
)
BEGIN
    SELECT RAISE(ABORT, 'retention_recovery_cursors cannot be replaced');
END;

CREATE TRIGGER retention_recovery_cursors_controlled_update
BEFORE UPDATE ON retention_recovery_cursors
WHEN NEW.run_id IS NOT OLD.run_id
BEGIN
    SELECT RAISE(ABORT, 'retention_recovery_cursors run scope is immutable');
END;

CREATE TRIGGER retention_recovery_cursors_no_delete
BEFORE DELETE ON retention_recovery_cursors
BEGIN
    SELECT RAISE(ABORT, 'retention_recovery_cursors cannot be deleted');
END;
