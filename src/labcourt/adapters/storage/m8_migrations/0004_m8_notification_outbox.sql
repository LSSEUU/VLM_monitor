CREATE TABLE m8_notification_targets (
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 64),
    channel TEXT NOT NULL CHECK (channel IN (
        'LOCAL_OFFLINE_FAKE', 'FEISHU', 'WECHAT_WORK', 'DINGTALK'
    )),
    authority_revision INTEGER NOT NULL CHECK (authority_revision > 0),
    target_authority_id TEXT NOT NULL UNIQUE CHECK (
        length(target_authority_id) = 64 AND target_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    target_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(target_document_sha256) = 64
        AND target_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    prior_target_authority_id TEXT CHECK (
        prior_target_authority_id IS NULL OR (
            length(prior_target_authority_id) = 64
            AND prior_target_authority_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    prior_document_sha256 TEXT CHECK (
        prior_document_sha256 IS NULL OR (
            length(prior_document_sha256) = 64
            AND prior_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    PRIMARY KEY (actor_id, channel, authority_revision),
    CHECK ((prior_target_authority_id IS NULL) = (prior_document_sha256 IS NULL))
) STRICT;

CREATE INDEX idx_m8_notification_targets_current
ON m8_notification_targets(actor_id, channel, authority_revision DESC);

CREATE TRIGGER m8_notification_targets_validate_contiguous
BEFORE INSERT ON m8_notification_targets
WHEN NOT (
    (
        NEW.authority_revision = 1
        AND NEW.prior_target_authority_id IS NULL
        AND NEW.prior_document_sha256 IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM m8_notification_targets AS prior
            WHERE prior.actor_id = NEW.actor_id AND prior.channel = NEW.channel
        )
    )
    OR (
        NEW.authority_revision > 1
        AND EXISTS (
            SELECT 1 FROM m8_notification_targets AS prior
            WHERE prior.actor_id = NEW.actor_id
              AND prior.channel = NEW.channel
              AND prior.authority_revision = NEW.authority_revision - 1
              AND prior.target_authority_id = NEW.prior_target_authority_id
              AND prior.target_document_sha256 = NEW.prior_document_sha256
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 notification target revision must be contiguous');
END;

CREATE TABLE m8_notification_raw_artifacts (
    raw_artifact_ref TEXT PRIMARY KEY CHECK (
        length(raw_artifact_ref) BETWEEN 1 AND 512
        AND instr(raw_artifact_ref, '\') = 0
        AND instr(raw_artifact_ref, ':') = 0
    ),
    raw_artifact_sha256 TEXT NOT NULL CHECK (
        length(raw_artifact_sha256) = 64
        AND raw_artifact_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    raw_artifact_size_bytes INTEGER NOT NULL CHECK (
        raw_artifact_size_bytes BETWEEN 1 AND 1048576
    ),
    raw_artifact_bytes BLOB NOT NULL CHECK (length(raw_artifact_bytes) = raw_artifact_size_bytes),
    raw_storage_manifest_id TEXT NOT NULL CHECK (
        length(raw_storage_manifest_id) = 64
        AND raw_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    raw_commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(raw_commit_receipt_id) = 64
        AND raw_commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    UNIQUE (raw_artifact_ref, raw_artifact_sha256, raw_artifact_size_bytes)
) STRICT;

CREATE TABLE m8_notification_versions (
    notification_id TEXT NOT NULL CHECK (
        length(notification_id) = 64 AND notification_id NOT GLOB '*[^0-9a-f]*'
    ),
    notification_version INTEGER NOT NULL CHECK (notification_version > 0),
    status TEXT NOT NULL CHECK (status IN (
        'PLANNED', 'QUEUED', 'SENT', 'DELIVERED', 'FAILED',
        'ACKNOWLEDGED', 'RESPONDED'
    )),
    case_id TEXT NOT NULL CHECK (
        length(case_id) = 64 AND case_id NOT GLOB '*[^0-9a-f]*'
    ),
    case_version INTEGER NOT NULL CHECK (case_version > 0),
    target_actor_id TEXT NOT NULL CHECK (length(target_actor_id) BETWEEN 1 AND 64),
    target_channel TEXT NOT NULL CHECK (target_channel IN (
        'LOCAL_OFFLINE_FAKE', 'FEISHU', 'WECHAT_WORK', 'DINGTALK'
    )),
    target_authority_revision INTEGER NOT NULL CHECK (target_authority_revision > 0),
    target_authority_id TEXT NOT NULL CHECK (
        length(target_authority_id) = 64 AND target_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    plan_authority_id TEXT NOT NULL CHECK (
        length(plan_authority_id) = 64 AND plan_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    notification_authority_id TEXT NOT NULL UNIQUE CHECK (
        length(notification_authority_id) = 64
        AND notification_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    notification_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(notification_document_sha256) = 64
        AND notification_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    prior_notification_document_sha256 TEXT CHECK (
        prior_notification_document_sha256 IS NULL OR (
            length(prior_notification_document_sha256) = 64
            AND prior_notification_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    transition_command_id TEXT UNIQUE CHECK (
        transition_command_id IS NULL OR (
            length(transition_command_id) = 64
            AND transition_command_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    initiator_authority_id TEXT CHECK (
        initiator_authority_id IS NULL OR (
            length(initiator_authority_id) = 64
            AND initiator_authority_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    resolved_actor_document_sha256 TEXT CHECK (
        resolved_actor_document_sha256 IS NULL OR (
            length(resolved_actor_document_sha256) = 64
            AND resolved_actor_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    dispatch_result_id TEXT UNIQUE CHECK (
        dispatch_result_id IS NULL OR (
            length(dispatch_result_id) = 64 AND dispatch_result_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    delivery_receipt_id TEXT UNIQUE CHECK (
        delivery_receipt_id IS NULL OR (
            length(delivery_receipt_id) = 64 AND delivery_receipt_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    reply_authority_id TEXT UNIQUE CHECK (
        reply_authority_id IS NULL OR (
            length(reply_authority_id) = 64 AND reply_authority_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    raw_artifact_count INTEGER NOT NULL CHECK (raw_artifact_count BETWEEN 0 AND 2),
    raw_artifact_inventory_sha256 TEXT NOT NULL CHECK (
        length(raw_artifact_inventory_sha256) = 64
        AND raw_artifact_inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    total_raw_artifact_size_bytes INTEGER NOT NULL CHECK (
        total_raw_artifact_size_bytes BETWEEN 0 AND 2097152
    ),
    audit_event_id TEXT NOT NULL UNIQUE CHECK (
        length(audit_event_id) = 64 AND audit_event_id NOT GLOB '*[^0-9a-f]*'
    ),
    audit_event_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(audit_event_sha256) = 64 AND audit_event_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    prior_audit_event_sha256 TEXT NOT NULL CHECK (
        length(prior_audit_event_sha256) = 64
        AND prior_audit_event_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    notification_json TEXT NOT NULL CHECK (json_valid(notification_json)),
    audit_event_json TEXT NOT NULL CHECK (json_valid(audit_event_json)),
    commit_receipt_json TEXT NOT NULL CHECK (json_valid(commit_receipt_json)),
    PRIMARY KEY (notification_id, notification_version),
    FOREIGN KEY (case_id, case_version)
        REFERENCES m8_operational_case_versions(case_id, case_version),
    FOREIGN KEY (target_actor_id, target_channel, target_authority_revision)
        REFERENCES m8_notification_targets(actor_id, channel, authority_revision),
    CHECK (
        (notification_version = 1 AND status = 'PLANNED'
         AND prior_notification_document_sha256 IS NULL
         AND transition_command_id IS NULL AND initiator_authority_id IS NULL
         AND resolved_actor_document_sha256 IS NULL
         AND dispatch_result_id IS NULL AND delivery_receipt_id IS NULL
         AND reply_authority_id IS NULL AND raw_artifact_count = 0)
        OR
        (notification_version > 1
         AND prior_notification_document_sha256 IS NOT NULL
         AND transition_command_id IS NOT NULL AND initiator_authority_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX idx_m8_notifications_current
ON m8_notification_versions(notification_id, notification_version DESC);

CREATE INDEX idx_m8_notifications_status_current
ON m8_notification_versions(status, notification_id, notification_version DESC);

CREATE TABLE m8_notification_version_raw_artifacts (
    notification_id TEXT NOT NULL,
    notification_version INTEGER NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 1),
    raw_artifact_ref TEXT NOT NULL,
    PRIMARY KEY (notification_id, notification_version, position),
    UNIQUE (notification_id, notification_version, raw_artifact_ref),
    FOREIGN KEY (notification_id, notification_version)
        REFERENCES m8_notification_versions(notification_id, notification_version),
    FOREIGN KEY (raw_artifact_ref) REFERENCES m8_notification_raw_artifacts(raw_artifact_ref)
) STRICT;

CREATE TRIGGER m8_notification_versions_validate_contiguous
BEFORE INSERT ON m8_notification_versions
WHEN NOT (
    (
        NEW.notification_version = 1
        AND NEW.prior_notification_document_sha256 IS NULL
        AND NEW.prior_audit_event_sha256 =
            '0000000000000000000000000000000000000000000000000000000000000000'
        AND NOT EXISTS (
            SELECT 1 FROM m8_notification_versions AS prior
            WHERE prior.notification_id = NEW.notification_id
        )
    )
    OR (
        NEW.notification_version > 1
        AND EXISTS (
            SELECT 1 FROM m8_notification_versions AS prior
            WHERE prior.notification_id = NEW.notification_id
              AND prior.notification_version = NEW.notification_version - 1
              AND prior.notification_document_sha256 =
                  NEW.prior_notification_document_sha256
              AND prior.audit_event_sha256 = NEW.prior_audit_event_sha256
              AND prior.plan_authority_id = NEW.plan_authority_id
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 notification version and audit chain must be contiguous');
END;

CREATE TRIGGER m8_notification_targets_no_update
BEFORE UPDATE ON m8_notification_targets BEGIN
    SELECT RAISE(ABORT, 'M8 notification targets are append-only');
END;
CREATE TRIGGER m8_notification_targets_no_delete
BEFORE DELETE ON m8_notification_targets BEGIN
    SELECT RAISE(ABORT, 'M8 notification targets are append-only');
END;
CREATE TRIGGER m8_notification_targets_no_replace
BEFORE INSERT ON m8_notification_targets
WHEN EXISTS (
    SELECT 1 FROM m8_notification_targets AS existing
    WHERE existing.actor_id = NEW.actor_id
      AND existing.channel = NEW.channel
      AND existing.authority_revision = NEW.authority_revision
) BEGIN
    SELECT RAISE(ABORT, 'M8 notification targets are append-only');
END;
CREATE TRIGGER m8_notification_raw_artifacts_no_update
BEFORE UPDATE ON m8_notification_raw_artifacts BEGIN
    SELECT RAISE(ABORT, 'M8 notification raw artifacts are append-only');
END;
CREATE TRIGGER m8_notification_raw_artifacts_no_delete
BEFORE DELETE ON m8_notification_raw_artifacts BEGIN
    SELECT RAISE(ABORT, 'M8 notification raw artifacts are append-only');
END;
CREATE TRIGGER m8_notification_raw_artifacts_no_replace
BEFORE INSERT ON m8_notification_raw_artifacts
WHEN EXISTS (
    SELECT 1 FROM m8_notification_raw_artifacts AS existing
    WHERE existing.raw_artifact_ref = NEW.raw_artifact_ref
) BEGIN
    SELECT RAISE(ABORT, 'M8 notification raw artifacts are append-only');
END;
CREATE TRIGGER m8_notification_versions_no_update
BEFORE UPDATE ON m8_notification_versions BEGIN
    SELECT RAISE(ABORT, 'M8 notification versions are append-only');
END;
CREATE TRIGGER m8_notification_versions_no_delete
BEFORE DELETE ON m8_notification_versions BEGIN
    SELECT RAISE(ABORT, 'M8 notification versions are append-only');
END;
CREATE TRIGGER m8_notification_versions_no_replace
BEFORE INSERT ON m8_notification_versions
WHEN EXISTS (
    SELECT 1 FROM m8_notification_versions AS existing
    WHERE existing.notification_id = NEW.notification_id
      AND existing.notification_version = NEW.notification_version
) BEGIN
    SELECT RAISE(ABORT, 'M8 notification versions are append-only');
END;
CREATE TRIGGER m8_notification_version_raw_artifacts_no_update
BEFORE UPDATE ON m8_notification_version_raw_artifacts BEGIN
    SELECT RAISE(ABORT, 'M8 notification raw artifact links are append-only');
END;
CREATE TRIGGER m8_notification_version_raw_artifacts_no_delete
BEFORE DELETE ON m8_notification_version_raw_artifacts BEGIN
    SELECT RAISE(ABORT, 'M8 notification raw artifact links are append-only');
END;
CREATE TRIGGER m8_notification_version_raw_artifacts_no_replace
BEFORE INSERT ON m8_notification_version_raw_artifacts
WHEN EXISTS (
    SELECT 1 FROM m8_notification_version_raw_artifacts AS existing
    WHERE existing.notification_id = NEW.notification_id
      AND existing.notification_version = NEW.notification_version
      AND existing.position = NEW.position
) BEGIN
    SELECT RAISE(ABORT, 'M8 notification raw artifact links are append-only');
END;
