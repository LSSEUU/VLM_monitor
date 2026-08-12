CREATE TABLE m8_feishu_inbound_message_commits (
    commit_receipt_id TEXT PRIMARY KEY CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    verification_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(verification_receipt_id) = 64
        AND verification_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    inbound_profile_id TEXT NOT NULL CHECK (
        length(inbound_profile_id) = 64 AND inbound_profile_id NOT GLOB '*[^0-9a-f]*'
    ),
    ingress_request_id TEXT NOT NULL UNIQUE CHECK (
        length(ingress_request_id) = 64 AND ingress_request_id NOT GLOB '*[^0-9a-f]*'
    ),
    provider_message_id TEXT NOT NULL UNIQUE CHECK (
        length(provider_message_id) BETWEEN 1 AND 64
    ),
    provider_event_id TEXT NOT NULL CHECK (length(provider_event_id) BETWEEN 1 AND 64),
    provider_parent_message_id TEXT NOT NULL CHECK (
        length(provider_parent_message_id) BETWEEN 1 AND 64
    ),
    committed_at TEXT NOT NULL CHECK (length(committed_at) = 27),
    raw_artifact_inventory_sha256 TEXT NOT NULL CHECK (
        length(raw_artifact_inventory_sha256) = 64
        AND raw_artifact_inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    total_raw_artifact_size_bytes INTEGER NOT NULL CHECK (
        total_raw_artifact_size_bytes > 0
    ),
    raw_storage_manifest_id TEXT NOT NULL CHECK (
        length(raw_storage_manifest_id) = 64
        AND raw_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_manifest_id TEXT NOT NULL CHECK (
        length(commit_manifest_id) = 64 AND commit_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (
        json_valid(receipt_json)
        AND json_extract(receipt_json, '$.schema_version') =
            'm8-feishu-inbound-message-commit-receipt-v1'
        AND json_extract(receipt_json, '$.commit_receipt_id') = commit_receipt_id
        AND json_extract(receipt_json, '$.verification_receipt.verification_receipt_id') =
            verification_receipt_id
        AND json_extract(receipt_json, '$.verification_receipt.profile.inbound_profile_id') =
            inbound_profile_id
        AND json_extract(
            receipt_json,
            '$.verification_receipt.ingress_request.ingress_request_id'
        ) = ingress_request_id
        AND json_extract(receipt_json, '$.provider_message_id') = provider_message_id
        AND json_extract(receipt_json, '$.verification_receipt.provider_event_id') =
            provider_event_id
        AND json_extract(
            receipt_json,
            '$.verification_receipt.provider_parent_message_id'
        ) = provider_parent_message_id
        AND json_extract(receipt_json, '$.raw_artifact_inventory_sha256') =
            raw_artifact_inventory_sha256
        AND json_extract(receipt_json, '$.total_raw_artifact_size_bytes') =
            total_raw_artifact_size_bytes
        AND json_extract(receipt_json, '$.raw_storage_manifest_id') =
            raw_storage_manifest_id
        AND json_extract(receipt_json, '$.commit_manifest_id') = commit_manifest_id
        AND json_extract(receipt_json, '$.repository_manifest_id') =
            repository_manifest_id
        AND json_extract(receipt_json, '$.verified_evidence_persisted') = 1
        AND json_extract(receipt_json, '$.automatic_replay_permitted') = 0
        AND json_extract(receipt_json, '$.notification_reply_commit_permitted') = 0
        AND json_extract(receipt_json, '$.case_transition_permitted') = 0
        AND json_extract(receipt_json, '$.direct_disciplinary_action_permitted') = 0
    )
) STRICT;

CREATE INDEX idx_m8_feishu_inbound_messages_parent
ON m8_feishu_inbound_message_commits(provider_parent_message_id, provider_message_id);

CREATE TABLE m8_feishu_inbound_raw_artifacts (
    raw_artifact_ref TEXT PRIMARY KEY CHECK (length(raw_artifact_ref) BETWEEN 1 AND 64),
    commit_receipt_id TEXT NOT NULL,
    artifact_ordinal INTEGER NOT NULL CHECK (artifact_ordinal BETWEEN 0 AND 2),
    raw_artifact_sha256 TEXT NOT NULL CHECK (
        length(raw_artifact_sha256) = 64
        AND raw_artifact_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    raw_artifact_size_bytes INTEGER NOT NULL CHECK (raw_artifact_size_bytes > 0),
    raw_bytes BLOB NOT NULL CHECK (length(raw_bytes) = raw_artifact_size_bytes),
    raw_storage_manifest_id TEXT NOT NULL CHECK (
        length(raw_storage_manifest_id) = 64
        AND raw_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    UNIQUE (commit_receipt_id, artifact_ordinal),
    FOREIGN KEY (commit_receipt_id)
        REFERENCES m8_feishu_inbound_message_commits(commit_receipt_id)
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TRIGGER m8_feishu_inbound_message_commits_no_update
BEFORE UPDATE ON m8_feishu_inbound_message_commits BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound message commits are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_message_commits_no_delete
BEFORE DELETE ON m8_feishu_inbound_message_commits BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound message commits are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_message_commits_no_replace
BEFORE INSERT ON m8_feishu_inbound_message_commits
WHEN EXISTS (
    SELECT 1 FROM m8_feishu_inbound_message_commits
    WHERE commit_receipt_id = NEW.commit_receipt_id
       OR verification_receipt_id = NEW.verification_receipt_id
       OR ingress_request_id = NEW.ingress_request_id
       OR provider_message_id = NEW.provider_message_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound message commits are append-only');
END;

CREATE TRIGGER m8_feishu_inbound_raw_artifacts_no_update
BEFORE UPDATE ON m8_feishu_inbound_raw_artifacts BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound raw artifacts are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_raw_artifacts_no_delete
BEFORE DELETE ON m8_feishu_inbound_raw_artifacts BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound raw artifacts are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_raw_artifacts_no_replace
BEFORE INSERT ON m8_feishu_inbound_raw_artifacts
WHEN EXISTS (
    SELECT 1 FROM m8_feishu_inbound_raw_artifacts
    WHERE raw_artifact_ref = NEW.raw_artifact_ref
       OR (
           commit_receipt_id = NEW.commit_receipt_id
           AND artifact_ordinal = NEW.artifact_ordinal
       )
) BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound raw artifacts are append-only');
END;
