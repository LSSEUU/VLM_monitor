CREATE UNIQUE INDEX idx_m8_notification_provider_receipt
ON m8_notification_versions(
    json_extract(
        commit_receipt_json,
        '$.audit_event.transition_command.dispatch_result.request.channel_capability.adapter_id'
    ),
    json_extract(
        commit_receipt_json,
        '$.audit_event.transition_command.dispatch_result.provider_receipt_id'
    )
)
WHERE status = 'SENT' AND target_channel = 'FEISHU'
  AND json_extract(
      commit_receipt_json,
      '$.audit_event.transition_command.dispatch_result.provider_receipt_id'
  ) IS NOT NULL;

CREATE TABLE m8_feishu_inbound_reply_commits (
    commit_receipt_id TEXT PRIMARY KEY CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    provider_message_id TEXT NOT NULL UNIQUE CHECK (
        length(provider_message_id) BETWEEN 1 AND 64
    ),
    correlation_authority_id TEXT NOT NULL UNIQUE CHECK (
        length(correlation_authority_id) = 64
        AND correlation_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    correlation_authority_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(correlation_authority_document_sha256) = 64
        AND correlation_authority_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    inbound_commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(inbound_commit_receipt_id) = 64
        AND inbound_commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    outbound_provider_message_id TEXT NOT NULL CHECK (
        length(outbound_provider_message_id) BETWEEN 1 AND 512
    ),
    notification_id TEXT NOT NULL CHECK (
        length(notification_id) = 64 AND notification_id NOT GLOB '*[^0-9a-f]*'
    ),
    source_notification_version INTEGER NOT NULL CHECK (source_notification_version > 0),
    notification_version INTEGER NOT NULL CHECK (
        notification_version = source_notification_version + 1
    ),
    notification_commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(notification_commit_receipt_id) = 64
        AND notification_commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    reply_authority_id TEXT NOT NULL UNIQUE CHECK (
        length(reply_authority_id) = 64 AND reply_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    reply_commit_manifest_id TEXT NOT NULL CHECK (
        length(reply_commit_manifest_id) = 64
        AND reply_commit_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (
        json_valid(receipt_json)
        AND json_extract(receipt_json, '$.schema_version') =
            'm8-feishu-inbound-reply-commit-receipt-v1'
        AND json_extract(receipt_json, '$.commit_receipt_id') = commit_receipt_id
        AND json_extract(receipt_json, '$.provider_message_deduplication_key') =
            provider_message_id
        AND json_extract(
            receipt_json,
            '$.correlation_authority.correlation_authority_id'
        ) = correlation_authority_id
        AND json_extract(
            receipt_json,
            '$.correlation_authority.correlation_authority_document_sha256'
        ) = correlation_authority_document_sha256
        AND json_extract(
            receipt_json,
            '$.correlation_authority.inbound_commit.commit_receipt_id'
        ) = inbound_commit_receipt_id
        AND json_extract(
            receipt_json,
            '$.correlation_authority.reply_correlation_message_id'
        ) = outbound_provider_message_id
        AND json_extract(receipt_json, '$.notification_commit.notification_id') =
            notification_id
        AND json_extract(
            receipt_json,
            '$.correlation_authority.notification_commit_chain[#-1].notification_version'
        ) = source_notification_version
        AND json_extract(receipt_json, '$.notification_commit.notification_version') =
            notification_version
        AND json_extract(receipt_json, '$.notification_commit.commit_receipt_id') =
            notification_commit_receipt_id
        AND json_extract(
            receipt_json,
            '$.notification_commit.audit_event.transition_command.reply.reply_authority_id'
        ) = reply_authority_id
        AND json_extract(receipt_json, '$.reply_commit_manifest_id') = reply_commit_manifest_id
        AND json_extract(receipt_json, '$.notification_reply_committed') = 1
        AND json_extract(receipt_json, '$.automatic_replay_permitted') = 0
        AND json_extract(receipt_json, '$.case_transition_permitted') = 0
        AND json_extract(receipt_json, '$.direct_disciplinary_action_permitted') = 0
    ),
    FOREIGN KEY (inbound_commit_receipt_id)
        REFERENCES m8_feishu_inbound_message_commits(commit_receipt_id),
    FOREIGN KEY (notification_id, notification_version)
        REFERENCES m8_notification_versions(notification_id, notification_version)
) STRICT;

CREATE INDEX idx_m8_feishu_inbound_replies_notification
ON m8_feishu_inbound_reply_commits(notification_id, notification_version);

CREATE TRIGGER m8_feishu_inbound_reply_commits_no_update
BEFORE UPDATE ON m8_feishu_inbound_reply_commits BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound reply commits are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_reply_commits_no_delete
BEFORE DELETE ON m8_feishu_inbound_reply_commits BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound reply commits are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_reply_commits_no_replace
BEFORE INSERT ON m8_feishu_inbound_reply_commits
WHEN EXISTS (
    SELECT 1 FROM m8_feishu_inbound_reply_commits
    WHERE commit_receipt_id = NEW.commit_receipt_id
       OR provider_message_id = NEW.provider_message_id
       OR correlation_authority_id = NEW.correlation_authority_id
       OR inbound_commit_receipt_id = NEW.inbound_commit_receipt_id
       OR notification_commit_receipt_id = NEW.notification_commit_receipt_id
       OR reply_authority_id = NEW.reply_authority_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound reply commits are append-only');
END;
