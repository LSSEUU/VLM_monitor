CREATE TABLE m8_agent_conversation_removals (
    removal_receipt_id TEXT PRIMARY KEY
        CHECK(length(removal_receipt_id) = 64 AND removal_receipt_id NOT GLOB '*[^0-9a-f]*'),
    conversation_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    actor_authority_commit_receipt_id TEXT NOT NULL
        CHECK(length(actor_authority_commit_receipt_id) = 64
              AND actor_authority_commit_receipt_id NOT GLOB '*[^0-9a-f]*'),
    removed_at TEXT NOT NULL,
    repository_manifest_id TEXT NOT NULL
        CHECK(length(repository_manifest_id) = 64
              AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'),
    FOREIGN KEY (conversation_id) REFERENCES m8_agent_conversations(conversation_id)
) STRICT;

CREATE INDEX idx_m8_agent_conversation_removals_actor
ON m8_agent_conversation_removals(actor_id, removed_at DESC, conversation_id);

CREATE TRIGGER m8_agent_conversation_removals_no_update
BEFORE UPDATE ON m8_agent_conversation_removals BEGIN
    SELECT RAISE(ABORT, 'm8_agent_conversation_removals is append-only');
END;
CREATE TRIGGER m8_agent_conversation_removals_no_delete
BEFORE DELETE ON m8_agent_conversation_removals BEGIN
    SELECT RAISE(ABORT, 'm8_agent_conversation_removals is append-only');
END;
CREATE TRIGGER m8_agent_conversation_removals_no_replace
BEFORE INSERT ON m8_agent_conversation_removals
WHEN EXISTS (
    SELECT 1 FROM m8_agent_conversation_removals AS existing
    WHERE existing.removal_receipt_id = NEW.removal_receipt_id
       OR existing.conversation_id = NEW.conversation_id
)
BEGIN
    SELECT RAISE(ABORT, 'm8_agent_conversation_removals replacement is forbidden');
END;
