CREATE TABLE m8_agent_conversations (
    conversation_id TEXT PRIMARY KEY CHECK (
        length(conversation_id) = 64
        AND conversation_id NOT GLOB '*[^0-9a-f]*'
    ),
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL CHECK (
        actor_role IN ('LEADER', 'SAFETY_OFFICER', 'STUDENT', 'OPERATIONS')
    ),
    actor_authority_commit_receipt_id TEXT NOT NULL CHECK (
        length(actor_authority_commit_receipt_id) = 64
        AND actor_authority_commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE INDEX idx_m8_agent_conversations_actor
ON m8_agent_conversations(actor_id, created_at DESC, conversation_id);

CREATE TABLE m8_agent_turn_events (
    event_id TEXT PRIMARY KEY CHECK (
        length(event_id) = 64
        AND event_id NOT GLOB '*[^0-9a-f]*'
    ),
    conversation_id TEXT NOT NULL,
    turn_id TEXT NOT NULL CHECK (
        length(turn_id) = 64
        AND turn_id NOT GLOB '*[^0-9a-f]*'
    ),
    event_sequence INTEGER NOT NULL CHECK (event_sequence IN (1, 2)),
    event_kind TEXT NOT NULL CHECK (event_kind IN ('ACCEPTED', 'COMPLETED', 'FAILED')),
    occurred_at TEXT NOT NULL,
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    event_sha256 TEXT NOT NULL CHECK (
        length(event_sha256) = 64
        AND event_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    UNIQUE(conversation_id, turn_id, event_sequence),
    FOREIGN KEY (conversation_id) REFERENCES m8_agent_conversations(conversation_id)
) STRICT;

CREATE INDEX idx_m8_agent_turn_events_conversation
ON m8_agent_turn_events(conversation_id, occurred_at, turn_id, event_sequence);

CREATE TABLE m8_agent_raw_responses (
    raw_response_ref TEXT PRIMARY KEY,
    model_call_id TEXT NOT NULL UNIQUE,
    conversation_id TEXT NOT NULL,
    turn_id TEXT NOT NULL,
    round_index INTEGER NOT NULL CHECK (round_index BETWEEN 1 AND 4),
    content_sha256 TEXT NOT NULL CHECK (
        length(content_sha256) = 64
        AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 8388608),
    raw_bytes BLOB NOT NULL,
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    FOREIGN KEY (conversation_id) REFERENCES m8_agent_conversations(conversation_id)
) STRICT;

CREATE INDEX idx_m8_agent_raw_responses_turn
ON m8_agent_raw_responses(conversation_id, turn_id, round_index);

CREATE TABLE m8_agent_cache_entries (
    cache_key TEXT PRIMARY KEY CHECK (
        length(cache_key) = 64
        AND cache_key NOT GLOB '*[^0-9a-f]*'
    ),
    actor_authority_commit_receipt_id TEXT NOT NULL CHECK (
        length(actor_authority_commit_receipt_id) = 64
        AND actor_authority_commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    source_conversation_id TEXT NOT NULL,
    source_turn_id TEXT NOT NULL,
    completion_json TEXT NOT NULL CHECK (json_valid(completion_json)),
    completion_sha256 TEXT NOT NULL CHECK (
        length(completion_sha256) = 64
        AND completion_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    FOREIGN KEY (source_conversation_id) REFERENCES m8_agent_conversations(conversation_id)
) STRICT;

CREATE INDEX idx_m8_agent_cache_entries_actor
ON m8_agent_cache_entries(actor_authority_commit_receipt_id, created_at DESC);

CREATE TRIGGER m8_agent_conversations_no_update
BEFORE UPDATE ON m8_agent_conversations BEGIN
    SELECT RAISE(ABORT, 'M8 Agent conversations are append-only');
END;
CREATE TRIGGER m8_agent_conversations_no_delete
BEFORE DELETE ON m8_agent_conversations BEGIN
    SELECT RAISE(ABORT, 'M8 Agent conversations are append-only');
END;
CREATE TRIGGER m8_agent_conversations_no_replace
BEFORE INSERT ON m8_agent_conversations
WHEN EXISTS (
    SELECT 1 FROM m8_agent_conversations AS existing
    WHERE existing.conversation_id = NEW.conversation_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 Agent conversations are append-only');
END;

CREATE TRIGGER m8_agent_turn_events_validate_sequence
BEFORE INSERT ON m8_agent_turn_events BEGIN
    SELECT CASE
        WHEN NEW.event_sequence = 1 AND NEW.event_kind <> 'ACCEPTED'
            THEN RAISE(ABORT, 'M8 Agent first turn event must be ACCEPTED')
        WHEN NEW.event_sequence = 2 AND NEW.event_kind NOT IN ('COMPLETED', 'FAILED')
            THEN RAISE(ABORT, 'M8 Agent terminal turn event is invalid')
        WHEN NEW.event_sequence = 2 AND NOT EXISTS (
            SELECT 1 FROM m8_agent_turn_events AS accepted
            WHERE accepted.conversation_id = NEW.conversation_id
              AND accepted.turn_id = NEW.turn_id
              AND accepted.event_sequence = 1
              AND accepted.event_kind = 'ACCEPTED'
        ) THEN RAISE(ABORT, 'M8 Agent terminal turn event requires ACCEPTED')
    END;
END;
CREATE TRIGGER m8_agent_turn_events_no_update
BEFORE UPDATE ON m8_agent_turn_events BEGIN
    SELECT RAISE(ABORT, 'M8 Agent turn events are append-only');
END;
CREATE TRIGGER m8_agent_turn_events_no_delete
BEFORE DELETE ON m8_agent_turn_events BEGIN
    SELECT RAISE(ABORT, 'M8 Agent turn events are append-only');
END;
CREATE TRIGGER m8_agent_turn_events_no_replace
BEFORE INSERT ON m8_agent_turn_events
WHEN EXISTS (
    SELECT 1 FROM m8_agent_turn_events AS existing
    WHERE existing.event_id = NEW.event_id
       OR (existing.conversation_id = NEW.conversation_id
           AND existing.turn_id = NEW.turn_id
           AND existing.event_sequence = NEW.event_sequence)
) BEGIN
    SELECT RAISE(ABORT, 'M8 Agent turn events are append-only');
END;

CREATE TRIGGER m8_agent_raw_responses_no_update
BEFORE UPDATE ON m8_agent_raw_responses BEGIN
    SELECT RAISE(ABORT, 'M8 Agent raw responses are append-only');
END;
CREATE TRIGGER m8_agent_raw_responses_no_delete
BEFORE DELETE ON m8_agent_raw_responses BEGIN
    SELECT RAISE(ABORT, 'M8 Agent raw responses are append-only');
END;
CREATE TRIGGER m8_agent_raw_responses_no_replace
BEFORE INSERT ON m8_agent_raw_responses
WHEN EXISTS (
    SELECT 1 FROM m8_agent_raw_responses AS existing
    WHERE existing.raw_response_ref = NEW.raw_response_ref
       OR existing.model_call_id = NEW.model_call_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 Agent raw responses are append-only');
END;

CREATE TRIGGER m8_agent_cache_entries_no_update
BEFORE UPDATE ON m8_agent_cache_entries BEGIN
    SELECT RAISE(ABORT, 'M8 Agent cache entries are append-only');
END;
CREATE TRIGGER m8_agent_cache_entries_no_delete
BEFORE DELETE ON m8_agent_cache_entries BEGIN
    SELECT RAISE(ABORT, 'M8 Agent cache entries are append-only');
END;
CREATE TRIGGER m8_agent_cache_entries_no_replace
BEFORE INSERT ON m8_agent_cache_entries
WHEN EXISTS (
    SELECT 1 FROM m8_agent_cache_entries AS existing
    WHERE existing.cache_key = NEW.cache_key
) BEGIN
    SELECT RAISE(ABORT, 'M8 Agent cache entries are append-only');
END;
