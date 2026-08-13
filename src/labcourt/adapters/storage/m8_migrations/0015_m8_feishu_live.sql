CREATE TABLE m8_feishu_duty_route_revisions (
    route_id TEXT PRIMARY KEY CHECK(length(route_id) = 64),
    route_revision INTEGER NOT NULL UNIQUE CHECK(route_revision > 0),
    route_json TEXT NOT NULL CHECK(json_valid(route_json)),
    committed_at TEXT NOT NULL
) STRICT;

CREATE TABLE m8_feishu_runtime_heartbeats (
    heartbeat_id TEXT PRIMARY KEY CHECK(length(heartbeat_id) = 64),
    component TEXT NOT NULL CHECK(component IN (
        'LONG_CONNECTION', 'AUTHORITY_WORKER', 'DELIVERY_WORKER'
    )),
    heartbeat_json TEXT NOT NULL CHECK(json_valid(heartbeat_json)),
    observed_at TEXT NOT NULL
) STRICT;
CREATE INDEX idx_m8_feishu_runtime_heartbeats_component
ON m8_feishu_runtime_heartbeats(component, observed_at DESC, heartbeat_id DESC);

CREATE TABLE m8_feishu_live_inbound_events (
    inbound_event_id TEXT PRIMARY KEY CHECK(length(inbound_event_id) = 64),
    provider_event_id TEXT NOT NULL UNIQUE,
    event_kind TEXT NOT NULL CHECK(event_kind IN ('DIRECT_MESSAGE', 'CARD_ACTION')),
    event_json TEXT NOT NULL CHECK(json_valid(event_json)),
    received_at TEXT NOT NULL
) STRICT;

CREATE TABLE m8_feishu_live_inbound_artifacts (
    artifact_ref TEXT PRIMARY KEY,
    inbound_event_id TEXT NOT NULL,
    artifact_kind TEXT NOT NULL CHECK(artifact_kind IN ('SANITIZED_EVENT', 'MESSAGE_CONTENT')),
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
    content_size_bytes INTEGER NOT NULL CHECK(content_size_bytes BETWEEN 0 AND 1048576),
    content_bytes BLOB NOT NULL,
    UNIQUE(inbound_event_id, artifact_kind),
    FOREIGN KEY(inbound_event_id) REFERENCES m8_feishu_live_inbound_events(inbound_event_id)
) STRICT;

CREATE TABLE m8_feishu_inbound_job_events (
    job_event_id TEXT PRIMARY KEY CHECK(length(job_event_id) = 64),
    inbound_event_id TEXT NOT NULL,
    state_revision INTEGER NOT NULL CHECK(state_revision BETWEEN 1 AND 3),
    state TEXT NOT NULL CHECK(state IN ('QUEUED', 'CLAIMED', 'COMPLETED', 'FAILED')),
    job_json TEXT NOT NULL CHECK(json_valid(job_json)),
    occurred_at TEXT NOT NULL,
    UNIQUE(inbound_event_id, state_revision),
    FOREIGN KEY(inbound_event_id) REFERENCES m8_feishu_live_inbound_events(inbound_event_id)
) STRICT;
CREATE INDEX idx_m8_feishu_inbound_job_events_state
ON m8_feishu_inbound_job_events(state, occurred_at, inbound_event_id);

CREATE TABLE m8_feishu_agent_conversation_bindings (
    conversation_id TEXT PRIMARY KEY CHECK(length(conversation_id) = 64),
    actor_id TEXT NOT NULL UNIQUE,
    binding_revision INTEGER NOT NULL CHECK(binding_revision > 0),
    projection_json TEXT NOT NULL CHECK(json_valid(projection_json)),
    bound_at TEXT NOT NULL,
    FOREIGN KEY(conversation_id) REFERENCES m8_agent_conversations(conversation_id)
) STRICT;

CREATE TABLE m8_feishu_agent_turn_origins (
    turn_id TEXT PRIMARY KEY CHECK(length(turn_id) = 64),
    conversation_id TEXT NOT NULL CHECK(length(conversation_id) = 64),
    origin TEXT NOT NULL CHECK(origin IN ('WEB', 'FEISHU')),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY(conversation_id) REFERENCES m8_feishu_agent_conversation_bindings(conversation_id)
) STRICT;

CREATE TABLE m8_feishu_card_action_intents (
    intent_id TEXT PRIMARY KEY CHECK(length(intent_id) = 64),
    confirmation_token_sha256 TEXT NOT NULL UNIQUE CHECK(length(confirmation_token_sha256) = 64),
    intent_json TEXT NOT NULL CHECK(json_valid(intent_json)),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE m8_feishu_card_action_receipts (
    action_receipt_id TEXT PRIMARY KEY CHECK(length(action_receipt_id) = 64),
    intent_id TEXT NOT NULL UNIQUE,
    receipt_json TEXT NOT NULL CHECK(json_valid(receipt_json)),
    completed_at TEXT NOT NULL,
    FOREIGN KEY(intent_id) REFERENCES m8_feishu_card_action_intents(intent_id)
) STRICT;

CREATE TABLE m8_feishu_alert_bridge_receipts (
    bridge_receipt_id TEXT PRIMARY KEY CHECK(length(bridge_receipt_id) = 64),
    source_case_id TEXT NOT NULL,
    source_case_version INTEGER NOT NULL CHECK(source_case_version > 0),
    receipt_json TEXT NOT NULL CHECK(json_valid(receipt_json)),
    assessed_at TEXT NOT NULL,
    UNIQUE(source_case_id, source_case_version)
) STRICT;

CREATE TABLE m8_feishu_reminder_receipts (
    reminder_receipt_id TEXT PRIMARY KEY CHECK(length(reminder_receipt_id) = 64),
    source_dispatch_request_id TEXT NOT NULL UNIQUE,
    receipt_json TEXT NOT NULL CHECK(json_valid(receipt_json)),
    assessed_at TEXT NOT NULL
) STRICT;

CREATE TABLE m8_feishu_agent_reply_outbox (
    outbox_id TEXT PRIMARY KEY CHECK(length(outbox_id) = 64),
    envelope_json TEXT NOT NULL CHECK(json_valid(envelope_json)),
    content_ref TEXT NOT NULL UNIQUE,
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
    content_size_bytes INTEGER NOT NULL CHECK(content_size_bytes BETWEEN 1 AND 30720),
    content_bytes BLOB NOT NULL,
    queued_at TEXT NOT NULL
) STRICT;

CREATE TABLE m8_feishu_agent_reply_claim_events (
    claim_event_id TEXT PRIMARY KEY CHECK(length(claim_event_id) = 64),
    outbox_id TEXT NOT NULL,
    claim_kind TEXT NOT NULL CHECK(claim_kind IN ('CLAIMED', 'RELEASED')),
    worker_token_sha256 TEXT NOT NULL CHECK(length(worker_token_sha256) = 64),
    claim_fence INTEGER NOT NULL CHECK(claim_fence > 0),
    occurred_at TEXT NOT NULL,
    UNIQUE(outbox_id, claim_fence, claim_kind),
    FOREIGN KEY(outbox_id) REFERENCES m8_feishu_agent_reply_outbox(outbox_id)
) STRICT;

CREATE TABLE m8_feishu_agent_reply_completions (
    completion_id TEXT PRIMARY KEY CHECK(length(completion_id) = 64),
    outbox_id TEXT NOT NULL UNIQUE,
    completion_json TEXT NOT NULL CHECK(json_valid(completion_json)),
    raw_response_ref TEXT NOT NULL UNIQUE,
    raw_response_sha256 TEXT NOT NULL CHECK(length(raw_response_sha256) = 64),
    raw_response_bytes BLOB NOT NULL,
    completed_at TEXT NOT NULL,
    FOREIGN KEY(outbox_id) REFERENCES m8_feishu_agent_reply_outbox(outbox_id)
) STRICT;

CREATE TRIGGER m8_feishu_inbound_job_events_validate_sequence
BEFORE INSERT ON m8_feishu_inbound_job_events BEGIN
    SELECT CASE
        WHEN NEW.state_revision = 1 AND NEW.state <> 'QUEUED'
            THEN RAISE(ABORT, 'M8 Feishu inbound job must begin QUEUED')
        WHEN NEW.state_revision = 2 AND NEW.state <> 'CLAIMED'
            THEN RAISE(ABORT, 'M8 Feishu inbound job revision 2 must be CLAIMED')
        WHEN NEW.state_revision = 3 AND NEW.state NOT IN ('COMPLETED', 'FAILED')
            THEN RAISE(ABORT, 'M8 Feishu inbound job revision 3 must be terminal')
        WHEN NEW.state_revision > 1 AND NOT EXISTS (
            SELECT 1 FROM m8_feishu_inbound_job_events AS prior
            WHERE prior.inbound_event_id = NEW.inbound_event_id
              AND prior.state_revision = NEW.state_revision - 1
        ) THEN RAISE(ABORT, 'M8 Feishu inbound job state requires prior event')
    END;
END;

CREATE TRIGGER m8_feishu_agent_reply_claim_events_validate
BEFORE INSERT ON m8_feishu_agent_reply_claim_events BEGIN
    SELECT CASE
        WHEN EXISTS (
            SELECT 1 FROM m8_feishu_agent_reply_completions AS completed
            WHERE completed.outbox_id = NEW.outbox_id
        ) THEN RAISE(ABORT, 'M8 Feishu completed Agent reply cannot be claimed')
        WHEN NEW.claim_kind = 'CLAIMED' AND EXISTS (
            SELECT 1 FROM m8_feishu_agent_reply_claim_events AS earlier
            WHERE earlier.outbox_id = NEW.outbox_id
              AND earlier.claim_kind = 'CLAIMED'
        ) THEN RAISE(ABORT, 'M8 Feishu Agent reply is single-attempt')
    END;
END;

CREATE TRIGGER m8_feishu_agent_reply_completions_validate_claim
BEFORE INSERT ON m8_feishu_agent_reply_completions
WHEN NOT EXISTS (
    SELECT 1 FROM m8_feishu_agent_reply_claim_events AS claim
    WHERE claim.outbox_id = NEW.outbox_id AND claim.claim_kind = 'CLAIMED'
) BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu Agent reply completion requires claim');
END;

CREATE TRIGGER m8_feishu_duty_route_revisions_no_update BEFORE UPDATE ON m8_feishu_duty_route_revisions BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_duty_route_revisions_no_delete BEFORE DELETE ON m8_feishu_duty_route_revisions BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_runtime_heartbeats_no_update BEFORE UPDATE ON m8_feishu_runtime_heartbeats BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_runtime_heartbeats_no_delete BEFORE DELETE ON m8_feishu_runtime_heartbeats BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_live_inbound_events_no_update BEFORE UPDATE ON m8_feishu_live_inbound_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_live_inbound_events_no_delete BEFORE DELETE ON m8_feishu_live_inbound_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_live_inbound_artifacts_no_update BEFORE UPDATE ON m8_feishu_live_inbound_artifacts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_live_inbound_artifacts_no_delete BEFORE DELETE ON m8_feishu_live_inbound_artifacts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_inbound_job_events_no_update BEFORE UPDATE ON m8_feishu_inbound_job_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_inbound_job_events_no_delete BEFORE DELETE ON m8_feishu_inbound_job_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_conversation_bindings_no_update BEFORE UPDATE ON m8_feishu_agent_conversation_bindings BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_conversation_bindings_no_delete BEFORE DELETE ON m8_feishu_agent_conversation_bindings BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_turn_origins_no_update BEFORE UPDATE ON m8_feishu_agent_turn_origins BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_turn_origins_no_delete BEFORE DELETE ON m8_feishu_agent_turn_origins BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_card_action_intents_no_update BEFORE UPDATE ON m8_feishu_card_action_intents BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_card_action_intents_no_delete BEFORE DELETE ON m8_feishu_card_action_intents BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_card_action_receipts_no_update BEFORE UPDATE ON m8_feishu_card_action_receipts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_card_action_receipts_no_delete BEFORE DELETE ON m8_feishu_card_action_receipts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_alert_bridge_receipts_no_update BEFORE UPDATE ON m8_feishu_alert_bridge_receipts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_alert_bridge_receipts_no_delete BEFORE DELETE ON m8_feishu_alert_bridge_receipts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_reminder_receipts_no_update BEFORE UPDATE ON m8_feishu_reminder_receipts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_reminder_receipts_no_delete BEFORE DELETE ON m8_feishu_reminder_receipts BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_reply_outbox_no_update BEFORE UPDATE ON m8_feishu_agent_reply_outbox BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_reply_outbox_no_delete BEFORE DELETE ON m8_feishu_agent_reply_outbox BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_reply_claim_events_no_update BEFORE UPDATE ON m8_feishu_agent_reply_claim_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_reply_claim_events_no_delete BEFORE DELETE ON m8_feishu_agent_reply_claim_events BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_reply_completions_no_update BEFORE UPDATE ON m8_feishu_agent_reply_completions BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER m8_feishu_agent_reply_completions_no_delete BEFORE DELETE ON m8_feishu_agent_reply_completions BEGIN SELECT RAISE(ABORT, 'append-only'); END;
