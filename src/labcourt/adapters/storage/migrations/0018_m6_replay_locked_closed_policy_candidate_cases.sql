CREATE TABLE m6_replay_locked_closed_policy_candidate_cases (
    candidate_run_id TEXT NOT NULL
        CHECK (length(candidate_run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    pre_policy_execution_scope_authority_id TEXT NOT NULL
        CHECK (length(pre_policy_execution_scope_authority_id) = 64
               AND pre_policy_execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    ledger_sequence INTEGER NOT NULL
        CHECK (ledger_sequence BETWEEN 0 AND 99999),
    sample_id TEXT NOT NULL CHECK (length(sample_id) BETWEEN 1 AND 64),
    execution_entry_id TEXT NOT NULL
        CHECK (length(execution_entry_id) = 64
               AND execution_entry_id NOT GLOB '*[^0-9a-f]*'),
    source_catalog_entry_id TEXT NOT NULL
        CHECK (length(source_catalog_entry_id) = 64
               AND source_catalog_entry_id NOT GLOB '*[^0-9a-f]*'),
    pending_commitment_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(pending_commitment_authority_id) = 64
               AND pending_commitment_authority_id NOT GLOB '*[^0-9a-f]*'),
    pre_policy_pending_commitment_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(pre_policy_pending_commitment_authority_id) = 64
               AND pre_policy_pending_commitment_authority_id NOT GLOB '*[^0-9a-f]*'),
    source_binding_authority_id TEXT NOT NULL
        CHECK (length(source_binding_authority_id) = 64
               AND source_binding_authority_id NOT GLOB '*[^0-9a-f]*'),
    policy_causal_cut_authority_id TEXT NOT NULL
        CHECK (length(policy_causal_cut_authority_id) = 64
               AND policy_causal_cut_authority_id NOT GLOB '*[^0-9a-f]*'),
    locked_config_sha256 TEXT NOT NULL
        CHECK (length(locked_config_sha256) = 64
               AND locked_config_sha256 NOT GLOB '*[^0-9a-f]*'),
    route TEXT NOT NULL CHECK (route = 'ALERT_POLICY_CLOSED'),
    pre_policy_route TEXT NOT NULL
        CHECK (pre_policy_route IN (
            'M3_FAST_TERMINAL_POST_PARSE',
            'M4_HEARING_GATE_TERMINAL_POST_PARSE'
        )),
    case_id TEXT NOT NULL CHECK (length(case_id) = 36),
    event_id TEXT NOT NULL CHECK (length(event_id) = 36),
    case_revision INTEGER NOT NULL CHECK (case_revision = 1),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL CHECK (status = 'CLOSED'),
    case_json TEXT NOT NULL CHECK (json_valid(case_json)),
    case_document_sha256 TEXT NOT NULL
        CHECK (length(case_document_sha256) = 64
               AND case_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    case_document_size_bytes INTEGER NOT NULL
        CHECK (case_document_size_bytes BETWEEN 1 AND 268435456),
    candidate_alert_policy_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(candidate_alert_policy_authority_id) = 64
               AND candidate_alert_policy_authority_id NOT GLOB '*[^0-9a-f]*'),
    alert_policy_json TEXT NOT NULL CHECK (json_valid(alert_policy_json)),
    alert_policy_document_sha256 TEXT NOT NULL
        CHECK (length(alert_policy_document_sha256) = 64
               AND alert_policy_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    alert_policy_document_size_bytes INTEGER NOT NULL
        CHECK (alert_policy_document_size_bytes BETWEEN 1 AND 268435456),
    case_audit_sequence INTEGER NOT NULL CHECK (case_audit_sequence >= 0),
    case_audit_entry_hash TEXT NOT NULL
        CHECK (length(case_audit_entry_hash) = 64
               AND case_audit_entry_hash NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (candidate_run_id, ledger_sequence),
    UNIQUE (candidate_run_id, sample_id),
    UNIQUE (candidate_run_id, execution_entry_id),
    UNIQUE (candidate_run_id, case_id),
    UNIQUE (candidate_run_id, event_id),
    UNIQUE (execution_scope_authority_id, ledger_sequence),
    UNIQUE (pre_policy_execution_scope_authority_id, ledger_sequence),
    FOREIGN KEY (candidate_run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (
        candidate_run_id, case_audit_sequence, case_audit_entry_hash
    ) REFERENCES audit_entries(run_id, sequence, entry_hash)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (case_audit_sequence = ledger_sequence),
    CHECK (execution_scope_authority_id
           <> pre_policy_execution_scope_authority_id),
    CHECK (pending_commitment_authority_id
           <> pre_policy_pending_commitment_authority_id)
) STRICT;

-- The transient READY Case is never persisted.  This row atomically records
-- only its deterministic AlertPolicy intent and exact CLOSED successor.  The
-- V2 Scope/Pending and the embedded V1 pre-policy identities remain separate
-- filesystem authorities and are rejoined by the repository.
CREATE TRIGGER m6_replay_locked_closed_policy_candidate_cases_validate
BEFORE INSERT ON m6_replay_locked_closed_policy_candidate_cases
WHEN NOT EXISTS (
    SELECT 1
    FROM m6_replay_locked_closed_policy_candidate_cases AS existing
    WHERE (
        existing.candidate_run_id = NEW.candidate_run_id
        AND (
            existing.ledger_sequence = NEW.ledger_sequence
            OR existing.sample_id = NEW.sample_id
            OR existing.execution_entry_id = NEW.execution_entry_id
            OR existing.case_id = NEW.case_id
            OR existing.event_id = NEW.event_id
        )
    )
    OR existing.pending_commitment_authority_id
        = NEW.pending_commitment_authority_id
    OR existing.pre_policy_pending_commitment_authority_id
        = NEW.pre_policy_pending_commitment_authority_id
    OR existing.candidate_alert_policy_authority_id
        = NEW.candidate_alert_policy_authority_id
)
AND NOT EXISTS (
    SELECT 1
    FROM m6_replay_locked_candidate_cases AS existing
    WHERE existing.candidate_run_id = NEW.candidate_run_id
    OR existing.pending_commitment_authority_id IN (
        NEW.pending_commitment_authority_id,
        NEW.pre_policy_pending_commitment_authority_id
    )
    OR (
        existing.execution_scope_authority_id
            = NEW.pre_policy_execution_scope_authority_id
        AND existing.ledger_sequence = NEW.ledger_sequence
    )
)
AND NOT EXISTS (
    SELECT 1
    FROM m6_replay_locked_m4_candidate_cases AS existing
    WHERE existing.candidate_run_id = NEW.candidate_run_id
    OR existing.pending_commitment_authority_id IN (
        NEW.pending_commitment_authority_id,
        NEW.pre_policy_pending_commitment_authority_id
    )
    OR (
        existing.execution_scope_authority_id
            = NEW.pre_policy_execution_scope_authority_id
        AND existing.ledger_sequence = NEW.ledger_sequence
    )
)
AND (
    json_valid(NEW.case_json)
    AND NEW.case_json = json(NEW.case_json)
    AND json_type(NEW.case_json, '$') = 'object'
    AND json_extract(NEW.case_json, '$.run_id') = NEW.candidate_run_id
    AND json_extract(NEW.case_json, '$.case_id') = NEW.case_id
    AND json_extract(NEW.case_json, '$.event.event_id') = NEW.event_id
    AND json_extract(NEW.case_json, '$.manifest_id') = NEW.manifest_id
    AND json_extract(NEW.case_json, '$.status') = 'CLOSED'
    AND json_extract(NEW.case_json, '$.status') = NEW.status
    AND json_type(NEW.case_json, '$.evidence_packs') = 'array'
    AND json_array_length(NEW.case_json, '$.evidence_packs') = 1
    AND json_type(NEW.case_json, '$.screening_results') = 'array'
    AND json_array_length(NEW.case_json, '$.screening_results') = 1
    AND json_type(NEW.case_json, '$.verdicts') = 'array'
    AND json_array_length(NEW.case_json, '$.verdicts') = 1
    AND json_type(NEW.case_json, '$.procedural_reviews') = 'array'
    AND json_array_length(NEW.case_json, '$.procedural_reviews') = 1
    AND json_type(NEW.case_json, '$.appeals') = 'array'
    AND json_array_length(NEW.case_json, '$.appeals') = 0
    AND json_type(NEW.case_json, '$.timeline') = 'array'
    AND json_array_length(NEW.case_json, '$.timeline') = 1
    AND json_extract(NEW.case_json, '$.timeline[0].sequence') = 0
    AND json_extract(NEW.case_json, '$.timeline[0].action') = 'CASE_CLOSED'
    AND json_extract(NEW.case_json, '$.timeline[0].stage') = 'ALERT_POLICY'
    AND json_extract(NEW.case_json, '$.timeline[0].details.status') = 'CLOSED'
    AND json_type(NEW.case_json, '$.usage') = 'object'
    AND json_extract(NEW.case_json, '$.usage.input_images') = 0
    AND json_extract(NEW.case_json, '$.usage.input_pixels') = 0
    AND json_extract(NEW.case_json, '$.usage.input_tokens') = 0
    AND json_extract(NEW.case_json, '$.usage.output_tokens') = 0
    AND json_extract(NEW.case_json, '$.usage.provider_latency_ms') = 0
    AND json_extract(NEW.case_json, '$.usage.retries') = 0
    AND json_extract(NEW.case_json, '$.usage.estimated_cost') = 0
    AND json_extract(NEW.case_json, '$.evidence_packs[0].version') = 1
    AND json_type(NEW.case_json, '$.evidence_packs[0].tool_results') = 'array'
    AND json_array_length(NEW.case_json, '$.evidence_packs[0].tool_results') = 0
    AND json_extract(NEW.case_json, '$.screening_results[0].evidence_pack_id')
        = json_extract(NEW.case_json, '$.evidence_packs[0].pack_id')
    AND json_extract(NEW.case_json, '$.verdicts[0].screening_id')
        = json_extract(NEW.case_json, '$.screening_results[0].screening_id')
    AND json_extract(NEW.case_json, '$.verdicts[0].evidence_pack_id')
        = json_extract(NEW.case_json, '$.evidence_packs[0].pack_id')
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].reviewed_verdict_id')
        = json_extract(NEW.case_json, '$.verdicts[0].verdict_id')
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].evidence_pack_id')
        = json_extract(NEW.case_json, '$.evidence_packs[0].pack_id')
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].passed') = 1
    AND (
        (
            NEW.pre_policy_route = 'M3_FAST_TERMINAL_POST_PARSE'
            AND json_extract(NEW.case_json, '$.screening_results[0].decision')
                IN ('ESTABLISHED', 'NOT_ESTABLISHED')
        )
        OR (
            NEW.pre_policy_route = 'M4_HEARING_GATE_TERMINAL_POST_PARSE'
            AND json_extract(NEW.case_json, '$.screening_results[0].decision')
                = 'ESCALATE'
            AND json_extract(
                NEW.case_json,
                '$.screening_results[0].evidence_pack_version'
            ) = json_extract(NEW.case_json, '$.evidence_packs[0].version')
            AND json_extract(NEW.case_json, '$.verdicts[0].evidence_pack_version')
                = json_extract(NEW.case_json, '$.evidence_packs[0].version')
            AND json_extract(
                NEW.case_json,
                '$.procedural_reviews[0].reviewed_verdict_version'
            ) = json_extract(NEW.case_json, '$.verdicts[0].version')
            AND json_extract(
                NEW.case_json,
                '$.procedural_reviews[0].reviewed_verdict_sha256'
            ) = json_extract(NEW.case_json, '$.verdicts[0].verdict_sha256')
            AND json_extract(
                NEW.case_json,
                '$.procedural_reviews[0].evidence_pack_version'
            ) = json_extract(NEW.case_json, '$.evidence_packs[0].version')
        )
    )
    AND json_type(NEW.case_json, '$.final_decision') = 'text'
    AND json_type(NEW.case_json, '$.current_backlog_item_id') = 'null'
    AND json_valid(NEW.alert_policy_json)
    AND NEW.alert_policy_json = json(NEW.alert_policy_json)
    AND json_type(NEW.alert_policy_json, '$') = 'object'
    AND json_extract(NEW.alert_policy_json, '$.authority_id')
        = NEW.candidate_alert_policy_authority_id
    AND json_extract(NEW.alert_policy_json, '$.request.run_id')
        = NEW.candidate_run_id
    AND json_extract(NEW.alert_policy_json, '$.request.case_id') = NEW.case_id
    AND json_extract(NEW.alert_policy_json, '$.request.source_case_status')
        = 'READY_FOR_ALERT_POLICY'
    AND json_extract(NEW.alert_policy_json, '$.request.config_sha256')
        = NEW.locked_config_sha256
    AND json_extract(NEW.alert_policy_json, '$.request.manifest_id')
        = NEW.manifest_id
    AND json_extract(NEW.alert_policy_json, '$.request.camera_id')
        = json_extract(NEW.case_json, '$.event.camera_id')
    AND json_extract(NEW.alert_policy_json, '$.request.stream_id')
        = json_extract(NEW.case_json, '$.event.stream_id')
    AND json_extract(NEW.alert_policy_json, '$.request.zone_id')
        = json_extract(NEW.case_json, '$.event.zone_id')
    AND json_extract(NEW.alert_policy_json, '$.request.violation_type')
        = json_extract(NEW.case_json, '$.event.violation_type')
    AND json_extract(NEW.alert_policy_json, '$.request.trigger_frame')
        = json_extract(NEW.case_json, '$.event.trigger_frame')
    AND json_extract(NEW.alert_policy_json, '$.request.verdict_id')
        = json_extract(NEW.case_json, '$.verdicts[0].verdict_id')
    AND json_extract(NEW.alert_policy_json, '$.request.verdict_version')
        = json_extract(NEW.case_json, '$.verdicts[0].version')
    AND json_extract(NEW.alert_policy_json, '$.request.verdict_sha256')
        = json_extract(NEW.case_json, '$.verdicts[0].verdict_sha256')
    AND json_extract(NEW.alert_policy_json, '$.request.procedural_review_id')
        = json_extract(NEW.case_json, '$.procedural_reviews[0].review_id')
    AND json_extract(NEW.alert_policy_json, '$.request.procedural_review_version')
        = json_extract(NEW.case_json, '$.procedural_reviews[0].version')
    AND json_extract(NEW.alert_policy_json, '$.request.procedural_review_passed') = 1
    AND json_type(
        NEW.alert_policy_json,
        '$.request.prior_emergency_delivery'
    ) = 'null'
    AND json_extract(NEW.alert_policy_json, '$.target_case_status') = 'CLOSED'
    AND json_extract(NEW.alert_policy_json, '$.final_decision')
        = json_extract(NEW.case_json, '$.final_decision')
    AND json_type(NEW.alert_policy_json, '$.policy_rule_ids') = 'array'
    AND json_array_length(NEW.alert_policy_json, '$.policy_rule_ids') >= 1
    AND (
        (
            json_extract(NEW.alert_policy_json, '$.disposition') = 'CLOSE_NO_ALERT'
            AND json_extract(
                NEW.alert_policy_json,
                '$.request.verdict_decision'
            ) = 'NOT_ESTABLISHED'
            AND json_type(NEW.alert_policy_json, '$.decision') = 'null'
            AND json_type(NEW.alert_policy_json, '$.cooldown_write') = 'null'
            AND json_type(NEW.alert_policy_json, '$.outbox_item') = 'null'
            AND json_array_length(NEW.case_json, '$.alerts') = 0
            AND json_extract(NEW.case_json, '$.timeline[0].object_ref')
                = NEW.case_id
            AND json_extract(NEW.case_json, '$.timeline[0].details.alert_id') = 'NONE'
        )
        OR (
            json_extract(NEW.alert_policy_json, '$.disposition')
                IN ('ENQUEUE', 'SUPPRESSED_MERGED')
            AND json_type(NEW.alert_policy_json, '$.decision') = 'object'
            AND json_extract(NEW.alert_policy_json, '$.decision.case_id')
                = NEW.case_id
            AND json(
                json_extract(NEW.alert_policy_json, '$.decision.policy_rule_ids')
            ) = json(
                json_extract(NEW.alert_policy_json, '$.policy_rule_ids')
            )
            AND json_extract(NEW.alert_policy_json, '$.decision.rescinded') = 0
            AND json_type(NEW.case_json, '$.alerts') = 'array'
            AND json_array_length(NEW.case_json, '$.alerts') = 1
            AND json(json_extract(NEW.case_json, '$.alerts[0]'))
                = json(json_extract(NEW.alert_policy_json, '$.decision'))
            AND json_extract(NEW.case_json, '$.timeline[0].object_ref')
                = json_extract(NEW.alert_policy_json, '$.decision.alert_id')
            AND json_extract(NEW.case_json, '$.timeline[0].details.alert_id')
                = json_extract(NEW.alert_policy_json, '$.decision.alert_id')
            AND (
                (
                    json_extract(NEW.alert_policy_json, '$.disposition')
                        = 'SUPPRESSED_MERGED'
                    AND json_extract(
                        NEW.alert_policy_json,
                        '$.decision.suppressed_by_cooldown'
                    ) = 1
                    AND json_type(
                        NEW.alert_policy_json,
                        '$.decision.merged_into_alert_id'
                    ) = 'text'
                    AND json_type(NEW.alert_policy_json, '$.cooldown_write')
                        = 'null'
                    AND json_type(NEW.alert_policy_json, '$.outbox_item')
                        = 'null'
                )
                OR (
                    json_extract(NEW.alert_policy_json, '$.disposition')
                        = 'ENQUEUE'
                    AND json_extract(
                        NEW.alert_policy_json,
                        '$.decision.suppressed_by_cooldown'
                    ) = 0
                    AND json_type(
                        NEW.alert_policy_json,
                        '$.decision.merged_into_alert_id'
                    ) = 'null'
                    AND json_type(NEW.alert_policy_json, '$.outbox_item')
                        = 'object'
                    AND json_extract(NEW.alert_policy_json, '$.outbox_item.run_id')
                        = NEW.candidate_run_id
                    AND json_extract(NEW.alert_policy_json, '$.outbox_item.case_id')
                        = NEW.case_id
                    AND json_extract(
                        NEW.alert_policy_json,
                        '$.outbox_item.policy_request_id'
                    ) = json_extract(NEW.alert_policy_json, '$.request.request_id')
                    AND json_extract(
                        NEW.alert_policy_json,
                        '$.outbox_item.manifest_id'
                    ) = NEW.manifest_id
                    AND json(
                        json_extract(NEW.alert_policy_json, '$.outbox_item.alert')
                    ) = json(
                        json_extract(NEW.alert_policy_json, '$.decision')
                    )
                    AND json_extract(
                        NEW.alert_policy_json,
                        '$.outbox_item.idempotency_key'
                    ) = json_extract(NEW.alert_policy_json, '$.decision.alert_id')
                    AND (
                        (
                            json_type(
                                NEW.alert_policy_json,
                                '$.request.primary_track_ref'
                            ) = 'null'
                            AND json_type(
                                NEW.alert_policy_json,
                                '$.cooldown_write'
                            ) = 'null'
                        )
                        OR (
                            json_type(
                                NEW.alert_policy_json,
                                '$.request.primary_track_ref'
                            ) = 'text'
                            AND json_type(
                                NEW.alert_policy_json,
                                '$.cooldown_write'
                            ) = 'object'
                            AND json_extract(
                                NEW.alert_policy_json,
                                '$.cooldown_write.key.zone_id'
                            ) = json_extract(
                                NEW.alert_policy_json,
                                '$.request.zone_id'
                            )
                            AND json_extract(
                                NEW.alert_policy_json,
                                '$.cooldown_write.key.violation_type'
                            ) = json_extract(
                                NEW.alert_policy_json,
                                '$.request.violation_type'
                            )
                            AND json_extract(
                                NEW.alert_policy_json,
                                '$.cooldown_write.key.track_ref'
                            ) = json_extract(
                                NEW.alert_policy_json,
                                '$.request.primary_track_ref'
                            )
                            AND json_extract(
                                NEW.alert_policy_json,
                                '$.cooldown_write.stream_id'
                            ) = json_extract(
                                NEW.alert_policy_json,
                                '$.request.stream_id'
                            )
                            AND json_extract(
                                NEW.alert_policy_json,
                                '$.cooldown_write.source_alert_id'
                            ) = json_extract(
                                NEW.alert_policy_json,
                                '$.decision.alert_id'
                            )
                            AND json_extract(
                                NEW.alert_policy_json,
                                '$.cooldown_write.source_trigger_frame'
                            ) = json_extract(
                                NEW.alert_policy_json,
                                '$.request.trigger_frame'
                            )
                            AND json_extract(
                                NEW.alert_policy_json,
                                '$.cooldown_write.cooldown_frames'
                            ) = json_extract(
                                NEW.alert_policy_json,
                                '$.request.cooldown_frames'
                            )
                        )
                    )
                )
            )
        )
    )
    AND json_extract(NEW.case_json, '$.timeline[0].details.disposition')
        = json_extract(NEW.alert_policy_json, '$.disposition')
    AND length(CAST(NEW.case_json AS BLOB)) = NEW.case_document_size_bytes
    AND length(CAST(NEW.alert_policy_json AS BLOB))
        = NEW.alert_policy_document_size_bytes
    AND COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + COALESCE((
        SELECT SUM(
            existing.case_document_size_bytes
            + existing.alert_policy_document_size_bytes
        )
        FROM m6_replay_locked_closed_policy_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + NEW.case_document_size_bytes
       + NEW.alert_policy_document_size_bytes <= 268435456
    AND NEW.case_revision = 1
    AND NEW.case_audit_sequence = NEW.ledger_sequence
    AND NOT EXISTS (
        SELECT 1
        FROM m6_replay_locked_closed_policy_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
          AND (
              existing.execution_scope_authority_id
                  <> NEW.execution_scope_authority_id
              OR existing.pre_policy_execution_scope_authority_id
                  <> NEW.pre_policy_execution_scope_authority_id
          )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
          AND existing.execution_scope_authority_id
              <> NEW.pre_policy_execution_scope_authority_id
    )
    AND NOT EXISTS (
        SELECT 1
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
          AND existing.execution_scope_authority_id
              <> NEW.pre_policy_execution_scope_authority_id
    )
    AND (
        SELECT COUNT(*)
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ) + (
        SELECT COUNT(*)
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ) + (
        SELECT COUNT(*)
        FROM m6_replay_locked_closed_policy_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ) = NEW.ledger_sequence
    AND EXISTS (
        SELECT 1
        FROM audit_entries AS audit
        JOIN runs AS run
          ON run.run_id = audit.run_id
         AND run.manifest_id = audit.manifest_id
        WHERE audit.run_id = NEW.candidate_run_id
          AND audit.sequence = NEW.case_audit_sequence
          AND audit.manifest_id = NEW.manifest_id
          AND audit.actor = 'SYSTEM'
          AND audit.action = 'CASE_CREATED'
          AND audit.object_kind = 'CASE'
          AND audit.object_id = NEW.case_id
          AND audit.before_sha256 IS NULL
          AND audit.after_sha256 = NEW.case_document_sha256
          AND audit.entry_hash = NEW.case_audit_entry_hash
          AND run.revision = NEW.ledger_sequence + 1
          AND run.audit_head_sequence = NEW.ledger_sequence
          AND run.audit_head_hash = NEW.case_audit_entry_hash
    )
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 replay-locked CLOSED policy candidate');
END;

CREATE TRIGGER m6_replay_locked_closed_policy_candidate_cases_no_replace
BEFORE INSERT ON m6_replay_locked_closed_policy_candidate_cases
WHEN EXISTS (
    SELECT 1
    FROM m6_replay_locked_closed_policy_candidate_cases AS existing
    WHERE (
        existing.candidate_run_id = NEW.candidate_run_id
        AND (
            existing.ledger_sequence = NEW.ledger_sequence
            OR existing.sample_id = NEW.sample_id
            OR existing.execution_entry_id = NEW.execution_entry_id
            OR existing.case_id = NEW.case_id
            OR existing.event_id = NEW.event_id
        )
    )
    OR existing.pending_commitment_authority_id
        = NEW.pending_commitment_authority_id
    OR existing.pre_policy_pending_commitment_authority_id
        = NEW.pre_policy_pending_commitment_authority_id
    OR existing.candidate_alert_policy_authority_id
        = NEW.candidate_alert_policy_authority_id
)
BEGIN
    SELECT RAISE(
        ABORT,
        'M6 replay-locked CLOSED policy candidate Cases are append-only'
    );
END;

CREATE TRIGGER m6_replay_locked_closed_policy_candidate_cases_no_update
BEFORE UPDATE ON m6_replay_locked_closed_policy_candidate_cases
BEGIN
    SELECT RAISE(
        ABORT,
        'M6 replay-locked CLOSED policy candidate Cases are append-only'
    );
END;

CREATE TRIGGER m6_replay_locked_closed_policy_candidate_cases_no_delete
BEFORE DELETE ON m6_replay_locked_closed_policy_candidate_cases
BEGIN
    SELECT RAISE(
        ABORT,
        'M6 replay-locked CLOSED policy candidate Cases are append-only'
    );
END;

-- All three physical candidate tables consume one run-global 256 MiB budget.
-- These guards extend the legacy insertion direction without changing the
-- frozen 0016/0017 migration bytes or checksums.
CREATE TRIGGER m6_replay_locked_candidate_cases_closed_policy_budget
BEFORE INSERT ON m6_replay_locked_candidate_cases
WHEN (
    COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + COALESCE((
        SELECT SUM(
            existing.case_document_size_bytes
            + existing.alert_policy_document_size_bytes
        )
        FROM m6_replay_locked_closed_policy_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + NEW.case_document_size_bytes <= 268435456
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked candidate byte budget exceeded');
END;

CREATE TRIGGER m6_replay_locked_m4_candidate_cases_closed_policy_budget
BEFORE INSERT ON m6_replay_locked_m4_candidate_cases
WHEN (
    COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + COALESCE((
        SELECT SUM(
            existing.case_document_size_bytes
            + existing.alert_policy_document_size_bytes
        )
        FROM m6_replay_locked_closed_policy_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + NEW.case_document_size_bytes <= 268435456
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked candidate byte budget exceeded');
END;

-- Cross-generation identity collisions fail in both insertion directions.
CREATE TRIGGER m6_replay_locked_closed_policy_candidate_cases_cross_route_no_replace
BEFORE INSERT ON m6_replay_locked_closed_policy_candidate_cases
WHEN EXISTS (
    SELECT 1
    FROM m6_replay_locked_candidate_cases AS existing
    WHERE existing.candidate_run_id = NEW.candidate_run_id
    OR existing.pending_commitment_authority_id IN (
        NEW.pending_commitment_authority_id,
        NEW.pre_policy_pending_commitment_authority_id
    )
    OR (
        existing.execution_scope_authority_id
            = NEW.pre_policy_execution_scope_authority_id
        AND existing.ledger_sequence = NEW.ledger_sequence
    )
)
OR EXISTS (
    SELECT 1
    FROM m6_replay_locked_m4_candidate_cases AS existing
    WHERE existing.candidate_run_id = NEW.candidate_run_id
    OR existing.pending_commitment_authority_id IN (
        NEW.pending_commitment_authority_id,
        NEW.pre_policy_pending_commitment_authority_id
    )
    OR (
        existing.execution_scope_authority_id
            = NEW.pre_policy_execution_scope_authority_id
        AND existing.ledger_sequence = NEW.ledger_sequence
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked candidate generations are append-only');
END;

CREATE TRIGGER m6_replay_locked_candidate_cases_closed_policy_no_replace
BEFORE INSERT ON m6_replay_locked_candidate_cases
WHEN EXISTS (
    SELECT 1
    FROM m6_replay_locked_closed_policy_candidate_cases AS existing
    WHERE existing.candidate_run_id = NEW.candidate_run_id
    OR NEW.pending_commitment_authority_id IN (
        existing.pending_commitment_authority_id,
        existing.pre_policy_pending_commitment_authority_id
    )
    OR (
        NEW.execution_scope_authority_id
            = existing.pre_policy_execution_scope_authority_id
        AND NEW.ledger_sequence = existing.ledger_sequence
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked candidate generations are append-only');
END;

CREATE TRIGGER m6_replay_locked_m4_candidate_cases_closed_policy_no_replace
BEFORE INSERT ON m6_replay_locked_m4_candidate_cases
WHEN EXISTS (
    SELECT 1
    FROM m6_replay_locked_closed_policy_candidate_cases AS existing
    WHERE existing.candidate_run_id = NEW.candidate_run_id
    OR NEW.pending_commitment_authority_id IN (
        existing.pending_commitment_authority_id,
        existing.pre_policy_pending_commitment_authority_id
    )
    OR (
        NEW.execution_scope_authority_id
            = existing.pre_policy_execution_scope_authority_id
        AND NEW.ledger_sequence = existing.ledger_sequence
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked candidate generations are append-only');
END;
