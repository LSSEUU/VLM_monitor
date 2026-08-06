CREATE TABLE m6_replay_locked_m4_candidate_cases (
    candidate_run_id TEXT NOT NULL
        CHECK (length(candidate_run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
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
    route TEXT NOT NULL
        CHECK (route = 'M4_HEARING_GATE_TERMINAL_POST_PARSE'),
    case_id TEXT NOT NULL CHECK (length(case_id) = 36),
    event_id TEXT NOT NULL CHECK (length(event_id) = 36),
    case_revision INTEGER NOT NULL CHECK (case_revision = 1),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL
        CHECK (status IN ('READY_FOR_ALERT_POLICY', 'REWORK_REQUIRED')),
    case_json TEXT NOT NULL CHECK (json_valid(case_json)),
    case_document_sha256 TEXT NOT NULL
        CHECK (length(case_document_sha256) = 64
               AND case_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    case_document_size_bytes INTEGER NOT NULL
        CHECK (case_document_size_bytes BETWEEN 1 AND 268435456),
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
    FOREIGN KEY (candidate_run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (
        candidate_run_id, case_audit_sequence, case_audit_entry_hash
    ) REFERENCES audit_entries(run_id, sequence, entry_hash)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (case_audit_sequence = ledger_sequence)
) STRICT;

-- Migration 0016 is immutable.  Replace only its validation trigger so both
-- replay routes consume one run-global byte budget, scope, and ledger prefix.
DROP TRIGGER m6_replay_locked_candidate_cases_validate;
DROP TRIGGER m6_replay_locked_candidate_cases_no_replace;

CREATE TRIGGER m6_replay_locked_candidate_cases_validate
BEFORE INSERT ON m6_replay_locked_candidate_cases
WHEN NOT EXISTS (
    SELECT 1
    FROM m6_replay_locked_candidate_cases AS existing
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
)
AND NOT EXISTS (
    SELECT 1
    FROM m6_replay_locked_m4_candidate_cases AS existing
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
    OR (
        existing.execution_scope_authority_id = NEW.execution_scope_authority_id
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
    AND json_extract(NEW.case_json, '$.status') = NEW.status
    AND json_type(NEW.case_json, '$.evidence_packs') = 'array'
    AND json_array_length(NEW.case_json, '$.evidence_packs') = 1
    AND json_type(NEW.case_json, '$.screening_results') = 'array'
    AND json_array_length(NEW.case_json, '$.screening_results') = 1
    AND json_type(NEW.case_json, '$.verdicts') = 'array'
    AND json_array_length(NEW.case_json, '$.verdicts') = 1
    AND json_type(NEW.case_json, '$.procedural_reviews') = 'array'
    AND json_array_length(NEW.case_json, '$.procedural_reviews') = 1
    AND json_type(NEW.case_json, '$.alerts') = 'array'
    AND json_array_length(NEW.case_json, '$.alerts') = 0
    AND json_type(NEW.case_json, '$.appeals') = 'array'
    AND json_array_length(NEW.case_json, '$.appeals') = 0
    AND json_type(NEW.case_json, '$.timeline') = 'array'
    AND json_array_length(NEW.case_json, '$.timeline') = 0
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
    AND json_extract(NEW.case_json, '$.screening_results[0].decision')
        IN ('ESTABLISHED', 'NOT_ESTABLISHED')
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
    AND (
        (
            json_extract(NEW.case_json, '$.procedural_reviews[0].passed') = 1
            AND NEW.status = 'READY_FOR_ALERT_POLICY'
        )
        OR (
            json_extract(NEW.case_json, '$.procedural_reviews[0].passed') = 0
            AND NEW.status = 'REWORK_REQUIRED'
        )
    )
    AND json_type(NEW.case_json, '$.final_decision') = 'null'
    AND json_type(NEW.case_json, '$.current_backlog_item_id') = 'null'
    AND length(CAST(NEW.case_json AS BLOB)) = NEW.case_document_size_bytes
    AND COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + NEW.case_document_size_bytes <= 268435456
    AND NEW.case_revision = 1
    AND NEW.case_audit_sequence = NEW.ledger_sequence
    AND NOT EXISTS (
        SELECT 1
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
          AND existing.execution_scope_authority_id
              <> NEW.execution_scope_authority_id
    )
    AND NOT EXISTS (
        SELECT 1
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
          AND existing.execution_scope_authority_id
              <> NEW.execution_scope_authority_id
    )
    AND (
        SELECT COUNT(*)
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ) + (
        SELECT COUNT(*)
        FROM m6_replay_locked_m4_candidate_cases AS existing
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
    SELECT RAISE(ABORT, 'invalid M6 replay-locked candidate Case');
END;

-- Recreate no-replace after validation.  The validation trigger also excludes
-- every collision path, so replacement retains the v16 append-only exit
-- independently of the replacement payload's validity.
CREATE TRIGGER m6_replay_locked_candidate_cases_no_replace
BEFORE INSERT ON m6_replay_locked_candidate_cases
WHEN EXISTS (
    SELECT 1
    FROM m6_replay_locked_candidate_cases AS existing
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
)
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked candidate Cases are append-only');
END;

-- An M4 candidate is a single terminal post-parse unit: the ESCALATE
-- screening, hearing Verdict, and ProceduralReview must all bind the same
-- Case, manifest, evidence-pack revision, and verdict document.
CREATE TRIGGER m6_replay_locked_m4_candidate_cases_validate
BEFORE INSERT ON m6_replay_locked_m4_candidate_cases
WHEN NOT EXISTS (
    SELECT 1
    FROM m6_replay_locked_m4_candidate_cases AS existing
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
)
AND NOT EXISTS (
    SELECT 1
    FROM m6_replay_locked_candidate_cases AS existing
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
    OR (
        existing.execution_scope_authority_id = NEW.execution_scope_authority_id
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
    AND json_extract(NEW.case_json, '$.status') = NEW.status
    AND json_type(NEW.case_json, '$.evidence_packs') = 'array'
    AND json_array_length(NEW.case_json, '$.evidence_packs') = 1
    AND json_type(NEW.case_json, '$.screening_results') = 'array'
    AND json_array_length(NEW.case_json, '$.screening_results') = 1
    AND json_type(NEW.case_json, '$.verdicts') = 'array'
    AND json_array_length(NEW.case_json, '$.verdicts') = 1
    AND json_type(NEW.case_json, '$.procedural_reviews') = 'array'
    AND json_array_length(NEW.case_json, '$.procedural_reviews') = 1
    AND json_type(NEW.case_json, '$.alerts') = 'array'
    AND json_array_length(NEW.case_json, '$.alerts') = 0
    AND json_type(NEW.case_json, '$.appeals') = 'array'
    AND json_array_length(NEW.case_json, '$.appeals') = 0
    AND json_type(NEW.case_json, '$.timeline') = 'array'
    AND json_array_length(NEW.case_json, '$.timeline') = 0
    AND json_type(NEW.case_json, '$.usage') = 'object'
    AND json_extract(NEW.case_json, '$.usage.input_images') = 0
    AND json_extract(NEW.case_json, '$.usage.input_pixels') = 0
    AND json_extract(NEW.case_json, '$.usage.input_tokens') = 0
    AND json_extract(NEW.case_json, '$.usage.output_tokens') = 0
    AND json_extract(NEW.case_json, '$.usage.provider_latency_ms') = 0
    AND json_extract(NEW.case_json, '$.usage.retries') = 0
    AND json_extract(NEW.case_json, '$.usage.estimated_cost') = 0
    AND json_type(NEW.case_json, '$.evidence_packs[0]') = 'object'
    AND json_extract(NEW.case_json, '$.evidence_packs[0].run_id')
        = NEW.candidate_run_id
    AND json_extract(NEW.case_json, '$.evidence_packs[0].case_id') = NEW.case_id
    AND json_extract(NEW.case_json, '$.evidence_packs[0].manifest_id')
        = NEW.manifest_id
    AND json_extract(NEW.case_json, '$.evidence_packs[0].version') = 1
    AND json_extract(NEW.case_json, '$.evidence_packs[0].closure_report.run_id')
        = NEW.candidate_run_id
    AND json_type(NEW.case_json, '$.evidence_packs[0].tool_results') = 'array'
    AND json_array_length(NEW.case_json, '$.evidence_packs[0].tool_results') = 0
    AND json_type(NEW.case_json, '$.screening_results[0]') = 'object'
    AND json_extract(NEW.case_json, '$.screening_results[0].run_id')
        = NEW.candidate_run_id
    AND json_extract(NEW.case_json, '$.screening_results[0].case_id') = NEW.case_id
    AND json_extract(NEW.case_json, '$.screening_results[0].manifest_id')
        = NEW.manifest_id
    AND json_extract(NEW.case_json, '$.screening_results[0].version') >= 1
    AND json_extract(NEW.case_json, '$.screening_results[0].decision') = 'ESCALATE'
    AND json_extract(NEW.case_json, '$.screening_results[0].evidence_pack_id')
        = json_extract(NEW.case_json, '$.evidence_packs[0].pack_id')
    AND json_extract(NEW.case_json, '$.screening_results[0].evidence_pack_version')
        = json_extract(NEW.case_json, '$.evidence_packs[0].version')
    AND json_type(NEW.case_json, '$.screening_results[0].parsed_output') = 'object'
    AND json_extract(NEW.case_json, '$.screening_results[0].parsed_output.run_id')
        = NEW.candidate_run_id
    AND json_extract(NEW.case_json, '$.screening_results[0].parsed_output.case_id')
        = NEW.case_id
    AND json_extract(NEW.case_json, '$.screening_results[0].parsed_output.manifest_id')
        = NEW.manifest_id
    AND json_extract(
        NEW.case_json,
        '$.screening_results[0].parsed_output.evidence_pack_id'
    ) = json_extract(NEW.case_json, '$.evidence_packs[0].pack_id')
    AND json_extract(
        NEW.case_json,
        '$.screening_results[0].parsed_output.evidence_pack_version'
    ) = json_extract(NEW.case_json, '$.evidence_packs[0].version')
    AND json_type(NEW.case_json, '$.verdicts[0]') = 'object'
    AND json_extract(NEW.case_json, '$.verdicts[0].run_id') = NEW.candidate_run_id
    AND json_extract(NEW.case_json, '$.verdicts[0].case_id') = NEW.case_id
    AND json_extract(NEW.case_json, '$.verdicts[0].manifest_id') = NEW.manifest_id
    AND json_extract(NEW.case_json, '$.verdicts[0].version') >= 1
    AND json_extract(NEW.case_json, '$.verdicts[0].screening_id')
        = json_extract(NEW.case_json, '$.screening_results[0].screening_id')
    AND json_extract(NEW.case_json, '$.verdicts[0].evidence_pack_id')
        = json_extract(NEW.case_json, '$.evidence_packs[0].pack_id')
    AND json_extract(NEW.case_json, '$.verdicts[0].evidence_pack_version')
        = json_extract(NEW.case_json, '$.evidence_packs[0].version')
    AND json_type(NEW.case_json, '$.procedural_reviews[0]') = 'object'
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].run_id')
        = NEW.candidate_run_id
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].case_id') = NEW.case_id
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].manifest_id')
        = NEW.manifest_id
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].version') >= 1
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].reviewed_verdict_id')
        = json_extract(NEW.case_json, '$.verdicts[0].verdict_id')
    AND json_extract(
        NEW.case_json,
        '$.procedural_reviews[0].reviewed_verdict_version'
    ) = json_extract(NEW.case_json, '$.verdicts[0].version')
    AND json_extract(
        NEW.case_json,
        '$.procedural_reviews[0].reviewed_verdict_sha256'
    ) = json_extract(NEW.case_json, '$.verdicts[0].verdict_sha256')
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].evidence_pack_id')
        = json_extract(NEW.case_json, '$.evidence_packs[0].pack_id')
    AND json_extract(NEW.case_json, '$.procedural_reviews[0].evidence_pack_version')
        = json_extract(NEW.case_json, '$.evidence_packs[0].version')
    AND (
        (
            json_extract(NEW.case_json, '$.procedural_reviews[0].passed') = 1
            AND NEW.status = 'READY_FOR_ALERT_POLICY'
        )
        OR (
            json_extract(NEW.case_json, '$.procedural_reviews[0].passed') = 0
            AND NEW.status = 'REWORK_REQUIRED'
        )
    )
    AND json_type(NEW.case_json, '$.final_decision') = 'null'
    AND json_type(NEW.case_json, '$.current_backlog_item_id') = 'null'
    AND length(CAST(NEW.case_json AS BLOB)) = NEW.case_document_size_bytes
    AND COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + COALESCE((
        SELECT SUM(existing.case_document_size_bytes)
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ), 0) + NEW.case_document_size_bytes <= 268435456
    AND NEW.case_revision = 1
    AND NEW.case_audit_sequence = NEW.ledger_sequence
    AND NOT EXISTS (
        SELECT 1
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
          AND existing.execution_scope_authority_id
              <> NEW.execution_scope_authority_id
    )
    AND NOT EXISTS (
        SELECT 1
        FROM m6_replay_locked_m4_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
          AND existing.execution_scope_authority_id
              <> NEW.execution_scope_authority_id
    )
    AND (
        SELECT COUNT(*)
        FROM m6_replay_locked_candidate_cases AS existing
        WHERE existing.candidate_run_id = NEW.candidate_run_id
    ) + (
        SELECT COUNT(*)
        FROM m6_replay_locked_m4_candidate_cases AS existing
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
    SELECT RAISE(ABORT, 'invalid M6 replay-locked M4 candidate Case');
END;

CREATE TRIGGER m6_replay_locked_m4_candidate_cases_no_replace
BEFORE INSERT ON m6_replay_locked_m4_candidate_cases
WHEN EXISTS (
    SELECT 1
    FROM m6_replay_locked_m4_candidate_cases AS existing
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
)
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked M4 candidate Cases are append-only');
END;

CREATE TRIGGER m6_replay_locked_m4_candidate_cases_no_update
BEFORE UPDATE ON m6_replay_locked_m4_candidate_cases
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked M4 candidate Cases are append-only');
END;

CREATE TRIGGER m6_replay_locked_m4_candidate_cases_no_delete
BEFORE DELETE ON m6_replay_locked_m4_candidate_cases
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked M4 candidate Cases are append-only');
END;

-- Cross-route collisions are rejected in both insertion directions.  This
-- turns the two physical tables into one logical append-only candidate ledger.
CREATE TRIGGER m6_replay_locked_candidate_cases_cross_route_no_replace
BEFORE INSERT ON m6_replay_locked_candidate_cases
WHEN EXISTS (
    SELECT 1
    FROM m6_replay_locked_m4_candidate_cases AS existing
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
    OR (
        existing.execution_scope_authority_id = NEW.execution_scope_authority_id
        AND existing.ledger_sequence = NEW.ledger_sequence
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked candidate routes are append-only');
END;

CREATE TRIGGER m6_replay_locked_m4_candidate_cases_cross_route_no_replace
BEFORE INSERT ON m6_replay_locked_m4_candidate_cases
WHEN EXISTS (
    SELECT 1
    FROM m6_replay_locked_candidate_cases AS existing
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
    OR (
        existing.execution_scope_authority_id = NEW.execution_scope_authority_id
        AND existing.ledger_sequence = NEW.ledger_sequence
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M6 replay-locked candidate routes are append-only');
END;
