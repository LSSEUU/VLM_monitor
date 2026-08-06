ALTER TABLE backlog_item_versions
    ADD COLUMN retry_generation INTEGER NOT NULL DEFAULT 0
        CHECK (retry_generation >= 0);

CREATE TABLE backlog_completion_receipts (
    run_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL
        CHECK (length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    item_id TEXT NOT NULL
        CHECK (length(item_id) = 64 AND item_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('SUCCESS', 'FAILURE')),
    outcome_id TEXT NOT NULL
        CHECK (length(outcome_id) = 64 AND outcome_id NOT GLOB '*[^0-9a-f]*'),
    lease_identity_sha256 TEXT NOT NULL
        CHECK (
            length(lease_identity_sha256) = 64
            AND lease_identity_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    lease_id TEXT NOT NULL
        CHECK (length(lease_id) = 64 AND lease_id NOT GLOB '*[^0-9a-f]*'),
    attempt_count INTEGER NOT NULL CHECK (attempt_count > 0),
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    backlog_status TEXT NOT NULL
        CHECK (backlog_status IN ('PENDING', 'COMPLETED', 'EXHAUSTED')),
    backlog_version INTEGER NOT NULL CHECK (backlog_version > 0),
    completion_kind TEXT NOT NULL
        CHECK (completion_kind IN ('BACKLOG_ITEM', 'SCREENING_RESULT', 'PROCEDURAL_REVIEW')),
    completion_id TEXT NOT NULL,
    completion_case_status TEXT NOT NULL CHECK (
        completion_case_status IN (
            'BACKLOGGED',
            'ESCALATED',
            'READY_FOR_ALERT_POLICY',
            'REWORK_REQUIRED',
            'HUMAN_REVIEW'
        )
    ),
    completion_case_revision INTEGER NOT NULL CHECK (completion_case_revision > 0),
    completion_audit_sequence INTEGER NOT NULL CHECK (completion_audit_sequence >= 0),
    completion_audit_entry_hash TEXT NOT NULL CHECK (
        length(completion_audit_entry_hash) = 64
        AND completion_audit_entry_hash NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    receipt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, receipt_id),
    UNIQUE (run_id, item_id, lease_identity_sha256),
    UNIQUE (run_id, item_id, lease_id),
    UNIQUE (run_id, outcome_id),
    FOREIGN KEY (run_id, item_id)
        REFERENCES backlog_items(run_id, item_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, item_id, backlog_version)
        REFERENCES backlog_item_versions(run_id, item_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, completion_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, completion_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (outcome_kind = 'SUCCESS'
         AND backlog_status = 'COMPLETED'
         AND (
             (completion_kind = 'SCREENING_RESULT'
              AND completion_case_status = 'ESCALATED')
             OR
             (completion_kind = 'PROCEDURAL_REVIEW'
              AND completion_case_status IN ('READY_FOR_ALERT_POLICY', 'REWORK_REQUIRED'))
         ))
        OR
        (outcome_kind = 'FAILURE'
         AND completion_kind = 'BACKLOG_ITEM'
         AND completion_id = item_id
         AND (
             (backlog_status = 'PENDING' AND completion_case_status = 'BACKLOGGED')
             OR
             (backlog_status = 'EXHAUSTED' AND completion_case_status = 'HUMAN_REVIEW')
         ))
    )
) STRICT;

CREATE INDEX idx_backlog_completion_receipts_item_attempt
    ON backlog_completion_receipts(
        run_id,
        item_id,
        attempt_count,
        retry_generation,
        receipt_id
    );

CREATE TRIGGER backlog_completion_receipts_validate_authority
BEFORE INSERT ON backlog_completion_receipts
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM backlog_item_versions AS completed
        JOIN backlog_heads AS head
          ON head.run_id = completed.run_id
         AND head.item_id = completed.item_id
         AND head.current_version = completed.version
        WHERE completed.run_id = NEW.run_id
          AND completed.item_id = NEW.item_id
          AND completed.version = NEW.backlog_version
          AND completed.status = NEW.backlog_status
          AND completed.attempt_count = NEW.attempt_count
          AND completed.retry_generation = CASE
              WHEN NEW.outcome_kind = 'FAILURE'
                   AND NEW.backlog_status = 'PENDING'
                  THEN json_extract(NEW.receipt_json, '$.outcome.next_retry_generation')
              ELSE NEW.retry_generation
          END
          AND completed.lease_id IS NULL
          AND completed.lease_owner_sha256 IS NULL
          AND completed.lease_expires_at IS NULL
    )
    AND EXISTS (
        SELECT 1 FROM backlog_item_versions AS leased
        WHERE leased.run_id = NEW.run_id
          AND leased.item_id = NEW.item_id
          AND leased.version = NEW.backlog_version - 1
          AND leased.status = 'LEASED'
          AND leased.lease_id = NEW.lease_id
          AND leased.attempt_count = NEW.attempt_count
          AND leased.retry_generation = NEW.retry_generation
    )
    AND EXISTS (
        SELECT 1
        FROM case_versions AS cv
        JOIN audit_entries AS ae
          ON ae.run_id = cv.run_id
         AND ae.sequence = cv.audit_sequence
        WHERE cv.run_id = NEW.run_id
          AND cv.case_id = NEW.case_id
          AND cv.revision = NEW.completion_case_revision
          AND cv.status = NEW.completion_case_status
          AND cv.audit_sequence = NEW.completion_audit_sequence
          AND ae.entry_hash = NEW.completion_audit_entry_hash
          AND ae.manifest_id = NEW.manifest_id
          AND ae.object_kind = NEW.completion_kind
          AND ae.object_id = NEW.completion_id
    )
    AND (
        (NEW.completion_kind = 'BACKLOG_ITEM'
         AND EXISTS (
             SELECT 1 FROM backlog_items AS bi
             WHERE bi.run_id = NEW.run_id
               AND bi.item_id = NEW.completion_id
               AND bi.case_id = NEW.case_id
               AND bi.manifest_id = NEW.manifest_id
         ))
        OR
        (NEW.completion_kind = 'SCREENING_RESULT'
         AND EXISTS (
             SELECT 1 FROM screening_results AS sr
             WHERE sr.run_id = NEW.run_id
               AND sr.screening_id = NEW.completion_id
               AND sr.case_id = NEW.case_id
               AND sr.manifest_id = NEW.manifest_id
               AND sr.audit_sequence = NEW.completion_audit_sequence
         ))
        OR
        (NEW.completion_kind = 'PROCEDURAL_REVIEW'
         AND EXISTS (
             SELECT 1 FROM procedural_reviews AS pr
             WHERE pr.run_id = NEW.run_id
               AND pr.review_id = NEW.completion_id
               AND pr.case_id = NEW.case_id
               AND pr.manifest_id = NEW.manifest_id
               AND pr.audit_sequence = NEW.completion_audit_sequence
         ))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'backlog completion receipt authority is invalid');
END;

CREATE TRIGGER backlog_completion_receipts_no_replace
BEFORE INSERT ON backlog_completion_receipts
WHEN EXISTS (
    SELECT 1 FROM backlog_completion_receipts
    WHERE run_id = NEW.run_id
      AND (
          receipt_id = NEW.receipt_id
          OR outcome_id = NEW.outcome_id
          OR (
              item_id = NEW.item_id
              AND lease_identity_sha256 = NEW.lease_identity_sha256
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'backlog_completion_receipts is append-only');
END;

CREATE TRIGGER backlog_completion_receipts_no_update
BEFORE UPDATE ON backlog_completion_receipts
BEGIN
    SELECT RAISE(ABORT, 'backlog_completion_receipts is append-only');
END;

CREATE TRIGGER backlog_completion_receipts_no_delete
BEFORE DELETE ON backlog_completion_receipts
BEGIN
    SELECT RAISE(ABORT, 'backlog_completion_receipts is append-only');
END;
