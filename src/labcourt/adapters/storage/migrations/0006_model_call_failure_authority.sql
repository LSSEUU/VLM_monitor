-- A provider call may be retried by the business path only after its current
-- owner has captured a known delivery outcome and closed that outcome with the
-- authoritative backlog aggregate in the same transaction.  Unknown expired
-- claims remain ACTIVE for provider-free maintenance recovery.
CREATE TABLE model_call_failure_authorities (
    run_id TEXT NOT NULL,
    authority_id TEXT NOT NULL
        CHECK (length(authority_id) = 64 AND authority_id NOT GLOB '*[^0-9a-f]*'),
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    request_sha256 TEXT NOT NULL
        CHECK (length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
    request_document_sha256 TEXT NOT NULL
        CHECK (
            length(request_document_sha256) = 64
            AND request_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    cache_key TEXT NOT NULL
        CHECK (length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    purpose TEXT NOT NULL CHECK (purpose IN ('SCREENING', 'STRUCTURE_REPAIR')),
    model_manifest_id TEXT NOT NULL,
    claim_owner_sha256 TEXT NOT NULL
        CHECK (
            length(claim_owner_sha256) = 64
            AND claim_owner_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    claim_lease_expires_at TEXT NOT NULL CHECK (length(claim_lease_expires_at) = 27),
    claim_takeover_count INTEGER NOT NULL CHECK (claim_takeover_count >= 0),
    failure_code TEXT NOT NULL CHECK (failure_code IN (
        'FIXTURE_MISSING', 'PROVIDER_OUTAGE', 'PROVIDER_TIMEOUT',
        'TRANSPORT_UNAVAILABLE', 'EXPIRED_CLAIM_REQUIRES_RECOVERY',
        'REQUEST_IDENTITY_MISMATCH', 'PROMPT_MISSING',
        'PROMPT_INTEGRITY_FAILURE', 'MEDIA_POLICY_REJECTED',
        'MEDIA_INTEGRITY_FAILURE', 'RESPONSE_ENVELOPE_INVALID',
        'RESPONSE_TOO_LARGE', 'RESPONSE_TOKEN_BUDGET_EXCEEDED',
        'RESPONSE_COST_BUDGET_EXCEEDED', 'RESPONSE_PERSISTENCE_FAILURE'
    )),
    delivery_certainty TEXT NOT NULL
        CHECK (delivery_certainty IN ('DEFINITELY_NOT_SENT', 'COMPLETED')),
    backlog_reason_code TEXT NOT NULL,
    backlog_item_id TEXT NOT NULL
        CHECK (length(backlog_item_id) = 64 AND backlog_item_id NOT GLOB '*[^0-9a-f]*'),
    backlog_version INTEGER NOT NULL CHECK (backlog_version > 0),
    backlog_status TEXT NOT NULL CHECK (backlog_status IN ('PENDING', 'EXHAUSTED')),
    backlog_attempt_count INTEGER NOT NULL CHECK (backlog_attempt_count >= 0),
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    closure_kind TEXT NOT NULL CHECK (closure_kind IN ('INITIAL_BACKLOG', 'RETRY_FAILURE')),
    completion_receipt_id TEXT,
    closure_case_revision INTEGER NOT NULL CHECK (closure_case_revision > 0),
    closure_audit_sequence INTEGER NOT NULL CHECK (closure_audit_sequence >= 0),
    closure_audit_entry_hash TEXT NOT NULL
        CHECK (
            length(closure_audit_entry_hash) = 64
            AND closure_audit_entry_hash NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    recorded_at TEXT NOT NULL CHECK (length(recorded_at) = 27),
    authority_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, authority_id),
    UNIQUE (run_id, request_id, claim_takeover_count),
    FOREIGN KEY (run_id, request_id)
        REFERENCES model_call_claims(run_id, request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, backlog_item_id, backlog_version)
        REFERENCES backlog_item_versions(run_id, item_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, closure_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, closure_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, completion_receipt_id)
        REFERENCES backlog_completion_receipts(run_id, receipt_id) ON DELETE RESTRICT,
    CHECK (
        (closure_kind = 'INITIAL_BACKLOG'
         AND backlog_version = 1
         AND backlog_attempt_count = 0
         AND completion_receipt_id IS NULL)
        OR
        (closure_kind = 'RETRY_FAILURE'
         AND backlog_attempt_count > 0
         AND completion_receipt_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX idx_model_call_failure_authorities_backlog
    ON model_call_failure_authorities(
        run_id, backlog_item_id, retry_generation, backlog_version, authority_id
    );

CREATE TRIGGER model_call_failure_authorities_validate
BEFORE INSERT ON model_call_failure_authorities
WHEN NOT (
    EXISTS (
        SELECT 1 FROM model_call_claims AS claim
        WHERE claim.run_id = NEW.run_id
          AND claim.request_id = NEW.request_id
          AND claim.request_sha256 = NEW.request_sha256
          AND claim.cache_key = NEW.cache_key
          AND claim.case_id = NEW.case_id
          AND claim.evidence_pack_id = NEW.evidence_pack_id
          AND claim.evidence_pack_version = NEW.evidence_pack_version
          AND claim.purpose = NEW.purpose
          AND claim.model_manifest_id = NEW.model_manifest_id
          AND claim.manifest_id = NEW.manifest_id
          AND claim.status = 'ACTIVE'
          AND claim.owner_token_sha256 = NEW.claim_owner_sha256
          AND claim.lease_expires_at = NEW.claim_lease_expires_at
          AND claim.takeover_count = NEW.claim_takeover_count
          AND claim.response_id IS NULL
          AND claim.completed_at IS NULL
    )
    AND EXISTS (
        SELECT 1
        FROM backlog_item_versions AS version
        JOIN backlog_heads AS head
          ON head.run_id = version.run_id
         AND head.item_id = version.item_id
         AND head.current_version = version.version
        JOIN backlog_items AS item
          ON item.run_id = version.run_id
         AND item.item_id = version.item_id
        WHERE version.run_id = NEW.run_id
          AND version.item_id = NEW.backlog_item_id
          AND version.version = NEW.backlog_version
          AND version.status = NEW.backlog_status
          AND version.attempt_count = NEW.backlog_attempt_count
          AND version.retry_generation = NEW.retry_generation
          AND version.lease_id IS NULL
          AND version.lease_owner_sha256 IS NULL
          AND version.lease_expires_at IS NULL
          AND item.case_id = NEW.case_id
          AND item.manifest_id = NEW.manifest_id
          AND item.reason_code = NEW.backlog_reason_code
    )
    AND EXISTS (
        SELECT 1
        FROM case_versions AS cv
        JOIN audit_entries AS audit
          ON audit.run_id = cv.run_id
         AND audit.sequence = cv.audit_sequence
        WHERE cv.run_id = NEW.run_id
          AND cv.case_id = NEW.case_id
          AND cv.revision = NEW.closure_case_revision
          AND cv.audit_sequence = NEW.closure_audit_sequence
          AND audit.entry_hash = NEW.closure_audit_entry_hash
          AND audit.manifest_id = NEW.manifest_id
          AND audit.object_kind = 'BACKLOG_ITEM'
          AND audit.object_id = NEW.backlog_item_id
    )
    AND (
        (NEW.closure_kind = 'INITIAL_BACKLOG'
         AND NEW.completion_receipt_id IS NULL)
        OR
        (NEW.closure_kind = 'RETRY_FAILURE'
         AND EXISTS (
             SELECT 1 FROM backlog_completion_receipts AS receipt
             WHERE receipt.run_id = NEW.run_id
               AND receipt.receipt_id = NEW.completion_receipt_id
               AND receipt.item_id = NEW.backlog_item_id
               AND receipt.case_id = NEW.case_id
               AND receipt.outcome_kind = 'FAILURE'
               AND receipt.backlog_version = NEW.backlog_version
               AND receipt.backlog_status = NEW.backlog_status
               AND receipt.attempt_count = NEW.backlog_attempt_count
               AND receipt.retry_generation = NEW.retry_generation
               AND receipt.completion_case_revision = NEW.closure_case_revision
               AND receipt.completion_audit_sequence = NEW.closure_audit_sequence
               AND receipt.completion_audit_entry_hash = NEW.closure_audit_entry_hash
               AND receipt.manifest_id = NEW.manifest_id
               AND json_extract(receipt.receipt_json, '$.outcome.reason_code')
                   = NEW.backlog_reason_code
         ))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'model call failure authority closure is invalid');
END;

CREATE TRIGGER model_call_failure_authorities_no_replace
BEFORE INSERT ON model_call_failure_authorities
WHEN EXISTS (
    SELECT 1 FROM model_call_failure_authorities
    WHERE run_id = NEW.run_id
      AND (
          authority_id = NEW.authority_id
          OR (request_id = NEW.request_id
              AND claim_takeover_count = NEW.claim_takeover_count)
      )
)
BEGIN
    SELECT RAISE(ABORT, 'model_call_failure_authorities is append-only');
END;

CREATE TRIGGER model_call_failure_authorities_no_update
BEFORE UPDATE ON model_call_failure_authorities
BEGIN
    SELECT RAISE(ABORT, 'model_call_failure_authorities is append-only');
END;

CREATE TRIGGER model_call_failure_authorities_no_delete
BEFORE DELETE ON model_call_failure_authorities
BEGIN
    SELECT RAISE(ABORT, 'model_call_failure_authorities is append-only');
END;
