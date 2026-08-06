CREATE TABLE model_responses (
    run_id TEXT NOT NULL,
    response_id TEXT NOT NULL
        CHECK (length(response_id) = 64 AND response_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    evidence_pack_id TEXT NOT NULL
        CHECK (
            length(evidence_pack_id) = 64
            AND evidence_pack_id NOT GLOB '*[^0-9a-f]*'
        ),
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    request_sha256 TEXT NOT NULL
        CHECK (
            length(request_sha256) = 64
            AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    cache_key TEXT NOT NULL
        CHECK (length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'),
    purpose TEXT NOT NULL CHECK (purpose IN ('SCREENING', 'STRUCTURE_REPAIR')),
    attempt_index INTEGER NOT NULL CHECK (attempt_index IN (0, 1)),
    raw_response_ref TEXT NOT NULL,
    content_sha256 TEXT NOT NULL
        CHECK (
            length(content_sha256) = 64
            AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    model_manifest_id TEXT NOT NULL
        CHECK (
            length(model_manifest_id) = 64
            AND model_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (
            length(document_sha256) = 64
            AND document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    PRIMARY KEY (run_id, response_id),
    UNIQUE (run_id, request_id),
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    CHECK (
        (purpose = 'SCREENING' AND attempt_index = 0)
        OR (purpose = 'STRUCTURE_REPAIR' AND attempt_index = 1)
    )
) STRICT;

-- Durable request-level singleflight authority.  The caller keeps the
-- unpredictable owner token; only its SHA-256 digest crosses the SQLite
-- boundary.  A row may move ACTIVE -> ACTIVE only for an expired CAS takeover,
-- and ACTIVE -> COMPLETED only in the same transaction that appends the raw
-- receipt and cache binding.
CREATE TABLE model_call_claims (
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    request_sha256 TEXT NOT NULL
        CHECK (
            length(request_sha256) = 64
            AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    cache_key TEXT NOT NULL
        CHECK (length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    purpose TEXT NOT NULL CHECK (purpose IN ('SCREENING', 'STRUCTURE_REPAIR')),
    model_manifest_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    request_document_sha256 TEXT NOT NULL
        CHECK (
            length(request_document_sha256) = 64
            AND request_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'COMPLETED')),
    owner_token_sha256 TEXT NOT NULL
        CHECK (
            length(owner_token_sha256) = 64
            AND owner_token_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    lease_expires_at TEXT NOT NULL CHECK (length(lease_expires_at) = 27),
    takeover_count INTEGER NOT NULL CHECK (takeover_count >= 0),
    created_at TEXT NOT NULL CHECK (length(created_at) = 27),
    response_id TEXT,
    completed_at TEXT,
    PRIMARY KEY (run_id, request_id),
    UNIQUE (run_id, cache_key),
    UNIQUE (run_id, request_id, response_id),
    FOREIGN KEY (run_id, response_id)
        REFERENCES model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (status = 'ACTIVE' AND response_id IS NULL AND completed_at IS NULL)
        OR
        (status = 'COMPLETED' AND response_id IS NOT NULL AND completed_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE parsed_screening_outputs (
    run_id TEXT NOT NULL,
    parsed_output_id TEXT NOT NULL
        CHECK (
            length(parsed_output_id) = 64
            AND parsed_output_id NOT GLOB '*[^0-9a-f]*'
        ),
    case_id TEXT NOT NULL,
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    request_id TEXT NOT NULL,
    response_id TEXT NOT NULL,
    response_content_sha256 TEXT NOT NULL,
    output_schema_sha256 TEXT NOT NULL,
    model_payload_sha256 TEXT NOT NULL,
    parsed_output_sha256 TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    output_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (
            length(document_sha256) = 64
            AND document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    PRIMARY KEY (run_id, parsed_output_id),
    UNIQUE (run_id, response_id),
    FOREIGN KEY (run_id, response_id)
        REFERENCES model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'
        AND length(response_content_sha256) = 64
        AND response_content_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(output_schema_sha256) = 64
        AND output_schema_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(model_payload_sha256) = 64
        AND model_payload_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(parsed_output_sha256) = 64
        AND parsed_output_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE model_parse_receipts (
    run_id TEXT NOT NULL,
    parse_receipt_id TEXT NOT NULL
        CHECK (
            length(parse_receipt_id) = 64
            AND parse_receipt_id NOT GLOB '*[^0-9a-f]*'
        ),
    case_id TEXT NOT NULL,
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    request_id TEXT NOT NULL,
    response_id TEXT NOT NULL,
    attempt_index INTEGER NOT NULL CHECK (attempt_index IN (0, 1)),
    status TEXT NOT NULL
        CHECK (status IN ('PARSED', 'REPAIR_REQUIRED', 'INVALID_FINAL')),
    parsed_output_id TEXT,
    parsed_output_sha256 TEXT,
    repair_request_id TEXT,
    manifest_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (
            length(document_sha256) = 64
            AND document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    PRIMARY KEY (run_id, parse_receipt_id),
    UNIQUE (run_id, response_id),
    FOREIGN KEY (run_id, response_id)
        REFERENCES model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, parsed_output_id)
        REFERENCES parsed_screening_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    CHECK (
        (status = 'PARSED'
         AND parsed_output_id IS NOT NULL
         AND parsed_output_sha256 IS NOT NULL
         AND repair_request_id IS NULL)
        OR
        (status = 'REPAIR_REQUIRED'
         AND attempt_index = 0
         AND parsed_output_id IS NULL
         AND parsed_output_sha256 IS NULL
         AND repair_request_id IS NOT NULL)
        OR
        (status = 'INVALID_FINAL'
         AND attempt_index = 1
         AND parsed_output_id IS NULL
         AND parsed_output_sha256 IS NULL
         AND repair_request_id IS NULL)
    )
) STRICT;

CREATE TABLE model_cache (
    run_id TEXT NOT NULL,
    cache_key TEXT NOT NULL
        CHECK (length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'),
    cache_entry_id TEXT NOT NULL
        CHECK (
            length(cache_entry_id) = 64
            AND cache_entry_id NOT GLOB '*[^0-9a-f]*'
        ),
    case_id TEXT NOT NULL,
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response_id TEXT NOT NULL,
    response_content_sha256 TEXT NOT NULL,
    model_manifest_id TEXT NOT NULL,
    prompt_manifest_id TEXT NOT NULL,
    output_schema_sha256 TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    request_document_sha256 TEXT NOT NULL,
    entry_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, cache_key),
    UNIQUE (run_id, cache_entry_id),
    UNIQUE (run_id, request_id),
    FOREIGN KEY (run_id, response_id)
        REFERENCES model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'
        AND length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(response_content_sha256) = 64
        AND response_content_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(model_manifest_id) = 64
        AND model_manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(prompt_manifest_id) = 64
        AND prompt_manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(output_schema_sha256) = 64
        AND output_schema_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(request_document_sha256) = 64
        AND request_document_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

-- Append-only exactly-once usage consumption.  The completed claim is the
-- unique accounting root; retries/cache replays cannot insert a second row for
-- the same request.
CREATE TABLE model_call_usage_accounting (
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    response_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    case_revision INTEGER NOT NULL CHECK (case_revision > 0),
    consumer_kind TEXT NOT NULL
        CHECK (consumer_kind IN ('SCREENING_RESULT', 'BACKLOG_ITEM')),
    consumer_id TEXT NOT NULL,
    accounted_at TEXT NOT NULL CHECK (length(accounted_at) = 27),
    input_images INTEGER NOT NULL CHECK (input_images >= 0),
    input_pixels INTEGER NOT NULL CHECK (input_pixels >= 0),
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    provider_latency_ms INTEGER NOT NULL CHECK (provider_latency_ms >= 0),
    retries INTEGER NOT NULL CHECK (retries IN (0, 1)),
    estimated_cost REAL NOT NULL CHECK (estimated_cost >= 0),
    usage_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (
            length(document_sha256) = 64
            AND document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    PRIMARY KEY (run_id, request_id),
    UNIQUE (run_id, response_id),
    FOREIGN KEY (run_id, request_id, response_id)
        REFERENCES model_call_claims(run_id, request_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, response_id)
        REFERENCES model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE screening_results (
    run_id TEXT NOT NULL,
    screening_id TEXT NOT NULL
        CHECK (
            length(screening_id) = 64
            AND screening_id NOT GLOB '*[^0-9a-f]*'
        ),
    case_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    parsed_output_id TEXT NOT NULL,
    decision TEXT NOT NULL
        CHECK (decision IN ('ESTABLISHED', 'NOT_ESTABLISHED', 'ESCALATE')),
    manifest_id TEXT NOT NULL,
    audit_sequence INTEGER NOT NULL CHECK (audit_sequence >= 0),
    result_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (
            length(document_sha256) = 64
            AND document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    PRIMARY KEY (run_id, screening_id),
    UNIQUE (run_id, case_id, version),
    UNIQUE (run_id, case_id, screening_id, version),
    UNIQUE (run_id, audit_sequence),
    FOREIGN KEY (run_id, parsed_output_id)
        REFERENCES parsed_screening_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE verdicts (
    run_id TEXT NOT NULL,
    verdict_id TEXT NOT NULL
        CHECK (length(verdict_id) = 64 AND verdict_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    screening_id TEXT NOT NULL,
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    verdict_input_sha256 TEXT NOT NULL,
    verdict_sha256 TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    audit_sequence INTEGER NOT NULL CHECK (audit_sequence >= 0),
    verdict_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, verdict_id),
    UNIQUE (run_id, case_id, version),
    UNIQUE (run_id, case_id, verdict_id, version),
    UNIQUE (run_id, audit_sequence),
    FOREIGN KEY (run_id, screening_id)
        REFERENCES screening_results(run_id, screening_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        length(verdict_input_sha256) = 64
        AND verdict_input_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(verdict_sha256) = 64
        AND verdict_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE procedural_reviews (
    run_id TEXT NOT NULL,
    review_id TEXT NOT NULL
        CHECK (length(review_id) = 64 AND review_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    reviewed_verdict_id TEXT NOT NULL,
    reviewed_verdict_version INTEGER NOT NULL CHECK (reviewed_verdict_version > 0),
    reviewed_verdict_sha256 TEXT NOT NULL,
    passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
    manifest_id TEXT NOT NULL,
    audit_sequence INTEGER NOT NULL CHECK (audit_sequence >= 0),
    review_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, review_id),
    UNIQUE (run_id, case_id, version),
    UNIQUE (run_id, audit_sequence),
    FOREIGN KEY (
        run_id, case_id, reviewed_verdict_id, reviewed_verdict_version
    ) REFERENCES verdicts(run_id, case_id, verdict_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        length(reviewed_verdict_sha256) = 64
        AND reviewed_verdict_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE procedural_defects (
    run_id TEXT NOT NULL,
    owner_kind TEXT NOT NULL
        CHECK (owner_kind IN ('MODEL_PARSE_RECEIPT', 'PROCEDURAL_REVIEW')),
    owner_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    defect_id TEXT NOT NULL
        CHECK (length(defect_id) = 64 AND defect_id NOT GLOB '*[^0-9a-f]*'),
    origin TEXT NOT NULL CHECK (origin IN ('PARSER', 'PROCEDURAL_GATE')),
    code TEXT NOT NULL,
    artifact_kind TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    parse_receipt_id TEXT,
    review_id TEXT,
    defect_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (
            length(document_sha256) = 64
            AND document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    PRIMARY KEY (run_id, owner_kind, owner_id, ordinal),
    UNIQUE (run_id, owner_kind, owner_id, defect_id),
    FOREIGN KEY (run_id, parse_receipt_id)
        REFERENCES model_parse_receipts(run_id, parse_receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    CHECK (
        (owner_kind = 'MODEL_PARSE_RECEIPT'
         AND owner_id = parse_receipt_id
         AND review_id IS NULL
         AND origin = 'PARSER'
         AND artifact_kind = 'MODEL_RESPONSE')
        OR
        (owner_kind = 'PROCEDURAL_REVIEW'
         AND owner_id = review_id
         AND parse_receipt_id IS NULL
         AND origin = 'PROCEDURAL_GATE'
         AND artifact_kind = 'VERDICT')
    )
) STRICT;

CREATE TABLE backlog_items (
    run_id TEXT NOT NULL,
    item_id TEXT NOT NULL
        CHECK (length(item_id) = 64 AND item_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    stage TEXT NOT NULL CHECK (stage IN ('SCREENING', 'HEARING', 'EVIDENCE', 'HUMAN_REVIEW')),
    role TEXT,
    reason_code TEXT NOT NULL,
    stage_input_kind TEXT NOT NULL,
    stage_input_id TEXT NOT NULL,
    stage_input_sha256 TEXT NOT NULL,
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    manifest_id TEXT NOT NULL,
    initial_json TEXT NOT NULL,
    initial_document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, item_id),
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        length(stage_input_sha256) = 64
        AND stage_input_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(initial_document_sha256) = 64
        AND initial_document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE backlog_item_versions (
    run_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'LEASED', 'COMPLETED', 'EXHAUSTED')),
    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
    lease_id TEXT,
    lease_owner_sha256 TEXT,
    lease_expires_at TEXT,
    item_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, item_id, version),
    FOREIGN KEY (run_id, item_id)
        REFERENCES backlog_items(run_id, item_id) ON DELETE RESTRICT,
    CHECK (
        length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (status = 'LEASED'
         AND attempt_count > 0
         AND lease_id IS NOT NULL
         AND lease_owner_sha256 IS NOT NULL
         AND lease_expires_at IS NOT NULL)
        OR
        (status <> 'LEASED'
         AND lease_id IS NULL
         AND lease_owner_sha256 IS NULL
         AND lease_expires_at IS NULL)
    )
) STRICT;

CREATE TABLE backlog_heads (
    run_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    current_version INTEGER NOT NULL CHECK (current_version > 0),
    PRIMARY KEY (run_id, item_id),
    FOREIGN KEY (run_id, item_id, current_version)
        REFERENCES backlog_item_versions(run_id, item_id, version) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_model_responses_case_request
    ON model_responses(run_id, case_id, request_id);
CREATE INDEX idx_model_call_claims_active_expiry
    ON model_call_claims(run_id, status, lease_expires_at, request_id);
CREATE INDEX idx_model_call_usage_case
    ON model_call_usage_accounting(run_id, case_id, case_revision, request_id);
CREATE INDEX idx_model_parse_receipts_case_response
    ON model_parse_receipts(run_id, case_id, response_id);
CREATE INDEX idx_screening_results_case_version
    ON screening_results(run_id, case_id, version);
CREATE INDEX idx_verdicts_case_version
    ON verdicts(run_id, case_id, version);
CREATE INDEX idx_procedural_reviews_case_version
    ON procedural_reviews(run_id, case_id, version);
CREATE INDEX idx_procedural_defects_code
    ON procedural_defects(run_id, code, owner_kind, owner_id);
CREATE INDEX idx_backlog_versions_lease
    ON backlog_item_versions(run_id, status, lease_expires_at, item_id, version);

CREATE TRIGGER model_responses_no_replace
BEFORE INSERT ON model_responses
WHEN EXISTS (
    SELECT 1 FROM model_responses
    WHERE run_id = NEW.run_id
      AND (response_id = NEW.response_id OR request_id = NEW.request_id)
)
BEGIN
    SELECT RAISE(ABORT, 'model_responses is append-only');
END;

CREATE TRIGGER model_responses_no_update
BEFORE UPDATE ON model_responses
BEGIN
    SELECT RAISE(ABORT, 'model_responses is append-only');
END;

CREATE TRIGGER model_responses_no_delete
BEFORE DELETE ON model_responses
BEGIN
    SELECT RAISE(ABORT, 'model_responses is append-only');
END;

CREATE TRIGGER model_call_claims_no_replace
BEFORE INSERT ON model_call_claims
WHEN EXISTS (
    SELECT 1 FROM model_call_claims
    WHERE run_id = NEW.run_id
      AND (request_id = NEW.request_id OR cache_key = NEW.cache_key)
)
BEGIN
    SELECT RAISE(ABORT, 'model_call_claims cannot be replaced');
END;

CREATE TRIGGER model_call_claims_controlled_update
BEFORE UPDATE ON model_call_claims
WHEN NOT (
    OLD.run_id = NEW.run_id
    AND OLD.request_id = NEW.request_id
    AND OLD.request_sha256 = NEW.request_sha256
    AND OLD.cache_key = NEW.cache_key
    AND OLD.case_id = NEW.case_id
    AND OLD.evidence_pack_id = NEW.evidence_pack_id
    AND OLD.evidence_pack_version = NEW.evidence_pack_version
    AND OLD.purpose = NEW.purpose
    AND OLD.model_manifest_id = NEW.model_manifest_id
    AND OLD.manifest_id = NEW.manifest_id
    AND OLD.request_json = NEW.request_json
    AND OLD.request_document_sha256 = NEW.request_document_sha256
    AND OLD.created_at = NEW.created_at
    AND OLD.status = 'ACTIVE'
    AND (
        (
            NEW.status = 'ACTIVE'
            AND OLD.owner_token_sha256 != NEW.owner_token_sha256
            AND OLD.lease_expires_at != NEW.lease_expires_at
            AND NEW.takeover_count = OLD.takeover_count + 1
            AND OLD.response_id IS NULL AND NEW.response_id IS NULL
            AND OLD.completed_at IS NULL AND NEW.completed_at IS NULL
        )
        OR
        (
            NEW.status = 'COMPLETED'
            AND OLD.owner_token_sha256 = NEW.owner_token_sha256
            AND OLD.lease_expires_at = NEW.lease_expires_at
            AND OLD.takeover_count = NEW.takeover_count
            AND OLD.response_id IS NULL AND NEW.response_id IS NOT NULL
            AND OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'model_call_claims update is not a controlled transition');
END;

CREATE TRIGGER model_call_claims_no_delete
BEFORE DELETE ON model_call_claims
BEGIN
    SELECT RAISE(ABORT, 'model_call_claims cannot be deleted');
END;

CREATE TRIGGER parsed_screening_outputs_no_replace
BEFORE INSERT ON parsed_screening_outputs
WHEN EXISTS (
    SELECT 1 FROM parsed_screening_outputs
    WHERE run_id = NEW.run_id
      AND (parsed_output_id = NEW.parsed_output_id OR response_id = NEW.response_id)
)
BEGIN
    SELECT RAISE(ABORT, 'parsed_screening_outputs is append-only');
END;

CREATE TRIGGER parsed_screening_outputs_no_update
BEFORE UPDATE ON parsed_screening_outputs
BEGIN
    SELECT RAISE(ABORT, 'parsed_screening_outputs is append-only');
END;

CREATE TRIGGER parsed_screening_outputs_no_delete
BEFORE DELETE ON parsed_screening_outputs
BEGIN
    SELECT RAISE(ABORT, 'parsed_screening_outputs is append-only');
END;

CREATE TRIGGER model_parse_receipts_no_replace
BEFORE INSERT ON model_parse_receipts
WHEN EXISTS (
    SELECT 1 FROM model_parse_receipts
    WHERE run_id = NEW.run_id
      AND (parse_receipt_id = NEW.parse_receipt_id OR response_id = NEW.response_id)
)
BEGIN
    SELECT RAISE(ABORT, 'model_parse_receipts is append-only');
END;

CREATE TRIGGER model_parse_receipts_no_update
BEFORE UPDATE ON model_parse_receipts
BEGIN
    SELECT RAISE(ABORT, 'model_parse_receipts is append-only');
END;

CREATE TRIGGER model_parse_receipts_no_delete
BEFORE DELETE ON model_parse_receipts
BEGIN
    SELECT RAISE(ABORT, 'model_parse_receipts is append-only');
END;

CREATE TRIGGER model_cache_no_replace
BEFORE INSERT ON model_cache
WHEN EXISTS (
    SELECT 1 FROM model_cache
    WHERE run_id = NEW.run_id
      AND (cache_key = NEW.cache_key OR cache_entry_id = NEW.cache_entry_id)
)
BEGIN
    SELECT RAISE(ABORT, 'model_cache is append-only');
END;

CREATE TRIGGER model_cache_no_update
BEFORE UPDATE ON model_cache
BEGIN
    SELECT RAISE(ABORT, 'model_cache is append-only');
END;

CREATE TRIGGER model_cache_no_delete
BEFORE DELETE ON model_cache
BEGIN
    SELECT RAISE(ABORT, 'model_cache is append-only');
END;

CREATE TRIGGER model_call_usage_accounting_no_replace
BEFORE INSERT ON model_call_usage_accounting
WHEN EXISTS (
    SELECT 1 FROM model_call_usage_accounting
    WHERE run_id = NEW.run_id
      AND (request_id = NEW.request_id OR response_id = NEW.response_id)
)
BEGIN
    SELECT RAISE(ABORT, 'model_call_usage_accounting is append-only');
END;

CREATE TRIGGER model_call_usage_accounting_no_update
BEFORE UPDATE ON model_call_usage_accounting
BEGIN
    SELECT RAISE(ABORT, 'model_call_usage_accounting is append-only');
END;

CREATE TRIGGER model_call_usage_accounting_no_delete
BEFORE DELETE ON model_call_usage_accounting
BEGIN
    SELECT RAISE(ABORT, 'model_call_usage_accounting is append-only');
END;

CREATE TRIGGER screening_results_no_replace
BEFORE INSERT ON screening_results
WHEN EXISTS (
    SELECT 1 FROM screening_results
    WHERE run_id = NEW.run_id
      AND (screening_id = NEW.screening_id
           OR (case_id = NEW.case_id AND version = NEW.version))
)
BEGIN
    SELECT RAISE(ABORT, 'screening_results is append-only');
END;

CREATE TRIGGER screening_results_no_update
BEFORE UPDATE ON screening_results
BEGIN
    SELECT RAISE(ABORT, 'screening_results is append-only');
END;

CREATE TRIGGER screening_results_no_delete
BEFORE DELETE ON screening_results
BEGIN
    SELECT RAISE(ABORT, 'screening_results is append-only');
END;

CREATE TRIGGER verdicts_no_replace
BEFORE INSERT ON verdicts
WHEN EXISTS (
    SELECT 1 FROM verdicts
    WHERE run_id = NEW.run_id
      AND (verdict_id = NEW.verdict_id
           OR (case_id = NEW.case_id AND version = NEW.version))
)
BEGIN
    SELECT RAISE(ABORT, 'verdicts is append-only');
END;

CREATE TRIGGER verdicts_no_update
BEFORE UPDATE ON verdicts
BEGIN
    SELECT RAISE(ABORT, 'verdicts is append-only');
END;

CREATE TRIGGER verdicts_no_delete
BEFORE DELETE ON verdicts
BEGIN
    SELECT RAISE(ABORT, 'verdicts is append-only');
END;

CREATE TRIGGER procedural_reviews_no_replace
BEFORE INSERT ON procedural_reviews
WHEN EXISTS (
    SELECT 1 FROM procedural_reviews
    WHERE run_id = NEW.run_id
      AND (review_id = NEW.review_id
           OR (case_id = NEW.case_id AND version = NEW.version))
)
BEGIN
    SELECT RAISE(ABORT, 'procedural_reviews is append-only');
END;

CREATE TRIGGER procedural_reviews_no_update
BEFORE UPDATE ON procedural_reviews
BEGIN
    SELECT RAISE(ABORT, 'procedural_reviews is append-only');
END;

CREATE TRIGGER procedural_reviews_no_delete
BEFORE DELETE ON procedural_reviews
BEGIN
    SELECT RAISE(ABORT, 'procedural_reviews is append-only');
END;

CREATE TRIGGER procedural_defects_no_replace
BEFORE INSERT ON procedural_defects
WHEN EXISTS (
    SELECT 1 FROM procedural_defects
    WHERE run_id = NEW.run_id
      AND owner_kind = NEW.owner_kind
      AND owner_id = NEW.owner_id
      AND (ordinal = NEW.ordinal OR defect_id = NEW.defect_id)
)
BEGIN
    SELECT RAISE(ABORT, 'procedural_defects is append-only');
END;

CREATE TRIGGER procedural_defects_no_update
BEFORE UPDATE ON procedural_defects
BEGIN
    SELECT RAISE(ABORT, 'procedural_defects is append-only');
END;

CREATE TRIGGER procedural_defects_no_delete
BEFORE DELETE ON procedural_defects
BEGIN
    SELECT RAISE(ABORT, 'procedural_defects is append-only');
END;

CREATE TRIGGER backlog_items_no_replace
BEFORE INSERT ON backlog_items
WHEN EXISTS (
    SELECT 1 FROM backlog_items
    WHERE run_id = NEW.run_id AND item_id = NEW.item_id
)
BEGIN
    SELECT RAISE(ABORT, 'backlog_items is append-only');
END;

CREATE TRIGGER backlog_items_no_update
BEFORE UPDATE ON backlog_items
BEGIN
    SELECT RAISE(ABORT, 'backlog_items is append-only');
END;

CREATE TRIGGER backlog_items_no_delete
BEFORE DELETE ON backlog_items
BEGIN
    SELECT RAISE(ABORT, 'backlog_items is append-only');
END;

CREATE TRIGGER backlog_item_versions_no_replace
BEFORE INSERT ON backlog_item_versions
WHEN EXISTS (
    SELECT 1 FROM backlog_item_versions
    WHERE run_id = NEW.run_id
      AND item_id = NEW.item_id
      AND version = NEW.version
)
BEGIN
    SELECT RAISE(ABORT, 'backlog_item_versions is append-only');
END;

CREATE TRIGGER backlog_item_versions_no_update
BEFORE UPDATE ON backlog_item_versions
BEGIN
    SELECT RAISE(ABORT, 'backlog_item_versions is append-only');
END;

CREATE TRIGGER backlog_item_versions_no_delete
BEFORE DELETE ON backlog_item_versions
BEGIN
    SELECT RAISE(ABORT, 'backlog_item_versions is append-only');
END;

CREATE TRIGGER backlog_heads_no_replace
BEFORE INSERT ON backlog_heads
WHEN EXISTS (
    SELECT 1 FROM backlog_heads
    WHERE run_id = NEW.run_id AND item_id = NEW.item_id
)
BEGIN
    SELECT RAISE(ABORT, 'backlog_heads cannot be replaced');
END;

CREATE TRIGGER backlog_heads_monotonic_update
BEFORE UPDATE ON backlog_heads
WHEN NEW.run_id IS NOT OLD.run_id
  OR NEW.item_id IS NOT OLD.item_id
  OR NEW.current_version != OLD.current_version + 1
BEGIN
    SELECT RAISE(ABORT, 'backlog head update is not monotonic');
END;

CREATE TRIGGER backlog_heads_no_delete
BEFORE DELETE ON backlog_heads
BEGIN
    SELECT RAISE(ABORT, 'backlog_heads cannot be deleted');
END;
