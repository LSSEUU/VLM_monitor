-- M4 is an additive authority slice.  The frozen M3 model-call tables keep
-- their SCREENING/STRUCTURE_REPAIR check matrices; hearing calls therefore
-- use independent roots.  Existing backlog lease history is shared, while
-- M4 owns a role-aware completion receipt.

-- A v7 database could contain speculative HEARING queue rows even though v7
-- has no hearing/session authority capable of proving their origin.  Do not
-- silently adopt such rows as M4 work.
CREATE TABLE m4_authority_preflight (
    violation_count INTEGER NOT NULL CHECK (violation_count = 0)
) STRICT;

INSERT INTO m4_authority_preflight(violation_count)
SELECT COUNT(*) FROM backlog_items WHERE stage = 'HEARING';

DROP TABLE m4_authority_preflight;

CREATE TABLE m4_hearings (
    run_id TEXT NOT NULL,
    hearing_id TEXT NOT NULL
        CHECK (length(hearing_id) = 64 AND hearing_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    screening_id TEXT NOT NULL
        CHECK (length(screening_id) = 64 AND screening_id NOT GLOB '*[^0-9a-f]*'),
    entry_status TEXT NOT NULL CHECK (entry_status IN ('ESCALATED', 'REWORK_REQUIRED')),
    trigger_review_id TEXT,
    initial_defect_codes_json TEXT NOT NULL
        CHECK (
            json_valid(initial_defect_codes_json)
            AND json_type(initial_defect_codes_json) = 'array'
        ),
    initial_pack_id TEXT NOT NULL
        CHECK (length(initial_pack_id) = 64 AND initial_pack_id NOT GLOB '*[^0-9a-f]*'),
    initial_pack_version INTEGER NOT NULL CHECK (initial_pack_version > 0),
    max_acquisition_rounds INTEGER NOT NULL CHECK (max_acquisition_rounds BETWEEN 0 AND 2),
    max_rework_rounds INTEGER NOT NULL CHECK (max_rework_rounds BETWEEN 0 AND 2),
    max_total_images INTEGER NOT NULL CHECK (max_total_images BETWEEN 1 AND 320),
    max_total_output_tokens INTEGER NOT NULL
        CHECK (max_total_output_tokens BETWEEN 1 AND 1000000),
    max_judge_cycles INTEGER NOT NULL CHECK (max_judge_cycles > 0),
    hearing_prompt_bundle_sha256 TEXT NOT NULL CHECK (
        length(hearing_prompt_bundle_sha256) = 64
        AND hearing_prompt_bundle_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    prosecutor_model_manifest_id TEXT NOT NULL CHECK (
        length(prosecutor_model_manifest_id) = 64
        AND prosecutor_model_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    defender_model_manifest_id TEXT NOT NULL CHECK (
        length(defender_model_manifest_id) = 64
        AND defender_model_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    judge_model_manifest_id TEXT NOT NULL CHECK (
        length(judge_model_manifest_id) = 64
        AND judge_model_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    created_audit_sequence INTEGER NOT NULL CHECK (created_audit_sequence >= 0),
    hearing_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, hearing_id),
    UNIQUE (run_id, hearing_id, case_id),
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, screening_id)
        REFERENCES screening_results(run_id, screening_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, trigger_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, initial_pack_id, initial_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, created_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT,
    CHECK (
        max_judge_cycles
            = 1 + max_acquisition_rounds + max_rework_rounds
    ),
    CHECK (
        (entry_status = 'ESCALATED'
         AND trigger_review_id IS NULL
         AND json_array_length(initial_defect_codes_json) = 0)
        OR
        (entry_status = 'REWORK_REQUIRED'
         AND trigger_review_id IS NOT NULL
         AND json_array_length(initial_defect_codes_json) > 0)
    )
) STRICT;

CREATE TABLE m4_hearing_cycles (
    run_id TEXT NOT NULL,
    cycle_id TEXT NOT NULL
        CHECK (length(cycle_id) = 64 AND cycle_id NOT GLOB '*[^0-9a-f]*'),
    cycle_sha256 TEXT NOT NULL CHECK (
        length(cycle_sha256) = 64 AND cycle_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    hearing_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    cycle_index INTEGER NOT NULL CHECK (cycle_index BETWEEN 1 AND 5),
    prior_acquisition_rounds INTEGER NOT NULL
        CHECK (prior_acquisition_rounds BETWEEN 0 AND 2),
    prior_rework_rounds INTEGER NOT NULL CHECK (prior_rework_rounds BETWEEN 0 AND 2),
    cycle_pack_id TEXT NOT NULL
        CHECK (
            length(cycle_pack_id) = 64
            AND cycle_pack_id NOT GLOB '*[^0-9a-f]*'
        ),
    cycle_pack_version INTEGER NOT NULL CHECK (cycle_pack_version > 0),
    initial_trigger_review_id TEXT,
    initial_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(initial_defect_codes_json)
        AND json_type(initial_defect_codes_json) = 'array'
        AND json_array_length(initial_defect_codes_json) <= 14
    ),
    rework_review_id TEXT,
    rework_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(rework_defect_codes_json)
        AND json_type(rework_defect_codes_json) = 'array'
        AND json_array_length(rework_defect_codes_json) <= 14
    ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    created_audit_sequence INTEGER NOT NULL CHECK (created_audit_sequence >= 0),
    cycle_json TEXT NOT NULL CHECK (json_valid(cycle_json)),
    PRIMARY KEY (run_id, cycle_id),
    UNIQUE (run_id, cycle_id, cycle_sha256),
    UNIQUE (run_id, hearing_id, cycle_index),
    UNIQUE (run_id, cycle_id, cycle_sha256, hearing_id),
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, cycle_pack_id, cycle_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, initial_trigger_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, rework_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, created_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT,
    CHECK (cycle_index = 1 + prior_acquisition_rounds + prior_rework_rounds),
    CHECK (
        (initial_trigger_review_id IS NULL
         AND json_array_length(initial_defect_codes_json) = 0)
        OR
        (initial_trigger_review_id IS NOT NULL
         AND json_array_length(initial_defect_codes_json) > 0
         AND cycle_index = 1)
    ),
    CHECK (
        (prior_rework_rounds = 0
         AND rework_review_id IS NULL
         AND json_array_length(rework_defect_codes_json) = 0)
        OR
        (prior_rework_rounds > 0
         AND rework_review_id IS NOT NULL
         AND json_array_length(rework_defect_codes_json) > 0)
    )
) STRICT;

CREATE TABLE m4_precedent_retrieval_receipts (
    run_id TEXT NOT NULL,
    retrieval_receipt_id TEXT NOT NULL
        CHECK (
            length(retrieval_receipt_id) = 64
            AND retrieval_receipt_id NOT GLOB '*[^0-9a-f]*'
        ),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    prior_acquisition_rounds INTEGER NOT NULL
        CHECK (prior_acquisition_rounds BETWEEN 0 AND 2),
    prior_rework_rounds INTEGER NOT NULL
        CHECK (prior_rework_rounds BETWEEN 0 AND 2),
    current_pack_id TEXT NOT NULL
        CHECK (length(current_pack_id) = 64 AND current_pack_id NOT GLOB '*[^0-9a-f]*'),
    current_pack_version INTEGER NOT NULL CHECK (current_pack_version > 0),
    evidence_class TEXT NOT NULL CHECK (evidence_class IN ('PRESENCE', 'ABSENCE')),
    violation_type TEXT NOT NULL CHECK (violation_type IN (
        'PPE_GOGGLES_MISSING', 'PPE_GLOVES_MISSING', 'PPE_LAB_COAT_MISSING',
        'REAGENT_CONTAINER_OPEN', 'FOOD_OR_DRINK_IN_LAB',
        'SINGLE_PERSON_HAZARDOUS_OPERATION', 'FUME_HOOD_SASH_TOO_HIGH',
        'UNATTENDED_HEATING', 'SMOKE_ABNORMAL', 'OPEN_FLAME'
    )),
    rule_version TEXT NOT NULL,
    top_k INTEGER NOT NULL CHECK (top_k BETWEEN 0 AND 64),
    initial_trigger_review_id TEXT,
    initial_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(initial_defect_codes_json)
        AND json_type(initial_defect_codes_json) = 'array'
        AND json_array_length(initial_defect_codes_json) <= 14
    ),
    rework_review_id TEXT,
    rework_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(rework_defect_codes_json)
        AND json_type(rework_defect_codes_json) = 'array'
        AND json_array_length(rework_defect_codes_json) <= 14
    ),
    candidate_precedent_refs_json TEXT NOT NULL CHECK (
        json_valid(candidate_precedent_refs_json)
        AND json_type(candidate_precedent_refs_json) = 'array'
        AND json_array_length(candidate_precedent_refs_json) <= 10000
    ),
    candidate_snapshot_sha256 TEXT NOT NULL CHECK (
        length(candidate_snapshot_sha256) = 64
        AND candidate_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    visible_precedent_refs_json TEXT NOT NULL CHECK (
        json_valid(visible_precedent_refs_json)
        AND json_type(visible_precedent_refs_json) = 'array'
        AND json_array_length(visible_precedent_refs_json) <= 10000
    ),
    visible_snapshot_sha256 TEXT NOT NULL CHECK (
        length(visible_snapshot_sha256) = 64
        AND visible_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    scored_precedents_json TEXT NOT NULL CHECK (
        json_valid(scored_precedents_json)
        AND json_type(scored_precedents_json) = 'array'
        AND json_array_length(scored_precedents_json) <= 64
        AND json_array_length(scored_precedents_json) <= top_k
    ),
    retrieval_status TEXT NOT NULL CHECK (retrieval_status IN ('SUCCESS', 'DEGRADED')),
    degraded_reason TEXT CHECK (degraded_reason IS NULL OR degraded_reason IN (
        'EMBEDDING_PROVIDER_UNAVAILABLE', 'EMBEDDING_MODEL_UNAVAILABLE',
        'PRECEDENT_INDEX_UNAVAILABLE'
    )),
    precedent_retrieval_degraded INTEGER NOT NULL
        CHECK (precedent_retrieval_degraded IN (0, 1)),
    retriever_version TEXT NOT NULL CHECK (length(retriever_version) BETWEEN 1 AND 64),
    retriever_manifest_id TEXT NOT NULL
        CHECK (
            length(retriever_manifest_id) = 64
            AND retriever_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    query_sha256 TEXT NOT NULL
        CHECK (length(query_sha256) = 64 AND query_sha256 NOT GLOB '*[^0-9a-f]*'),
    embedding_model_manifest_id TEXT,
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    receipt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, retrieval_receipt_id),
    UNIQUE (run_id, cycle_scope_id),
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, current_pack_id, current_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, initial_trigger_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, rework_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (retrieval_status = 'DEGRADED'
         AND degraded_reason IS NOT NULL
         AND precedent_retrieval_degraded = 1)
        OR
        (retrieval_status = 'SUCCESS'
         AND degraded_reason IS NULL
         AND precedent_retrieval_degraded = 0)
    ),
    CHECK (
        (initial_trigger_review_id IS NULL
         AND json_array_length(initial_defect_codes_json) = 0)
        OR
        (initial_trigger_review_id IS NOT NULL
         AND json_array_length(initial_defect_codes_json) > 0)
    ),
    CHECK (
        (prior_rework_rounds = 0
         AND rework_review_id IS NULL
         AND json_array_length(rework_defect_codes_json) = 0)
        OR
        (prior_rework_rounds > 0
         AND rework_review_id IS NOT NULL
         AND json_array_length(rework_defect_codes_json) > 0)
    ),
    CHECK (
        embedding_model_manifest_id IS NULL
        OR (length(embedding_model_manifest_id) = 64
            AND embedding_model_manifest_id NOT GLOB '*[^0-9a-f]*')
    )
) STRICT;

-- Raw response receipts are declared before claims so a claim can carry a
-- deferred terminal response FK without a response-to-claim insertion cycle.
CREATE TABLE m4_model_responses (
    run_id TEXT NOT NULL,
    response_id TEXT NOT NULL
        CHECK (length(response_id) = 64 AND response_id NOT GLOB '*[^0-9a-f]*'),
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    request_sha256 TEXT NOT NULL
        CHECK (length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
    cache_key TEXT NOT NULL
        CHECK (length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    purpose TEXT NOT NULL CHECK (purpose IN ('ROLE_CALL', 'STRUCTURE_REPAIR')),
    attempt_index INTEGER NOT NULL CHECK (attempt_index IN (0, 1)),
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    raw_response_ref TEXT NOT NULL,
    content_sha256 TEXT NOT NULL
        CHECK (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    model_manifest_id TEXT NOT NULL
        CHECK (
            length(model_manifest_id) = 64
            AND model_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    response_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, response_id),
    UNIQUE (run_id, request_id),
    UNIQUE (run_id, request_id, response_id),
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (purpose = 'ROLE_CALL' AND attempt_index = 0)
        OR (purpose = 'STRUCTURE_REPAIR' AND attempt_index = 1)
    )
) STRICT;

CREATE TABLE m4_model_call_claims (
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    request_sha256 TEXT NOT NULL
        CHECK (length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'),
    cache_key TEXT NOT NULL
        CHECK (length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    purpose TEXT NOT NULL CHECK (purpose IN ('ROLE_CALL', 'STRUCTURE_REPAIR')),
    attempt_index INTEGER NOT NULL CHECK (attempt_index IN (0, 1)),
    call_generation TEXT NOT NULL CHECK (call_generation IN ('INITIAL', 'BACKLOG')),
    backlog_item_id TEXT,
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    reserved_images INTEGER NOT NULL CHECK (reserved_images BETWEEN 0 AND 64),
    reserved_pixels INTEGER NOT NULL CHECK (reserved_pixels BETWEEN 0 AND 1000000000),
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    model_manifest_id TEXT NOT NULL,
    prompt_manifest_id TEXT NOT NULL,
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
        REFERENCES m4_model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, backlog_item_id)
        REFERENCES backlog_items(run_id, item_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (purpose = 'ROLE_CALL' AND attempt_index = 0)
        OR (purpose = 'STRUCTURE_REPAIR' AND attempt_index = 1)
    ),
    CHECK (
        (purpose = 'ROLE_CALL' AND reserved_images > 0 AND reserved_pixels > 0)
        OR (purpose = 'STRUCTURE_REPAIR' AND reserved_images = 0 AND reserved_pixels = 0)
    ),
    CHECK (
        (call_generation = 'INITIAL'
         AND backlog_item_id IS NULL
         AND retry_generation = 0)
        OR
        (call_generation = 'BACKLOG'
         AND backlog_item_id IS NOT NULL
         AND retry_generation > 0)
    ),
    CHECK (
        (status = 'ACTIVE' AND response_id IS NULL AND completed_at IS NULL)
        OR
        (status = 'COMPLETED' AND response_id IS NOT NULL AND completed_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE m4_parsed_hearing_outputs (
    run_id TEXT NOT NULL,
    parsed_output_id TEXT NOT NULL
        CHECK (
            length(parsed_output_id) = 64
            AND parsed_output_id NOT GLOB '*[^0-9a-f]*'
        ),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    prior_acquisition_rounds INTEGER NOT NULL
        CHECK (prior_acquisition_rounds BETWEEN 0 AND 2),
    prior_rework_rounds INTEGER NOT NULL
        CHECK (prior_rework_rounds BETWEEN 0 AND 2),
    current_pack_id TEXT NOT NULL
        CHECK (length(current_pack_id) = 64 AND current_pack_id NOT GLOB '*[^0-9a-f]*'),
    current_pack_version INTEGER NOT NULL CHECK (current_pack_version > 0),
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    payload_kind TEXT NOT NULL CHECK (
        payload_kind IN ('PROSECUTION', 'DEFENSE', 'JUDGE_VERDICT', 'JUDGE_ACQUISITION')
    ),
    request_id TEXT NOT NULL,
    response_id TEXT NOT NULL,
    parse_receipt_id TEXT NOT NULL,
    response_content_sha256 TEXT NOT NULL,
    output_schema_sha256 TEXT NOT NULL,
    prompt_manifest_id TEXT NOT NULL,
    model_manifest_id TEXT NOT NULL,
    prosecutor_output_id TEXT,
    defender_output_id TEXT,
    precedent_retrieval_degraded INTEGER NOT NULL
        CHECK (precedent_retrieval_degraded IN (0, 1)),
    precedent_retrieval_receipt_id TEXT NOT NULL,
    precedent_retrieval_receipt_sha256 TEXT NOT NULL,
    initial_trigger_review_id TEXT,
    initial_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(initial_defect_codes_json)
        AND json_type(initial_defect_codes_json) = 'array'
        AND json_array_length(initial_defect_codes_json) <= 14
    ),
    rework_review_id TEXT,
    rework_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(rework_defect_codes_json)
        AND json_type(rework_defect_codes_json) = 'array'
        AND json_array_length(rework_defect_codes_json) <= 14
    ),
    payload_sha256 TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    output_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, parsed_output_id),
    UNIQUE (run_id, response_id),
    UNIQUE (run_id, cycle_scope_id, role),
    UNIQUE (run_id, parse_receipt_id),
    FOREIGN KEY (run_id, response_id)
        REFERENCES m4_model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, request_id, response_id)
        REFERENCES m4_model_call_claims(run_id, request_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, parse_receipt_id)
        REFERENCES m4_model_parse_receipts(run_id, parse_receipt_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, precedent_retrieval_receipt_id)
        REFERENCES m4_precedent_retrieval_receipts(run_id, retrieval_receipt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, prosecutor_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, defender_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, initial_trigger_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, rework_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    CHECK (
        length(response_content_sha256) = 64
        AND response_content_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(output_schema_sha256) = 64
        AND output_schema_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(prompt_manifest_id) = 64
        AND prompt_manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(model_manifest_id) = 64
        AND model_manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(precedent_retrieval_receipt_sha256) = 64
        AND precedent_retrieval_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(payload_sha256) = 64
        AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64
        AND manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (role = 'PROSECUTOR' AND payload_kind = 'PROSECUTION')
        OR (role = 'DEFENDER' AND payload_kind = 'DEFENSE')
        OR (role = 'JUDGE' AND payload_kind IN ('JUDGE_VERDICT', 'JUDGE_ACQUISITION'))
    ),
    CHECK (
        (role = 'PROSECUTOR'
         AND prosecutor_output_id IS NULL
         AND defender_output_id IS NULL)
        OR
        (role = 'DEFENDER'
         AND prosecutor_output_id IS NOT NULL
         AND defender_output_id IS NULL)
        OR
        (role = 'JUDGE'
         AND prosecutor_output_id IS NOT NULL
         AND defender_output_id IS NOT NULL)
    ),
    CHECK (
        (initial_trigger_review_id IS NULL
         AND json_array_length(initial_defect_codes_json) = 0)
        OR
        (initial_trigger_review_id IS NOT NULL
         AND json_array_length(initial_defect_codes_json) > 0)
    ),
    CHECK (
        (prior_rework_rounds = 0
         AND rework_review_id IS NULL
         AND json_array_length(rework_defect_codes_json) = 0)
        OR
        (prior_rework_rounds > 0
         AND rework_review_id IS NOT NULL
         AND json_array_length(rework_defect_codes_json) > 0)
    )
) STRICT;

CREATE TABLE m4_model_parse_receipts (
    run_id TEXT NOT NULL,
    parse_receipt_id TEXT NOT NULL
        CHECK (
            length(parse_receipt_id) = 64
            AND parse_receipt_id NOT GLOB '*[^0-9a-f]*'
        ),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    response_id TEXT NOT NULL,
    response_content_sha256 TEXT NOT NULL CHECK (
        length(response_content_sha256) = 64
        AND response_content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    attempt_index INTEGER NOT NULL CHECK (attempt_index IN (0, 1)),
    parser_version TEXT NOT NULL CHECK (length(parser_version) BETWEEN 1 AND 64),
    output_schema_sha256 TEXT NOT NULL CHECK (
        length(output_schema_sha256) = 64
        AND output_schema_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('PARSED', 'REPAIR_REQUIRED', 'INVALID_FINAL')),
    defects_json TEXT NOT NULL CHECK (
        json_valid(defects_json) AND json_type(defects_json) = 'array'
    ),
    parsed_output_id TEXT,
    repair_request_id TEXT,
    manifest_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, parse_receipt_id),
    UNIQUE (run_id, response_id),
    UNIQUE (run_id, request_id, response_id),
    FOREIGN KEY (run_id, request_id, response_id)
        REFERENCES m4_model_responses(run_id, request_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, parsed_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, repair_request_id)
        REFERENCES m4_model_call_claims(run_id, request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    CHECK (
        (status = 'PARSED' AND parsed_output_id IS NOT NULL AND repair_request_id IS NULL)
        OR
        (status = 'REPAIR_REQUIRED'
         AND attempt_index = 0
         AND parsed_output_id IS NULL
         AND repair_request_id IS NOT NULL)
        OR
        (status = 'INVALID_FINAL'
         AND attempt_index = 1
         AND parsed_output_id IS NULL
         AND repair_request_id IS NULL)
    )
) STRICT;

CREATE TABLE m4_model_cache (
    run_id TEXT NOT NULL,
    cache_key TEXT NOT NULL
        CHECK (length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'),
    cache_entry_id TEXT NOT NULL
        CHECK (
            length(cache_entry_id) = 64
            AND cache_entry_id NOT GLOB '*[^0-9a-f]*'
        ),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
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
        REFERENCES m4_model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, request_id, response_id)
        REFERENCES m4_model_call_claims(run_id, request_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    CHECK (
        length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(response_content_sha256) = 64
        AND response_content_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(model_manifest_id) = 64
        AND model_manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(prompt_manifest_id) = 64
        AND prompt_manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(output_schema_sha256) = 64
        AND output_schema_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64
        AND manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(request_document_sha256) = 64
        AND request_document_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE m4_hearing_usage_receipts (
    run_id TEXT NOT NULL,
    usage_receipt_id TEXT NOT NULL
        CHECK (
            length(usage_receipt_id) = 64
            AND usage_receipt_id NOT GLOB '*[^0-9a-f]*'
        ),
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    response_id TEXT NOT NULL
        CHECK (length(response_id) = 64 AND response_id NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    accounted_at TEXT NOT NULL CHECK (length(accounted_at) = 27),
    input_images INTEGER NOT NULL CHECK (input_images >= 0),
    input_pixels INTEGER NOT NULL CHECK (input_pixels >= 0),
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    provider_latency_ms INTEGER NOT NULL CHECK (provider_latency_ms >= 0),
    retries INTEGER NOT NULL CHECK (retries BETWEEN 0 AND 16),
    estimated_cost REAL NOT NULL CHECK (estimated_cost >= 0),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    usage_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, usage_receipt_id),
    UNIQUE (run_id, request_id),
    UNIQUE (run_id, response_id),
    FOREIGN KEY (run_id, request_id, response_id)
        REFERENCES m4_model_call_claims(run_id, request_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, response_id)
        REFERENCES m4_model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        input_images <= 64
        AND input_pixels <= 1000000000
        AND estimated_cost <= 1000000
        AND ((input_images = 0 AND input_pixels = 0)
             OR (input_images > 0 AND input_pixels > 0))
    )
) STRICT;

CREATE TABLE m4_acquisition_requests (
    run_id TEXT NOT NULL,
    acquisition_request_id TEXT NOT NULL
        CHECK (
            length(acquisition_request_id) = 64
            AND acquisition_request_id NOT GLOB '*[^0-9a-f]*'
        ),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    round_index INTEGER NOT NULL CHECK (round_index BETWEEN 1 AND 5),
    prior_acquisition_rounds INTEGER NOT NULL
        CHECK (prior_acquisition_rounds BETWEEN 0 AND 1),
    prior_rework_rounds INTEGER NOT NULL CHECK (prior_rework_rounds BETWEEN 0 AND 2),
    evidence_pack_id TEXT NOT NULL
        CHECK (length(evidence_pack_id) = 64 AND evidence_pack_id NOT GLOB '*[^0-9a-f]*'),
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    judge_output_id TEXT NOT NULL,
    source_model_request_id TEXT NOT NULL,
    source_model_response_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN (
        'REQUEST_MORE_FRAMES', 'RECROP', 'OTHER_CAMERA_SAME_TIME',
        'TRACK_CONFIDENCE_CURVE', 'REDETECT_HIGH_RES'
    )),
    validated_parameters_sha256 TEXT NOT NULL
        CHECK (
            length(validated_parameters_sha256) = 64
            AND validated_parameters_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    request_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, acquisition_request_id),
    UNIQUE (run_id, cycle_scope_id),
    UNIQUE (run_id, judge_output_id),
    FOREIGN KEY (run_id, judge_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, source_model_request_id, source_model_response_id)
        REFERENCES m4_model_call_claims(run_id, request_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (round_index = 1 + prior_acquisition_rounds + prior_rework_rounds)
) STRICT;

-- One request-id key owns the external acquisition boundary.  PURE claims may
-- rotate after expiry; IDEMPOTENT_EXTERNAL claims require explicit recovery
-- before a new fence can be granted.
CREATE TABLE m4_acquisition_execution_claims (
    run_id TEXT NOT NULL,
    acquisition_request_id TEXT NOT NULL CHECK (
        length(acquisition_request_id) = 64
        AND acquisition_request_id NOT GLOB '*[^0-9a-f]*'
    ),
    request_document_sha256 TEXT NOT NULL CHECK (
        length(request_document_sha256) = 64
        AND request_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    request_json TEXT NOT NULL CHECK (json_valid(request_json)),
    case_id TEXT NOT NULL,
    hearing_id TEXT NOT NULL,
    execution_mode TEXT NOT NULL CHECK (
        execution_mode IN ('PURE', 'IDEMPOTENT_EXTERNAL')
    ),
    idempotency_key TEXT NOT NULL CHECK (
        length(idempotency_key) = 64
        AND idempotency_key NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'COMPLETED', 'ABANDONED')),
    owner_token_sha256 TEXT NOT NULL CHECK (
        length(owner_token_sha256) = 64
        AND owner_token_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    owner_fence INTEGER NOT NULL CHECK (owner_fence > 0),
    lease_expires_at TEXT,
    execution_publication_id TEXT,
    created_at TEXT NOT NULL CHECK (length(created_at) = 27),
    updated_at TEXT NOT NULL CHECK (length(updated_at) = 27),
    claim_json TEXT NOT NULL CHECK (json_valid(claim_json)),
    document_sha256 TEXT NOT NULL CHECK (
        length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (run_id, acquisition_request_id),
    UNIQUE (run_id, idempotency_key),
    UNIQUE (run_id, execution_publication_id),
    FOREIGN KEY (run_id, acquisition_request_id)
        REFERENCES m4_acquisition_requests(run_id, acquisition_request_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, execution_publication_id)
        REFERENCES m4_acquisition_execution_publications(
            run_id, execution_publication_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    CHECK (idempotency_key = acquisition_request_id),
    CHECK (
        (status = 'ACTIVE' AND lease_expires_at IS NOT NULL
         AND execution_publication_id IS NULL)
        OR
        (status = 'COMPLETED' AND lease_expires_at IS NULL
         AND execution_publication_id IS NOT NULL)
        OR
        (status = 'ABANDONED' AND lease_expires_at IS NULL
         AND execution_publication_id IS NULL)
    )
) STRICT;

CREATE TABLE m4_hearing_rounds (
    run_id TEXT NOT NULL,
    round_id TEXT NOT NULL
        CHECK (length(round_id) = 64 AND round_id NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    round_index INTEGER NOT NULL CHECK (round_index BETWEEN 1 AND 5),
    prior_acquisition_rounds INTEGER NOT NULL
        CHECK (prior_acquisition_rounds BETWEEN 0 AND 2),
    prior_rework_rounds INTEGER NOT NULL CHECK (prior_rework_rounds BETWEEN 0 AND 2),
    current_pack_id TEXT NOT NULL CHECK (
        length(current_pack_id) = 64 AND current_pack_id NOT GLOB '*[^0-9a-f]*'
    ),
    current_pack_version INTEGER NOT NULL CHECK (current_pack_version > 0),
    precedent_retrieval_degraded INTEGER NOT NULL
        CHECK (precedent_retrieval_degraded IN (0, 1)),
    retrieval_receipt_id TEXT NOT NULL,
    retrieval_receipt_sha256 TEXT NOT NULL CHECK (
        length(retrieval_receipt_sha256) = 64
        AND retrieval_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    initial_trigger_review_id TEXT,
    initial_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(initial_defect_codes_json)
        AND json_type(initial_defect_codes_json) = 'array'
    ),
    rework_review_id TEXT,
    rework_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(rework_defect_codes_json)
        AND json_type(rework_defect_codes_json) = 'array'
    ),
    prosecutor_output_id TEXT NOT NULL,
    defender_output_id TEXT NOT NULL,
    judge_output_id TEXT NOT NULL,
    acquisition_request_id TEXT,
    tool_receipt_id TEXT,
    resulting_pack_id TEXT NOT NULL CHECK (
        length(resulting_pack_id) = 64 AND resulting_pack_id NOT GLOB '*[^0-9a-f]*'
    ),
    resulting_pack_version INTEGER NOT NULL CHECK (resulting_pack_version > 0),
    manifest_id TEXT NOT NULL CHECK (
        length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    round_json TEXT NOT NULL CHECK (json_valid(round_json)),
    PRIMARY KEY (run_id, round_id),
    UNIQUE (run_id, round_id, hearing_id),
    UNIQUE (run_id, cycle_scope_id),
    UNIQUE (run_id, hearing_id, round_index),
    FOREIGN KEY (run_id, retrieval_receipt_id)
        REFERENCES m4_precedent_retrieval_receipts(run_id, retrieval_receipt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, prosecutor_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, defender_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, judge_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, acquisition_request_id)
        REFERENCES m4_acquisition_requests(run_id, acquisition_request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, tool_receipt_id)
        REFERENCES m4_tool_execution_receipts(run_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, current_pack_id, current_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, resulting_pack_id, resulting_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, initial_trigger_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, rework_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (round_index = 1 + prior_acquisition_rounds + prior_rework_rounds),
    CHECK (
        (acquisition_request_id IS NULL AND tool_receipt_id IS NULL
         AND resulting_pack_id = current_pack_id
         AND resulting_pack_version = current_pack_version)
        OR
        (acquisition_request_id IS NOT NULL AND tool_receipt_id IS NOT NULL
         AND resulting_pack_id <> current_pack_id
         AND resulting_pack_version = current_pack_version + 1)
    )
) STRICT;

CREATE TABLE m4_tool_execution_manifests (
    run_id TEXT NOT NULL,
    execution_manifest_id TEXT NOT NULL
        CHECK (
            length(execution_manifest_id) = 64
            AND execution_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    case_id TEXT NOT NULL,
    hearing_id TEXT NOT NULL,
    acquisition_request_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN (
        'REQUEST_MORE_FRAMES', 'RECROP', 'OTHER_CAMERA_SAME_TIME',
        'TRACK_CONFIDENCE_CURVE', 'REDETECT_HIGH_RES'
    )),
    tool_id TEXT NOT NULL CHECK (length(tool_id) BETWEEN 1 AND 64),
    tool_revision TEXT NOT NULL CHECK (length(tool_revision) BETWEEN 1 AND 64),
    parameters_schema_sha256 TEXT NOT NULL
        CHECK (
            length(parameters_schema_sha256) = 64
            AND parameters_schema_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    component_manifest_id TEXT NOT NULL
        CHECK (
            length(component_manifest_id) = 64
            AND component_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    model_manifest_id TEXT,
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    manifest_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, execution_manifest_id),
    UNIQUE (run_id, acquisition_request_id),
    FOREIGN KEY (run_id, acquisition_request_id)
        REFERENCES m4_acquisition_requests(run_id, acquisition_request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (action = 'REDETECT_HIGH_RES'
         AND model_manifest_id IS NOT NULL
         AND length(model_manifest_id) = 64
         AND model_manifest_id NOT GLOB '*[^0-9a-f]*')
        OR (action <> 'REDETECT_HIGH_RES' AND model_manifest_id IS NULL)
    )
) STRICT;

-- The fenced execution publication is the durable boundary immediately after
-- tool delivery and before any EvidencePack or Case mutation.  It deliberately
-- contains the complete typed result so a completed execution can be replayed
-- without calling the provider again.
CREATE TABLE m4_acquisition_execution_publications (
    run_id TEXT NOT NULL,
    execution_publication_id TEXT NOT NULL CHECK (
        length(execution_publication_id) = 64
        AND execution_publication_id NOT GLOB '*[^0-9a-f]*'
    ),
    acquisition_request_id TEXT NOT NULL,
    request_document_sha256 TEXT NOT NULL CHECK (
        length(request_document_sha256) = 64
        AND request_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    hearing_id TEXT NOT NULL,
    execution_manifest_id TEXT NOT NULL,
    tool_result_id TEXT NOT NULL CHECK (
        length(tool_result_id) = 64
        AND tool_result_id NOT GLOB '*[^0-9a-f]*'
    ),
    execution_mode TEXT NOT NULL CHECK (
        execution_mode IN ('PURE', 'IDEMPOTENT_EXTERNAL')
    ),
    idempotency_key TEXT NOT NULL CHECK (
        length(idempotency_key) = 64
        AND idempotency_key NOT GLOB '*[^0-9a-f]*'
    ),
    claim_owner_sha256 TEXT NOT NULL CHECK (
        length(claim_owner_sha256) = 64
        AND claim_owner_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    claim_fence INTEGER NOT NULL CHECK (claim_fence > 0),
    publication_json TEXT NOT NULL CHECK (json_valid(publication_json)),
    document_sha256 TEXT NOT NULL CHECK (
        length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (run_id, execution_publication_id),
    UNIQUE (run_id, acquisition_request_id),
    UNIQUE (run_id, execution_manifest_id),
    UNIQUE (run_id, tool_result_id),
    FOREIGN KEY (run_id, acquisition_request_id)
        REFERENCES m4_acquisition_requests(run_id, acquisition_request_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, execution_manifest_id)
        REFERENCES m4_tool_execution_manifests(run_id, execution_manifest_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    CHECK (idempotency_key = acquisition_request_id),
    CHECK (
        json_extract(publication_json, '$.publication_id')
            = execution_publication_id
        AND json_extract(publication_json, '$.request.request_id')
            = acquisition_request_id
        AND json_extract(publication_json, '$.request.document_sha256')
            = request_document_sha256
        AND json_extract(publication_json, '$.request.run_id') = run_id
        AND json_extract(publication_json, '$.request.case_id') = case_id
        AND json_extract(
            publication_json, '$.request.hearing_session_id'
        ) = hearing_id
        AND json_extract(
            publication_json, '$.execution_manifest.execution_manifest_id'
        ) = execution_manifest_id
        AND json_extract(publication_json, '$.tool_result.tool_result_id')
            = tool_result_id
        AND json_extract(publication_json, '$.execution_mode') = execution_mode
        AND json_extract(publication_json, '$.idempotency_key') = idempotency_key
        AND json_extract(publication_json, '$.claim_owner_sha256')
            = claim_owner_sha256
        AND json_extract(publication_json, '$.claim_fence') = claim_fence
    )
) STRICT;

-- RECROP results cannot be embedded in the frozen EvidencePack crop tuples.
-- This registry gives the acquired Crop its own content-addressed authority so
-- later hearing calls can resolve a CROP ref without weakening M2 pack rules.
CREATE TABLE m4_acquired_crops (
    run_id TEXT NOT NULL,
    crop_id TEXT NOT NULL
        CHECK (length(crop_id) = 64 AND crop_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    hearing_id TEXT NOT NULL,
    acquisition_request_id TEXT NOT NULL,
    execution_manifest_id TEXT NOT NULL,
    frame_id TEXT NOT NULL,
    media_sha256 TEXT NOT NULL
        CHECK (length(media_sha256) = 64 AND media_sha256 NOT GLOB '*[^0-9a-f]*'),
    source_media_sha256 TEXT NOT NULL CHECK (
        length(source_media_sha256) = 64
        AND source_media_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    pixel_sha256 TEXT NOT NULL
        CHECK (length(pixel_sha256) = 64 AND pixel_sha256 NOT GLOB '*[^0-9a-f]*'),
    source_pack_id TEXT NOT NULL
        CHECK (length(source_pack_id) = 64 AND source_pack_id NOT GLOB '*[^0-9a-f]*'),
    source_pack_version INTEGER NOT NULL CHECK (source_pack_version > 0),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    crop_json TEXT NOT NULL CHECK (json_valid(crop_json)),
    document_sha256 TEXT NOT NULL CHECK (
        length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (run_id, crop_id),
    UNIQUE (run_id, acquisition_request_id),
    UNIQUE (run_id, crop_id, acquisition_request_id),
    FOREIGN KEY (run_id, acquisition_request_id)
        REFERENCES m4_acquisition_requests(run_id, acquisition_request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, execution_manifest_id)
        REFERENCES m4_tool_execution_manifests(run_id, execution_manifest_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, frame_id, manifest_id)
        REFERENCES frames(run_id, frame_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, media_sha256)
        REFERENCES media_assets(run_id, media_sha256) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, source_pack_id, source_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        json_extract(crop_json, '$.crop_id') = crop_id
        AND json_extract(crop_json, '$.frame_id') = frame_id
        AND json_extract(crop_json, '$.source') = 'RECROP'
        AND json_extract(crop_json, '$.media_sha256') = media_sha256
        AND json_extract(crop_json, '$.source_media_sha256') = source_media_sha256
        AND json_extract(crop_json, '$.pixel_sha256') = pixel_sha256
        AND json_extract(crop_json, '$.media_type') = 'IMAGE_PNG'
    )
) STRICT;

CREATE TABLE m4_tool_execution_receipts (
    run_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL
        CHECK (length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    acquisition_request_id TEXT NOT NULL,
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN (
        'REQUEST_MORE_FRAMES', 'RECROP', 'OTHER_CAMERA_SAME_TIME',
        'TRACK_CONFIDENCE_CURVE', 'REDETECT_HIGH_RES'
    )),
    execution_manifest_id TEXT NOT NULL,
    tool_result_id TEXT NOT NULL CHECK (length(tool_result_id) BETWEEN 1 AND 64),
    resulting_pack_id TEXT NOT NULL
        CHECK (
            length(resulting_pack_id) = 64
            AND resulting_pack_id NOT GLOB '*[^0-9a-f]*'
        ),
    resulting_pack_version INTEGER NOT NULL CHECK (resulting_pack_version > 0),
    receipt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, receipt_id),
    UNIQUE (run_id, acquisition_request_id),
    UNIQUE (run_id, tool_result_id),
    FOREIGN KEY (run_id, acquisition_request_id)
        REFERENCES m4_acquisition_requests(run_id, acquisition_request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, execution_manifest_id)
        REFERENCES m4_tool_execution_manifests(run_id, execution_manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, resulting_pack_id, resulting_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT
) STRICT;

CREATE TABLE m4_evidence_pack_derivations (
    run_id TEXT NOT NULL,
    derivation_id TEXT NOT NULL
        CHECK (length(derivation_id) = 64 AND derivation_id NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    source_cycle_scope_id TEXT NOT NULL,
    source_cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(source_cycle_scope_sha256) = 64
        AND source_cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    previous_pack_id TEXT NOT NULL,
    previous_pack_version INTEGER NOT NULL CHECK (previous_pack_version > 0),
    new_pack_id TEXT NOT NULL,
    new_pack_version INTEGER NOT NULL CHECK (new_pack_version > 0),
    tool_receipt_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    derivation_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, derivation_id),
    UNIQUE (run_id, new_pack_id),
    UNIQUE (run_id, tool_receipt_id),
    FOREIGN KEY (
        run_id, source_cycle_scope_id, source_cycle_scope_sha256, hearing_id
    ) REFERENCES m4_hearing_cycles(
        run_id, cycle_id, cycle_sha256, hearing_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, previous_pack_id, previous_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, new_pack_id, new_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, tool_receipt_id)
        REFERENCES m4_tool_execution_receipts(run_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (new_pack_version = previous_pack_version + 1),
    CHECK (
        length(previous_pack_id) = 64
        AND previous_pack_id NOT GLOB '*[^0-9a-f]*'
        AND length(new_pack_id) = 64
        AND new_pack_id NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64
        AND manifest_id NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE m4_hearing_verdict_bindings (
    run_id TEXT NOT NULL,
    binding_id TEXT NOT NULL
        CHECK (length(binding_id) = 64 AND binding_id NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    hearing_record_id TEXT NOT NULL,
    hearing_record_version INTEGER NOT NULL CHECK (hearing_record_version > 0),
    hearing_record_sha256 TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    round_id TEXT NOT NULL,
    judge_round_index INTEGER NOT NULL CHECK (judge_round_index BETWEEN 1 AND 5),
    case_id TEXT NOT NULL,
    evidence_pack_id TEXT NOT NULL,
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version > 0),
    verdict_id TEXT NOT NULL,
    verdict_version INTEGER NOT NULL CHECK (verdict_version > 0),
    verdict_input_sha256 TEXT NOT NULL,
    verdict_sha256 TEXT NOT NULL,
    prosecutor_output_id TEXT NOT NULL,
    defender_output_id TEXT NOT NULL,
    judge_output_id TEXT NOT NULL,
    model_request_refs_json TEXT NOT NULL CHECK (
        json_valid(model_request_refs_json)
        AND json_type(model_request_refs_json) = 'array'
    ),
    model_response_refs_json TEXT NOT NULL CHECK (
        json_valid(model_response_refs_json)
        AND json_type(model_response_refs_json) = 'array'
    ),
    parse_receipt_refs_json TEXT NOT NULL CHECK (
        json_valid(parse_receipt_refs_json)
        AND json_type(parse_receipt_refs_json) = 'array'
    ),
    manifest_id TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, binding_id),
    UNIQUE (run_id, verdict_id),
    UNIQUE (run_id, round_id),
    FOREIGN KEY (run_id, round_id)
        REFERENCES m4_hearing_rounds(run_id, round_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, evidence_pack_id, evidence_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, verdict_id, verdict_version)
        REFERENCES verdicts(run_id, case_id, verdict_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, prosecutor_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, defender_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, judge_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    CHECK (
        length(verdict_sha256) = 64
        AND verdict_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(verdict_input_sha256) = 64
        AND verdict_input_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(hearing_record_id) = 64
        AND hearing_record_id NOT GLOB '*[^0-9a-f]*'
        AND length(hearing_record_sha256) = 64
        AND hearing_record_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64
        AND manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE m4_rework_receipts (
    run_id TEXT NOT NULL,
    rework_receipt_id TEXT NOT NULL
        CHECK (
            length(rework_receipt_id) = 64
            AND rework_receipt_id NOT GLOB '*[^0-9a-f]*'
        ),
    hearing_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    failed_review_id TEXT NOT NULL,
    prior_round_id TEXT NOT NULL,
    next_cycle_scope_id TEXT NOT NULL,
    next_cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(next_cycle_scope_sha256) = 64
        AND next_cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    rework_index INTEGER NOT NULL CHECK (rework_index BETWEEN 1 AND 2),
    defect_set_sha256 TEXT NOT NULL,
    defect_codes_json TEXT NOT NULL CHECK (
        json_valid(defect_codes_json)
        AND json_type(defect_codes_json) = 'array'
        AND json_array_length(defect_codes_json) BETWEEN 1 AND 14
    ),
    prompt_defect_summary_sha256 TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, rework_receipt_id),
    UNIQUE (run_id, failed_review_id),
    UNIQUE (run_id, next_cycle_scope_id),
    FOREIGN KEY (run_id, failed_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, prior_round_id, hearing_id)
        REFERENCES m4_hearing_rounds(run_id, round_id, hearing_id) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, next_cycle_scope_id, next_cycle_scope_sha256, hearing_id
    ) REFERENCES m4_hearing_cycles(
        run_id, cycle_id, cycle_sha256, hearing_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        length(defect_set_sha256) = 64
        AND defect_set_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(prompt_defect_summary_sha256) = 64
        AND prompt_defect_summary_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64
        AND manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE m4_backlog_completion_receipts (
    run_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL
        CHECK (length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    receipt_sha256 TEXT NOT NULL
        CHECK (length(receipt_sha256) = 64 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'),
    item_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    hearing_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('SUCCESS', 'FAILURE')),
    outcome_id TEXT NOT NULL
        CHECK (length(outcome_id) = 64 AND outcome_id NOT GLOB '*[^0-9a-f]*'),
    lease_identity_sha256 TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    attempt_count INTEGER NOT NULL CHECK (attempt_count > 0),
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    backlog_status TEXT NOT NULL CHECK (backlog_status IN ('PENDING', 'COMPLETED', 'EXHAUSTED')),
    backlog_version INTEGER NOT NULL CHECK (backlog_version > 1),
    source_checkpoint_id TEXT NOT NULL,
    source_checkpoint_sha256 TEXT NOT NULL,
    source_checkpoint_version INTEGER NOT NULL CHECK (source_checkpoint_version > 0),
    resulting_checkpoint_id TEXT NOT NULL,
    resulting_checkpoint_sha256 TEXT NOT NULL,
    resulting_checkpoint_version INTEGER NOT NULL CHECK (resulting_checkpoint_version > 0),
    completion_case_status TEXT NOT NULL CHECK (
        completion_case_status IN ('DELIBERATING', 'BACKLOGGED', 'HUMAN_REVIEW')
    ),
    completion_case_revision INTEGER NOT NULL CHECK (completion_case_revision > 0),
    completion_audit_sequence INTEGER NOT NULL CHECK (completion_audit_sequence >= 0),
    completion_audit_entry_hash TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, receipt_id),
    UNIQUE (run_id, item_id, lease_identity_sha256),
    UNIQUE (run_id, item_id, lease_id),
    UNIQUE (run_id, outcome_id),
    FOREIGN KEY (run_id, outcome_id)
        REFERENCES m4_hearing_backlog_retry_outcomes(run_id, outcome_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, item_id)
        REFERENCES backlog_items(run_id, item_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, item_id, backlog_version)
        REFERENCES backlog_item_versions(run_id, item_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, source_checkpoint_id,
        source_checkpoint_sha256, source_checkpoint_version
    ) REFERENCES m4_hearing_checkpoints(
        run_id, checkpoint_id, checkpoint_sha256, version
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, resulting_checkpoint_id,
        resulting_checkpoint_sha256, resulting_checkpoint_version
    ) REFERENCES m4_hearing_checkpoints(
        run_id, checkpoint_id, checkpoint_sha256, version
    ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, completion_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, completion_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        length(item_id) = 64 AND item_id NOT GLOB '*[^0-9a-f]*'
        AND length(lease_identity_sha256) = 64
        AND lease_identity_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(lease_id) = 64 AND lease_id NOT GLOB '*[^0-9a-f]*'
        AND length(completion_audit_entry_hash) = 64
        AND completion_audit_entry_hash NOT GLOB '*[^0-9a-f]*'
        AND length(source_checkpoint_sha256) = 64
        AND source_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(resulting_checkpoint_sha256) = 64
        AND resulting_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE m4_model_call_failure_authorities (
    run_id TEXT NOT NULL,
    authority_id TEXT NOT NULL
        CHECK (length(authority_id) = 64 AND authority_id NOT GLOB '*[^0-9a-f]*'),
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    request_document_sha256 TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    source_checkpoint_id TEXT NOT NULL,
    source_checkpoint_sha256 TEXT NOT NULL,
    source_checkpoint_version INTEGER NOT NULL CHECK (source_checkpoint_version > 0),
    lease_identity_sha256 TEXT,
    lease_id TEXT,
    backlog_attempt_count INTEGER NOT NULL CHECK (backlog_attempt_count >= 0),
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    claim_owner_sha256 TEXT NOT NULL,
    claim_lease_expires_at TEXT NOT NULL CHECK (length(claim_lease_expires_at) = 27),
    claim_takeover_count INTEGER NOT NULL CHECK (claim_takeover_count >= 0),
    failure_code TEXT NOT NULL CHECK (failure_code IN (
        'FIXTURE_MISSING', 'PROVIDER_OUTAGE', 'PROVIDER_TIMEOUT',
        'REQUEST_IDENTITY_MISMATCH', 'PROMPT_MISSING', 'PROMPT_INTEGRITY_FAILURE',
        'MEDIA_POLICY_REJECTED', 'MEDIA_INTEGRITY_FAILURE',
        'RESPONSE_ENVELOPE_INVALID', 'RESPONSE_TOO_LARGE',
        'RESPONSE_TOKEN_BUDGET_EXCEEDED', 'RESPONSE_COST_BUDGET_EXCEEDED',
        'RESPONSE_PERSISTENCE_FAILURE'
    )),
    delivery_certainty TEXT NOT NULL CHECK (
        delivery_certainty IN ('DEFINITELY_NOT_SENT', 'COMPLETED')
    ),
    provider_response_content_sha256 TEXT,
    reserved_images INTEGER NOT NULL CHECK (reserved_images BETWEEN 0 AND 64),
    reserved_pixels INTEGER NOT NULL CHECK (reserved_pixels BETWEEN 0 AND 1000000000),
    disclosed_images INTEGER NOT NULL CHECK (disclosed_images BETWEEN 0 AND 64),
    disclosed_pixels INTEGER NOT NULL CHECK (disclosed_pixels BETWEEN 0 AND 1000000000),
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    latency_ms INTEGER NOT NULL CHECK (latency_ms >= 0),
    estimated_cost REAL NOT NULL CHECK (estimated_cost BETWEEN 0 AND 1000000),
    backlog_item_id TEXT NOT NULL,
    backlog_reason_code TEXT NOT NULL CHECK (backlog_reason_code IN (
        'PROVIDER_UNAVAILABLE', 'MODEL_OUTPUT_INVALID', 'BUDGET_EXCEEDED',
        'RESPONSE_INTEGRITY_FAILURE', 'CURRENT_PACK_CHANGED', 'WORKER_LEASE_EXPIRED'
    )),
    backlog_version INTEGER NOT NULL CHECK (backlog_version > 0),
    backlog_status TEXT NOT NULL CHECK (backlog_status IN ('PENDING', 'EXHAUSTED')),
    closure_kind TEXT NOT NULL CHECK (closure_kind IN ('INITIAL_BACKLOG', 'RETRY_FAILURE')),
    completion_receipt_id TEXT,
    closure_case_revision INTEGER NOT NULL CHECK (closure_case_revision > 0),
    closure_audit_sequence INTEGER NOT NULL CHECK (closure_audit_sequence >= 0),
    closure_audit_entry_hash TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL CHECK (length(recorded_at) = 27),
    authority_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, authority_id),
    UNIQUE (run_id, request_id, claim_takeover_count),
    UNIQUE (run_id, completion_receipt_id),
    FOREIGN KEY (run_id, request_id)
        REFERENCES m4_model_call_claims(run_id, request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, source_checkpoint_id,
        source_checkpoint_sha256, source_checkpoint_version
    ) REFERENCES m4_hearing_checkpoints(
        run_id, checkpoint_id, checkpoint_sha256, version
    ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, backlog_item_id, backlog_version)
        REFERENCES backlog_item_versions(run_id, item_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, completion_receipt_id)
        REFERENCES m4_backlog_completion_receipts(run_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, closure_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, closure_audit_sequence)
        REFERENCES audit_entries(run_id, sequence) ON DELETE RESTRICT,
    CHECK (
        length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'
        AND length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(request_document_sha256) = 64
        AND request_document_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'
        AND length(claim_owner_sha256) = 64
        AND claim_owner_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(backlog_item_id) = 64
        AND backlog_item_id NOT GLOB '*[^0-9a-f]*'
        AND (
            (lease_identity_sha256 IS NULL AND lease_id IS NULL)
            OR
            (length(lease_identity_sha256) = 64
             AND lease_identity_sha256 NOT GLOB '*[^0-9a-f]*'
             AND length(lease_id) = 64
             AND lease_id NOT GLOB '*[^0-9a-f]*')
        )
        AND length(source_checkpoint_sha256) = 64
        AND source_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(closure_audit_entry_hash) = 64
        AND closure_audit_entry_hash NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (closure_kind = 'INITIAL_BACKLOG'
         AND lease_identity_sha256 IS NULL
         AND lease_id IS NULL
         AND backlog_version = 1
         AND backlog_status = 'PENDING'
         AND backlog_attempt_count = 0
         AND retry_generation = 0
         AND completion_receipt_id IS NULL)
        OR
        (closure_kind = 'RETRY_FAILURE'
         AND lease_identity_sha256 IS NOT NULL
         AND lease_id IS NOT NULL
         AND backlog_attempt_count > 0
         AND completion_receipt_id IS NOT NULL)
    ),
    CHECK (
        (failure_code IN (
             'FIXTURE_MISSING', 'PROVIDER_OUTAGE', 'PROVIDER_TIMEOUT',
             'REQUEST_IDENTITY_MISMATCH', 'PROMPT_MISSING',
             'PROMPT_INTEGRITY_FAILURE', 'MEDIA_POLICY_REJECTED',
             'MEDIA_INTEGRITY_FAILURE'
         ) AND delivery_certainty = 'DEFINITELY_NOT_SENT')
        OR
        (failure_code IN (
             'RESPONSE_ENVELOPE_INVALID', 'RESPONSE_TOO_LARGE',
             'RESPONSE_TOKEN_BUDGET_EXCEEDED',
             'RESPONSE_COST_BUDGET_EXCEEDED', 'RESPONSE_PERSISTENCE_FAILURE'
         ) AND delivery_certainty = 'COMPLETED')
    ),
    CHECK (
        (delivery_certainty = 'DEFINITELY_NOT_SENT'
         AND provider_response_content_sha256 IS NULL
         AND disclosed_images = 0
         AND disclosed_pixels = 0
         AND input_tokens = 0
         AND output_tokens = 0
         AND latency_ms = 0
         AND estimated_cost = 0)
        OR
        (delivery_certainty = 'COMPLETED'
         AND provider_response_content_sha256 IS NOT NULL
         AND length(provider_response_content_sha256) = 64
         AND provider_response_content_sha256 NOT GLOB '*[^0-9a-f]*'
         AND disclosed_images = reserved_images
         AND disclosed_pixels = reserved_pixels)
    )
) STRICT;

-- Checkpoints are the crash-resume head for a hearing.  A cycle root exists
-- before any model call, so prosecutor/defender/Judge and tool-pending phases
-- can be committed independently without pretending a full HearingRound exists.
CREATE TABLE m4_hearing_checkpoints (
    run_id TEXT NOT NULL,
    checkpoint_id TEXT NOT NULL
        CHECK (length(checkpoint_id) = 64 AND checkpoint_id NOT GLOB '*[^0-9a-f]*'),
    checkpoint_sha256 TEXT NOT NULL
        CHECK (
            length(checkpoint_sha256) = 64
            AND checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    hearing_id TEXT NOT NULL,
    hearing_sha256 TEXT NOT NULL
        CHECK (length(hearing_sha256) = 64 AND hearing_sha256 NOT GLOB '*[^0-9a-f]*'),
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    phase TEXT NOT NULL CHECK (phase IN (
        'PRECEDENT_RETRIEVAL_PENDING', 'PROSECUTOR_PENDING',
        'DEFENDER_PENDING', 'JUDGE_PENDING', 'ACQUISITION_PENDING',
        'ROUND_COMPLETE', 'REWORK_READY', 'COMPLETE', 'HUMAN_REVIEW'
    )),
    judge_cycle INTEGER NOT NULL CHECK (judge_cycle BETWEEN 1 AND 5),
    prior_acquisition_rounds INTEGER NOT NULL
        CHECK (prior_acquisition_rounds BETWEEN 0 AND 2),
    prior_rework_rounds INTEGER NOT NULL
        CHECK (prior_rework_rounds BETWEEN 0 AND 2),
    cycle_pack_id TEXT NOT NULL
        CHECK (length(cycle_pack_id) = 64 AND cycle_pack_id NOT GLOB '*[^0-9a-f]*'),
    cycle_pack_version INTEGER NOT NULL CHECK (cycle_pack_version > 0),
    current_pack_id TEXT NOT NULL
        CHECK (length(current_pack_id) = 64 AND current_pack_id NOT GLOB '*[^0-9a-f]*'),
    current_pack_version INTEGER NOT NULL CHECK (current_pack_version > 0),
    previous_checkpoint_id TEXT,
    previous_checkpoint_sha256 TEXT,
    previous_phase TEXT CHECK (previous_phase IS NULL OR previous_phase IN (
        'PRECEDENT_RETRIEVAL_PENDING', 'PROSECUTOR_PENDING',
        'DEFENDER_PENDING', 'JUDGE_PENDING', 'ACQUISITION_PENDING',
        'ROUND_COMPLETE', 'REWORK_READY', 'COMPLETE', 'HUMAN_REVIEW'
    )),
    initial_trigger_review_id TEXT,
    initial_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(initial_defect_codes_json)
        AND json_type(initial_defect_codes_json) = 'array'
        AND json_array_length(initial_defect_codes_json) <= 14
    ),
    cycle_trigger_review_id TEXT,
    cycle_trigger_defect_codes_json TEXT NOT NULL CHECK (
        json_valid(cycle_trigger_defect_codes_json)
        AND json_type(cycle_trigger_defect_codes_json) = 'array'
        AND json_array_length(cycle_trigger_defect_codes_json) <= 14
    ),
    retrieval_receipt_id TEXT,
    retrieval_receipt_sha256 TEXT,
    prosecutor_output_id TEXT,
    defender_output_id TEXT,
    judge_output_id TEXT,
    acquisition_request_id TEXT,
    tool_receipt_id TEXT,
    procedural_review_id TEXT,
    human_review_receipt_id TEXT,
    human_review_receipt_sha256 TEXT,
    human_review_reason TEXT CHECK (human_review_reason IS NULL OR human_review_reason IN (
        'ACQUISITION_LIMIT_EXHAUSTED', 'REWORK_LIMIT_EXHAUSTED',
        'HEARING_BUDGET_EXHAUSTED', 'EVIDENCE_UNAVAILABLE',
        'ACQUISITION_UNRECOVERABLE', 'HEARING_BACKLOG_EXHAUSTED'
    )),
    model_request_refs_json TEXT NOT NULL
        CHECK (json_valid(model_request_refs_json) AND json_type(model_request_refs_json) = 'array'),
    model_response_refs_json TEXT NOT NULL
        CHECK (
            json_valid(model_response_refs_json)
            AND json_type(model_response_refs_json) = 'array'
        ),
    parse_receipt_refs_json TEXT NOT NULL
        CHECK (json_valid(parse_receipt_refs_json) AND json_type(parse_receipt_refs_json) = 'array'),
    usage_receipt_ids_json TEXT NOT NULL
        CHECK (json_valid(usage_receipt_ids_json) AND json_type(usage_receipt_ids_json) = 'array'),
    failure_authority_ids_json TEXT NOT NULL CHECK (
        json_valid(failure_authority_ids_json)
        AND json_type(failure_authority_ids_json) = 'array'
        AND json_array_length(failure_authority_ids_json) BETWEEN 0 AND 640
    ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    checkpoint_json TEXT NOT NULL,
    PRIMARY KEY (run_id, checkpoint_id),
    UNIQUE (run_id, checkpoint_id, checkpoint_sha256),
    UNIQUE (run_id, checkpoint_id, checkpoint_sha256, version),
    UNIQUE (run_id, hearing_id, version),
    UNIQUE (run_id, previous_checkpoint_id),
    UNIQUE (run_id, human_review_receipt_id),
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, cycle_pack_id, cycle_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, current_pack_id, current_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, previous_checkpoint_id, previous_checkpoint_sha256)
        REFERENCES m4_hearing_checkpoints(
            run_id, checkpoint_id, checkpoint_sha256
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, initial_trigger_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_trigger_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, retrieval_receipt_id)
        REFERENCES m4_precedent_retrieval_receipts(run_id, retrieval_receipt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, prosecutor_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, defender_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, judge_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, acquisition_request_id)
        REFERENCES m4_acquisition_requests(run_id, acquisition_request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, tool_receipt_id)
        REFERENCES m4_tool_execution_receipts(run_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, procedural_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, human_review_receipt_id)
        REFERENCES m4_hearing_human_review_receipts(run_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (judge_cycle = 1 + prior_acquisition_rounds + prior_rework_rounds),
    CHECK (
        (initial_trigger_review_id IS NULL
         AND json_array_length(initial_defect_codes_json) = 0)
        OR
        (initial_trigger_review_id IS NOT NULL
         AND json_array_length(initial_defect_codes_json) > 0
         AND judge_cycle = 1
         AND prior_acquisition_rounds = 0
         AND prior_rework_rounds = 0)
    ),
    CHECK (
        (prior_rework_rounds = 0
         AND cycle_trigger_review_id IS NULL
         AND json_array_length(cycle_trigger_defect_codes_json) = 0)
        OR
        (prior_rework_rounds > 0
         AND cycle_trigger_review_id IS NOT NULL
         AND json_array_length(cycle_trigger_defect_codes_json) > 0)
    ),
    CHECK (
        json_array_length(model_request_refs_json)
            = json_array_length(model_response_refs_json)
        AND json_array_length(model_request_refs_json)
            = json_array_length(parse_receipt_refs_json)
        AND json_array_length(model_request_refs_json)
            = json_array_length(usage_receipt_ids_json)
        AND json_array_length(model_request_refs_json) BETWEEN 0 AND 640
    ),
    CHECK (
        (version = 1
         AND previous_checkpoint_id IS NULL
         AND previous_checkpoint_sha256 IS NULL
         AND previous_phase IS NULL)
        OR
        (version > 1
         AND previous_checkpoint_id IS NOT NULL
         AND previous_checkpoint_sha256 IS NOT NULL
         AND previous_phase IS NOT NULL)
    ),
    CHECK (
        (retrieval_receipt_id IS NULL AND retrieval_receipt_sha256 IS NULL)
        OR
        (retrieval_receipt_id IS NOT NULL
         AND retrieval_receipt_sha256 IS NOT NULL
         AND length(retrieval_receipt_sha256) = 64
         AND retrieval_receipt_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    CHECK (
        (phase = 'HUMAN_REVIEW'
         AND human_review_receipt_id IS NOT NULL
         AND human_review_receipt_sha256 IS NOT NULL
         AND human_review_reason IS NOT NULL
         AND length(human_review_receipt_sha256) = 64
         AND human_review_receipt_sha256 NOT GLOB '*[^0-9a-f]*')
        OR
        (phase <> 'HUMAN_REVIEW'
         AND human_review_receipt_id IS NULL
         AND human_review_receipt_sha256 IS NULL
         AND human_review_reason IS NULL)
    )
) STRICT;

CREATE TABLE m4_hearing_human_review_receipts (
    run_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL
        CHECK (length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    receipt_sha256 TEXT NOT NULL
        CHECK (length(receipt_sha256) = 64 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    current_pack_id TEXT NOT NULL
        CHECK (length(current_pack_id) = 64 AND current_pack_id NOT GLOB '*[^0-9a-f]*'),
    current_pack_version INTEGER NOT NULL CHECK (current_pack_version > 0),
    judge_cycle INTEGER NOT NULL CHECK (judge_cycle BETWEEN 1 AND 5),
    reason TEXT NOT NULL CHECK (reason IN (
        'ACQUISITION_LIMIT_EXHAUSTED', 'REWORK_LIMIT_EXHAUSTED',
        'HEARING_BUDGET_EXHAUSTED', 'EVIDENCE_UNAVAILABLE',
        'ACQUISITION_UNRECOVERABLE', 'HEARING_BACKLOG_EXHAUSTED'
    )),
    source_checkpoint_id TEXT NOT NULL,
    source_checkpoint_sha256 TEXT NOT NULL
        CHECK (
            length(source_checkpoint_sha256) = 64
            AND source_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    source_checkpoint_version INTEGER NOT NULL CHECK (source_checkpoint_version > 0),
    procedural_review_id TEXT,
    backlog_item_id TEXT,
    acquisition_model_request_id TEXT,
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    receipt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, receipt_id),
    UNIQUE (run_id, source_checkpoint_id),
    FOREIGN KEY (
        run_id, source_checkpoint_id,
        source_checkpoint_sha256, source_checkpoint_version
    ) REFERENCES m4_hearing_checkpoints(
        run_id, checkpoint_id, checkpoint_sha256, version
    ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, current_pack_id, current_pack_version)
        REFERENCES evidence_packs(run_id, case_id, pack_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, procedural_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, backlog_item_id)
        REFERENCES backlog_items(run_id, item_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, acquisition_model_request_id)
        REFERENCES m4_model_call_claims(run_id, request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (reason = 'REWORK_LIMIT_EXHAUSTED'
         AND procedural_review_id IS NOT NULL
         AND backlog_item_id IS NULL
         AND acquisition_model_request_id IS NULL)
        OR
        (reason = 'HEARING_BACKLOG_EXHAUSTED'
         AND procedural_review_id IS NULL
         AND backlog_item_id IS NOT NULL
         AND acquisition_model_request_id IS NULL)
        OR
        (reason IN ('ACQUISITION_LIMIT_EXHAUSTED', 'ACQUISITION_UNRECOVERABLE')
         AND procedural_review_id IS NULL
         AND backlog_item_id IS NULL
         AND acquisition_model_request_id IS NOT NULL)
        OR
        (reason IN ('HEARING_BUDGET_EXHAUSTED', 'EVIDENCE_UNAVAILABLE')
         AND procedural_review_id IS NULL
         AND backlog_item_id IS NULL
         AND acquisition_model_request_id IS NULL)
    )
) STRICT;

CREATE TABLE m4_hearing_strict_parse_failure_attempts (
    run_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL
        CHECK (length(attempt_id) = 64 AND attempt_id NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    attempt_index INTEGER NOT NULL CHECK (attempt_index IN (0, 1)),
    backlog_item_id TEXT NOT NULL,
    -- Generation zero is the original role call.  It is used both by the
    -- no-lease INITIAL_BACKLOG closure and by a leased generation-zero retry
    -- that resumes the original request.  Later retries carry an explicit
    -- BACKLOG request context.
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response_id TEXT NOT NULL,
    response_content_sha256 TEXT NOT NULL,
    parse_receipt_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    attempt_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, attempt_id),
    UNIQUE (run_id, request_id),
    UNIQUE (run_id, response_id),
    UNIQUE (run_id, parse_receipt_id),
    FOREIGN KEY (run_id, request_id, response_id)
        REFERENCES m4_model_call_claims(run_id, request_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, response_id)
        REFERENCES m4_model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, parse_receipt_id)
        REFERENCES m4_model_parse_receipts(run_id, parse_receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, backlog_item_id)
        REFERENCES backlog_items(run_id, item_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    CHECK (
        length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(response_content_sha256) = 64
        AND response_content_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE m4_hearing_strict_parse_failure_proofs (
    run_id TEXT NOT NULL,
    proof_id TEXT NOT NULL
        CHECK (length(proof_id) = 64 AND proof_id NOT GLOB '*[^0-9a-f]*'),
    hearing_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    source_checkpoint_id TEXT NOT NULL,
    source_checkpoint_sha256 TEXT NOT NULL,
    source_checkpoint_version INTEGER NOT NULL CHECK (source_checkpoint_version > 0),
    backlog_item_id TEXT NOT NULL,
    closure_kind TEXT NOT NULL CHECK (closure_kind IN ('INITIAL_BACKLOG', 'RETRY_FAILURE')),
    lease_identity_sha256 TEXT,
    lease_id TEXT,
    lease_attempt_count INTEGER CHECK (lease_attempt_count IS NULL OR lease_attempt_count > 0),
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    primary_attempt_id TEXT NOT NULL,
    repair_attempt_id TEXT NOT NULL,
    proof_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, proof_id),
    UNIQUE (run_id, lease_identity_sha256, role),
    UNIQUE (run_id, backlog_item_id, retry_generation, role),
    UNIQUE (run_id, primary_attempt_id),
    UNIQUE (run_id, repair_attempt_id),
    FOREIGN KEY (
        run_id, source_checkpoint_id,
        source_checkpoint_sha256, source_checkpoint_version
    ) REFERENCES m4_hearing_checkpoints(
        run_id, checkpoint_id, checkpoint_sha256, version
    ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, primary_attempt_id)
        REFERENCES m4_hearing_strict_parse_failure_attempts(run_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, repair_attempt_id)
        REFERENCES m4_hearing_strict_parse_failure_attempts(run_id, attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, backlog_item_id)
        REFERENCES backlog_items(run_id, item_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    CHECK (
        primary_attempt_id <> repair_attempt_id
        AND length(source_checkpoint_sha256) = 64
        AND source_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
        AND (
            (closure_kind = 'INITIAL_BACKLOG'
             AND lease_identity_sha256 IS NULL
             AND lease_id IS NULL
             AND lease_attempt_count IS NULL)
            OR
            (closure_kind = 'RETRY_FAILURE'
             AND length(lease_identity_sha256) = 64
             AND lease_identity_sha256 NOT GLOB '*[^0-9a-f]*'
             AND length(lease_id) = 64
             AND lease_id NOT GLOB '*[^0-9a-f]*'
             AND lease_attempt_count IS NOT NULL)
        )
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

CREATE TABLE m4_hearing_backlog_retry_outcomes (
    run_id TEXT NOT NULL,
    outcome_id TEXT NOT NULL
        CHECK (length(outcome_id) = 64 AND outcome_id NOT GLOB '*[^0-9a-f]*'),
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('SUCCESS', 'FAILURE')),
    hearing_id TEXT NOT NULL,
    cycle_scope_id TEXT NOT NULL,
    cycle_scope_sha256 TEXT NOT NULL CHECK (
        length(cycle_scope_sha256) = 64
        AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE')),
    backlog_item_id TEXT NOT NULL,
    lease_identity_sha256 TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    lease_attempt_count INTEGER NOT NULL CHECK (lease_attempt_count > 0),
    retry_generation INTEGER NOT NULL CHECK (retry_generation >= 0),
    source_checkpoint_id TEXT NOT NULL,
    source_checkpoint_sha256 TEXT NOT NULL,
    source_checkpoint_version INTEGER NOT NULL CHECK (source_checkpoint_version > 0),
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    response_id TEXT,
    parse_receipt_id TEXT,
    parsed_output_id TEXT,
    next_checkpoint_id TEXT,
    next_checkpoint_sha256 TEXT,
    next_checkpoint_version INTEGER,
    reason_code TEXT CHECK (reason_code IS NULL OR reason_code IN (
        'PROVIDER_UNAVAILABLE', 'MODEL_OUTPUT_INVALID', 'BUDGET_EXCEEDED',
        'RESPONSE_INTEGRITY_FAILURE', 'CURRENT_PACK_CHANGED', 'WORKER_LEASE_EXPIRED'
    )),
    next_status TEXT CHECK (next_status IS NULL OR next_status IN ('PENDING', 'EXHAUSTED')),
    response_refs_json TEXT NOT NULL
        CHECK (json_valid(response_refs_json) AND json_type(response_refs_json) = 'array'),
    strict_parse_failure_proof_id TEXT,
    human_review_receipt_id TEXT,
    next_retry_generation INTEGER NOT NULL CHECK (next_retry_generation >= 0),
    manifest_id TEXT NOT NULL,
    outcome_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    PRIMARY KEY (run_id, outcome_id),
    UNIQUE (run_id, lease_identity_sha256),
    FOREIGN KEY (run_id, request_id)
        REFERENCES m4_model_call_claims(run_id, request_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, response_id)
        REFERENCES m4_model_responses(run_id, response_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, parse_receipt_id)
        REFERENCES m4_model_parse_receipts(run_id, parse_receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, parsed_output_id)
        REFERENCES m4_parsed_hearing_outputs(run_id, parsed_output_id) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, source_checkpoint_id,
        source_checkpoint_sha256, source_checkpoint_version
    ) REFERENCES m4_hearing_checkpoints(
        run_id, checkpoint_id, checkpoint_sha256, version
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, next_checkpoint_id,
        next_checkpoint_sha256, next_checkpoint_version
    ) REFERENCES m4_hearing_checkpoints(
        run_id, checkpoint_id, checkpoint_sha256, version
    ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, strict_parse_failure_proof_id)
        REFERENCES m4_hearing_strict_parse_failure_proofs(run_id, proof_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, human_review_receipt_id)
        REFERENCES m4_hearing_human_review_receipts(run_id, receipt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, backlog_item_id)
        REFERENCES backlog_items(run_id, item_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(
            run_id, cycle_id, cycle_sha256, hearing_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    CHECK (
        json_array_length(response_refs_json) BETWEEN 0 AND 2
        AND length(lease_identity_sha256) = 64
        AND lease_identity_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(lease_id) = 64 AND lease_id NOT GLOB '*[^0-9a-f]*'
        AND length(source_checkpoint_sha256) = 64
        AND source_checkpoint_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(request_sha256) = 64 AND request_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'
        AND length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (outcome_kind = 'SUCCESS'
         AND response_id IS NOT NULL
         AND parse_receipt_id IS NOT NULL
         AND parsed_output_id IS NOT NULL
         AND next_checkpoint_id IS NOT NULL
         AND next_checkpoint_sha256 IS NOT NULL
         AND next_checkpoint_version IS NOT NULL
         AND reason_code IS NULL
         AND next_status IS NULL
         AND json_array_length(response_refs_json) = 0
         AND strict_parse_failure_proof_id IS NULL
         AND next_retry_generation = retry_generation)
        OR
        (outcome_kind = 'FAILURE'
         AND response_id IS NULL
         AND parse_receipt_id IS NULL
         AND parsed_output_id IS NULL
         AND next_checkpoint_id IS NULL
         AND next_checkpoint_sha256 IS NULL
         AND next_checkpoint_version IS NULL
         AND reason_code IS NOT NULL
         AND next_status IS NOT NULL
         AND (
             (reason_code = 'MODEL_OUTPUT_INVALID'
              AND json_array_length(response_refs_json) = 2
              AND strict_parse_failure_proof_id IS NOT NULL)
             OR
             (reason_code <> 'MODEL_OUTPUT_INVALID'
              AND json_array_length(response_refs_json) = 0
              AND strict_parse_failure_proof_id IS NULL)
         )
         AND (
             (next_status = 'PENDING' AND human_review_receipt_id IS NULL)
             OR
             (next_status = 'EXHAUSTED' AND human_review_receipt_id IS NOT NULL)
         ))
    )
) STRICT;

CREATE UNIQUE INDEX uq_m4_hearings_screening_start
    ON m4_hearings(run_id, case_id, screening_id)
    WHERE trigger_review_id IS NULL;
CREATE UNIQUE INDEX uq_m4_hearings_review_start
    ON m4_hearings(run_id, case_id, trigger_review_id)
    WHERE trigger_review_id IS NOT NULL;
CREATE INDEX idx_m4_hearing_cycles_sequence
    ON m4_hearing_cycles(run_id, hearing_id, cycle_index, cycle_id);
CREATE INDEX idx_m4_retrieval_round
    ON m4_precedent_retrieval_receipts(run_id, hearing_id, cycle_scope_id);
CREATE INDEX idx_m4_model_responses_round_role
    ON m4_model_responses(run_id, hearing_id, cycle_scope_id, role, response_id);
CREATE INDEX idx_m4_model_claims_active_expiry
    ON m4_model_call_claims(run_id, status, lease_expires_at, request_id);
CREATE INDEX idx_m4_claims_hearing_reservation
    ON m4_model_call_claims(run_id, hearing_id, reserved_images, request_id);
CREATE UNIQUE INDEX uq_m4_model_claims_initial_generation
    ON m4_model_call_claims(run_id, cycle_scope_id, role, attempt_index)
    WHERE call_generation = 'INITIAL';
CREATE UNIQUE INDEX uq_m4_model_claims_backlog_generation
    ON m4_model_call_claims(run_id, backlog_item_id, retry_generation, attempt_index)
    WHERE call_generation = 'BACKLOG';
CREATE INDEX idx_m4_parsed_outputs_round_role
    ON m4_parsed_hearing_outputs(run_id, hearing_id, cycle_scope_id, role);
CREATE INDEX idx_m4_parse_receipts_response
    ON m4_model_parse_receipts(run_id, response_id, parse_receipt_id);
CREATE INDEX idx_m4_cache_round_role
    ON m4_model_cache(run_id, hearing_id, cycle_scope_id, role, cache_key);
CREATE INDEX idx_m4_usage_hearing
    ON m4_hearing_usage_receipts(run_id, hearing_id, cycle_scope_id, role, request_id);
CREATE INDEX idx_m4_acquisition_round
    ON m4_acquisition_requests(run_id, hearing_id, cycle_scope_id);
CREATE INDEX idx_m4_acquisition_claims_active_expiry
    ON m4_acquisition_execution_claims(
        run_id, status, lease_expires_at, acquisition_request_id
    );
CREATE INDEX idx_m4_acquisition_publications_hearing
    ON m4_acquisition_execution_publications(
        run_id, hearing_id, acquisition_request_id, execution_publication_id
    );
CREATE INDEX idx_m4_hearing_rounds_hearing
    ON m4_hearing_rounds(run_id, hearing_id, round_index, round_id);
CREATE INDEX idx_m4_tool_receipts_round
    ON m4_tool_execution_receipts(run_id, hearing_id, cycle_scope_id, receipt_id);
CREATE INDEX idx_m4_acquired_crops_request
    ON m4_acquired_crops(run_id, hearing_id, acquisition_request_id, crop_id);
CREATE INDEX idx_m4_pack_derivations_case_version
    ON m4_evidence_pack_derivations(run_id, case_id, new_pack_version, derivation_id);
CREATE INDEX idx_m4_verdict_bindings_case_version
    ON m4_hearing_verdict_bindings(run_id, case_id, verdict_version, binding_id);
CREATE INDEX idx_m4_rework_hearing
    ON m4_rework_receipts(run_id, hearing_id, rework_index, rework_receipt_id);
CREATE INDEX idx_m4_backlog_receipts_item_attempt
    ON m4_backlog_completion_receipts(
        run_id, item_id, attempt_count, retry_generation, receipt_id
    );
CREATE INDEX idx_m4_failure_authorities_backlog
    ON m4_model_call_failure_authorities(
        run_id, backlog_item_id, retry_generation, backlog_version, authority_id
    );
CREATE INDEX idx_m4_checkpoints_hearing_version
    ON m4_hearing_checkpoints(run_id, hearing_id, version, phase);
CREATE INDEX idx_m4_human_review_receipts_session
    ON m4_hearing_human_review_receipts(run_id, hearing_id, judge_cycle, receipt_id);
CREATE INDEX idx_m4_strict_attempts_backlog_generation
    ON m4_hearing_strict_parse_failure_attempts(
        run_id, backlog_item_id, retry_generation, attempt_index
    );
CREATE INDEX idx_m4_strict_proofs_lease
    ON m4_hearing_strict_parse_failure_proofs(
        run_id, backlog_item_id, retry_generation, proof_id
    );
CREATE INDEX idx_m4_backlog_outcomes_source
    ON m4_hearing_backlog_retry_outcomes(
        run_id, backlog_item_id, source_checkpoint_version, outcome_id
    );

CREATE TRIGGER m4_hearings_validate_scope
BEFORE INSERT ON m4_hearings
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM screening_results AS sr
        WHERE sr.run_id = NEW.run_id
          AND sr.screening_id = NEW.screening_id
          AND sr.case_id = NEW.case_id
          AND sr.evidence_pack_id = NEW.initial_pack_id
          AND sr.evidence_pack_version = NEW.initial_pack_version
          AND sr.manifest_id = NEW.manifest_id
    )
    AND (
        (NEW.entry_status = 'ESCALATED'
         AND NEW.trigger_review_id IS NULL
         AND json_array_length(NEW.initial_defect_codes_json) = 0)
        OR
        (NEW.entry_status = 'REWORK_REQUIRED'
         AND NEW.trigger_review_id IS NOT NULL
         AND json_array_length(NEW.initial_defect_codes_json) > 0
         AND EXISTS (
             SELECT 1
             FROM procedural_reviews AS pr
             JOIN verdicts AS v
               ON v.run_id = pr.run_id
              AND v.case_id = pr.case_id
              AND v.verdict_id = pr.reviewed_verdict_id
              AND v.version = pr.reviewed_verdict_version
             WHERE pr.run_id = NEW.run_id
               AND pr.review_id = NEW.trigger_review_id
               AND pr.case_id = NEW.case_id
               AND pr.passed = 0
               AND pr.evidence_pack_id = NEW.initial_pack_id
               AND pr.evidence_pack_version = NEW.initial_pack_version
               AND v.screening_id = NEW.screening_id
         ))
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.initial_defect_codes_json) AS defect
        WHERE defect.type <> 'text'
           OR defect.value NOT IN (
               'MALFORMED_STRUCTURE', 'INVALID_ENUM', 'MISSING_REQUIRED_FIELD',
               'FABRICATED_EVIDENCE_REFERENCE', 'INVALID_COORDINATES',
               'FABRICATED_PRECEDENT_REFERENCE', 'PRECEDENT_DIRECTION_MISMATCH',
               'EMPTY_DISTINGUISHING_REASON', 'ESTABLISHED_WITHOUT_EVIDENCE',
               'UNANSWERED_DEFENSE_POINT', 'CONFIDENCE_ALERT_LEVEL_MISMATCH',
               'OBJECTIVE_ASSERTION_CONTRADICTION', 'VIOLATION_TYPE_MISMATCH',
               'ABSENCE_FROM_INSUFFICIENT_OBSERVATION'
           )
           OR EXISTS (
               SELECT 1
               FROM json_each(NEW.initial_defect_codes_json) AS earlier
               WHERE CAST(earlier.key AS INTEGER) < CAST(defect.key AS INTEGER)
                 AND instr(
                     '|MALFORMED_STRUCTURE|INVALID_ENUM|MISSING_REQUIRED_FIELD|FABRICATED_EVIDENCE_REFERENCE|INVALID_COORDINATES|FABRICATED_PRECEDENT_REFERENCE|PRECEDENT_DIRECTION_MISMATCH|EMPTY_DISTINGUISHING_REASON|ESTABLISHED_WITHOUT_EVIDENCE|UNANSWERED_DEFENSE_POINT|CONFIDENCE_ALERT_LEVEL_MISMATCH|OBJECTIVE_ASSERTION_CONTRADICTION|VIOLATION_TYPE_MISMATCH|ABSENCE_FROM_INSUFFICIENT_OBSERVATION|',
                     '|' || earlier.value || '|'
                 ) >= instr(
                     '|MALFORMED_STRUCTURE|INVALID_ENUM|MISSING_REQUIRED_FIELD|FABRICATED_EVIDENCE_REFERENCE|INVALID_COORDINATES|FABRICATED_PRECEDENT_REFERENCE|PRECEDENT_DIRECTION_MISMATCH|EMPTY_DISTINGUISHING_REASON|ESTABLISHED_WITHOUT_EVIDENCE|UNANSWERED_DEFENSE_POINT|CONFIDENCE_ALERT_LEVEL_MISMATCH|OBJECTIVE_ASSERTION_CONTRADICTION|VIOLATION_TYPE_MISMATCH|ABSENCE_FROM_INSUFFICIENT_OBSERVATION|',
                     '|' || defect.value || '|'
                 )
           )
    )
    AND (
        NEW.trigger_review_id IS NULL
        OR (
            json_array_length(NEW.initial_defect_codes_json) = (
                SELECT COUNT(DISTINCT defect.code)
                FROM procedural_defects AS defect
                WHERE defect.run_id = NEW.run_id
                  AND defect.owner_kind = 'PROCEDURAL_REVIEW'
                  AND defect.owner_id = NEW.trigger_review_id
            )
            AND NOT EXISTS (
                SELECT 1
                FROM procedural_defects AS defect
                WHERE defect.run_id = NEW.run_id
                  AND defect.owner_kind = 'PROCEDURAL_REVIEW'
                  AND defect.owner_id = NEW.trigger_review_id
                  AND NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.initial_defect_codes_json) AS supplied
                      WHERE supplied.value = defect.code
                  )
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing scope authority is invalid');
END;

CREATE TRIGGER m4_hearing_cycles_validate_transition
BEFORE INSERT ON m4_hearing_cycles
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_hearings AS hearing
        WHERE hearing.run_id = NEW.run_id
          AND hearing.hearing_id = NEW.hearing_id
          AND hearing.case_id = NEW.case_id
          AND hearing.manifest_id = NEW.manifest_id
          AND NEW.prior_acquisition_rounds <= hearing.max_acquisition_rounds
          AND NEW.prior_rework_rounds <= hearing.max_rework_rounds
          AND (
              (NEW.cycle_index = 1
               AND NEW.cycle_pack_id = hearing.initial_pack_id
               AND NEW.cycle_pack_version = hearing.initial_pack_version
               AND NEW.prior_acquisition_rounds = 0
               AND NEW.prior_rework_rounds = 0
               AND NEW.initial_trigger_review_id IS hearing.trigger_review_id
               AND json(NEW.initial_defect_codes_json)
                   = json(hearing.initial_defect_codes_json)
               AND NEW.rework_review_id IS NULL
               AND json_array_length(NEW.rework_defect_codes_json) = 0)
              OR
              (NEW.cycle_index > 1
               AND NEW.initial_trigger_review_id IS NULL
               AND json_array_length(NEW.initial_defect_codes_json) = 0
               AND EXISTS (
                   SELECT 1
                   FROM m4_hearing_cycles AS previous
                   WHERE previous.run_id = NEW.run_id
                     AND previous.hearing_id = NEW.hearing_id
                     AND previous.cycle_index = NEW.cycle_index - 1
                     AND (
                         (NEW.prior_acquisition_rounds
                              = previous.prior_acquisition_rounds + 1
                          AND NEW.prior_rework_rounds
                              = previous.prior_rework_rounds
                          AND NEW.rework_review_id IS NULL
                          AND json_array_length(NEW.rework_defect_codes_json) = 0
                          AND EXISTS (
                              SELECT 1
                              FROM m4_evidence_pack_derivations AS derivation
                              WHERE derivation.run_id = NEW.run_id
                                AND derivation.hearing_id = NEW.hearing_id
                                AND derivation.source_cycle_scope_id
                                    = previous.cycle_id
                                AND derivation.source_cycle_scope_sha256
                                    = previous.cycle_sha256
                                AND derivation.previous_pack_id
                                    = previous.cycle_pack_id
                                AND derivation.previous_pack_version
                                    = previous.cycle_pack_version
                                AND derivation.new_pack_id = NEW.cycle_pack_id
                                AND derivation.new_pack_version
                                    = NEW.cycle_pack_version
                          ))
                         OR
                         (NEW.prior_acquisition_rounds
                              = previous.prior_acquisition_rounds
                          AND NEW.prior_rework_rounds
                              = previous.prior_rework_rounds + 1
                          AND NEW.cycle_pack_id = previous.cycle_pack_id
                          AND NEW.cycle_pack_version = previous.cycle_pack_version
                          AND EXISTS (
                              SELECT 1
                              FROM procedural_reviews AS review
                              JOIN m4_hearing_verdict_bindings AS binding
                                ON binding.run_id = review.run_id
                               AND binding.case_id = review.case_id
                               AND binding.verdict_id = review.reviewed_verdict_id
                               AND binding.verdict_version
                                   = review.reviewed_verdict_version
                              JOIN m4_hearing_rounds AS completed_round
                                ON completed_round.run_id = binding.run_id
                               AND completed_round.round_id = binding.round_id
                              WHERE review.run_id = NEW.run_id
                                AND review.review_id = NEW.rework_review_id
                                AND review.passed = 0
                                AND completed_round.cycle_scope_id
                                    = previous.cycle_id
                          ))
                     )
               ))
          )
    )
    AND json_extract(NEW.cycle_json, '$.cycle_id') = NEW.cycle_id
    AND json_extract(NEW.cycle_json, '$.cycle_sha256') = NEW.cycle_sha256
    AND json_extract(NEW.cycle_json, '$.run_id') = NEW.run_id
    AND json_extract(NEW.cycle_json, '$.case_id') = NEW.case_id
    AND json_extract(NEW.cycle_json, '$.hearing_session_id') = NEW.hearing_id
    AND json_extract(NEW.cycle_json, '$.cycle_index') = NEW.cycle_index
    AND json_extract(NEW.cycle_json, '$.prior_acquisition_rounds')
        = NEW.prior_acquisition_rounds
    AND json_extract(NEW.cycle_json, '$.prior_rework_rounds')
        = NEW.prior_rework_rounds
    AND json_extract(NEW.cycle_json, '$.cycle_evidence_pack_id') = NEW.cycle_pack_id
    AND json_extract(NEW.cycle_json, '$.cycle_evidence_pack_version')
        = NEW.cycle_pack_version
    AND json_extract(NEW.cycle_json, '$.manifest_id') = NEW.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing cycle authority is invalid');
END;

CREATE TRIGGER m4_precedent_retrieval_receipts_validate_scope
BEFORE INSERT ON m4_precedent_retrieval_receipts
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_hearing_cycles AS cycle
        JOIN m4_hearings AS hearing
          ON hearing.run_id = cycle.run_id
         AND hearing.hearing_id = cycle.hearing_id
        WHERE cycle.run_id = NEW.run_id
          AND cycle.cycle_id = NEW.cycle_scope_id
          AND cycle.cycle_sha256 = NEW.cycle_scope_sha256
          AND cycle.hearing_id = NEW.hearing_id
          AND cycle.case_id = NEW.case_id
          AND cycle.cycle_index
              = 1 + NEW.prior_acquisition_rounds + NEW.prior_rework_rounds
          AND cycle.prior_acquisition_rounds = NEW.prior_acquisition_rounds
          AND cycle.prior_rework_rounds = NEW.prior_rework_rounds
          AND cycle.cycle_pack_id = NEW.current_pack_id
          AND cycle.cycle_pack_version = NEW.current_pack_version
          AND hearing.case_id = NEW.case_id
          AND hearing.manifest_id = NEW.manifest_id
          AND (
              (cycle.cycle_index = 1
               AND NEW.initial_trigger_review_id IS cycle.initial_trigger_review_id
               AND json(NEW.initial_defect_codes_json)
                   = json(cycle.initial_defect_codes_json))
              OR
              (cycle.cycle_index > 1
               AND NEW.initial_trigger_review_id IS NULL
               AND json_array_length(NEW.initial_defect_codes_json) = 0)
          )
          AND (
              (cycle.prior_rework_rounds = 0
               AND NEW.rework_review_id IS NULL
               AND json_array_length(NEW.rework_defect_codes_json) = 0)
              OR
              (cycle.prior_rework_rounds > 0
               AND NEW.rework_review_id = cycle.rework_review_id
               AND json(NEW.rework_defect_codes_json)
                   = json(cycle.rework_defect_codes_json))
          )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.rework_defect_codes_json) AS defect
        WHERE defect.type <> 'text'
           OR defect.value NOT IN (
               'MALFORMED_STRUCTURE', 'INVALID_ENUM', 'MISSING_REQUIRED_FIELD',
               'FABRICATED_EVIDENCE_REFERENCE', 'INVALID_COORDINATES',
               'FABRICATED_PRECEDENT_REFERENCE', 'PRECEDENT_DIRECTION_MISMATCH',
               'EMPTY_DISTINGUISHING_REASON', 'ESTABLISHED_WITHOUT_EVIDENCE',
               'UNANSWERED_DEFENSE_POINT', 'CONFIDENCE_ALERT_LEVEL_MISMATCH',
               'OBJECTIVE_ASSERTION_CONTRADICTION', 'VIOLATION_TYPE_MISMATCH',
               'ABSENCE_FROM_INSUFFICIENT_OBSERVATION'
           )
           OR EXISTS (
               SELECT 1
               FROM json_each(NEW.rework_defect_codes_json) AS earlier
               WHERE CAST(earlier.key AS INTEGER) < CAST(defect.key AS INTEGER)
                 AND instr(
                     '|MALFORMED_STRUCTURE|INVALID_ENUM|MISSING_REQUIRED_FIELD|FABRICATED_EVIDENCE_REFERENCE|INVALID_COORDINATES|FABRICATED_PRECEDENT_REFERENCE|PRECEDENT_DIRECTION_MISMATCH|EMPTY_DISTINGUISHING_REASON|ESTABLISHED_WITHOUT_EVIDENCE|UNANSWERED_DEFENSE_POINT|CONFIDENCE_ALERT_LEVEL_MISMATCH|OBJECTIVE_ASSERTION_CONTRADICTION|VIOLATION_TYPE_MISMATCH|ABSENCE_FROM_INSUFFICIENT_OBSERVATION|',
                     '|' || earlier.value || '|'
                 ) >= instr(
                     '|MALFORMED_STRUCTURE|INVALID_ENUM|MISSING_REQUIRED_FIELD|FABRICATED_EVIDENCE_REFERENCE|INVALID_COORDINATES|FABRICATED_PRECEDENT_REFERENCE|PRECEDENT_DIRECTION_MISMATCH|EMPTY_DISTINGUISHING_REASON|ESTABLISHED_WITHOUT_EVIDENCE|UNANSWERED_DEFENSE_POINT|CONFIDENCE_ALERT_LEVEL_MISMATCH|OBJECTIVE_ASSERTION_CONTRADICTION|VIOLATION_TYPE_MISMATCH|ABSENCE_FROM_INSUFFICIENT_OBSERVATION|',
                     '|' || defect.value || '|'
                 )
           )
    )
    AND (
        NEW.rework_review_id IS NULL
        OR (
            json_array_length(NEW.rework_defect_codes_json) = (
                SELECT COUNT(DISTINCT defect.code)
                FROM procedural_defects AS defect
                WHERE defect.run_id = NEW.run_id
                  AND defect.owner_kind = 'PROCEDURAL_REVIEW'
                  AND defect.owner_id = NEW.rework_review_id
            )
            AND NOT EXISTS (
                SELECT 1
                FROM procedural_defects AS defect
                WHERE defect.run_id = NEW.run_id
                  AND defect.owner_kind = 'PROCEDURAL_REVIEW'
                  AND defect.owner_id = NEW.rework_review_id
                  AND NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.rework_defect_codes_json) AS supplied
                      WHERE supplied.value = defect.code
                  )
            )
        )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.candidate_precedent_refs_json) AS candidate
        WHERE json_extract(candidate.value, '$.kind') <> 'PRECEDENT'
           OR length(json_extract(candidate.value, '$.artifact_id')) <> 64
           OR json_extract(candidate.value, '$.artifact_id') GLOB '*[^0-9a-f]*'
           OR EXISTS (
               SELECT 1
               FROM json_each(NEW.candidate_precedent_refs_json) AS earlier
               WHERE CAST(earlier.key AS INTEGER) < CAST(candidate.key AS INTEGER)
                 AND json_extract(earlier.value, '$.artifact_id')
                     >= json_extract(candidate.value, '$.artifact_id')
           )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.visible_precedent_refs_json) AS visible
        WHERE json_extract(visible.value, '$.kind') <> 'PRECEDENT'
           OR NOT EXISTS (
               SELECT 1
               FROM json_each(NEW.candidate_precedent_refs_json) AS candidate
               WHERE json_extract(candidate.value, '$.artifact_id')
                   = json_extract(visible.value, '$.artifact_id')
           )
           OR EXISTS (
               SELECT 1
               FROM json_each(NEW.visible_precedent_refs_json) AS earlier
               WHERE CAST(earlier.key AS INTEGER) < CAST(visible.key AS INTEGER)
                 AND json_extract(earlier.value, '$.artifact_id')
                     >= json_extract(visible.value, '$.artifact_id')
           )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 precedent retrieval scope authority is invalid');
END;

-- Reserve the configured image budget before provider delivery.  One claim
-- owns one durable reservation; lease takeover mutates that row and cannot
-- reserve the same request twice.
CREATE TRIGGER m4_model_call_claims_validate_reservation
BEFORE INSERT ON m4_model_call_claims
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_hearings AS hearing
        JOIN m4_hearing_cycles AS cycle
          ON cycle.run_id = hearing.run_id
         AND cycle.hearing_id = hearing.hearing_id
        WHERE hearing.run_id = NEW.run_id
          AND hearing.hearing_id = NEW.hearing_id
          AND hearing.case_id = NEW.case_id
          AND hearing.manifest_id = NEW.manifest_id
          AND cycle.cycle_id = NEW.cycle_scope_id
          AND cycle.cycle_sha256 = NEW.cycle_scope_sha256
          AND cycle.case_id = NEW.case_id
          AND cycle.cycle_pack_id = NEW.evidence_pack_id
          AND cycle.cycle_pack_version = NEW.evidence_pack_version
          AND NEW.model_manifest_id = CASE NEW.role
              WHEN 'PROSECUTOR' THEN hearing.prosecutor_model_manifest_id
              WHEN 'DEFENDER' THEN hearing.defender_model_manifest_id
              ELSE hearing.judge_model_manifest_id
          END
          AND COALESCE((
              SELECT SUM(reservation.reserved_images)
              FROM (
                  SELECT claim.request_id, MAX(claim.reserved_images) AS reserved_images
                  FROM m4_model_call_claims AS claim
                  WHERE claim.run_id = NEW.run_id
                    AND claim.hearing_id = NEW.hearing_id
                  GROUP BY claim.request_id
              ) AS reservation
          ), 0) + NEW.reserved_images <= hearing.max_total_images
    )
    AND (
        NEW.call_generation = 'INITIAL'
        OR EXISTS (
            SELECT 1 FROM backlog_items AS item
            WHERE item.run_id = NEW.run_id
              AND item.item_id = NEW.backlog_item_id
              AND item.case_id = NEW.case_id
              AND item.stage = 'HEARING'
              AND item.role = NEW.role
              AND item.manifest_id = NEW.manifest_id
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 model call image reservation is invalid');
END;

CREATE TRIGGER m4_model_call_claims_controlled_update
BEFORE UPDATE ON m4_model_call_claims
WHEN NOT (
    OLD.run_id = NEW.run_id
    AND OLD.request_id = NEW.request_id
    AND OLD.request_sha256 = NEW.request_sha256
    AND OLD.cache_key = NEW.cache_key
    AND OLD.hearing_id = NEW.hearing_id
    AND OLD.cycle_scope_id = NEW.cycle_scope_id
    AND OLD.cycle_scope_sha256 = NEW.cycle_scope_sha256
    AND OLD.case_id = NEW.case_id
    AND OLD.role = NEW.role
    AND OLD.purpose = NEW.purpose
    AND OLD.attempt_index = NEW.attempt_index
    AND OLD.call_generation = NEW.call_generation
    AND OLD.backlog_item_id IS NEW.backlog_item_id
    AND OLD.retry_generation = NEW.retry_generation
    AND OLD.reserved_images = NEW.reserved_images
    AND OLD.reserved_pixels = NEW.reserved_pixels
    AND OLD.evidence_pack_id = NEW.evidence_pack_id
    AND OLD.evidence_pack_version = NEW.evidence_pack_version
    AND OLD.model_manifest_id = NEW.model_manifest_id
    AND OLD.prompt_manifest_id = NEW.prompt_manifest_id
    AND OLD.manifest_id = NEW.manifest_id
    AND OLD.request_json = NEW.request_json
    AND OLD.request_document_sha256 = NEW.request_document_sha256
    AND OLD.created_at = NEW.created_at
    AND OLD.status = 'ACTIVE'
    AND OLD.response_id IS NULL
    AND OLD.completed_at IS NULL
    AND (
        (
            NEW.status = 'ACTIVE'
            AND NEW.response_id IS NULL
            AND NEW.completed_at IS NULL
            AND NEW.owner_token_sha256 <> OLD.owner_token_sha256
            AND NEW.lease_expires_at > OLD.lease_expires_at
            AND NEW.takeover_count = OLD.takeover_count + 1
        )
        OR
        (
            NEW.status = 'COMPLETED'
            AND NEW.response_id IS NOT NULL
            AND NEW.completed_at IS NOT NULL
            AND OLD.owner_token_sha256 = NEW.owner_token_sha256
            AND OLD.lease_expires_at = NEW.lease_expires_at
            AND OLD.takeover_count = NEW.takeover_count
            AND EXISTS (
                SELECT 1
                FROM m4_model_responses AS response
                WHERE response.run_id = NEW.run_id
                  AND response.response_id = NEW.response_id
                  AND response.request_id = NEW.request_id
                  AND response.request_sha256 = NEW.request_sha256
                  AND response.cache_key = NEW.cache_key
                  AND response.hearing_id = NEW.hearing_id
                  AND response.cycle_scope_id = NEW.cycle_scope_id
                  AND response.cycle_scope_sha256 = NEW.cycle_scope_sha256
                  AND response.case_id = NEW.case_id
                  AND response.role = NEW.role
                  AND response.purpose = NEW.purpose
                  AND response.attempt_index = NEW.attempt_index
                  AND response.retry_generation = NEW.retry_generation
                  AND response.model_manifest_id = NEW.model_manifest_id
                  AND response.manifest_id = NEW.manifest_id
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 model call claim update is invalid');
END;

CREATE TRIGGER m4_model_responses_validate_claim
BEFORE INSERT ON m4_model_responses
WHEN NOT EXISTS (
    SELECT 1
    FROM m4_model_call_claims AS claim
    WHERE claim.run_id = NEW.run_id
      AND claim.request_id = NEW.request_id
      AND claim.request_sha256 = NEW.request_sha256
      AND claim.cache_key = NEW.cache_key
      AND claim.hearing_id = NEW.hearing_id
      AND claim.cycle_scope_id = NEW.cycle_scope_id
      AND claim.cycle_scope_sha256 = NEW.cycle_scope_sha256
      AND claim.case_id = NEW.case_id
      AND claim.role = NEW.role
      AND claim.purpose = NEW.purpose
      AND claim.attempt_index = NEW.attempt_index
      AND claim.retry_generation = NEW.retry_generation
      AND claim.model_manifest_id = NEW.model_manifest_id
      AND claim.manifest_id = NEW.manifest_id
      AND claim.status = 'ACTIVE'
      AND claim.response_id IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'M4 model response lacks its exact active claim');
END;

-- A provider call has exactly one request/response usage receipt.  Cache hits
-- and crash recovery reuse that pair and therefore cannot mint fresh usage.
CREATE TRIGGER m4_hearing_usage_receipts_validate_scope
BEFORE INSERT ON m4_hearing_usage_receipts
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_model_responses AS response
        JOIN m4_model_call_claims AS claim
          ON claim.run_id = response.run_id
         AND claim.request_id = response.request_id
         AND claim.response_id = response.response_id
        WHERE response.run_id = NEW.run_id
          AND response.request_id = NEW.request_id
          AND response.response_id = NEW.response_id
          AND response.hearing_id = NEW.hearing_id
          AND response.cycle_scope_id = NEW.cycle_scope_id
          AND response.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND response.case_id = NEW.case_id
          AND response.role = NEW.role
          AND response.manifest_id = NEW.manifest_id
          AND claim.status = 'COMPLETED'
          AND claim.reserved_images = NEW.input_images
          AND claim.reserved_pixels = NEW.input_pixels
    )
    AND EXISTS (
        SELECT 1
        FROM m4_hearings AS hearing
        WHERE hearing.run_id = NEW.run_id
          AND hearing.hearing_id = NEW.hearing_id
          AND hearing.case_id = NEW.case_id
          AND hearing.manifest_id = NEW.manifest_id
          AND (
              COALESCE((
                  SELECT SUM(usage.output_tokens)
                  FROM m4_hearing_usage_receipts AS usage
                  WHERE usage.run_id = NEW.run_id
                    AND usage.hearing_id = NEW.hearing_id
              ), 0)
              + COALESCE((
                  SELECT SUM(failure.output_tokens)
                  FROM m4_model_call_failure_authorities AS failure
                  WHERE failure.run_id = NEW.run_id
                    AND failure.hearing_id = NEW.hearing_id
                    AND failure.delivery_certainty = 'COMPLETED'
              ), 0)
              + NEW.output_tokens
          ) <= hearing.max_total_output_tokens
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing usage scope authority is invalid');
END;

CREATE TRIGGER m4_parsed_hearing_outputs_validate_scope
BEFORE INSERT ON m4_parsed_hearing_outputs
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_model_responses AS response
        JOIN m4_model_call_claims AS claim
          ON claim.run_id = response.run_id
         AND claim.request_id = response.request_id
         AND claim.response_id = response.response_id
         AND claim.status = 'COMPLETED'
        JOIN m4_hearing_cycles AS cycle
          ON cycle.run_id = response.run_id
         AND cycle.cycle_id = response.cycle_scope_id
         AND cycle.cycle_sha256 = response.cycle_scope_sha256
        JOIN m4_precedent_retrieval_receipts AS retrieval
          ON retrieval.run_id = response.run_id
         AND retrieval.retrieval_receipt_id = NEW.precedent_retrieval_receipt_id
        WHERE response.run_id = NEW.run_id
          AND response.response_id = NEW.response_id
          AND response.request_id = NEW.request_id
          AND response.hearing_id = NEW.hearing_id
          AND response.cycle_scope_id = NEW.cycle_scope_id
          AND response.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND response.case_id = NEW.case_id
          AND response.role = NEW.role
          AND response.content_sha256 = NEW.response_content_sha256
          AND response.model_manifest_id = NEW.model_manifest_id
          AND response.manifest_id = NEW.manifest_id
          AND claim.prompt_manifest_id = NEW.prompt_manifest_id
          AND claim.model_manifest_id = NEW.model_manifest_id
          AND claim.evidence_pack_id = NEW.current_pack_id
          AND claim.evidence_pack_version = NEW.current_pack_version
          AND cycle.prior_acquisition_rounds = NEW.prior_acquisition_rounds
          AND cycle.prior_rework_rounds = NEW.prior_rework_rounds
          AND cycle.cycle_index
              = 1 + NEW.prior_acquisition_rounds + NEW.prior_rework_rounds
          AND cycle.cycle_pack_id = NEW.current_pack_id
          AND cycle.cycle_pack_version = NEW.current_pack_version
          AND retrieval.hearing_id = NEW.hearing_id
          AND retrieval.cycle_scope_id = NEW.cycle_scope_id
          AND retrieval.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND retrieval.case_id = NEW.case_id
          AND retrieval.document_sha256 = NEW.precedent_retrieval_receipt_sha256
          AND retrieval.precedent_retrieval_degraded
              = NEW.precedent_retrieval_degraded
          AND retrieval.initial_trigger_review_id IS NEW.initial_trigger_review_id
          AND json(retrieval.initial_defect_codes_json)
              = json(NEW.initial_defect_codes_json)
          AND retrieval.rework_review_id IS NEW.rework_review_id
          AND json(retrieval.rework_defect_codes_json)
              = json(NEW.rework_defect_codes_json)
          AND retrieval.manifest_id = NEW.manifest_id
    )
    AND (
        NEW.role = 'PROSECUTOR'
        OR (
            EXISTS (
                SELECT 1
                FROM m4_parsed_hearing_outputs AS prosecutor
                WHERE prosecutor.run_id = NEW.run_id
                  AND prosecutor.parsed_output_id = NEW.prosecutor_output_id
                  AND prosecutor.hearing_id = NEW.hearing_id
                  AND prosecutor.cycle_scope_id = NEW.cycle_scope_id
                  AND prosecutor.cycle_scope_sha256 = NEW.cycle_scope_sha256
                  AND prosecutor.case_id = NEW.case_id
                  AND prosecutor.role = 'PROSECUTOR'
                  AND prosecutor.current_pack_id = NEW.current_pack_id
                  AND prosecutor.current_pack_version = NEW.current_pack_version
                  AND prosecutor.precedent_retrieval_receipt_id
                      = NEW.precedent_retrieval_receipt_id
                  AND prosecutor.manifest_id = NEW.manifest_id
            )
            AND (
                NEW.role = 'DEFENDER'
                OR EXISTS (
                    SELECT 1
                    FROM m4_parsed_hearing_outputs AS defender
                    WHERE defender.run_id = NEW.run_id
                      AND defender.parsed_output_id = NEW.defender_output_id
                      AND defender.hearing_id = NEW.hearing_id
                      AND defender.cycle_scope_id = NEW.cycle_scope_id
                      AND defender.cycle_scope_sha256 = NEW.cycle_scope_sha256
                      AND defender.case_id = NEW.case_id
                      AND defender.role = 'DEFENDER'
                      AND defender.prosecutor_output_id = NEW.prosecutor_output_id
                      AND defender.current_pack_id = NEW.current_pack_id
                      AND defender.current_pack_version = NEW.current_pack_version
                      AND defender.precedent_retrieval_receipt_id
                          = NEW.precedent_retrieval_receipt_id
                      AND defender.manifest_id = NEW.manifest_id
                )
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 parsed output scope authority is invalid');
END;

CREATE TRIGGER m4_model_parse_receipts_validate_scope
BEFORE INSERT ON m4_model_parse_receipts
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_model_responses AS response
        JOIN m4_model_call_claims AS claim
          ON claim.run_id = response.run_id
         AND claim.request_id = response.request_id
         AND claim.response_id = response.response_id
        WHERE response.run_id = NEW.run_id
          AND response.request_id = NEW.request_id
          AND response.request_sha256 = NEW.request_sha256
          AND response.response_id = NEW.response_id
          AND response.content_sha256 = NEW.response_content_sha256
          AND response.hearing_id = NEW.hearing_id
          AND response.cycle_scope_id = NEW.cycle_scope_id
          AND response.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND response.case_id = NEW.case_id
          AND response.role = NEW.role
          AND response.attempt_index = NEW.attempt_index
          AND response.manifest_id = NEW.manifest_id
          AND claim.status = 'COMPLETED'
    )
    AND (
        (
            NEW.status = 'PARSED'
            AND json_array_length(NEW.defects_json) = 0
            AND EXISTS (
                SELECT 1
                FROM m4_parsed_hearing_outputs AS output
                WHERE output.run_id = NEW.run_id
                  AND output.parsed_output_id = NEW.parsed_output_id
                  AND output.parse_receipt_id = NEW.parse_receipt_id
                  AND output.request_id = NEW.request_id
                  AND output.response_id = NEW.response_id
                  AND output.output_schema_sha256 = NEW.output_schema_sha256
                  AND output.hearing_id = NEW.hearing_id
                  AND output.cycle_scope_id = NEW.cycle_scope_id
                  AND output.cycle_scope_sha256 = NEW.cycle_scope_sha256
                  AND output.case_id = NEW.case_id
                  AND output.role = NEW.role
                  AND output.manifest_id = NEW.manifest_id
            )
        )
        OR
        (
            NEW.status = 'REPAIR_REQUIRED'
            AND json_array_length(NEW.defects_json) > 0
            AND EXISTS (
                SELECT 1
                FROM m4_model_call_claims AS primary_claim
                JOIN m4_model_call_claims AS repair_claim
                  ON repair_claim.run_id = primary_claim.run_id
                 AND repair_claim.request_id = NEW.repair_request_id
                WHERE primary_claim.run_id = NEW.run_id
                  AND primary_claim.request_id = NEW.request_id
                  AND repair_claim.hearing_id = primary_claim.hearing_id
                  AND repair_claim.cycle_scope_id = primary_claim.cycle_scope_id
                  AND repair_claim.case_id = primary_claim.case_id
                  AND repair_claim.role = primary_claim.role
                  AND repair_claim.purpose = 'STRUCTURE_REPAIR'
                  AND repair_claim.attempt_index = 1
                  AND repair_claim.call_generation = primary_claim.call_generation
                  AND repair_claim.backlog_item_id IS primary_claim.backlog_item_id
                  AND repair_claim.retry_generation = primary_claim.retry_generation
                  AND repair_claim.evidence_pack_id = primary_claim.evidence_pack_id
                  AND repair_claim.evidence_pack_version
                      = primary_claim.evidence_pack_version
                  AND repair_claim.manifest_id = primary_claim.manifest_id
            )
        )
        OR
        (
            NEW.status = 'INVALID_FINAL'
            AND json_array_length(NEW.defects_json) > 0
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 model parse receipt scope authority is invalid');
END;

CREATE TRIGGER m4_acquisition_requests_validate_authority
BEFORE INSERT ON m4_acquisition_requests
WHEN NOT EXISTS (
    SELECT 1
    FROM m4_parsed_hearing_outputs AS output
    JOIN m4_hearing_cycles AS round
      ON round.run_id = output.run_id
     AND round.cycle_id = output.cycle_scope_id
     AND round.cycle_sha256 = output.cycle_scope_sha256
    JOIN m4_hearings AS hearing
      ON hearing.run_id = round.run_id
     AND hearing.hearing_id = round.hearing_id
    WHERE output.run_id = NEW.run_id
      AND output.parsed_output_id = NEW.judge_output_id
      AND output.role = 'JUDGE'
      AND output.payload_kind = 'JUDGE_ACQUISITION'
      AND output.hearing_id = NEW.hearing_id
      AND output.cycle_scope_id = NEW.cycle_scope_id
      AND output.cycle_scope_sha256 = NEW.cycle_scope_sha256
      AND output.case_id = NEW.case_id
      AND output.request_id = NEW.source_model_request_id
      AND output.response_id = NEW.source_model_response_id
      AND output.manifest_id = NEW.manifest_id
      AND round.cycle_index = NEW.round_index
      AND round.prior_acquisition_rounds = NEW.prior_acquisition_rounds
      AND round.prior_rework_rounds = NEW.prior_rework_rounds
      AND round.cycle_pack_id = NEW.evidence_pack_id
      AND round.cycle_pack_version = NEW.evidence_pack_version
      AND round.manifest_id = NEW.manifest_id
      AND hearing.case_id = NEW.case_id
      AND hearing.manifest_id = NEW.manifest_id
      AND round.prior_acquisition_rounds < hearing.max_acquisition_rounds
)
BEGIN
    SELECT RAISE(ABORT, 'M4 acquisition request authority is invalid');
END;

CREATE TRIGGER m4_acquisition_execution_claims_validate_authority
BEFORE INSERT ON m4_acquisition_execution_claims
WHEN NOT (
    NEW.status = 'ACTIVE'
    AND NEW.owner_fence = 1
    AND NEW.execution_publication_id IS NULL
    AND NEW.lease_expires_at > NEW.created_at
    AND NEW.updated_at = NEW.created_at
    AND json_extract(NEW.claim_json, '$.schema_version')
        = 'm4-acquisition-execution-claim-v1'
    AND json_extract(NEW.claim_json, '$.request.request_id')
        = NEW.acquisition_request_id
    AND json_extract(NEW.claim_json, '$.request.run_id') = NEW.run_id
    AND json_extract(NEW.claim_json, '$.request.case_id') = NEW.case_id
    AND json_extract(NEW.claim_json, '$.request.hearing_session_id') = NEW.hearing_id
    AND json_extract(NEW.claim_json, '$.execution_mode') = NEW.execution_mode
    AND json_extract(NEW.claim_json, '$.idempotency_key') = NEW.idempotency_key
    AND json_extract(NEW.claim_json, '$.status') = NEW.status
    AND json_extract(NEW.claim_json, '$.owner_token_sha256')
        = NEW.owner_token_sha256
    AND json_extract(NEW.claim_json, '$.owner_fence') = NEW.owner_fence
    AND json_extract(NEW.claim_json, '$.lease_expires_at') IS NEW.lease_expires_at
    AND json_extract(NEW.claim_json, '$.execution_publication_id')
        IS NEW.execution_publication_id
    AND json_extract(NEW.claim_json, '$.created_at') = NEW.created_at
    AND json_extract(NEW.claim_json, '$.updated_at') = NEW.updated_at
    AND EXISTS (
        SELECT 1
        FROM m4_acquisition_requests AS request
        JOIN m4_hearing_checkpoints AS checkpoint
          ON checkpoint.run_id = request.run_id
         AND checkpoint.hearing_id = request.hearing_id
         AND checkpoint.case_id = request.case_id
         AND checkpoint.phase = 'ACQUISITION_PENDING'
         AND checkpoint.acquisition_request_id = request.acquisition_request_id
        WHERE request.run_id = NEW.run_id
          AND request.acquisition_request_id = NEW.acquisition_request_id
          AND request.document_sha256 = NEW.request_document_sha256
          AND request.request_json = NEW.request_json
          AND request.hearing_id = NEW.hearing_id
          AND request.case_id = NEW.case_id
          AND NOT EXISTS (
              SELECT 1
              FROM m4_hearing_checkpoints AS later
              WHERE later.run_id = checkpoint.run_id
                AND later.hearing_id = checkpoint.hearing_id
                AND later.version > checkpoint.version
          )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 acquisition execution claim authority is invalid');
END;

CREATE TRIGGER m4_acquisition_execution_claims_controlled_update
BEFORE UPDATE ON m4_acquisition_execution_claims
WHEN NOT (
    OLD.run_id = NEW.run_id
    AND OLD.acquisition_request_id = NEW.acquisition_request_id
    AND OLD.request_document_sha256 = NEW.request_document_sha256
    AND OLD.request_json = NEW.request_json
    AND OLD.case_id = NEW.case_id
    AND OLD.hearing_id = NEW.hearing_id
    AND OLD.execution_mode = NEW.execution_mode
    AND OLD.idempotency_key = NEW.idempotency_key
    AND OLD.created_at = NEW.created_at
    AND OLD.status = 'ACTIVE'
    AND OLD.execution_publication_id IS NULL
    AND NEW.updated_at >= OLD.updated_at
    AND json_extract(NEW.claim_json, '$.schema_version')
        = 'm4-acquisition-execution-claim-v1'
    AND json_extract(NEW.claim_json, '$.request.request_id')
        = NEW.acquisition_request_id
    AND json_extract(NEW.claim_json, '$.request.run_id') = NEW.run_id
    AND json_extract(NEW.claim_json, '$.request.case_id') = NEW.case_id
    AND json_extract(NEW.claim_json, '$.request.hearing_session_id') = NEW.hearing_id
    AND json_extract(NEW.claim_json, '$.execution_mode') = NEW.execution_mode
    AND json_extract(NEW.claim_json, '$.idempotency_key') = NEW.idempotency_key
    AND json_extract(NEW.claim_json, '$.status') = NEW.status
    AND json_extract(NEW.claim_json, '$.owner_token_sha256')
        = NEW.owner_token_sha256
    AND json_extract(NEW.claim_json, '$.owner_fence') = NEW.owner_fence
    AND json_extract(NEW.claim_json, '$.lease_expires_at') IS NEW.lease_expires_at
    AND json_extract(NEW.claim_json, '$.execution_publication_id')
        IS NEW.execution_publication_id
    AND json_extract(NEW.claim_json, '$.created_at') = NEW.created_at
    AND json_extract(NEW.claim_json, '$.updated_at') = NEW.updated_at
    AND (
        (
            NEW.status = 'ACTIVE'
            AND OLD.lease_expires_at <= NEW.updated_at
            AND NEW.lease_expires_at > NEW.updated_at
            AND NEW.execution_publication_id IS NULL
            AND NEW.owner_token_sha256 <> OLD.owner_token_sha256
            AND NEW.owner_fence = OLD.owner_fence + 1
        )
        OR
        (
            NEW.status = 'COMPLETED'
            AND OLD.lease_expires_at > NEW.updated_at
            AND NEW.lease_expires_at IS NULL
            AND NEW.execution_publication_id IS NOT NULL
            AND NEW.owner_token_sha256 = OLD.owner_token_sha256
            AND NEW.owner_fence = OLD.owner_fence
            AND EXISTS (
                SELECT 1
                FROM m4_acquisition_execution_publications AS publication
                WHERE publication.run_id = NEW.run_id
                  AND publication.execution_publication_id
                      = NEW.execution_publication_id
                  AND publication.acquisition_request_id
                      = NEW.acquisition_request_id
                  AND publication.request_document_sha256
                      = NEW.request_document_sha256
                  AND publication.case_id = NEW.case_id
                  AND publication.hearing_id = NEW.hearing_id
                  AND publication.execution_mode = NEW.execution_mode
                  AND publication.idempotency_key = NEW.idempotency_key
                  AND publication.claim_owner_sha256 = NEW.owner_token_sha256
                  AND publication.claim_fence = NEW.owner_fence
            )
        )
        OR
        (
            NEW.status = 'ABANDONED'
            AND NEW.lease_expires_at IS NULL
            AND NEW.execution_publication_id IS NULL
            AND NEW.owner_fence = OLD.owner_fence + 1
            AND (
                NEW.owner_token_sha256 = OLD.owner_token_sha256
                OR
                (OLD.execution_mode = 'IDEMPOTENT_EXTERNAL'
                 AND OLD.lease_expires_at <= NEW.updated_at
                 AND NEW.owner_token_sha256 <> OLD.owner_token_sha256)
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 acquisition execution claim update is invalid');
END;

CREATE TRIGGER m4_acquisition_execution_publications_validate_authority
BEFORE INSERT ON m4_acquisition_execution_publications
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_acquisition_execution_claims AS claim
        JOIN m4_acquisition_requests AS request
          ON request.run_id = claim.run_id
         AND request.acquisition_request_id = claim.acquisition_request_id
        JOIN m4_tool_execution_manifests AS execution
          ON execution.run_id = claim.run_id
         AND execution.acquisition_request_id = claim.acquisition_request_id
        WHERE claim.run_id = NEW.run_id
          AND claim.acquisition_request_id = NEW.acquisition_request_id
          AND claim.request_document_sha256 = NEW.request_document_sha256
          AND claim.case_id = NEW.case_id
          AND claim.hearing_id = NEW.hearing_id
          AND claim.execution_mode = NEW.execution_mode
          AND claim.idempotency_key = NEW.idempotency_key
          AND claim.status = 'ACTIVE'
          AND claim.owner_token_sha256 = NEW.claim_owner_sha256
          AND claim.owner_fence = NEW.claim_fence
          AND claim.lease_expires_at > claim.updated_at
          AND claim.execution_publication_id IS NULL
          AND request.document_sha256 = NEW.request_document_sha256
          AND execution.execution_manifest_id = NEW.execution_manifest_id
          AND execution.hearing_id = NEW.hearing_id
          AND execution.case_id = NEW.case_id
    )
)
BEGIN
    SELECT RAISE(
        ABORT, 'M4 acquisition execution publication authority is invalid'
    );
END;

CREATE TRIGGER m4_hearing_rounds_validate_authority
BEFORE INSERT ON m4_hearing_rounds
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_hearing_cycles AS cycle
        WHERE cycle.run_id = NEW.run_id
          AND cycle.cycle_id = NEW.cycle_scope_id
          AND cycle.cycle_sha256 = NEW.cycle_scope_sha256
          AND cycle.hearing_id = NEW.hearing_id
          AND cycle.case_id = NEW.case_id
          AND cycle.cycle_index = NEW.round_index
          AND cycle.prior_acquisition_rounds = NEW.prior_acquisition_rounds
          AND cycle.prior_rework_rounds = NEW.prior_rework_rounds
          AND cycle.cycle_pack_id = NEW.current_pack_id
          AND cycle.cycle_pack_version = NEW.current_pack_version
          AND cycle.initial_trigger_review_id IS NEW.initial_trigger_review_id
          AND json(cycle.initial_defect_codes_json)
              = json(NEW.initial_defect_codes_json)
          AND cycle.rework_review_id IS NEW.rework_review_id
          AND json(cycle.rework_defect_codes_json)
              = json(NEW.rework_defect_codes_json)
          AND cycle.manifest_id = NEW.manifest_id
    )
    AND EXISTS (
        SELECT 1
        FROM m4_precedent_retrieval_receipts AS retrieval
        WHERE retrieval.run_id = NEW.run_id
          AND retrieval.retrieval_receipt_id = NEW.retrieval_receipt_id
          AND retrieval.document_sha256 = NEW.retrieval_receipt_sha256
          AND retrieval.hearing_id = NEW.hearing_id
          AND retrieval.cycle_scope_id = NEW.cycle_scope_id
          AND retrieval.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND retrieval.case_id = NEW.case_id
          AND retrieval.prior_acquisition_rounds = NEW.prior_acquisition_rounds
          AND retrieval.prior_rework_rounds = NEW.prior_rework_rounds
          AND retrieval.current_pack_id = NEW.current_pack_id
          AND retrieval.current_pack_version = NEW.current_pack_version
          AND retrieval.precedent_retrieval_degraded
              = NEW.precedent_retrieval_degraded
          AND retrieval.initial_trigger_review_id IS NEW.initial_trigger_review_id
          AND json(retrieval.initial_defect_codes_json)
              = json(NEW.initial_defect_codes_json)
          AND retrieval.rework_review_id IS NEW.rework_review_id
          AND json(retrieval.rework_defect_codes_json)
              = json(NEW.rework_defect_codes_json)
          AND retrieval.manifest_id = NEW.manifest_id
    )
    AND EXISTS (
        SELECT 1
        FROM m4_parsed_hearing_outputs AS prosecutor
        JOIN m4_parsed_hearing_outputs AS defender
          ON defender.run_id = prosecutor.run_id
         AND defender.parsed_output_id = NEW.defender_output_id
        JOIN m4_parsed_hearing_outputs AS judge
          ON judge.run_id = prosecutor.run_id
         AND judge.parsed_output_id = NEW.judge_output_id
        WHERE prosecutor.run_id = NEW.run_id
          AND prosecutor.parsed_output_id = NEW.prosecutor_output_id
          AND prosecutor.role = 'PROSECUTOR'
          AND prosecutor.payload_kind = 'PROSECUTION'
          AND defender.role = 'DEFENDER'
          AND defender.payload_kind = 'DEFENSE'
          AND defender.prosecutor_output_id = prosecutor.parsed_output_id
          AND judge.role = 'JUDGE'
          AND judge.payload_kind IN ('JUDGE_VERDICT', 'JUDGE_ACQUISITION')
          AND judge.prosecutor_output_id = prosecutor.parsed_output_id
          AND judge.defender_output_id = defender.parsed_output_id
          AND prosecutor.hearing_id = NEW.hearing_id
          AND defender.hearing_id = NEW.hearing_id
          AND judge.hearing_id = NEW.hearing_id
          AND prosecutor.cycle_scope_id = NEW.cycle_scope_id
          AND defender.cycle_scope_id = NEW.cycle_scope_id
          AND judge.cycle_scope_id = NEW.cycle_scope_id
          AND prosecutor.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND defender.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND judge.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND prosecutor.case_id = NEW.case_id
          AND defender.case_id = NEW.case_id
          AND judge.case_id = NEW.case_id
          AND prosecutor.precedent_retrieval_receipt_id = NEW.retrieval_receipt_id
          AND defender.precedent_retrieval_receipt_id = NEW.retrieval_receipt_id
          AND judge.precedent_retrieval_receipt_id = NEW.retrieval_receipt_id
          AND prosecutor.precedent_retrieval_receipt_sha256
              = NEW.retrieval_receipt_sha256
          AND defender.precedent_retrieval_receipt_sha256
              = NEW.retrieval_receipt_sha256
          AND judge.precedent_retrieval_receipt_sha256
              = NEW.retrieval_receipt_sha256
          AND prosecutor.manifest_id = NEW.manifest_id
          AND defender.manifest_id = NEW.manifest_id
          AND judge.manifest_id = NEW.manifest_id
          AND (
              (judge.payload_kind = 'JUDGE_VERDICT'
               AND NEW.acquisition_request_id IS NULL
               AND NEW.tool_receipt_id IS NULL)
              OR
              (judge.payload_kind = 'JUDGE_ACQUISITION'
               AND EXISTS (
                   SELECT 1
                   FROM m4_acquisition_requests AS request
                   JOIN m4_tool_execution_receipts AS receipt
                     ON receipt.run_id = request.run_id
                    AND receipt.acquisition_request_id
                        = request.acquisition_request_id
                   WHERE request.run_id = NEW.run_id
                     AND request.acquisition_request_id
                         = NEW.acquisition_request_id
                     AND request.hearing_id = NEW.hearing_id
                     AND request.cycle_scope_id = NEW.cycle_scope_id
                     AND request.cycle_scope_sha256 = NEW.cycle_scope_sha256
                     AND request.case_id = NEW.case_id
                     AND request.judge_output_id = NEW.judge_output_id
                     AND receipt.receipt_id = NEW.tool_receipt_id
                     AND receipt.hearing_id = NEW.hearing_id
                     AND receipt.cycle_scope_id = NEW.cycle_scope_id
                     AND receipt.cycle_scope_sha256 = NEW.cycle_scope_sha256
                     AND receipt.case_id = NEW.case_id
                     AND receipt.resulting_pack_id = NEW.resulting_pack_id
                     AND receipt.resulting_pack_version
                         = NEW.resulting_pack_version
               ))
          )
    )
    AND json_extract(NEW.round_json, '$.round_id') = NEW.round_id
    AND json_extract(NEW.round_json, '$.cycle_scope_id') = NEW.cycle_scope_id
    AND json_extract(NEW.round_json, '$.cycle_scope_sha256')
        = NEW.cycle_scope_sha256
    AND json_extract(NEW.round_json, '$.run_id') = NEW.run_id
    AND json_extract(NEW.round_json, '$.case_id') = NEW.case_id
    AND json_extract(NEW.round_json, '$.hearing_session_id') = NEW.hearing_id
    AND json_extract(NEW.round_json, '$.round_index') = NEW.round_index
    AND json_extract(NEW.round_json, '$.prior_acquisition_rounds')
        = NEW.prior_acquisition_rounds
    AND json_extract(NEW.round_json, '$.prior_rework_rounds')
        = NEW.prior_rework_rounds
    AND json_extract(NEW.round_json, '$.current_evidence_pack_id')
        = NEW.current_pack_id
    AND json_extract(NEW.round_json, '$.current_evidence_pack_version')
        = NEW.current_pack_version
    AND json_extract(NEW.round_json, '$.resulting_evidence_pack_id')
        = NEW.resulting_pack_id
    AND json_extract(NEW.round_json, '$.resulting_evidence_pack_version')
        = NEW.resulting_pack_version
    AND json_extract(NEW.round_json, '$.manifest_id') = NEW.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing round authority is invalid');
END;

CREATE TRIGGER m4_tool_execution_manifests_validate_authority
BEFORE INSERT ON m4_tool_execution_manifests
WHEN NOT EXISTS (
    SELECT 1 FROM m4_acquisition_requests AS request
    WHERE request.run_id = NEW.run_id
      AND request.acquisition_request_id = NEW.acquisition_request_id
      AND request.hearing_id = NEW.hearing_id
      AND request.case_id = NEW.case_id
      AND request.action = NEW.action
      AND request.manifest_id = NEW.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'M4 tool execution manifest authority is invalid');
END;

CREATE TRIGGER m4_acquired_crops_validate_authority
BEFORE INSERT ON m4_acquired_crops
WHEN NOT EXISTS (
    SELECT 1
    FROM m4_acquisition_requests AS request
    JOIN m4_tool_execution_manifests AS execution
      ON execution.run_id = request.run_id
     AND execution.acquisition_request_id = request.acquisition_request_id
    JOIN frames AS frame
      ON frame.run_id = request.run_id
     AND frame.frame_id = NEW.frame_id
     AND frame.manifest_id = NEW.manifest_id
    JOIN media_assets AS media
      ON media.run_id = request.run_id
     AND media.media_sha256 = NEW.media_sha256
    WHERE request.run_id = NEW.run_id
      AND request.acquisition_request_id = NEW.acquisition_request_id
      AND request.hearing_id = NEW.hearing_id
      AND request.case_id = NEW.case_id
      AND request.action = 'RECROP'
      AND request.evidence_pack_id = NEW.source_pack_id
      AND request.evidence_pack_version = NEW.source_pack_version
      AND request.manifest_id = NEW.manifest_id
      AND execution.execution_manifest_id = NEW.execution_manifest_id
      AND execution.hearing_id = NEW.hearing_id
      AND execution.case_id = NEW.case_id
      AND execution.action = 'RECROP'
      AND execution.manifest_id = NEW.manifest_id
      AND json_extract(
              request.request_json,
              '$.request_payload.validated_parameters.action'
          ) = 'RECROP'
      AND json_extract(
              request.request_json,
              '$.request_payload.validated_parameters.frame_id'
          ) = NEW.frame_id
      AND json_extract(NEW.crop_json, '$.bbox.x1') = json_extract(
              request.request_json,
              '$.request_payload.validated_parameters.bbox.x1'
          )
      AND json_extract(NEW.crop_json, '$.bbox.y1') = json_extract(
              request.request_json,
              '$.request_payload.validated_parameters.bbox.y1'
          )
      AND json_extract(NEW.crop_json, '$.bbox.x2') = json_extract(
              request.request_json,
              '$.request_payload.validated_parameters.bbox.x2'
          )
      AND json_extract(NEW.crop_json, '$.bbox.y2') = json_extract(
              request.request_json,
              '$.request_payload.validated_parameters.bbox.y2'
          )
      AND json_extract(NEW.crop_json, '$.bbox.x1') >= 0
      AND json_extract(NEW.crop_json, '$.bbox.y1') >= 0
      AND json_extract(NEW.crop_json, '$.bbox.x2') <= frame.width
      AND json_extract(NEW.crop_json, '$.bbox.y2') <= frame.height
      AND json_extract(NEW.crop_json, '$.output_width')
          = json_extract(NEW.crop_json, '$.bbox.x2')
            - json_extract(NEW.crop_json, '$.bbox.x1')
      AND json_extract(NEW.crop_json, '$.output_height')
          = json_extract(NEW.crop_json, '$.bbox.y2')
            - json_extract(NEW.crop_json, '$.bbox.y1')
      AND media.manifest_id = NEW.manifest_id
      AND media.pixel_sha256 = NEW.pixel_sha256
      AND media.width = json_extract(NEW.crop_json, '$.output_width')
      AND media.height = json_extract(NEW.crop_json, '$.output_height')
      AND media.size_bytes = json_extract(NEW.crop_json, '$.size_bytes')
      AND media.media_type = 'IMAGE_PNG'
      AND media.encoding_version = json_extract(NEW.crop_json, '$.encoding_version')
      AND EXISTS (
          SELECT 1
          FROM json_each(NEW.crop_json, '$.source_refs') AS ref
          WHERE json_extract(ref.value, '$.kind') = 'FRAME'
            AND json_extract(ref.value, '$.artifact_id') = NEW.frame_id
      )
      AND EXISTS (
          SELECT 1
          FROM json_each(NEW.crop_json, '$.source_refs') AS ref
          WHERE json_extract(ref.value, '$.kind') IN ('CROP', 'TOOL_RESULT')
      )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 acquired crop authority is invalid');
END;

CREATE TRIGGER m4_tool_execution_receipts_validate_authority
BEFORE INSERT ON m4_tool_execution_receipts
WHEN NOT EXISTS (
    SELECT 1
    FROM m4_acquisition_requests AS request
    JOIN m4_tool_execution_manifests AS execution
      ON execution.run_id = request.run_id
     AND execution.acquisition_request_id = request.acquisition_request_id
    WHERE request.run_id = NEW.run_id
      AND request.acquisition_request_id = NEW.acquisition_request_id
      AND request.hearing_id = NEW.hearing_id
      AND request.cycle_scope_id = NEW.cycle_scope_id
      AND request.cycle_scope_sha256 = NEW.cycle_scope_sha256
      AND request.case_id = NEW.case_id
      AND request.action = NEW.action
      AND execution.execution_manifest_id = NEW.execution_manifest_id
      AND execution.hearing_id = NEW.hearing_id
      AND execution.case_id = NEW.case_id
      AND execution.action = NEW.action
      AND NEW.resulting_pack_version = request.evidence_pack_version + 1
      AND NEW.resulting_pack_id <> request.evidence_pack_id
      AND (
          NEW.action <> 'RECROP'
          OR EXISTS (
              SELECT 1
              FROM m4_acquired_crops AS crop
              WHERE crop.run_id = NEW.run_id
                AND crop.acquisition_request_id = NEW.acquisition_request_id
                AND crop.execution_manifest_id = NEW.execution_manifest_id
                AND crop.hearing_id = NEW.hearing_id
                AND crop.case_id = NEW.case_id
                AND json_array_length(
                    NEW.receipt_json,
                    '$.tool_result.output_refs'
                ) = 1
                AND json_extract(
                    NEW.receipt_json,
                    '$.tool_result.output_refs[0].kind'
                ) = 'CROP'
                AND json_extract(
                    NEW.receipt_json,
                    '$.tool_result.output_refs[0].artifact_id'
                ) = crop.crop_id
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 tool execution receipt authority is invalid');
END;

CREATE TRIGGER m4_evidence_pack_derivations_validate_authority
BEFORE INSERT ON m4_evidence_pack_derivations
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM evidence_packs AS previous
        JOIN evidence_packs AS current
          ON current.run_id = previous.run_id
         AND current.case_id = previous.case_id
         AND current.manifest_id = previous.manifest_id
        WHERE previous.run_id = NEW.run_id
          AND previous.case_id = NEW.case_id
          AND previous.pack_id = NEW.previous_pack_id
          AND previous.version = NEW.previous_pack_version
          AND previous.manifest_id = NEW.manifest_id
          AND current.pack_id = NEW.new_pack_id
          AND current.version = NEW.new_pack_version
    )
    AND EXISTS (
        SELECT 1
        FROM m4_tool_execution_receipts AS receipt
        JOIN m4_acquisition_requests AS request
          ON request.run_id = receipt.run_id
         AND request.acquisition_request_id = receipt.acquisition_request_id
        WHERE receipt.run_id = NEW.run_id
          AND receipt.receipt_id = NEW.tool_receipt_id
          AND receipt.hearing_id = NEW.hearing_id
          AND receipt.cycle_scope_id = NEW.source_cycle_scope_id
          AND receipt.cycle_scope_sha256 = NEW.source_cycle_scope_sha256
          AND receipt.case_id = NEW.case_id
          AND receipt.resulting_pack_id = NEW.new_pack_id
          AND receipt.resulting_pack_version = NEW.new_pack_version
          AND request.evidence_pack_id = NEW.previous_pack_id
          AND request.evidence_pack_version = NEW.previous_pack_version
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 evidence pack derivation authority is invalid');
END;

CREATE TRIGGER m4_hearing_verdict_bindings_validate_authority
BEFORE INSERT ON m4_hearing_verdict_bindings
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_hearing_rounds AS round
        JOIN m4_parsed_hearing_outputs AS judge
          ON judge.run_id = round.run_id
         AND judge.parsed_output_id = round.judge_output_id
        WHERE round.run_id = NEW.run_id
          AND round.round_id = NEW.round_id
          AND round.hearing_id = NEW.hearing_id
          AND round.cycle_scope_id = NEW.cycle_scope_id
          AND round.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND round.case_id = NEW.case_id
          AND round.round_index = NEW.judge_round_index
          AND round.current_pack_id = NEW.evidence_pack_id
          AND round.current_pack_version = NEW.evidence_pack_version
          AND round.prosecutor_output_id = NEW.prosecutor_output_id
          AND round.defender_output_id = NEW.defender_output_id
          AND round.judge_output_id = NEW.judge_output_id
          AND judge.payload_kind = 'JUDGE_VERDICT'
    )
    AND EXISTS (
        SELECT 1
        FROM verdicts AS verdict
        WHERE verdict.run_id = NEW.run_id
          AND verdict.case_id = NEW.case_id
          AND verdict.verdict_id = NEW.verdict_id
          AND verdict.version = NEW.verdict_version
          AND verdict.verdict_input_sha256 = NEW.verdict_input_sha256
          AND verdict.verdict_sha256 = NEW.verdict_sha256
          AND verdict.evidence_pack_id = NEW.evidence_pack_id
          AND verdict.evidence_pack_version = NEW.evidence_pack_version
          AND verdict.manifest_id = NEW.manifest_id
    )
    AND json_array_length(NEW.model_request_refs_json)
        = json_array_length(NEW.model_response_refs_json)
    AND json_array_length(NEW.model_request_refs_json)
        = json_array_length(NEW.parse_receipt_refs_json)
    AND json_array_length(NEW.model_request_refs_json) >= 3
    AND NOT EXISTS (
        SELECT 1 FROM json_each(NEW.model_request_refs_json) AS ref
        WHERE json_extract(ref.value, '$.kind') <> 'MODEL_REQUEST'
    )
    AND NOT EXISTS (
        SELECT 1 FROM json_each(NEW.model_response_refs_json) AS ref
        WHERE json_extract(ref.value, '$.kind') <> 'MODEL_RESPONSE'
    )
    AND NOT EXISTS (
        SELECT 1 FROM json_each(NEW.parse_receipt_refs_json) AS ref
        WHERE json_extract(ref.value, '$.kind') <> 'MODEL_PARSE_RECEIPT'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing verdict binding authority is invalid');
END;

CREATE TRIGGER m4_rework_receipts_validate_authority
BEFORE INSERT ON m4_rework_receipts
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM procedural_reviews AS review
        JOIN m4_hearing_verdict_bindings AS binding
          ON binding.run_id = review.run_id
         AND binding.case_id = review.case_id
         AND binding.verdict_id = review.reviewed_verdict_id
         AND binding.verdict_version = review.reviewed_verdict_version
        WHERE review.run_id = NEW.run_id
          AND review.review_id = NEW.failed_review_id
          AND review.passed = 0
          AND review.case_id = NEW.case_id
          AND review.manifest_id = NEW.manifest_id
          AND binding.hearing_id = NEW.hearing_id
          AND binding.round_id = NEW.prior_round_id
          AND binding.manifest_id = NEW.manifest_id
          AND NOT EXISTS (
              SELECT 1
              FROM procedural_defects AS defect
              WHERE defect.run_id = NEW.run_id
                AND defect.owner_kind = 'PROCEDURAL_REVIEW'
                AND defect.owner_id = NEW.failed_review_id
                AND NOT EXISTS (
                    SELECT 1 FROM json_each(NEW.defect_codes_json) AS supplied
                    WHERE supplied.value = defect.code
                )
          )
          AND NOT EXISTS (
              SELECT 1 FROM json_each(NEW.defect_codes_json) AS supplied
              WHERE NOT EXISTS (
                  SELECT 1
                  FROM procedural_defects AS defect
                  WHERE defect.run_id = NEW.run_id
                    AND defect.owner_kind = 'PROCEDURAL_REVIEW'
                    AND defect.owner_id = NEW.failed_review_id
                    AND defect.code = supplied.value
              )
          )
    )
    AND EXISTS (
        SELECT 1
        FROM m4_hearing_rounds AS previous
        JOIN m4_hearing_cycles AS next
          ON next.run_id = previous.run_id
         AND next.hearing_id = previous.hearing_id
        WHERE previous.run_id = NEW.run_id
          AND previous.round_id = NEW.prior_round_id
          AND previous.hearing_id = NEW.hearing_id
          AND previous.case_id = NEW.case_id
          AND next.cycle_id = NEW.next_cycle_scope_id
          AND next.cycle_sha256 = NEW.next_cycle_scope_sha256
          AND next.rework_review_id = NEW.failed_review_id
          AND next.prior_rework_rounds = NEW.rework_index
          AND next.prior_rework_rounds = previous.prior_rework_rounds + 1
          AND next.prior_acquisition_rounds = previous.prior_acquisition_rounds
          AND next.cycle_pack_id = previous.resulting_pack_id
          AND next.cycle_pack_version = previous.resulting_pack_version
          AND next.manifest_id = NEW.manifest_id
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 rework receipt authority is invalid');
END;

CREATE TRIGGER m4_hearing_strict_parse_failure_attempts_validate_authority
BEFORE INSERT ON m4_hearing_strict_parse_failure_attempts
WHEN NOT EXISTS (
    SELECT 1
    FROM m4_model_call_claims AS claim
    JOIN m4_model_responses AS response
      ON response.run_id = claim.run_id
     AND response.request_id = claim.request_id
     AND response.response_id = claim.response_id
    JOIN m4_model_parse_receipts AS parse
      ON parse.run_id = response.run_id
     AND parse.request_id = response.request_id
     AND parse.response_id = response.response_id
    WHERE claim.run_id = NEW.run_id
      AND claim.request_id = NEW.request_id
      AND claim.request_sha256 = NEW.request_sha256
      AND claim.hearing_id = NEW.hearing_id
      AND claim.cycle_scope_id = NEW.cycle_scope_id
      AND claim.cycle_scope_sha256 = NEW.cycle_scope_sha256
      AND claim.case_id = NEW.case_id
      AND claim.role = NEW.role
      AND claim.attempt_index = NEW.attempt_index
      AND (
          (NEW.retry_generation = 0
           AND claim.call_generation = 'INITIAL'
           AND claim.backlog_item_id IS NULL
           AND claim.retry_generation = 0)
          OR
          (NEW.retry_generation > 0
           AND claim.call_generation = 'BACKLOG'
           AND claim.backlog_item_id = NEW.backlog_item_id
           AND claim.retry_generation = NEW.retry_generation)
      )
      AND claim.manifest_id = NEW.manifest_id
      AND claim.status = 'COMPLETED'
      AND response.response_id = NEW.response_id
      AND response.content_sha256 = NEW.response_content_sha256
      AND parse.parse_receipt_id = NEW.parse_receipt_id
      AND parse.hearing_id = NEW.hearing_id
      AND parse.cycle_scope_id = NEW.cycle_scope_id
      AND parse.case_id = NEW.case_id
      AND parse.role = NEW.role
      AND parse.attempt_index = NEW.attempt_index
      AND parse.status = CASE
          WHEN NEW.attempt_index = 0 THEN 'REPAIR_REQUIRED'
          ELSE 'INVALID_FINAL'
      END
)
BEGIN
    SELECT RAISE(ABORT, 'M4 strict parse-failure attempt authority is invalid');
END;

CREATE TRIGGER m4_hearing_strict_parse_failure_proofs_validate_authority
BEFORE INSERT ON m4_hearing_strict_parse_failure_proofs
WHEN NOT (
    (
        (NEW.closure_kind = 'INITIAL_BACKLOG'
         AND NEW.retry_generation = 0
         AND NEW.lease_identity_sha256 IS NULL
         AND NEW.lease_id IS NULL
         AND NEW.lease_attempt_count IS NULL
         AND EXISTS (
             SELECT 1
             FROM backlog_item_versions AS pending
             JOIN backlog_heads AS head
               ON head.run_id = pending.run_id
              AND head.item_id = pending.item_id
              AND head.current_version = pending.version
             JOIN backlog_items AS item
               ON item.run_id = pending.run_id
              AND item.item_id = pending.item_id
             WHERE pending.run_id = NEW.run_id
               AND pending.item_id = NEW.backlog_item_id
               AND pending.version = 1
               AND pending.status = 'PENDING'
               AND pending.attempt_count = 0
               AND pending.retry_generation = 1
               AND pending.lease_id IS NULL
               AND pending.lease_owner_sha256 IS NULL
               AND pending.lease_expires_at IS NULL
               AND item.case_id = NEW.case_id
               AND item.stage = 'HEARING'
               AND item.role = NEW.role
               AND item.reason_code = 'MODEL_OUTPUT_INVALID'
         ))
        OR
        (NEW.closure_kind = 'RETRY_FAILURE'
         AND NEW.lease_identity_sha256 IS NOT NULL
         AND NEW.lease_id IS NOT NULL
         AND NEW.lease_attempt_count IS NOT NULL
         AND EXISTS (
             SELECT 1
             FROM backlog_item_versions AS leased
             JOIN backlog_heads AS head
               ON head.run_id = leased.run_id
              AND head.item_id = leased.item_id
              AND head.current_version = leased.version
             JOIN backlog_items AS item
               ON item.run_id = leased.run_id
              AND item.item_id = leased.item_id
             WHERE leased.run_id = NEW.run_id
               AND leased.item_id = NEW.backlog_item_id
               AND leased.status = 'LEASED'
               AND leased.lease_id = NEW.lease_id
               AND leased.attempt_count = NEW.lease_attempt_count
               AND leased.retry_generation = NEW.retry_generation
               AND item.case_id = NEW.case_id
               AND item.stage = 'HEARING'
               AND item.role = NEW.role
         ))
    )
    AND EXISTS (
        SELECT 1
        FROM m4_hearing_strict_parse_failure_attempts AS primary_attempt
        JOIN m4_hearing_strict_parse_failure_attempts AS repair_attempt
          ON repair_attempt.run_id = primary_attempt.run_id
        JOIN m4_model_parse_receipts AS primary_parse
          ON primary_parse.run_id = primary_attempt.run_id
         AND primary_parse.parse_receipt_id = primary_attempt.parse_receipt_id
        WHERE primary_attempt.run_id = NEW.run_id
          AND primary_attempt.attempt_id = NEW.primary_attempt_id
          AND repair_attempt.attempt_id = NEW.repair_attempt_id
          AND primary_attempt.hearing_id = NEW.hearing_id
          AND repair_attempt.hearing_id = NEW.hearing_id
          AND primary_attempt.case_id = NEW.case_id
          AND repair_attempt.case_id = NEW.case_id
          AND primary_attempt.role = NEW.role
          AND repair_attempt.role = NEW.role
          AND primary_attempt.attempt_index = 0
          AND repair_attempt.attempt_index = 1
          AND primary_attempt.backlog_item_id = NEW.backlog_item_id
          AND repair_attempt.backlog_item_id = NEW.backlog_item_id
          AND primary_attempt.retry_generation = NEW.retry_generation
          AND repair_attempt.retry_generation = NEW.retry_generation
          AND primary_parse.repair_request_id = repair_attempt.request_id
    )
    AND EXISTS (
        SELECT 1 FROM m4_hearing_checkpoints AS checkpoint
        WHERE checkpoint.run_id = NEW.run_id
          AND checkpoint.checkpoint_id = NEW.source_checkpoint_id
          AND checkpoint.checkpoint_sha256 = NEW.source_checkpoint_sha256
          AND checkpoint.version = NEW.source_checkpoint_version
          AND checkpoint.hearing_id = NEW.hearing_id
          AND checkpoint.case_id = NEW.case_id
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 strict parse-failure proof authority is invalid');
END;

CREATE TRIGGER m4_hearing_backlog_retry_outcomes_validate_authority
BEFORE INSERT ON m4_hearing_backlog_retry_outcomes
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM backlog_items AS item
        JOIN backlog_item_versions AS leased
          ON leased.run_id = item.run_id
         AND leased.item_id = item.item_id
        JOIN backlog_heads AS head
          ON head.run_id = leased.run_id
         AND head.item_id = leased.item_id
         AND head.current_version = leased.version
        WHERE item.run_id = NEW.run_id
          AND item.item_id = NEW.backlog_item_id
          AND item.case_id = NEW.case_id
          AND item.stage = 'HEARING'
          AND item.role = NEW.role
          AND item.manifest_id = NEW.manifest_id
          AND leased.status = 'LEASED'
          AND leased.lease_id = NEW.lease_id
          AND leased.attempt_count = NEW.lease_attempt_count
          AND leased.retry_generation = NEW.retry_generation
    )
    AND EXISTS (
        SELECT 1 FROM m4_hearing_checkpoints AS checkpoint
        WHERE checkpoint.run_id = NEW.run_id
          AND checkpoint.checkpoint_id = NEW.source_checkpoint_id
          AND checkpoint.checkpoint_sha256 = NEW.source_checkpoint_sha256
          AND checkpoint.version = NEW.source_checkpoint_version
          AND checkpoint.hearing_id = NEW.hearing_id
          AND checkpoint.cycle_scope_id = NEW.cycle_scope_id
          AND checkpoint.case_id = NEW.case_id
    )
    AND EXISTS (
        SELECT 1 FROM m4_model_call_claims AS claim
        WHERE claim.run_id = NEW.run_id
          AND claim.request_id = NEW.request_id
          AND claim.request_sha256 = NEW.request_sha256
          AND claim.hearing_id = NEW.hearing_id
          AND claim.cycle_scope_id = NEW.cycle_scope_id
          AND claim.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND claim.case_id = NEW.case_id
          AND claim.role = NEW.role
          AND claim.manifest_id = NEW.manifest_id
          AND (
              (NEW.outcome_kind = 'FAILURE'
               AND NEW.reason_code = 'WORKER_LEASE_EXPIRED'
               AND json_extract(NEW.outcome_json, '$.request_binding')
                   = 'BACKLOG_STAGE_INPUT'
               AND EXISTS (
                   SELECT 1 FROM backlog_items AS stage_item
                   WHERE stage_item.run_id = NEW.run_id
                     AND stage_item.item_id = NEW.backlog_item_id
                     AND stage_item.stage_input_kind = 'MODEL_REQUEST'
                     AND stage_item.stage_input_id = NEW.request_id
                     AND stage_item.stage_input_sha256 = claim.request_document_sha256
               )
               AND (
                   json_type(
                       NEW.outcome_json,
                       '$.lease_expiry_resume_request_ref'
                   ) = 'null'
                   OR EXISTS (
                       SELECT 1 FROM m4_model_call_claims AS resume
                       WHERE resume.run_id = NEW.run_id
                         AND resume.request_id = json_extract(
                             NEW.outcome_json,
                             '$.lease_expiry_resume_request_ref.artifact_id'
                         )
                         AND json_extract(
                             NEW.outcome_json,
                             '$.lease_expiry_resume_request_ref.kind'
                         ) = 'MODEL_REQUEST'
                         AND resume.hearing_id = NEW.hearing_id
                         AND resume.cycle_scope_id = NEW.cycle_scope_id
                         AND resume.cycle_scope_sha256 = NEW.cycle_scope_sha256
                         AND resume.case_id = NEW.case_id
                         AND resume.role = NEW.role
                         AND resume.manifest_id = NEW.manifest_id
                         AND (
                             (NEW.retry_generation = 0
                              AND resume.call_generation = 'INITIAL'
                              AND resume.backlog_item_id IS NULL
                              AND resume.retry_generation = 0)
                             OR
                             (NEW.retry_generation > 0
                              AND resume.call_generation = 'BACKLOG'
                              AND resume.backlog_item_id = NEW.backlog_item_id
                              AND resume.retry_generation = NEW.retry_generation)
                         )
                   )
               ))
              OR
              ((NEW.outcome_kind = 'SUCCESS'
                OR NEW.reason_code <> 'WORKER_LEASE_EXPIRED')
               AND (
                   (claim.call_generation = 'INITIAL'
                    AND claim.backlog_item_id IS NULL
                    AND NEW.retry_generation = 0)
                   OR
                   (claim.call_generation = 'BACKLOG'
                    AND claim.backlog_item_id = NEW.backlog_item_id
                    AND claim.retry_generation = NEW.retry_generation)
               )
               AND (
                   NEW.outcome_kind = 'SUCCESS'
                   OR json_extract(NEW.outcome_json, '$.request_binding')
                       = 'LEASE_GENERATION_CALL'
               ))
          )
    )
    AND (
        (
            NEW.outcome_kind = 'SUCCESS'
            AND EXISTS (
                SELECT 1
                FROM m4_model_responses AS response
                JOIN m4_model_parse_receipts AS parse
                  ON parse.run_id = response.run_id
                 AND parse.request_id = response.request_id
                 AND parse.response_id = response.response_id
                JOIN m4_parsed_hearing_outputs AS output
                  ON output.run_id = parse.run_id
                 AND output.parsed_output_id = parse.parsed_output_id
                JOIN m4_hearing_checkpoints AS next
                  ON next.run_id = output.run_id
                 AND next.checkpoint_id = NEW.next_checkpoint_id
                JOIN m4_hearings AS hearing
                  ON hearing.run_id = output.run_id
                 AND hearing.hearing_id = output.hearing_id
                WHERE response.run_id = NEW.run_id
                  AND response.request_id = NEW.request_id
                  AND response.response_id = NEW.response_id
                  AND parse.parse_receipt_id = NEW.parse_receipt_id
                  AND parse.status = 'PARSED'
                  AND output.parsed_output_id = NEW.parsed_output_id
                  AND output.role = NEW.role
                  AND output.hearing_id = NEW.hearing_id
                  AND output.cycle_scope_id = NEW.cycle_scope_id
                  AND output.cycle_scope_sha256 = NEW.cycle_scope_sha256
                  AND output.case_id = NEW.case_id
                  AND next.checkpoint_sha256 = NEW.next_checkpoint_sha256
                  AND next.version = NEW.next_checkpoint_version
                  AND next.previous_checkpoint_id = NEW.source_checkpoint_id
                  AND next.previous_checkpoint_sha256 = NEW.source_checkpoint_sha256
                  AND next.version = NEW.source_checkpoint_version + 1
                  AND (
                      (NEW.role = 'PROSECUTOR'
                       AND next.phase = 'DEFENDER_PENDING'
                       AND next.prosecutor_output_id = NEW.parsed_output_id
                       AND NEW.human_review_receipt_id IS NULL)
                      OR
                      (NEW.role = 'DEFENDER'
                       AND next.phase = 'JUDGE_PENDING'
                       AND next.defender_output_id = NEW.parsed_output_id
                       AND NEW.human_review_receipt_id IS NULL)
                      OR
                      (NEW.role = 'JUDGE'
                       AND output.payload_kind = 'JUDGE_VERDICT'
                       AND next.phase = 'ROUND_COMPLETE'
                       AND next.judge_output_id = NEW.parsed_output_id
                       AND NEW.human_review_receipt_id IS NULL)
                      OR
                      (NEW.role = 'JUDGE'
                       AND output.payload_kind = 'JUDGE_ACQUISITION'
                       AND next.judge_output_id = NEW.parsed_output_id
                       AND (
                           (output.prior_acquisition_rounds
                                < hearing.max_acquisition_rounds
                            AND next.phase = 'ACQUISITION_PENDING'
                            AND NEW.human_review_receipt_id IS NULL)
                           OR
                           (output.prior_acquisition_rounds
                                >= hearing.max_acquisition_rounds
                            AND next.phase = 'HUMAN_REVIEW'
                            AND EXISTS (
                                SELECT 1
                                FROM m4_hearing_human_review_receipts AS human
                                WHERE human.run_id = NEW.run_id
                                  AND human.receipt_id = NEW.human_review_receipt_id
                                  AND human.receipt_sha256
                                      = next.human_review_receipt_sha256
                                  AND human.reason = 'ACQUISITION_LIMIT_EXHAUSTED'
                                  AND human.acquisition_model_request_id = NEW.request_id
                                  AND human.source_checkpoint_id
                                      = NEW.source_checkpoint_id
                                  AND human.source_checkpoint_sha256
                                      = NEW.source_checkpoint_sha256
                                  AND human.source_checkpoint_version
                                      = NEW.source_checkpoint_version
                            ))
                       ))
                  )
            )
        )
        OR
        (
            NEW.outcome_kind = 'FAILURE'
            AND NEW.next_retry_generation = CASE
                WHEN NEW.next_status = 'PENDING'
                 AND NEW.strict_parse_failure_proof_id IS NOT NULL
                    THEN NEW.retry_generation + 1
                ELSE NEW.retry_generation
            END
            AND (
                (NEW.reason_code = 'MODEL_OUTPUT_INVALID'
                 AND NEW.strict_parse_failure_proof_id IS NOT NULL
                 AND json_extract(NEW.response_refs_json, '$[0].kind') = 'MODEL_RESPONSE'
                 AND json_extract(NEW.response_refs_json, '$[1].kind') = 'MODEL_RESPONSE'
                 AND json_extract(NEW.response_refs_json, '$[0].artifact_id')
                     < json_extract(NEW.response_refs_json, '$[1].artifact_id')
                 AND EXISTS (
                     SELECT 1
                     FROM m4_hearing_strict_parse_failure_proofs AS proof
                     JOIN m4_hearing_strict_parse_failure_attempts AS primary_attempt
                       ON primary_attempt.run_id = proof.run_id
                      AND primary_attempt.attempt_id = proof.primary_attempt_id
                     JOIN m4_hearing_strict_parse_failure_attempts AS repair_attempt
                       ON repair_attempt.run_id = proof.run_id
                      AND repair_attempt.attempt_id = proof.repair_attempt_id
                     WHERE proof.run_id = NEW.run_id
                       AND proof.proof_id = NEW.strict_parse_failure_proof_id
                       AND proof.backlog_item_id = NEW.backlog_item_id
                       AND proof.lease_identity_sha256 = NEW.lease_identity_sha256
                       AND proof.retry_generation = NEW.retry_generation
                       AND proof.source_checkpoint_id = NEW.source_checkpoint_id
                       AND proof.source_checkpoint_sha256 = NEW.source_checkpoint_sha256
                       AND proof.source_checkpoint_version = NEW.source_checkpoint_version
                       AND proof.role = NEW.role
                       AND json_extract(NEW.response_refs_json, '$[0].artifact_id')
                           = MIN(
                               primary_attempt.response_id,
                               repair_attempt.response_id
                           )
                       AND json_extract(NEW.response_refs_json, '$[1].artifact_id')
                           = MAX(
                               primary_attempt.response_id,
                               repair_attempt.response_id
                           )
                 ))
                OR
                (NEW.reason_code <> 'MODEL_OUTPUT_INVALID'
                 AND NEW.strict_parse_failure_proof_id IS NULL)
            )
            AND (
                (NEW.next_status = 'PENDING' AND NEW.human_review_receipt_id IS NULL)
                OR
                (NEW.next_status = 'EXHAUSTED'
                 AND EXISTS (
                     SELECT 1 FROM m4_hearing_human_review_receipts AS human
                     WHERE human.run_id = NEW.run_id
                       AND human.receipt_id = NEW.human_review_receipt_id
                       AND human.receipt_sha256 = json_extract(
                           NEW.outcome_json,
                           '$.human_review_receipt.receipt_sha256'
                       )
                       AND human.reason = 'HEARING_BACKLOG_EXHAUSTED'
                       AND human.backlog_item_id = NEW.backlog_item_id
                       AND human.source_checkpoint_id = NEW.source_checkpoint_id
                       AND human.source_checkpoint_sha256 = NEW.source_checkpoint_sha256
                       AND human.source_checkpoint_version = NEW.source_checkpoint_version
                 ))
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing backlog retry outcome authority is invalid');
END;

CREATE TRIGGER m4_backlog_completion_receipts_validate_authority
BEFORE INSERT ON m4_backlog_completion_receipts
WHEN NOT (
    json_extract(NEW.receipt_json, '$.receipt_id') = NEW.receipt_id
    AND json_extract(NEW.receipt_json, '$.receipt_sha256') = NEW.receipt_sha256
    AND json_extract(NEW.receipt_json, '$.completion_case_status')
        = NEW.completion_case_status
    AND EXISTS (
        SELECT 1
        FROM m4_hearing_backlog_retry_outcomes AS outcome
        WHERE outcome.run_id = NEW.run_id
          AND outcome.outcome_id = NEW.outcome_id
          AND outcome.outcome_kind = NEW.outcome_kind
          AND outcome.backlog_item_id = NEW.item_id
          AND outcome.hearing_id = NEW.hearing_id
          AND outcome.case_id = NEW.case_id
          AND outcome.role = NEW.role
          AND outcome.lease_identity_sha256 = NEW.lease_identity_sha256
          AND outcome.lease_id = NEW.lease_id
          AND outcome.lease_attempt_count = NEW.attempt_count
          AND outcome.retry_generation = NEW.retry_generation
          AND outcome.source_checkpoint_id = NEW.source_checkpoint_id
          AND outcome.source_checkpoint_sha256 = NEW.source_checkpoint_sha256
          AND outcome.source_checkpoint_version = NEW.source_checkpoint_version
          AND outcome.manifest_id = NEW.manifest_id
          AND (
              (outcome.outcome_kind = 'SUCCESS'
               AND NEW.backlog_status = 'COMPLETED'
               AND NEW.resulting_checkpoint_id = outcome.next_checkpoint_id
               AND NEW.resulting_checkpoint_sha256 = outcome.next_checkpoint_sha256
               AND NEW.resulting_checkpoint_version = outcome.next_checkpoint_version
               AND NEW.completion_case_status = CASE
                   WHEN EXISTS (
                       SELECT 1
                       FROM m4_hearing_checkpoints AS next
                       WHERE next.run_id = outcome.run_id
                         AND next.checkpoint_id = outcome.next_checkpoint_id
                         AND next.phase = 'HUMAN_REVIEW'
                   ) THEN 'HUMAN_REVIEW'
                   ELSE 'DELIBERATING'
               END)
              OR
              (outcome.outcome_kind = 'FAILURE'
               AND NEW.backlog_status = outcome.next_status
               AND NEW.completion_case_status = CASE
                   WHEN outcome.next_status = 'PENDING' THEN 'BACKLOGGED'
                   ELSE 'HUMAN_REVIEW'
               END
               AND NEW.resulting_checkpoint_id = NEW.source_checkpoint_id
               AND NEW.resulting_checkpoint_sha256 = NEW.source_checkpoint_sha256
               AND NEW.resulting_checkpoint_version = NEW.source_checkpoint_version)
          )
    )
    AND EXISTS (
        SELECT 1
        FROM backlog_item_versions AS leased
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
          AND completed.retry_generation = (
              SELECT outcome.next_retry_generation
              FROM m4_hearing_backlog_retry_outcomes AS outcome
              WHERE outcome.run_id = NEW.run_id
                AND outcome.outcome_id = NEW.outcome_id
          )
          AND completed.lease_id IS NULL
          AND completed.lease_owner_sha256 IS NULL
          AND completed.lease_expires_at IS NULL
    )
    AND EXISTS (
        SELECT 1
        FROM case_versions AS version
        JOIN audit_entries AS audit
          ON audit.run_id = version.run_id
         AND audit.sequence = version.audit_sequence
        WHERE version.run_id = NEW.run_id
          AND version.case_id = NEW.case_id
          AND version.revision = NEW.completion_case_revision
          AND version.audit_sequence = NEW.completion_audit_sequence
          AND audit.entry_hash = NEW.completion_audit_entry_hash
          AND audit.manifest_id = NEW.manifest_id
          AND audit.object_kind = 'BACKLOG_ITEM'
          AND audit.object_id = NEW.item_id
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 backlog completion receipt authority is invalid');
END;

CREATE TRIGGER m4_model_call_failure_authorities_validate
BEFORE INSERT ON m4_model_call_failure_authorities
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_model_call_claims AS claim
        WHERE claim.run_id = NEW.run_id
          AND claim.request_id = NEW.request_id
          AND claim.request_sha256 = NEW.request_sha256
          AND claim.cache_key = NEW.cache_key
          AND claim.hearing_id = NEW.hearing_id
          AND claim.cycle_scope_id = NEW.cycle_scope_id
          AND claim.cycle_scope_sha256 = NEW.cycle_scope_sha256
          AND claim.case_id = NEW.case_id
          AND claim.role = NEW.role
          AND claim.owner_token_sha256 = NEW.claim_owner_sha256
          AND claim.lease_expires_at = NEW.claim_lease_expires_at
          AND claim.takeover_count = NEW.claim_takeover_count
          AND claim.reserved_images = NEW.reserved_images
          AND claim.reserved_pixels = NEW.reserved_pixels
          AND claim.status = 'ACTIVE'
          AND claim.response_id IS NULL
    )
    AND EXISTS (
        SELECT 1
        FROM backlog_items AS item
        JOIN backlog_item_versions AS version
          ON version.run_id = item.run_id
         AND version.item_id = item.item_id
        JOIN backlog_heads AS head
          ON head.run_id = version.run_id
         AND head.item_id = version.item_id
         AND head.current_version = version.version
        WHERE item.run_id = NEW.run_id
          AND item.item_id = NEW.backlog_item_id
          AND item.case_id = NEW.case_id
          AND item.stage = 'HEARING'
          AND item.role = NEW.role
          AND version.version = NEW.backlog_version
          AND version.status = NEW.backlog_status
          AND version.retry_generation = NEW.retry_generation
          AND version.attempt_count = NEW.backlog_attempt_count
    )
    AND (
        (NEW.closure_kind = 'INITIAL_BACKLOG'
         AND NEW.completion_receipt_id IS NULL
         AND EXISTS (
             SELECT 1 FROM m4_model_call_claims AS claim
             WHERE claim.run_id = NEW.run_id
               AND claim.request_id = NEW.request_id
               AND claim.call_generation = 'INITIAL'
               AND claim.backlog_item_id IS NULL
         ))
        OR
        (NEW.closure_kind = 'RETRY_FAILURE'
         AND EXISTS (
             SELECT 1
             FROM m4_model_call_claims AS claim
             WHERE claim.run_id = NEW.run_id
               AND claim.request_id = NEW.request_id
               AND (
                   (NEW.retry_generation = 0
                    AND claim.call_generation = 'INITIAL'
                    AND claim.backlog_item_id IS NULL
                    AND claim.retry_generation = 0)
                   OR
                   (NEW.retry_generation > 0
                    AND claim.call_generation = 'BACKLOG'
                    AND claim.backlog_item_id = NEW.backlog_item_id
                    AND claim.retry_generation = NEW.retry_generation)
               )
         )
         AND EXISTS (
             SELECT 1 FROM m4_backlog_completion_receipts AS receipt
             JOIN m4_hearing_backlog_retry_outcomes AS outcome
               ON outcome.run_id = receipt.run_id
              AND outcome.outcome_id = receipt.outcome_id
             WHERE receipt.run_id = NEW.run_id
               AND receipt.receipt_id = NEW.completion_receipt_id
               AND receipt.item_id = NEW.backlog_item_id
               AND receipt.case_id = NEW.case_id
               AND receipt.outcome_kind = 'FAILURE'
               AND receipt.backlog_version = NEW.backlog_version
               AND receipt.lease_identity_sha256 = NEW.lease_identity_sha256
               AND receipt.lease_id = NEW.lease_id
               AND receipt.attempt_count = NEW.backlog_attempt_count
               AND receipt.retry_generation = NEW.retry_generation
               AND receipt.completion_case_revision = NEW.closure_case_revision
               AND receipt.completion_audit_sequence = NEW.closure_audit_sequence
               AND receipt.completion_audit_entry_hash = NEW.closure_audit_entry_hash
               AND outcome.request_id = NEW.request_id
               AND outcome.source_checkpoint_id = NEW.source_checkpoint_id
               AND outcome.source_checkpoint_sha256 = NEW.source_checkpoint_sha256
               AND outcome.source_checkpoint_version = NEW.source_checkpoint_version
         ))
    )
    AND (
        (NEW.failure_code IN ('FIXTURE_MISSING', 'PROVIDER_OUTAGE', 'PROVIDER_TIMEOUT')
         AND NEW.backlog_reason_code = 'PROVIDER_UNAVAILABLE')
        OR
        (NEW.failure_code IN (
             'RESPONSE_TOO_LARGE', 'RESPONSE_TOKEN_BUDGET_EXCEEDED',
             'RESPONSE_COST_BUDGET_EXCEEDED'
         ) AND NEW.backlog_reason_code = 'BUDGET_EXCEEDED')
        OR
        (NEW.failure_code IN (
             'REQUEST_IDENTITY_MISMATCH', 'PROMPT_MISSING',
             'PROMPT_INTEGRITY_FAILURE', 'MEDIA_POLICY_REJECTED',
             'MEDIA_INTEGRITY_FAILURE', 'RESPONSE_ENVELOPE_INVALID',
             'RESPONSE_PERSISTENCE_FAILURE'
         ) AND NEW.backlog_reason_code = 'RESPONSE_INTEGRITY_FAILURE')
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 model call failure authority is invalid');
END;

CREATE TRIGGER m4_hearing_human_review_receipts_validate_authority
BEFORE INSERT ON m4_hearing_human_review_receipts
WHEN NOT (
    json_extract(NEW.receipt_json, '$.receipt_id') = NEW.receipt_id
    AND json_extract(NEW.receipt_json, '$.receipt_sha256') = NEW.receipt_sha256
    AND EXISTS (
        SELECT 1
        FROM m4_hearing_checkpoints AS source
        WHERE source.run_id = NEW.run_id
          AND source.checkpoint_id = NEW.source_checkpoint_id
          AND source.checkpoint_sha256 = NEW.source_checkpoint_sha256
          AND source.version = NEW.source_checkpoint_version
          AND source.hearing_id = NEW.hearing_id
          AND source.case_id = NEW.case_id
          AND source.current_pack_id = NEW.current_pack_id
          AND source.current_pack_version = NEW.current_pack_version
          AND source.judge_cycle = NEW.judge_cycle
          AND source.manifest_id = NEW.manifest_id
          AND source.phase NOT IN ('COMPLETE', 'HUMAN_REVIEW')
    )
    AND (
        NEW.procedural_review_id IS NULL
        OR EXISTS (
            SELECT 1 FROM procedural_reviews AS review
            WHERE review.run_id = NEW.run_id
              AND review.review_id = NEW.procedural_review_id
              AND review.case_id = NEW.case_id
              AND review.evidence_pack_id = NEW.current_pack_id
              AND review.evidence_pack_version = NEW.current_pack_version
        )
    )
    AND (
        NEW.backlog_item_id IS NULL
        OR EXISTS (
            SELECT 1 FROM backlog_items AS item
            WHERE item.run_id = NEW.run_id
              AND item.item_id = NEW.backlog_item_id
              AND item.case_id = NEW.case_id
              AND item.stage = 'HEARING'
              AND item.manifest_id = NEW.manifest_id
        )
    )
    AND (
        NEW.acquisition_model_request_id IS NULL
        OR EXISTS (
            SELECT 1
            FROM m4_model_call_claims AS request
            JOIN m4_hearing_checkpoints AS source
              ON source.run_id = request.run_id
             AND source.checkpoint_id = NEW.source_checkpoint_id
            WHERE request.run_id = NEW.run_id
              AND request.request_id = NEW.acquisition_model_request_id
              AND request.hearing_id = NEW.hearing_id
              AND request.case_id = NEW.case_id
              AND request.cycle_scope_id = source.cycle_scope_id
              AND request.role = 'JUDGE'
              AND request.manifest_id = NEW.manifest_id
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing human-review authority is invalid');
END;

CREATE TRIGGER m4_hearing_checkpoints_validate_transition
BEFORE INSERT ON m4_hearing_checkpoints
WHEN NOT (
    EXISTS (
        SELECT 1
        FROM m4_hearings AS hearing
        JOIN m4_hearing_cycles AS cycle
          ON cycle.run_id = hearing.run_id
         AND cycle.hearing_id = hearing.hearing_id
        WHERE hearing.run_id = NEW.run_id
          AND hearing.hearing_id = NEW.hearing_id
          AND hearing.document_sha256 = NEW.hearing_sha256
          AND hearing.case_id = NEW.case_id
          AND hearing.manifest_id = NEW.manifest_id
          AND cycle.cycle_id = NEW.cycle_scope_id
          AND cycle.cycle_sha256 = NEW.cycle_scope_sha256
          AND cycle.case_id = NEW.case_id
          AND cycle.cycle_index = NEW.judge_cycle
          AND cycle.prior_acquisition_rounds = NEW.prior_acquisition_rounds
          AND cycle.prior_rework_rounds = NEW.prior_rework_rounds
          AND cycle.cycle_pack_id = NEW.cycle_pack_id
          AND cycle.cycle_pack_version = NEW.cycle_pack_version
          AND cycle.manifest_id = NEW.manifest_id
          AND NEW.initial_trigger_review_id IS cycle.initial_trigger_review_id
          AND json(NEW.initial_defect_codes_json)
              = json(cycle.initial_defect_codes_json)
          AND NEW.cycle_trigger_review_id IS cycle.rework_review_id
          AND json(NEW.cycle_trigger_defect_codes_json)
              = json(cycle.rework_defect_codes_json)
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.cycle_trigger_defect_codes_json) AS defect
        WHERE defect.type <> 'text'
           OR defect.value NOT IN (
               'MALFORMED_STRUCTURE', 'INVALID_ENUM', 'MISSING_REQUIRED_FIELD',
               'FABRICATED_EVIDENCE_REFERENCE', 'INVALID_COORDINATES',
               'FABRICATED_PRECEDENT_REFERENCE', 'PRECEDENT_DIRECTION_MISMATCH',
               'EMPTY_DISTINGUISHING_REASON', 'ESTABLISHED_WITHOUT_EVIDENCE',
               'UNANSWERED_DEFENSE_POINT', 'CONFIDENCE_ALERT_LEVEL_MISMATCH',
               'OBJECTIVE_ASSERTION_CONTRADICTION', 'VIOLATION_TYPE_MISMATCH',
               'ABSENCE_FROM_INSUFFICIENT_OBSERVATION'
           )
           OR EXISTS (
               SELECT 1
               FROM json_each(NEW.cycle_trigger_defect_codes_json) AS earlier
               WHERE CAST(earlier.key AS INTEGER) < CAST(defect.key AS INTEGER)
                 AND instr(
                     '|MALFORMED_STRUCTURE|INVALID_ENUM|MISSING_REQUIRED_FIELD|FABRICATED_EVIDENCE_REFERENCE|INVALID_COORDINATES|FABRICATED_PRECEDENT_REFERENCE|PRECEDENT_DIRECTION_MISMATCH|EMPTY_DISTINGUISHING_REASON|ESTABLISHED_WITHOUT_EVIDENCE|UNANSWERED_DEFENSE_POINT|CONFIDENCE_ALERT_LEVEL_MISMATCH|OBJECTIVE_ASSERTION_CONTRADICTION|VIOLATION_TYPE_MISMATCH|ABSENCE_FROM_INSUFFICIENT_OBSERVATION|',
                     '|' || earlier.value || '|'
                 ) >= instr(
                     '|MALFORMED_STRUCTURE|INVALID_ENUM|MISSING_REQUIRED_FIELD|FABRICATED_EVIDENCE_REFERENCE|INVALID_COORDINATES|FABRICATED_PRECEDENT_REFERENCE|PRECEDENT_DIRECTION_MISMATCH|EMPTY_DISTINGUISHING_REASON|ESTABLISHED_WITHOUT_EVIDENCE|UNANSWERED_DEFENSE_POINT|CONFIDENCE_ALERT_LEVEL_MISMATCH|OBJECTIVE_ASSERTION_CONTRADICTION|VIOLATION_TYPE_MISMATCH|ABSENCE_FROM_INSUFFICIENT_OBSERVATION|',
                     '|' || defect.value || '|'
                 )
           )
    )
    AND (
        (
            NEW.version = 1
            AND NEW.phase = 'PRECEDENT_RETRIEVAL_PENDING'
            AND NEW.judge_cycle = 1
            AND NEW.prior_acquisition_rounds = 0
            AND NEW.prior_rework_rounds = 0
            AND EXISTS (
                SELECT 1 FROM m4_hearings AS hearing
                WHERE hearing.run_id = NEW.run_id
                  AND hearing.hearing_id = NEW.hearing_id
                  AND hearing.initial_pack_id = NEW.cycle_pack_id
                  AND hearing.initial_pack_version = NEW.cycle_pack_version
            )
        )
        OR
        (
            NEW.version > 1
            AND EXISTS (
                SELECT 1
                FROM m4_hearing_checkpoints AS previous
                WHERE previous.run_id = NEW.run_id
                  AND previous.checkpoint_id = NEW.previous_checkpoint_id
                  AND previous.checkpoint_sha256 = NEW.previous_checkpoint_sha256
                  AND previous.version = NEW.version - 1
                  AND previous.phase = NEW.previous_phase
                  AND previous.hearing_id = NEW.hearing_id
                  AND previous.hearing_sha256 = NEW.hearing_sha256
                  AND previous.case_id = NEW.case_id
                  AND previous.manifest_id = NEW.manifest_id
                  AND (
                      (previous.phase = 'PRECEDENT_RETRIEVAL_PENDING'
                       AND NEW.phase IN ('PROSECUTOR_PENDING', 'HUMAN_REVIEW'))
                      OR
                      (previous.phase = 'PROSECUTOR_PENDING'
                       AND NEW.phase IN ('DEFENDER_PENDING', 'HUMAN_REVIEW'))
                      OR
                      (previous.phase = 'DEFENDER_PENDING'
                       AND NEW.phase IN ('JUDGE_PENDING', 'HUMAN_REVIEW'))
                      OR
                      (previous.phase = 'JUDGE_PENDING'
                       AND NEW.phase IN (
                           'ACQUISITION_PENDING', 'ROUND_COMPLETE', 'HUMAN_REVIEW'
                       ))
                      OR
                      (previous.phase = 'ACQUISITION_PENDING'
                       AND NEW.phase IN ('ROUND_COMPLETE', 'HUMAN_REVIEW'))
                      OR
                      (previous.phase = 'ROUND_COMPLETE'
                       AND NEW.phase IN (
                           'PRECEDENT_RETRIEVAL_PENDING', 'REWORK_READY',
                           'COMPLETE', 'HUMAN_REVIEW'
                       ))
                      OR
                      (previous.phase = 'REWORK_READY'
                       AND NEW.phase IN ('PRECEDENT_RETRIEVAL_PENDING', 'HUMAN_REVIEW'))
                  )
                  AND (
                      (
                          NEW.phase = 'PRECEDENT_RETRIEVAL_PENDING'
                          AND (
                              (
                                  previous.phase = 'ROUND_COMPLETE'
                                  AND previous.acquisition_request_id IS NOT NULL
                                  AND previous.tool_receipt_id IS NOT NULL
                                  AND NEW.prior_acquisition_rounds
                                      = previous.prior_acquisition_rounds + 1
                                  AND NEW.prior_rework_rounds
                                      = previous.prior_rework_rounds
                                  AND EXISTS (
                                      SELECT 1
                                      FROM m4_parsed_hearing_outputs AS judge
                                      JOIN m4_evidence_pack_derivations AS derivation
                                        ON derivation.run_id = judge.run_id
                                       AND derivation.hearing_id = judge.hearing_id
                                       AND derivation.source_cycle_scope_id
                                           = judge.cycle_scope_id
                                       AND derivation.source_cycle_scope_sha256
                                           = judge.cycle_scope_sha256
                                      WHERE judge.run_id = previous.run_id
                                        AND judge.parsed_output_id = previous.judge_output_id
                                        AND judge.payload_kind = 'JUDGE_ACQUISITION'
                                        AND derivation.tool_receipt_id = previous.tool_receipt_id
                                        AND derivation.previous_pack_id
                                            = previous.cycle_pack_id
                                        AND derivation.previous_pack_version
                                            = previous.cycle_pack_version
                                        AND derivation.new_pack_id = previous.current_pack_id
                                        AND derivation.new_pack_version
                                            = previous.current_pack_version
                                  )
                              )
                              OR
                              (
                                  previous.phase = 'REWORK_READY'
                                  AND NEW.prior_acquisition_rounds
                                      = previous.prior_acquisition_rounds
                                  AND NEW.prior_rework_rounds
                                      = previous.prior_rework_rounds + 1
                                  AND EXISTS (
                                      SELECT 1 FROM procedural_reviews AS review
                                      WHERE review.run_id = previous.run_id
                                        AND review.review_id
                                            = previous.procedural_review_id
                                        AND review.passed = 0
                                  )
                              )
                          )
                          AND NEW.cycle_pack_id = previous.current_pack_id
                          AND NEW.cycle_pack_version = previous.current_pack_version
                          AND NEW.current_pack_id = NEW.cycle_pack_id
                          AND NEW.current_pack_version = NEW.cycle_pack_version
                          AND NEW.cycle_scope_id <> previous.cycle_scope_id
                      )
                      OR
                      (
                          NEW.phase <> 'PRECEDENT_RETRIEVAL_PENDING'
                          AND NEW.prior_acquisition_rounds
                              = previous.prior_acquisition_rounds
                          AND NEW.prior_rework_rounds = previous.prior_rework_rounds
                          AND NEW.cycle_pack_id = previous.cycle_pack_id
                          AND NEW.cycle_pack_version = previous.cycle_pack_version
                          AND NEW.cycle_scope_id = previous.cycle_scope_id
                          AND NEW.cycle_scope_sha256
                              = previous.cycle_scope_sha256
                          AND (
                              NEW.phase = 'ROUND_COMPLETE'
                              OR (
                                  NEW.current_pack_id = previous.current_pack_id
                                  AND NEW.current_pack_version = previous.current_pack_version
                              )
                          )
                      )
                  )
                  AND (
                      NEW.phase <> 'HUMAN_REVIEW'
                      OR (
                          (
                              NEW.retrieval_receipt_id IS previous.retrieval_receipt_id
                              AND NEW.retrieval_receipt_sha256
                                  IS previous.retrieval_receipt_sha256
                              AND NEW.prosecutor_output_id IS previous.prosecutor_output_id
                              AND NEW.defender_output_id IS previous.defender_output_id
                              AND NEW.judge_output_id IS previous.judge_output_id
                              AND NEW.acquisition_request_id
                                  IS previous.acquisition_request_id
                              AND NEW.tool_receipt_id IS previous.tool_receipt_id
                              AND NEW.procedural_review_id
                                  IS previous.procedural_review_id
                          )
                          OR
                          (
                              previous.phase = 'JUDGE_PENDING'
                              AND NEW.retrieval_receipt_id
                                  = previous.retrieval_receipt_id
                              AND NEW.retrieval_receipt_sha256
                                  = previous.retrieval_receipt_sha256
                              AND NEW.prosecutor_output_id
                                  = previous.prosecutor_output_id
                              AND NEW.defender_output_id
                                  = previous.defender_output_id
                              AND previous.judge_output_id IS NULL
                              AND NEW.judge_output_id IS NOT NULL
                              AND NEW.acquisition_request_id IS NULL
                              AND NEW.tool_receipt_id IS NULL
                              AND NEW.procedural_review_id IS NULL
                              AND EXISTS (
                                  SELECT 1
                                  FROM m4_parsed_hearing_outputs AS judge
                                  JOIN m4_hearing_human_review_receipts AS human
                                    ON human.run_id = judge.run_id
                                   AND human.receipt_id
                                       = NEW.human_review_receipt_id
                                  WHERE judge.run_id = NEW.run_id
                                    AND judge.parsed_output_id
                                        = NEW.judge_output_id
                                    AND judge.role = 'JUDGE'
                                    AND judge.payload_kind = 'JUDGE_ACQUISITION'
                                    AND human.reason
                                        = 'ACQUISITION_LIMIT_EXHAUSTED'
                                    AND human.acquisition_model_request_id
                                        = judge.request_id
                              )
                          )
                      )
                  )
            )
        )
    )
    AND (
        NEW.phase NOT IN ('REWORK_READY', 'COMPLETE')
        OR EXISTS (
            SELECT 1 FROM procedural_reviews AS review
            WHERE review.run_id = NEW.run_id
              AND review.review_id = NEW.procedural_review_id
              AND review.case_id = NEW.case_id
              AND review.passed = CASE WHEN NEW.phase = 'COMPLETE' THEN 1 ELSE 0 END
        )
    )
    AND (
        NEW.phase <> 'HUMAN_REVIEW'
        OR EXISTS (
            SELECT 1 FROM m4_hearing_human_review_receipts AS receipt
            WHERE receipt.run_id = NEW.run_id
              AND receipt.receipt_id = NEW.human_review_receipt_id
              AND receipt.receipt_sha256 = NEW.human_review_receipt_sha256
              AND receipt.reason = NEW.human_review_reason
              AND receipt.hearing_id = NEW.hearing_id
              AND receipt.case_id = NEW.case_id
              AND receipt.current_pack_id = NEW.current_pack_id
              AND receipt.current_pack_version = NEW.current_pack_version
              AND receipt.judge_cycle = NEW.judge_cycle
              AND receipt.source_checkpoint_id = NEW.previous_checkpoint_id
              AND receipt.source_checkpoint_sha256 = NEW.previous_checkpoint_sha256
              AND receipt.source_checkpoint_version = NEW.version - 1
              AND receipt.manifest_id = NEW.manifest_id
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing checkpoint transition is invalid');
END;

CREATE TRIGGER m4_hearing_checkpoints_validate_artifacts
BEFORE INSERT ON m4_hearing_checkpoints
WHEN NOT (
    (
        NEW.retrieval_receipt_id IS NULL
        OR EXISTS (
            SELECT 1 FROM m4_precedent_retrieval_receipts AS retrieval
            WHERE retrieval.run_id = NEW.run_id
              AND retrieval.retrieval_receipt_id = NEW.retrieval_receipt_id
              AND retrieval.document_sha256 = NEW.retrieval_receipt_sha256
              AND retrieval.hearing_id = NEW.hearing_id
              AND retrieval.cycle_scope_id = NEW.cycle_scope_id
              AND retrieval.cycle_scope_sha256 = NEW.cycle_scope_sha256
              AND retrieval.case_id = NEW.case_id
              AND retrieval.prior_acquisition_rounds = NEW.prior_acquisition_rounds
              AND retrieval.prior_rework_rounds = NEW.prior_rework_rounds
              AND retrieval.current_pack_id = NEW.cycle_pack_id
              AND retrieval.current_pack_version = NEW.cycle_pack_version
              AND retrieval.initial_trigger_review_id IS NEW.initial_trigger_review_id
              AND json(retrieval.initial_defect_codes_json)
                  = json(NEW.initial_defect_codes_json)
              AND retrieval.rework_review_id IS NEW.cycle_trigger_review_id
              AND json(retrieval.rework_defect_codes_json)
                  = json(NEW.cycle_trigger_defect_codes_json)
              AND retrieval.manifest_id = NEW.manifest_id
        )
    )
    AND (
        NEW.prosecutor_output_id IS NULL
        OR EXISTS (
            SELECT 1 FROM m4_parsed_hearing_outputs AS output
            WHERE output.run_id = NEW.run_id
              AND output.parsed_output_id = NEW.prosecutor_output_id
              AND output.hearing_id = NEW.hearing_id
              AND output.cycle_scope_id = NEW.cycle_scope_id
              AND output.cycle_scope_sha256 = NEW.cycle_scope_sha256
              AND output.case_id = NEW.case_id
              AND output.role = 'PROSECUTOR'
              AND output.prior_acquisition_rounds = NEW.prior_acquisition_rounds
              AND output.prior_rework_rounds = NEW.prior_rework_rounds
              AND output.current_pack_id = NEW.cycle_pack_id
              AND output.current_pack_version = NEW.cycle_pack_version
              AND output.initial_trigger_review_id IS NEW.initial_trigger_review_id
              AND json(output.initial_defect_codes_json)
                  = json(NEW.initial_defect_codes_json)
              AND output.rework_review_id IS NEW.cycle_trigger_review_id
              AND json(output.rework_defect_codes_json)
                  = json(NEW.cycle_trigger_defect_codes_json)
              AND output.manifest_id = NEW.manifest_id
        )
    )
    AND (
        NEW.defender_output_id IS NULL
        OR EXISTS (
            SELECT 1 FROM m4_parsed_hearing_outputs AS output
            WHERE output.run_id = NEW.run_id
              AND output.parsed_output_id = NEW.defender_output_id
              AND output.hearing_id = NEW.hearing_id
              AND output.cycle_scope_id = NEW.cycle_scope_id
              AND output.cycle_scope_sha256 = NEW.cycle_scope_sha256
              AND output.case_id = NEW.case_id
              AND output.role = 'DEFENDER'
              AND output.prior_acquisition_rounds = NEW.prior_acquisition_rounds
              AND output.prior_rework_rounds = NEW.prior_rework_rounds
              AND output.current_pack_id = NEW.cycle_pack_id
              AND output.current_pack_version = NEW.cycle_pack_version
              AND output.initial_trigger_review_id IS NEW.initial_trigger_review_id
              AND json(output.initial_defect_codes_json)
                  = json(NEW.initial_defect_codes_json)
              AND output.rework_review_id IS NEW.cycle_trigger_review_id
              AND json(output.rework_defect_codes_json)
                  = json(NEW.cycle_trigger_defect_codes_json)
              AND output.manifest_id = NEW.manifest_id
        )
    )
    AND (
        NEW.judge_output_id IS NULL
        OR EXISTS (
            SELECT 1 FROM m4_parsed_hearing_outputs AS output
            WHERE output.run_id = NEW.run_id
              AND output.parsed_output_id = NEW.judge_output_id
              AND output.hearing_id = NEW.hearing_id
              AND output.cycle_scope_id = NEW.cycle_scope_id
              AND output.cycle_scope_sha256 = NEW.cycle_scope_sha256
              AND output.case_id = NEW.case_id
              AND output.role = 'JUDGE'
              AND output.prior_acquisition_rounds = NEW.prior_acquisition_rounds
              AND output.prior_rework_rounds = NEW.prior_rework_rounds
              AND output.current_pack_id = NEW.cycle_pack_id
              AND output.current_pack_version = NEW.cycle_pack_version
              AND output.initial_trigger_review_id IS NEW.initial_trigger_review_id
              AND json(output.initial_defect_codes_json)
                  = json(NEW.initial_defect_codes_json)
              AND output.rework_review_id IS NEW.cycle_trigger_review_id
              AND json(output.rework_defect_codes_json)
                  = json(NEW.cycle_trigger_defect_codes_json)
              AND output.manifest_id = NEW.manifest_id
        )
    )
    AND (
        NEW.acquisition_request_id IS NULL
        OR EXISTS (
            SELECT 1 FROM m4_acquisition_requests AS request
            WHERE request.run_id = NEW.run_id
              AND request.acquisition_request_id = NEW.acquisition_request_id
              AND request.hearing_id = NEW.hearing_id
              AND request.cycle_scope_id = NEW.cycle_scope_id
              AND request.cycle_scope_sha256 = NEW.cycle_scope_sha256
              AND request.case_id = NEW.case_id
              AND request.judge_output_id = NEW.judge_output_id
        )
    )
    AND (
        NEW.tool_receipt_id IS NULL
        OR EXISTS (
            SELECT 1 FROM m4_tool_execution_receipts AS result
            WHERE result.run_id = NEW.run_id
              AND result.receipt_id = NEW.tool_receipt_id
              AND result.acquisition_request_id = NEW.acquisition_request_id
              AND result.hearing_id = NEW.hearing_id
              AND result.cycle_scope_id = NEW.cycle_scope_id
              AND result.case_id = NEW.case_id
        )
    )
    AND (
        NEW.procedural_review_id IS NULL
        OR EXISTS (
            SELECT 1 FROM procedural_reviews AS review
            WHERE review.run_id = NEW.run_id
              AND review.review_id = NEW.procedural_review_id
              AND review.case_id = NEW.case_id
              AND review.evidence_pack_id = NEW.current_pack_id
              AND review.evidence_pack_version = NEW.current_pack_version
        )
    )
    AND (
        (NEW.tool_receipt_id IS NULL
         AND NEW.current_pack_id = NEW.cycle_pack_id
         AND NEW.current_pack_version = NEW.cycle_pack_version)
        OR
        (NEW.tool_receipt_id IS NOT NULL
         AND EXISTS (
             SELECT 1 FROM m4_evidence_pack_derivations AS derivation
             WHERE derivation.run_id = NEW.run_id
               AND derivation.hearing_id = NEW.hearing_id
               AND derivation.source_cycle_scope_id = NEW.cycle_scope_id
               AND derivation.source_cycle_scope_sha256
                   = NEW.cycle_scope_sha256
               AND derivation.tool_receipt_id = NEW.tool_receipt_id
               AND derivation.previous_pack_id = NEW.cycle_pack_id
               AND derivation.previous_pack_version = NEW.cycle_pack_version
               AND derivation.new_pack_id = NEW.current_pack_id
               AND derivation.new_pack_version = NEW.current_pack_version
         ))
    )
    AND (
        (NEW.phase = 'PRECEDENT_RETRIEVAL_PENDING'
         AND NEW.retrieval_receipt_id IS NULL
         AND NEW.prosecutor_output_id IS NULL
         AND NEW.defender_output_id IS NULL
         AND NEW.judge_output_id IS NULL
         AND NEW.acquisition_request_id IS NULL
         AND NEW.tool_receipt_id IS NULL
         AND NEW.procedural_review_id IS NULL)
        OR
        (NEW.phase = 'PROSECUTOR_PENDING'
         AND NEW.retrieval_receipt_id IS NOT NULL
         AND NEW.prosecutor_output_id IS NULL
         AND NEW.defender_output_id IS NULL
         AND NEW.judge_output_id IS NULL
         AND NEW.acquisition_request_id IS NULL
         AND NEW.tool_receipt_id IS NULL
         AND NEW.procedural_review_id IS NULL)
        OR
        (NEW.phase = 'DEFENDER_PENDING'
         AND NEW.retrieval_receipt_id IS NOT NULL
         AND NEW.prosecutor_output_id IS NOT NULL
         AND NEW.defender_output_id IS NULL
         AND NEW.judge_output_id IS NULL
         AND NEW.acquisition_request_id IS NULL
         AND NEW.tool_receipt_id IS NULL
         AND NEW.procedural_review_id IS NULL)
        OR
        (NEW.phase = 'JUDGE_PENDING'
         AND NEW.retrieval_receipt_id IS NOT NULL
         AND NEW.prosecutor_output_id IS NOT NULL
         AND NEW.defender_output_id IS NOT NULL
         AND NEW.judge_output_id IS NULL
         AND NEW.acquisition_request_id IS NULL
         AND NEW.tool_receipt_id IS NULL
         AND NEW.procedural_review_id IS NULL)
        OR
        (NEW.phase = 'ACQUISITION_PENDING'
         AND NEW.retrieval_receipt_id IS NOT NULL
         AND NEW.prosecutor_output_id IS NOT NULL
         AND NEW.defender_output_id IS NOT NULL
         AND NEW.judge_output_id IS NOT NULL
         AND NEW.acquisition_request_id IS NOT NULL
         AND NEW.tool_receipt_id IS NULL
         AND NEW.procedural_review_id IS NULL)
        OR
        (NEW.phase = 'ROUND_COMPLETE'
         AND NEW.retrieval_receipt_id IS NOT NULL
         AND NEW.prosecutor_output_id IS NOT NULL
         AND NEW.defender_output_id IS NOT NULL
         AND NEW.judge_output_id IS NOT NULL
         AND ((NEW.acquisition_request_id IS NULL AND NEW.tool_receipt_id IS NULL)
              OR (NEW.acquisition_request_id IS NOT NULL AND NEW.tool_receipt_id IS NOT NULL))
         AND NEW.procedural_review_id IS NULL)
        OR
        (NEW.phase IN ('REWORK_READY', 'COMPLETE')
         AND NEW.retrieval_receipt_id IS NOT NULL
         AND NEW.prosecutor_output_id IS NOT NULL
         AND NEW.defender_output_id IS NOT NULL
         AND NEW.judge_output_id IS NOT NULL
         AND NEW.acquisition_request_id IS NULL
         AND NEW.tool_receipt_id IS NULL
         AND NEW.procedural_review_id IS NOT NULL)
        OR NEW.phase = 'HUMAN_REVIEW'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing checkpoint artifact scope is invalid');
END;

CREATE TRIGGER m4_hearing_checkpoints_validate_trace
BEFORE INSERT ON m4_hearing_checkpoints
WHEN NOT (
    NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.model_request_refs_json) AS request_ref
        WHERE json_extract(request_ref.value, '$.kind') <> 'MODEL_REQUEST'
           OR NOT EXISTS (
               SELECT 1
               FROM m4_model_call_claims AS claim
               JOIN m4_model_responses AS response
                 ON response.run_id = claim.run_id
                AND response.request_id = claim.request_id
                AND response.response_id = claim.response_id
               JOIN m4_model_parse_receipts AS parse
                 ON parse.run_id = response.run_id
                AND parse.request_id = response.request_id
                AND parse.response_id = response.response_id
               JOIN m4_hearing_usage_receipts AS usage
                 ON usage.run_id = response.run_id
                AND usage.request_id = response.request_id
                AND usage.response_id = response.response_id
               WHERE claim.run_id = NEW.run_id
                 AND claim.request_id
                     = json_extract(request_ref.value, '$.artifact_id')
                 AND EXISTS (
                     SELECT 1
                     FROM json_each(NEW.model_response_refs_json) AS response_ref
                     WHERE json_extract(response_ref.value, '$.kind') = 'MODEL_RESPONSE'
                       AND json_extract(response_ref.value, '$.artifact_id')
                           = response.response_id
                 )
                 AND EXISTS (
                     SELECT 1
                     FROM json_each(NEW.parse_receipt_refs_json) AS parse_ref
                     WHERE json_extract(parse_ref.value, '$.kind')
                               = 'MODEL_PARSE_RECEIPT'
                       AND json_extract(parse_ref.value, '$.artifact_id')
                           = parse.parse_receipt_id
                 )
                 AND EXISTS (
                     SELECT 1
                     FROM json_each(NEW.usage_receipt_ids_json) AS usage_ref
                     WHERE usage_ref.type = 'text'
                       AND usage_ref.value = usage.usage_receipt_id
                 )
                 AND claim.status = 'COMPLETED'
                 AND claim.hearing_id = NEW.hearing_id
                 AND claim.cycle_scope_id = NEW.cycle_scope_id
                 AND claim.cycle_scope_sha256 = NEW.cycle_scope_sha256
                 AND claim.case_id = NEW.case_id
                 AND claim.manifest_id = NEW.manifest_id
           )
    )
    AND json_array_length(NEW.model_request_refs_json)
        = json_array_length(NEW.model_response_refs_json)
    AND json_array_length(NEW.model_request_refs_json)
        = json_array_length(NEW.parse_receipt_refs_json)
    AND json_array_length(NEW.model_request_refs_json)
        = json_array_length(NEW.usage_receipt_ids_json)
    AND NOT EXISTS (
        SELECT 1 FROM json_each(NEW.model_response_refs_json) AS ref
        WHERE json_extract(ref.value, '$.kind') <> 'MODEL_RESPONSE'
    )
    AND NOT EXISTS (
        SELECT 1 FROM json_each(NEW.parse_receipt_refs_json) AS ref
        WHERE json_extract(ref.value, '$.kind') <> 'MODEL_PARSE_RECEIPT'
    )
    AND json_array_length(NEW.model_request_refs_json) = (
        SELECT COUNT(DISTINCT json_extract(value, '$.artifact_id'))
        FROM json_each(NEW.model_request_refs_json)
    )
    AND json_array_length(NEW.model_response_refs_json) = (
        SELECT COUNT(DISTINCT json_extract(value, '$.artifact_id'))
        FROM json_each(NEW.model_response_refs_json)
    )
    AND json_array_length(NEW.parse_receipt_refs_json) = (
        SELECT COUNT(DISTINCT json_extract(value, '$.artifact_id'))
        FROM json_each(NEW.parse_receipt_refs_json)
    )
    AND json_array_length(NEW.usage_receipt_ids_json) = (
        SELECT COUNT(DISTINCT value)
        FROM json_each(NEW.usage_receipt_ids_json)
    )
    AND json_array_length(NEW.failure_authority_ids_json) = (
        SELECT COUNT(DISTINCT value)
        FROM json_each(NEW.failure_authority_ids_json)
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(NEW.failure_authority_ids_json) AS authority_ref
        WHERE authority_ref.type <> 'text'
           OR NOT EXISTS (
               SELECT 1
               FROM m4_model_call_failure_authorities AS authority
               WHERE authority.run_id = NEW.run_id
                 AND authority.authority_id = authority_ref.value
                 AND authority.hearing_id = NEW.hearing_id
                 AND authority.cycle_scope_id = NEW.cycle_scope_id
                 AND authority.case_id = NEW.case_id
                 AND authority.manifest_id = NEW.manifest_id
           )
    )
    AND (
        NEW.phase <> 'PRECEDENT_RETRIEVAL_PENDING'
        OR (
            json_array_length(NEW.model_request_refs_json) = 0
            AND json_array_length(NEW.failure_authority_ids_json) = 0
        )
    )
    AND (
        NEW.version = 1
        OR NEW.phase = 'PRECEDENT_RETRIEVAL_PENDING'
        OR EXISTS (
            SELECT 1
            FROM m4_hearing_checkpoints AS previous
            WHERE previous.run_id = NEW.run_id
              AND previous.checkpoint_id = NEW.previous_checkpoint_id
              AND previous.checkpoint_sha256 = NEW.previous_checkpoint_sha256
              AND previous.version = NEW.version - 1
              AND json_array_length(NEW.model_request_refs_json)
                  >= json_array_length(previous.model_request_refs_json)
              AND json_array_length(NEW.failure_authority_ids_json)
                  >= json_array_length(previous.failure_authority_ids_json)
              AND (
                  NEW.phase <> 'HUMAN_REVIEW'
                  OR json_array_length(NEW.model_request_refs_json)
                      = json_array_length(previous.model_request_refs_json)
                  OR (
                      previous.phase = 'JUDGE_PENDING'
                      AND NEW.judge_output_id IS NOT NULL
                      AND json_array_length(NEW.model_request_refs_json)
                          = json_array_length(previous.model_request_refs_json) + 1
                      AND EXISTS (
                          SELECT 1
                          FROM m4_hearing_human_review_receipts AS human
                          WHERE human.run_id = NEW.run_id
                            AND human.receipt_id = NEW.human_review_receipt_id
                            AND human.reason = 'ACQUISITION_LIMIT_EXHAUSTED'
                      )
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(previous.model_request_refs_json) AS old
                  WHERE NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.model_request_refs_json) AS current
                      WHERE json_extract(current.value, '$.artifact_id')
                          = json_extract(old.value, '$.artifact_id')
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(previous.model_response_refs_json) AS old
                  WHERE NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.model_response_refs_json) AS current
                      WHERE json_extract(current.value, '$.artifact_id')
                          = json_extract(old.value, '$.artifact_id')
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(previous.parse_receipt_refs_json) AS old
                  WHERE NOT EXISTS (
                      SELECT 1
                      FROM json_each(NEW.parse_receipt_refs_json) AS current
                      WHERE json_extract(current.value, '$.artifact_id')
                          = json_extract(old.value, '$.artifact_id')
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(previous.usage_receipt_ids_json) AS old
                  WHERE old.value NOT IN (
                      SELECT current.value
                      FROM json_each(NEW.usage_receipt_ids_json) AS current
                  )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM json_each(previous.failure_authority_ids_json) AS old
                  WHERE old.value NOT IN (
                      SELECT current.value
                      FROM json_each(NEW.failure_authority_ids_json) AS current
                  )
              )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M4 hearing checkpoint call trace is invalid');
END;

-- Every content root is append-only.  Explicit no-replace triggers are
-- required because INSERT OR REPLACE must never turn a content collision into
-- an implicit delete-and-insert.  Claims are the sole controlled-update root.
CREATE TRIGGER m4_hearings_no_replace
BEFORE INSERT ON m4_hearings
WHEN EXISTS (SELECT 1 FROM m4_hearings WHERE run_id = NEW.run_id AND hearing_id = NEW.hearing_id)
BEGIN SELECT RAISE(ABORT, 'm4_hearings is append-only'); END;
CREATE TRIGGER m4_hearings_no_update
BEFORE UPDATE ON m4_hearings
BEGIN SELECT RAISE(ABORT, 'm4_hearings is append-only'); END;
CREATE TRIGGER m4_hearings_no_delete
BEFORE DELETE ON m4_hearings
BEGIN SELECT RAISE(ABORT, 'm4_hearings is append-only'); END;

CREATE TRIGGER m4_hearing_cycles_no_replace
BEFORE INSERT ON m4_hearing_cycles
WHEN EXISTS (SELECT 1 FROM m4_hearing_cycles WHERE run_id = NEW.run_id AND cycle_id = NEW.cycle_id)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_cycles is append-only'); END;
CREATE TRIGGER m4_hearing_cycles_no_update
BEFORE UPDATE ON m4_hearing_cycles
BEGIN SELECT RAISE(ABORT, 'm4_hearing_cycles is append-only'); END;
CREATE TRIGGER m4_hearing_cycles_no_delete
BEFORE DELETE ON m4_hearing_cycles
BEGIN SELECT RAISE(ABORT, 'm4_hearing_cycles is append-only'); END;

CREATE TRIGGER m4_precedent_retrieval_receipts_no_replace
BEFORE INSERT ON m4_precedent_retrieval_receipts
WHEN EXISTS (
    SELECT 1 FROM m4_precedent_retrieval_receipts
    WHERE run_id = NEW.run_id AND retrieval_receipt_id = NEW.retrieval_receipt_id
)
BEGIN SELECT RAISE(ABORT, 'm4_precedent_retrieval_receipts is append-only'); END;
CREATE TRIGGER m4_precedent_retrieval_receipts_no_update
BEFORE UPDATE ON m4_precedent_retrieval_receipts
BEGIN SELECT RAISE(ABORT, 'm4_precedent_retrieval_receipts is append-only'); END;
CREATE TRIGGER m4_precedent_retrieval_receipts_no_delete
BEFORE DELETE ON m4_precedent_retrieval_receipts
BEGIN SELECT RAISE(ABORT, 'm4_precedent_retrieval_receipts is append-only'); END;

CREATE TRIGGER m4_model_responses_no_replace
BEFORE INSERT ON m4_model_responses
WHEN EXISTS (
    SELECT 1 FROM m4_model_responses
    WHERE run_id = NEW.run_id AND (response_id = NEW.response_id OR request_id = NEW.request_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_model_responses is append-only'); END;
CREATE TRIGGER m4_model_responses_no_update
BEFORE UPDATE ON m4_model_responses
BEGIN SELECT RAISE(ABORT, 'm4_model_responses is append-only'); END;
CREATE TRIGGER m4_model_responses_no_delete
BEFORE DELETE ON m4_model_responses
BEGIN SELECT RAISE(ABORT, 'm4_model_responses is append-only'); END;

CREATE TRIGGER m4_model_call_claims_no_replace
BEFORE INSERT ON m4_model_call_claims
WHEN EXISTS (
    SELECT 1 FROM m4_model_call_claims
    WHERE run_id = NEW.run_id AND (request_id = NEW.request_id OR cache_key = NEW.cache_key)
)
BEGIN SELECT RAISE(ABORT, 'm4_model_call_claims has an existing authority'); END;
CREATE TRIGGER m4_model_call_claims_no_delete
BEFORE DELETE ON m4_model_call_claims
BEGIN SELECT RAISE(ABORT, 'm4_model_call_claims cannot be deleted'); END;

CREATE TRIGGER m4_parsed_hearing_outputs_no_replace
BEFORE INSERT ON m4_parsed_hearing_outputs
WHEN EXISTS (
    SELECT 1 FROM m4_parsed_hearing_outputs
    WHERE run_id = NEW.run_id
      AND (parsed_output_id = NEW.parsed_output_id OR response_id = NEW.response_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_parsed_hearing_outputs is append-only'); END;
CREATE TRIGGER m4_parsed_hearing_outputs_no_update
BEFORE UPDATE ON m4_parsed_hearing_outputs
BEGIN SELECT RAISE(ABORT, 'm4_parsed_hearing_outputs is append-only'); END;
CREATE TRIGGER m4_parsed_hearing_outputs_no_delete
BEFORE DELETE ON m4_parsed_hearing_outputs
BEGIN SELECT RAISE(ABORT, 'm4_parsed_hearing_outputs is append-only'); END;

CREATE TRIGGER m4_model_parse_receipts_no_replace
BEFORE INSERT ON m4_model_parse_receipts
WHEN EXISTS (
    SELECT 1 FROM m4_model_parse_receipts
    WHERE run_id = NEW.run_id
      AND (parse_receipt_id = NEW.parse_receipt_id OR response_id = NEW.response_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_model_parse_receipts is append-only'); END;
CREATE TRIGGER m4_model_parse_receipts_no_update
BEFORE UPDATE ON m4_model_parse_receipts
BEGIN SELECT RAISE(ABORT, 'm4_model_parse_receipts is append-only'); END;
CREATE TRIGGER m4_model_parse_receipts_no_delete
BEFORE DELETE ON m4_model_parse_receipts
BEGIN SELECT RAISE(ABORT, 'm4_model_parse_receipts is append-only'); END;

CREATE TRIGGER m4_model_cache_no_replace
BEFORE INSERT ON m4_model_cache
WHEN EXISTS (
    SELECT 1 FROM m4_model_cache
    WHERE run_id = NEW.run_id
      AND (cache_key = NEW.cache_key OR cache_entry_id = NEW.cache_entry_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_model_cache is append-only'); END;
CREATE TRIGGER m4_model_cache_no_update
BEFORE UPDATE ON m4_model_cache
BEGIN SELECT RAISE(ABORT, 'm4_model_cache is append-only'); END;
CREATE TRIGGER m4_model_cache_no_delete
BEFORE DELETE ON m4_model_cache
BEGIN SELECT RAISE(ABORT, 'm4_model_cache is append-only'); END;

CREATE TRIGGER m4_hearing_usage_receipts_no_replace
BEFORE INSERT ON m4_hearing_usage_receipts
WHEN EXISTS (
    SELECT 1 FROM m4_hearing_usage_receipts
    WHERE run_id = NEW.run_id
      AND (usage_receipt_id = NEW.usage_receipt_id
           OR request_id = NEW.request_id
           OR response_id = NEW.response_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_usage_receipts is append-only'); END;
CREATE TRIGGER m4_hearing_usage_receipts_no_update
BEFORE UPDATE ON m4_hearing_usage_receipts
BEGIN SELECT RAISE(ABORT, 'm4_hearing_usage_receipts is append-only'); END;
CREATE TRIGGER m4_hearing_usage_receipts_no_delete
BEFORE DELETE ON m4_hearing_usage_receipts
BEGIN SELECT RAISE(ABORT, 'm4_hearing_usage_receipts is append-only'); END;

CREATE TRIGGER m4_acquisition_requests_no_replace
BEFORE INSERT ON m4_acquisition_requests
WHEN EXISTS (
    SELECT 1 FROM m4_acquisition_requests
    WHERE run_id = NEW.run_id
      AND (acquisition_request_id = NEW.acquisition_request_id OR cycle_scope_id = NEW.cycle_scope_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_acquisition_requests is append-only'); END;
CREATE TRIGGER m4_acquisition_requests_no_update
BEFORE UPDATE ON m4_acquisition_requests
BEGIN SELECT RAISE(ABORT, 'm4_acquisition_requests is append-only'); END;
CREATE TRIGGER m4_acquisition_requests_no_delete
BEFORE DELETE ON m4_acquisition_requests
BEGIN SELECT RAISE(ABORT, 'm4_acquisition_requests is append-only'); END;

CREATE TRIGGER m4_acquisition_execution_claims_no_replace
BEFORE INSERT ON m4_acquisition_execution_claims
WHEN EXISTS (
    SELECT 1 FROM m4_acquisition_execution_claims
    WHERE run_id = NEW.run_id
      AND (acquisition_request_id = NEW.acquisition_request_id
           OR idempotency_key = NEW.idempotency_key)
)
BEGIN SELECT RAISE(ABORT, 'm4 acquisition execution claim already exists'); END;
CREATE TRIGGER m4_acquisition_execution_claims_no_delete
BEFORE DELETE ON m4_acquisition_execution_claims
BEGIN SELECT RAISE(ABORT, 'm4 acquisition execution claim cannot be deleted'); END;

CREATE TRIGGER m4_hearing_rounds_no_replace
BEFORE INSERT ON m4_hearing_rounds
WHEN EXISTS (
    SELECT 1 FROM m4_hearing_rounds
    WHERE run_id = NEW.run_id
      AND (round_id = NEW.round_id OR cycle_scope_id = NEW.cycle_scope_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_rounds is append-only'); END;
CREATE TRIGGER m4_hearing_rounds_no_update
BEFORE UPDATE ON m4_hearing_rounds
BEGIN SELECT RAISE(ABORT, 'm4_hearing_rounds is append-only'); END;
CREATE TRIGGER m4_hearing_rounds_no_delete
BEFORE DELETE ON m4_hearing_rounds
BEGIN SELECT RAISE(ABORT, 'm4_hearing_rounds is append-only'); END;

CREATE TRIGGER m4_tool_execution_manifests_no_replace
BEFORE INSERT ON m4_tool_execution_manifests
WHEN EXISTS (
    SELECT 1 FROM m4_tool_execution_manifests
    WHERE run_id = NEW.run_id
      AND (execution_manifest_id = NEW.execution_manifest_id
           OR acquisition_request_id = NEW.acquisition_request_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_tool_execution_manifests is append-only'); END;
CREATE TRIGGER m4_tool_execution_manifests_no_update
BEFORE UPDATE ON m4_tool_execution_manifests
BEGIN SELECT RAISE(ABORT, 'm4_tool_execution_manifests is append-only'); END;
CREATE TRIGGER m4_tool_execution_manifests_no_delete
BEFORE DELETE ON m4_tool_execution_manifests
BEGIN SELECT RAISE(ABORT, 'm4_tool_execution_manifests is append-only'); END;

CREATE TRIGGER m4_acquisition_execution_publications_no_replace
BEFORE INSERT ON m4_acquisition_execution_publications
WHEN EXISTS (
    SELECT 1 FROM m4_acquisition_execution_publications
    WHERE run_id = NEW.run_id
      AND (execution_publication_id = NEW.execution_publication_id
           OR acquisition_request_id = NEW.acquisition_request_id
           OR execution_manifest_id = NEW.execution_manifest_id
           OR tool_result_id = NEW.tool_result_id)
)
BEGIN SELECT RAISE(ABORT, 'm4 acquisition execution publication is append-only'); END;
CREATE TRIGGER m4_acquisition_execution_publications_no_update
BEFORE UPDATE ON m4_acquisition_execution_publications
BEGIN SELECT RAISE(ABORT, 'm4 acquisition execution publication is append-only'); END;
CREATE TRIGGER m4_acquisition_execution_publications_no_delete
BEFORE DELETE ON m4_acquisition_execution_publications
BEGIN SELECT RAISE(ABORT, 'm4 acquisition execution publication is append-only'); END;

CREATE TRIGGER m4_acquired_crops_no_replace
BEFORE INSERT ON m4_acquired_crops
WHEN EXISTS (
    SELECT 1 FROM m4_acquired_crops
    WHERE run_id = NEW.run_id
      AND (crop_id = NEW.crop_id
           OR acquisition_request_id = NEW.acquisition_request_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_acquired_crops is append-only'); END;
CREATE TRIGGER m4_acquired_crops_no_update
BEFORE UPDATE ON m4_acquired_crops
BEGIN SELECT RAISE(ABORT, 'm4_acquired_crops is append-only'); END;
CREATE TRIGGER m4_acquired_crops_no_delete
BEFORE DELETE ON m4_acquired_crops
BEGIN SELECT RAISE(ABORT, 'm4_acquired_crops is append-only'); END;

CREATE TRIGGER m4_tool_execution_receipts_no_replace
BEFORE INSERT ON m4_tool_execution_receipts
WHEN EXISTS (
    SELECT 1 FROM m4_tool_execution_receipts
    WHERE run_id = NEW.run_id
      AND (receipt_id = NEW.receipt_id
           OR tool_result_id = NEW.tool_result_id
           OR acquisition_request_id = NEW.acquisition_request_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_tool_execution_receipts is append-only'); END;
CREATE TRIGGER m4_tool_execution_receipts_no_update
BEFORE UPDATE ON m4_tool_execution_receipts
BEGIN SELECT RAISE(ABORT, 'm4_tool_execution_receipts is append-only'); END;
CREATE TRIGGER m4_tool_execution_receipts_no_delete
BEFORE DELETE ON m4_tool_execution_receipts
BEGIN SELECT RAISE(ABORT, 'm4_tool_execution_receipts is append-only'); END;

CREATE TRIGGER m4_evidence_pack_derivations_no_replace
BEFORE INSERT ON m4_evidence_pack_derivations
WHEN EXISTS (
    SELECT 1 FROM m4_evidence_pack_derivations
    WHERE run_id = NEW.run_id
      AND (derivation_id = NEW.derivation_id
           OR new_pack_id = NEW.new_pack_id
           OR tool_receipt_id = NEW.tool_receipt_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_evidence_pack_derivations is append-only'); END;
CREATE TRIGGER m4_evidence_pack_derivations_no_update
BEFORE UPDATE ON m4_evidence_pack_derivations
BEGIN SELECT RAISE(ABORT, 'm4_evidence_pack_derivations is append-only'); END;
CREATE TRIGGER m4_evidence_pack_derivations_no_delete
BEFORE DELETE ON m4_evidence_pack_derivations
BEGIN SELECT RAISE(ABORT, 'm4_evidence_pack_derivations is append-only'); END;

CREATE TRIGGER m4_hearing_verdict_bindings_no_replace
BEFORE INSERT ON m4_hearing_verdict_bindings
WHEN EXISTS (
    SELECT 1 FROM m4_hearing_verdict_bindings
    WHERE run_id = NEW.run_id
      AND (binding_id = NEW.binding_id
           OR verdict_id = NEW.verdict_id
           OR round_id = NEW.round_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_verdict_bindings is append-only'); END;
CREATE TRIGGER m4_hearing_verdict_bindings_no_update
BEFORE UPDATE ON m4_hearing_verdict_bindings
BEGIN SELECT RAISE(ABORT, 'm4_hearing_verdict_bindings is append-only'); END;
CREATE TRIGGER m4_hearing_verdict_bindings_no_delete
BEFORE DELETE ON m4_hearing_verdict_bindings
BEGIN SELECT RAISE(ABORT, 'm4_hearing_verdict_bindings is append-only'); END;

CREATE TRIGGER m4_rework_receipts_no_replace
BEFORE INSERT ON m4_rework_receipts
WHEN EXISTS (
    SELECT 1 FROM m4_rework_receipts
    WHERE run_id = NEW.run_id
      AND (rework_receipt_id = NEW.rework_receipt_id
           OR failed_review_id = NEW.failed_review_id
           OR next_cycle_scope_id = NEW.next_cycle_scope_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_rework_receipts is append-only'); END;
CREATE TRIGGER m4_rework_receipts_no_update
BEFORE UPDATE ON m4_rework_receipts
BEGIN SELECT RAISE(ABORT, 'm4_rework_receipts is append-only'); END;
CREATE TRIGGER m4_rework_receipts_no_delete
BEFORE DELETE ON m4_rework_receipts
BEGIN SELECT RAISE(ABORT, 'm4_rework_receipts is append-only'); END;

CREATE TRIGGER m4_backlog_completion_receipts_no_replace
BEFORE INSERT ON m4_backlog_completion_receipts
WHEN EXISTS (
    SELECT 1 FROM m4_backlog_completion_receipts
    WHERE run_id = NEW.run_id
      AND (receipt_id = NEW.receipt_id
           OR outcome_id = NEW.outcome_id
           OR (item_id = NEW.item_id AND lease_identity_sha256 = NEW.lease_identity_sha256))
)
BEGIN SELECT RAISE(ABORT, 'm4_backlog_completion_receipts is append-only'); END;
CREATE TRIGGER m4_backlog_completion_receipts_no_update
BEFORE UPDATE ON m4_backlog_completion_receipts
BEGIN SELECT RAISE(ABORT, 'm4_backlog_completion_receipts is append-only'); END;
CREATE TRIGGER m4_backlog_completion_receipts_no_delete
BEFORE DELETE ON m4_backlog_completion_receipts
BEGIN SELECT RAISE(ABORT, 'm4_backlog_completion_receipts is append-only'); END;

CREATE TRIGGER m4_model_call_failure_authorities_no_replace
BEFORE INSERT ON m4_model_call_failure_authorities
WHEN EXISTS (
    SELECT 1 FROM m4_model_call_failure_authorities
    WHERE run_id = NEW.run_id
      AND (authority_id = NEW.authority_id
           OR (request_id = NEW.request_id
               AND claim_takeover_count = NEW.claim_takeover_count))
)
BEGIN SELECT RAISE(ABORT, 'm4_model_call_failure_authorities is append-only'); END;
CREATE TRIGGER m4_model_call_failure_authorities_no_update
BEFORE UPDATE ON m4_model_call_failure_authorities
BEGIN SELECT RAISE(ABORT, 'm4_model_call_failure_authorities is append-only'); END;
CREATE TRIGGER m4_model_call_failure_authorities_no_delete
BEFORE DELETE ON m4_model_call_failure_authorities
BEGIN SELECT RAISE(ABORT, 'm4_model_call_failure_authorities is append-only'); END;

CREATE TRIGGER m4_hearing_checkpoints_no_replace
BEFORE INSERT ON m4_hearing_checkpoints
WHEN EXISTS (
    SELECT 1 FROM m4_hearing_checkpoints
    WHERE run_id = NEW.run_id
      AND (checkpoint_id = NEW.checkpoint_id
           OR (hearing_id = NEW.hearing_id AND version = NEW.version)
           OR previous_checkpoint_id = NEW.previous_checkpoint_id
           OR human_review_receipt_id = NEW.human_review_receipt_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_checkpoints is append-only'); END;
CREATE TRIGGER m4_hearing_checkpoints_no_update
BEFORE UPDATE ON m4_hearing_checkpoints
BEGIN SELECT RAISE(ABORT, 'm4_hearing_checkpoints is append-only'); END;
CREATE TRIGGER m4_hearing_checkpoints_no_delete
BEFORE DELETE ON m4_hearing_checkpoints
BEGIN SELECT RAISE(ABORT, 'm4_hearing_checkpoints is append-only'); END;

CREATE TRIGGER m4_hearing_human_review_receipts_no_replace
BEFORE INSERT ON m4_hearing_human_review_receipts
WHEN EXISTS (
    SELECT 1 FROM m4_hearing_human_review_receipts
    WHERE run_id = NEW.run_id
      AND (receipt_id = NEW.receipt_id
           OR source_checkpoint_id = NEW.source_checkpoint_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_human_review_receipts is append-only'); END;
CREATE TRIGGER m4_hearing_human_review_receipts_no_update
BEFORE UPDATE ON m4_hearing_human_review_receipts
BEGIN SELECT RAISE(ABORT, 'm4_hearing_human_review_receipts is append-only'); END;
CREATE TRIGGER m4_hearing_human_review_receipts_no_delete
BEFORE DELETE ON m4_hearing_human_review_receipts
BEGIN SELECT RAISE(ABORT, 'm4_hearing_human_review_receipts is append-only'); END;

CREATE TRIGGER m4_hearing_strict_parse_failure_attempts_no_replace
BEFORE INSERT ON m4_hearing_strict_parse_failure_attempts
WHEN EXISTS (
    SELECT 1 FROM m4_hearing_strict_parse_failure_attempts
    WHERE run_id = NEW.run_id
      AND (attempt_id = NEW.attempt_id
           OR request_id = NEW.request_id
           OR response_id = NEW.response_id
           OR parse_receipt_id = NEW.parse_receipt_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_strict_parse_failure_attempts is append-only'); END;
CREATE TRIGGER m4_hearing_strict_parse_failure_attempts_no_update
BEFORE UPDATE ON m4_hearing_strict_parse_failure_attempts
BEGIN SELECT RAISE(ABORT, 'm4_hearing_strict_parse_failure_attempts is append-only'); END;
CREATE TRIGGER m4_hearing_strict_parse_failure_attempts_no_delete
BEFORE DELETE ON m4_hearing_strict_parse_failure_attempts
BEGIN SELECT RAISE(ABORT, 'm4_hearing_strict_parse_failure_attempts is append-only'); END;

CREATE TRIGGER m4_hearing_strict_parse_failure_proofs_no_replace
BEFORE INSERT ON m4_hearing_strict_parse_failure_proofs
WHEN EXISTS (
    SELECT 1 FROM m4_hearing_strict_parse_failure_proofs
    WHERE run_id = NEW.run_id
      AND (proof_id = NEW.proof_id
           OR (lease_identity_sha256 = NEW.lease_identity_sha256 AND role = NEW.role)
           OR primary_attempt_id = NEW.primary_attempt_id
           OR repair_attempt_id = NEW.repair_attempt_id)
)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_strict_parse_failure_proofs is append-only'); END;
CREATE TRIGGER m4_hearing_strict_parse_failure_proofs_no_update
BEFORE UPDATE ON m4_hearing_strict_parse_failure_proofs
BEGIN SELECT RAISE(ABORT, 'm4_hearing_strict_parse_failure_proofs is append-only'); END;
CREATE TRIGGER m4_hearing_strict_parse_failure_proofs_no_delete
BEFORE DELETE ON m4_hearing_strict_parse_failure_proofs
BEGIN SELECT RAISE(ABORT, 'm4_hearing_strict_parse_failure_proofs is append-only'); END;

CREATE TRIGGER m4_hearing_backlog_retry_outcomes_no_replace
BEFORE INSERT ON m4_hearing_backlog_retry_outcomes
WHEN EXISTS (
    SELECT 1 FROM m4_hearing_backlog_retry_outcomes
    WHERE run_id = NEW.run_id
      AND (outcome_id = NEW.outcome_id
           OR lease_identity_sha256 = NEW.lease_identity_sha256)
)
BEGIN SELECT RAISE(ABORT, 'm4_hearing_backlog_retry_outcomes is append-only'); END;
CREATE TRIGGER m4_hearing_backlog_retry_outcomes_no_update
BEFORE UPDATE ON m4_hearing_backlog_retry_outcomes
BEGIN SELECT RAISE(ABORT, 'm4_hearing_backlog_retry_outcomes is append-only'); END;
CREATE TRIGGER m4_hearing_backlog_retry_outcomes_no_delete
BEFORE DELETE ON m4_hearing_backlog_retry_outcomes
BEGIN SELECT RAISE(ABORT, 'm4_hearing_backlog_retry_outcomes is append-only'); END;
