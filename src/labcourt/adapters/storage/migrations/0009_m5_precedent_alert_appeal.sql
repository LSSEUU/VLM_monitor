-- M4's wire contract has always allowed ReferenceToken precedent IDs.  The
-- 0008 storage trigger accidentally narrowed candidate IDs to 64-hex digests,
-- which the M5 production corpus does not require.  Replace only that storage
-- narrowing while preserving every frozen M4 scope, ordering, and defect check.
DROP TRIGGER m4_precedent_retrieval_receipts_validate_scope;

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

CREATE TABLE precedent_embeddings (
    run_id TEXT NOT NULL,
    embedding_id TEXT NOT NULL
        CHECK (length(embedding_id) = 64 AND embedding_id NOT GLOB '*[^0-9a-f]*'),
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    channel TEXT NOT NULL CHECK (channel IN ('TEXT', 'VISUAL')),
    input_ref TEXT NOT NULL,
    input_sha256 TEXT NOT NULL
        CHECK (length(input_sha256) = 64 AND input_sha256 NOT GLOB '*[^0-9a-f]*'),
    model_manifest_id TEXT NOT NULL
        CHECK (length(model_manifest_id) = 64 AND model_manifest_id NOT GLOB '*[^0-9a-f]*'),
    dimensions INTEGER NOT NULL CHECK (dimensions BETWEEN 1 AND 4096),
    algorithm TEXT NOT NULL CHECK (algorithm = 'FAKE_SHA256_SIGNED_PROJECTION_V1'),
    manifest_id TEXT NOT NULL,
    embedding_json TEXT NOT NULL CHECK (json_valid(embedding_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, embedding_id),
    UNIQUE (run_id, request_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE precedents (
    run_id TEXT NOT NULL,
    precedent_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    authority_id TEXT NOT NULL
        CHECK (length(authority_id) = 64 AND authority_id NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL
        CHECK (status IN ('PROVISIONAL', 'ACTIVE', 'CONFLICT', 'INVALIDATED', 'REVOKED')),
    source TEXT NOT NULL
        CHECK (source IN ('PRESET', 'AUTOMATIC', 'HUMAN_REVIEW', 'APPEAL_OVERTURN')),
    evidence_class TEXT NOT NULL CHECK (evidence_class IN ('PRESENCE', 'ABSENCE')),
    violation_type TEXT NOT NULL,
    decision_direction TEXT NOT NULL
        CHECK (decision_direction IN ('ESTABLISHED', 'NOT_ESTABLISHED', 'INSUFFICIENT_EVIDENCE')),
    rule_version TEXT NOT NULL,
    source_case_id TEXT,
    citation_count INTEGER NOT NULL CHECK (citation_count = 0),
    text_embedding_id TEXT,
    visual_embedding_ids_json TEXT NOT NULL
        CHECK (json_valid(visual_embedding_ids_json) AND json_type(visual_embedding_ids_json) = 'array'),
    created_at TEXT NOT NULL,
    activation_not_before TEXT,
    activated_at TEXT,
    manifest_id TEXT NOT NULL,
    authority_json TEXT NOT NULL CHECK (json_valid(authority_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, precedent_id, revision),
    UNIQUE (run_id, authority_id),
    UNIQUE (run_id, precedent_id, authority_id, revision),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, source_case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, text_embedding_id)
        REFERENCES precedent_embeddings(run_id, embedding_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE precedent_citations (
    run_id TEXT NOT NULL,
    citation_kind TEXT NOT NULL CHECK (citation_kind IN ('DIRECT', 'APPLIED')),
    citation_id TEXT NOT NULL
        CHECK (length(citation_id) = 64 AND citation_id NOT GLOB '*[^0-9a-f]*'),
    commit_id TEXT NOT NULL
        CHECK (length(commit_id) = 64 AND commit_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    precedent_id TEXT NOT NULL,
    precedent_authority_id TEXT NOT NULL,
    precedent_revision INTEGER NOT NULL CHECK (precedent_revision >= 1),
    retrieval_result_id TEXT NOT NULL
        CHECK (length(retrieval_result_id) = 64 AND retrieval_result_id NOT GLOB '*[^0-9a-f]*'),
    application_batch_id TEXT CHECK (
        application_batch_id IS NULL
        OR (
            length(application_batch_id) = 64
            AND application_batch_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    application_binding_id TEXT CHECK (
        application_binding_id IS NULL
        OR (
            length(application_binding_id) = 64
            AND application_binding_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    query_id TEXT NOT NULL
        CHECK (length(query_id) = 64 AND query_id NOT GLOB '*[^0-9a-f]*'),
    score REAL NOT NULL CHECK (score BETWEEN -10.0 AND 10.0),
    cited_at TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    citation_json TEXT NOT NULL CHECK (json_valid(citation_json)),
    commit_json TEXT NOT NULL CHECK (json_valid(commit_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, citation_id),
    UNIQUE (run_id, commit_id),
    UNIQUE (run_id, case_id, precedent_id, query_id),
    FOREIGN KEY (run_id, case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, precedent_id, precedent_authority_id, precedent_revision)
        REFERENCES precedents(run_id, precedent_id, authority_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, application_batch_id)
        REFERENCES m5_precedent_application_batches(run_id, application_batch_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (citation_kind = 'DIRECT'
            AND application_batch_id IS NULL
            AND application_binding_id IS NULL)
        OR
        (citation_kind = 'APPLIED'
            AND application_batch_id IS NOT NULL
            AND application_binding_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE m5_precedent_causal_events (
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_id TEXT NOT NULL
        CHECK (length(event_id) = 64 AND event_id NOT GLOB '*[^0-9a-f]*'),
    source_identity_sha256 TEXT NOT NULL
        CHECK (
            length(source_identity_sha256) = 64
            AND source_identity_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    event_kind TEXT NOT NULL CHECK (
        event_kind IN (
            'PRECEDENT_AUTHORITY_APPENDED',
            'PRECEDENT_CITATION_APPENDED',
            'PRECEDENT_CONFLICT_BATCH_COMMITTED',
            'PRECEDENT_REVOCATION_COMMITTED',
            'APPEAL_RESOLUTION_COMMITTED'
        )
    ),
    source_id TEXT NOT NULL
        CHECK (length(source_id) = 64 AND source_id NOT GLOB '*[^0-9a-f]*'),
    precedent_id TEXT,
    precedent_authority_id TEXT
        CHECK (
            precedent_authority_id IS NULL
            OR (
                length(precedent_authority_id) = 64
                AND precedent_authority_id NOT GLOB '*[^0-9a-f]*'
            )
        ),
    precedent_revision INTEGER CHECK (
        precedent_revision IS NULL OR precedent_revision >= 1
    ),
    citation_kind TEXT CHECK (citation_kind IN ('DIRECT', 'APPLIED')),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    source_document_sha256 TEXT NOT NULL
        CHECK (
            length(source_document_sha256) = 64
            AND source_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    previous_event_sha256 TEXT NOT NULL
        CHECK (
            length(previous_event_sha256) = 64
            AND previous_event_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    event_sha256 TEXT NOT NULL
        CHECK (length(event_sha256) = 64 AND event_sha256 NOT GLOB '*[^0-9a-f]*'),
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, sequence),
    UNIQUE (run_id, event_id),
    UNIQUE (run_id, source_identity_sha256),
    UNIQUE (run_id, event_sha256),
    UNIQUE (run_id, event_kind, source_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, precedent_id, precedent_authority_id, precedent_revision
    ) REFERENCES precedents(run_id, precedent_id, authority_id, revision) ON DELETE RESTRICT,
    CHECK (
        (event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
            AND precedent_id IS NOT NULL
            AND precedent_authority_id IS NOT NULL
            AND precedent_revision IS NOT NULL
            AND source_id = precedent_authority_id
            AND citation_kind IS NULL)
        OR
        (event_kind = 'PRECEDENT_CITATION_APPENDED'
            AND precedent_id IS NOT NULL
            AND precedent_authority_id IS NOT NULL
            AND precedent_revision IS NOT NULL
            AND citation_kind IS NOT NULL)
        OR
        (event_kind = 'PRECEDENT_REVOCATION_COMMITTED'
            AND precedent_id IS NOT NULL
            AND precedent_authority_id IS NOT NULL
            AND precedent_revision IS NOT NULL
            AND citation_kind IS NULL)
        OR
        (event_kind IN (
                'PRECEDENT_CONFLICT_BATCH_COMMITTED',
                'APPEAL_RESOLUTION_COMMITTED'
            )
            AND precedent_id IS NULL
            AND precedent_authority_id IS NULL
            AND precedent_revision IS NULL
            AND citation_kind IS NULL)
    )
) STRICT;

CREATE TABLE m5_precedent_exposures (
    run_id TEXT NOT NULL,
    exposure_id TEXT NOT NULL
        CHECK (length(exposure_id) = 64 AND exposure_id NOT GLOB '*[^0-9a-f]*'),
    exposure_sha256 TEXT NOT NULL
        CHECK (
            length(exposure_sha256) = 64
            AND exposure_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    case_id TEXT NOT NULL,
    hearing_id TEXT NOT NULL
        CHECK (length(hearing_id) = 64 AND hearing_id NOT GLOB '*[^0-9a-f]*'),
    cycle_index INTEGER NOT NULL CHECK (cycle_index BETWEEN 1 AND 5),
    cycle_scope_id TEXT NOT NULL
        CHECK (length(cycle_scope_id) = 64 AND cycle_scope_id NOT GLOB '*[^0-9a-f]*'),
    cycle_scope_sha256 TEXT NOT NULL
        CHECK (
            length(cycle_scope_sha256) = 64
            AND cycle_scope_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    retrieval_receipt_id TEXT NOT NULL
        CHECK (
            length(retrieval_receipt_id) = 64
            AND retrieval_receipt_id NOT GLOB '*[^0-9a-f]*'
        ),
    m4_query_id TEXT NOT NULL
        CHECK (length(m4_query_id) = 64 AND m4_query_id NOT GLOB '*[^0-9a-f]*'),
    m5_query_id TEXT NOT NULL
        CHECK (length(m5_query_id) = 64 AND m5_query_id NOT GLOB '*[^0-9a-f]*'),
    m5_result_id TEXT NOT NULL
        CHECK (length(m5_result_id) = 64 AND m5_result_id NOT GLOB '*[^0-9a-f]*'),
    candidate_count INTEGER NOT NULL CHECK (candidate_count BETWEEN 0 AND 10000),
    exposed_count INTEGER NOT NULL
        CHECK (exposed_count BETWEEN 0 AND 64 AND exposed_count <= candidate_count),
    policy_id TEXT NOT NULL
        CHECK (length(policy_id) = 64 AND policy_id NOT GLOB '*[^0-9a-f]*'),
    bridge_manifest_id TEXT NOT NULL
        CHECK (
            length(bridge_manifest_id) = 64
            AND bridge_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    exposure_json TEXT NOT NULL CHECK (json_valid(exposure_json)),
    document_sha256 TEXT NOT NULL
        CHECK (
            length(document_sha256) = 64
            AND document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    PRIMARY KEY (run_id, exposure_id),
    UNIQUE (run_id, exposure_sha256),
    UNIQUE (run_id, cycle_scope_id),
    UNIQUE (run_id, retrieval_receipt_id),
    UNIQUE (run_id, m4_query_id),
    FOREIGN KEY (run_id, retrieval_receipt_id)
        REFERENCES m4_precedent_retrieval_receipts(run_id, retrieval_receipt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, cycle_scope_id, cycle_scope_sha256, hearing_id)
        REFERENCES m4_hearing_cycles(run_id, cycle_id, cycle_sha256, hearing_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, hearing_id, case_id)
        REFERENCES m4_hearings(run_id, hearing_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, manifest_id)
        REFERENCES cases(run_id, case_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE m5_precedent_application_batches (
    run_id TEXT NOT NULL,
    application_batch_id TEXT NOT NULL CHECK (
        length(application_batch_id) = 64
        AND application_batch_id NOT GLOB '*[^0-9a-f]*'
    ),
    application_batch_sha256 TEXT NOT NULL CHECK (
        length(application_batch_sha256) = 64
        AND application_batch_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    case_id TEXT NOT NULL,
    ready_case_revision INTEGER NOT NULL CHECK (ready_case_revision >= 1),
    closing_case_revision INTEGER NOT NULL
        CHECK (closing_case_revision = ready_case_revision + 1),
    ready_case_document_sha256 TEXT NOT NULL CHECK (
        length(ready_case_document_sha256) = 64
        AND ready_case_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    verdict_id TEXT NOT NULL,
    verdict_version INTEGER NOT NULL CHECK (verdict_version >= 1),
    verdict_sha256 TEXT NOT NULL CHECK (
        length(verdict_sha256) = 64
        AND verdict_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    exposure_id TEXT NOT NULL CHECK (
        length(exposure_id) = 64
        AND exposure_id NOT GLOB '*[^0-9a-f]*'
    ),
    binding_count INTEGER NOT NULL CHECK (binding_count BETWEEN 0 AND 64),
    config_sha256 TEXT NOT NULL CHECK (
        length(config_sha256) = 64
        AND config_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    manifest_id TEXT NOT NULL CHECK (
        length(manifest_id) = 64
        AND manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    application_batch_json TEXT NOT NULL CHECK (json_valid(application_batch_json)),
    document_sha256 TEXT NOT NULL CHECK (
        length(document_sha256) = 64
        AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (run_id, application_batch_id),
    UNIQUE (run_id, application_batch_sha256),
    UNIQUE (run_id, case_id),
    UNIQUE (run_id, verdict_id, verdict_version),
    UNIQUE (run_id, exposure_id, verdict_id),
    FOREIGN KEY (run_id, case_id, ready_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, closing_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, case_id, verdict_id, verdict_version)
        REFERENCES verdicts(run_id, case_id, verdict_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, exposure_id)
        REFERENCES m5_precedent_exposures(run_id, exposure_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE precedent_lifecycle_receipts (
    run_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL
        CHECK (length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    receipt_kind TEXT NOT NULL CHECK (receipt_kind IN ('ACTIVATION', 'CONFLICT', 'REVOCATION')),
    outcome TEXT NOT NULL,
    primary_precedent_id TEXT NOT NULL,
    primary_prior_authority_id TEXT NOT NULL,
    primary_prior_revision INTEGER NOT NULL CHECK (primary_prior_revision >= 1),
    primary_resulting_authority_id TEXT NOT NULL,
    primary_resulting_revision INTEGER NOT NULL CHECK (primary_resulting_revision >= 1),
    secondary_precedent_id TEXT,
    secondary_prior_authority_id TEXT,
    secondary_prior_revision INTEGER CHECK (secondary_prior_revision >= 1),
    secondary_resulting_authority_id TEXT,
    secondary_resulting_revision INTEGER CHECK (secondary_resulting_revision >= 1),
    manifest_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    context_json TEXT NOT NULL CHECK (json_valid(context_json)),
    context_sha256 TEXT NOT NULL
        CHECK (length(context_sha256) = 64 AND context_sha256 NOT GLOB '*[^0-9a-f]*'),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, receipt_id),
    UNIQUE (
        run_id,
        receipt_kind,
        primary_precedent_id,
        primary_prior_authority_id,
        secondary_precedent_id,
        secondary_prior_authority_id
    ),
    FOREIGN KEY (
        run_id, primary_precedent_id, primary_prior_authority_id, primary_prior_revision
    ) REFERENCES precedents(run_id, precedent_id, authority_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, primary_precedent_id, primary_resulting_authority_id, primary_resulting_revision
    ) REFERENCES precedents(run_id, precedent_id, authority_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, secondary_precedent_id, secondary_prior_authority_id, secondary_prior_revision
    ) REFERENCES precedents(run_id, precedent_id, authority_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, secondary_precedent_id, secondary_resulting_authority_id,
        secondary_resulting_revision
    ) REFERENCES precedents(run_id, precedent_id, authority_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (receipt_kind = 'CONFLICT'
            AND secondary_precedent_id IS NOT NULL
            AND secondary_prior_authority_id IS NOT NULL
            AND secondary_prior_revision IS NOT NULL
            AND secondary_resulting_authority_id IS NOT NULL
            AND secondary_resulting_revision IS NOT NULL)
        OR
        (receipt_kind <> 'CONFLICT'
            AND secondary_precedent_id IS NULL
            AND secondary_prior_authority_id IS NULL
            AND secondary_prior_revision IS NULL
            AND secondary_resulting_authority_id IS NULL
            AND secondary_resulting_revision IS NULL)
    )
) STRICT;

CREATE TABLE precedent_conflict_batches (
    run_id TEXT NOT NULL,
    batch_authority_id TEXT NOT NULL
        CHECK (
            length(batch_authority_id) = 64
            AND batch_authority_id NOT GLOB '*[^0-9a-f]*'
        ),
    policy_id TEXT NOT NULL
        CHECK (length(policy_id) = 64 AND policy_id NOT GLOB '*[^0-9a-f]*'),
    config_sha256 TEXT NOT NULL
        CHECK (length(config_sha256) = 64 AND config_sha256 NOT GLOB '*[^0-9a-f]*'),
    causal_cut_id TEXT NOT NULL
        CHECK (length(causal_cut_id) = 64 AND causal_cut_id NOT GLOB '*[^0-9a-f]*'),
    authority_event_sequence INTEGER NOT NULL CHECK (authority_event_sequence >= 0),
    authority_event_sha256 TEXT NOT NULL
        CHECK (
            length(authority_event_sha256) = 64
            AND authority_event_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    active_head_root_sha256 TEXT NOT NULL
        CHECK (
            length(active_head_root_sha256) = 64
            AND active_head_root_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    scan_limit INTEGER NOT NULL CHECK (scan_limit BETWEEN 1 AND 9999),
    candidate_count INTEGER NOT NULL CHECK (candidate_count BETWEEN 0 AND scan_limit),
    evaluated_pair_count INTEGER NOT NULL
        CHECK (evaluated_pair_count BETWEEN 0 AND 49985001),
    edge_count INTEGER NOT NULL
        CHECK (edge_count BETWEEN 0 AND evaluated_pair_count),
    manifest_id TEXT NOT NULL,
    authority_json TEXT NOT NULL CHECK (json_valid(authority_json)),
    policy_json TEXT NOT NULL CHECK (json_valid(policy_json)),
    policy_sha256 TEXT NOT NULL
        CHECK (length(policy_sha256) = 64 AND policy_sha256 NOT GLOB '*[^0-9a-f]*'),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, batch_authority_id),
    UNIQUE (run_id, batch_authority_id, causal_cut_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (
            authority_event_sequence = 0
            AND authority_event_sha256 = printf('%064d', 0)
            AND candidate_count = 0
        )
        OR
        (
            authority_event_sequence > 0
            AND authority_event_sha256 <> printf('%064d', 0)
        )
    )
) STRICT;

CREATE TABLE precedent_conflict_batch_receipts (
    run_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL
        CHECK (length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    batch_authority_id TEXT NOT NULL
        CHECK (
            length(batch_authority_id) = 64
            AND batch_authority_id NOT GLOB '*[^0-9a-f]*'
        ),
    causal_cut_id TEXT NOT NULL
        CHECK (length(causal_cut_id) = 64 AND causal_cut_id NOT GLOB '*[^0-9a-f]*'),
    result_count INTEGER NOT NULL CHECK (result_count BETWEEN 0 AND 9999),
    changed_count INTEGER NOT NULL CHECK (changed_count BETWEEN 0 AND result_count),
    manifest_id TEXT NOT NULL,
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, receipt_id),
    UNIQUE (run_id, batch_authority_id),
    FOREIGN KEY (run_id, batch_authority_id, causal_cut_id)
        REFERENCES precedent_conflict_batches(
            run_id, batch_authority_id, causal_cut_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE alerts (
    run_id TEXT NOT NULL,
    authority_id TEXT NOT NULL
        CHECK (length(authority_id) = 64 AND authority_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL,
    source_case_revision INTEGER NOT NULL CHECK (source_case_revision >= 1),
    closing_case_revision INTEGER NOT NULL CHECK (closing_case_revision = source_case_revision + 1),
    policy_request_id TEXT NOT NULL
        CHECK (length(policy_request_id) = 64 AND policy_request_id NOT GLOB '*[^0-9a-f]*'),
    verdict_id TEXT NOT NULL,
    verdict_version INTEGER NOT NULL CHECK (verdict_version >= 1),
    procedural_review_id TEXT NOT NULL,
    procedural_review_version INTEGER NOT NULL CHECK (procedural_review_version >= 1),
    disposition TEXT NOT NULL
        CHECK (disposition IN ('ENQUEUE', 'SUPPRESSED_MERGED', 'CLOSE_NO_ALERT')),
    alert_id TEXT,
    final_decision TEXT NOT NULL
        CHECK (final_decision IN ('ESTABLISHED', 'NOT_ESTABLISHED', 'INSUFFICIENT_EVIDENCE')),
    config_sha256 TEXT NOT NULL
        CHECK (length(config_sha256) = 64 AND config_sha256 NOT GLOB '*[^0-9a-f]*'),
    manifest_id TEXT NOT NULL,
    authority_json TEXT NOT NULL CHECK (json_valid(authority_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, authority_id),
    UNIQUE (run_id, case_id),
    UNIQUE (run_id, policy_request_id),
    FOREIGN KEY (run_id, case_id, source_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, closing_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, case_id, verdict_id, verdict_version)
        REFERENCES verdicts(run_id, case_id, verdict_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, procedural_review_id)
        REFERENCES procedural_reviews(run_id, review_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (disposition = 'CLOSE_NO_ALERT' AND alert_id IS NULL)
        OR (disposition <> 'CLOSE_NO_ALERT' AND alert_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE alert_cooldowns (
    run_id TEXT NOT NULL,
    key_id TEXT NOT NULL
        CHECK (length(key_id) = 64 AND key_id NOT GLOB '*[^0-9a-f]*'),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    authority_id TEXT NOT NULL
        CHECK (length(authority_id) = 64 AND authority_id NOT GLOB '*[^0-9a-f]*'),
    zone_id TEXT NOT NULL,
    violation_type TEXT NOT NULL,
    track_ref TEXT NOT NULL,
    tracker_epoch TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    stream_authority_sha256 TEXT NOT NULL
        CHECK (
            length(stream_authority_sha256) = 64
            AND stream_authority_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    source_alert_id TEXT NOT NULL,
    source_trigger_frame INTEGER NOT NULL CHECK (source_trigger_frame >= 0),
    cooldown_until_frame_exclusive INTEGER NOT NULL
        CHECK (cooldown_until_frame_exclusive >= source_trigger_frame),
    manifest_id TEXT NOT NULL,
    authority_json TEXT NOT NULL CHECK (json_valid(authority_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, key_id, revision),
    UNIQUE (run_id, authority_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE alert_outbox (
    run_id TEXT NOT NULL,
    outbox_id TEXT NOT NULL
        CHECK (length(outbox_id) = 64 AND outbox_id NOT GLOB '*[^0-9a-f]*'),
    alert_authority_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    case_authority_sha256 TEXT NOT NULL
        CHECK (length(case_authority_sha256) = 64 AND case_authority_sha256 NOT GLOB '*[^0-9a-f]*'),
    policy_request_id TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('NORMAL', 'HIGH', 'CRITICAL')),
    idempotency_key TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    outbox_json TEXT NOT NULL CHECK (json_valid(outbox_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, outbox_id),
    UNIQUE (run_id, alert_id),
    UNIQUE (run_id, idempotency_key),
    FOREIGN KEY (run_id, alert_authority_id)
        REFERENCES alerts(run_id, authority_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (idempotency_key = alert_id)
) STRICT;

CREATE TABLE alert_channel_capabilities (
    run_id TEXT NOT NULL,
    capability_id TEXT NOT NULL
        CHECK (length(capability_id) = 64 AND capability_id NOT GLOB '*[^0-9a-f]*'),
    channel TEXT NOT NULL,
    capability_revision TEXT NOT NULL,
    idempotency_guarantee TEXT NOT NULL
        CHECK (idempotency_guarantee IN ('NONE', 'EXACT_ALERT_ID')),
    provider_idempotency_key TEXT,
    manifest_id TEXT NOT NULL,
    config_sha256 TEXT NOT NULL
        CHECK (length(config_sha256) = 64 AND config_sha256 NOT GLOB '*[^0-9a-f]*'),
    authority_json TEXT NOT NULL CHECK (json_valid(authority_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, capability_id),
    UNIQUE (run_id, channel),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (idempotency_guarantee = 'EXACT_ALERT_ID' AND provider_idempotency_key = 'alert_id')
        OR (idempotency_guarantee = 'NONE' AND provider_idempotency_key IS NULL)
    )
) STRICT;

CREATE TABLE alert_dispatch_attempts (
    run_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL
        CHECK (length(attempt_id) = 64 AND attempt_id NOT GLOB '*[^0-9a-f]*'),
    outbox_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 3),
    fence INTEGER NOT NULL CHECK (fence = attempt_number),
    lease_owner_sha256 TEXT NOT NULL
        CHECK (length(lease_owner_sha256) = 64 AND lease_owner_sha256 NOT GLOB '*[^0-9a-f]*'),
    started_at TEXT NOT NULL CHECK (length(started_at) = 27),
    lease_expires_at TEXT NOT NULL
        CHECK (length(lease_expires_at) = 27 AND lease_expires_at > started_at),
    channel_capability_id TEXT NOT NULL
        CHECK (length(channel_capability_id) = 64 AND channel_capability_id NOT GLOB '*[^0-9a-f]*'),
    idempotency_key TEXT NOT NULL,
    attempt_json TEXT NOT NULL CHECK (json_valid(attempt_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, attempt_id),
    UNIQUE (run_id, outbox_id, attempt_number),
    FOREIGN KEY (run_id, outbox_id)
        REFERENCES alert_outbox(run_id, outbox_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, channel_capability_id)
        REFERENCES alert_channel_capabilities(run_id, capability_id) ON DELETE RESTRICT,
    CHECK (idempotency_key = alert_id)
) STRICT;

CREATE TABLE alert_dispatch_receipts (
    run_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL
        CHECK (length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    attempt_id TEXT NOT NULL,
    outbox_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 3),
    fence INTEGER NOT NULL CHECK (fence = attempt_number),
    lease_owner_sha256 TEXT NOT NULL
        CHECK (length(lease_owner_sha256) = 64 AND lease_owner_sha256 NOT GLOB '*[^0-9a-f]*'),
    channel_capability_id TEXT NOT NULL
        CHECK (length(channel_capability_id) = 64 AND channel_capability_id NOT GLOB '*[^0-9a-f]*'),
    idempotency_key TEXT NOT NULL,
    disposition TEXT NOT NULL
        CHECK (disposition IN ('SUCCEEDED', 'RETRYABLE_FAILURE', 'UNKNOWN_DELIVERY')),
    continuation TEXT NOT NULL
        CHECK (continuation IN ('CLOSED', 'RETRY_ALLOWED', 'ATTENTION_REQUIRED')),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, receipt_id),
    UNIQUE (run_id, attempt_id),
    FOREIGN KEY (run_id, attempt_id)
        REFERENCES alert_dispatch_attempts(run_id, attempt_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, outbox_id)
        REFERENCES alert_outbox(run_id, outbox_id) ON DELETE RESTRICT,
    CHECK (idempotency_key = alert_id),
    CHECK (
        (disposition = 'SUCCEEDED' AND continuation = 'CLOSED')
        OR (disposition <> 'SUCCEEDED' AND continuation <> 'CLOSED')
    )
) STRICT;

CREATE TABLE m5_immediate_safety_deliveries (
    run_id TEXT NOT NULL,
    authority_id TEXT NOT NULL
        CHECK (length(authority_id) = 64 AND authority_id NOT GLOB '*[^0-9a-f]*'),
    incident_id TEXT NOT NULL,
    signal_id TEXT NOT NULL,
    zone_id TEXT NOT NULL,
    delivery_idempotency_key TEXT NOT NULL,
    delivery_alert_id TEXT NOT NULL,
    delivery_channel TEXT NOT NULL,
    provider_receipt_ref TEXT,
    manifest_id TEXT NOT NULL,
    authority_json TEXT NOT NULL CHECK (json_valid(authority_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, authority_id),
    UNIQUE (run_id, incident_id),
    UNIQUE (run_id, delivery_idempotency_key),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (delivery_alert_id = incident_id),
    CHECK (delivery_idempotency_key = incident_id OR length(delivery_idempotency_key) > 0)
) STRICT;

CREATE TABLE appeals (
    run_id TEXT NOT NULL,
    appeal_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 3),
    authority_sha256 TEXT NOT NULL
        CHECK (length(authority_sha256) = 64 AND authority_sha256 NOT GLOB '*[^0-9a-f]*'),
    previous_authority_sha256 TEXT,
    case_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SUBMITTED', 'UNDER_REVIEW', 'UPHELD', 'OVERTURNED')),
    assigned_reviewer_id TEXT,
    source_case_revision INTEGER NOT NULL CHECK (source_case_revision >= 1),
    source_case_authority_sha256 TEXT NOT NULL,
    source_verdict_id TEXT NOT NULL,
    source_verdict_version INTEGER NOT NULL CHECK (source_verdict_version >= 1),
    source_verdict_sha256 TEXT NOT NULL,
    source_decision TEXT NOT NULL
        CHECK (source_decision IN ('ESTABLISHED', 'NOT_ESTABLISHED', 'INSUFFICIENT_EVIDENCE')),
    text_embedding_manifest_id TEXT NOT NULL,
    visual_embedding_manifest_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    authority_json TEXT NOT NULL CHECK (json_valid(authority_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, appeal_id, version),
    UNIQUE (run_id, authority_sha256),
    UNIQUE (run_id, appeal_id, authority_sha256),
    FOREIGN KEY (run_id, case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, source_verdict_id, source_verdict_version)
        REFERENCES verdicts(run_id, case_id, verdict_id, version) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (version = 1 AND status = 'SUBMITTED' AND previous_authority_sha256 IS NULL
            AND assigned_reviewer_id IS NULL)
        OR (version = 2 AND status = 'UNDER_REVIEW' AND previous_authority_sha256 IS NOT NULL
            AND assigned_reviewer_id IS NOT NULL)
        OR (version = 3 AND status IN ('UPHELD', 'OVERTURNED')
            AND previous_authority_sha256 IS NOT NULL AND assigned_reviewer_id IS NOT NULL)
    )
) STRICT;

CREATE TABLE appeal_resolution_receipts (
    run_id TEXT NOT NULL,
    intent_id TEXT NOT NULL
        CHECK (length(intent_id) = 64 AND intent_id NOT GLOB '*[^0-9a-f]*'),
    appeal_id TEXT NOT NULL,
    appeal_authority_sha256 TEXT NOT NULL,
    case_id TEXT NOT NULL,
    final_decision TEXT NOT NULL
        CHECK (final_decision IN ('ESTABLISHED', 'NOT_ESTABLISHED', 'INSUFFICIENT_EVIDENCE')),
    final_decision_changed INTEGER NOT NULL CHECK (final_decision_changed IN (0, 1)),
    affected_citation_report_sha256 TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    intent_json TEXT NOT NULL CHECK (json_valid(intent_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, intent_id),
    UNIQUE (run_id, appeal_id),
    UNIQUE (run_id, intent_id, document_sha256),
    FOREIGN KEY (run_id, appeal_id, appeal_authority_sha256)
        REFERENCES appeals(run_id, appeal_id, authority_sha256) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE appeal_resolution_commit_receipts (
    run_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL
        CHECK (length(receipt_id) = 64 AND receipt_id NOT GLOB '*[^0-9a-f]*'),
    effect_root_sha256 TEXT NOT NULL
        CHECK (
            length(effect_root_sha256) = 64
            AND effect_root_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    resolution_intent_id TEXT NOT NULL
        CHECK (
            length(resolution_intent_id) = 64
            AND resolution_intent_id NOT GLOB '*[^0-9a-f]*'
        ),
    resolution_document_sha256 TEXT NOT NULL
        CHECK (
            length(resolution_document_sha256) = 64
            AND resolution_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    appeal_id TEXT NOT NULL,
    appeal_authority_sha256 TEXT NOT NULL
        CHECK (
            length(appeal_authority_sha256) = 64
            AND appeal_authority_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    case_id TEXT NOT NULL,
    source_case_revision INTEGER NOT NULL CHECK (source_case_revision >= 1),
    resulting_case_revision INTEGER NOT NULL CHECK (
        resulting_case_revision = source_case_revision + 3
    ),
    resulting_case_document_sha256 TEXT NOT NULL
        CHECK (
            length(resulting_case_document_sha256) = 64
            AND resulting_case_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    verdict_rescission_ids_json TEXT NOT NULL CHECK (
        json_valid(verdict_rescission_ids_json)
        AND json_type(verdict_rescission_ids_json) = 'array'
        AND json_array_length(verdict_rescission_ids_json) <= 1
    ),
    alert_rescission_ids_json TEXT NOT NULL CHECK (
        json_valid(alert_rescission_ids_json)
        AND json_type(alert_rescission_ids_json) = 'array'
        AND json_array_length(alert_rescission_ids_json) <= 10000
    ),
    precedent_revocation_receipt_ids_json TEXT NOT NULL CHECK (
        json_valid(precedent_revocation_receipt_ids_json)
        AND json_type(precedent_revocation_receipt_ids_json) = 'array'
        AND json_array_length(precedent_revocation_receipt_ids_json) <= 10000
    ),
    replacement_precedent_authority_id TEXT CHECK (
        replacement_precedent_authority_id IS NULL
        OR (
            length(replacement_precedent_authority_id) = 64
            AND replacement_precedent_authority_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    training_label_ids_json TEXT NOT NULL CHECK (
        json_valid(training_label_ids_json)
        AND json_type(training_label_ids_json) = 'array'
        AND json_array_length(training_label_ids_json) <= 10000
    ),
    affected_citation_report_sha256 TEXT NOT NULL
        CHECK (
            length(affected_citation_report_sha256) = 64
            AND affected_citation_report_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, receipt_id),
    UNIQUE (run_id, effect_root_sha256),
    UNIQUE (run_id, resolution_intent_id),
    UNIQUE (run_id, appeal_id),
    UNIQUE (run_id, receipt_id, effect_root_sha256, resolution_intent_id),
    FOREIGN KEY (run_id, resolution_intent_id, resolution_document_sha256)
        REFERENCES appeal_resolution_receipts(run_id, intent_id, document_sha256)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, appeal_id, appeal_authority_sha256)
        REFERENCES appeals(run_id, appeal_id, authority_sha256) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, source_case_revision)
        REFERENCES case_versions(run_id, case_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, case_id, resulting_case_revision, resulting_case_document_sha256
    ) REFERENCES case_versions(run_id, case_id, revision, document_sha256)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (
            replacement_precedent_authority_id IS NOT NULL
            AND json_array_length(verdict_rescission_ids_json) = 1
            AND json_array_length(precedent_revocation_receipt_ids_json) >= 1
            AND json_array_length(training_label_ids_json) >= 1
        )
        OR
        (
            replacement_precedent_authority_id IS NULL
            AND json_array_length(verdict_rescission_ids_json) = 0
            AND json_array_length(alert_rescission_ids_json) = 0
            AND json_array_length(precedent_revocation_receipt_ids_json) = 0
        )
    )
) STRICT;

CREATE TABLE verdict_rescissions (
    run_id TEXT NOT NULL,
    rescission_id TEXT NOT NULL
        CHECK (length(rescission_id) = 64 AND rescission_id NOT GLOB '*[^0-9a-f]*'),
    resolution_intent_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    verdict_id TEXT NOT NULL,
    verdict_version INTEGER NOT NULL CHECK (verdict_version >= 1),
    verdict_sha256 TEXT NOT NULL,
    rescission_json TEXT NOT NULL CHECK (json_valid(rescission_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, rescission_id),
    UNIQUE (run_id, verdict_id, verdict_version),
    FOREIGN KEY (run_id, resolution_intent_id)
        REFERENCES appeal_resolution_receipts(run_id, intent_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, verdict_id, verdict_version)
        REFERENCES verdicts(run_id, case_id, verdict_id, version) ON DELETE RESTRICT
) STRICT;

CREATE TABLE alert_rescissions (
    run_id TEXT NOT NULL,
    rescission_id TEXT NOT NULL
        CHECK (length(rescission_id) = 64 AND rescission_id NOT GLOB '*[^0-9a-f]*'),
    resolution_intent_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    rescission_json TEXT NOT NULL CHECK (json_valid(rescission_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, rescission_id),
    UNIQUE (run_id, alert_id),
    FOREIGN KEY (run_id, resolution_intent_id)
        REFERENCES appeal_resolution_receipts(run_id, intent_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE m5_training_causal_events (
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 100000),
    event_id TEXT NOT NULL
        CHECK (length(event_id) = 64 AND event_id NOT GLOB '*[^0-9a-f]*'),
    source_identity TEXT NOT NULL
        CHECK (length(source_identity) = 64 AND source_identity NOT GLOB '*[^0-9a-f]*'),
    event_kind TEXT NOT NULL CHECK (
        event_kind IN ('TRAINING_LABEL_APPENDED', 'DATASET_REGISTRATION_COMMITTED')
    ),
    source_id TEXT NOT NULL
        CHECK (length(source_id) = 64 AND source_id NOT GLOB '*[^0-9a-f]*'),
    source_document_sha256 TEXT NOT NULL
        CHECK (
            length(source_document_sha256) = 64
            AND source_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    previous_event_sha256 TEXT NOT NULL
        CHECK (
            length(previous_event_sha256) = 64
            AND previous_event_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    event_sha256 TEXT NOT NULL
        CHECK (length(event_sha256) = 64 AND event_sha256 NOT GLOB '*[^0-9a-f]*'),
    label_id TEXT,
    event_json TEXT NOT NULL CHECK (json_valid(event_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, sequence),
    UNIQUE (run_id, event_id),
    UNIQUE (run_id, source_identity),
    UNIQUE (run_id, event_sha256),
    UNIQUE (run_id, event_kind, source_id),
    UNIQUE (run_id, label_id),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, label_id)
        REFERENCES training_labels(run_id, label_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (event_kind = 'TRAINING_LABEL_APPENDED' AND label_id IS NOT NULL)
        OR
        (event_kind = 'DATASET_REGISTRATION_COMMITTED' AND label_id IS NULL)
    )
) STRICT;

CREATE TABLE training_labels (
    run_id TEXT NOT NULL,
    label_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    crop_id TEXT NOT NULL
        CHECK (length(crop_id) = 64 AND crop_id NOT GLOB '*[^0-9a-f]*'),
    quality TEXT NOT NULL
        CHECK (quality IN ('WEAK_AUTO', 'CONSENSUS_REVIEWED', 'HUMAN_CONFIRMED', 'APPEAL_CONFIRMED')),
    source TEXT NOT NULL,
    reviewer_id TEXT,
    rule_version TEXT NOT NULL,
    detector_manifest_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    strong_provenance_id TEXT CHECK (
        strong_provenance_id IS NULL
        OR (
            length(strong_provenance_id) = 64
            AND strong_provenance_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    label_json TEXT NOT NULL CHECK (json_valid(label_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, label_id),
    UNIQUE (run_id, strong_provenance_id),
    FOREIGN KEY (run_id, case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, strong_provenance_id)
        REFERENCES strong_training_label_provenance_receipts(run_id, provenance_id)
        ON DELETE RESTRICT,
    CHECK (
        (
            quality IN ('HUMAN_CONFIRMED', 'APPEAL_CONFIRMED')
            AND strong_provenance_id IS NOT NULL
        )
        OR
        (
            quality IN ('WEAK_AUTO', 'CONSENSUS_REVIEWED')
            AND strong_provenance_id IS NULL
        )
    )
) STRICT;

CREATE TABLE strong_training_label_provenance_receipts (
    run_id TEXT NOT NULL,
    provenance_id TEXT NOT NULL
        CHECK (length(provenance_id) = 64 AND provenance_id NOT GLOB '*[^0-9a-f]*'),
    case_id TEXT NOT NULL CHECK (length(case_id) >= 1),
    appeal_id TEXT NOT NULL CHECK (length(appeal_id) >= 1),
    label_id TEXT NOT NULL
        CHECK (length(label_id) = 64 AND label_id NOT GLOB '*[^0-9a-f]*'),
    label_document_sha256 TEXT NOT NULL
        CHECK (
            length(label_document_sha256) = 64
            AND label_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    crop_id TEXT NOT NULL
        CHECK (length(crop_id) = 64 AND crop_id NOT GLOB '*[^0-9a-f]*'),
    reviewer_id TEXT NOT NULL CHECK (length(reviewer_id) >= 1),
    quality TEXT NOT NULL CHECK (quality IN ('HUMAN_CONFIRMED', 'APPEAL_CONFIRMED')),
    authored_input_id TEXT NOT NULL
        CHECK (length(authored_input_id) = 64 AND authored_input_id NOT GLOB '*[^0-9a-f]*'),
    review_authority_sha256 TEXT NOT NULL
        CHECK (
            length(review_authority_sha256) = 64
            AND review_authority_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    terminal_authority_sha256 TEXT NOT NULL
        CHECK (
            length(terminal_authority_sha256) = 64
            AND terminal_authority_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    terminal_status TEXT NOT NULL CHECK (terminal_status IN ('UPHELD', 'OVERTURNED')),
    resolution_intent_id TEXT NOT NULL
        CHECK (
            length(resolution_intent_id) = 64
            AND resolution_intent_id NOT GLOB '*[^0-9a-f]*'
        ),
    resolution_document_sha256 TEXT NOT NULL
        CHECK (
            length(resolution_document_sha256) = 64
            AND resolution_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    resolution_commit_receipt_id TEXT NOT NULL
        CHECK (
            length(resolution_commit_receipt_id) = 64
            AND resolution_commit_receipt_id NOT GLOB '*[^0-9a-f]*'
        ),
    resolution_commit_effect_root_sha256 TEXT NOT NULL
        CHECK (
            length(resolution_commit_effect_root_sha256) = 64
            AND resolution_commit_effect_root_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    rule_version TEXT NOT NULL CHECK (length(rule_version) BETWEEN 1 AND 128),
    detector_manifest_id TEXT NOT NULL
        CHECK (
            length(detector_manifest_id) = 64
            AND detector_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    provenance_json TEXT NOT NULL CHECK (json_valid(provenance_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, provenance_id),
    UNIQUE (run_id, label_id),
    UNIQUE (run_id, review_authority_sha256, authored_input_id),
    FOREIGN KEY (
        run_id, label_id, label_document_sha256, case_id, crop_id, reviewer_id,
        quality, rule_version, detector_manifest_id, manifest_id, provenance_id
    ) REFERENCES training_labels(
        run_id, label_id, document_sha256, case_id, crop_id, reviewer_id,
        quality, rule_version, detector_manifest_id, manifest_id, strong_provenance_id
    ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, case_id)
        REFERENCES cases(run_id, case_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, appeal_id, review_authority_sha256)
        REFERENCES appeals(run_id, appeal_id, authority_sha256) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, appeal_id, terminal_authority_sha256)
        REFERENCES appeals(run_id, appeal_id, authority_sha256) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, resolution_intent_id, resolution_document_sha256)
        REFERENCES appeal_resolution_receipts(run_id, intent_id, document_sha256)
        ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, resolution_commit_receipt_id,
        resolution_commit_effect_root_sha256, resolution_intent_id
    ) REFERENCES appeal_resolution_commit_receipts(
        run_id, receipt_id, effect_root_sha256, resolution_intent_id
    ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    CHECK (
        (terminal_status = 'UPHELD' AND quality = 'HUMAN_CONFIRMED')
        OR
        (terminal_status = 'OVERTURNED' AND quality = 'APPEAL_CONFIRMED')
    )
) STRICT;

CREATE TABLE dataset_registration_snapshots (
    run_id TEXT NOT NULL,
    authority_id TEXT NOT NULL
        CHECK (length(authority_id) = 64 AND authority_id NOT GLOB '*[^0-9a-f]*'),
    dataset_id TEXT NOT NULL CHECK (length(dataset_id) >= 1),
    report_id TEXT NOT NULL
        CHECK (length(report_id) = 64 AND report_id NOT GLOB '*[^0-9a-f]*'),
    command_id TEXT NOT NULL
        CHECK (length(command_id) = 64 AND command_id NOT GLOB '*[^0-9a-f]*'),
    report_document_sha256 TEXT NOT NULL
        CHECK (
            length(report_document_sha256) = 64
            AND report_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    causal_cut_sequence INTEGER NOT NULL CHECK (causal_cut_sequence BETWEEN 0 AND 100000),
    causal_cut_event_id TEXT CHECK (
        causal_cut_event_id IS NULL
        OR (
            length(causal_cut_event_id) = 64
            AND causal_cut_event_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    causal_cut_event_sha256 TEXT NOT NULL
        CHECK (
            length(causal_cut_event_sha256) = 64
            AND causal_cut_event_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    label_count INTEGER NOT NULL CHECK (label_count BETWEEN 0 AND 10000),
    label_inventory_root_sha256 TEXT NOT NULL
        CHECK (
            length(label_inventory_root_sha256) = 64
            AND label_inventory_root_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    crop_count INTEGER NOT NULL CHECK (crop_count BETWEEN 0 AND 10000),
    crop_inventory_root_sha256 TEXT NOT NULL
        CHECK (
            length(crop_inventory_root_sha256) = 64
            AND crop_inventory_root_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    manifest_id TEXT NOT NULL
        CHECK (length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'),
    rule_version TEXT NOT NULL CHECK (length(rule_version) BETWEEN 1 AND 128),
    detector_manifest_id TEXT NOT NULL
        CHECK (
            length(detector_manifest_id) = 64
            AND detector_manifest_id NOT GLOB '*[^0-9a-f]*'
        ),
    snapshot_json TEXT NOT NULL CHECK (json_valid(snapshot_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, authority_id),
    UNIQUE (run_id, dataset_id),
    UNIQUE (run_id, report_id),
    UNIQUE (run_id, command_id),
    UNIQUE (run_id, authority_id, dataset_id, report_id),
    UNIQUE (run_id, authority_id, dataset_id, report_id, command_id),
    UNIQUE (
        run_id, authority_id, dataset_id, report_id,
        report_document_sha256, manifest_id, rule_version, detector_manifest_id
    ),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, causal_cut_sequence, causal_cut_event_id, causal_cut_event_sha256
    ) REFERENCES m5_training_causal_events(
        run_id, sequence, event_id, event_sha256
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, dataset_id, report_id, command_id, authority_id
    ) REFERENCES dataset_artifacts(
        run_id, dataset_id, report_id, command_id, registration_snapshot_authority_id
    ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (
            causal_cut_sequence = 0
            AND causal_cut_event_id IS NULL
            AND causal_cut_event_sha256 = printf('%064d', 0)
        )
        OR
        (
            causal_cut_sequence > 0
            AND causal_cut_event_id IS NOT NULL
            AND causal_cut_event_sha256 <> printf('%064d', 0)
        )
    ),
    CHECK (crop_count <= label_count)
) STRICT;

CREATE TABLE dataset_crop_snapshots (
    run_id TEXT NOT NULL,
    authority_id TEXT NOT NULL
        CHECK (length(authority_id) = 64 AND authority_id NOT GLOB '*[^0-9a-f]*'),
    registration_snapshot_authority_id TEXT NOT NULL
        CHECK (
            length(registration_snapshot_authority_id) = 64
            AND registration_snapshot_authority_id NOT GLOB '*[^0-9a-f]*'
        ),
    dataset_id TEXT NOT NULL CHECK (length(dataset_id) >= 1),
    report_id TEXT NOT NULL
        CHECK (length(report_id) = 64 AND report_id NOT GLOB '*[^0-9a-f]*'),
    crop_id TEXT NOT NULL
        CHECK (length(crop_id) = 64 AND crop_id NOT GLOB '*[^0-9a-f]*'),
    crop_authority_sha256 TEXT NOT NULL
        CHECK (
            length(crop_authority_sha256) = 64
            AND crop_authority_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    case_id TEXT NOT NULL CHECK (length(case_id) >= 1),
    case_revision INTEGER NOT NULL CHECK (case_revision >= 1),
    case_document_sha256 TEXT NOT NULL
        CHECK (
            length(case_document_sha256) = 64
            AND case_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    evidence_pack_id TEXT NOT NULL
        CHECK (length(evidence_pack_id) = 64 AND evidence_pack_id NOT GLOB '*[^0-9a-f]*'),
    evidence_pack_version INTEGER NOT NULL CHECK (evidence_pack_version >= 1),
    evidence_pack_document_sha256 TEXT NOT NULL
        CHECK (
            length(evidence_pack_document_sha256) = 64
            AND evidence_pack_document_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
    authority_json TEXT NOT NULL CHECK (json_valid(authority_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, authority_id),
    UNIQUE (run_id, registration_snapshot_authority_id, crop_id),
    UNIQUE (run_id, registration_snapshot_authority_id, crop_authority_sha256),
    FOREIGN KEY (
        run_id, registration_snapshot_authority_id, dataset_id, report_id
    ) REFERENCES dataset_registration_snapshots(
        run_id, authority_id, dataset_id, report_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, case_revision, case_document_sha256)
        REFERENCES case_versions(run_id, case_id, revision, document_sha256)
        ON DELETE RESTRICT,
    FOREIGN KEY (
        run_id, case_id, evidence_pack_id,
        evidence_pack_version, evidence_pack_document_sha256
    ) REFERENCES evidence_packs(
        run_id, case_id, pack_id, version, document_sha256
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE dataset_artifacts (
    run_id TEXT NOT NULL,
    dataset_id TEXT NOT NULL,
    report_id TEXT NOT NULL
        CHECK (length(report_id) = 64 AND report_id NOT GLOB '*[^0-9a-f]*'),
    command_id TEXT NOT NULL
        CHECK (length(command_id) = 64 AND command_id NOT GLOB '*[^0-9a-f]*'),
    format TEXT NOT NULL CHECK (format = 'COCO'),
    relative_path TEXT NOT NULL,
    content_sha256 TEXT NOT NULL
        CHECK (length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
    content_size_bytes INTEGER NOT NULL CHECK (content_size_bytes >= 0),
    label_count INTEGER NOT NULL CHECK (label_count >= 0),
    minimum_quality TEXT NOT NULL
        CHECK (minimum_quality IN ('HUMAN_CONFIRMED', 'APPEAL_CONFIRMED')),
    rule_version TEXT NOT NULL,
    detector_manifest_id TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    registration_snapshot_authority_id TEXT NOT NULL
        CHECK (
            length(registration_snapshot_authority_id) = 64
            AND registration_snapshot_authority_id NOT GLOB '*[^0-9a-f]*'
        ),
    artifact_json TEXT NOT NULL CHECK (json_valid(artifact_json)),
    report_json TEXT NOT NULL CHECK (json_valid(report_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (run_id, dataset_id),
    UNIQUE (run_id, report_id),
    UNIQUE (run_id, command_id),
    UNIQUE (run_id, relative_path),
    UNIQUE (
        run_id, dataset_id, report_id, command_id, registration_snapshot_authority_id
    ),
    FOREIGN KEY (run_id, manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, registration_snapshot_authority_id)
        REFERENCES dataset_registration_snapshots(run_id, authority_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE INDEX idx_precedents_retrieval
    ON precedents(run_id, evidence_class, rule_version, status, precedent_id, revision DESC);
CREATE INDEX idx_precedents_source_case
    ON precedents(run_id, source_case_id, precedent_id, revision DESC);
CREATE UNIQUE INDEX uq_precedents_automatic_source_case
    ON precedents(run_id, source_case_id)
    WHERE source = 'AUTOMATIC' AND revision = 1;
CREATE INDEX idx_precedent_embeddings_manifest
    ON precedent_embeddings(run_id, model_manifest_id, channel, embedding_id);
CREATE INDEX idx_precedent_citations_precedent
    ON precedent_citations(run_id, precedent_id, case_id, citation_id);
CREATE INDEX idx_precedent_citations_case
    ON precedent_citations(run_id, case_id, precedent_id, citation_id);
CREATE UNIQUE INDEX uq_precedent_citations_application_binding
    ON precedent_citations(run_id, application_batch_id, application_binding_id)
    WHERE citation_kind = 'APPLIED';
CREATE INDEX idx_m5_precedent_causal_events_authority_watermark
    ON m5_precedent_causal_events(run_id, event_kind, sequence DESC);
CREATE INDEX idx_m5_precedent_exposures_hearing
    ON m5_precedent_exposures(run_id, hearing_id, cycle_index, exposure_id);
CREATE INDEX idx_m5_precedent_application_batches_case
    ON m5_precedent_application_batches(
        run_id, case_id, ready_case_revision, application_batch_id
    );
CREATE INDEX idx_precedent_lifecycle_primary
    ON precedent_lifecycle_receipts(run_id, primary_precedent_id, receipt_kind, receipt_id);
CREATE UNIQUE INDEX uq_precedent_lifecycle_appeal_present_prior
    ON precedent_lifecycle_receipts(
        run_id, primary_precedent_id, primary_prior_authority_id
    )
    WHERE receipt_kind = 'ACTIVATION' AND outcome = 'APPEAL_PRESENT';
CREATE UNIQUE INDEX uq_alerts_alert_id
    ON alerts(run_id, alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX idx_alerts_case
    ON alerts(run_id, case_id, authority_id);
CREATE INDEX idx_alert_cooldowns_lookup
    ON alert_cooldowns(
        run_id, key_id, tracker_epoch, stream_id, source_trigger_frame DESC, revision DESC
    );
CREATE INDEX idx_alert_outbox_case
    ON alert_outbox(run_id, case_id, outbox_id);
CREATE INDEX idx_alert_dispatch_attempts_outbox
    ON alert_dispatch_attempts(run_id, outbox_id, attempt_number);
CREATE INDEX idx_alert_dispatch_receipts_outbox
    ON alert_dispatch_receipts(run_id, outbox_id, attempt_number);
CREATE UNIQUE INDEX uq_alert_dispatch_receipts_success_outbox
    ON alert_dispatch_receipts(run_id, outbox_id) WHERE disposition = 'SUCCEEDED';
CREATE UNIQUE INDEX uq_alert_dispatch_receipts_success_alert
    ON alert_dispatch_receipts(run_id, alert_id) WHERE disposition = 'SUCCEEDED';
CREATE UNIQUE INDEX uq_alert_dispatch_receipts_terminal_outbox
    ON alert_dispatch_receipts(run_id, outbox_id)
    WHERE continuation IN ('CLOSED', 'ATTENTION_REQUIRED');
CREATE INDEX idx_m5_immediate_safety_deliveries_incident
    ON m5_immediate_safety_deliveries(run_id, incident_id, authority_id);
CREATE INDEX idx_appeals_case_current
    ON appeals(run_id, case_id, version DESC, appeal_id);
CREATE INDEX idx_appeals_status
    ON appeals(run_id, status, appeal_id, version DESC);
CREATE INDEX idx_appeal_resolution_case
    ON appeal_resolution_receipts(run_id, case_id, appeal_id);
CREATE INDEX idx_appeal_resolution_commit_case
    ON appeal_resolution_commit_receipts(run_id, case_id, receipt_id);
CREATE UNIQUE INDEX uq_case_versions_revision_document_sha256
    ON case_versions(run_id, case_id, revision, document_sha256);
CREATE UNIQUE INDEX uq_evidence_packs_version_document_sha256
    ON evidence_packs(run_id, case_id, pack_id, version, document_sha256);
CREATE INDEX idx_verdict_rescissions_case
    ON verdict_rescissions(run_id, case_id, verdict_id, verdict_version);
CREATE INDEX idx_alert_rescissions_case
    ON alert_rescissions(run_id, case_id, alert_id);
CREATE INDEX idx_training_labels_quality
    ON training_labels(run_id, quality, label_id);
CREATE INDEX idx_training_labels_crop
    ON training_labels(run_id, crop_id, label_id);
CREATE UNIQUE INDEX uq_m5_training_causal_events_exact_head
    ON m5_training_causal_events(
        run_id, sequence, event_id, event_sha256
    );
CREATE INDEX idx_m5_training_causal_events_kind
    ON m5_training_causal_events(run_id, event_kind, sequence);
CREATE UNIQUE INDEX uq_training_labels_strong_provenance_binding
    ON training_labels(
        run_id, label_id, document_sha256, case_id, crop_id, reviewer_id,
        quality, rule_version, detector_manifest_id, manifest_id, strong_provenance_id
    );
CREATE INDEX idx_strong_training_label_provenance_resolution
    ON strong_training_label_provenance_receipts(
        run_id, resolution_intent_id, label_id
    );
CREATE INDEX idx_dataset_registration_snapshots_cut
    ON dataset_registration_snapshots(
        run_id, causal_cut_sequence, authority_id
    );
CREATE INDEX idx_dataset_crop_snapshots_registration
    ON dataset_crop_snapshots(
        run_id, registration_snapshot_authority_id, crop_id
    );
CREATE INDEX idx_dataset_artifacts_content
    ON dataset_artifacts(run_id, content_sha256, dataset_id);

CREATE TRIGGER precedents_validate_contiguous_revision
BEFORE INSERT ON precedents
WHEN NEW.revision <> COALESCE(
    (
        SELECT MAX(revision) + 1
        FROM precedents
        WHERE run_id = NEW.run_id AND precedent_id = NEW.precedent_id
    ),
    1
)
BEGIN
    SELECT RAISE(ABORT, 'precedent revisions must be contiguous');
END;

CREATE TRIGGER alert_cooldowns_validate_contiguous_revision
BEFORE INSERT ON alert_cooldowns
WHEN NEW.revision <> COALESCE(
    (
        SELECT MAX(revision) + 1
        FROM alert_cooldowns
        WHERE run_id = NEW.run_id AND key_id = NEW.key_id
    ),
    1
)
BEGIN
    SELECT RAISE(ABORT, 'alert cooldown revisions must be contiguous');
END;

CREATE TRIGGER alert_dispatch_attempts_validate_contiguous_attempt
BEFORE INSERT ON alert_dispatch_attempts
WHEN NEW.attempt_number <> COALESCE(
        (
            SELECT MAX(attempt_number) + 1
            FROM alert_dispatch_attempts
            WHERE run_id = NEW.run_id AND outbox_id = NEW.outbox_id
        ),
        1
    )
    OR (
        NEW.attempt_number > 1
        AND COALESCE(
            (
                SELECT continuation
                FROM alert_dispatch_receipts
                WHERE run_id = NEW.run_id
                  AND outbox_id = NEW.outbox_id
                  AND attempt_number = NEW.attempt_number - 1
            ),
            ''
        ) <> 'RETRY_ALLOWED'
    )
BEGIN
    SELECT RAISE(ABORT, 'alert dispatch attempt requires a contiguous retry authority');
END;

CREATE TRIGGER appeals_validate_contiguous_version
BEFORE INSERT ON appeals
WHEN NEW.version <> COALESCE(
    (
        SELECT MAX(version) + 1
        FROM appeals
        WHERE run_id = NEW.run_id AND appeal_id = NEW.appeal_id
    ),
    1
)
BEGIN
    SELECT RAISE(ABORT, 'appeal versions must be contiguous');
END;

CREATE TRIGGER appeals_validate_predecessor
BEFORE INSERT ON appeals
WHEN NEW.version > 1 AND NEW.previous_authority_sha256 <> (
    SELECT authority_sha256
    FROM appeals
    WHERE run_id = NEW.run_id
      AND appeal_id = NEW.appeal_id
      AND version = NEW.version - 1
)
BEGIN
    SELECT RAISE(ABORT, 'appeal previous authority does not match');
END;


CREATE TRIGGER precedent_embeddings_no_replace
BEFORE INSERT ON precedent_embeddings
WHEN EXISTS (SELECT 1 FROM precedent_embeddings WHERE run_id = NEW.run_id AND (embedding_id = NEW.embedding_id OR request_id = NEW.request_id))
BEGIN
    SELECT RAISE(ABORT, 'precedent_embeddings is append-only');
END;

CREATE TRIGGER precedent_embeddings_no_update
BEFORE UPDATE ON precedent_embeddings
BEGIN
    SELECT RAISE(ABORT, 'precedent_embeddings is append-only');
END;

CREATE TRIGGER precedent_embeddings_no_delete
BEFORE DELETE ON precedent_embeddings
BEGIN
    SELECT RAISE(ABORT, 'precedent_embeddings is append-only');
END;

CREATE TRIGGER precedents_no_replace
BEFORE INSERT ON precedents
WHEN EXISTS (SELECT 1 FROM precedents WHERE run_id = NEW.run_id AND ((precedent_id = NEW.precedent_id AND revision = NEW.revision) OR authority_id = NEW.authority_id))
BEGIN
    SELECT RAISE(ABORT, 'precedents is append-only');
END;

CREATE TRIGGER precedents_no_update
BEFORE UPDATE ON precedents
BEGIN
    SELECT RAISE(ABORT, 'precedents is append-only');
END;

CREATE TRIGGER precedents_no_delete
BEFORE DELETE ON precedents
BEGIN
    SELECT RAISE(ABORT, 'precedents is append-only');
END;

CREATE TRIGGER precedent_citations_no_replace
BEFORE INSERT ON precedent_citations
WHEN EXISTS (SELECT 1 FROM precedent_citations WHERE run_id = NEW.run_id AND (citation_id = NEW.citation_id OR commit_id = NEW.commit_id OR (case_id = NEW.case_id AND precedent_id = NEW.precedent_id AND query_id = NEW.query_id)))
BEGIN
    SELECT RAISE(ABORT, 'precedent_citations is append-only');
END;

CREATE TRIGGER precedent_citations_no_update
BEFORE UPDATE ON precedent_citations
BEGIN
    SELECT RAISE(ABORT, 'precedent_citations is append-only');
END;

CREATE TRIGGER precedent_citations_no_delete
BEFORE DELETE ON precedent_citations
BEGIN
    SELECT RAISE(ABORT, 'precedent_citations is append-only');
END;

CREATE TRIGGER m5_precedent_causal_events_validate_contiguous_sequence
BEFORE INSERT ON m5_precedent_causal_events
WHEN NEW.sequence <> COALESCE(
    (
        SELECT MAX(sequence) + 1
        FROM m5_precedent_causal_events
        WHERE run_id = NEW.run_id
    ),
    1
)
BEGIN
    SELECT RAISE(ABORT, 'M5 precedent causal event sequence is not contiguous');
END;

CREATE TRIGGER m5_precedent_causal_events_validate_predecessor
BEFORE INSERT ON m5_precedent_causal_events
WHEN (
    NEW.sequence = 1
    AND NEW.previous_event_sha256 <> printf('%064d', 0)
) OR (
    NEW.sequence > 1
    AND NOT EXISTS (
        SELECT 1
        FROM m5_precedent_causal_events
        WHERE run_id = NEW.run_id
          AND sequence = NEW.sequence - 1
          AND event_sha256 = NEW.previous_event_sha256
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M5 precedent causal event predecessor is invalid');
END;

CREATE TRIGGER m5_precedent_causal_events_validate_semantic_order
BEFORE INSERT ON m5_precedent_causal_events
WHEN (
    NEW.event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
    AND COALESCE(
        (
            SELECT MAX(precedent_revision)
            FROM m5_precedent_causal_events
            WHERE run_id = NEW.run_id
              AND event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
              AND precedent_id = NEW.precedent_id
        ),
        0
    ) <> NEW.precedent_revision - 1
) OR (
    NEW.event_kind = 'PRECEDENT_CITATION_APPENDED'
    AND NOT EXISTS (
        SELECT 1
        FROM m5_precedent_causal_events
        WHERE run_id = NEW.run_id
          AND event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
          AND precedent_id = NEW.precedent_id
          AND precedent_authority_id = NEW.precedent_authority_id
          AND precedent_revision = NEW.precedent_revision
          AND sequence < NEW.sequence
    )
) OR (
    NEW.event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
    AND NOT EXISTS (
        SELECT 1
        FROM precedent_conflict_batch_receipts AS receipt
        JOIN precedent_conflict_batches AS batch
          ON batch.run_id = receipt.run_id
         AND batch.batch_authority_id = receipt.batch_authority_id
         AND batch.causal_cut_id = receipt.causal_cut_id
        WHERE receipt.run_id = NEW.run_id
          AND receipt.receipt_id = NEW.source_id
          AND NEW.sequence > batch.authority_event_sequence
          AND (
              (
                  batch.authority_event_sequence = 0
                  AND batch.authority_event_sha256 = printf('%064d', 0)
              )
              OR EXISTS (
                  SELECT 1
                  FROM m5_precedent_causal_events AS cut_event
                  WHERE cut_event.run_id = NEW.run_id
                    AND cut_event.sequence = batch.authority_event_sequence
                    AND cut_event.event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
                    AND cut_event.event_sha256 = batch.authority_event_sha256
              )
          )
          AND COALESCE(
              (
                  SELECT group_concat(interval_event.source_id, '|')
                  FROM (
                      SELECT source_id
                      FROM m5_precedent_causal_events
                      WHERE run_id = NEW.run_id
                        AND event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
                        AND sequence > batch.authority_event_sequence
                        AND sequence < NEW.sequence
                      ORDER BY sequence
                  ) AS interval_event
              ),
              ''
          ) = COALESCE(
              (
                  SELECT group_concat(changed_result.resulting_authority_id, '|')
                  FROM (
                      SELECT
                          json_extract(value, '$.resulting_authority_id')
                              AS resulting_authority_id
                      FROM json_each(receipt.receipt_json, '$.results')
                      WHERE json_extract(value, '$.resulting_authority_id')
                            <> json_extract(value, '$.prior_authority_id')
                      ORDER BY CAST(key AS INTEGER)
                  ) AS changed_result
              ),
              ''
          )
    )
) OR (
    NEW.event_kind = 'PRECEDENT_REVOCATION_COMMITTED'
    AND NOT (
        EXISTS (
            SELECT 1
            FROM precedent_lifecycle_receipts AS receipt
            JOIN m5_precedent_causal_events AS authority_event
              ON authority_event.run_id = receipt.run_id
             AND authority_event.sequence = NEW.sequence - 1
             AND authority_event.event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
             AND authority_event.source_id = receipt.primary_resulting_authority_id
             AND authority_event.precedent_id = receipt.primary_precedent_id
             AND authority_event.precedent_authority_id
                 = receipt.primary_resulting_authority_id
             AND authority_event.precedent_revision
                 = receipt.primary_resulting_revision
            JOIN precedents AS authority
              ON authority.run_id = authority_event.run_id
             AND authority.precedent_id = authority_event.precedent_id
             AND authority.authority_id = authority_event.precedent_authority_id
             AND authority.revision = authority_event.precedent_revision
            WHERE receipt.run_id = NEW.run_id
              AND receipt.receipt_id = NEW.source_id
              AND receipt.receipt_kind = 'REVOCATION'
              AND receipt.outcome = 'REVOKED'
              AND authority.status = 'REVOKED'
        )
        OR EXISTS (
            SELECT 1
            FROM precedent_lifecycle_receipts AS receipt
            JOIN m5_precedent_causal_events AS authority_event
              ON authority_event.run_id = receipt.run_id
             AND authority_event.event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
             AND authority_event.source_id = receipt.primary_resulting_authority_id
             AND authority_event.precedent_id = receipt.primary_precedent_id
             AND authority_event.precedent_authority_id
                 = receipt.primary_resulting_authority_id
             AND authority_event.precedent_revision
                 = receipt.primary_resulting_revision
             AND authority_event.sequence < NEW.sequence
            WHERE receipt.run_id = NEW.run_id
              AND receipt.receipt_id = NEW.source_id
              AND receipt.receipt_kind = 'REVOCATION'
              AND receipt.outcome = 'ALREADY_REVOKED'
              AND receipt.primary_resulting_authority_id
                  = receipt.primary_prior_authority_id
              AND receipt.primary_resulting_revision
                  = receipt.primary_prior_revision
        )
    )
) OR (
    NEW.sequence > 1
    AND EXISTS (
        SELECT 1
        FROM m5_precedent_causal_events AS prior_event
        JOIN precedents AS prior_authority
          ON prior_authority.run_id = prior_event.run_id
         AND prior_authority.precedent_id = prior_event.precedent_id
         AND prior_authority.authority_id = prior_event.precedent_authority_id
         AND prior_authority.revision = prior_event.precedent_revision
        WHERE prior_event.run_id = NEW.run_id
          AND prior_event.sequence = NEW.sequence - 1
          AND prior_event.event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
          AND prior_authority.status = 'REVOKED'
          AND NOT (
              NEW.event_kind = 'PRECEDENT_REVOCATION_COMMITTED'
              AND NEW.precedent_id = prior_event.precedent_id
              AND NEW.precedent_authority_id = prior_event.precedent_authority_id
              AND NEW.precedent_revision = prior_event.precedent_revision
          )
    )
) OR (
    NEW.event_kind = 'APPEAL_RESOLUTION_COMMITTED'
    AND EXISTS (
        SELECT 1
        FROM appeal_resolution_commit_receipts AS appeal_commit
        JOIN json_each(
            appeal_commit.precedent_revocation_receipt_ids_json
        ) AS revocation_receipt
        WHERE appeal_commit.run_id = NEW.run_id
          AND appeal_commit.receipt_id = NEW.source_id
          AND NOT EXISTS (
              SELECT 1
              FROM m5_precedent_causal_events AS revocation_event
              WHERE revocation_event.run_id = NEW.run_id
                AND revocation_event.event_kind = 'PRECEDENT_REVOCATION_COMMITTED'
                AND revocation_event.source_id = revocation_receipt.value
                AND revocation_event.sequence < NEW.sequence
          )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M5 precedent causal event semantic order is invalid');
END;

CREATE TRIGGER precedent_conflict_batches_validate_causal_cut
BEFORE INSERT ON precedent_conflict_batches
WHEN NEW.authority_event_sequence > 0
 AND NOT EXISTS (
    SELECT 1
    FROM m5_precedent_causal_events
    WHERE run_id = NEW.run_id
      AND sequence = NEW.authority_event_sequence
      AND event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
      AND event_sha256 = NEW.authority_event_sha256
 )
BEGIN
    SELECT RAISE(ABORT, 'M5 conflict batch authority causal cut is invalid');
END;

CREATE TRIGGER m5_precedent_causal_events_validate_source
BEFORE INSERT ON m5_precedent_causal_events
WHEN COALESCE((
    json_extract(NEW.event_json, '$.schema_version') = 'm5-precedent-causal-event-v1'
    AND json_extract(NEW.event_json, '$.run_id') = NEW.run_id
    AND json_type(NEW.event_json, '$.sequence') = 'integer'
    AND json_extract(NEW.event_json, '$.sequence') = NEW.sequence
    AND json_extract(NEW.event_json, '$.event_kind') = NEW.event_kind
    AND json_extract(NEW.event_json, '$.source_id') = NEW.source_id
    AND json_extract(NEW.event_json, '$.precedent_id') IS NEW.precedent_id
    AND json_extract(NEW.event_json, '$.precedent_authority_id')
        IS NEW.precedent_authority_id
    AND (
        (NEW.precedent_revision IS NULL
            AND json_type(NEW.event_json, '$.precedent_revision') = 'null')
        OR
        (NEW.precedent_revision IS NOT NULL
            AND json_type(NEW.event_json, '$.precedent_revision') = 'integer'
            AND json_extract(NEW.event_json, '$.precedent_revision')
                = NEW.precedent_revision)
    )
    AND json_extract(NEW.event_json, '$.citation_kind') IS NEW.citation_kind
    AND json_extract(NEW.event_json, '$.manifest_id') = NEW.manifest_id
    AND json_extract(NEW.event_json, '$.source_document_sha256')
        = NEW.source_document_sha256
    AND json_extract(NEW.event_json, '$.previous_event_sha256')
        = NEW.previous_event_sha256
    AND json_extract(NEW.event_json, '$.source_identity_sha256')
        = NEW.source_identity_sha256
    AND json_extract(NEW.event_json, '$.event_id') = NEW.event_id
    AND json_extract(NEW.event_json, '$.event_sha256') = NEW.event_sha256
    AND (
        (
            NEW.event_kind IN (
                'PRECEDENT_AUTHORITY_APPENDED',
                'PRECEDENT_REVOCATION_COMMITTED'
            )
            AND json_type(NEW.event_json, '$.precedent_id') = 'text'
            AND json_type(NEW.event_json, '$.precedent_authority_id') = 'text'
            AND json_type(NEW.event_json, '$.precedent_revision') = 'integer'
            AND json_type(NEW.event_json, '$.citation_kind') = 'null'
        )
        OR
        (
            NEW.event_kind = 'PRECEDENT_CITATION_APPENDED'
            AND json_type(NEW.event_json, '$.precedent_id') = 'text'
            AND json_type(NEW.event_json, '$.precedent_authority_id') = 'text'
            AND json_type(NEW.event_json, '$.precedent_revision') = 'integer'
            AND json_type(NEW.event_json, '$.citation_kind') = 'text'
        )
        OR
        (
            NEW.event_kind IN (
                'PRECEDENT_CONFLICT_BATCH_COMMITTED',
                'APPEAL_RESOLUTION_COMMITTED'
            )
            AND json_type(NEW.event_json, '$.precedent_id') = 'null'
            AND json_type(NEW.event_json, '$.precedent_authority_id') = 'null'
            AND json_type(NEW.event_json, '$.precedent_revision') = 'null'
            AND json_type(NEW.event_json, '$.citation_kind') = 'null'
        )
    )
    AND (
        (
            NEW.event_kind = 'PRECEDENT_AUTHORITY_APPENDED'
            AND EXISTS (
                SELECT 1
                FROM precedents
                WHERE run_id = NEW.run_id
                  AND precedent_id = NEW.precedent_id
                  AND authority_id = NEW.source_id
                  AND authority_id = NEW.precedent_authority_id
                  AND revision = NEW.precedent_revision
                  AND manifest_id = NEW.manifest_id
                  AND document_sha256 = NEW.source_document_sha256
            )
        )
        OR
        (
            NEW.event_kind = 'PRECEDENT_CITATION_APPENDED'
            AND EXISTS (
                SELECT 1
                FROM precedent_citations
                WHERE run_id = NEW.run_id
                  AND citation_id = NEW.source_id
                  AND precedent_id = NEW.precedent_id
                  AND precedent_authority_id = NEW.precedent_authority_id
                  AND precedent_revision = NEW.precedent_revision
                  AND citation_kind = NEW.citation_kind
                  AND manifest_id = NEW.manifest_id
                  AND document_sha256 = NEW.source_document_sha256
            )
        )
        OR
        (
            NEW.event_kind = 'PRECEDENT_CONFLICT_BATCH_COMMITTED'
            AND EXISTS (
                SELECT 1
                FROM precedent_conflict_batch_receipts
                WHERE run_id = NEW.run_id
                  AND receipt_id = NEW.source_id
                  AND manifest_id = NEW.manifest_id
                  AND document_sha256 = NEW.source_document_sha256
            )
        )
        OR
        (
            NEW.event_kind = 'PRECEDENT_REVOCATION_COMMITTED'
            AND EXISTS (
                SELECT 1
                FROM precedent_lifecycle_receipts
                WHERE run_id = NEW.run_id
                  AND receipt_id = NEW.source_id
                  AND receipt_kind = 'REVOCATION'
                  AND primary_precedent_id = NEW.precedent_id
                  AND primary_resulting_authority_id = NEW.precedent_authority_id
                  AND primary_resulting_revision = NEW.precedent_revision
                  AND (
                      (
                          outcome = 'REVOKED'
                          AND primary_resulting_revision = primary_prior_revision + 1
                          AND primary_resulting_authority_id <> primary_prior_authority_id
                      )
                      OR
                      (
                          outcome = 'ALREADY_REVOKED'
                          AND primary_resulting_revision = primary_prior_revision
                          AND primary_resulting_authority_id = primary_prior_authority_id
                      )
                  )
                  AND manifest_id = NEW.manifest_id
                  AND document_sha256 = NEW.source_document_sha256
            )
        )
        OR
        (
            NEW.event_kind = 'APPEAL_RESOLUTION_COMMITTED'
            AND EXISTS (
                SELECT 1
                FROM appeal_resolution_commit_receipts
                WHERE run_id = NEW.run_id
                  AND receipt_id = NEW.source_id
                  AND manifest_id = NEW.manifest_id
                  AND document_sha256 = NEW.source_document_sha256
            )
        )
    )
), 0) = 0
BEGIN
    SELECT RAISE(ABORT, 'M5 precedent causal event source or index binding is invalid');
END;

CREATE TRIGGER m5_precedent_causal_events_no_replace
BEFORE INSERT ON m5_precedent_causal_events
WHEN EXISTS (
    SELECT 1
    FROM m5_precedent_causal_events
    WHERE run_id = NEW.run_id
      AND (
          sequence = NEW.sequence
          OR event_id = NEW.event_id
          OR source_identity_sha256 = NEW.source_identity_sha256
          OR event_sha256 = NEW.event_sha256
          OR (event_kind = NEW.event_kind AND source_id = NEW.source_id)
      )
)
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_causal_events is append-only');
END;

CREATE TRIGGER m5_precedent_causal_events_no_update
BEFORE UPDATE ON m5_precedent_causal_events
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_causal_events is append-only');
END;

CREATE TRIGGER m5_precedent_causal_events_no_delete
BEFORE DELETE ON m5_precedent_causal_events
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_causal_events is append-only');
END;

CREATE TRIGGER m5_precedent_exposures_no_replace
BEFORE INSERT ON m5_precedent_exposures
WHEN EXISTS (
    SELECT 1 FROM m5_precedent_exposures
    WHERE run_id = NEW.run_id
      AND (
          exposure_id = NEW.exposure_id
          OR exposure_sha256 = NEW.exposure_sha256
          OR cycle_scope_id = NEW.cycle_scope_id
          OR retrieval_receipt_id = NEW.retrieval_receipt_id
          OR m4_query_id = NEW.m4_query_id
      )
)
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_exposures is append-only');
END;

CREATE TRIGGER m5_precedent_exposures_no_update
BEFORE UPDATE ON m5_precedent_exposures
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_exposures is append-only');
END;

CREATE TRIGGER m5_precedent_exposures_no_delete
BEFORE DELETE ON m5_precedent_exposures
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_exposures is append-only');
END;

CREATE TRIGGER m5_precedent_application_batches_no_replace
BEFORE INSERT ON m5_precedent_application_batches
WHEN EXISTS (
    SELECT 1 FROM m5_precedent_application_batches
    WHERE run_id = NEW.run_id
      AND (
          application_batch_id = NEW.application_batch_id
          OR application_batch_sha256 = NEW.application_batch_sha256
          OR case_id = NEW.case_id
          OR (verdict_id = NEW.verdict_id AND verdict_version = NEW.verdict_version)
          OR (exposure_id = NEW.exposure_id AND verdict_id = NEW.verdict_id)
      )
)
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_application_batches is append-only');
END;

CREATE TRIGGER m5_precedent_application_batches_no_update
BEFORE UPDATE ON m5_precedent_application_batches
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_application_batches is append-only');
END;

CREATE TRIGGER m5_precedent_application_batches_no_delete
BEFORE DELETE ON m5_precedent_application_batches
BEGIN
    SELECT RAISE(ABORT, 'm5_precedent_application_batches is append-only');
END;

CREATE TRIGGER precedent_lifecycle_receipts_no_replace
BEFORE INSERT ON precedent_lifecycle_receipts
WHEN EXISTS (SELECT 1 FROM precedent_lifecycle_receipts WHERE run_id = NEW.run_id AND receipt_id = NEW.receipt_id)
BEGIN
    SELECT RAISE(ABORT, 'precedent_lifecycle_receipts is append-only');
END;

CREATE TRIGGER precedent_lifecycle_receipts_no_update
BEFORE UPDATE ON precedent_lifecycle_receipts
BEGIN
    SELECT RAISE(ABORT, 'precedent_lifecycle_receipts is append-only');
END;

CREATE TRIGGER precedent_lifecycle_receipts_no_delete
BEFORE DELETE ON precedent_lifecycle_receipts
BEGIN
    SELECT RAISE(ABORT, 'precedent_lifecycle_receipts is append-only');
END;

CREATE TRIGGER precedent_conflict_batches_no_replace
BEFORE INSERT ON precedent_conflict_batches
WHEN EXISTS (
    SELECT 1 FROM precedent_conflict_batches
    WHERE run_id = NEW.run_id AND batch_authority_id = NEW.batch_authority_id
)
BEGIN
    SELECT RAISE(ABORT, 'precedent_conflict_batches is append-only');
END;

CREATE TRIGGER precedent_conflict_batches_no_update
BEFORE UPDATE ON precedent_conflict_batches
BEGIN
    SELECT RAISE(ABORT, 'precedent_conflict_batches is append-only');
END;

CREATE TRIGGER precedent_conflict_batches_no_delete
BEFORE DELETE ON precedent_conflict_batches
BEGIN
    SELECT RAISE(ABORT, 'precedent_conflict_batches is append-only');
END;

CREATE TRIGGER precedent_conflict_batch_receipts_no_replace
BEFORE INSERT ON precedent_conflict_batch_receipts
WHEN EXISTS (
    SELECT 1 FROM precedent_conflict_batch_receipts
    WHERE run_id = NEW.run_id
      AND (receipt_id = NEW.receipt_id OR batch_authority_id = NEW.batch_authority_id)
)
BEGIN
    SELECT RAISE(ABORT, 'precedent_conflict_batch_receipts is append-only');
END;

CREATE TRIGGER precedent_conflict_batch_receipts_no_update
BEFORE UPDATE ON precedent_conflict_batch_receipts
BEGIN
    SELECT RAISE(ABORT, 'precedent_conflict_batch_receipts is append-only');
END;

CREATE TRIGGER precedent_conflict_batch_receipts_no_delete
BEFORE DELETE ON precedent_conflict_batch_receipts
BEGIN
    SELECT RAISE(ABORT, 'precedent_conflict_batch_receipts is append-only');
END;

CREATE TRIGGER alerts_no_replace
BEFORE INSERT ON alerts
WHEN EXISTS (SELECT 1 FROM alerts WHERE run_id = NEW.run_id AND (authority_id = NEW.authority_id OR case_id = NEW.case_id OR policy_request_id = NEW.policy_request_id OR (NEW.alert_id IS NOT NULL AND alert_id = NEW.alert_id)))
BEGIN
    SELECT RAISE(ABORT, 'alerts is append-only');
END;

CREATE TRIGGER alerts_no_update
BEFORE UPDATE ON alerts
BEGIN
    SELECT RAISE(ABORT, 'alerts is append-only');
END;

CREATE TRIGGER alerts_no_delete
BEFORE DELETE ON alerts
BEGIN
    SELECT RAISE(ABORT, 'alerts is append-only');
END;

CREATE TRIGGER alert_cooldowns_no_replace
BEFORE INSERT ON alert_cooldowns
WHEN EXISTS (SELECT 1 FROM alert_cooldowns WHERE run_id = NEW.run_id AND ((key_id = NEW.key_id AND revision = NEW.revision) OR authority_id = NEW.authority_id))
BEGIN
    SELECT RAISE(ABORT, 'alert_cooldowns is append-only');
END;

CREATE TRIGGER alert_cooldowns_no_update
BEFORE UPDATE ON alert_cooldowns
BEGIN
    SELECT RAISE(ABORT, 'alert_cooldowns is append-only');
END;

CREATE TRIGGER alert_cooldowns_no_delete
BEFORE DELETE ON alert_cooldowns
BEGIN
    SELECT RAISE(ABORT, 'alert_cooldowns is append-only');
END;

CREATE TRIGGER alert_outbox_no_replace
BEFORE INSERT ON alert_outbox
WHEN EXISTS (SELECT 1 FROM alert_outbox WHERE run_id = NEW.run_id AND (outbox_id = NEW.outbox_id OR alert_id = NEW.alert_id OR idempotency_key = NEW.idempotency_key))
BEGIN
    SELECT RAISE(ABORT, 'alert_outbox is append-only');
END;

CREATE TRIGGER alert_outbox_no_update
BEFORE UPDATE ON alert_outbox
BEGIN
    SELECT RAISE(ABORT, 'alert_outbox is append-only');
END;

CREATE TRIGGER alert_outbox_no_delete
BEFORE DELETE ON alert_outbox
BEGIN
    SELECT RAISE(ABORT, 'alert_outbox is append-only');
END;

CREATE TRIGGER alert_channel_capabilities_no_replace
BEFORE INSERT ON alert_channel_capabilities
WHEN EXISTS (
    SELECT 1 FROM alert_channel_capabilities
    WHERE run_id = NEW.run_id
      AND (capability_id = NEW.capability_id OR channel = NEW.channel)
)
BEGIN
    SELECT RAISE(ABORT, 'alert_channel_capabilities is append-only');
END;

CREATE TRIGGER alert_channel_capabilities_no_update
BEFORE UPDATE ON alert_channel_capabilities
BEGIN
    SELECT RAISE(ABORT, 'alert_channel_capabilities is append-only');
END;

CREATE TRIGGER alert_channel_capabilities_no_delete
BEFORE DELETE ON alert_channel_capabilities
BEGIN
    SELECT RAISE(ABORT, 'alert_channel_capabilities is append-only');
END;

CREATE TRIGGER alert_dispatch_attempts_no_replace
BEFORE INSERT ON alert_dispatch_attempts
WHEN EXISTS (SELECT 1 FROM alert_dispatch_attempts WHERE run_id = NEW.run_id AND (attempt_id = NEW.attempt_id OR (outbox_id = NEW.outbox_id AND attempt_number = NEW.attempt_number)))
BEGIN
    SELECT RAISE(ABORT, 'alert_dispatch_attempts is append-only');
END;

CREATE TRIGGER alert_dispatch_attempts_no_update
BEFORE UPDATE ON alert_dispatch_attempts
BEGIN
    SELECT RAISE(ABORT, 'alert_dispatch_attempts is append-only');
END;

CREATE TRIGGER alert_dispatch_attempts_no_delete
BEFORE DELETE ON alert_dispatch_attempts
BEGIN
    SELECT RAISE(ABORT, 'alert_dispatch_attempts is append-only');
END;

CREATE TRIGGER alert_dispatch_receipts_no_replace
BEFORE INSERT ON alert_dispatch_receipts
WHEN EXISTS (SELECT 1 FROM alert_dispatch_receipts WHERE run_id = NEW.run_id AND (receipt_id = NEW.receipt_id OR attempt_id = NEW.attempt_id OR (NEW.disposition = 'SUCCEEDED' AND disposition = 'SUCCEEDED' AND (outbox_id = NEW.outbox_id OR alert_id = NEW.alert_id))))
    OR NOT EXISTS (
        SELECT 1 FROM alert_dispatch_attempts
        WHERE run_id = NEW.run_id
          AND attempt_id = NEW.attempt_id
          AND outbox_id = NEW.outbox_id
          AND alert_id = NEW.alert_id
          AND case_id = NEW.case_id
          AND attempt_number = NEW.attempt_number
          AND fence = NEW.fence
          AND lease_owner_sha256 = NEW.lease_owner_sha256
          AND channel_capability_id = NEW.channel_capability_id
          AND idempotency_key = NEW.idempotency_key
          AND attempt_number = (
              SELECT MAX(attempt_number) FROM alert_dispatch_attempts
              WHERE run_id = NEW.run_id AND outbox_id = NEW.outbox_id
          )
    )
BEGIN
    SELECT RAISE(ABORT, 'alert_dispatch_receipts requires the exact current attempt fence');
END;

CREATE TRIGGER alert_dispatch_receipts_no_update
BEFORE UPDATE ON alert_dispatch_receipts
BEGIN
    SELECT RAISE(ABORT, 'alert_dispatch_receipts is append-only');
END;

CREATE TRIGGER alert_dispatch_receipts_no_delete
BEFORE DELETE ON alert_dispatch_receipts
BEGIN
    SELECT RAISE(ABORT, 'alert_dispatch_receipts is append-only');
END;

CREATE TRIGGER m5_immediate_safety_deliveries_no_replace
BEFORE INSERT ON m5_immediate_safety_deliveries
WHEN EXISTS (SELECT 1 FROM m5_immediate_safety_deliveries WHERE run_id = NEW.run_id AND (authority_id = NEW.authority_id OR incident_id = NEW.incident_id OR delivery_idempotency_key = NEW.delivery_idempotency_key))
BEGIN
    SELECT RAISE(ABORT, 'm5_immediate_safety_deliveries is append-only');
END;

CREATE TRIGGER m5_immediate_safety_deliveries_reject_uncertified_insert
BEFORE INSERT ON m5_immediate_safety_deliveries
BEGIN
    SELECT RAISE(
        ABORT,
        'immediate safety delivery disabled without certified signal authority'
    );
END;

CREATE TRIGGER m5_immediate_safety_deliveries_no_update
BEFORE UPDATE ON m5_immediate_safety_deliveries
BEGIN
    SELECT RAISE(ABORT, 'm5_immediate_safety_deliveries is append-only');
END;

CREATE TRIGGER m5_immediate_safety_deliveries_no_delete
BEFORE DELETE ON m5_immediate_safety_deliveries
BEGIN
    SELECT RAISE(ABORT, 'm5_immediate_safety_deliveries is append-only');
END;

CREATE TRIGGER appeals_no_replace
BEFORE INSERT ON appeals
WHEN EXISTS (SELECT 1 FROM appeals WHERE run_id = NEW.run_id AND ((appeal_id = NEW.appeal_id AND version = NEW.version) OR authority_sha256 = NEW.authority_sha256))
BEGIN
    SELECT RAISE(ABORT, 'appeals is append-only');
END;

CREATE TRIGGER appeals_no_update
BEFORE UPDATE ON appeals
BEGIN
    SELECT RAISE(ABORT, 'appeals is append-only');
END;

CREATE TRIGGER appeals_no_delete
BEFORE DELETE ON appeals
BEGIN
    SELECT RAISE(ABORT, 'appeals is append-only');
END;

CREATE TRIGGER appeal_resolution_receipts_no_replace
BEFORE INSERT ON appeal_resolution_receipts
WHEN EXISTS (SELECT 1 FROM appeal_resolution_receipts WHERE run_id = NEW.run_id AND (intent_id = NEW.intent_id OR appeal_id = NEW.appeal_id))
BEGIN
    SELECT RAISE(ABORT, 'appeal_resolution_receipts is append-only');
END;

CREATE TRIGGER appeal_resolution_receipts_no_update
BEFORE UPDATE ON appeal_resolution_receipts
BEGIN
    SELECT RAISE(ABORT, 'appeal_resolution_receipts is append-only');
END;

CREATE TRIGGER appeal_resolution_receipts_no_delete
BEFORE DELETE ON appeal_resolution_receipts
BEGIN
    SELECT RAISE(ABORT, 'appeal_resolution_receipts is append-only');
END;

CREATE TRIGGER strong_training_label_provenance_receipts_validate_source
BEFORE INSERT ON strong_training_label_provenance_receipts
WHEN COALESCE((
    json_extract(NEW.provenance_json, '$.schema_version')
        = 'm5-strong-training-label-provenance-receipt-v1'
    AND json_extract(NEW.provenance_json, '$.run_id') = NEW.run_id
    AND json_extract(NEW.provenance_json, '$.case_id') = NEW.case_id
    AND json_extract(NEW.provenance_json, '$.appeal_id') = NEW.appeal_id
    AND json_extract(NEW.provenance_json, '$.label_id') = NEW.label_id
    AND json_extract(NEW.provenance_json, '$.label_document_sha256')
        = NEW.label_document_sha256
    AND json_extract(NEW.provenance_json, '$.crop_id') = NEW.crop_id
    AND json_extract(NEW.provenance_json, '$.reviewer_id') = NEW.reviewer_id
    AND json_extract(NEW.provenance_json, '$.quality') = NEW.quality
    AND json_extract(NEW.provenance_json, '$.authored_input.input_id')
        = NEW.authored_input_id
    AND json_extract(NEW.provenance_json, '$.authored_input.crop_id') = NEW.crop_id
    AND json_extract(NEW.provenance_json, '$.review_authority_sha256')
        = NEW.review_authority_sha256
    AND json_extract(NEW.provenance_json, '$.terminal_authority_sha256')
        = NEW.terminal_authority_sha256
    AND json_extract(NEW.provenance_json, '$.terminal_status') = NEW.terminal_status
    AND json_extract(NEW.provenance_json, '$.resolution_intent_id')
        = NEW.resolution_intent_id
    AND json_extract(NEW.provenance_json, '$.resolution_document_sha256')
        = NEW.resolution_document_sha256
    AND json_extract(NEW.provenance_json, '$.resolution_commit_receipt_id')
        = NEW.resolution_commit_receipt_id
    AND json_extract(
        NEW.provenance_json, '$.resolution_commit_effect_root_sha256'
    ) = NEW.resolution_commit_effect_root_sha256
    AND json_extract(NEW.provenance_json, '$.manifest_id') = NEW.manifest_id
    AND json_extract(NEW.provenance_json, '$.rule_version') = NEW.rule_version
    AND json_extract(NEW.provenance_json, '$.detector_manifest_id')
        = NEW.detector_manifest_id
    AND json_extract(NEW.provenance_json, '$.provenance_id') = NEW.provenance_id
    AND EXISTS (
        SELECT 1
        FROM appeals AS review_authority
        JOIN appeals AS terminal_authority
          ON terminal_authority.run_id = review_authority.run_id
         AND terminal_authority.appeal_id = review_authority.appeal_id
        JOIN appeal_resolution_receipts AS resolution
          ON resolution.run_id = terminal_authority.run_id
         AND resolution.appeal_id = terminal_authority.appeal_id
         AND resolution.appeal_authority_sha256 = terminal_authority.authority_sha256
        WHERE review_authority.run_id = NEW.run_id
          AND review_authority.appeal_id = NEW.appeal_id
          AND review_authority.authority_sha256 = NEW.review_authority_sha256
          AND review_authority.version = 2
          AND review_authority.status = 'UNDER_REVIEW'
          AND review_authority.case_id = NEW.case_id
          AND review_authority.assigned_reviewer_id = NEW.reviewer_id
          AND terminal_authority.authority_sha256 = NEW.terminal_authority_sha256
          AND terminal_authority.version = 3
          AND terminal_authority.status = NEW.terminal_status
          AND terminal_authority.previous_authority_sha256 = NEW.review_authority_sha256
          AND terminal_authority.case_id = NEW.case_id
          AND terminal_authority.assigned_reviewer_id = NEW.reviewer_id
          AND terminal_authority.manifest_id = NEW.manifest_id
          AND terminal_authority.rule_version = NEW.rule_version
          AND resolution.intent_id = NEW.resolution_intent_id
          AND resolution.document_sha256 = NEW.resolution_document_sha256
          AND resolution.case_id = NEW.case_id
          AND resolution.manifest_id = NEW.manifest_id
          AND EXISTS (
              SELECT 1
              FROM json_each(resolution.intent_json, '$.training_labels') AS label
              WHERE json_extract(label.value, '$.label_id') = NEW.label_id
                AND json_extract(label.value, '$.case_id') = NEW.case_id
                AND json_extract(label.value, '$.crop_id') = NEW.crop_id
                AND json_extract(label.value, '$.reviewer_id') = NEW.reviewer_id
                AND json_extract(label.value, '$.quality') = NEW.quality
                AND json_extract(label.value, '$.rule_version') = NEW.rule_version
                AND json_extract(label.value, '$.detector_manifest_id')
                    = NEW.detector_manifest_id
                AND json_extract(label.value, '$.source')
                    = 'appeal-review:' || NEW.appeal_id
                AND json_extract(label.value, '$.excluded_reason') IS NULL
          )
    )
    AND (
        NOT EXISTS (
            SELECT 1
            FROM appeal_resolution_commit_receipts
            WHERE run_id = NEW.run_id
              AND resolution_intent_id = NEW.resolution_intent_id
        )
        OR EXISTS (
            SELECT 1
            FROM appeal_resolution_commit_receipts AS committed
            JOIN json_each(committed.training_label_ids_json) AS inventory
            WHERE committed.run_id = NEW.run_id
              AND committed.resolution_intent_id = NEW.resolution_intent_id
              AND committed.receipt_id = NEW.resolution_commit_receipt_id
              AND committed.effect_root_sha256
                  = NEW.resolution_commit_effect_root_sha256
              AND committed.resolution_document_sha256
                  = NEW.resolution_document_sha256
              AND committed.appeal_id = NEW.appeal_id
              AND committed.appeal_authority_sha256 = NEW.terminal_authority_sha256
              AND committed.case_id = NEW.case_id
              AND committed.manifest_id = NEW.manifest_id
              AND inventory.type = 'text'
              AND inventory.value = NEW.label_id
        )
    )
), 0) = 0
BEGIN
    SELECT RAISE(ABORT, 'strong training label provenance source is invalid');
END;

CREATE TRIGGER appeal_resolution_commit_receipts_validate_training_provenance_closure
BEFORE INSERT ON appeal_resolution_commit_receipts
WHEN EXISTS (
    SELECT 1
    FROM json_each(NEW.training_label_ids_json) AS inventory
    WHERE inventory.type <> 'text'
) OR EXISTS (
    SELECT 1
    FROM json_each(NEW.training_label_ids_json) AS inventory
    JOIN json_each(NEW.training_label_ids_json) AS earlier
      ON CAST(earlier.key AS INTEGER) < CAST(inventory.key AS INTEGER)
    WHERE earlier.value >= inventory.value
) OR EXISTS (
    SELECT 1
    FROM json_each(NEW.training_label_ids_json) AS inventory
    WHERE NOT EXISTS (
        SELECT 1
        FROM strong_training_label_provenance_receipts AS provenance
        WHERE provenance.run_id = NEW.run_id
          AND provenance.label_id = inventory.value
          AND provenance.resolution_intent_id = NEW.resolution_intent_id
          AND provenance.resolution_document_sha256 = NEW.resolution_document_sha256
          AND provenance.resolution_commit_receipt_id = NEW.receipt_id
          AND provenance.resolution_commit_effect_root_sha256 = NEW.effect_root_sha256
          AND provenance.appeal_id = NEW.appeal_id
          AND provenance.terminal_authority_sha256 = NEW.appeal_authority_sha256
          AND provenance.case_id = NEW.case_id
          AND provenance.manifest_id = NEW.manifest_id
    )
) OR EXISTS (
    SELECT 1
    FROM strong_training_label_provenance_receipts AS provenance
    WHERE provenance.run_id = NEW.run_id
      AND provenance.resolution_intent_id = NEW.resolution_intent_id
      AND (
          provenance.resolution_document_sha256 <> NEW.resolution_document_sha256
          OR provenance.resolution_commit_receipt_id <> NEW.receipt_id
          OR provenance.resolution_commit_effect_root_sha256 <> NEW.effect_root_sha256
          OR provenance.appeal_id <> NEW.appeal_id
          OR provenance.terminal_authority_sha256 <> NEW.appeal_authority_sha256
          OR provenance.case_id <> NEW.case_id
          OR provenance.manifest_id <> NEW.manifest_id
          OR NOT EXISTS (
              SELECT 1
              FROM json_each(NEW.training_label_ids_json) AS inventory
              WHERE inventory.type = 'text'
                AND inventory.value = provenance.label_id
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'appeal resolution strong label provenance closure is invalid');
END;

CREATE TRIGGER appeal_resolution_commit_receipts_no_replace
BEFORE INSERT ON appeal_resolution_commit_receipts
WHEN EXISTS (
    SELECT 1
    FROM appeal_resolution_commit_receipts
    WHERE run_id = NEW.run_id
      AND (
          receipt_id = NEW.receipt_id
          OR effect_root_sha256 = NEW.effect_root_sha256
          OR resolution_intent_id = NEW.resolution_intent_id
          OR appeal_id = NEW.appeal_id
      )
)
BEGIN
    SELECT RAISE(ABORT, 'appeal_resolution_commit_receipts is append-only');
END;

CREATE TRIGGER appeal_resolution_commit_receipts_no_update
BEFORE UPDATE ON appeal_resolution_commit_receipts
BEGIN
    SELECT RAISE(ABORT, 'appeal_resolution_commit_receipts is append-only');
END;

CREATE TRIGGER appeal_resolution_commit_receipts_no_delete
BEFORE DELETE ON appeal_resolution_commit_receipts
BEGIN
    SELECT RAISE(ABORT, 'appeal_resolution_commit_receipts is append-only');
END;

CREATE TRIGGER verdict_rescissions_no_replace
BEFORE INSERT ON verdict_rescissions
WHEN EXISTS (SELECT 1 FROM verdict_rescissions WHERE run_id = NEW.run_id AND (rescission_id = NEW.rescission_id OR (verdict_id = NEW.verdict_id AND verdict_version = NEW.verdict_version)))
BEGIN
    SELECT RAISE(ABORT, 'verdict_rescissions is append-only');
END;

CREATE TRIGGER verdict_rescissions_no_update
BEFORE UPDATE ON verdict_rescissions
BEGIN
    SELECT RAISE(ABORT, 'verdict_rescissions is append-only');
END;

CREATE TRIGGER verdict_rescissions_no_delete
BEFORE DELETE ON verdict_rescissions
BEGIN
    SELECT RAISE(ABORT, 'verdict_rescissions is append-only');
END;

CREATE TRIGGER alert_rescissions_no_replace
BEFORE INSERT ON alert_rescissions
WHEN EXISTS (SELECT 1 FROM alert_rescissions WHERE run_id = NEW.run_id AND (rescission_id = NEW.rescission_id OR alert_id = NEW.alert_id))
BEGIN
    SELECT RAISE(ABORT, 'alert_rescissions is append-only');
END;

CREATE TRIGGER alert_rescissions_no_update
BEFORE UPDATE ON alert_rescissions
BEGIN
    SELECT RAISE(ABORT, 'alert_rescissions is append-only');
END;

CREATE TRIGGER alert_rescissions_no_delete
BEFORE DELETE ON alert_rescissions
BEGIN
    SELECT RAISE(ABORT, 'alert_rescissions is append-only');
END;

CREATE TRIGGER m5_training_causal_events_validate_contiguous_sequence
BEFORE INSERT ON m5_training_causal_events
WHEN NEW.sequence <> COALESCE(
    (
        SELECT MAX(sequence) + 1
        FROM m5_training_causal_events
        WHERE run_id = NEW.run_id
    ),
    1
)
BEGIN
    SELECT RAISE(ABORT, 'M5 training causal event sequence is not contiguous');
END;

CREATE TRIGGER m5_training_causal_events_validate_predecessor
BEFORE INSERT ON m5_training_causal_events
WHEN (
    NEW.sequence = 1
    AND NEW.previous_event_sha256 <> printf('%064d', 0)
) OR (
    NEW.sequence > 1
    AND NOT EXISTS (
        SELECT 1
        FROM m5_training_causal_events
        WHERE run_id = NEW.run_id
          AND sequence = NEW.sequence - 1
          AND event_sha256 = NEW.previous_event_sha256
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M5 training causal event predecessor is invalid');
END;

CREATE TRIGGER m5_training_causal_events_validate_source
BEFORE INSERT ON m5_training_causal_events
WHEN COALESCE((
    json_extract(NEW.event_json, '$.schema_version') = 'm5-training-causal-event-v1'
    AND json_extract(NEW.event_json, '$.run_id') = NEW.run_id
    AND json_type(NEW.event_json, '$.sequence') = 'integer'
    AND json_extract(NEW.event_json, '$.sequence') = NEW.sequence
    AND json_extract(NEW.event_json, '$.event_kind') = NEW.event_kind
    AND json_extract(NEW.event_json, '$.source_id') = NEW.source_id
    AND json_extract(NEW.event_json, '$.source_document_sha256')
        = NEW.source_document_sha256
    AND json_extract(NEW.event_json, '$.manifest_id') = NEW.manifest_id
    AND json_extract(NEW.event_json, '$.previous_event_sha256')
        = NEW.previous_event_sha256
    AND json_extract(NEW.event_json, '$.label_id') IS NEW.label_id
    AND json_extract(NEW.event_json, '$.source_identity') = NEW.source_identity
    AND json_extract(NEW.event_json, '$.event_id') = NEW.event_id
    AND json_extract(NEW.event_json, '$.event_sha256') = NEW.event_sha256
    AND (
        (
            NEW.event_kind = 'TRAINING_LABEL_APPENDED'
            AND json_type(NEW.event_json, '$.label_id') = 'text'
        )
        OR
        (
            NEW.event_kind = 'DATASET_REGISTRATION_COMMITTED'
            AND json_type(NEW.event_json, '$.label_id') = 'null'
            AND EXISTS (
                SELECT 1
                FROM dataset_registration_snapshots AS snapshot
                WHERE snapshot.run_id = NEW.run_id
                  AND snapshot.authority_id = NEW.source_id
                  AND snapshot.document_sha256 = NEW.source_document_sha256
                  AND snapshot.manifest_id = NEW.manifest_id
                  AND NEW.sequence = snapshot.causal_cut_sequence + 1
                  AND NEW.previous_event_sha256 = snapshot.causal_cut_event_sha256
            )
        )
    )
), 0) = 0
BEGIN
    SELECT RAISE(ABORT, 'M5 training causal event source or index binding is invalid');
END;

CREATE TRIGGER m5_training_causal_events_no_replace
BEFORE INSERT ON m5_training_causal_events
WHEN EXISTS (
    SELECT 1
    FROM m5_training_causal_events
    WHERE run_id = NEW.run_id
      AND (
          sequence = NEW.sequence
          OR event_id = NEW.event_id
          OR source_identity = NEW.source_identity
          OR event_sha256 = NEW.event_sha256
          OR (event_kind = NEW.event_kind AND source_id = NEW.source_id)
          OR (label_id IS NOT NULL AND label_id = NEW.label_id)
      )
)
BEGIN
    SELECT RAISE(ABORT, 'm5_training_causal_events is append-only');
END;

CREATE TRIGGER m5_training_causal_events_no_update
BEFORE UPDATE ON m5_training_causal_events
BEGIN
    SELECT RAISE(ABORT, 'm5_training_causal_events is append-only');
END;

CREATE TRIGGER m5_training_causal_events_no_delete
BEFORE DELETE ON m5_training_causal_events
BEGIN
    SELECT RAISE(ABORT, 'm5_training_causal_events is append-only');
END;

CREATE TRIGGER training_labels_require_causal_event
BEFORE INSERT ON training_labels
WHEN NOT EXISTS (
    SELECT 1
    FROM m5_training_causal_events
    WHERE run_id = NEW.run_id
      AND event_kind = 'TRAINING_LABEL_APPENDED'
      AND label_id = NEW.label_id
      AND manifest_id = NEW.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'training label requires its causal append event');
END;

CREATE TRIGGER dataset_registration_snapshots_validate_source
BEFORE INSERT ON dataset_registration_snapshots
WHEN COALESCE((
    json_extract(NEW.snapshot_json, '$.schema_version')
        = 'm5-dataset-registration-snapshot-authority-v1'
    AND json_extract(NEW.snapshot_json, '$.run_id') = NEW.run_id
    AND json_extract(NEW.snapshot_json, '$.dataset_id') = NEW.dataset_id
    AND json_extract(NEW.snapshot_json, '$.report_id') = NEW.report_id
    AND json_extract(NEW.snapshot_json, '$.command_id') = NEW.command_id
    AND json_extract(NEW.snapshot_json, '$.report_document_sha256')
        = NEW.report_document_sha256
    AND json_extract(NEW.snapshot_json, '$.causal_cut.run_id') = NEW.run_id
    AND json_type(NEW.snapshot_json, '$.causal_cut.sequence') = 'integer'
    AND json_extract(NEW.snapshot_json, '$.causal_cut.sequence')
        = NEW.causal_cut_sequence
    AND json_extract(NEW.snapshot_json, '$.causal_cut.event_id')
        IS NEW.causal_cut_event_id
    AND json_extract(NEW.snapshot_json, '$.causal_cut.event_sha256')
        = NEW.causal_cut_event_sha256
    AND json_type(NEW.snapshot_json, '$.label_count') = 'integer'
    AND json_extract(NEW.snapshot_json, '$.label_count') = NEW.label_count
    AND json_extract(NEW.snapshot_json, '$.label_inventory_root_sha256')
        = NEW.label_inventory_root_sha256
    AND json_type(NEW.snapshot_json, '$.crop_count') = 'integer'
    AND json_extract(NEW.snapshot_json, '$.crop_count') = NEW.crop_count
    AND json_extract(NEW.snapshot_json, '$.crop_inventory_root_sha256')
        = NEW.crop_inventory_root_sha256
    AND json_extract(NEW.snapshot_json, '$.manifest_id') = NEW.manifest_id
    AND json_extract(NEW.snapshot_json, '$.rule_version') = NEW.rule_version
    AND json_extract(NEW.snapshot_json, '$.detector_manifest_id')
        = NEW.detector_manifest_id
    AND json_extract(NEW.snapshot_json, '$.authority_id') = NEW.authority_id
    AND NEW.label_count = (
        SELECT COUNT(*)
        FROM m5_training_causal_events AS event
        WHERE event.run_id = NEW.run_id
          AND event.sequence <= NEW.causal_cut_sequence
          AND event.event_kind = 'TRAINING_LABEL_APPENDED'
    )
), 0) = 0
BEGIN
    SELECT RAISE(ABORT, 'dataset registration snapshot source or index binding is invalid');
END;

CREATE TRIGGER dataset_registration_snapshots_no_replace
BEFORE INSERT ON dataset_registration_snapshots
WHEN EXISTS (
    SELECT 1
    FROM dataset_registration_snapshots
    WHERE run_id = NEW.run_id
      AND (
          authority_id = NEW.authority_id
          OR dataset_id = NEW.dataset_id
          OR report_id = NEW.report_id
          OR command_id = NEW.command_id
      )
)
BEGIN
    SELECT RAISE(ABORT, 'dataset_registration_snapshots is append-only');
END;

CREATE TRIGGER dataset_registration_snapshots_no_update
BEFORE UPDATE ON dataset_registration_snapshots
BEGIN
    SELECT RAISE(ABORT, 'dataset_registration_snapshots is append-only');
END;

CREATE TRIGGER dataset_registration_snapshots_no_delete
BEFORE DELETE ON dataset_registration_snapshots
BEGIN
    SELECT RAISE(ABORT, 'dataset_registration_snapshots is append-only');
END;

CREATE TRIGGER dataset_crop_snapshots_validate_source
BEFORE INSERT ON dataset_crop_snapshots
WHEN COALESCE((
    json_extract(NEW.authority_json, '$.schema_version')
        = 'm5-dataset-crop-snapshot-authority-v1'
    AND json_extract(NEW.authority_json, '$.run_id') = NEW.run_id
    AND json_extract(NEW.authority_json, '$.dataset_id') = NEW.dataset_id
    AND json_extract(NEW.authority_json, '$.report_id') = NEW.report_id
    AND json_extract(NEW.authority_json, '$.crop_authority.crop.crop_id') = NEW.crop_id
    AND json_extract(NEW.authority_json, '$.crop_authority.authority_sha256')
        = NEW.crop_authority_sha256
    AND json_extract(NEW.authority_json, '$.crop_authority.case_id') = NEW.case_id
    AND json_type(NEW.authority_json, '$.case_revision') = 'integer'
    AND json_extract(NEW.authority_json, '$.case_revision') = NEW.case_revision
    AND json_extract(NEW.authority_json, '$.case_document_sha256')
        = NEW.case_document_sha256
    AND json_extract(NEW.authority_json, '$.evidence_pack_id') = NEW.evidence_pack_id
    AND json_type(NEW.authority_json, '$.evidence_pack_version') = 'integer'
    AND json_extract(NEW.authority_json, '$.evidence_pack_version')
        = NEW.evidence_pack_version
    AND json_extract(NEW.authority_json, '$.evidence_pack_document_sha256')
        = NEW.evidence_pack_document_sha256
    AND json_extract(NEW.authority_json, '$.authority_id') = NEW.authority_id
), 0) = 0
BEGIN
    SELECT RAISE(ABORT, 'dataset Crop snapshot source or index binding is invalid');
END;

CREATE TRIGGER dataset_crop_snapshots_no_replace
BEFORE INSERT ON dataset_crop_snapshots
WHEN EXISTS (
    SELECT 1
    FROM dataset_crop_snapshots
    WHERE run_id = NEW.run_id
      AND (
          authority_id = NEW.authority_id
          OR (
              registration_snapshot_authority_id
                  = NEW.registration_snapshot_authority_id
              AND crop_id = NEW.crop_id
          )
          OR (
              registration_snapshot_authority_id
                  = NEW.registration_snapshot_authority_id
              AND crop_authority_sha256 = NEW.crop_authority_sha256
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'dataset_crop_snapshots is append-only');
END;

CREATE TRIGGER dataset_crop_snapshots_no_update
BEFORE UPDATE ON dataset_crop_snapshots
BEGIN
    SELECT RAISE(ABORT, 'dataset_crop_snapshots is append-only');
END;

CREATE TRIGGER dataset_crop_snapshots_no_delete
BEFORE DELETE ON dataset_crop_snapshots
BEGIN
    SELECT RAISE(ABORT, 'dataset_crop_snapshots is append-only');
END;

CREATE TRIGGER dataset_artifacts_validate_registration_snapshot
BEFORE INSERT ON dataset_artifacts
WHEN NOT EXISTS (
    SELECT 1
    FROM dataset_registration_snapshots AS snapshot
    WHERE snapshot.run_id = NEW.run_id
      AND snapshot.authority_id = NEW.registration_snapshot_authority_id
      AND snapshot.dataset_id = NEW.dataset_id
      AND snapshot.report_id = NEW.report_id
      AND snapshot.command_id = NEW.command_id
      AND snapshot.report_document_sha256 = NEW.document_sha256
      AND snapshot.manifest_id = NEW.manifest_id
      AND snapshot.rule_version = NEW.rule_version
      AND snapshot.detector_manifest_id = NEW.detector_manifest_id
      AND snapshot.label_count = json_extract(NEW.report_json, '$.input_label_count')
      AND snapshot.crop_count = json_extract(NEW.report_json, '$.exported_image_count')
      AND snapshot.crop_count = (
          SELECT COUNT(*)
          FROM dataset_crop_snapshots AS crop
          WHERE crop.run_id = NEW.run_id
            AND crop.registration_snapshot_authority_id = snapshot.authority_id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM m5_training_causal_events AS label_event
          WHERE label_event.run_id = NEW.run_id
            AND label_event.sequence <= snapshot.causal_cut_sequence
            AND label_event.event_kind = 'TRAINING_LABEL_APPENDED'
            AND label_event.label_id NOT IN (
                SELECT value
                FROM json_each(NEW.report_json, '$.exported_label_ids')
                UNION ALL
                SELECT value
                FROM json_each(NEW.report_json, '$.quarantined_label_ids')
            )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM (
              SELECT value AS label_id
              FROM json_each(NEW.report_json, '$.exported_label_ids')
              UNION ALL
              SELECT value AS label_id
              FROM json_each(NEW.report_json, '$.quarantined_label_ids')
          ) AS report_label
          WHERE NOT EXISTS (
              SELECT 1
              FROM m5_training_causal_events AS label_event
              WHERE label_event.run_id = NEW.run_id
                AND label_event.sequence <= snapshot.causal_cut_sequence
                AND label_event.event_kind = 'TRAINING_LABEL_APPENDED'
                AND label_event.label_id = report_label.label_id
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM json_each(NEW.report_json, '$.crop_receipts') AS receipt
          WHERE NOT EXISTS (
              SELECT 1
              FROM dataset_crop_snapshots AS crop
              WHERE crop.run_id = NEW.run_id
                AND crop.registration_snapshot_authority_id = snapshot.authority_id
                AND crop.crop_id = json_extract(receipt.value, '$.crop_id')
                AND crop.crop_authority_sha256
                    = json_extract(receipt.value, '$.authority_sha256')
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM dataset_crop_snapshots AS crop
          WHERE crop.run_id = NEW.run_id
            AND crop.registration_snapshot_authority_id = snapshot.authority_id
            AND NOT EXISTS (
                SELECT 1
                FROM json_each(NEW.report_json, '$.crop_receipts') AS receipt
                WHERE json_extract(receipt.value, '$.crop_id') = crop.crop_id
                  AND json_extract(receipt.value, '$.authority_sha256')
                      = crop.crop_authority_sha256
            )
      )
      AND EXISTS (
          SELECT 1
          FROM m5_training_causal_events AS commit_event
          WHERE commit_event.run_id = NEW.run_id
            AND commit_event.sequence = snapshot.causal_cut_sequence + 1
            AND commit_event.event_kind = 'DATASET_REGISTRATION_COMMITTED'
            AND commit_event.source_id = snapshot.authority_id
            AND commit_event.source_document_sha256 = snapshot.document_sha256
            AND commit_event.manifest_id = snapshot.manifest_id
            AND commit_event.previous_event_sha256 = snapshot.causal_cut_event_sha256
      )
)
BEGIN
    SELECT RAISE(ABORT, 'dataset artifact registration snapshot closure is invalid');
END;

CREATE TRIGGER training_labels_no_replace
BEFORE INSERT ON training_labels
WHEN EXISTS (SELECT 1 FROM training_labels WHERE run_id = NEW.run_id AND label_id = NEW.label_id)
BEGIN
    SELECT RAISE(ABORT, 'training_labels is append-only');
END;

CREATE TRIGGER training_labels_no_update
BEFORE UPDATE ON training_labels
BEGIN
    SELECT RAISE(ABORT, 'training_labels is append-only');
END;

CREATE TRIGGER training_labels_no_delete
BEFORE DELETE ON training_labels
BEGIN
    SELECT RAISE(ABORT, 'training_labels is append-only');
END;

CREATE TRIGGER strong_training_label_provenance_receipts_no_replace
BEFORE INSERT ON strong_training_label_provenance_receipts
WHEN EXISTS (
    SELECT 1
    FROM strong_training_label_provenance_receipts
    WHERE run_id = NEW.run_id
      AND (
          provenance_id = NEW.provenance_id
          OR label_id = NEW.label_id
          OR (
              review_authority_sha256 = NEW.review_authority_sha256
              AND authored_input_id = NEW.authored_input_id
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'strong_training_label_provenance_receipts is append-only');
END;

CREATE TRIGGER strong_training_label_provenance_receipts_no_update
BEFORE UPDATE ON strong_training_label_provenance_receipts
BEGIN
    SELECT RAISE(ABORT, 'strong_training_label_provenance_receipts is append-only');
END;

CREATE TRIGGER strong_training_label_provenance_receipts_no_delete
BEFORE DELETE ON strong_training_label_provenance_receipts
BEGIN
    SELECT RAISE(ABORT, 'strong_training_label_provenance_receipts is append-only');
END;

CREATE TRIGGER dataset_artifacts_no_replace
BEFORE INSERT ON dataset_artifacts
WHEN EXISTS (SELECT 1 FROM dataset_artifacts WHERE run_id = NEW.run_id AND (dataset_id = NEW.dataset_id OR report_id = NEW.report_id OR command_id = NEW.command_id OR relative_path = NEW.relative_path))
BEGIN
    SELECT RAISE(ABORT, 'dataset_artifacts is append-only');
END;

CREATE TRIGGER dataset_artifacts_no_update
BEFORE UPDATE ON dataset_artifacts
BEGIN
    SELECT RAISE(ABORT, 'dataset_artifacts is append-only');
END;

CREATE TRIGGER dataset_artifacts_no_delete
BEFORE DELETE ON dataset_artifacts
BEGIN
    SELECT RAISE(ABORT, 'dataset_artifacts is append-only');
END;
