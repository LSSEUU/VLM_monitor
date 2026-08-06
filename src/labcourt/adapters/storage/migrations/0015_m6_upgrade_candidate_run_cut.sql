CREATE TABLE m6_upgrade_candidate_run_cuts (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    ledger_seal_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(ledger_seal_authority_id) = 64
               AND ledger_seal_authority_id NOT GLOB '*[^0-9a-f]*'),
    candidate_manifest_id TEXT NOT NULL
        CHECK (length(candidate_manifest_id) = 64
               AND candidate_manifest_id NOT GLOB '*[^0-9a-f]*'),
    candidate_manifest_content_sha256 TEXT NOT NULL
        CHECK (length(candidate_manifest_content_sha256) = 64
               AND candidate_manifest_content_sha256 NOT GLOB '*[^0-9a-f]*'),
    candidate_config_sha256 TEXT NOT NULL
        CHECK (length(candidate_config_sha256) = 64
               AND candidate_config_sha256 NOT GLOB '*[^0-9a-f]*'),
    candidate_config_content_sha256 TEXT NOT NULL
        CHECK (length(candidate_config_content_sha256) = 64
               AND candidate_config_content_sha256 NOT GLOB '*[^0-9a-f]*'),
    execution_component_manifest_id TEXT NOT NULL
        CHECK (length(execution_component_manifest_id) = 64
               AND execution_component_manifest_id NOT GLOB '*[^0-9a-f]*'),
    audit_head_sequence INTEGER NOT NULL CHECK (audit_head_sequence >= -1),
    audit_head_hash TEXT NOT NULL
        CHECK (length(audit_head_hash) = 64
               AND audit_head_hash NOT GLOB '*[^0-9a-f]*'),
    validation_report_id TEXT NOT NULL
        CHECK (length(validation_report_id) = 64
               AND validation_report_id NOT GLOB '*[^0-9a-f]*'),
    validation_report_content_sha256 TEXT NOT NULL
        CHECK (length(validation_report_content_sha256) = 64
               AND validation_report_content_sha256 NOT GLOB '*[^0-9a-f]*'),
    validation_report_size_bytes INTEGER NOT NULL
        CHECK (validation_report_size_bytes BETWEEN 1 AND 268435456),
    candidate_run_cut_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(candidate_run_cut_authority_id) = 64
               AND candidate_run_cut_authority_id NOT GLOB '*[^0-9a-f]*'),
    run_cut_json TEXT NOT NULL CHECK (json_valid(run_cut_json)),
    document_sha256 TEXT NOT NULL UNIQUE
        CHECK (length(document_sha256) = 64
               AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 268435456),
    UNIQUE (run_id, execution_scope_authority_id),
    FOREIGN KEY (run_id, execution_scope_authority_id)
        REFERENCES m6_upgrade_execution_scopes(
            run_id, execution_scope_authority_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (run_id)
        REFERENCES m6_upgrade_execution_ledger_seals(run_id) ON DELETE RESTRICT,
    FOREIGN KEY (ledger_seal_authority_id)
        REFERENCES m6_upgrade_execution_ledger_seals(ledger_seal_authority_id)
        ON DELETE RESTRICT,
    CHECK (validation_report_size_bytes <= size_bytes),
    CHECK (
        audit_head_sequence <> -1
        OR audit_head_hash
            = '0000000000000000000000000000000000000000000000000000000000000000'
    )
) STRICT;

-- A cut is admissible only after the exact protocol-V3 scope has one Seal V2.
-- The JSON projections make the normalized row an index, never a second source
-- of authority.
CREATE TRIGGER m6_upgrade_candidate_run_cuts_validate
BEFORE INSERT ON m6_upgrade_candidate_run_cuts
WHEN (
    json_valid(NEW.run_cut_json)
    AND NEW.run_cut_json = json(NEW.run_cut_json)
    AND json_type(NEW.run_cut_json, '$') = 'object'
    AND json_extract(NEW.run_cut_json, '$.schema_version')
        = 'm6-upgrade-candidate-run-cut-authority-v1'
    AND json_extract(NEW.run_cut_json, '$.candidate_run_id') = NEW.run_id
    AND json_extract(
        NEW.run_cut_json,
        '$.candidate_manifest.manifest_id'
    ) = NEW.candidate_manifest_id
    AND json_extract(
        NEW.run_cut_json,
        '$.candidate_manifest.config_sha256'
    ) = NEW.candidate_config_sha256
    AND json_extract(
        NEW.run_cut_json,
        '$.candidate_manifest_content_sha256'
    ) = NEW.candidate_manifest_content_sha256
    AND json_extract(
        NEW.run_cut_json,
        '$.candidate_config.config_sha256'
    ) = NEW.candidate_config_sha256
    AND json_extract(
        NEW.run_cut_json,
        '$.candidate_config_content_sha256'
    ) = NEW.candidate_config_content_sha256
    AND json_extract(
        NEW.run_cut_json,
        '$.execution_component_manifest_id'
    ) = NEW.execution_component_manifest_id
    AND json_extract(NEW.run_cut_json, '$.audit_head_sequence')
        = NEW.audit_head_sequence
    AND json_extract(NEW.run_cut_json, '$.audit_head_hash')
        = NEW.audit_head_hash
    AND json_extract(
        NEW.run_cut_json,
        '$.validation_report.report_id'
    ) = NEW.validation_report_id
    AND json_extract(
        NEW.run_cut_json,
        '$.validation_report_content_sha256'
    ) = NEW.validation_report_content_sha256
    AND json_extract(NEW.run_cut_json, '$.validation_report.run_id')
        = NEW.run_id
    AND json_extract(NEW.run_cut_json, '$.validation_report.manifest_id')
        = NEW.candidate_manifest_id
    AND json_extract(NEW.run_cut_json, '$.validation_report.config_sha256')
        = NEW.candidate_config_sha256
    AND json_extract(NEW.run_cut_json, '$.validation_report.passed') = 1
    AND json_extract(
        NEW.run_cut_json,
        '$.validation_report.predecessor_report.m3_report.m2_report.manifest_id'
    ) = NEW.candidate_manifest_id
    AND json_extract(
        NEW.run_cut_json,
        '$.validation_report.predecessor_report.m3_report.m2_report.audit_head_sequence'
    ) = NEW.audit_head_sequence
    AND json_extract(
        NEW.run_cut_json,
        '$.validation_report.predecessor_report.m3_report.m2_report.audit_head_hash'
    ) = NEW.audit_head_hash
    AND json_extract(
        NEW.run_cut_json,
        '$.candidate_run_cut_authority_id'
    ) = NEW.candidate_run_cut_authority_id
    AND length(CAST(
        json_extract(NEW.run_cut_json, '$.validation_report') AS BLOB
    )) = NEW.validation_report_size_bytes
    AND length(CAST(NEW.run_cut_json AS BLOB)) = NEW.size_bytes
    AND EXISTS (
        SELECT 1
        FROM m6_upgrade_execution_scopes AS scope
        JOIN m6_upgrade_execution_ledger_protocols AS protocol
          ON protocol.run_id = scope.run_id
         AND protocol.execution_scope_authority_id
             = scope.execution_scope_authority_id
        JOIN m6_upgrade_execution_ledger_seals AS seal
          ON seal.run_id = scope.run_id
         AND seal.execution_scope_authority_id
             = scope.execution_scope_authority_id
        WHERE scope.run_id = NEW.run_id
          AND scope.execution_scope_authority_id
              = NEW.execution_scope_authority_id
          AND protocol.protocol_version = 'v3'
          AND seal.seal_schema_version = 'v2'
          AND seal.ledger_seal_authority_id = NEW.ledger_seal_authority_id
          AND scope.candidate_manifest_id = NEW.candidate_manifest_id
          AND scope.candidate_manifest_document_sha256
              = NEW.candidate_manifest_content_sha256
          AND scope.candidate_config_sha256 = NEW.candidate_config_sha256
          AND json_extract(
              scope.scope_json,
              '$.candidate_config_content_sha256'
          ) = NEW.candidate_config_content_sha256
          AND scope.execution_component_authority_id
              = NEW.execution_component_manifest_id
          AND seal.source_audit_head_sequence = NEW.audit_head_sequence
          AND seal.source_audit_head_hash = NEW.audit_head_hash
          AND seal.candidate_case_count = json_extract(
              NEW.run_cut_json,
              '$.validation_report.counts.case_roots'
          )
    )
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade candidate run cut');
END;

CREATE TRIGGER m6_upgrade_candidate_run_cuts_no_replace
BEFORE INSERT ON m6_upgrade_candidate_run_cuts
WHEN EXISTS (
    SELECT 1
    FROM m6_upgrade_candidate_run_cuts AS cut
    WHERE cut.run_id = NEW.run_id
       OR cut.execution_scope_authority_id = NEW.execution_scope_authority_id
       OR cut.ledger_seal_authority_id = NEW.ledger_seal_authority_id
       OR cut.candidate_run_cut_authority_id
            = NEW.candidate_run_cut_authority_id
       OR cut.document_sha256 = NEW.document_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade candidate run cuts are append-only');
END;

CREATE TRIGGER m6_upgrade_candidate_run_cuts_no_update
BEFORE UPDATE ON m6_upgrade_candidate_run_cuts
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade candidate run cuts are append-only');
END;

CREATE TRIGGER m6_upgrade_candidate_run_cuts_no_delete
BEFORE DELETE ON m6_upgrade_candidate_run_cuts
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade candidate run cuts are append-only');
END;
