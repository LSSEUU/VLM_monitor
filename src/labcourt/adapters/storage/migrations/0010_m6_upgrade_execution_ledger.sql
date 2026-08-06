CREATE TABLE m6_audit_chain_preflight (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

INSERT INTO m6_audit_chain_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM runs AS run
    WHERE NOT (
        (
            run.audit_head_sequence = -1
            AND run.audit_head_hash
                = '0000000000000000000000000000000000000000000000000000000000000000'
            AND run.revision = 0
            AND NOT EXISTS (
                SELECT 1 FROM audit_entries AS audit
                WHERE audit.run_id = run.run_id
            )
        )
        OR (
            run.audit_head_sequence >= 0
            AND run.revision = run.audit_head_sequence + 1
            AND (
                SELECT COUNT(*) FROM audit_entries AS audit
                WHERE audit.run_id = run.run_id
            ) = run.revision
            AND EXISTS (
                SELECT 1 FROM audit_entries AS head
                WHERE head.run_id = run.run_id
                  AND head.sequence = run.audit_head_sequence
                  AND head.manifest_id = run.manifest_id
                  AND head.entry_hash = run.audit_head_hash
            )
        )
    )
    OR EXISTS (
        SELECT 1
        FROM audit_entries AS audit
        JOIN runs AS owner ON owner.run_id = audit.run_id
        WHERE audit.manifest_id <> owner.manifest_id
           OR (
               audit.sequence = 0
               AND audit.prev_entry_hash
                   <> '0000000000000000000000000000000000000000000000000000000000000000'
           )
           OR (
               audit.sequence > 0
               AND NOT EXISTS (
                   SELECT 1 FROM audit_entries AS predecessor
                   WHERE predecessor.run_id = audit.run_id
                     AND predecessor.sequence = audit.sequence - 1
                     AND predecessor.entry_hash = audit.prev_entry_hash
               )
           )
    )
);

DROP TABLE m6_audit_chain_preflight;

CREATE UNIQUE INDEX uq_runs_m6_audit_cut
    ON runs(run_id, audit_head_sequence, audit_head_hash);

CREATE UNIQUE INDEX uq_run_manifests_m6_document_cut
    ON run_manifests(manifest_id, document_sha256);

CREATE UNIQUE INDEX uq_case_versions_m6_binding
    ON case_versions(run_id, case_id, revision, document_sha256, audit_sequence);

CREATE UNIQUE INDEX uq_audit_entries_m6_binding
    ON audit_entries(run_id, sequence, entry_hash);

CREATE TABLE m6_upgrade_execution_scopes (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    command_id TEXT NOT NULL
        CHECK (length(command_id) = 64 AND command_id NOT GLOB '*[^0-9a-f]*'),
    execution_dataset_snapshot_id TEXT NOT NULL
        CHECK (length(execution_dataset_snapshot_id) = 64
               AND execution_dataset_snapshot_id NOT GLOB '*[^0-9a-f]*'),
    candidate_manifest_id TEXT NOT NULL
        CHECK (length(candidate_manifest_id) = 64
               AND candidate_manifest_id NOT GLOB '*[^0-9a-f]*'),
    candidate_manifest_document_sha256 TEXT NOT NULL
        CHECK (length(candidate_manifest_document_sha256) = 64
               AND candidate_manifest_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    candidate_config_sha256 TEXT NOT NULL
        CHECK (length(candidate_config_sha256) = 64
               AND candidate_config_sha256 NOT GLOB '*[^0-9a-f]*'),
    execution_component_authority_id TEXT NOT NULL
        CHECK (length(execution_component_authority_id) = 64
               AND execution_component_authority_id NOT GLOB '*[^0-9a-f]*'),
    expected_sample_count INTEGER NOT NULL
        CHECK (expected_sample_count BETWEEN 1 AND 100000),
    execution_start_audit_head_sequence INTEGER NOT NULL
        CHECK (execution_start_audit_head_sequence >= -1),
    execution_start_audit_head_hash TEXT NOT NULL
        CHECK (length(execution_start_audit_head_hash) = 64
               AND execution_start_audit_head_hash NOT GLOB '*[^0-9a-f]*'),
    scope_json TEXT NOT NULL CHECK (json_valid(scope_json)),
    document_sha256 TEXT NOT NULL UNIQUE
        CHECK (length(document_sha256) = 64
               AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 268435456),
    UNIQUE (run_id, execution_scope_authority_id),
    FOREIGN KEY (run_id, candidate_manifest_id)
        REFERENCES runs(run_id, manifest_id) ON DELETE RESTRICT,
    FOREIGN KEY (candidate_manifest_id, candidate_manifest_document_sha256)
        REFERENCES run_manifests(manifest_id, document_sha256) ON DELETE RESTRICT,
    CHECK (
        execution_start_audit_head_sequence = -1
        AND execution_start_audit_head_hash
            = '0000000000000000000000000000000000000000000000000000000000000000'
    )
) STRICT;

CREATE TABLE m6_upgrade_physical_artifact_refs (
    run_id TEXT NOT NULL,
    execution_scope_authority_id TEXT NOT NULL,
    artifact_ref_id TEXT NOT NULL
        CHECK (length(artifact_ref_id) = 64
               AND artifact_ref_id NOT GLOB '*[^0-9a-f]*'),
    source TEXT NOT NULL CHECK (source IN (
        'M2_PERCEPTION', 'M2_EVIDENCE', 'M3_SCREENING_MODEL',
        'M4_HEARING_MODEL', 'M4_ACQUISITION', 'M5_PRECEDENT'
    )),
    kind TEXT NOT NULL CHECK (kind IN (
        'FRAME', 'DETECTION', 'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
        'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT', 'MODEL_CALL_FAILURE',
        'MODEL_USAGE_RECEIPT', 'EMBEDDING', 'PRECEDENT_EXPOSURE',
        'TOOL_EXECUTION_MANIFEST', 'TOOL_RESULT', 'EVIDENCE_PACK'
    )),
    artifact_id TEXT NOT NULL CHECK (length(artifact_id) BETWEEN 1 AND 192),
    container_id TEXT CHECK (container_id IS NULL OR length(container_id) BETWEEN 1 AND 192),
    artifact_document_sha256 TEXT NOT NULL
        CHECK (length(artifact_document_sha256) = 64
               AND artifact_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    artifact_content_sha256 TEXT NOT NULL
        CHECK (length(artifact_content_sha256) = 64
               AND artifact_content_sha256 NOT GLOB '*[^0-9a-f]*'),
    artifact_size_bytes INTEGER NOT NULL CHECK (artifact_size_bytes > 0),
    ref_json TEXT NOT NULL CHECK (json_valid(ref_json)),
    ref_document_sha256 TEXT NOT NULL
        CHECK (length(ref_document_sha256) = 64
               AND ref_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    ref_size_bytes INTEGER NOT NULL CHECK (ref_size_bytes BETWEEN 1 AND 1048576),
    PRIMARY KEY (run_id, artifact_ref_id),
    FOREIGN KEY (run_id, execution_scope_authority_id)
        REFERENCES m6_upgrade_execution_scopes(run_id, execution_scope_authority_id)
        ON DELETE RESTRICT,
    CHECK (
        (source = 'M2_PERCEPTION' AND kind IN ('FRAME', 'DETECTION'))
        OR (source = 'M2_EVIDENCE' AND kind = 'EVIDENCE_PACK')
        OR (source IN ('M3_SCREENING_MODEL', 'M4_HEARING_MODEL') AND kind IN (
            'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
            'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT',
            'MODEL_CALL_FAILURE', 'MODEL_USAGE_RECEIPT'
        ))
        OR (source = 'M4_ACQUISITION' AND kind IN (
            'TOOL_EXECUTION_MANIFEST', 'TOOL_RESULT'
        ))
        OR (source = 'M5_PRECEDENT' AND kind IN (
            'EMBEDDING', 'PRECEDENT_EXPOSURE'
        ))
    ),
    CHECK (
        (kind = 'DETECTION' AND container_id IS NOT NULL)
        OR (kind <> 'DETECTION' AND container_id IS NULL)
    ),
    CHECK (
        kind IN ('FRAME', 'MODEL_RESPONSE')
        OR artifact_content_sha256 = artifact_document_sha256
    )
) STRICT;

CREATE UNIQUE INDEX uq_m6_upgrade_physical_artifact_key
    ON m6_upgrade_physical_artifact_refs(
        run_id, source, kind, ifnull(container_id, ''), artifact_id
    );

CREATE TABLE m6_upgrade_sample_executions (
    run_id TEXT NOT NULL,
    execution_scope_authority_id TEXT NOT NULL,
    ledger_sequence INTEGER NOT NULL CHECK (ledger_sequence >= 0),
    previous_ledger_entry_hash TEXT NOT NULL
        CHECK (length(previous_ledger_entry_hash) = 64
               AND previous_ledger_entry_hash NOT GLOB '*[^0-9a-f]*'),
    command_id TEXT NOT NULL
        CHECK (length(command_id) = 64 AND command_id NOT GLOB '*[^0-9a-f]*'),
    execution_dataset_snapshot_id TEXT NOT NULL
        CHECK (length(execution_dataset_snapshot_id) = 64
               AND execution_dataset_snapshot_id NOT GLOB '*[^0-9a-f]*'),
    execution_entry_id TEXT NOT NULL
        CHECK (length(execution_entry_id) = 64
               AND execution_entry_id NOT GLOB '*[^0-9a-f]*'),
    sample_id TEXT NOT NULL CHECK (length(sample_id) BETWEEN 1 AND 64),
    outcome TEXT NOT NULL CHECK (outcome IN ('CASE_REPLAYED', 'NO_CASE')),
    case_id TEXT,
    case_revision INTEGER CHECK (case_revision IS NULL OR case_revision > 0),
    case_document_sha256 TEXT
        CHECK (case_document_sha256 IS NULL OR (
            length(case_document_sha256) = 64
            AND case_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )),
    case_audit_sequence INTEGER
        CHECK (case_audit_sequence IS NULL OR case_audit_sequence >= 0),
    case_audit_entry_hash TEXT
        CHECK (case_audit_entry_hash IS NULL OR (
            length(case_audit_entry_hash) = 64
            AND case_audit_entry_hash NOT GLOB '*[^0-9a-f]*'
        )),
    artifact_link_count INTEGER NOT NULL CHECK (artifact_link_count BETWEEN 1 AND 20000),
    artifact_link_inventory_root_sha256 TEXT NOT NULL
        CHECK (length(artifact_link_inventory_root_sha256) = 64
               AND artifact_link_inventory_root_sha256 NOT GLOB '*[^0-9a-f]*'),
    sample_execution_record_id TEXT NOT NULL
        CHECK (length(sample_execution_record_id) = 64
               AND sample_execution_record_id NOT GLOB '*[^0-9a-f]*'),
    record_json TEXT NOT NULL CHECK (json_valid(record_json)),
    record_document_sha256 TEXT NOT NULL
        CHECK (length(record_document_sha256) = 64
               AND record_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    record_size_bytes INTEGER NOT NULL CHECK (record_size_bytes BETWEEN 1 AND 67108864),
    PRIMARY KEY (run_id, ledger_sequence),
    UNIQUE (run_id, execution_entry_id),
    UNIQUE (run_id, sample_id),
    UNIQUE (run_id, sample_execution_record_id),
    UNIQUE (run_id, case_id),
    FOREIGN KEY (run_id, execution_scope_authority_id)
        REFERENCES m6_upgrade_execution_scopes(run_id, execution_scope_authority_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, case_id, case_revision, case_document_sha256, case_audit_sequence)
        REFERENCES case_versions(run_id, case_id, revision, document_sha256, audit_sequence)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (run_id, case_audit_sequence, case_audit_entry_hash)
        REFERENCES audit_entries(run_id, sequence, entry_hash)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (outcome = 'CASE_REPLAYED'
         AND case_id IS NOT NULL
         AND case_revision IS NOT NULL
         AND case_document_sha256 IS NOT NULL
         AND case_audit_sequence IS NOT NULL
         AND case_audit_entry_hash IS NOT NULL)
        OR
        (outcome = 'NO_CASE'
         AND case_id IS NULL
         AND case_revision IS NULL
         AND case_document_sha256 IS NULL
         AND case_audit_sequence IS NULL
         AND case_audit_entry_hash IS NULL)
    )
) STRICT;

CREATE TABLE m6_upgrade_sample_artifact_links (
    run_id TEXT NOT NULL,
    execution_entry_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    usage TEXT NOT NULL CHECK (usage IN ('CONSUMED', 'PRODUCED')),
    artifact_ref_id TEXT NOT NULL,
    artifact_link_id TEXT NOT NULL
        CHECK (length(artifact_link_id) = 64
               AND artifact_link_id NOT GLOB '*[^0-9a-f]*'),
    link_json TEXT NOT NULL CHECK (json_valid(link_json)),
    link_document_sha256 TEXT NOT NULL
        CHECK (length(link_document_sha256) = 64
               AND link_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    link_size_bytes INTEGER NOT NULL CHECK (link_size_bytes BETWEEN 1 AND 1048576),
    PRIMARY KEY (run_id, execution_entry_id, ordinal),
    UNIQUE (run_id, execution_entry_id, artifact_ref_id),
    FOREIGN KEY (run_id, artifact_ref_id)
        REFERENCES m6_upgrade_physical_artifact_refs(run_id, artifact_ref_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, execution_entry_id)
        REFERENCES m6_upgrade_sample_executions(run_id, execution_entry_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE m6_upgrade_execution_ledger_seals (
    run_id TEXT PRIMARY KEY,
    execution_scope_authority_id TEXT NOT NULL,
    execution_scope_document_sha256 TEXT NOT NULL,
    execution_scope_size_bytes INTEGER NOT NULL CHECK (execution_scope_size_bytes > 0),
    source_audit_head_sequence INTEGER NOT NULL CHECK (source_audit_head_sequence >= -1),
    source_audit_head_hash TEXT NOT NULL
        CHECK (length(source_audit_head_hash) = 64
               AND source_audit_head_hash NOT GLOB '*[^0-9a-f]*'),
    sample_execution_count INTEGER NOT NULL CHECK (sample_execution_count BETWEEN 1 AND 100000),
    sample_execution_inventory_root_sha256 TEXT NOT NULL,
    artifact_link_count INTEGER NOT NULL CHECK (artifact_link_count BETWEEN 1 AND 250000),
    artifact_link_inventory_root_sha256 TEXT NOT NULL,
    candidate_case_count INTEGER NOT NULL CHECK (candidate_case_count BETWEEN 0 AND 100000),
    candidate_case_inventory_root_sha256 TEXT NOT NULL,
    ledger_preseal_sequence INTEGER NOT NULL CHECK (ledger_preseal_sequence >= 0),
    ledger_preseal_hash TEXT NOT NULL,
    ledger_head_sequence INTEGER NOT NULL CHECK (ledger_head_sequence > 0),
    ledger_seal_authority_id TEXT NOT NULL UNIQUE,
    seal_json TEXT NOT NULL CHECK (json_valid(seal_json)),
    document_sha256 TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 268435456),
    FOREIGN KEY (run_id, execution_scope_authority_id)
        REFERENCES m6_upgrade_execution_scopes(run_id, execution_scope_authority_id)
        ON DELETE RESTRICT,
    CHECK (
        source_audit_head_sequence <> -1
        OR source_audit_head_hash
            = '0000000000000000000000000000000000000000000000000000000000000000'
    )
) STRICT;

CREATE TRIGGER runs_m6_require_genesis_insert
BEFORE INSERT ON runs
WHEN NEW.revision <> 0
  OR NEW.audit_head_sequence <> -1
  OR NEW.audit_head_hash
      <> '0000000000000000000000000000000000000000000000000000000000000000'
BEGIN
    SELECT RAISE(ABORT, 'new runs must start at the immutable audit genesis');
END;

CREATE TRIGGER audit_entries_m6_require_next
BEFORE INSERT ON audit_entries
WHEN NOT EXISTS (
    SELECT 1 FROM runs AS run
    WHERE run.run_id = NEW.run_id
      AND run.manifest_id = NEW.manifest_id
      AND NEW.sequence = run.audit_head_sequence + 1
      AND NEW.prev_entry_hash = run.audit_head_hash
)
BEGIN
    SELECT RAISE(ABORT, 'audit entry must extend the exact current run head');
END;

CREATE TRIGGER runs_m6_audit_head_matches_entry
BEFORE UPDATE ON runs
WHEN NOT EXISTS (
    SELECT 1 FROM audit_entries AS audit
    WHERE audit.run_id = NEW.run_id
      AND audit.sequence = NEW.audit_head_sequence
      AND audit.manifest_id = NEW.manifest_id
      AND audit.prev_entry_hash = OLD.audit_head_hash
      AND audit.entry_hash = NEW.audit_head_hash
)
BEGIN
    SELECT RAISE(
        ABORT,
        'run identity is immutable; audit head updates must be monotonic and match the exact immutable audit entry'
    );
END;

CREATE TRIGGER m6_upgrade_execution_scopes_validate
BEFORE INSERT ON m6_upgrade_execution_scopes
WHEN NOT (
    EXISTS (
        SELECT 1 FROM runs AS run
        JOIN run_manifests AS manifest ON manifest.manifest_id = run.manifest_id
        WHERE run.run_id = NEW.run_id
          AND run.manifest_id = NEW.candidate_manifest_id
          AND manifest.document_sha256 = NEW.candidate_manifest_document_sha256
          AND run.audit_head_sequence = NEW.execution_start_audit_head_sequence
          AND run.audit_head_hash = NEW.execution_start_audit_head_hash
    )
    AND (
        NEW.execution_start_audit_head_sequence = -1
        AND NOT EXISTS (
            SELECT 1 FROM audit_entries AS audit
            WHERE audit.run_id = NEW.run_id
        )
    )
    AND json_extract(NEW.scope_json, '$.candidate_run_id') = NEW.run_id
    AND json_extract(NEW.scope_json, '$.execution_scope_authority_id')
        = NEW.execution_scope_authority_id
    AND json_extract(NEW.scope_json, '$.command.command_id') = NEW.command_id
    AND json_extract(NEW.scope_json, '$.execution_dataset.execution_dataset_snapshot_id')
        = NEW.execution_dataset_snapshot_id
    AND json_extract(NEW.scope_json, '$.candidate_manifest.manifest_id')
        = NEW.candidate_manifest_id
    AND json_extract(NEW.scope_json, '$.candidate_manifest_content_sha256')
        = NEW.candidate_manifest_document_sha256
    AND json_extract(NEW.scope_json, '$.candidate_config.config_sha256')
        = NEW.candidate_config_sha256
    AND json_extract(NEW.scope_json, '$.execution_component.component_authority_id')
        = NEW.execution_component_authority_id
    AND json_extract(NEW.scope_json, '$.execution_dataset.entry_count')
        = NEW.expected_sample_count
    AND json_extract(NEW.scope_json, '$.execution_start_audit_head_sequence')
        = NEW.execution_start_audit_head_sequence
    AND json_extract(NEW.scope_json, '$.execution_start_audit_head_hash')
        = NEW.execution_start_audit_head_hash
    AND length(CAST(NEW.scope_json AS BLOB)) = NEW.size_bytes
)
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade execution scope');
END;

CREATE TRIGGER m6_upgrade_physical_artifact_refs_validate
BEFORE INSERT ON m6_upgrade_physical_artifact_refs
WHEN NOT (
    EXISTS (
        SELECT 1 FROM m6_upgrade_execution_scopes AS scope
        WHERE scope.run_id = NEW.run_id
          AND scope.execution_scope_authority_id = NEW.execution_scope_authority_id
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_execution_ledger_seals AS seal
        WHERE seal.run_id = NEW.run_id
    )
    AND json_extract(NEW.ref_json, '$.artifact_ref_id') = NEW.artifact_ref_id
    AND json_extract(NEW.ref_json, '$.source') = NEW.source
    AND json_extract(NEW.ref_json, '$.kind') = NEW.kind
    AND json_extract(NEW.ref_json, '$.artifact_id') = NEW.artifact_id
    AND json_extract(NEW.ref_json, '$.container_id') IS NEW.container_id
    AND json_extract(NEW.ref_json, '$.document_sha256') = NEW.artifact_document_sha256
    AND json_extract(NEW.ref_json, '$.content_sha256') = NEW.artifact_content_sha256
    AND json_extract(NEW.ref_json, '$.size_bytes') = NEW.artifact_size_bytes
    AND length(CAST(NEW.ref_json AS BLOB)) = NEW.ref_size_bytes
)
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade physical artifact ref');
END;

CREATE TRIGGER m6_upgrade_sample_artifact_links_validate
BEFORE INSERT ON m6_upgrade_sample_artifact_links
WHEN NOT (
    NOT EXISTS (
        SELECT 1 FROM m6_upgrade_execution_ledger_seals AS seal
        WHERE seal.run_id = NEW.run_id
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
          AND sample.execution_entry_id = NEW.execution_entry_id
    )
    AND EXISTS (
        SELECT 1 FROM m6_upgrade_physical_artifact_refs AS ref
        WHERE ref.run_id = NEW.run_id
          AND ref.artifact_ref_id = NEW.artifact_ref_id
          AND (
              (ref.kind = 'FRAME' AND NEW.usage = 'CONSUMED')
              OR ref.kind IN ('MODEL_CACHE', 'EMBEDDING')
              OR (
                  ref.kind IN (
                      'DETECTION', 'MODEL_REQUEST', 'MODEL_RESPONSE',
                      'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT',
                      'MODEL_CALL_FAILURE', 'MODEL_USAGE_RECEIPT',
                      'PRECEDENT_EXPOSURE', 'TOOL_EXECUTION_MANIFEST',
                      'TOOL_RESULT', 'EVIDENCE_PACK'
                  )
                  AND NEW.usage = 'PRODUCED'
              )
          )
          AND json_extract(NEW.link_json, '$.artifact.source') = ref.source
          AND json_extract(NEW.link_json, '$.artifact.kind') = ref.kind
          AND json_extract(NEW.link_json, '$.artifact.artifact_id') = ref.artifact_id
          AND json_extract(NEW.link_json, '$.artifact.container_id') IS ref.container_id
          AND json_extract(NEW.link_json, '$.artifact.document_sha256')
              = ref.artifact_document_sha256
          AND json_extract(NEW.link_json, '$.artifact.content_sha256')
              = ref.artifact_content_sha256
          AND json_extract(NEW.link_json, '$.artifact.size_bytes')
              = ref.artifact_size_bytes
    )
    AND json_extract(NEW.link_json, '$.ordinal') = NEW.ordinal
    AND json_extract(NEW.link_json, '$.usage') = NEW.usage
    AND json_extract(NEW.link_json, '$.artifact.artifact_ref_id') = NEW.artifact_ref_id
    AND json_extract(NEW.link_json, '$.artifact_link_id') = NEW.artifact_link_id
    AND length(CAST(NEW.link_json AS BLOB)) = NEW.link_size_bytes
)
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade sample artifact link');
END;

CREATE TRIGGER m6_upgrade_sample_executions_validate
BEFORE INSERT ON m6_upgrade_sample_executions
WHEN NOT (
    NOT EXISTS (
        SELECT 1 FROM m6_upgrade_execution_ledger_seals AS seal
        WHERE seal.run_id = NEW.run_id
    )
    AND EXISTS (
        SELECT 1 FROM m6_upgrade_execution_scopes AS scope
        WHERE scope.run_id = NEW.run_id
          AND scope.execution_scope_authority_id = NEW.execution_scope_authority_id
          AND scope.command_id = NEW.command_id
          AND scope.execution_dataset_snapshot_id = NEW.execution_dataset_snapshot_id
          AND NEW.ledger_sequence < scope.expected_sample_count
          AND json_extract(
              scope.scope_json,
              '$.execution_dataset.entries[' || NEW.ledger_sequence || '].execution_entry_id'
          ) = NEW.execution_entry_id
          AND json_extract(
              scope.scope_json,
              '$.execution_dataset.entries[' || NEW.ledger_sequence || '].sample_id'
          ) = NEW.sample_id
    )
    AND (
        (NEW.ledger_sequence = 0
         AND NEW.previous_ledger_entry_hash
             = '0000000000000000000000000000000000000000000000000000000000000000')
        OR
        (NEW.ledger_sequence > 0 AND EXISTS (
            SELECT 1 FROM m6_upgrade_sample_executions AS prior
            WHERE prior.run_id = NEW.run_id
              AND prior.ledger_sequence = NEW.ledger_sequence - 1
              AND prior.sample_execution_record_id = NEW.previous_ledger_entry_hash
        ))
    )
    AND (
        NEW.outcome = 'NO_CASE'
        OR EXISTS (
            SELECT 1
            FROM case_versions AS version
            JOIN audit_entries AS audit
              ON audit.run_id = version.run_id
             AND audit.sequence = version.audit_sequence
            WHERE version.run_id = NEW.run_id
              AND version.case_id = NEW.case_id
              AND version.revision = NEW.case_revision
              AND version.document_sha256 = NEW.case_document_sha256
              AND version.audit_sequence = NEW.case_audit_sequence
              AND audit.entry_hash = NEW.case_audit_entry_hash
              AND audit.object_kind = 'CASE'
              AND audit.object_id = NEW.case_id
              AND audit.after_sha256 = NEW.case_document_sha256
        )
    )
    AND (
        NEW.outcome = 'NO_CASE'
        OR NEW.case_audit_sequence > (
            SELECT scope.execution_start_audit_head_sequence
            FROM m6_upgrade_execution_scopes AS scope
            WHERE scope.run_id = NEW.run_id
              AND scope.execution_scope_authority_id = NEW.execution_scope_authority_id
        )
    )
    AND (SELECT COUNT(*) FROM m6_upgrade_sample_artifact_links AS link
         WHERE link.run_id = NEW.run_id
           AND link.execution_entry_id = NEW.execution_entry_id)
        = NEW.artifact_link_count
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_sample_artifact_links AS link
        WHERE link.run_id = NEW.run_id
          AND link.execution_entry_id = NEW.execution_entry_id
          AND json(link.link_json) <> json_extract(
              NEW.record_json,
              '$.artifact_links[' || link.ordinal || ']'
          )
    )
    AND (
        NEW.outcome <> 'NO_CASE'
        OR NOT EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_artifact_links AS link
            JOIN m6_upgrade_physical_artifact_refs AS ref
              ON ref.run_id = link.run_id
             AND ref.artifact_ref_id = link.artifact_ref_id
            WHERE link.run_id = NEW.run_id
              AND link.execution_entry_id = NEW.execution_entry_id
              AND ref.kind NOT IN ('FRAME', 'DETECTION')
        )
    )
    AND EXISTS (
        SELECT 1
        FROM m6_upgrade_sample_artifact_links AS link
        JOIN m6_upgrade_physical_artifact_refs AS ref
          ON ref.run_id = link.run_id
         AND ref.artifact_ref_id = link.artifact_ref_id
        WHERE link.run_id = NEW.run_id
          AND link.execution_entry_id = NEW.execution_entry_id
          AND ref.kind = 'FRAME'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM m6_upgrade_sample_artifact_links AS detection_link
        JOIN m6_upgrade_physical_artifact_refs AS detection
          ON detection.run_id = detection_link.run_id
         AND detection.artifact_ref_id = detection_link.artifact_ref_id
        WHERE detection_link.run_id = NEW.run_id
          AND detection_link.execution_entry_id = NEW.execution_entry_id
          AND detection.kind = 'DETECTION'
          AND NOT EXISTS (
              SELECT 1
              FROM m6_upgrade_sample_artifact_links AS frame_link
              JOIN m6_upgrade_physical_artifact_refs AS frame
                ON frame.run_id = frame_link.run_id
               AND frame.artifact_ref_id = frame_link.artifact_ref_id
              WHERE frame_link.run_id = detection_link.run_id
                AND frame_link.execution_entry_id = detection_link.execution_entry_id
                AND frame.kind = 'FRAME'
                AND frame.artifact_id = detection.container_id
          )
    )
    AND json_extract(NEW.record_json, '$.execution_scope_authority_id')
        = NEW.execution_scope_authority_id
    AND json_extract(NEW.record_json, '$.candidate_run_id') = NEW.run_id
    AND json_extract(NEW.record_json, '$.command_id') = NEW.command_id
    AND json_extract(NEW.record_json, '$.execution_dataset_snapshot_id')
        = NEW.execution_dataset_snapshot_id
    AND json_extract(NEW.record_json, '$.ledger_sequence') = NEW.ledger_sequence
    AND json_extract(NEW.record_json, '$.previous_ledger_entry_hash')
        = NEW.previous_ledger_entry_hash
    AND json_extract(NEW.record_json, '$.execution_entry_id') = NEW.execution_entry_id
    AND json_extract(NEW.record_json, '$.sample_id') = NEW.sample_id
    AND json_extract(NEW.record_json, '$.outcome') = NEW.outcome
    AND json_extract(NEW.record_json, '$.candidate_case.case_id') IS NEW.case_id
    AND json_extract(NEW.record_json, '$.candidate_case.case_revision') IS NEW.case_revision
    AND json_extract(NEW.record_json, '$.candidate_case.case_document_sha256')
        IS NEW.case_document_sha256
    AND json_extract(NEW.record_json, '$.candidate_case.case_audit_sequence')
        IS NEW.case_audit_sequence
    AND json_extract(NEW.record_json, '$.candidate_case.case_audit_entry_hash')
        IS NEW.case_audit_entry_hash
    AND json_extract(NEW.record_json, '$.artifact_link_count') = NEW.artifact_link_count
    AND json_extract(NEW.record_json, '$.artifact_link_inventory_root_sha256')
        = NEW.artifact_link_inventory_root_sha256
    AND json_extract(NEW.record_json, '$.sample_execution_record_id')
        = NEW.sample_execution_record_id
    AND length(CAST(NEW.record_json AS BLOB)) = NEW.record_size_bytes
)
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade sample execution');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_seals_validate
BEFORE INSERT ON m6_upgrade_execution_ledger_seals
WHEN NOT (
    EXISTS (
        SELECT 1 FROM m6_upgrade_execution_scopes AS scope
        JOIN runs AS run ON run.run_id = scope.run_id
        WHERE scope.run_id = NEW.run_id
          AND scope.execution_scope_authority_id = NEW.execution_scope_authority_id
          AND scope.document_sha256 = NEW.execution_scope_document_sha256
          AND scope.size_bytes = NEW.execution_scope_size_bytes
          AND scope.expected_sample_count = NEW.sample_execution_count
          AND run.audit_head_sequence = NEW.source_audit_head_sequence
          AND run.audit_head_hash = NEW.source_audit_head_hash
          AND json(scope.scope_json) = json_extract(
              NEW.seal_json,
              '$.execution_scope'
          )
    )
    AND (
        NEW.source_audit_head_sequence = -1
        OR EXISTS (
            SELECT 1 FROM audit_entries AS audit
            WHERE audit.run_id = NEW.run_id
              AND audit.sequence = NEW.source_audit_head_sequence
              AND audit.entry_hash = NEW.source_audit_head_hash
        )
    )
    AND (SELECT COUNT(*) FROM m6_upgrade_sample_executions AS sample
         WHERE sample.run_id = NEW.run_id) = NEW.sample_execution_count
    AND (SELECT MAX(sample.ledger_sequence) FROM m6_upgrade_sample_executions AS sample
         WHERE sample.run_id = NEW.run_id) = NEW.ledger_preseal_sequence
    AND EXISTS (
        SELECT 1 FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
          AND sample.ledger_sequence = NEW.ledger_preseal_sequence
          AND sample.sample_execution_record_id = NEW.ledger_preseal_hash
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
          AND json(sample.record_json) <> json_extract(
              NEW.seal_json,
              '$.sample_executions[' || sample.ledger_sequence || ']'
          )
    )
    AND NEW.ledger_head_sequence = NEW.sample_execution_count
    AND NEW.ledger_preseal_sequence = NEW.sample_execution_count - 1
    AND (SELECT COUNT(*) FROM m6_upgrade_sample_artifact_links AS link
         WHERE link.run_id = NEW.run_id) = NEW.artifact_link_count
    AND (SELECT COALESCE(SUM(sample.artifact_link_count), 0)
         FROM m6_upgrade_sample_executions AS sample
         WHERE sample.run_id = NEW.run_id) = NEW.artifact_link_count
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_physical_artifact_refs AS ref
        WHERE ref.run_id = NEW.run_id
          AND NOT EXISTS (
              SELECT 1 FROM m6_upgrade_sample_artifact_links AS link
              WHERE link.run_id = ref.run_id
                AND link.artifact_ref_id = ref.artifact_ref_id
          )
    )
    AND (SELECT COUNT(*) FROM cases AS current_case
         WHERE current_case.run_id = NEW.run_id) = NEW.candidate_case_count
    AND NOT EXISTS (
        SELECT 1 FROM cases AS current_case
        JOIN case_versions AS version
          ON version.run_id = current_case.run_id
         AND version.case_id = current_case.case_id
         AND version.revision = current_case.current_revision
        WHERE current_case.run_id = NEW.run_id
          AND NOT EXISTS (
              SELECT 1 FROM m6_upgrade_sample_executions AS sample
              WHERE sample.run_id = current_case.run_id
                AND sample.case_id = current_case.case_id
                AND sample.case_revision = current_case.current_revision
                AND sample.case_document_sha256 = version.document_sha256
                AND sample.case_audit_sequence = version.audit_sequence
          )
    )
    AND json_extract(NEW.seal_json, '$.execution_scope.execution_scope_authority_id')
        = NEW.execution_scope_authority_id
    AND json_extract(NEW.seal_json, '$.execution_scope_content_sha256')
        = NEW.execution_scope_document_sha256
    AND json_extract(NEW.seal_json, '$.execution_scope_size_bytes')
        = NEW.execution_scope_size_bytes
    AND json_extract(NEW.seal_json, '$.source_audit_head_sequence')
        = NEW.source_audit_head_sequence
    AND json_extract(NEW.seal_json, '$.source_audit_head_hash') = NEW.source_audit_head_hash
    AND json_extract(NEW.seal_json, '$.sample_execution_count') = NEW.sample_execution_count
    AND json_extract(NEW.seal_json, '$.sample_execution_inventory_root_sha256')
        = NEW.sample_execution_inventory_root_sha256
    AND json_extract(NEW.seal_json, '$.artifact_link_count') = NEW.artifact_link_count
    AND json_extract(NEW.seal_json, '$.artifact_link_inventory_root_sha256')
        = NEW.artifact_link_inventory_root_sha256
    AND json_extract(NEW.seal_json, '$.candidate_case_count') = NEW.candidate_case_count
    AND json_extract(NEW.seal_json, '$.candidate_case_inventory_root_sha256')
        = NEW.candidate_case_inventory_root_sha256
    AND json_extract(NEW.seal_json, '$.ledger_preseal_sequence') = NEW.ledger_preseal_sequence
    AND json_extract(NEW.seal_json, '$.ledger_preseal_hash') = NEW.ledger_preseal_hash
    AND json_extract(NEW.seal_json, '$.ledger_head_sequence') = NEW.ledger_head_sequence
    AND json_extract(NEW.seal_json, '$.ledger_seal_authority_id')
        = NEW.ledger_seal_authority_id
    AND length(CAST(NEW.seal_json AS BLOB)) = NEW.size_bytes
)
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade execution ledger seal');
END;

CREATE TRIGGER m6_upgrade_execution_scopes_no_replace
BEFORE INSERT ON m6_upgrade_execution_scopes
WHEN EXISTS (SELECT 1 FROM m6_upgrade_execution_scopes WHERE run_id = NEW.run_id)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution scopes are append-only');
END;

CREATE TRIGGER m6_upgrade_physical_artifact_refs_no_replace
BEFORE INSERT ON m6_upgrade_physical_artifact_refs
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_physical_artifact_refs
    WHERE run_id = NEW.run_id AND artifact_ref_id = NEW.artifact_ref_id
)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade physical artifact refs are append-only');
END;

CREATE TRIGGER m6_upgrade_sample_artifact_links_no_replace
BEFORE INSERT ON m6_upgrade_sample_artifact_links
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_sample_artifact_links
    WHERE run_id = NEW.run_id
      AND execution_entry_id = NEW.execution_entry_id
      AND ordinal = NEW.ordinal
)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade sample artifact links are append-only');
END;

CREATE TRIGGER m6_upgrade_sample_executions_no_replace
BEFORE INSERT ON m6_upgrade_sample_executions
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_sample_executions
    WHERE run_id = NEW.run_id
      AND (ledger_sequence = NEW.ledger_sequence
           OR execution_entry_id = NEW.execution_entry_id
           OR sample_id = NEW.sample_id)
)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade sample executions are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_seals_no_replace
BEFORE INSERT ON m6_upgrade_execution_ledger_seals
WHEN EXISTS (SELECT 1 FROM m6_upgrade_execution_ledger_seals WHERE run_id = NEW.run_id)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution ledger seals are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_scopes_no_update
BEFORE UPDATE ON m6_upgrade_execution_scopes
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution scopes are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_scopes_no_delete
BEFORE DELETE ON m6_upgrade_execution_scopes
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution scopes are append-only');
END;

CREATE TRIGGER m6_upgrade_physical_artifact_refs_no_update
BEFORE UPDATE ON m6_upgrade_physical_artifact_refs
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade physical artifact refs are append-only');
END;

CREATE TRIGGER m6_upgrade_physical_artifact_refs_no_delete
BEFORE DELETE ON m6_upgrade_physical_artifact_refs
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade physical artifact refs are append-only');
END;

CREATE TRIGGER m6_upgrade_sample_artifact_links_no_update
BEFORE UPDATE ON m6_upgrade_sample_artifact_links
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade sample artifact links are append-only');
END;

CREATE TRIGGER m6_upgrade_sample_artifact_links_no_delete
BEFORE DELETE ON m6_upgrade_sample_artifact_links
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade sample artifact links are append-only');
END;

CREATE TRIGGER m6_upgrade_sample_executions_no_update
BEFORE UPDATE ON m6_upgrade_sample_executions
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade sample executions are append-only');
END;

CREATE TRIGGER m6_upgrade_sample_executions_no_delete
BEFORE DELETE ON m6_upgrade_sample_executions
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade sample executions are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_seals_no_update
BEFORE UPDATE ON m6_upgrade_execution_ledger_seals
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution ledger seals are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_seals_no_delete
BEFORE DELETE ON m6_upgrade_execution_ledger_seals
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution ledger seals are append-only');
END;
