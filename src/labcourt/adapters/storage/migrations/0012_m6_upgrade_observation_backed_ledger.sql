CREATE TABLE m6_upgrade_observation_backed_ledger_preflight (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

INSERT INTO m6_upgrade_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1 FROM m6_upgrade_sample_execution_observations AS observation
    WHERE EXISTS (
        SELECT 1 FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = observation.run_id
    )
       OR EXISTS (
        SELECT 1 FROM m6_upgrade_execution_ledger_seals AS seal
        WHERE seal.run_id = observation.run_id
    )
);

INSERT INTO m6_upgrade_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1 FROM m6_upgrade_sample_executions AS sample
    WHERE json_array_length(sample.record_json, '$.artifact_links')
              IS NOT sample.artifact_link_count
       OR EXISTS (
            SELECT 1 FROM m6_upgrade_sample_artifact_links AS link
            WHERE link.run_id = sample.run_id
              AND link.execution_entry_id = sample.execution_entry_id
              AND (
                  link.ordinal >= sample.artifact_link_count
                  OR json(link.link_json) IS NOT json_extract(
                      sample.record_json,
                      '$.artifact_links[' || link.ordinal || ']'
                  )
              )
       )
);

INSERT INTO m6_upgrade_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT observation.run_id
    FROM m6_upgrade_sample_execution_observations AS observation
    GROUP BY observation.run_id
    HAVING SUM(observation.size_bytes) > 268435456
       OR SUM(observation.size_bytes) IS NOT SUM(
           length(CAST(observation.observation_json AS BLOB))
       )
)
OR EXISTS (
    SELECT artifact.run_id
    FROM m6_upgrade_observed_non_model_artifacts AS artifact
    GROUP BY artifact.run_id
    HAVING COUNT(*) > 270000
)
OR EXISTS (
    SELECT model_call.run_id
    FROM m6_upgrade_observed_model_calls AS model_call
    GROUP BY model_call.run_id
    HAVING COUNT(*) > 270000
);

INSERT INTO m6_upgrade_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_scopes AS scope
    WHERE (
        json_type(scope.scope_json, '$') = 'object'
        AND json_extract(scope.scope_json, '$.schema_version')
            = 'm6-upgrade-execution-scope-authority-v1'
        AND json_extract(scope.scope_json, '$.candidate_run_id') = scope.run_id
        AND json_extract(scope.scope_json, '$.execution_scope_authority_id')
            = scope.execution_scope_authority_id
        AND json_extract(scope.scope_json, '$.command.command_id') = scope.command_id
        AND json_extract(
            scope.scope_json,
            '$.execution_dataset.execution_dataset_snapshot_id'
        ) = scope.execution_dataset_snapshot_id
        AND json_extract(scope.scope_json, '$.candidate_manifest.manifest_id')
            = scope.candidate_manifest_id
        AND json_extract(scope.scope_json, '$.candidate_manifest_content_sha256')
            = scope.candidate_manifest_document_sha256
        AND json_extract(scope.scope_json, '$.candidate_config.config_sha256')
            = scope.candidate_config_sha256
        AND json_extract(
            scope.scope_json,
            '$.execution_component.component_authority_id'
        ) = scope.execution_component_authority_id
        AND json_extract(scope.scope_json, '$.execution_dataset.entry_count')
            = scope.expected_sample_count
        AND json_extract(scope.scope_json, '$.execution_start_audit_head_sequence')
            = scope.execution_start_audit_head_sequence
        AND json_extract(scope.scope_json, '$.execution_start_audit_head_hash')
            = scope.execution_start_audit_head_hash
        AND length(CAST(scope.scope_json AS BLOB)) = scope.size_bytes
    ) IS NOT TRUE
);

INSERT INTO m6_upgrade_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_physical_artifact_refs AS ref
    WHERE (
        json_type(ref.ref_json, '$') = 'object'
        AND json_extract(ref.ref_json, '$.schema_version')
            = 'm6-upgrade-physical-artifact-ref-v1'
        AND json_extract(ref.ref_json, '$.artifact_ref_id') = ref.artifact_ref_id
        AND json_extract(ref.ref_json, '$.source') = ref.source
        AND json_extract(ref.ref_json, '$.kind') = ref.kind
        AND json_extract(ref.ref_json, '$.artifact_id') = ref.artifact_id
        AND json_type(ref.ref_json, '$.container_id') IS NOT NULL
        AND json_extract(ref.ref_json, '$.container_id') IS ref.container_id
        AND json_extract(ref.ref_json, '$.document_sha256')
            = ref.artifact_document_sha256
        AND json_extract(ref.ref_json, '$.content_sha256')
            = ref.artifact_content_sha256
        AND json_extract(ref.ref_json, '$.size_bytes') = ref.artifact_size_bytes
        AND length(CAST(ref.ref_json AS BLOB)) = ref.ref_size_bytes
    ) IS NOT TRUE
);

INSERT INTO m6_upgrade_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_artifact_links AS link
    WHERE (
        json_type(link.link_json, '$') = 'object'
        AND json_type(link.link_json, '$.artifact') = 'object'
        AND json_extract(link.link_json, '$.ordinal') = link.ordinal
        AND json_extract(link.link_json, '$.usage') = link.usage
        AND json_extract(link.link_json, '$.artifact.artifact_ref_id')
            = link.artifact_ref_id
        AND json_extract(link.link_json, '$.artifact_link_id')
            = link.artifact_link_id
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_physical_artifact_refs AS ref
            WHERE ref.run_id = link.run_id
              AND ref.artifact_ref_id = link.artifact_ref_id
              AND json_extract(link.link_json, '$.artifact') = json(ref.ref_json)
        )
        AND length(CAST(link.link_json AS BLOB)) = link.link_size_bytes
    ) IS NOT TRUE
);

INSERT INTO m6_upgrade_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_executions AS sample
    WHERE (
        json_type(sample.record_json, '$') = 'object'
        AND json_extract(sample.record_json, '$.schema_version')
            = 'm6-upgrade-sample-execution-record-v1'
        AND json_extract(sample.record_json, '$.execution_scope_authority_id')
            = sample.execution_scope_authority_id
        AND json_extract(sample.record_json, '$.candidate_run_id') = sample.run_id
        AND json_extract(sample.record_json, '$.command_id') = sample.command_id
        AND json_extract(sample.record_json, '$.execution_dataset_snapshot_id')
            = sample.execution_dataset_snapshot_id
        AND json_extract(sample.record_json, '$.ledger_sequence')
            = sample.ledger_sequence
        AND json_extract(sample.record_json, '$.previous_ledger_entry_hash')
            = sample.previous_ledger_entry_hash
        AND json_extract(sample.record_json, '$.execution_entry_id')
            = sample.execution_entry_id
        AND json_extract(sample.record_json, '$.sample_id') = sample.sample_id
        AND json_extract(sample.record_json, '$.outcome') = sample.outcome
        AND json_type(sample.record_json, '$.candidate_case') IN ('object', 'null')
        AND json_extract(sample.record_json, '$.candidate_case.case_id') IS sample.case_id
        AND json_extract(sample.record_json, '$.candidate_case.case_revision')
            IS sample.case_revision
        AND json_extract(
            sample.record_json,
            '$.candidate_case.case_document_sha256'
        ) IS sample.case_document_sha256
        AND json_extract(
            sample.record_json,
            '$.candidate_case.case_audit_sequence'
        ) IS sample.case_audit_sequence
        AND json_extract(
            sample.record_json,
            '$.candidate_case.case_audit_entry_hash'
        ) IS sample.case_audit_entry_hash
        AND json_type(sample.record_json, '$.artifact_links') = 'array'
        AND json_array_length(sample.record_json, '$.artifact_links')
            = sample.artifact_link_count
        AND json_extract(sample.record_json, '$.artifact_link_count')
            = sample.artifact_link_count
        AND json_extract(
            sample.record_json,
            '$.artifact_link_inventory_root_sha256'
        ) = sample.artifact_link_inventory_root_sha256
        AND json_extract(sample.record_json, '$.sample_execution_record_id')
            = sample.sample_execution_record_id
        AND NOT EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_artifact_links AS link
            WHERE link.run_id = sample.run_id
              AND link.execution_entry_id = sample.execution_entry_id
              AND (
                  link.ordinal >= sample.artifact_link_count
                  OR json(link.link_json) IS NOT json_extract(
                      sample.record_json,
                      '$.artifact_links[' || link.ordinal || ']'
                  )
              )
        )
        AND length(CAST(sample.record_json AS BLOB)) = sample.record_size_bytes
    ) IS NOT TRUE
);

INSERT INTO m6_upgrade_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_ledger_seals AS seal
    WHERE (
        json_type(seal.seal_json, '$') = 'object'
        AND json_extract(seal.seal_json, '$.schema_version')
            = 'm6-upgrade-execution-ledger-seal-v1'
        AND json_extract(
            seal.seal_json,
            '$.execution_scope.execution_scope_authority_id'
        ) = seal.execution_scope_authority_id
        AND json_extract(seal.seal_json, '$.execution_scope_content_sha256')
            = seal.execution_scope_document_sha256
        AND json_extract(seal.seal_json, '$.execution_scope_size_bytes')
            = seal.execution_scope_size_bytes
        AND json_extract(seal.seal_json, '$.source_audit_head_sequence')
            = seal.source_audit_head_sequence
        AND json_extract(seal.seal_json, '$.source_audit_head_hash')
            = seal.source_audit_head_hash
        AND json_type(seal.seal_json, '$.sample_executions') = 'array'
        AND json_array_length(seal.seal_json, '$.sample_executions')
            = seal.sample_execution_count
        AND json_extract(seal.seal_json, '$.sample_execution_count')
            = seal.sample_execution_count
        AND json_extract(
            seal.seal_json,
            '$.sample_execution_inventory_root_sha256'
        ) = seal.sample_execution_inventory_root_sha256
        AND json_extract(seal.seal_json, '$.artifact_link_count')
            = seal.artifact_link_count
        AND json_extract(
            seal.seal_json,
            '$.artifact_link_inventory_root_sha256'
        ) = seal.artifact_link_inventory_root_sha256
        AND json_extract(seal.seal_json, '$.candidate_case_count')
            = seal.candidate_case_count
        AND json_extract(
            seal.seal_json,
            '$.candidate_case_inventory_root_sha256'
        ) = seal.candidate_case_inventory_root_sha256
        AND json_extract(seal.seal_json, '$.ledger_preseal_sequence')
            = seal.ledger_preseal_sequence
        AND json_extract(seal.seal_json, '$.ledger_preseal_hash')
            = seal.ledger_preseal_hash
        AND json_extract(seal.seal_json, '$.ledger_head_sequence')
            = seal.ledger_head_sequence
        AND json_extract(seal.seal_json, '$.ledger_seal_authority_id')
            = seal.ledger_seal_authority_id
        AND NOT EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = seal.run_id
              AND json_extract(
                  seal.seal_json,
                  '$.sample_executions[' || sample.ledger_sequence || ']'
              ) IS NOT json(sample.record_json)
        )
        AND length(CAST(seal.seal_json AS BLOB)) = seal.size_bytes
    ) IS NOT TRUE
);

DROP TABLE m6_upgrade_observation_backed_ledger_preflight;

CREATE TABLE m6_upgrade_execution_ledger_protocols (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    protocol_version TEXT NOT NULL CHECK (protocol_version IN ('v1', 'v2')),
    UNIQUE (run_id, execution_scope_authority_id),
    FOREIGN KEY (run_id, execution_scope_authority_id)
        REFERENCES m6_upgrade_execution_scopes(run_id, execution_scope_authority_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

INSERT INTO m6_upgrade_execution_ledger_protocols(
    run_id, execution_scope_authority_id, protocol_version
)
SELECT
    scope.run_id,
    scope.execution_scope_authority_id,
    CASE
        WHEN EXISTS (
            SELECT 1 FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = scope.run_id
        ) THEN 'v2'
        ELSE 'v1'
    END
FROM m6_upgrade_execution_scopes AS scope;

CREATE TRIGGER m6_upgrade_execution_scopes_default_v1_protocol
AFTER INSERT ON m6_upgrade_execution_scopes
WHEN NOT EXISTS (
    SELECT 1 FROM m6_upgrade_execution_ledger_protocols AS protocol
    WHERE protocol.run_id = NEW.run_id
)
BEGIN
    INSERT INTO m6_upgrade_execution_ledger_protocols(
        run_id, execution_scope_authority_id, protocol_version
    ) VALUES (NEW.run_id, NEW.execution_scope_authority_id, 'v1');
END;

ALTER TABLE m6_upgrade_sample_executions
ADD COLUMN record_schema_version TEXT NOT NULL DEFAULT 'v1'
    CHECK (record_schema_version IN ('v1', 'v2'));

ALTER TABLE m6_upgrade_sample_executions
ADD COLUMN observation_authority_id TEXT
    CHECK (
        observation_authority_id IS NULL
        OR (
            length(observation_authority_id) = 64
            AND observation_authority_id NOT GLOB '*[^0-9a-f]*'
        )
    );

ALTER TABLE m6_upgrade_execution_ledger_seals
ADD COLUMN seal_schema_version TEXT NOT NULL DEFAULT 'v1'
    CHECK (seal_schema_version IN ('v1', 'v2'));

CREATE TABLE m6_upgrade_pending_sample_commitments (
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    ledger_sequence INTEGER NOT NULL CHECK (ledger_sequence >= 0),
    pending_sample_commitment_authority_id TEXT NOT NULL
        CHECK (length(pending_sample_commitment_authority_id) = 64
               AND pending_sample_commitment_authority_id NOT GLOB '*[^0-9a-f]*'),
    command_id TEXT NOT NULL
        CHECK (length(command_id) = 64 AND command_id NOT GLOB '*[^0-9a-f]*'),
    execution_dataset_snapshot_id TEXT NOT NULL
        CHECK (length(execution_dataset_snapshot_id) = 64
               AND execution_dataset_snapshot_id NOT GLOB '*[^0-9a-f]*'),
    execution_entry_id TEXT NOT NULL
        CHECK (length(execution_entry_id) = 64
               AND execution_entry_id NOT GLOB '*[^0-9a-f]*'),
    sample_id TEXT NOT NULL CHECK (length(sample_id) BETWEEN 1 AND 64),
    observation_authority_id TEXT NOT NULL
        CHECK (length(observation_authority_id) = 64
               AND observation_authority_id NOT GLOB '*[^0-9a-f]*'),
    sample_execution_record_id TEXT NOT NULL
        CHECK (length(sample_execution_record_id) = 64
               AND sample_execution_record_id NOT GLOB '*[^0-9a-f]*'),
    sample_execution_record_json TEXT NOT NULL
        CHECK (json_valid(sample_execution_record_json)),
    sample_execution_record_document_sha256 TEXT NOT NULL
        CHECK (length(sample_execution_record_document_sha256) = 64
               AND sample_execution_record_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    sample_execution_record_size_bytes INTEGER NOT NULL
        CHECK (sample_execution_record_size_bytes BETWEEN 1 AND 67108864),
    commitment_json TEXT NOT NULL CHECK (json_valid(commitment_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64
               AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 268435456),
    PRIMARY KEY (run_id, execution_scope_authority_id, ledger_sequence),
    FOREIGN KEY (run_id, execution_scope_authority_id)
        REFERENCES m6_upgrade_execution_scopes(run_id, execution_scope_authority_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (run_id, ledger_sequence)
        REFERENCES m6_upgrade_sample_execution_observations(run_id, ledger_sequence)
        ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX uq_m6_upgrade_sample_execution_observation
    ON m6_upgrade_sample_executions(run_id, observation_authority_id)
    WHERE observation_authority_id IS NOT NULL;

CREATE UNIQUE INDEX uq_m6_upgrade_pending_commitment_authority_id
    ON m6_upgrade_pending_sample_commitments(pending_sample_commitment_authority_id);

CREATE UNIQUE INDEX uq_m6_upgrade_pending_commitment_observation
    ON m6_upgrade_pending_sample_commitments(observation_authority_id);

CREATE UNIQUE INDEX uq_m6_upgrade_pending_commitment_record
    ON m6_upgrade_pending_sample_commitments(sample_execution_record_id);

CREATE TRIGGER m6_upgrade_observations_require_closed_v2_prefix
BEFORE INSERT ON m6_upgrade_sample_execution_observations
WHEN (
    EXISTS (
        SELECT 1
        FROM m6_upgrade_execution_scopes AS scope
        JOIN m6_upgrade_execution_ledger_protocols AS protocol
          ON protocol.run_id = scope.run_id
         AND protocol.execution_scope_authority_id
             = scope.execution_scope_authority_id
        WHERE scope.run_id = NEW.run_id
          AND scope.execution_scope_authority_id = NEW.execution_scope_authority_id
          AND protocol.protocol_version = 'v2'
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
          AND (
              sample.record_schema_version <> 'v2'
              OR sample.observation_authority_id IS NULL
          )
    )
    AND (
        SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments AS commitment
        WHERE commitment.run_id = NEW.run_id
    ) = (
        SELECT COUNT(*) FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
    )
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade observation requires a closed V2 ledger prefix');
END;

CREATE TRIGGER m6_upgrade_observations_require_global_inventory_budget
BEFORE INSERT ON m6_upgrade_sample_execution_observations
WHEN (
    COALESCE((
        SELECT SUM(observation.size_bytes)
        FROM m6_upgrade_sample_execution_observations AS observation
        WHERE observation.run_id = NEW.run_id
    ), 0) + NEW.size_bytes <= 268435456
    AND (
        SELECT COUNT(*)
        FROM m6_upgrade_observed_non_model_artifacts AS artifact
        WHERE artifact.run_id = NEW.run_id
    ) <= 270000
    AND (
        SELECT COUNT(*)
        FROM m6_upgrade_observed_model_calls AS model_call
        WHERE model_call.run_id = NEW.run_id
    ) <= 270000
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade observation inventory budget exceeded');
END;

CREATE TRIGGER m6_upgrade_execution_scopes_require_complete_json
BEFORE INSERT ON m6_upgrade_execution_scopes
WHEN (
    json_type(NEW.scope_json, '$') = 'object'
    AND json_extract(NEW.scope_json, '$.schema_version')
        = 'm6-upgrade-execution-scope-authority-v1'
    AND json_extract(NEW.scope_json, '$.candidate_run_id') = NEW.run_id
    AND json_extract(NEW.scope_json, '$.execution_scope_authority_id')
        = NEW.execution_scope_authority_id
    AND json_extract(NEW.scope_json, '$.command.command_id') = NEW.command_id
    AND json_extract(
        NEW.scope_json,
        '$.execution_dataset.execution_dataset_snapshot_id'
    ) = NEW.execution_dataset_snapshot_id
    AND json_extract(NEW.scope_json, '$.candidate_manifest.manifest_id')
        = NEW.candidate_manifest_id
    AND json_extract(NEW.scope_json, '$.candidate_manifest_content_sha256')
        = NEW.candidate_manifest_document_sha256
    AND json_extract(NEW.scope_json, '$.candidate_config.config_sha256')
        = NEW.candidate_config_sha256
    AND json_extract(
        NEW.scope_json,
        '$.execution_component.component_authority_id'
    ) = NEW.execution_component_authority_id
    AND json_extract(NEW.scope_json, '$.execution_dataset.entry_count')
        = NEW.expected_sample_count
    AND json_extract(NEW.scope_json, '$.execution_start_audit_head_sequence')
        = NEW.execution_start_audit_head_sequence
    AND json_extract(NEW.scope_json, '$.execution_start_audit_head_hash')
        = NEW.execution_start_audit_head_hash
    AND length(CAST(NEW.scope_json AS BLOB)) = NEW.size_bytes
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade execution scope');
END;

CREATE TRIGGER m6_upgrade_physical_artifact_refs_require_complete_json
BEFORE INSERT ON m6_upgrade_physical_artifact_refs
WHEN (
    json_type(NEW.ref_json, '$') = 'object'
    AND json_extract(NEW.ref_json, '$.schema_version')
        = 'm6-upgrade-physical-artifact-ref-v1'
    AND json_extract(NEW.ref_json, '$.artifact_ref_id') = NEW.artifact_ref_id
    AND json_extract(NEW.ref_json, '$.source') = NEW.source
    AND json_extract(NEW.ref_json, '$.kind') = NEW.kind
    AND json_extract(NEW.ref_json, '$.artifact_id') = NEW.artifact_id
    AND json_type(NEW.ref_json, '$.container_id') IS NOT NULL
    AND json_extract(NEW.ref_json, '$.container_id') IS NEW.container_id
    AND json_extract(NEW.ref_json, '$.document_sha256')
        = NEW.artifact_document_sha256
    AND json_extract(NEW.ref_json, '$.content_sha256')
        = NEW.artifact_content_sha256
    AND json_extract(NEW.ref_json, '$.size_bytes') = NEW.artifact_size_bytes
    AND length(CAST(NEW.ref_json AS BLOB)) = NEW.ref_size_bytes
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade physical artifact ref');
END;

CREATE TRIGGER m6_upgrade_sample_artifact_links_require_complete_json
BEFORE INSERT ON m6_upgrade_sample_artifact_links
WHEN (
    json_type(NEW.link_json, '$') = 'object'
    AND json_type(NEW.link_json, '$.artifact') = 'object'
    AND json_extract(NEW.link_json, '$.ordinal') = NEW.ordinal
    AND json_extract(NEW.link_json, '$.usage') = NEW.usage
    AND json_extract(NEW.link_json, '$.artifact.artifact_ref_id')
        = NEW.artifact_ref_id
    AND json_extract(NEW.link_json, '$.artifact_link_id') = NEW.artifact_link_id
    AND EXISTS (
        SELECT 1
        FROM m6_upgrade_physical_artifact_refs AS ref
        WHERE ref.run_id = NEW.run_id
          AND ref.artifact_ref_id = NEW.artifact_ref_id
          AND json_extract(NEW.link_json, '$.artifact') = json(ref.ref_json)
    )
    AND length(CAST(NEW.link_json AS BLOB)) = NEW.link_size_bytes
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade sample artifact link');
END;

CREATE TRIGGER m6_upgrade_pending_sample_commitments_validate
BEFORE INSERT ON m6_upgrade_pending_sample_commitments
WHEN (
    EXISTS (
        SELECT 1
        FROM m6_upgrade_execution_scopes AS scope
        JOIN m6_upgrade_execution_ledger_protocols AS protocol
          ON protocol.run_id = scope.run_id
         AND protocol.execution_scope_authority_id
             = scope.execution_scope_authority_id
        WHERE scope.run_id = NEW.run_id
          AND scope.execution_scope_authority_id = NEW.execution_scope_authority_id
          AND protocol.protocol_version = 'v2'
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
          AND json_extract(
              scope.scope_json,
              '$.execution_dataset.entries[' || NEW.ledger_sequence || ']'
          ) = json_extract(NEW.commitment_json, '$.execution_entry')
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_execution_ledger_seals AS seal
        WHERE seal.run_id = NEW.run_id
    )
    AND NEW.ledger_sequence = (
        SELECT COUNT(*) FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
    )
    AND (
        SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments AS commitment
        WHERE commitment.run_id = NEW.run_id
    ) = (
        SELECT COUNT(*) FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
    )
    AND (
        SELECT COUNT(*) FROM m6_upgrade_sample_execution_observations AS observation
        WHERE observation.run_id = NEW.run_id
    ) = (
        SELECT COUNT(*) + 1 FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
    )
    AND COALESCE((
        SELECT SUM(observation.size_bytes)
        FROM m6_upgrade_sample_execution_observations AS observation
        WHERE observation.run_id = NEW.run_id
    ), 0) <= 268435456
    AND (
        SELECT COUNT(*)
        FROM m6_upgrade_observed_non_model_artifacts AS artifact
        WHERE artifact.run_id = NEW.run_id
    ) <= 270000
    AND (
        SELECT COUNT(*)
        FROM m6_upgrade_observed_model_calls AS call
        WHERE call.run_id = NEW.run_id
    ) <= 270000
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
          AND (
              sample.record_schema_version <> 'v2'
              OR sample.observation_authority_id IS NULL
          )
    )
    AND EXISTS (
        SELECT 1 FROM m6_upgrade_sample_execution_observations AS observation
        WHERE observation.run_id = NEW.run_id
          AND observation.execution_scope_authority_id = NEW.execution_scope_authority_id
          AND observation.ledger_sequence = NEW.ledger_sequence
          AND observation.observation_authority_id = NEW.observation_authority_id
          AND observation.command_id = NEW.command_id
          AND observation.execution_dataset_snapshot_id = NEW.execution_dataset_snapshot_id
          AND observation.execution_entry_id = NEW.execution_entry_id
          AND observation.sample_id = NEW.sample_id
          AND observation.outcome = json_extract(
              NEW.sample_execution_record_json,
              '$.outcome'
          )
          AND observation.case_id IS json_extract(
              NEW.sample_execution_record_json,
              '$.candidate_case.case_id'
          )
          AND observation.case_revision IS json_extract(
              NEW.sample_execution_record_json,
              '$.candidate_case.case_revision'
          )
          AND observation.case_document_sha256 IS json_extract(
              NEW.sample_execution_record_json,
              '$.candidate_case.case_document_sha256'
          )
          AND observation.case_audit_sequence IS json_extract(
              NEW.sample_execution_record_json,
              '$.candidate_case.case_audit_sequence'
          )
          AND observation.case_audit_entry_hash IS json_extract(
              NEW.sample_execution_record_json,
              '$.candidate_case.case_audit_entry_hash'
          )
    )
    AND (
        (NEW.ledger_sequence = 0
         AND json_extract(
             NEW.sample_execution_record_json,
             '$.previous_ledger_entry_hash'
         ) = '0000000000000000000000000000000000000000000000000000000000000000')
        OR
        (NEW.ledger_sequence > 0 AND EXISTS (
            SELECT 1 FROM m6_upgrade_sample_executions AS prior
            WHERE prior.run_id = NEW.run_id
              AND prior.ledger_sequence = NEW.ledger_sequence - 1
              AND prior.record_schema_version = 'v2'
              AND prior.sample_execution_record_id = json_extract(
                  NEW.sample_execution_record_json,
                  '$.previous_ledger_entry_hash'
              )
        ))
    )
    AND json_type(NEW.sample_execution_record_json, '$.artifact_links') = 'array'
    AND json_array_length(NEW.sample_execution_record_json, '$.artifact_links')
        BETWEEN 1 AND 20000
    AND json_extract(NEW.sample_execution_record_json, '$.artifact_link_count')
        = json_array_length(NEW.sample_execution_record_json, '$.artifact_links')
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE json_type(candidate.value, '$.ordinal') IS NOT 'integer'
           OR json_extract(candidate.value, '$.ordinal')
               IS NOT CAST(candidate.key AS INTEGER)
           OR json_type(candidate.value, '$.usage') IS NOT 'text'
           OR json_extract(candidate.value, '$.usage') NOT IN ('CONSUMED', 'PRODUCED')
           OR json_type(candidate.value, '$.artifact_link_id') IS NOT 'text'
           OR length(json_extract(candidate.value, '$.artifact_link_id')) <> 64
           OR json_extract(candidate.value, '$.artifact_link_id') GLOB '*[^0-9a-f]*'
           OR json_type(candidate.value, '$.artifact') IS NOT 'object'
           OR json_extract(candidate.value, '$.artifact.schema_version')
               IS NOT 'm6-upgrade-physical-artifact-ref-v1'
           OR json_type(
               candidate.value,
               '$.artifact.artifact_ref_id'
           ) IS NOT 'text'
           OR length(json_extract(candidate.value, '$.artifact.artifact_ref_id')) <> 64
           OR json_extract(
               candidate.value,
               '$.artifact.artifact_ref_id'
           ) GLOB '*[^0-9a-f]*'
           OR json_type(candidate.value, '$.artifact.source') IS NOT 'text'
           OR json_extract(candidate.value, '$.artifact.source') NOT IN (
               'M2_PERCEPTION', 'M2_EVIDENCE', 'M3_SCREENING_MODEL',
               'M4_HEARING_MODEL', 'M4_ACQUISITION', 'M5_PRECEDENT'
           )
           OR json_type(candidate.value, '$.artifact.kind') IS NOT 'text'
           OR json_extract(candidate.value, '$.artifact.kind') NOT IN (
               'FRAME', 'DETECTION', 'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
               'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT', 'MODEL_CALL_FAILURE',
               'MODEL_USAGE_RECEIPT', 'EMBEDDING', 'PRECEDENT_EXPOSURE',
               'TOOL_EXECUTION_MANIFEST', 'TOOL_RESULT', 'EVIDENCE_PACK'
           )
           OR json_type(candidate.value, '$.artifact.artifact_id') IS NOT 'text'
           OR length(json_extract(candidate.value, '$.artifact.artifact_id'))
               NOT BETWEEN 1 AND 192
           OR (
               json_type(candidate.value, '$.artifact.container_id') IS NOT 'null'
               AND json_type(
                   candidate.value,
                   '$.artifact.container_id'
               ) IS NOT 'text'
           )
           OR (
               json_extract(candidate.value, '$.artifact.container_id') IS NOT NULL
               AND length(json_extract(candidate.value, '$.artifact.container_id'))
                   NOT BETWEEN 1 AND 192
           )
           OR json_type(
               candidate.value,
               '$.artifact.document_sha256'
           ) IS NOT 'text'
           OR length(json_extract(candidate.value, '$.artifact.document_sha256')) <> 64
           OR json_extract(
               candidate.value,
               '$.artifact.document_sha256'
           ) GLOB '*[^0-9a-f]*'
           OR json_type(
               candidate.value,
               '$.artifact.content_sha256'
           ) IS NOT 'text'
           OR length(json_extract(candidate.value, '$.artifact.content_sha256')) <> 64
           OR json_extract(
               candidate.value,
               '$.artifact.content_sha256'
           ) GLOB '*[^0-9a-f]*'
           OR json_type(candidate.value, '$.artifact.size_bytes') IS NOT 'integer'
           OR json_extract(candidate.value, '$.artifact.size_bytes') NOT BETWEEN 1 AND 4294967296
           OR NOT (
               (
                   json_extract(candidate.value, '$.artifact.source') = 'M2_PERCEPTION'
                   AND json_extract(candidate.value, '$.artifact.kind')
                       IN ('FRAME', 'DETECTION')
               )
               OR (
                   json_extract(candidate.value, '$.artifact.source') = 'M2_EVIDENCE'
                   AND json_extract(candidate.value, '$.artifact.kind') = 'EVIDENCE_PACK'
               )
               OR (
                   json_extract(candidate.value, '$.artifact.source')
                       IN ('M3_SCREENING_MODEL', 'M4_HEARING_MODEL')
                   AND json_extract(candidate.value, '$.artifact.kind') IN (
                       'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
                       'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT',
                       'MODEL_CALL_FAILURE', 'MODEL_USAGE_RECEIPT'
                   )
               )
               OR (
                   json_extract(candidate.value, '$.artifact.source') = 'M4_ACQUISITION'
                   AND json_extract(candidate.value, '$.artifact.kind')
                       IN ('TOOL_EXECUTION_MANIFEST', 'TOOL_RESULT')
               )
               OR (
                   json_extract(candidate.value, '$.artifact.source') = 'M5_PRECEDENT'
                   AND json_extract(candidate.value, '$.artifact.kind')
                       IN ('EMBEDDING', 'PRECEDENT_EXPOSURE')
               )
           )
           OR NOT (
               (
                   json_extract(candidate.value, '$.artifact.kind') = 'DETECTION'
                   AND json_extract(candidate.value, '$.artifact.container_id') IS NOT NULL
               )
               OR (
                   json_extract(candidate.value, '$.artifact.kind') <> 'DETECTION'
                   AND json_extract(candidate.value, '$.artifact.container_id') IS NULL
               )
           )
           OR NOT (
               (
                   json_extract(candidate.value, '$.artifact.kind') = 'FRAME'
                   AND json_extract(candidate.value, '$.usage') = 'CONSUMED'
               )
               OR json_extract(candidate.value, '$.artifact.kind')
                   IN ('MODEL_CACHE', 'EMBEDDING')
               OR (
                   json_extract(candidate.value, '$.artifact.kind')
                       NOT IN ('FRAME', 'MODEL_CACHE', 'EMBEDDING')
                   AND json_extract(candidate.value, '$.usage') = 'PRODUCED'
               )
           )
           OR (
               json_extract(candidate.value, '$.artifact.kind')
                   NOT IN ('FRAME', 'MODEL_RESPONSE')
               AND json_extract(candidate.value, '$.artifact.content_sha256')
                   IS NOT json_extract(candidate.value, '$.artifact.document_sha256')
           )
    )
    AND COALESCE((
        SELECT SUM(json_extract(candidate.value, '$.artifact.size_bytes'))
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
    ), 0) <= 268435456
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        GROUP BY json_extract(candidate.value, '$.artifact.artifact_ref_id')
        HAVING COUNT(*) > 1
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        GROUP BY
            json_extract(candidate.value, '$.artifact.source'),
            json_extract(candidate.value, '$.artifact.kind'),
            ifnull(json_extract(candidate.value, '$.artifact.container_id'), ''),
            json_extract(candidate.value, '$.artifact.artifact_id')
        HAVING COUNT(*) > 1
    )
    AND NOT EXISTS (
        SELECT json_extract(
            detection.value,
            '$.artifact.container_id'
        )
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS detection
        WHERE json_extract(detection.value, '$.artifact.kind') = 'DETECTION'

        EXCEPT

        SELECT json_extract(frame.value, '$.artifact.artifact_id')
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS frame
        WHERE json_extract(frame.value, '$.artifact.kind') = 'FRAME'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM (
            SELECT
                ranked.ordinal,
                ranked.source_rank,
                ranked.kind_rank,
                ranked.container_id,
                ranked.artifact_id,
                LAG(ranked.source_rank) OVER (ORDER BY ranked.ordinal) AS prior_source_rank,
                LAG(ranked.kind_rank) OVER (ORDER BY ranked.ordinal) AS prior_kind_rank,
                LAG(ranked.container_id) OVER (ORDER BY ranked.ordinal) AS prior_container_id,
                LAG(ranked.artifact_id) OVER (ORDER BY ranked.ordinal) AS prior_artifact_id
            FROM (
                SELECT
                    CAST(candidate.key AS INTEGER) AS ordinal,
                    CASE json_extract(candidate.value, '$.artifact.source')
                        WHEN 'M2_PERCEPTION' THEN 0
                        WHEN 'M2_EVIDENCE' THEN 1
                        WHEN 'M3_SCREENING_MODEL' THEN 2
                        WHEN 'M4_HEARING_MODEL' THEN 3
                        WHEN 'M4_ACQUISITION' THEN 4
                        WHEN 'M5_PRECEDENT' THEN 5
                    END AS source_rank,
                    CASE json_extract(candidate.value, '$.artifact.kind')
                        WHEN 'FRAME' THEN 0
                        WHEN 'DETECTION' THEN 1
                        WHEN 'MODEL_REQUEST' THEN 2
                        WHEN 'MODEL_RESPONSE' THEN 3
                        WHEN 'MODEL_CACHE' THEN 4
                        WHEN 'MODEL_PARSE_RECEIPT' THEN 5
                        WHEN 'MODEL_PARSED_OUTPUT' THEN 6
                        WHEN 'MODEL_CALL_FAILURE' THEN 7
                        WHEN 'MODEL_USAGE_RECEIPT' THEN 8
                        WHEN 'EMBEDDING' THEN 9
                        WHEN 'PRECEDENT_EXPOSURE' THEN 10
                        WHEN 'TOOL_EXECUTION_MANIFEST' THEN 11
                        WHEN 'TOOL_RESULT' THEN 12
                        WHEN 'EVIDENCE_PACK' THEN 13
                    END AS kind_rank,
                    ifnull(
                        json_extract(candidate.value, '$.artifact.container_id'),
                        ''
                    ) AS container_id,
                    json_extract(candidate.value, '$.artifact.artifact_id') AS artifact_id
                FROM json_each(
                    NEW.sample_execution_record_json,
                    '$.artifact_links'
                ) AS candidate
            ) AS ranked
        ) AS ordered
        WHERE ordered.ordinal > 0
          AND (
              ordered.source_rank,
              ordered.kind_rank,
              ordered.container_id,
              ordered.artifact_id
          ) < (
              ordered.prior_source_rank,
              ordered.prior_kind_rank,
              ordered.prior_container_id,
              ordered.prior_artifact_id
          )
    )
    AND COALESCE((
        SELECT SUM(sample.artifact_link_count)
        FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
    ), 0) + json_array_length(
        NEW.sample_execution_record_json,
        '$.artifact_links'
    ) <= 250000
    AND (
        (
            json_extract(NEW.sample_execution_record_json, '$.outcome') = 'NO_CASE'
            AND json_type(
                NEW.sample_execution_record_json,
                '$.candidate_case'
            ) = 'null'
        )
        OR (
            json_extract(
                NEW.sample_execution_record_json,
                '$.outcome'
            ) = 'CASE_REPLAYED'
            AND json_type(
                NEW.sample_execution_record_json,
                '$.candidate_case'
            ) = 'object'
            AND json_type(
                NEW.sample_execution_record_json,
                '$.candidate_case.case_id'
            ) = 'text'
            AND NOT EXISTS (
                SELECT 1 FROM m6_upgrade_sample_executions AS sample
                WHERE sample.run_id = NEW.run_id
                  AND sample.case_id = json_extract(
                      NEW.sample_execution_record_json,
                      '$.candidate_case.case_id'
                  )
            )
        )
    )
    AND NOT (
        json_type(NEW.sample_execution_record_json, '$.candidate_case') = 'null'
        AND EXISTS (
            SELECT 1
            FROM json_each(
                NEW.sample_execution_record_json,
                '$.artifact_links'
            ) AS candidate
            WHERE json_extract(candidate.value, '$.artifact.kind')
                NOT IN ('FRAME', 'DETECTION')
        )
    )
    AND (
        SELECT COUNT(*)
        FROM m6_upgrade_observed_non_model_artifacts AS observed
        WHERE observed.run_id = NEW.run_id
          AND observed.observation_authority_id = NEW.observation_authority_id
    ) = (
        SELECT COUNT(*)
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE json_extract(candidate.value, '$.artifact.kind') NOT IN (
            'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
            'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT',
            'MODEL_CALL_FAILURE', 'MODEL_USAGE_RECEIPT'
        )
    )
    AND NOT EXISTS (
        SELECT observed.source, observed.kind, observed.artifact_id, observed.usage
        FROM m6_upgrade_observed_non_model_artifacts AS observed
        WHERE observed.run_id = NEW.run_id
          AND observed.observation_authority_id = NEW.observation_authority_id

        EXCEPT

        SELECT
            json_extract(candidate.value, '$.artifact.source'),
            json_extract(candidate.value, '$.artifact.kind'),
            json_extract(candidate.value, '$.artifact.artifact_id'),
            json_extract(candidate.value, '$.usage')
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE json_extract(candidate.value, '$.artifact.kind') NOT IN (
            'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
            'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT',
            'MODEL_CALL_FAILURE', 'MODEL_USAGE_RECEIPT'
        )
    )
    AND NOT EXISTS (
        SELECT
            json_extract(candidate.value, '$.artifact.source'),
            json_extract(candidate.value, '$.artifact.kind'),
            json_extract(candidate.value, '$.artifact.artifact_id'),
            json_extract(candidate.value, '$.usage')
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE json_extract(candidate.value, '$.artifact.kind') NOT IN (
            'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
            'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT',
            'MODEL_CALL_FAILURE', 'MODEL_USAGE_RECEIPT'
        )

        EXCEPT

        SELECT observed.source, observed.kind, observed.artifact_id, observed.usage
        FROM m6_upgrade_observed_non_model_artifacts AS observed
        WHERE observed.run_id = NEW.run_id
          AND observed.observation_authority_id = NEW.observation_authority_id
    )
    AND (
        SELECT COUNT(*)
        FROM m6_upgrade_observed_model_calls AS observed
        WHERE observed.run_id = NEW.run_id
          AND observed.observation_authority_id = NEW.observation_authority_id
    ) = (
        SELECT COUNT(*)
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE json_extract(candidate.value, '$.artifact.kind') = 'MODEL_REQUEST'
    )
    AND NOT EXISTS (
        SELECT
            CASE observed.layer
                WHEN 'SCREENING' THEN 'M3_SCREENING_MODEL'
                WHEN 'HEARING' THEN 'M4_HEARING_MODEL'
            END,
            observed.request_id
        FROM m6_upgrade_observed_model_calls AS observed
        WHERE observed.run_id = NEW.run_id
          AND observed.observation_authority_id = NEW.observation_authority_id

        EXCEPT

        SELECT
            json_extract(candidate.value, '$.artifact.source'),
            json_extract(candidate.value, '$.artifact.artifact_id')
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE json_extract(candidate.value, '$.artifact.kind') = 'MODEL_REQUEST'
    )
    AND NOT EXISTS (
        SELECT
            json_extract(candidate.value, '$.artifact.source'),
            json_extract(candidate.value, '$.artifact.artifact_id')
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE json_extract(candidate.value, '$.artifact.kind') = 'MODEL_REQUEST'

        EXCEPT

        SELECT
            CASE observed.layer
                WHEN 'SCREENING' THEN 'M3_SCREENING_MODEL'
                WHEN 'HEARING' THEN 'M4_HEARING_MODEL'
            END,
            observed.request_id
        FROM m6_upgrade_observed_model_calls AS observed
        WHERE observed.run_id = NEW.run_id
          AND observed.observation_authority_id = NEW.observation_authority_id
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE EXISTS (
            SELECT 1
            FROM m6_upgrade_physical_artifact_refs AS ref
            WHERE ref.run_id = NEW.run_id
              AND ref.artifact_ref_id = json_extract(
                  candidate.value,
                  '$.artifact.artifact_ref_id'
              )
              AND json(ref.ref_json) IS NOT json_extract(candidate.value, '$.artifact')
        )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM json_each(
            NEW.sample_execution_record_json,
            '$.artifact_links'
        ) AS candidate
        WHERE EXISTS (
            SELECT 1
            FROM m6_upgrade_physical_artifact_refs AS ref
            WHERE ref.run_id = NEW.run_id
              AND ref.source = json_extract(candidate.value, '$.artifact.source')
              AND ref.kind = json_extract(candidate.value, '$.artifact.kind')
              AND ifnull(ref.container_id, '') = ifnull(
                  json_extract(candidate.value, '$.artifact.container_id'),
                  ''
              )
              AND ref.artifact_id = json_extract(
                  candidate.value,
                  '$.artifact.artifact_id'
              )
              AND json(ref.ref_json) IS NOT json_extract(candidate.value, '$.artifact')
        )
    )
    AND (
        SELECT scope.size_bytes + COALESCE((
            SELECT SUM(sample.record_size_bytes)
            FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
        ), 0) + NEW.sample_execution_record_size_bytes
        FROM m6_upgrade_execution_scopes AS scope
        WHERE scope.run_id = NEW.run_id
          AND scope.execution_scope_authority_id = NEW.execution_scope_authority_id
    ) <= 268435456
    AND COALESCE((
        SELECT SUM(commitment.size_bytes)
        FROM m6_upgrade_pending_sample_commitments AS commitment
        WHERE commitment.run_id = NEW.run_id
    ), 0) + NEW.size_bytes <= 268435456
    AND COALESCE((
        SELECT SUM(commitment.sample_execution_record_size_bytes)
        FROM m6_upgrade_pending_sample_commitments AS commitment
        WHERE commitment.run_id = NEW.run_id
    ), 0) + NEW.sample_execution_record_size_bytes <= 268435456
    AND json_extract(NEW.commitment_json, '$.schema_version')
        = 'm6-upgrade-pending-sample-commitment-authority-v1'
    AND json_extract(NEW.commitment_json, '$.execution_scope_authority_id')
        = NEW.execution_scope_authority_id
    AND json_extract(NEW.commitment_json, '$.candidate_run_id') = NEW.run_id
    AND json_extract(NEW.commitment_json, '$.command_id') = NEW.command_id
    AND json_extract(NEW.commitment_json, '$.execution_dataset_snapshot_id')
        = NEW.execution_dataset_snapshot_id
    AND json_extract(NEW.commitment_json, '$.execution_entry.execution_entry_id')
        = NEW.execution_entry_id
    AND json_extract(NEW.commitment_json, '$.execution_entry.sample_id') = NEW.sample_id
    AND json_extract(NEW.commitment_json, '$.ledger_sequence') = NEW.ledger_sequence
    AND json_extract(NEW.commitment_json, '$.observation_authority_id')
        = NEW.observation_authority_id
    AND json_extract(NEW.commitment_json, '$.sample_id') = NEW.sample_id
    AND json_extract(NEW.commitment_json, '$.execution_entry_id') = NEW.execution_entry_id
    AND json_extract(NEW.commitment_json, '$.sample_execution_record_id')
        = NEW.sample_execution_record_id
    AND json_extract(
        NEW.commitment_json,
        '$.sample_execution_record_document_sha256'
    ) = NEW.sample_execution_record_document_sha256
    AND json_extract(NEW.commitment_json, '$.sample_execution_record_size_bytes')
        = NEW.sample_execution_record_size_bytes
    AND json_extract(
        NEW.commitment_json,
        '$.pending_sample_commitment_authority_id'
    ) = NEW.pending_sample_commitment_authority_id
    AND json_extract(NEW.commitment_json, '$.sample_execution_record')
        = NEW.sample_execution_record_json
    AND json_extract(NEW.commitment_json, '$.execution_entry')
        = json_extract(NEW.sample_execution_record_json, '$.execution_entry')
    AND json_extract(NEW.sample_execution_record_json, '$.schema_version')
        = 'm6-upgrade-sample-execution-record-v2'
    AND json_extract(
        NEW.sample_execution_record_json,
        '$.execution_scope_authority_id'
    ) = NEW.execution_scope_authority_id
    AND json_extract(NEW.sample_execution_record_json, '$.candidate_run_id') = NEW.run_id
    AND json_extract(NEW.sample_execution_record_json, '$.command_id') = NEW.command_id
    AND json_extract(
        NEW.sample_execution_record_json,
        '$.execution_dataset_snapshot_id'
    ) = NEW.execution_dataset_snapshot_id
    AND json_extract(NEW.sample_execution_record_json, '$.execution_entry_id')
        = NEW.execution_entry_id
    AND json_extract(NEW.sample_execution_record_json, '$.sample_id') = NEW.sample_id
    AND json_extract(NEW.sample_execution_record_json, '$.ledger_sequence')
        = NEW.ledger_sequence
    AND json_extract(NEW.sample_execution_record_json, '$.observation_authority_id')
        = NEW.observation_authority_id
    AND json_extract(NEW.sample_execution_record_json, '$.sample_execution_record_id')
        = NEW.sample_execution_record_id
    AND length(CAST(NEW.sample_execution_record_json AS BLOB))
        = NEW.sample_execution_record_size_bytes
    AND length(CAST(NEW.commitment_json AS BLOB)) = NEW.size_bytes
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade pending sample commitment');
END;

CREATE TRIGGER m6_upgrade_sample_executions_validate_observation_backing
BEFORE INSERT ON m6_upgrade_sample_executions
WHEN (
    (
    (
        NEW.record_schema_version = 'v1'
        AND NEW.observation_authority_id IS NULL
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_execution_scopes AS scope
            JOIN m6_upgrade_execution_ledger_protocols AS protocol
              ON protocol.run_id = scope.run_id
             AND protocol.execution_scope_authority_id
                 = scope.execution_scope_authority_id
            WHERE scope.run_id = NEW.run_id
              AND scope.execution_scope_authority_id
                  = NEW.execution_scope_authority_id
              AND protocol.protocol_version = 'v1'
        )
        AND json_extract(NEW.record_json, '$.schema_version')
            = 'm6-upgrade-sample-execution-record-v1'
        AND json_array_length(NEW.record_json, '$.artifact_links')
            = NEW.artifact_link_count
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_artifact_links AS link
            WHERE link.run_id = NEW.run_id
              AND link.execution_entry_id = NEW.execution_entry_id
              AND (
                  link.ordinal >= NEW.artifact_link_count
                  OR json(link.link_json) IS NOT json_extract(
                      NEW.record_json,
                      '$.artifact_links[' || link.ordinal || ']'
                  )
              )
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = NEW.run_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_pending_sample_commitments AS commitment
            WHERE commitment.run_id = NEW.run_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
              AND (
                  sample.record_schema_version <> 'v1'
                  OR sample.observation_authority_id IS NOT NULL
              )
        )
    )
    OR
    (
        NEW.record_schema_version = 'v2'
        AND NEW.observation_authority_id IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_execution_scopes AS scope
            JOIN m6_upgrade_execution_ledger_protocols AS protocol
              ON protocol.run_id = scope.run_id
             AND protocol.execution_scope_authority_id
                 = scope.execution_scope_authority_id
            WHERE scope.run_id = NEW.run_id
              AND scope.execution_scope_authority_id
                  = NEW.execution_scope_authority_id
              AND protocol.protocol_version = 'v2'
        )
        AND json_extract(NEW.record_json, '$.schema_version')
            = 'm6-upgrade-sample-execution-record-v2'
        AND json_extract(NEW.record_json, '$.observation_authority_id')
            = NEW.observation_authority_id
        AND json_array_length(NEW.record_json, '$.artifact_links')
            = NEW.artifact_link_count
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_artifact_links AS link
            WHERE link.run_id = NEW.run_id
              AND link.execution_entry_id = NEW.execution_entry_id
              AND (
                  link.ordinal >= NEW.artifact_link_count
                  OR json(link.link_json) IS NOT json_extract(
                      NEW.record_json,
                      '$.artifact_links[' || link.ordinal || ']'
                  )
              )
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
              AND (
                  sample.record_schema_version <> 'v2'
                  OR sample.observation_authority_id IS NULL
              )
        )
        AND (
            SELECT COUNT(*) FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = NEW.run_id
        ) = (
            SELECT COUNT(*) + 1 FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
        )
        AND (
            SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments AS commitment
            WHERE commitment.run_id = NEW.run_id
        ) = (
            SELECT COUNT(*) + 1 FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
        )
        AND EXISTS (
            SELECT 1 FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = NEW.run_id
              AND observation.execution_scope_authority_id
                  = NEW.execution_scope_authority_id
              AND observation.ledger_sequence = NEW.ledger_sequence
              AND observation.observation_authority_id = NEW.observation_authority_id
              AND observation.command_id = NEW.command_id
              AND observation.execution_dataset_snapshot_id
                  = NEW.execution_dataset_snapshot_id
              AND observation.execution_entry_id = NEW.execution_entry_id
              AND observation.sample_id = NEW.sample_id
              AND observation.outcome = NEW.outcome
              AND observation.case_id IS NEW.case_id
              AND observation.case_revision IS NEW.case_revision
              AND observation.case_document_sha256 IS NEW.case_document_sha256
              AND observation.case_audit_sequence IS NEW.case_audit_sequence
              AND observation.case_audit_entry_hash IS NEW.case_audit_entry_hash
        )
        AND EXISTS (
            SELECT 1 FROM m6_upgrade_pending_sample_commitments AS commitment
            WHERE commitment.run_id = NEW.run_id
              AND commitment.execution_scope_authority_id
                  = NEW.execution_scope_authority_id
              AND commitment.ledger_sequence = NEW.ledger_sequence
              AND commitment.command_id = NEW.command_id
              AND commitment.execution_dataset_snapshot_id
                  = NEW.execution_dataset_snapshot_id
              AND commitment.execution_entry_id = NEW.execution_entry_id
              AND commitment.sample_id = NEW.sample_id
              AND commitment.observation_authority_id = NEW.observation_authority_id
              AND commitment.sample_execution_record_id
                  = NEW.sample_execution_record_id
              AND commitment.sample_execution_record_json = NEW.record_json
              AND commitment.sample_execution_record_document_sha256
                  = NEW.record_document_sha256
              AND commitment.sample_execution_record_size_bytes = NEW.record_size_bytes
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_observed_non_model_artifacts AS observed
            WHERE observed.run_id = NEW.run_id
              AND observed.observation_authority_id = NEW.observation_authority_id
              AND NOT EXISTS (
                  SELECT 1
                  FROM m6_upgrade_sample_artifact_links AS link
                  JOIN m6_upgrade_physical_artifact_refs AS ref
                    ON ref.run_id = link.run_id
                   AND ref.artifact_ref_id = link.artifact_ref_id
                  WHERE link.run_id = NEW.run_id
                    AND link.execution_entry_id = NEW.execution_entry_id
                    AND ref.source = observed.source
                    AND ref.kind = observed.kind
                    AND ref.artifact_id = observed.artifact_id
                    AND link.usage = observed.usage
              )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_artifact_links AS link
            JOIN m6_upgrade_physical_artifact_refs AS ref
              ON ref.run_id = link.run_id
             AND ref.artifact_ref_id = link.artifact_ref_id
            WHERE link.run_id = NEW.run_id
              AND link.execution_entry_id = NEW.execution_entry_id
              AND ref.kind NOT IN (
                  'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
                  'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT',
                  'MODEL_CALL_FAILURE', 'MODEL_USAGE_RECEIPT'
              )
              AND NOT EXISTS (
                  SELECT 1 FROM m6_upgrade_observed_non_model_artifacts AS observed
                  WHERE observed.run_id = NEW.run_id
                    AND observed.observation_authority_id
                        = NEW.observation_authority_id
                    AND observed.source = ref.source
                    AND observed.kind = ref.kind
                    AND observed.artifact_id = ref.artifact_id
                    AND observed.usage = link.usage
              )
        )
        AND (
            SELECT COUNT(*)
            FROM m6_upgrade_sample_artifact_links AS link
            JOIN m6_upgrade_physical_artifact_refs AS ref
              ON ref.run_id = link.run_id
             AND ref.artifact_ref_id = link.artifact_ref_id
            WHERE link.run_id = NEW.run_id
              AND link.execution_entry_id = NEW.execution_entry_id
              AND ref.kind NOT IN (
                  'MODEL_REQUEST', 'MODEL_RESPONSE', 'MODEL_CACHE',
                  'MODEL_PARSE_RECEIPT', 'MODEL_PARSED_OUTPUT',
                  'MODEL_CALL_FAILURE', 'MODEL_USAGE_RECEIPT'
              )
        ) = (
            SELECT COUNT(*)
            FROM m6_upgrade_observed_non_model_artifacts AS observed
            WHERE observed.run_id = NEW.run_id
              AND observed.observation_authority_id
                  = NEW.observation_authority_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_observed_model_calls AS observed
            WHERE observed.run_id = NEW.run_id
              AND observed.observation_authority_id = NEW.observation_authority_id
              AND NOT EXISTS (
                  SELECT 1
                  FROM m6_upgrade_sample_artifact_links AS link
                  JOIN m6_upgrade_physical_artifact_refs AS ref
                    ON ref.run_id = link.run_id
                   AND ref.artifact_ref_id = link.artifact_ref_id
                  WHERE link.run_id = NEW.run_id
                    AND link.execution_entry_id = NEW.execution_entry_id
                    AND ref.kind = 'MODEL_REQUEST'
                    AND ref.artifact_id = observed.request_id
                    AND (
                        (observed.layer = 'SCREENING'
                         AND ref.source = 'M3_SCREENING_MODEL')
                        OR
                        (observed.layer = 'HEARING'
                         AND ref.source = 'M4_HEARING_MODEL')
                    )
              )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_artifact_links AS link
            JOIN m6_upgrade_physical_artifact_refs AS ref
              ON ref.run_id = link.run_id
             AND ref.artifact_ref_id = link.artifact_ref_id
            WHERE link.run_id = NEW.run_id
              AND link.execution_entry_id = NEW.execution_entry_id
              AND ref.kind = 'MODEL_REQUEST'
              AND NOT EXISTS (
                  SELECT 1 FROM m6_upgrade_observed_model_calls AS observed
                  WHERE observed.run_id = NEW.run_id
                    AND observed.observation_authority_id
                        = NEW.observation_authority_id
                    AND observed.request_id = ref.artifact_id
                    AND (
                        (observed.layer = 'SCREENING'
                         AND ref.source = 'M3_SCREENING_MODEL')
                        OR
                        (observed.layer = 'HEARING'
                         AND ref.source = 'M4_HEARING_MODEL')
                    )
              )
        )
        AND (
            SELECT COALESCE(SUM(ref.artifact_size_bytes), 0)
            FROM m6_upgrade_sample_artifact_links AS link
            JOIN m6_upgrade_physical_artifact_refs AS ref
              ON ref.run_id = link.run_id
             AND ref.artifact_ref_id = link.artifact_ref_id
            WHERE link.run_id = NEW.run_id
              AND link.execution_entry_id = NEW.execution_entry_id
        ) <= 268435456
    )
    )
    AND json_type(NEW.record_json, '$') = 'object'
    AND json_extract(NEW.record_json, '$.execution_scope_authority_id')
        = NEW.execution_scope_authority_id
    AND json_extract(NEW.record_json, '$.candidate_run_id') = NEW.run_id
    AND json_extract(NEW.record_json, '$.command_id') = NEW.command_id
    AND json_extract(NEW.record_json, '$.execution_dataset_snapshot_id')
        = NEW.execution_dataset_snapshot_id
    AND json_extract(NEW.record_json, '$.ledger_sequence') = NEW.ledger_sequence
    AND json_extract(NEW.record_json, '$.previous_ledger_entry_hash')
        = NEW.previous_ledger_entry_hash
    AND json_extract(NEW.record_json, '$.execution_entry_id')
        = NEW.execution_entry_id
    AND json_extract(NEW.record_json, '$.sample_id') = NEW.sample_id
    AND json_extract(NEW.record_json, '$.outcome') = NEW.outcome
    AND json_type(NEW.record_json, '$.candidate_case') IN ('object', 'null')
    AND json_extract(NEW.record_json, '$.candidate_case.case_id') IS NEW.case_id
    AND json_extract(NEW.record_json, '$.candidate_case.case_revision')
        IS NEW.case_revision
    AND json_extract(NEW.record_json, '$.candidate_case.case_document_sha256')
        IS NEW.case_document_sha256
    AND json_extract(NEW.record_json, '$.candidate_case.case_audit_sequence')
        IS NEW.case_audit_sequence
    AND json_extract(NEW.record_json, '$.candidate_case.case_audit_entry_hash')
        IS NEW.case_audit_entry_hash
    AND json_extract(NEW.record_json, '$.artifact_link_count')
        = NEW.artifact_link_count
    AND json_extract(NEW.record_json, '$.artifact_link_inventory_root_sha256')
        = NEW.artifact_link_inventory_root_sha256
    AND json_extract(NEW.record_json, '$.sample_execution_record_id')
        = NEW.sample_execution_record_id
    AND length(CAST(NEW.record_json AS BLOB)) = NEW.record_size_bytes
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 observation-backed sample execution');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_seals_validate_schema_version
BEFORE INSERT ON m6_upgrade_execution_ledger_seals
WHEN (
    (
    (
        NEW.seal_schema_version = 'v1'
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_execution_scopes AS scope
            JOIN m6_upgrade_execution_ledger_protocols AS protocol
              ON protocol.run_id = scope.run_id
             AND protocol.execution_scope_authority_id
                 = scope.execution_scope_authority_id
            WHERE scope.run_id = NEW.run_id
              AND scope.execution_scope_authority_id
                  = NEW.execution_scope_authority_id
              AND protocol.protocol_version = 'v1'
        )
        AND json_extract(NEW.seal_json, '$.schema_version')
            = 'm6-upgrade-execution-ledger-seal-v1'
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
              AND (
                  sample.record_schema_version <> 'v1'
                  OR sample.observation_authority_id IS NOT NULL
              )
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = NEW.run_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_pending_sample_commitments AS commitment
            WHERE commitment.run_id = NEW.run_id
        )
    )
    OR
    (
        NEW.seal_schema_version = 'v2'
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_execution_scopes AS scope
            JOIN m6_upgrade_execution_ledger_protocols AS protocol
              ON protocol.run_id = scope.run_id
             AND protocol.execution_scope_authority_id
                 = scope.execution_scope_authority_id
            WHERE scope.run_id = NEW.run_id
              AND scope.execution_scope_authority_id
                  = NEW.execution_scope_authority_id
              AND protocol.protocol_version = 'v2'
        )
        AND json_extract(NEW.seal_json, '$.schema_version')
            = 'm6-upgrade-execution-ledger-seal-v2'
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
              AND (
                  sample.record_schema_version <> 'v2'
                  OR sample.observation_authority_id IS NULL
              )
        )
        AND (
            SELECT COUNT(*) FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = NEW.run_id
        ) = NEW.sample_execution_count
        AND (
            SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments AS commitment
            WHERE commitment.run_id = NEW.run_id
        ) = NEW.sample_execution_count
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
              AND NOT EXISTS (
                  SELECT 1 FROM m6_upgrade_sample_execution_observations AS observation
                  WHERE observation.run_id = sample.run_id
                    AND observation.execution_scope_authority_id
                        = sample.execution_scope_authority_id
                    AND observation.ledger_sequence = sample.ledger_sequence
                    AND observation.observation_authority_id
                        = sample.observation_authority_id
                    AND observation.execution_entry_id = sample.execution_entry_id
                    AND observation.sample_id = sample.sample_id
                    AND observation.outcome = sample.outcome
                    AND observation.case_id IS sample.case_id
                    AND observation.case_revision IS sample.case_revision
                    AND observation.case_document_sha256
                        IS sample.case_document_sha256
                    AND observation.case_audit_sequence IS sample.case_audit_sequence
                    AND observation.case_audit_entry_hash IS sample.case_audit_entry_hash
              )
        )
        AND NOT EXISTS (
            SELECT 1 FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = NEW.run_id
              AND NOT EXISTS (
                  SELECT 1 FROM m6_upgrade_pending_sample_commitments AS commitment
                  WHERE commitment.run_id = sample.run_id
                    AND commitment.execution_scope_authority_id
                        = sample.execution_scope_authority_id
                    AND commitment.ledger_sequence = sample.ledger_sequence
                    AND commitment.execution_entry_id = sample.execution_entry_id
                    AND commitment.sample_id = sample.sample_id
                    AND commitment.observation_authority_id
                        = sample.observation_authority_id
                    AND commitment.sample_execution_record_id
                        = sample.sample_execution_record_id
                    AND commitment.sample_execution_record_json = sample.record_json
                    AND commitment.sample_execution_record_document_sha256
                        = sample.record_document_sha256
                    AND commitment.sample_execution_record_size_bytes
                        = sample.record_size_bytes
              )
        )
    )
    )
    AND json_type(NEW.seal_json, '$') = 'object'
    AND json_extract(
        NEW.seal_json,
        '$.execution_scope.execution_scope_authority_id'
    ) = NEW.execution_scope_authority_id
    AND json_extract(NEW.seal_json, '$.execution_scope_content_sha256')
        = NEW.execution_scope_document_sha256
    AND json_extract(NEW.seal_json, '$.execution_scope_size_bytes')
        = NEW.execution_scope_size_bytes
    AND json_extract(NEW.seal_json, '$.source_audit_head_sequence')
        = NEW.source_audit_head_sequence
    AND json_extract(NEW.seal_json, '$.source_audit_head_hash')
        = NEW.source_audit_head_hash
    AND json_extract(NEW.seal_json, '$.sample_execution_count')
        = NEW.sample_execution_count
    AND json_extract(NEW.seal_json, '$.sample_execution_inventory_root_sha256')
        = NEW.sample_execution_inventory_root_sha256
    AND json_extract(NEW.seal_json, '$.artifact_link_count')
        = NEW.artifact_link_count
    AND json_extract(NEW.seal_json, '$.artifact_link_inventory_root_sha256')
        = NEW.artifact_link_inventory_root_sha256
    AND json_extract(NEW.seal_json, '$.candidate_case_count')
        = NEW.candidate_case_count
    AND json_extract(NEW.seal_json, '$.candidate_case_inventory_root_sha256')
        = NEW.candidate_case_inventory_root_sha256
    AND json_extract(NEW.seal_json, '$.ledger_preseal_sequence')
        = NEW.ledger_preseal_sequence
    AND json_extract(NEW.seal_json, '$.ledger_preseal_hash')
        = NEW.ledger_preseal_hash
    AND json_extract(NEW.seal_json, '$.ledger_head_sequence')
        = NEW.ledger_head_sequence
    AND json_extract(NEW.seal_json, '$.ledger_seal_authority_id')
        = NEW.ledger_seal_authority_id
    AND json_array_length(NEW.seal_json, '$.sample_executions')
        = NEW.sample_execution_count
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
          AND json_extract(
              NEW.seal_json,
              '$.sample_executions[' || sample.ledger_sequence || ']'
           ) IS NOT json(sample.record_json)
    )
    AND length(CAST(NEW.seal_json AS BLOB)) = NEW.size_bytes
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade ledger schema-version closure');
END;

CREATE TRIGGER m6_upgrade_pending_sample_commitments_no_replace
BEFORE INSERT ON m6_upgrade_pending_sample_commitments
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_pending_sample_commitments AS commitment
    WHERE commitment.pending_sample_commitment_authority_id
              = NEW.pending_sample_commitment_authority_id
       OR commitment.observation_authority_id = NEW.observation_authority_id
       OR commitment.sample_execution_record_id = NEW.sample_execution_record_id
       OR (
          commitment.run_id = NEW.run_id
          AND (
              commitment.execution_scope_authority_id
                  <> NEW.execution_scope_authority_id
              OR commitment.ledger_sequence = NEW.ledger_sequence
              OR commitment.execution_entry_id = NEW.execution_entry_id
              OR commitment.sample_id = NEW.sample_id
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade pending sample commitments are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_seals_no_cross_run_replace
BEFORE INSERT ON m6_upgrade_execution_ledger_seals
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_execution_ledger_seals AS seal
    WHERE seal.ledger_seal_authority_id = NEW.ledger_seal_authority_id
       OR seal.document_sha256 = NEW.document_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution ledger seals are append-only');
END;

CREATE TRIGGER m6_upgrade_pending_sample_commitments_no_update
BEFORE UPDATE ON m6_upgrade_pending_sample_commitments
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade pending sample commitments are append-only');
END;

CREATE TRIGGER m6_upgrade_pending_sample_commitments_no_delete
BEFORE DELETE ON m6_upgrade_pending_sample_commitments
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade pending sample commitments are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_protocols_no_replace
BEFORE INSERT ON m6_upgrade_execution_ledger_protocols
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_execution_ledger_protocols AS protocol
    WHERE protocol.run_id = NEW.run_id
       OR protocol.execution_scope_authority_id = NEW.execution_scope_authority_id
)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution ledger protocols are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_protocols_no_update
BEFORE UPDATE ON m6_upgrade_execution_ledger_protocols
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution ledger protocols are append-only');
END;

CREATE TRIGGER m6_upgrade_execution_ledger_protocols_no_delete
BEFORE DELETE ON m6_upgrade_execution_ledger_protocols
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution ledger protocols are append-only');
END;
