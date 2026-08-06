CREATE TABLE m6_upgrade_sample_execution_observations (
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    ledger_sequence INTEGER NOT NULL CHECK (ledger_sequence >= 0),
    observation_authority_id TEXT NOT NULL
        CHECK (length(observation_authority_id) = 64
               AND observation_authority_id NOT GLOB '*[^0-9a-f]*'),
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
    artifact_count INTEGER NOT NULL CHECK (artifact_count BETWEEN 1 AND 20000),
    model_call_count INTEGER NOT NULL CHECK (model_call_count BETWEEN 0 AND 1000),
    observation_json TEXT NOT NULL CHECK (json_valid(observation_json)),
    document_sha256 TEXT NOT NULL
        CHECK (length(document_sha256) = 64
               AND document_sha256 NOT GLOB '*[^0-9a-f]*'),
    size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 67108864),
    PRIMARY KEY (run_id, ledger_sequence),
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

CREATE UNIQUE INDEX uq_m6_upgrade_execution_observation_id
    ON m6_upgrade_sample_execution_observations(run_id, observation_authority_id);

CREATE UNIQUE INDEX uq_m6_upgrade_execution_observation_entry
    ON m6_upgrade_sample_execution_observations(run_id, execution_entry_id);

CREATE UNIQUE INDEX uq_m6_upgrade_execution_observation_sample
    ON m6_upgrade_sample_execution_observations(run_id, sample_id);

CREATE TABLE m6_upgrade_observed_non_model_artifacts (
    run_id TEXT NOT NULL,
    observation_authority_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 19999),
    source TEXT NOT NULL CHECK (source IN (
        'M2_PERCEPTION', 'M2_EVIDENCE', 'M4_ACQUISITION', 'M5_PRECEDENT'
    )),
    kind TEXT NOT NULL CHECK (kind IN (
        'FRAME', 'DETECTION', 'EMBEDDING', 'PRECEDENT_EXPOSURE',
        'TOOL_EXECUTION_MANIFEST', 'TOOL_RESULT', 'EVIDENCE_PACK'
    )),
    artifact_id TEXT NOT NULL CHECK (length(artifact_id) BETWEEN 1 AND 192),
    usage TEXT NOT NULL CHECK (usage IN ('CONSUMED', 'PRODUCED')),
    PRIMARY KEY (run_id, observation_authority_id, ordinal),
    FOREIGN KEY (run_id, observation_authority_id)
        REFERENCES m6_upgrade_sample_execution_observations(
            run_id, observation_authority_id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (source = 'M2_PERCEPTION' AND kind IN ('FRAME', 'DETECTION'))
        OR (source = 'M2_EVIDENCE' AND kind = 'EVIDENCE_PACK')
        OR (source = 'M4_ACQUISITION' AND kind IN (
            'TOOL_EXECUTION_MANIFEST', 'TOOL_RESULT'
        ))
        OR (source = 'M5_PRECEDENT' AND kind IN (
            'EMBEDDING', 'PRECEDENT_EXPOSURE'
        ))
    ),
    CHECK (
        (kind = 'FRAME' AND usage = 'CONSUMED')
        OR (kind = 'EMBEDDING')
        OR (kind NOT IN ('FRAME', 'EMBEDDING') AND usage = 'PRODUCED')
    )
) STRICT;

CREATE UNIQUE INDEX uq_m6_upgrade_observed_non_model_identity
    ON m6_upgrade_observed_non_model_artifacts(
        run_id, observation_authority_id, source, kind, artifact_id
    );

CREATE TABLE m6_upgrade_observed_model_calls (
    run_id TEXT NOT NULL,
    observation_authority_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 999),
    request_id TEXT NOT NULL
        CHECK (length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'),
    layer TEXT NOT NULL CHECK (layer IN ('SCREENING', 'HEARING')),
    role TEXT NOT NULL CHECK (role IN ('SCREENING', 'PROSECUTOR', 'DEFENDER', 'JUDGE')),
    attempt_index INTEGER NOT NULL CHECK (attempt_index IN (0, 1)),
    result_kind TEXT NOT NULL CHECK (result_kind IN ('RESPONSE', 'FAILURE')),
    provider_invoked INTEGER NOT NULL CHECK (provider_invoked IN (0, 1)),
    PRIMARY KEY (run_id, observation_authority_id, ordinal),
    FOREIGN KEY (run_id, observation_authority_id)
        REFERENCES m6_upgrade_sample_execution_observations(
            run_id, observation_authority_id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        (layer = 'SCREENING' AND role = 'SCREENING')
        OR (layer = 'HEARING' AND role IN ('PROSECUTOR', 'DEFENDER', 'JUDGE'))
    )
) STRICT;

CREATE UNIQUE INDEX uq_m6_upgrade_observed_model_request
    ON m6_upgrade_observed_model_calls(run_id, observation_authority_id, request_id);

CREATE TRIGGER m6_upgrade_observed_non_model_artifacts_validate
BEFORE INSERT ON m6_upgrade_observed_non_model_artifacts
WHEN (
    EXISTS (
        SELECT 1 FROM m6_upgrade_execution_scopes AS scope
        WHERE scope.run_id = NEW.run_id
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_execution_ledger_seals AS seal
        WHERE seal.run_id = NEW.run_id
    )
    AND NOT EXISTS (
        SELECT 1
        FROM m6_upgrade_sample_execution_observations AS observation
        WHERE observation.run_id = NEW.run_id
          AND observation.observation_authority_id = NEW.observation_authority_id
    )
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 observed non-model artifact');
END;

CREATE TRIGGER m6_upgrade_observed_model_calls_validate
BEFORE INSERT ON m6_upgrade_observed_model_calls
WHEN (
    EXISTS (
        SELECT 1 FROM m6_upgrade_execution_scopes AS scope
        WHERE scope.run_id = NEW.run_id
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_execution_ledger_seals AS seal
        WHERE seal.run_id = NEW.run_id
    )
    AND NOT EXISTS (
        SELECT 1
        FROM m6_upgrade_sample_execution_observations AS observation
        WHERE observation.run_id = NEW.run_id
          AND observation.observation_authority_id = NEW.observation_authority_id
    )
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 observed model call');
END;

CREATE TRIGGER m6_upgrade_sample_execution_observations_validate
BEFORE INSERT ON m6_upgrade_sample_execution_observations
WHEN (
    EXISTS (
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
          AND json_extract(
              scope.scope_json,
              '$.execution_dataset.entries[' || NEW.ledger_sequence || ']'
          ) = json_extract(NEW.observation_json, '$.execution_entry')
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
        SELECT COUNT(*) FROM m6_upgrade_sample_execution_observations AS observation
        WHERE observation.run_id = NEW.run_id
    ) = (
        SELECT COUNT(*) FROM m6_upgrade_sample_executions AS sample
        WHERE sample.run_id = NEW.run_id
    )
    AND (
        (NEW.outcome = 'NO_CASE')
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
              AND version.audit_sequence > (
                  SELECT scope.execution_start_audit_head_sequence
                  FROM m6_upgrade_execution_scopes AS scope
                  WHERE scope.run_id = NEW.run_id
              )
        )
    )
    AND (SELECT COUNT(*) FROM m6_upgrade_observed_non_model_artifacts AS artifact
         WHERE artifact.run_id = NEW.run_id
           AND artifact.observation_authority_id = NEW.observation_authority_id)
        = NEW.artifact_count
    AND (SELECT COUNT(*) FROM m6_upgrade_observed_model_calls AS call
         WHERE call.run_id = NEW.run_id
           AND call.observation_authority_id = NEW.observation_authority_id)
        = NEW.model_call_count
    AND EXISTS (
        SELECT 1 FROM m6_upgrade_observed_non_model_artifacts AS artifact
        WHERE artifact.run_id = NEW.run_id
          AND artifact.observation_authority_id = NEW.observation_authority_id
          AND artifact.kind = 'FRAME'
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_observed_non_model_artifacts AS artifact
        WHERE artifact.run_id = NEW.run_id
          AND artifact.observation_authority_id = NEW.observation_authority_id
          AND (
              artifact.ordinal >= NEW.artifact_count
              OR json_extract(
                  NEW.observation_json,
                  '$.artifacts[' || artifact.ordinal || '].source'
              ) IS NOT artifact.source
              OR json_extract(
                  NEW.observation_json,
                  '$.artifacts[' || artifact.ordinal || '].kind'
              ) IS NOT artifact.kind
              OR json_extract(
                  NEW.observation_json,
                  '$.artifacts[' || artifact.ordinal || '].artifact_id'
              ) IS NOT artifact.artifact_id
              OR json_extract(
                  NEW.observation_json,
                  '$.artifacts[' || artifact.ordinal || '].usage'
              ) IS NOT artifact.usage
          )
    )
    AND NOT EXISTS (
        SELECT 1 FROM m6_upgrade_observed_model_calls AS call
        WHERE call.run_id = NEW.run_id
          AND call.observation_authority_id = NEW.observation_authority_id
          AND (
              call.ordinal >= NEW.model_call_count
              OR json_extract(
                  NEW.observation_json,
                  '$.model_calls[' || call.ordinal || '].request_id'
              ) IS NOT call.request_id
              OR json_extract(
                  NEW.observation_json,
                  '$.model_calls[' || call.ordinal || '].layer'
              ) IS NOT call.layer
              OR json_extract(
                  NEW.observation_json,
                  '$.model_calls[' || call.ordinal || '].role'
              ) IS NOT call.role
              OR json_extract(
                  NEW.observation_json,
                  '$.model_calls[' || call.ordinal || '].attempt_index'
              ) IS NOT call.attempt_index
              OR json_extract(
                  NEW.observation_json,
                  '$.model_calls[' || call.ordinal || '].result_kind'
              ) IS NOT call.result_kind
              OR json_extract(
                  NEW.observation_json,
                  '$.model_calls[' || call.ordinal || '].provider_invoked'
              ) IS NOT call.provider_invoked
          )
    )
    AND (
        NEW.outcome <> 'NO_CASE'
        OR (
            NEW.model_call_count = 0
            AND NOT EXISTS (
                SELECT 1 FROM m6_upgrade_observed_non_model_artifacts AS artifact
                WHERE artifact.run_id = NEW.run_id
                  AND artifact.observation_authority_id = NEW.observation_authority_id
                  AND artifact.kind NOT IN ('FRAME', 'DETECTION')
            )
        )
    )
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
    AND COALESCE((
        SELECT SUM(observation.size_bytes)
        FROM m6_upgrade_sample_execution_observations AS observation
        WHERE observation.run_id = NEW.run_id
    ), 0) + NEW.size_bytes <= 268435456
    AND json_extract(NEW.observation_json, '$.schema_version')
        = 'm6-upgrade-sample-execution-observation-authority-v1'
    AND json_extract(NEW.observation_json, '$.execution_scope_authority_id')
        = NEW.execution_scope_authority_id
    AND json_extract(NEW.observation_json, '$.candidate_run_id') = NEW.run_id
    AND json_extract(NEW.observation_json, '$.command_id') = NEW.command_id
    AND json_extract(NEW.observation_json, '$.execution_dataset_snapshot_id')
        = NEW.execution_dataset_snapshot_id
    AND json_extract(NEW.observation_json, '$.execution_entry.execution_entry_id')
        = NEW.execution_entry_id
    AND json_extract(NEW.observation_json, '$.execution_entry.sample_id') = NEW.sample_id
    AND json_extract(NEW.observation_json, '$.ledger_sequence') = NEW.ledger_sequence
    AND json_extract(NEW.observation_json, '$.outcome') = NEW.outcome
    AND json_extract(NEW.observation_json, '$.observation_authority_id')
        = NEW.observation_authority_id
    AND json_array_length(json_extract(NEW.observation_json, '$.artifacts'))
        = NEW.artifact_count
    AND json_array_length(json_extract(NEW.observation_json, '$.model_calls'))
        = NEW.model_call_count
    AND (
        (
            NEW.outcome = 'NO_CASE'
            AND json_type(NEW.observation_json, '$.candidate_case') = 'null'
        )
        OR (
            NEW.outcome = 'CASE_REPLAYED'
            AND json_extract(NEW.observation_json, '$.candidate_case.case_id') = NEW.case_id
            AND json_extract(NEW.observation_json, '$.candidate_case.case_revision')
                = NEW.case_revision
            AND json_extract(
                NEW.observation_json,
                '$.candidate_case.case_document_sha256'
            ) = NEW.case_document_sha256
            AND json_extract(
                NEW.observation_json,
                '$.candidate_case.case_audit_sequence'
            ) = NEW.case_audit_sequence
            AND json_extract(
                NEW.observation_json,
                '$.candidate_case.case_audit_entry_hash'
            ) = NEW.case_audit_entry_hash
        )
    )
    AND length(CAST(NEW.observation_json AS BLOB)) = NEW.size_bytes
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade sample execution observation');
END;

CREATE TRIGGER m6_upgrade_sample_execution_observations_no_replace
BEFORE INSERT ON m6_upgrade_sample_execution_observations
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_sample_execution_observations
    WHERE run_id = NEW.run_id
      AND (
          ledger_sequence = NEW.ledger_sequence
          OR observation_authority_id = NEW.observation_authority_id
          OR execution_entry_id = NEW.execution_entry_id
          OR sample_id = NEW.sample_id
      )
)
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution observations are append-only');
END;

CREATE TRIGGER m6_upgrade_observed_non_model_artifacts_no_replace
BEFORE INSERT ON m6_upgrade_observed_non_model_artifacts
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_observed_non_model_artifacts
    WHERE run_id = NEW.run_id
      AND observation_authority_id = NEW.observation_authority_id
      AND (
          ordinal = NEW.ordinal
          OR (
              source = NEW.source
              AND kind = NEW.kind
              AND artifact_id = NEW.artifact_id
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'M6 observed non-model artifacts are append-only');
END;

CREATE TRIGGER m6_upgrade_observed_model_calls_no_replace
BEFORE INSERT ON m6_upgrade_observed_model_calls
WHEN EXISTS (
    SELECT 1 FROM m6_upgrade_observed_model_calls
    WHERE run_id = NEW.run_id
      AND observation_authority_id = NEW.observation_authority_id
      AND (ordinal = NEW.ordinal OR request_id = NEW.request_id)
)
BEGIN
    SELECT RAISE(ABORT, 'M6 observed model calls are append-only');
END;

CREATE TRIGGER m6_upgrade_sample_execution_observations_no_update
BEFORE UPDATE ON m6_upgrade_sample_execution_observations
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution observations are append-only');
END;

CREATE TRIGGER m6_upgrade_sample_execution_observations_no_delete
BEFORE DELETE ON m6_upgrade_sample_execution_observations
BEGIN
    SELECT RAISE(ABORT, 'M6 upgrade execution observations are append-only');
END;

CREATE TRIGGER m6_upgrade_observed_non_model_artifacts_no_update
BEFORE UPDATE ON m6_upgrade_observed_non_model_artifacts
BEGIN
    SELECT RAISE(ABORT, 'M6 observed non-model artifacts are append-only');
END;

CREATE TRIGGER m6_upgrade_observed_non_model_artifacts_no_delete
BEFORE DELETE ON m6_upgrade_observed_non_model_artifacts
BEGIN
    SELECT RAISE(ABORT, 'M6 observed non-model artifacts are append-only');
END;

CREATE TRIGGER m6_upgrade_observed_model_calls_no_update
BEFORE UPDATE ON m6_upgrade_observed_model_calls
BEGIN
    SELECT RAISE(ABORT, 'M6 observed model calls are append-only');
END;

CREATE TRIGGER m6_upgrade_observed_model_calls_no_delete
BEFORE DELETE ON m6_upgrade_observed_model_calls
BEGIN
    SELECT RAISE(ABORT, 'M6 observed model calls are append-only');
END;
