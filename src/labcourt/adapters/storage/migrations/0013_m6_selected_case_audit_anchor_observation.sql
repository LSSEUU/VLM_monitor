CREATE TABLE m6_selected_case_audit_anchor_observation_preflight (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

INSERT INTO m6_selected_case_audit_anchor_observation_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_scopes AS scope
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = scope.run_id
     AND protocol.execution_scope_authority_id = scope.execution_scope_authority_id
    WHERE protocol.run_id IS NULL
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_ledger_protocols AS protocol
    LEFT JOIN m6_upgrade_execution_scopes AS scope
      ON scope.run_id = protocol.run_id
     AND scope.execution_scope_authority_id = protocol.execution_scope_authority_id
    WHERE scope.run_id IS NULL
       OR protocol.protocol_version NOT IN ('v1', 'v2')
);

INSERT INTO m6_selected_case_audit_anchor_observation_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_execution_observations AS observation
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = observation.run_id
     AND protocol.execution_scope_authority_id
         = observation.execution_scope_authority_id
    WHERE (
        protocol.protocol_version = 'v2'
        AND json_type(observation.observation_json, '$') = 'object'
        AND json_extract(observation.observation_json, '$.schema_version')
            = 'm6-upgrade-sample-execution-observation-authority-v1'
        AND json_type(
            observation.observation_json,
            '$.selected_case_audit_anchor'
        ) IS NULL
        AND json_extract(observation.observation_json, '$.observation_authority_id')
            = observation.observation_authority_id
        AND json_extract(observation.observation_json, '$.candidate_run_id')
            = observation.run_id
        AND json_extract(observation.observation_json, '$.outcome')
            = observation.outcome
        AND length(CAST(observation.observation_json AS BLOB))
            = observation.size_bytes
        AND (
            (
                observation.outcome = 'NO_CASE'
                AND json_type(
                    observation.observation_json,
                    '$.candidate_case'
                ) = 'null'
            )
            OR
            (
                observation.outcome = 'CASE_REPLAYED'
                AND json_extract(
                    observation.observation_json,
                    '$.candidate_case.case_id'
                ) = observation.case_id
                AND json_extract(
                    observation.observation_json,
                    '$.candidate_case.case_revision'
                ) = observation.case_revision
                AND json_extract(
                    observation.observation_json,
                    '$.candidate_case.case_document_sha256'
                ) = observation.case_document_sha256
                AND json_extract(
                    observation.observation_json,
                    '$.candidate_case.case_audit_sequence'
                ) = observation.case_audit_sequence
                AND json_extract(
                    observation.observation_json,
                    '$.candidate_case.case_audit_entry_hash'
                ) = observation.case_audit_entry_hash
                AND EXISTS (
                    SELECT 1
                    FROM case_versions AS version
                    JOIN audit_entries AS audit
                      ON audit.run_id = version.run_id
                     AND audit.sequence = version.audit_sequence
                    WHERE version.run_id = observation.run_id
                      AND version.case_id = observation.case_id
                      AND version.revision = observation.case_revision
                      AND version.document_sha256
                          = observation.case_document_sha256
                      AND version.audit_sequence
                          = observation.case_audit_sequence
                      AND audit.entry_hash = observation.case_audit_entry_hash
                      AND audit.object_kind = 'CASE'
                      AND audit.object_id = observation.case_id
                      AND audit.after_sha256
                          = observation.case_document_sha256
                )
            )
        )
    ) IS NOT TRUE
);

DROP TABLE m6_selected_case_audit_anchor_observation_preflight;

DROP TRIGGER m6_upgrade_sample_execution_observations_validate;
DROP TRIGGER m6_upgrade_observations_require_closed_v2_prefix;
DROP TRIGGER m6_upgrade_execution_scopes_default_v1_protocol;
DROP TRIGGER m6_upgrade_execution_ledger_protocols_no_replace;
DROP TRIGGER m6_upgrade_execution_ledger_protocols_no_update;
DROP TRIGGER m6_upgrade_execution_ledger_protocols_no_delete;

CREATE TABLE m6_upgrade_execution_ledger_protocols_v3 (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    protocol_version TEXT NOT NULL CHECK (protocol_version IN ('v1', 'v2', 'v3')),
    UNIQUE (run_id, execution_scope_authority_id),
    FOREIGN KEY (run_id, execution_scope_authority_id)
        REFERENCES m6_upgrade_execution_scopes(run_id, execution_scope_authority_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

INSERT INTO m6_upgrade_execution_ledger_protocols_v3(
    run_id, execution_scope_authority_id, protocol_version
)
SELECT run_id, execution_scope_authority_id, protocol_version
FROM m6_upgrade_execution_ledger_protocols;

DROP TABLE m6_upgrade_execution_ledger_protocols;

CREATE TABLE m6_upgrade_execution_ledger_protocols (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) BETWEEN 1 AND 64),
    execution_scope_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(execution_scope_authority_id) = 64
               AND execution_scope_authority_id NOT GLOB '*[^0-9a-f]*'),
    protocol_version TEXT NOT NULL CHECK (protocol_version IN ('v1', 'v2', 'v3')),
    UNIQUE (run_id, execution_scope_authority_id),
    FOREIGN KEY (run_id, execution_scope_authority_id)
        REFERENCES m6_upgrade_execution_scopes(run_id, execution_scope_authority_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

INSERT INTO m6_upgrade_execution_ledger_protocols(
    run_id, execution_scope_authority_id, protocol_version
)
SELECT run_id, execution_scope_authority_id, protocol_version
FROM m6_upgrade_execution_ledger_protocols_v3;

DROP TABLE m6_upgrade_execution_ledger_protocols_v3;

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

ALTER TABLE m6_upgrade_sample_execution_observations
ADD COLUMN observation_schema_version TEXT NOT NULL DEFAULT 'v1'
    CHECK (observation_schema_version IN ('v1', 'v2'));

ALTER TABLE m6_upgrade_sample_execution_observations
ADD COLUMN selected_case_audit_anchor_id TEXT
    CHECK (
        selected_case_audit_anchor_id IS NULL
        OR (
            length(selected_case_audit_anchor_id) = 64
            AND selected_case_audit_anchor_id NOT GLOB '*[^0-9a-f]*'
        )
    );

ALTER TABLE m6_upgrade_sample_execution_observations
ADD COLUMN case_audit_action TEXT
    CHECK (
        case_audit_action IS NULL
        OR case_audit_action IN (
            'CASE_CREATED', 'CASE_STATE_CHANGED',
            'CASE_CLOSED', 'EVIDENCE_PACK_PUBLISHED'
        )
    );

ALTER TABLE m6_upgrade_sample_execution_observations
ADD COLUMN case_audit_object_kind TEXT
    CHECK (
        case_audit_object_kind IS NULL
        OR case_audit_object_kind IN (
            'CASE', 'SCREENING_RESULT', 'PROCEDURAL_REVIEW',
            'BACKLOG_ITEM', 'APPEAL', 'ALERT'
        )
    );

ALTER TABLE m6_upgrade_sample_execution_observations
ADD COLUMN case_audit_object_id TEXT
    CHECK (
        case_audit_object_id IS NULL
        OR length(case_audit_object_id) BETWEEN 1 AND 214
    );

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
    AND json_type(NEW.observation_json, '$') = 'object'
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
            AND json_type(NEW.observation_json, '$.candidate_case') = 'object'
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
    AND EXISTS (
        SELECT 1
        FROM m6_upgrade_execution_ledger_protocols AS protocol
        WHERE protocol.run_id = NEW.run_id
          AND protocol.execution_scope_authority_id = NEW.execution_scope_authority_id
          AND (
              (
                  protocol.protocol_version = 'v2'
                  AND NEW.observation_schema_version = 'v1'
                  AND json_extract(NEW.observation_json, '$.schema_version')
                      = 'm6-upgrade-sample-execution-observation-authority-v1'
                  AND json_type(
                      NEW.observation_json,
                      '$.selected_case_audit_anchor'
                  ) IS NULL
                  AND NEW.selected_case_audit_anchor_id IS NULL
                  AND NEW.case_audit_action IS NULL
                  AND NEW.case_audit_object_kind IS NULL
                  AND NEW.case_audit_object_id IS NULL
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
                            AND version.audit_sequence > (
                                SELECT scope.execution_start_audit_head_sequence
                                FROM m6_upgrade_execution_scopes AS scope
                                WHERE scope.run_id = NEW.run_id
                            )
                      )
                  )
              )
              OR
              (
                  protocol.protocol_version = 'v3'
                  AND NEW.observation_schema_version = 'v2'
                  AND json_extract(NEW.observation_json, '$.schema_version')
                      = 'm6-upgrade-sample-execution-observation-authority-v2'
                  AND (
                      (
                          NEW.outcome = 'NO_CASE'
                          AND NEW.selected_case_audit_anchor_id IS NULL
                          AND NEW.case_audit_action IS NULL
                          AND NEW.case_audit_object_kind IS NULL
                          AND NEW.case_audit_object_id IS NULL
                          AND json_type(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor'
                          ) = 'null'
                      )
                      OR
                      (
                          NEW.outcome = 'CASE_REPLAYED'
                          AND NEW.selected_case_audit_anchor_id IS NOT NULL
                          AND NEW.case_audit_action IS NOT NULL
                          AND NEW.case_audit_object_kind IS NOT NULL
                          AND NEW.case_audit_object_id IS NOT NULL
                          AND json_type(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor'
                          ) = 'object'
                          AND json_extract(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor.schema_version'
                          ) = 'm6-upgrade-selected-case-audit-anchor-v1'
                          AND json_extract(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor.selected_case_audit_anchor_id'
                          ) = NEW.selected_case_audit_anchor_id
                          AND json_extract(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor.candidate_case_binding_id'
                          ) = json_extract(
                              NEW.observation_json,
                              '$.candidate_case.case_binding_id'
                          )
                          AND json_extract(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor.action'
                          ) = NEW.case_audit_action
                          AND json_type(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor.object_ref'
                          ) = 'object'
                          AND json_extract(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor.object_ref.kind'
                          ) = NEW.case_audit_object_kind
                          AND json_extract(
                              NEW.observation_json,
                              '$.selected_case_audit_anchor.object_ref.artifact_id'
                          ) = NEW.case_audit_object_id
                          AND (
                              (
                                  NEW.case_audit_action = 'CASE_CREATED'
                                  AND NEW.case_audit_object_kind = 'CASE'
                              )
                              OR (
                                  NEW.case_audit_action
                                      = 'EVIDENCE_PACK_PUBLISHED'
                                  AND NEW.case_audit_object_kind = 'CASE'
                              )
                              OR (
                                  NEW.case_audit_action = 'CASE_STATE_CHANGED'
                                  AND NEW.case_audit_object_kind IN (
                                      'CASE', 'SCREENING_RESULT', 'PROCEDURAL_REVIEW',
                                      'BACKLOG_ITEM', 'APPEAL'
                                  )
                              )
                              OR (
                                  NEW.case_audit_action = 'CASE_CLOSED'
                                  AND NEW.case_audit_object_kind IN ('CASE', 'ALERT')
                              )
                          )
                          AND (
                              (
                                  NEW.case_revision = 1
                                  AND NEW.case_audit_action = 'CASE_CREATED'
                              )
                              OR (
                                  NEW.case_revision > 1
                                  AND NEW.case_audit_action <> 'CASE_CREATED'
                              )
                          )
                          AND (
                              NEW.case_audit_object_kind <> 'CASE'
                              OR NEW.case_audit_object_id = NEW.case_id
                          )
                          AND EXISTS (
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
                                AND audit.action = NEW.case_audit_action
                                AND audit.object_kind
                                    = NEW.case_audit_object_kind
                                AND audit.object_id = NEW.case_audit_object_id
                                AND audit.after_sha256 = NEW.case_document_sha256
                                AND version.audit_sequence > (
                                    SELECT scope.execution_start_audit_head_sequence
                                    FROM m6_upgrade_execution_scopes AS scope
                                    WHERE scope.run_id = NEW.run_id
                                )
                          )
                      )
                  )
              )
          )
    )
    AND length(CAST(NEW.observation_json AS BLOB)) = NEW.size_bytes
) IS NOT TRUE
BEGIN
    SELECT RAISE(ABORT, 'invalid M6 upgrade sample execution observation');
END;

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
          AND protocol.protocol_version IN ('v2', 'v3')
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
    SELECT RAISE(
        ABORT,
        'M6 upgrade observation requires a closed observation-backed ledger prefix'
    );
END;
