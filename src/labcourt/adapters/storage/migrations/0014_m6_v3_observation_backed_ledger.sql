CREATE TABLE m6_v3_observation_backed_ledger_preflight (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

-- Reject malformed, oversized, or over-count stored authority inventories
-- before any JSON parser or application-defined function sees their raw TEXT.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
WITH budget_limits AS (
    SELECT
        268435456 AS max_inventory_bytes,
        250000 AS max_links,
        20000 AS max_links_per_sample,
        100000 AS max_samples,
        270000 AS max_observation_children
),
stored_documents(
    run_id,
    inventory_kind,
    raw_document,
    claimed_size_bytes,
    max_item_bytes,
    max_items
) AS (
    SELECT
        run_id,
        'scope',
        scope_json,
        size_bytes,
        budget.max_inventory_bytes,
        1
    FROM m6_upgrade_execution_scopes
    CROSS JOIN budget_limits AS budget
    UNION ALL
    SELECT
        run_id,
        'physical-ref',
        ref_json,
        ref_size_bytes,
        1048576,
        250000
    FROM m6_upgrade_physical_artifact_refs
    UNION ALL
    SELECT
        run_id,
        'artifact-link',
        link_json,
        link_size_bytes,
        1048576,
        250000
    FROM m6_upgrade_sample_artifact_links
    UNION ALL
    SELECT
        run_id,
        'sample-record',
        record_json,
        record_size_bytes,
        67108864,
        100000
    FROM m6_upgrade_sample_executions
    UNION ALL
    SELECT
        run_id,
        'observation',
        observation_json,
        size_bytes,
        67108864,
        100000
    FROM m6_upgrade_sample_execution_observations
    UNION ALL
    SELECT
        run_id,
        'pending-commitment',
        commitment_json,
        size_bytes,
        budget.max_inventory_bytes,
        100000
    FROM m6_upgrade_pending_sample_commitments
    CROSS JOIN budget_limits AS budget
    UNION ALL
    SELECT
        run_id,
        'pending-record',
        sample_execution_record_json,
        sample_execution_record_size_bytes,
        67108864,
        100000
    FROM m6_upgrade_pending_sample_commitments
    UNION ALL
    SELECT
        run_id,
        'ledger-seal',
        seal_json,
        size_bytes,
        budget.max_inventory_bytes,
        1
    FROM m6_upgrade_execution_ledger_seals
    CROSS JOIN budget_limits AS budget
)
SELECT 0
FROM budget_limits AS budget
WHERE EXISTS (
    SELECT 1
    FROM stored_documents AS document
    WHERE typeof(document.raw_document) <> 'text'
       OR typeof(document.claimed_size_bytes) <> 'integer'
       OR document.claimed_size_bytes < 1
       OR document.claimed_size_bytes > document.max_item_bytes
       OR length(CAST(document.raw_document AS BLOB)) < 1
       OR length(CAST(document.raw_document AS BLOB))
            > document.max_item_bytes
       OR length(CAST(document.raw_document AS BLOB))
            <> document.claimed_size_bytes
)
OR EXISTS (
    SELECT 1
    FROM stored_documents AS document
    GROUP BY document.run_id, document.inventory_kind
    HAVING COUNT(*) > MIN(document.max_items)
       OR SUM(length(CAST(document.raw_document AS BLOB)))
            > budget.max_inventory_bytes
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_scopes AS scope
    WHERE length(CAST(scope.scope_json AS BLOB))
        + COALESCE((
            SELECT SUM(length(CAST(sample.record_json AS BLOB)))
            FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = scope.run_id
        ), 0)
        + COALESCE((
            SELECT SUM(length(CAST(
                commitment.sample_execution_record_json AS BLOB
            )))
            FROM m6_upgrade_pending_sample_commitments AS commitment
            WHERE commitment.run_id = scope.run_id
              AND NOT EXISTS (
                  SELECT 1
                  FROM m6_upgrade_sample_executions AS sample
                  WHERE sample.run_id = commitment.run_id
                    AND sample.ledger_sequence = commitment.ledger_sequence
              )
        ), 0) > budget.max_inventory_bytes
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_artifact_links AS link
    GROUP BY link.run_id, link.execution_entry_id
    HAVING COUNT(*) > budget.max_links_per_sample
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_artifact_links AS link
    GROUP BY link.run_id
    HAVING COUNT(*) > budget.max_links
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_physical_artifact_refs AS ref
    GROUP BY ref.run_id
    HAVING COUNT(*) > budget.max_links
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_executions AS sample
    GROUP BY sample.run_id
    HAVING COUNT(*) > budget.max_samples
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_execution_observations AS observation
    GROUP BY observation.run_id
    HAVING COUNT(*) > budget.max_samples
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_pending_sample_commitments AS commitment
    GROUP BY commitment.run_id
    HAVING COUNT(*) > budget.max_samples
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_observed_non_model_artifacts AS artifact
    GROUP BY artifact.run_id
    HAVING COUNT(*) > budget.max_observation_children
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_observed_model_calls AS model_call
    GROUP BY model_call.run_id
    HAVING COUNT(*) > budget.max_observation_children
);

-- Recompute every raw digest and validate the exact allowlisted canonical
-- contract wire, including derived/computed identities and unknown-field bans.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
WITH authority_documents(contract_kind, raw_document, document_sha256) AS (
    SELECT
        'execution-scope-v1',
        scope_json,
        document_sha256
    FROM m6_upgrade_execution_scopes
    UNION ALL
    SELECT
        'physical-artifact-ref-v1',
        ref_json,
        ref_document_sha256
    FROM m6_upgrade_physical_artifact_refs
    UNION ALL
    SELECT
        'sample-artifact-link-v1',
        link_json,
        link_document_sha256
    FROM m6_upgrade_sample_artifact_links
    UNION ALL
    SELECT
        CASE record_schema_version
            WHEN 'v1' THEN 'sample-execution-record-v1'
            WHEN 'v2' THEN 'sample-execution-record-v2'
            ELSE NULL
        END,
        record_json,
        record_document_sha256
    FROM m6_upgrade_sample_executions
    UNION ALL
    SELECT
        CASE observation_schema_version
            WHEN 'v1' THEN 'sample-execution-observation-v1'
            WHEN 'v2' THEN 'sample-execution-observation-v2'
            ELSE NULL
        END,
        observation_json,
        document_sha256
    FROM m6_upgrade_sample_execution_observations
    UNION ALL
    SELECT
        'pending-sample-commitment-v1',
        commitment_json,
        document_sha256
    FROM m6_upgrade_pending_sample_commitments
    UNION ALL
    SELECT
        'sample-execution-record-v2',
        sample_execution_record_json,
        sample_execution_record_document_sha256
    FROM m6_upgrade_pending_sample_commitments
    UNION ALL
    SELECT
        CASE seal_schema_version
            WHEN 'v1' THEN 'execution-ledger-seal-v1'
            WHEN 'v2' THEN 'execution-ledger-seal-v2'
            ELSE NULL
        END,
        seal_json,
        document_sha256
    FROM m6_upgrade_execution_ledger_seals
)
SELECT 0
FROM authority_documents AS document
WHERE labcourt_migration_sha256_utf8(document.raw_document)
        IS NOT document.document_sha256
   OR labcourt_migration_contract_is_canonical(
        document.contract_kind,
        document.raw_document
   ) IS NOT 1
LIMIT 1;

-- Every execution scope must retain one supported protocol row, and every
-- protocol row must still name its exact scope.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_scopes AS scope
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = scope.run_id
     AND protocol.execution_scope_authority_id
         = scope.execution_scope_authority_id
    WHERE protocol.run_id IS NULL
       OR protocol.protocol_version NOT IN ('v1', 'v2', 'v3')
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_ledger_protocols AS protocol
    LEFT JOIN m6_upgrade_execution_scopes AS scope
      ON scope.run_id = protocol.run_id
     AND scope.execution_scope_authority_id
         = protocol.execution_scope_authority_id
    WHERE scope.run_id IS NULL
);

-- Preserve the prefix state machine.  Under migration 0013 a V3 run could
-- legally contain only zero or one ObservationV2 and no later authority.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
WITH ledger_state AS (
    SELECT
        scope.run_id AS run_id,
        scope.expected_sample_count AS expected_count,
        protocol.protocol_version AS protocol_version,
        (
            SELECT COUNT(*)
            FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = scope.run_id
        ) AS sample_count,
        (
            SELECT COUNT(*)
            FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = scope.run_id
        ) AS observation_count,
        (
            SELECT COUNT(*)
            FROM m6_upgrade_pending_sample_commitments AS commitment
            WHERE commitment.run_id = scope.run_id
        ) AS commitment_count,
        (
            SELECT COUNT(*)
            FROM m6_upgrade_execution_ledger_seals AS seal
            WHERE seal.run_id = scope.run_id
        ) AS seal_count
    FROM m6_upgrade_execution_scopes AS scope
    JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = scope.run_id
     AND protocol.execution_scope_authority_id
         = scope.execution_scope_authority_id
)
SELECT 0
FROM ledger_state AS state
WHERE (
    (
        state.protocol_version = 'v1'
        AND state.sample_count BETWEEN 0 AND state.expected_count
        AND state.observation_count = 0
        AND state.commitment_count = 0
        AND state.seal_count IN (0, 1)
        AND (state.seal_count = 0 OR state.sample_count = state.expected_count)
    )
    OR (
        state.protocol_version = 'v2'
        AND state.sample_count BETWEEN 0 AND state.expected_count
        AND state.observation_count
            BETWEEN state.sample_count AND state.sample_count + 1
        AND state.commitment_count
            BETWEEN state.sample_count AND state.sample_count + 1
        AND state.commitment_count <= state.observation_count
        AND (
            state.sample_count < state.expected_count
            OR (
                state.observation_count = state.sample_count
                AND state.commitment_count = state.sample_count
            )
        )
        AND state.seal_count IN (0, 1)
        AND (
            state.seal_count = 0
            OR (
                state.sample_count = state.expected_count
                AND state.observation_count = state.expected_count
                AND state.commitment_count = state.expected_count
            )
        )
    )
    OR (
        state.protocol_version = 'v3'
        AND state.sample_count = 0
        AND state.commitment_count = 0
        AND state.seal_count = 0
        AND state.observation_count BETWEEN 0 AND 1
        AND NOT EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = state.run_id
              AND observation.ledger_sequence <> 0
        )
    )
) IS NOT TRUE
LIMIT 1;

-- V1/V2 wire formats remain immutable.  Any forged V3 record, commitment, or
-- seal is rejected before the old triggers are removed.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_executions AS sample
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = sample.run_id
     AND protocol.execution_scope_authority_id
         = sample.execution_scope_authority_id
    WHERE (
        (
            protocol.protocol_version = 'v1'
            AND sample.record_schema_version = 'v1'
            AND sample.observation_authority_id IS NULL
            AND json_extract(sample.record_json, '$.schema_version')
                = 'm6-upgrade-sample-execution-record-v1'
        )
        OR (
            protocol.protocol_version = 'v2'
            AND sample.record_schema_version = 'v2'
            AND sample.observation_authority_id IS NOT NULL
            AND json_extract(sample.record_json, '$.schema_version')
                = 'm6-upgrade-sample-execution-record-v2'
        )
    ) IS NOT TRUE
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_pending_sample_commitments AS commitment
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = commitment.run_id
     AND protocol.execution_scope_authority_id
         = commitment.execution_scope_authority_id
    WHERE (
        protocol.protocol_version = 'v2'
        AND json_extract(commitment.commitment_json, '$.schema_version')
            = 'm6-upgrade-pending-sample-commitment-authority-v1'
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.schema_version'
        ) = 'm6-upgrade-sample-execution-record-v2'
        AND json_extract(
            commitment.commitment_json,
            '$.observation_authority_id'
        ) = commitment.observation_authority_id
        AND json_extract(
            commitment.commitment_json,
            '$.sample_execution_record_id'
        ) = commitment.sample_execution_record_id
        AND length(CAST(commitment.commitment_json AS BLOB))
            = commitment.size_bytes
        AND length(CAST(commitment.sample_execution_record_json AS BLOB))
            = commitment.sample_execution_record_size_bytes
    ) IS NOT TRUE
)
OR EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_ledger_seals AS seal
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = seal.run_id
     AND protocol.execution_scope_authority_id
         = seal.execution_scope_authority_id
    WHERE (
        (
            protocol.protocol_version = 'v1'
            AND seal.seal_schema_version = 'v1'
            AND json_extract(seal.seal_json, '$.schema_version')
                = 'm6-upgrade-execution-ledger-seal-v1'
        )
        OR (
            protocol.protocol_version = 'v2'
            AND seal.seal_schema_version = 'v2'
            AND json_extract(seal.seal_json, '$.schema_version')
                = 'm6-upgrade-execution-ledger-seal-v2'
        )
    ) IS NOT TRUE
);

-- ObservationV1 remains exclusive to V2.  ObservationV2 is exclusive to V3,
-- and its normalized anchor must still be an exact projection of the JSON and
-- of the selected case-version audit row.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_execution_observations AS observation
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = observation.run_id
     AND protocol.execution_scope_authority_id
         = observation.execution_scope_authority_id
    WHERE (
        (
            protocol.protocol_version = 'v2'
            AND observation.observation_schema_version = 'v1'
            AND json_extract(
                observation.observation_json,
                '$.schema_version'
            ) = 'm6-upgrade-sample-execution-observation-authority-v1'
            AND json_type(
                observation.observation_json,
                '$.selected_case_audit_anchor'
            ) IS NULL
            AND observation.selected_case_audit_anchor_id IS NULL
            AND observation.case_audit_action IS NULL
            AND observation.case_audit_object_kind IS NULL
            AND observation.case_audit_object_id IS NULL
        )
        OR (
            protocol.protocol_version = 'v3'
            AND observation.observation_schema_version = 'v2'
            AND json_type(observation.observation_json, '$') = 'object'
            AND json_extract(
                observation.observation_json,
                '$.schema_version'
            ) = 'm6-upgrade-sample-execution-observation-authority-v2'
            AND json_extract(
                observation.observation_json,
                '$.execution_scope_authority_id'
            ) = observation.execution_scope_authority_id
            AND json_extract(
                observation.observation_json,
                '$.candidate_run_id'
            ) = observation.run_id
            AND json_extract(observation.observation_json, '$.command_id')
                = observation.command_id
            AND json_extract(
                observation.observation_json,
                '$.execution_dataset_snapshot_id'
            ) = observation.execution_dataset_snapshot_id
            AND json_extract(
                observation.observation_json,
                '$.execution_entry.execution_entry_id'
            ) = observation.execution_entry_id
            AND json_extract(
                observation.observation_json,
                '$.execution_entry.sample_id'
            ) = observation.sample_id
            AND json_extract(
                observation.observation_json,
                '$.ledger_sequence'
            ) = observation.ledger_sequence
            AND json_extract(observation.observation_json, '$.outcome')
                = observation.outcome
            AND json_extract(
                observation.observation_json,
                '$.observation_authority_id'
            ) = observation.observation_authority_id
            AND json_array_length(
                observation.observation_json,
                '$.artifacts'
            ) = observation.artifact_count
            AND json_array_length(
                observation.observation_json,
                '$.model_calls'
            ) = observation.model_call_count
            AND length(CAST(observation.observation_json AS BLOB))
                = observation.size_bytes
            AND (
                (
                    observation.outcome = 'NO_CASE'
                    AND json_type(
                        observation.observation_json,
                        '$.candidate_case'
                    ) = 'null'
                    AND observation.selected_case_audit_anchor_id IS NULL
                    AND observation.case_audit_action IS NULL
                    AND observation.case_audit_object_kind IS NULL
                    AND observation.case_audit_object_id IS NULL
                    AND json_type(
                        observation.observation_json,
                        '$.selected_case_audit_anchor'
                    ) = 'null'
                )
                OR (
                    observation.outcome = 'CASE_REPLAYED'
                    AND json_type(
                        observation.observation_json,
                        '$.candidate_case'
                    ) = 'object'
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
                    AND observation.selected_case_audit_anchor_id IS NOT NULL
                    AND observation.case_audit_action IS NOT NULL
                    AND observation.case_audit_object_kind IS NOT NULL
                    AND observation.case_audit_object_id IS NOT NULL
                    AND json_type(
                        observation.observation_json,
                        '$.selected_case_audit_anchor'
                    ) = 'object'
                    AND json_extract(
                        observation.observation_json,
                        '$.selected_case_audit_anchor.schema_version'
                    ) = 'm6-upgrade-selected-case-audit-anchor-v1'
                    AND json_extract(
                        observation.observation_json,
                        '$.selected_case_audit_anchor.selected_case_audit_anchor_id'
                    ) = observation.selected_case_audit_anchor_id
                    AND json_extract(
                        observation.observation_json,
                        '$.selected_case_audit_anchor.candidate_case_binding_id'
                    ) = json_extract(
                        observation.observation_json,
                        '$.candidate_case.case_binding_id'
                    )
                    AND json_extract(
                        observation.observation_json,
                        '$.selected_case_audit_anchor.action'
                    ) = observation.case_audit_action
                    AND json_type(
                        observation.observation_json,
                        '$.selected_case_audit_anchor.object_ref'
                    ) = 'object'
                    AND json_extract(
                        observation.observation_json,
                        '$.selected_case_audit_anchor.object_ref.kind'
                    ) = observation.case_audit_object_kind
                    AND json_extract(
                        observation.observation_json,
                        '$.selected_case_audit_anchor.object_ref.artifact_id'
                    ) = observation.case_audit_object_id
                    AND (
                        (
                            observation.case_audit_action = 'CASE_CREATED'
                            AND observation.case_audit_object_kind = 'CASE'
                        )
                        OR (
                            observation.case_audit_action
                                = 'EVIDENCE_PACK_PUBLISHED'
                            AND observation.case_audit_object_kind = 'CASE'
                        )
                        OR (
                            observation.case_audit_action
                                = 'CASE_STATE_CHANGED'
                            AND observation.case_audit_object_kind IN (
                                'CASE', 'SCREENING_RESULT',
                                'PROCEDURAL_REVIEW', 'BACKLOG_ITEM', 'APPEAL'
                            )
                        )
                        OR (
                            observation.case_audit_action = 'CASE_CLOSED'
                            AND observation.case_audit_object_kind
                                IN ('CASE', 'ALERT')
                        )
                    )
                    AND (
                        (
                            observation.case_revision = 1
                            AND observation.case_audit_action = 'CASE_CREATED'
                        )
                        OR (
                            observation.case_revision > 1
                            AND observation.case_audit_action <> 'CASE_CREATED'
                        )
                    )
                    AND (
                        observation.case_audit_object_kind <> 'CASE'
                        OR observation.case_audit_object_id = observation.case_id
                    )
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
                          AND audit.entry_hash
                              = observation.case_audit_entry_hash
                          AND audit.action = observation.case_audit_action
                          AND audit.object_kind
                              = observation.case_audit_object_kind
                          AND audit.object_id = observation.case_audit_object_id
                          AND audit.after_sha256
                              = observation.case_document_sha256
                          AND version.audit_sequence > (
                              SELECT scope.execution_start_audit_head_sequence
                              FROM m6_upgrade_execution_scopes AS scope
                              WHERE scope.run_id = observation.run_id
                                AND scope.execution_scope_authority_id
                                    = observation.execution_scope_authority_id
                          )
                    )
                )
            )
        )
    ) IS NOT TRUE
);

-- Revalidate every immutable dependency consumed by the replacement sample
-- trigger.  This closes the upgrade-time gap even if an append-only trigger
-- was removed and a stored projection was altered out of band.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
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
)
OR EXISTS (
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
)
OR EXISTS (
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

-- Revalidate the complete normalized observation projection for both wires;
-- the protocol/anchor block above supplies the wire-specific authority proof.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_execution_observations AS observation
    WHERE (
        json_type(observation.observation_json, '$') = 'object'
        AND json_extract(
            observation.observation_json,
            '$.execution_scope_authority_id'
        ) = observation.execution_scope_authority_id
        AND json_extract(observation.observation_json, '$.candidate_run_id')
            = observation.run_id
        AND json_extract(observation.observation_json, '$.command_id')
            = observation.command_id
        AND json_extract(
            observation.observation_json,
            '$.execution_dataset_snapshot_id'
        ) = observation.execution_dataset_snapshot_id
        AND json_extract(
            observation.observation_json,
            '$.execution_entry.execution_entry_id'
        ) = observation.execution_entry_id
        AND json_extract(
            observation.observation_json,
            '$.execution_entry.sample_id'
        ) = observation.sample_id
        AND json_extract(observation.observation_json, '$.ledger_sequence')
            = observation.ledger_sequence
        AND json_extract(observation.observation_json, '$.outcome')
            = observation.outcome
        AND json_extract(
            observation.observation_json,
            '$.observation_authority_id'
        ) = observation.observation_authority_id
        AND json_array_length(observation.observation_json, '$.artifacts')
            = observation.artifact_count
        AND json_array_length(observation.observation_json, '$.model_calls')
            = observation.model_call_count
        AND (
            (
                observation.outcome = 'NO_CASE'
                AND observation.case_id IS NULL
                AND observation.case_revision IS NULL
                AND observation.case_document_sha256 IS NULL
                AND observation.case_audit_sequence IS NULL
                AND observation.case_audit_entry_hash IS NULL
                AND json_type(
                    observation.observation_json,
                    '$.candidate_case'
                ) = 'null'
            )
            OR (
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
            )
        )
        AND length(CAST(observation.observation_json AS BLOB))
            = observation.size_bytes
    ) IS NOT TRUE
);

-- Revalidate committed record projections, ledger order, physical inventory,
-- case authority, and the exact ObservationV1/PendingV1 closure used by V2.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_executions AS sample
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = sample.run_id
     AND protocol.execution_scope_authority_id
         = sample.execution_scope_authority_id
    WHERE (
        (
            (
                protocol.protocol_version = 'v1'
                AND sample.record_schema_version = 'v1'
                AND sample.observation_authority_id IS NULL
                AND json_extract(sample.record_json, '$.schema_version')
                    = 'm6-upgrade-sample-execution-record-v1'
            )
            OR (
                protocol.protocol_version = 'v2'
                AND sample.record_schema_version = 'v2'
                AND sample.observation_authority_id IS NOT NULL
                AND json_extract(sample.record_json, '$.schema_version')
                    = 'm6-upgrade-sample-execution-record-v2'
            )
        )
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_execution_scopes AS scope
            WHERE scope.run_id = sample.run_id
              AND scope.execution_scope_authority_id
                  = sample.execution_scope_authority_id
              AND scope.command_id = sample.command_id
              AND scope.execution_dataset_snapshot_id
                  = sample.execution_dataset_snapshot_id
              AND sample.ledger_sequence < scope.expected_sample_count
              AND json_extract(
                  scope.scope_json,
                  '$.execution_dataset.entries['
                      || sample.ledger_sequence || '].execution_entry_id'
              ) = sample.execution_entry_id
              AND json_extract(
                  scope.scope_json,
                  '$.execution_dataset.entries['
                      || sample.ledger_sequence || '].sample_id'
              ) = sample.sample_id
        )
        AND (
            (
                sample.ledger_sequence = 0
                AND sample.previous_ledger_entry_hash
                    = '0000000000000000000000000000000000000000000000000000000000000000'
            )
            OR (
                sample.ledger_sequence > 0
                AND EXISTS (
                    SELECT 1
                    FROM m6_upgrade_sample_executions AS prior
                    WHERE prior.run_id = sample.run_id
                      AND prior.ledger_sequence = sample.ledger_sequence - 1
                      AND prior.sample_execution_record_id
                          = sample.previous_ledger_entry_hash
                )
            )
        )
        AND json_type(sample.record_json, '$') = 'object'
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
        AND json_extract(sample.record_json, '$.candidate_case.case_id')
            IS sample.case_id
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
        AND length(CAST(sample.record_json AS BLOB)) = sample.record_size_bytes
        AND (
            SELECT COUNT(*)
            FROM m6_upgrade_sample_artifact_links AS link
            WHERE link.run_id = sample.run_id
              AND link.execution_entry_id = sample.execution_entry_id
        ) = sample.artifact_link_count
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
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_artifact_links AS link
            JOIN m6_upgrade_physical_artifact_refs AS ref
              ON ref.run_id = link.run_id
             AND ref.artifact_ref_id = link.artifact_ref_id
            WHERE link.run_id = sample.run_id
              AND link.execution_entry_id = sample.execution_entry_id
              AND ref.kind = 'FRAME'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_artifact_links AS detection_link
            JOIN m6_upgrade_physical_artifact_refs AS detection
              ON detection.run_id = detection_link.run_id
             AND detection.artifact_ref_id = detection_link.artifact_ref_id
            WHERE detection_link.run_id = sample.run_id
              AND detection_link.execution_entry_id = sample.execution_entry_id
              AND detection.kind = 'DETECTION'
              AND NOT EXISTS (
                  SELECT 1
                  FROM m6_upgrade_sample_artifact_links AS frame_link
                  JOIN m6_upgrade_physical_artifact_refs AS frame
                    ON frame.run_id = frame_link.run_id
                   AND frame.artifact_ref_id = frame_link.artifact_ref_id
                  WHERE frame_link.run_id = detection_link.run_id
                    AND frame_link.execution_entry_id
                        = detection_link.execution_entry_id
                    AND frame.kind = 'FRAME'
                    AND frame.artifact_id = detection.container_id
              )
        )
        AND (
            sample.outcome = 'NO_CASE'
            OR EXISTS (
                SELECT 1
                FROM case_versions AS version
                JOIN audit_entries AS audit
                  ON audit.run_id = version.run_id
                 AND audit.sequence = version.audit_sequence
                WHERE version.run_id = sample.run_id
                  AND version.case_id = sample.case_id
                  AND version.revision = sample.case_revision
                  AND version.document_sha256 = sample.case_document_sha256
                  AND version.audit_sequence = sample.case_audit_sequence
                  AND audit.entry_hash = sample.case_audit_entry_hash
                  AND audit.object_kind = 'CASE'
                  AND audit.object_id = sample.case_id
                  AND audit.after_sha256 = sample.case_document_sha256
                  AND version.audit_sequence > (
                      SELECT scope.execution_start_audit_head_sequence
                      FROM m6_upgrade_execution_scopes AS scope
                      WHERE scope.run_id = sample.run_id
                        AND scope.execution_scope_authority_id
                            = sample.execution_scope_authority_id
                  )
            )
        )
        AND (
            protocol.protocol_version = 'v1'
            OR (
                protocol.protocol_version = 'v2'
                AND EXISTS (
                    SELECT 1
                    FROM m6_upgrade_sample_execution_observations AS observation
                    WHERE observation.run_id = sample.run_id
                      AND observation.execution_scope_authority_id
                          = sample.execution_scope_authority_id
                      AND observation.ledger_sequence = sample.ledger_sequence
                      AND observation.observation_authority_id
                          = sample.observation_authority_id
                      AND observation.command_id = sample.command_id
                      AND observation.execution_dataset_snapshot_id
                          = sample.execution_dataset_snapshot_id
                      AND observation.execution_entry_id
                          = sample.execution_entry_id
                      AND observation.sample_id = sample.sample_id
                      AND observation.outcome = sample.outcome
                      AND observation.case_id IS sample.case_id
                      AND observation.case_revision IS sample.case_revision
                      AND observation.case_document_sha256
                          IS sample.case_document_sha256
                      AND observation.case_audit_sequence
                          IS sample.case_audit_sequence
                      AND observation.case_audit_entry_hash
                          IS sample.case_audit_entry_hash
                      AND observation.observation_schema_version = 'v1'
                )
                AND EXISTS (
                    SELECT 1
                    FROM m6_upgrade_pending_sample_commitments AS commitment
                    WHERE commitment.run_id = sample.run_id
                      AND commitment.execution_scope_authority_id
                          = sample.execution_scope_authority_id
                      AND commitment.ledger_sequence = sample.ledger_sequence
                      AND commitment.command_id = sample.command_id
                      AND commitment.execution_dataset_snapshot_id
                          = sample.execution_dataset_snapshot_id
                      AND commitment.execution_entry_id
                          = sample.execution_entry_id
                      AND commitment.sample_id = sample.sample_id
                      AND commitment.observation_authority_id
                          = sample.observation_authority_id
                      AND commitment.sample_execution_record_id
                          = sample.sample_execution_record_id
                      AND commitment.sample_execution_record_json
                          = sample.record_json
                      AND commitment.sample_execution_record_document_sha256
                          = sample.record_document_sha256
                      AND commitment.sample_execution_record_size_bytes
                          = sample.record_size_bytes
                )
            )
        )
    ) IS NOT TRUE
);

-- Revalidate every historical PendingV1 envelope and its embedded RecordV2.
-- Pending records intentionally precede physical materialization, so this
-- proof is self-contained and joins only the exact observation and prefix.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_pending_sample_commitments AS commitment
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = commitment.run_id
     AND protocol.execution_scope_authority_id
         = commitment.execution_scope_authority_id
    WHERE (
        protocol.protocol_version = 'v2'
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_execution_scopes AS scope
            WHERE scope.run_id = commitment.run_id
              AND scope.execution_scope_authority_id
                  = commitment.execution_scope_authority_id
              AND scope.command_id = commitment.command_id
              AND scope.execution_dataset_snapshot_id
                  = commitment.execution_dataset_snapshot_id
              AND commitment.ledger_sequence < scope.expected_sample_count
              AND json_extract(
                  scope.scope_json,
                  '$.execution_dataset.entries['
                      || commitment.ledger_sequence || '].execution_entry_id'
              ) = commitment.execution_entry_id
              AND json_extract(
                  scope.scope_json,
                  '$.execution_dataset.entries['
                      || commitment.ledger_sequence || '].sample_id'
              ) = commitment.sample_id
              AND json_extract(
                  scope.scope_json,
                  '$.execution_dataset.entries['
                      || commitment.ledger_sequence || ']'
              ) = json_extract(commitment.commitment_json, '$.execution_entry')
        )
        AND (
            (
                commitment.ledger_sequence = 0
                AND json_extract(
                    commitment.sample_execution_record_json,
                    '$.previous_ledger_entry_hash'
                ) = '0000000000000000000000000000000000000000000000000000000000000000'
            )
            OR (
                commitment.ledger_sequence > 0
                AND EXISTS (
                    SELECT 1
                    FROM m6_upgrade_sample_executions AS prior
                    WHERE prior.run_id = commitment.run_id
                      AND prior.ledger_sequence = commitment.ledger_sequence - 1
                      AND prior.record_schema_version = 'v2'
                      AND prior.sample_execution_record_id = json_extract(
                          commitment.sample_execution_record_json,
                          '$.previous_ledger_entry_hash'
                      )
                )
            )
        )
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_execution_observations AS observation
            WHERE observation.run_id = commitment.run_id
              AND observation.execution_scope_authority_id
                  = commitment.execution_scope_authority_id
              AND observation.ledger_sequence = commitment.ledger_sequence
              AND observation.observation_authority_id
                  = commitment.observation_authority_id
              AND observation.command_id = commitment.command_id
              AND observation.execution_dataset_snapshot_id
                  = commitment.execution_dataset_snapshot_id
              AND observation.execution_entry_id
                  = commitment.execution_entry_id
              AND observation.sample_id = commitment.sample_id
              AND observation.observation_schema_version = 'v1'
              AND observation.outcome = json_extract(
                  commitment.sample_execution_record_json,
                  '$.outcome'
              )
              AND observation.case_id IS json_extract(
                  commitment.sample_execution_record_json,
                  '$.candidate_case.case_id'
              )
              AND observation.case_revision IS json_extract(
                  commitment.sample_execution_record_json,
                  '$.candidate_case.case_revision'
              )
              AND observation.case_document_sha256 IS json_extract(
                  commitment.sample_execution_record_json,
                  '$.candidate_case.case_document_sha256'
              )
              AND observation.case_audit_sequence IS json_extract(
                  commitment.sample_execution_record_json,
                  '$.candidate_case.case_audit_sequence'
              )
              AND observation.case_audit_entry_hash IS json_extract(
                  commitment.sample_execution_record_json,
                  '$.candidate_case.case_audit_entry_hash'
              )
              AND (
                  observation.outcome = 'NO_CASE'
                  OR EXISTS (
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
                        AND audit.entry_hash
                            = observation.case_audit_entry_hash
                        AND audit.object_kind = 'CASE'
                        AND audit.object_id = observation.case_id
                        AND audit.after_sha256
                            = observation.case_document_sha256
                        AND version.audit_sequence > (
                            SELECT scope.execution_start_audit_head_sequence
                            FROM m6_upgrade_execution_scopes AS scope
                            WHERE scope.run_id = observation.run_id
                              AND scope.execution_scope_authority_id
                                  = observation.execution_scope_authority_id
                        )
                  )
              )
        )
        AND json_type(commitment.commitment_json, '$') = 'object'
        AND json_extract(commitment.commitment_json, '$.schema_version')
            = 'm6-upgrade-pending-sample-commitment-authority-v1'
        AND json_extract(
            commitment.commitment_json,
            '$.execution_scope_authority_id'
        ) = commitment.execution_scope_authority_id
        AND json_extract(commitment.commitment_json, '$.candidate_run_id')
            = commitment.run_id
        AND json_extract(commitment.commitment_json, '$.command_id')
            = commitment.command_id
        AND json_extract(
            commitment.commitment_json,
            '$.execution_dataset_snapshot_id'
        ) = commitment.execution_dataset_snapshot_id
        AND json_extract(
            commitment.commitment_json,
            '$.execution_entry.execution_entry_id'
        ) = commitment.execution_entry_id
        AND json_extract(
            commitment.commitment_json,
            '$.execution_entry.sample_id'
        ) = commitment.sample_id
        AND json_extract(commitment.commitment_json, '$.ledger_sequence')
            = commitment.ledger_sequence
        AND json_extract(
            commitment.commitment_json,
            '$.observation_authority_id'
        ) = commitment.observation_authority_id
        AND json_extract(commitment.commitment_json, '$.sample_id')
            = commitment.sample_id
        AND json_extract(commitment.commitment_json, '$.execution_entry_id')
            = commitment.execution_entry_id
        AND json_extract(
            commitment.commitment_json,
            '$.sample_execution_record_id'
        ) = commitment.sample_execution_record_id
        AND json_extract(
            commitment.commitment_json,
            '$.sample_execution_record_document_sha256'
        ) = commitment.sample_execution_record_document_sha256
        AND json_extract(
            commitment.commitment_json,
            '$.sample_execution_record_size_bytes'
        ) = commitment.sample_execution_record_size_bytes
        AND json_extract(
            commitment.commitment_json,
            '$.pending_sample_commitment_authority_id'
        ) = commitment.pending_sample_commitment_authority_id
        AND json_extract(
            commitment.commitment_json,
            '$.sample_execution_record'
        ) = commitment.sample_execution_record_json
        AND json_extract(commitment.commitment_json, '$.execution_entry')
            = json_extract(
                commitment.sample_execution_record_json,
                '$.execution_entry'
            )
        AND json_type(commitment.sample_execution_record_json, '$') = 'object'
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.schema_version'
        ) = 'm6-upgrade-sample-execution-record-v2'
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.execution_scope_authority_id'
        ) = commitment.execution_scope_authority_id
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.candidate_run_id'
        ) = commitment.run_id
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.command_id'
        ) = commitment.command_id
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.execution_dataset_snapshot_id'
        ) = commitment.execution_dataset_snapshot_id
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.execution_entry_id'
        ) = commitment.execution_entry_id
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.sample_id'
        ) = commitment.sample_id
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.ledger_sequence'
        ) = commitment.ledger_sequence
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.observation_authority_id'
        ) = commitment.observation_authority_id
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.sample_execution_record_id'
        ) = commitment.sample_execution_record_id
        AND json_type(
            commitment.sample_execution_record_json,
            '$.artifact_links'
        ) = 'array'
        AND json_array_length(
            commitment.sample_execution_record_json,
            '$.artifact_links'
        ) BETWEEN 1 AND 20000
        AND json_extract(
            commitment.sample_execution_record_json,
            '$.artifact_link_count'
        ) = json_array_length(
            commitment.sample_execution_record_json,
            '$.artifact_links'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM json_each(
                commitment.sample_execution_record_json,
                '$.artifact_links'
            ) AS candidate
            WHERE json_type(candidate.value, '$.ordinal') IS NOT 'integer'
               OR json_extract(candidate.value, '$.ordinal')
                   IS NOT CAST(candidate.key AS INTEGER)
               OR json_type(candidate.value, '$.usage') IS NOT 'text'
               OR json_extract(candidate.value, '$.usage')
                   NOT IN ('CONSUMED', 'PRODUCED')
               OR json_type(candidate.value, '$.artifact_link_id') IS NOT 'text'
               OR length(json_extract(candidate.value, '$.artifact_link_id')) <> 64
               OR json_type(candidate.value, '$.artifact') IS NOT 'object'
               OR json_extract(candidate.value, '$.artifact.schema_version')
                   IS NOT 'm6-upgrade-physical-artifact-ref-v1'
        )
        AND length(CAST(commitment.sample_execution_record_json AS BLOB))
            = commitment.sample_execution_record_size_bytes
        AND length(CAST(commitment.commitment_json AS BLOB))
            = commitment.size_bytes
    ) IS NOT TRUE
);

-- Revalidate every historical seal as an exact closure of its scope, record
-- inventory, physical inventory, candidate-case inventory, and protocol wire.
INSERT INTO m6_v3_observation_backed_ledger_preflight(valid)
SELECT 0
WHERE EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_ledger_seals AS seal
    LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
      ON protocol.run_id = seal.run_id
     AND protocol.execution_scope_authority_id
         = seal.execution_scope_authority_id
    WHERE (
        (
            (
                protocol.protocol_version = 'v1'
                AND seal.seal_schema_version = 'v1'
                AND json_extract(seal.seal_json, '$.schema_version')
                    = 'm6-upgrade-execution-ledger-seal-v1'
                AND NOT EXISTS (
                    SELECT 1
                    FROM m6_upgrade_sample_executions AS sample
                    WHERE sample.run_id = seal.run_id
                      AND (
                          sample.record_schema_version <> 'v1'
                          OR sample.observation_authority_id IS NOT NULL
                      )
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM m6_upgrade_sample_execution_observations AS observation
                    WHERE observation.run_id = seal.run_id
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM m6_upgrade_pending_sample_commitments AS commitment
                    WHERE commitment.run_id = seal.run_id
                )
            )
            OR (
                protocol.protocol_version = 'v2'
                AND seal.seal_schema_version = 'v2'
                AND json_extract(seal.seal_json, '$.schema_version')
                    = 'm6-upgrade-execution-ledger-seal-v2'
                AND NOT EXISTS (
                    SELECT 1
                    FROM m6_upgrade_sample_executions AS sample
                    WHERE sample.run_id = seal.run_id
                      AND (
                          sample.record_schema_version <> 'v2'
                          OR sample.observation_authority_id IS NULL
                      )
                )
                AND (
                    SELECT COUNT(*)
                    FROM m6_upgrade_sample_execution_observations AS observation
                    WHERE observation.run_id = seal.run_id
                ) = seal.sample_execution_count
                AND (
                    SELECT COUNT(*)
                    FROM m6_upgrade_pending_sample_commitments AS commitment
                    WHERE commitment.run_id = seal.run_id
                ) = seal.sample_execution_count
            )
        )
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_execution_scopes AS scope
            JOIN runs AS run ON run.run_id = scope.run_id
            WHERE scope.run_id = seal.run_id
              AND scope.execution_scope_authority_id
                  = seal.execution_scope_authority_id
              AND scope.document_sha256
                  = seal.execution_scope_document_sha256
              AND scope.size_bytes = seal.execution_scope_size_bytes
              AND scope.expected_sample_count = seal.sample_execution_count
              AND run.audit_head_sequence = seal.source_audit_head_sequence
              AND run.audit_head_hash = seal.source_audit_head_hash
              AND json(scope.scope_json) = json_extract(
                  seal.seal_json,
                  '$.execution_scope'
              )
        )
        AND (
            seal.source_audit_head_sequence = -1
            OR EXISTS (
                SELECT 1
                FROM audit_entries AS audit
                WHERE audit.run_id = seal.run_id
                  AND audit.sequence = seal.source_audit_head_sequence
                  AND audit.entry_hash = seal.source_audit_head_hash
            )
        )
        AND (
            SELECT COUNT(*)
            FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = seal.run_id
        ) = seal.sample_execution_count
        AND (
            SELECT MAX(sample.ledger_sequence)
            FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = seal.run_id
        ) = seal.ledger_preseal_sequence
        AND EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = seal.run_id
              AND sample.ledger_sequence = seal.ledger_preseal_sequence
              AND sample.sample_execution_record_id = seal.ledger_preseal_hash
        )
        AND seal.ledger_head_sequence = seal.sample_execution_count
        AND seal.ledger_preseal_sequence = seal.sample_execution_count - 1
        AND (
            SELECT COUNT(*)
            FROM m6_upgrade_sample_artifact_links AS link
            WHERE link.run_id = seal.run_id
        ) = seal.artifact_link_count
        AND (
            SELECT COALESCE(SUM(sample.artifact_link_count), 0)
            FROM m6_upgrade_sample_executions AS sample
            WHERE sample.run_id = seal.run_id
        ) = seal.artifact_link_count
        AND NOT EXISTS (
            SELECT 1
            FROM m6_upgrade_physical_artifact_refs AS ref
            WHERE ref.run_id = seal.run_id
              AND NOT EXISTS (
                  SELECT 1
                  FROM m6_upgrade_sample_artifact_links AS link
                  WHERE link.run_id = ref.run_id
                    AND link.artifact_ref_id = ref.artifact_ref_id
              )
        )
        AND (
            SELECT COUNT(*)
            FROM cases AS current_case
            WHERE current_case.run_id = seal.run_id
        ) = seal.candidate_case_count
        AND NOT EXISTS (
            SELECT 1
            FROM cases AS current_case
            JOIN case_versions AS version
              ON version.run_id = current_case.run_id
             AND version.case_id = current_case.case_id
             AND version.revision = current_case.current_revision
            WHERE current_case.run_id = seal.run_id
              AND NOT EXISTS (
                  SELECT 1
                  FROM m6_upgrade_sample_executions AS sample
                  WHERE sample.run_id = current_case.run_id
                    AND sample.case_id = current_case.case_id
                    AND sample.case_revision = current_case.current_revision
                    AND sample.case_document_sha256 = version.document_sha256
                    AND sample.case_audit_sequence = version.audit_sequence
              )
        )
        AND json_type(seal.seal_json, '$') = 'object'
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
        AND json_type(seal.seal_json, '$.sample_executions') = 'array'
        AND json_array_length(seal.seal_json, '$.sample_executions')
            = seal.sample_execution_count
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

DROP TABLE m6_v3_observation_backed_ledger_preflight;

DROP TRIGGER m6_upgrade_sample_executions_validate;
DROP TRIGGER m6_upgrade_pending_sample_commitments_validate;
DROP TRIGGER m6_upgrade_sample_executions_validate_observation_backing;
DROP TRIGGER m6_upgrade_execution_ledger_seals_validate_schema_version;

CREATE TRIGGER m6_upgrade_sample_executions_validate
BEFORE INSERT ON m6_upgrade_sample_executions
WHEN NOT EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_executions AS existing
    WHERE existing.run_id = NEW.run_id
      AND (
          existing.ledger_sequence = NEW.ledger_sequence
          OR existing.execution_entry_id = NEW.execution_entry_id
          OR existing.sample_id = NEW.sample_id
      )
)
AND NOT (
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
            JOIN m6_upgrade_execution_ledger_protocols AS protocol
              ON protocol.run_id = version.run_id
             AND protocol.execution_scope_authority_id
                 = NEW.execution_scope_authority_id
            WHERE version.run_id = NEW.run_id
              AND version.case_id = NEW.case_id
              AND version.revision = NEW.case_revision
              AND version.document_sha256 = NEW.case_document_sha256
              AND version.audit_sequence = NEW.case_audit_sequence
              AND audit.entry_hash = NEW.case_audit_entry_hash
              AND audit.object_kind = 'CASE'
              AND audit.object_id = NEW.case_id
              AND audit.after_sha256 = NEW.case_document_sha256
              AND protocol.protocol_version IN ('v1', 'v2')
        )
        OR EXISTS (
            SELECT 1
            FROM m6_upgrade_sample_execution_observations AS observation
            JOIN m6_upgrade_execution_ledger_protocols AS protocol
              ON protocol.run_id = observation.run_id
             AND protocol.execution_scope_authority_id
                 = observation.execution_scope_authority_id
            WHERE observation.run_id = NEW.run_id
              AND observation.execution_scope_authority_id
                  = NEW.execution_scope_authority_id
              AND observation.ledger_sequence = NEW.ledger_sequence
              AND observation.observation_authority_id
                  = NEW.observation_authority_id
              AND observation.execution_entry_id = NEW.execution_entry_id
              AND observation.sample_id = NEW.sample_id
              AND observation.outcome = NEW.outcome
              AND observation.case_id IS NEW.case_id
              AND observation.case_revision IS NEW.case_revision
              AND observation.case_document_sha256
                  IS NEW.case_document_sha256
              AND observation.case_audit_sequence IS NEW.case_audit_sequence
              AND observation.case_audit_entry_hash
                  IS NEW.case_audit_entry_hash
              AND protocol.protocol_version = 'v3'
              AND json_extract(
                  observation.observation_json,
                  '$.candidate_case.case_binding_id'
              ) IS json_extract(
                  NEW.record_json,
                  '$.candidate_case.case_binding_id'
              )
              AND (
                  (
                      protocol.protocol_version = 'v2'
                      AND observation.observation_schema_version = 'v1'
                      AND json_extract(
                          observation.observation_json,
                          '$.schema_version'
                      ) = 'm6-upgrade-sample-execution-observation-authority-v1'
                      AND json_type(
                          observation.observation_json,
                          '$.selected_case_audit_anchor'
                      ) IS NULL
                      AND observation.selected_case_audit_anchor_id IS NULL
                      AND observation.case_audit_action IS NULL
                      AND observation.case_audit_object_kind IS NULL
                      AND observation.case_audit_object_id IS NULL
                  )
                  OR (
                      protocol.protocol_version = 'v3'
                      AND observation.observation_schema_version = 'v2'
                      AND json_extract(
                          observation.observation_json,
                          '$.schema_version'
                      ) = 'm6-upgrade-sample-execution-observation-authority-v2'
                      AND (
                          (
                              observation.outcome = 'NO_CASE'
                              AND observation.selected_case_audit_anchor_id IS NULL
                              AND observation.case_audit_action IS NULL
                              AND observation.case_audit_object_kind IS NULL
                              AND observation.case_audit_object_id IS NULL
                              AND json_type(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor'
                              ) = 'null'
                          )
                          OR (
                              observation.outcome = 'CASE_REPLAYED'
                              AND observation.selected_case_audit_anchor_id IS NOT NULL
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.selected_case_audit_anchor_id'
                              ) = observation.selected_case_audit_anchor_id
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.candidate_case_binding_id'
                              ) = json_extract(
                                  observation.observation_json,
                                  '$.candidate_case.case_binding_id'
                              )
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.action'
                              ) = observation.case_audit_action
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.object_ref.kind'
                              ) = observation.case_audit_object_kind
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.object_ref.artifact_id'
                              ) = observation.case_audit_object_id
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
                                    AND audit.entry_hash
                                        = observation.case_audit_entry_hash
                                    AND audit.action = observation.case_audit_action
                                    AND audit.object_kind
                                        = observation.case_audit_object_kind
                                    AND audit.object_id
                                        = observation.case_audit_object_id
                                    AND audit.after_sha256
                                        = observation.case_document_sha256
                                    AND version.audit_sequence > (
                                        SELECT scope.execution_start_audit_head_sequence
                                        FROM m6_upgrade_execution_scopes AS scope
                                        WHERE scope.run_id = observation.run_id
                                          AND scope.execution_scope_authority_id
                                              = observation.execution_scope_authority_id
                                    )
                              )
                          )
                      )
                  )
              )
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

CREATE TRIGGER m6_upgrade_pending_sample_commitments_validate
BEFORE INSERT ON m6_upgrade_pending_sample_commitments
WHEN NOT EXISTS (
    SELECT 1
    FROM m6_upgrade_pending_sample_commitments AS existing
    WHERE existing.pending_sample_commitment_authority_id
              = NEW.pending_sample_commitment_authority_id
       OR existing.observation_authority_id = NEW.observation_authority_id
       OR existing.sample_execution_record_id = NEW.sample_execution_record_id
       OR (
          existing.run_id = NEW.run_id
          AND (
              existing.execution_scope_authority_id
                  <> NEW.execution_scope_authority_id
              OR existing.ledger_sequence = NEW.ledger_sequence
              OR existing.execution_entry_id = NEW.execution_entry_id
              OR existing.sample_id = NEW.sample_id
          )
      )
)
AND (
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
        JOIN m6_upgrade_execution_ledger_protocols AS protocol
          ON protocol.run_id = observation.run_id
         AND protocol.execution_scope_authority_id
             = observation.execution_scope_authority_id
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
          AND (
              (
                  protocol.protocol_version = 'v2'
                  AND observation.observation_schema_version = 'v1'
                  AND json_extract(
                      observation.observation_json,
                      '$.schema_version'
                  ) = 'm6-upgrade-sample-execution-observation-authority-v1'
                  AND json_type(
                      observation.observation_json,
                      '$.selected_case_audit_anchor'
                  ) IS NULL
                  AND observation.selected_case_audit_anchor_id IS NULL
                  AND observation.case_audit_action IS NULL
                  AND observation.case_audit_object_kind IS NULL
                  AND observation.case_audit_object_id IS NULL
              )
              OR (
                  protocol.protocol_version = 'v3'
                  AND observation.observation_schema_version = 'v2'
                  AND json_extract(
                      observation.observation_json,
                      '$.schema_version'
                  ) = 'm6-upgrade-sample-execution-observation-authority-v2'
                  AND (
                      (
                          observation.outcome = 'NO_CASE'
                          AND observation.selected_case_audit_anchor_id IS NULL
                          AND observation.case_audit_action IS NULL
                          AND observation.case_audit_object_kind IS NULL
                          AND observation.case_audit_object_id IS NULL
                          AND json_type(
                              observation.observation_json,
                              '$.selected_case_audit_anchor'
                          ) = 'null'
                      )
                      OR (
                          observation.outcome = 'CASE_REPLAYED'
                          AND observation.selected_case_audit_anchor_id IS NOT NULL
                          AND json_extract(
                              observation.observation_json,
                              '$.selected_case_audit_anchor.selected_case_audit_anchor_id'
                          ) = observation.selected_case_audit_anchor_id
                          AND json_extract(
                              observation.observation_json,
                              '$.selected_case_audit_anchor.candidate_case_binding_id'
                          ) = json_extract(
                              observation.observation_json,
                              '$.candidate_case.case_binding_id'
                          )
                          AND json_extract(
                              observation.observation_json,
                              '$.selected_case_audit_anchor.action'
                          ) = observation.case_audit_action
                          AND json_extract(
                              observation.observation_json,
                              '$.selected_case_audit_anchor.object_ref.kind'
                          ) = observation.case_audit_object_kind
                          AND json_extract(
                              observation.observation_json,
                              '$.selected_case_audit_anchor.object_ref.artifact_id'
                          ) = observation.case_audit_object_id
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
                                AND audit.entry_hash
                                    = observation.case_audit_entry_hash
                                AND audit.action = observation.case_audit_action
                                AND audit.object_kind
                                    = observation.case_audit_object_kind
                                AND audit.object_id
                                    = observation.case_audit_object_id
                                AND audit.after_sha256
                                    = observation.case_document_sha256
                                AND version.audit_sequence > (
                                    SELECT scope.execution_start_audit_head_sequence
                                    FROM m6_upgrade_execution_scopes AS scope
                                    WHERE scope.run_id = observation.run_id
                                      AND scope.execution_scope_authority_id
                                          = observation.execution_scope_authority_id
                                )
                          )
                      )
                  )
              )
          )
          AND (
              protocol.protocol_version <> 'v3'
              OR json_extract(
                  observation.observation_json,
                  '$.candidate_case.case_binding_id'
              ) IS json_extract(
                  NEW.sample_execution_record_json,
                  '$.candidate_case.case_binding_id'
              )
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
WHEN NOT EXISTS (
    SELECT 1
    FROM m6_upgrade_sample_executions AS existing
    WHERE existing.run_id = NEW.run_id
      AND (
          existing.ledger_sequence = NEW.ledger_sequence
          OR existing.execution_entry_id = NEW.execution_entry_id
          OR existing.sample_id = NEW.sample_id
      )
)
AND (
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
              AND protocol.protocol_version IN ('v2', 'v3')
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
            JOIN m6_upgrade_execution_ledger_protocols AS protocol
              ON protocol.run_id = observation.run_id
             AND protocol.execution_scope_authority_id
                 = observation.execution_scope_authority_id
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
              AND (
                  (
                      protocol.protocol_version = 'v2'
                      AND observation.observation_schema_version = 'v1'
                      AND json_extract(
                          observation.observation_json,
                          '$.schema_version'
                      ) = 'm6-upgrade-sample-execution-observation-authority-v1'
                      AND json_type(
                          observation.observation_json,
                          '$.selected_case_audit_anchor'
                      ) IS NULL
                      AND observation.selected_case_audit_anchor_id IS NULL
                      AND observation.case_audit_action IS NULL
                      AND observation.case_audit_object_kind IS NULL
                      AND observation.case_audit_object_id IS NULL
                  )
                  OR (
                      protocol.protocol_version = 'v3'
                      AND observation.observation_schema_version = 'v2'
                      AND json_extract(
                          observation.observation_json,
                          '$.schema_version'
                      ) = 'm6-upgrade-sample-execution-observation-authority-v2'
                      AND (
                          (
                              observation.outcome = 'NO_CASE'
                              AND observation.selected_case_audit_anchor_id IS NULL
                              AND observation.case_audit_action IS NULL
                              AND observation.case_audit_object_kind IS NULL
                              AND observation.case_audit_object_id IS NULL
                              AND json_type(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor'
                              ) = 'null'
                          )
                          OR (
                              observation.outcome = 'CASE_REPLAYED'
                              AND observation.selected_case_audit_anchor_id IS NOT NULL
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.selected_case_audit_anchor_id'
                              ) = observation.selected_case_audit_anchor_id
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.candidate_case_binding_id'
                              ) = json_extract(
                                  observation.observation_json,
                                  '$.candidate_case.case_binding_id'
                              )
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.action'
                              ) = observation.case_audit_action
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.object_ref.kind'
                              ) = observation.case_audit_object_kind
                              AND json_extract(
                                  observation.observation_json,
                                  '$.selected_case_audit_anchor.object_ref.artifact_id'
                              ) = observation.case_audit_object_id
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
                                    AND audit.entry_hash
                                        = observation.case_audit_entry_hash
                                    AND audit.action = observation.case_audit_action
                                    AND audit.object_kind
                                        = observation.case_audit_object_kind
                                    AND audit.object_id
                                        = observation.case_audit_object_id
                                    AND audit.after_sha256
                                        = observation.case_document_sha256
                                    AND version.audit_sequence > (
                                        SELECT scope.execution_start_audit_head_sequence
                                        FROM m6_upgrade_execution_scopes AS scope
                                        WHERE scope.run_id = observation.run_id
                                          AND scope.execution_scope_authority_id
                                              = observation.execution_scope_authority_id
                                    )
                              )
                          )
                      )
                  )
              )
              AND (
                  protocol.protocol_version <> 'v3'
                  OR json_extract(
                      observation.observation_json,
                      '$.candidate_case.case_binding_id'
                  ) IS json_extract(
                      NEW.record_json,
                      '$.candidate_case.case_binding_id'
                  )
              )
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
WHEN NOT EXISTS (
    SELECT 1
    FROM m6_upgrade_execution_ledger_seals AS existing
    WHERE existing.run_id = NEW.run_id
       OR existing.ledger_seal_authority_id = NEW.ledger_seal_authority_id
       OR existing.document_sha256 = NEW.document_sha256
)
AND (
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
              AND protocol.protocol_version IN ('v2', 'v3')
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
                  JOIN m6_upgrade_execution_ledger_protocols AS protocol
                    ON protocol.run_id = observation.run_id
                   AND protocol.execution_scope_authority_id
                       = observation.execution_scope_authority_id
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
                    AND (
                        (
                            protocol.protocol_version = 'v2'
                            AND observation.observation_schema_version = 'v1'
                            AND json_extract(
                                observation.observation_json,
                                '$.schema_version'
                            ) = 'm6-upgrade-sample-execution-observation-authority-v1'
                            AND json_type(
                                observation.observation_json,
                                '$.selected_case_audit_anchor'
                            ) IS NULL
                            AND observation.selected_case_audit_anchor_id IS NULL
                            AND observation.case_audit_action IS NULL
                            AND observation.case_audit_object_kind IS NULL
                            AND observation.case_audit_object_id IS NULL
                        )
                        OR (
                            protocol.protocol_version = 'v3'
                            AND observation.observation_schema_version = 'v2'
                            AND json_extract(
                                observation.observation_json,
                                '$.schema_version'
                            ) = 'm6-upgrade-sample-execution-observation-authority-v2'
                            AND (
                                (
                                    observation.outcome = 'NO_CASE'
                                    AND observation.selected_case_audit_anchor_id IS NULL
                                    AND observation.case_audit_action IS NULL
                                    AND observation.case_audit_object_kind IS NULL
                                    AND observation.case_audit_object_id IS NULL
                                    AND json_type(
                                        observation.observation_json,
                                        '$.selected_case_audit_anchor'
                                    ) = 'null'
                                )
                                OR (
                                    observation.outcome = 'CASE_REPLAYED'
                                    AND observation.selected_case_audit_anchor_id IS NOT NULL
                                    AND json_extract(
                                        observation.observation_json,
                                        '$.selected_case_audit_anchor.selected_case_audit_anchor_id'
                                    ) = observation.selected_case_audit_anchor_id
                                    AND json_extract(
                                        observation.observation_json,
                                        '$.selected_case_audit_anchor.candidate_case_binding_id'
                                    ) = json_extract(
                                        observation.observation_json,
                                        '$.candidate_case.case_binding_id'
                                    )
                                    AND json_extract(
                                        observation.observation_json,
                                        '$.selected_case_audit_anchor.action'
                                    ) = observation.case_audit_action
                                    AND json_extract(
                                        observation.observation_json,
                                        '$.selected_case_audit_anchor.object_ref.kind'
                                    ) = observation.case_audit_object_kind
                                    AND json_extract(
                                        observation.observation_json,
                                        '$.selected_case_audit_anchor.object_ref.artifact_id'
                                    ) = observation.case_audit_object_id
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
                                          AND audit.entry_hash
                                              = observation.case_audit_entry_hash
                                          AND audit.action = observation.case_audit_action
                                          AND audit.object_kind
                                              = observation.case_audit_object_kind
                                          AND audit.object_id
                                              = observation.case_audit_object_id
                                          AND audit.after_sha256
                                              = observation.case_document_sha256
                                          AND version.audit_sequence > (
                                              SELECT scope.execution_start_audit_head_sequence
                                              FROM m6_upgrade_execution_scopes AS scope
                                              WHERE scope.run_id = observation.run_id
                                                AND scope.execution_scope_authority_id
                                                    = observation.execution_scope_authority_id
                                          )
                                    )
                                )
                            )
                        )
                    )
                    AND (
                        protocol.protocol_version <> 'v3'
                        OR json_extract(
                            observation.observation_json,
                            '$.candidate_case.case_binding_id'
                        ) IS json_extract(
                            sample.record_json,
                            '$.candidate_case.case_binding_id'
                        )
                    )
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
