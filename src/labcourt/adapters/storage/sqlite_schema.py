"""Shared immutable SQLite schema identities used by readers and writers."""

from __future__ import annotations

import sqlite3

M3_LATEST_SCHEMA_VERSION = 7
M3_REQUIRED_MIGRATION_VERSIONS = frozenset({4, 5, 6, 7})
M3_AUTHORITY_HARDENING_OBJECTS = frozenset(
    {
        ("index", "uq_runs_filesystem_identity_nocase"),
        ("trigger", "runs_portable_filesystem_identity_insert"),
        ("trigger", "backlog_item_versions_validate_transition"),
    }
)

M4_LATEST_SCHEMA_VERSION = 8
M4_REQUIRED_MIGRATION_VERSIONS = frozenset({4, 5, 6, 7, 8})
M4_AUTHORITY_TABLES = frozenset(
    {
        "m4_acquired_crops",
        "m4_acquisition_execution_claims",
        "m4_acquisition_execution_publications",
        "m4_acquisition_requests",
        "m4_backlog_completion_receipts",
        "m4_evidence_pack_derivations",
        "m4_hearing_checkpoints",
        "m4_hearing_backlog_retry_outcomes",
        "m4_hearing_human_review_receipts",
        "m4_hearing_rounds",
        "m4_hearing_cycles",
        "m4_hearing_verdict_bindings",
        "m4_hearings",
        "m4_hearing_usage_receipts",
        "m4_hearing_strict_parse_failure_attempts",
        "m4_hearing_strict_parse_failure_proofs",
        "m4_model_cache",
        "m4_model_call_claims",
        "m4_model_call_failure_authorities",
        "m4_model_parse_receipts",
        "m4_model_responses",
        "m4_parsed_hearing_outputs",
        "m4_precedent_retrieval_receipts",
        "m4_rework_receipts",
        "m4_tool_execution_manifests",
        "m4_tool_execution_receipts",
    }
)
M4_AUTHORITY_INDEXES = frozenset(
    {
        "idx_m4_acquired_crops_request",
        "idx_m4_acquisition_claims_active_expiry",
        "idx_m4_acquisition_publications_hearing",
        "idx_m4_acquisition_round",
        "idx_m4_backlog_receipts_item_attempt",
        "idx_m4_cache_round_role",
        "idx_m4_claims_hearing_reservation",
        "idx_m4_checkpoints_hearing_version",
        "idx_m4_failure_authorities_backlog",
        "idx_m4_hearing_cycles_sequence",
        "idx_m4_human_review_receipts_session",
        "idx_m4_backlog_outcomes_source",
        "idx_m4_model_claims_active_expiry",
        "idx_m4_model_responses_round_role",
        "idx_m4_pack_derivations_case_version",
        "idx_m4_parse_receipts_response",
        "idx_m4_parsed_outputs_round_role",
        "idx_m4_retrieval_round",
        "idx_m4_hearing_rounds_hearing",
        "idx_m4_rework_hearing",
        "idx_m4_tool_receipts_round",
        "idx_m4_usage_hearing",
        "idx_m4_strict_attempts_backlog_generation",
        "idx_m4_strict_proofs_lease",
        "idx_m4_verdict_bindings_case_version",
        "uq_m4_hearings_review_start",
        "uq_m4_hearings_screening_start",
        "uq_m4_model_claims_backlog_generation",
        "uq_m4_model_claims_initial_generation",
    }
)
_M4_FULLY_APPEND_ONLY_TABLES = M4_AUTHORITY_TABLES - {
    "m4_acquisition_execution_claims",
    "m4_model_call_claims",
}
M4_AUTHORITY_TRIGGERS = frozenset(
    {
        f"{table}_{operation}"
        for table in _M4_FULLY_APPEND_ONLY_TABLES
        for operation in ("no_replace", "no_update", "no_delete")
    }
    | {
        "m4_acquired_crops_validate_authority",
        "m4_acquisition_execution_claims_controlled_update",
        "m4_acquisition_execution_claims_no_delete",
        "m4_acquisition_execution_claims_no_replace",
        "m4_acquisition_execution_claims_validate_authority",
        "m4_acquisition_execution_publications_validate_authority",
        "m4_acquisition_requests_validate_authority",
        "m4_backlog_completion_receipts_validate_authority",
        "m4_evidence_pack_derivations_validate_authority",
        "m4_hearing_rounds_validate_authority",
        "m4_hearing_cycles_validate_transition",
        "m4_hearing_verdict_bindings_validate_authority",
        "m4_hearing_checkpoints_validate_artifacts",
        "m4_hearing_checkpoints_validate_trace",
        "m4_hearing_checkpoints_validate_transition",
        "m4_hearing_backlog_retry_outcomes_validate_authority",
        "m4_hearing_human_review_receipts_validate_authority",
        "m4_hearing_strict_parse_failure_attempts_validate_authority",
        "m4_hearing_strict_parse_failure_proofs_validate_authority",
        "m4_hearing_usage_receipts_validate_scope",
        "m4_hearings_validate_scope",
        "m4_model_call_claims_controlled_update",
        "m4_model_call_claims_validate_reservation",
        "m4_model_responses_validate_claim",
        "m4_model_call_claims_no_delete",
        "m4_model_call_claims_no_replace",
        "m4_model_call_failure_authorities_validate",
        "m4_model_parse_receipts_validate_scope",
        "m4_parsed_hearing_outputs_validate_scope",
        "m4_precedent_retrieval_receipts_validate_scope",
        "m4_rework_receipts_validate_authority",
        "m4_tool_execution_manifests_validate_authority",
        "m4_tool_execution_receipts_validate_authority",
    }
)
M4_AUTHORITY_OBJECTS = frozenset(
    {("table", name) for name in M4_AUTHORITY_TABLES}
    | {("index", name) for name in M4_AUTHORITY_INDEXES}
    | {("trigger", name) for name in M4_AUTHORITY_TRIGGERS}
)

M5_LATEST_SCHEMA_VERSION = 9
M5_REQUIRED_MIGRATION_VERSIONS = frozenset({4, 5, 6, 7, 8, 9})
M5_AUTHORITY_TABLES = frozenset(
    {
        "alert_cooldowns",
        "alert_channel_capabilities",
        "alert_dispatch_attempts",
        "alert_dispatch_receipts",
        "alert_outbox",
        "alert_rescissions",
        "alerts",
        "appeal_resolution_commit_receipts",
        "appeal_resolution_receipts",
        "appeals",
        "dataset_artifacts",
        "dataset_crop_snapshots",
        "dataset_registration_snapshots",
        "m5_immediate_safety_deliveries",
        "m5_precedent_application_batches",
        "m5_precedent_causal_events",
        "m5_precedent_exposures",
        "m5_training_causal_events",
        "precedent_citations",
        "precedent_conflict_batch_receipts",
        "precedent_conflict_batches",
        "precedent_embeddings",
        "precedent_lifecycle_receipts",
        "precedents",
        "strong_training_label_provenance_receipts",
        "training_labels",
        "verdict_rescissions",
    }
)
M5_AUTHORITY_INDEXES = frozenset(
    {
        "idx_alert_cooldowns_lookup",
        "idx_alert_dispatch_attempts_outbox",
        "idx_alert_dispatch_receipts_outbox",
        "idx_alert_outbox_case",
        "idx_alert_rescissions_case",
        "idx_alerts_case",
        "idx_appeal_resolution_commit_case",
        "idx_appeal_resolution_case",
        "idx_appeals_case_current",
        "idx_appeals_status",
        "idx_dataset_artifacts_content",
        "idx_dataset_crop_snapshots_registration",
        "idx_dataset_registration_snapshots_cut",
        "idx_m5_immediate_safety_deliveries_incident",
        "idx_m5_precedent_causal_events_authority_watermark",
        "idx_m5_precedent_application_batches_case",
        "idx_m5_precedent_exposures_hearing",
        "idx_m5_training_causal_events_kind",
        "idx_precedent_citations_case",
        "idx_precedent_citations_precedent",
        "idx_precedent_embeddings_manifest",
        "idx_precedent_lifecycle_primary",
        "idx_strong_training_label_provenance_resolution",
        "uq_precedent_lifecycle_appeal_present_prior",
        "idx_precedents_retrieval",
        "idx_precedents_source_case",
        "idx_training_labels_crop",
        "idx_training_labels_quality",
        "idx_verdict_rescissions_case",
        "uq_alert_dispatch_receipts_success_alert",
        "uq_alert_dispatch_receipts_success_outbox",
        "uq_alert_dispatch_receipts_terminal_outbox",
        "uq_alerts_alert_id",
        "uq_case_versions_revision_document_sha256",
        "uq_evidence_packs_version_document_sha256",
        "uq_m5_training_causal_events_exact_head",
        "uq_training_labels_strong_provenance_binding",
        "uq_precedents_automatic_source_case",
        "uq_precedent_citations_application_binding",
    }
)
M5_AUTHORITY_TRIGGERS = frozenset(
    {
        f"{table}_{operation}"
        for table in M5_AUTHORITY_TABLES
        for operation in ("no_replace", "no_update", "no_delete")
    }
    | {
        "alert_cooldowns_validate_contiguous_revision",
        "alert_dispatch_attempts_validate_contiguous_attempt",
        "m5_immediate_safety_deliveries_reject_uncertified_insert",
        "appeals_validate_contiguous_version",
        "appeals_validate_predecessor",
        "appeal_resolution_commit_receipts_validate_training_provenance_closure",
        "dataset_artifacts_validate_registration_snapshot",
        "dataset_crop_snapshots_validate_source",
        "dataset_registration_snapshots_validate_source",
        "precedents_validate_contiguous_revision",
        "strong_training_label_provenance_receipts_validate_source",
        "m5_precedent_causal_events_validate_contiguous_sequence",
        "m5_precedent_causal_events_validate_predecessor",
        "m5_precedent_causal_events_validate_semantic_order",
        "m5_precedent_causal_events_validate_source",
        "m5_training_causal_events_validate_contiguous_sequence",
        "m5_training_causal_events_validate_predecessor",
        "m5_training_causal_events_validate_source",
        "precedent_conflict_batches_validate_causal_cut",
        "training_labels_require_causal_event",
    }
)
M5_AUTHORITY_OBJECTS = frozenset(
    {("table", name) for name in M5_AUTHORITY_TABLES}
    | {("index", name) for name in M5_AUTHORITY_INDEXES}
    | {("trigger", name) for name in M5_AUTHORITY_TRIGGERS}
)

M6_LATEST_SCHEMA_VERSION = 14
M6_REQUIRED_MIGRATION_VERSIONS = frozenset({4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14})
M6_UPGRADE_EXECUTION_OBSERVATION_TABLES = frozenset(
    {
        "m6_upgrade_sample_execution_observations",
        "m6_upgrade_observed_non_model_artifacts",
        "m6_upgrade_observed_model_calls",
    }
)
M6_UPGRADE_LEDGER_TABLES = (
    frozenset(
        {
            "m6_upgrade_execution_scopes",
            "m6_upgrade_execution_ledger_protocols",
            "m6_upgrade_physical_artifact_refs",
            "m6_upgrade_sample_artifact_links",
            "m6_upgrade_sample_executions",
            "m6_upgrade_execution_ledger_seals",
            "m6_upgrade_pending_sample_commitments",
        }
    )
    | M6_UPGRADE_EXECUTION_OBSERVATION_TABLES
)
M6_UPGRADE_EXECUTION_OBSERVATION_INDEXES = frozenset(
    {
        "uq_m6_upgrade_execution_observation_id",
        "uq_m6_upgrade_execution_observation_entry",
        "uq_m6_upgrade_execution_observation_sample",
        "uq_m6_upgrade_observed_non_model_identity",
        "uq_m6_upgrade_observed_model_request",
    }
)
M6_UPGRADE_LEDGER_INDEXES = (
    frozenset(
        {
            "uq_runs_m6_audit_cut",
            "uq_run_manifests_m6_document_cut",
            "uq_case_versions_m6_binding",
            "uq_audit_entries_m6_binding",
            "uq_m6_upgrade_physical_artifact_key",
            "uq_m6_upgrade_pending_commitment_authority_id",
            "uq_m6_upgrade_pending_commitment_observation",
            "uq_m6_upgrade_pending_commitment_record",
            "uq_m6_upgrade_sample_execution_observation",
        }
    )
    | M6_UPGRADE_EXECUTION_OBSERVATION_INDEXES
)
M6_UPGRADE_EXECUTION_OBSERVATION_TRIGGERS = frozenset(
    {
        "m6_upgrade_sample_execution_observations_validate",
        "m6_upgrade_observed_non_model_artifacts_validate",
        "m6_upgrade_observed_model_calls_validate",
        "m6_upgrade_observations_require_global_inventory_budget",
    }
)
M6_UPGRADE_LEDGER_TRIGGERS = (
    frozenset(
        {
            f"{table}_{operation}"
            for table in M6_UPGRADE_LEDGER_TABLES
            for operation in ("no_replace", "no_update", "no_delete")
        }
        | {
            "audit_entries_m6_require_next",
            "m6_upgrade_execution_scopes_validate",
            "m6_upgrade_execution_scopes_require_complete_json",
            "m6_upgrade_execution_scopes_default_v1_protocol",
            "m6_upgrade_physical_artifact_refs_validate",
            "m6_upgrade_physical_artifact_refs_require_complete_json",
            "m6_upgrade_sample_artifact_links_validate",
            "m6_upgrade_sample_artifact_links_require_complete_json",
            "m6_upgrade_sample_executions_validate",
            "m6_upgrade_sample_executions_validate_observation_backing",
            "m6_upgrade_execution_ledger_seals_validate",
            "m6_upgrade_execution_ledger_seals_validate_schema_version",
            "m6_upgrade_execution_ledger_seals_no_cross_run_replace",
            "m6_upgrade_observations_require_closed_v2_prefix",
            "m6_upgrade_pending_sample_commitments_validate",
            "runs_m6_audit_head_matches_entry",
            "runs_m6_require_genesis_insert",
        }
    )
    | M6_UPGRADE_EXECUTION_OBSERVATION_TRIGGERS
)
M6_UPGRADE_LEDGER_OBJECTS = frozenset(
    {("table", name) for name in M6_UPGRADE_LEDGER_TABLES}
    | {("index", name) for name in M6_UPGRADE_LEDGER_INDEXES}
    | {("trigger", name) for name in M6_UPGRADE_LEDGER_TRIGGERS}
)


def m3_authority_hardening_installed(connection: sqlite3.Connection) -> bool:
    """Return whether migration 0007 and each security-bearing object exist."""

    migration = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = ?",
        (M3_LATEST_SCHEMA_VERSION,),
    ).fetchone()
    if migration is None:
        return False
    rows = connection.execute(
        """
        SELECT type, name
        FROM sqlite_master
        WHERE name IN (
            'uq_runs_filesystem_identity_nocase',
            'runs_portable_filesystem_identity_insert',
            'backlog_item_versions_validate_transition'
        )
        """
    ).fetchall()
    observed = {
        (str(row[0]), str(row[1]))
        for row in rows
        if isinstance(row[0], str) and isinstance(row[1], str)
    }
    return observed == M3_AUTHORITY_HARDENING_OBJECTS


def m4_hearing_authority_installed(connection: sqlite3.Connection) -> bool:
    """Return whether migration 0008 and every M4 safety object exist."""

    migration = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE version = ?",
        (M4_LATEST_SCHEMA_VERSION,),
    ).fetchone()
    if migration is None:
        return False
    names = sorted(name for _object_type, name in M4_AUTHORITY_OBJECTS)
    placeholders = ", ".join("?" for _name in names)
    rows = connection.execute(
        f"SELECT type, name FROM sqlite_master WHERE name IN ({placeholders})",
        names,
    ).fetchall()
    observed = {
        (str(row[0]), str(row[1]))
        for row in rows
        if isinstance(row[0], str) and isinstance(row[1], str)
    }
    return observed == M4_AUTHORITY_OBJECTS


def m5_authority_installed(connection: sqlite3.Connection) -> bool:
    """Return whether every M5 migration and immutable authority object exists."""

    rows = connection.execute(
        "SELECT version FROM schema_migrations WHERE version BETWEEN 4 AND 9"
    ).fetchall()
    observed_versions = frozenset(int(row[0]) for row in rows)
    if observed_versions != M5_REQUIRED_MIGRATION_VERSIONS:
        return False
    names = sorted(name for _object_type, name in M5_AUTHORITY_OBJECTS)
    placeholders = ", ".join("?" for _name in names)
    rows = connection.execute(
        f"SELECT type, name FROM sqlite_master WHERE name IN ({placeholders})",
        names,
    ).fetchall()
    observed = {
        (str(row[0]), str(row[1]))
        for row in rows
        if isinstance(row[0], str) and isinstance(row[1], str)
    }
    return observed == M5_AUTHORITY_OBJECTS


def m6_upgrade_ledger_installed(connection: sqlite3.Connection) -> bool:
    """Return whether migrations 0010--0014 and every M6 ledger object exist."""

    if not m5_authority_installed(connection):
        return False
    rows = connection.execute(
        "SELECT version FROM schema_migrations WHERE version BETWEEN 4 AND 14"
    ).fetchall()
    observed_versions = frozenset(int(row[0]) for row in rows)
    if observed_versions != M6_REQUIRED_MIGRATION_VERSIONS:
        return False
    names = sorted(name for _object_type, name in M6_UPGRADE_LEDGER_OBJECTS)
    placeholders = ", ".join("?" for _name in names)
    rows = connection.execute(
        f"SELECT type, name FROM sqlite_master WHERE name IN ({placeholders})",
        names,
    ).fetchall()
    observed = {
        (str(row[0]), str(row[1]))
        for row in rows
        if isinstance(row[0], str) and isinstance(row[1], str)
    }
    return observed == M6_UPGRADE_LEDGER_OBJECTS


__all__ = [
    "M3_AUTHORITY_HARDENING_OBJECTS",
    "M3_LATEST_SCHEMA_VERSION",
    "M3_REQUIRED_MIGRATION_VERSIONS",
    "M4_AUTHORITY_INDEXES",
    "M4_AUTHORITY_OBJECTS",
    "M4_AUTHORITY_TABLES",
    "M4_AUTHORITY_TRIGGERS",
    "M4_LATEST_SCHEMA_VERSION",
    "M4_REQUIRED_MIGRATION_VERSIONS",
    "M5_AUTHORITY_INDEXES",
    "M5_AUTHORITY_OBJECTS",
    "M5_AUTHORITY_TABLES",
    "M5_AUTHORITY_TRIGGERS",
    "M5_LATEST_SCHEMA_VERSION",
    "M5_REQUIRED_MIGRATION_VERSIONS",
    "M6_LATEST_SCHEMA_VERSION",
    "M6_REQUIRED_MIGRATION_VERSIONS",
    "M6_UPGRADE_EXECUTION_OBSERVATION_INDEXES",
    "M6_UPGRADE_EXECUTION_OBSERVATION_TABLES",
    "M6_UPGRADE_EXECUTION_OBSERVATION_TRIGGERS",
    "M6_UPGRADE_LEDGER_INDEXES",
    "M6_UPGRADE_LEDGER_OBJECTS",
    "M6_UPGRADE_LEDGER_TABLES",
    "M6_UPGRADE_LEDGER_TRIGGERS",
    "m3_authority_hardening_installed",
    "m4_hearing_authority_installed",
    "m5_authority_installed",
    "m6_upgrade_ledger_installed",
]
