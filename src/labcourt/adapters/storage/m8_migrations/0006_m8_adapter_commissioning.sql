CREATE TABLE m8_production_adapter_candidates (
    candidate_authority_id TEXT PRIMARY KEY CHECK (
        length(candidate_authority_id) = 64
        AND candidate_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    adapter_id TEXT NOT NULL CHECK (length(adapter_id) BETWEEN 1 AND 64),
    adapter_revision TEXT NOT NULL CHECK (length(adapter_revision) BETWEEN 1 AND 64),
    adapter_kind TEXT NOT NULL CHECK (adapter_kind IN (
        'DISASTER_RECOVERY', 'EXTERNAL_NOTIFICATION', 'OBSERVABILITY',
        'OIDC_IDENTITY', 'PHYSICAL_SENSOR', 'RTSP_CAMERA'
    )),
    campus_id TEXT NOT NULL CHECK (length(campus_id) BETWEEN 1 AND 64),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('CAMPUS_WIDE', 'LOCATIONS')),
    candidate_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(candidate_document_sha256) = 64
        AND candidate_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    registrar_actor_authority_id TEXT NOT NULL,
    registrar_actor_document_sha256 TEXT NOT NULL CHECK (
        length(registrar_actor_document_sha256) = 64
        AND registrar_actor_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    candidate_json TEXT NOT NULL CHECK (json_valid(candidate_json)),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    UNIQUE (adapter_id, adapter_revision),
    FOREIGN KEY (registrar_actor_authority_id)
        REFERENCES m8_actor_authorities(actor_authority_id)
) STRICT;

CREATE INDEX idx_m8_adapter_candidates_campus_kind
ON m8_production_adapter_candidates(campus_id, adapter_kind, adapter_id, adapter_revision);

CREATE TABLE m8_commissioning_evidence (
    evidence_authority_id TEXT PRIMARY KEY CHECK (
        length(evidence_authority_id) = 64
        AND evidence_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    candidate_authority_id TEXT NOT NULL,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
        'LICENSE_REVIEW', 'OFFLINE_FALLBACK_DRILL', 'SAFETY_REVIEW',
        'SECURITY_REVIEW', 'SITE_ACCEPTANCE'
    )),
    outcome TEXT NOT NULL CHECK (outcome IN ('FAILED', 'PASSED')),
    reviewer_actor_authority_id TEXT NOT NULL,
    reviewer_actor_document_sha256 TEXT NOT NULL CHECK (
        length(reviewer_actor_document_sha256) = 64
        AND reviewer_actor_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    reviewed_at TEXT NOT NULL,
    valid_through TEXT,
    simulated INTEGER NOT NULL CHECK (simulated IN (0, 1)),
    artifact_ref TEXT NOT NULL UNIQUE CHECK (length(artifact_ref) BETWEEN 1 AND 64),
    artifact_sha256 TEXT NOT NULL CHECK (
        length(artifact_sha256) = 64 AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_size_bytes INTEGER NOT NULL CHECK (
        artifact_size_bytes BETWEEN 1 AND 16777216
    ),
    artifact_bytes BLOB NOT NULL CHECK (length(artifact_bytes) = artifact_size_bytes),
    artifact_storage_manifest_id TEXT NOT NULL CHECK (
        length(artifact_storage_manifest_id) = 64
        AND artifact_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    evidence_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(evidence_document_sha256) = 64
        AND evidence_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    FOREIGN KEY (candidate_authority_id)
        REFERENCES m8_production_adapter_candidates(candidate_authority_id),
    FOREIGN KEY (reviewer_actor_authority_id)
        REFERENCES m8_actor_authorities(actor_authority_id)
) STRICT;

CREATE INDEX idx_m8_commissioning_evidence_candidate
ON m8_commissioning_evidence(
    candidate_authority_id, evidence_kind, reviewed_at, evidence_authority_id
);

CREATE TRIGGER m8_production_adapter_candidates_no_update
BEFORE UPDATE ON m8_production_adapter_candidates BEGIN
    SELECT RAISE(ABORT, 'M8 production adapter candidates are append-only');
END;
CREATE TRIGGER m8_production_adapter_candidates_no_delete
BEFORE DELETE ON m8_production_adapter_candidates BEGIN
    SELECT RAISE(ABORT, 'M8 production adapter candidates are append-only');
END;
CREATE TRIGGER m8_production_adapter_candidates_no_replace
BEFORE INSERT ON m8_production_adapter_candidates
WHEN EXISTS (
    SELECT 1 FROM m8_production_adapter_candidates AS existing
    WHERE existing.candidate_authority_id = NEW.candidate_authority_id
       OR (
            existing.adapter_id = NEW.adapter_id
            AND existing.adapter_revision = NEW.adapter_revision
       )
) BEGIN
    SELECT RAISE(ABORT, 'M8 production adapter candidates are append-only');
END;

CREATE TRIGGER m8_commissioning_evidence_no_update
BEFORE UPDATE ON m8_commissioning_evidence BEGIN
    SELECT RAISE(ABORT, 'M8 commissioning evidence is append-only');
END;
CREATE TRIGGER m8_commissioning_evidence_no_delete
BEFORE DELETE ON m8_commissioning_evidence BEGIN
    SELECT RAISE(ABORT, 'M8 commissioning evidence is append-only');
END;
CREATE TRIGGER m8_commissioning_evidence_no_replace
BEFORE INSERT ON m8_commissioning_evidence
WHEN EXISTS (
    SELECT 1 FROM m8_commissioning_evidence AS existing
    WHERE existing.evidence_authority_id = NEW.evidence_authority_id
       OR existing.artifact_ref = NEW.artifact_ref
) BEGIN
    SELECT RAISE(ABORT, 'M8 commissioning evidence is append-only');
END;
