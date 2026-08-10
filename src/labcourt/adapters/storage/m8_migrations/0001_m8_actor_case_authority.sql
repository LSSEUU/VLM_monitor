CREATE TABLE m8_actor_authorities (
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 64),
    authority_revision INTEGER NOT NULL CHECK (authority_revision > 0),
    actor_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(actor_authority_id) = 64
               AND actor_authority_id NOT GLOB '*[^0-9a-f]*'),
    authority_document_sha256 TEXT NOT NULL UNIQUE
        CHECK (length(authority_document_sha256) = 64
               AND authority_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    role TEXT NOT NULL CHECK (role IN ('LEADER', 'SAFETY_OFFICER', 'STUDENT', 'OPERATIONS')),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    prior_authority_id TEXT
        CHECK (prior_authority_id IS NULL OR (
            length(prior_authority_id) = 64
            AND prior_authority_id NOT GLOB '*[^0-9a-f]*'
        )),
    prior_document_sha256 TEXT
        CHECK (prior_document_sha256 IS NULL OR (
            length(prior_document_sha256) = 64
            AND prior_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )),
    repository_manifest_id TEXT NOT NULL
        CHECK (length(repository_manifest_id) = 64
               AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'),
    commit_receipt_id TEXT NOT NULL UNIQUE
        CHECK (length(commit_receipt_id) = 64
               AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    PRIMARY KEY (actor_id, authority_revision),
    CHECK ((prior_authority_id IS NULL) = (prior_document_sha256 IS NULL))
) STRICT;

CREATE INDEX idx_m8_actor_authorities_current
ON m8_actor_authorities(actor_id, authority_revision DESC);

CREATE TRIGGER m8_actor_authorities_validate_contiguous
BEFORE INSERT ON m8_actor_authorities
WHEN NOT (
    (
        NEW.authority_revision = 1
        AND NEW.prior_authority_id IS NULL
        AND NEW.prior_document_sha256 IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM m8_actor_authorities AS prior
            WHERE prior.actor_id = NEW.actor_id
        )
    )
    OR (
        NEW.authority_revision > 1
        AND EXISTS (
            SELECT 1 FROM m8_actor_authorities AS prior
            WHERE prior.actor_id = NEW.actor_id
              AND prior.authority_revision = NEW.authority_revision - 1
              AND prior.actor_authority_id = NEW.prior_authority_id
              AND prior.authority_document_sha256 = NEW.prior_document_sha256
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 actor authority revision must be contiguous');
END;

CREATE TRIGGER m8_actor_authorities_no_update
BEFORE UPDATE ON m8_actor_authorities
BEGIN
    SELECT RAISE(ABORT, 'M8 actor authorities are append-only');
END;

CREATE TRIGGER m8_actor_authorities_no_delete
BEFORE DELETE ON m8_actor_authorities
BEGIN
    SELECT RAISE(ABORT, 'M8 actor authorities are append-only');
END;

CREATE TRIGGER m8_actor_authorities_no_replace
BEFORE INSERT ON m8_actor_authorities
WHEN EXISTS (
    SELECT 1 FROM m8_actor_authorities AS existing
    WHERE existing.actor_id = NEW.actor_id
      AND existing.authority_revision = NEW.authority_revision
)
BEGIN
    SELECT RAISE(ABORT, 'M8 actor authorities are append-only');
END;

CREATE TABLE m8_operational_case_versions (
    case_id TEXT NOT NULL
        CHECK (length(case_id) = 64 AND case_id NOT GLOB '*[^0-9a-f]*'),
    case_version INTEGER NOT NULL CHECK (case_version > 0),
    status TEXT NOT NULL CHECK (status IN (
        'PENDING_VERIFICATION', 'CONFIRMED', 'REJECTED', 'EVIDENCE_REQUESTED',
        'RESOLVED', 'APPEALED', 'APPEAL_RESOLVED'
    )),
    location_id TEXT NOT NULL CHECK (length(location_id) BETWEEN 1 AND 64),
    subject_actor_id TEXT CHECK (
        subject_actor_id IS NULL OR length(subject_actor_id) BETWEEN 1 AND 64
    ),
    case_authority_id TEXT NOT NULL UNIQUE
        CHECK (length(case_authority_id) = 64
               AND case_authority_id NOT GLOB '*[^0-9a-f]*'),
    case_document_sha256 TEXT NOT NULL UNIQUE
        CHECK (length(case_document_sha256) = 64
               AND case_document_sha256 NOT GLOB '*[^0-9a-f]*'),
    prior_case_document_sha256 TEXT
        CHECK (prior_case_document_sha256 IS NULL OR (
            length(prior_case_document_sha256) = 64
            AND prior_case_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )),
    create_command_id TEXT NOT NULL
        CHECK (length(create_command_id) = 64
               AND create_command_id NOT GLOB '*[^0-9a-f]*'),
    transition_command_id TEXT UNIQUE
        CHECK (transition_command_id IS NULL OR (
            length(transition_command_id) = 64
            AND transition_command_id NOT GLOB '*[^0-9a-f]*'
        )),
    actor_authority_id TEXT
        CHECK (actor_authority_id IS NULL OR (
            length(actor_authority_id) = 64
            AND actor_authority_id NOT GLOB '*[^0-9a-f]*'
        )),
    resolved_actor_document_sha256 TEXT
        CHECK (resolved_actor_document_sha256 IS NULL OR (
            length(resolved_actor_document_sha256) = 64
            AND resolved_actor_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )),
    audit_event_id TEXT NOT NULL UNIQUE
        CHECK (length(audit_event_id) = 64
               AND audit_event_id NOT GLOB '*[^0-9a-f]*'),
    audit_event_sha256 TEXT NOT NULL UNIQUE
        CHECK (length(audit_event_sha256) = 64
               AND audit_event_sha256 NOT GLOB '*[^0-9a-f]*'),
    prior_audit_event_sha256 TEXT NOT NULL
        CHECK (length(prior_audit_event_sha256) = 64
               AND prior_audit_event_sha256 NOT GLOB '*[^0-9a-f]*'),
    commit_receipt_id TEXT NOT NULL UNIQUE
        CHECK (length(commit_receipt_id) = 64
               AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'),
    repository_manifest_id TEXT NOT NULL
        CHECK (length(repository_manifest_id) = 64
               AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'),
    case_json TEXT NOT NULL CHECK (json_valid(case_json)),
    audit_event_json TEXT NOT NULL CHECK (json_valid(audit_event_json)),
    commit_receipt_json TEXT NOT NULL CHECK (json_valid(commit_receipt_json)),
    PRIMARY KEY (case_id, case_version),
    CHECK (
        (case_version = 1 AND prior_case_document_sha256 IS NULL
         AND transition_command_id IS NULL AND actor_authority_id IS NULL
         AND resolved_actor_document_sha256 IS NULL)
        OR
        (case_version > 1 AND prior_case_document_sha256 IS NOT NULL
         AND transition_command_id IS NOT NULL AND actor_authority_id IS NOT NULL
         AND resolved_actor_document_sha256 IS NOT NULL)
    )
) STRICT;

CREATE INDEX idx_m8_operational_cases_current
ON m8_operational_case_versions(case_id, case_version DESC);

CREATE INDEX idx_m8_operational_cases_status_location
ON m8_operational_case_versions(status, location_id, case_version DESC);

CREATE TRIGGER m8_operational_case_versions_validate_contiguous
BEFORE INSERT ON m8_operational_case_versions
WHEN NOT (
    (
        NEW.case_version = 1
        AND NEW.status = 'PENDING_VERIFICATION'
        AND NEW.prior_case_document_sha256 IS NULL
        AND NEW.prior_audit_event_sha256 =
            '0000000000000000000000000000000000000000000000000000000000000000'
        AND NOT EXISTS (
            SELECT 1 FROM m8_operational_case_versions AS prior
            WHERE prior.case_id = NEW.case_id
        )
    )
    OR (
        NEW.case_version > 1
        AND EXISTS (
            SELECT 1 FROM m8_operational_case_versions AS prior
            WHERE prior.case_id = NEW.case_id
              AND prior.case_version = NEW.case_version - 1
              AND prior.case_document_sha256 = NEW.prior_case_document_sha256
              AND prior.audit_event_sha256 = NEW.prior_audit_event_sha256
              AND prior.create_command_id = NEW.create_command_id
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 Case version and audit chain must be contiguous');
END;

CREATE TRIGGER m8_operational_case_versions_no_update
BEFORE UPDATE ON m8_operational_case_versions
BEGIN
    SELECT RAISE(ABORT, 'M8 operational Case versions are append-only');
END;

CREATE TRIGGER m8_operational_case_versions_no_delete
BEFORE DELETE ON m8_operational_case_versions
BEGIN
    SELECT RAISE(ABORT, 'M8 operational Case versions are append-only');
END;

CREATE TRIGGER m8_operational_case_versions_no_replace
BEFORE INSERT ON m8_operational_case_versions
WHEN EXISTS (
    SELECT 1 FROM m8_operational_case_versions AS existing
    WHERE existing.case_id = NEW.case_id
      AND existing.case_version = NEW.case_version
)
BEGIN
    SELECT RAISE(ABORT, 'M8 operational Case versions are append-only');
END;
