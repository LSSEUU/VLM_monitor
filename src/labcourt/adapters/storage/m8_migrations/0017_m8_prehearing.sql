-- M8 pre-hearing authority (migration 0017).
CREATE TABLE m8_prehearing_preparation_versions (
    preparation_id TEXT NOT NULL CHECK (
        length(preparation_id) = 64 AND preparation_id NOT GLOB '*[^0-9a-f]*'
    ),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 2),
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 64),
    case_id TEXT NOT NULL CHECK (length(case_id) BETWEEN 1 AND 64),
    source_case_revision INTEGER NOT NULL CHECK (source_case_revision > 0),
    source_screening_id TEXT NOT NULL CHECK (
        length(source_screening_id) = 64
        AND source_screening_id NOT GLOB '*[^0-9a-f]*'
    ),
    source_screening_version INTEGER NOT NULL CHECK (source_screening_version > 0),
    source_evidence_pack_id TEXT NOT NULL CHECK (
        length(source_evidence_pack_id) = 64
        AND source_evidence_pack_id NOT GLOB '*[^0-9a-f]*'
    ),
    source_evidence_pack_version INTEGER NOT NULL CHECK (
        source_evidence_pack_version > 0
    ),
    manifest_id TEXT NOT NULL CHECK (
        length(manifest_id) = 64 AND manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('PENDING', 'COMPLETED')),
    document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(document_sha256) = 64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    preparation_json TEXT NOT NULL CHECK (json_valid(preparation_json)),
    PRIMARY KEY(preparation_id, revision),
    UNIQUE(run_id, case_id, revision)
) STRICT;

CREATE INDEX idx_m8_prehearing_preparations_case_current
ON m8_prehearing_preparation_versions(run_id, case_id, revision DESC);

CREATE TRIGGER m8_prehearing_preparations_validate_contiguous
BEFORE INSERT ON m8_prehearing_preparation_versions
WHEN NEW.revision != COALESCE((
    SELECT MAX(revision) FROM m8_prehearing_preparation_versions
    WHERE preparation_id = NEW.preparation_id
), 0) + 1
BEGIN
    SELECT RAISE(ABORT, 'M8 pre-hearing preparation revision must be contiguous');
END;

CREATE TRIGGER m8_prehearing_preparations_reject_second_identity
BEFORE INSERT ON m8_prehearing_preparation_versions
WHEN EXISTS (
    SELECT 1 FROM m8_prehearing_preparation_versions AS existing
    WHERE existing.run_id = NEW.run_id
      AND existing.case_id = NEW.case_id
      AND existing.preparation_id != NEW.preparation_id
)
BEGIN
    SELECT RAISE(ABORT, 'M8 pre-hearing Case already has a preparation identity');
END;

CREATE TRIGGER m8_prehearing_preparations_validate_source
BEFORE INSERT ON m8_prehearing_preparation_versions
WHEN NEW.revision > 1 AND NOT EXISTS (
    SELECT 1 FROM m8_prehearing_preparation_versions AS prior
    WHERE prior.preparation_id = NEW.preparation_id
      AND prior.revision = NEW.revision - 1
      AND prior.run_id = NEW.run_id
      AND prior.case_id = NEW.case_id
      AND prior.source_case_revision = NEW.source_case_revision
      AND prior.source_screening_id = NEW.source_screening_id
      AND prior.source_screening_version = NEW.source_screening_version
      AND prior.source_evidence_pack_id = NEW.source_evidence_pack_id
      AND prior.source_evidence_pack_version = NEW.source_evidence_pack_version
      AND prior.manifest_id = NEW.manifest_id
)
BEGIN
    SELECT RAISE(ABORT, 'M8 pre-hearing preparation source authority changed');
END;

CREATE TRIGGER m8_prehearing_preparations_no_update
BEFORE UPDATE ON m8_prehearing_preparation_versions
BEGIN
    SELECT RAISE(ABORT, 'M8 pre-hearing preparations are append-only');
END;

CREATE TRIGGER m8_prehearing_preparations_no_delete
BEFORE DELETE ON m8_prehearing_preparation_versions
BEGIN
    SELECT RAISE(ABORT, 'M8 pre-hearing preparations are append-only');
END;
