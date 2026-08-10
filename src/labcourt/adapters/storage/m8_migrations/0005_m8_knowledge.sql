CREATE TABLE m8_knowledge_raw_contents (
    content_ref TEXT PRIMARY KEY CHECK (length(content_ref) BETWEEN 1 AND 64),
    document_authority_id TEXT NOT NULL UNIQUE CHECK (
        length(document_authority_id) = 64
        AND document_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    content_sha256 TEXT NOT NULL CHECK (
        length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    content_size_bytes INTEGER NOT NULL CHECK (
        content_size_bytes BETWEEN 1 AND 1048576
    ),
    content_bytes BLOB NOT NULL CHECK (length(content_bytes) = content_size_bytes),
    raw_storage_manifest_id TEXT NOT NULL CHECK (
        length(raw_storage_manifest_id) = 64
        AND raw_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    document_commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(document_commit_receipt_id) = 64
        AND document_commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json))
) STRICT;

CREATE TABLE m8_knowledge_catalog_versions (
    catalog_id TEXT NOT NULL CHECK (length(catalog_id) BETWEEN 1 AND 64),
    catalog_revision INTEGER NOT NULL CHECK (catalog_revision > 0),
    catalog_authority_id TEXT NOT NULL UNIQUE CHECK (
        length(catalog_authority_id) = 64
        AND catalog_authority_id NOT GLOB '*[^0-9a-f]*'
    ),
    catalog_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(catalog_document_sha256) = 64
        AND catalog_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    content_inventory_sha256 TEXT NOT NULL CHECK (
        length(content_inventory_sha256) = 64
        AND content_inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    total_content_size_bytes INTEGER NOT NULL CHECK (total_content_size_bytes > 0),
    prior_catalog_authority_id TEXT CHECK (
        prior_catalog_authority_id IS NULL OR (
            length(prior_catalog_authority_id) = 64
            AND prior_catalog_authority_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    prior_catalog_document_sha256 TEXT CHECK (
        prior_catalog_document_sha256 IS NULL OR (
            length(prior_catalog_document_sha256) = 64
            AND prior_catalog_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    raw_storage_manifest_id TEXT NOT NULL CHECK (
        length(raw_storage_manifest_id) = 64
        AND raw_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    catalog_json TEXT NOT NULL CHECK (json_valid(catalog_json)),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    PRIMARY KEY (catalog_id, catalog_revision),
    CHECK (
        (prior_catalog_authority_id IS NULL) =
        (prior_catalog_document_sha256 IS NULL)
    )
) STRICT;

CREATE INDEX idx_m8_knowledge_catalogs_current
ON m8_knowledge_catalog_versions(catalog_id, catalog_revision DESC);

CREATE TABLE m8_knowledge_catalog_documents (
    catalog_id TEXT NOT NULL,
    catalog_revision INTEGER NOT NULL,
    position INTEGER NOT NULL CHECK (position BETWEEN 0 AND 999),
    document_authority_id TEXT NOT NULL,
    content_ref TEXT NOT NULL,
    PRIMARY KEY (catalog_id, catalog_revision, position),
    UNIQUE (catalog_id, catalog_revision, document_authority_id),
    UNIQUE (catalog_id, catalog_revision, content_ref),
    FOREIGN KEY (catalog_id, catalog_revision)
        REFERENCES m8_knowledge_catalog_versions(catalog_id, catalog_revision),
    FOREIGN KEY (document_authority_id)
        REFERENCES m8_knowledge_raw_contents(document_authority_id),
    FOREIGN KEY (content_ref) REFERENCES m8_knowledge_raw_contents(content_ref)
) STRICT;

CREATE TABLE m8_knowledge_answer_receipts (
    query_id TEXT PRIMARY KEY CHECK (
        length(query_id) = 64 AND query_id NOT GLOB '*[^0-9a-f]*'
    ),
    answer_id TEXT NOT NULL UNIQUE CHECK (
        length(answer_id) = 64 AND answer_id NOT GLOB '*[^0-9a-f]*'
    ),
    catalog_authority_id TEXT NOT NULL,
    requester_actor_id TEXT NOT NULL CHECK (length(requester_actor_id) BETWEEN 1 AND 64),
    requester_actor_authority_id TEXT NOT NULL,
    resolved_actor_document_sha256 TEXT NOT NULL CHECK (
        length(resolved_actor_document_sha256) = 64
        AND resolved_actor_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    query_as_of TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('ANSWERED', 'NO_MATCH')),
    adapter_manifest_id TEXT NOT NULL CHECK (
        length(adapter_manifest_id) = 64
        AND adapter_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    answer_json TEXT NOT NULL CHECK (json_valid(answer_json)),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    FOREIGN KEY (catalog_authority_id)
        REFERENCES m8_knowledge_catalog_versions(catalog_authority_id),
    FOREIGN KEY (requester_actor_authority_id)
        REFERENCES m8_actor_authorities(actor_authority_id)
) STRICT;

CREATE INDEX idx_m8_knowledge_answers_actor
ON m8_knowledge_answer_receipts(requester_actor_id, query_id);

CREATE TRIGGER m8_knowledge_catalog_versions_validate_contiguous
BEFORE INSERT ON m8_knowledge_catalog_versions
WHEN NOT (
    (
        NEW.catalog_revision = 1
        AND NEW.prior_catalog_authority_id IS NULL
        AND NEW.prior_catalog_document_sha256 IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM m8_knowledge_catalog_versions AS prior
            WHERE prior.catalog_id = NEW.catalog_id
        )
    )
    OR (
        NEW.catalog_revision > 1
        AND EXISTS (
            SELECT 1 FROM m8_knowledge_catalog_versions AS prior
            WHERE prior.catalog_id = NEW.catalog_id
              AND prior.catalog_revision = NEW.catalog_revision - 1
              AND prior.catalog_authority_id = NEW.prior_catalog_authority_id
              AND prior.catalog_document_sha256 = NEW.prior_catalog_document_sha256
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge catalog revision must be contiguous');
END;

CREATE TRIGGER m8_knowledge_raw_contents_no_update
BEFORE UPDATE ON m8_knowledge_raw_contents BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge raw contents are append-only');
END;
CREATE TRIGGER m8_knowledge_raw_contents_no_delete
BEFORE DELETE ON m8_knowledge_raw_contents BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge raw contents are append-only');
END;
CREATE TRIGGER m8_knowledge_raw_contents_no_replace
BEFORE INSERT ON m8_knowledge_raw_contents
WHEN EXISTS (
    SELECT 1 FROM m8_knowledge_raw_contents AS existing
    WHERE existing.content_ref = NEW.content_ref
       OR existing.document_authority_id = NEW.document_authority_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge raw contents are append-only');
END;
CREATE TRIGGER m8_knowledge_catalog_versions_no_update
BEFORE UPDATE ON m8_knowledge_catalog_versions BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge catalog versions are append-only');
END;
CREATE TRIGGER m8_knowledge_catalog_versions_no_delete
BEFORE DELETE ON m8_knowledge_catalog_versions BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge catalog versions are append-only');
END;
CREATE TRIGGER m8_knowledge_catalog_versions_no_replace
BEFORE INSERT ON m8_knowledge_catalog_versions
WHEN EXISTS (
    SELECT 1 FROM m8_knowledge_catalog_versions AS existing
    WHERE existing.catalog_id = NEW.catalog_id
      AND existing.catalog_revision = NEW.catalog_revision
) BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge catalog versions are append-only');
END;
CREATE TRIGGER m8_knowledge_catalog_documents_no_update
BEFORE UPDATE ON m8_knowledge_catalog_documents BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge catalog links are append-only');
END;
CREATE TRIGGER m8_knowledge_catalog_documents_no_delete
BEFORE DELETE ON m8_knowledge_catalog_documents BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge catalog links are append-only');
END;
CREATE TRIGGER m8_knowledge_catalog_documents_no_replace
BEFORE INSERT ON m8_knowledge_catalog_documents
WHEN EXISTS (
    SELECT 1 FROM m8_knowledge_catalog_documents AS existing
    WHERE existing.catalog_id = NEW.catalog_id
      AND existing.catalog_revision = NEW.catalog_revision
      AND existing.position = NEW.position
) BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge catalog links are append-only');
END;
CREATE TRIGGER m8_knowledge_answer_receipts_no_update
BEFORE UPDATE ON m8_knowledge_answer_receipts BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge answer receipts are append-only');
END;
CREATE TRIGGER m8_knowledge_answer_receipts_no_delete
BEFORE DELETE ON m8_knowledge_answer_receipts BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge answer receipts are append-only');
END;
CREATE TRIGGER m8_knowledge_answer_receipts_no_replace
BEFORE INSERT ON m8_knowledge_answer_receipts
WHEN EXISTS (
    SELECT 1 FROM m8_knowledge_answer_receipts AS existing
    WHERE existing.query_id = NEW.query_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 knowledge answer receipts are append-only');
END;
