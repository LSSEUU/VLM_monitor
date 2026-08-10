CREATE TABLE m8_campus_topology_versions (
    campus_id TEXT NOT NULL CHECK (length(campus_id) BETWEEN 1 AND 64),
    revision INTEGER NOT NULL CHECK (revision > 0),
    topology_id TEXT NOT NULL UNIQUE CHECK (
        length(topology_id) = 64 AND topology_id NOT GLOB '*[^0-9a-f]*'
    ),
    topology_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(topology_document_sha256) = 64
        AND topology_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    prior_topology_id TEXT CHECK (
        prior_topology_id IS NULL OR (
            length(prior_topology_id) = 64 AND prior_topology_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    prior_document_sha256 TEXT CHECK (
        prior_document_sha256 IS NULL OR (
            length(prior_document_sha256) = 64
            AND prior_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    topology_manifest_id TEXT NOT NULL CHECK (
        length(topology_manifest_id) = 64 AND topology_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    PRIMARY KEY (campus_id, revision),
    UNIQUE (topology_id, topology_document_sha256, commit_receipt_id),
    CHECK ((prior_topology_id IS NULL) = (prior_document_sha256 IS NULL))
) STRICT;

CREATE INDEX idx_m8_campus_topologies_current
ON m8_campus_topology_versions(campus_id, revision DESC);

CREATE TRIGGER m8_campus_topologies_validate_contiguous
BEFORE INSERT ON m8_campus_topology_versions
WHEN NOT (
    (
        NEW.revision = 1
        AND NEW.prior_topology_id IS NULL
        AND NEW.prior_document_sha256 IS NULL
        AND NOT EXISTS (
            SELECT 1 FROM m8_campus_topology_versions AS prior
            WHERE prior.campus_id = NEW.campus_id
        )
    )
    OR (
        NEW.revision > 1
        AND EXISTS (
            SELECT 1 FROM m8_campus_topology_versions AS prior
            WHERE prior.campus_id = NEW.campus_id
              AND prior.revision = NEW.revision - 1
              AND prior.topology_id = NEW.prior_topology_id
              AND prior.topology_document_sha256 = NEW.prior_document_sha256
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 topology revision must be contiguous');
END;

CREATE TRIGGER m8_campus_topologies_no_update
BEFORE UPDATE ON m8_campus_topology_versions
BEGIN
    SELECT RAISE(ABORT, 'M8 campus topologies are append-only');
END;

CREATE TRIGGER m8_campus_topologies_no_delete
BEFORE DELETE ON m8_campus_topology_versions
BEGIN
    SELECT RAISE(ABORT, 'M8 campus topologies are append-only');
END;

CREATE TRIGGER m8_campus_topologies_no_replace
BEFORE INSERT ON m8_campus_topology_versions
WHEN EXISTS (
    SELECT 1 FROM m8_campus_topology_versions AS existing
    WHERE existing.campus_id = NEW.campus_id AND existing.revision = NEW.revision
)
BEGIN
    SELECT RAISE(ABORT, 'M8 campus topologies are append-only');
END;

CREATE TABLE m8_source_catalog_versions (
    campus_id TEXT NOT NULL CHECK (length(campus_id) BETWEEN 1 AND 64),
    revision INTEGER NOT NULL CHECK (revision > 0),
    catalog_id TEXT NOT NULL UNIQUE CHECK (
        length(catalog_id) = 64 AND catalog_id NOT GLOB '*[^0-9a-f]*'
    ),
    catalog_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(catalog_document_sha256) = 64
        AND catalog_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    topology_id TEXT NOT NULL,
    resolved_topology_document_sha256 TEXT NOT NULL,
    resolved_topology_commit_receipt_id TEXT NOT NULL,
    prior_catalog_id TEXT CHECK (
        prior_catalog_id IS NULL OR (
            length(prior_catalog_id) = 64 AND prior_catalog_id NOT GLOB '*[^0-9a-f]*'
        )
    ),
    prior_document_sha256 TEXT CHECK (
        prior_document_sha256 IS NULL OR (
            length(prior_document_sha256) = 64
            AND prior_document_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    source_count INTEGER NOT NULL CHECK (source_count > 0),
    simulated_source_count INTEGER NOT NULL CHECK (
        simulated_source_count >= 0 AND simulated_source_count <= source_count
    ),
    life_safety_eligible_source_count INTEGER NOT NULL CHECK (
        life_safety_eligible_source_count >= 0
        AND life_safety_eligible_source_count <= source_count
    ),
    catalog_manifest_id TEXT NOT NULL CHECK (
        length(catalog_manifest_id) = 64 AND catalog_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    PRIMARY KEY (campus_id, revision),
    CHECK ((prior_catalog_id IS NULL) = (prior_document_sha256 IS NULL)),
    FOREIGN KEY (
        topology_id,
        resolved_topology_document_sha256,
        resolved_topology_commit_receipt_id
    ) REFERENCES m8_campus_topology_versions(
        topology_id,
        topology_document_sha256,
        commit_receipt_id
    )
) STRICT;

CREATE INDEX idx_m8_source_catalogs_current
ON m8_source_catalog_versions(campus_id, revision DESC);

CREATE TRIGGER m8_source_catalogs_validate_contiguous
BEFORE INSERT ON m8_source_catalog_versions
WHEN NOT (
    EXISTS (
        SELECT 1 FROM m8_campus_topology_versions AS topology
        WHERE topology.campus_id = NEW.campus_id
          AND topology.topology_id = NEW.topology_id
          AND topology.topology_document_sha256 = NEW.resolved_topology_document_sha256
          AND topology.commit_receipt_id = NEW.resolved_topology_commit_receipt_id
          AND topology.revision = (
              SELECT MAX(current.revision)
              FROM m8_campus_topology_versions AS current
              WHERE current.campus_id = NEW.campus_id
          )
    )
    AND (
        (
            NEW.revision = 1
            AND NEW.prior_catalog_id IS NULL
            AND NEW.prior_document_sha256 IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM m8_source_catalog_versions AS prior
                WHERE prior.campus_id = NEW.campus_id
            )
        )
        OR (
            NEW.revision > 1
            AND EXISTS (
                SELECT 1 FROM m8_source_catalog_versions AS prior
                WHERE prior.campus_id = NEW.campus_id
                  AND prior.revision = NEW.revision - 1
                  AND prior.catalog_id = NEW.prior_catalog_id
                  AND prior.catalog_document_sha256 = NEW.prior_document_sha256
            )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 source catalog revision or topology authority is stale');
END;

CREATE TRIGGER m8_source_catalogs_no_update
BEFORE UPDATE ON m8_source_catalog_versions
BEGIN
    SELECT RAISE(ABORT, 'M8 source catalogs are append-only');
END;

CREATE TRIGGER m8_source_catalogs_no_delete
BEFORE DELETE ON m8_source_catalog_versions
BEGIN
    SELECT RAISE(ABORT, 'M8 source catalogs are append-only');
END;

CREATE TRIGGER m8_source_catalogs_no_replace
BEFORE INSERT ON m8_source_catalog_versions
WHEN EXISTS (
    SELECT 1 FROM m8_source_catalog_versions AS existing
    WHERE existing.campus_id = NEW.campus_id AND existing.revision = NEW.revision
)
BEGIN
    SELECT RAISE(ABORT, 'M8 source catalogs are append-only');
END;
