CREATE UNIQUE INDEX idx_m8_source_catalog_receipt_binding
ON m8_source_catalog_versions(catalog_id, commit_receipt_id);

CREATE TABLE m8_sensor_raw_signals (
    raw_signal_ref TEXT PRIMARY KEY CHECK (
        length(raw_signal_ref) BETWEEN 1 AND 512
        AND instr(raw_signal_ref, '\') = 0
        AND instr(raw_signal_ref, ':') = 0
    ),
    raw_signal_sha256 TEXT NOT NULL CHECK (
        length(raw_signal_sha256) = 64 AND raw_signal_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    raw_signal_size_bytes INTEGER NOT NULL CHECK (
        raw_signal_size_bytes BETWEEN 1 AND 1048576
    ),
    raw_signal_bytes BLOB NOT NULL CHECK (length(raw_signal_bytes) = raw_signal_size_bytes),
    raw_storage_manifest_id TEXT NOT NULL CHECK (
        length(raw_storage_manifest_id) = 64
        AND raw_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    UNIQUE (raw_signal_ref, raw_signal_sha256, raw_signal_size_bytes)
) STRICT;

CREATE TABLE m8_sensor_samples (
    sample_id TEXT PRIMARY KEY CHECK (
        length(sample_id) = 64 AND sample_id NOT GLOB '*[^0-9a-f]*'
    ),
    source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64),
    source_sequence INTEGER NOT NULL CHECK (source_sequence >= 0),
    source_catalog_id TEXT NOT NULL,
    sample_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(sample_document_sha256) = 64
        AND sample_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    raw_signal_ref TEXT NOT NULL,
    raw_signal_sha256 TEXT NOT NULL,
    raw_signal_size_bytes INTEGER NOT NULL,
    resolved_source_catalog_commit_receipt_id TEXT NOT NULL,
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
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    UNIQUE (source_id, source_sequence),
    FOREIGN KEY (source_catalog_id, resolved_source_catalog_commit_receipt_id)
        REFERENCES m8_source_catalog_versions(catalog_id, commit_receipt_id),
    FOREIGN KEY (raw_signal_ref, raw_signal_sha256, raw_signal_size_bytes)
        REFERENCES m8_sensor_raw_signals(
            raw_signal_ref,
            raw_signal_sha256,
            raw_signal_size_bytes
        )
) STRICT;

CREATE INDEX idx_m8_sensor_samples_source_sequence
ON m8_sensor_samples(source_id, source_sequence);

CREATE TABLE m8_sensor_poll_cache (
    cache_key TEXT PRIMARY KEY CHECK (
        length(cache_key) = 64 AND cache_key NOT GLOB '*[^0-9a-f]*'
    ),
    request_id TEXT NOT NULL UNIQUE CHECK (
        length(request_id) = 64 AND request_id NOT GLOB '*[^0-9a-f]*'
    ),
    result_id TEXT NOT NULL UNIQUE CHECK (
        length(result_id) = 64 AND result_id NOT GLOB '*[^0-9a-f]*'
    ),
    source_catalog_id TEXT NOT NULL,
    resolved_source_catalog_commit_receipt_id TEXT NOT NULL,
    poll_result_document_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(poll_result_document_sha256) = 64
        AND poll_result_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    sample_count INTEGER NOT NULL CHECK (sample_count BETWEEN 0 AND 1024),
    sample_receipt_inventory_sha256 TEXT NOT NULL CHECK (
        length(sample_receipt_inventory_sha256) = 64
        AND sample_receipt_inventory_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    total_raw_signal_size_bytes INTEGER NOT NULL CHECK (
        total_raw_signal_size_bytes BETWEEN 0 AND 67108864
    ),
    raw_storage_manifest_id TEXT NOT NULL CHECK (
        length(raw_storage_manifest_id) = 64
        AND raw_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    cache_manifest_id TEXT NOT NULL CHECK (
        length(cache_manifest_id) = 64 AND cache_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(commit_receipt_id) = 64 AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    FOREIGN KEY (source_catalog_id, resolved_source_catalog_commit_receipt_id)
        REFERENCES m8_source_catalog_versions(catalog_id, commit_receipt_id)
) STRICT;

CREATE TABLE m8_sensor_poll_cache_samples (
    cache_key TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    sample_id TEXT NOT NULL,
    PRIMARY KEY (cache_key, position),
    UNIQUE (cache_key, sample_id),
    FOREIGN KEY (cache_key) REFERENCES m8_sensor_poll_cache(cache_key),
    FOREIGN KEY (sample_id) REFERENCES m8_sensor_samples(sample_id)
) STRICT;

CREATE TRIGGER m8_sensor_raw_signals_no_update
BEFORE UPDATE ON m8_sensor_raw_signals BEGIN
    SELECT RAISE(ABORT, 'M8 sensor raw signals are append-only');
END;
CREATE TRIGGER m8_sensor_raw_signals_no_delete
BEFORE DELETE ON m8_sensor_raw_signals BEGIN
    SELECT RAISE(ABORT, 'M8 sensor raw signals are append-only');
END;
CREATE TRIGGER m8_sensor_raw_signals_no_replace
BEFORE INSERT ON m8_sensor_raw_signals
WHEN EXISTS (
    SELECT 1 FROM m8_sensor_raw_signals AS existing
    WHERE existing.raw_signal_ref = NEW.raw_signal_ref
) BEGIN
    SELECT RAISE(ABORT, 'M8 sensor raw signals are append-only');
END;
CREATE TRIGGER m8_sensor_samples_no_update
BEFORE UPDATE ON m8_sensor_samples BEGIN
    SELECT RAISE(ABORT, 'M8 sensor samples are append-only');
END;
CREATE TRIGGER m8_sensor_samples_no_delete
BEFORE DELETE ON m8_sensor_samples BEGIN
    SELECT RAISE(ABORT, 'M8 sensor samples are append-only');
END;
CREATE TRIGGER m8_sensor_samples_no_replace
BEFORE INSERT ON m8_sensor_samples
WHEN EXISTS (
    SELECT 1 FROM m8_sensor_samples AS existing WHERE existing.sample_id = NEW.sample_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 sensor samples are append-only');
END;
CREATE TRIGGER m8_sensor_poll_cache_no_update
BEFORE UPDATE ON m8_sensor_poll_cache BEGIN
    SELECT RAISE(ABORT, 'M8 sensor poll cache is append-only');
END;
CREATE TRIGGER m8_sensor_poll_cache_no_delete
BEFORE DELETE ON m8_sensor_poll_cache BEGIN
    SELECT RAISE(ABORT, 'M8 sensor poll cache is append-only');
END;
CREATE TRIGGER m8_sensor_poll_cache_no_replace
BEFORE INSERT ON m8_sensor_poll_cache
WHEN EXISTS (
    SELECT 1 FROM m8_sensor_poll_cache AS existing WHERE existing.cache_key = NEW.cache_key
) BEGIN
    SELECT RAISE(ABORT, 'M8 sensor poll cache is append-only');
END;
CREATE TRIGGER m8_sensor_poll_cache_samples_no_update
BEFORE UPDATE ON m8_sensor_poll_cache_samples BEGIN
    SELECT RAISE(ABORT, 'M8 sensor poll cache samples are append-only');
END;
CREATE TRIGGER m8_sensor_poll_cache_samples_no_delete
BEFORE DELETE ON m8_sensor_poll_cache_samples BEGIN
    SELECT RAISE(ABORT, 'M8 sensor poll cache samples are append-only');
END;
CREATE TRIGGER m8_sensor_poll_cache_samples_no_replace
BEFORE INSERT ON m8_sensor_poll_cache_samples
WHEN EXISTS (
    SELECT 1 FROM m8_sensor_poll_cache_samples AS existing
    WHERE existing.cache_key = NEW.cache_key AND existing.position = NEW.position
) BEGIN
    SELECT RAISE(ABORT, 'M8 sensor poll cache samples are append-only');
END;
