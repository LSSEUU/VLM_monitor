CREATE TABLE m8_feishu_inbound_sandbox_activations (
    activation_commit_id TEXT PRIMARY KEY CHECK (
        length(activation_commit_id) = 64
        AND activation_commit_id NOT GLOB '*[^0-9a-f]*'
    ),
    candidate_authority_id TEXT NOT NULL,
    inbound_profile_id TEXT NOT NULL CHECK (
        length(inbound_profile_id) = 64
        AND inbound_profile_id NOT GLOB '*[^0-9a-f]*'
    ),
    runtime_config_id TEXT NOT NULL UNIQUE CHECK (
        length(runtime_config_id) = 64
        AND runtime_config_id NOT GLOB '*[^0-9a-f]*'
    ),
    runtime_config_ref TEXT NOT NULL UNIQUE CHECK (
        length(runtime_config_ref) BETWEEN 1 AND 64
    ),
    public_callback_url_sha256 TEXT NOT NULL CHECK (
        length(public_callback_url_sha256) = 64
        AND public_callback_url_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    tls_configuration_sha256 TEXT NOT NULL CHECK (
        length(tls_configuration_sha256) = 64
        AND tls_configuration_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    runtime_config_document_sha256 TEXT NOT NULL CHECK (
        length(runtime_config_document_sha256) = 64
        AND runtime_config_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    runtime_config_size_bytes INTEGER NOT NULL CHECK (
        runtime_config_size_bytes BETWEEN 1 AND 1048576
    ),
    runtime_config_bytes BLOB NOT NULL CHECK (
        length(runtime_config_bytes) = runtime_config_size_bytes
    ),
    activation_intent_id TEXT NOT NULL UNIQUE CHECK (
        length(activation_intent_id) = 64
        AND activation_intent_id NOT GLOB '*[^0-9a-f]*'
    ),
    activation_revision INTEGER NOT NULL CHECK (activation_revision >= 1),
    prior_activation_commit_id TEXT,
    operations_actor_authority_id TEXT NOT NULL,
    safety_actor_authority_id TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    runtime_config_storage_manifest_id TEXT NOT NULL CHECK (
        length(runtime_config_storage_manifest_id) = 64
        AND runtime_config_storage_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    runtime_config_json TEXT NOT NULL CHECK (json_valid(runtime_config_json)),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    UNIQUE (candidate_authority_id, activation_revision),
    CHECK (
        (activation_revision = 1 AND prior_activation_commit_id IS NULL)
        OR (activation_revision > 1 AND prior_activation_commit_id IS NOT NULL)
    ),
    FOREIGN KEY (candidate_authority_id)
        REFERENCES m8_production_adapter_candidates(candidate_authority_id),
    FOREIGN KEY (prior_activation_commit_id)
        REFERENCES m8_feishu_inbound_sandbox_activations(activation_commit_id),
    FOREIGN KEY (operations_actor_authority_id)
        REFERENCES m8_actor_authorities(actor_authority_id),
    FOREIGN KEY (safety_actor_authority_id)
        REFERENCES m8_actor_authorities(actor_authority_id)
) STRICT;

CREATE INDEX idx_m8_feishu_inbound_sandbox_activations_current
ON m8_feishu_inbound_sandbox_activations(
    candidate_authority_id,
    activation_revision DESC
);

CREATE TABLE m8_feishu_inbound_sandbox_activation_revocations (
    revocation_commit_id TEXT PRIMARY KEY CHECK (
        length(revocation_commit_id) = 64
        AND revocation_commit_id NOT GLOB '*[^0-9a-f]*'
    ),
    activation_commit_id TEXT NOT NULL UNIQUE,
    candidate_authority_id TEXT NOT NULL,
    revoked_by_actor_authority_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN (
        'COMMISSIONING_INVALIDATED', 'CONFIGURATION_REPLACED',
        'CREDENTIAL_ROTATION', 'MANUAL_OPERATIONS_STOP', 'MANUAL_SAFETY_STOP',
        'TLS_CONFIGURATION_INVALIDATED'
    )),
    reason_ref TEXT NOT NULL CHECK (length(reason_ref) BETWEEN 1 AND 64),
    revoked_at TEXT NOT NULL,
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
    FOREIGN KEY (activation_commit_id)
        REFERENCES m8_feishu_inbound_sandbox_activations(activation_commit_id),
    FOREIGN KEY (candidate_authority_id)
        REFERENCES m8_production_adapter_candidates(candidate_authority_id),
    FOREIGN KEY (revoked_by_actor_authority_id)
        REFERENCES m8_actor_authorities(actor_authority_id)
) STRICT;

CREATE INDEX idx_m8_feishu_inbound_sandbox_revocations_candidate
ON m8_feishu_inbound_sandbox_activation_revocations(
    candidate_authority_id,
    revoked_at
);

CREATE TRIGGER m8_feishu_inbound_sandbox_activations_validate_contiguous
BEFORE INSERT ON m8_feishu_inbound_sandbox_activations
WHEN (
    NEW.activation_revision = 1 AND EXISTS (
        SELECT 1 FROM m8_feishu_inbound_sandbox_activations
        WHERE candidate_authority_id = NEW.candidate_authority_id
    )
) OR (
    NEW.activation_revision > 1 AND NOT EXISTS (
        SELECT 1
        FROM m8_feishu_inbound_sandbox_activations AS prior
        JOIN m8_feishu_inbound_sandbox_activation_revocations AS revocation
          ON revocation.activation_commit_id = prior.activation_commit_id
        WHERE prior.candidate_authority_id = NEW.candidate_authority_id
          AND prior.activation_revision = NEW.activation_revision - 1
          AND prior.activation_commit_id = NEW.prior_activation_commit_id
    )
) BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound activation revision is not contiguous');
END;

CREATE TRIGGER m8_feishu_inbound_sandbox_activations_no_update
BEFORE UPDATE ON m8_feishu_inbound_sandbox_activations BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound activations are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_sandbox_activations_no_delete
BEFORE DELETE ON m8_feishu_inbound_sandbox_activations BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound activations are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_sandbox_activations_no_replace
BEFORE INSERT ON m8_feishu_inbound_sandbox_activations
WHEN EXISTS (
    SELECT 1 FROM m8_feishu_inbound_sandbox_activations AS existing
    WHERE existing.activation_commit_id = NEW.activation_commit_id
       OR existing.activation_intent_id = NEW.activation_intent_id
       OR existing.runtime_config_id = NEW.runtime_config_id
       OR existing.runtime_config_ref = NEW.runtime_config_ref
       OR (
            existing.candidate_authority_id = NEW.candidate_authority_id
            AND existing.activation_revision = NEW.activation_revision
       )
) BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound activations are append-only');
END;

CREATE TRIGGER m8_feishu_inbound_sandbox_activation_revocations_no_update
BEFORE UPDATE ON m8_feishu_inbound_sandbox_activation_revocations BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound activation revocations are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_sandbox_activation_revocations_no_delete
BEFORE DELETE ON m8_feishu_inbound_sandbox_activation_revocations BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound activation revocations are append-only');
END;
CREATE TRIGGER m8_feishu_inbound_sandbox_activation_revocations_no_replace
BEFORE INSERT ON m8_feishu_inbound_sandbox_activation_revocations
WHEN EXISTS (
    SELECT 1 FROM m8_feishu_inbound_sandbox_activation_revocations AS existing
    WHERE existing.revocation_commit_id = NEW.revocation_commit_id
       OR existing.activation_commit_id = NEW.activation_commit_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu inbound activation revocations are append-only');
END;
