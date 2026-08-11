CREATE TABLE m8_feishu_url_challenge_commits (
    commit_receipt_id TEXT PRIMARY KEY CHECK (
        length(commit_receipt_id) = 64
        AND commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    verification_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(verification_receipt_id) = 64
        AND verification_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    inbound_profile_id TEXT NOT NULL CHECK (
        length(inbound_profile_id) = 64
        AND inbound_profile_id NOT GLOB '*[^0-9a-f]*'
    ),
    ingress_request_id TEXT NOT NULL CHECK (
        length(ingress_request_id) = 64
        AND ingress_request_id NOT GLOB '*[^0-9a-f]*'
    ),
    encrypted_body_sha256 TEXT NOT NULL CHECK (
        length(encrypted_body_sha256) = 64
        AND encrypted_body_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    decrypted_challenge_sha256 TEXT NOT NULL CHECK (
        length(decrypted_challenge_sha256) = 64
        AND decrypted_challenge_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    response_document_sha256 TEXT NOT NULL CHECK (
        length(response_document_sha256) = 64
        AND response_document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    verified_at TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    commit_manifest_id TEXT NOT NULL CHECK (
        length(commit_manifest_id) = 64
        AND commit_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json))
) STRICT;

CREATE INDEX idx_m8_feishu_url_challenge_commits_profile
ON m8_feishu_url_challenge_commits(inbound_profile_id, committed_at);

CREATE TRIGGER m8_feishu_url_challenge_commits_no_update
BEFORE UPDATE ON m8_feishu_url_challenge_commits BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu URL challenge commits are append-only');
END;
CREATE TRIGGER m8_feishu_url_challenge_commits_no_delete
BEFORE DELETE ON m8_feishu_url_challenge_commits BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu URL challenge commits are append-only');
END;
CREATE TRIGGER m8_feishu_url_challenge_commits_no_replace
BEFORE INSERT ON m8_feishu_url_challenge_commits
WHEN EXISTS (
    SELECT 1 FROM m8_feishu_url_challenge_commits AS existing
    WHERE existing.commit_receipt_id = NEW.commit_receipt_id
       OR existing.verification_receipt_id = NEW.verification_receipt_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 Feishu URL challenge commits are append-only');
END;
