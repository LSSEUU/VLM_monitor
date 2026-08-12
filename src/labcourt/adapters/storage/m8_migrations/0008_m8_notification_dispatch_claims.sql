CREATE TABLE m8_notification_dispatch_claims (
    claim_id TEXT PRIMARY KEY CHECK (
        length(claim_id) = 64 AND claim_id NOT GLOB '*[^0-9a-f]*'
    ),
    notification_id TEXT NOT NULL CHECK (
        length(notification_id) = 64 AND notification_id NOT GLOB '*[^0-9a-f]*'
    ),
    source_notification_version INTEGER NOT NULL CHECK (source_notification_version > 0),
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    dispatch_request_id TEXT NOT NULL UNIQUE CHECK (
        length(dispatch_request_id) = 64 AND dispatch_request_id NOT GLOB '*[^0-9a-f]*'
    ),
    worker_owner_sha256 TEXT NOT NULL CHECK (
        length(worker_owner_sha256) = 64 AND worker_owner_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    claimed_at TEXT NOT NULL CHECK (length(claimed_at) = 27),
    lease_expires_at TEXT NOT NULL CHECK (length(lease_expires_at) = 27),
    claim_manifest_id TEXT NOT NULL CHECK (
        length(claim_manifest_id) = 64 AND claim_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (
        json_valid(receipt_json)
        AND json_extract(receipt_json, '$.schema_version') =
            'm8-notification-dispatch-claim-receipt-v1'
        AND json_extract(receipt_json, '$.claim_id') = claim_id
        AND json_extract(receipt_json, '$.notification_id') = notification_id
        AND json_extract(receipt_json, '$.source_notification_version') =
            source_notification_version
        AND json_extract(receipt_json, '$.attempt_number') = attempt_number
        AND json_extract(receipt_json, '$.request.dispatch_request_id') = dispatch_request_id
        AND json_extract(receipt_json, '$.worker_owner_sha256') = worker_owner_sha256
        AND json_extract(receipt_json, '$.claim_manifest_id') = claim_manifest_id
        AND json_extract(receipt_json, '$.repository_manifest_id') = repository_manifest_id
        AND json_extract(receipt_json, '$.dispatch_call_claimed') = 1
        AND json_extract(receipt_json, '$.dispatch_call_permitted') = 0
        AND json_extract(receipt_json, '$.automatic_takeover_permitted') = 0
    ),
    UNIQUE (notification_id, source_notification_version),
    FOREIGN KEY (notification_id, source_notification_version)
        REFERENCES m8_notification_versions(notification_id, notification_version),
    CHECK (claimed_at < lease_expires_at)
) STRICT;

CREATE INDEX idx_m8_notification_dispatch_claims_source
ON m8_notification_dispatch_claims(notification_id, source_notification_version);

CREATE TABLE m8_notification_dispatch_call_fences (
    call_fence_id TEXT PRIMARY KEY CHECK (
        length(call_fence_id) = 64 AND call_fence_id NOT GLOB '*[^0-9a-f]*'
    ),
    claim_id TEXT NOT NULL UNIQUE,
    dispatch_authorization_id TEXT NOT NULL CHECK (
        length(dispatch_authorization_id) = 64
        AND dispatch_authorization_id NOT GLOB '*[^0-9a-f]*'
    ),
    fenced_at TEXT NOT NULL CHECK (length(fenced_at) = 27),
    call_fence_manifest_id TEXT NOT NULL CHECK (
        length(call_fence_manifest_id) = 64
        AND call_fence_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (
        json_valid(receipt_json)
        AND json_extract(receipt_json, '$.schema_version') =
            'm8-notification-dispatch-call-fence-receipt-v1'
        AND json_extract(receipt_json, '$.call_fence_id') = call_fence_id
        AND json_extract(receipt_json, '$.claim.claim_id') = claim_id
        AND json_extract(receipt_json, '$.dispatch_authorization_id') =
            dispatch_authorization_id
        AND json_extract(receipt_json, '$.call_fence_manifest_id') = call_fence_manifest_id
        AND json_extract(receipt_json, '$.repository_manifest_id') = repository_manifest_id
        AND json_extract(receipt_json, '$.external_call_boundary_crossed') = 1
        AND json_extract(receipt_json, '$.additional_dispatch_call_permitted') = 0
        AND json_extract(receipt_json, '$.automatic_retry_permitted') = 0
    ),
    FOREIGN KEY (claim_id) REFERENCES m8_notification_dispatch_claims(claim_id)
) STRICT;

CREATE TABLE m8_notification_dispatch_completions (
    completion_id TEXT PRIMARY KEY CHECK (
        length(completion_id) = 64 AND completion_id NOT GLOB '*[^0-9a-f]*'
    ),
    claim_id TEXT NOT NULL UNIQUE,
    call_fence_id TEXT NOT NULL UNIQUE,
    dispatch_result_id TEXT NOT NULL UNIQUE CHECK (
        length(dispatch_result_id) = 64 AND dispatch_result_id NOT GLOB '*[^0-9a-f]*'
    ),
    notification_id TEXT NOT NULL CHECK (
        length(notification_id) = 64 AND notification_id NOT GLOB '*[^0-9a-f]*'
    ),
    notification_version INTEGER NOT NULL CHECK (notification_version > 1),
    notification_commit_receipt_id TEXT NOT NULL UNIQUE CHECK (
        length(notification_commit_receipt_id) = 64
        AND notification_commit_receipt_id NOT GLOB '*[^0-9a-f]*'
    ),
    committed_at TEXT NOT NULL CHECK (length(committed_at) = 27),
    completion_manifest_id TEXT NOT NULL CHECK (
        length(completion_manifest_id) = 64
        AND completion_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    repository_manifest_id TEXT NOT NULL CHECK (
        length(repository_manifest_id) = 64
        AND repository_manifest_id NOT GLOB '*[^0-9a-f]*'
    ),
    receipt_json TEXT NOT NULL CHECK (
        json_valid(receipt_json)
        AND json_extract(receipt_json, '$.schema_version') =
            'm8-notification-dispatch-completion-receipt-v1'
        AND json_extract(receipt_json, '$.completion_id') = completion_id
        AND json_extract(receipt_json, '$.claim.claim_id') = claim_id
        AND json_extract(receipt_json, '$.call_fence.call_fence_id') = call_fence_id
        AND json_extract(receipt_json, '$.dispatch_result.dispatch_result_id') =
            dispatch_result_id
        AND json_extract(receipt_json, '$.notification_commit.notification_id') =
            notification_id
        AND json_extract(receipt_json, '$.notification_commit.notification_version') =
            notification_version
        AND json_extract(receipt_json, '$.notification_commit.commit_receipt_id') =
            notification_commit_receipt_id
        AND json_extract(receipt_json, '$.completion_manifest_id') = completion_manifest_id
        AND json_extract(receipt_json, '$.repository_manifest_id') = repository_manifest_id
        AND json_extract(receipt_json, '$.notification_transition_committed') = 1
        AND json_extract(receipt_json, '$.additional_dispatch_call_permitted') = 0
    ),
    FOREIGN KEY (claim_id) REFERENCES m8_notification_dispatch_claims(claim_id),
    FOREIGN KEY (call_fence_id)
        REFERENCES m8_notification_dispatch_call_fences(call_fence_id),
    FOREIGN KEY (notification_id, notification_version)
        REFERENCES m8_notification_versions(notification_id, notification_version)
) STRICT;

CREATE TRIGGER m8_notification_dispatch_claims_validate_current
BEFORE INSERT ON m8_notification_dispatch_claims
WHEN NOT EXISTS (
    SELECT 1 FROM m8_notification_versions AS source
    WHERE source.notification_id = NEW.notification_id
      AND source.notification_version = NEW.source_notification_version
      AND source.status = 'QUEUED'
      AND source.notification_document_sha256 = json_extract(
          NEW.receipt_json, '$.request.source_notification_authority_sha256'
      )
      AND NOT EXISTS (
          SELECT 1 FROM m8_notification_versions AS newer
          WHERE newer.notification_id = source.notification_id
            AND newer.notification_version > source.notification_version
      )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 dispatch claim requires the current queued notification version');
END;

CREATE TRIGGER m8_notification_dispatch_call_fences_validate_current
BEFORE INSERT ON m8_notification_dispatch_call_fences
WHEN NOT EXISTS (
    SELECT 1 FROM m8_notification_dispatch_claims AS claim
    JOIN m8_notification_versions AS source
      ON source.notification_id = claim.notification_id
     AND source.notification_version = claim.source_notification_version
    WHERE claim.claim_id = NEW.claim_id
      AND NEW.fenced_at >= claim.claimed_at
      AND NEW.fenced_at < claim.lease_expires_at
      AND source.status = 'QUEUED'
      AND NOT EXISTS (
          SELECT 1 FROM m8_notification_versions AS newer
          WHERE newer.notification_id = source.notification_id
            AND newer.notification_version > source.notification_version
      )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 dispatch call fence requires a live current claim');
END;

CREATE TRIGGER m8_notification_dispatch_completions_validate_transition
BEFORE INSERT ON m8_notification_dispatch_completions
WHEN NOT EXISTS (
    SELECT 1 FROM m8_notification_dispatch_claims AS claim
    JOIN m8_notification_dispatch_call_fences AS fence ON fence.claim_id = claim.claim_id
    JOIN m8_notification_versions AS completed
      ON completed.notification_id = claim.notification_id
     AND completed.notification_version = claim.source_notification_version + 1
    WHERE claim.claim_id = NEW.claim_id
      AND fence.call_fence_id = NEW.call_fence_id
      AND completed.notification_id = NEW.notification_id
      AND completed.notification_version = NEW.notification_version
      AND completed.dispatch_result_id = NEW.dispatch_result_id
      AND completed.commit_receipt_id = NEW.notification_commit_receipt_id
      AND (
          (json_extract(NEW.receipt_json, '$.dispatch_result.disposition') = 'ACCEPTED'
           AND completed.status = 'SENT')
          OR
          (json_extract(NEW.receipt_json, '$.dispatch_result.disposition') != 'ACCEPTED'
           AND completed.status = 'FAILED')
      )
)
BEGIN
    SELECT RAISE(ABORT, 'M8 dispatch completion lacks its exact notification transition');
END;

CREATE TRIGGER m8_notification_dispatch_claims_no_update
BEFORE UPDATE ON m8_notification_dispatch_claims BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch claims are append-only');
END;
CREATE TRIGGER m8_notification_dispatch_claims_no_delete
BEFORE DELETE ON m8_notification_dispatch_claims BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch claims are append-only');
END;
CREATE TRIGGER m8_notification_dispatch_claims_no_replace
BEFORE INSERT ON m8_notification_dispatch_claims
WHEN EXISTS (
    SELECT 1 FROM m8_notification_dispatch_claims
    WHERE claim_id = NEW.claim_id
       OR (notification_id = NEW.notification_id
           AND source_notification_version = NEW.source_notification_version)
) BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch claims are append-only');
END;

CREATE TRIGGER m8_notification_dispatch_call_fences_no_update
BEFORE UPDATE ON m8_notification_dispatch_call_fences BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch call fences are append-only');
END;
CREATE TRIGGER m8_notification_dispatch_call_fences_no_delete
BEFORE DELETE ON m8_notification_dispatch_call_fences BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch call fences are append-only');
END;
CREATE TRIGGER m8_notification_dispatch_call_fences_no_replace
BEFORE INSERT ON m8_notification_dispatch_call_fences
WHEN EXISTS (
    SELECT 1 FROM m8_notification_dispatch_call_fences
    WHERE call_fence_id = NEW.call_fence_id OR claim_id = NEW.claim_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch call fences are append-only');
END;

CREATE TRIGGER m8_notification_dispatch_completions_no_update
BEFORE UPDATE ON m8_notification_dispatch_completions BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch completions are append-only');
END;
CREATE TRIGGER m8_notification_dispatch_completions_no_delete
BEFORE DELETE ON m8_notification_dispatch_completions BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch completions are append-only');
END;
CREATE TRIGGER m8_notification_dispatch_completions_no_replace
BEFORE INSERT ON m8_notification_dispatch_completions
WHEN EXISTS (
    SELECT 1 FROM m8_notification_dispatch_completions
    WHERE completion_id = NEW.completion_id OR claim_id = NEW.claim_id
) BEGIN
    SELECT RAISE(ABORT, 'M8 notification dispatch completions are append-only');
END;
