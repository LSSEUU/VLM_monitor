-- Fail closed when upgrading a database whose run identities cannot map to
-- distinct portable filesystem directories, or whose backlog history already
-- contains an impossible adjacent transition.  This table exists only inside
-- the migration transaction and is removed before the migration commits.
CREATE TABLE m3_authority_hardening_preflight (
    violation_count INTEGER NOT NULL CHECK (violation_count = 0)
) STRICT;

INSERT INTO m3_authority_hardening_preflight(violation_count)
SELECT COUNT(*)
FROM runs
WHERE substr(run_id, -1, 1) = '.'
   OR upper(
        CASE
            WHEN instr(run_id, '.') > 0
                THEN substr(run_id, 1, instr(run_id, '.') - 1)
            ELSE run_id
        END
      ) IN (
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
        'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5',
        'LPT6', 'LPT7', 'LPT8', 'LPT9'
      );

INSERT INTO m3_authority_hardening_preflight(violation_count)
SELECT COUNT(*)
FROM backlog_item_versions AS current
LEFT JOIN backlog_item_versions AS previous
  ON previous.run_id = current.run_id
 AND previous.item_id = current.item_id
 AND previous.version = current.version - 1
LEFT JOIN backlog_items AS identity
  ON identity.run_id = current.run_id
 AND identity.item_id = current.item_id
WHERE (
        current.version = 1
        AND (
            identity.item_id IS NULL
            OR current.status <> 'PENDING'
            OR current.attempt_count <> 0
            OR current.retry_generation
                <> CAST(json_extract(identity.initial_json, '$.retry_generation') AS INTEGER)
            OR current.lease_id IS NOT NULL
            OR current.lease_owner_sha256 IS NOT NULL
            OR current.lease_expires_at IS NOT NULL
            OR current.item_json <> identity.initial_json
            OR current.document_sha256 <> identity.initial_document_sha256
        )
      )
   OR (
        current.version > 1
        AND (
            previous.version IS NULL
            OR NOT (
                (
                    previous.status = 'PENDING'
                    AND current.status = 'LEASED'
                    AND current.attempt_count = previous.attempt_count + 1
                    AND current.retry_generation = previous.retry_generation
                    AND current.lease_id IS NOT NULL
                    AND current.lease_owner_sha256 IS NOT NULL
                    AND current.lease_expires_at IS NOT NULL
                )
                OR
                (
                    previous.status = 'LEASED'
                    AND current.status IN ('PENDING', 'COMPLETED', 'EXHAUSTED')
                    AND current.attempt_count = previous.attempt_count
                    AND current.lease_id IS NULL
                    AND current.lease_owner_sha256 IS NULL
                    AND current.lease_expires_at IS NULL
                    AND (
                        current.retry_generation = previous.retry_generation
                        OR (
                            current.status = 'PENDING'
                            AND current.retry_generation = previous.retry_generation + 1
                        )
                    )
                )
            )
        )
      );

DROP TABLE m3_authority_hardening_preflight;

-- SQLite's built-in NOCASE collation folds ASCII only.  That is exactly the
-- reference-token alphabet and the common case-insensitive filesystem model.
CREATE UNIQUE INDEX uq_runs_filesystem_identity_nocase
    ON runs(run_id COLLATE NOCASE);

CREATE TRIGGER runs_portable_filesystem_identity_insert
BEFORE INSERT ON runs
WHEN substr(NEW.run_id, -1, 1) = '.'
  OR upper(
        CASE
            WHEN instr(NEW.run_id, '.') > 0
                THEN substr(NEW.run_id, 1, instr(NEW.run_id, '.') - 1)
            ELSE NEW.run_id
        END
     ) IN (
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
        'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5',
        'LPT6', 'LPT7', 'LPT8', 'LPT9'
     )
BEGIN
    SELECT RAISE(ABORT, 'run_id is not a portable filesystem identity');
END;

CREATE TRIGGER backlog_item_versions_validate_transition
BEFORE INSERT ON backlog_item_versions
WHEN NOT (
    (
        NEW.version = 1
        AND NEW.status = 'PENDING'
        AND NEW.attempt_count = 0
        AND NEW.lease_id IS NULL
        AND NEW.lease_owner_sha256 IS NULL
        AND NEW.lease_expires_at IS NULL
        AND EXISTS (
            SELECT 1
            FROM backlog_items AS identity
            WHERE identity.run_id = NEW.run_id
              AND identity.item_id = NEW.item_id
              AND identity.initial_json = NEW.item_json
              AND identity.initial_document_sha256 = NEW.document_sha256
              AND NEW.retry_generation
                  = CAST(json_extract(identity.initial_json, '$.retry_generation') AS INTEGER)
        )
    )
    OR
    (
        NEW.version > 1
        AND EXISTS (
            SELECT 1
            FROM backlog_item_versions AS previous
            WHERE previous.run_id = NEW.run_id
              AND previous.item_id = NEW.item_id
              AND previous.version = NEW.version - 1
              AND (
                  (
                      previous.status = 'PENDING'
                      AND NEW.status = 'LEASED'
                      AND NEW.attempt_count = previous.attempt_count + 1
                      AND NEW.retry_generation = previous.retry_generation
                      AND NEW.lease_id IS NOT NULL
                      AND NEW.lease_owner_sha256 IS NOT NULL
                      AND NEW.lease_expires_at IS NOT NULL
                  )
                  OR
                  (
                      previous.status = 'LEASED'
                      AND NEW.status IN ('PENDING', 'COMPLETED', 'EXHAUSTED')
                      AND NEW.attempt_count = previous.attempt_count
                      AND NEW.lease_id IS NULL
                      AND NEW.lease_owner_sha256 IS NULL
                      AND NEW.lease_expires_at IS NULL
                      AND (
                          NEW.retry_generation = previous.retry_generation
                          OR (
                              NEW.status = 'PENDING'
                              AND NEW.retry_generation = previous.retry_generation + 1
                          )
                      )
                  )
              )
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'backlog history transition is invalid');
END;
