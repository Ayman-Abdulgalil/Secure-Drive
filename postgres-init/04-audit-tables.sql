-- =============================================================
-- Append-Select-only audit log tables.
-- Depends on: 01-users-groups.sql, 02-files-sharing.sql
--
-- Design principles:
--   • Audit rows are NEVER updated or deleted; enforced via triggers.
--   • Foreign keys use ON DELETE SET NULL (not CASCADE) so audit history
--     is preserved even when the referenced entity is removed.
--   • Sensitive parent IDs are also stored as plain columns (denormalized)
--     so records remain queryable after the parent is deleted.
-- =============================================================

-- ─────────────────────────────────────────────────────────────
-- Shared: block mutations on any audit table
-- ─────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_audit_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit table "%" is append-only — UPDATE and DELETE are not permitted.',
        TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;


-- ─────────────────────────────────────────────────────────────
-- Users Audit
-- ─────────────────────────────────────────────────────────────
CREATE TABLE users_audit (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Subject (SET NULL on delete to preserve history)
    user_id         UUID NOT NULL,
    user_id_fk      UUID REFERENCES users(user_id) ON DELETE SET NULL,

    -- Actor
    actor_id        UUID REFERENCES users(user_id) ON DELETE SET NULL,
    actor_type      VARCHAR(10) NOT NULL CHECK (actor_type IN ('user', 'admin', 'system')),

    -- Event
    action          VARCHAR(40) NOT NULL CHECK (action IN (
                        'login_success',
                        'login_failed',
                        'logout',
                        'session_revoked',
                        'account_created',
                        'account_deleted',
                        'account_restored',
                        'email_verified',
                        'password_changed',
                        'password_reset_requested',
                        'email_changed',
                        'storage_quota_changed'
                    )),
    outcome         VARCHAR(10) NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    denial_reason   VARCHAR(100) DEFAULT NULL,

    -- Delta (never store raw passwords — hashed or masked values only)
    old_value       JSONB DEFAULT NULL,
    new_value       JSONB DEFAULT NULL,

    -- Request context
    ip_address      VARCHAR(45) NOT NULL,
    user_agent      TEXT,
    request_id      UUID,
    geo_country     CHAR(2),
    geo_region      VARCHAR(100),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

ALTER TABLE users_audit
    ADD CONSTRAINT chk_users_audit_denial_reason
        CHECK (
            (outcome = 'success' AND denial_reason IS NULL)
            OR
            (outcome != 'success' AND denial_reason IS NOT NULL)
        ),
    ADD CONSTRAINT chk_users_audit_actor_consistency
        CHECK (actor_type != 'user' OR actor_id IS NOT NULL);

CREATE INDEX idx_users_audit_user_id         ON users_audit(user_id);
CREATE INDEX idx_users_audit_actor_id        ON users_audit(actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_users_audit_action          ON users_audit(action);
CREATE INDEX idx_users_audit_created_at      ON users_audit(created_at DESC);
CREATE INDEX idx_users_audit_outcome         ON users_audit(outcome) WHERE outcome != 'success';
CREATE INDEX idx_users_audit_ip              ON users_audit(ip_address);
CREATE INDEX idx_users_audit_user_activity   ON users_audit(user_id, created_at DESC);
CREATE INDEX idx_users_audit_ip_failed       ON users_audit(ip_address, action, created_at DESC)
                                            WHERE outcome = 'denied';

CREATE TRIGGER trg_users_audit_immutable
    BEFORE UPDATE OR DELETE ON users_audit
    FOR EACH ROW EXECUTE FUNCTION fn_audit_immutable();


-- ─────────────────────────────────────────────────────────────
-- Groups Audit
-- ─────────────────────────────────────────────────────────────
CREATE TABLE groups_audit (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Subject
    group_id        UUID NOT NULL,
    group_id_fk     UUID REFERENCES groups(group_id) ON DELETE SET NULL,

    -- Actor
    actor_id        UUID REFERENCES users(user_id) ON DELETE SET NULL,
    actor_type      VARCHAR(10) NOT NULL CHECK (actor_type IN ('user', 'admin', 'system')),

    -- Affected member (for membership events only)
    target_user_id  UUID REFERENCES users(user_id) ON DELETE SET NULL,

    -- Event
    action          VARCHAR(40) NOT NULL CHECK (action IN (
                        'group_created',
                        'group_deleted',
                        'group_restored',
                        'group_renamed',
                        'group_description_changed',
                        'member_added',
                        'member_removed',
                        'member_deactivated',
                        'member_role_changed',
                        'ownership_transferred',
                        'storage_quota_changed'
                    )),
    outcome         VARCHAR(10) NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    denial_reason   VARCHAR(100) DEFAULT NULL,

    -- Delta
    old_value       JSONB DEFAULT NULL,
    new_value       JSONB DEFAULT NULL,

    -- Request context
    ip_address      VARCHAR(45) NOT NULL,
    user_agent      TEXT,
    request_id      UUID,
    geo_country     CHAR(2),
    geo_region      VARCHAR(100),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

ALTER TABLE groups_audit
    ADD CONSTRAINT chk_groups_audit_denial_reason
        CHECK (
            (outcome = 'success' AND denial_reason IS NULL)
            OR
            (outcome != 'success' AND denial_reason IS NOT NULL)
        ),
    ADD CONSTRAINT chk_groups_audit_membership_target
        CHECK (
            action NOT IN ('member_added', 'member_removed', 'member_deactivated', 'member_role_changed')
            OR target_user_id IS NOT NULL
        ),
    ADD CONSTRAINT chk_groups_audit_actor_consistency
        CHECK (actor_type != 'user' OR actor_id IS NOT NULL);

CREATE INDEX idx_groups_audit_group_id       ON groups_audit(group_id);
CREATE INDEX idx_groups_audit_actor_id       ON groups_audit(actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_groups_audit_target_user    ON groups_audit(target_user_id) WHERE target_user_id IS NOT NULL;
CREATE INDEX idx_groups_audit_action         ON groups_audit(action);
CREATE INDEX idx_groups_audit_created_at     ON groups_audit(created_at DESC);
CREATE INDEX idx_groups_audit_outcome        ON groups_audit(outcome) WHERE outcome != 'success';
CREATE INDEX idx_groups_audit_group_activity ON groups_audit(group_id, created_at DESC);
CREATE INDEX idx_groups_audit_user_history   ON groups_audit(target_user_id, created_at DESC)
                                            WHERE target_user_id IS NOT NULL;

CREATE TRIGGER trg_groups_audit_immutable
    BEFORE UPDATE OR DELETE ON groups_audit
    FOR EACH ROW EXECUTE FUNCTION fn_audit_immutable();


-- ─────────────────────────────────────────────────────────────
-- Files Audit
-- ─────────────────────────────────────────────────────────────
CREATE TABLE files_audit (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Subject (denormalized + FK; FK becomes NULL if file is deleted)
    file_id       UUID NOT NULL,
    file_id_fk    UUID REFERENCES files_metadata(file_id) ON DELETE SET NULL,

    -- Actor
    actor_id        UUID REFERENCES users(user_id) ON DELETE SET NULL,
    actor_type      VARCHAR(10) NOT NULL CHECK (actor_type IN ('user', 'admin', 'system')),

    -- Event
    action          VARCHAR(40) NOT NULL CHECK (action IN (
                        'file_uploaded',
                        'file_deleted',
                        'file_restored',
                        'file_renamed',
                        'file_moved',
                        'content_type_changed',
                        'file_overwritten',
                        'ownership_transferred'
                    )),
    outcome         VARCHAR(10) NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    denial_reason   VARCHAR(100) DEFAULT NULL,

    -- Delta
    old_value       JSONB DEFAULT NULL,
    new_value       JSONB DEFAULT NULL,

    -- Snapshot of file state at event time (survives file deletion/rename)
    file_key_snap TEXT NOT NULL,
    name_snap       TEXT NOT NULL,
    folder_snap     TEXT NOT NULL,
    size_bytes_snap BIGINT NOT NULL,
    sha256_snap     CHAR(64) NOT NULL,

    -- Request context
    ip_address      VARCHAR(45) NOT NULL,
    user_agent      TEXT,
    request_id      UUID,
    geo_country     CHAR(2),
    geo_region      VARCHAR(100),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

ALTER TABLE files_audit
    ADD CONSTRAINT chk_files_audit_denial_reason
        CHECK (
            (outcome = 'success' AND denial_reason IS NULL)
            OR
            (outcome != 'success' AND denial_reason IS NOT NULL)
        ),
    ADD CONSTRAINT chk_files_audit_actor_consistency
        CHECK (actor_type != 'user' OR actor_id IS NOT NULL),
    ADD CONSTRAINT chk_files_audit_upload_has_new_value
        CHECK (action != 'file_uploaded' OR new_value IS NOT NULL),
    ADD CONSTRAINT chk_files_audit_mutation_has_both_values
        CHECK (
            action NOT IN ('file_renamed', 'file_moved', 'content_type_changed',
                           'file_overwritten', 'ownership_transferred')
            OR (old_value IS NOT NULL AND new_value IS NOT NULL)
        ),
    ADD CONSTRAINT chk_files_audit_size_snap_positive
        CHECK (size_bytes_snap > 0),
    ADD CONSTRAINT chk_files_audit_sha256_snap_format
        CHECK (sha256_snap ~ '^[a-f0-9]{64}$');

CREATE INDEX idx_files_audit_file_id      ON files_audit(file_id);
CREATE INDEX idx_files_audit_actor_id       ON files_audit(actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_files_audit_action         ON files_audit(action);
CREATE INDEX idx_files_audit_created_at     ON files_audit(created_at DESC);
CREATE INDEX idx_files_audit_outcome        ON files_audit(outcome) WHERE outcome != 'success';
CREATE INDEX idx_files_audit_sha256         ON files_audit(sha256_snap);
CREATE INDEX idx_files_audit_file_activity  ON files_audit(file_id, created_at DESC);
CREATE INDEX idx_files_audit_actor_activity ON files_audit(actor_id, created_at DESC)
                                            WHERE actor_id IS NOT NULL;

CREATE TRIGGER trg_files_audit_immutable
    BEFORE UPDATE OR DELETE ON files_audit
    FOR EACH ROW EXECUTE FUNCTION fn_audit_immutable();


-- ─────────────────────────────────────────────────────────────
-- Shared Files Audit
-- ─────────────────────────────────────────────────────────────
CREATE TABLE shared_files_audit (
    audit_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Subject (denormalized + FK)
    share_id        UUID NOT NULL,
    share_id_fk     UUID REFERENCES shared_files(share_id) ON DELETE SET NULL,
    file_id         UUID NOT NULL,                  -- denormalized; survives share deletion

    -- Actor
    actor_id        UUID REFERENCES users(user_id) ON DELETE SET NULL,
    actor_type      VARCHAR(10) NOT NULL CHECK (actor_type IN ('user', 'admin', 'system')),

    -- Recipient snapshot
    recipient_id    UUID REFERENCES users(user_id) ON DELETE SET NULL,
    share_type_snap VARCHAR(20) NOT NULL
                        CHECK (share_type_snap IN ('public_link', 'specific_user')),

    -- Event
    action          VARCHAR(40) NOT NULL CHECK (action IN (
                        'share_created',
                        'share_revoked',
                        'share_accessed',
                        'share_access_denied',
                        'permission_changed',
                        'password_added',
                        'password_removed',
                        'password_changed',
                        'password_failed',
                        'expiry_set',
                        'expiry_changed',
                        'expiry_removed',
                        'share_expired',
                        'access_limit_set',
                        'access_limit_changed',
                        'access_limit_removed',
                        'access_limit_reached'
                    )),
    outcome         VARCHAR(10) NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    denial_reason   VARCHAR(100) DEFAULT NULL,

    -- Delta
    old_value       JSONB DEFAULT NULL,
    new_value       JSONB DEFAULT NULL,

    -- Request context
    ip_address      VARCHAR(45) NOT NULL,
    user_agent      TEXT,
    request_id      UUID,
    geo_country     CHAR(2),
    geo_region      VARCHAR(100),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc')
);

ALTER TABLE shared_files_audit
    ADD CONSTRAINT chk_shared_audit_denial_reason
        CHECK (
            (outcome = 'success' AND denial_reason IS NULL)
            OR
            (outcome != 'success' AND denial_reason IS NOT NULL)
        ),
    ADD CONSTRAINT chk_shared_audit_actor_consistency
        CHECK (actor_type != 'user' OR actor_id IS NOT NULL),
    ADD CONSTRAINT chk_shared_audit_mutation_has_values
        CHECK (
            action NOT IN (
                'permission_changed', 'password_changed',
                'expiry_changed', 'access_limit_changed'
            )
            OR (old_value IS NOT NULL AND new_value IS NOT NULL)
        );

CREATE INDEX idx_shared_audit_share_id       ON shared_files_audit(share_id);
CREATE INDEX idx_shared_audit_file_id        ON shared_files_audit(file_id);
CREATE INDEX idx_shared_audit_actor_id       ON shared_files_audit(actor_id) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_shared_audit_recipient_id   ON shared_files_audit(recipient_id) WHERE recipient_id IS NOT NULL;
CREATE INDEX idx_shared_audit_action         ON shared_files_audit(action);
CREATE INDEX idx_shared_audit_created_at     ON shared_files_audit(created_at DESC);
CREATE INDEX idx_shared_audit_outcome        ON shared_files_audit(outcome) WHERE outcome != 'success';
CREATE INDEX idx_shared_audit_ip             ON shared_files_audit(ip_address);
CREATE INDEX idx_shared_audit_share_activity ON shared_files_audit(share_id, created_at DESC);
CREATE INDEX idx_shared_audit_file_activity  ON shared_files_audit(file_id, created_at DESC);
CREATE INDEX idx_shared_audit_ip_denied      ON shared_files_audit(ip_address, action, created_at DESC)
                                            WHERE outcome = 'denied';

CREATE TRIGGER trg_shared_files_audit_immutable
    BEFORE UPDATE OR DELETE ON shared_files_audit
    FOR EACH ROW EXECUTE FUNCTION fn_audit_immutable();