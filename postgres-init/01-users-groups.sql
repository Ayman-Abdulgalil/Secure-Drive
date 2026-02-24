-- =============================================================
-- Tables: users, groups, group_members
-- Shared trigger functions are defined here first so subsequent
-- scripts can reference them safely.
-- =============================================================

-- ─────────────────────────────────────────────────────────────
-- Shared trigger: auto-update updated_at on any table
-- Named update_updated_at() — single canonical definition.
-- All other scripts reference this; do NOT redefine it.
-- ─────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW() AT TIME ZONE 'utc';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- ─────────────────────────────────────────────────────────────
-- Users
-- ─────────────────────────────────────────────────────────────
CREATE TABLE users (
    user_id         UUID PRIMARY KEY,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,

    -- Timestamps
    created_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    updated_at      TIMESTAMPTZ DEFAULT NULL,
    last_login      TIMESTAMPTZ DEFAULT NULL,

    -- Storage
    storage_used    BIGINT NOT NULL DEFAULT 0,
    storage_quota   BIGINT NOT NULL DEFAULT 10737418240,    -- 10 GiB

    -- State
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    valid_since     TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),   -- used to invalidate old tokens
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

ALTER TABLE users
    ADD CONSTRAINT chk_users_email_format
        CHECK (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
    ADD CONSTRAINT chk_users_storage_used_non_negative
        CHECK (storage_used >= 0),
    ADD CONSTRAINT chk_users_storage_quota_positive
        CHECK (storage_quota > 0),
    ADD CONSTRAINT chk_users_storage_within_quota
        CHECK (storage_used <= storage_quota),
    ADD CONSTRAINT chk_users_name_not_blank
        CHECK (LENGTH(TRIM(name)) > 0);

CREATE INDEX idx_users_created_at  ON users(created_at);
CREATE INDEX idx_users_is_active   ON users(is_active) WHERE is_active = TRUE;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ─────────────────────────────────────────────────────────────
-- Groups
-- ─────────────────────────────────────────────────────────────
CREATE TABLE groups (
    group_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    slug            VARCHAR(255) UNIQUE NOT NULL,   -- URL-friendly identifier (e.g. "engineering-team")

    -- Ownership
    owner_id        UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,

    -- Storage
    storage_quota   BIGINT NOT NULL DEFAULT 10737418240,
    storage_used    BIGINT NOT NULL DEFAULT 0,

    -- State
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,

    -- Timestamps
    created_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    updated_at      TIMESTAMPTZ DEFAULT NULL
);

ALTER TABLE groups
    ADD CONSTRAINT chk_groups_storage_used_non_negative
        CHECK (storage_used >= 0),
    ADD CONSTRAINT chk_groups_storage_quota_positive
        CHECK (storage_quota > 0),
    ADD CONSTRAINT chk_groups_storage_within_quota
        CHECK (storage_used <= storage_quota),
    ADD CONSTRAINT chk_groups_slug_format
        CHECK (slug ~ '^[a-z0-9]+(?:-[a-z0-9]+)*$'),
    ADD CONSTRAINT chk_groups_name_not_blank
        CHECK (LENGTH(TRIM(name)) > 0);

CREATE INDEX idx_groups_owner_id    ON groups(owner_id);
CREATE INDEX idx_groups_slug        ON groups(slug);
CREATE INDEX idx_groups_is_active   ON groups(is_active) WHERE is_active = TRUE;

CREATE TRIGGER trg_groups_updated_at
    BEFORE UPDATE ON groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ─────────────────────────────────────────────────────────────
-- Group Members
-- ─────────────────────────────────────────────────────────────
CREATE TABLE group_members (
    membership_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id        UUID NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

    -- Role
    role            VARCHAR(20) NOT NULL DEFAULT 'member'
                        CHECK (role IN ('admin', 'member')),

    -- Invitation tracking
    invited_by      UUID REFERENCES users(user_id) ON DELETE SET NULL,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),

    -- State
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    deactivated_at  TIMESTAMPTZ DEFAULT NULL,
    deactivated_by  UUID REFERENCES users(user_id) ON DELETE SET NULL,

    UNIQUE (group_id, user_id)
);

ALTER TABLE group_members
    ADD CONSTRAINT chk_group_members_deactivation_consistency
        CHECK (
            (is_active = TRUE  AND deactivated_at IS NULL AND deactivated_by IS NULL)
            OR
            (is_active = FALSE AND deactivated_at IS NOT NULL)
        ),
    ADD CONSTRAINT chk_group_members_not_self_invite
        CHECK (invited_by IS NULL OR invited_by != user_id);

CREATE INDEX idx_group_members_group_id  ON group_members(group_id);
CREATE INDEX idx_group_members_user_id   ON group_members(user_id);
CREATE INDEX idx_group_members_role      ON group_members(group_id, role) WHERE is_active = TRUE;
CREATE INDEX idx_group_members_active    ON group_members(group_id, user_id) WHERE is_active = TRUE;


-- ─────────────────────────────────────────────────────────────
-- Prevent deactivating the group owner's membership
-- ─────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION fn_check_owner_is_member()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_active = FALSE THEN
        IF EXISTS (
            SELECT 1 FROM groups
            WHERE group_id = NEW.group_id
              AND owner_id  = NEW.user_id
        ) THEN
            RAISE EXCEPTION 'Cannot deactivate the group owner membership (group_id=%, user_id=%).',
                NEW.group_id, NEW.user_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_group_members_check_owner
    BEFORE UPDATE ON group_members
    FOR EACH ROW EXECUTE FUNCTION fn_check_owner_is_member();