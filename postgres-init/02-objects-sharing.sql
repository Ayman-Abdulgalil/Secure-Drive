-- =============================================================
-- Tables: files_metadata, shared_files
-- Depends on: 01-users-groups.sql
-- =============================================================

-- ─────────────────────────────────────────────────────────────
-- files Metadata  (one row per stored file)
-- ─────────────────────────────────────────────────────────────
CREATE TABLE files_metadata (
    file_id       UUID PRIMARY KEY,
    owner_id        UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

    -- Storage location
    bucket          TEXT NOT NULL,
    folder          TEXT NOT NULL DEFAULT '/',
    file_key      TEXT NOT NULL UNIQUE,

    -- File identity
    original_name   TEXT NOT NULL,
    current_name    TEXT NOT NULL,
    content_type    VARCHAR(255),
    size_bytes      BIGINT NOT NULL,
    sha256_hex      CHAR(64) NOT NULL,

    -- Timestamps
    created_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    updated_at      TIMESTAMPTZ DEFAULT NULL
);

ALTER TABLE files_metadata
    ADD CONSTRAINT chk_files_size_positive
        CHECK (size_bytes > 0),
    ADD CONSTRAINT chk_files_sha256_format
        CHECK (sha256_hex ~ '^[a-f0-9]{64}$'),
    ADD CONSTRAINT chk_files_folder_starts_with_slash
        CHECK (folder ~ '^/'),
    ADD CONSTRAINT chk_files_names_not_blank
        CHECK (LENGTH(TRIM(original_name)) > 0 AND LENGTH(TRIM(current_name)) > 0);

CREATE INDEX idx_files_folder      ON files_metadata(folder);
CREATE INDEX idx_files_owner_id    ON files_metadata(owner_id);
CREATE INDEX idx_files_created_at  ON files_metadata(created_at);
CREATE INDEX idx_files_sha256      ON files_metadata(sha256_hex);

CREATE TRIGGER trg_files_updated_at
    BEFORE UPDATE ON files_metadata
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ─────────────────────────────────────────────────────────────
-- Shared Files
-- ─────────────────────────────────────────────────────────────
CREATE TABLE shared_files (
    share_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The file being shared — enforced FK into files_metadata
    file_id         UUID NOT NULL REFERENCES files_metadata(file_id) ON DELETE CASCADE,
    owner_id        UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

    -- Sharing model
    share_type      VARCHAR(20) NOT NULL CHECK (share_type IN ('public_link', 'specific_user')),
    recipient_id    UUID REFERENCES users(user_id) ON DELETE CASCADE,       -- NULL for public_link
    public_token    VARCHAR(128) UNIQUE,                                    -- NULL for specific_user; must be cryptographically random (≥ 128 bits)

    -- Password protection
    password_hash   VARCHAR(256),
    password_salt   VARCHAR(64),

    -- Permissions
    can_view        BOOLEAN NOT NULL DEFAULT TRUE,
    can_download    BOOLEAN NOT NULL DEFAULT FALSE,
    can_edit        BOOLEAN NOT NULL DEFAULT FALSE,
    can_reshare     BOOLEAN NOT NULL DEFAULT FALSE,

    -- Expiry
    expires_at      TIMESTAMPTZ DEFAULT NULL,                               -- NULL = no expiry

    -- State
    is_revoked      BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ DEFAULT NULL,
    revoked_by      UUID REFERENCES users(user_id) ON DELETE SET NULL,

    -- Access limits
    max_access_count    INT DEFAULT NULL,                                   -- NULL = unlimited
    access_count        INT NOT NULL DEFAULT 0,

    -- Metadata
    created_at          TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    created_by_ip       VARCHAR(45),
    note                TEXT DEFAULT NULL
);

ALTER TABLE shared_files
    ADD CONSTRAINT chk_shared_recipient_or_token
        CHECK (
            (share_type = 'specific_user' AND recipient_id IS NOT NULL AND public_token IS NULL)
            OR
            (share_type = 'public_link'   AND public_token IS NOT NULL AND recipient_id IS NULL)
        ),
    ADD CONSTRAINT chk_shared_password_fields
        CHECK (
            (password_hash IS NULL AND password_salt IS NULL)
            OR
            (password_hash IS NOT NULL AND password_salt IS NOT NULL)
        ),
    ADD CONSTRAINT chk_shared_revoked_consistency
        CHECK (
            (is_revoked = FALSE AND revoked_at IS NULL AND revoked_by IS NULL)
            OR
            (is_revoked = TRUE  AND revoked_at IS NOT NULL)
        ),
    ADD CONSTRAINT chk_shared_reshare_requires_view
        CHECK (can_reshare = FALSE OR can_view = TRUE),
    ADD CONSTRAINT chk_shared_max_access_count_positive
        CHECK (max_access_count IS NULL OR max_access_count > 0),
    ADD CONSTRAINT chk_shared_access_count_non_negative
        CHECK (access_count >= 0),
    ADD CONSTRAINT chk_shared_access_count_within_max
        CHECK (max_access_count IS NULL OR access_count <= max_access_count),
    ADD CONSTRAINT chk_shared_expires_future_on_create
        -- Prevents setting an expiry that is already in the past at insert time.
        -- NOTE: only validated at row creation; update path enforced at app layer.
        CHECK (expires_at IS NULL OR expires_at > created_at),
    ADD CONSTRAINT chk_shared_owner_not_recipient
        CHECK (recipient_id IS NULL OR recipient_id != owner_id);

CREATE INDEX idx_shared_files_file_id        ON shared_files(file_id);
CREATE INDEX idx_shared_files_owner_id       ON shared_files(owner_id);
CREATE INDEX idx_shared_files_recipient_id   ON shared_files(recipient_id)   WHERE recipient_id IS NOT NULL;
CREATE INDEX idx_shared_files_public_token   ON shared_files(public_token)   WHERE public_token IS NOT NULL;
CREATE INDEX idx_shared_files_expires_at     ON shared_files(expires_at)     WHERE expires_at IS NOT NULL;
CREATE INDEX idx_shared_files_active         ON shared_files(file_id, is_revoked) WHERE is_revoked = FALSE;

CREATE TRIGGER trg_shared_files_updated_at
    BEFORE UPDATE ON shared_files
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();