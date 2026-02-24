-- =============================================================
-- Table: refresh_tokens
-- Depends on: 01-users-groups.sql
-- =============================================================

CREATE TABLE refresh_tokens (
    token_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,

    -- The stored value must be a SHA-256 hex digest of the raw token.
    -- Never store the raw token itself.
    token_hash      CHAR(64) NOT NULL,

    -- Validity window
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT (NOW() AT TIME ZONE 'utc'),
    expires_at      TIMESTAMPTZ NOT NULL,

    -- Revocation
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ DEFAULT NULL,

    -- Rotation / replay detection
    -- All tokens belonging to the same rotation chain share a family_id.
    -- Detecting reuse of a superseded token in a family → revoke the whole family.
    family_id       UUID NOT NULL DEFAULT gen_random_uuid(),
    superseded_by   UUID REFERENCES refresh_tokens(token_id) ON DELETE SET NULL,

    -- Context
    device_info     TEXT,
    ip_address      VARCHAR(45),
    last_used_at    TIMESTAMPTZ DEFAULT NULL
);

ALTER TABLE refresh_tokens
    ADD CONSTRAINT chk_tokens_hash_format
        CHECK (token_hash ~ '^[a-f0-9]{64}$'),
    ADD CONSTRAINT chk_tokens_expires_after_issued
        CHECK (expires_at > issued_at),
    ADD CONSTRAINT chk_tokens_revoked_consistency
        CHECK (
            (revoked = FALSE AND revoked_at IS NULL)
            OR
            (revoked = TRUE  AND revoked_at IS NOT NULL)
        );

-- Lookup by hash (hot path for every authenticated request)
CREATE UNIQUE INDEX idx_refresh_tokens_token_hash
    ON refresh_tokens(token_hash);

-- Efficiently find all tokens for a user (e.g. logout-all-devices)
CREATE INDEX idx_refresh_tokens_user_id
    ON refresh_tokens(user_id);

-- Active tokens per user — most common security query
CREATE INDEX idx_refresh_tokens_user_active
    ON refresh_tokens(user_id, revoked)
    WHERE revoked = FALSE;

-- Expiry sweeper job
CREATE INDEX idx_refresh_tokens_expires_at
    ON refresh_tokens(expires_at)
    WHERE revoked = FALSE;

-- Family-level revocation (token reuse / replay attack response)
CREATE INDEX idx_refresh_tokens_family_id
    ON refresh_tokens(family_id);