-- =============================================================
-- Application database roles: secure_drive, secure_drive_audit_reader
--
-- Principle of least privilege:
--   • The app user gets only the permissions it actually needs.
--   • Audit tables: INSERT only — secure_drive can write events but
--     cannot read, update, or delete its own audit trail.
--   • Audit tables: SELECT only — secure_drive_audit_reader can read
--     audit tables but cannot write, update, or delete them.
--   • No DDL, no TRUNCATE, no REFERENCES, no TRIGGER grants.
--   • Public schema default privileges are tightened.
--   • Password must be passed via psql variable:
--       psql -v audit_log_password="'s3cr3t'" -f 05-secure-drive-user.sql
--     Or replace :audit_log_password below with a vault-injected secret.
-- =============================================================

-- Create the role (connection limit guards against connection exhaustion)
CREATE ROLE secure_drive WITH
    LOGIN
    PASSWORD :audit_log_password          -- supply via -v audit_log_password="'...'" or your secrets manager
    CONNECTION LIMIT 100
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT;

-- Create the role (connection limit guards against connection exhaustion)
CREATE ROLE secure_drive_audit_reader WITH
    LOGIN
    PASSWORD :audit_query_password          -- supply via -v audit_query_password="'...'" or your secrets manager
    CONNECTION LIMIT 10
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT;

-- ─────────────────────────────────────────────────────────────
-- Schema usage
-- ─────────────────────────────────────────────────────────────
GRANT USAGE ON SCHEMA public TO secure_drive;

-- Revoke the default CREATE that PUBLIC has on the public schema
-- (PostgreSQL ≤ 14 grants this by default; safe to run on all versions)
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- ─────────────────────────────────────────────────────────────
-- Core application tables  (SELECT, INSERT, UPDATE, DELETE)
-- ─────────────────────────────────────────────────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    users, 
    groups,
    group_members,
    files_metadata,
    shared_files,
    refresh_tokens
TO secure_drive;

-- ─────────────────────────────────────────────────────────────
-- Audit tables  (INSERT only — the app appends but never edits)
-- ─────────────────────────────────────────────────────────────
GRANT INSERT ON TABLE
    users_audit,
    groups_audit,
    files_audit,
    shared_files_audit
TO secure_drive;

-- ─────────────────────────────────────────────────────────────
-- Audit tables  (INSERT only — the app appends but never edits)
-- ─────────────────────────────────────────────────────────────
GRANT INSERT ON TABLE
    users_audit,
    groups_audit,
    files_audit,
    shared_files_audit
TO secure_drive;

-- ─────────────────────────────────────────────────────────────
-- Audit tables  (SELECT only — the reader can read but not write)
-- ─────────────────────────────────────────────────────────────
GRANT SELECT ON TABLE
    users_audit,
    groups_audit,
    files_audit,
    shared_files_audit
TO secure_drive_audit_reader;

-- ─────────────────────────────────────────────────────────────
-- Sequences  (needed for gen_random_uuid()-backed DEFAULT values
-- generated outside Postgres, and any SERIAL/BIGSERIAL columns)
-- ─────────────────────────────────────────────────────────────
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO secure_drive;

-- ─────────────────────────────────────────────────────────────
-- Lock down defaults so future tables are NOT auto-accessible
-- ─────────────────────────────────────────────────────────────
-- Revoke the default PUBLIC privileges on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON TABLES FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM PUBLIC;

-- ─────────────────────────────────────────────────────────────
-- Read-only reporting role  (optional — uncomment if needed)
-- ─────────────────────────────────────────────────────────────
-- CREATE ROLE secure_drive_readonly WITH LOGIN PASSWORD :readonly_password
--     CONNECTION LIMIT 20 NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
--
-- GRANT USAGE ON SCHEMA public TO secure_drive_readonly;
--
-- GRANT SELECT ON TABLE
--     users, groups, group_members, files_metadata, shared_files,
--     refresh_tokens, users_audit, groups_audit, files_audit, shared_files_audit
-- TO secure_drive_readonly;