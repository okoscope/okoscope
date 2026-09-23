CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at TIMESTAMPTZ,
    CHECK (email = lower(email)),
    CHECK (email = btrim(email)),
    CHECK (char_length(email) BETWEEN 3 AND 254),
    CHECK (char_length(password_hash) BETWEEN 32 AND 512)
);

CREATE TABLE organization_memberships (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX organization_memberships_user_idx
    ON organization_memberships (user_id, created_at, organization_id);

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (organization_id, user_id)
        REFERENCES organization_memberships(organization_id, user_id) ON DELETE CASCADE,
    CHECK (expires_at > created_at)
);

CREATE INDEX user_sessions_active_lookup_idx
    ON user_sessions (token_hash, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX user_sessions_user_recent_idx
    ON user_sessions (user_id, created_at DESC)
    WHERE revoked_at IS NULL;

ALTER TABLE runtime_event_groups
    RENAME COLUMN status_changed_by TO status_changed_by_legacy_api_credential_id;

ALTER TABLE runtime_event_groups
    DROP CONSTRAINT IF EXISTS runtime_event_groups_status_changed_by_fkey;

ALTER TABLE runtime_event_groups
    ADD COLUMN status_changed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN status_changed_by_kind TEXT CHECK (
        status_changed_by_kind IN ('user', 'system_admin', 'legacy_api_credential')
    );

UPDATE runtime_event_groups
SET status_changed_by_kind = 'legacy_api_credential'
WHERE status_changed_by_legacy_api_credential_id IS NOT NULL;

ALTER TABLE notification_recovery_operations
    DROP CONSTRAINT IF EXISTS notification_recovery_operations_actor_id_fkey,
    DROP CONSTRAINT IF EXISTS notification_recovery_operations_actor_kind_check;

ALTER TABLE notification_recovery_operations
    ALTER COLUMN actor_id DROP NOT NULL,
    ADD CONSTRAINT notification_recovery_operations_actor_kind_check
        CHECK (actor_kind IN ('user', 'system_admin', 'legacy_api_credential')),
    ADD CONSTRAINT notification_recovery_operations_actor_shape_check
        CHECK (
            (actor_kind = 'system_admin' AND actor_id IS NULL)
            OR (actor_kind IN ('user', 'legacy_api_credential') AND actor_id IS NOT NULL)
        );

UPDATE notification_recovery_operations
SET actor_kind = 'legacy_api_credential'
WHERE actor_kind = 'api_credential';

ALTER TABLE notification_recovery_operations
    ADD CONSTRAINT notification_recovery_operations_user_actor_fkey
        FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE RESTRICT NOT VALID;

DROP TABLE api_credentials;
