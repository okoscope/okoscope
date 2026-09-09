ALTER TABLE users
    ADD COLUMN email_verified_at TIMESTAMPTZ,
    ADD COLUMN preferred_locale TEXT NOT NULL DEFAULT 'en'
        CHECK (preferred_locale IN ('en', 'ru'));

-- Users created before mandatory verification already proved operational access.
UPDATE users SET email_verified_at = created_at WHERE email_verified_at IS NULL;

CREATE TABLE user_email_actions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
    token_digest BYTEA NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX user_email_actions_live_user_idx
    ON user_email_actions (user_id, purpose, created_at DESC)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX user_email_actions_expiry_idx
    ON user_email_actions (expires_at, id)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE transactional_mail_outbox (
    id UUID PRIMARY KEY,
    logical_key TEXT NOT NULL,
    template_kind TEXT NOT NULL CHECK (template_kind IN (
        'verify_email', 'reset_password', 'password_changed',
        'application_created'
    )),
    recipient_email TEXT NOT NULL,
    locale TEXT NOT NULL CHECK (locale IN ('en', 'ru')),
    payload_ciphertext BYTEA,
    payload_nonce BYTEA CHECK (payload_nonce IS NULL OR octet_length(payload_nonce) = 24),
    action_id UUID REFERENCES user_email_actions(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    claimed_by UUID,
    claimed_until TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_attempt_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    terminal_at TIMESTAMPTZ,
    terminal_reason TEXT CHECK (terminal_reason IN (
        'permanent_rejection', 'attempts_exhausted', 'action_expired',
        'payload_invalid'
    )),
    ciphertext_erased_at TIMESTAMPTZ,
    retain_until TIMESTAMPTZ NOT NULL,
    CHECK (char_length(logical_key) BETWEEN 1 AND 256),
    CHECK (char_length(recipient_email) BETWEEN 3 AND 254),
    CHECK (recipient_email = lower(recipient_email) AND recipient_email = btrim(recipient_email)),
    CHECK ((payload_ciphertext IS NULL) = (payload_nonce IS NULL)),
    CHECK ((claimed_by IS NULL) = (claimed_until IS NULL)),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (retain_until > created_at),
    CHECK (delivered_at IS NULL OR terminal_at IS NULL),
    UNIQUE (logical_key, recipient_email)
);

CREATE INDEX transactional_mail_due_idx
    ON transactional_mail_outbox (available_at, created_at, id)
    WHERE delivered_at IS NULL AND terminal_at IS NULL;
CREATE INDEX transactional_mail_claim_idx
    ON transactional_mail_outbox (claimed_until, id)
    WHERE delivered_at IS NULL AND terminal_at IS NULL;
CREATE INDEX transactional_mail_retention_idx
    ON transactional_mail_outbox (retain_until, id)
    WHERE delivered_at IS NOT NULL OR terminal_at IS NOT NULL;

CREATE INDEX users_unverified_cleanup_idx
    ON users (created_at, id) WHERE email_verified_at IS NULL;
