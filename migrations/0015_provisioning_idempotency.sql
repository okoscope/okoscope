CREATE TABLE provisioning_idempotency_keys (
    id UUID PRIMARY KEY,
    operation VARCHAR(64) NOT NULL,
    key_hash BYTEA NOT NULL CHECK (octet_length(key_hash) = 32),
    request_fingerprint BYTEA NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    resource_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (operation, key_hash)
);

CREATE INDEX provisioning_idempotency_keys_created_at_idx
    ON provisioning_idempotency_keys (created_at);
