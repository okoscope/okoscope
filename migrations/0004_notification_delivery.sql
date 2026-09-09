ALTER TABLE outbox_messages
    ADD COLUMN materialized_at TIMESTAMPTZ,
    ADD COLUMN completion_reason TEXT,
    ADD UNIQUE (organization_id, project_id, id);

CREATE TABLE webhook_destinations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    url TEXT NOT NULL CHECK (length(url) BETWEEN 1 AND 2048),
    encrypted_secret BYTEA NOT NULL,
    secret_nonce BYTEA NOT NULL CHECK (octet_length(secret_nonce) = 24),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    deliver_backfill BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at TIMESTAMPTZ,
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, project_id, name),
    UNIQUE (organization_id, project_id, id)
);

CREATE TABLE notification_deliveries (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    destination_id UUID NOT NULL,
    outbox_message_id UUID REFERENCES outbox_messages(id) ON DELETE RESTRICT,
    origin TEXT NOT NULL CHECK (origin IN ('outbox', 'test')),
    source TEXT NOT NULL CHECK (source IN ('live', 'backfill', 'test')),
    event_name TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','in_flight','succeeded','failed','suppressed','cancelled')),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    last_error_class TEXT,
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    terminal_at TIMESTAMPTZ,
    FOREIGN KEY (organization_id, project_id, destination_id)
        REFERENCES webhook_destinations(organization_id, project_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, project_id, outbox_message_id)
        REFERENCES outbox_messages(organization_id, project_id, id) ON DELETE RESTRICT,
    UNIQUE (organization_id, project_id, id),
    CHECK ((origin='outbox' AND outbox_message_id IS NOT NULL) OR (origin='test' AND outbox_message_id IS NULL)),
    CHECK ((status='in_flight') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((status IN ('succeeded','failed','suppressed','cancelled')) = (terminal_at IS NOT NULL))
);

CREATE UNIQUE INDEX notification_deliveries_outbox_destination_uidx
    ON notification_deliveries (outbox_message_id, destination_id)
    WHERE outbox_message_id IS NOT NULL;

CREATE TABLE notification_delivery_attempts (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    delivery_id UUID NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    duration_ms BIGINT NOT NULL CHECK (duration_ms >= 0),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded','retryable','failed')),
    http_status INTEGER CHECK (http_status BETWEEN 100 AND 599),
    error_class TEXT,
    response_excerpt TEXT CHECK (response_excerpt IS NULL OR length(response_excerpt) <= 65536),
    FOREIGN KEY (organization_id, project_id, delivery_id)
        REFERENCES notification_deliveries(organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (delivery_id, attempt_number)
);

CREATE INDEX notification_deliveries_due_idx
    ON notification_deliveries (available_at, created_at)
    WHERE status='pending';

CREATE INDEX notification_deliveries_expired_lease_idx
    ON notification_deliveries (lease_expires_at)
    WHERE status='in_flight';

CREATE INDEX notification_deliveries_tenant_recent_idx
    ON notification_deliveries (organization_id, project_id, created_at DESC, id DESC);

CREATE INDEX notification_delivery_attempts_recent_idx
    ON notification_delivery_attempts (delivery_id, attempt_number DESC);

CREATE INDEX outbox_messages_unmaterialized_idx
    ON outbox_messages (created_at, id)
    WHERE processed_at IS NULL AND materialized_at IS NULL AND topic='runtime_group.first_seen';

CREATE INDEX outbox_messages_delivery_completion_idx
    ON outbox_messages (id)
    WHERE processed_at IS NULL AND materialized_at IS NOT NULL;
