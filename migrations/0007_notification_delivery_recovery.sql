ALTER TABLE notification_deliveries
    ADD COLUMN recovery_generation INTEGER NOT NULL DEFAULT 0
        CHECK (recovery_generation >= 0),
    ADD COLUMN last_recovery_operation_id UUID;

ALTER TABLE notification_delivery_attempts
    ADD COLUMN recovery_generation INTEGER NOT NULL DEFAULT 0
        CHECK (recovery_generation >= 0),
    DROP CONSTRAINT notification_delivery_attempts_delivery_id_attempt_number_key,
    ADD CONSTRAINT notification_delivery_attempts_generation_attempt_uidx
        UNIQUE (delivery_id, recovery_generation, attempt_number);

CREATE TABLE notification_recovery_operations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    command_type TEXT NOT NULL
        CHECK (command_type IN ('retry','cancel','bulk_retry')),
    target_delivery_id UUID,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('api_credential')),
    actor_id UUID NOT NULL,
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 200),
    idempotency_key_hash BYTEA NOT NULL
        CHECK (octet_length(idempotency_key_hash) = 32),
    request_fingerprint BYTEA NOT NULL
        CHECK (octet_length(request_fingerprint) = 32),
    safe_filters JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(safe_filters) = 'object'),
    outcome TEXT NOT NULL CHECK (outcome IN ('completed','conflict')),
    selected_count INTEGER NOT NULL DEFAULT 0 CHECK (selected_count >= 0),
    retried_count INTEGER NOT NULL DEFAULT 0 CHECK (retried_count >= 0),
    cancelled_count INTEGER NOT NULL DEFAULT 0 CHECK (cancelled_count >= 0),
    skipped_count INTEGER NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
    remaining_count INTEGER NOT NULL DEFAULT 0 CHECK (remaining_count >= 0),
    result JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (actor_id)
        REFERENCES api_credentials(id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, project_id, target_delivery_id)
        REFERENCES notification_deliveries(organization_id, project_id, id)
        ON DELETE RESTRICT,
    UNIQUE (organization_id, project_id, id),
    UNIQUE (organization_id, project_id, idempotency_key_hash)
);

CREATE TABLE notification_recovery_operation_deliveries (
    operation_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    delivery_id UUID NOT NULL,
    recovery_generation INTEGER NOT NULL CHECK (recovery_generation >= 0),
    action TEXT NOT NULL CHECK (action IN ('retried','cancelled','skipped')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (operation_id, delivery_id),
    FOREIGN KEY (organization_id, project_id, operation_id)
        REFERENCES notification_recovery_operations(organization_id, project_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, delivery_id)
        REFERENCES notification_deliveries(organization_id, project_id, id)
        ON DELETE CASCADE
);

ALTER TABLE notification_deliveries
    ADD CONSTRAINT notification_deliveries_last_recovery_operation_fk
    FOREIGN KEY (last_recovery_operation_id)
    REFERENCES notification_recovery_operations(id)
    ON DELETE SET NULL
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX notification_deliveries_failed_recovery_idx
    ON notification_deliveries
        (organization_id, project_id, terminal_at, created_at, id)
    WHERE status = 'failed';

CREATE INDEX notification_deliveries_terminal_retention_idx
    ON notification_deliveries (terminal_at, id)
    WHERE status IN ('succeeded','failed','suppressed','cancelled');

CREATE INDEX notification_recovery_operations_tenant_recent_idx
    ON notification_recovery_operations
        (organization_id, project_id, created_at DESC, id DESC);

CREATE INDEX notification_recovery_operations_retention_idx
    ON notification_recovery_operations (completed_at, id);

CREATE INDEX notification_recovery_links_delivery_idx
    ON notification_recovery_operation_deliveries
        (organization_id, project_id, delivery_id, created_at DESC);
