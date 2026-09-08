CREATE TABLE runtime_event_groups (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    application_id UUID NOT NULL,
    namespace TEXT NOT NULL,
    workload_kind TEXT NOT NULL,
    workload_name TEXT NOT NULL,
    fingerprint_version SMALLINT NOT NULL CHECK (fingerprint_version > 0),
    fingerprint_digest BYTEA NOT NULL CHECK (octet_length(fingerprint_digest) = 32),
    event_kind TEXT NOT NULL,
    semantic_summary JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    occurrence_count BIGINT NOT NULL CHECK (occurrence_count > 0),
    representative_event_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id),
    FOREIGN KEY (representative_event_id)
        REFERENCES runtime_events(id),
    UNIQUE (
        organization_id, project_id, application_id, cluster_id,
        namespace, workload_kind, workload_name,
        fingerprint_version, fingerprint_digest
    ),
    UNIQUE (organization_id, project_id, application_id, id),
    CHECK (first_seen_at <= last_seen_at)
);

CREATE TABLE runtime_event_group_memberships (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    event_id UUID NOT NULL REFERENCES runtime_events(id) ON DELETE CASCADE,
    group_id UUID NOT NULL,
    fingerprint_version SMALLINT NOT NULL CHECK (fingerprint_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, fingerprint_version),
    FOREIGN KEY (organization_id, project_id, application_id, group_id)
        REFERENCES runtime_event_groups(organization_id, project_id, application_id, id)
        ON DELETE CASCADE
);

CREATE TABLE outbox_messages (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    topic TEXT NOT NULL,
    aggregate_id UUID NOT NULL,
    schema_version SMALLINT NOT NULL CHECK (schema_version > 0),
    source TEXT NOT NULL DEFAULT 'live' CHECK (source IN ('live', 'backfill')),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id),
    UNIQUE (topic, aggregate_id, schema_version)
);

CREATE TABLE api_credentials (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    credential_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(credential_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (organization_id, name)
);

CREATE INDEX runtime_event_groups_recent_idx
    ON runtime_event_groups (organization_id, project_id, application_id, last_seen_at DESC, id DESC);

CREATE INDEX runtime_event_groups_filter_idx
    ON runtime_event_groups (organization_id, project_id, application_id, event_kind, status, last_seen_at DESC);

CREATE INDEX runtime_event_groups_workload_idx
    ON runtime_event_groups (organization_id, project_id, application_id, namespace, workload_kind, workload_name, last_seen_at DESC);

CREATE INDEX runtime_event_group_memberships_recent_idx
    ON runtime_event_group_memberships (group_id, created_at DESC, event_id DESC);

CREATE INDEX runtime_event_group_memberships_tenant_idx
    ON runtime_event_group_memberships (organization_id, project_id, application_id, group_id);

CREATE INDEX outbox_messages_pending_idx
    ON outbox_messages (available_at, created_at)
    WHERE processed_at IS NULL;
