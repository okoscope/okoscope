CREATE TABLE application_installations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    credential_id UUID NOT NULL,
    idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
    cluster_name TEXT NOT NULL CHECK (char_length(cluster_name) BETWEEN 1 AND 64),
    workload_namespace TEXT NOT NULL CHECK (char_length(workload_namespace) BETWEEN 1 AND 63),
    workload_kind TEXT NOT NULL CHECK (workload_kind = 'Deployment'),
    workload_name TEXT,
    workload_labels JSONB,
    chart_version TEXT NOT NULL,
    configuration_schema_version INTEGER NOT NULL CHECK (configuration_schema_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, credential_id)
        REFERENCES application_ingestion_credentials(organization_id, project_id, application_id, id),
    UNIQUE (organization_id, idempotency_key),
    CHECK ((workload_name IS NOT NULL) <> (workload_labels IS NOT NULL))
);

CREATE INDEX application_installations_application_idx
    ON application_installations (organization_id, project_id, application_id, created_at, id);

CREATE TABLE application_installation_status (
    installation_id UUID NOT NULL REFERENCES application_installations(id) ON DELETE CASCADE,
    node_name TEXT NOT NULL CHECK (char_length(node_name) BETWEEN 1 AND 253),
    state TEXT NOT NULL CHECK (state IN (
        'agent_authenticated', 'workload_not_matched', 'permission_denied',
        'kernel_unsupported', 'waiting_for_event'
    )),
    reason TEXT CHECK (reason IN (
        'selector_no_match', 'kubernetes_watch_forbidden', 'ebpf_unavailable',
        'btf_unavailable', 'event_not_observed'
    )),
    observed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (installation_id, node_name)
);

CREATE INDEX application_installation_status_fresh_idx
    ON application_installation_status (installation_id, observed_at DESC);
