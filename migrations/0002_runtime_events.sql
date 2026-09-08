CREATE TABLE runtime_events (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    application_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    node_name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    pod_uid TEXT NOT NULL,
    pod_name TEXT NOT NULL,
    container_id TEXT NOT NULL,
    container_name TEXT NOT NULL,
    workload_uid TEXT NOT NULL,
    workload_kind TEXT NOT NULL,
    workload_name TEXT NOT NULL,
    cgroup_id BIGINT NOT NULL CHECK (cgroup_id >= 0),
    pid BIGINT NOT NULL,
    tgid BIGINT NOT NULL,
    process_command TEXT NOT NULL,
    event_kind TEXT NOT NULL,
    event_schema_version INTEGER NOT NULL,
    payload JSONB NOT NULL,
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id),
    FOREIGN KEY (organization_id, cluster_id, agent_id)
        REFERENCES agents(organization_id, cluster_id, id),
    UNIQUE (agent_id, event_id)
);

CREATE INDEX runtime_events_tenant_lookup_idx
    ON runtime_events (organization_id, project_id, application_id, event_kind, observed_at DESC);

CREATE INDEX runtime_events_workload_lookup_idx
    ON runtime_events (cluster_id, namespace, workload_kind, workload_name, observed_at DESC);
