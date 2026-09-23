CREATE TABLE application_agents (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    authenticated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    history_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat_at TIMESTAMPTZ,
    last_session_ended_at TIMESTAMPTZ,
    PRIMARY KEY (organization_id, project_id, application_id, agent_id),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, cluster_id, agent_id)
        REFERENCES agents(organization_id, cluster_id, id) ON DELETE CASCADE,
    CHECK (jsonb_typeof(capabilities) = 'array'),
    CHECK (jsonb_array_length(capabilities) <= 32)
);

CREATE INDEX application_agents_page_idx
    ON application_agents (organization_id, project_id, application_id, authenticated_at DESC, agent_id DESC);

CREATE TABLE application_agent_signal_buckets (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    bucket_at TIMESTAMPTZ NOT NULL,
    received_count INTEGER NOT NULL DEFAULT 1 CHECK (received_count BETWEEN 1 AND 120),
    first_received_at TIMESTAMPTZ NOT NULL,
    last_received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, project_id, application_id, agent_id, bucket_at),
    FOREIGN KEY (organization_id, project_id, application_id, agent_id)
        REFERENCES application_agents(organization_id, project_id, application_id, agent_id) ON DELETE CASCADE,
    CHECK (bucket_at = date_trunc('minute', bucket_at)),
    CHECK (first_received_at <= last_received_at)
);

CREATE INDEX application_agent_signal_cleanup_idx
    ON application_agent_signal_buckets (bucket_at);

CREATE TABLE agent_counter_baselines (
    organization_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL,
    drop_counters JSONB,
    resource_counters JSONB,
    PRIMARY KEY (organization_id, cluster_id, agent_id),
    FOREIGN KEY (organization_id, cluster_id, agent_id)
        REFERENCES agents(organization_id, cluster_id, id) ON DELETE CASCADE,
    CHECK (drop_counters IS NULL OR jsonb_typeof(drop_counters) = 'array'),
    CHECK (resource_counters IS NULL OR jsonb_typeof(resource_counters) = 'array')
);

CREATE TABLE agent_diagnostic_buckets (
    organization_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    bucket_at TIMESTAMPTZ NOT NULL,
    diagnostics_available BOOLEAN NOT NULL DEFAULT FALSE,
    reset BOOLEAN NOT NULL DEFAULT FALSE,
    dropped BIGINT NOT NULL DEFAULT 0 CHECK (dropped >= 0),
    rate_limited BIGINT NOT NULL DEFAULT 0 CHECK (rate_limited >= 0),
    decode_failed BIGINT NOT NULL DEFAULT 0 CHECK (decode_failed >= 0),
    attribution_failed BIGINT NOT NULL DEFAULT 0 CHECK (attribution_failed >= 0),
    capacity BIGINT NOT NULL DEFAULT 0 CHECK (capacity >= 0),
    kernel_lost BIGINT NOT NULL DEFAULT 0 CHECK (kernel_lost >= 0),
    correlation BIGINT NOT NULL DEFAULT 0 CHECK (correlation >= 0),
    delivery_retry BIGINT NOT NULL DEFAULT 0 CHECK (delivery_retry >= 0),
    unsupported BIGINT NOT NULL DEFAULT 0 CHECK (unsupported >= 0),
    PRIMARY KEY (organization_id, cluster_id, agent_id, bucket_at),
    FOREIGN KEY (organization_id, cluster_id, agent_id)
        REFERENCES agents(organization_id, cluster_id, id) ON DELETE CASCADE,
    CHECK (bucket_at = date_trunc('minute', bucket_at))
);

CREATE INDEX agent_diagnostic_cleanup_idx ON agent_diagnostic_buckets (bucket_at);
CREATE INDEX agent_diagnostic_history_idx
    ON agent_diagnostic_buckets (organization_id, agent_id, bucket_at);
