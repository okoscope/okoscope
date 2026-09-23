ALTER TABLE application_agents
    ADD CONSTRAINT application_agents_scoped_diagnostics_key
    UNIQUE (organization_id, project_id, application_id, cluster_id, agent_id);

CREATE TABLE application_agent_counter_baselines (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    sent_at TIMESTAMPTZ NOT NULL,
    counters JSONB NOT NULL CHECK (jsonb_typeof(counters) = 'array'),
    PRIMARY KEY (organization_id, project_id, application_id, cluster_id, agent_id),
    FOREIGN KEY (organization_id, project_id, application_id, cluster_id, agent_id)
        REFERENCES application_agents(organization_id, project_id, application_id, cluster_id, agent_id)
        ON DELETE CASCADE
);

CREATE TABLE application_agent_diagnostic_buckets (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    bucket_at TIMESTAMPTZ NOT NULL,
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
    PRIMARY KEY (organization_id, project_id, application_id, cluster_id, agent_id, bucket_at),
    FOREIGN KEY (organization_id, project_id, application_id, cluster_id, agent_id)
        REFERENCES application_agents(organization_id, project_id, application_id, cluster_id, agent_id)
        ON DELETE CASCADE,
    CHECK (bucket_at = date_trunc('minute', bucket_at))
);

CREATE INDEX application_agent_diagnostic_cleanup_idx
    ON application_agent_diagnostic_buckets (bucket_at);
CREATE INDEX application_agent_diagnostic_history_idx
    ON application_agent_diagnostic_buckets
        (organization_id, project_id, application_id, agent_id, bucket_at);
