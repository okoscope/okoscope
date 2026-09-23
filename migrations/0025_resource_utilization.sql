ALTER TABLE organizations
    ADD COLUMN resource_detail_retention_days INTEGER NOT NULL DEFAULT 7
        CHECK (resource_detail_retention_days BETWEEN 1 AND 31),
    ADD COLUMN resource_rollup_retention_days INTEGER NOT NULL DEFAULT 90
        CHECK (resource_rollup_retention_days BETWEEN resource_detail_retention_days AND 366);

ALTER TABLE projects
    ADD COLUMN resource_detail_retention_days INTEGER,
    ADD COLUMN resource_rollup_retention_days INTEGER,
    ADD COLUMN resource_closed_before TIMESTAMPTZ,
    ADD COLUMN resource_rollup_expired_before TIMESTAMPTZ,
    ADD CONSTRAINT project_resource_retention CHECK (
        (resource_detail_retention_days IS NULL AND resource_rollup_retention_days IS NULL)
        OR (resource_detail_retention_days BETWEEN 1 AND 31
            AND resource_rollup_retention_days BETWEEN resource_detail_retention_days AND 366));

CREATE TABLE resource_contributions (
    id UUID NOT NULL,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    release_id UUID,
    schema_version SMALLINT NOT NULL CHECK (schema_version = 1),
    interval_start TIMESTAMPTZ NOT NULL,
    interval_end TIMESTAMPTZ NOT NULL,
    covered_usec BIGINT NOT NULL CHECK (covered_usec >= 0),
    sample_count INTEGER NOT NULL CHECK (sample_count > 0),
    contributing_containers INTEGER NOT NULL CHECK (contributing_containers > 0),
    namespace TEXT NOT NULL CHECK (char_length(namespace) BETWEEN 1 AND 253),
    workload_uid TEXT NOT NULL CHECK (char_length(workload_uid) BETWEEN 1 AND 253),
    workload_kind TEXT NOT NULL CHECK (char_length(workload_kind) BETWEEN 1 AND 64),
    workload_name TEXT NOT NULL CHECK (char_length(workload_name) BETWEEN 1 AND 253),
    container_name TEXT NOT NULL CHECK (char_length(container_name) BETWEEN 1 AND 256),
    node_name TEXT NOT NULL CHECK (char_length(node_name) BETWEEN 1 AND 253),
    unavailable_sources BIGINT NOT NULL CHECK (unavailable_sources >= 0),
    values JSONB NOT NULL CHECK (jsonb_typeof(values) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, application_id, id),
    CHECK (interval_start < interval_end AND interval_end - interval_start <= interval '5 minutes'),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, cluster_id, agent_id)
        REFERENCES agents(organization_id, cluster_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, release_id)
        REFERENCES releases(organization_id, project_id, application_id, id)
);

CREATE INDEX resource_contributions_history_idx
    ON resource_contributions (organization_id, project_id, application_id, interval_start, id);
CREATE INDEX resource_contributions_cleanup_idx
    ON resource_contributions (project_id, interval_end, id);

CREATE TABLE resource_rollup_points (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    release_key UUID NOT NULL,
    release_id UUID,
    container_name TEXT NOT NULL CHECK (char_length(container_name) BETWEEN 1 AND 256),
    bucket_start TIMESTAMPTZ NOT NULL,
    step_seconds INTEGER NOT NULL CHECK (step_seconds IN (60, 3600)),
    metric TEXT NOT NULL,
    unit TEXT NOT NULL,
    value_sum DOUBLE PRECISION NOT NULL,
    value_min DOUBLE PRECISION NOT NULL,
    value_max DOUBLE PRECISION NOT NULL,
    value_weight DOUBLE PRECISION NOT NULL CHECK (value_weight > 0),
    limit_value DOUBLE PRECISION,
    covered_usec BIGINT NOT NULL CHECK (covered_usec >= 0),
    expected_usec BIGINT NOT NULL CHECK (expected_usec > 0),
    sample_count BIGINT NOT NULL CHECK (sample_count > 0),
    contributor_count BIGINT NOT NULL CHECK (contributor_count > 0),
    observed_replicas INTEGER NOT NULL CHECK (observed_replicas >= 0),
    ready_replicas INTEGER NOT NULL CHECK (ready_replicas >= 0),
    unavailable_sources BIGINT NOT NULL CHECK (unavailable_sources >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, release_key, container_name, bucket_start, step_seconds, metric),
    CHECK (release_key = COALESCE(release_id, '00000000-0000-0000-0000-000000000000'::uuid)),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, release_id)
        REFERENCES releases(organization_id, project_id, application_id, id)
);

CREATE INDEX resource_rollup_history_idx
    ON resource_rollup_points (organization_id, project_id, application_id, metric, step_seconds, bucket_start);
CREATE INDEX resource_rollup_cleanup_idx
    ON resource_rollup_points (project_id, step_seconds, bucket_start, application_id);

CREATE TABLE release_resource_findings (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    target_release_id UUID NOT NULL,
    baseline_release_id UUID,
    reason_code TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('urgent', 'high', 'normal')),
    metric TEXT NOT NULL,
    rule_version SMALLINT NOT NULL CHECK (rule_version > 0),
    facts JSONB NOT NULL CHECK (jsonb_typeof(facts) = 'object'),
    opened_at TIMESTAMPTZ NOT NULL,
    closed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    clean_evaluations SMALLINT NOT NULL DEFAULT 0 CHECK (clean_evaluations BETWEEN 0 AND 2),
    CHECK (closed_at IS NULL OR opened_at <= closed_at),
    FOREIGN KEY (organization_id, project_id, application_id, target_release_id)
        REFERENCES releases(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, baseline_release_id)
        REFERENCES releases(organization_id, project_id, application_id, id),
    UNIQUE (application_id, target_release_id, reason_code, metric, rule_version)
);

CREATE INDEX release_resource_findings_attention_idx
    ON release_resource_findings (organization_id, closed_at, priority, opened_at DESC);
