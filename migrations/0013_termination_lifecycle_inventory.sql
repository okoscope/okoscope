ALTER TABLE runtime_inventory_items
    DROP CONSTRAINT runtime_inventory_items_inventory_kind_check,
    ADD CONSTRAINT runtime_inventory_items_inventory_kind_check
        CHECK (
            inventory_kind IN (
                'process', 'destination', 'domain', 'syscall',
                'inbound_endpoint', 'file_activity', 'process_exit',
                'container_termination', 'container_restart'
            )
        );

CREATE TABLE runtime_event_correlations (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    lifecycle_event_id UUID NOT NULL REFERENCES runtime_events(id) ON DELETE CASCADE,
    kernel_event_id UUID NOT NULL REFERENCES runtime_events(id) ON DELETE CASCADE,
    correlation_kind TEXT NOT NULL CHECK (correlation_kind = 'qualified'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, lifecycle_event_id, kernel_event_id)
);

CREATE TABLE runtime_event_correlation_outcomes (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    event_id UUID PRIMARY KEY REFERENCES runtime_events(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('absent', 'qualified', 'ambiguous')),
    candidate_count INTEGER NOT NULL CHECK (candidate_count >= 0),
    tolerance_seconds INTEGER NOT NULL CHECK (tolerance_seconds > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE runtime_restart_projection_memberships (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    projection_version SMALLINT NOT NULL CHECK (projection_version > 0),
    event_id UUID NOT NULL REFERENCES runtime_events(id) ON DELETE CASCADE,
    window_started_at TIMESTAMPTZ NOT NULL,
    window_ended_at TIMESTAMPTZ NOT NULL,
    restart_delta INTEGER NOT NULL CHECK (restart_delta > 0),
    PRIMARY KEY (organization_id, projection_version, event_id)
);

CREATE TABLE runtime_restart_loop_projections (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    pod_uid TEXT NOT NULL,
    container_name TEXT NOT NULL,
    runtime_container_id TEXT NOT NULL,
    projection_version SMALLINT NOT NULL CHECK (projection_version > 0),
    group_id UUID REFERENCES runtime_event_groups(id) ON DELETE SET NULL,
    window_started_at TIMESTAMPTZ NOT NULL,
    window_ended_at TIMESTAMPTZ NOT NULL,
    observed_restart_count INTEGER NOT NULL CHECK (observed_restart_count >= 0),
    latest_termination JSONB,
    latest_waiting_reason TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (
        organization_id, project_id, application_id, cluster_id, pod_uid,
        container_name, runtime_container_id, projection_version
    ),
    CHECK (window_started_at <= window_ended_at)
);

CREATE INDEX runtime_events_termination_correlation_idx
    ON runtime_events (
        organization_id, project_id, application_id, pod_uid,
        container_name, container_id, observed_at
    )
    WHERE event_kind IN ('process.exit', 'container.terminated', 'container.restart');
