CREATE TABLE thread_activity_windows (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    application_id uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    cluster_id uuid NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    observed_at timestamptz NOT NULL,
    process_cgroup_id bigint NOT NULL,
    process_pid bigint NOT NULL,
    process_tgid bigint NOT NULL,
    process_command text NOT NULL,
    process_generation bigint NOT NULL CHECK (process_generation > 0),
    observation_epoch uuid NOT NULL,
    start_observed boolean NOT NULL,
    window_started_at timestamptz NOT NULL,
    window_ended_at timestamptz NOT NULL,
    created_count bigint NOT NULL CHECK (created_count >= 0),
    exited_count bigint NOT NULL CHECK (exited_count >= 0),
    active_at_start bigint NOT NULL CHECK (active_at_start >= 0),
    active_at_end bigint NOT NULL CHECK (active_at_end >= 0),
    peak_active bigint NOT NULL CHECK (peak_active >= 0),
    baseline_provenance text NOT NULL CHECK (baseline_provenance IN ('observed','snapshot','unavailable')),
    baseline_complete boolean NOT NULL,
    name_overflow bigint NOT NULL CHECK (name_overflow >= 0),
    names jsonb NOT NULL,
    gaps jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (window_ended_at > window_started_at),
    UNIQUE (organization_id, application_id, process_cgroup_id, process_tgid,
            process_generation, observation_epoch, window_started_at, window_ended_at)
);

CREATE INDEX thread_activity_windows_application_scope_idx
    ON thread_activity_windows
    (organization_id, project_id, application_id, window_started_at DESC, id DESC);

CREATE INDEX thread_activity_windows_process_scope_idx
    ON thread_activity_windows
    (organization_id, application_id, process_cgroup_id, process_tgid,
     process_generation, observation_epoch, window_started_at DESC, id DESC);
