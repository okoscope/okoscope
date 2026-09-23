ALTER TABLE agents
    ADD COLUMN architecture TEXT,
    ADD COLUMN kernel_release TEXT,
    ADD CONSTRAINT agents_architecture_length CHECK (
        architecture IS NULL OR char_length(architecture) BETWEEN 1 AND 64
    ),
    ADD CONSTRAINT agents_kernel_release_length CHECK (
        kernel_release IS NULL OR char_length(kernel_release) BETWEEN 1 AND 255
    );

CREATE INDEX runtime_events_application_agent_observed_idx
    ON runtime_events (organization_id, project_id, application_id, agent_id, observed_at);
