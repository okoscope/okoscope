CREATE INDEX runtime_events_application_observed_idx
    ON runtime_events (
        organization_id,
        project_id,
        application_id,
        observed_at DESC
    );
