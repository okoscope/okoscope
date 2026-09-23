ALTER TABLE runtime_event_groups
    DROP CONSTRAINT runtime_event_groups_status_check,
    ADD COLUMN first_seen_event_id UUID REFERENCES runtime_events(id),
    ADD COLUMN status_changed_at TIMESTAMPTZ,
    ADD COLUMN status_changed_by UUID REFERENCES api_credentials(id),
    ADD CONSTRAINT runtime_event_groups_status_check
        CHECK (status IN ('open', 'acknowledged', 'resolved'));

UPDATE runtime_event_groups AS groups
SET first_seen_event_id = (
    SELECT memberships.event_id
    FROM runtime_event_group_memberships AS memberships
    JOIN runtime_events AS events ON events.id = memberships.event_id
    WHERE memberships.group_id = groups.id
    ORDER BY events.observed_at ASC, events.id ASC
    LIMIT 1
);

ALTER TABLE runtime_event_groups
    ALTER COLUMN first_seen_event_id SET NOT NULL;

CREATE INDEX runtime_event_groups_first_seen_idx
    ON runtime_event_groups
        (organization_id, project_id, application_id, first_seen_at DESC, id DESC);

CREATE INDEX runtime_event_group_memberships_occurrences_idx
    ON runtime_event_group_memberships (group_id, event_id);

CREATE INDEX runtime_event_group_releases_group_release_idx
    ON runtime_event_group_releases (group_id, release_id);
