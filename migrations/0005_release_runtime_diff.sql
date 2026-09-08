CREATE TABLE releases (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    version TEXT NOT NULL CHECK (char_length(version) BETWEEN 1 AND 200),
    description TEXT CHECK (description IS NULL OR char_length(description) <= 2000),
    deployed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (application_id, version),
    UNIQUE (organization_id, project_id, application_id, id)
);

ALTER TABLE runtime_events
    ADD COLUMN release_id UUID,
    ADD CONSTRAINT runtime_events_tenant_identity_uidx
        UNIQUE (organization_id, project_id, application_id, id),
    ADD CONSTRAINT runtime_events_release_fk
        FOREIGN KEY (organization_id, project_id, application_id, release_id)
        REFERENCES releases(organization_id, project_id, application_id, id);

ALTER TABLE runtime_event_group_memberships
    ADD COLUMN release_id UUID,
    ADD CONSTRAINT runtime_event_group_memberships_release_fk
        FOREIGN KEY (organization_id, project_id, application_id, release_id)
        REFERENCES releases(organization_id, project_id, application_id, id);

CREATE TABLE runtime_event_group_releases (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    release_id UUID NOT NULL,
    group_id UUID NOT NULL,
    occurrence_count BIGINT NOT NULL CHECK (occurrence_count > 0),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    representative_event_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, group_id),
    FOREIGN KEY (organization_id, project_id, application_id, release_id)
        REFERENCES releases(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, group_id)
        REFERENCES runtime_event_groups(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, representative_event_id)
        REFERENCES runtime_events(organization_id, project_id, application_id, id),
    CHECK (first_seen_at <= last_seen_at)
);

CREATE INDEX releases_recent_idx
    ON releases (organization_id, project_id, application_id, deployed_at DESC, id DESC);

CREATE INDEX releases_version_lookup_idx
    ON releases (organization_id, project_id, application_id, version);

CREATE INDEX runtime_events_release_idx
    ON runtime_events (organization_id, project_id, application_id, release_id, observed_at DESC)
    WHERE release_id IS NOT NULL;

CREATE INDEX runtime_event_group_memberships_release_idx
    ON runtime_event_group_memberships (release_id, group_id, created_at DESC)
    WHERE release_id IS NOT NULL;

CREATE INDEX runtime_event_group_releases_diff_idx
    ON runtime_event_group_releases (organization_id, project_id, application_id, release_id, group_id);
