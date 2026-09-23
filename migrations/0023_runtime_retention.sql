ALTER TABLE organizations
    ADD COLUMN runtime_retention_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN runtime_retention_raw_days INTEGER NOT NULL DEFAULT 30 CHECK (runtime_retention_raw_days BETWEEN 1 AND 3650),
    ADD COLUMN runtime_retention_history_days INTEGER DEFAULT 365,
    ADD COLUMN runtime_retention_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN runtime_retention_updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT organization_runtime_history CHECK (runtime_retention_history_days IS NULL OR runtime_retention_history_days BETWEEN runtime_retention_raw_days AND 3650);
ALTER TABLE projects
    ADD COLUMN runtime_retention_enabled BOOLEAN,
    ADD COLUMN runtime_retention_raw_days INTEGER,
    ADD COLUMN runtime_retention_history_days INTEGER,
    ADD COLUMN runtime_retention_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN runtime_retention_updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN runtime_closed_before TIMESTAMPTZ,
    ADD COLUMN runtime_history_expired_before TIMESTAMPTZ,
    ADD CONSTRAINT project_runtime_policy CHECK (
        (runtime_retention_enabled IS NULL AND runtime_retention_raw_days IS NULL AND runtime_retention_history_days IS NULL)
        OR (runtime_retention_enabled IS NOT NULL AND runtime_retention_raw_days IS NOT NULL
            AND runtime_retention_raw_days BETWEEN 1 AND 3650
            AND (runtime_retention_history_days IS NULL OR runtime_retention_history_days BETWEEN runtime_retention_raw_days AND 3650)));
ALTER TABLE runtime_event_groups
    ALTER COLUMN representative_event_id DROP NOT NULL,
    ALTER COLUMN first_seen_event_id DROP NOT NULL,
    DROP CONSTRAINT runtime_event_groups_occurrence_count_check,
    ADD CHECK (occurrence_count >= 0);
ALTER TABLE runtime_event_group_releases
    ALTER COLUMN representative_event_id DROP NOT NULL;
ALTER TABLE runtime_inventory_items
    DROP CONSTRAINT runtime_inventory_items_occurrence_count_check,
    ADD CHECK (occurrence_count >= 0);
ALTER TABLE runtime_event_correlation_outcomes ADD COLUMN retention_incomplete BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE runtime_history_snapshots (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    group_id UUID NOT NULL,
    release_id UUID,
    day DATE NOT NULL,
    format_version SMALLINT NOT NULL DEFAULT 1 CHECK (format_version = 1),
    occurrence_count BIGINT NOT NULL CHECK (occurrence_count > 0),
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    CHECK (first_observed_at <= last_observed_at),
    FOREIGN KEY (organization_id,project_id,application_id,group_id)
        REFERENCES runtime_event_groups(organization_id,project_id,application_id,id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id,project_id,application_id,release_id)
        REFERENCES releases(organization_id,project_id,application_id,id),
    CHECK ((first_observed_at AT TIME ZONE 'UTC')::date = day AND (last_observed_at AT TIME ZONE 'UTC')::date = day)
);
CREATE UNIQUE INDEX runtime_snapshots_released_unique ON runtime_history_snapshots(group_id,release_id,day,format_version) WHERE release_id IS NOT NULL;
CREATE UNIQUE INDEX runtime_snapshots_unreleased_unique ON runtime_history_snapshots(group_id,day,format_version) WHERE release_id IS NULL;
CREATE INDEX runtime_snapshots_cleanup_idx ON runtime_history_snapshots(project_id,day,id);
CREATE INDEX runtime_snapshots_group_page_idx ON runtime_history_snapshots(group_id,day DESC,id DESC);
CREATE INDEX runtime_events_retention_idx ON runtime_events(project_id,observed_at,id);
