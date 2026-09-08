CREATE TABLE runtime_inventory_items (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    inventory_kind TEXT NOT NULL CHECK (inventory_kind IN ('process', 'destination', 'domain', 'syscall')),
    identity_version SMALLINT NOT NULL CHECK (identity_version > 0),
    identity_digest BYTEA NOT NULL CHECK (octet_length(identity_digest) = 32),
    semantic_summary JSONB NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    occurrence_count BIGINT NOT NULL CHECK (occurrence_count > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (
        organization_id, project_id, application_id,
        inventory_kind, identity_version, identity_digest
    ),
    UNIQUE (organization_id, project_id, application_id, id),
    CHECK (first_seen_at <= last_seen_at)
);

CREATE TABLE runtime_inventory_event_memberships (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    event_id UUID NOT NULL,
    item_id UUID NOT NULL,
    identity_version SMALLINT NOT NULL CHECK (identity_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, identity_version),
    FOREIGN KEY (organization_id, project_id, application_id, event_id)
        REFERENCES runtime_events(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, item_id)
        REFERENCES runtime_inventory_items(organization_id, project_id, application_id, id) ON DELETE CASCADE
);

CREATE TABLE runtime_inventory_group_links (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    item_id UUID NOT NULL,
    group_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, group_id),
    FOREIGN KEY (organization_id, project_id, application_id, item_id)
        REFERENCES runtime_inventory_items(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, group_id)
        REFERENCES runtime_event_groups(organization_id, project_id, application_id, id) ON DELETE CASCADE
);

CREATE TABLE runtime_inventory_releases (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    item_id UUID NOT NULL,
    release_id UUID NOT NULL,
    occurrence_count BIGINT NOT NULL CHECK (occurrence_count > 0),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, release_id),
    FOREIGN KEY (organization_id, project_id, application_id, item_id)
        REFERENCES runtime_inventory_items(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, release_id)
        REFERENCES releases(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    CHECK (first_seen_at <= last_seen_at)
);

CREATE TABLE runtime_inventory_sightings (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    item_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    namespace TEXT NOT NULL,
    workload_kind TEXT NOT NULL,
    workload_name TEXT NOT NULL,
    pod_uid TEXT NOT NULL,
    pod_name TEXT NOT NULL,
    container_name TEXT NOT NULL,
    occurrence_count BIGINT NOT NULL CHECK (occurrence_count > 0),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (
        item_id, cluster_id, namespace, workload_kind, workload_name,
        pod_uid, container_name
    ),
    FOREIGN KEY (organization_id, project_id, application_id, item_id)
        REFERENCES runtime_inventory_items(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, cluster_id)
        REFERENCES clusters(organization_id, id) ON DELETE CASCADE,
    CHECK (first_seen_at <= last_seen_at)
);

CREATE INDEX runtime_inventory_items_recent_idx
    ON runtime_inventory_items (
        organization_id, project_id, application_id,
        identity_version, last_seen_at DESC, id DESC
    );

CREATE INDEX runtime_inventory_items_kind_recent_idx
    ON runtime_inventory_items (
        organization_id, project_id, application_id,
        identity_version, inventory_kind, last_seen_at DESC, id DESC
    );

CREATE INDEX runtime_inventory_event_memberships_item_idx
    ON runtime_inventory_event_memberships (item_id, created_at DESC, event_id DESC);

CREATE INDEX runtime_inventory_group_links_group_idx
    ON runtime_inventory_group_links (group_id, item_id);

CREATE INDEX runtime_inventory_releases_release_idx
    ON runtime_inventory_releases (
        organization_id, project_id, application_id, release_id, item_id
    );

CREATE INDEX runtime_inventory_sightings_filter_idx
    ON runtime_inventory_sightings (
        organization_id, project_id, application_id,
        cluster_id, namespace, workload_kind, workload_name, container_name,
        last_seen_at DESC, item_id
    );

CREATE INDEX runtime_inventory_sightings_item_recent_idx
    ON runtime_inventory_sightings (item_id, last_seen_at DESC, cluster_id, pod_uid, container_name);
