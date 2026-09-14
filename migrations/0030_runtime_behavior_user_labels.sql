CREATE TABLE runtime_behavior_user_labels (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    inventory_kind TEXT NOT NULL,
    identity_version SMALLINT NOT NULL CHECK (identity_version > 0),
    identity_digest BYTEA NOT NULL CHECK (octet_length(identity_digest) = 32),
    display_name TEXT NOT NULL CHECK (
        display_name = btrim(display_name)
        AND char_length(display_name) BETWEEN 1 AND 120
        AND display_name !~ '[[:cntrl:]]'
    ),
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (
        organization_id, project_id, application_id,
        inventory_kind, identity_version, identity_digest
    )
);

CREATE INDEX runtime_behavior_user_labels_identity_cover_idx
    ON runtime_behavior_user_labels (
        organization_id, project_id, application_id,
        inventory_kind, identity_version, identity_digest
    ) INCLUDE (display_name, created_by_user_id, updated_by_user_id, created_at, updated_at);

CREATE INDEX runtime_behavior_user_labels_search_idx
    ON runtime_behavior_user_labels (
        organization_id, project_id, application_id, lower(display_name) text_pattern_ops
    );
