CREATE TABLE application_ingestion_credentials (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    credential_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(credential_hash) = 32),
    token_hint TEXT NOT NULL CHECK (char_length(token_hint) BETWEEN 4 AND 12),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (application_id, name),
    UNIQUE (organization_id, project_id, application_id, id)
);

CREATE INDEX application_ingestion_credentials_active_idx
    ON application_ingestion_credentials (application_id, created_at, id)
    WHERE revoked_at IS NULL;

CREATE INDEX application_ingestion_credentials_tenant_idx
    ON application_ingestion_credentials (organization_id, project_id, application_id, id);
