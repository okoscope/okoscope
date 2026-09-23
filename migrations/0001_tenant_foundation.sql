CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at TIMESTAMPTZ,
    UNIQUE (organization_id, slug),
    UNIQUE (organization_id, id)
);

CREATE TABLE clusters (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    UNIQUE (organization_id, external_id),
    UNIQUE (organization_id, id)
);

CREATE TABLE applications (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id) ON DELETE CASCADE,
    UNIQUE (project_id, slug),
    UNIQUE (organization_id, project_id, id)
);

CREATE TABLE cluster_credentials (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    credential_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (organization_id, cluster_id)
        REFERENCES clusters(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE agents (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    node_name TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, cluster_id)
        REFERENCES clusters(organization_id, id) ON DELETE CASCADE,
    UNIQUE (cluster_id, node_name),
    UNIQUE (organization_id, cluster_id, id)
);

CREATE TABLE agent_sessions (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    protocol_version INTEGER NOT NULL,
    connected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    disconnected_at TIMESTAMPTZ,
    FOREIGN KEY (organization_id, cluster_id, agent_id)
        REFERENCES agents(organization_id, cluster_id, id) ON DELETE CASCADE
);

