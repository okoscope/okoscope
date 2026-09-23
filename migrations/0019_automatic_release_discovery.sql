ALTER TABLE releases
    ADD COLUMN source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','observed')),
    ADD COLUMN identity_version SMALLINT,
    ADD COLUMN identity_digest BYTEA,
    ADD COLUMN identity_components JSONB,
    ADD CONSTRAINT releases_observed_identity_shape CHECK (
        (source='manual' AND identity_version IS NULL AND identity_digest IS NULL AND identity_components IS NULL)
        OR (source='observed' AND identity_version>0 AND octet_length(identity_digest)=32
            AND jsonb_typeof(identity_components)='array' AND jsonb_array_length(identity_components) BETWEEN 1 AND 64));

CREATE UNIQUE INDEX releases_observed_identity_uidx ON releases
    (organization_id,project_id,application_id,identity_version,identity_digest) WHERE source='observed';

CREATE TABLE kubernetes_workload_revisions (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, project_id UUID NOT NULL,
    application_id UUID NOT NULL, cluster_id UUID NOT NULL, release_id UUID NOT NULL,
    identity_version SMALLINT NOT NULL CHECK(identity_version>0),
    identity_digest BYTEA NOT NULL CHECK(octet_length(identity_digest)=32),
    namespace TEXT NOT NULL CHECK(namespace=btrim(namespace) AND char_length(namespace) BETWEEN 1 AND 253),
    workload_uid TEXT NOT NULL CHECK(workload_uid=btrim(workload_uid) AND char_length(workload_uid) BETWEEN 1 AND 253),
    workload_kind TEXT NOT NULL CHECK(workload_kind='Deployment'),
    workload_name TEXT NOT NULL CHECK(workload_name=btrim(workload_name) AND char_length(workload_name) BETWEEN 1 AND 253),
    replica_set_uid TEXT NOT NULL CHECK(replica_set_uid=btrim(replica_set_uid) AND char_length(replica_set_uid) BETWEEN 1 AND 253),
    replica_set_name TEXT NOT NULL CHECK(replica_set_name=btrim(replica_set_name) AND char_length(replica_set_name) BETWEEN 1 AND 253),
    pod_template_hash TEXT CHECK(pod_template_hash=btrim(pod_template_hash) AND char_length(pod_template_hash) BETWEEN 1 AND 253),
    first_observed_at TIMESTAMPTZ NOT NULL, last_observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(organization_id,project_id,application_id,release_id) REFERENCES releases(organization_id,project_id,application_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,cluster_id) REFERENCES clusters(organization_id,id) ON DELETE CASCADE,
    UNIQUE(organization_id,project_id,application_id,id),
    UNIQUE(application_id,cluster_id,workload_uid,replica_set_uid),
    UNIQUE(application_id,cluster_id,identity_version,identity_digest),
    CHECK(first_observed_at<=last_observed_at));

CREATE TABLE deployment_episodes (
    id UUID PRIMARY KEY, organization_id UUID NOT NULL, project_id UUID NOT NULL,
    application_id UUID NOT NULL, cluster_id UUID NOT NULL, release_id UUID NOT NULL, revision_id UUID NOT NULL,
    occurrence_number BIGINT NOT NULL CHECK(occurrence_number>0),
    state TEXT NOT NULL CHECK(state IN ('detected','active','inactive')),
    transition_kind TEXT NOT NULL DEFAULT 'unknown' CHECK(transition_kind IN ('rollout','rollback_candidate','concurrent','unknown')),
    first_observed_at TIMESTAMPTZ NOT NULL, first_ready_at TIMESTAMPTZ,
    last_observed_at TIMESTAMPTZ NOT NULL, ended_at TIMESTAMPTZ,
    pod_count INTEGER NOT NULL DEFAULT 0 CHECK(pod_count>=0),
    ready_pod_count INTEGER NOT NULL DEFAULT 0 CHECK(ready_pod_count>=0 AND ready_pod_count<=pod_count),
    workload_ready_pod_count INTEGER NOT NULL DEFAULT 0 CHECK(workload_ready_pod_count>=ready_pod_count),
    snapshot_observed_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(organization_id,project_id,application_id,release_id) REFERENCES releases(organization_id,project_id,application_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,project_id,application_id,revision_id) REFERENCES kubernetes_workload_revisions(organization_id,project_id,application_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,cluster_id) REFERENCES clusters(organization_id,id) ON DELETE CASCADE,
    UNIQUE(organization_id,project_id,application_id,id), UNIQUE(revision_id,occurrence_number),
    CHECK(first_observed_at<=last_observed_at), CHECK(first_ready_at IS NULL OR first_ready_at>=first_observed_at),
    CHECK((state='inactive')=(ended_at IS NOT NULL)), CHECK(ended_at IS NULL OR ended_at>=first_observed_at));

CREATE UNIQUE INDEX deployment_episodes_one_open_uidx ON deployment_episodes(revision_id) WHERE state<>'inactive';

CREATE TABLE deployment_episode_predecessors (
    organization_id UUID NOT NULL, project_id UUID NOT NULL, application_id UUID NOT NULL,
    episode_id UUID NOT NULL, predecessor_episode_id UUID NOT NULL, observed_at TIMESTAMPTZ NOT NULL,
    concurrent BOOLEAN NOT NULL, PRIMARY KEY(episode_id,predecessor_episode_id),
    FOREIGN KEY(organization_id,project_id,application_id,episode_id) REFERENCES deployment_episodes(organization_id,project_id,application_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,project_id,application_id,predecessor_episode_id) REFERENCES deployment_episodes(organization_id,project_id,application_id,id) ON DELETE CASCADE,
    CHECK(episode_id<>predecessor_episode_id));

CREATE TABLE kubernetes_revision_snapshots (
    organization_id UUID NOT NULL, project_id UUID NOT NULL, application_id UUID NOT NULL,
    cluster_id UUID NOT NULL, revision_id UUID NOT NULL,
    snapshot_id TEXT NOT NULL CHECK(snapshot_id=btrim(snapshot_id) AND char_length(snapshot_id) BETWEEN 1 AND 200),
    observed_at TIMESTAMPTZ NOT NULL, initialized BOOLEAN NOT NULL, continuous BOOLEAN NOT NULL,
    pod_count INTEGER NOT NULL CHECK(pod_count>=0),
    ready_pod_count INTEGER NOT NULL CHECK(ready_pod_count>=0 AND ready_pod_count<=pod_count),
    workload_ready_pod_count INTEGER NOT NULL CHECK(workload_ready_pod_count>=ready_pod_count),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(organization_id,cluster_id,snapshot_id,revision_id),
    FOREIGN KEY(organization_id,project_id,application_id,revision_id) REFERENCES kubernetes_workload_revisions(organization_id,project_id,application_id,id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id,cluster_id) REFERENCES clusters(organization_id,id) ON DELETE CASCADE);

CREATE INDEX kubernetes_revisions_release_idx ON kubernetes_workload_revisions(organization_id,project_id,application_id,release_id,last_observed_at DESC);
CREATE INDEX deployment_episodes_release_recent_idx ON deployment_episodes(organization_id,project_id,application_id,release_id,first_observed_at DESC,id DESC);
CREATE INDEX deployment_episodes_active_idx ON deployment_episodes(organization_id,application_id,cluster_id,last_observed_at DESC) WHERE state<>'inactive';
CREATE INDEX deployment_episode_predecessors_target_idx ON deployment_episode_predecessors(organization_id,project_id,application_id,episode_id,observed_at DESC);
