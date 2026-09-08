CREATE TABLE runtime_policies (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    name TEXT NOT NULL CHECK (name = btrim(name) AND char_length(name) BETWEEN 1 AND 160),
    current_revision_id UUID,
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, project_id, application_id, id)
);

CREATE TABLE runtime_policy_states (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    state_version BIGINT NOT NULL DEFAULT 0 CHECK (state_version >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, project_id, application_id),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE
);

CREATE TABLE runtime_policy_revisions (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    revision_number BIGINT NOT NULL CHECK (revision_number > 0),
    prior_revision_id UUID,
    enabled BOOLEAN NOT NULL,
    inventory_kind TEXT NOT NULL CHECK (inventory_kind IN ('process','destination','domain','syscall','inbound_endpoint','file_activity','lifecycle')),
    identity_version SMALLINT NOT NULL CHECK (identity_version > 0),
    identity_digest BYTEA NOT NULL CHECK (octet_length(identity_digest) = 32),
    behavior_matcher JSONB NOT NULL CHECK (jsonb_typeof(behavior_matcher) = 'object'),
    cluster_ids UUID[] NOT NULL DEFAULT '{}',
    namespaces TEXT[] NOT NULL DEFAULT '{}',
    workload_kinds TEXT[] NOT NULL DEFAULT '{}',
    workload_names TEXT[] NOT NULL DEFAULT '{}',
    inside_effect TEXT NOT NULL CHECK (inside_effect IN ('expected','requires_review')),
    outside_effect TEXT CHECK (outside_effect = 'requires_review'),
    source_inventory_item_id UUID,
    source_runtime_group_id UUID,
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id, policy_id)
        REFERENCES runtime_policies(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, source_inventory_item_id)
        REFERENCES runtime_inventory_items(organization_id, project_id, application_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, project_id, application_id, source_runtime_group_id)
        REFERENCES runtime_event_groups(organization_id, project_id, application_id, id) ON DELETE RESTRICT,
    UNIQUE (policy_id, revision_number),
    UNIQUE (organization_id, project_id, application_id, id),
    CHECK (cardinality(cluster_ids) <= 50),
    CHECK (cardinality(namespaces) <= 50),
    CHECK (cardinality(workload_kinds) <= 50),
    CHECK (cardinality(workload_names) <= 50)
);

ALTER TABLE runtime_policy_revisions
    ADD CONSTRAINT runtime_policy_revisions_prior_fkey
    FOREIGN KEY (organization_id, project_id, application_id, prior_revision_id)
    REFERENCES runtime_policy_revisions(organization_id, project_id, application_id, id) ON DELETE RESTRICT;

ALTER TABLE runtime_policies
    ADD CONSTRAINT runtime_policies_current_revision_fkey
    FOREIGN KEY (organization_id, project_id, application_id, current_revision_id)
    REFERENCES runtime_policy_revisions(organization_id, project_id, application_id, id) ON DELETE RESTRICT;

CREATE FUNCTION reject_runtime_policy_revision_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (
        SELECT 1 FROM runtime_policies WHERE id = OLD.policy_id
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'runtime policy revisions are immutable';
END
$$;

CREATE TRIGGER runtime_policy_revisions_immutable
BEFORE UPDATE OR DELETE ON runtime_policy_revisions
FOR EACH ROW EXECUTE FUNCTION reject_runtime_policy_revision_mutation();

CREATE TABLE runtime_policy_commands (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    idempotency_key UUID NOT NULL,
    command_kind TEXT NOT NULL CHECK (command_kind IN ('create','replace','enable','disable','suppress','cancel_suppression')),
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    actor_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    result_resource_id UUID NOT NULL,
    result JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, idempotency_key)
);

CREATE TABLE runtime_policy_suppressions (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    inventory_kind TEXT NOT NULL CHECK (inventory_kind IN ('process','destination','domain','syscall','inbound_endpoint','file_activity','lifecycle')),
    identity_version SMALLINT NOT NULL CHECK (identity_version > 0),
    identity_digest BYTEA NOT NULL CHECK (octet_length(identity_digest) = 32),
    behavior_matcher JSONB NOT NULL CHECK (jsonb_typeof(behavior_matcher) = 'object'),
    cluster_ids UUID[] NOT NULL DEFAULT '{}',
    namespaces TEXT[] NOT NULL DEFAULT '{}',
    workload_kinds TEXT[] NOT NULL DEFAULT '{}',
    workload_names TEXT[] NOT NULL DEFAULT '{}',
    reason TEXT NOT NULL CHECK (reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 500),
    expires_at TIMESTAMPTZ NOT NULL,
    cancelled_at TIMESTAMPTZ,
    cancelled_by_user_id UUID REFERENCES users(id) ON DELETE RESTRICT,
    source_inventory_item_id UUID,
    source_runtime_group_id UUID,
    created_by_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, source_inventory_item_id)
        REFERENCES runtime_inventory_items(organization_id, project_id, application_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, project_id, application_id, source_runtime_group_id)
        REFERENCES runtime_event_groups(organization_id, project_id, application_id, id) ON DELETE RESTRICT,
    UNIQUE (organization_id, project_id, application_id, id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days'),
    CHECK ((cancelled_at IS NULL) = (cancelled_by_user_id IS NULL)),
    CHECK (cancelled_at IS NULL OR cancelled_at >= created_at)
);

CREATE TABLE runtime_policy_recomputations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    identity_version SMALLINT NOT NULL CHECK (identity_version > 0),
    identity_digest BYTEA NOT NULL CHECK (octet_length(identity_digest) = 32),
    requested_policy_revision_id UUID,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','running','completed','failed')),
    group_cursor UUID,
    sighting_cursor JSONB,
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id, application_id)
        REFERENCES applications(organization_id, project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, requested_policy_revision_id)
        REFERENCES runtime_policy_revisions(organization_id, project_id, application_id, id) ON DELETE RESTRICT,
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);

CREATE TABLE runtime_group_policy_evaluations (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    group_id UUID NOT NULL,
    policy_state_version BIGINT NOT NULL CHECK (policy_state_version >= 0),
    evaluator_version SMALLINT NOT NULL CHECK (evaluator_version > 0),
    verdict TEXT NOT NULL CHECK (verdict IN ('unclassified','expected','requires_review','policy_conflict')),
    reason_code TEXT NOT NULL CHECK (reason_code IN ('no_matching_policy','inside_placement','outside_placement','equal_specificity_conflict')),
    winning_revision_id UUID,
    explanation JSONB NOT NULL CHECK (jsonb_typeof(explanation) = 'object'),
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id),
    FOREIGN KEY (organization_id, project_id, application_id, group_id)
        REFERENCES runtime_event_groups(organization_id, project_id, application_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, winning_revision_id)
        REFERENCES runtime_policy_revisions(organization_id, project_id, application_id, id) ON DELETE RESTRICT
);

CREATE TABLE runtime_sighting_policy_evaluations (
    organization_id UUID NOT NULL,
    project_id UUID NOT NULL,
    application_id UUID NOT NULL,
    item_id UUID NOT NULL,
    cluster_id UUID NOT NULL,
    namespace TEXT NOT NULL,
    workload_kind TEXT NOT NULL,
    workload_name TEXT NOT NULL,
    pod_uid TEXT NOT NULL,
    container_name TEXT NOT NULL,
    policy_state_version BIGINT NOT NULL CHECK (policy_state_version >= 0),
    evaluator_version SMALLINT NOT NULL CHECK (evaluator_version > 0),
    verdict TEXT NOT NULL CHECK (verdict IN ('unclassified','expected','requires_review','policy_conflict')),
    reason_code TEXT NOT NULL CHECK (reason_code IN ('no_matching_policy','inside_placement','outside_placement','equal_specificity_conflict')),
    winning_revision_id UUID,
    explanation JSONB NOT NULL CHECK (jsonb_typeof(explanation) = 'object'),
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, cluster_id, namespace, workload_kind, workload_name, pod_uid, container_name),
    FOREIGN KEY (item_id, cluster_id, namespace, workload_kind, workload_name, pod_uid, container_name)
        REFERENCES runtime_inventory_sightings(item_id, cluster_id, namespace, workload_kind, workload_name, pod_uid, container_name) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, application_id, winning_revision_id)
        REFERENCES runtime_policy_revisions(organization_id, project_id, application_id, id) ON DELETE RESTRICT
);

CREATE INDEX runtime_policy_revisions_match_idx ON runtime_policy_revisions
    (organization_id, project_id, application_id, identity_version, identity_digest, enabled, revision_number DESC);
CREATE INDEX runtime_policy_suppressions_active_idx ON runtime_policy_suppressions
    (organization_id, project_id, application_id, identity_version, identity_digest, expires_at)
    WHERE cancelled_at IS NULL;
CREATE INDEX runtime_policy_recomputations_claim_idx ON runtime_policy_recomputations
    (state, created_at, id) WHERE state IN ('pending','running');
CREATE INDEX runtime_group_policy_evaluations_filter_idx ON runtime_group_policy_evaluations
    (organization_id, project_id, application_id, verdict, evaluated_at DESC, group_id);
CREATE INDEX runtime_sighting_policy_evaluations_filter_idx ON runtime_sighting_policy_evaluations
    (organization_id, project_id, application_id, verdict, evaluated_at DESC, item_id);

ALTER TABLE outbox_messages
    ADD COLUMN policy_eligibility_reason TEXT CHECK (policy_eligibility_reason IN ('expected','active_suppression','backfill_suppressed','eligible','evaluation_pending','no_destinations')),
    ADD COLUMN policy_evaluated_at TIMESTAMPTZ,
    ADD COLUMN policy_revision_id UUID REFERENCES runtime_policy_revisions(id) ON DELETE RESTRICT,
    ADD COLUMN policy_suppression_id UUID REFERENCES runtime_policy_suppressions(id) ON DELETE RESTRICT;
