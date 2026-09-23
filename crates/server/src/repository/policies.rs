//! Runtime policy persistence: policies and their append-only revisions,
//! suppressions, the per-application policy state version, recomputation
//! requests, and the idempotent command log behind the policy API.
//!
//! Reads returning projections owned by the policy endpoints are generic over
//! the row type and document the columns they select.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

/// Runtime policies, their revisions and suppressions, and the commands that change them.
#[derive(Clone, Copy, Debug)]
pub struct PolicyRepository;

impl PolicyRepository {
    /// The application's policy state version, if it has one.
    pub async fn state_version<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<i64>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("SELECT state_version FROM runtime_policy_states WHERE organization_id=$1 AND project_id=$2 AND application_id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }

    /// The current, enabled revisions of the application's policies for one
    /// identity.
    ///
    /// Selects `revision_id`, `identity_version`, `identity_digest`, the
    /// placement lists, `inside_effect` and `outside_effect`.
    pub async fn enabled_revisions_for_identity<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        identity_version: i16,
        identity_digest: &[u8],
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT r.id revision_id,r.identity_version,r.identity_digest,r.cluster_ids,r.namespaces,r.workload_kinds,r.workload_names,r.inside_effect,r.outside_effect FROM runtime_policies p JOIN runtime_policy_revisions r ON r.id=p.current_revision_id WHERE p.organization_id=$1 AND p.project_id=$2 AND p.application_id=$3 AND r.enabled AND r.identity_version=$4 AND r.identity_digest=$5")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(identity_version)
            .bind(identity_digest)
            .fetch_all(executor)
            .await
    }

    /// Records, or replaces, a group's policy evaluation.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_group_evaluation<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        group_id: Uuid,
        policy_state_version: i64,
        evaluator_version: i16,
        verdict: &str,
        reason_code: &str,
        winning_revision_id: Option<Uuid>,
        explanation: &serde_json::Value,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_group_policy_evaluations(organization_id,project_id,application_id,group_id,policy_state_version,evaluator_version,verdict,reason_code,winning_revision_id,explanation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(group_id) DO UPDATE SET policy_state_version=EXCLUDED.policy_state_version,evaluator_version=EXCLUDED.evaluator_version,verdict=EXCLUDED.verdict,reason_code=EXCLUDED.reason_code,winning_revision_id=EXCLUDED.winning_revision_id,explanation=EXCLUDED.explanation,evaluated_at=now()")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(group_id)
            .bind(policy_state_version)
            .bind(evaluator_version)
            .bind(verdict)
            .bind(reason_code)
            .bind(winning_revision_id)
            .bind(explanation)
            .execute(executor)
            .await
    }

    /// Records, or replaces, a sighting's policy evaluation.
    #[allow(clippy::too_many_arguments)]
    pub async fn store_sighting_evaluation<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        cluster_id: Uuid,
        namespace: &str,
        workload_kind: &str,
        workload_name: &str,
        pod_uid: &str,
        container_name: &str,
        policy_state_version: i64,
        evaluator_version: i16,
        verdict: &str,
        reason_code: &str,
        winning_revision_id: Option<Uuid>,
        explanation: &serde_json::Value,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_sighting_policy_evaluations(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,container_name,policy_state_version,evaluator_version,verdict,reason_code,winning_revision_id,explanation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,container_name) DO UPDATE SET policy_state_version=EXCLUDED.policy_state_version,evaluator_version=EXCLUDED.evaluator_version,verdict=EXCLUDED.verdict,reason_code=EXCLUDED.reason_code,winning_revision_id=EXCLUDED.winning_revision_id,explanation=EXCLUDED.explanation,evaluated_at=now()")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(cluster_id)
            .bind(namespace)
            .bind(workload_kind)
            .bind(workload_name)
            .bind(pod_uid)
            .bind(container_name)
            .bind(policy_state_version)
            .bind(evaluator_version)
            .bind(verdict)
            .bind(reason_code)
            .bind(winning_revision_id)
            .bind(explanation)
            .execute(executor)
            .await
    }

    /// Leases the oldest pending recomputation, or one whose lease expired,
    /// to `owner`, counting an attempt.
    ///
    /// Selects the recomputation's `id`, tenant path, `identity_version` and
    /// `identity_digest`.
    pub async fn claim_recomputation<'e, E, T>(
        executor: E,
        owner: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH candidate AS (SELECT id FROM runtime_policy_recomputations WHERE state='pending' OR (state='running' AND lease_expires_at<now()) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE runtime_policy_recomputations o SET state='running',lease_owner=$1,lease_expires_at=now()+interval '30 seconds',attempt_count=attempt_count+1,started_at=COALESCE(started_at,now()),updated_at=now() FROM candidate c WHERE o.id=c.id RETURNING o.id,o.organization_id,o.project_id,o.application_id,o.identity_version,o.identity_digest")
            .bind(owner)
            .fetch_optional(executor)
            .await
    }

    /// Up to `limit` runtime groups of an identity whose evaluation is not
    /// current, with their placement.
    ///
    /// Selects `item_id`, `group_id`, `cluster_id`, `namespace`,
    /// `workload_kind` and `workload_name`.
    #[allow(clippy::too_many_arguments)]
    pub async fn groups_to_evaluate<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        identity_version: i16,
        identity_digest: &[u8],
        evaluator_version: i16,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT l.item_id,g.id group_id,g.cluster_id,g.namespace,g.workload_kind,g.workload_name FROM runtime_inventory_group_links l JOIN runtime_inventory_items i ON i.id=l.item_id JOIN runtime_event_groups g ON g.id=l.group_id LEFT JOIN runtime_group_policy_evaluations e ON e.group_id=g.id LEFT JOIN runtime_policy_states s ON s.organization_id=g.organization_id AND s.project_id=g.project_id AND s.application_id=g.application_id WHERE l.organization_id=$1 AND l.project_id=$2 AND l.application_id=$3 AND i.identity_version=$4 AND i.identity_digest=$5 AND (e.group_id IS NULL OR e.policy_state_version<COALESCE(s.state_version,0) OR e.evaluator_version<>$6) ORDER BY g.id LIMIT $7")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(identity_version)
            .bind(identity_digest)
            .bind(evaluator_version)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Up to `limit` sightings of an identity whose evaluation is not current.
    ///
    /// Selects `item_id`, `cluster_id`, `namespace`, `workload_kind`,
    /// `workload_name`, `pod_uid` and `container_name`.
    #[allow(clippy::too_many_arguments)]
    pub async fn sightings_to_evaluate<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        identity_version: i16,
        identity_digest: &[u8],
        evaluator_version: i16,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT s.item_id,s.cluster_id,s.namespace,s.workload_kind,s.workload_name,s.pod_uid,s.container_name FROM runtime_inventory_sightings s JOIN runtime_inventory_items i ON i.id=s.item_id LEFT JOIN runtime_sighting_policy_evaluations e ON e.item_id=s.item_id AND e.cluster_id=s.cluster_id AND e.namespace=s.namespace AND e.workload_kind=s.workload_kind AND e.workload_name=s.workload_name AND e.pod_uid=s.pod_uid AND e.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id WHERE s.organization_id=$1 AND s.project_id=$2 AND s.application_id=$3 AND i.identity_version=$4 AND i.identity_digest=$5 AND (e.item_id IS NULL OR e.policy_state_version<COALESCE(ps.state_version,0) OR e.evaluator_version<>$6) ORDER BY s.item_id,s.cluster_id,s.namespace,s.workload_kind,s.workload_name,s.pod_uid,s.container_name LIMIT $7")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(identity_version)
            .bind(identity_digest)
            .bind(evaluator_version)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Completes a recomputation leased to `owner`.
    pub async fn complete_recomputation<'e, E>(
        executor: E,
        recomputation_id: Uuid,
        owner: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_policy_recomputations SET state='completed',completed_at=now(),lease_owner=NULL,lease_expires_at=NULL,updated_at=now() WHERE id=$1 AND lease_owner=$2")
            .bind(recomputation_id)
            .bind(owner)
            .execute(executor)
            .await
    }

    /// Returns a recomputation leased to `owner` to pending, for the next
    /// batch.
    pub async fn release_recomputation<'e, E>(
        executor: E,
        recomputation_id: Uuid,
        owner: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_policy_recomputations SET state='pending',lease_owner=NULL,lease_expires_at=NULL,updated_at=now() WHERE id=$1 AND lease_owner=$2")
            .bind(recomputation_id)
            .bind(owner)
            .execute(executor)
            .await
    }

    /// Requests a recomputation for every identity of the project, or of one
    /// application.
    pub async fn backfill_recomputations<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Option<Uuid>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_policy_recomputations(id,organization_id,project_id,application_id,identity_version,identity_digest) SELECT gen_random_uuid(),i.organization_id,i.project_id,i.application_id,i.identity_version,i.identity_digest FROM runtime_inventory_items i WHERE i.organization_id=$1 AND i.project_id=$2 AND ($3::uuid IS NULL OR i.application_id=$3) AND NOT EXISTS(SELECT 1 FROM runtime_policy_recomputations o WHERE o.organization_id=i.organization_id AND o.project_id=i.project_id AND o.application_id=i.application_id AND o.identity_version=i.identity_version AND o.identity_digest=i.identity_digest AND o.state IN ('pending','running')) GROUP BY i.organization_id,i.project_id,i.application_id,i.identity_version,i.identity_digest")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .execute(executor)
            .await
    }

    /// One recomputation request of the application.
    ///
    /// Selects `id`, `state`, `attempt_count`, `requested_policy_revision_id`,
    /// `created_at`, `started_at`, `completed_at` and `updated_at`.
    pub async fn recomputation<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        recomputation_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,state,attempt_count,requested_policy_revision_id,created_at,started_at,completed_at,updated_at FROM runtime_policy_recomputations WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(recomputation_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of the application's policies by id, after the cursor when one
    /// is given, each with its current revision.
    ///
    /// Selects `id`, `project_id`, `application_id`, `name`,
    /// `current_revision_id`, the current revision's `revision_number`,
    /// `enabled`, `inventory_kind`, `identity_version`, `behavior_matcher`,
    /// `cluster_ids`, `namespaces`, `workload_kinds`, `workload_names`,
    /// `inside_effect` and `outside_effect`, and the policy's
    /// `created_by_user_id`, `created_at` and `updated_at`.
    pub async fn page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT p.id,p.project_id,p.application_id,p.name,p.current_revision_id,r.revision_number,r.enabled,r.inventory_kind,r.identity_version,r.behavior_matcher,r.cluster_ids,r.namespaces,r.workload_kinds,r.workload_names,r.inside_effect,r.outside_effect,p.created_by_user_id,p.created_at,p.updated_at FROM runtime_policies p LEFT JOIN runtime_policy_revisions r ON r.id=p.current_revision_id WHERE p.organization_id=$1 AND p.project_id=$2 AND p.application_id=$3 AND ($4::uuid IS NULL OR p.id>$4) ORDER BY p.id LIMIT $5")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// One policy of the application with the columns of [`Self::page`].
    pub async fn get<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT p.id,p.project_id,p.application_id,p.name,p.current_revision_id,r.revision_number,r.enabled,r.inventory_kind,r.identity_version,r.behavior_matcher,r.cluster_ids,r.namespaces,r.workload_kinds,r.workload_names,r.inside_effect,r.outside_effect,p.created_by_user_id,p.created_at,p.updated_at FROM runtime_policies p LEFT JOIN runtime_policy_revisions r ON r.id=p.current_revision_id WHERE p.organization_id=$1 AND p.project_id=$2 AND p.application_id=$3 AND p.id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(policy_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of a policy's revisions, newest first, before the cursor when
    /// one is given.
    ///
    /// Selects every revision column but the tenant path.
    pub async fn revision_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        policy_id: Uuid,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT r.id,r.policy_id,r.revision_number,r.prior_revision_id,r.enabled,r.inventory_kind,r.identity_version,r.identity_digest,r.behavior_matcher,r.cluster_ids,r.namespaces,r.workload_kinds,r.workload_names,r.inside_effect,r.outside_effect,r.source_inventory_item_id,r.source_runtime_group_id,r.created_by_user_id,r.created_at FROM runtime_policy_revisions r WHERE r.organization_id=$1 AND r.project_id=$2 AND r.application_id=$3 AND r.policy_id=$4 AND ($5::uuid IS NULL OR r.id<$5) ORDER BY r.id DESC LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(policy_id)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// A page of the application's suppressions, newest first, before the
    /// cursor when one is given; `active` keeps only suppressions that are,
    /// or are not, uncancelled and unexpired.
    ///
    /// Selects every suppression column but the tenant path.
    pub async fn suppression_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cursor: Option<Uuid>,
        active: Option<bool>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,inventory_kind,identity_version,identity_digest,behavior_matcher,cluster_ids,namespaces,workload_kinds,workload_names,reason,expires_at,cancelled_at,cancelled_by_user_id,source_inventory_item_id,source_runtime_group_id,created_by_user_id,created_at FROM runtime_policy_suppressions WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND ($4::uuid IS NULL OR id<$4) AND ($5::boolean IS NULL OR $5=(cancelled_at IS NULL AND expires_at>now())) ORDER BY id DESC LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cursor)
            .bind(active)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// Takes the transaction-scoped advisory lock for one idempotency key,
    /// given as `"{organization_id}:{key}"`, so a repeated command waits for
    /// the first to commit.
    pub async fn lock_command<'e, E>(
        executor: E,
        lock_key: String,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_key)
            .execute(executor)
            .await
    }

    /// The request digest and result recorded for an idempotency key.
    pub async fn command<'e, E>(
        executor: E,
        organization_id: Uuid,
        idempotency_key: Uuid,
    ) -> Result<Option<(Vec<u8>, Value)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Vec<u8>, Value)>("SELECT request_digest,result FROM runtime_policy_commands WHERE organization_id=$1 AND idempotency_key=$2")
            .bind(organization_id)
            .bind(idempotency_key)
            .fetch_optional(executor)
            .await
    }

    /// Records a command's result under its idempotency key.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_command<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        idempotency_key: Uuid,
        command_kind: &str,
        request_digest: &[u8],
        actor_user_id: Uuid,
        result_resource_id: Uuid,
        result: Value,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_policy_commands(id,organization_id,project_id,application_id,idempotency_key,command_kind,request_digest,actor_user_id,result_resource_id,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(idempotency_key)
            .bind(command_kind)
            .bind(request_digest)
            .bind(actor_user_id)
            .bind(result_resource_id)
            .bind(result)
            .execute(executor)
            .await
    }

    /// Increments the application's policy state version, starting it at 1,
    /// and returns the new version.
    pub async fn bump_state_version<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("INSERT INTO runtime_policy_states(organization_id,project_id,application_id,state_version) VALUES($1,$2,$3,1) ON CONFLICT(organization_id,project_id,application_id) DO UPDATE SET state_version=runtime_policy_states.state_version+1,updated_at=now() RETURNING state_version")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_one(executor)
            .await
    }

    /// The application's policy state version, creating it when absent.
    pub async fn current_state_version<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("INSERT INTO runtime_policy_states(organization_id,project_id,application_id) VALUES($1,$2,$3) ON CONFLICT(organization_id,project_id,application_id) DO UPDATE SET updated_at=runtime_policy_states.updated_at RETURNING state_version")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_one(executor)
            .await
    }

    /// Inserts a policy with no revision yet.
    pub async fn insert<'e, E>(
        executor: E,
        policy_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        name: &str,
        created_by_user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_policies(id,organization_id,project_id,application_id,name,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(policy_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(name)
            .bind(created_by_user_id)
            .execute(executor)
            .await
    }

    /// Appends a revision to a policy.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_revision<'e, E>(
        executor: E,
        revision_id: Uuid,
        policy_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        revision_number: i64,
        prior_revision_id: Option<Uuid>,
        enabled: bool,
        inventory_kind: &str,
        identity_version: i16,
        identity_digest: &[u8],
        behavior_matcher: Value,
        cluster_ids: Vec<Uuid>,
        namespaces: Vec<String>,
        workload_kinds: Vec<String>,
        workload_names: Vec<String>,
        inside_effect: &str,
        outside_effect: Option<&str>,
        source_inventory_item_id: Uuid,
        source_runtime_group_id: Option<Uuid>,
        created_by_user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_policy_revisions(id,policy_id,organization_id,project_id,application_id,revision_number,prior_revision_id,enabled,inventory_kind,identity_version,identity_digest,behavior_matcher,cluster_ids,namespaces,workload_kinds,workload_names,inside_effect,outside_effect,source_inventory_item_id,source_runtime_group_id,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)")
            .bind(revision_id)
            .bind(policy_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(revision_number)
            .bind(prior_revision_id)
            .bind(enabled)
            .bind(inventory_kind)
            .bind(identity_version)
            .bind(identity_digest)
            .bind(behavior_matcher)
            .bind(cluster_ids)
            .bind(namespaces)
            .bind(workload_kinds)
            .bind(workload_names)
            .bind(inside_effect)
            .bind(outside_effect)
            .bind(source_inventory_item_id)
            .bind(source_runtime_group_id)
            .bind(created_by_user_id)
            .execute(executor)
            .await
    }

    /// Points a policy at its new current revision.
    pub async fn set_current_revision<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        revision_id: Uuid,
        policy_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_policies SET current_revision_id=$4,updated_at=now() WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$5")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(revision_id)
            .bind(policy_id)
            .execute(executor)
            .await
    }

    /// Requests recomputation of the evaluations for one inventory identity
    /// after a revision.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_recomputation<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        identity_version: i16,
        identity_digest: &[u8],
        requested_policy_revision_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_policy_recomputations(id,organization_id,project_id,application_id,identity_version,identity_digest,requested_policy_revision_id) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(identity_version)
            .bind(identity_digest)
            .bind(requested_policy_revision_id)
            .execute(executor)
            .await
    }

    /// Counts an inventory item's sightings for a placement preview: all
    /// sightings, their distinct clusters, namespaces and workloads, and the
    /// sightings inside the placement. An empty placement list matches
    /// everything.
    pub async fn preview_counts<'e, E>(
        executor: E,
        item_id: Uuid,
        cluster_ids: &[Uuid],
        namespaces: &[String],
        workload_kinds: &[String],
        workload_names: &[String],
    ) -> Result<(i64, i64, i64, i64, i64), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (i64, i64, i64, i64, i64)>("SELECT count(*)::bigint,count(DISTINCT cluster_id)::bigint,count(DISTINCT (cluster_id,namespace))::bigint,count(DISTINCT (cluster_id,namespace,workload_kind,workload_name))::bigint,count(*) FILTER(WHERE (cardinality($2::uuid[])=0 OR cluster_id=ANY($2)) AND (cardinality($3::text[])=0 OR namespace=ANY($3)) AND (cardinality($4::text[])=0 OR workload_kind=ANY($4)) AND (cardinality($5::text[])=0 OR workload_name=ANY($5)))::bigint FROM runtime_inventory_sightings WHERE item_id=$1")
            .bind(item_id)
            .bind(cluster_ids)
            .bind(namespaces)
            .bind(workload_kinds)
            .bind(workload_names)
            .fetch_one(executor)
            .await
    }

    /// Up to 20 runtime groups linked to the item, by id, inside the
    /// placement or, with `include_outside`, anywhere.
    pub async fn preview_group_ids<'e, E>(
        executor: E,
        item_id: Uuid,
        cluster_ids: &[Uuid],
        namespaces: &[String],
        workload_kinds: &[String],
        workload_names: &[String],
        include_outside: bool,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT g.id FROM runtime_inventory_group_links l JOIN runtime_event_groups g ON g.organization_id=l.organization_id AND g.project_id=l.project_id AND g.application_id=l.application_id AND g.id=l.group_id WHERE l.item_id=$1 AND ((cardinality($2::uuid[])=0 OR g.cluster_id=ANY($2)) AND (cardinality($3::text[])=0 OR g.namespace=ANY($3)) AND (cardinality($4::text[])=0 OR g.workload_kind=ANY($4)) AND (cardinality($5::text[])=0 OR g.workload_name=ANY($5)) OR $6::boolean) ORDER BY g.id LIMIT 20")
            .bind(item_id)
            .bind(cluster_ids)
            .bind(namespaces)
            .bind(workload_kinds)
            .bind(workload_names)
            .bind(include_outside)
            .fetch_all(executor)
            .await
    }

    /// Up to 20 of the item's sightings, most recent first, inside the
    /// placement or, with `include_outside`, anywhere.
    ///
    /// Selects `cluster_id`, `namespace`, `workload_kind`, `workload_name`,
    /// `pod_uid` and `container_name`.
    pub async fn preview_sightings<'e, E, T>(
        executor: E,
        item_id: Uuid,
        cluster_ids: &[Uuid],
        namespaces: &[String],
        workload_kinds: &[String],
        workload_names: &[String],
        include_outside: bool,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT cluster_id,namespace,workload_kind,workload_name,pod_uid,container_name FROM runtime_inventory_sightings WHERE item_id=$1 AND ((cardinality($2::uuid[])=0 OR cluster_id=ANY($2)) AND (cardinality($3::text[])=0 OR namespace=ANY($3)) AND (cardinality($4::text[])=0 OR workload_kind=ANY($4)) AND (cardinality($5::text[])=0 OR workload_name=ANY($5)) OR $6::boolean) ORDER BY last_seen_at DESC,cluster_id,namespace,workload_kind,workload_name,pod_uid,container_name LIMIT 20")
            .bind(item_id)
            .bind(cluster_ids)
            .bind(namespaces)
            .bind(workload_kinds)
            .bind(workload_names)
            .bind(include_outside)
            .fetch_all(executor)
            .await
    }

    /// Locks a policy of the application and returns its current revision's
    /// id and number.
    pub async fn current_revision_for_update<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Option<(Uuid, i64)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Uuid, i64)>("SELECT current_revision_id,r.revision_number FROM runtime_policies p JOIN runtime_policy_revisions r ON r.id=p.current_revision_id WHERE p.organization_id=$1 AND p.project_id=$2 AND p.application_id=$3 AND p.id=$4 FOR UPDATE OF p")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(policy_id)
            .fetch_optional(executor)
            .await
    }

    /// Locks a policy of the application and returns its current revision
    /// with the columns of [`Self::revision_page`].
    pub async fn current_revision_detail_for_update<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT r.id,r.policy_id,r.revision_number,r.prior_revision_id,r.enabled,r.inventory_kind,r.identity_version,r.identity_digest,r.behavior_matcher,r.cluster_ids,r.namespaces,r.workload_kinds,r.workload_names,r.inside_effect,r.outside_effect,r.source_inventory_item_id,r.source_runtime_group_id,r.created_by_user_id,r.created_at FROM runtime_policies p JOIN runtime_policy_revisions r ON r.id=p.current_revision_id WHERE p.organization_id=$1 AND p.project_id=$2 AND p.application_id=$3 AND p.id=$4 FOR UPDATE OF p")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(policy_id)
            .fetch_optional(executor)
            .await
    }

    /// Renames a policy.
    pub async fn rename<'e, E>(
        executor: E,
        name: &str,
        policy_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_policies SET name=$1 WHERE id=$2")
            .bind(name)
            .bind(policy_id)
            .execute(executor)
            .await
    }

    /// Inserts a suppression of one inventory identity within a placement
    /// until it expires.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_suppression<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        inventory_kind: &str,
        identity_version: i16,
        identity_digest: &[u8],
        behavior_matcher: Value,
        cluster_ids: Vec<Uuid>,
        namespaces: Vec<String>,
        workload_kinds: Vec<String>,
        workload_names: Vec<String>,
        reason: &str,
        expires_at: DateTime<Utc>,
        source_inventory_item_id: Uuid,
        source_runtime_group_id: Option<Uuid>,
        created_by_user_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_policy_suppressions(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,behavior_matcher,cluster_ids,namespaces,workload_kinds,workload_names,reason,expires_at,source_inventory_item_id,source_runtime_group_id,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(inventory_kind)
            .bind(identity_version)
            .bind(identity_digest)
            .bind(behavior_matcher)
            .bind(cluster_ids)
            .bind(namespaces)
            .bind(workload_kinds)
            .bind(workload_names)
            .bind(reason)
            .bind(expires_at)
            .bind(source_inventory_item_id)
            .bind(source_runtime_group_id)
            .bind(created_by_user_id)
            .bind(created_at)
            .execute(executor)
            .await
    }

    /// Cancels a suppression of the application, keeping an earlier
    /// cancellation. Affects no row when there is no such suppression.
    pub async fn cancel_suppression<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        suppression_id: Uuid,
        cancelled_by_user_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_policy_suppressions SET cancelled_at=COALESCE(cancelled_at,now()),cancelled_by_user_id=COALESCE(cancelled_by_user_id,$5) WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(suppression_id)
            .bind(cancelled_by_user_id)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{Value, json};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::PolicyRepository;
    use crate::policy::BehaviorIdentity;
    use crate::repository::inventory::InventoryRepository;
    use crate::repository::test_support::{Tenant, exec, group_ids, ingest, tenant, user};
    use crate::repository::transaction::TransactionRepository;

    #[derive(Debug, FromRow)]
    struct ItemIdentity {
        id: Uuid,
        inventory_kind: String,
        identity_version: i16,
        identity_digest: Vec<u8>,
        semantic_summary: Value,
    }

    #[derive(Debug, FromRow)]
    struct Seed {
        item_id: Uuid,
        namespace: String,
        workload_name: String,
    }

    #[derive(Debug, FromRow)]
    struct Policy {
        id: Uuid,
        name: String,
        current_revision_id: Option<Uuid>,
        revision_number: Option<i64>,
        inside_effect: Option<String>,
    }

    #[derive(Debug, FromRow)]
    struct PolicyRevision {
        id: Uuid,
        revision_number: i64,
        prior_revision_id: Option<Uuid>,
        outside_effect: Option<String>,
    }

    #[derive(Debug, FromRow)]
    struct Recomputation {
        id: Uuid,
        state: String,
        attempt_count: i32,
        requested_policy_revision_id: Option<Uuid>,
    }

    #[derive(Debug, FromRow)]
    struct Suppression {
        id: Uuid,
        cancelled_at: Option<DateTime<Utc>>,
        cancelled_by_user_id: Option<Uuid>,
    }

    #[derive(Debug, FromRow)]
    struct Sighting {
        namespace: String,
    }

    /// The only inventory item of the tenant, with its identity.
    async fn identity(pool: &PgPool, own: &Tenant) -> ItemIdentity {
        let item_id: Uuid =
            sqlx::query_scalar("SELECT id FROM runtime_inventory_items WHERE application_id=$1")
                .bind(own.application_id)
                .fetch_one(pool)
                .await
                .unwrap();
        InventoryRepository::identity(
            pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            item_id,
        )
        .await
        .unwrap()
        .unwrap()
    }

    fn matcher(identity: &ItemIdentity) -> Value {
        let behavior = BehaviorIdentity::from_inventory(
            &identity.inventory_kind,
            identity.identity_version,
            &identity.identity_digest,
            &identity.semantic_summary,
        )
        .unwrap();
        serde_json::to_value(behavior.matcher).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    async fn revise(
        pool: &PgPool,
        own: &Tenant,
        actor: Uuid,
        policy_id: Uuid,
        number: i64,
        prior: Option<Uuid>,
        identity: &ItemIdentity,
        outside: Option<&str>,
    ) -> Uuid {
        let revision_id = Uuid::new_v4();
        PolicyRepository::insert_revision(
            pool,
            revision_id,
            policy_id,
            own.organization_id,
            own.project_id,
            own.application_id,
            number,
            prior,
            true,
            &identity.inventory_kind,
            identity.identity_version,
            &identity.identity_digest,
            matcher(identity),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "expected",
            outside,
            identity.id,
            None,
            actor,
        )
        .await
        .unwrap();
        PolicyRepository::set_current_revision(
            pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            revision_id,
            policy_id,
        )
        .await
        .unwrap();
        revision_id
    }

    async fn policy(pool: &PgPool, own: &Tenant, actor: Uuid, name: &str) -> Uuid {
        let id = Uuid::new_v4();
        PolicyRepository::insert(
            pool,
            id,
            own.organization_id,
            own.project_id,
            own.application_id,
            name,
            actor,
        )
        .await
        .unwrap();
        id
    }

    /// The inventory reads that seed a policy: an item's identity, the item
    /// behind a group with the group's placement, and their link.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn seeds_come_from_items_and_groups(pool: PgPool) {
        let own = tenant(&pool, "policies-seed").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let item = identity(&pool, &own).await;
        assert_eq!(
            (item.inventory_kind.as_str(), item.identity_digest.len()),
            ("process", 32)
        );
        let group = group_ids(&pool, &own).await[0];
        let seed: Seed = InventoryRepository::group_seed(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            group,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (
                seed.item_id,
                seed.namespace.as_str(),
                seed.workload_name.as_str()
            ),
            (item.id, "production", "app")
        );
        let linked = |group_id: Uuid| {
            InventoryRepository::item_linked_to_group(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                item.id,
                group_id,
            )
        };
        assert!(linked(group).await.unwrap());
        assert!(!linked(Uuid::new_v4()).await.unwrap());
        assert_eq!(
            InventoryRepository::linked_group_count(&pool, item.id)
                .await
                .unwrap(),
            1
        );
        let stranger = tenant(&pool, "policies-seed-other").await;
        assert!(
            InventoryRepository::identity::<_, ItemIdentity>(
                &pool,
                stranger.organization_id,
                stranger.project_id,
                stranger.application_id,
                item.id,
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    /// Policies page by id with their current revision; revisions append and
    /// page newest id first; recomputations are requested per revision; the
    /// state version only moves when bumped.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn policies_revise_and_bump_the_state(pool: PgPool) {
        let own = tenant(&pool, "policies-revise").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let item = identity(&pool, &own).await;
        let actor = user(&pool).await;
        let first = policy(&pool, &own, actor, "Shell").await;
        let bare = policy(&pool, &own, actor, "Bare").await;
        let r1 = revise(&pool, &own, actor, first, 1, None, &item, None).await;

        let read = |id: Uuid| {
            PolicyRepository::get::<_, Policy>(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                id,
            )
        };
        let shell = read(first).await.unwrap().unwrap();
        assert_eq!(
            (
                shell.current_revision_id,
                shell.revision_number,
                shell.inside_effect.as_deref()
            ),
            (Some(r1), Some(1), Some("expected"))
        );
        assert_eq!(read(bare).await.unwrap().unwrap().current_revision_id, None);
        let mut by_id = vec![first, bare];
        by_id.sort();
        let page: Vec<Policy> = PolicyRepository::page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(page.iter().map(|p| p.id).collect::<Vec<_>>(), by_id);
        let after: Vec<Policy> = PolicyRepository::page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            Some(by_id[0]),
            10,
        )
        .await
        .unwrap();
        assert_eq!(after.iter().map(|p| p.id).collect::<Vec<_>>(), by_id[1..]);

        let locked = |id: Uuid| {
            PolicyRepository::current_revision_for_update(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                id,
            )
        };
        assert_eq!(locked(first).await.unwrap(), Some((r1, 1)));
        assert_eq!(
            locked(bare).await.unwrap(),
            None,
            "no revision, nothing to lock"
        );
        let r2 = revise(
            &pool,
            &own,
            actor,
            first,
            2,
            Some(r1),
            &item,
            Some("requires_review"),
        )
        .await;
        let current: PolicyRevision = PolicyRepository::current_revision_detail_for_update(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            first,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (
                current.id,
                current.revision_number,
                current.prior_revision_id
            ),
            (r2, 2, Some(r1))
        );
        assert_eq!(current.outside_effect.as_deref(), Some("requires_review"));
        let revisions: Vec<PolicyRevision> = PolicyRepository::revision_page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            first,
            None,
            10,
        )
        .await
        .unwrap();
        let mut newest_id_first = vec![r1, r2];
        newest_id_first.sort_by(|a, b| b.cmp(a));
        assert_eq!(
            revisions.iter().map(|r| r.id).collect::<Vec<_>>(),
            newest_id_first
        );

        PolicyRepository::rename(&pool, "Renamed", first)
            .await
            .unwrap();
        assert_eq!(read(first).await.unwrap().unwrap().name, "Renamed");

        let state = || {
            PolicyRepository::current_state_version(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
            )
        };
        let before = state().await.unwrap();
        assert_eq!(state().await.unwrap(), before, "reading does not bump");
        let bumped = PolicyRepository::bump_state_version(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
        )
        .await
        .unwrap();
        assert_eq!(bumped, before + 1);
        assert_eq!(state().await.unwrap(), before + 1);

        let recomputation = Uuid::new_v4();
        PolicyRepository::request_recomputation(
            &pool,
            recomputation,
            own.organization_id,
            own.project_id,
            own.application_id,
            item.identity_version,
            &item.identity_digest,
            r2,
        )
        .await
        .unwrap();
        let requested: Recomputation = PolicyRepository::recomputation(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            recomputation,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (
                requested.id,
                requested.state.as_str(),
                requested.attempt_count
            ),
            (recomputation, "pending", 0)
        );
        assert_eq!(requested.requested_policy_revision_id, Some(r2));
    }

    /// A command's result is recorded once per idempotency key, and the key's
    /// lock is held until commit.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn commands_are_recorded_once_under_a_lock(pool: PgPool) {
        let own = tenant(&pool, "policies-commands").await;
        let actor = user(&pool).await;
        let key = Uuid::new_v4();
        let lock_key = format!("{}:{key}", own.organization_id);
        let try_lock = || async {
            sqlx::query_scalar::<_, bool>(
                "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
            )
            .bind(format!("{}:{key}", own.organization_id))
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        let mut tx = pool.begin().await.unwrap();
        PolicyRepository::lock_command(&mut *tx, lock_key)
            .await
            .unwrap();
        assert!(!try_lock().await);
        tx.commit().await.unwrap();
        assert!(try_lock().await);

        assert_eq!(
            PolicyRepository::command(&pool, own.organization_id, key)
                .await
                .unwrap(),
            None
        );
        let record = || {
            PolicyRepository::record_command(
                &pool,
                Uuid::new_v4(),
                own.organization_id,
                own.project_id,
                own.application_id,
                key,
                "create",
                &[3; 32],
                actor,
                Uuid::new_v4(),
                json!({"ok": true}),
            )
        };
        record().await.unwrap();
        assert_eq!(
            PolicyRepository::command(&pool, own.organization_id, key)
                .await
                .unwrap(),
            Some((vec![3; 32], json!({"ok": true})))
        );
        let repeated = record().await.unwrap_err();
        assert_eq!(
            repeated
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("23505")
        );
    }

    /// Suppressions page newest id first, filter by whether they are active,
    /// and keep their first cancellation.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn suppressions_are_cancelled_once_and_filtered(pool: PgPool) {
        let own = tenant(&pool, "policies-suppressions").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let item = identity(&pool, &own).await;
        let actor = user(&pool).await;
        let mut ids = Vec::new();
        for _ in 0..2 {
            let id = Uuid::new_v4();
            let now = Utc::now();
            PolicyRepository::insert_suppression(
                &pool,
                id,
                own.organization_id,
                own.project_id,
                own.application_id,
                &item.inventory_kind,
                item.identity_version,
                &item.identity_digest,
                matcher(&item),
                Vec::new(),
                vec!["production".into()],
                Vec::new(),
                Vec::new(),
                "known noise",
                now + Duration::days(1),
                item.id,
                None,
                actor,
                now,
            )
            .await
            .unwrap();
            ids.push(id);
        }
        let cancel = |id: Uuid| {
            PolicyRepository::cancel_suppression(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                id,
                actor,
            )
        };
        assert_eq!(cancel(ids[0]).await.unwrap().rows_affected(), 1);
        let page = |active: Option<bool>| {
            PolicyRepository::suppression_page::<_, Suppression>(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                None,
                active,
                10,
            )
        };
        let first_cancel = page(Some(false)).await.unwrap();
        assert_eq!(
            first_cancel.iter().map(|s| s.id).collect::<Vec<_>>(),
            [ids[0]]
        );
        assert_eq!(first_cancel[0].cancelled_by_user_id, Some(actor));
        cancel(ids[0]).await.unwrap();
        assert_eq!(
            page(Some(false)).await.unwrap()[0].cancelled_at,
            first_cancel[0].cancelled_at,
            "the first cancellation stays"
        );
        assert_eq!(cancel(Uuid::new_v4()).await.unwrap().rows_affected(), 0);
        assert_eq!(
            page(Some(true))
                .await
                .unwrap()
                .iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
            [ids[1]]
        );
        let mut newest_id_first = ids.clone();
        newest_id_first.sort_by(|a, b| b.cmp(a));
        assert_eq!(
            page(None)
                .await
                .unwrap()
                .iter()
                .map(|s| s.id)
                .collect::<Vec<_>>(),
            newest_id_first
        );
        let after: Vec<Suppression> = PolicyRepository::suppression_page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            Some(newest_id_first[0]),
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(
            after.iter().map(|s| s.id).collect::<Vec<_>>(),
            newest_id_first[1..]
        );
    }

    /// The preview counts an item's sightings inside a placement and lists
    /// representative groups and sightings inside it or, when the outside
    /// counts too, anywhere.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_preview_counts_inside_and_outside(pool: PgPool) {
        let own = tenant(&pool, "policies-preview").await;
        ingest(
            &pool,
            &own,
            &[
                exec(&own, "/bin/a", Utc::now()),
                exec(&own, "/bin/a", Utc::now()),
            ],
        )
        .await;
        let item = identity(&pool, &own).await;
        let group = group_ids(&pool, &own).await[0];
        let everywhere: Vec<String> = Vec::new();
        let staging = vec!["staging".to_owned()];
        let counts = |namespaces: Vec<String>| {
            let pool = pool.clone();
            async move {
                PolicyRepository::preview_counts(&pool, item.id, &[], &namespaces, &[], &[])
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            counts(everywhere.clone()).await,
            (2, 1, 1, 1, 2),
            "two pods, one workload"
        );
        assert_eq!(counts(staging.clone()).await, (2, 1, 1, 1, 0));

        let groups = |namespaces: Vec<String>, outside: bool| {
            let pool = pool.clone();
            async move {
                PolicyRepository::preview_group_ids(
                    &pool,
                    item.id,
                    &[],
                    &namespaces,
                    &[],
                    &[],
                    outside,
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(groups(everywhere.clone(), false).await, [group]);
        assert!(groups(staging.clone(), false).await.is_empty());
        assert_eq!(groups(staging.clone(), true).await, [group]);
        let sightings = |namespaces: Vec<String>, outside: bool| {
            let pool = pool.clone();
            async move {
                PolicyRepository::preview_sightings::<_, Sighting>(
                    &pool,
                    item.id,
                    &[],
                    &namespaces,
                    &[],
                    &[],
                    outside,
                )
                .await
                .unwrap()
            }
        };
        let all = sightings(everywhere, false).await;
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|s| s.namespace == "production"));
        assert!(sightings(staging.clone(), false).await.is_empty());
        assert_eq!(sightings(staging, true).await.len(), 2);
    }

    /// A consistent read is a read-only repeatable-read snapshot whose time is
    /// the transaction's start.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_consistent_read_is_a_snapshot(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        TransactionRepository::begin_consistent_read(&mut *tx)
            .await
            .unwrap();
        let first = TransactionRepository::snapshot_time(&mut *tx)
            .await
            .unwrap();
        let settings: (String, String) = sqlx::query_as(
            "SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(settings, ("repeatable read".into(), "on".into()));
        let second = TransactionRepository::snapshot_time(&mut *tx)
            .await
            .unwrap();
        assert_eq!(first, second, "the snapshot time does not move");
        tx.commit().await.unwrap();
    }

    /// A recomputation is leased, finds the groups and sightings whose
    /// evaluation is stale, stores fresh evaluations, and is released or
    /// completed by its owner; backfill requests one per identity.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn recomputations_reevaluate_stale_placements(pool: PgPool) {
        #[derive(Debug, FromRow)]
        struct Leased {
            id: Uuid,
            identity_version: i16,
        }
        #[derive(Debug, FromRow)]
        struct GroupTarget {
            group_id: Uuid,
        }
        #[derive(Debug, FromRow)]
        struct SightingTarget {
            item_id: Uuid,
            cluster_id: Uuid,
            namespace: String,
            workload_kind: String,
            workload_name: String,
            pod_uid: String,
            container_name: String,
        }
        #[derive(Debug, FromRow)]
        struct EnabledRevision {
            revision_id: Uuid,
        }

        let own = tenant(&pool, "policies-recompute").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let item = identity(&pool, &own).await;
        let group = group_ids(&pool, &own).await[0];
        let actor = user(&pool).await;
        let shell = policy(&pool, &own, actor, "Shell").await;
        let revision = revise(&pool, &own, actor, shell, 1, None, &item, None).await;
        let version = PolicyRepository::bump_state_version(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
        )
        .await
        .unwrap();
        assert_eq!(
            PolicyRepository::state_version(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id
            )
            .await
            .unwrap(),
            Some(version)
        );
        let enabled: Vec<EnabledRevision> = PolicyRepository::enabled_revisions_for_identity(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            item.identity_version,
            &item.identity_digest,
        )
        .await
        .unwrap();
        assert_eq!(
            enabled.iter().map(|r| r.revision_id).collect::<Vec<_>>(),
            [revision]
        );

        let recomputation = Uuid::new_v4();
        PolicyRepository::request_recomputation(
            &pool,
            recomputation,
            own.organization_id,
            own.project_id,
            own.application_id,
            item.identity_version,
            &item.identity_digest,
            revision,
        )
        .await
        .unwrap();
        let owner = Uuid::new_v4();
        let leased: Leased = PolicyRepository::claim_recomputation(&pool, owner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (leased.id, leased.identity_version),
            (recomputation, item.identity_version)
        );
        assert!(
            PolicyRepository::claim_recomputation::<_, Leased>(&pool, Uuid::new_v4())
                .await
                .unwrap()
                .is_none(),
            "leased once"
        );

        let groups = || {
            PolicyRepository::groups_to_evaluate::<_, GroupTarget>(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                item.identity_version,
                &item.identity_digest,
                crate::policy::POLICY_EVALUATOR_VERSION,
                10,
            )
        };
        let sightings = || {
            PolicyRepository::sightings_to_evaluate::<_, SightingTarget>(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                item.identity_version,
                &item.identity_digest,
                crate::policy::POLICY_EVALUATOR_VERSION,
                10,
            )
        };
        assert_eq!(
            groups()
                .await
                .unwrap()
                .iter()
                .map(|g| g.group_id)
                .collect::<Vec<_>>(),
            [group],
            "the state moved on, the evaluation is stale"
        );
        let stale_sightings = sightings().await.unwrap();
        assert_eq!(stale_sightings.len(), 1);
        let explanation = json!({"policy": "Shell"});
        PolicyRepository::store_group_evaluation(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            group,
            version,
            crate::policy::POLICY_EVALUATOR_VERSION,
            "expected",
            "inside_placement",
            Some(revision),
            &explanation,
        )
        .await
        .unwrap();
        for s in &stale_sightings {
            assert_eq!(s.item_id, item.id);
            PolicyRepository::store_sighting_evaluation(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                s.item_id,
                s.cluster_id,
                &s.namespace,
                &s.workload_kind,
                &s.workload_name,
                &s.pod_uid,
                &s.container_name,
                version,
                crate::policy::POLICY_EVALUATOR_VERSION,
                "expected",
                "inside_placement",
                Some(revision),
                &explanation,
            )
            .await
            .unwrap();
        }
        assert!(groups().await.unwrap().is_empty());
        assert!(sightings().await.unwrap().is_empty());

        let state = || async {
            sqlx::query_scalar::<_, String>(
                "SELECT state FROM runtime_policy_recomputations WHERE id=$1",
            )
            .bind(recomputation)
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        PolicyRepository::release_recomputation(&pool, recomputation, Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(state().await, "running", "only the owner releases it");
        PolicyRepository::release_recomputation(&pool, recomputation, owner)
            .await
            .unwrap();
        assert_eq!(state().await, "pending");
        let second_owner = Uuid::new_v4();
        PolicyRepository::claim_recomputation::<_, Leased>(&pool, second_owner)
            .await
            .unwrap()
            .unwrap();
        PolicyRepository::complete_recomputation(&pool, recomputation, second_owner)
            .await
            .unwrap();
        assert_eq!(state().await, "completed");

        PolicyRepository::backfill_recomputations(&pool, own.organization_id, own.project_id, None)
            .await
            .unwrap();
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runtime_policy_recomputations WHERE project_id=$1 AND state='pending'",
        )
        .bind(own.project_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(pending, 1, "one per identity of the project");
    }
}
