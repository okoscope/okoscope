//! Runtime event group persistence.
//!
//! A group is the deduplicated unit the product reasons about: many raw
//! `runtime_events` rows collapse onto one `runtime_event_groups` row keyed by
//! a fingerprint. Two independent writers create groups — the live grouping
//! path in [`crate::grouping`] and the derived restart-loop projection in
//! [`crate::termination_projection`] — and both used to carry their own copy of
//! the insert, the conflict target, and the occurrence bookkeeping. They are
//! collected here so that the two remain visibly different where they must be
//! and identical where they should be.
//!
//! The analytical reads that project groups into API responses are not here.
//! An attention feed or an inventory listing is a multi-table CTE written for
//! one endpoint, and moving it would relocate the statement without giving any
//! other caller a reason to share it. What lives here is the write path, the
//! tenant lookup, and the counting predicates — the statements more than one
//! call site genuinely needs.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

/// The columns that uniquely identify a group.
///
/// These are exactly the nine columns of the `runtime_event_groups` unique
/// index, in its order. Passing them as one value rather than nine arguments
/// keeps a caller from silently omitting one: dropping a column here would not
/// widen a query, it would change which row the conflict target matches.
#[derive(Clone, Copy, Debug)]
pub struct GroupKey<'a> {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub cluster_id: Uuid,
    pub namespace: &'a str,
    pub workload_kind: &'a str,
    pub workload_name: &'a str,
    pub fingerprint_version: i16,
    pub fingerprint_digest: &'a [u8],
}

/// Scalar subqueries aggregating a tenant's groups.
///
/// These are string fragments rather than methods on purpose. Every call site
/// embeds the aggregate in a paginated listing that already selects the owning
/// row, so a method would turn one query into a query per row. Sharing the text
/// is what keeps the definition in one place.
///
/// Each fragment expects the owning table under a fixed alias, named in its
/// documentation, and carries the full tenant path even where a foreign key
/// makes part of it redundant — an aggregate that reads as tenant-scoped should
/// not depend on the reader knowing the schema to see that it is.
///
/// # Two definitions of the same number
///
/// Retention can leave a group row behind at `occurrence_count = 0`, which
/// splits every aggregate here in two: over all groups, or only over groups
/// that still have evidence.
///
/// That count is not "raw events" — it sums raw events and history snapshots,
/// so a compacted group keeps its count. It reaches zero only after the
/// snapshots expire too, leaving a group with no surviving record of any kind,
/// held in place by a policy revision, a suppression or an unprocessed outbox
/// message. Anything else at zero is deleted, and `runtime_history_snapshots`
/// cascades with it — so counting over all groups yields neither a live total
/// nor a historical one, but live groups plus whatever residue policy happens
/// to pin. A genuine historical total belongs to `runtime_history_snapshots`.
///
/// The endpoints do not agree on which reading they mean: `runtime_group_count`
/// is counted one way for a project and another for its applications, so one
/// cannot be summed into the other. Both readings are spelled out and named
/// rather than reconciled, because picking one changes a number an API already
/// returns.
pub mod aggregates {
    /// Counts every group of a project, evidence or not.
    /// Expects `projects` aliased as `p`.
    pub const COUNT_ALL_FOR_PROJECT: &str = "(SELECT count(*) FROM runtime_event_groups g \
         WHERE g.organization_id=p.organization_id AND g.project_id=p.id)";

    /// Counts every group of an application, evidence or not.
    /// Expects `applications` aliased as `a`.
    pub const COUNT_ALL_FOR_APPLICATION: &str = "(SELECT count(*) FROM runtime_event_groups g \
         WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id \
           AND g.application_id=a.id)";

    /// Counts an application's groups that still have raw evidence behind them.
    /// Expects `applications` aliased as `a`.
    pub const COUNT_WITH_EVIDENCE_FOR_APPLICATION: &str = "(SELECT count(*) FROM runtime_event_groups g \
         WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id \
           AND g.application_id=a.id AND g.occurrence_count>0)";

    /// The most recent sighting across an application's groups, evidence or not.
    /// Expects `applications` aliased as `a`.
    pub const LATEST_SEEN_ALL_FOR_APPLICATION: &str = "(SELECT max(g.last_seen_at) FROM runtime_event_groups g \
         WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id \
           AND g.application_id=a.id)";

    /// The most recent sighting an application still holds evidence for.
    /// Expects `applications` aliased as `a`.
    pub const LATEST_SEEN_WITH_EVIDENCE_FOR_APPLICATION: &str = "(SELECT max(g.last_seen_at) FROM runtime_event_groups g \
         WHERE g.organization_id=a.organization_id AND g.project_id=a.project_id \
           AND g.application_id=a.id AND g.occurrence_count>0)";
}

/// Queries against the `runtime_event_groups` table.
#[derive(Clone, Copy, Debug)]
pub struct EventGroupRepository;

impl EventGroupRepository {
    /// Makes an event a member of a group under a fingerprint version, with
    /// its release, once; `None` when it already was.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_release_membership<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        event_id: Uuid,
        group_id: Uuid,
        fingerprint_version: i16,
        release_id: Option<Uuid>,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO runtime_event_group_memberships (organization_id, project_id, application_id, event_id, group_id, fingerprint_version, release_id) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (event_id, fingerprint_version) DO NOTHING RETURNING event_id")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(event_id)
            .bind(group_id)
            .bind(fingerprint_version)
            .bind(release_id)
            .fetch_optional(executor)
            .await
    }

    /// Counts an occurrence of a group in a release, widening its seen
    /// window and making the event its representative when it is the latest.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_release_occurrence<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        release_id: Uuid,
        group_id: Uuid,
        observed_at: DateTime<Utc>,
        event_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_event_group_releases (organization_id,project_id,application_id,release_id,group_id,occurrence_count,first_seen_at,last_seen_at,representative_event_id) VALUES ($1,$2,$3,$4,$5,1,$6,$6,$7) ON CONFLICT (release_id,group_id) DO UPDATE SET representative_event_id=COALESCE(runtime_event_group_releases.representative_event_id,EXCLUDED.representative_event_id),occurrence_count=runtime_event_group_releases.occurrence_count+1,first_seen_at=LEAST(runtime_event_group_releases.first_seen_at,EXCLUDED.first_seen_at),last_seen_at=GREATEST(runtime_event_group_releases.last_seen_at,EXCLUDED.last_seen_at),updated_at=now()")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(release_id)
            .bind(group_id)
            .bind(observed_at)
            .bind(event_id)
            .execute(executor)
            .await
    }

    /// The application's group memberships plus snapshot occurrences, and
    /// the total occurrence count of its groups.
    pub async fn evidence_counts<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT (SELECT count(*) FROM runtime_event_group_memberships WHERE organization_id=$1 AND project_id=$2 AND application_id=$3)+(SELECT COALESCE(sum(occurrence_count),0)::bigint FROM runtime_history_snapshots WHERE organization_id=$1 AND project_id=$2 AND application_id=$3),(SELECT COALESCE(sum(occurrence_count),0)::bigint FROM runtime_event_groups WHERE organization_id=$1 AND project_id=$2 AND application_id=$3)")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_one(executor)
            .await
    }

    /// How many per-release group rollups exist.
    pub async fn release_rollup_count<'e, E>(executor: E) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM runtime_event_group_releases")
            .fetch_one(executor)
            .await
    }

    /// Makes an event a member of a group, once.
    pub async fn add_membership<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        event_id: Uuid,
        group_id: Uuid,
        fingerprint_version: i16,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_event_group_memberships (organization_id,project_id,application_id,event_id,group_id,fingerprint_version) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(event_id)
            .bind(group_id)
            .bind(fingerprint_version)
            .execute(executor)
            .await
    }

    /// Whether a group's first sighting should be notified under its current
    /// policy state: `active_suppression`, `evaluation_pending`, `expected`
    /// or `eligible`, with the winning revision and suppression behind it.
    ///
    /// Selects `reason`, `evaluated_at`, `policy_revision_id` and
    /// `policy_suppression_id`.
    pub async fn notification_eligibility<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
        evaluator_version: i16,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT CASE WHEN s.id IS NOT NULL THEN 'active_suppression' WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 THEN 'evaluation_pending' WHEN e.verdict='expected' THEN 'expected' ELSE 'eligible' END reason,now() evaluated_at,CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 THEN e.winning_revision_id END policy_revision_id,s.id policy_suppression_id FROM runtime_event_groups g LEFT JOIN runtime_group_policy_evaluations e ON e.group_id=g.id LEFT JOIN runtime_policy_states ps ON ps.organization_id=g.organization_id AND ps.project_id=g.project_id AND ps.application_id=g.application_id LEFT JOIN LATERAL (SELECT x.id FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id JOIN runtime_policy_suppressions x ON x.organization_id=i.organization_id AND x.project_id=i.project_id AND x.application_id=i.application_id AND x.identity_version=i.identity_version AND x.identity_digest=i.identity_digest WHERE gl.group_id=g.id AND x.cancelled_at IS NULL AND x.expires_at>now() AND (cardinality(x.cluster_ids)=0 OR g.cluster_id=ANY(x.cluster_ids)) AND (cardinality(x.namespaces)=0 OR g.namespace=ANY(x.namespaces)) AND (cardinality(x.workload_kinds)=0 OR g.workload_kind=ANY(x.workload_kinds)) AND (cardinality(x.workload_names)=0 OR g.workload_name=ANY(x.workload_names)) ORDER BY x.expires_at,x.id LIMIT 1) s ON true WHERE g.organization_id=$1 AND g.id=$2")
            .bind(organization_id)
            .bind(group_id)
            .bind(evaluator_version)
            .fetch_one(executor)
            .await
    }

    /// Up to 20 user labels on the inventory items behind a group, as a JSON
    /// array ordered by display name.
    pub async fn user_labels_json<'e, E>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
    ) -> Result<Value, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Value>("SELECT COALESCE(jsonb_agg(label ORDER BY label->>'display_name',label->>'updated_at'),'[]'::jsonb) FROM (SELECT jsonb_build_object('display_name',l.display_name,'created_by_user_id',l.created_by_user_id,'updated_by_user_id',l.updated_by_user_id,'created_at',l.created_at,'updated_at',l.updated_at) label FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id JOIN runtime_behavior_user_labels l ON l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest WHERE gl.organization_id=$1 AND gl.group_id=$2 ORDER BY l.display_name,l.id LIMIT 20) labels")
            .bind(organization_id)
            .bind(group_id)
            .fetch_one(executor)
            .await
    }

    /// The user-assigned behaviour labels attached to each of the given
    /// groups through their inventory items, one row per group.
    pub async fn user_labels<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_ids: Vec<Uuid>,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT gl.group_id,jsonb_agg(jsonb_build_object('display_name',l.display_name,'created_by_user_id',l.created_by_user_id,'updated_by_user_id',l.updated_by_user_id,'created_at',l.created_at,'updated_at',l.updated_at) ORDER BY l.display_name,l.id) user_labels FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id JOIN runtime_behavior_user_labels l ON l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest WHERE gl.organization_id=$1 AND gl.group_id=ANY($2) GROUP BY gl.group_id")
            .bind(organization_id)
            .bind(group_ids)
            .fetch_all(executor)
            .await
    }

    /// The current policy verdict of each of the given groups, as a JSON
    /// object per group. A verdict computed by an older evaluator or against
    /// an older policy state is reported as pending rather than as current.
    pub async fn policy_states<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_ids: &[Uuid],
        evaluator_version: i16,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT g.id group_id,jsonb_build_object('state',CASE WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 THEN 'evaluation_pending' ELSE 'current' END,'verdict',CASE WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 THEN NULL ELSE e.verdict END,'reason_code',CASE WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 THEN 'evaluation_pending' ELSE e.reason_code END,'winning_revision_id',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 THEN e.winning_revision_id END,'explanation',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 THEN e.explanation ELSE '{}'::jsonb END,'evaluated_at',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 THEN e.evaluated_at END) policy_evaluation,s.summary active_suppression,(s.summary IS NULL AND (e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 OR e.verdict<>'expected')) actionable FROM runtime_event_groups g LEFT JOIN runtime_group_policy_evaluations e ON e.group_id=g.id LEFT JOIN runtime_policy_states ps ON ps.organization_id=g.organization_id AND ps.project_id=g.project_id AND ps.application_id=g.application_id LEFT JOIN LATERAL (SELECT jsonb_build_object('id',x.id,'reason',x.reason,'expires_at',x.expires_at,'created_at',x.created_at) summary FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id JOIN runtime_policy_suppressions x ON x.organization_id=i.organization_id AND x.project_id=i.project_id AND x.application_id=i.application_id AND x.identity_version=i.identity_version AND x.identity_digest=i.identity_digest WHERE gl.group_id=g.id AND x.cancelled_at IS NULL AND x.expires_at>now() AND (cardinality(x.cluster_ids)=0 OR g.cluster_id=ANY(x.cluster_ids)) AND (cardinality(x.namespaces)=0 OR g.namespace=ANY(x.namespaces)) AND (cardinality(x.workload_kinds)=0 OR g.workload_kind=ANY(x.workload_kinds)) AND (cardinality(x.workload_names)=0 OR g.workload_name=ANY(x.workload_names)) ORDER BY (cardinality(x.cluster_ids)>0)::int+(cardinality(x.namespaces)>0)::int+(cardinality(x.workload_kinds)>0)::int+(cardinality(x.workload_names)>0)::int DESC,x.expires_at,x.id LIMIT 1) s ON true WHERE g.organization_id=$1 AND g.id=ANY($2)")
            .bind(organization_id)
            .bind(group_ids)
            .bind(evaluator_version)
            .fetch_all(executor)
            .await
    }

    /// Resolves a group id used as a list cursor into its
    /// `(last_seen_at, id)` ordering key, within the application.
    pub async fn list_cursor<'e, E>(
        executor: E,
        group_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT last_seen_at,id FROM runtime_event_groups WHERE id=$1 AND organization_id=$2 AND project_id=$3 AND application_id=$4")
            .bind(group_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of an application's groups, most recently seen first, under
    /// the list filters, after the cursor's `(last_seen_at, id)` when one is
    /// given. Selects the columns of the runtime groups API's group summary.
    #[allow(clippy::too_many_arguments)]
    pub async fn summary_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        event_kind: Option<String>,
        status: Option<String>,
        namespace: Option<String>,
        workload_kind: Option<String>,
        workload_name: Option<String>,
        since: Option<DateTime<Utc>>,
        first_seen_from: Option<DateTime<Utc>>,
        first_seen_to: Option<DateTime<Utc>>,
        last_seen_to: Option<DateTime<Utc>>,
        release_id: Option<Uuid>,
        cursor_last_seen_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,project_id,application_id,cluster_id,namespace,workload_kind,workload_name,fingerprint_version,event_kind,semantic_summary,status,first_seen_at,first_seen_event_id,last_seen_at,occurrence_count,representative_event_id,status_changed_at,status_changed_by_user_id AS status_changed_by FROM runtime_event_groups g WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND ($4::text IS NULL OR event_kind=$4) AND ($5::text IS NULL OR status=$5) AND ($6::text IS NULL OR namespace=$6) AND ($7::text IS NULL OR workload_kind=$7) AND ($8::text IS NULL OR workload_name=$8) AND ($9::timestamptz IS NULL OR last_seen_at >= $9) AND ($10::timestamptz IS NULL OR first_seen_at >= $10) AND ($11::timestamptz IS NULL OR first_seen_at <= $11) AND ($12::timestamptz IS NULL OR last_seen_at <= $12) AND ($13::uuid IS NULL OR EXISTS (SELECT 1 FROM runtime_event_group_releases gr WHERE gr.group_id=g.id AND gr.release_id=$13)) AND ($14::timestamptz IS NULL OR (last_seen_at,id) < ($14,$15)) ORDER BY last_seen_at DESC,id DESC LIMIT $16")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(event_kind)
            .bind(status)
            .bind(namespace)
            .bind(workload_kind)
            .bind(workload_name)
            .bind(since)
            .bind(first_seen_from)
            .bind(first_seen_to)
            .bind(last_seen_to)
            .bind(release_id)
            .bind(cursor_last_seen_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// One group with the same columns as [`Self::summary_page`].
    pub async fn summary<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,project_id,application_id,cluster_id,namespace,workload_kind,workload_name,fingerprint_version,event_kind,semantic_summary,status,first_seen_at,first_seen_event_id,last_seen_at,occurrence_count,representative_event_id,status_changed_at,status_changed_by_user_id AS status_changed_by FROM runtime_event_groups WHERE organization_id=$1 AND id=$2")
            .bind(organization_id)
            .bind(group_id)
            .fetch_optional(executor)
            .await
    }

    /// Resolves an event id used as an occurrence cursor into its
    /// `(received_at, observed_at, id)` ordering key, within the group.
    pub async fn occurrence_cursor<'e, E>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, DateTime<Utc>, Uuid)>("SELECT e.received_at,e.observed_at,e.id FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.organization_id=$1 AND m.group_id=$2 AND e.id=$3")
            .bind(organization_id)
            .bind(group_id)
            .bind(event_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of the raw events grouped into a group, newest first, after
    /// the cursor when one is given.
    pub async fn occurrence_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
        cursor_received_at: Option<DateTime<Utc>>,
        cursor_observed_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.observed_at,e.received_at,e.node_name,e.namespace,e.pod_name,e.container_name,e.process_command,CASE WHEN g.event_kind='container.restart_loop' THEN g.event_kind ELSE e.event_kind END event_kind,CASE WHEN g.event_kind='container.restart_loop' THEN jsonb_build_object('type','ContainerRestartLoop','data',g.semantic_summary) ELSE e.payload END payload,COALESCE((SELECT jsonb_build_object('retention_incomplete',o.retention_incomplete,'status',o.status,'candidate_count',o.candidate_count,'tolerance_seconds',o.tolerance_seconds,'related_event_ids',COALESCE((SELECT jsonb_agg(c.kernel_event_id) FROM runtime_event_correlations c WHERE c.lifecycle_event_id=e.id),'[]'::jsonb)) FROM runtime_event_correlation_outcomes o WHERE o.event_id=e.id),jsonb_build_object('status','absent','candidate_count',0,'related_event_ids','[]'::jsonb)) correlation,e.release_id,r.version release_version,CASE WHEN r.id IS NULL THEN 'Unattributed' ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name FROM runtime_event_group_memberships m JOIN runtime_event_groups g ON g.id=m.group_id AND g.organization_id=m.organization_id JOIN runtime_events e ON e.id=m.event_id AND e.organization_id=m.organization_id LEFT JOIN releases r ON r.id=e.release_id LEFT JOIN applications a ON a.id=r.application_id WHERE m.organization_id=$1 AND m.group_id=$2 AND ($3::timestamptz IS NULL OR (e.received_at,e.observed_at,e.id)<($3,$4,$5)) ORDER BY e.received_at DESC,e.observed_at DESC,e.id DESC LIMIT $6")
            .bind(organization_id)
            .bind(group_id)
            .bind(cursor_received_at)
            .bind(cursor_observed_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// Moves a group to `status` and records who did it, provided its current
    /// status is one of `allowed`; returns the updated summary, or `None`
    /// when the transition is not allowed from the current status. Setting
    /// the status it already has keeps the original change time.
    pub async fn set_status<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
        status: &str,
        actor_user_id: Uuid,
        allowed: &[&str],
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("UPDATE runtime_event_groups SET status=$3,status_changed_at=CASE WHEN status=$3 THEN status_changed_at ELSE now() END,status_changed_by_user_id=CASE WHEN status=$3 THEN status_changed_by_user_id ELSE $4 END,status_changed_by_kind=CASE WHEN status=$3 THEN status_changed_by_kind ELSE 'user' END,updated_at=CASE WHEN status=$3 THEN updated_at ELSE now() END WHERE organization_id=$1 AND id=$2 AND (status=$3 OR status=ANY($5)) RETURNING id,project_id,application_id,cluster_id,namespace,workload_kind,workload_name,fingerprint_version,event_kind,semantic_summary,status,first_seen_at,first_seen_event_id,last_seen_at,occurrence_count,representative_event_id,status_changed_at,status_changed_by_user_id AS status_changed_by")
            .bind(organization_id)
            .bind(group_id)
            .bind(status)
            .bind(actor_user_id)
            .bind(allowed)
            .fetch_optional(executor)
            .await
    }

    /// The group's current status.
    pub async fn status<'e, E>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM runtime_event_groups WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization_id)
        .bind(group_id)
        .fetch_optional(executor)
        .await
    }

    /// The notification state of a group: whether its first sighting has been
    /// delivered, and the outcome of its deliveries.
    pub async fn notification_summary<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT CASE WHEN o.completion_reason='expected' THEN 'policy_expected' WHEN o.completion_reason='active_suppression' THEN 'temporary_policy_suppressed' WHEN o.completion_reason='backfill_suppressed' OR o.source='backfill' AND count(d.id) FILTER(WHERE d.status<>'suppressed')=0 THEN 'backfill_suppressed' WHEN count(d.id)=0 AND o.processed_at IS NOT NULL THEN 'not_configured' WHEN count(d.id) FILTER (WHERE d.status IN ('pending','in_flight'))>0 THEN CASE WHEN count(d.id) FILTER (WHERE d.status='in_flight')>0 THEN 'delivering' ELSE 'pending' END WHEN count(d.id) FILTER (WHERE d.status='succeeded')>0 THEN 'delivered' WHEN count(d.id) FILTER (WHERE d.status IN ('failed','cancelled','suppressed'))>0 THEN 'terminally_failed' ELSE 'pending' END state,count(d.id)::bigint delivery_count,count(d.id) FILTER (WHERE d.status='succeeded')::bigint succeeded_count,count(d.id) FILTER (WHERE d.status IN ('failed','cancelled','suppressed'))::bigint failed_count FROM outbox_messages o LEFT JOIN notification_deliveries d ON d.outbox_message_id=o.id WHERE o.organization_id=$1 AND o.aggregate_id=$2 AND o.topic='runtime_group.first_seen' GROUP BY o.id,o.source,o.processed_at,o.completion_reason")
            .bind(organization_id)
            .bind(group_id)
            .fetch_optional(executor)
            .await
    }

    /// Evidence correlated with the group's events — the kernel records and
    /// lifecycle events linked to them — up to `limit`.
    pub async fn related_evidence<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.observed_at,e.received_at,e.event_kind,COALESCE(e.payload#>>'{data,source}','unknown') source,e.payload FROM runtime_restart_loop_projections p JOIN runtime_restart_projection_memberships m ON m.organization_id=p.organization_id AND m.project_id=p.project_id AND m.projection_version=p.projection_version JOIN runtime_events e ON e.id=m.event_id AND e.organization_id=p.organization_id AND e.project_id=p.project_id AND e.application_id=p.application_id AND e.cluster_id=p.cluster_id AND e.pod_uid=p.pod_uid AND e.container_name=p.container_name AND e.container_id=p.runtime_container_id AND e.observed_at BETWEEN p.window_started_at AND p.window_ended_at WHERE p.organization_id=$1 AND p.group_id=$2 ORDER BY e.observed_at,e.received_at,e.id LIMIT $3")
            .bind(organization_id)
            .bind(group_id)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Returns the organization and project owning the group, or `None` when
    /// no such group exists.
    ///
    /// Like [`crate::repository::ProjectRepository::organization_of`], the
    /// lookup itself is unauthenticated: the caller needs the tenant path in
    /// order to authorize against it, and maps `None` onto `404`.
    pub async fn tenant_of<'e, E>(
        executor: E,
        group_id: Uuid,
    ) -> Result<Option<(Uuid, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT organization_id, project_id
            FROM runtime_event_groups
            WHERE id = $1
            "#,
        )
        .bind(group_id)
        .fetch_optional(executor)
        .await
    }

    /// Inserts a new group, returning its id, or `None` when one already
    /// exists for the key.
    ///
    /// The row starts at one occurrence with `first_seen_at` and `last_seen_at`
    /// both at the observation, and the same event as both representative and
    /// first-seen. A `None` result means another writer won the race; pair this
    /// with [`Self::lock_existing`] to obtain the winner's id.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_if_absent<'e, E>(
        executor: E,
        candidate_id: Uuid,
        key: GroupKey<'_>,
        event_kind: &str,
        semantic_summary: &Value,
        observed_at: DateTime<Utc>,
        event_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            INSERT INTO runtime_event_groups (
                id, organization_id, project_id, cluster_id, application_id,
                namespace, workload_kind, workload_name,
                fingerprint_version, fingerprint_digest,
                event_kind, semantic_summary,
                first_seen_at, last_seen_at, occurrence_count,
                representative_event_id, first_seen_event_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,1,$14,$14)
            ON CONFLICT (organization_id, project_id, application_id, cluster_id,
                         namespace, workload_kind, workload_name,
                         fingerprint_version, fingerprint_digest)
            DO NOTHING
            RETURNING id
            "#,
        )
        .bind(candidate_id)
        .bind(key.organization_id)
        .bind(key.project_id)
        .bind(key.cluster_id)
        .bind(key.application_id)
        .bind(key.namespace)
        .bind(key.workload_kind)
        .bind(key.workload_name)
        .bind(key.fingerprint_version)
        .bind(key.fingerprint_digest)
        .bind(event_kind)
        .bind(semantic_summary)
        .bind(observed_at)
        .bind(event_id)
        .fetch_optional(executor)
        .await
    }

    /// Locks the existing group for the key and returns its id.
    ///
    /// `FOR UPDATE` serializes concurrent writers against the same group, so
    /// the occurrence bookkeeping that follows cannot interleave. This requires
    /// a transaction; pass `&mut *tx`.
    pub async fn lock_existing<'e, E>(executor: E, key: GroupKey<'_>) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT id FROM runtime_event_groups
            WHERE organization_id = $1
              AND project_id = $2
              AND application_id = $3
              AND cluster_id = $4
              AND namespace = $5
              AND workload_kind = $6
              AND workload_name = $7
              AND fingerprint_version = $8
              AND fingerprint_digest = $9
            FOR UPDATE
            "#,
        )
        .bind(key.organization_id)
        .bind(key.project_id)
        .bind(key.application_id)
        .bind(key.cluster_id)
        .bind(key.namespace)
        .bind(key.workload_kind)
        .bind(key.workload_name)
        .bind(key.fingerprint_version)
        .bind(key.fingerprint_digest)
        .fetch_one(executor)
        .await
    }

    /// Folds one further observation into an existing group.
    ///
    /// The `occurrence_count = 0` branches are not defensive padding, and the
    /// state they guard is narrower than "retention ran". `recount_groups` in
    /// [`crate::runtime_retention::worker`] sums raw events and history
    /// snapshots together, so compacting a group's raw events into a snapshot
    /// leaves the count intact — the snapshot carries it. The count reaches
    /// zero only once the snapshots have expired in turn, at which point the
    /// group has no surviving record of any kind, raw or summarised, and
    /// survives deletion only because a policy revision, a suppression or an
    /// unprocessed outbox message still points at it.
    ///
    /// Such a group can still be observed again. Extending its old window with
    /// `LEAST`/`GREATEST` would report a first sighting that nothing at all
    /// substantiates, so a group at zero restarts its window at the new
    /// observation instead.
    pub async fn record_occurrence<'e, E>(
        executor: E,
        group_id: Uuid,
        observed_at: DateTime<Utc>,
        event_id: Uuid,
    ) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE runtime_event_groups
            SET first_seen_event_id = CASE
                    WHEN ($2,$3) < (first_seen_at, first_seen_event_id) THEN $3
                    ELSE first_seen_event_id END,
                first_seen_at = CASE
                    WHEN occurrence_count = 0 THEN $2 ELSE LEAST(first_seen_at, $2) END,
                last_seen_at = CASE
                    WHEN occurrence_count = 0 THEN $2 ELSE GREATEST(last_seen_at, $2) END,
                representative_event_id = COALESCE(representative_event_id, $3),
                occurrence_count = occurrence_count + 1,
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(group_id)
        .bind(observed_at)
        .bind(event_id)
        .execute(executor)
        .await?;
        Ok(())
    }

    /// Creates or refreshes a group derived from a projection rather than from
    /// a fingerprinted event, returning its id.
    ///
    /// Unlike [`Self::insert_if_absent`] this always returns a row, because a
    /// derived group carries a recomputed summary that must overwrite the
    /// stored one on every pass. A caller tells creation from refresh by
    /// comparing the result against the candidate id it supplied.
    ///
    /// The window maintenance here is deliberately weaker than
    /// [`Self::record_occurrence`]: it advances `last_seen_at` but does not
    /// restart the window of a group retention has emptied. Both writers reach
    /// the same table, so that difference is a real inconsistency rather than a
    /// property of derived groups; it is preserved as-is because changing it
    /// moves user-visible timestamps.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_derived<'e, E>(
        executor: E,
        candidate_id: Uuid,
        key: GroupKey<'_>,
        event_kind: &str,
        semantic_summary: &Value,
        observed_at: DateTime<Utc>,
        event_id: Uuid,
    ) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            INSERT INTO runtime_event_groups (
                id, organization_id, project_id, cluster_id, application_id,
                namespace, workload_kind, workload_name,
                fingerprint_version, fingerprint_digest,
                event_kind, semantic_summary,
                first_seen_at, last_seen_at, occurrence_count,
                representative_event_id, first_seen_event_id)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,1,$14,$14)
            ON CONFLICT (organization_id, project_id, application_id, cluster_id,
                         namespace, workload_kind, workload_name,
                         fingerprint_version, fingerprint_digest)
            DO UPDATE SET
                semantic_summary = EXCLUDED.semantic_summary,
                last_seen_at = GREATEST(runtime_event_groups.last_seen_at,
                                        EXCLUDED.last_seen_at),
                representative_event_id = EXCLUDED.representative_event_id,
                updated_at = now()
            RETURNING id
            "#,
        )
        .bind(candidate_id)
        .bind(key.organization_id)
        .bind(key.project_id)
        .bind(key.cluster_id)
        .bind(key.application_id)
        .bind(key.namespace)
        .bind(key.workload_kind)
        .bind(key.workload_name)
        .bind(key.fingerprint_version)
        .bind(key.fingerprint_digest)
        .bind(event_kind)
        .bind(semantic_summary)
        .bind(observed_at)
        .bind(event_id)
        .fetch_one(executor)
        .await
    }

    /// Adds one to a group's occurrence count without touching its window.
    ///
    /// This is the derived-projection counterpart to
    /// [`Self::record_occurrence`], used where the caller has already written
    /// the window through [`Self::upsert_derived`].
    pub async fn increment_occurrence<'e, E>(executor: E, group_id: Uuid) -> Result<(), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            r#"
            UPDATE runtime_event_groups
            SET occurrence_count = occurrence_count + 1
            WHERE id = $1
            "#,
        )
        .bind(group_id)
        .execute(executor)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{EventGroupRepository, GroupKey};
    use chrono::{DateTime, TimeZone, Utc};
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use uuid::Uuid;

    const DIGEST: [u8; 32] = [7u8; 32];

    struct Fixture {
        organization: Uuid,
        project: Uuid,
        application: Uuid,
        cluster: Uuid,
        agent: Uuid,
    }

    impl Fixture {
        fn key(&self) -> GroupKey<'_> {
            GroupKey {
                organization_id: self.organization,
                project_id: self.project,
                application_id: self.application,
                cluster_id: self.cluster,
                namespace: "default",
                workload_kind: "Deployment",
                workload_name: "api",
                fingerprint_version: 1,
                fingerprint_digest: &DIGEST,
            }
        }
    }

    fn at(minute: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, minute, 0).unwrap()
    }

    async fn seed(pool: &PgPool) -> Fixture {
        let fixture = Fixture {
            organization: Uuid::new_v4(),
            project: Uuid::new_v4(),
            application: Uuid::new_v4(),
            cluster: Uuid::new_v4(),
            agent: Uuid::new_v4(),
        };
        sqlx::query("INSERT INTO organizations(id,slug,name) VALUES($1,$2,'Repository')")
            .bind(fixture.organization)
            .bind(fixture.organization.to_string())
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,'p','P')")
            .bind(fixture.project)
            .bind(fixture.organization)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES($1,$2,$3,'a','A')",
        )
        .bind(fixture.application)
        .bind(fixture.organization)
        .bind(fixture.project)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO clusters(id,organization_id,external_id,name) VALUES($1,$2,'c','C')",
        )
        .bind(fixture.cluster)
        .bind(fixture.organization)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node','0.0.0')",
        )
        .bind(fixture.agent)
        .bind(fixture.organization)
        .bind(fixture.cluster)
        .execute(pool)
        .await
        .unwrap();
        fixture
    }

    /// `representative_event_id` and `first_seen_event_id` are foreign keys, so
    /// every group needs a real event behind it.
    async fn seed_event(pool: &PgPool, fixture: &Fixture, observed_at: DateTime<Utc>) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO runtime_events(id,event_id,organization_id,project_id,cluster_id,application_id,agent_id,observed_at,node_name,namespace,pod_uid,pod_name,container_id,container_name,workload_uid,workload_kind,workload_name,cgroup_id,pid,tgid,process_command,event_kind,event_schema_version,payload) \
             VALUES($1,$1,$2,$3,$4,$5,$6,$7,'node','default','pod-uid','pod','container','container','workload-uid','Deployment','api',1,1,1,'cmd','process.exec',1,'{}'::jsonb)",
        )
        .bind(id)
        .bind(fixture.organization)
        .bind(fixture.project)
        .bind(fixture.cluster)
        .bind(fixture.application)
        .bind(fixture.agent)
        .bind(observed_at)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn window(pool: &PgPool, group: Uuid) -> (DateTime<Utc>, DateTime<Utc>, i64, Value) {
        sqlx::query_as(
            "SELECT first_seen_at,last_seen_at,occurrence_count,semantic_summary FROM runtime_event_groups WHERE id=$1",
        )
        .bind(group)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn resolves_the_owning_tenant(pool: PgPool) {
        let fixture = seed(&pool).await;
        let event = seed_event(&pool, &fixture, at(0)).await;
        let group = Uuid::new_v4();
        EventGroupRepository::insert_if_absent(
            &pool,
            group,
            fixture.key(),
            "process.exec",
            &json!({}),
            at(0),
            event,
        )
        .await
        .unwrap();

        assert_eq!(
            EventGroupRepository::tenant_of(&pool, group).await.unwrap(),
            Some((fixture.organization, fixture.project))
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn reports_an_unknown_group_as_absent(pool: PgPool) {
        assert_eq!(
            EventGroupRepository::tenant_of(&pool, Uuid::new_v4())
                .await
                .unwrap(),
            None
        );
    }

    /// The second insert for one key must not create a second group: the
    /// conflict target is what makes grouping idempotent under concurrent
    /// ingestion.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn inserts_once_per_key_and_locks_the_winner(pool: PgPool) {
        let fixture = seed(&pool).await;
        let first_event = seed_event(&pool, &fixture, at(0)).await;
        let winner = Uuid::new_v4();
        assert_eq!(
            EventGroupRepository::insert_if_absent(
                &pool,
                winner,
                fixture.key(),
                "process.exec",
                &json!({}),
                at(0),
                first_event,
            )
            .await
            .unwrap(),
            Some(winner)
        );

        let second_event = seed_event(&pool, &fixture, at(1)).await;
        assert_eq!(
            EventGroupRepository::insert_if_absent(
                &pool,
                Uuid::new_v4(),
                fixture.key(),
                "process.exec",
                &json!({}),
                at(1),
                second_event,
            )
            .await
            .unwrap(),
            None,
            "a repeated key must not create a second group"
        );

        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            EventGroupRepository::lock_existing(&mut *tx, fixture.key())
                .await
                .unwrap(),
            winner,
            "the loser of the race must find the winner's group"
        );
        tx.commit().await.unwrap();
    }

    /// A group that differs in any one key column is a different group. The
    /// digest is the column most likely to be dropped from a hand-written
    /// conflict target, so it is the one exercised here.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn separates_groups_differing_only_by_digest(pool: PgPool) {
        let fixture = seed(&pool).await;
        let event = seed_event(&pool, &fixture, at(0)).await;
        let first = Uuid::new_v4();
        EventGroupRepository::insert_if_absent(
            &pool,
            first,
            fixture.key(),
            "process.exec",
            &json!({}),
            at(0),
            event,
        )
        .await
        .unwrap();

        let other_digest = [9u8; 32];
        let mut key = fixture.key();
        key.fingerprint_digest = &other_digest;
        let second = Uuid::new_v4();
        assert_eq!(
            EventGroupRepository::insert_if_absent(
                &pool,
                second,
                key,
                "process.exec",
                &json!({}),
                at(1),
                event,
            )
            .await
            .unwrap(),
            Some(second)
        );
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn folds_a_later_observation_into_the_window(pool: PgPool) {
        let fixture = seed(&pool).await;
        let first_event = seed_event(&pool, &fixture, at(10)).await;
        let group = Uuid::new_v4();
        EventGroupRepository::insert_if_absent(
            &pool,
            group,
            fixture.key(),
            "process.exec",
            &json!({}),
            at(10),
            first_event,
        )
        .await
        .unwrap();

        let later = seed_event(&pool, &fixture, at(20)).await;
        EventGroupRepository::record_occurrence(&pool, group, at(20), later)
            .await
            .unwrap();
        let (first_seen, last_seen, count, _) = window(&pool, group).await;
        assert_eq!((first_seen, last_seen, count), (at(10), at(20), 2));

        // An out-of-order arrival widens the window backwards rather than
        // replacing it.
        let earlier = seed_event(&pool, &fixture, at(5)).await;
        EventGroupRepository::record_occurrence(&pool, group, at(5), earlier)
            .await
            .unwrap();
        let (first_seen, last_seen, count, _) = window(&pool, group).await;
        assert_eq!((first_seen, last_seen, count), (at(5), at(20), 3));
    }

    /// A group whose raw events and history snapshots have both expired sits at
    /// zero without being deleted, because something outside retention's reach
    /// still references it. The next observation must restart the window rather
    /// than extend one whose evidence is wholly gone — otherwise the group
    /// reports a first sighting that nothing can substantiate.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn restarts_the_window_of_a_group_retention_emptied(pool: PgPool) {
        let fixture = seed(&pool).await;
        let old_event = seed_event(&pool, &fixture, at(0)).await;
        let group = Uuid::new_v4();
        EventGroupRepository::insert_if_absent(
            &pool,
            group,
            fixture.key(),
            "process.exec",
            &json!({}),
            at(0),
            old_event,
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE runtime_event_groups SET occurrence_count=0, representative_event_id=NULL, first_seen_event_id=NULL WHERE id=$1",
        )
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();

        let fresh = seed_event(&pool, &fixture, at(30)).await;
        EventGroupRepository::record_occurrence(&pool, group, at(30), fresh)
            .await
            .unwrap();

        let (first_seen, last_seen, count, _) = window(&pool, group).await;
        assert_eq!(
            (first_seen, last_seen, count),
            (at(30), at(30), 1),
            "an emptied group restarts its window at the new observation"
        );
        let representative: Option<Uuid> = sqlx::query_scalar(
            "SELECT representative_event_id FROM runtime_event_groups WHERE id=$1",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            representative,
            Some(fresh),
            "an emptied group adopts the new event as representative"
        );
    }

    /// The derived path always returns a row, and refreshes the stored summary
    /// on every pass. The caller distinguishes creation from refresh by
    /// comparing against the candidate it supplied.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn upserts_a_derived_group_and_refreshes_its_summary(pool: PgPool) {
        let fixture = seed(&pool).await;
        let first_event = seed_event(&pool, &fixture, at(0)).await;
        let created = Uuid::new_v4();
        assert_eq!(
            EventGroupRepository::upsert_derived(
                &pool,
                created,
                fixture.key(),
                "container.restart_loop",
                &json!({"observed_restart_count": 3}),
                at(0),
                first_event,
            )
            .await
            .unwrap(),
            created
        );

        let later_event = seed_event(&pool, &fixture, at(15)).await;
        let candidate = Uuid::new_v4();
        let refreshed = EventGroupRepository::upsert_derived(
            &pool,
            candidate,
            fixture.key(),
            "container.restart_loop",
            &json!({"observed_restart_count": 9}),
            at(15),
            later_event,
        )
        .await
        .unwrap();
        assert_eq!(refreshed, created, "a refresh returns the existing group");
        assert_ne!(
            refreshed, candidate,
            "the candidate id marks creation, so it must not come back from a refresh"
        );

        let (first_seen, last_seen, count, summary) = window(&pool, created).await;
        assert_eq!((first_seen, last_seen), (at(0), at(15)));
        assert_eq!(
            count, 1,
            "the upsert leaves the count alone; the caller increments it"
        );
        assert_eq!(summary, json!({"observed_restart_count": 9}));
    }

    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn increments_without_touching_the_window(pool: PgPool) {
        let fixture = seed(&pool).await;
        let event = seed_event(&pool, &fixture, at(0)).await;
        let group = Uuid::new_v4();
        EventGroupRepository::upsert_derived(
            &pool,
            group,
            fixture.key(),
            "container.restart_loop",
            &json!({}),
            at(0),
            event,
        )
        .await
        .unwrap();

        EventGroupRepository::increment_occurrence(&pool, group)
            .await
            .unwrap();

        let (first_seen, last_seen, count, _) = window(&pool, group).await;
        assert_eq!((first_seen, last_seen, count), (at(0), at(0), 2));
    }
}

#[cfg(test)]
mod api_statement_tests {
    use super::EventGroupRepository;
    use crate::repository::EventRepository;
    use crate::repository::test_support::{
        correlated_termination, exec, exec_in_release, group_ids, ingest, manual_release, restarts,
        tenant, user,
    };
    use chrono::{DateTime, Duration, Utc};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    #[derive(Debug, FromRow)]
    struct Summary {
        id: Uuid,
        status: String,
        event_kind: String,
        last_seen_at: DateTime<Utc>,
        occurrence_count: i64,
        status_changed_by: Option<Uuid>,
    }

    #[derive(Debug, FromRow)]
    struct Occurrence {
        id: Uuid,
        received_at: DateTime<Utc>,
        observed_at: DateTime<Utc>,
    }

    #[derive(Debug, FromRow)]
    struct Labels {
        group_id: Uuid,
        user_labels: serde_json::Value,
    }

    #[derive(Debug, FromRow)]
    struct PolicyState {
        group_id: Uuid,
        policy_evaluation: serde_json::Value,
        actionable: bool,
    }

    #[derive(Debug, FromRow)]
    struct Notification {
        state: String,
        delivery_count: i64,
    }

    #[derive(Debug, FromRow)]
    struct Evidence {
        id: Uuid,
        event_kind: String,
    }

    #[allow(clippy::too_many_arguments)]
    async fn page(
        pool: &PgPool,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        event_kind: Option<String>,
        release_id: Option<Uuid>,
        cursor: Option<(DateTime<Utc>, Uuid)>,
        fetch_limit: i64,
    ) -> Vec<Summary> {
        EventGroupRepository::summary_page(
            pool,
            organization_id,
            project_id,
            application_id,
            event_kind,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            release_id,
            cursor.map(|c| c.0),
            cursor.map(|c| c.1),
            fetch_limit,
        )
        .await
        .unwrap()
    }

    /// The list pages most recently seen first, honours its filters, resumes
    /// after a cursor, and never crosses tenants.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_group_list_pages_filters_and_scopes(pool: PgPool) {
        let own = tenant(&pool, "groups-list").await;
        let other = tenant(&pool, "groups-list-other").await;
        let now = Utc::now();
        let release = manual_release(&pool, &own, "v1", now).await;
        ingest(
            &pool,
            &own,
            &[
                exec(&own, "/bin/old", now - Duration::minutes(3)),
                exec(&own, "/bin/mid", now - Duration::minutes(2)),
                exec_in_release(&own, "/bin/new", "v1", now - Duration::minutes(1)),
            ],
        )
        .await;
        ingest(&pool, &other, &[exec(&other, "/bin/elsewhere", now)]).await;

        let all = page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            None,
            None,
            None,
            10,
        )
        .await;
        assert_eq!(all.len(), 3);
        assert!(
            all.windows(2)
                .all(|w| w[0].last_seen_at >= w[1].last_seen_at)
        );

        let released = page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            None,
            Some(release),
            None,
            10,
        )
        .await;
        assert_eq!(
            released.len(),
            1,
            "the release filter keeps groups seen in it"
        );

        let none = page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            Some("network.connect".into()),
            None,
            None,
            10,
        )
        .await;
        assert!(
            none.is_empty(),
            "the event kind filter excludes other kinds"
        );

        let (at, id) = EventGroupRepository::list_cursor(
            &pool,
            all[0].id,
            own.organization_id,
            own.project_id,
            own.application_id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(id, all[0].id);
        let rest = page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            None,
            None,
            Some((at, id)),
            10,
        )
        .await;
        assert_eq!(
            rest.iter().map(|s| s.id).collect::<Vec<_>>(),
            all[1..].iter().map(|s| s.id).collect::<Vec<_>>()
        );

        assert!(
            EventGroupRepository::list_cursor(
                &pool,
                all[0].id,
                other.organization_id,
                other.project_id,
                other.application_id
            )
            .await
            .unwrap()
            .is_none()
        );
        let summary: Summary = EventGroupRepository::summary(&pool, own.organization_id, all[0].id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                summary.id,
                summary.event_kind.as_str(),
                summary.occurrence_count
            ),
            (all[0].id, "process.exec", all[0].occurrence_count)
        );
        assert!(
            EventGroupRepository::summary::<_, Summary>(&pool, other.organization_id, all[0].id)
                .await
                .unwrap()
                .is_none(),
            "another organization cannot read the group"
        );
    }

    /// A transition happens only from an allowed status; setting the status a
    /// group already has keeps who changed it and when.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn status_changes_only_from_an_allowed_status(pool: PgPool) {
        let own = tenant(&pool, "groups-status").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let group = group_ids(&pool, &own).await[0];
        let actor = user(&pool).await;
        let other_actor = user(&pool).await;

        assert_eq!(
            EventGroupRepository::status(&pool, own.organization_id, group)
                .await
                .unwrap()
                .as_deref(),
            Some("open")
        );
        assert!(
            EventGroupRepository::set_status::<_, Summary>(
                &pool,
                own.organization_id,
                group,
                "resolved",
                actor,
                &["acknowledged"]
            )
            .await
            .unwrap()
            .is_none(),
            "open is not an allowed source for this transition"
        );

        let acknowledged: Summary = EventGroupRepository::set_status(
            &pool,
            own.organization_id,
            group,
            "acknowledged",
            actor,
            &["open"],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (acknowledged.status.as_str(), acknowledged.status_changed_by),
            ("acknowledged", Some(actor))
        );

        let repeated: Summary = EventGroupRepository::set_status(
            &pool,
            own.organization_id,
            group,
            "acknowledged",
            other_actor,
            &["open"],
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            repeated.status_changed_by,
            Some(actor),
            "re-setting the same status keeps the original actor"
        );
    }

    /// Occurrences page newest received first and resolve cursors only within
    /// their group.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn occurrences_page_newest_first_within_their_group(pool: PgPool) {
        let own = tenant(&pool, "groups-occurrences").await;
        let now = Utc::now();
        for minute in 0..3 {
            ingest(
                &pool,
                &own,
                &[exec(&own, "/bin/a", now - Duration::minutes(minute))],
            )
            .await;
        }
        let group = group_ids(&pool, &own).await[0];

        let all: Vec<Occurrence> = EventGroupRepository::occurrence_page(
            &pool,
            own.organization_id,
            group,
            None,
            None,
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(all.len(), 3);
        assert!(
            all.windows(2)
                .all(|w| (w[0].received_at, w[0].observed_at, w[0].id)
                    > (w[1].received_at, w[1].observed_at, w[1].id))
        );

        let (received, observed, id) =
            EventGroupRepository::occurrence_cursor(&pool, own.organization_id, group, all[0].id)
                .await
                .unwrap()
                .unwrap();
        let rest: Vec<Occurrence> = EventGroupRepository::occurrence_page(
            &pool,
            own.organization_id,
            group,
            Some(received),
            Some(observed),
            Some(id),
            10,
        )
        .await
        .unwrap();
        assert_eq!(rest.len(), 2);
        assert!(
            EventGroupRepository::occurrence_cursor(
                &pool,
                own.organization_id,
                Uuid::new_v4(),
                all[0].id
            )
            .await
            .unwrap()
            .is_none(),
            "an event resolves only within its own group"
        );

        let single: Occurrence = EventRepository::occurrence(&pool, own.organization_id, all[1].id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(single.id, all[1].id);
        assert!(
            EventRepository::occurrence::<_, Occurrence>(&pool, Uuid::new_v4(), all[1].id)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Labels attach to a group through its inventory item; the policy state
    /// reads pending until a current evaluation exists.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn labels_and_policy_state_attach_to_groups(pool: PgPool) {
        let own = tenant(&pool, "groups-attachments").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let group = group_ids(&pool, &own).await[0];
        let actor = user(&pool).await;
        sqlx::query(
            "INSERT INTO runtime_behavior_user_labels(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,display_name,created_by_user_id,updated_by_user_id) \
             SELECT gen_random_uuid(),i.organization_id,i.project_id,i.application_id,i.inventory_kind,i.identity_version,i.identity_digest,'Shell',$2,$2 \
             FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id WHERE gl.group_id=$1",
        )
        .bind(group)
        .bind(actor)
        .execute(&pool)
        .await
        .unwrap();

        let labels: Vec<Labels> =
            EventGroupRepository::user_labels(&pool, own.organization_id, vec![group])
                .await
                .unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].group_id, group);
        assert_eq!(labels[0].user_labels[0]["display_name"], "Shell");
        assert!(
            EventGroupRepository::user_labels::<_, Labels>(&pool, Uuid::new_v4(), vec![group])
                .await
                .unwrap()
                .is_empty()
        );

        let version = crate::policy::POLICY_EVALUATOR_VERSION;
        let states = |evaluator_version: i16| {
            let pool = pool.clone();
            async move {
                EventGroupRepository::policy_states::<_, PolicyState>(
                    &pool,
                    own.organization_id,
                    &[group],
                    evaluator_version,
                )
                .await
                .unwrap()
            }
        };

        // Ingestion evaluates a new group straight away.
        let current = states(version).await;
        assert_eq!(current[0].group_id, group);
        assert_eq!(current[0].policy_evaluation["state"], "current");
        assert_eq!(current[0].policy_evaluation["verdict"], "unclassified");
        assert!(
            current[0].actionable,
            "an unclassified group needs a reaction"
        );

        // An evaluation from another evaluator version is not trusted.
        let stale = states(version + 1).await;
        assert_eq!(stale[0].policy_evaluation["state"], "evaluation_pending");
        assert_eq!(
            stale[0].policy_evaluation["reason_code"],
            "evaluation_pending"
        );
        assert!(stale[0].policy_evaluation["verdict"].is_null());
        assert!(stale[0].actionable);

        sqlx::query("DELETE FROM runtime_group_policy_evaluations WHERE group_id=$1")
            .bind(group)
            .execute(&pool)
            .await
            .unwrap();
        let missing = states(version).await;
        assert_eq!(missing[0].policy_evaluation["state"], "evaluation_pending");
        assert!(missing[0].actionable);

        sqlx::query(
            "INSERT INTO runtime_group_policy_evaluations(organization_id,project_id,application_id,group_id,policy_state_version,evaluator_version,verdict,reason_code,explanation) \
             VALUES($1,$2,$3,$4,0,$5,'expected','inside_placement','{}'::jsonb)",
        )
        .bind(own.organization_id)
        .bind(own.project_id)
        .bind(own.application_id)
        .bind(group)
        .bind(version)
        .execute(&pool)
        .await
        .unwrap();
        let expected = states(version).await;
        assert_eq!(expected[0].policy_evaluation["state"], "current");
        assert_eq!(expected[0].policy_evaluation["verdict"], "expected");
        assert_eq!(
            expected[0].policy_evaluation["reason_code"],
            "inside_placement"
        );
        assert!(
            !expected[0].actionable,
            "an expected verdict is not actionable"
        );
        assert!(
            states(version).await.len() == 1
                && EventGroupRepository::policy_states::<_, PolicyState>(
                    &pool,
                    Uuid::new_v4(),
                    &[group],
                    version,
                )
                .await
                .unwrap()
                .is_empty(),
            "another organization sees nothing"
        );
    }

    /// A new group's first-seen notification is pending until the outbox
    /// processes it, and with no destinations it then reads not configured.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_notification_summary_follows_the_outbox(pool: PgPool) {
        let own = tenant(&pool, "groups-notification").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let group = group_ids(&pool, &own).await[0];

        let pending: Notification =
            EventGroupRepository::notification_summary(&pool, own.organization_id, group)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            (pending.state.as_str(), pending.delivery_count),
            ("pending", 0)
        );

        sqlx::query("UPDATE outbox_messages SET processed_at=now() WHERE aggregate_id=$1")
            .bind(group)
            .execute(&pool)
            .await
            .unwrap();
        let processed: Notification =
            EventGroupRepository::notification_summary(&pool, own.organization_id, group)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(processed.state, "not_configured");
    }

    /// A restart loop's evidence is its restart events; an event's evidence
    /// is what it was correlated with.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn evidence_follows_projections_and_correlations(pool: PgPool) {
        let own = tenant(&pool, "groups-evidence").await;
        let now = Utc::now() - Duration::minutes(10);
        let [kernel, lifecycle] = correlated_termination(&own, now);
        ingest(&pool, &own, &[kernel.clone(), lifecycle.clone()]).await;
        ingest(&pool, &own, &restarts(&own, now, 3)).await;

        let loop_group: Uuid = sqlx::query_scalar(
            "SELECT id FROM runtime_event_groups WHERE organization_id=$1 AND event_kind='container.restart_loop'",
        )
        .bind(own.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let loop_evidence: Vec<Evidence> =
            EventGroupRepository::related_evidence(&pool, own.organization_id, loop_group, 20)
                .await
                .unwrap();
        assert_eq!(loop_evidence.len(), 3);
        assert!(
            loop_evidence
                .iter()
                .all(|e| e.event_kind == "container.restart")
        );
        let limited: Vec<Evidence> =
            EventGroupRepository::related_evidence(&pool, own.organization_id, loop_group, 2)
                .await
                .unwrap();
        assert_eq!(limited.len(), 2, "the limit applies");
        assert!(
            EventGroupRepository::related_evidence::<_, Evidence>(
                &pool,
                Uuid::new_v4(),
                loop_group,
                20
            )
            .await
            .unwrap()
            .is_empty()
        );

        let raw = |event_id: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, Uuid>("SELECT id FROM runtime_events WHERE event_id=$1")
                    .bind(event_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        let kernel_raw = raw(kernel.id).await;
        let lifecycle_raw = raw(lifecycle.id).await;
        let from_kernel: Vec<Evidence> =
            EventRepository::related_evidence(&pool, own.organization_id, kernel_raw, 20)
                .await
                .unwrap();
        assert_eq!(
            from_kernel.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![lifecycle_raw]
        );
        let from_lifecycle: Vec<Evidence> =
            EventRepository::related_evidence(&pool, own.organization_id, lifecycle_raw, 20)
                .await
                .unwrap();
        assert_eq!(
            from_lifecycle.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![kernel_raw],
            "correlation reads both ways"
        );
    }
}
