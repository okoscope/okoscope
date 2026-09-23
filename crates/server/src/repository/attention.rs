//! The reads behind the attention views: what changed between each
//! application's latest two releases, open discoveries, notification
//! delivery problems and resource findings, across the projects a user can
//! see or within one application.
//!
//! Every projection belongs to the attention endpoints, so the reads are
//! generic over the row type and document the columns they select. They are
//! meant to run inside one read-only snapshot; see
//! [`crate::repository::transaction::TransactionRepository`].

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

/// The comparison of each application's latest release with its baseline:
/// the transition predecessor when one was recorded, otherwise the previous
/// deployment. Binds `$1` to the organization and `$2` to the project ids,
/// and ends with the per-application aggregate `agg`.
const CHANGED_CTE: &str = "WITH ranked AS (SELECT r.*,row_number() OVER(PARTITION BY application_id ORDER BY deployed_at DESC,id DESC) rn FROM releases r WHERE organization_id=$1 AND project_id=ANY($2)), pairs AS (SELECT t.organization_id,t.project_id,t.application_id,t.id target_id,t.version target_version,t.deployed_at target_deployed_at,b.id baseline_id,b.version baseline_version,b.deployed_at baseline_deployed_at FROM ranked t JOIN LATERAL (((SELECT r.*,0 priority FROM deployment_episodes te JOIN deployment_episode_predecessors x ON x.episode_id=te.id JOIN deployment_episodes pe ON pe.id=x.predecessor_episode_id JOIN releases r ON r.id=pe.release_id WHERE te.organization_id=t.organization_id AND te.application_id=t.application_id AND te.release_id=t.id ORDER BY te.first_observed_at DESC,te.id DESC,x.observed_at DESC,pe.id DESC LIMIT 1) UNION ALL (SELECT r.*,1 priority FROM releases r WHERE r.organization_id=t.organization_id AND r.application_id=t.application_id AND (r.deployed_at,r.id)<(t.deployed_at,t.id) ORDER BY r.deployed_at DESC,r.id DESC LIMIT 1)) ORDER BY priority LIMIT 1) b ON true WHERE t.rn=1), diff AS (SELECT p.*,ids.group_id,CASE WHEN b.group_id IS NULL AND EXISTS(SELECT 1 FROM releases r JOIN projects pr ON pr.id=r.project_id WHERE r.id=p.baseline_id AND r.deployed_at<pr.runtime_history_expired_before) THEN 'unknown' WHEN b.group_id IS NULL THEN 'new' WHEN t.group_id IS NULL AND (EXISTS(SELECT 1 FROM releases r JOIN projects pr ON pr.id=r.project_id WHERE r.id=p.target_id AND r.deployed_at<pr.runtime_history_expired_before) OR NOT (EXISTS(SELECT 1 FROM runtime_event_group_releases gr WHERE gr.release_id=p.target_id AND gr.occurrence_count>0) OR EXISTS(SELECT 1 FROM runtime_events ev WHERE ev.release_id=p.target_id))) THEN 'unknown' WHEN t.group_id IS NULL THEN 'disappeared' ELSE 'unchanged' END classification,coalesce(t.occurrence_count,0) tc,coalesce(b.occurrence_count,0) bc FROM pairs p JOIN LATERAL (SELECT group_id FROM runtime_event_group_releases WHERE release_id=p.target_id AND occurrence_count>0 UNION SELECT group_id FROM runtime_event_group_releases WHERE release_id=p.baseline_id AND occurrence_count>0) ids ON true LEFT JOIN runtime_event_group_releases t ON t.release_id=p.target_id AND t.group_id=ids.group_id LEFT JOIN runtime_event_group_releases b ON b.release_id=p.baseline_id AND b.group_id=ids.group_id), agg AS (SELECT project_id,application_id,target_id,target_version,target_deployed_at,baseline_id,baseline_version,baseline_deployed_at,count(*) FILTER(WHERE classification='new')::bigint new_count,count(*) FILTER(WHERE classification='disappeared')::bigint disappeared_count,count(*) FILTER(WHERE classification='unchanged')::bigint unchanged_count,count(*)::bigint total_item_count,coalesce(sum(abs(tc-bc)),0)::bigint absolute_occurrence_delta_sum,coalesce(max(abs(tc-bc)),0)::bigint max_absolute_occurrence_delta FROM diff WHERE classification<>'unknown' GROUP BY project_id,application_id,target_id,target_version,target_deployed_at,baseline_id,baseline_version,baseline_deployed_at)";

/// Reads behind the attention views.
#[derive(Clone, Copy, Debug)]
pub struct AttentionRepository;

impl AttentionRepository {
    /// Applications of the projects whose latest release added or dropped
    /// runtime groups against its baseline, most changes first.
    ///
    /// Selects the project and application identity, the target and baseline
    /// release ids, versions, display names and deployment times,
    /// `new_count`, `disappeared_count`, `unchanged_count`,
    /// `total_item_count`, `absolute_occurrence_delta_sum` and
    /// `max_absolute_occurrence_delta`.
    pub async fn changed<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_ids: &[Uuid],
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let sql = format!(
            "{CHANGED_CTE} SELECT a.project_id,p.name project_name,p.slug project_slug,a.application_id,app.name application_name,app.slug application_slug,a.target_id,a.target_version,release_display_name(app.name,rt.source,rt.version,rt.identity_digest,rt.identity_components) target_display_name,a.target_deployed_at,a.baseline_id,a.baseline_version,release_display_name(app.name,rb.source,rb.version,rb.identity_digest,rb.identity_components) baseline_display_name,a.baseline_deployed_at,a.new_count,a.disappeared_count,a.unchanged_count,a.total_item_count,a.absolute_occurrence_delta_sum,a.max_absolute_occurrence_delta FROM agg a JOIN projects p ON p.organization_id=$1 AND p.id=a.project_id JOIN applications app ON app.organization_id=$1 AND app.id=a.application_id JOIN releases rt ON rt.id=a.target_id JOIN releases rb ON rb.id=a.baseline_id WHERE a.new_count+a.disappeared_count>0 ORDER BY a.new_count+a.disappeared_count DESC,a.target_deployed_at DESC,a.application_id LIMIT $3"
        );
        sqlx::query_as(&sql)
            .bind(organization_id)
            .bind(project_ids)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// The latest-release comparison of one application with the columns of
    /// [`Self::changed`], whether or not anything changed. `project_ids`
    /// holds the application's project.
    pub async fn application_changed<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_ids: Vec<Uuid>,
        application_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let sql = format!(
            "{CHANGED_CTE} SELECT a.project_id,p.name project_name,p.slug project_slug,a.application_id,app.name application_name,app.slug application_slug,a.target_id,a.target_version,release_display_name(app.name,rt.source,rt.version,rt.identity_digest,rt.identity_components) target_display_name,a.target_deployed_at,a.baseline_id,a.baseline_version,release_display_name(app.name,rb.source,rb.version,rb.identity_digest,rb.identity_components) baseline_display_name,a.baseline_deployed_at,a.new_count,a.disappeared_count,a.unchanged_count,a.total_item_count,a.absolute_occurrence_delta_sum,a.max_absolute_occurrence_delta FROM agg a JOIN projects p ON p.organization_id=$1 AND p.id=a.project_id JOIN applications app ON app.organization_id=$1 AND app.id=a.application_id JOIN releases rt ON rt.id=a.target_id JOIN releases rb ON rb.id=a.baseline_id WHERE a.application_id=$3"
        );
        sqlx::query_as(&sql)
            .bind(organization_id)
            .bind(project_ids)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }

    /// Organization-wide attention totals over the projects: groups first
    /// seen in `[from, to]`, open and acknowledged groups, changed
    /// applications, failed deliveries in `[from, to]`, open resource
    /// regressions, and the groups by policy state.
    ///
    /// Selects `new_discoveries`, `open_discoveries`,
    /// `acknowledged_discoveries`, `changed_applications`,
    /// `projects_with_notification_problems` (always 0, for the caller to
    /// fill), `failed_notification_deliveries`, `resource_regressions` and
    /// `policy`.
    pub async fn organization_totals<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_ids: &[Uuid],
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as(&format!("{CHANGED_CTE} SELECT (SELECT count(*) FROM runtime_event_groups WHERE occurrence_count>0 AND organization_id=$1 AND project_id=ANY($2) AND first_seen_at BETWEEN $3 AND $4)::bigint new_discoveries,(SELECT count(*) FROM runtime_event_groups WHERE occurrence_count>0 AND organization_id=$1 AND project_id=ANY($2) AND status='open')::bigint open_discoveries,(SELECT count(*) FROM runtime_event_groups WHERE occurrence_count>0 AND organization_id=$1 AND project_id=ANY($2) AND status='acknowledged')::bigint acknowledged_discoveries,(SELECT count(*) FROM agg WHERE new_count+disappeared_count>0)::bigint changed_applications,0::bigint projects_with_notification_problems,(SELECT count(*) FROM notification_deliveries WHERE organization_id=$1 AND project_id=ANY($2) AND status='failed' AND terminal_at BETWEEN $3 AND $4)::bigint failed_notification_deliveries,(SELECT count(*) FROM release_resource_findings WHERE organization_id=$1 AND project_id=ANY($2) AND closed_at IS NULL)::bigint resource_regressions,(SELECT jsonb_build_object('factual_total',count(*),'actionable_total',count(*) FILTER(WHERE (e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>1 OR e.verdict<>'expected')),'evaluation_pending',count(*) FILTER(WHERE e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>1),'expected',count(*) FILTER(WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=1 AND e.verdict='expected'),'requires_review',count(*) FILTER(WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=1 AND e.verdict='requires_review'),'policy_conflict',count(*) FILTER(WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=1 AND e.verdict='policy_conflict'),'unclassified',count(*) FILTER(WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=1 AND e.verdict='unclassified')) FROM runtime_event_groups g LEFT JOIN runtime_group_policy_evaluations e ON e.group_id=g.id LEFT JOIN runtime_policy_states ps ON ps.organization_id=g.organization_id AND ps.project_id=g.project_id AND ps.application_id=g.application_id WHERE g.occurrence_count>0 AND g.organization_id=$1 AND g.project_id=ANY($2)) policy"))
            .bind(organization_id)
            .bind(project_ids)
            .bind(from)
            .bind(to)
            .fetch_one(executor)
            .await
    }

    /// Open resource findings opened since `from` in the projects, optionally
    /// one application, most urgent first, then newest.
    ///
    /// Selects `id`, `project_id`, `project_name`, `project_slug`,
    /// `application_id`, `application_name`, `application_slug`,
    /// `target_release_id`, `priority`, `reason_code`, `facts` and
    /// `opened_at`.
    pub async fn resource_findings<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_ids: &[Uuid],
        application_id: Option<Uuid>,
        from: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT f.id,f.project_id,p.name project_name,p.slug project_slug,f.application_id,a.name application_name,a.slug application_slug,f.target_release_id,f.priority,f.reason_code,f.facts,f.opened_at FROM release_resource_findings f JOIN projects p ON p.organization_id=f.organization_id AND p.id=f.project_id JOIN applications a ON a.organization_id=f.organization_id AND a.project_id=f.project_id AND a.id=f.application_id WHERE f.organization_id=$1 AND f.project_id=ANY($2) AND ($3::uuid IS NULL OR f.application_id=$3) AND f.closed_at IS NULL AND f.opened_at >= $4 ORDER BY CASE f.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,f.opened_at DESC,f.id LIMIT $5")
            .bind(organization_id)
            .bind(project_ids)
            .bind(application_id)
            .bind(from)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// For each `(application, target, baseline)` release pair, up to
    /// `limit` groups whose occurrence count changed most between the two,
    /// most recent first on ties; groups whose classification is unknown are
    /// left out.
    ///
    /// Selects `application_id`, `group_id`, `classification`,
    /// `baseline_occurrence_count`, `target_occurrence_count` and
    /// `occurrence_delta`.
    pub async fn largest_changes<'e, E, T>(
        executor: E,
        application_ids: Vec<Uuid>,
        target_ids: Vec<Uuid>,
        baseline_ids: Vec<Uuid>,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH pairs AS (SELECT * FROM unnest($1::uuid[],$2::uuid[],$3::uuid[]) AS p(application_id,target_id,baseline_id)), changes AS (SELECT p.application_id,ids.group_id,CASE WHEN b.group_id IS NULL AND EXISTS(SELECT 1 FROM releases r JOIN projects pr ON pr.id=r.project_id WHERE r.id=p.baseline_id AND r.deployed_at<pr.runtime_history_expired_before) THEN 'unknown' WHEN b.group_id IS NULL THEN 'new' WHEN t.group_id IS NULL AND (EXISTS(SELECT 1 FROM releases r JOIN projects pr ON pr.id=r.project_id WHERE r.id=p.target_id AND r.deployed_at<pr.runtime_history_expired_before) OR NOT (EXISTS(SELECT 1 FROM runtime_event_group_releases gr WHERE gr.release_id=p.target_id AND gr.occurrence_count>0) OR EXISTS(SELECT 1 FROM runtime_events ev WHERE ev.release_id=p.target_id))) THEN 'unknown' WHEN t.group_id IS NULL THEN 'disappeared' ELSE 'unchanged' END classification,coalesce(b.occurrence_count,0)::bigint baseline_occurrence_count,coalesce(t.occurrence_count,0)::bigint target_occurrence_count,(coalesce(t.occurrence_count,0)-coalesce(b.occurrence_count,0))::bigint occurrence_delta,greatest(coalesce(t.last_seen_at,'epoch'),coalesce(b.last_seen_at,'epoch')) relevant_at FROM pairs p JOIN LATERAL (SELECT group_id FROM runtime_event_group_releases WHERE release_id=p.target_id AND occurrence_count>0 UNION SELECT group_id FROM runtime_event_group_releases WHERE release_id=p.baseline_id AND occurrence_count>0) ids ON true LEFT JOIN runtime_event_group_releases t ON t.release_id=p.target_id AND t.group_id=ids.group_id LEFT JOIN runtime_event_group_releases b ON b.release_id=p.baseline_id AND b.group_id=ids.group_id), ranked AS (SELECT *,row_number() OVER(PARTITION BY application_id ORDER BY abs(occurrence_delta) DESC,relevant_at DESC,group_id) rn FROM changes WHERE classification<>'unknown') SELECT application_id,group_id,classification,baseline_occurrence_count,target_occurrence_count,occurrence_delta FROM ranked WHERE rn<=$4 ORDER BY application_id,rn")
            .bind(application_ids)
            .bind(target_ids)
            .bind(baseline_ids)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Open runtime groups in the projects, optionally one application, that
    /// still need a reaction: not expected under current policy and not
    /// suppressed at `to`. Policy conflicts come first, then restart loops,
    /// then groups first seen in `[from, to]`, then by occurrences.
    ///
    /// Selects the group, project and application identity, the seen window,
    /// `occurrence_count`, `event_kind`, `semantic_summary`, `user_labels`,
    /// placement, `is_new`, `policy_verdict` and
    /// `policy_evaluation_state`.
    #[allow(clippy::too_many_arguments)]
    pub async fn discoveries<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_ids: &[Uuid],
        application_id: Option<Uuid>,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: i64,
        evaluator_version: i16,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT g.id group_id,g.project_id,p.name project_name,p.slug project_slug,g.application_id,a.name application_name,a.slug application_slug,g.first_seen_at,g.last_seen_at,g.occurrence_count,g.event_kind,g.semantic_summary,COALESCE((SELECT jsonb_agg(label ORDER BY label->>'display_name',label->>'updated_at') FROM (SELECT jsonb_build_object('display_name',l.display_name,'created_by_user_id',l.created_by_user_id,'updated_by_user_id',l.updated_by_user_id,'created_at',l.created_at,'updated_at',l.updated_at) label FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id JOIN runtime_behavior_user_labels l ON l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest WHERE gl.group_id=g.id ORDER BY l.display_name,l.id LIMIT 20) labels),'[]'::jsonb) user_labels,g.namespace,g.workload_kind,g.workload_name,(g.first_seen_at BETWEEN $4 AND $5) is_new,CASE WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$7 THEN NULL ELSE e.verdict END policy_verdict,CASE WHEN e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$7 THEN 'evaluation_pending' ELSE 'current' END policy_evaluation_state FROM runtime_event_groups g JOIN projects p ON p.organization_id=g.organization_id AND p.id=g.project_id JOIN applications a ON a.organization_id=g.organization_id AND a.project_id=g.project_id AND a.id=g.application_id LEFT JOIN runtime_group_policy_evaluations e ON e.group_id=g.id LEFT JOIN runtime_policy_states ps ON ps.organization_id=g.organization_id AND ps.project_id=g.project_id AND ps.application_id=g.application_id WHERE g.occurrence_count>0 AND g.organization_id=$1 AND g.project_id=ANY($2) AND ($3::uuid IS NULL OR g.application_id=$3) AND g.status='open' AND (e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$7 OR e.verdict<>'expected') AND NOT EXISTS(SELECT 1 FROM runtime_inventory_group_links gl JOIN runtime_inventory_items i ON i.id=gl.item_id JOIN runtime_policy_suppressions s ON s.organization_id=i.organization_id AND s.project_id=i.project_id AND s.application_id=i.application_id AND s.identity_version=i.identity_version AND s.identity_digest=i.identity_digest WHERE gl.group_id=g.id AND s.cancelled_at IS NULL AND s.expires_at>$5 AND (cardinality(s.cluster_ids)=0 OR g.cluster_id=ANY(s.cluster_ids)) AND (cardinality(s.namespaces)=0 OR g.namespace=ANY(s.namespaces)) AND (cardinality(s.workload_kinds)=0 OR g.workload_kind=ANY(s.workload_kinds)) AND (cardinality(s.workload_names)=0 OR g.workload_name=ANY(s.workload_names))) ORDER BY CASE WHEN e.verdict='policy_conflict' THEN 0 WHEN g.event_kind='container.restart_loop' THEN 1 WHEN g.first_seen_at BETWEEN $4 AND $5 THEN 2 ELSE 3 END,g.occurrence_count DESC,CASE WHEN g.first_seen_at BETWEEN $4 AND $5 THEN g.first_seen_at ELSE g.last_seen_at END DESC,g.id LIMIT $6")
            .bind(organization_id)
            .bind(project_ids)
            .bind(application_id)
            .bind(from)
            .bind(to)
            .bind(limit)
            .bind(evaluator_version)
            .fetch_all(executor)
            .await
    }

    /// Notification delivery queue snapshots of the projects that have a
    /// problem at `now`, worst first, with the total number of such projects.
    /// With `delivery_enabled`, a project without an enabled destination is a
    /// problem too.
    ///
    /// Selects `project_id`, `project_name`, `project_slug`,
    /// `enabled_destination_count`, the pending, due, retrying, in-flight,
    /// expired-lease and failed counts, `oldest_due_age_seconds` and
    /// `total_problem_count`.
    pub async fn notification_problems<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_ids: &[Uuid],
        now: DateTime<Utc>,
        delivery_enabled: bool,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("WITH snapshots AS (SELECT p.id project_id,p.name project_name,p.slug project_slug,(SELECT count(*) FROM webhook_destinations w WHERE w.organization_id=p.organization_id AND w.project_id=p.id AND w.enabled) enabled_destination_count,count(d.id) FILTER(WHERE d.status='pending')::bigint pending_count,count(d.id) FILTER(WHERE d.status='pending' AND d.available_at<=$3)::bigint due_count,count(d.id) FILTER(WHERE d.status='pending' AND d.attempt_count>0)::bigint retrying_count,count(d.id) FILTER(WHERE d.status='in_flight')::bigint in_flight_count,count(d.id) FILTER(WHERE d.status='in_flight' AND d.lease_expires_at<=$3)::bigint expired_lease_count,count(d.id) FILTER(WHERE d.status='failed')::bigint failed_count,CASE WHEN count(d.id) FILTER(WHERE d.status='pending' AND d.available_at<=$3)=0 THEN NULL ELSE greatest(extract(epoch from ($3-min(d.available_at) FILTER(WHERE d.status='pending' AND d.available_at<=$3)))::bigint,0) END oldest_due_age_seconds FROM projects p LEFT JOIN notification_deliveries d ON d.organization_id=p.organization_id AND d.project_id=p.id WHERE p.organization_id=$1 AND p.id=ANY($2) GROUP BY p.id,p.name,p.slug,p.organization_id), problems AS (SELECT *,count(*) OVER()::bigint total_problem_count FROM snapshots WHERE ($4 AND enabled_destination_count=0) OR failed_count>0 OR expired_lease_count>0 OR retrying_count>0 OR due_count>0 OR pending_count>0) SELECT * FROM problems ORDER BY CASE WHEN failed_count>0 OR expired_lease_count>0 OR ($4 AND enabled_destination_count=0) THEN 0 ELSE 1 END,greatest(failed_count,due_count,retrying_count,expired_lease_count) DESC,project_id LIMIT $5")
            .bind(organization_id)
            .bind(project_ids)
            .bind(now)
            .bind(delivery_enabled)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Applications in the projects with open groups first seen in
    /// `[from, to]`, most first.
    ///
    /// Selects `project_id`, `project_name`, `project_slug`,
    /// `application_id`, `application_name`, `application_slug` and
    /// `discovery_count`.
    pub async fn new_discovery_scopes<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_ids: &[Uuid],
        from: DateTime<Utc>,
        to: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT g.project_id,p.name project_name,p.slug project_slug,g.application_id,a.name application_name,a.slug application_slug,count(*)::bigint discovery_count FROM runtime_event_groups g JOIN projects p ON p.organization_id=g.organization_id AND p.id=g.project_id JOIN applications a ON a.organization_id=g.organization_id AND a.project_id=g.project_id AND a.id=g.application_id WHERE g.occurrence_count>0 AND g.organization_id=$1 AND g.project_id=ANY($2) AND g.status='open' AND g.first_seen_at BETWEEN $3 AND $4 GROUP BY g.project_id,p.name,p.slug,g.application_id,a.name,a.slug ORDER BY count(*) DESC,g.application_id LIMIT $5")
            .bind(organization_id)
            .bind(project_ids)
            .bind(from)
            .bind(to)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// The project's id, name and slug and the application's name and slug.
    pub async fn application_identity<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<Option<(Uuid, String, String, String, String)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Uuid, String, String, String, String)>("SELECT p.id,p.name,p.slug,a.name,a.slug FROM projects p JOIN applications a ON a.organization_id=p.organization_id AND a.project_id=p.id WHERE p.organization_id=$1 AND p.id=$2 AND a.id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }

    /// The application's groups first seen in `[from, to]`, open, and
    /// acknowledged.
    pub async fn application_discovery_counts<'e, E>(
        executor: E,
        organization_id: Uuid,
        application_id: Uuid,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<(i64, i64, i64), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (i64, i64, i64)>("SELECT count(*) FILTER(WHERE first_seen_at BETWEEN $3 AND $4)::bigint,count(*) FILTER(WHERE status='open')::bigint,count(*) FILTER(WHERE status='acknowledged')::bigint FROM runtime_event_groups WHERE occurrence_count>0 AND organization_id=$1 AND application_id=$2")
            .bind(organization_id)
            .bind(application_id)
            .bind(from)
            .bind(to)
            .fetch_one(executor)
            .await
    }

    /// Counts of the application's groups by current policy state: in all,
    /// needing a reaction, awaiting evaluation, and per verdict.
    pub async fn application_policy_summary<'e, E>(
        executor: E,
        organization_id: Uuid,
        application_id: Uuid,
        evaluator_version: i16,
    ) -> Result<Value, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('factual_total',count(*),'actionable_total',count(*) FILTER(WHERE e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3 OR e.verdict<>'expected'),'evaluation_pending',count(*) FILTER(WHERE e.group_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$3),'expected',count(*) FILTER(WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 AND e.verdict='expected'),'requires_review',count(*) FILTER(WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 AND e.verdict='requires_review'),'policy_conflict',count(*) FILTER(WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 AND e.verdict='policy_conflict'),'unclassified',count(*) FILTER(WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$3 AND e.verdict='unclassified')) FROM runtime_event_groups g LEFT JOIN runtime_group_policy_evaluations e ON e.group_id=g.id LEFT JOIN runtime_policy_states ps ON ps.organization_id=g.organization_id AND ps.project_id=g.project_id AND ps.application_id=g.application_id WHERE g.occurrence_count>0 AND g.organization_id=$1 AND g.application_id=$2")
            .bind(organization_id)
            .bind(application_id)
            .bind(evaluator_version)
            .fetch_one(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{Value, json};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::AttentionRepository;
    use crate::repository::resources::ResourceRepository;
    use crate::repository::test_support::{
        Tenant, exec_in_release, group_ids, ingest, manual_release, tenant,
    };

    #[derive(Debug, FromRow)]
    struct Changed {
        application_id: Uuid,
        project_name: String,
        target_id: Uuid,
        baseline_id: Uuid,
        target_display_name: String,
        new_count: i64,
        disappeared_count: i64,
        unchanged_count: i64,
        total_item_count: i64,
        absolute_occurrence_delta_sum: i64,
        max_absolute_occurrence_delta: i64,
    }

    #[derive(Debug, FromRow)]
    struct Largest {
        application_id: Uuid,
        classification: String,
        occurrence_delta: i64,
    }

    #[derive(Debug, FromRow)]
    struct Totals {
        new_discoveries: i64,
        open_discoveries: i64,
        acknowledged_discoveries: i64,
        changed_applications: i64,
        projects_with_notification_problems: i64,
        failed_notification_deliveries: i64,
        resource_regressions: i64,
        policy: Value,
    }

    #[derive(Debug, FromRow)]
    struct Discovery {
        group_id: Uuid,
        application_slug: String,
        is_new: bool,
        policy_evaluation_state: String,
    }

    #[derive(Debug, FromRow)]
    struct Problem {
        project_id: Uuid,
        enabled_destination_count: i64,
        total_problem_count: i64,
    }

    #[derive(Debug, FromRow)]
    struct Scope {
        application_id: Uuid,
        discovery_count: i64,
    }

    #[derive(Debug, FromRow)]
    struct Finding {
        id: Uuid,
        application_slug: String,
        priority: String,
    }

    /// Two releases: `v1` ran `/bin/gone` and `/bin/kept` once, `v2` ran
    /// `/bin/kept` three times and `/bin/added` once. Returns `(v1, v2)`.
    async fn releases(pool: &PgPool, own: &Tenant) -> (Uuid, Uuid) {
        let now = Utc::now();
        let v1 = manual_release(pool, own, "v1", now - Duration::hours(2)).await;
        let v2 = manual_release(pool, own, "v2", now - Duration::hours(1)).await;
        ingest(
            pool,
            own,
            &[
                exec_in_release(own, "/bin/gone", "v1", now),
                exec_in_release(own, "/bin/kept", "v1", now),
                exec_in_release(own, "/bin/kept", "v2", now),
                exec_in_release(own, "/bin/kept", "v2", now),
                exec_in_release(own, "/bin/kept", "v2", now),
                exec_in_release(own, "/bin/added", "v2", now),
            ],
        )
        .await;
        (v1, v2)
    }

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        (
            Utc::now() - Duration::days(1),
            Utc::now() + Duration::minutes(1),
        )
    }

    /// The latest release is compared with the one before it: groups it added
    /// and dropped, the ones it kept, and how far their counts moved.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_latest_release_is_compared_with_its_baseline(pool: PgPool) {
        let own = tenant(&pool, "attention-changed").await;
        let other = tenant(&pool, "attention-changed-other").await;
        let (v1, v2) = releases(&pool, &own).await;

        let changed: Vec<Changed> =
            AttentionRepository::changed(&pool, own.organization_id, &[own.project_id], 10)
                .await
                .unwrap();
        assert_eq!(changed.len(), 1);
        let row = &changed[0];
        assert_eq!(
            (row.application_id, row.target_id, row.baseline_id),
            (own.application_id, v2, v1)
        );
        assert_eq!(
            (row.project_name.as_str(), row.target_display_name.as_str()),
            ("Project", "v2")
        );
        assert_eq!(
            (
                row.new_count,
                row.disappeared_count,
                row.unchanged_count,
                row.total_item_count
            ),
            (1, 1, 1, 3)
        );
        assert_eq!(
            (
                row.absolute_occurrence_delta_sum,
                row.max_absolute_occurrence_delta
            ),
            (4, 2)
        );
        let one: Option<Changed> = AttentionRepository::application_changed(
            &pool,
            own.organization_id,
            vec![own.project_id],
            own.application_id,
        )
        .await
        .unwrap();
        assert_eq!(one.map(|c| c.target_id), Some(v2));
        assert!(
            AttentionRepository::changed::<_, Changed>(
                &pool,
                other.organization_id,
                &[own.project_id],
                10
            )
            .await
            .unwrap()
            .is_empty(),
            "scoped to the organization"
        );

        let largest: Vec<Largest> = AttentionRepository::largest_changes(
            &pool,
            vec![own.application_id],
            vec![v2],
            vec![v1],
            2,
        )
        .await
        .unwrap();
        assert_eq!(largest.len(), 2, "limited per application");
        assert_eq!(
            (
                largest[0].application_id,
                largest[0].classification.as_str(),
                largest[0].occurrence_delta
            ),
            (own.application_id, "unchanged", 2)
        );
        assert_eq!(largest[1].occurrence_delta.abs(), 1);
    }

    /// Organization totals and the discovery reads over open groups, and the
    /// one-application counts.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn discoveries_and_totals(pool: PgPool) {
        let own = tenant(&pool, "attention-discoveries").await;
        releases(&pool, &own).await;
        let groups = group_ids(&pool, &own).await;
        sqlx::query("UPDATE runtime_event_groups SET status='acknowledged' WHERE id=$1")
            .bind(groups[0])
            .execute(&pool)
            .await
            .unwrap();
        let (from, to) = window();

        let totals: Totals = AttentionRepository::organization_totals(
            &pool,
            own.organization_id,
            &[own.project_id],
            from,
            to,
        )
        .await
        .unwrap();
        assert_eq!(
            (
                totals.new_discoveries,
                totals.open_discoveries,
                totals.acknowledged_discoveries,
                totals.changed_applications,
            ),
            (3, 2, 1, 1)
        );
        assert_eq!(
            (
                totals.projects_with_notification_problems,
                totals.failed_notification_deliveries,
                totals.resource_regressions,
            ),
            (0, 0, 0)
        );
        assert_eq!(totals.policy["factual_total"], 3);

        let discoveries: Vec<Discovery> = AttentionRepository::discoveries(
            &pool,
            own.organization_id,
            &[own.project_id],
            None,
            from,
            to,
            10,
            crate::policy::POLICY_EVALUATOR_VERSION,
        )
        .await
        .unwrap();
        let mut open: Vec<Uuid> = discoveries.iter().map(|d| d.group_id).collect();
        open.sort();
        let mut expected = groups[1..].to_vec();
        expected.sort();
        assert_eq!(open, expected, "acknowledged groups need no reaction");
        assert!(
            discoveries
                .iter()
                .all(|d| d.is_new && d.application_slug == "app")
        );
        assert!(
            discoveries
                .iter()
                .all(|d| d.policy_evaluation_state == "current")
        );
        let elsewhere: Vec<Discovery> = AttentionRepository::discoveries(
            &pool,
            own.organization_id,
            &[own.project_id],
            Some(Uuid::new_v4()),
            from,
            to,
            10,
            crate::policy::POLICY_EVALUATOR_VERSION,
        )
        .await
        .unwrap();
        assert!(elsewhere.is_empty());

        let scopes: Vec<Scope> = AttentionRepository::new_discovery_scopes(
            &pool,
            own.organization_id,
            &[own.project_id],
            from,
            to,
            10,
        )
        .await
        .unwrap();
        assert_eq!(
            scopes
                .iter()
                .map(|s| (s.application_id, s.discovery_count))
                .collect::<Vec<_>>(),
            [(own.application_id, 2)]
        );

        assert_eq!(
            AttentionRepository::application_identity(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
            )
            .await
            .unwrap(),
            Some((
                own.project_id,
                "Project".into(),
                "project".into(),
                "Application".into(),
                "app".into()
            ))
        );
        assert_eq!(
            AttentionRepository::application_discovery_counts(
                &pool,
                own.organization_id,
                own.application_id,
                from,
                to,
            )
            .await
            .unwrap(),
            (3, 2, 1)
        );
        let policy = AttentionRepository::application_policy_summary(
            &pool,
            own.organization_id,
            own.application_id,
            crate::policy::POLICY_EVALUATOR_VERSION,
        )
        .await
        .unwrap();
        assert_eq!(
            (
                policy["factual_total"].clone(),
                policy["actionable_total"].clone()
            ),
            (json!(3), json!(3))
        );
    }

    /// Notification problems: without destinations a project is a problem
    /// only when delivery is enabled.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn a_project_without_destinations_is_a_problem_when_delivery_is_on(pool: PgPool) {
        let own = tenant(&pool, "attention-problems").await;
        let projects = [own.project_id];
        let problems = |enabled: bool| {
            AttentionRepository::notification_problems::<_, Problem>(
                &pool,
                own.organization_id,
                &projects,
                Utc::now(),
                enabled,
                10,
            )
        };
        let on = problems(true).await.unwrap();
        assert_eq!(
            on.iter()
                .map(|p| (
                    p.project_id,
                    p.enabled_destination_count,
                    p.total_problem_count
                ))
                .collect::<Vec<_>>(),
            [(own.project_id, 0, 1)]
        );
        assert!(problems(false).await.unwrap().is_empty());
    }

    /// Open resource findings since a time, with their application.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn open_resource_findings_are_listed(pool: PgPool) {
        let own = tenant(&pool, "attention-findings").await;
        let (v1, v2) = releases(&pool, &own).await;
        let finding = Uuid::new_v4();
        ResourceRepository::upsert_finding(
            &pool,
            finding,
            own.organization_id,
            own.project_id,
            own.application_id,
            v2,
            v1,
            "oom_observed",
            "urgent",
            "memory",
            1,
            json!({}),
            Utc::now(),
        )
        .await
        .unwrap();
        let (from, _) = window();
        let projects = [own.project_id];
        let listed = |from: DateTime<Utc>| {
            AttentionRepository::resource_findings::<_, Finding>(
                &pool,
                own.organization_id,
                &projects,
                None,
                from,
                10,
            )
        };
        let found = listed(from).await.unwrap();
        assert_eq!(
            found
                .iter()
                .map(|f| (f.id, f.application_slug.as_str(), f.priority.as_str()))
                .collect::<Vec<_>>(),
            [(finding, "app", "urgent")]
        );
        assert!(
            listed(Utc::now() + Duration::minutes(1))
                .await
                .unwrap()
                .is_empty(),
            "opened before the window"
        );
    }
}
