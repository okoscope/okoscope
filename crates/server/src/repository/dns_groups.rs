//! DNS behaviour groups: the grouped view of an application's observed DNS
//! lookups, and the variants inside each group.
//!
//! All three statements share one filter and one grouping CTE, and differ only
//! in what they select from it. They live together so the filter's sixteen
//! bind positions are written once. The row shapes belong to the DNS groups
//! endpoints, so each method is generic over the row type it decodes into.

use chrono::{DateTime, Utc};
use sqlx::postgres::{PgArguments, PgRow};
use sqlx::query::QueryAs;
use sqlx::{FromRow, PgExecutor, Postgres};
use uuid::Uuid;

use crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION;

/// The tenant path and the filters every DNS group statement applies, bound as
/// parameters `$1` to `$16` in this order.
#[derive(Clone, Copy, Debug)]
pub struct DnsGroupFilter<'a> {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub release_id: Option<Uuid>,
    pub cluster_id: Option<Uuid>,
    pub namespace: Option<&'a str>,
    pub workload_kind: Option<&'a str>,
    pub workload_name: Option<&'a str>,
    pub container_name: Option<&'a str>,
    pub observed_from: Option<DateTime<Utc>>,
    pub observed_to: Option<DateTime<Utc>>,
    pub verdict: Option<&'a str>,
    pub suppressed: Option<bool>,
    pub evaluation_pending: Option<bool>,
}

const GROUP_CTE: &str = r#"
WITH scoped AS MATERIALIZED (
 SELECT e.id occurrence_id,i.id item_id,lower(trim(trailing '.' from i.semantic_summary->>'name')) canonical_name,
        upper(i.semantic_summary->>'query_type') query_type,e.process_command,e.observed_at,e.release_id,e.cluster_id,
        e.namespace,e.workload_kind,e.workload_name,e.pod_uid,e.container_name
 FROM runtime_inventory_event_memberships m JOIN runtime_inventory_items i ON i.id=m.item_id
 JOIN runtime_events e ON e.id=m.event_id
 WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4
 AND i.inventory_kind='domain' AND i.occurrence_count>0
 AND ($5::uuid IS NULL OR e.release_id=$5) AND ($6::uuid IS NULL OR e.cluster_id=$6)
 AND ($7::text IS NULL OR e.namespace=$7) AND ($8::text IS NULL OR e.workload_kind=$8)
 AND ($9::text IS NULL OR e.workload_name=$9) AND ($10::text IS NULL OR e.container_name=$10)
 AND ($11::timestamptz IS NULL OR e.observed_at >= $11) AND ($12::timestamptz IS NULL OR e.observed_at <= $12)
 AND ($13::text IS NULL OR EXISTS(SELECT 1 FROM runtime_sighting_policy_evaluations p JOIN runtime_policy_states ps ON ps.organization_id=p.organization_id AND ps.project_id=p.project_id AND ps.application_id=p.application_id WHERE p.item_id=i.id AND p.cluster_id=e.cluster_id AND p.namespace=e.namespace AND p.workload_kind=e.workload_kind AND p.workload_name=e.workload_name AND p.pod_uid=e.pod_uid AND p.container_name=e.container_name AND p.policy_state_version=ps.state_version AND p.evaluator_version=$16 AND p.verdict=$13))
 AND ($14::bool IS NULL OR $14=EXISTS(SELECT 1 FROM runtime_policy_suppressions z WHERE z.organization_id=i.organization_id AND z.project_id=i.project_id AND z.application_id=i.application_id AND z.identity_version=i.identity_version AND z.identity_digest=i.identity_digest AND z.cancelled_at IS NULL AND z.expires_at>now() AND (cardinality(z.cluster_ids)=0 OR e.cluster_id=ANY(z.cluster_ids)) AND (cardinality(z.namespaces)=0 OR e.namespace=ANY(z.namespaces)) AND (cardinality(z.workload_kinds)=0 OR e.workload_kind=ANY(z.workload_kinds)) AND (cardinality(z.workload_names)=0 OR e.workload_name=ANY(z.workload_names))))
 AND ($15::bool IS NULL OR $15=EXISTS(SELECT 1 FROM runtime_inventory_sightings s LEFT JOIN runtime_sighting_policy_evaluations p ON p.item_id=s.item_id AND p.cluster_id=s.cluster_id AND p.namespace=s.namespace AND p.workload_kind=s.workload_kind AND p.workload_name=s.workload_name AND p.pod_uid=s.pod_uid AND p.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id WHERE s.item_id=i.id AND s.cluster_id=e.cluster_id AND s.namespace=e.namespace AND s.workload_kind=e.workload_kind AND s.workload_name=e.workload_name AND s.pod_uid=e.pod_uid AND s.container_name=e.container_name AND (p.item_id IS NULL OR p.policy_state_version<>COALESCE(ps.state_version,0) OR p.evaluator_version<>$16)))
), candidates AS MATERIALIZED (
 SELECT s.*,candidate.candidate_name,candidate.suffix_kind
 FROM scoped s
 CROSS JOIN LATERAL (
  VALUES
   (left(s.canonical_name,-length('.'||lower(s.namespace)||'.svc.cluster.local')),'namespace'),
   (left(s.canonical_name,-length('.svc.cluster.local')),'service'),
   (left(s.canonical_name,-length('.cluster.local')),'cluster')
 ) candidate(candidate_name,suffix_kind)
 WHERE (candidate.suffix_kind='namespace' AND s.canonical_name LIKE ('%.'||lower(s.namespace)||'.svc.cluster.local'))
    OR (candidate.suffix_kind='service' AND s.canonical_name LIKE '%.svc.cluster.local')
    OR (candidate.suffix_kind='cluster' AND s.canonical_name LIKE '%.cluster.local')
), candidate_evidence AS MATERIALIZED (
 SELECT candidate_name,process_command,cluster_id,namespace,pod_uid,container_name,
        count(DISTINCT canonical_name) exact_name_count,count(DISTINCT suffix_kind) suffix_kind_count
 FROM candidates
 GROUP BY candidate_name,process_command,cluster_id,namespace,pod_uid,container_name
), normalized AS MATERIALIZED (
 SELECT s.*,COALESCE(selected.candidate_name,s.canonical_name) display_name
 FROM scoped s
 LEFT JOIN LATERAL (
  SELECT c.candidate_name
  FROM candidates c
  JOIN candidate_evidence evidence ON evidence.candidate_name=c.candidate_name
   AND evidence.process_command=c.process_command AND evidence.cluster_id=c.cluster_id
   AND evidence.namespace=c.namespace AND evidence.pod_uid IS NOT DISTINCT FROM c.pod_uid
   AND evidence.container_name=c.container_name
  WHERE c.occurrence_id=s.occurrence_id AND c.item_id=s.item_id
   AND (EXISTS(
    SELECT 1 FROM scoped corroborating
    WHERE corroborating.process_command=c.process_command AND corroborating.canonical_name=c.candidate_name
     AND corroborating.cluster_id=c.cluster_id AND corroborating.namespace=c.namespace
     AND corroborating.pod_uid IS NOT DISTINCT FROM c.pod_uid
     AND corroborating.container_name=c.container_name
   ) OR (evidence.exact_name_count>=2 AND evidence.suffix_kind_count>=2))
  ORDER BY length(c.candidate_name) DESC,c.candidate_name
  LIMIT 1
 ) selected ON true
), groups AS MATERIALIZED (
 SELECT display_name,process_command,CASE WHEN bool_or(display_name<>canonical_name) THEN 'kubernetes_search_expansion' ELSE 'canonical_name' END grouping_reason,
 CASE WHEN bool_or(display_name<>canonical_name) THEN 'high' ELSE 'exact' END confidence,
 min(observed_at) first_seen_at,max(observed_at) last_seen_at,count(DISTINCT occurrence_id)::bigint observation_count,
 count(DISTINCT (item_id,canonical_name,query_type))::bigint variant_count,array_agg(DISTINCT query_type ORDER BY query_type) query_types,
 count(DISTINCT release_id)::bigint release_count,count(DISTINCT cluster_id)::bigint cluster_count,
 count(DISTINCT (cluster_id,namespace))::bigint namespace_count,count(DISTINCT (cluster_id,namespace,workload_kind,workload_name))::bigint workload_count,
 count(DISTINCT (cluster_id,pod_uid))::bigint pod_count,count(DISTINCT container_name)::bigint container_count,
 array_agg(DISTINCT canonical_name) exact_names
 FROM normalized GROUP BY display_name,process_command
)"#;

fn bind_filter<'q, T>(
    query: QueryAs<'q, Postgres, T, PgArguments>,
    filter: DnsGroupFilter<'q>,
) -> QueryAs<'q, Postgres, T, PgArguments> {
    query
        .bind(filter.organization_id)
        .bind(filter.project_id)
        .bind(filter.application_id)
        .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
        .bind(filter.release_id)
        .bind(filter.cluster_id)
        .bind(filter.namespace)
        .bind(filter.workload_kind)
        .bind(filter.workload_name)
        .bind(filter.container_name)
        .bind(filter.observed_from)
        .bind(filter.observed_to)
        .bind(filter.verdict)
        .bind(filter.suppressed)
        .bind(filter.evaluation_pending)
        .bind(crate::policy::POLICY_EVALUATOR_VERSION)
}

/// Queries over DNS behaviour groups.
#[derive(Clone, Copy, Debug)]
pub struct DnsGroupRepository;

impl DnsGroupRepository {
    /// One page of groups, newest sighting first, keyed by
    /// `(last_seen_at, display_name, process_command)`.
    ///
    /// Selects every column of the grouping CTE plus `total_group_count` and
    /// `total_observation_count` over the whole filtered set. `pattern` is a
    /// `LIKE` pattern over the display name; `fetch_limit` is the number of rows
    /// to return, which callers set one above the page size to detect a next
    /// page.
    #[allow(clippy::too_many_arguments)]
    pub async fn groups<'e, E, T>(
        executor: E,
        filter: DnsGroupFilter<'_>,
        pattern: Option<String>,
        cursor_last_seen_at: Option<DateTime<Utc>>,
        cursor_display_name: Option<&str>,
        cursor_process_command: Option<&str>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        let sql = format!(
            "{GROUP_CTE}, filtered AS (SELECT *,count(*) OVER()::bigint total_group_count,sum(observation_count) OVER()::bigint total_observation_count FROM groups WHERE ($17::text IS NULL OR display_name ILIKE $17 OR EXISTS(SELECT 1 FROM unnest(exact_names) n WHERE n ILIKE $17))) SELECT display_name,process_command,grouping_reason,confidence,first_seen_at,last_seen_at,observation_count,variant_count,query_types,release_count,cluster_count,namespace_count,workload_count,pod_count,container_count,total_group_count,total_observation_count FROM filtered WHERE ($18::timestamptz IS NULL OR (last_seen_at,display_name,process_command)<($18,$19,$20)) ORDER BY last_seen_at DESC,display_name DESC,process_command DESC LIMIT $21"
        );
        bind_filter(sqlx::query_as(&sql), filter)
            .bind(pattern)
            .bind(cursor_last_seen_at)
            .bind(cursor_display_name)
            .bind(cursor_process_command)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// The largest groups by observation count, for the distribution view.
    ///
    /// Selects the same columns as [`Self::groups`].
    pub async fn distribution<'e, E, T>(
        executor: E,
        filter: DnsGroupFilter<'_>,
        pattern: Option<String>,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        let sql = format!(
            "{GROUP_CTE}, filtered AS (SELECT *,count(*) OVER()::bigint total_group_count,sum(observation_count) OVER()::bigint total_observation_count FROM groups WHERE ($17::text IS NULL OR display_name ILIKE $17 OR EXISTS(SELECT 1 FROM unnest(exact_names) n WHERE n ILIKE $17))) SELECT display_name,process_command,grouping_reason,confidence,first_seen_at,last_seen_at,observation_count,variant_count,query_types,release_count,cluster_count,namespace_count,workload_count,pod_count,container_count,total_group_count,total_observation_count FROM filtered ORDER BY observation_count DESC,display_name ASC,process_command ASC LIMIT $18"
        );
        bind_filter(sqlx::query_as(&sql), filter)
            .bind(pattern)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// One page of the name and query-type variants inside a group, keyed by
    /// `item_id`.
    ///
    /// Selects `item_id`, `name`, `query_type`, `first_seen_at`,
    /// `last_seen_at` and `observation_count`. An empty result means the group
    /// has no variants under this filter, which callers treat as not found.
    pub async fn variants<'e, E, T>(
        executor: E,
        filter: DnsGroupFilter<'_>,
        display_name: &str,
        process_command: &str,
        cursor_item_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        let sql = format!(
            "{GROUP_CTE}, selected AS (SELECT n.item_id,n.canonical_name name,n.query_type,min(n.observed_at) first_seen_at,max(n.observed_at) last_seen_at,count(DISTINCT n.occurrence_id)::bigint observation_count FROM normalized n WHERE n.display_name=$17 AND n.process_command=$18 GROUP BY n.item_id,n.canonical_name,n.query_type) SELECT item_id,name,query_type,first_seen_at,last_seen_at,observation_count FROM selected WHERE ($19::uuid IS NULL OR item_id>$19) ORDER BY item_id ASC LIMIT $20"
        );
        bind_filter(sqlx::query_as(&sql), filter)
            .bind(display_name)
            .bind(process_command)
            .bind(cursor_item_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }
}
