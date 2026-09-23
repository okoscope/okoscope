//! Runtime inventory: the distinct behaviours observed per application, each
//! with a stable identity, the places they were sighted, and the runtime
//! groups they are linked to.
//!
//! Reads returning projections owned by an endpoint are generic over the row
//! type and document the columns they select.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::postgres::{PgArguments, PgRow};
use sqlx::query::QueryAs;
use sqlx::{FromRow, PgExecutor, Postgres};
use uuid::Uuid;

use crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION;

/// The tenant path and the scope filters the inventory reads share. Text
/// filters match exactly; `search` is an `ILIKE` pattern over the item's
/// summary and its label.
#[derive(Clone, Copy, Debug)]
pub struct InventoryFilter<'a> {
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
    pub operation: Option<&'a str>,
    pub search: Option<&'a str>,
}

/// The sighting column a facet groups by.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FacetColumn {
    Cluster,
    Namespace,
    WorkloadKind,
    WorkloadName,
    ContainerName,
}

/// Binds the filter's scope, from `release_id` to `search`, as the next ten
/// parameters.
fn bind_scope<'q, T>(
    query: QueryAs<'q, Postgres, T, PgArguments>,
    filter: InventoryFilter<'q>,
) -> QueryAs<'q, Postgres, T, PgArguments> {
    query
        .bind(filter.release_id)
        .bind(filter.cluster_id)
        .bind(filter.namespace)
        .bind(filter.workload_kind)
        .bind(filter.workload_name)
        .bind(filter.container_name)
        .bind(filter.observed_from)
        .bind(filter.observed_to)
        .bind(filter.operation)
        .bind(filter.search)
}

/// Runtime inventory items, their sightings and group links.
#[derive(Clone, Copy, Debug)]
pub struct InventoryRepository;

impl InventoryRepository {
    /// Grouped raw events of the project, or one application, after `cursor`
    /// up to `upper_bound` by id, that are not yet projected into the
    /// inventory under `identity_version`, at most `limit`.
    ///
    /// Selects the event row with its `group_id`.
    #[allow(clippy::too_many_arguments)]
    pub async fn projection_backfill_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Option<Uuid>,
        identity_version: i16,
        cursor: Option<Uuid>,
        upper_bound: Uuid,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.organization_id,e.project_id,e.cluster_id,e.application_id,e.release_id,m.group_id,e.observed_at,e.node_name,e.namespace,e.pod_uid,e.pod_name,e.container_id,e.container_name,e.workload_uid,e.workload_kind,e.workload_name,e.cgroup_id,e.pid,e.tgid,e.process_command,e.event_schema_version,e.payload FROM runtime_events e JOIN runtime_event_group_memberships m ON m.event_id=e.id AND m.fingerprint_version=1 LEFT JOIN runtime_inventory_event_memberships im ON im.event_id=e.id AND im.identity_version=$4 WHERE e.organization_id=$1 AND e.project_id=$2 AND ($3::uuid IS NULL OR e.application_id=$3) AND im.event_id IS NULL AND ($5::uuid IS NULL OR e.id>$5) AND e.id<=$6 ORDER BY e.id LIMIT $7")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(identity_version)
            .bind(cursor)
            .bind(upper_bound)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Compares the application's grouped raw events with its inventory
    /// projection under `identity_version`.
    ///
    /// Selects `source_event_count`, `membership_count`,
    /// `item_occurrence_count`, and the source and projected first and last
    /// seen times.
    pub async fn reconciliation<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        identity_version: i16,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT (SELECT count(*) FROM runtime_events e JOIN runtime_event_group_memberships gm ON gm.event_id=e.id AND gm.fingerprint_version=1 WHERE e.organization_id=$1 AND e.project_id=$2 AND e.application_id=$3) source_event_count,(SELECT count(*) FROM runtime_inventory_event_memberships WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND identity_version=$4) membership_count,(SELECT COALESCE(sum(occurrence_count),0)::bigint FROM runtime_inventory_items WHERE occurrence_count>0 AND organization_id=$1 AND project_id=$2 AND application_id=$3 AND identity_version=$4) item_occurrence_count,(SELECT min(e.observed_at) FROM runtime_events e JOIN runtime_event_group_memberships gm ON gm.event_id=e.id AND gm.fingerprint_version=1 WHERE e.organization_id=$1 AND e.project_id=$2 AND e.application_id=$3) source_first_seen_at,(SELECT min(first_seen_at) FROM runtime_inventory_items WHERE occurrence_count>0 AND organization_id=$1 AND project_id=$2 AND application_id=$3 AND identity_version=$4) projected_first_seen_at,(SELECT max(e.observed_at) FROM runtime_events e JOIN runtime_event_group_memberships gm ON gm.event_id=e.id AND gm.fingerprint_version=1 WHERE e.organization_id=$1 AND e.project_id=$2 AND e.application_id=$3) source_last_seen_at,(SELECT max(last_seen_at) FROM runtime_inventory_items WHERE occurrence_count>0 AND organization_id=$1 AND project_id=$2 AND application_id=$3 AND identity_version=$4) projected_last_seen_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(identity_version)
            .fetch_one(executor)
            .await
    }

    /// How many inventory items exist, and how many seconds ago the most
    /// recently updated one changed (0 when there are none).
    pub async fn item_count_and_staleness<'e, E>(executor: E) -> Result<(i64, i64), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (i64, i64)>("SELECT count(*)::bigint,COALESCE(EXTRACT(EPOCH FROM (now()-max(updated_at)))::bigint,0) FROM runtime_inventory_items")
            .fetch_one(executor)
            .await
    }

    /// An item's identity version and digest.
    pub async fn identity_key<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
    ) -> Result<(i16, Vec<u8>), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (i16, Vec<u8>)>("SELECT identity_version,identity_digest FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .fetch_one(executor)
            .await
    }

    /// Records a new inventory item for an identity, returning its id; `None`
    /// when the application already has that identity.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_item<'e, E>(
        executor: E,
        id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        inventory_kind: &str,
        identity_version: i16,
        identity_digest: &[u8],
        semantic_summary: &serde_json::Value,
        observed_at: DateTime<Utc>,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,1) ON CONFLICT (organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest) DO NOTHING RETURNING id")
            .bind(id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(inventory_kind)
            .bind(identity_version)
            .bind(identity_digest)
            .bind(semantic_summary)
            .bind(observed_at)
            .fetch_optional(executor)
            .await
    }

    /// The id of the application's item with this identity.
    pub async fn item_id_by_identity<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        inventory_kind: &str,
        identity_version: i16,
        identity_digest: &[u8],
    ) -> Result<Uuid, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND inventory_kind=$4 AND identity_version=$5 AND identity_digest=$6 FOR UPDATE")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(inventory_kind)
            .bind(identity_version)
            .bind(identity_digest)
            .fetch_one(executor)
            .await
    }

    /// Makes an event an occurrence of an item under `identity_version`,
    /// once; `None` when it already was.
    pub async fn add_event_membership<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        event_id: Uuid,
        item_id: Uuid,
        identity_version: i16,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO runtime_inventory_event_memberships(organization_id,project_id,application_id,event_id,item_id,identity_version) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (event_id,identity_version) DO NOTHING RETURNING event_id")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(event_id)
            .bind(item_id)
            .bind(identity_version)
            .fetch_optional(executor)
            .await
    }

    /// Counts an occurrence of an inbound endpoint item, widening its seen
    /// window and remembering whether a listener or an accept was observed.
    pub async fn record_inbound_occurrence<'e, E>(
        executor: E,
        item_id: Uuid,
        observed_at: DateTime<Utc>,
        listener_observed: bool,
        accept_observed: bool,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_inventory_items SET first_seen_at=CASE WHEN occurrence_count=0 THEN $2 ELSE LEAST(first_seen_at,$2) END,last_seen_at=CASE WHEN occurrence_count=0 THEN $2 ELSE GREATEST(last_seen_at,$2) END,occurrence_count=occurrence_count+1,semantic_summary=jsonb_set(jsonb_set(semantic_summary,'{listener_observed}',to_jsonb(COALESCE((semantic_summary->>'listener_observed')::boolean,false) OR $3)),'{accept_observed}',to_jsonb(COALESCE((semantic_summary->>'accept_observed')::boolean,false) OR $4)),updated_at=now() WHERE id=$1")
            .bind(item_id)
            .bind(observed_at)
            .bind(listener_observed)
            .bind(accept_observed)
            .execute(executor)
            .await
    }

    /// Counts an occurrence of an item and widens its seen window.
    pub async fn record_occurrence<'e, E>(
        executor: E,
        item_id: Uuid,
        observed_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_inventory_items SET first_seen_at=CASE WHEN occurrence_count=0 THEN $2 ELSE LEAST(first_seen_at,$2) END,last_seen_at=CASE WHEN occurrence_count=0 THEN $2 ELSE GREATEST(last_seen_at,$2) END,occurrence_count=occurrence_count+1,updated_at=now() WHERE id=$1")
            .bind(item_id)
            .bind(observed_at)
            .execute(executor)
            .await
    }

    /// Links an item to a runtime group, once.
    pub async fn link_group<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        group_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_inventory_group_links(organization_id,project_id,application_id,item_id,group_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT (item_id,group_id) DO NOTHING")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(group_id)
            .execute(executor)
            .await
    }

    /// Counts an occurrence of an item in a release.
    pub async fn record_release_occurrence<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        release_id: Uuid,
        observed_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_inventory_releases(organization_id,project_id,application_id,item_id,release_id,occurrence_count,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,1,$6,$6) ON CONFLICT (item_id,release_id) DO UPDATE SET occurrence_count=runtime_inventory_releases.occurrence_count+1,first_seen_at=LEAST(runtime_inventory_releases.first_seen_at,EXCLUDED.first_seen_at),last_seen_at=GREATEST(runtime_inventory_releases.last_seen_at,EXCLUDED.last_seen_at),updated_at=now()")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(release_id)
            .bind(observed_at)
            .execute(executor)
            .await
    }

    /// Counts an occurrence of an item at one placement.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_sighting<'e, E>(
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
        pod_name: &str,
        container_name: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_inventory_sightings(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,pod_name,container_name,occurrence_count,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$12) ON CONFLICT (item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,container_name) DO UPDATE SET occurrence_count=runtime_inventory_sightings.occurrence_count+1,first_seen_at=LEAST(runtime_inventory_sightings.first_seen_at,EXCLUDED.first_seen_at),last_seen_at=GREATEST(runtime_inventory_sightings.last_seen_at,EXCLUDED.last_seen_at),pod_name=EXCLUDED.pod_name,updated_at=now()")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(cluster_id)
            .bind(namespace)
            .bind(workload_kind)
            .bind(workload_name)
            .bind(pod_uid)
            .bind(pod_name)
            .bind(container_name)
            .bind(observed_at)
            .execute(executor)
            .await
    }

    /// Links the inventory items an event belongs to under `identity_version`
    /// to a group, once.
    pub async fn link_event_items_to_group<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        group_id: Uuid,
        event_id: Uuid,
        identity_version: i16,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_inventory_group_links (organization_id,project_id,application_id,item_id,group_id) SELECT $1,$2,$3,m.item_id,$4 FROM runtime_inventory_event_memberships m WHERE m.organization_id=$1 AND m.project_id=$2 AND m.application_id=$3 AND m.event_id=$5 AND m.identity_version=$6 ON CONFLICT (item_id,group_id) DO NOTHING")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(group_id)
            .bind(event_id)
            .bind(identity_version)
            .execute(executor)
            .await
    }

    /// Item and occurrence counts and the seen window per inventory kind under
    /// the filter, with the lifecycle kinds folded into `lifecycle`.
    ///
    /// Selects `kind`, `item_count`, `occurrence_count`, `first_seen_at` and
    /// `last_seen_at`.
    pub async fn kind_summary<'e, E, T>(
        executor: E,
        filter: InventoryFilter<'_>,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        let query = sqlx::query_as("SELECT CASE WHEN i.inventory_kind IN ('process_exit','container_termination','container_restart') THEN 'lifecycle' ELSE i.inventory_kind END kind,count(*)::bigint item_count,COALESCE(sum(i.occurrence_count),0)::bigint occurrence_count,min(i.first_seen_at) first_seen_at,max(i.last_seen_at) last_seen_at FROM runtime_inventory_items i WHERE i.occurrence_count>0 AND i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4 AND ($5::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$5)) AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.cluster_id=$6)) AND ($7::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.namespace=$7)) AND ($8::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_kind=$8)) AND ($9::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_name=$9)) AND ($10::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.container_name=$10)) AND ($11::timestamptz IS NULL OR i.last_seen_at >= $11) AND ($12::timestamptz IS NULL OR i.first_seen_at <= $12) AND ($13::text IS NULL OR i.semantic_summary->>'operation'=$13) AND ($14::text IS NULL OR concat_ws(' ',i.semantic_summary->>'executable',i.semantic_summary->>'process_command',i.semantic_summary->>'destination_address',i.semantic_summary->>'destination_port',i.semantic_summary->>'local_address',i.semantic_summary->>'local_port',i.semantic_summary->>'name',i.semantic_summary->>'query_type',i.semantic_summary->>'syscall',i.semantic_summary->>'operation',i.semantic_summary->>'path',i.semantic_summary->>'new_path') ILIKE $14 OR EXISTS(SELECT 1 FROM runtime_behavior_user_labels l WHERE l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest AND l.display_name ILIKE $14)) GROUP BY 1")
            .bind(filter.organization_id)
            .bind(filter.project_id)
            .bind(filter.application_id)
            .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get());
        bind_scope(query, filter).fetch_all(executor).await
    }

    /// The items of one kind under the filter with the most occurrences, at
    /// most `limit`, with totals over the whole filtered set.
    ///
    /// Selects `id`, `identity_digest`, `semantic_summary`, `user_label`,
    /// `occurrence_count`, `total_item_count` and `total_occurrence_count`.
    pub async fn distribution<'e, E, T>(
        executor: E,
        filter: InventoryFilter<'_>,
        kind: &str,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        let query = sqlx::query_as("WITH scoped AS MATERIALIZED (SELECT i.id,i.identity_digest,i.semantic_summary,CASE WHEN l.id IS NULL THEN NULL ELSE jsonb_build_object('display_name',l.display_name,'created_by_user_id',l.created_by_user_id,'updated_by_user_id',l.updated_by_user_id,'created_at',l.created_at,'updated_at',l.updated_at) END user_label,i.occurrence_count FROM runtime_inventory_items i LEFT JOIN runtime_behavior_user_labels l ON l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest WHERE i.occurrence_count>0 AND i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4 AND i.inventory_kind=$5 AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$6)) AND ($7::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.cluster_id=$7)) AND ($8::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.namespace=$8)) AND ($9::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_kind=$9)) AND ($10::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_name=$10)) AND ($11::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.container_name=$11)) AND ($12::timestamptz IS NULL OR i.last_seen_at >= $12) AND ($13::timestamptz IS NULL OR i.first_seen_at <= $13) AND ($14::text IS NULL OR i.semantic_summary->>'operation'=$14) AND ($15::text IS NULL OR concat_ws(' ',i.semantic_summary->>'executable',i.semantic_summary->>'process_command',i.semantic_summary->>'destination_address',i.semantic_summary->>'destination_port',i.semantic_summary->>'local_address',i.semantic_summary->>'local_port',i.semantic_summary->>'name',i.semantic_summary->>'query_type',i.semantic_summary->>'syscall',i.semantic_summary->>'operation',i.semantic_summary->>'path',i.semantic_summary->>'new_path',l.display_name) ILIKE $15)), ranked AS (SELECT id,identity_digest,semantic_summary,user_label,occurrence_count,count(*) OVER()::bigint total_item_count,COALESCE(sum(occurrence_count) OVER(),0)::bigint total_occurrence_count FROM scoped) SELECT id,identity_digest,semantic_summary,user_label,occurrence_count,total_item_count,total_occurrence_count FROM ranked ORDER BY occurrence_count DESC,identity_digest ASC LIMIT $16")
            .bind(filter.organization_id)
            .bind(filter.project_id)
            .bind(filter.application_id)
            .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
            .bind(kind);
        bind_scope(query, filter)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// A page of the values of one sighting column under the filter, most
    /// items first, then by label and value, after the cursor when one is
    /// given. `facet_search` is an `ILIKE` pattern over label and value.
    ///
    /// Selects `value`, `label`, `item_count` and `occurrence_count`.
    #[allow(clippy::too_many_arguments)]
    pub async fn facet_options<'e, E, T>(
        executor: E,
        column: FacetColumn,
        filter: InventoryFilter<'_>,
        kind: Option<&str>,
        facet_search: Option<&str>,
        cursor_item_count: Option<i64>,
        cursor_label: Option<&str>,
        cursor_value: Option<&str>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        let (value_sql, label_sql, cluster_join) = match column {
            FacetColumn::Cluster => (
                "s.cluster_id::text",
                "c.name",
                "JOIN clusters c ON c.organization_id=s.organization_id AND c.id=s.cluster_id",
            ),
            FacetColumn::Namespace => ("s.namespace", "s.namespace", ""),
            FacetColumn::WorkloadKind => ("s.workload_kind", "s.workload_kind", ""),
            FacetColumn::WorkloadName => ("s.workload_name", "s.workload_name", ""),
            FacetColumn::ContainerName => ("s.container_name", "s.container_name", ""),
        };
        let sql = format!(
            "SELECT {value_sql} value,{label_sql} label,count(DISTINCT i.id)::bigint item_count,COALESCE(sum(s.occurrence_count),0)::bigint occurrence_count FROM runtime_inventory_sightings s JOIN runtime_inventory_items i ON i.id=s.item_id {cluster_join} WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4 AND ($5::text IS NULL OR i.inventory_kind=$5) AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$6)) AND ($7::uuid IS NULL OR s.cluster_id=$7) AND ($8::text IS NULL OR s.namespace=$8) AND ($9::text IS NULL OR s.workload_kind=$9) AND ($10::text IS NULL OR s.workload_name=$10) AND ($11::text IS NULL OR s.container_name=$11) AND ($12::timestamptz IS NULL OR s.last_seen_at >= $12) AND ($13::timestamptz IS NULL OR s.first_seen_at <= $13) AND ($14::text IS NULL OR i.semantic_summary->>'operation'=$14) AND ($15::text IS NULL OR concat_ws(' ',i.semantic_summary->>'executable',i.semantic_summary->>'process_command',i.semantic_summary->>'destination_address',i.semantic_summary->>'destination_port',i.semantic_summary->>'local_address',i.semantic_summary->>'local_port',i.semantic_summary->>'name',i.semantic_summary->>'query_type',i.semantic_summary->>'syscall',i.semantic_summary->>'operation',i.semantic_summary->>'path',i.semantic_summary->>'new_path') ILIKE $15 OR EXISTS(SELECT 1 FROM runtime_behavior_user_labels l WHERE l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest AND l.display_name ILIKE $15)) AND ($16::text IS NULL OR concat_ws(' ',{label_sql},{value_sql}) ILIKE $16) GROUP BY {value_sql},{label_sql} HAVING ($17::bigint IS NULL OR count(DISTINCT i.id)<$17 OR (count(DISTINCT i.id)=$17 AND ({label_sql}>$18 OR ({label_sql}=$18 AND {value_sql}>$19)))) ORDER BY item_count DESC,label ASC,value ASC LIMIT $20"
        );
        let query = sqlx::query_as(&sql)
            .bind(filter.organization_id)
            .bind(filter.project_id)
            .bind(filter.application_id)
            .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
            .bind(kind);
        bind_scope(query, filter)
            .bind(facet_search)
            .bind(cursor_item_count)
            .bind(cursor_label)
            .bind(cursor_value)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// A page of the items under the filter, most recently seen first, after
    /// the cursor when one is given. `identity` narrows to one item with
    /// that identity digest; `verdict`, `suppressed` and `evaluation_pending`
    /// filter on the current policy state of the item's sightings.
    ///
    /// Selects `id`, `project_id`, `application_id`, `inventory_kind`,
    /// `identity_version`, `semantic_summary`, `user_label`, `first_seen_at`,
    /// `last_seen_at`, `occurrence_count`, and the `release_count`,
    /// `cluster_count`, `namespace_count`, `workload_count`, `pod_count`,
    /// `container_count` and `group_count` of the item.
    #[allow(clippy::too_many_arguments)]
    pub async fn item_page<'e, E, T>(
        executor: E,
        filter: InventoryFilter<'_>,
        kind: Option<&str>,
        identity_item_id: Option<Uuid>,
        identity_digest: Option<Vec<u8>>,
        verdict: Option<&str>,
        suppressed: Option<bool>,
        evaluation_pending: Option<bool>,
        cursor_last_seen_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> FromRow<'r, PgRow> + Send + Unpin,
    {
        let query = sqlx::query_as("SELECT i.id,i.project_id,i.application_id,i.inventory_kind,i.identity_version,i.semantic_summary,(SELECT jsonb_build_object('display_name',l.display_name,'created_by_user_id',l.created_by_user_id,'updated_by_user_id',l.updated_by_user_id,'created_at',l.created_at,'updated_at',l.updated_at) FROM runtime_behavior_user_labels l WHERE l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest) user_label,i.first_seen_at,i.last_seen_at,i.occurrence_count,(SELECT count(*) FROM runtime_inventory_releases r WHERE r.item_id=i.id) release_count,(SELECT count(DISTINCT s.cluster_id) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) cluster_count,(SELECT count(DISTINCT (s.cluster_id,s.namespace)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) namespace_count,(SELECT count(DISTINCT (s.cluster_id,s.namespace,s.workload_kind,s.workload_name)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) workload_count,(SELECT count(DISTINCT (s.cluster_id,s.pod_uid)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) pod_count,(SELECT count(DISTINCT s.container_name) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) container_count,(SELECT count(*) FROM runtime_inventory_group_links gl WHERE gl.item_id=i.id) group_count FROM runtime_inventory_items i WHERE i.occurrence_count>0 AND i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.identity_version=$4 AND ($5::text IS NULL OR i.inventory_kind=$5) AND ($6::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_releases r WHERE r.item_id=i.id AND r.release_id=$6)) AND ($7::uuid IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.cluster_id=$7)) AND ($8::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.namespace=$8)) AND ($9::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_kind=$9)) AND ($10::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.workload_name=$10)) AND ($11::text IS NULL OR EXISTS(SELECT 1 FROM runtime_inventory_sightings s WHERE s.item_id=i.id AND s.container_name=$11)) AND ($12::timestamptz IS NULL OR i.last_seen_at >= $12) AND ($13::timestamptz IS NULL OR i.first_seen_at <= $13) AND ($14::text IS NULL OR i.semantic_summary->>'operation'=$14) AND ($15::text IS NULL OR concat_ws(' ',i.semantic_summary->>'executable',i.semantic_summary->>'process_command',i.semantic_summary->>'destination_address',i.semantic_summary->>'destination_port',i.semantic_summary->>'local_address',i.semantic_summary->>'local_port',i.semantic_summary->>'name',i.semantic_summary->>'query_type',i.semantic_summary->>'syscall',i.semantic_summary->>'operation',i.semantic_summary->>'path',i.semantic_summary->>'new_path') ILIKE $15 OR EXISTS(SELECT 1 FROM runtime_behavior_user_labels l WHERE l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest AND l.display_name ILIKE $15)) AND ($16::uuid IS NULL OR (i.id=$16 AND i.identity_digest=$17)) AND ($18::text IS NULL OR EXISTS(SELECT 1 FROM runtime_sighting_policy_evaluations e JOIN runtime_policy_states ps ON ps.organization_id=e.organization_id AND ps.project_id=e.project_id AND ps.application_id=e.application_id WHERE e.item_id=i.id AND e.policy_state_version=ps.state_version AND e.evaluator_version=$21 AND e.verdict=$18)) AND ($19::bool IS NULL OR $19=EXISTS(SELECT 1 FROM runtime_inventory_sightings s JOIN runtime_policy_suppressions z ON z.organization_id=s.organization_id AND z.project_id=s.project_id AND z.application_id=s.application_id AND z.identity_version=i.identity_version AND z.identity_digest=i.identity_digest AND z.cancelled_at IS NULL AND z.expires_at>now() AND (cardinality(z.cluster_ids)=0 OR s.cluster_id=ANY(z.cluster_ids)) AND (cardinality(z.namespaces)=0 OR s.namespace=ANY(z.namespaces)) AND (cardinality(z.workload_kinds)=0 OR s.workload_kind=ANY(z.workload_kinds)) AND (cardinality(z.workload_names)=0 OR s.workload_name=ANY(z.workload_names)) WHERE s.item_id=i.id)) AND ($20::bool IS NULL OR $20=EXISTS(SELECT 1 FROM runtime_inventory_sightings s LEFT JOIN runtime_sighting_policy_evaluations e ON e.item_id=s.item_id AND e.cluster_id=s.cluster_id AND e.namespace=s.namespace AND e.workload_kind=s.workload_kind AND e.workload_name=s.workload_name AND e.pod_uid=s.pod_uid AND e.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id WHERE s.item_id=i.id AND (e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$21))) AND ($22::timestamptz IS NULL OR (i.last_seen_at,i.id)<($22,$23)) ORDER BY i.last_seen_at DESC,i.id DESC LIMIT $24")
            .bind(filter.organization_id)
            .bind(filter.project_id)
            .bind(filter.application_id)
            .bind(CURRENT_INVENTORY_IDENTITY_VERSION.get())
            .bind(kind);
        bind_scope(query, filter)
            .bind(identity_item_id)
            .bind(identity_digest)
            .bind(verdict)
            .bind(suppressed)
            .bind(evaluation_pending)
            .bind(crate::policy::POLICY_EVALUATOR_VERSION)
            .bind(cursor_last_seen_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// Sets the display name users gave an inventory item's identity, with
    /// optimistic concurrency: when `expected_updated_at` is given, an
    /// existing label is only replaced if it was last updated then. The label
    /// keeps its update time when the name does not change. `None` when there
    /// is no such item or the expectation failed.
    ///
    /// Selects `display_name`, `created_by_user_id`, `updated_by_user_id`,
    /// `created_at` and `updated_at`.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_user_label<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        display_name: String,
        user_id: Uuid,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("INSERT INTO runtime_behavior_user_labels(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,display_name,created_by_user_id,updated_by_user_id) SELECT gen_random_uuid(),i.organization_id,i.project_id,i.application_id,i.inventory_kind,i.identity_version,i.identity_digest,$5,$6,$6 FROM runtime_inventory_items i WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.id=$4 ON CONFLICT (organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest) DO UPDATE SET display_name=EXCLUDED.display_name,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=CASE WHEN runtime_behavior_user_labels.display_name=EXCLUDED.display_name THEN runtime_behavior_user_labels.updated_at ELSE now() END WHERE $7::timestamptz IS NULL OR runtime_behavior_user_labels.updated_at=$7 RETURNING display_name,created_by_user_id,updated_by_user_id,created_at,updated_at")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(display_name)
            .bind(user_id)
            .bind(expected_updated_at)
            .fetch_optional(executor)
            .await
    }

    /// Deletes the label of an inventory item's identity; with
    /// `expected_updated_at`, only if it was last updated then.
    pub async fn delete_user_label<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        expected_updated_at: Option<DateTime<Utc>>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM runtime_behavior_user_labels l USING runtime_inventory_items i WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.id=$4 AND l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest AND ($5::timestamptz IS NULL OR l.updated_at=$5)")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(expected_updated_at)
            .execute(executor)
            .await
    }

    /// Reports whether the identity of an inventory item has a label.
    pub async fn user_label_exists<'e, E>(executor: E, item_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM runtime_behavior_user_labels l JOIN runtime_inventory_items i ON i.organization_id=l.organization_id AND i.project_id=l.project_id AND i.application_id=l.application_id AND i.inventory_kind=l.inventory_kind AND i.identity_version=l.identity_version AND i.identity_digest=l.identity_digest WHERE i.id=$1)")
            .bind(item_id)
            .fetch_one(executor)
            .await
    }

    /// Reports whether the application has this inventory item under the
    /// current identity version.
    pub async fn exists<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        identity_version: i16,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 AND identity_version=$5)")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(identity_version)
            .fetch_one(executor)
            .await
    }

    /// Resolves an item id used as a list cursor into its
    /// `(last_seen_at, id)` ordering key.
    pub async fn item_cursor<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        identity_version: i16,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT last_seen_at,id FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4 AND identity_version=$5")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(identity_version)
            .fetch_optional(executor)
            .await
    }

    /// One inventory item of the application with the columns of
    /// [`Self::item_page`].
    pub async fn item<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        identity_version: i16,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT i.id,i.project_id,i.application_id,i.inventory_kind,i.identity_version,i.semantic_summary,(SELECT jsonb_build_object('display_name',l.display_name,'created_by_user_id',l.created_by_user_id,'updated_by_user_id',l.updated_by_user_id,'created_at',l.created_at,'updated_at',l.updated_at) FROM runtime_behavior_user_labels l WHERE l.organization_id=i.organization_id AND l.project_id=i.project_id AND l.application_id=i.application_id AND l.inventory_kind=i.inventory_kind AND l.identity_version=i.identity_version AND l.identity_digest=i.identity_digest) user_label,i.first_seen_at,i.last_seen_at,i.occurrence_count,(SELECT count(*) FROM runtime_inventory_releases r WHERE r.item_id=i.id) release_count,(SELECT count(DISTINCT s.cluster_id) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) cluster_count,(SELECT count(DISTINCT (s.cluster_id,s.namespace)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) namespace_count,(SELECT count(DISTINCT (s.cluster_id,s.namespace,s.workload_kind,s.workload_name)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) workload_count,(SELECT count(DISTINCT (s.cluster_id,s.pod_uid)) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) pod_count,(SELECT count(DISTINCT s.container_name) FROM runtime_inventory_sightings s WHERE s.item_id=i.id) container_count,(SELECT count(*) FROM runtime_inventory_group_links gl WHERE gl.item_id=i.id) group_count FROM runtime_inventory_items i WHERE i.organization_id=$1 AND i.project_id=$2 AND i.application_id=$3 AND i.id=$4 AND i.identity_version=$5")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(identity_version)
            .fetch_optional(executor)
            .await
    }

    /// Summarises the policy evaluations of an item's sightings: how many
    /// placements there are, how many await evaluation, and how many hold
    /// each current verdict.
    pub async fn placement_summary<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        evaluator_version: i16,
    ) -> Result<Value, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Value>("SELECT jsonb_build_object('placement_count',count(*),'evaluation_pending',count(*) FILTER (WHERE e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$5),'verdicts',jsonb_build_object('expected',count(*) FILTER (WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$5 AND e.verdict='expected'),'requires_review',count(*) FILTER (WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$5 AND e.verdict='requires_review'),'policy_conflict',count(*) FILTER (WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$5 AND e.verdict='policy_conflict'),'unclassified',count(*) FILTER (WHERE e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$5 AND e.verdict='unclassified'))) FROM runtime_inventory_sightings s LEFT JOIN runtime_sighting_policy_evaluations e ON e.item_id=s.item_id AND e.cluster_id=s.cluster_id AND e.namespace=s.namespace AND e.workload_kind=s.workload_kind AND e.workload_name=s.workload_name AND e.pod_uid=s.pod_uid AND e.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id WHERE s.organization_id=$1 AND s.project_id=$2 AND s.application_id=$3 AND s.item_id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(evaluator_version)
            .fetch_one(executor)
            .await
    }

    /// A page of the application's releases, newest deployment first, after
    /// the cursor when one is given, each with whether the item was observed
    /// in it: `observed`, `not_observed` when the release has events but not
    /// this item, or `unknown` when its history has expired or it has none.
    ///
    /// Selects `release_id`, `release_display_name`, `version`, `deployed_at`,
    /// `presence`, `occurrence_count`, `first_seen_at`, `last_seen_at` and
    /// `release_evidence_count`.
    #[allow(clippy::too_many_arguments)]
    pub async fn release_presence_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        cursor_deployed_at: Option<DateTime<Utc>>,
        cursor_release_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT r.id release_id,release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) release_display_name,r.version,r.deployed_at,CASE WHEN ir.release_id IS NOT NULL AND ir.occurrence_count>0 THEN 'observed' WHEN EXISTS(SELECT 1 FROM projects p WHERE p.id=r.project_id AND r.deployed_at<p.runtime_closed_before) THEN 'unknown' WHEN EXISTS(SELECT 1 FROM runtime_events e WHERE e.organization_id=r.organization_id AND e.project_id=r.project_id AND e.application_id=r.application_id AND e.release_id=r.id) THEN 'not_observed' ELSE 'unknown' END presence,ir.occurrence_count,ir.first_seen_at,ir.last_seen_at,(SELECT count(*) FROM runtime_events e WHERE e.organization_id=r.organization_id AND e.project_id=r.project_id AND e.application_id=r.application_id AND e.release_id=r.id) release_evidence_count FROM releases r JOIN applications a ON a.id=r.application_id LEFT JOIN runtime_inventory_releases ir ON ir.release_id=r.id AND ir.item_id=$4 WHERE r.organization_id=$1 AND r.project_id=$2 AND r.application_id=$3 AND ($5::timestamptz IS NULL OR (r.deployed_at,r.id)<($5,$6)) ORDER BY r.deployed_at DESC,r.id DESC LIMIT $7")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(cursor_deployed_at)
            .bind(cursor_release_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// A page of an item's sightings, most recent first, after the cursor
    /// when one is given, each with its policy evaluation and the active
    /// suppression covering it.
    ///
    /// Selects the sighting's placement, `occurrence_count`, `first_seen_at`
    /// and `last_seen_at`, and `policy_evaluation`, `active_suppression` and
    /// `actionable`.
    #[allow(clippy::too_many_arguments)]
    pub async fn sighting_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        cursor_last_seen_at: Option<DateTime<Utc>>,
        cursor_cluster_id: Option<Uuid>,
        cursor_namespace: Option<&str>,
        cursor_workload_kind: Option<&str>,
        cursor_workload_name: Option<&str>,
        cursor_pod_uid: Option<&str>,
        cursor_container_name: Option<&str>,
        fetch_limit: i64,
        evaluator_version: i16,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT s.cluster_id,s.namespace,s.workload_kind,s.workload_name,s.pod_uid,s.pod_name,s.container_name,s.occurrence_count,s.first_seen_at,s.last_seen_at,jsonb_build_object('state',CASE WHEN e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$13 THEN 'evaluation_pending' ELSE 'current' END,'verdict',CASE WHEN e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$13 THEN NULL ELSE e.verdict END,'reason_code',CASE WHEN e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$13 THEN 'evaluation_pending' ELSE e.reason_code END,'winning_revision_id',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$13 THEN e.winning_revision_id END,'explanation',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$13 THEN e.explanation ELSE '{}'::jsonb END,'evaluated_at',CASE WHEN e.policy_state_version=COALESCE(ps.state_version,0) AND e.evaluator_version=$13 THEN e.evaluated_at END) policy_evaluation,x.summary active_suppression,(x.summary IS NULL AND (e.item_id IS NULL OR e.policy_state_version<>COALESCE(ps.state_version,0) OR e.evaluator_version<>$13 OR e.verdict<>'expected')) actionable FROM runtime_inventory_sightings s LEFT JOIN runtime_sighting_policy_evaluations e ON e.item_id=s.item_id AND e.cluster_id=s.cluster_id AND e.namespace=s.namespace AND e.workload_kind=s.workload_kind AND e.workload_name=s.workload_name AND e.pod_uid=s.pod_uid AND e.container_name=s.container_name LEFT JOIN runtime_policy_states ps ON ps.organization_id=s.organization_id AND ps.project_id=s.project_id AND ps.application_id=s.application_id LEFT JOIN runtime_inventory_items i ON i.id=s.item_id LEFT JOIN LATERAL (SELECT jsonb_build_object('id',z.id,'reason',z.reason,'expires_at',z.expires_at,'created_at',z.created_at) summary FROM runtime_policy_suppressions z WHERE z.organization_id=s.organization_id AND z.project_id=s.project_id AND z.application_id=s.application_id AND z.identity_version=i.identity_version AND z.identity_digest=i.identity_digest AND z.cancelled_at IS NULL AND z.expires_at>now() AND (cardinality(z.cluster_ids)=0 OR s.cluster_id=ANY(z.cluster_ids)) AND (cardinality(z.namespaces)=0 OR s.namespace=ANY(z.namespaces)) AND (cardinality(z.workload_kinds)=0 OR s.workload_kind=ANY(z.workload_kinds)) AND (cardinality(z.workload_names)=0 OR s.workload_name=ANY(z.workload_names)) ORDER BY z.expires_at,z.id LIMIT 1) x ON true WHERE s.organization_id=$1 AND s.project_id=$2 AND s.application_id=$3 AND s.item_id=$4 AND ($5::timestamptz IS NULL OR (s.last_seen_at,s.cluster_id,s.namespace,s.workload_kind,s.workload_name,s.pod_uid,s.container_name)<($5,$6,$7,$8,$9,$10,$11)) ORDER BY s.last_seen_at DESC,s.cluster_id DESC,s.namespace DESC,s.workload_kind DESC,s.workload_name DESC,s.pod_uid DESC,s.container_name DESC LIMIT $12")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(cursor_last_seen_at)
            .bind(cursor_cluster_id)
            .bind(cursor_namespace)
            .bind(cursor_workload_kind)
            .bind(cursor_workload_name)
            .bind(cursor_pod_uid)
            .bind(cursor_container_name)
            .bind(fetch_limit)
            .bind(evaluator_version)
            .fetch_all(executor)
            .await
    }

    /// A page of the runtime groups an item is linked to, newest id first,
    /// before the cursor when one is given, with every label on each group.
    ///
    /// Selects `id`, `cluster_id`, `namespace`, `workload_kind`,
    /// `workload_name`, `event_kind`, `user_labels`, `status`,
    /// `first_seen_at`, `last_seen_at` and `occurrence_count`.
    pub async fn group_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT g.id,g.cluster_id,g.namespace,g.workload_kind,g.workload_name,g.event_kind,COALESCE((SELECT jsonb_agg(jsonb_build_object('display_name',ul.display_name,'created_by_user_id',ul.created_by_user_id,'updated_by_user_id',ul.updated_by_user_id,'created_at',ul.created_at,'updated_at',ul.updated_at) ORDER BY ul.display_name,ul.id) FROM runtime_inventory_group_links x JOIN runtime_inventory_items xi ON xi.id=x.item_id JOIN runtime_behavior_user_labels ul ON ul.organization_id=xi.organization_id AND ul.project_id=xi.project_id AND ul.application_id=xi.application_id AND ul.inventory_kind=xi.inventory_kind AND ul.identity_version=xi.identity_version AND ul.identity_digest=xi.identity_digest WHERE x.group_id=g.id),'[]'::jsonb) user_labels,g.status,g.first_seen_at,g.last_seen_at,g.occurrence_count FROM runtime_inventory_group_links l JOIN runtime_event_groups g ON g.id=l.group_id WHERE l.organization_id=$1 AND l.project_id=$2 AND l.application_id=$3 AND l.item_id=$4 AND ($5::uuid IS NULL OR g.id<$5) ORDER BY g.id DESC LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// Resolves an event id used as an occurrence cursor into its
    /// `(observed_at, id)` ordering key, when the event is an occurrence of
    /// the item.
    pub async fn occurrence_cursor<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (DateTime<Utc>, Uuid)>("SELECT e.observed_at,e.id FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.organization_id=$1 AND m.project_id=$2 AND m.application_id=$3 AND m.item_id=$4 AND e.id=$5")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(event_id)
            .fetch_optional(executor)
            .await
    }

    /// A page of an item's occurrences, newest first, after the cursor when
    /// one is given, with their release.
    ///
    /// Selects the event's `id`, `event_id`, `observed_at`, placement,
    /// `process_command`, `event_kind`, `payload` and `release_id`, and
    /// `release_version` and `release_display_name`.
    #[allow(clippy::too_many_arguments)]
    pub async fn occurrence_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        identity_version: i16,
        cursor_observed_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.observed_at,e.cluster_id,e.node_name,e.namespace,e.pod_uid,e.pod_name,e.container_name,e.process_command,e.event_kind,e.payload,e.release_id,r.version release_version,CASE WHEN r.id IS NULL THEN 'Unattributed' ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id LEFT JOIN releases r ON r.id=e.release_id LEFT JOIN applications a ON a.id=r.application_id WHERE m.organization_id=$1 AND m.project_id=$2 AND m.application_id=$3 AND m.item_id=$4 AND m.identity_version=$5 AND ($6::timestamptz IS NULL OR (e.observed_at,e.id)<($6,$7)) ORDER BY e.observed_at DESC,e.id DESC LIMIT $8")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(identity_version)
            .bind(cursor_observed_at)
            .bind(cursor_id)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// One inventory item of the application with its identity.
    ///
    /// Selects `id`, `inventory_kind`, `identity_version`, `identity_digest`
    /// and `semantic_summary`.
    pub async fn identity<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,inventory_kind,identity_version,identity_digest,semantic_summary FROM runtime_inventory_items WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND id=$4")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .fetch_optional(executor)
            .await
    }

    /// The inventory identity behind a runtime group of the application,
    /// with the group's placement. A group linked to several items yields the
    /// one with the lowest id.
    ///
    /// Selects `item_id`, `inventory_kind`, `identity_version`,
    /// `identity_digest`, `semantic_summary`, `cluster_id`, `namespace`,
    /// `workload_kind` and `workload_name`.
    pub async fn group_seed<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        group_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT i.id item_id,i.inventory_kind,i.identity_version,i.identity_digest,i.semantic_summary,g.cluster_id,g.namespace,g.workload_kind,g.workload_name FROM runtime_event_groups g JOIN runtime_inventory_group_links l ON l.organization_id=g.organization_id AND l.project_id=g.project_id AND l.application_id=g.application_id AND l.group_id=g.id JOIN runtime_inventory_items i ON i.organization_id=l.organization_id AND i.project_id=l.project_id AND i.application_id=l.application_id AND i.id=l.item_id WHERE g.organization_id=$1 AND g.project_id=$2 AND g.application_id=$3 AND g.id=$4 ORDER BY i.id LIMIT 1")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(group_id)
            .fetch_optional(executor)
            .await
    }

    /// Reports whether an inventory item of the application is linked to the
    /// runtime group.
    pub async fn item_linked_to_group<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        item_id: Uuid,
        group_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM runtime_inventory_group_links WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND item_id=$4 AND group_id=$5)")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(item_id)
            .bind(group_id)
            .fetch_one(executor)
            .await
    }

    /// How many runtime groups an inventory item is linked to.
    pub async fn linked_group_count<'e, E>(executor: E, item_id: Uuid) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM runtime_inventory_group_links WHERE item_id=$1",
        )
        .bind(item_id)
        .fetch_one(executor)
        .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, SubsecRound, Utc};
    use event_model::DnsQueryType;
    use serde_json::Value;
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::{FacetColumn, InventoryFilter, InventoryRepository};
    use crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION;
    use crate::repository::test_support::{
        Tenant, dns, exec, exec_in_release, group_ids, ingest, manual_release, tenant, user,
    };

    #[derive(Debug, FromRow)]
    struct Label {
        display_name: String,
        updated_at: DateTime<Utc>,
    }

    #[derive(Debug, FromRow)]
    struct Item {
        id: Uuid,
        inventory_kind: String,
        last_seen_at: DateTime<Utc>,
        occurrence_count: i64,
        release_count: i64,
        pod_count: i64,
        group_count: i64,
        user_label: Option<Value>,
    }

    #[derive(Debug, FromRow)]
    struct KindAggregate {
        kind: String,
        item_count: i64,
        occurrence_count: i64,
    }

    #[derive(Debug, FromRow)]
    struct Distribution {
        id: Uuid,
        identity_digest: Vec<u8>,
        occurrence_count: i64,
        total_item_count: i64,
        total_occurrence_count: i64,
    }

    #[derive(Debug, FromRow, PartialEq)]
    struct FacetOption {
        value: String,
        label: String,
        item_count: i64,
        occurrence_count: i64,
    }

    #[derive(Debug, FromRow)]
    struct ReleasePresence {
        release_id: Uuid,
        presence: String,
        occurrence_count: Option<i64>,
    }

    #[derive(Debug, FromRow)]
    struct Sighting {
        cluster_id: Uuid,
        namespace: String,
        workload_kind: String,
        workload_name: String,
        pod_uid: String,
        container_name: String,
        last_seen_at: DateTime<Utc>,
        policy_evaluation: Value,
        actionable: bool,
    }

    #[derive(Debug, FromRow)]
    struct Group {
        id: Uuid,
        event_kind: String,
    }

    #[derive(Debug, FromRow)]
    struct Occurrence {
        id: Uuid,
        observed_at: DateTime<Utc>,
        release_display_name: String,
    }

    fn filter(own: &Tenant) -> InventoryFilter<'static> {
        InventoryFilter {
            organization_id: own.organization_id,
            project_id: own.project_id,
            application_id: own.application_id,
            release_id: None,
            cluster_id: None,
            namespace: None,
            workload_kind: None,
            workload_name: None,
            container_name: None,
            observed_from: None,
            observed_to: None,
            operation: None,
            search: None,
        }
    }

    /// Ingests `/bin/a` twice from two pods, `/bin/b` once and one DNS
    /// lookup, a minute apart and oldest first, and returns the item ids of
    /// `/bin/a` and `/bin/b`.
    async fn seed(pool: &PgPool, own: &Tenant) -> (Uuid, Uuid) {
        let base = (Utc::now() - Duration::hours(1)).trunc_subsecs(0);
        let mut lookup = dns(own, "example.com", DnsQueryType::A, "app");
        lookup.observed_at = base + Duration::minutes(3);
        ingest(
            pool,
            own,
            &[
                exec(own, "/bin/a", base),
                exec(own, "/bin/a", base + Duration::minutes(1)),
                exec(own, "/bin/b", base + Duration::minutes(2)),
                lookup,
            ],
        )
        .await;
        let item = |executable: &'static str| async move {
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM runtime_inventory_items WHERE application_id=$1 AND semantic_summary->>'executable'=$2",
            )
            .bind(own.application_id)
            .bind(executable)
            .fetch_one(pool)
            .await
            .unwrap()
        };
        (item("/bin/a").await, item("/bin/b").await)
    }

    async fn page(pool: &PgPool, filter: InventoryFilter<'_>, kind: Option<&str>) -> Vec<Item> {
        InventoryRepository::item_page(
            pool, filter, kind, None, None, None, None, None, None, None, 10,
        )
        .await
        .unwrap()
    }

    fn ids(items: &[Item]) -> Vec<Uuid> {
        items.iter().map(|i| i.id).collect()
    }

    /// A label is set on an item's identity with optimistic concurrency,
    /// keeps its update time when the name is unchanged, and is deleted the
    /// same way.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn labels_follow_the_identity(pool: PgPool) {
        let own = tenant(&pool, "inventory-labels").await;
        let (a, _) = seed(&pool, &own).await;
        let actor = user(&pool).await;
        let put = |name: &'static str, expected: Option<DateTime<Utc>>| {
            let pool = pool.clone();
            async move {
                InventoryRepository::put_user_label::<_, Label>(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    a,
                    name.into(),
                    actor,
                    expected,
                )
                .await
                .unwrap()
            }
        };
        let created = put("Shell", None).await.unwrap();
        assert_eq!(created.display_name, "Shell");
        let same = put("Shell", Some(created.updated_at)).await.unwrap();
        assert_eq!(
            same.updated_at, created.updated_at,
            "an unchanged name keeps its time"
        );
        let stale = created.updated_at - Duration::seconds(1);
        assert!(
            put("Other", Some(stale)).await.is_none(),
            "a stale expectation fails"
        );
        let item: Option<Item> = InventoryRepository::item(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            a,
            CURRENT_INVENTORY_IDENTITY_VERSION.get(),
        )
        .await
        .unwrap();
        assert_eq!(item.unwrap().user_label.unwrap()["display_name"], "Shell");

        let delete = |expected: Option<DateTime<Utc>>| {
            InventoryRepository::delete_user_label(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                a,
                expected,
            )
        };
        assert_eq!(delete(Some(stale)).await.unwrap().rows_affected(), 0);
        assert!(
            InventoryRepository::user_label_exists(&pool, a)
                .await
                .unwrap()
        );
        assert_eq!(delete(None).await.unwrap().rows_affected(), 1);
        assert!(
            !InventoryRepository::user_label_exists(&pool, a)
                .await
                .unwrap()
        );

        let other = tenant(&pool, "inventory-labels-other").await;
        let foreign: Option<Label> = InventoryRepository::put_user_label(
            &pool,
            other.organization_id,
            other.project_id,
            other.application_id,
            a,
            "Shell".into(),
            actor,
            None,
        )
        .await
        .unwrap();
        assert!(
            foreign.is_none(),
            "another application's item is not labelled"
        );
    }

    /// Items page by last sighting after a cursor, narrowed by kind, search,
    /// scope, identity and policy filters; single reads resolve within the
    /// application and identity version.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn items_page_filter_and_resolve(pool: PgPool) {
        let own = tenant(&pool, "inventory-items").await;
        let (a, b) = seed(&pool, &own).await;
        let all = page(&pool, filter(&own), None).await;
        assert_eq!(all.len(), 3);
        assert!(
            all.windows(2)
                .all(|w| w[0].last_seen_at >= w[1].last_seen_at)
        );
        assert_eq!(
            ids(&page(&pool, filter(&own), Some("process")).await),
            [b, a]
        );
        let searched = InventoryFilter {
            search: Some("%/bin/b%"),
            ..filter(&own)
        };
        assert_eq!(ids(&page(&pool, searched, None).await), [b]);
        let elsewhere = InventoryFilter {
            namespace: Some("staging"),
            ..filter(&own)
        };
        assert!(page(&pool, elsewhere, None).await.is_empty());
        let here = InventoryFilter {
            namespace: Some("production"),
            workload_kind: Some("Deployment"),
            workload_name: Some("app"),
            container_name: Some("app"),
            cluster_id: Some(own.cluster_id),
            ..filter(&own)
        };
        assert_eq!(page(&pool, here, None).await.len(), 3);

        let digest: Vec<u8> =
            sqlx::query_scalar("SELECT identity_digest FROM runtime_inventory_items WHERE id=$1")
                .bind(a)
                .fetch_one(&pool)
                .await
                .unwrap();
        let narrowed = |digest: Vec<u8>| {
            let pool = pool.clone();
            async move {
                InventoryRepository::item_page::<_, Item>(
                    &pool,
                    filter(&own),
                    None,
                    Some(a),
                    Some(digest),
                    None,
                    None,
                    None,
                    None,
                    None,
                    10,
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(ids(&narrowed(digest).await), [a]);
        assert!(
            narrowed(vec![0; 32]).await.is_empty(),
            "the digest must match too"
        );
        let by_policy = |verdict: Option<&'static str>, suppressed: Option<bool>| {
            let pool = pool.clone();
            async move {
                InventoryRepository::item_page::<_, Item>(
                    &pool,
                    filter(&own),
                    None,
                    None,
                    None,
                    verdict,
                    suppressed,
                    None,
                    None,
                    None,
                    10,
                )
                .await
                .unwrap()
                .len()
            }
        };
        assert_eq!(by_policy(Some("expected"), None).await, 0);
        assert_eq!(by_policy(None, Some(false)).await, 3);
        assert_eq!(by_policy(None, Some(true)).await, 0);

        let (last_seen_at, cursor_id) = InventoryRepository::item_cursor(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            all[0].id,
            CURRENT_INVENTORY_IDENTITY_VERSION.get(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!((last_seen_at, cursor_id), (all[0].last_seen_at, all[0].id));
        let after: Vec<Item> = InventoryRepository::item_page(
            &pool,
            filter(&own),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(last_seen_at),
            Some(cursor_id),
            10,
        )
        .await
        .unwrap();
        assert_eq!(ids(&after), ids(&all[1..]));

        let one: Item = InventoryRepository::item(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            a,
            CURRENT_INVENTORY_IDENTITY_VERSION.get(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (
                one.inventory_kind.as_str(),
                one.occurrence_count,
                one.pod_count,
                one.group_count,
                one.release_count
            ),
            ("process", 2, 2, 1, 0)
        );
        let exists = |version: i16| {
            InventoryRepository::exists(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                a,
                version,
            )
        };
        assert!(
            exists(CURRENT_INVENTORY_IDENTITY_VERSION.get())
                .await
                .unwrap()
        );
        assert!(
            !exists(CURRENT_INVENTORY_IDENTITY_VERSION.get() + 1)
                .await
                .unwrap()
        );
    }

    /// Aggregates count items and occurrences per kind, rank the largest items
    /// of a kind, and group sightings into facet values.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn aggregates_summarise_by_kind_and_facet(pool: PgPool) {
        let own = tenant(&pool, "inventory-aggregates").await;
        let (a, _) = seed(&pool, &own).await;
        let mut kinds: Vec<KindAggregate> = InventoryRepository::kind_summary(&pool, filter(&own))
            .await
            .unwrap();
        kinds.sort_by(|x, y| x.kind.cmp(&y.kind));
        assert_eq!(
            kinds
                .iter()
                .map(|k| (k.kind.as_str(), k.item_count, k.occurrence_count))
                .collect::<Vec<_>>(),
            [("domain", 1, 1), ("process", 2, 3)]
        );

        let top: Vec<Distribution> =
            InventoryRepository::distribution(&pool, filter(&own), "process", 1)
                .await
                .unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(
            (
                top[0].id,
                top[0].occurrence_count,
                top[0].total_item_count,
                top[0].total_occurrence_count
            ),
            (a, 2, 2, 3)
        );
        assert_eq!(top[0].identity_digest.len(), 32);

        let facet = |column: FacetColumn,
                     facet_search: Option<&'static str>,
                     cursor: Option<(i64, &'static str, &'static str)>| {
            let pool = pool.clone();
            async move {
                InventoryRepository::facet_options::<_, FacetOption>(
                    &pool,
                    column,
                    filter(&own),
                    None,
                    facet_search,
                    cursor.map(|c| c.0),
                    cursor.map(|c| c.1),
                    cursor.map(|c| c.2),
                    10,
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(
            facet(FacetColumn::Namespace, None, None).await,
            [FacetOption {
                value: "production".into(),
                label: "production".into(),
                item_count: 3,
                occurrence_count: 4,
            }]
        );
        let clusters = facet(FacetColumn::Cluster, None, None).await;
        assert_eq!(
            (clusters[0].value.clone(), clusters[0].label.as_str()),
            (own.cluster_id.to_string(), "Cluster")
        );
        assert!(
            facet(FacetColumn::Namespace, Some("%staging%"), None)
                .await
                .is_empty()
        );
        assert!(
            facet(
                FacetColumn::Namespace,
                None,
                Some((3, "production", "production"))
            )
            .await
            .is_empty(),
            "nothing sorts after the only value"
        );
        let workloads = facet(FacetColumn::WorkloadName, None, None).await;
        assert_eq!(workloads[0].value, "app");
    }

    /// An item's detail reads: its placements' policy summary, its presence
    /// per release, and its sightings, groups and occurrences, each paging
    /// after a cursor.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn item_detail_reads(pool: PgPool) {
        let own = tenant(&pool, "inventory-detail").await;
        let (a, _) = seed(&pool, &own).await;
        let summary = InventoryRepository::placement_summary(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            a,
            crate::policy::POLICY_EVALUATOR_VERSION,
        )
        .await
        .unwrap();
        assert_eq!(summary["placement_count"], 2);

        let release = manual_release(&pool, &own, "v1", Utc::now() - Duration::days(1)).await;
        let quiet = manual_release(&pool, &own, "v2", Utc::now() - Duration::hours(2)).await;
        ingest(
            &pool,
            &own,
            &[exec_in_release(&own, "/bin/a", "v1", Utc::now())],
        )
        .await;
        let presence: Vec<ReleasePresence> = InventoryRepository::release_presence_page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            a,
            None,
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(
            presence
                .iter()
                .map(|p| (p.release_id, p.presence.as_str(), p.occurrence_count))
                .collect::<Vec<_>>(),
            [(quiet, "unknown", None), (release, "observed", Some(1))],
            "newest deployment first; a release without events is unknown"
        );

        let sightings = |cursor: Option<&Sighting>, limit: i64| {
            let pool = pool.clone();
            let cursor = cursor.map(|s| {
                (
                    s.last_seen_at,
                    s.cluster_id,
                    s.namespace.clone(),
                    s.workload_kind.clone(),
                    s.workload_name.clone(),
                    s.pod_uid.clone(),
                    s.container_name.clone(),
                )
            });
            async move {
                InventoryRepository::sighting_page::<_, Sighting>(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    a,
                    cursor.as_ref().map(|c| c.0),
                    cursor.as_ref().map(|c| c.1),
                    cursor.as_ref().map(|c| c.2.as_str()),
                    cursor.as_ref().map(|c| c.3.as_str()),
                    cursor.as_ref().map(|c| c.4.as_str()),
                    cursor.as_ref().map(|c| c.5.as_str()),
                    cursor.as_ref().map(|c| c.6.as_str()),
                    limit,
                    crate::policy::POLICY_EVALUATOR_VERSION,
                )
                .await
                .unwrap()
            }
        };
        let all = sightings(None, 10).await;
        assert_eq!(all.len(), 3, "two pods plus the release's pod");
        assert!(
            all.windows(2)
                .all(|w| w[0].last_seen_at >= w[1].last_seen_at)
        );
        assert!(
            all.iter()
                .all(|s| s.policy_evaluation.get("state").is_some())
        );
        assert!(all.iter().all(|s| s.actionable), "nothing is expected yet");
        let first = sightings(None, 1).await;
        let rest = sightings(Some(&first[0]), 10).await;
        assert_eq!(
            first
                .iter()
                .chain(&rest)
                .map(|s| s.pod_uid.clone())
                .collect::<Vec<_>>(),
            all.iter().map(|s| s.pod_uid.clone()).collect::<Vec<_>>()
        );

        let groups: Vec<Group> = InventoryRepository::group_page(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            a,
            None,
            10,
        )
        .await
        .unwrap();
        let expected_groups: Vec<Uuid> = group_ids(&pool, &own).await;
        assert_eq!(groups.len(), 1);
        assert!(expected_groups.contains(&groups[0].id));
        assert_eq!(groups[0].event_kind, "process.exec");

        let occurrences = |cursor: Option<(DateTime<Utc>, Uuid)>| {
            let pool = pool.clone();
            async move {
                InventoryRepository::occurrence_page::<_, Occurrence>(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    a,
                    CURRENT_INVENTORY_IDENTITY_VERSION.get(),
                    cursor.map(|c| c.0),
                    cursor.map(|c| c.1),
                    10,
                )
                .await
                .unwrap()
            }
        };
        let all = occurrences(None).await;
        assert_eq!(all.len(), 3);
        assert!(all.windows(2).all(|w| w[0].observed_at >= w[1].observed_at));
        assert_eq!(all[0].release_display_name, "v1", "the newest ran in v1");
        assert_eq!(all[2].release_display_name, "Unattributed");
        let cursor = InventoryRepository::occurrence_cursor(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            a,
            all[0].id,
        )
        .await
        .unwrap();
        assert_eq!(cursor, Some((all[0].observed_at, all[0].id)));
        assert_eq!(
            occurrences(cursor)
                .await
                .iter()
                .map(|o| o.id)
                .collect::<Vec<_>>(),
            all[1..].iter().map(|o| o.id).collect::<Vec<_>>()
        );
        assert_eq!(
            InventoryRepository::occurrence_cursor(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                a,
                Uuid::new_v4(),
            )
            .await
            .unwrap(),
            None
        );
    }
}
