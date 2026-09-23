//! Runtime retention: each project's effective retention policy and horizons,
//! and the compaction pass that folds closed raw events into daily history
//! snapshots, recounts the groups and inventory items they belonged to, and
//! expires history past its window.
//!
//! The pass runs inside one transaction holding the project lock; several
//! methods issue more than one statement and take `&mut PgConnection` for
//! that reason.

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{PgConnection, PgExecutor};
use uuid::Uuid;

/// Runtime retention policy and compaction.
#[derive(Clone, Copy, Debug)]
pub struct RuntimeRetentionRepository;

impl RuntimeRetentionRepository {
    /// The project's closed and history-expired horizons.
    ///
    /// Selects `closed_before` and `history_expired_before`.
    pub async fn coverage<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<T, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT runtime_closed_before closed_before,runtime_history_expired_before history_expired_before FROM projects WHERE organization_id=$1 AND id=$2")
            .bind(organization_id)
            .bind(project_id)
            .fetch_one(executor)
            .await
    }

    /// A page of a group's daily history snapshots, newest day first,
    /// optionally within `[day_from, day_to)` and for one release, after the
    /// cursor when one is given.
    ///
    /// Selects `id`, `group_id`, `release_id`, `day`, `format_version`,
    /// `occurrence_count`, `first_observed_at` and `last_observed_at`.
    #[allow(clippy::too_many_arguments)]
    pub async fn snapshot_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        group_id: Uuid,
        day_from: Option<NaiveDate>,
        day_to: Option<NaiveDate>,
        release_id: Option<Uuid>,
        cursor: Option<Uuid>,
        fetch_limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT id,group_id,release_id,day,format_version,occurrence_count,first_observed_at,last_observed_at FROM runtime_history_snapshots WHERE organization_id=$1 AND group_id=$2 AND ($3::date IS NULL OR day >= $3) AND ($4::date IS NULL OR day < $4) AND ($5::uuid IS NULL OR release_id=$5) AND ($6::uuid IS NULL OR (day,id)<(SELECT day,id FROM runtime_history_snapshots WHERE id=$6 AND organization_id=$1 AND group_id=$2)) ORDER BY day DESC,id DESC LIMIT $7")
            .bind(organization_id)
            .bind(group_id)
            .bind(day_from)
            .bind(day_to)
            .bind(release_id)
            .bind(cursor)
            .bind(fetch_limit)
            .fetch_all(executor)
            .await
    }

    /// The organization's retention policy.
    ///
    /// Selects `enabled`, `raw_days` and `history_days`.
    pub async fn organization_policy<'e, E, T>(
        executor: E,
        organization_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT runtime_retention_enabled enabled,runtime_retention_raw_days raw_days,runtime_retention_history_days history_days FROM organizations WHERE id=$1")
            .bind(organization_id)
            .fetch_optional(executor)
            .await
    }

    /// The project's retention override and the organization's policy it
    /// inherits otherwise.
    ///
    /// Selects `override_enabled`, `override_raw_days`,
    /// `override_history_days`, and the organization's `enabled`, `raw_days`
    /// and `history_days`.
    pub async fn project_policy<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT p.runtime_retention_enabled override_enabled,p.runtime_retention_raw_days override_raw_days,p.runtime_retention_history_days override_history_days,o.runtime_retention_enabled enabled,o.runtime_retention_raw_days raw_days,o.runtime_retention_history_days history_days FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.organization_id=$1 AND p.id=$2")
            .bind(organization_id)
            .bind(project_id)
            .fetch_optional(executor)
            .await
    }

    /// Sets the organization's retention policy.
    pub async fn set_organization_policy<'e, E>(
        executor: E,
        organization_id: Uuid,
        enabled: bool,
        raw_days: i32,
        history_days: Option<i32>,
        updated_by: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE organizations SET runtime_retention_enabled=$2,runtime_retention_raw_days=$3,runtime_retention_history_days=$4,runtime_retention_updated_at=now(),runtime_retention_updated_by=$5 WHERE id=$1")
            .bind(organization_id)
            .bind(enabled)
            .bind(raw_days)
            .bind(history_days)
            .bind(updated_by)
            .execute(executor)
            .await
    }

    /// Sets the project's retention override, or clears it with `None`s.
    pub async fn set_project_override<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        enabled: Option<bool>,
        raw_days: Option<i32>,
        history_days: Option<i32>,
        updated_by: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE projects SET runtime_retention_enabled=$3,runtime_retention_raw_days=$4,runtime_retention_history_days=$5,runtime_retention_updated_at=now(),runtime_retention_updated_by=$6 WHERE organization_id=$1 AND id=$2")
            .bind(organization_id)
            .bind(project_id)
            .bind(enabled)
            .bind(raw_days)
            .bind(history_days)
            .bind(updated_by)
            .execute(executor)
            .await
    }

    /// Folds the events into daily history snapshots per group and day, and
    /// per release when `released`, adding to existing snapshots. With an
    /// `expired_before` horizon, days already past it are skipped.
    pub async fn fold_into_history_snapshots(
        conn: &mut PgConnection,
        event_ids: &[Uuid],
        expired_before: Option<DateTime<Utc>>,
        released: bool,
    ) -> Result<(), sqlx::Error> {
        let conflict = if released {
            "(group_id,release_id,day,format_version) WHERE release_id IS NOT NULL"
        } else {
            "(group_id,day,format_version) WHERE release_id IS NULL"
        };
        let query = format!(
            "INSERT INTO runtime_history_snapshots(id,organization_id,project_id,application_id,group_id,release_id,day,occurrence_count,first_observed_at,last_observed_at) SELECT gen_random_uuid(),m.organization_id,m.project_id,m.application_id,m.group_id,m.release_id,(e.observed_at AT TIME ZONE 'UTC')::date,count(*),min(e.observed_at),max(e.observed_at) FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE e.id=ANY($1) AND ($2::timestamptz IS NULL OR e.observed_at >= $2) AND (m.release_id IS NOT NULL)=$3 GROUP BY m.organization_id,m.project_id,m.application_id,m.group_id,m.release_id,(e.observed_at AT TIME ZONE 'UTC')::date ON CONFLICT {conflict} DO UPDATE SET occurrence_count=runtime_history_snapshots.occurrence_count+EXCLUDED.occurrence_count,first_observed_at=LEAST(runtime_history_snapshots.first_observed_at,EXCLUDED.first_observed_at),last_observed_at=GREATEST(runtime_history_snapshots.last_observed_at,EXCLUDED.last_observed_at)"
        );
        sqlx::query(&query)
            .bind(event_ids)
            .bind(expired_before)
            .bind(released)
            .execute(&mut *conn)
            .await?;
        Ok(())
    }

    /// Clears every reference to the events as a group's representative or
    /// first-seen event, or a per-release rollup's representative, before the
    /// events are deleted.
    pub async fn detach_events(
        conn: &mut PgConnection,
        event_ids: &[Uuid],
    ) -> Result<(), sqlx::Error> {
        for query in [
            "UPDATE runtime_event_groups SET representative_event_id=NULL WHERE representative_event_id=ANY($1)",
            "UPDATE runtime_event_groups SET first_seen_event_id=NULL WHERE first_seen_event_id=ANY($1)",
            "UPDATE runtime_event_group_releases SET representative_event_id=NULL WHERE representative_event_id=ANY($1)",
        ] {
            sqlx::query(query)
                .bind(event_ids)
                .execute(&mut *conn)
                .await?;
        }
        Ok(())
    }

    /// Deletes an item's per-release presence, sightings and group links, to
    /// be rebuilt from its remaining raw events.
    pub async fn clear_item_projections(
        conn: &mut PgConnection,
        item_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        for table in [
            "runtime_inventory_releases",
            "runtime_inventory_sightings",
            "runtime_inventory_group_links",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE item_id=$1"))
                .bind(item_id)
                .execute(&mut *conn)
                .await?;
        }
        Ok(())
    }

    /// The next 32 projects by id after `cursor`, with their organization,
    /// for one retention tick.
    pub async fn project_page<'e, E>(
        executor: E,
        cursor: Uuid,
    ) -> Result<Vec<(Uuid, Uuid)>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Uuid, Uuid)>(
            "SELECT organization_id,id FROM projects WHERE id>$1 ORDER BY id LIMIT 32",
        )
        .bind(cursor)
        .fetch_all(executor)
        .await
    }

    /// Reports whether the project still has raw events before its closed
    /// horizon.
    pub async fn has_backlog<'e, E>(executor: E, project_id: Uuid) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM runtime_events e JOIN projects p ON p.id=e.project_id WHERE p.id=$1 AND e.observed_at<p.runtime_closed_before)")
            .bind(project_id)
            .fetch_one(executor)
            .await
    }

    /// The project's effective retention: whether it is enabled, raw days,
    /// and history days (`None` keeps history forever). A project override
    /// replaces the organization's policy as a whole.
    pub async fn policy<'e, E>(
        executor: E,
        project_id: Uuid,
    ) -> Result<(bool, i32, Option<i32>), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (bool, i32, Option<i32>)>("SELECT COALESCE(p.runtime_retention_enabled,o.runtime_retention_enabled),COALESCE(p.runtime_retention_raw_days,o.runtime_retention_raw_days),CASE WHEN p.runtime_retention_enabled IS NULL THEN o.runtime_retention_history_days ELSE p.runtime_retention_history_days END FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=$1")
            .bind(project_id)
            .fetch_one(executor)
            .await
    }

    /// The enabled flag and history days of [`Self::policy`].
    pub async fn enabled_history_days<'e, E>(
        executor: E,
        project_id: Uuid,
    ) -> Result<(bool, Option<i32>), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (bool, Option<i32>)>("SELECT COALESCE(p.runtime_retention_enabled,o.runtime_retention_enabled),CASE WHEN p.runtime_retention_enabled IS NULL THEN o.runtime_retention_history_days ELSE p.runtime_retention_history_days END FROM projects p JOIN organizations o ON o.id=p.organization_id WHERE p.id=$1")
            .bind(project_id)
            .fetch_one(executor)
            .await
    }

    /// Moves the project's closed and history-expired horizons forward,
    /// never back.
    pub async fn advance_horizons<'e, E>(
        executor: E,
        project_id: Uuid,
        closed_before: DateTime<Utc>,
        history_expired_before: Option<DateTime<Utc>>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE projects SET runtime_closed_before=GREATEST(runtime_closed_before,$2),runtime_history_expired_before=GREATEST(runtime_history_expired_before,$3) WHERE id=$1")
            .bind(project_id)
            .bind(closed_before)
            .bind(history_expired_before)
            .execute(executor)
            .await
    }

    /// Locks up to `limit` grouped raw events of the project observed before
    /// `closed_before`, oldest first. Lifecycle events get ten more minutes so
    /// their correlations can complete.
    pub async fn closed_events_for_update<'e, E>(
        executor: E,
        project_id: Uuid,
        closed_before: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM runtime_events WHERE project_id=$1 AND EXISTS(SELECT 1 FROM runtime_event_group_memberships m WHERE m.event_id=runtime_events.id AND m.fingerprint_version=1) AND observed_at<$2 AND (event_kind NOT IN ('container.restart','container.terminated','process.exit') OR observed_at<$2-interval '10 minutes') ORDER BY observed_at,id LIMIT $3 FOR UPDATE")
            .bind(project_id)
            .bind(closed_before)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// The runtime groups the events belong to.
    pub async fn groups_of_events<'e, E>(
        executor: E,
        event_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT DISTINCT group_id FROM runtime_event_group_memberships WHERE event_id=ANY($1)",
        )
        .bind(event_ids)
        .fetch_all(executor)
        .await
    }

    /// The inventory items the events belong to.
    pub async fn items_of_events<'e, E>(
        executor: E,
        event_ids: &[Uuid],
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT DISTINCT item_id FROM runtime_inventory_event_memberships WHERE event_id=ANY($1)")
            .bind(event_ids)
            .fetch_all(executor)
            .await
    }

    /// Records a qualified, retention-incomplete correlation outcome for the
    /// correlation partners of the events, whose evidence is about to go.
    pub async fn mark_correlations_incomplete<'e, E>(
        executor: E,
        event_ids: &[Uuid],
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_event_correlation_outcomes(organization_id,project_id,event_id,status,candidate_count,tolerance_seconds,retention_incomplete) SELECT e.organization_id,e.project_id,e.id,'qualified',1,30,true FROM runtime_events e WHERE e.id IN (SELECT kernel_event_id FROM runtime_event_correlations WHERE lifecycle_event_id=ANY($1) UNION SELECT lifecycle_event_id FROM runtime_event_correlations WHERE kernel_event_id=ANY($1)) ON CONFLICT(event_id) DO UPDATE SET retention_incomplete=true")
            .bind(event_ids)
            .execute(executor)
            .await
    }

    /// Deletes the raw events.
    pub async fn delete_events<'e, E>(
        executor: E,
        event_ids: &[Uuid],
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM runtime_events WHERE id=ANY($1)")
            .bind(event_ids)
            .execute(executor)
            .await
    }

    /// Drops the window fields from restart-loop groups that no longer have
    /// any raw event.
    pub async fn clear_restart_loop_windows<'e, E>(
        executor: E,
        group_ids: &[Uuid],
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_event_groups g SET semantic_summary=semantic_summary-'latest_termination'-'latest_waiting_reason'-'observed_restart_count'-'window_started_at'-'window_ended_at' WHERE id=ANY($1) AND event_kind='container.restart_loop' AND NOT EXISTS(SELECT 1 FROM runtime_event_group_memberships m WHERE m.group_id=g.id)")
            .bind(group_ids)
            .execute(executor)
            .await
    }

    /// Deletes up to `limit` of the project's history snapshots from before
    /// the day of `expired_before`, oldest first, returning their groups. With
    /// no horizon nothing expires.
    pub async fn expire_snapshots<'e, E>(
        executor: E,
        project_id: Uuid,
        expired_before: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("DELETE FROM runtime_history_snapshots WHERE id IN (SELECT id FROM runtime_history_snapshots WHERE project_id=$1 AND day<($2 AT TIME ZONE 'UTC')::date ORDER BY day,id LIMIT $3) RETURNING group_id")
            .bind(project_id)
            .bind(expired_before)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Deletes up to `limit` restart-loop projections whose window ended ten
    /// minutes before the project's closed horizon.
    pub async fn expire_restart_loop_projections<'e, E>(
        executor: E,
        project_id: Uuid,
        limit: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM runtime_restart_loop_projections WHERE ctid IN (SELECT ctid FROM runtime_restart_loop_projections WHERE project_id=$1 AND window_ended_at<(SELECT runtime_closed_before FROM projects WHERE id=$1)-interval '10 minutes' LIMIT $2)")
            .bind(project_id)
            .bind(limit)
            .execute(executor)
            .await
    }

    /// Points a group without a representative event at its latest remaining
    /// one.
    pub async fn restore_group_representative<'e, E>(
        executor: E,
        group_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_event_groups SET representative_event_id=(SELECT m.event_id FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.group_id=$1 ORDER BY e.observed_at DESC,e.id DESC LIMIT 1) WHERE id=$1 AND representative_event_id IS NULL")
            .bind(group_id)
            .execute(executor)
            .await
    }

    /// Recomputes a group's occurrence count and seen window from its raw
    /// events and history snapshots.
    pub async fn recount_group<'e, E>(
        executor: E,
        group_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("WITH evidence AS (SELECT e.observed_at first_at,e.observed_at last_at,1::bigint n FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.group_id=$1 UNION ALL SELECT first_observed_at,last_observed_at,occurrence_count FROM runtime_history_snapshots WHERE group_id=$1), totals AS (SELECT COALESCE(sum(n),0)::bigint n,min(first_at) first_at,max(last_at) last_at FROM evidence) UPDATE runtime_event_groups SET occurrence_count=totals.n,first_seen_at=COALESCE(totals.first_at,first_seen_at),last_seen_at=COALESCE(totals.last_at,last_seen_at),updated_at=now() FROM totals WHERE id=$1")
            .bind(group_id)
            .execute(executor)
            .await
    }

    /// Deletes a group's per-release rollups.
    pub async fn clear_group_releases<'e, E>(
        executor: E,
        group_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM runtime_event_group_releases WHERE group_id=$1")
            .bind(group_id)
            .execute(executor)
            .await
    }

    /// Rebuilds a group's per-release rollups from its raw events and history
    /// snapshots.
    pub async fn rebuild_group_releases<'e, E>(
        executor: E,
        group_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("WITH evidence AS (SELECT m.organization_id,m.project_id,m.application_id,m.release_id,m.group_id,e.observed_at first_at,e.observed_at last_at,1::bigint n FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.group_id=$1 AND m.release_id IS NOT NULL UNION ALL SELECT organization_id,project_id,application_id,release_id,group_id,first_observed_at,last_observed_at,occurrence_count FROM runtime_history_snapshots WHERE group_id=$1 AND release_id IS NOT NULL) INSERT INTO runtime_event_group_releases(organization_id,project_id,application_id,release_id,group_id,occurrence_count,first_seen_at,last_seen_at,representative_event_id) SELECT organization_id,project_id,application_id,release_id,group_id,sum(n),min(first_at),max(last_at),NULL FROM evidence GROUP BY organization_id,project_id,application_id,release_id,group_id")
            .bind(group_id)
            .execute(executor)
            .await
    }

    /// Points the groups' per-release rollups at their latest remaining raw
    /// event.
    pub async fn restore_release_representatives<'e, E>(
        executor: E,
        group_ids: &[Uuid],
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_event_group_releases gr SET representative_event_id=(SELECT m.event_id FROM runtime_event_group_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.group_id=gr.group_id AND m.release_id=gr.release_id ORDER BY e.observed_at DESC,e.id DESC LIMIT 1) WHERE gr.group_id=ANY($1)")
            .bind(group_ids)
            .execute(executor)
            .await
    }

    /// Recomputes an inventory item's occurrence count, seen window and
    /// listener flags from its remaining raw events.
    pub async fn recount_item<'e, E>(
        executor: E,
        item_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("WITH totals AS (SELECT count(*) n,min(e.observed_at) first_at,max(e.observed_at) last_at,bool_or(e.event_kind='network.listen') listener,bool_or(e.event_kind='network.accept') accept FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.item_id=$1) UPDATE runtime_inventory_items SET occurrence_count=totals.n,first_seen_at=COALESCE(totals.first_at,first_seen_at),last_seen_at=COALESCE(totals.last_at,last_seen_at),semantic_summary=CASE WHEN inventory_kind='inbound_endpoint' THEN semantic_summary || jsonb_build_object('listener_observed',COALESCE(listener,false),'accept_observed',COALESCE(accept,false)) ELSE semantic_summary END,updated_at=now() FROM totals WHERE id=$1")
            .bind(item_id)
            .execute(executor)
            .await
    }

    /// Rebuilds an item's per-release presence from its raw events.
    pub async fn rebuild_item_releases<'e, E>(
        executor: E,
        item_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_inventory_releases(organization_id,project_id,application_id,item_id,release_id,occurrence_count,first_seen_at,last_seen_at) SELECT m.organization_id,m.project_id,m.application_id,m.item_id,e.release_id,count(*),min(e.observed_at),max(e.observed_at) FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.item_id=$1 AND e.release_id IS NOT NULL GROUP BY m.organization_id,m.project_id,m.application_id,m.item_id,e.release_id")
            .bind(item_id)
            .execute(executor)
            .await
    }

    /// Rebuilds an item's sightings from its raw events.
    pub async fn rebuild_item_sightings<'e, E>(
        executor: E,
        item_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_inventory_sightings(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,pod_name,container_name,occurrence_count,first_seen_at,last_seen_at) SELECT m.organization_id,m.project_id,m.application_id,m.item_id,e.cluster_id,e.namespace,e.workload_kind,e.workload_name,e.pod_uid,max(e.pod_name),e.container_name,count(*),min(e.observed_at),max(e.observed_at) FROM runtime_inventory_event_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.item_id=$1 GROUP BY m.organization_id,m.project_id,m.application_id,m.item_id,e.cluster_id,e.namespace,e.workload_kind,e.workload_name,e.pod_uid,e.container_name")
            .bind(item_id)
            .execute(executor)
            .await
    }

    /// Rebuilds an item's links to runtime groups from its raw events.
    pub async fn rebuild_item_group_links<'e, E>(
        executor: E,
        item_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_inventory_group_links(organization_id,project_id,application_id,item_id,group_id) SELECT DISTINCT m.organization_id,m.project_id,m.application_id,m.item_id,g.group_id FROM runtime_inventory_event_memberships m JOIN runtime_event_group_memberships g ON g.event_id=m.event_id WHERE m.item_id=$1")
            .bind(item_id)
            .execute(executor)
            .await
    }

    /// Deletes up to `limit` processed outbox messages without deliveries
    /// whose group has no occurrence left, oldest first.
    pub async fn delete_empty_group_outbox<'e, E>(
        executor: E,
        project_id: Uuid,
        limit: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM outbox_messages WHERE id IN (SELECT o.id FROM outbox_messages o JOIN runtime_event_groups g ON g.id=o.aggregate_id WHERE g.project_id=$1 AND g.occurrence_count=0 AND o.processed_at IS NOT NULL AND NOT EXISTS(SELECT 1 FROM notification_deliveries d WHERE d.outbox_message_id=o.id) ORDER BY o.created_at,o.id LIMIT $2)")
            .bind(project_id)
            .bind(limit)
            .execute(executor)
            .await
    }

    /// Deletes up to `limit` of the project's items with no occurrence left
    /// that no policy revision or suppression was seeded from.
    pub async fn delete_empty_items<'e, E>(
        executor: E,
        project_id: Uuid,
        limit: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM runtime_inventory_items WHERE id IN (SELECT i.id FROM runtime_inventory_items i WHERE i.project_id=$1 AND i.occurrence_count=0 AND NOT EXISTS(SELECT 1 FROM runtime_policy_revisions p WHERE p.source_inventory_item_id=i.id) AND NOT EXISTS(SELECT 1 FROM runtime_policy_suppressions p WHERE p.source_inventory_item_id=i.id) LIMIT $2)")
            .bind(project_id)
            .bind(limit)
            .execute(executor)
            .await
    }

    /// Deletes up to `limit` of the project's groups with no occurrence left
    /// that no policy revision, suppression or outbox message references.
    pub async fn delete_empty_groups<'e, E>(
        executor: E,
        project_id: Uuid,
        limit: i64,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("DELETE FROM runtime_event_groups WHERE id IN (SELECT g.id FROM runtime_event_groups g WHERE g.project_id=$1 AND g.occurrence_count=0 AND NOT EXISTS(SELECT 1 FROM runtime_policy_revisions p WHERE p.source_runtime_group_id=g.id) AND NOT EXISTS(SELECT 1 FROM runtime_policy_suppressions p WHERE p.source_runtime_group_id=g.id) AND NOT EXISTS(SELECT 1 FROM outbox_messages o WHERE o.aggregate_id=g.id) LIMIT $2)")
            .bind(project_id)
            .bind(limit)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, NaiveDate, Utc};
    use sqlx::{FromRow, PgPool};
    use uuid::Uuid;

    use super::RuntimeRetentionRepository;
    use crate::repository::outbox::OutboxRepository;
    use crate::repository::test_support::{
        Tenant, exec_in_release, first_seen_messages, group_ids, ingest, manual_release, tenant,
        user,
    };
    use crate::repository::transaction::TransactionRepository;
    use crate::repository::{OrganizationRepository, ProjectRepository};

    #[derive(Debug, FromRow, PartialEq)]
    struct Policy {
        enabled: bool,
        raw_days: i32,
        history_days: Option<i32>,
    }

    #[derive(Debug, FromRow)]
    struct ProjectPolicy {
        override_enabled: Option<bool>,
        override_raw_days: Option<i32>,
        override_history_days: Option<i32>,
        enabled: bool,
    }

    #[derive(Debug, FromRow, PartialEq)]
    struct Coverage {
        closed_before: Option<DateTime<Utc>>,
        history_expired_before: Option<DateTime<Utc>>,
    }

    #[derive(Debug, FromRow)]
    struct Snapshot {
        group_id: Uuid,
        release_id: Option<Uuid>,
        day: NaiveDate,
        occurrence_count: i64,
    }

    async fn scalar_i64(pool: &PgPool, sql: &str, id: Uuid) -> i64 {
        sqlx::query_scalar(sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn group_count(pool: &PgPool, group: Uuid) -> i64 {
        scalar_i64(
            pool,
            "SELECT occurrence_count FROM runtime_event_groups WHERE id=$1",
            group,
        )
        .await
    }

    async fn item(pool: &PgPool, own: &Tenant) -> Uuid {
        sqlx::query_scalar("SELECT id FROM runtime_inventory_items WHERE project_id=$1")
            .bind(own.project_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Settings resolve with a project override replacing the organization
    /// policy as a whole; horizons only move forward; the page and locks
    /// resolve projects and organizations.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn settings_horizons_and_locks(pool: PgPool) {
        let own = tenant(&pool, "runtime-retention-settings").await;
        let actor = user(&pool).await;
        RuntimeRetentionRepository::set_organization_policy(
            &pool,
            own.organization_id,
            true,
            7,
            Some(30),
            actor,
        )
        .await
        .unwrap();
        assert_eq!(
            RuntimeRetentionRepository::organization_policy::<_, Policy>(
                &pool,
                own.organization_id
            )
            .await
            .unwrap(),
            Some(Policy {
                enabled: true,
                raw_days: 7,
                history_days: Some(30)
            })
        );
        assert_eq!(
            RuntimeRetentionRepository::policy(&pool, own.project_id)
                .await
                .unwrap(),
            (true, 7, Some(30))
        );
        RuntimeRetentionRepository::set_project_override(
            &pool,
            own.organization_id,
            own.project_id,
            Some(true),
            Some(3),
            None,
            actor,
        )
        .await
        .unwrap();
        let overridden: ProjectPolicy =
            RuntimeRetentionRepository::project_policy(&pool, own.organization_id, own.project_id)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            (
                overridden.override_enabled,
                overridden.override_raw_days,
                overridden.override_history_days,
                overridden.enabled
            ),
            (Some(true), Some(3), None, true)
        );
        assert_eq!(
            RuntimeRetentionRepository::policy(&pool, own.project_id)
                .await
                .unwrap(),
            (true, 3, None),
            "an override replaces the whole policy, keeping history forever"
        );
        assert_eq!(
            RuntimeRetentionRepository::enabled_history_days(&pool, own.project_id)
                .await
                .unwrap(),
            (true, None)
        );
        RuntimeRetentionRepository::set_project_override(
            &pool,
            own.organization_id,
            own.project_id,
            None,
            None,
            None,
            actor,
        )
        .await
        .unwrap();
        assert_eq!(
            RuntimeRetentionRepository::policy(&pool, own.project_id)
                .await
                .unwrap(),
            (true, 7, Some(30))
        );

        let later = Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc();
        RuntimeRetentionRepository::advance_horizons(&pool, own.project_id, later, Some(later))
            .await
            .unwrap();
        RuntimeRetentionRepository::advance_horizons(
            &pool,
            own.project_id,
            later - Duration::days(1),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            RuntimeRetentionRepository::coverage::<_, Coverage>(
                &pool,
                own.organization_id,
                own.project_id
            )
            .await
            .unwrap(),
            Coverage {
                closed_before: Some(later),
                history_expired_before: Some(later)
            },
            "horizons never move back"
        );

        let other = tenant(&pool, "runtime-retention-settings-other").await;
        let mut projects = vec![
            (own.organization_id, own.project_id),
            (other.organization_id, other.project_id),
        ];
        projects.sort_by_key(|p| p.1);
        assert_eq!(
            RuntimeRetentionRepository::project_page(&pool, Uuid::nil())
                .await
                .unwrap(),
            projects
        );
        assert_eq!(
            RuntimeRetentionRepository::project_page(&pool, projects[0].1)
                .await
                .unwrap(),
            projects[1..]
        );

        let mut tx = pool.begin().await.unwrap();
        TransactionRepository::begin_repeatable_read(&mut *tx)
            .await
            .unwrap();
        let settings: (String, String) = sqlx::query_as(
            "SELECT current_setting('transaction_isolation'),current_setting('transaction_read_only')",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(settings, ("repeatable read".into(), "off".into()));
        OrganizationRepository::lock_for_update(&mut *tx, own.organization_id)
            .await
            .unwrap();
        ProjectRepository::lock_row_for_update(&mut *tx, own.organization_id, own.project_id)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(matches!(
            OrganizationRepository::lock_for_update(&pool, Uuid::new_v4()).await,
            Err(sqlx::Error::RowNotFound)
        ));
        assert!(matches!(
            ProjectRepository::lock_row_for_update(&pool, other.organization_id, own.project_id)
                .await,
            Err(sqlx::Error::RowNotFound)
        ));
    }

    /// Compaction folds closed events into daily snapshots per group, keyed by
    /// release when the event has one, detaches and deletes them, and rebuilds the group and item
    /// projections from what remains.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn compaction_folds_events_into_history(pool: PgPool) {
        let own = tenant(&pool, "runtime-retention-compaction").await;
        let now = Utc::now();
        let release = manual_release(&pool, &own, "v1", now - Duration::days(5)).await;
        let old = now - Duration::days(3);
        ingest(
            &pool,
            &own,
            &[
                exec_in_release(&own, "/bin/a", "v1", old),
                exec_in_release(&own, "/bin/a", "v1", old + Duration::minutes(1)),
                exec_in_release(&own, "/bin/a", "v1", now),
            ],
        )
        .await;
        let group = group_ids(&pool, &own).await[0];
        let item = item(&pool, &own).await;
        let closed = now - Duration::days(1);
        RuntimeRetentionRepository::advance_horizons(&pool, own.project_id, closed, None)
            .await
            .unwrap();
        assert!(
            RuntimeRetentionRepository::has_backlog(&pool, own.project_id)
                .await
                .unwrap()
        );

        let mut tx = pool.begin().await.unwrap();
        let ids = RuntimeRetentionRepository::closed_events_for_update(
            &mut *tx,
            own.project_id,
            Some(closed),
            10,
        )
        .await
        .unwrap();
        assert_eq!(ids.len(), 2, "only events before the horizon");
        assert_eq!(
            RuntimeRetentionRepository::groups_of_events(&mut *tx, &ids)
                .await
                .unwrap(),
            [group]
        );
        assert_eq!(
            RuntimeRetentionRepository::items_of_events(&mut *tx, &ids)
                .await
                .unwrap(),
            [item]
        );
        for released in [false, true] {
            RuntimeRetentionRepository::fold_into_history_snapshots(&mut tx, &ids, None, released)
                .await
                .unwrap();
        }
        RuntimeRetentionRepository::mark_correlations_incomplete(&mut *tx, &ids)
            .await
            .unwrap();
        RuntimeRetentionRepository::detach_events(&mut tx, &ids)
            .await
            .unwrap();
        RuntimeRetentionRepository::delete_events(&mut *tx, &ids)
            .await
            .unwrap();
        RuntimeRetentionRepository::clear_restart_loop_windows(&mut *tx, &[group])
            .await
            .unwrap();
        RuntimeRetentionRepository::restore_group_representative(&mut *tx, group)
            .await
            .unwrap();
        RuntimeRetentionRepository::recount_group(&mut *tx, group)
            .await
            .unwrap();
        RuntimeRetentionRepository::clear_group_releases(&mut *tx, group)
            .await
            .unwrap();
        RuntimeRetentionRepository::rebuild_group_releases(&mut *tx, group)
            .await
            .unwrap();
        RuntimeRetentionRepository::restore_release_representatives(&mut *tx, &[group])
            .await
            .unwrap();
        RuntimeRetentionRepository::recount_item(&mut *tx, item)
            .await
            .unwrap();
        RuntimeRetentionRepository::clear_item_projections(&mut tx, item)
            .await
            .unwrap();
        RuntimeRetentionRepository::rebuild_item_releases(&mut *tx, item)
            .await
            .unwrap();
        RuntimeRetentionRepository::rebuild_item_sightings(&mut *tx, item)
            .await
            .unwrap();
        RuntimeRetentionRepository::rebuild_item_group_links(&mut *tx, item)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let snapshots: Vec<Snapshot> = RuntimeRetentionRepository::snapshot_page(
            &pool,
            own.organization_id,
            group,
            None,
            None,
            None,
            None,
            10,
        )
        .await
        .unwrap();
        let mut shape: Vec<_> = snapshots
            .iter()
            .map(|s| (s.group_id, s.release_id, s.day, s.occurrence_count))
            .collect();
        shape.sort();
        let day = old.date_naive();
        assert_eq!(
            shape,
            [(group, Some(release), day, 2)],
            "released events fold into their release's snapshot only"
        );
        let for_release: Vec<Snapshot> = RuntimeRetentionRepository::snapshot_page(
            &pool,
            own.organization_id,
            group,
            Some(day),
            day.succ_opt(),
            Some(release),
            None,
            10,
        )
        .await
        .unwrap();
        assert_eq!(for_release.len(), 1, "days are a half-open range");

        assert!(
            !RuntimeRetentionRepository::has_backlog(&pool, own.project_id)
                .await
                .unwrap()
        );
        assert_eq!(
            group_count(&pool, group).await,
            3,
            "two in history, one raw"
        );
        let group_release: i64 = sqlx::query_scalar(
            "SELECT occurrence_count FROM runtime_event_group_releases WHERE group_id=$1 AND release_id=$2",
        )
        .bind(group)
        .bind(release)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(group_release, 3);
        let representative: Option<Uuid> = sqlx::query_scalar(
            "SELECT representative_event_id FROM runtime_event_groups WHERE id=$1",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            representative.is_some(),
            "the remaining event represents the group"
        );
        assert_eq!(
            scalar_i64(
                &pool,
                "SELECT occurrence_count FROM runtime_inventory_items WHERE id=$1",
                item
            )
            .await,
            1,
            "items count raw events only"
        );
        for table in [
            "runtime_inventory_releases",
            "runtime_inventory_sightings",
            "runtime_inventory_group_links",
        ] {
            let rows = scalar_i64(
                &pool,
                &format!("SELECT count(*) FROM {table} WHERE item_id=$1"),
                item,
            )
            .await;
            assert_eq!(rows, 1, "{table} rebuilt from the remaining event");
        }
    }

    /// Expiry drops snapshots before the horizon, and cleanup deletes the
    /// outbox messages, items and groups left without occurrences.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn expiry_and_cleanup_empty_history(pool: PgPool) {
        let own = tenant(&pool, "runtime-retention-expiry").await;
        let old = Utc::now() - Duration::days(3);
        ingest(&pool, &own, &[exec_in_release(&own, "/bin/a", "none", old)]).await;
        let group = group_ids(&pool, &own).await[0];
        let item = item(&pool, &own).await;
        let (message, _) = first_seen_messages(&pool, &own).await[0];
        OutboxRepository::complete(&pool, message, "eligible")
            .await
            .unwrap();

        let mut tx = pool.begin().await.unwrap();
        let ids = RuntimeRetentionRepository::closed_events_for_update(
            &mut *tx,
            own.project_id,
            Some(Utc::now()),
            10,
        )
        .await
        .unwrap();
        RuntimeRetentionRepository::fold_into_history_snapshots(&mut tx, &ids, None, false)
            .await
            .unwrap();
        RuntimeRetentionRepository::detach_events(&mut tx, &ids)
            .await
            .unwrap();
        RuntimeRetentionRepository::delete_events(&mut *tx, &ids)
            .await
            .unwrap();
        assert!(
            RuntimeRetentionRepository::expire_snapshots(&mut *tx, own.project_id, None, 10)
                .await
                .unwrap()
                .is_empty(),
            "no horizon, nothing expires"
        );
        let expired = RuntimeRetentionRepository::expire_snapshots(
            &mut *tx,
            own.project_id,
            Some(Utc::now()),
            10,
        )
        .await
        .unwrap();
        assert_eq!(expired, [group]);
        RuntimeRetentionRepository::recount_group(&mut *tx, group)
            .await
            .unwrap();
        RuntimeRetentionRepository::recount_item(&mut *tx, item)
            .await
            .unwrap();
        RuntimeRetentionRepository::expire_restart_loop_projections(&mut *tx, own.project_id, 10)
            .await
            .unwrap();
        RuntimeRetentionRepository::delete_empty_group_outbox(&mut *tx, own.project_id, 10)
            .await
            .unwrap();
        RuntimeRetentionRepository::delete_empty_items(&mut *tx, own.project_id, 10)
            .await
            .unwrap();
        RuntimeRetentionRepository::delete_empty_groups(&mut *tx, own.project_id, 10)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        for (sql, what) in [
            (
                "SELECT count(*) FROM outbox_messages WHERE project_id=$1",
                "outbox",
            ),
            (
                "SELECT count(*) FROM runtime_inventory_items WHERE project_id=$1",
                "items",
            ),
            (
                "SELECT count(*) FROM runtime_event_groups WHERE project_id=$1",
                "groups",
            ),
            (
                "SELECT count(*) FROM runtime_history_snapshots WHERE project_id=$1",
                "snapshots",
            ),
        ] {
            assert_eq!(
                scalar_i64(&pool, sql, own.project_id).await,
                0,
                "{what} cleaned up"
            );
        }
    }
}
