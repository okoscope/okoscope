//! Container termination evidence: correlations between kernel process exits
//! and the container terminations that explain them, and the restart-loop
//! projections built from container restarts.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// Termination correlations and restart-loop projections.
#[derive(Clone, Copy, Debug)]
pub struct TerminationRepository;

impl TerminationRepository {
    /// Kernel process exits of the same container within `tolerance` (an
    /// interval such as `"30 seconds"`) of a termination.
    #[allow(clippy::too_many_arguments)]
    pub async fn kernel_exit_candidates<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        workload_uid: &str,
        pod_uid: &str,
        container_name: &str,
        container_id: &str,
        observed_at: DateTime<Utc>,
        tolerance: String,
    ) -> Result<Vec<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND workload_uid=$4 AND pod_uid=$5 AND container_name=$6 AND container_id=$7 AND event_kind='process.exit' AND observed_at BETWEEN $8-$9::interval AND $8+$9::interval ORDER BY observed_at,id LIMIT 2")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(workload_uid)
            .bind(pod_uid)
            .bind(container_name)
            .bind(container_id)
            .bind(observed_at)
            .bind(tolerance)
            .fetch_all(executor)
            .await
    }

    /// Records, or replaces, how a termination correlated.
    pub async fn record_outcome<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        event_id: Uuid,
        status: &str,
        candidate_count: i32,
        tolerance_seconds: i32,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_event_correlation_outcomes (organization_id,project_id,event_id,status,candidate_count,tolerance_seconds) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (event_id) DO UPDATE SET status=EXCLUDED.status,candidate_count=EXCLUDED.candidate_count,tolerance_seconds=EXCLUDED.tolerance_seconds,updated_at=now()")
            .bind(organization_id)
            .bind(project_id)
            .bind(event_id)
            .bind(status)
            .bind(candidate_count)
            .bind(tolerance_seconds)
            .execute(executor)
            .await
    }

    /// Links a termination to the kernel exit it explains, once.
    pub async fn link<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        lifecycle_event_id: Uuid,
        kernel_event_id: Uuid,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_event_correlations (organization_id,project_id,lifecycle_event_id,kernel_event_id,correlation_kind) VALUES ($1,$2,$3,$4,'qualified') ON CONFLICT DO NOTHING")
            .bind(organization_id)
            .bind(project_id)
            .bind(lifecycle_event_id)
            .bind(kernel_event_id)
            .execute(executor)
            .await
    }

    /// Adds a restart to the projection, once per event.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_restart<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        projection_version: i16,
        event_id: Uuid,
        window_started_at: DateTime<Utc>,
        window_ended_at: DateTime<Utc>,
        restart_delta: i32,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_restart_projection_memberships (organization_id,project_id,projection_version,event_id,window_started_at,window_ended_at,restart_delta) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
            .bind(organization_id)
            .bind(project_id)
            .bind(projection_version)
            .bind(event_id)
            .bind(window_started_at)
            .bind(window_ended_at)
            .bind(restart_delta)
            .execute(executor)
            .await
    }

    /// The latest restart of the container within `[from, to]`, or `from`
    /// when there is none.
    #[allow(clippy::too_many_arguments)]
    pub async fn restart_window_end<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        pod_uid: &str,
        container_name: &str,
        container_id: &str,
        projection_version: i16,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, DateTime<Utc>>("SELECT COALESCE(max(e.observed_at),$9) FROM runtime_restart_projection_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.organization_id=$1 AND m.project_id=$2 AND e.application_id=$3 AND e.cluster_id=$4 AND e.pod_uid=$5 AND e.container_name=$6 AND e.container_id=$7 AND m.projection_version=$8 AND e.observed_at BETWEEN $9 AND $10")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(pod_uid)
            .bind(container_name)
            .bind(container_id)
            .bind(projection_version)
            .bind(from)
            .bind(to)
            .fetch_one(executor)
            .await
    }

    /// The container's restarts within `(start, end]`.
    #[allow(clippy::too_many_arguments)]
    pub async fn restarts_in_window<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        pod_uid: &str,
        container_name: &str,
        container_id: &str,
        projection_version: i16,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(sum(m.restart_delta),0)::bigint FROM runtime_restart_projection_memberships m JOIN runtime_events e ON e.id=m.event_id WHERE m.organization_id=$1 AND m.project_id=$2 AND e.application_id=$3 AND e.cluster_id=$4 AND e.pod_uid=$5 AND e.container_name=$6 AND e.container_id=$7 AND m.projection_version=$8 AND e.observed_at BETWEEN $9 AND $10")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(pod_uid)
            .bind(container_name)
            .bind(container_id)
            .bind(projection_version)
            .bind(start)
            .bind(end)
            .fetch_one(executor)
            .await
    }

    /// Records, or updates, the container's restart-loop projection for the
    /// window.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_restart_loop<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        pod_uid: &str,
        container_name: &str,
        container_id: &str,
        projection_version: i16,
        window_started_at: DateTime<Utc>,
        window_ended_at: DateTime<Utc>,
        observed_restart_count: i32,
        previous_termination: Option<serde_json::Value>,
        waiting_reason: Option<&str>,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("INSERT INTO runtime_restart_loop_projections (organization_id,project_id,application_id,cluster_id,pod_uid,container_name,runtime_container_id,projection_version,window_started_at,window_ended_at,observed_restart_count,latest_termination,latest_waiting_reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT (organization_id,project_id,application_id,cluster_id,pod_uid,container_name,runtime_container_id,projection_version) DO UPDATE SET window_started_at=EXCLUDED.window_started_at,window_ended_at=EXCLUDED.window_ended_at,observed_restart_count=EXCLUDED.observed_restart_count,latest_termination=COALESCE(EXCLUDED.latest_termination,runtime_restart_loop_projections.latest_termination),latest_waiting_reason=COALESCE(EXCLUDED.latest_waiting_reason,runtime_restart_loop_projections.latest_waiting_reason),updated_at=now()")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(pod_uid)
            .bind(container_name)
            .bind(container_id)
            .bind(projection_version)
            .bind(window_started_at)
            .bind(window_ended_at)
            .bind(observed_restart_count)
            .bind(previous_termination)
            .bind(waiting_reason)
            .execute(executor)
            .await
    }

    /// Points the container's restart-loop projection at its group.
    #[allow(clippy::too_many_arguments)]
    pub async fn attach_restart_loop_group<'e, E>(
        executor: E,
        group_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        cluster_id: Uuid,
        pod_uid: &str,
        container_name: &str,
        container_id: &str,
        projection_version: i16,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query("UPDATE runtime_restart_loop_projections SET group_id=$1 WHERE organization_id=$2 AND project_id=$3 AND application_id=$4 AND cluster_id=$5 AND pod_uid=$6 AND container_name=$7 AND runtime_container_id=$8 AND projection_version=$9")
            .bind(group_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .bind(cluster_id)
            .bind(pod_uid)
            .bind(container_name)
            .bind(container_id)
            .bind(projection_version)
            .execute(executor)
            .await
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, SubsecRound, Utc};
    use serde_json::json;
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::TerminationRepository;
    use crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION;
    use crate::repository::EventGroupRepository;
    use crate::repository::inventory::InventoryRepository;
    use crate::repository::outbox::OutboxRepository;
    use crate::repository::test_support::{
        Tenant, correlated_termination, exec, group_ids, ingest, restarts, tenant,
    };

    async fn event_ids(pool: &PgPool, own: &Tenant, kind: &str) -> Vec<Uuid> {
        sqlx::query_scalar(
            "SELECT id FROM runtime_events WHERE project_id=$1 AND event_kind=$2 ORDER BY observed_at,id",
        )
        .bind(own.project_id)
        .bind(kind)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// A termination finds the kernel exits of its container within the
    /// tolerance; outcomes are replaced and links recorded once.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn terminations_correlate_with_kernel_exits(pool: PgPool) {
        let own = tenant(&pool, "terminations-correlate").await;
        let at = Utc::now().trunc_subsecs(0);
        let [kernel, lifecycle] = correlated_termination(&own, at);
        ingest(&pool, &own, &[kernel, lifecycle]).await;
        let kernel_id = event_ids(&pool, &own, "process.exit").await[0];
        let lifecycle_id = event_ids(&pool, &own, "container.terminated").await[0];
        let candidates = |container_id: &'static str, tolerance: &'static str| {
            let pool = pool.clone();
            async move {
                TerminationRepository::kernel_exit_candidates(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    "workload-a",
                    "pod-uid",
                    "app",
                    container_id,
                    at,
                    tolerance.into(),
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(candidates("abc", "30 seconds").await, [kernel_id]);
        assert!(candidates("other", "30 seconds").await.is_empty());

        TerminationRepository::record_outcome(
            &pool,
            own.organization_id,
            own.project_id,
            lifecycle_id,
            "ambiguous",
            2,
            30,
        )
        .await
        .unwrap();
        let outcome: (String, i32) = sqlx::query_as(
            "SELECT status,candidate_count FROM runtime_event_correlation_outcomes WHERE event_id=$1",
        )
        .bind(lifecycle_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(outcome, ("ambiguous".into(), 2), "replaced");
        for _ in 0..2 {
            TerminationRepository::link(
                &pool,
                own.organization_id,
                own.project_id,
                lifecycle_id,
                kernel_id,
            )
            .await
            .unwrap();
        }
        let links: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runtime_event_correlations WHERE lifecycle_event_id=$1",
        )
        .bind(lifecycle_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(links, 1);
    }

    /// Restart-loop projections: the window's restarts and end, the upserted
    /// projection and its group, and memberships recorded once.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn restart_loops_are_projected(pool: PgPool) {
        let own = tenant(&pool, "terminations-restarts").await;
        let at = Utc::now().trunc_subsecs(0) - Duration::hours(1);
        ingest(&pool, &own, &restarts(&own, at, 3)).await;
        let in_window = |start: DateTime<Utc>, end: DateTime<Utc>| {
            let pool = pool.clone();
            async move {
                TerminationRepository::restarts_in_window(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    own.cluster_id,
                    "pod-uid",
                    "app",
                    "abc",
                    1,
                    start,
                    end,
                )
                .await
                .unwrap()
            }
        };
        let total = in_window(at - Duration::hours(1), at + Duration::hours(1)).await;
        assert!(total >= 2, "the restarts are counted: {total}");
        assert_eq!(
            in_window(at + Duration::hours(1), at + Duration::hours(2)).await,
            0
        );
        let end = |from: DateTime<Utc>, to: DateTime<Utc>| {
            let pool = pool.clone();
            async move {
                TerminationRepository::restart_window_end(
                    &pool,
                    own.organization_id,
                    own.project_id,
                    own.application_id,
                    own.cluster_id,
                    "pod-uid",
                    "app",
                    "abc",
                    1,
                    from,
                    to,
                )
                .await
                .unwrap()
            }
        };
        assert_eq!(
            end(at, at + Duration::hours(1)).await,
            at + Duration::minutes(3),
            "the latest restart in the window"
        );
        let later = at + Duration::hours(2);
        assert_eq!(
            end(later, later + Duration::hours(1)).await,
            later,
            "none, the window start"
        );

        TerminationRepository::upsert_restart_loop(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            own.cluster_id,
            "pod-uid",
            "app",
            "abc",
            1,
            at - Duration::minutes(7),
            at + Duration::minutes(3),
            9,
            Some(json!({"reason": "OOMKilled"})),
            Some("CrashLoopBackOff"),
        )
        .await
        .unwrap();
        let group = group_ids(&pool, &own).await[0];
        TerminationRepository::attach_restart_loop_group(
            &pool,
            group,
            own.organization_id,
            own.project_id,
            own.application_id,
            own.cluster_id,
            "pod-uid",
            "app",
            "abc",
            1,
        )
        .await
        .unwrap();
        let projection: (i32, Option<Uuid>) = sqlx::query_as(
            "SELECT observed_restart_count,group_id FROM runtime_restart_loop_projections WHERE project_id=$1 AND window_ended_at=$2",
        )
        .bind(own.project_id)
        .bind(at + Duration::minutes(3))
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(projection, (9, Some(group)));

        ingest(&pool, &own, &[exec(&own, "/bin/a", at)]).await;
        let exec_id = event_ids(&pool, &own, "process.exec").await[0];
        for _ in 0..2 {
            TerminationRepository::add_restart(
                &pool,
                own.organization_id,
                own.project_id,
                1,
                exec_id,
                at,
                at + Duration::minutes(1),
                1,
            )
            .await
            .unwrap();
            EventGroupRepository::add_membership(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                exec_id,
                group,
                101,
            )
            .await
            .unwrap();
            InventoryRepository::link_event_items_to_group(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                group,
                exec_id,
                CURRENT_INVENTORY_IDENTITY_VERSION.get(),
            )
            .await
            .unwrap();
            OutboxRepository::insert_first_seen(
                &pool,
                Uuid::new_v4(),
                own.organization_id,
                own.project_id,
                group,
                json!({"group_id": group}),
            )
            .await
            .unwrap();
        }
        for (sql, expected) in [
            (
                "SELECT count(*) FROM runtime_restart_projection_memberships WHERE event_id=$1",
                1,
            ),
            (
                "SELECT count(*) FROM runtime_event_group_memberships WHERE event_id=$1 AND fingerprint_version=101",
                1,
            ),
        ] {
            let n: i64 = sqlx::query_scalar(sql)
                .bind(exec_id)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(n, expected, "{sql}");
        }
        let links: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM runtime_inventory_group_links WHERE group_id=$1",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(links >= 1, "the exec item is linked to the group");
        let messages: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM outbox_messages WHERE aggregate_id=$1 AND topic='runtime_group.first_seen'",
        )
        .bind(group)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(messages, 1, "announced once per group");
    }
}
