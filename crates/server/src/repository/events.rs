//! Raw runtime-event persistence.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// A stored runtime event as persisted in `runtime_events`.
///
/// This is a persistence row, not an API response shape. Endpoints project it
/// into their own serializable types so that the table layout and the public
/// JSON contract can evolve independently.
#[derive(Clone, Debug, FromRow, PartialEq)]
pub struct StoredEvent {
    pub event_id: Uuid,
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub application_id: Uuid,
    pub event_kind: String,
    pub observed_at: DateTime<Utc>,
    pub payload: Value,
}

/// Queries against the `runtime_events` table.
#[derive(Clone, Copy, Debug)]
pub struct EventRepository;

impl EventRepository {
    /// The highest raw event id of the project.
    pub async fn latest_project_id<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM runtime_events WHERE organization_id=$1 AND project_id=$2 ORDER BY id DESC LIMIT 1")
            .bind(organization_id)
            .bind(project_id)
            .fetch_optional(executor)
            .await
    }

    /// Raw events of the project after `cursor` up to `upper_bound` by id
    /// that have no group membership under `fingerprint_version`, at most
    /// `limit`.
    ///
    /// Selects the event row.
    pub async fn grouping_backfill_page<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        fingerprint_version: i16,
        cursor: Option<Uuid>,
        upper_bound: Uuid,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.project_id,e.cluster_id,e.application_id,e.release_id,e.observed_at,e.node_name,e.namespace,e.pod_uid,e.pod_name,e.container_id,e.container_name,e.workload_uid,e.workload_kind,e.workload_name,e.cgroup_id,e.pid,e.tgid,e.process_command,e.event_schema_version,e.payload FROM runtime_events e LEFT JOIN runtime_event_group_memberships m ON m.event_id=e.id AND m.fingerprint_version=$3 WHERE e.organization_id=$1 AND e.project_id=$2 AND m.event_id IS NULL AND ($4::uuid IS NULL OR e.id>$4) AND e.id<=$5 ORDER BY e.id LIMIT $6")
            .bind(organization_id)
            .bind(project_id)
            .bind(fingerprint_version)
            .bind(cursor)
            .bind(upper_bound)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Stores a raw event once per agent-assigned event id, returning its id;
    /// `None` when it was already stored.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert<'e, E>(
        executor: E,
        id: Uuid,
        event_id: Uuid,
        organization_id: Uuid,
        project_id: Uuid,
        cluster_id: Uuid,
        application_id: Uuid,
        agent_id: Uuid,
        release_id: Option<Uuid>,
        observed_at: DateTime<Utc>,
        node_name: &str,
        namespace: &str,
        pod_uid: &str,
        pod_name: &str,
        container_id: &str,
        container_name: &str,
        workload_uid: &str,
        workload_kind: &str,
        workload_name: &str,
        cgroup_id: i64,
        pid: i64,
        tgid: i64,
        process_command: &str,
        event_kind: &str,
        schema_version: i32,
        payload: serde_json::Value,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("INSERT INTO runtime_events (id, event_id, organization_id, project_id, cluster_id, application_id, agent_id, release_id, observed_at, node_name, namespace, pod_uid, pod_name, container_id, container_name, workload_uid, workload_kind, workload_name, cgroup_id, pid, tgid, process_command, event_kind, event_schema_version, payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25) ON CONFLICT (agent_id, event_id) DO NOTHING RETURNING id")
            .bind(id)
            .bind(event_id)
            .bind(organization_id)
            .bind(project_id)
            .bind(cluster_id)
            .bind(application_id)
            .bind(agent_id)
            .bind(release_id)
            .bind(observed_at)
            .bind(node_name)
            .bind(namespace)
            .bind(pod_uid)
            .bind(pod_name)
            .bind(container_id)
            .bind(container_name)
            .bind(workload_uid)
            .bind(workload_kind)
            .bind(workload_name)
            .bind(cgroup_id)
            .bind(pid)
            .bind(tgid)
            .bind(process_command)
            .bind(event_kind)
            .bind(schema_version)
            .bind(payload)
            .fetch_optional(executor)
            .await
    }

    /// The highest raw event id of the project, or of one application.
    pub async fn latest_id<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Option<Uuid>,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND ($3::uuid IS NULL OR application_id=$3) ORDER BY id DESC LIMIT 1")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_optional(executor)
            .await
    }

    /// When the application's earliest and latest retained events were
    /// received; both `None` when it has none.
    pub async fn received_window<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
    ) -> Result<(Option<DateTime<Utc>>, Option<DateTime<Utc>>), sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, (Option<DateTime<Utc>>, Option<DateTime<Utc>>)>("SELECT min(received_at),max(received_at) FROM runtime_events WHERE organization_id=$1 AND project_id=$2 AND application_id=$3")
            .bind(organization_id)
            .bind(project_id)
            .bind(application_id)
            .fetch_one(executor)
            .await
    }

    /// One raw event as an occurrence, within the organization.
    pub async fn occurrence<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        event_id: Uuid,
    ) -> Result<Option<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.observed_at,e.received_at,e.node_name,e.namespace,e.pod_name,e.container_name,e.process_command,e.event_kind,e.payload,COALESCE((SELECT jsonb_build_object('retention_incomplete',o.retention_incomplete,'status',o.status,'candidate_count',o.candidate_count,'tolerance_seconds',o.tolerance_seconds,'related_event_ids',COALESCE((SELECT jsonb_agg(c.kernel_event_id) FROM runtime_event_correlations c WHERE c.lifecycle_event_id=e.id),'[]'::jsonb)) FROM runtime_event_correlation_outcomes o WHERE o.event_id=e.id),jsonb_build_object('status','absent','candidate_count',0,'related_event_ids','[]'::jsonb)) correlation,e.release_id,r.version release_version,CASE WHEN r.id IS NULL THEN 'Unattributed' ELSE release_display_name(a.name,r.source,r.version,r.identity_digest,r.identity_components) END release_display_name FROM runtime_events e LEFT JOIN releases r ON r.id=e.release_id LEFT JOIN applications a ON a.id=r.application_id WHERE e.organization_id=$1 AND e.id=$2")
            .bind(organization_id)
            .bind(event_id)
            .fetch_optional(executor)
            .await
    }

    /// Evidence correlated with one raw event, up to `limit`.
    pub async fn related_evidence<'e, E, T>(
        executor: E,
        organization_id: Uuid,
        event_id: Uuid,
        limit: i64,
    ) -> Result<Vec<T>, sqlx::Error>
    where
        E: PgExecutor<'e>,
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        sqlx::query_as("SELECT e.id,e.event_id,e.observed_at,e.received_at,e.event_kind,COALESCE(e.payload#>>'{data,source}','unknown') source,e.payload FROM runtime_event_correlations c JOIN runtime_events e ON e.id=CASE WHEN c.lifecycle_event_id=$2 THEN c.kernel_event_id ELSE c.lifecycle_event_id END WHERE c.organization_id=$1 AND (c.lifecycle_event_id=$2 OR c.kernel_event_id=$2) ORDER BY e.observed_at,e.received_at,e.id LIMIT $3")
            .bind(organization_id)
            .bind(event_id)
            .bind(limit)
            .fetch_all(executor)
            .await
    }

    /// Returns the most recent events of one kind for an application, newest
    /// first.
    ///
    /// `limit` is clamped to `1..=1000` inside the repository so that no call
    /// site can issue an unbounded scan.
    pub async fn recent_for_application<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Uuid,
        event_kind: &str,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<StoredEvent>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, StoredEvent>(
            r#"
            SELECT event_id, organization_id, project_id, application_id,
                   event_kind, observed_at, payload
            FROM runtime_events
            WHERE organization_id = $1
              AND project_id = $2
              AND application_id = $3
              AND event_kind = $4
              AND observed_at >= $5
            ORDER BY observed_at DESC
            LIMIT $6
            "#,
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .bind(event_kind)
        .bind(since)
        .bind(limit.clamp(1, 1000))
        .fetch_all(executor)
        .await
    }
}

#[cfg(test)]
mod ingestion_statement_tests {
    use chrono::{DateTime, Duration, SubsecRound, Utc};
    use serde_json::json;
    use sqlx::PgPool;
    use uuid::Uuid;

    #[derive(sqlx::FromRow)]
    struct Reconciliation {
        source_event_count: i64,
        membership_count: i64,
    }

    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
    }

    use super::EventRepository;
    use crate::inventory::CURRENT_INVENTORY_IDENTITY_VERSION;
    use crate::repository::EventGroupRepository;
    use crate::repository::inventory::InventoryRepository;
    use crate::repository::outbox::OutboxRepository;
    use crate::repository::runtime_retention::RuntimeRetentionRepository;
    use crate::repository::test_support::{
        Tenant, destination, exec, first_seen_messages, group_ids, ingest, manual_release, tenant,
    };
    use crate::repository::webhook_destinations::WebhookDestinationRepository;

    async fn raw(pool: &PgPool, own: &Tenant, event_id: Uuid, at: DateTime<Utc>) -> Option<Uuid> {
        EventRepository::insert(
            pool,
            Uuid::new_v4(),
            event_id,
            own.organization_id,
            own.project_id,
            own.cluster_id,
            own.application_id,
            own.agent_id,
            None,
            at,
            "node-a",
            "production",
            "pod-1",
            "app-1",
            "container-1",
            "app",
            "workload-a",
            "Deployment",
            "app",
            1,
            10,
            10,
            "app",
            "process.exec",
            1,
            json!({"executable": "/bin/raw"}),
        )
        .await
        .unwrap()
    }

    async fn count(pool: &PgPool, sql: &str, id: Uuid) -> i64 {
        sqlx::query_scalar(sql)
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Raw events are stored once per agent event id; the backfill reads find
    /// the latest id and the events not yet grouped or projected.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn raw_events_and_backfill_reads(pool: PgPool) {
        let own = tenant(&pool, "ingestion-raw").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let event_id = Uuid::new_v4();
        let at = Utc::now().trunc_subsecs(0);
        let stored = raw(&pool, &own, event_id, at).await.unwrap();
        assert_eq!(
            raw(&pool, &own, event_id, at).await,
            None,
            "stored once per agent event id"
        );

        let mut ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM runtime_events WHERE project_id=$1")
                .bind(own.project_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        ids.sort();
        let latest = *ids.last().unwrap();
        assert_eq!(
            EventRepository::latest_id(&pool, own.organization_id, own.project_id, None)
                .await
                .unwrap(),
            Some(latest)
        );
        assert_eq!(
            EventRepository::latest_id(
                &pool,
                own.organization_id,
                own.project_id,
                Some(Uuid::new_v4())
            )
            .await
            .unwrap(),
            None
        );
        assert_eq!(
            EventRepository::latest_project_id(&pool, own.organization_id, own.project_id)
                .await
                .unwrap(),
            Some(latest)
        );
        let ungrouped: Vec<Row> = EventRepository::grouping_backfill_page(
            &pool,
            own.organization_id,
            own.project_id,
            1,
            None,
            latest,
            10,
        )
        .await
        .unwrap();
        assert_eq!(
            ungrouped.iter().map(|r| r.id).collect::<Vec<_>>(),
            [stored],
            "only the raw one"
        );
        let unprojected: Vec<Row> = InventoryRepository::projection_backfill_page(
            &pool,
            own.organization_id,
            own.project_id,
            None,
            CURRENT_INVENTORY_IDENTITY_VERSION.get() + 1,
            None,
            latest,
            10,
        )
        .await
        .unwrap();
        assert_eq!(
            unprojected.len(),
            1,
            "the grouped event, under a new identity version"
        );
        assert!(
            InventoryRepository::projection_backfill_page::<_, Row>(
                &pool,
                own.organization_id,
                own.project_id,
                None,
                CURRENT_INVENTORY_IDENTITY_VERSION.get(),
                None,
                latest,
                10,
            )
            .await
            .unwrap()
            .is_empty(),
            "already projected"
        );

        assert_eq!(
            RuntimeRetentionRepository::closed_before(&pool, own.project_id)
                .await
                .unwrap(),
            None
        );
        RuntimeRetentionRepository::advance_horizons(&pool, own.project_id, at, None)
            .await
            .unwrap();
        assert_eq!(
            RuntimeRetentionRepository::closed_before(&pool, own.project_id)
                .await
                .unwrap(),
            Some(at)
        );
    }

    /// Group memberships and per-release rollups are recorded once and
    /// counted; the outbox announces a group once and counts what waits.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn group_writes_and_counts(pool: PgPool) {
        let own = tenant(&pool, "ingestion-groups").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let group = group_ids(&pool, &own).await[0];
        let release = manual_release(&pool, &own, "v1", Utc::now() - Duration::hours(1)).await;
        let stored = raw(&pool, &own, Uuid::new_v4(), Utc::now()).await.unwrap();
        let add = || {
            EventGroupRepository::add_release_membership(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                stored,
                group,
                1,
                Some(release),
            )
        };
        assert_eq!(add().await.unwrap(), Some(stored));
        assert_eq!(
            add().await.unwrap(),
            None,
            "once per event and fingerprint version"
        );

        let rollups = EventGroupRepository::release_rollup_count(&pool)
            .await
            .unwrap();
        for _ in 0..2 {
            EventGroupRepository::record_release_occurrence(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                release,
                group,
                Utc::now(),
                stored,
            )
            .await
            .unwrap();
        }
        assert_eq!(
            EventGroupRepository::release_rollup_count(&pool)
                .await
                .unwrap(),
            rollups + 1
        );
        assert_eq!(
            count(
                &pool,
                "SELECT occurrence_count FROM runtime_event_group_releases WHERE release_id=$1",
                release
            )
            .await,
            2
        );
        let evidence: (i64, i64) = EventGroupRepository::evidence_counts(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
        )
        .await
        .unwrap();
        assert_eq!(evidence.0, 2, "two memberships");

        let (message, _) = first_seen_messages(&pool, &own).await[0];
        assert_eq!(OutboxRepository::unprocessed_count(&pool).await.unwrap(), 1);
        sqlx::query("DELETE FROM outbox_messages WHERE id=$1")
            .bind(message)
            .execute(&pool)
            .await
            .unwrap();
        for _ in 0..2 {
            OutboxRepository::insert_first_seen_from(
                &pool,
                Uuid::new_v4(),
                own.organization_id,
                own.project_id,
                group,
                "backfill",
                json!({"group_id": group}),
            )
            .await
            .unwrap();
        }
        let sources: Vec<String> =
            sqlx::query_scalar("SELECT source FROM outbox_messages WHERE aggregate_id=$1")
                .bind(group)
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(sources, ["backfill"]);

        let one = destination(&pool, &own, "one").await;
        destination(&pool, &own, "two").await;
        assert_eq!(
            WebhookDestinationRepository::enabled_count(&pool)
                .await
                .unwrap(),
            2
        );
        WebhookDestinationRepository::disable::<_, (Uuid,)>(
            &pool,
            own.organization_id,
            own.project_id,
            one,
        )
        .await
        .unwrap();
        assert_eq!(
            WebhookDestinationRepository::enabled_count(&pool)
                .await
                .unwrap(),
            1
        );
    }

    /// Inventory writes: an identity is recorded once, occurrences widen its
    /// counts, and its memberships, links, releases and sightings are
    /// recorded; the reconciliation compares source and projection.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn inventory_writes_and_reconciliation(pool: PgPool) {
        let own = tenant(&pool, "ingestion-inventory").await;
        ingest(&pool, &own, &[exec(&own, "/bin/a", Utc::now())]).await;
        let group = group_ids(&pool, &own).await[0];
        let release = manual_release(&pool, &own, "v1", Utc::now() - Duration::hours(1)).await;
        let at = Utc::now().trunc_subsecs(0);
        let item = Uuid::new_v4();
        let summary = json!({"local_port": 443});
        let insert = || {
            InventoryRepository::insert_item(
                &pool,
                item,
                own.organization_id,
                own.project_id,
                own.application_id,
                "inbound_endpoint",
                1,
                &[3; 32],
                &summary,
                at,
            )
        };
        assert_eq!(insert().await.unwrap(), Some(item));
        assert_eq!(insert().await.unwrap(), None, "one item per identity");
        assert_eq!(
            InventoryRepository::item_id_by_identity(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                "inbound_endpoint",
                1,
                &[3; 32],
            )
            .await
            .unwrap(),
            item
        );
        assert_eq!(
            InventoryRepository::identity_key(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                item
            )
            .await
            .unwrap(),
            (1, vec![3; 32])
        );
        let stored = raw(&pool, &own, Uuid::new_v4(), at).await.unwrap();
        let member = || {
            InventoryRepository::add_event_membership(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                stored,
                item,
                1,
            )
        };
        assert_eq!(member().await.unwrap(), Some(stored));
        assert_eq!(member().await.unwrap(), None);

        InventoryRepository::record_occurrence(&pool, item, at - Duration::minutes(5))
            .await
            .unwrap();
        InventoryRepository::record_inbound_occurrence(
            &pool,
            item,
            at + Duration::minutes(5),
            true,
            false,
        )
        .await
        .unwrap();
        let (occurrences, first, last, listener): (i64, DateTime<Utc>, DateTime<Utc>, bool) = sqlx::query_as(
            "SELECT occurrence_count,first_seen_at,last_seen_at,(semantic_summary->>'listener_observed')::boolean FROM runtime_inventory_items WHERE id=$1",
        )
        .bind(item)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (occurrences, first, last, listener),
            (
                3,
                at - Duration::minutes(5),
                at + Duration::minutes(5),
                true
            )
        );
        for _ in 0..2 {
            InventoryRepository::link_group(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                item,
                group,
            )
            .await
            .unwrap();
            InventoryRepository::record_release_occurrence(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                item,
                release,
                at,
            )
            .await
            .unwrap();
            InventoryRepository::record_sighting(
                &pool,
                own.organization_id,
                own.project_id,
                own.application_id,
                item,
                own.cluster_id,
                "production",
                "Deployment",
                "app",
                "pod-1",
                "app-1",
                "app",
                at,
            )
            .await
            .unwrap();
        }
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM runtime_inventory_group_links WHERE item_id=$1",
                item
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &pool,
                "SELECT occurrence_count FROM runtime_inventory_releases WHERE item_id=$1",
                item
            )
            .await,
            2
        );
        assert_eq!(
            count(
                &pool,
                "SELECT occurrence_count FROM runtime_inventory_sightings WHERE item_id=$1",
                item
            )
            .await,
            2
        );

        let (items, staleness) = InventoryRepository::item_count_and_staleness(&pool)
            .await
            .unwrap();
        assert_eq!(items, 2);
        assert!(staleness >= 0);
        let reconciled: Reconciliation = InventoryRepository::reconciliation(
            &pool,
            own.organization_id,
            own.project_id,
            own.application_id,
            CURRENT_INVENTORY_IDENTITY_VERSION.get(),
        )
        .await
        .unwrap();
        assert_eq!(
            (reconciled.source_event_count, reconciled.membership_count),
            (1, 1),
            "the ingested event is projected once"
        );
    }
}
