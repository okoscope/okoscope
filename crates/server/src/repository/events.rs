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
    /// Returns the largest event id in a project, optionally narrowed to one
    /// application, for use as the upper bound of a scan keyed by id.
    ///
    /// **This is not the most recent event.** Event ids are random (v4)
    /// UUIDs, so the largest one says nothing about time. It is the right
    /// bound for a scan that walks `id > cursor AND id <= bound ORDER BY id`,
    /// because every event that existed when the scan began has an id no
    /// greater than it, whatever order those events arrived in. Events that
    /// arrive during the scan may or may not fall under the bound; the
    /// backfills that use this skip rows already processed, so either outcome
    /// is safe.
    ///
    /// Two backfills — grouping and inventory — computed this separately. The
    /// query reads like a "latest event" lookup written with the wrong column,
    /// which is why the explanation lives here.
    pub async fn scan_upper_bound<'e, E>(
        executor: E,
        organization_id: Uuid,
        project_id: Uuid,
        application_id: Option<Uuid>,
    ) -> Result<Option<Uuid>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            r#"
            SELECT id FROM runtime_events
            WHERE organization_id = $1 AND project_id = $2
              AND ($3::uuid IS NULL OR application_id = $3)
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .bind(organization_id)
        .bind(project_id)
        .bind(application_id)
        .fetch_optional(executor)
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
mod tests {
    use super::EventRepository;
    use sqlx::PgPool;
    use uuid::Uuid;

    struct Scope {
        organization: Uuid,
        project: Uuid,
        cluster: Uuid,
        agent: Uuid,
    }

    async fn seed(pool: &PgPool) -> Scope {
        let scope = Scope {
            organization: Uuid::new_v4(),
            project: Uuid::new_v4(),
            cluster: Uuid::new_v4(),
            agent: Uuid::new_v4(),
        };
        for statement in [
            "INSERT INTO organizations(id,slug,name) VALUES($1,$1::text,'Events')",
            "INSERT INTO projects(id,organization_id,slug,name) VALUES($2,$1,'p','P')",
            "INSERT INTO clusters(id,organization_id,external_id,name) VALUES($3,$1,'c','C')",
            "INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($4,$1,$3,'node','0')",
        ] {
            sqlx::query(statement)
                .bind(scope.organization)
                .bind(scope.project)
                .bind(scope.cluster)
                .bind(scope.agent)
                .execute(pool)
                .await
                .unwrap();
        }
        scope
    }

    async fn application(pool: &PgPool, scope: &Scope) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES($1,$2,$3,$1::text,'A')",
        )
        .bind(id)
        .bind(scope.organization)
        .bind(scope.project)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn event(pool: &PgPool, scope: &Scope, application: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO runtime_events(id,event_id,organization_id,project_id,cluster_id,application_id,agent_id,observed_at,node_name,namespace,pod_uid,pod_name,container_id,container_name,workload_uid,workload_kind,workload_name,cgroup_id,pid,tgid,process_command,event_kind,event_schema_version,payload) \
             VALUES($1,$1,$2,$3,$4,$5,$6,now(),'n','ns','pu','p','ci','c','wu','Deployment','w',1,1,1,'cmd','process.exec',1,'{}'::jsonb)",
        )
        .bind(id)
        .bind(scope.organization)
        .bind(scope.project)
        .bind(scope.cluster)
        .bind(application)
        .bind(scope.agent)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    /// The bound is the largest id, not the latest event: ids are random, so
    /// the last event inserted is usually not the largest. What matters to the
    /// scans that use it is that no existing event lies above it.
    #[sqlx::test(migrator = "crate::database::MIGRATOR")]
    #[ignore = "requires isolated PostgreSQL DATABASE_URL"]
    async fn the_scan_bound_covers_every_existing_event(pool: PgPool) {
        let scope = seed(&pool).await;
        let first = application(&pool, &scope).await;
        let second = application(&pool, &scope).await;
        assert_eq!(
            EventRepository::scan_upper_bound(&pool, scope.organization, scope.project, None)
                .await
                .unwrap(),
            None,
            "an empty project has nothing to scan"
        );

        let mut in_first = Vec::new();
        let mut in_project = Vec::new();
        for _ in 0..20 {
            let id = event(&pool, &scope, first).await;
            in_first.push(id);
            in_project.push(id);
            in_project.push(event(&pool, &scope, second).await);
        }

        let bound =
            EventRepository::scan_upper_bound(&pool, scope.organization, scope.project, None)
                .await
                .unwrap()
                .unwrap();
        assert!(in_project.iter().all(|id| *id <= bound));
        assert_eq!(Some(bound), in_project.iter().max().copied());

        let narrowed = EventRepository::scan_upper_bound(
            &pool,
            scope.organization,
            scope.project,
            Some(first),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            Some(narrowed),
            in_first.iter().max().copied(),
            "the application filter bounds that application's events only"
        );

        assert_eq!(
            EventRepository::scan_upper_bound(&pool, Uuid::new_v4(), scope.project, None)
                .await
                .unwrap(),
            None,
            "another organization's scan sees nothing"
        );
    }
}
