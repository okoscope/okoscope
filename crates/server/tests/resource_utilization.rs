use axum::{
    body::Body,
    http::{Request, StatusCode, header::COOKIE},
};
use chrono::{Duration, Timelike, Utc};
use event_model::{RESOURCE_SCHEMA_VERSION, ResourceAggregate, ResourceValues};
use server::{
    application_credentials::ApplicationCredentialScope,
    auth::{SESSION_COOKIE, SessionScope, SessionToken},
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    resources::{PersistResourceOutcome, cleanup_project, persist_resource_aggregate},
};
use sqlx::Row;
use tower::ServiceExt;
use uuid::Uuid;

fn config() -> BootstrapConfig {
    let suffix = Uuid::new_v4();
    BootstrapConfig {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        cluster_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        organization_slug: format!("resource-{suffix}"),
        organization_name: "Resource test".into(),
        project_slug: "project".into(),
        project_name: "Project".into(),
        cluster_external_id: "cluster".into(),
        cluster_name: "Cluster".into(),
        application_slug: "app".into(),
        application_name: "App".into(),
        cluster_credential: format!("cluster-{suffix}"),
        api_credential: format!("api-{suffix}"),
    }
}

fn aggregate(id: Uuid) -> ResourceAggregate {
    let end = Utc::now()
        .with_second(0)
        .unwrap()
        .with_nanosecond(0)
        .unwrap();
    ResourceAggregate {
        id,
        schema_version: RESOURCE_SCHEMA_VERSION,
        interval_start: end - Duration::minutes(1),
        interval_end: end,
        covered_usec: 60_000_000,
        sample_count: 4,
        contributing_containers: 1,
        ready_containers: 1,
        namespace: "default".into(),
        workload_uid: "deployment-api".into(),
        workload_kind: "Deployment".into(),
        workload_name: "api".into(),
        container_name: "api".into(),
        node_name: "node-a".into(),
        release_identity: None,
        unavailable_sources: 0,
        values: ResourceValues {
            cpu_usage_usec: Some(15_000_000),
            memory_current_sum_bytes: Some(400_000_000),
            memory_current_min_bytes: Some(390_000_000),
            memory_current_max_bytes: Some(410_000_000),
            ..ResourceValues::default()
        },
    }
}

async fn owner_session(pool: &sqlx::PgPool, ids: &BootstrapIds) -> String {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .bind(server::auth::hash_password("resource-test-password").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(ids.organization_id)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(ids.organization_id)
        .bind(token.digest().as_slice())
        .execute(pool)
        .await
        .unwrap();
    token.expose().to_owned()
}

fn history_request(
    project: Uuid,
    application: Uuid,
    token: Option<&str>,
    metric: &str,
) -> Request<Body> {
    let uri = format!(
        "/api/v1/projects/{project}/applications/{application}/resources?metric={metric}&from=2026-01-01T00%3A00%3A00Z&to=2026-01-01T01%3A00%3A00Z&step=minute"
    );
    let mut request = Request::builder().uri(uri);
    if let Some(token) = token {
        request = request.header(COOKIE, format!("{SESSION_COOKIE}={token}"));
    }
    request.body(Body::empty()).unwrap()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
async fn ingestion_is_idempotent_and_cleanup_retries_transactionally(pool: sqlx::PgPool) {
    let ids = bootstrap(&pool, &config()).await.unwrap();
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node-a','test')")
        .bind(agent_id)
        .bind(ids.organization_id)
        .bind(ids.cluster_id)
        .execute(&pool)
        .await
        .unwrap();
    let scope = SessionScope {
        organization_id: ids.organization_id,
        cluster_id: ids.cluster_id,
    };
    let application = ApplicationCredentialScope {
        credential_id: Uuid::new_v4(),
        organization_id: ids.organization_id,
        project_id: ids.project_id,
        application_id: ids.application_id,
    };
    let value = aggregate(Uuid::new_v4());
    let (left, right) = tokio::join!(
        persist_resource_aggregate(&pool, scope, application, agent_id, &value),
        persist_resource_aggregate(&pool, scope, application, agent_id, &value)
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert!(outcomes.contains(&PersistResourceOutcome::Accepted));
    assert!(outcomes.contains(&PersistResourceOutcome::Duplicate));
    let contribution_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM resource_contributions WHERE project_id=$1")
            .bind(ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(contribution_count, 1);
    let rollup_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM resource_rollup_points WHERE project_id=$1")
            .bind(ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rollup_count, 4, "retry must not reconcile rollups twice");

    let mut plan_tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL enable_seqscan=off")
        .execute(&mut *plan_tx)
        .await
        .unwrap();
    let plan = sqlx::query("EXPLAIN SELECT bucket_start,value_sum FROM resource_rollup_points WHERE organization_id=$1 AND project_id=$2 AND application_id=$3 AND metric=$4 AND step_seconds=$5 AND bucket_start >= $6 AND bucket_start < $7 ORDER BY bucket_start LIMIT 45360")
        .bind(ids.organization_id)
        .bind(ids.project_id)
        .bind(ids.application_id)
        .bind("cpu_usage_cores")
        .bind(60_i32)
        .bind(value.interval_start)
        .bind(value.interval_end)
        .fetch_all(&mut *plan_tx)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<String, _>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(plan.contains("Index Scan"), "{plan}");
    assert!(!plan.contains("Seq Scan"), "{plan}");
    plan_tx.rollback().await.unwrap();

    sqlx::query("UPDATE resource_contributions SET interval_start=interval_start-interval '30 days',interval_end=interval_end-interval '30 days' WHERE project_id=$1")
        .bind(ids.project_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE FUNCTION fail_resource_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected resource cleanup failure'; END $$; CREATE TRIGGER fail_resource_cleanup BEFORE DELETE ON resource_contributions FOR EACH ROW EXECUTE FUNCTION fail_resource_cleanup();")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        cleanup_project(&pool, ids.project_id, Utc::now(), 1)
            .await
            .is_err()
    );
    let closed_before: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT resource_closed_before FROM projects WHERE id=$1")
            .bind(ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(closed_before.is_none());

    sqlx::raw_sql("DROP TRIGGER fail_resource_cleanup ON resource_contributions; DROP FUNCTION fail_resource_cleanup();")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        cleanup_project(&pool, ids.project_id, Utc::now(), 1)
            .await
            .unwrap(),
        1
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM resource_contributions WHERE project_id=$1")
            .bind(ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    let rollups: i64 =
        sqlx::query_scalar("SELECT count(*) FROM resource_rollup_points WHERE project_id=$1")
            .bind(ids.project_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        rollups > 0,
        "longer-lived rollups must survive detail cleanup"
    );
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
async fn history_api_enforces_auth_tenant_scope_and_bounds(pool: sqlx::PgPool) {
    let own = bootstrap(&pool, &config()).await.unwrap();
    let foreign = bootstrap(&pool, &config()).await.unwrap();
    let token = owner_session(&pool, &own).await;
    let app = server::resources::router(pool);

    let unauthenticated = app
        .clone()
        .oneshot(history_request(
            own.project_id,
            own.application_id,
            None,
            "cpu_usage_cores",
        ))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let cross_tenant = app
        .clone()
        .oneshot(history_request(
            foreign.project_id,
            foreign.application_id,
            Some(&token),
            "cpu_usage_cores",
        ))
        .await
        .unwrap();
    assert_eq!(cross_tenant.status(), StatusCode::NOT_FOUND);

    let invalid_metric = app
        .clone()
        .oneshot(history_request(
            own.project_id,
            own.application_id,
            Some(&token),
            "unbounded_custom_metric",
        ))
        .await
        .unwrap();
    assert_eq!(invalid_metric.status(), StatusCode::BAD_REQUEST);

    let valid = app
        .oneshot(history_request(
            own.project_id,
            own.application_id,
            Some(&token),
            "cpu_usage_cores",
        ))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::OK);
}
