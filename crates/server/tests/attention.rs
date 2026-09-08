use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::COOKIE},
};
use chrono::{Duration, Utc};
use event_model::{
    EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, ProcessExec, ProcessIdentity,
    RuntimeEvent,
};
use server::{
    auth::{SESSION_COOKIE, SessionScope, SessionToken},
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    health,
    ingestion::{IngestionContext, persist_batch},
    notification::NotificationService,
    notification_config::NotificationArgs,
    web_api::WebApiConfig,
};
use tower::ServiceExt;
use uuid::Uuid;

fn config(name: &str) -> BootstrapConfig {
    BootstrapConfig {
        organization_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        cluster_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        organization_slug: name.into(),
        organization_name: name.into(),
        project_slug: "project".into(),
        project_name: "Project".into(),
        cluster_external_id: "cluster".into(),
        cluster_name: "Cluster".into(),
        application_slug: "app".into(),
        application_name: "Application".into(),
        cluster_credential: format!("cluster-{name}"),
        api_credential: format!("api-{name}"),
    }
}
fn notifications(pool: sqlx::PgPool) -> NotificationService {
    NotificationService::new(
        pool,
        NotificationArgs {
            enabled: true,
            encryption_key: Some(hex::encode([9_u8; 32])),
            ..NotificationArgs::default()
        }
        .build(false)
        .unwrap(),
    )
    .unwrap()
}
fn request(uri: &str, credential: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(uri);
    if let Some(c) = credential {
        b = b.header(COOKIE, format!("{SESSION_COOKIE}={c}"));
    }
    b.body(Body::empty()).unwrap()
}
async fn owner_session(pool: &sqlx::PgPool, ids: &BootstrapIds) -> String {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .bind(server::auth::hash_password("attention-test-password").unwrap())
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
async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}
async fn release(
    pool: &sqlx::PgPool,
    ids: &BootstrapIds,
    version: &str,
    deployed_at: chrono::DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO releases(id,organization_id,project_id,application_id,version,deployed_at) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(ids.organization_id).bind(ids.project_id).bind(ids.application_id).bind(version).bind(deployed_at).execute(pool).await.unwrap();
    id
}
async fn agent(pool: &sqlx::PgPool, ids: &BootstrapIds) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version) VALUES($1,$2,$3,'node','test')").bind(id).bind(ids.organization_id).bind(ids.cluster_id).execute(pool).await.unwrap();
    id
}
fn event(
    ids: &BootstrapIds,
    release: &str,
    executable: &str,
    observed_at: chrono::DateTime<Utc>,
) -> RuntimeEvent {
    RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at,
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id: ids.project_id,
            application_id: ids.application_id,
            node_name: "node".into(),
            namespace: "default".into(),
            pod_uid: Uuid::new_v4().to_string(),
            pod_name: "app".into(),
            container_id: Uuid::new_v4().to_string(),
            container_name: "app".into(),
            workload_uid: "workload".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: Some(release.into()),
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 1,
            pid: 1,
            tgid: 1,
            command: "app".into(),
        },
        payload: EventPayload::ProcessExec(ProcessExec {
            executable: executable.into(),
            parent_command: None,
        }),
    }
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn summaries_are_complete_ranked_and_tenant_isolated(pool: sqlx::PgPool) {
    let first_cfg = config("attention-first");
    let first = bootstrap(&pool, &first_cfg).await.unwrap();
    let first_session = owner_session(&pool, &first).await;
    let second_cfg = config("attention-second");
    let second = bootstrap(&pool, &second_cfg).await.unwrap();
    let now = Utc::now();
    let _baseline = release(&pool, &first, "1.0", now - Duration::hours(2)).await;
    let _target = release(&pool, &first, "1.1", now - Duration::hours(1)).await;
    release(&pool, &second, "1.0", now).await;
    let first_agent = agent(&pool, &first).await;
    let second_agent = agent(&pool, &second).await;
    let first_context = IngestionContext {
        scope: SessionScope {
            organization_id: first.organization_id,
            cluster_id: first.cluster_id,
        },
        agent_id: first_agent,
    };
    let second_context = IngestionContext {
        scope: SessionScope {
            organization_id: second.organization_id,
            cluster_id: second.cluster_id,
        },
        agent_id: second_agent,
    };
    let events = vec![
        event(&first, "1.0", "/bin/shared", now - Duration::minutes(30)),
        event(&first, "1.0", "/bin/old", now - Duration::minutes(25)),
        event(&first, "1.1", "/bin/shared", now - Duration::minutes(10)),
        event(&first, "1.1", "/bin/new", now - Duration::minutes(5)),
    ];
    assert_eq!(
        persist_batch(&pool, first_context, &events).await.unwrap(),
        4
    );
    assert_eq!(
        persist_batch(
            &pool,
            second_context,
            &[event(&second, "1.0", "/bin/foreign", now)]
        )
        .await
        .unwrap(),
        1
    );
    let app = health::router(
        pool.clone(),
        true,
        Some(notifications(pool.clone())),
        &WebApiConfig::default(),
    );
    let organization = app
        .clone()
        .oneshot(request(
            "/api/v1/attention-summary?limit=1&changed_application_limit=1&recommendation_limit=5",
            Some(&first_session),
        ))
        .await
        .unwrap();
    assert_eq!(organization.status(), StatusCode::OK);
    assert_eq!(organization.headers()["cache-control"], "no-store");
    let organization = json(organization).await;
    assert_eq!(organization["window"]["to"], organization["generated_at"]);
    assert_eq!(organization["totals"]["new_discoveries"], 3);
    assert_eq!(organization["totals"]["open_discoveries"], 3);
    assert_eq!(organization["totals"]["changed_applications"], 1);
    assert_eq!(
        organization["changed_applications"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(organization["changed_applications"][0]["new_count"], 1);
    assert_eq!(
        organization["changed_applications"][0]["disappeared_count"],
        1
    );
    assert_eq!(organization["priority_items"].as_array().unwrap().len(), 1);
    assert_eq!(organization["priority_items"][0]["priority"], "urgent");
    assert!(
        organization
            .to_string()
            .contains(&first.application_id.to_string())
    );
    assert!(
        !organization
            .to_string()
            .contains(&second.application_id.to_string())
    );
    let recommendation_text = organization["recommendations"].to_string();
    for kind in [
        "configure_webhook_destination",
        "review_release_changes",
        "review_new_discoveries",
    ] {
        assert!(recommendation_text.contains(kind));
    }
    let application_uri = format!(
        "/api/v1/projects/{}/applications/{}/attention-summary?largest_change_limit=1",
        first.project_id, first.application_id
    );
    let application = app
        .clone()
        .oneshot(request(&application_uri, Some(&first_session)))
        .await
        .unwrap();
    assert_eq!(application.status(), StatusCode::OK);
    let application = json(application).await;
    assert_eq!(application["totals"]["new_runtime_items"], 1);
    assert_eq!(application["totals"]["disappeared_runtime_items"], 1);
    assert_eq!(application["totals"]["unchanged_runtime_items"], 1);
    assert_eq!(
        application["release_comparison"]["largest_changes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let runtime_group_resource = application["priority_items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| &item["resource"])
        .find(|resource| resource["type"] == "runtime_group")
        .expect("runtime-group priority resource");
    assert_eq!(runtime_group_resource["event_kind"], "process.exec");
    assert!(runtime_group_resource["semantic_summary"].is_object());
    assert_eq!(runtime_group_resource["namespace"], "default");
    assert_eq!(runtime_group_resource["workload_kind"], "Deployment");
    assert_eq!(runtime_group_resource["workload_name"], "app");
    let custom = app
        .clone()
        .oneshot(request(
            &format!("{application_uri}&window=7d&limit=50&recommendation_limit=10"),
            Some(&first_session),
        ))
        .await
        .unwrap();
    assert_eq!(custom.status(), StatusCode::OK);
    for invalid in [
        "/api/v1/attention-summary?window=30d",
        "/api/v1/attention-summary?limit=0",
        "/api/v1/attention-summary?changed_application_limit=11",
        "/api/v1/attention-summary?recommendation_limit=11",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(invalid, Some(&first_session)))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let mismatch = format!(
        "/api/v1/projects/{}/applications/{}/attention-summary",
        second.project_id, first.application_id
    );
    assert_eq!(
        app.oneshot(request(&mismatch, Some(&first_session)))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn empty_and_baseline_less_states_are_explicit(pool: sqlx::PgPool) {
    let cfg = config("attention-empty");
    let ids = bootstrap(&pool, &cfg).await.unwrap();
    let session = owner_session(&pool, &ids).await;
    let app = health::router(
        pool.clone(),
        true,
        Some(notifications(pool.clone())),
        &WebApiConfig::default(),
    );
    let uri = format!(
        "/api/v1/projects/{}/applications/{}/attention-summary",
        ids.project_id, ids.application_id
    );
    let no_release = app
        .clone()
        .oneshot(request(&uri, Some(&session)))
        .await
        .unwrap();
    assert_eq!(no_release.status(), StatusCode::OK);
    assert!(json(no_release).await["release_comparison"].is_null());
    release(&pool, &ids, "1.0", Utc::now()).await;
    let response = app
        .clone()
        .oneshot(request(&uri, Some(&session)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["totals"]["total_runtime_items"], 0);
    assert!(body["release_comparison"].is_null());
    assert!(body["priority_items"].as_array().unwrap().is_empty());
    sqlx::query("DROP TABLE runtime_event_groups CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    let failed = app
        .oneshot(request("/api/v1/attention-summary", Some(&session)))
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let failed = json(failed).await;
    assert_eq!(failed["error"], "internal_error");
    assert!(failed.get("totals").is_none());
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn organization_response_and_query_plan_remain_bounded(pool: sqlx::PgPool) {
    let cfg = config("attention-performance");
    let ids = bootstrap(&pool, &cfg).await.unwrap();
    let session = owner_session(&pool, &ids).await;
    for index in 0..100 {
        sqlx::query("INSERT INTO projects(id,organization_id,slug,name) VALUES($1,$2,$3,$4)")
            .bind(Uuid::new_v4())
            .bind(ids.organization_id)
            .bind(format!("project-{index}"))
            .bind(format!("Project {index}"))
            .execute(&pool)
            .await
            .unwrap();
    }
    let plan: serde_json::Value = sqlx::query_scalar("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT p.id,(SELECT count(*) FROM webhook_destinations w WHERE w.organization_id=p.organization_id AND w.project_id=p.id AND w.enabled) FROM projects p WHERE p.organization_id=$1 ORDER BY p.id LIMIT 5")
        .bind(ids.organization_id).fetch_one(&pool).await.unwrap();
    let plan_text = plan.to_string();
    assert!(plan_text.contains("Execution Time"));
    assert!(plan_text.contains("Plan"));
    let app = health::router(
        pool.clone(),
        true,
        Some(notifications(pool)),
        &WebApiConfig::default(),
    );
    let started = std::time::Instant::now();
    let response = app
        .oneshot(request(
            "/api/v1/attention-summary?limit=5&changed_application_limit=3&recommendation_limit=4",
            Some(&session),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json(response).await;
    assert_eq!(body["totals"]["projects_with_notification_problems"], 101);
    assert_eq!(body["notification_problems"].as_array().unwrap().len(), 5);
    assert_eq!(body["priority_items"].as_array().unwrap().len(), 5);
    assert_eq!(body["recommendations"].as_array().unwrap().len(), 4);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(server::attention::ORGANIZATION_ATTENTION_QUERY_BUDGET, 9);
    assert_eq!(server::attention::APPLICATION_ATTENTION_QUERY_BUDGET, 9);
}
