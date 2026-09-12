use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::COOKIE},
};
use chrono::Utc;
use protocol::v1::{ApplicationDiagnosticSnapshot, DropCounters, Heartbeat};
use server::{
    agent_health::{record_heartbeat, register_application_agent},
    application_credentials::ApplicationCredentialScope,
    bootstrap::{BootstrapConfig, bootstrap},
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

fn request(uri: &str, credential: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(
            COOKIE,
            format!("{}={credential}", server::auth::SESSION_COOKIE),
        )
        .body(Body::empty())
        .unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

async fn owner_session(pool: &sqlx::PgPool, organization: Uuid) -> String {
    organization_session(pool, organization, "owner").await
}

async fn organization_session(pool: &sqlx::PgPool, organization: Uuid, role: &str) -> String {
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .bind(server::auth::hash_password("agent-health-test-password").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
    )
    .bind(organization)
    .bind(user)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    let token = server::auth::SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(user).bind(organization).bind(token.digest().as_slice()).execute(pool).await.unwrap();
    token.expose().to_owned()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn health_includes_no_event_agent_ranges_deltas_and_tenant_isolation(pool: sqlx::PgPool) {
    let first = bootstrap(&pool, &config("health-first")).await.unwrap();
    let second = bootstrap(&pool, &config("health-second")).await.unwrap();
    let credential = owner_session(&pool, first.organization_id).await;
    let unscoped_member = organization_session(&pool, first.organization_id, "member").await;
    let foreign_credential = owner_session(&pool, second.organization_id).await;
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version,architecture,kernel_release) VALUES($1,$2,$3,'node-health','1.2.3','x86_64','6.9')")
        .bind(agent_id).bind(first.organization_id).bind(first.cluster_id).execute(&pool).await.unwrap();
    let scope = ApplicationCredentialScope {
        credential_id: Uuid::new_v4(),
        organization_id: first.organization_id,
        project_id: first.project_id,
        application_id: first.application_id,
    };
    register_application_agent(
        &pool,
        scope,
        first.cluster_id,
        agent_id,
        &["process.exec/v1".into()],
    )
    .await
    .unwrap();
    for decode_failed in [3, 8, 2, 4] {
        record_heartbeat(
            &pool,
            scope,
            first.cluster_id,
            agent_id,
            &Heartbeat {
                sent_at_unix_nanos: Utc::now().timestamp_nanos_opt().unwrap(),
                drop_counters: Some(DropCounters {
                    decode_failed: decode_failed + 100,
                    ..Default::default()
                }),
                resource_counters: None,
                application_diagnostics: Some(ApplicationDiagnosticSnapshot {
                    decode_failed,
                    ..Default::default()
                }),
            },
        )
        .await
        .unwrap();
    }
    let other_application = Uuid::new_v4();
    sqlx::query("INSERT INTO applications(id,organization_id,project_id,slug,name) VALUES($1,$2,$3,'other-app','Other Application')")
        .bind(other_application).bind(first.organization_id).bind(first.project_id)
        .execute(&pool).await.unwrap();
    let other_scope = ApplicationCredentialScope {
        credential_id: Uuid::new_v4(),
        application_id: other_application,
        ..scope
    };
    register_application_agent(&pool, other_scope, first.cluster_id, agent_id, &[])
        .await
        .unwrap();
    for dropped in [10, 60] {
        record_heartbeat(
            &pool,
            other_scope,
            first.cluster_id,
            agent_id,
            &Heartbeat {
                sent_at_unix_nanos: Utc::now().timestamp_nanos_opt().unwrap(),
                drop_counters: Some(DropCounters {
                    decode_failed: 10_000,
                    ..Default::default()
                }),
                resource_counters: None,
                application_diagnostics: Some(ApplicationDiagnosticSnapshot {
                    dropped,
                    ..Default::default()
                }),
            },
        )
        .await
        .unwrap();
    }
    let app = server::agent_health::router(pool.clone()).layer(axum::Extension(
        server::web_api::RequestId("health-test".into()),
    ));
    let base = format!(
        "/api/v1/projects/{}/applications/{}/agent-health",
        first.project_id, first.application_id
    );
    for (range, count) in [("1h", 60), ("6h", 72), ("24h", 96)] {
        let response = app
            .clone()
            .oneshot(request(&format!("{base}?range={range}"), &credential))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(
            body["items"][0]["timeline"].as_array().unwrap().len(),
            count
        );
        assert_eq!(body["items"][0]["stream_state"], "reporting");
        assert_eq!(body["items"][0]["diagnostics_available"], true);
        assert!(body["items"][0]["first_event_at"].is_null());
        assert_eq!(
            body["items"][0]["node_diagnostics"][0]["category"],
            "decode_failed"
        );
        assert_eq!(body["items"][0]["node_diagnostics"][0]["delta"], 7);
        assert!(
            body["items"][0]["timeline"]
                .as_array()
                .unwrap()
                .iter()
                .any(|point| point["diagnostics_available"] == true)
        );
        assert!(
            body["items"][0]["timeline"]
                .as_array()
                .unwrap()
                .iter()
                .any(|point| point["reset"] == true)
        );
    }
    let foreign = app
        .clone()
        .oneshot(request(&base, &foreign_credential))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    let inaccessible_project = app
        .clone()
        .oneshot(request(&base, &unscoped_member))
        .await
        .unwrap();
    assert_eq!(inaccessible_project.status(), StatusCode::NOT_FOUND);
    let invalid = app
        .oneshot(request(&format!("{base}?limit=21"), &credential))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
}
