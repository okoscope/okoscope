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
    auth::SessionScope,
    bootstrap::{BootstrapConfig, bootstrap},
    ingestion::{IngestionContext, persist_batch},
    navigation,
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
        cluster_name: format!("{name} Cluster"),
        application_slug: "app".into(),
        application_name: "Application".into(),
        cluster_credential: format!("cluster-{name}"),
        api_credential: format!("api-{name}"),
    }
}

fn event(project_id: Uuid, application_id: Uuid, node_name: &str, offset: i64) -> RuntimeEvent {
    RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at: Utc::now() + Duration::seconds(offset),
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id,
            application_id,
            node_name: node_name.into(),
            namespace: "default".into(),
            pod_uid: format!("{node_name}-pod"),
            pod_name: format!("{node_name}-pod"),
            container_id: format!("{node_name}-container"),
            container_name: "app".into(),
            workload_uid: "workload".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: None,
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 1,
            pid: 1,
            tgid: 1,
            command: "app".into(),
        },
        payload: EventPayload::ProcessExec(ProcessExec {
            executable: "/app".into(),
            parent_command: None,
        }),
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

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn workers_are_evidence_based_paginated_and_tenant_safe(pool: sqlx::PgPool) {
    let mut first_config = config("worker-first");
    let first = bootstrap(&pool, &first_config).await.unwrap();
    let mut second_config = config("worker-second");
    let second = bootstrap(&pool, &second_config).await.unwrap();

    first_config.api_credential = owner_session(&pool, first.organization_id).await;
    second_config.api_credential = owner_session(&pool, second.organization_id).await;
    let rich_agent = Uuid::new_v4();
    let sparse_agent = Uuid::new_v4();
    let no_evidence_agent = Uuid::new_v4();
    sqlx::query("INSERT INTO agents(id,organization_id,cluster_id,node_name,agent_version,architecture,kernel_release) VALUES($1,$2,$3,'node-new','1.2.3','x86_64','6.9.2'),($4,$2,$3,'node-old','1.1.0',NULL,NULL),($5,$2,$3,'node-idle','1.2.3','aarch64','6.8.1')")
        .bind(rich_agent)
        .bind(first.organization_id)
        .bind(first.cluster_id)
        .bind(sparse_agent)
        .bind(no_evidence_agent)
        .execute(&pool)
        .await
        .unwrap();
    let scope = SessionScope {
        organization_id: first.organization_id,
        cluster_id: first.cluster_id,
    };
    persist_batch(
        &pool,
        IngestionContext {
            scope,
            agent_id: sparse_agent,
        },
        &[event(
            first.project_id,
            first.application_id,
            "node-old",
            -30,
        )],
    )
    .await
    .unwrap();
    persist_batch(
        &pool,
        IngestionContext {
            scope,
            agent_id: rich_agent,
        },
        &[
            event(first.project_id, first.application_id, "node-new", -20),
            event(first.project_id, first.application_id, "node-new", -10),
        ],
    )
    .await
    .unwrap();

    let app = navigation::router(pool.clone()).layer(axum::Extension(server::web_api::RequestId(
        "worker-test".into(),
    )));
    let base = format!(
        "/api/v1/projects/{}/applications/{}/workers",
        first.project_id, first.application_id
    );
    let first_page = app
        .clone()
        .oneshot(request(
            &format!("{base}?limit=1"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_body = json(first_page).await;
    assert_eq!(first_body["items"].as_array().unwrap().len(), 1);
    assert_eq!(first_body["items"][0]["agent_id"], rich_agent.to_string());
    assert_eq!(first_body["items"][0]["kernel_release"], "6.9.2");
    assert_eq!(first_body["items"][0]["architecture"], "x86_64");
    assert_eq!(
        first_body["items"][0]["cluster_name"],
        first_config.cluster_name
    );
    assert!(first_body["items"][0]["first_observed_at"].is_string());
    assert!(first_body["items"][0]["agent_last_seen_at"].is_string());
    assert!(first_body["items"][0].get("online").is_none());
    let cursor = first_body["next_cursor"].as_str().unwrap();

    let second_page = app
        .clone()
        .oneshot(request(
            &format!("{base}?limit=1&cursor={cursor}"),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    let second_body = json(second_page).await;
    assert_eq!(
        second_body["items"][0]["agent_id"],
        sparse_agent.to_string()
    );
    assert!(second_body["items"][0]["kernel_release"].is_null());
    assert!(second_body["items"][0]["architecture"].is_null());
    assert!(second_body["next_cursor"].is_null());
    assert_ne!(
        second_body["items"][0]["agent_id"],
        no_evidence_agent.to_string()
    );

    for uri in [
        format!("{base}?cursor=not-hex"),
        format!("{base}?limit=0"),
        format!("{base}?limit=201"),
    ] {
        let response = app
            .clone()
            .oneshot(request(&uri, &first_config.api_credential))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let mismatched = app
        .clone()
        .oneshot(request(
            &format!(
                "/api/v1/projects/{}/applications/{}/workers",
                second.project_id, first.application_id
            ),
            &first_config.api_credential,
        ))
        .await
        .unwrap();
    assert_eq!(mismatched.status(), StatusCode::NOT_FOUND);
    let foreign = app
        .oneshot(request(&base, &second_config.api_credential))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
}

async fn owner_session(pool: &sqlx::PgPool, organization: Uuid) -> String {
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user)
        .bind(format!("{user}@example.test"))
        .bind(server::auth::hash_password("worker-test-password").unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(organization)
    .bind(user)
    .execute(pool)
    .await
    .unwrap();
    let token = server::auth::SessionToken::generate();
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(user).bind(organization).bind(token.digest().as_slice()).execute(pool).await.unwrap();
    token.expose().to_owned()
}
