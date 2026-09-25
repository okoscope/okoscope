use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use event_model::{
    EVENT_SCHEMA_VERSION, EventPayload, KubernetesAttribution, ProcessExec, ProcessIdentity,
    RuntimeEvent,
};
use server::{
    auth::{SESSION_COOKIE, SessionScope, SessionToken},
    bootstrap::{BootstrapConfig, BootstrapIds, bootstrap},
    ingestion::{IngestionContext, persist_batch},
    policy_api,
    web_api::{self, REQUEST_ID_HEADER, WebApiConfig},
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
        api_credential: String::new(),
    }
}

async fn session(pool: &sqlx::PgPool, ids: &BootstrapIds, role: &str) -> String {
    let user = Uuid::new_v4();
    let token = SessionToken::generate();
    sqlx::query("INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)")
        .bind(user)
        .bind(format!("{user}@example.com"))
        .bind("x".repeat(32))
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,$3)",
    )
    .bind(ids.organization_id)
    .bind(user)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    if role == "member" {
        sqlx::query("INSERT INTO project_memberships(organization_id,project_id,user_id,role) VALUES($1,$2,$3,'member')")
            .bind(ids.organization_id)
            .bind(ids.project_id)
            .bind(user)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO user_sessions(id,user_id,organization_id,token_hash,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 hour')").bind(Uuid::new_v4()).bind(user).bind(ids.organization_id).bind(token.digest().as_slice()).execute(pool).await.unwrap();
    format!("{SESSION_COOKIE}={}", token.expose())
}

async fn item(pool: &sqlx::PgPool, ids: &BootstrapIds) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO runtime_inventory_items(id,organization_id,project_id,application_id,inventory_kind,identity_version,identity_digest,semantic_summary,first_seen_at,last_seen_at,occurrence_count) VALUES($1,$2,$3,$4,'process',2,$5,$6,now(),now(),1)").bind(id).bind(ids.organization_id).bind(ids.project_id).bind(ids.application_id).bind(vec![7_u8;32]).bind(serde_json::json!({"executable":"/app"})).execute(pool).await.unwrap();
    id
}

fn request(
    method: &str,
    uri: &str,
    cookie: &str,
    key: Option<Uuid>,
    body: Option<serde_json::Value>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header(header::HOST, "ui.test")
        .header(header::ORIGIN, "https://ui.test");
    if let Some(key) = key {
        builder = builder.header("idempotency-key", key.to_string());
    }
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    builder
        .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
        .unwrap()
}
async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1_048_576).await.unwrap()).unwrap()
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn policy_commands_preview_and_suppression_are_tenant_scoped_and_idempotent(
    pool: sqlx::PgPool,
) {
    let first = bootstrap(&pool, &config("policy-first")).await.unwrap();
    let second = bootstrap(&pool, &config("policy-second")).await.unwrap();
    let cookie = session(&pool, &first, "member").await;
    let item_id = item(&pool, &first).await;
    sqlx::query("INSERT INTO runtime_inventory_sightings(organization_id,project_id,application_id,item_id,cluster_id,namespace,workload_kind,workload_name,pod_uid,pod_name,container_name,occurrence_count,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,'production','Deployment','app','pod-1','app-1','app',1,now(),now())").bind(first.organization_id).bind(first.project_id).bind(first.application_id).bind(item_id).bind(first.cluster_id).execute(&pool).await.unwrap();
    let app = web_api::router(policy_api::router(pool.clone()), &WebApiConfig::default());
    let base = format!(
        "/api/v1/projects/{}/applications/{}",
        first.project_id, first.application_id
    );
    let revision = serde_json::json!({"source_inventory_item_id":item_id,"placement":{"namespaces":["production"]},"inside_effect":"expected","outside_effect":"requires_review"});
    let preview = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("{base}/policies/preview"),
            &cookie,
            None,
            Some(revision.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = json(preview).await;
    assert_eq!(preview["sighting_count"], 1);
    assert_eq!(preview["expected_count"], 1);
    let key = Uuid::new_v4();
    let body = serde_json::json!({"name":"Expected app process","revision":revision});
    let created = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("{base}/policies"),
            &cookie,
            Some(key),
            Some(body.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::OK);
    let created = json(created).await;
    let policy_id = created["resource_id"].as_str().unwrap();
    let recomputation_id = created["recomputation_id"].as_str().unwrap();
    let recomputation = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("{base}/policy-recomputations/{recomputation_id}"),
            &cookie,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(recomputation.status(), StatusCode::OK);
    assert_eq!(json(recomputation).await["state"], "pending");
    assert!(
        server::policy_recompute::run_one_batch(&pool, Uuid::new_v4(), 100)
            .await
            .unwrap()
    );
    let verdict: String = sqlx::query_scalar(
        "SELECT verdict FROM runtime_sighting_policy_evaluations WHERE item_id=$1",
    )
    .bind(item_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(verdict, "expected");
    let replay = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("{base}/policies"),
            &cookie,
            Some(key),
            Some(body),
        ))
        .await
        .unwrap();
    assert_eq!(json(replay).await, created);
    let reused = app.clone().oneshot(request("POST", &format!("{base}/policies"), &cookie, Some(key), Some(serde_json::json!({"name":"different","revision":{"source_inventory_item_id":item_id,"placement":{},"inside_effect":"expected"}})))).await.unwrap();
    assert_eq!(reused.status(), StatusCode::CONFLICT);
    let list = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("{base}/policies"),
            &cookie,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(json(list).await["items"].as_array().unwrap().len(), 1);
    let revisions = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("{base}/policies/{policy_id}/revisions"),
            &cookie,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(json(revisions).await["items"].as_array().unwrap().len(), 1);
    for action in ["disable", "enable"] {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                &format!("{base}/policies/{policy_id}/{action}"),
                &cookie,
                Some(Uuid::new_v4()),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let replacement = serde_json::json!({"revision":{"source_inventory_item_id":item_id,"placement":{"workload_names":["app"]},"inside_effect":"expected"}});
    let (left, right) = tokio::join!(
        app.clone().oneshot(request(
            "POST",
            &format!("{base}/policies/{policy_id}/replace"),
            &cookie,
            Some(Uuid::new_v4()),
            Some(replacement.clone())
        )),
        app.clone().oneshot(request(
            "POST",
            &format!("{base}/policies/{policy_id}/replace"),
            &cookie,
            Some(Uuid::new_v4()),
            Some(replacement)
        ))
    );
    assert_eq!(left.unwrap().status(), StatusCode::OK);
    assert_eq!(right.unwrap().status(), StatusCode::OK);
    let revisions = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("{base}/policies/{policy_id}/revisions?limit=1"),
            &cookie,
            None,
            None,
        ))
        .await
        .unwrap();
    let revisions = json(revisions).await;
    assert_eq!(revisions["items"].as_array().unwrap().len(), 1);
    assert!(revisions["next_cursor"].is_string());
    assert_eq!(
        revisions["items"][0]["source_inventory_item_id"],
        item_id.to_string()
    );
    let owner_cookie = session(&pool, &first, "owner").await;
    let owner_read = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("{base}/policies/{policy_id}"),
            &owner_cookie,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(owner_read.status(), StatusCode::OK);
    let suppression = serde_json::json!({"source_inventory_item_id":item_id,"placement":{},"reason":"migration window","expires_at":(Utc::now()+Duration::days(1)).to_rfc3339()});
    let invalid=app.clone().oneshot(request("POST",&format!("{base}/policy-suppressions"),&cookie,Some(Uuid::new_v4()),Some(serde_json::json!({"source_inventory_item_id":item_id,"placement":{},"reason":"","expires_at":Utc::now().to_rfc3339()})))).await.unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let suppression_key = Uuid::new_v4();
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("{base}/policy-suppressions"),
            &cookie,
            Some(suppression_key),
            Some(suppression.clone()),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let suppression_result = json(response).await;
    let replay = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("{base}/policy-suppressions"),
            &cookie,
            Some(suppression_key),
            Some(suppression),
        ))
        .await
        .unwrap();
    assert_eq!(json(replay).await, suppression_result);
    let suppression_id = suppression_result["resource_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let cancel_key = Uuid::new_v4();
    let cancel = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("{base}/policy-suppressions/{suppression_id}/cancel"),
            &cookie,
            Some(cancel_key),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(cancel.status(), StatusCode::OK);
    let cancel_replay = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("{base}/policy-suppressions/{suppression_id}/cancel"),
            &cookie,
            Some(cancel_key),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(cancel_replay.status(), StatusCode::OK);
    while server::policy_recompute::run_one_batch(&pool, Uuid::new_v4(), 100)
        .await
        .unwrap()
    {}
    sqlx::query("DELETE FROM runtime_sighting_policy_evaluations WHERE item_id=$1")
        .bind(item_id)
        .execute(&pool)
        .await
        .unwrap();
    let options = server::policy_recompute::BackfillOptions {
        organization_id: first.organization_id,
        project_id: first.project_id,
        application_id: Some(first.application_id),
    };
    assert_eq!(
        server::policy_recompute::backfill(&pool, options)
            .await
            .unwrap()
            .operations_created,
        1
    );
    assert_eq!(
        server::policy_recompute::backfill(&pool, options)
            .await
            .unwrap()
            .operations_created,
        0
    );
    let crashed_owner = Uuid::new_v4();
    sqlx::query("UPDATE runtime_policy_recomputations SET state='running',lease_owner=$1,lease_expires_at=now()-interval '1 second' WHERE state='pending'")
        .bind(crashed_owner)
        .execute(&pool)
        .await
        .unwrap();
    let (worker_a, worker_b) = tokio::join!(
        server::policy_recompute::run_one_batch(&pool, Uuid::new_v4(), 1),
        server::policy_recompute::run_one_batch(&pool, Uuid::new_v4(), 1)
    );
    assert!(worker_a.unwrap() || worker_b.unwrap());
    while server::policy_recompute::run_one_batch(&pool, Uuid::new_v4(), 100)
        .await
        .unwrap()
    {}
    let restored: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runtime_sighting_policy_evaluations WHERE item_id=$1",
    )
    .bind(item_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored, 1);
    let reclaimed: i32 = sqlx::query_scalar(
        "SELECT max(attempt_count) FROM runtime_policy_recomputations WHERE application_id=$1",
    )
    .bind(first.application_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(reclaimed >= 1, "expired worker lease must be reclaimed");
    let foreign = app
        .oneshot(request(
            "GET",
            &format!(
                "/api/v1/projects/{}/applications/{}/policies",
                second.project_id, second.application_id
            ),
            &cookie,
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
}

/// Ingests one process execution, which projects an inventory item and a
/// runtime group linked to it. Returns both ids.
async fn observed_process(pool: &sqlx::PgPool, ids: &BootstrapIds) -> (Uuid, Uuid) {
    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agents (id,organization_id,cluster_id,node_name,agent_version) VALUES ($1,$2,$3,'node-1','test')")
        .bind(agent_id).bind(ids.organization_id).bind(ids.cluster_id).execute(pool).await.unwrap();
    let event = RuntimeEvent {
        id: Uuid::new_v4(),
        observed_at: Utc::now(),
        schema_version: EVENT_SCHEMA_VERSION,
        attribution: KubernetesAttribution {
            project_id: ids.project_id,
            application_id: ids.application_id,
            node_name: "node-1".into(),
            namespace: "production".into(),
            pod_uid: "pod-uid".into(),
            pod_name: "app-1".into(),
            container_id: "container-id".into(),
            container_name: "app".into(),
            workload_uid: "workload-uid".into(),
            workload_kind: "Deployment".into(),
            workload_name: "app".into(),
            release: None,
            release_identity: None,
        },
        process: ProcessIdentity {
            cgroup_id: 42,
            pid: 10,
            tgid: 10,
            command: "sh".into(),
        },
        payload: EventPayload::ProcessExec(ProcessExec {
            executable: "/bin/sh".into(),
            parent_command: None,
        }),
    };
    let context = IngestionContext {
        scope: SessionScope {
            organization_id: ids.organization_id,
            cluster_id: ids.cluster_id,
        },
        agent_id,
    };
    persist_batch(pool, context, &[event]).await.unwrap();
    sqlx::query_as("SELECT item_id,group_id FROM runtime_inventory_group_links WHERE project_id=$1")
        .bind(ids.project_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Sends a request and returns its status and JSON body. An error body must
/// carry the request's correlation id.
async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    key: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut request = request(method, uri, cookie, None, body);
    if let Some(key) = key {
        request
            .headers_mut()
            .insert("idempotency-key", key.parse().unwrap());
    }
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let request_id = response.headers()[REQUEST_ID_HEADER]
        .to_str()
        .unwrap()
        .to_owned();
    let body = json(response).await;
    if status.is_client_error() || status.is_server_error() {
        assert_eq!(body["request_id"], request_id, "{method} {uri}");
    }
    (status, body)
}

fn assert_error(
    (status, body): &(StatusCode, serde_json::Value),
    expected: StatusCode,
    code: &str,
    message: &str,
    route: &str,
) {
    assert_eq!(*status, expected, "{route}: {body}");
    assert_eq!(body["error"], code, "{route}");
    assert_eq!(body["message"], message, "{route}");
}

#[sqlx::test(migrator = "server::database::MIGRATOR")]
#[ignore = "requires a PostgreSQL server with DATABASE_URL"]
async fn policy_routes_map_each_service_error_onto_the_error_envelope(pool: sqlx::PgPool) {
    let first = bootstrap(&pool, &config("policy-errors-first"))
        .await
        .unwrap();
    let second = bootstrap(&pool, &config("policy-errors-second"))
        .await
        .unwrap();
    let member = session(&pool, &first, "member").await;
    let foreign = session(&pool, &second, "owner").await;
    let (item_id, group_id) = observed_process(&pool, &first).await;
    let app = web_api::router(policy_api::router(pool.clone()), &WebApiConfig::default());
    let base = format!(
        "/api/v1/projects/{}/applications/{}",
        first.project_id, first.application_id
    );
    let revision = serde_json::json!({"source_inventory_item_id":item_id,"placement":{},"inside_effect":"expected"});
    let policy = serde_json::json!({"name":"Shell","revision":revision});
    let suppression = serde_json::json!({"source_inventory_item_id":item_id,"placement":{},"reason":"maintenance","expires_at":(Utc::now()+Duration::days(1)).to_rfc3339()});

    // Seeds: an observed item and its runtime group both seed a policy.
    let (status, seed) = send(
        &app,
        "GET",
        &format!("{base}/runtime-inventory/{item_id}/policy-seed"),
        &member,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seed["state"], "available");
    let (status, seed) = send(
        &app,
        "GET",
        &format!("{base}/runtime-groups/{group_id}/policy-seed"),
        &member,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seed["state"], "available");

    let key = Uuid::new_v4().to_string();
    let (status, created) = send(
        &app,
        "POST",
        &format!("{base}/policies"),
        &member,
        Some(&key),
        Some(policy.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let policy_id = created["resource_id"].as_str().unwrap().to_owned();
    let recomputation_id = created["recomputation_id"].as_str().unwrap().to_owned();
    let (status, created_suppression) = send(
        &app,
        "POST",
        &format!("{base}/policy-suppressions"),
        &member,
        Some(&Uuid::new_v4().to_string()),
        Some(suppression.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let suppression_id = created_suppression["resource_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let routes: Vec<(&str, String, Option<serde_json::Value>)> = vec![
        ("GET", format!("{base}/policies"), None),
        ("POST", format!("{base}/policies"), Some(policy.clone())),
        (
            "POST",
            format!("{base}/policies/preview"),
            Some(revision.clone()),
        ),
        ("GET", format!("{base}/policies/{policy_id}"), None),
        (
            "GET",
            format!("{base}/policies/{policy_id}/revisions"),
            None,
        ),
        (
            "POST",
            format!("{base}/policies/{policy_id}/replace"),
            Some(serde_json::json!({"revision":revision})),
        ),
        ("POST", format!("{base}/policies/{policy_id}/enable"), None),
        ("POST", format!("{base}/policies/{policy_id}/disable"), None),
        (
            "GET",
            format!("{base}/runtime-inventory/{item_id}/policy-seed"),
            None,
        ),
        (
            "GET",
            format!("{base}/runtime-groups/{group_id}/policy-seed"),
            None,
        ),
        ("GET", format!("{base}/policy-suppressions"), None),
        (
            "POST",
            format!("{base}/policy-suppressions"),
            Some(suppression.clone()),
        ),
        (
            "POST",
            format!("{base}/policy-suppressions/{suppression_id}/cancel"),
            None,
        ),
        (
            "GET",
            format!("{base}/policy-recomputations/{recomputation_id}"),
            None,
        ),
    ];
    for (method, uri, body) in &routes {
        let route = format!("{method} {uri}");
        let key = Uuid::new_v4().to_string();
        // Without a session, every route refuses before anything else.
        assert_error(
            &send(&app, method, uri, "", Some(&key), body.clone()).await,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid or missing bearer credential",
            &route,
        );
        // Another organization's session cannot see the project.
        assert_error(
            &send(&app, method, uri, &foreign, Some(&key), body.clone()).await,
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &route,
        );
    }

    // Unknown resources inside a visible project are not found either.
    let unknown = Uuid::new_v4();
    let other_app = format!(
        "/api/v1/projects/{}/applications/{unknown}",
        first.project_id
    );
    for (method, uri, body) in [
        ("GET", format!("{other_app}/policies"), None),
        (
            "POST",
            format!("{other_app}/policies"),
            Some(policy.clone()),
        ),
        (
            "POST",
            format!("{other_app}/policies/preview"),
            Some(revision.clone()),
        ),
        (
            "POST",
            format!("{other_app}/policy-suppressions"),
            Some(suppression.clone()),
        ),
        ("GET", format!("{base}/policies/{unknown}"), None),
        ("GET", format!("{base}/policies/{unknown}/revisions"), None),
        ("POST", format!("{base}/policies/{unknown}/enable"), None),
        (
            "GET",
            format!("{base}/runtime-inventory/{unknown}/policy-seed"),
            None,
        ),
        (
            "GET",
            format!("{base}/runtime-groups/{unknown}/policy-seed"),
            None,
        ),
        (
            "POST",
            format!("{base}/policy-suppressions/{unknown}/cancel"),
            None,
        ),
        (
            "GET",
            format!("{base}/policy-recomputations/{unknown}"),
            None,
        ),
        (
            "POST",
            format!("{base}/policies/preview"),
            Some(
                serde_json::json!({"source_inventory_item_id":unknown,"placement":{},"inside_effect":"expected"}),
            ),
        ),
    ] {
        let route = format!("{method} {uri}");
        assert_error(
            &send(
                &app,
                method,
                &uri,
                &member,
                Some(&Uuid::new_v4().to_string()),
                body,
            )
            .await,
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found",
            &route,
        );
    }

    // Invalid requests name what is wrong.
    for uri in [
        format!("{base}/policies?limit=0"),
        format!("{base}/policies/{policy_id}/revisions?limit=201"),
        format!("{base}/policy-suppressions?limit=0"),
    ] {
        assert_error(
            &send(&app, "GET", &uri, &member, None, None).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "limit must be between 1 and 200",
            &uri,
        );
    }
    for (uri, body) in [
        (format!("{base}/policies"), Some(policy.clone())),
        (
            format!("{base}/policies/{policy_id}/replace"),
            Some(serde_json::json!({"revision":revision})),
        ),
        (format!("{base}/policies/{policy_id}/disable"), None),
        (
            format!("{base}/policy-suppressions"),
            Some(suppression.clone()),
        ),
        (
            format!("{base}/policy-suppressions/{suppression_id}/cancel"),
            None,
        ),
    ] {
        for key in [None, Some("not-a-uuid")] {
            assert_error(
                &send(&app, "POST", &uri, &member, key, body.clone()).await,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Idempotency-Key must be a canonical UUID",
                &uri,
            );
        }
    }
    assert_error(
        &send(
            &app,
            "POST",
            &format!("{base}/policies"),
            &member,
            Some(&Uuid::new_v4().to_string()),
            Some(serde_json::json!({"name":"  ","revision":revision})),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "policy name must contain between 1 and 160 characters",
        "empty policy name",
    );
    assert_error(
        &send(&app, "POST", &format!("{base}/policies/preview"), &member, None, Some(serde_json::json!({"source_inventory_item_id":item_id,"placement":{},"inside_effect":"expected","outside_effect":"expected"}))).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "outside_effect may only be requires_review",
        "outside effect",
    );
    assert_error(
        &send(&app, "POST", &format!("{base}/policy-suppressions"), &member, Some(&Uuid::new_v4().to_string()), Some(serde_json::json!({"source_inventory_item_id":item_id,"placement":{},"reason":"maintenance","expires_at":(Utc::now()+Duration::days(91)).to_rfc3339()}))).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "suppression requires a reason and an expiry within 90 days",
        "suppression expiry",
    );

    // A key reused for a different request conflicts.
    assert_error(
        &send(
            &app,
            "POST",
            &format!("{base}/policies"),
            &member,
            Some(&key),
            Some(serde_json::json!({"name":"Other","revision":revision})),
        )
        .await,
        StatusCode::CONFLICT,
        "conflict",
        "idempotency key was already used for another request",
        "reused key",
    );
}
